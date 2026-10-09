package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ---------------------------------------------------------------------------
// 四层去重第四层:人工合并(发现页多选 → 合并到一条)。
//
// 与档 A 自动合并的分工:自动合并只在写入时按结构化键命中「同入口」,零人工;
// 人工合并是用户在列表里显式勾选,允许跨类别 / 跨资产地判「其实就是同一个洞」。
// 合并后:
//   - source: status=duplicate、merged_into=target,并清掉 suspected 标记;
//   - target: 吸收 source 的严重度(取高)、摘要(取新,旧的归档进证据)、证据
//             (追加带时间戳的审计段),流量绑定 / 复测 / 校验记录迁到 target,
//             证据版本 +1。
// source 行保留不删:导出与审计仍能看到「这条被并到了哪」。
// ---------------------------------------------------------------------------

// MergeFindingsResult 是一次人工合并的结果。Merged 是实际并入的 source,
// Skipped 是「不存在 / 已经并到同一目标」的 source(幂等,不报错)。
type MergeFindingsResult struct {
	TargetID int64   `json:"target_id,string"`
	Merged   []int64 `json:"merged"`
	Skipped  []int64 `json:"skipped"`
}

// MergeFindings 把 sourceIDs 全部合并进 targetID。
func (d *DB) MergeFindings(ctx context.Context, sourceIDs []int64, targetID int64) (*MergeFindingsResult, error) {
	if targetID <= 0 {
		return nil, errors.New("目标漏洞 id 无效")
	}
	res := &MergeFindingsResult{TargetID: targetID, Merged: []int64{}, Skipped: []int64{}}
	err := d.WithEvidenceTx(ctx, func(tx *sql.Tx) error {
		target, err := findingForUpdateTx(tx, targetID)
		if err != nil {
			return err
		}
		if target.MergedInto != nil {
			return fmt.Errorf("目标漏洞 #%d 已被合并,不能再作为合并目标", targetID)
		}
		severity, summary, evidence := target.Severity, target.Summary, target.Evidence
		seen := map[int64]bool{targetID: true}
		changed := false
		for _, sid := range sourceIDs {
			if sid <= 0 || seen[sid] {
				continue
			}
			seen[sid] = true
			src, err := findingForUpdateTx(tx, sid)
			if err != nil {
				if errors.Is(err, ErrFindingNotFound) {
					res.Skipped = append(res.Skipped, sid)
					continue
				}
				return err
			}
			if src.MergedInto != nil && *src.MergedInto == targetID {
				res.Skipped = append(res.Skipped, sid)
				continue
			}
			// 复用档 A 的合并语义:严重度取高、摘要替换并把旧摘要归档、证据追加审计段。
			in := RecordFindingInput{
				VulnClass: src.VulnClass, Name: src.Name, Severity: src.Severity,
				Summary: src.Summary, Evidence: src.Evidence, Worker: "manual-merge",
			}
			if src.TaskID != nil {
				in.TaskID = *src.TaskID
			}
			cand := DBFinding{
				ID: target.ID, TaskID: target.TaskID, VulnClass: target.VulnClass,
				Severity: severity, Summary: summary, Evidence: evidence,
			}
			severity, summary, evidence = mergeFindingFields(cand, in, time.Now())
			changed = true

			if err := moveFindingEvidenceTx(tx, sid, targetID); err != nil {
				return err
			}
			if _, err := tx.Exec(`UPDATE findings
				SET status=$2, merged_into=$3, suspected_dup_of=NULL, suspected_dup_score=NULL
				WHERE id=$1`, sid, FindingDuplicate, targetID); err != nil {
				return err
			}
			res.Merged = append(res.Merged, sid)
		}
		if !changed {
			return nil
		}
		if _, err := tx.Exec(`UPDATE findings SET severity=$2, summary=$3, evidence=$4 WHERE id=$1`,
			targetID, severity, summary, evidence); err != nil {
			return err
		}
		// 探索节点 payload 同步(与档 A 合并一致),保证按任务发现 Tab 与 findings 表一致。
		if target.NodeID != nil {
			if _, err := tx.Exec(`UPDATE exploration_nodes
SET payload = jsonb_set(jsonb_set(jsonb_set(payload, '{severity}', to_jsonb($2::text)),
'{summary}', to_jsonb($3::text)), '{evidence,poc}', to_jsonb($4::text))
WHERE id=$1 AND kind='finding'`, *target.NodeID, severity, summary, evidence); err != nil {
				return err
			}
		}
		return bumpEvidenceVersionTx(tx, targetID)
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// findingForUpdateTx 读一行 finding 并加行锁。不存在返回 ErrFindingNotFound。
func findingForUpdateTx(tx *sql.Tx, id int64) (*DBFinding, error) {
	var (
		f          DBFinding
		taskID     sql.NullInt64
		nodeID     sql.NullInt64
		mergedInto sql.NullInt64
		name       sql.NullString
		worker     sql.NullString
	)
	err := tx.QueryRow(`SELECT id, task_id, node_id, vulnclass, COALESCE(name,''), severity,
		COALESCE(summary,''), COALESCE(evidence,''), COALESCE(worker,''), COALESCE(status,'pending'), merged_into
		FROM findings WHERE id=$1 FOR UPDATE`, id).Scan(
		&f.ID, &taskID, &nodeID, &f.VulnClass, &name, &f.Severity,
		&f.Summary, &f.Evidence, &worker, &f.Status, &mergedInto)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrFindingNotFound
	}
	if err != nil {
		return nil, err
	}
	if taskID.Valid {
		v := taskID.Int64
		f.TaskID = &v
	}
	if nodeID.Valid {
		v := nodeID.Int64
		f.NodeID = &v
	}
	if mergedInto.Valid {
		v := mergedInto.Int64
		f.MergedInto = &v
	}
	f.Name = name.String
	f.Worker = worker.String
	return &f, nil
}

// moveFindingEvidenceTx 把 source 的流量绑定 / 复测 / 校验记录迁到 target。
// 冲突行留在 source(不丢历史,也不违反唯一索引):
//   - 流量绑定唯一键是 (finding_id, snapshot_id):同快照已在 target 上时,source 那条
//     是重复引用,直接删;
//   - 复测 / 校验的唯一键是「每 finding 至多一条活跃」:两边都有活跃任务时保留 source 的,
//     等它跑完再迁,避免把正在跑的会话改挂到别的漏洞上。
func moveFindingEvidenceTx(tx *sql.Tx, sourceID, targetID int64) error {
	if _, err := tx.Exec(`UPDATE finding_traffic_bindings AS b SET finding_id=$2
WHERE b.finding_id=$1
  AND NOT EXISTS (SELECT 1 FROM finding_traffic_bindings t WHERE t.finding_id=$2 AND t.snapshot_id=b.snapshot_id)`,
		sourceID, targetID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM finding_traffic_bindings AS b
WHERE b.finding_id=$1
  AND EXISTS (SELECT 1 FROM finding_traffic_bindings t WHERE t.finding_id=$2 AND t.snapshot_id=b.snapshot_id)`,
		sourceID, targetID); err != nil {
		return err
	}
	// 迁完后重排顺序,保证发现页证据列表顺序稳定。
	if _, err := tx.Exec(`UPDATE finding_traffic_bindings AS b SET position = t.rn
FROM (SELECT id, row_number() OVER (ORDER BY position, id) - 1 AS rn
      FROM finding_traffic_bindings WHERE finding_id=$1) AS t
WHERE b.id = t.id`, targetID); err != nil {
		return err
	}
	for _, tbl := range []string{"finding_retests", "finding_checks"} {
		if _, err := tx.Exec(`UPDATE `+tbl+` AS r SET finding_id=$2
WHERE r.finding_id=$1
  AND NOT (r.status IN ('pending','running')
           AND EXISTS (SELECT 1 FROM `+tbl+` t WHERE t.finding_id=$2 AND t.status IN ('pending','running')))`,
			sourceID, targetID); err != nil {
			return err
		}
	}
	return nil
}

// FindingDupMember 是疑似重复分组里的一条(被指认重复 / 已被合并的漏洞)。
type FindingDupMember struct {
	ID        int64    `json:"id,string"`
	VulnClass string   `json:"vulnclass"`
	Name      string   `json:"name,omitempty"`
	Status    string   `json:"status"`
	Score     *float64 `json:"score,omitempty"`
	Merged    bool     `json:"merged"`
}

// FindingDupGroup 是一组「同一目标 + 若干疑似/已合并成员」。
type FindingDupGroup struct {
	TargetID  int64             `json:"target_id,string"`
	VulnClass string            `json:"vulnclass"`
	Name      string            `json:"name,omitempty"`
	Status    string            `json:"status"`
	Members   []FindingDupMember `json:"members"`
}

// ListFindingDuplicateGroups 返回疑似重复 / 已合并的分组视图:按目标 finding 聚合,
// 成员的 suspected_dup_score 是相似度或 1(审核模型指认)。
// taskID>0 时只返回目标属于该任务的分组。limit<=0 → 200(成员行数上限)。
func (d *DB) ListFindingDuplicateGroups(taskID int64, limit int) ([]FindingDupGroup, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := d.Query(`
		SELECT t.id, t.vulnclass, COALESCE(t.name,''), COALESCE(t.status,'pending'),
		       m.id, m.vulnclass, COALESCE(m.name,''), COALESCE(m.status,'pending'),
		       m.suspected_dup_score, (m.merged_into IS NOT NULL)
		FROM findings m
		JOIN findings t ON t.id = COALESCE(m.suspected_dup_of, m.merged_into)
		WHERE (m.suspected_dup_of IS NOT NULL OR m.merged_into IS NOT NULL)
		  AND ($1::bigint <= 0 OR t.task_id = $1)
		ORDER BY t.id DESC, m.id ASC
		LIMIT $2`, taskID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []FindingDupGroup{}
	for rows.Next() {
		var (
			g     FindingDupGroup
			m     FindingDupMember
			score sql.NullFloat64
		)
		if err := rows.Scan(&g.TargetID, &g.VulnClass, &g.Name, &g.Status,
			&m.ID, &m.VulnClass, &m.Name, &m.Status, &score, &m.Merged); err != nil {
			return nil, err
		}
		if score.Valid {
			v := score.Float64
			m.Score = &v
		}
		if n := len(out); n > 0 && out[n-1].TargetID == g.TargetID {
			out[n-1].Members = append(out[n-1].Members, m)
			continue
		}
		g.Members = []FindingDupMember{m}
		out = append(out, g)
	}
	return out, rows.Err()
}
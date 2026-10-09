package db

// ---------------------------------------------------------------------------
// 四层去重第三层:二次审核判重参照。
//
// 审核模型能判「这条是不是重复」,但它看不到已有漏洞长什么样,只能给出一个
// is_duplicate 布尔值。这里把「同任务 / 资产有交集的既有漏洞清单」(id + 类别 +
// 状态 + 摘要截断)喂给模型,模型就能在 is_duplicate=true 时指认重复目标
// (duplicate_of),再由 MarkFindingSuspectedDuplicate 落到 suspected_dup_of,
// 供第四层人工合并 UI 直接使用。
// ---------------------------------------------------------------------------

// FindingDupCandidate 是喂给审核模型的既有漏洞摘要(判重参照)。
type FindingDupCandidate struct {
	ID        int64
	VulnClass string
	Name      string
	Severity  string
	Status    string
	Summary   string
}

// findingDupContextSummaryRunes 是判重清单里单条摘要的截断长度:够模型比对语义,
// 又不至于把 prompt 撑大(20 条 × 300 字上限可控)。
const findingDupContextSummaryRunes = 300

// ListFindingDupCandidates 返回可能与 findingID 重复的既有漏洞:同任务,或
// asset_ids 有交集(任一资产相同即可,不是包含)。已合并(merged_into 非空)与已判
// 重复(status=duplicate)的行排除。按新到旧。
func (d *DB) ListFindingDupCandidates(taskID, findingID int64, assetIDs []int64, limit int) ([]FindingDupCandidate, error) {
	if limit <= 0 {
		limit = 20
	}
	assets := assetIDs
	if assets == nil {
		assets = []int64{}
	}
	rows, err := d.Query(`
		SELECT id, vulnclass, COALESCE(name,''), severity, COALESCE(status,'pending'), COALESCE(summary,'')
		FROM findings
		WHERE id <> $1
		  AND merged_into IS NULL
		  AND COALESCE(status,'') <> $5
		  AND ( ($2::bigint > 0 AND task_id = $2)
		     OR EXISTS (SELECT 1 FROM jsonb_array_elements_text(asset_ids) AS a(v)
		                WHERE a.v::bigint = ANY($3::bigint[])) )
		ORDER BY created_at DESC, id DESC
		LIMIT $4`, findingID, taskID, assets, limit, FindingDuplicate)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []FindingDupCandidate{}
	for rows.Next() {
		var c FindingDupCandidate
		if err := rows.Scan(&c.ID, &c.VulnClass, &c.Name, &c.Severity, &c.Status, &c.Summary); err != nil {
			return nil, err
		}
		c.Summary = truncateFindingRunes(c.Summary, findingDupContextSummaryRunes)
		out = append(out, c)
	}
	return out, rows.Err()
}

// MarkFindingSuspectedDuplicate 把 findingID 标成「疑似与 targetID 重复」。
// 只标记不合并 —— 合并必须人工在发现页确认(或跨任务开关显式打开)。目标不存在时
// 静默不动,避免留下指向空洞的悬空引用。
func (d *DB) MarkFindingSuspectedDuplicate(findingID, targetID int64, score float64) error {
	if findingID <= 0 || targetID <= 0 || findingID == targetID {
		return nil
	}
	_, err := d.Exec(`UPDATE findings SET suspected_dup_of=$2, suspected_dup_score=$3
		WHERE id=$1 AND EXISTS(SELECT 1 FROM findings WHERE id=$2)`, findingID, targetID, score)
	return err
}

// ClearFindingSuspectedDuplicate 清掉疑似重复标记(人工判定「不是重复」后调用)。
func (d *DB) ClearFindingSuspectedDuplicate(findingID int64) error {
	if findingID <= 0 {
		return nil
	}
	_, err := d.Exec(`UPDATE findings SET suspected_dup_of=NULL, suspected_dup_score=NULL WHERE id=$1`, findingID)
	return err
}

func truncateFindingRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}
package db

import "strings"

// asset_screening 落库层（schema.sql §N）。
//
// 资产漏斗：insert_assets 落库时由 assetscreen 包算出「优先级评分」与「同款聚类键」，
// 写在这里供三处消费：
//   ① 派发排序 —— 高分资产优先派发；
//   ② 同款聚类冷却 —— 同一 cluster 的 pending 上限（避免一口气把同一套系统的 500 个域名全铺开）；
//   ③ graph_overview 摘要 —— 让 planner 能解释「这批资产为什么没被展开」。
//
// 与 assets 是一对多：同一资产在不同任务下可有不同评分，按 (asset_id, task_id) 幂等覆盖。
// taskID <= 0（chat/auto 等无任务上下文）时不落库——这些资产不参与派发排序。

// ScreeningRecord 是一条资产的筛选结果。
type ScreeningRecord struct {
	AssetID int64    `json:"asset_id"`
	TaskID  int64    `json:"task_id"`
	Score   float64  `json:"score"`
	Reasons []string `json:"reasons"`
	Cluster string   `json:"cluster"`
}

// ScreeningSummary 是一个任务的筛选摘要（供 graph_overview 展示）。
type ScreeningSummary struct {
	Scored     int     `json:"scored"`      // 已评分资产数
	LowScore   int     `json:"low_score"`   // 负分（降权）资产数
	Clusters   int     `json:"clusters"`    // 不同聚类数
	TopCluster string  `json:"top_cluster"` // 资产最多的聚类键
	TopCount   int     `json:"top_count"`   // 该聚类资产数
	AvgScore   float64 `json:"avg_score"`
}

// SetAssetScreening 幂等写入一条筛选结果。taskID<=0 或 assetID<=0 时静默跳过。
func (s *AssetStore) SetAssetScreening(taskID, assetID int64, score float64, reasons []string, cluster string) error {
	if s == nil || s.db == nil || taskID <= 0 || assetID <= 0 {
		return nil
	}
	if reasons == nil {
		reasons = []string{}
	}
	_, err := s.db.Exec(`
		INSERT INTO asset_screening (asset_id, task_id, score, reasons, cluster, updated_at)
		VALUES ($1, $2, $3, $4::text[], $5, now())
		ON CONFLICT (asset_id, task_id) DO UPDATE
		SET score = EXCLUDED.score, reasons = EXCLUDED.reasons,
		    cluster = EXCLUDED.cluster, updated_at = now()`,
		assetID, taskID, score, reasons, nullIfEmpty(cluster))
	return err
}

// ScreeningSummary 汇总某任务的筛选结果；无数据时返回零值。
func (s *AssetStore) ScreeningSummary(taskID int64) (ScreeningSummary, error) {
	var out ScreeningSummary
	if s == nil || s.db == nil || taskID <= 0 {
		return out, nil
	}
	err := s.db.QueryRow(`
		SELECT count(*),
		       count(*) FILTER (WHERE score < 0),
		       count(DISTINCT cluster) FILTER (WHERE cluster IS NOT NULL AND cluster <> ''),
		       COALESCE(avg(score), 0)
		FROM asset_screening WHERE task_id = $1`, taskID).
		Scan(&out.Scored, &out.LowScore, &out.Clusters, &out.AvgScore)
	if err != nil {
		return out, err
	}
	// 资产最多的聚类（用于提示 planner「这一簇可能是同一套系统」）。
	_ = s.db.QueryRow(`
		SELECT cluster, count(*) FROM asset_screening
		WHERE task_id = $1 AND cluster IS NOT NULL AND cluster <> ''
		GROUP BY cluster ORDER BY count(*) DESC, cluster ASC LIMIT 1`, taskID).
		Scan(&out.TopCluster, &out.TopCount)
	return out, nil
}

// ClusterAssetCounts 返回某任务下各聚类的资产数（供同款聚类冷却判断）。
func (s *AssetStore) ClusterAssetCounts(taskID int64) (map[string]int, error) {
	out := map[string]int{}
	if s == nil || s.db == nil || taskID <= 0 {
		return out, nil
	}
	rows, err := s.db.Query(`
		SELECT cluster, count(*) FROM asset_screening
		WHERE task_id = $1 AND cluster IS NOT NULL AND cluster <> ''
		GROUP BY cluster`, taskID)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			return out, err
		}
		out[k] = n
	}
	return out, rows.Err()
}

// AddScreeningSkips 把一批预筛跳过原因累加进任务计数（reason 为空按 "unspecified" 记）。
// 用于 graph_overview 展示「有多少资产在入库前就被机械预筛挡掉、分别因为什么」。
func (s *AssetStore) AddScreeningSkips(taskID int64, reasons []string) error {
	if s == nil || s.db == nil || taskID <= 0 || len(reasons) == 0 {
		return nil
	}
	tally := map[string]int64{}
	for _, r := range reasons {
		r = strings.TrimSpace(r)
		if r == "" {
			r = "unspecified"
		}
		tally[r]++
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	for reason, n := range tally {
		if _, err := tx.Exec(`
			INSERT INTO task_screening_skip (task_id, reason, count, updated_at)
			VALUES ($1, $2, $3, now())
			ON CONFLICT (task_id, reason) DO UPDATE
			SET count = task_screening_skip.count + EXCLUDED.count, updated_at = now()`,
			taskID, reason, n); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ScreeningSkips 返回某任务各预筛原因累计跳过数。
func (s *AssetStore) ScreeningSkips(taskID int64) (map[string]int64, error) {
	out := map[string]int64{}
	if s == nil || s.db == nil || taskID <= 0 {
		return out, nil
	}
	rows, err := s.db.Query(`SELECT reason, count FROM task_screening_skip WHERE task_id = $1`, taskID)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var n int64
		if err := rows.Scan(&k, &n); err != nil {
			return out, err
		}
		out[k] = n
	}
	return out, rows.Err()
}

// AssetClusters 返回若干资产在指定任务下的同款聚类键。
// 优先取 asset_screening.cluster(insert_assets 落库时算好);缺失时回退到
// assets 的 root_domain / domain / ip,保证老资产也有可用聚类键。
// 供 agent 建意图时把 cluster 写进 payload,派发闸门据此限流。
func (s *AssetStore) AssetClusters(taskID int64, assetIDs []int64) (map[int64]string, error) {
	out := map[int64]string{}
	if s == nil || s.db == nil || len(assetIDs) == 0 {
		return out, nil
	}
	rows, err := s.db.Query(`
		SELECT a.id,
		       COALESCE(NULLIF(sc.cluster, ''), NULLIF(a.root_domain, ''),
		                NULLIF(a.domain, ''), COALESCE(a.ip, ''))
		FROM assets a
		LEFT JOIN asset_screening sc ON sc.asset_id = a.id AND sc.task_id = $2
		WHERE a.id = ANY($1)`, assetIDs, taskID)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var cluster string
		if err := rows.Scan(&id, &cluster); err != nil {
			return out, err
		}
		if strings.TrimSpace(cluster) != "" {
			out[id] = cluster
		}
	}
	return out, rows.Err()
}

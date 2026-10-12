package db

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// cluster_cooldown 落库层(schema.sql §N):同款聚类派发闸门的状态。
//
// 与 dispatch 包(纯策略)分工:这里只负责读写「某探索下某 cluster 的连续失败
// 计数与冷却截止时间」,判定逻辑在 dispatch.Evaluate。
//
// 聚类键(cluster)由 agent 建意图时写入 payload(payload.cluster / payload.clusters),
// 因此派发侧读意图 payload 即可,无需 join 资产表。

// ClusterCooldownRow 是 cluster_cooldown 的一行。
type ClusterCooldownRow struct {
	Cluster       string     `json:"cluster"`
	DeadCount     int        `json:"dead_count"`
	CooldownUntil *time.Time `json:"cooldown_until,omitempty"`
	Reason        string     `json:"reason,omitempty"`
}

// ClustersFromPayload 从意图 payload 里读出聚类键(payload.cluster / payload.clusters)。
// 导出给 server 侧派发闸门复用。
func ClustersFromPayload(payload json.RawMessage) []string {
	if len(payload) == 0 {
		return nil
	}
	var p struct {
		Cluster  string   `json:"cluster"`
		Clusters []string `json:"clusters"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil
	}
	out := make([]string, 0, len(p.Clusters)+1)
	if c := strings.TrimSpace(p.Cluster); c != "" {
		out = append(out, c)
	}
	for _, c := range p.Clusters {
		if c = strings.TrimSpace(c); c != "" {
			out = append(out, c)
		}
	}
	return out
}

// ClusterCooldowns 返回本探索中仍在冷却期内的 cluster → 截止时间。
func (s *ExplorationStore) ClusterCooldowns() (map[string]time.Time, error) {
	out := map[string]time.Time{}
	if s == nil || s.db == nil {
		return out, nil
	}
	rows, err := s.db.Query(`
SELECT cluster, cooldown_until FROM cluster_cooldown
WHERE exploration_id=$1 AND cooldown_until IS NOT NULL AND cooldown_until > now()`, s.expID)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var c string
		var until time.Time
		if err := rows.Scan(&c, &until); err != nil {
			return out, err
		}
		out[c] = until
	}
	return out, rows.Err()
}

// ClusterRunningCounts 统计本探索中 running 意图在各 cluster 上的条数。
func (s *ExplorationStore) ClusterRunningCounts() (map[string]int, error) {
	out := map[string]int{}
	if s == nil || s.db == nil {
		return out, nil
	}
	rows, err := s.db.Query(`
SELECT payload FROM exploration_nodes
WHERE exploration_id=$1 AND kind='intent' AND state='running'`, s.expID)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return out, err
		}
		for _, c := range ClustersFromPayload(payload) {
			out[c]++
		}
	}
	return out, rows.Err()
}

// BumpClusterDead 对一组 cluster 各记一次失败;连续失败达到 threshold 时进入
// cooldown 冷却并清零计数。返回本次进入冷却的 cluster 列表。
func (s *ExplorationStore) BumpClusterDead(clusters []string, threshold int, cooldown time.Duration) ([]string, error) {
	cooled := []string{}
	if s == nil || s.db == nil || threshold <= 0 || len(clusters) == 0 {
		return cooled, nil
	}
	interval := intervalLiteral(cooldown)
	seen := map[string]bool{}
	for _, c := range clusters {
		c = strings.TrimSpace(c)
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		var dead int
		err := s.db.QueryRow(`
INSERT INTO cluster_cooldown(exploration_id, cluster, dead_count, updated_at)
VALUES ($1, $2, 1, now())
ON CONFLICT (exploration_id, cluster) DO UPDATE
SET dead_count = cluster_cooldown.dead_count + 1, updated_at = now()
RETURNING dead_count`, s.expID, c).Scan(&dead)
		if err != nil {
			return cooled, err
		}
		if dead < threshold {
			continue
		}
		if _, err := s.db.Exec(`
UPDATE cluster_cooldown
SET dead_count=0, cooldown_until=now() + $3::interval, reason=$4, updated_at=now()
WHERE exploration_id=$1 AND cluster=$2`,
			s.expID, c, interval, "同款聚类连续失败 "+strconv.Itoa(dead)+" 次,自动冷却"); err != nil {
			return cooled, err
		}
		cooled = append(cooled, c)
	}
	return cooled, nil
}

// ClusterCooldownRows 返回本探索的冷却表全量(供 graph_overview 展示)。
func (s *ExplorationStore) ClusterCooldownRows() ([]ClusterCooldownRow, error) {
	out := []ClusterCooldownRow{}
	if s == nil || s.db == nil {
		return out, nil
	}
	rows, err := s.db.Query(`
SELECT cluster, dead_count, cooldown_until, COALESCE(reason,'') FROM cluster_cooldown
WHERE exploration_id=$1 ORDER BY cooldown_until DESC NULLS LAST, dead_count DESC, cluster ASC`, s.expID)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var r ClusterCooldownRow
		if err := rows.Scan(&r.Cluster, &r.DeadCount, &r.CooldownUntil, &r.Reason); err != nil {
			return out, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// intervalLiteral 把时长转成 Postgres interval 字面量(整数秒,避免依赖驱动格式)。
func intervalLiteral(d time.Duration) string {
	if d <= 0 {
		d = time.Minute
	}
	return strconv.Itoa(int(d/time.Second)) + " seconds"
}

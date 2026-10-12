package db

import (
	"testing"
	"time"

	"github.com/Autumn-27/artex/dispatch"
)

// 同款聚类派发闸门:running 计数 + 连续失败冷却(需要 dev PG;无 DSN 时 skip)。
func TestClusterDispatchPolicy(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	expID, err := d.CreateExploration("test", "cluster dispatch")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM explorations WHERE id=$1`, expID)
	es := d.Exploration(expID)

	clusterA, clusterB := "a.com|portal", "b.com"
	aID, err := es.AddIntent(map[string]any{"summary": "a", "cluster": clusterA}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := es.AddIntent(map[string]any{"summary": "b", "clusters": []string{clusterB}}, 5, nil, "planner"); err != nil {
		t.Fatal(err)
	}
	if ok, err := es.ClaimIntent(aID, "w1"); err != nil || !ok {
		t.Fatalf("claim a: ok=%v err=%v", ok, err)
	}

	running, err := es.ClusterRunningCounts()
	if err != nil {
		t.Fatal(err)
	}
	if running[clusterA] != 1 {
		t.Fatalf("running[%s]=%d, want 1 (got %v)", clusterA, running[clusterA], running)
	}
	if running[clusterB] != 0 {
		t.Fatalf("running[%s]=%d, want 0", clusterB, running[clusterB])
	}

	// 未达阈值不冷却。
	for i := 1; i <= 2; i++ {
		cooled, err := es.BumpClusterDead([]string{clusterA}, 3, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if len(cooled) != 0 {
			t.Fatalf("第 %d 次失败不应冷却, got %v", i, cooled)
		}
	}
	// 第 3 次达阈值 → 冷却。
	cooled, err := es.BumpClusterDead([]string{clusterA}, 3, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(cooled) != 1 || cooled[0] != clusterA {
		t.Fatalf("第 3 次失败应冷却 %s, got %v", clusterA, cooled)
	}

	cooldowns, err := es.ClusterCooldowns()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cooldowns[clusterA]; !ok {
		t.Fatalf("%s 应处于冷却中, got %v", clusterA, cooldowns)
	}

	cfg := dispatch.Config{PendingLimit: 3, DeadThreshold: 3}
	now := time.Now()
	if v := dispatch.Evaluate([]string{clusterA}, cooldowns, running, cfg, now); !v.Skip {
		t.Fatalf("冷却中的 %s 应被闸门拦下", clusterA)
	}
	if v := dispatch.Evaluate([]string{clusterB}, cooldowns, running, cfg, now); v.Skip {
		t.Fatalf("未冷却的 %s 不应被拦下: %+v", clusterB, v)
	}

	// 并发上限:同簇 running 达 3 → 拦。
	limit := map[string]int{clusterB: 3}
	if v := dispatch.Evaluate([]string{clusterB}, nil, limit, cfg, now); !v.Skip {
		t.Fatalf("同簇 running 达上限应被拦下")
	}

	// 冷却行展示。
	rows, err := es.ClusterCooldownRows()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 || rows[0].Cluster != clusterA {
		t.Fatalf("冷却表应含 %s, got %+v", clusterA, rows)
	}
	if rows[0].CooldownUntil == nil || !rows[0].CooldownUntil.After(now) {
		t.Fatalf("冷却截止时间应晚于当前, got %+v", rows[0])
	}
}

package agent

import (
	"testing"

	"github.com/Autumn-27/artex/db"
)

// TestInsertAssetsPrefilterSkipsNoise 验证机械预筛把噪声/敏感域/平台默认域挡在入库之前，
// 并把跳过原因回给模型；同时验证保留项带上了评分与聚类键。
func TestInsertAssetsPrefilterSkipsNoise(t *testing.T) {
	d := testDB(t)
	defer d.Close()

	ts := NewToolSet(nil, "")
	ts.SetAssetStore(d.Assets(), d.Companies())
	defer d.Exec(`DELETE FROM assets WHERE domain IN ('screen-ok.prefilter-test.com') OR domain = 'foo.prefilter-test.github.io'`)

	out := callInsertAssets(t, ts, map[string]any{
		"assets": []any{
			map[string]any{"type": "subdomain", "domain": "localhost"},
			map[string]any{"type": "subdomain", "domain": "mail.abc.gov.cn"},
			map[string]any{"type": "subdomain", "domain": "foo.prefilter-test.github.io"},
			map[string]any{"type": "subdomain", "domain": "screen-ok.prefilter-test.com"},
		},
	})

	skipped, _ := out["skipped"].([]any)
	if len(skipped) != 3 {
		t.Fatalf("expected 3 skipped, got %d: %v", len(skipped), out)
	}
	results, _ := out["results"].([]any)
	if len(results) != 1 {
		t.Fatalf("expected 1 inserted, got %d: %v", len(results), results)
	}
	row, _ := results[0].(map[string]any)
	if row["cluster"] != "prefilter-test.com" {
		t.Errorf("expected cluster prefilter-test.com, got %v", row["cluster"])
	}
	// 保留的资产必须真的入库。
	var n int
	if err := d.QueryRow(`SELECT count(*) FROM assets WHERE domain = 'screen-ok.prefilter-test.com'`).Scan(&n); err != nil {
		t.Fatalf("query: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected asset persisted, got %d", n)
	}
}

// TestInsertAssetsScreeningDisabledByEnv 验证 ARTEX_SCREEN_DISABLE 关闭预筛后噪声也能入库。
func TestInsertAssetsScreeningDisabledByEnv(t *testing.T) {
	t.Setenv("ARTEX_SCREEN_DISABLE", "1")
	d := testDB(t)
	defer d.Close()

	ts := NewToolSet(nil, "")
	ts.SetAssetStore(d.Assets(), d.Companies())
	defer d.Exec(`DELETE FROM assets WHERE domain = 'screen-disabled.prefilter-test.com'`)

	out := callInsertAssets(t, ts, map[string]any{
		"assets": []any{
			map[string]any{"type": "subdomain", "domain": "screen-disabled.prefilter-test.com"},
		},
	})
	if _, ok := out["skipped"]; ok {
		t.Fatalf("screening disabled but got skipped: %v", out)
	}
	if results, _ := out["results"].([]any); len(results) != 1 {
		t.Fatalf("expected 1 inserted, got %v", out)
	}
}

// TestInsertAssetsAggressiveModeKeepsPlatformHosts 验证激进模式任务不做【丢弃性】预筛：
// 第三方托管平台默认域(github.io) 不再被 assetscreen 挡掉，而是照常入库。
//
// 注意：.gov.cn 这类内置拦截规则(资产闸门)是【硬底线】，激进模式也不豁免——
// 它由 intercept 层在预筛之前拦下并回 errors，与预筛是两道独立的闸。
func TestInsertAssetsAggressiveModeKeepsPlatformHosts(t *testing.T) {
	d := testDB(t)
	defer d.Close()

	task, err := d.CreateTaskWithOptions("aggressive screening", "verify aggressive keeps hosts", db.TaskCreateOptions{
		OpMode: db.OpModeAggressive,
	})
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	defer d.Exec(`DELETE FROM tasks WHERE id = $1`, task.ID)
	defer d.Exec(`DELETE FROM assets WHERE domain = 'foo.aggr-test.github.io'`)

	ts := NewToolSet(nil, "")
	ts.SetAssetStore(d.Assets(), d.Companies())
	ts.SetTaskID(task.ID)

	out := callInsertAssets(t, ts, map[string]any{
		"assets": []any{
			map[string]any{"type": "subdomain", "domain": "foo.aggr-test.github.io"},
		},
	})
	if _, ok := out["skipped"]; ok {
		t.Fatalf("aggressive mode must not run the drop-prefilter: %v", out)
	}
	results, _ := out["results"].([]any)
	if len(results) != 1 {
		t.Fatalf("expected 1 inserted, got %v", out)
	}
	var n int
	if err := d.QueryRow(`SELECT count(*) FROM assets WHERE domain = 'foo.aggr-test.github.io'`).Scan(&n); err != nil {
		t.Fatalf("query: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected platform host persisted in aggressive mode, got %d", n)
	}
}

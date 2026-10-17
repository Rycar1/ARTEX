package db

import (
	"fmt"
	"testing"
	"time"
)

// TestMaterializeCompanyScope 覆盖「声明范围 → 待测资产」物化层:
//   - 只物化可落成一条资产的规则(domain / 单主机 IP),网段与关键词不物化;
//   - 幂等:重复调用不会重复建行;
//   - RoE 门控:被全局/任务级拦截的规则不物化,但要记账(Remaining 能归零);
//   - 拦截规则解除后,规则重新回到待物化队列;
//   - batch 限制 + Remaining 递减。
func TestMaterializeCompanyScope(t *testing.T) {
	d, as, cs := testSetup(t)
	// 注意:t.Cleanup 后进先出 —— 先注册关闭,保证所有清理语句都在连接可用时执行。
	t.Cleanup(func() { d.Close() })

	stamp := time.Now().UnixNano()
	taskID := int64(900000000) + stamp%1000000000

	// 清掉上一次失败运行残留的测试资产(唯一索引会让「新建行数」不再是 4)。
	if _, err := d.Exec(`DELETE FROM assets WHERE domain LIKE 'mat-%.invalid'`); err != nil {
		t.Fatalf("预清理: %v", err)
	}

	companyID, _, err := cs.UpsertCompany(fmt.Sprintf("Materialize Co %d", stamp), "")
	if err != nil {
		t.Fatalf("UpsertCompany: %v", err)
	}
	t.Cleanup(func() {
		if _, err := d.Exec(`DELETE FROM assets WHERE task_ids @> ARRAY[$1]::bigint[]`, taskID); err != nil {
			t.Errorf("清理物化资产失败: %v", err)
		}
		if _, err := d.Exec(`DELETE FROM company_scope_materialize_skip WHERE task_id=$1`, taskID); err != nil {
			t.Errorf("清理跳过台账失败: %v", err)
		}
		if _, err := d.Exec(`DELETE FROM companies WHERE id=$1`, companyID); err != nil {
			t.Errorf("清理公司失败: %v", err)
		}
	})

	blockedDomain := fmt.Sprintf("mat-blocked-%d.invalid", stamp)
	d1 := fmt.Sprintf("mat-a-%d.invalid", stamp)
	d2 := fmt.Sprintf("mat-b-%d.invalid", stamp)
	ip1 := fmt.Sprintf("198.51.%d.%d", (stamp/256)%200+10, stamp%200+20)
	ip2 := fmt.Sprintf("198.51.%d.%d", (stamp/256)%200+10, stamp%200+21)

	// 全局拦截规则:被挡下的规则不物化。
	var ruleID int64
	if err := d.QueryRow(`INSERT INTO asset_intercept_rules(enabled,kind,pattern,note)
		VALUES (true,'exact_domain',$1,'materialize unit test') RETURNING id`, blockedDomain).Scan(&ruleID); err != nil {
		t.Fatalf("插入全局拦截规则: %v", err)
	}
	t.Cleanup(func() {
		if _, err := d.Exec(`DELETE FROM asset_intercept_rules WHERE id=$1`, ruleID); err != nil {
			t.Errorf("清理拦截规则失败: %v", err)
		}
	})

	rules := []ScopeInput{
		{Kind: "domain", Value: d1},
		{Kind: "domain", Value: d2},
		{Kind: "domain", Value: blockedDomain},
		{Kind: "ip", Value: ip1},
		{Kind: "ip", Value: ip2},
		{Kind: "cidr", Value: "198.51.100.0/24"},
		{Kind: "keyword", Value: fmt.Sprintf("matco-%d", stamp)},
	}
	if added, _, invalid, errs := cs.AddScopeInputs(companyID, rules, "unit test"); added != len(rules) || invalid != 0 || len(errs) != 0 {
		t.Fatalf("AddScopeInputs: added=%d invalid=%d errors=%v", added, invalid, errs)
	}

	// 可物化 = 3 domain + 2 ip(cidr /24 与 keyword 不物化)。
	pending, err := as.CountPendingCompanyScope(taskID, companyID)
	if err != nil {
		t.Fatalf("CountPendingCompanyScope: %v", err)
	}
	if pending != 5 {
		t.Fatalf("初始待物化 = %d, 期望 5", pending)
	}

	res, err := as.MaterializeCompanyScope(taskID, companyID, 100)
	if err != nil {
		t.Fatalf("MaterializeCompanyScope: %v", err)
	}
	if res.Rules != 4 {
		t.Fatalf("首次物化 rules=%d, 期望 4(2 domain + 2 ip)", res.Rules)
	}
	if res.Blocked != 1 {
		t.Fatalf("被拦截规则数 = %d, 期望 1", res.Blocked)
	}
	if res.Remaining != 0 {
		t.Fatalf("物化后剩余 = %d, 期望 0(被拦截的规则应记账而非永久挂起)", res.Remaining)
	}

	assertAsset := func(typ, key string, wantCompany int64) {
		t.Helper()
		var companyID *int64
		var source string
		var n int
		where := "domain=$1"
		if typ == "ip" {
			where = "ip=$1"
		}
		if err := d.QueryRow(`SELECT count(*) FROM assets WHERE type=$2 AND `+where+` AND task_ids @> ARRAY[$3]::bigint[]`,
			key, typ, taskID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Fatalf("%s %s 物化行数 = %d, 期望 1", typ, key, n)
		}
		if err := d.QueryRow(`SELECT company_id, company_source FROM assets WHERE type=$2 AND `+where+` AND task_ids @> ARRAY[$3]::bigint[]`,
			key, typ, taskID).Scan(&companyID, &source); err != nil {
			t.Fatal(err)
		}
		if companyID == nil || *companyID != wantCompany || source != "scope" {
			t.Fatalf("%s %s company=%v source=%q, 期望 %d/scope", typ, key, companyID, source, wantCompany)
		}
	}
	assertAsset("root_domain", d1, companyID)
	assertAsset("root_domain", d2, companyID)
	assertAsset("ip", ip1, companyID)
	assertAsset("ip", ip2, companyID)

	// 幂等:再跑一次什么都不新建。
	res2, err := as.MaterializeCompanyScope(taskID, companyID, 100)
	if err != nil {
		t.Fatalf("幂等物化: %v", err)
	}
	if res2.Rules != 0 || res2.Domains != 0 || res2.IPs != 0 || res2.Remaining != 0 {
		t.Fatalf("幂等物化 rules=%d domains=%d ips=%d remaining=%d, 期望全 0",
			res2.Rules, res2.Domains, res2.IPs, res2.Remaining)
	}

	// 解除拦截 → 被跳过的规则重新回到待物化队列。
	if _, err := d.Exec(`DELETE FROM asset_intercept_rules WHERE id=$1`, ruleID); err != nil {
		t.Fatal(err)
	}
	res3, err := as.MaterializeCompanyScope(taskID, companyID, 100)
	if err != nil {
		t.Fatalf("解除拦截后物化: %v", err)
	}
	if res3.Blocked != 0 || res3.Remaining != 0 {
		t.Fatalf("解除拦截后 blocked=%d remaining=%d, 期望 0/0", res3.Blocked, res3.Remaining)
	}
	assertAsset("root_domain", blockedDomain, companyID)
}

// TestMaterializeCompanyScopeBatch 校验 batch 上限与 Remaining 递减。
func TestMaterializeCompanyScopeBatch(t *testing.T) {
	d, as, cs := testSetup(t)
	t.Cleanup(func() { d.Close() })

	stamp := time.Now().UnixNano()
	taskID := int64(800000000) + stamp%1000000000

	companyID, _, err := cs.UpsertCompany(fmt.Sprintf("Materialize Batch Co %d", stamp), "")
	if err != nil {
		t.Fatalf("UpsertCompany: %v", err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM assets WHERE task_ids @> ARRAY[$1]::bigint[]`, taskID)
		_, _ = d.Exec(`DELETE FROM company_scope_materialize_skip WHERE task_id=$1`, taskID)
		_, _ = d.Exec(`DELETE FROM companies WHERE id=$1`, companyID)
	})

	var rules []ScopeInput
	for i := 0; i < 5; i++ {
		rules = append(rules, ScopeInput{Kind: "domain", Value: fmt.Sprintf("matbatch-%d-%d.invalid", stamp, i)})
	}
	if added, _, invalid, errs := cs.AddScopeInputs(companyID, rules, "unit test"); added != 5 || invalid != 0 || len(errs) != 0 {
		t.Fatalf("AddScopeInputs: added=%d invalid=%d errors=%v", added, invalid, errs)
	}

	res, err := as.MaterializeCompanyScope(taskID, companyID, 2)
	if err != nil {
		t.Fatalf("首批物化: %v", err)
	}
	if res.Domains != 2 || res.Remaining != 3 {
		t.Fatalf("首批 domains=%d remaining=%d, 期望 2/3", res.Domains, res.Remaining)
	}

	res, err = as.MaterializeCompanyScope(taskID, companyID, 2)
	if err != nil {
		t.Fatalf("第二批物化: %v", err)
	}
	if res.Domains != 2 || res.Remaining != 1 {
		t.Fatalf("第二批 domains=%d remaining=%d, 期望 2/1", res.Domains, res.Remaining)
	}

	res, err = as.MaterializeCompanyScope(taskID, companyID, 2)
	if err != nil {
		t.Fatalf("第三批物化: %v", err)
	}
	if res.Domains != 1 || res.Remaining != 0 {
		t.Fatalf("第三批 domains=%d remaining=%d, 期望 1/0", res.Domains, res.Remaining)
	}
}

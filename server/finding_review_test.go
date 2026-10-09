package server

import (
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestRuleReviewFindingIgnoresJunk(t *testing.T) {
	cases := []struct{ class, name string }{
		{"XSS", "登录处反射型XSS"},
		{"信息泄露", "phpinfo 页面"},
		{"信息泄露", "用户名枚举"},
		{"DoS", "拒绝服务"},
		{"其他", "短信轰炸"},
		{"其他", "钓鱼页面"},
	}
	for _, c := range cases {
		f := &db.DBFinding{VulnClass: c.class, Name: c.name}
		rev := ruleReviewFinding(f)
		if rev == nil || rev.Verdict != db.ReviewVerdictIgnored {
			t.Fatalf("%s/%s: 期望规则层 ignored,得到 %+v", c.class, c.name, rev)
		}
	}
}

func TestRuleReviewFindingPassesRealVuln(t *testing.T) {
	f := &db.DBFinding{VulnClass: "SQL注入", Name: "订单查询接口注入"}
	if rev := ruleReviewFinding(f); rev != nil {
		t.Fatalf("真实漏洞不该被规则层拦截: %+v", rev)
	}
}

func TestApplyReviewFallbackDeepensBlindRCE(t *testing.T) {
	f := &db.DBFinding{
		VulnClass: "RCE",
		Name:      "命令注入(时间盲)",
		Summary:   "疑似无回显命令执行,已观察到响应延时",
		Evidence:  "sleep 5 后响应时间 5.2s",
	}
	rev := &db.FindingReview{Verdict: db.ReviewVerdictIgnored, Reasons: "证据不足"}
	got := applyReviewFallback(f, rev, db.ReviewSrcEduSRC)
	if got.Verdict != db.ReviewVerdictDeepen {
		t.Fatalf("盲打 RCE 应转 deepen,得到 %q", got.Verdict)
	}
	if got.Reasons == "" {
		t.Fatal("deepen 必须写明深挖指引")
	}
}

func TestApplyReviewFallbackKeepsJunkIgnored(t *testing.T) {
	// 名称里带 RCE 关键字也不该救活反射型 XSS(never-deepen 优先)。
	f := &db.DBFinding{VulnClass: "XSS", Name: "反射型XSS", Evidence: "页面提到 RCE 命令执行 sleep( 延时"}
	rev := &db.FindingReview{Verdict: db.ReviewVerdictIgnored, Reasons: "反射型XSS"}
	if got := applyReviewFallback(f, rev, db.ReviewSrcEduSRC); got.Verdict != db.ReviewVerdictIgnored {
		t.Fatalf("反射型XSS 不该被兜底转 deepen,得到 %q", got.Verdict)
	}
}

func TestApplyReviewFallbackLeavesAcceptedAlone(t *testing.T) {
	f := &db.DBFinding{VulnClass: "RCE", Name: "命令注入", Evidence: "sleep 5 延时"}
	rev := &db.FindingReview{Verdict: db.ReviewVerdictAccepted}
	if got := applyReviewFallback(f, rev, db.ReviewSrcEduSRC); got.Verdict != db.ReviewVerdictAccepted {
		t.Fatalf("accepted 不该被兜底改动,得到 %q", got.Verdict)
	}
}

func TestApplyReviewFallbackNilSafe(t *testing.T) {
	if got := applyReviewFallback(&db.DBFinding{}, nil, db.ReviewSrcEduSRC); got != nil {
		t.Fatalf("nil 结论应原样返回 nil,得到 %+v", got)
	}
}

func TestParseReviewJSONDuplicateForcesIgnored(t *testing.T) {
	raw := `{"verdict":"accepted","severity":"high","is_duplicate":true,"reviewer_notes":"与 #12 重复"}`
	got, err := parseReviewJSON(raw, db.ReviewSrcEduSRC)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if got.Verdict != db.ReviewVerdictIgnored {
		t.Fatalf("is_duplicate=true 应强制 ignored,得到 %q", got.Verdict)
	}
	if got.Reasons == "" {
		t.Fatal("ignored 必须带原因")
	}
}

func TestParseReviewJSONOutOfScopeForcesIgnored(t *testing.T) {
	raw := `{"verdict":"accepted","in_scope":false,"reviewer_notes":"不在授权范围"}`
	got, err := parseReviewJSON(raw, db.ReviewSrcEduSRC)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if got.Verdict != db.ReviewVerdictIgnored {
		t.Fatalf("in_scope=false 应强制 ignored,得到 %q", got.Verdict)
	}
	if got.Reasons == "" {
		t.Fatal("ignored 必须带原因")
	}
}

func TestParseReviewJSONKeepsValidAccepted(t *testing.T) {
	raw := `{"verdict":"accepted","severity":"critical","score":9,"in_scope":true,"is_duplicate":false}`
	got, err := parseReviewJSON(raw, db.ReviewSrcEnterprise)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if got.Verdict != db.ReviewVerdictAccepted {
		t.Fatalf("合法 accepted 应保留,得到 %q", got.Verdict)
	}
	if got.Severity != "critical" {
		t.Fatalf("严重度应归一为 critical,得到 %q", got.Severity)
	}
}

func TestParseReviewJSONCapturesDuplicateTarget(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want int64
	}{
		{"数字", `{"verdict":"accepted","is_duplicate":true,"duplicate_of":12}`, 12},
		{"字符串", `{"verdict":"accepted","is_duplicate":true,"duplicate_of":"34"}`, 34},
		{"带前缀文本", `{"verdict":"accepted","is_duplicate":true,"duplicate_of":"finding #56"}`, 56},
		{"未指认", `{"verdict":"accepted","is_duplicate":true,"duplicate_of":""}`, 0},
	}
	for _, c := range cases {
		got, err := parseReviewJSON(c.raw, db.ReviewSrcEduSRC)
		if err != nil {
			t.Fatalf("%s: 解析失败: %v", c.name, err)
		}
		if got.Verdict != db.ReviewVerdictIgnored {
			t.Fatalf("%s: is_duplicate=true 应强制 ignored,得到 %q", c.name, got.Verdict)
		}
		if c.want == 0 {
			if got.DuplicateOf != nil {
				t.Fatalf("%s: 不该有重复目标,得到 %d", c.name, *got.DuplicateOf)
			}
			continue
		}
		if got.DuplicateOf == nil || *got.DuplicateOf != c.want {
			t.Fatalf("%s: 重复目标应为 %d,得到 %v", c.name, c.want, got.DuplicateOf)
		}
	}
}

func TestParseReviewJSONNotDuplicateHasNoTarget(t *testing.T) {
	got, err := parseReviewJSON(`{"verdict":"accepted","is_duplicate":false,"duplicate_of":""}`, db.ReviewSrcEnterprise)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if got.DuplicateOf != nil {
		t.Fatalf("非重复不该有目标: %d", *got.DuplicateOf)
	}
}

func TestApplyReviewFallbackKeepsDuplicateIgnored(t *testing.T) {
	dup := int64(9)
	f := &db.DBFinding{VulnClass: "RCE", Name: "命令注入", Evidence: "sleep 5 延时"}
	rev := &db.FindingReview{Verdict: db.ReviewVerdictIgnored, DuplicateOf: &dup}
	if got := applyReviewFallback(f, rev, db.ReviewSrcEduSRC); got.Verdict != db.ReviewVerdictIgnored {
		t.Fatalf("已判重复不该被兜底转 deepen,得到 %q", got.Verdict)
	}
}

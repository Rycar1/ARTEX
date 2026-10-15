package server

import (
	"encoding/json"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func fptr(v float64) *float64 { return &v }

// 审后确定性改判层(参考 AutoHunter 的 _maybe_* 系列):模型会摇摆的几类边界用
// 纯代码钉死。这些用例锁定四类改判的正反两个方向。
func TestPostReviewAdjust(t *testing.T) {
	s := &Server{}

	// ---- ① 轰炸/DoS:按操作者口径**算漏洞**,改判层不得把它们压成 ignored ----
	{
		for _, f := range []*db.DBFinding{
			{VulnClass: "短信轰炸", Name: "验证码接口无频率限制可对任意手机号连发", Severity: "medium"},
			{VulnClass: "邮箱轰炸", Name: "注册邮件发送无频率限制", Severity: "low"},
			{VulnClass: "拒绝服务", Name: "单请求资源耗尽致服务不可用", Severity: "high"},
		} {
			rev := &db.FindingReview{Verdict: db.ReviewVerdictAccepted, Severity: f.Severity, Score: fptr(5)}
			if s.postReviewAdjust(f, rev, db.ReviewSrcEduSRC) {
				t.Errorf("%q 已按操作者口径算漏洞,不应被改判", f.Name)
			}
			if rev.Verdict != db.ReviewVerdictAccepted {
				t.Errorf("%q 不应被改判 ignored, got %s", f.Name, rev.Verdict)
			}
		}
	}
	// 反向:短信 OTP 明文回显是有效漏洞,同样不能被误杀。
	{
		f := &db.DBFinding{
			VulnClass: "unauthorized_access", Name: "短信验证码明文回显致任意用户登录",
			Evidence: "发送验证码接口把发往手机的 OTP 明文写在响应里，用该 OTP 成功登录他人账号",
		}
		rev := &db.FindingReview{Verdict: db.ReviewVerdictAccepted, Severity: "high", Score: fptr(7)}
		if s.postReviewAdjust(f, rev, db.ReviewSrcEduSRC) {
			t.Fatalf("OTP 回显不应被改判, got %s", rev.Verdict)
		}
	}

	// ---- ② 假被黑:只有图床/CDN 外链 → 强制 ignored ----
	{
		f := &db.DBFinding{VulnClass: "backdoor", Name: "疑似被黑", Evidence: "首页引用外部图床与第三方 JS，有外链", Severity: "high"}
		rev := &db.FindingReview{Verdict: db.ReviewVerdictAccepted, Severity: "high", Score: fptr(8)}
		if !s.postReviewAdjust(f, rev, db.ReviewSrcEduSRC) {
			t.Fatal("图床冒充被黑应被改判")
		}
		if rev.Verdict != db.ReviewVerdictIgnored {
			t.Fatalf("应改判 ignored, got %s", rev.Verdict)
		}
	}
	// 反向:真有页面被替换/webshell 可执行 → 不改判。
	{
		f := &db.DBFinding{VulnClass: "backdoor", Name: "首页被篡改为赌博页面", Evidence: "首页正文被替换为 KentangBet 赌博页，原站内容消失", Severity: "high"}
		rev := &db.FindingReview{Verdict: db.ReviewVerdictAccepted, Severity: "high", Score: fptr(8)}
		if s.postReviewAdjust(f, rev, db.ReviewSrcEduSRC) {
			t.Fatal("有页面替换实锤不应改判")
		}
	}

	// ---- ③ 无害写证据齐全却被驳回 → 强制 accepted(反向纠偏) ----
	{
		f := &db.DBFinding{
			VulnClass: "unauthorized_access", Name: "未授权新增/修改/删除评论", Severity: "high",
			Evidence: "自建哨兵 SRC_TEST_a8f3 新增成功;修改后旁路 GET 读到新值;删除后再次查询已消失",
		}
		rev := &db.FindingReview{Verdict: db.ReviewVerdictIgnored, Reasons: "没有破坏真实数据"}
		if !s.postReviewAdjust(f, rev, db.ReviewSrcEduSRC) {
			t.Fatal("无害写证据齐全应被改判为 accepted")
		}
		if rev.Verdict != db.ReviewVerdictAccepted {
			t.Fatalf("应改判 accepted, got %s", rev.Verdict)
		}
		if rev.Score == nil || *rev.Score < 5.0 || *rev.Score > 7.4 {
			t.Fatalf("分值应落在 [5.0,7.4], got %v", rev.Score)
		}
	}
	// 幂等回写同样算强证据。
	{
		f := &db.DBFinding{
			VulnClass: "idor", Name: "越权修改配置", Severity: "medium",
			Evidence: `幂等回写原值,返回 {"affectedRows":1} 授权通过且值未变`,
		}
		rev := &db.FindingReview{Verdict: db.ReviewVerdictDeepen, DeepenDirective: "继续挖"}
		if !s.postReviewAdjust(f, rev, db.ReviewSrcEduSRC) || rev.Verdict != db.ReviewVerdictAccepted {
			t.Fatalf("幂等回写应从 deepen 改判 accepted, got %s", rev.Verdict)
		}
	}
	// 反向:没有无害证法、只有成功文案 → 不改判(交给 ignored/deepen 原判)。
	{
		f := &db.DBFinding{
			VulnClass: "unauthorized_access", Name: "未授权删除评论", Severity: "high",
			Evidence: `POST /api/delete → 200 {"code":200,"data":0,"msg":"操作成功"}`,
		}
		rev := &db.FindingReview{Verdict: db.ReviewVerdictIgnored}
		// 无可无害证法时不该被抬成 accepted;可能被 deepen(若线索够),但不能是 accepted。
		s.postReviewAdjust(f, rev, db.ReviewSrcEduSRC)
		if rev.Verdict == db.ReviewVerdictAccepted {
			t.Fatal("只有成功文案+零影响不应被改判 accepted")
		}
	}

	// ---- ④ 有价值的半成品被 ignored → 改判 deepen 并给定向指令 ----
	{
		f := &db.DBFinding{
			VulnClass: "info_disclosure", Name: "前端 JS 硬编码 appSecret",
			Evidence: "config.js 里硬编码 appSecret=xxx，接口 /api/user/info 走 sha1 签名鉴权",
		}
		rev := &db.FindingReview{Verdict: db.ReviewVerdictIgnored, Reasons: "仅发现 secret 未利用"}
		if !s.postReviewAdjust(f, rev, db.ReviewSrcEduSRC) {
			t.Fatal("真线索半成品应从 ignored 改判 deepen")
		}
		if rev.Verdict != db.ReviewVerdictDeepen {
			t.Fatalf("应改判 deepen, got %s", rev.Verdict)
		}
		if rev.DeepenDirective == "" {
			t.Fatal("deepen 必须带定向指令")
		}
		if rev.Score == nil || *rev.Score < 2.5 || *rev.Score > 3.9 {
			t.Fatalf("deepen 分值应落在 [2.5,3.9], got %v", rev.Score)
		}
	}
	// 盲打/无回显 RCE:有侧信道线索 → 回炉坐实,不当垃圾丢。
	{
		f := &db.DBFinding{
			VulnClass: "command_injection", Name: "疑似命令注入(无回显)",
			Evidence: "id 参数注入 sleep(5) 响应延迟稳定递增，时间盲特征明显",
		}
		rev := &db.FindingReview{Verdict: db.ReviewVerdictIgnored}
		if !s.postReviewAdjust(f, rev, db.ReviewSrcEduSRC) || rev.Verdict != db.ReviewVerdictDeepen {
			t.Fatalf("有侧信道的无回显 RCE 应回炉, got %s", rev.Verdict)
		}
		if rev.DeepenDirective == "" {
			t.Fatal("无回显 RCE 必须给坐实侧信道的定向指令")
		}
	}
	// 反向:明确不收的类型不回炉(反射XSS/phpinfo/公开接口/轰炸)。
	for _, f := range []*db.DBFinding{
		{VulnClass: "xss", Name: "反射型 XSS", Evidence: "参数回显 payload"},
		{VulnClass: "info", Name: "phpinfo 信息泄露", Evidence: "phpinfo 页面暴露路径"},
		{VulnClass: "unauthorized", Name: "公告接口未授权", Evidence: "公开接口，本就公开面向访客"},
		{VulnClass: "短信轰炸", Name: "短信轰炸", Evidence: "可连发短信"},
	} {
		rev := &db.FindingReview{Verdict: db.ReviewVerdictIgnored}
		s.postReviewAdjust(f, rev, db.ReviewSrcEduSRC)
		if rev.Verdict == db.ReviewVerdictDeepen {
			t.Errorf("%q 是明确不收类型,不应回炉(deepen)", f.Name)
		}
	}
	// 重复的不管证据多好都不回炉(避免去重挖一个已报过的洞)。
	{
		f := &db.DBFinding{VulnClass: "unauthorized_access", Name: "未授权写", Evidence: "未授权 modify 接口"}
		dup := int64(12)
		rev := &db.FindingReview{Verdict: db.ReviewVerdictIgnored, DuplicateOf: &dup}
		s.postReviewAdjust(f, rev, db.ReviewSrcEduSRC)
		if rev.Verdict == db.ReviewVerdictDeepen {
			t.Fatal("重复漏洞不应回炉")
		}
	}
	// worker 自检自认打不穿的不回炉。
	{
		sc, _ := json.Marshal(map[string]bool{"scanner_only_no_poc": true})
		f := &db.DBFinding{VulnClass: "sqli", Name: "疑似注入", Evidence: "nuclei 命中模板", SelfCheck: sc}
		rev := &db.FindingReview{Verdict: db.ReviewVerdictIgnored}
		s.postReviewAdjust(f, rev, db.ReviewSrcEduSRC)
		if rev.Verdict == db.ReviewVerdictDeepen {
			t.Fatal("worker 自认仅扫描器结果且非 RCE,不应回炉")
		}
	}
}

// parseReviewJSON 的三分类 + 自洽性硬约束(deepen 不得与重复/越界共存)。
func TestParseReviewJSONDeepen(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"正常 deepen", `{"verdict":"deepen","score":3,"in_scope":true,"is_duplicate":false,"deepen_directive":"用 appSecret 伪造签名调 /api/user/info 取出他人数据"}`, db.ReviewVerdictDeepen},
		{"deepen+重复 → ignored", `{"verdict":"deepen","is_duplicate":true,"duplicate_of":"12","deepen_directive":"继续"}`, db.ReviewVerdictIgnored},
		{"deepen+越界 → ignored", `{"verdict":"deepen","in_scope":false,"deepen_directive":"继续"}`, db.ReviewVerdictIgnored},
		{"正常 accepted", `{"verdict":"accepted","severity":"high","score":8,"in_scope":true,"is_duplicate":false}`, db.ReviewVerdictAccepted},
		{"accepted+越界 → ignored", `{"verdict":"accepted","severity":"high","in_scope":false}`, db.ReviewVerdictIgnored},
		{"正常 ignored", `{"verdict":"ignored","ignore_reasons":["无实际利用"]}`, db.ReviewVerdictIgnored},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rev, err := parseReviewJSON(tc.body, db.ReviewSrcEduSRC)
			if err != nil {
				t.Fatal(err)
			}
			if rev.Verdict != tc.want {
				t.Fatalf("verdict = %s, want %s", rev.Verdict, tc.want)
			}
		})
	}
	// deepen 必须能带出定向指令(回炉层要用它建意图)。
	rev, err := parseReviewJSON(`{"verdict":"deepen","deepen_directive":"去打 /api/export 拿数据"}`, db.ReviewSrcEduSRC)
	if err != nil {
		t.Fatal(err)
	}
	if rev.DeepenDirective != "去打 /api/export 拿数据" {
		t.Fatalf("deepen_directive 未解析出来: %q", rev.DeepenDirective)
	}
}

// 回归:looksLikeRCEText 曾用裸 strings.Contains,短标记 "rce" 命中 "source"/"force",
// 把一条 source map 纯信息暴露误判成「疑似盲打 RCE」并自动回炉。
func TestLooksLikeRCETextNeedsWordBoundary(t *testing.T) {
	// 不该命中的(含 "source"/"force"/"resource" 这类含 rce 子串的词)。
	for _, head := range []string{
		"信息泄露-源码泄露 source map 公开可读",
		"source_map_leak",
		"brute force 弱口令登录",
		"resource exhaustion",
	} {
		if looksLikeRCEText(head) {
			t.Errorf("%q 不应被判定为 RCE 一族(rce 子串误报)", head)
		}
	}
	// 该命中的。
	for _, head := range []string{
		"rce", "RCE 命令执行", "command_injection", "ssti 模板注入",
		"deserialization", "反序列化导致代码执行", "命令注入",
	} {
		if !looksLikeRCEText(head) {
			t.Errorf("%q 应被判定为 RCE 一族", head)
		}
	}
}

// 端到端:source map 纯信息暴露不得被改判 deepen(旧实现会因 rce/source 误报回炉)。
func TestSourceMapInfoLeakIsNotDeepened(t *testing.T) {
	s := &Server{}
	f := &db.DBFinding{
		VulnClass: "信息泄露-源码泄露",
		Name:      "信息泄露-源码泄露 https://x.example.com/static/js/main.75a4b3ad.js.map",
		Evidence:  "source map 可直接下载;响应时间稳定",
	}
	rev := &db.FindingReview{Verdict: db.ReviewVerdictIgnored}
	s.postReviewAdjust(f, rev, db.ReviewSrcEduSRC)
	if rev.Verdict == db.ReviewVerdictDeepen {
		t.Fatalf("source map 纯暴露不得因 rce 子串误报被回炉, directive=%q", rev.DeepenDirective)
	}
}

package server

import (
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

// 逃逸条件(unless)实测 —— 从规则表**自动生成**用例,规则改了测试自动跟上,不会漏。
//
// 每条带 unless 的规则都要验两个方向:
//   - 只有「名字命中规则」、没有任何打穿证据 → 必须被判 ignored(规则层该拦的拦住);
//   - 名字命中规则、但证据里出现逃逸标记 → 必须**返回 nil**(放行给 LLM 按证据判)。
//
// 这是防「规则层越权替模型拍死真洞」的核心保证,也是防「逃逸标记写太宽把垃圾放跑」
// 的回归网。
func TestEveryUnlessRuleEscapesOnEvidence(t *testing.T) {
	checked := 0
	for _, rule := range reviewJunkRules {
		if len(rule.unless) == 0 {
			continue // 无条件规则另有覆盖(见下)
		}
		key := rule.keys[0]
		src := db.ReviewSrcEduSRC
		checked++

		// A. 裸命中:没有任何打穿迹象 → 规则层必须拦下。
		bare := db.DBFinding{VulnClass: key, Name: key}
		got := ruleReviewFinding(&bare, src)
		if got == nil || got.Verdict != db.ReviewVerdictIgnored {
			t.Errorf("规则 %q 的裸命中应判 ignored, got %+v", key, got)
		}

		// B. 逐条验逃逸:每个 unless 标记都必须真的能把规则顶开。
		for _, esc := range rule.unless {
			f := db.DBFinding{
				VulnClass: key,
				Name:      key,
				// 逃逸证据写在 evidence(最贴近真实形态:标题是垃圾,证据里才有打穿事实)
				Evidence: "实测证据:" + esc,
			}
			if got := ruleReviewFinding(&f, src); got != nil {
				t.Errorf("规则 %q 的逃逸标记 %q 未生效(仍被规则层判 %s)", key, esc, got.Verdict)
			}
			// 企业标准下 eduOnly 规则本就不参与,这里只在 edusrc 下断言逃逸,
			// 避免把「规则不适用」误当「逃逸生效」。
		}
	}
	if checked == 0 {
		t.Fatal("没有扫到任何带 unless 的规则 —— 规则表结构可能已变,测试失效")
	}
	t.Logf("已逐条验证 %d 条条件规则的逃逸标记", checked)
}

// 无条件规则必须始终拦得住(它们没有逃逸口,验的是「别被误加逃逸」)。
func TestUnconditionalRulesAlwaysBlock(t *testing.T) {
	for _, rule := range reviewJunkRules {
		if len(rule.unless) > 0 || rule.eduOnly {
			continue
		}
		key := rule.keys[0]
		f := db.DBFinding{VulnClass: key, Name: key, Evidence: "随便写点证据"}
		got := ruleReviewFinding(&f, db.ReviewSrcEduSRC)
		if got == nil || got.Verdict != db.ReviewVerdictIgnored {
			t.Errorf("无条件规则 %q 应判 ignored, got %+v", key, got)
		}
	}
}

// 按操作者口径:短信/邮箱轰炸、DoS **算漏洞**,规则层不得无条件拦下,
// 改判层也不得把它们压成 ignored(见 finding_review_adjust_test.go)。
func TestBombingAndDoSAreCollectible(t *testing.T) {
	cases := []db.DBFinding{
		{VulnClass: "短信轰炸", Name: "发送验证码接口无频率限制可对任意手机号连发",
			Evidence: "连续 5 次 POST /api/sms/send 均 200 且目标收到短信,无验证码无频率限制"},
		{VulnClass: "邮箱轰炸", Name: "注册邮件发送无频率限制", Evidence: "对任意邮箱连发均成功"},
		{VulnClass: "拒绝服务", Name: "单请求触发资源耗尽致服务不可用",
			Evidence: "深层嵌套 JSON 单请求后服务 5xx 持续 30s,连接数打满"},
		{VulnClass: "DoS", Name: "压缩炸弹导致 CPU 打满", Evidence: "单个 zip 解压占满 CPU"},
	}
	for _, f := range cases {
		if got := ruleReviewFinding(&f, db.ReviewSrcEduSRC); got != nil {
			t.Errorf("%q 已按操作者口径算漏洞,规则层不应拦下: %s", f.Name, got.Reasons)
		}
	}
}

// infoLeak 类(响应头/版本/内部域名/source map)的逃逸:只在**证据文本**上判,
// 且证据里出现真实利用迹象时必须放行。
func TestInfoLeakRulesEscapeOnEvidence(t *testing.T) {
	// A. 纯暴露(证据里只有暴露事实)→ 规则层拦下。
	bare := []db.DBFinding{
		{VulnClass: "信息泄露（响应头泄露内网/节点 IP）", Name: "信息泄露（响应头泄露内网/节点 IP） a.example.com",
			Evidence: "响应头 X-Backend-Server: 10.213.0.5:8080"},
		{VulnClass: "信息泄露-源码泄露", Name: "信息泄露-源码泄露 https://x.example.com/main.75a4b3ad.js.map",
			Evidence: "source map 可直接下载"},
		{VulnClass: "信息泄露（EOL 组件精确版本）", Name: "信息泄露（EOL 组件精确版本） b.example.com",
			Evidence: "Server: nginx/1.16.1"},
	}
	for _, f := range bare {
		got := ruleReviewFinding(&f, db.ReviewSrcEduSRC)
		if got == nil || got.Verdict != db.ReviewVerdictIgnored {
			t.Errorf("纯信息暴露应判 ignored: %q -> %+v", f.Name, got)
		}
	}

	// B. 证据里打穿了 → 必须放行(不再是纯暴露,而是有利用链的真洞)。
	escaped := []db.DBFinding{
		{VulnClass: "信息泄露（响应头泄露内网 IP）", Name: "信息泄露（响应头泄露内网 IP） c.example.com",
			Evidence: "据该内网地址 SSRF 打通内网 Redis 未授权访问,写入公钥拿到登录"},
		{VulnClass: "信息泄露-源码泄露", Name: "信息泄露-源码泄露 https://y.example.com/main.js.map",
			Evidence: "从 source map 提取 appSecret 后伪造签名调通敏感接口,登录成功并拿到用户数据"},
		{VulnClass: "信息泄露-内部路径泄露", Name: "信息泄露-内部路径泄露 d.example.com",
			Evidence: "按泄露路径直接下载到数据库备份文件 backup_students.sql,含身份证号"},
	}
	for _, f := range escaped {
		if got := ruleReviewFinding(&f, db.ReviewSrcEduSRC); got != nil {
			t.Errorf("证据已打穿,应放行给 LLM: %q -> %s (%s)", f.Name, got.Verdict, got.Reasons)
		}
	}
}

// 短 ASCII 标记必须有词边界 —— 否则 "rce" 会命中 "source"(真机实测踩到过),
// 让纯信息暴露凭空触发逃逸被放跑。
func TestShortASCIIMarkersNeedWordBoundary(t *testing.T) {
	// "source map 可直接下载" 里的 source 含 "rce",不得被当成「RCE 已打通」的证据。
	f := db.DBFinding{
		VulnClass: "信息泄露-源码泄露",
		Name:      "信息泄露-源码泄露 https://z.example.com/static/js/main.75a4b3ad.js.map",
		Evidence:  "source map 可直接下载,资源文件可读",
	}
	if got := ruleReviewFinding(&f, db.ReviewSrcEduSRC); got == nil || got.Verdict != db.ReviewVerdictIgnored {
		t.Fatalf("source 里的 rce 不得触发逃逸,应仍判 ignored, got %+v", got)
	}
	// 真的写了 RCE 就该逃逸。
	f2 := db.DBFinding{
		VulnClass: "信息泄露（响应头泄露内网 IP）", Name: "信息泄露（响应头泄露内网 IP） e.example.com",
		Evidence: "据该内网地址打通内网服务并实现 RCE,命令回显 uid=0",
	}
	if got := ruleReviewFinding(&f2, db.ReviewSrcEduSRC); got != nil {
		t.Fatalf("证据含 RCE 应逃逸放行, got %s (%s)", got.Verdict, got.Reasons)
	}
	// 边界工具本身的直接断言。
	if agent.ContainsAnyFold("source map", []string{"rce"}) {
		t.Error("containsAnyFold: source 不应命中 rce")
	}
	if !agent.ContainsAnyFold("实现 RCE 命令执行", []string{"rce"}) {
		t.Error("containsAnyFold: 独立的 RCE 应命中")
	}
	if !agent.ContainsAnyFold("下载到 config.env 文件", []string{".env"}) {
		t.Error("containsAnyFold: .env 以非字母数字开头,应命中")
	}
	if agent.ContainsAnyFold("delivery model", []string{"del"}) {
		t.Error("containsAnyFold: del 不应命中 delivery")
	}
}

// CORS 逃逸:只有实证跨域窃取到敏感数据才放行。
func TestCORSEscape(t *testing.T) {
	// 只证明配置宽松 → ignored。
	bare := db.DBFinding{VulnClass: "CORS", Name: "任意 Origin 反射 + Allow-Credentials",
		Evidence: "ACAO 反射任意 Origin,Allow-Credentials: true"}
	if got := ruleReviewFinding(&bare, db.ReviewSrcEduSRC); got == nil || got.Verdict != db.ReviewVerdictIgnored {
		t.Fatalf("无 PoC 的 CORS 应 ignored, got %+v", got)
	}
	// 实证窃取到敏感数据 → 放行。
	for _, esc := range corsExploitProofMarkers {
		f := db.DBFinding{VulnClass: "CORS 配置不当", Name: "CORS 配置不当导致跨域读取用户数据",
			Evidence: "构造恶意页面" + esc + "受害者的手机号与身份证号"}
		if got := ruleReviewFinding(&f, db.ReviewSrcEduSRC); got != nil {
			t.Errorf("CORS 逃逸标记 %q 未生效: %s", esc, got.Reasons)
		}
	}
}

// eduOnly 规则(反射型XSS)必须分标准:edusrc 拦、enterprise 放行给 LLM。
func TestEduOnlyRulesRespectStandard(t *testing.T) {
	f := db.DBFinding{VulnClass: "反射型XSS", Name: "搜索参数反射型 XSS", Evidence: "q 参数原样回显"}
	if got := ruleReviewFinding(&f, db.ReviewSrcEduSRC); got == nil || got.Verdict != db.ReviewVerdictIgnored {
		t.Errorf("EduSRC 下反射型 XSS 应被规则层拦下, got %+v", got)
	}
	if got := ruleReviewFinding(&f, db.ReviewSrcEnterprise); got != nil {
		t.Errorf("企业标准下反射型 XSS 应交给 LLM 按影响判, got %s (%s)", got.Verdict, got.Reasons)
	}
	// 有影响证据时,EduSRC 下也必须放行。
	f2 := db.DBFinding{VulnClass: "反射型XSS", Name: "反射型 XSS 可窃取管理员会话",
		Evidence: "诱使管理员点击后成功窃取 session cookie 并接管后台"}
	if got := ruleReviewFinding(&f2, db.ReviewSrcEduSRC); got != nil {
		t.Errorf("有接管证据的反射型 XSS 应放行, got %s", got.Verdict)
	}
}

// 规则理由文本与行为必须自洽:reason 里写了例外的规则,必须真的带 unless,
// 否则就是「文档承诺了但代码做不到」(本次修掉的原始缺陷)。
func TestRuleReasonsMatchBehavior(t *testing.T) {
	for _, rule := range reviewJunkRules {
		reason := rule.reason
		claimsException := strings.Contains(reason, "除非") || strings.Contains(reason, "不含敏感") ||
			strings.Contains(reason, "无实际影响") || strings.Contains(reason, "仅")
		if claimsException && len(rule.unless) == 0 && !rule.eduOnly {
			t.Errorf("规则 %q 的理由文本声称有条件(%q),但没有 unless 逃逸 —— 代码无法执行该例外",
				rule.keys[0], reason)
		}
	}
}

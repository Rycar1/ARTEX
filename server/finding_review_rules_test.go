package server

import (
	"testing"

	"github.com/Autumn-27/artex/db"
)

// 生产实测回测:腾讯任务 651 条推送里 586 条(90%)是无利用影响的纯信息暴露噪音。
// 规则层必须把它们拦下(不再交给 LLM、更不该推送),同时**不能**误杀真漏洞 ——
// 真漏洞要继续走 LLM 复核(reviewFindingOnce 返回 nil 规则结论)。
func TestReviewJunkRulesCoverProductionNoise(t *testing.T) {
	// A. 生产上真实推送过的垃圾:必须被规则层判 ignored。
	junk := []db.DBFinding{
		{VulnClass: "信息泄露（响应头泄露内网/节点 IP）", Name: "信息泄露（响应头泄露内网/节点 IP） gamerobot.qq.com"},
		{VulnClass: "信息泄露（EOL 组件精确版本）", Name: "信息泄露（EOL 组件精确版本） https://qbquery.qq.com/"},
		{VulnClass: "info_leak_trpc_service_name", Name: "info_leak_trpc_service_name https://tetrack.qq.com/"},
		{VulnClass: "信息泄露（响应头泄露内网 IP）", Name: "信息泄露（响应头泄露内网 IP） https://cdn.rail.tgp.qq.com/"},
		{VulnClass: "信息泄露（内部开发者标识）", Name: "信息泄露（内部开发者标识） https://tafhttpproxy.mia.ai.qq.com/"},
		{VulnClass: "信息泄露-内部域名泄露", Name: "信息泄露-内部域名泄露 https://lizhi-assistant.testsite.woa.com"},
		{VulnClass: "信息泄露-源码泄露", Name: "信息泄露-源码泄露 https://xuanjing.qq.com/maat/static/js/main.75a4b3ad.js.map"},
		{VulnClass: "信息泄露（错误页泄露内部路径）", Name: "信息泄露（错误页泄露内部路径） https://fwcx.qq.com/x/doSe"},
		{VulnClass: "信息泄露（响应体回显内网 IP）", Name: "信息泄露（响应体回显内网 IP） https://ai-controller.mia.ai.qq.com/"},
		{VulnClass: "CORS", Name: "yybadaccesstest.3g.qq.com CORS 任意 Origin 反射 + Allow-Credentials"},
		{VulnClass: "", Name: "doc.tvi.v.qq.com 未知路由响应体回显内部 tRPC 服务名 open.private.weboffice.cgi"},
		{VulnClass: "", Name: "sso.e.qq.com 泄露 Spring Boot 内部应用上下文名与端口（x-application-context）"},
		{VulnClass: "", Name: "xui.ptlogin2.qq.com 登录壳泄露 API 网关精确版本 TAPISIX/2.2.2"},
		{VulnClass: "", Name: "EOL 组件精确版本泄露（boss2.b/iyuedu/android.bugly）"},
		{VulnClass: "", Name: "tRPC 内部服务名泄露（hstask.video.qq.com 新实例）"},
		{VulnClass: "", Name: "信息泄露（响应头泄露内网/节点 IP） sma.cache.qcloudcdn.qq.com"},
	}
	for _, f := range junk {
		got := ruleReviewFinding(&f)
		if got == nil {
			t.Errorf("生产噪音未被规则层拦下(会继续走 LLM 并可能推送): %q / %q", f.VulnClass, f.Name)
			continue
		}
		if got.Verdict != db.ReviewVerdictIgnored {
			t.Errorf("%q 应判 ignored, got %q", f.Name, got.Verdict)
		}
	}

	// B. 真漏洞必须放行给 LLM 复核(规则层只能拦垃圾,不能拦真洞)。
	real := []db.DBFinding{
		{VulnClass: "SQL注入", Name: "DVWA SQL Injection - 可 UNION 读取 users 表口令哈希"},
		{VulnClass: "命令注入", Name: "DVWA Command Injection - 可执行任意系统命令(RCE)"},
		{VulnClass: "文件上传", Name: "DVWA 文件上传绕过 - 上传 PHP webshell 并执行"},
		{VulnClass: "文件包含", Name: "DVWA LFI - 读取 /etc/passwd 与源码"},
		{VulnClass: "tRPC 反序列化", Name: "tRPC 服务反序列化导致远程代码执行"},
		{VulnClass: "越权", Name: "越权访问他人订单详情,可读取身份证号与手机号"},
		{VulnClass: "信息泄露", Name: "配置文件泄露导致数据库明文密码可登录生产库"},
		{VulnClass: "SSRF", Name: "SSRF 打通内网并读取云元数据凭证"},
		{VulnClass: "弱口令", Name: "后台弱口令 admin/123456 登录成功并可执行管理操作"},
	}
	for _, f := range real {
		if got := ruleReviewFinding(&f); got != nil {
			t.Errorf("真漏洞被规则层误杀(应交给 LLM 复核): %q / %q -> %s (%s)",
				f.VulnClass, f.Name, got.Verdict, got.Reasons)
		}
	}
}

// CORS 类:CORS/跨域标记本身在「类型+名称」上命中,但证据里写了真实跨域窃取数据时,
// 规则层必须放行给 LLM —— 不能因为标题里有 CORS 就一律判掉。
func TestCORSExploitedPassesRuleLayer(t *testing.T) {
	f := db.DBFinding{
		VulnClass: "CORS 配置不当",
		Name:      "CORS 配置不当导致跨域窃取用户数据",
		Summary:   "构造恶意页面成功跨域读取到受害者的手机号与身份证号",
		Evidence:  "已跨域读取到用户数据: {\"phone\":\"138****\"}",
	}
	if got := ruleReviewFinding(&f); got != nil {
		t.Fatalf("有真实跨域窃取证据的 CORS 应放行给 LLM, got %s (%s)", got.Verdict, got.Reasons)
	}
	// 无利用证据的 CORS 误配仍应被规则层判掉。
	bare := db.DBFinding{VulnClass: "CORS", Name: "任意 Origin 反射 + Allow-Credentials"}
	if got := ruleReviewFinding(&bare); got == nil || got.Verdict != db.ReviewVerdictIgnored {
		t.Fatalf("无 PoC 的 CORS 误配应判 ignored, got %+v", got)
	}
}

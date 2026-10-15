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
		got := ruleReviewFinding(&f, db.ReviewSrcEduSRC)
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
		if got := ruleReviewFinding(&f, db.ReviewSrcEduSRC); got != nil {
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
	if got := ruleReviewFinding(&f, db.ReviewSrcEduSRC); got != nil {
		t.Fatalf("有真实跨域窃取证据的 CORS 应放行给 LLM, got %s (%s)", got.Verdict, got.Reasons)
	}
	// 无利用证据的 CORS 误配仍应被规则层判掉。
	bare := db.DBFinding{VulnClass: "CORS", Name: "任意 Origin 反射 + Allow-Credentials"}
	if got := ruleReviewFinding(&bare, db.ReviewSrcEduSRC); got == nil || got.Verdict != db.ReviewVerdictIgnored {
		t.Fatalf("无 PoC 的 CORS 误配应判 ignored, got %+v", got)
	}
}

// 规则里的 unless 例外:理由文本写了条件的规则(「目录列表,不含敏感数据」
// 「反射型 XSS…除非能造成账号接管」),必须在证据里出现打穿迹象时**让路**给 LLM。
//
// 这是修一个真实缺陷:早期实现只做单关键词匹配,于是「目录列表泄露数据库备份」
// 「反射型 XSS 可接管账号」这类真洞会被规则层直接枪毙,连 evidence 都不看。
func TestReviewJunkRulesRespectUnlessExceptions(t *testing.T) {
	// A. 名字像垃圾 + 证据里出现打穿迹象 → 规则必须让路(返回 nil,交 LLM)。
	pass := []db.DBFinding{
		{
			VulnClass: "目录列表", Name: "目录列表暴露数据库备份文件",
			Evidence: "GET /files/ 索引列出 backup_students_20240311.sql,下载后含 8 名学生身份证号与密码哈希",
		},
		{
			VulnClass: "directory listing", Name: "Directory listing enabled",
			Summary: "索引可直接下载 config.inc.php.bak,内含数据库明文密码",
		},
		{
			VulnClass: "目录遍历", Name: "目录遍历可读取源码与 .git",
			Evidence: "读到 /files/.git/config 与 web.config,含数据库连接串与凭据",
		},
		{
			VulnClass: "反射型XSS", Name: "反射型 XSS 可窃取管理员会话",
			Evidence: "构造链接诱使管理员点击后成功窃取 session cookie 并接管后台",
		},
		{
			VulnClass: "内网IP泄露", Name: "响应头泄露内网 IP",
			Evidence: "据该内网地址 SSRF 打通内网 Redis 未授权访问,写入公钥拿到登录",
		},
		{
			VulnClass: "用户名枚举", Name: "登录接口用户名枚举",
			Evidence: "枚举出管理员账号后配合弱口令登录成功并接管后台",
		},
		{
			VulnClass: "公开接口", Name: "公告接口本就公开",
			Evidence: "同前缀 /api/user/list 未授权返回他人身份证号与密码哈希(批量)",
		},
	}
	for _, f := range pass {
		f := f
		if got := ruleReviewFinding(&f, db.ReviewSrcEduSRC); got != nil {
			t.Errorf("证据已打穿,规则层应让路给 LLM: %q / %q -> %s (%s)",
				f.VulnClass, f.Name, got.Verdict, got.Reasons)
		}
	}

	// B. 名字像垃圾且**没有任何**打穿迹象 → 规则层照旧零成本拦下。
	block := []db.DBFinding{
		{VulnClass: "目录列表", Name: "目录列表 /files/ 开启", Evidence: "GET /files/ 返回索引页,列出 notice.pdf 等公开文档"},
		{VulnClass: "反射型XSS", Name: "反射型 XSS(参数回显)", Evidence: "q 参数原样回显到页面"},
		{VulnClass: "phpinfo", Name: "phpinfo 信息泄露", Evidence: "phpinfo 页面可访问,暴露 PHP 版本与路径"},
		{VulnClass: "用户名枚举", Name: "用户名枚举", Evidence: "登录返回 1001 用户不存在 / 1002 密码错误"},
		{VulnClass: "内网IP泄露", Name: "响应头泄露内网 IP", Evidence: "X-Backend-Server: 10.213.0.5:8080"},
	}
	for _, f := range block {
		f := f
		got := ruleReviewFinding(&f, db.ReviewSrcEduSRC)
		if got == nil || got.Verdict != db.ReviewVerdictIgnored {
			t.Errorf("无打穿迹象的垃圾应被规则层判 ignored: %q / %q -> %+v", f.VulnClass, f.Name, got)
		}
	}
}

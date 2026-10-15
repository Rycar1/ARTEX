package agent

import "testing"

// 挖掘期提交闸门的核心正确性保证,分两半:
//
//	A. 该拦的必须拦下(否则垃圾照旧落库刷屏)
//	B. 不该拦的必须放行(闸门误杀真洞的代价远大于漏放一条垃圾 —— 垃圾还有审核兜底,
//	   真洞丢了就没了)
func TestFindingGateRejectsJunk(t *testing.T) {
	cases := []struct {
		name string
		in   FindingGateInput
		want string // 期望的拒收类别;"" = 放行
	}{
		// ---- 自检自认(worker 自己都填了 true) ----
		{"自检:反射XSS", FindingGateInput{
			VulnClass: "xss", Name: "反射型 XSS", Summary: "参数回显", Evidence: "payload 回显",
			SelfCheck: &FindingSelfCheck{IsReflectedXSS: true},
		}, GateSelfDeclaredIgnore},
		{"自检:需管理员后台", FindingGateInput{
			VulnClass: "csrf", Name: "后台 CSRF", Evidence: "需要管理员登录后触发",
			SelfCheck: &FindingSelfCheck{NeedsAdminLogin: true},
		}, GateSelfDeclaredIgnore},
		{"自检:需中间人", FindingGateInput{
			VulnClass: "mitm", Name: "中间人", Evidence: "需控制链路",
			SelfCheck: &FindingSelfCheck{NeedsMITM: true},
		}, GateSelfDeclaredIgnore},
		{"自检:纯信息泄露", FindingGateInput{
			VulnClass: "info", Name: "phpinfo 泄露", Evidence: "phpinfo 页面",
			SelfCheck: &FindingSelfCheck{IsPureInfoLeak: true},
		}, GatePureInfoLeakSelfDeclared},
		{"自检:公开接口", FindingGateInput{
			VulnClass: "unauthorized", Name: "公告接口未授权", Evidence: "匿名可读公告列表",
			SelfCheck: &FindingSelfCheck{IsPublicInterface: true},
		}, GatePublicInterface},
		{"自检:仅扫描器", FindingGateInput{
			VulnClass: "sqli", Name: "可能注入", Evidence: "nuclei 模板命中",
			SelfCheck: &FindingSelfCheck{ScannerOnlyNoPoc: true},
		}, GateScannerOnly},

		// ---- 生产实测的 7 类纯信息暴露(线上 90% 噪音) ----
		{"响应头泄露内网/节点 IP", FindingGateInput{
			VulnClass: "信息泄露（响应头泄露内网/节点 IP）", Name: "信息泄露（响应头泄露内网/节点 IP） gamerobot.qq.com",
			Evidence: "Content-Security-Policy 的 img-src 白名单明文暴露内网地址 http://9.130.160.194:9000",
		}, GateInfoExposure},
		{"EOL 组件精确版本", FindingGateInput{
			VulnClass: "信息泄露（EOL 组件精确版本）", Name: "信息泄露（EOL 组件精确版本） https://qbquery.qq.com/",
			Evidence: "响应头 Server: nginx/1.16.1 EOL",
		}, GateInfoExposure},
		{"tRPC 内部服务名泄露", FindingGateInput{
			VulnClass: "info_leak_trpc_service_name", Name: "info_leak_trpc_service_name https://tetrack.qq.com/",
			Evidence: "响应体回显内部 tRPC 服务名 open.private.weboffice.cgi",
		}, GateInfoExposure},
		{"内部域名泄露", FindingGateInput{
			VulnClass: "信息泄露-内部域名泄露", Name: "信息泄露-内部域名泄露 https://lizhi-assistant.testsite.woa.com",
			Evidence: "错误页泄露内部域名",
		}, GateInfoExposure},
		{"source map 公开可读", FindingGateInput{
			VulnClass: "信息泄露-源码泄露", Name: "信息泄露-源码泄露 https://xuanjing.qq.com/maat/static/js/main.75a4b3ad.js.map",
			Evidence: "source map 可直接下载",
		}, GateInfoExposure},
		{"内部开发者标识", FindingGateInput{
			VulnClass: "信息泄露（内部开发者标识）", Name: "信息泄露（内部开发者标识） https://tafhttpproxy.mia.ai.qq.com/",
			Evidence: "响应头带内部开发者标识",
		}, GateInfoExposure},
		{"内部路径泄露", FindingGateInput{
			VulnClass: "信息泄露（错误页泄露内部路径）", Name: "信息泄露（错误页泄露内部路径） https://fwcx.qq.com/x",
			Evidence: "报错页泄露 /data/app/... 内部路径",
		}, GateInfoExposure},

		// ---- 假被黑 ----
		{"图床冒充被黑", FindingGateInput{
			VulnClass: "backdoor", Name: "疑似被黑页面", Severity: "high",
			Evidence: "首页引用了外部图床与第三方 JS，存在外链",
		}, GateWeakBackdoor},

		// ---- 写接口零影响 ----
		{"写接口只有成功文案+零影响", FindingGateInput{
			VulnClass: "unauthorized_access", Name: "未授权删除他人评论", Severity: "high",
			Evidence: `POST /api/comment/delete {"id":123} → 200 {"code":200,"data":0,"msg":"操作成功"}`,
		}, GateWeakWrite},

		// ---- 只有扫描器输出 ----
		{"只有扫描器输出", FindingGateInput{
			VulnClass: "sqli", Name: "SQL 注入", Severity: "high",
			Evidence: "nuclei -t sqli.yaml 命中 sqli-error-based 模板，输出 [sqli] [http] ...",
		}, GateScannerOnly},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := CheckFindingGate(tc.in)
			if tc.want == "" {
				if got != nil {
					t.Fatalf("应放行却被拒收: kind=%s reason=%s", got.Kind, got.Reason)
				}
				return
			}
			if got == nil {
				t.Fatalf("应被拒收(kind=%s)却放行了", tc.want)
			}
			if got.Kind != tc.want {
				t.Fatalf("拒收类别 = %s, want %s(reason=%s)", got.Kind, tc.want, got.Reason)
			}
			// 拒收必须给可执行的下一步 —— 只说"不行"会让 worker 换个说法再撞一次。
			if got.Guidance == "" {
				t.Fatal("拒收必须给出 Guidance(怎么补证据/改走 record_fact)")
			}
		})
	}
}

// B:不该拦的必须放行。真洞被闸门误杀是不可接受的。
func TestFindingGatePassesRealVulns(t *testing.T) {
	cases := []struct {
		name string
		in   FindingGateInput
	}{
		{"SQL 注入脱库", FindingGateInput{
			VulnClass: "sql_injection", Name: "教务系统 SQL 注入可 UNION 拖库",
			Severity: "critical", Summary: "id 参数可 UNION 注入",
			Evidence: "GET /list?id=1' UNION SELECT username,password FROM users-- HTTP/1.1\nHost: t\n\nHTTP/1.1 200 OK\n...admin:$2y$10$...",
		}},
		{"上传 getshell", FindingGateInput{
			VulnClass: "file_upload", Name: "无限制文件上传导致 RCE", Severity: "critical",
			Evidence: "上传 shell.php 成功，访问 /uploads/shell.php?c=id 返回 uid=33(www-data)",
		}},
		{"水平越权读他人数据", FindingGateInput{
			VulnClass: "idor", Name: "越权读取他人订单详情", Severity: "high",
			Evidence: "换 orderId 即可读到他人订单，含身份证号与手机号:GET /api/order/8821 HTTP/1.1 → 200 {\"idcard\":\"...\"}",
		}},
		// 关键:写接口但**给出了无害证法**,必须放行(不能被 weakWriteGate 误杀)。
		{"未授权写+自建哨兵闭环", FindingGateInput{
			VulnClass: "unauthorized_access", Name: "未授权新增/修改/删除评论", Severity: "high",
			Evidence: "自建哨兵 SRC_TEST_a8f3 新增成功返回 id=991;修改该条后旁路 GET /api/comment/991 读到新值;删除该条后再次查询已消失(before→after 证据齐全)",
		}},
		{"未授权写+鉴权对照", FindingGateInput{
			VulnClass: "unauthorized_access", Name: "未授权修改他人资料", Severity: "high",
			Evidence: "未登录访问应 401;带普通用户 token 访问返回 200 授权通过;对照明显",
		}},
		{"未授权写+幂等回写", FindingGateInput{
			VulnClass: "idor", Name: "越权修改配置", Severity: "medium",
			Evidence: "幂等回写:先读现值再把同一个值写回,返回 affectedRows\":1 授权通过且值未变",
		}},
		// 关键:source map 但**翻出密钥并实际用起来了** → 不再是纯暴露。
		{"source map 翻出密钥并登录成功", FindingGateInput{
			VulnClass: "信息泄露-源码泄露", Name: "source map 泄露后台密钥并成功登录后台",
			Severity: "high",
			Evidence: "从 .js.map 提取到 admin appSecret，伪造签名调通 /api/admin/list 并成功登录后台拿到数据(session set-cookie 见响应)",
		}},
		// 关键:tRPC 但打成 RCE → 不能被 "trpc" 关键词误杀。
		{"tRPC 反序列化 RCE", FindingGateInput{
			VulnClass: "deserialization", Name: "tRPC 服务反序列化导致远程代码执行",
			Severity: "critical", Evidence: "构造 payload 后命令执行回显 uid=0(root)",
		}},
		{"存储型 XSS 上传到目标域", FindingGateInput{
			VulnClass: "xss", Name: "上传 HTML 到目标站自身域名形成存储型 XSS", Severity: "medium",
			Evidence: "上传 a.html 到 /uploads/，访问返回 Content-Type: text/html 原样返回，浏览器执行其中 JS",
		}},
		{"短信 OTP 明文回显", FindingGateInput{
			VulnClass: "unauthorized_access", Name: "短信验证码明文回显致任意用户登录", Severity: "high",
			Evidence: "发送验证码接口把发往手机的 OTP 明文写在响应里，用该 OTP 成功登录他人账号(Set-Cookie 见响应)",
		}},
		{"正常漏洞（无 self_check）", FindingGateInput{
			VulnClass: "ssrf", Name: "SSRF 打通内网并读取云元数据", Severity: "high",
			Evidence: "url 参数请求 169.254.169.254 返回临时凭证",
		}},
		// 操作者口径:短信/邮箱轰炸与 DoS **算漏洞**,闸门不得拒收。
		{"短信轰炸(可收录)", FindingGateInput{
			VulnClass: "短信轰炸", Name: "发送验证码接口无频率限制可对任意手机号连发", Severity: "medium",
			Evidence: "连续 5 次 POST /api/sms/send 均返回 200 且目标号码收到短信，无验证码无频率限制",
		}},
		{"邮箱轰炸(可收录)", FindingGateInput{
			VulnClass: "邮箱轰炸", Name: "注册接口邮件发送无频率限制", Severity: "low",
			Evidence: "对任意邮箱连续发送均成功",
		}},
		{"DoS/资源耗尽(可收录)", FindingGateInput{
			VulnClass: "拒绝服务", Name: "单个请求触发资源耗尽导致服务不可用", Severity: "high",
			Evidence: "构造深层嵌套 JSON 单请求后服务 5xx 持续 30s，连接数被打满",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CheckFindingGate(tc.in); got != nil {
				t.Fatalf("真洞被闸门误杀: kind=%s\nreason=%s\nguidance=%s", got.Kind, got.Reason, got.Guidance)
			}
		})
	}
}

// 拒收文本必须可读、含类别与下一步(模型要靠它当场修正)。
func TestGateToolErrorIsActionable(t *testing.T) {
	rej := &GateRejection{Kind: GateWeakWrite, Reason: "证据不足", Guidance: "改用无害证法", Retriable: true}
	got := GateToolError(rej)
	for _, want := range []string{GateWeakWrite, "证据不足", "无害证法", "下一步"} {
		if !containsAnyFold(got, []string{want}) {
			t.Fatalf("拒收文本缺少 %q: %s", want, got)
		}
	}
	if containsAnyFold(got, []string{"补证据也无法"}) {
		t.Fatal("Retriable=true 时不应出现「无法收录」的定论")
	}
	// 不可重试的类别要明确劝退,避免 worker 反复撞。
	hard := GateToolError(&GateRejection{Kind: GateBombing, Reason: "轰炸不收", Guidance: "别连发", Retriable: false})
	if !containsAnyFold(hard, []string{"无法"}) {
		t.Fatalf("Retriable=false 应明确说明补证据也无用: %s", hard)
	}
}

package agent

// ---------------------------------------------------------------------------
// 挖掘期提交闸门(参考 StanleyNull/AutoHunter 的 submit_finding 前置校验)。
//
// 为什么要有这一层:二次审核是**兜底**,不是主闸。垃圾洞在挖掘阶段就被报出来、
// 进了库、触发了推送,再去审核已经晚了一步 —— 线上实测 651 条 finding_created
// 里 586 条(90%)是「无利用影响的信息暴露」,全都要靠事后 ignored 才收场。
// AutoHunter 的做法是在 submit_finding 这个工具调用上**直接拒收**,并把「该怎么
// 补证据」一起返回给 worker,逼它当场改对。本文件把那套闸门移植过来。
//
// 三条设计纪律(抄 AutoHunter 的克制,别做成万能过滤器):
//  1. **只拦最明确的半成品**。拿不准一律放行给 reviewer 判 —— 闸门误杀真洞的
//     代价远大于漏放一条垃圾(垃圾还有 reviewer 兜底,真洞丢了就没了)。
//  2. **拒收不是丢**。拒收只表示「不能作为 finding 落库」,线索仍应走 record_fact
//     记为 inferred 事实,规划者能看到,不浪费这一轮的发现。
//  3. **拒收必须给可执行的下一步**。只说"不行"会让 worker 换个说法再撞一次;
//     要说清缺哪一步、怎么补(无害证法三条),或者明确让它改记 fact / 交棒。
// ---------------------------------------------------------------------------

import (
	"fmt"
	"regexp"
	"strings"
)

// FindingGateInput 是一条待提交 finding 的判定输入。字段与 report_finding 的
// 入参一一对应,外加 worker 的自检结果。
type FindingGateInput struct {
	VulnClass string
	Name      string
	Severity  string
	Summary   string
	Evidence  string
	// SelfCheck 是 worker 提交前的结构化自检。nil = 没填(旧调用/模型没给)。
	SelfCheck *FindingSelfCheck
	// SrcType 是任务的收录标准(edusrc | enterprise),决定启用哪些闸门。
	SrcType string
}

// GateRejection 是一次拒收:为什么拒、以及让 worker 怎么改。
type GateRejection struct {
	// Kind 是机器可读的拒收类别,写进工具返回与日志,便于统计哪类噪音最多。
	Kind string
	// Reason 是给模型看的原因(会作为 tool error 返回)。
	Reason string
	// Guidance 是可执行的下一步(怎么补证据 / 改走 record_fact / 交棒)。
	Guidance string
	// Retriable 为 true 表示补证据后可以重新提交同一漏洞;false 表示这类内容
	// 不该作为 finding 提交(应改 record_fact 或直接放弃)。
	Retriable bool
}

// 拒收类别。
const (
	// GateInfoExposure —— 无利用影响的信息暴露(线上占噪音 90%)。
	GateInfoExposure = "info_exposure"
	// GateScannerOnly —— 只有扫描器输出 / 无原始请求响应证据。
	GateScannerOnly = "scanner_only_no_poc"
	// GateWeakWrite —— 写/删/改接口只有成功文案、零影响,且无旁路证据。
	GateWeakWrite = "weak_write_evidence"
	// GateBombing —— 短信/邮箱轰炸(EduSRC 明确不收)。
	GateBombing = "edu_bombing"
	// GateWeakBackdoor —— 只是图床/CDN 外链就声称"被黑"。
	GateWeakBackdoor = "weak_backdoor"
	// GatePublicInterface —— worker 自检已承认该接口本就公开。
	GatePublicInterface = "public_interface"
	// GateSelfDeclaredIgnore —— worker 自检已承认命中忽略清单(反射XSS/需后台/需MITM)。
	GateSelfDeclaredIgnore = "self_declared_ignore"
	// GatePureInfoLeakSelfDeclared —— worker 自检已承认是无利用的信息泄露。
	GatePureInfoLeakSelfDeclared = "self_declared_pure_info_leak"
)

// ---------------------------------------------------------------------------
// 无害证法契约(等价于 AutoHunter 的 HARMLESS_PROTOCOL)
// ---------------------------------------------------------------------------

// HarmlessProofProtocol 是「证明写/删/改能力但绝不破坏真实数据」的三条无害证法。
// 与 server 侧审核规则层共用同一套口径:worker 拿它补证据,reviewer 拿它认证据。
const HarmlessProofProtocol = "请改用无害证法补证据(绝不删改真实/他人数据):" +
	"① 自建哨兵闭环 —— 新增一条带唯一标识的测试数据(如 SRC_TEST_<随机串> 的测试账号/评论/工单),成功回包含新 ID = 增权实锤;" +
	"改这条自建记录、旁路回读(列表/详情/再次查询)到新值 = 改权;删这条自建记录、旁路回读已消失 = 删权;用后自删、全程只碰自己刚建的对象;" +
	"② 鉴权对照 —— 未登录/不带 token 时应 401/403,带低权登录态应变为 200/授权通过,两相对照证明鉴权缺失;" +
	"③ 幂等回写 —— 只能碰已有对象时,先读现值再**把同一个值写回**,返回 affectedRows≥1 或授权通过且值未变,证明有写授权而数据未动。" +
	"三者都做不到就改用 record_fact 记一条 inferred 事实把线索交棒,禁止硬删真数据凑证据。"

// HarmlessProofMarkers 是识别「无害证法已给出」的正向特征(worker 与 reviewer 共用)。
var harmlessProofMarkers = []string{
	"src_test_", "哨兵", "自建测试", "幂等", "写回原值", "原值写回", "同一值", "值未变",
	"before", "after", "前后对比", "状态变化", "旁路", "再次查询", "修改后查询", "删除后查询",
	"未登录", "无cookie", "无 cookie", "不带token", "不带 token", "不带授权", "对照", "对比", "匿名",
}

// zeroEffectEvidence 是「写了等于没写」的强特征:出现它且没有任何无害证法 → 半成品。
var zeroEffectEvidence = []*regexp.Regexp{
	regexp.MustCompile(`(?i)"data"\s*:\s*0\b`),
	regexp.MustCompile(`(?i)"affected(?:rows)?"\s*:\s*0\b`),
	regexp.MustCompile(`(?i)"row(?:s|count)?"\s*:\s*0\b`),
	regexp.MustCompile(`(?i)"count"\s*:\s*0\b`),
	regexp.MustCompile(`(?i)\b0\s+rows?\b`),
	regexp.MustCompile(`影响\s*0`),
	regexp.MustCompile(`0\s*行`),
	regexp.MustCompile(`不存在`),
	regexp.MustCompile(`未实证`),
	regexp.MustCompile(`未证明`),
}

// writeSemanticMarkers 判断这条 finding 是不是「写/删/改」类语义。
// 刻意不用裸 "del":会误伤 delivery / model 等词。
var writeSemanticMarkers = []string{
	"updatedel", "delete", "remove", "update", "modify", "edit", "save",
	"insert", "create", "删除", "修改", "更新", "写操作", "新增", "重置密码",
}

// writeTypeMarkers 判断漏洞类型是否属于「未授权/越权」这一族。
var writeTypeMarkers = []string{"unauthorized", "idor", "auth", "access", "越权", "未授权"}

// scannerOnlyMarkers 是「只有扫描器输出、没有真实请求响应」的特征。
var scannerOnlyMarkers = []string{
	"nuclei", "sqlmap", "nmap -s", "nessus", "awvs", "xray", "goby", "扫描器",
	"scanner output", "template matched", "批量扫描", "扫描结果",
}

// realRequestMarkers 是「有原始请求/响应证据」的正向特征。命中即认为证据扎实,
// 不再因"像扫描器输出"而拒收。
var realRequestMarkers = []string{
	"http/1.", "http/2", "curl ", "请求包", "响应包", "raw_request", "raw_response",
	"response:", "status:", "get /", "post /", "set-cookie", "content-type",
}

// ---------------------------------------------------------------------------
// 闸门主体
// ---------------------------------------------------------------------------

// CheckFindingGate 在 report_finding 落库前判定一条提交要不要拒收。
// 返回 nil = 放行(reviewer 继续按证据判);非 nil = 拒收,调用方**不要落库**,
// 把 Reason+Guidance 作为工具错误返回给模型。
//
// 判定顺序按「拒收理由最明确 → 最需要补证据」排列:自检自认的垃圾先拦(worker
// 自己都承认了),再拦轰炸/假被黑这类硬性不收的,最后拦需要补证据的两类。
func CheckFindingGate(in FindingGateInput) *GateRejection {
	head := strings.ToLower(strings.TrimSpace(in.VulnClass + " " + in.Name))
	body := strings.ToLower(strings.Join([]string{in.VulnClass, in.Name, in.Summary, in.Evidence}, "\n"))

	// ① worker 自检自认命中忽略清单 —— 它自己都填了 true,没什么可争的。
	if sc := in.SelfCheck; sc != nil {
		if sc.IsReflectedXSS || sc.NeedsAdminLogin || sc.NeedsMITM {
			return &GateRejection{
				Kind: GateSelfDeclaredIgnore,
				Reason: "你提交时自检已标记该漏洞命中忽略清单(反射型 XSS / 需管理员后台才能触发 / 需中间人攻击)。" +
					"这类在 EduSRC 与主流 SRC 均不予收录,不应作为 finding 提交。",
				Guidance:  "这条不落库。若它只是某个更强漏洞的线索,改用 record_fact 记一条 inferred 事实(写清'由它可能通向什么')交给规划者;否则直接放弃,把轮次留给真正可交付的目标。",
				Retriable: false,
			}
		}
		if sc.IsPureInfoLeak {
			return &GateRejection{
				Kind: GatePureInfoLeakSelfDeclared,
				Reason: "你提交时自检已标记这是「无实际利用的信息泄露」。纯信息暴露(phpinfo/内网IP/版本号/内部域名等)" +
					"只证明某个信息被看见,没有任何越权或数据获取,不予收录。",
				Guidance:  "要么把它打穿成有效危害(读到死规矩敏感数据:身份证照片/人脸照片/身份证号/密码哈希;或拿到可用凭证/getshell/敏感写操作)后重新提交,要么改用 record_fact 记 inferred 交棒。",
				Retriable: true,
			}
		}
		if sc.IsPublicInterface {
			return &GateRejection{
				Kind: GatePublicInterface,
				Reason: "你提交时自检已标记该接口本就是面向公众的公开接口。访问公开接口不构成漏洞 —— " +
					"既不是信息泄露(数据通常不敏感),也不是未授权访问(本就该公开)。",
				Guidance:  "不要提交这一类。若你发现的是「同前缀下本该鉴权却被匿名访问」的具体接口,那是另一条 finding:请先排除公开接口,再带越权/受限资源的请求+响应实证重新提交。",
				Retriable: false,
			}
		}
		if sc.ScannerOnlyNoPoc {
			return &GateRejection{
				Kind:      GateScannerOnly,
				Reason:    "你提交时自检已标记「只有扫描器结果、给不出利用方法」。扫描器输出不是漏洞,必须回到真实请求证明可控性与影响。",
				Guidance:  "用 http_request / curl 构造最小验证请求,拿到原始请求+响应(证明实际读到了什么/改动了什么)后再提交;确认打不穿就改用 record_fact 记 inferred 交棒。",
				Retriable: true,
			}
		}
	}

	// ② 无利用影响的信息暴露 —— 线上 90% 的噪音都在这一类。
	if r := infoExposureGate(head, body, in.SrcType); r != nil {
		return r
	}

	// ③ 短信/邮箱轰炸(EduSRC 明确不收;不许 worker 为了取证去连发)。
	if isEduSrc(in.SrcType) && isBombing(head, body) {
		return &GateRejection{
			Kind:      GateBombing,
			Reason:    "这是短信/邮箱轰炸类(发送验证码或通知的接口无频率限制,只能对手机号/邮箱连发)。EduSRC 明确不予收录。",
			Guidance:  "不要提交,也不要为了取证真去连发。注意区分:若同一接口把**发往手机的短信验证码**明文回显在响应里、并能打通任意用户登录或改密,那才是有效漏洞(按 OTP 回显提交,不要写成轰炸)。",
			Retriable: false,
		}
	}

	// ④ 只是图床/CDN 外链就声称「服务器被黑」。
	if isWeakBackdoor(head, body) {
		return &GateRejection{
			Kind: GateWeakBackdoor,
			Reason: "疑似被黑类要求「本站自身页面被攻陷」的实锤(首页/栏目正文被替换成赌博色情彩票、hacked by/deface、webshell 可执行)。" +
				"当前证据只是引用了图床/CDN/OSS/第三方 JS 等外部资源,原站内容仍正常,不构成被黑。",
			Guidance:  "不要作为 backdoor/被黑类提交。若确实在响应里看到了被篡改的恶意正文,请把那段原文放进 evidence 重新提交;否则放弃或记为普通 fact。",
			Retriable: true,
		}
	}

	// ⑤ 写/删/改接口:只有成功文案 + 零影响,且没有任何无害证法 → 半成品。
	if r := weakWriteGate(head, body, in.SrcType); r != nil {
		return r
	}

	// ⑥ 只有扫描器输出、没有任何真实请求响应特征的提交。
	if r := scannerOnlyGate(body); r != nil {
		return r
	}

	return nil
}

// infoExposureGate 拦「无利用影响的信息暴露」。
//
// 判定要求「信息暴露形态词」与「具体噪音标记」**同时**命中 —— 单靠 trpc /
// source map 这类词会把「tRPC 反序列化 RCE」「source map 里翻出后台密钥」一起误杀。
// 同一套标记与 server 侧审核规则层共用口径(server/finding_review.go)。
func infoExposureGate(head, body, srcType string) *GateRejection {
	if !containsAnyFold(head, InfoLeakShapeMarkers) {
		return nil
	}
	for _, rule := range InfoLeakJunkRules {
		if !containsAnyFold(head, rule.Keys) {
			continue
		}
		// 反向保护:证据里已出现「实际利用」的痕迹就放行给 reviewer —— 例如
		// source map 里翻出密钥并且登录成功了,那就不再是纯暴露。
		if containsAnyFold(body, infoExposureExploitMarkers) {
			return nil
		}
		return &GateRejection{
			Kind: GateInfoExposure,
			Reason: "这是无利用影响的信息暴露(" + rule.Reason + ")。" +
				"它只证明某个内部信息被看见,没有任何越权、系统控制或数据获取,不予收录。",
			Guidance: "两条路:① 把它打穿 —— 用泄露的密钥/版本/路径实际拿到受限数据、可用凭证或 getshell 后再提交;② 打不穿就用 record_fact 记一条 inferred 事实把线索交给规划者。" +
				"不要原样再提交一次(换个标题也不行)。",
			Retriable: true,
		}
	}
	// 同时命中形态词 + 内网/节点 IP 这类(与旧规则口径一致的兜底)。
	if containsAnyFold(head, []string{"内网ip", "私网ip", "内网地址"}) {
		return &GateRejection{
			Kind:      GateInfoExposure,
			Reason:    "内网 IP / 私网地址泄露属于无利用影响的信息暴露,不予收录。",
			Guidance:  "要打穿成有效危害(借它访问到实际受限资源、或以它为基础打通了其它系统)再提交;否则改用 record_fact 记 inferred 交棒。",
			Retriable: true,
		}
	}
	return nil
}

// infoExposureExploitMarkers 是「已把信息暴露打成实际危害」的正向特征。
// 命中即放行:此时它不再是纯暴露,而是有利用链的真洞。
var infoExposureExploitMarkers = []string{
	"窃取到", "窃取成功", "成功读取", "读取到用户", "读取到受害者", "读取到个人信息",
	"登录成功", "getshell", "命令执行", "拿到凭据", "可用凭证", "接管", "越权",
	"set-cookie", "伪造签名调通", "实际盗刷", "脱库", "dump",
}

// weakWriteGate 拦「写/删/改接口只有成功文案 + 零影响」的半成品。
//
// 只拦最明确的一种:命中零影响特征(或"不存在/未实证/未证明")、且**没有**任何
// 无害证法痕迹。有任何一条无害证法就放行 —— 那是实锤,只是形式与"破坏了真数据"
// 不同,不能因此驳回(AutoHunter 的 _maybe_accept_write_proof 就是为纠这个)。
func weakWriteGate(head, body, srcType string) *GateRejection {
	if !isWriteSemantic(head, body) {
		return nil
	}
	if containsAnyFold(body, harmlessProofMarkers) {
		return nil // 无害证法已给出 → 放行
	}
	if !hasZeroEffect(body) {
		return nil // 没有"零影响"特征 → 证据是否够由 reviewer 判,闸门不越权
	}
	return &GateRejection{
		Kind: GateWeakWrite,
		Reason: "写/删/改类接口的证据不足:当前只有成功文案(或 data:0 / affectedRows:0 / 对象不存在)," +
			"不能证明具备写授权,也无法证明产生了真实影响。",
		Guidance:  HarmlessProofProtocol,
		Retriable: true,
	}
}

// scannerOnlyGate 拦「只贴了扫描器输出、没有任何真实请求响应」的提交。
func scannerOnlyGate(body string) *GateRejection {
	if !containsAnyFold(body, scannerOnlyMarkers) {
		return nil
	}
	if containsAnyFold(body, realRequestMarkers) {
		return nil // 有真实请求/响应特征 → 放行给 reviewer
	}
	return &GateRejection{
		Kind:   GateScannerOnly,
		Reason: "证据里只有扫描器输出,没有原始请求/响应。扫描器结果不是漏洞 —— 它只能提示可疑点,不能证明真实影响。",
		Guidance: "用 http_request / curl 对可疑点构造最小验证请求,把原始请求包 + 响应包(或命令回显)写进 evidence 后重新提交;" +
			"确认打不穿就改用 record_fact 记一条 inferred 事实(写清嫌疑点与为何未触发)交棒。",
		Retriable: true,
	}
}

// isWriteSemantic 判断是否「未授权/越权」族 + 写删改语义。
func isWriteSemantic(head, body string) bool {
	if !containsAnyFold(head, writeTypeMarkers) {
		return false
	}
	return containsAnyFold(body, writeSemanticMarkers)
}

// hasZeroEffect 判断证据里是否出现「写了等于没写」的强特征。
func hasZeroEffect(body string) bool {
	for _, re := range zeroEffectEvidence {
		if re.MatchString(body) {
			return true
		}
	}
	return false
}

// isBombing 判断是否短信/邮箱轰炸。
func isBombing(head, body string) bool {
	blob := head + "\n" + body
	return containsAnyFold(blob, []string{
		"短信轰炸", "邮箱轰炸", "邮件轰炸", "验证码轰炸", "短信炸弹", "sms bomb", "email bomb",
		"轰炸",
	})
}

// isWeakBackdoor 判断"疑似被黑"证据是否只是外链/图床。
func isWeakBackdoor(head, body string) bool {
	claims := []string{"被黑", "被攻陷", "deface", "hacked by", "后门", "赌博", "色情", "暗链", "blackdoor", "webshell"}
	if !containsAnyFold(head+body, claims) {
		return false
	}
	// 有 webshell 可执行 / 页面被替换的实锤 → 不算弱证据。
	if containsAnyFold(body, []string{"webshell 可执行", "命令回显", "uid=", "whoami", "hacked by", "deface"}) {
		return false
	}
	weak := []string{"图床", "oss", "cdn", "七牛", "又拍云", "imgur", "jsdelivr", "外部图片", "外链", "第三方 js", "第三方统计"}
	return containsAnyFold(body, weak)
}

func isEduSrc(srcType string) bool {
	return !strings.EqualFold(strings.TrimSpace(srcType), "enterprise")
}

// ---------------------------------------------------------------------------
// 与 server 侧审核规则层共用的标记表(单一事实源,避免两边漂移)
// ---------------------------------------------------------------------------

// InfoLeakJunkRule 是一条「纯信息暴露」噪音规则:同时命中 Keys 与 Shapes 才判定。
type InfoLeakJunkRule struct {
	Keys   []string
	Reason string
}

// InfoLeakShapeMarkers 判断一条 finding 是否属于「纯信息暴露形态」。
// 必须与具体标记**同时**命中才判噪音,否则会误杀 trpc RCE / source map 取密钥这类真洞。
var InfoLeakShapeMarkers = []string{
	"信息泄露", "信息泄漏", "info_leak", "info leak", "information disclosure",
	"泄露", "泄漏", "暴露", "disclosure",
	// 「响应体回显内部 X」这类没有「泄露」字样的写法也属于纯暴露形态(生产实测出现)。
	"回显内部", "回显内网", "回显节点",
}

// InfoLeakJunkRules 是「纯信息暴露」类噪音清单,来自 ARTEX 线上真实推送数据:
// 651 条 finding_created 里 586 条(90%)属于这七类,共同点是「只证明某个内部信息
// 被看见」,没有任何越权/控制/数据获取。
var InfoLeakJunkRules = []InfoLeakJunkRule{
	{Keys: []string{"响应头泄露", "响应体回显", "响应头内网", "节点 ip", "节点ip", "回显内网", "回显内部", "内网/节点"},
		Reason: "响应头/响应体泄露内网 IP 或节点信息"},
	{Keys: []string{"eol 组件", "组件精确版本", "精确版本泄露", "网关精确版本", "组件版本泄露", "版本指纹"},
		Reason: "EOL/组件精确版本指纹泄露"},
	{Keys: []string{"trpc", "服务名泄露", "内部服务名", "内部应用上下文", "x-application-context"},
		Reason: "内部服务名/应用上下文泄露"},
	{Keys: []string{"内部域名泄露", "内部路径泄露", "泄露内部路径", "内部开发者标识", "开发者标识"},
		Reason: "内部域名/路径/开发者标识泄露"},
	{Keys: []string{"source map", "sourcemap", ".js.map", "source-map"},
		Reason: "source map 公开可读"},
}

// IsWriteFindingText 判断「类型/名称 + 全文」是否属于写/删/改类漏洞。
// 导出给 server 侧审核改判层复用,保证「worker 按闸门指引补的证据,审核一定认」——
// 两边口径漂移会让 worker 白忙一轮。
func IsWriteFindingText(head, body string) bool {
	return isWriteSemantic(head, body)
}

// ContainsAnyFold 报告 s 是否包含 keywords 中任一关键词(大小写不敏感)。
// 导出以便 server 侧审核改判层复用同一套匹配语义 —— 两侧口径漂移会让
// 「worker 按闸门指引补的证据」在审核层认不出来。
func ContainsAnyFold(s string, keywords []string) bool {
	return containsAnyFold(s, keywords)
}

// containsAnyFold 报告 s 是否包含 keywords 中任一关键词(大小写不敏感)。
func containsAnyFold(s string, keywords []string) bool {
	lower := strings.ToLower(s)
	for _, kw := range keywords {
		kw = strings.ToLower(strings.TrimSpace(kw))
		if kw != "" && strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// GateToolError 把一次拒收渲染成工具错误的文本(模型直接看到这段)。
// 格式对齐 AutoHunter 的 submit_finding 返回:说清 kind、为什么、下一步怎么改。
func GateToolError(r *GateRejection) string {
	if r == nil {
		return ""
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "拒收(%s):%s\n下一步:%s", r.Kind, r.Reason, r.Guidance)
	if !r.Retriable {
		sb.WriteString("\n(这类内容补证据也无法作为 finding 收录,请改记 fact 或转其它目标。)")
	}
	return sb.String()
}

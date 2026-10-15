package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

// parseSelfCheck 解析 finding 里原样保存的 worker 自检 JSON。解析不出返回 nil
// (旧数据/空值),调用方按「未填」处理,不因此拒收或改判。
func parseSelfCheck(raw json.RawMessage) *agent.FindingSelfCheck {
	if len(raw) == 0 {
		return nil
	}
	var sc agent.FindingSelfCheck
	if err := json.Unmarshal(raw, &sc); err != nil {
		return nil
	}
	return &sc
}

// ---------------------------------------------------------------------------
// 审核结论的**确定性改判层**(参考 StanleyNull/AutoHunter 的 _maybe_* 系列)。
//
// 为什么 LLM 判完还要加一层纯代码改判:审核模型会摇摆 —— 同一类 CORS 一会儿
// accepted 一会儿 ignored,无回显 RCE 容易被当垃圾丢,而「无害写证据已经齐了」的
// 真洞又可能因为「没破坏真实数据」被驳回。模型判完再套一层确定性规则,把这几类
// 反复出错的边界钉死,比反复调提示词可靠。
//
// AutoHunter 有四个这样的函数,这里对应实现:
//   - maybeRejectEduBombing   —— 轰炸类 LLM 误收 → 强制 ignored
//   - maybeRejectWeakBackdoor —— 图床/CDN 冒充被黑 → 强制 ignored
//   - maybeAcceptWriteProof   —— 无害写证据齐全却被驳回 → 强制 accepted(反向纠偏)
//   - maybeDeepenIgnored      —— 有价值的半成品被 ignored → 改判 deepen 并给定向指令
//
// 纪律:只做「确定性、可解释」的改判,每条都在 notes 里留 [系统改判] 痕迹,绝不
// 静默改动模型结论。
// ---------------------------------------------------------------------------

// postReviewAdjust 对模型的审核结论做确定性改判。返回是否发生了改判。
func (s *Server) postReviewAdjust(f *db.DBFinding, rev *db.FindingReview, srcType string) bool {
	if rev == nil || f == nil {
		return false
	}
	switch {
	case maybeRejectEduBombing(f, rev, srcType):
		return true
	case maybeRejectWeakBackdoor(f, rev):
		return true
	case maybeAcceptWriteProof(f, rev):
		return true
	case maybeDeepenIgnored(f, rev, srcType):
		return true
	}
	return false
}

// maybeRejectEduBombing:EduSRC 不收短信/邮箱轰炸。LLM 误收或误打回深挖时改判 ignored。
func maybeRejectEduBombing(f *db.DBFinding, rev *db.FindingReview, srcType string) bool {
	if !isEduSrcType(srcType) || rev.Verdict == db.ReviewVerdictIgnored {
		return false
	}
	if !looksLikeBombing(f) {
		return false
	}
	toIgnored(rev, "EduSRC 不收短信/邮箱轰炸", "轰炸类不属于可收录漏洞,且不得为取证去连发。")
	return true
}

// maybeRejectWeakBackdoor:只有图床/CDN/第三方外链的「疑似被黑」改判 ignored。
func maybeRejectWeakBackdoor(f *db.DBFinding, rev *db.FindingReview) bool {
	if rev.Verdict == db.ReviewVerdictIgnored {
		return false
	}
	if !looksLikeWeakBackdoor(f) {
		return false
	}
	toIgnored(rev, "图床/CDN/第三方外链不是被黑", "只有本站页面被攻陷(正文被替换/webshell 可执行)才算被黑。")
	return true
}

// maybeAcceptWriteProof:写/删/改的**无害证法**已经齐时,不允许因「没破坏真实数据」
// 被 ignored/deepen —— 这是 AutoHunter 专门为纠这个误判写的反向规则。
func maybeAcceptWriteProof(f *db.DBFinding, rev *db.FindingReview) bool {
	if rev.Verdict != db.ReviewVerdictIgnored && rev.Verdict != db.ReviewVerdictDeepen {
		return false
	}
	if rev.DuplicateOf != nil && *rev.DuplicateOf > 0 {
		return false // 重复而已,与证据强度无关
	}
	kind := classifyHarmlessWriteProof(f)
	if kind == "" {
		return false
	}
	rev.Verdict = db.ReviewVerdictAccepted
	if strings.TrimSpace(rev.Severity) == "" {
		rev.Severity = normalizeReviewSeverity(f.Severity)
	}
	if rev.Severity == "" {
		rev.Severity = "medium"
	}
	low, high := 5.0, 7.4
	if rev.Score == nil {
		v := low
		rev.Score = &v
	} else if *rev.Score < low {
		v := low
		rev.Score = &v
	} else if *rev.Score > high {
		v := high
		rev.Score = &v
	}
	rev.Reasons = ""
	rev.Notes = strings.TrimSpace(rev.Notes) + fmt.Sprintf(
		"\n[系统改判] 写/删/改证据属于无害证法(%s),不得因未破坏真实数据驳回或打回深挖。", kind)
	return true
}

// maybeDeepenIgnored:模型判 ignored,但这条属于「入口真实、下一步明确」的半成品时,
// 改判 deepen 并给出定向回炉指令 —— 不允许用一个 ignored 把有价值的线索归档。
//
// 这是 AutoHunter 最有价值的一条:它把「审核」从「二分类」变成「三分类 + 反馈回路」。
func maybeDeepenIgnored(f *db.DBFinding, rev *db.FindingReview, srcType string) bool {
	if rev.Verdict != db.ReviewVerdictIgnored {
		return false
	}
	if rev.DuplicateOf != nil && *rev.DuplicateOf > 0 {
		return false // 重复的不用回炉
	}
	directive := deepenDirectiveFor(f, srcType)
	if directive == "" {
		return false
	}
	rev.Verdict = db.ReviewVerdictDeepen
	if strings.TrimSpace(rev.DeepenDirective) == "" {
		rev.DeepenDirective = directive
	}
	low, high := 2.5, 3.9
	if rev.Score == nil {
		v := low
		rev.Score = &v
	} else if *rev.Score < low {
		v := low
		rev.Score = &v
	} else if *rev.Score > high {
		v := high
		rev.Score = &v
	}
	rev.Notes = strings.TrimSpace(rev.Notes) +
		"\n[系统改判] 该漏洞不够 accepted,但属「入口真实、下一步明确」的半成品;已从 ignored 改为 deepen,要求 worker 定向补链。"
	return true
}

// ---------------------------------------------------------------------------
// 判定辅助
// ---------------------------------------------------------------------------

func toIgnored(rev *db.FindingReview, reason, note string) {
	rev.Verdict = db.ReviewVerdictIgnored
	rev.Severity = ""
	if rev.Score == nil || *rev.Score > 1.5 {
		v := 1.0
		rev.Score = &v
	}
	reasons := strings.TrimSpace(rev.Reasons)
	if !strings.Contains(reasons, reason) {
		if reasons == "" {
			reasons = reason
		} else {
			reasons = reasons + "\n" + reason
		}
	}
	rev.Reasons = reasons
	rev.Notes = strings.TrimSpace(rev.Notes) + "\n[系统改判] " + note
}

func isEduSrcType(srcType string) bool {
	return db.NormalizeReviewSrcType(srcType) == db.ReviewSrcEduSRC
}

// findingHeadText 只取「类型 + 名称」,与规则层同一口径 —— 不拿 evidence 里的
// 顺带提及去判定,避免把「SQL 注入 + 顺带目录列表」这类真洞误杀。
func findingHeadText(f *db.DBFinding) string {
	return strings.ToLower(f.VulnClass + " " + f.Name)
}

// findingFullText 取全文,供需要看证据的判定(无害证法、利用痕迹)使用。
func findingFullText(f *db.DBFinding) string {
	return strings.ToLower(strings.Join([]string{f.VulnClass, f.Name, f.Summary, f.Evidence, f.Report}, "\n"))
}

func looksLikeBombing(f *db.DBFinding) bool {
	blob := findingHeadText(f) + "\n" + findingFullText(f)
	for _, k := range []string{"短信轰炸", "邮箱轰炸", "邮件轰炸", "验证码轰炸", "短信炸弹", "sms bomb", "email bomb"} {
		if strings.Contains(blob, k) {
			return true
		}
	}
	return false
}

// looksLikeWeakBackdoor:「疑似被黑」但证据只有外部资源引用,没有页面被攻陷的实锤。
func looksLikeWeakBackdoor(f *db.DBFinding) bool {
	head := findingHeadText(f)
	body := findingFullText(f)
	claims := []string{"被黑", "被攻陷", "deface", "hacked by", "后门", "赌博", "色情", "暗链", "webshell", "blackdoor"}
	if !agent.ContainsAnyFold(head+body, claims) {
		return false
	}
	// 有页面替换 / webshell 执行的实锤 → 不是弱证据。
	if agent.ContainsAnyFold(body, []string{"webshell 可执行", "命令回显", "uid=", "whoami", "hacked by", "deface", "标题被替换", "正文被替换"}) {
		return false
	}
	weak := []string{"图床", "oss", "cdn", "七牛", "又拍云", "imgur", "jsdelivr", "外部图片", "外链", "第三方 js", "第三方统计", "cloudfront"}
	return agent.ContainsAnyFold(body, weak)
}

// classifyHarmlessWriteProof 判定写/删/改类漏洞是否已给出无害证法,返回证法名。
// 与挖掘期闸门(agent/finding_gate.go)共用同一套标记,保证「worker 按闸门指引补的
// 证据,审核层一定认」——两边口径漂移会让 worker 白忙。
func classifyHarmlessWriteProof(f *db.DBFinding) string {
	head := findingHeadText(f)
	body := findingFullText(f)
	if !agent.IsWriteFindingText(head, body) {
		return ""
	}
	if agent.ContainsAnyFold(body, []string{"src_test_", "哨兵", "自建测试"}) &&
		agent.ContainsAnyFold(body, []string{"新增", "创建", "insert", "create", "已删除", "已更新", "旁路", "再次查询", "before", "after"}) {
		return "自建哨兵闭环"
	}
	if agent.ContainsAnyFold(body, []string{"未登录", "无cookie", "无 cookie", "不带token", "不带 token", "不带授权", "对照", "对比", "匿名"}) &&
		agent.ContainsAnyFold(body, []string{"401", "403", "没有权限", "无权"}) &&
		agent.ContainsAnyFold(body, []string{"200", "操作成功", "授权通过"}) {
		return "鉴权对照"
	}
	if agent.ContainsAnyFold(body, []string{"幂等", "写回原值", "原值写回", "同一值", "值未变"}) &&
		agent.ContainsAnyFold(body, []string{"affectedrows", "affected_rows", "授权通过", "操作成功"}) {
		return "幂等回写"
	}
	// 只读越权取证 + 明确的旁路回读也算(拿不到写权限但证到了越权读)。
	if agent.ContainsAnyFold(body, []string{"旁路", "再次查询", "前后对比", "before", "after"}) {
		return "旁路回读"
	}
	return ""
}

// ---------------------------------------------------------------------------
// 定向回炉指令(对应 AutoHunter 的 _ignored_deepen_directive)
// ---------------------------------------------------------------------------

// deepenNeverMarkers 命中即不回炉:这些是明确不收的类型,打了也是白发一轮。
var deepenNeverMarkers = []string{
	"反射型xss", "反射型 xss", "反射xss", "reflected xss", "self-xss", "self xss",
	"用户名枚举", "用户枚举", "phpinfo", "拒绝服务", "dos攻击",
	"短信轰炸", "邮箱轰炸", "邮件轰炸", "验证码轰炸",
	"非教育", "不在范围", "钓鱼", "中间人", "mitm",
	"本就公开", "公开展示", "公开接口", "图形验证码", "算术验证码",
}

// deepenDirectiveFor 对一条被判 ignored 的 finding 判断「值不值得回炉」并给出定向指令。
// 返回空串 = 不值得回炉(保持 ignored)。
//
// 触发条件必须同时成立(抄 AutoHunter 的三条):
//  1. 线索真实(确实发现了 secret/可疑越权点/疑似注入点等),不是臆想;
//  2. 存在明确的下一步利用路径,打穿后构成真实危害;
//  3. 这一轮只是没去做/没做完那一步(不是做了但证明打不穿)。
func deepenDirectiveFor(f *db.DBFinding, srcType string) string {
	head := findingHeadText(f)
	body := findingFullText(f)

	// 自检自认的垃圾不回炉(worker 自己都说打不穿)。
	if sc := parseSelfCheck(f.SelfCheck); sc != nil {
		if sc.IsReflectedXSS || sc.NeedsAdminLogin || sc.NeedsMITM || sc.IsPureInfoLeak {
			return ""
		}
		if sc.ScannerOnlyNoPoc && !looksLikeRCEText(head) {
			return ""
		}
	}
	if agent.ContainsAnyFold(head, deepenNeverMarkers) {
		return ""
	}

	authSignal := agent.ContainsAnyFold(body, []string{"未授权", "无需登录", "无鉴权", "未鉴权", "unauthorized", "without auth", "no auth"})
	secretSignal := agent.ContainsAnyFold(body, []string{"secret", "appsecret", "clientsecret", "api key", "apikey", "accesskey", "私钥", "密钥", "签名密钥"})
	tokenSignal := agent.ContainsAnyFold(body, []string{"token", "jwt", "session"}) &&
		agent.ContainsAnyFold(body, []string{"泄露", "硬编码", "暴露", "明文", "返回", "前端", "js", "配置", "config"})
	uploadSignal := agent.ContainsAnyFold(body, []string{"上传", "upload", "savefile", "fileupload", "multipart/form-data"})
	writeSignal := agent.ContainsAnyFold(body, []string{"修改", "删除", "新增", "保存", "重置", "update", "delete", "remove", "save", "reset"})
	registerSignal := agent.ContainsAnyFold(body, []string{"注册", "register", "signup"}) &&
		agent.ContainsAnyFold(body, []string{"无验证码", "免验证码", "批量注册", "captcha"})
	rceSignal := looksLikeRCEText(head) || agent.ContainsAnyFold(body, []string{"命令执行", "命令注入", "rce", "code execution", "ssti", "模板注入", "反序列化"})
	sideChannel := agent.ContainsAnyFold(body, []string{
		"时间盲", "time-based", "time based", "sleep(", "延时", "响应时间", "响应延迟",
		"dnslog", "oast", "带外", "ceye", "interactsh", "回连", "外连",
		"落地文件", "写入文件", "outfile", "结果写入",
	})
	configSignal := agent.ContainsAnyFold(body, []string{"系统配置", "配置项", "系统参数", "configkey", "initpassword", "sys.user.initpassword", "/config", "appconfig", "setting"})
	idorSignal := agent.ContainsAnyFold(body, []string{"越权", "idor", "水平越权", "遍历他人", "换 id", "他人数据"})
	injectSignal := agent.ContainsAnyFold(body, []string{"注入", "injection", "sqli", "盲注"})

	switch {
	// 无回显/盲打 RCE:有侧信道证据但缺直接回显 → 回炉坐实。
	case rceSignal && sideChannel:
		return "这是疑似盲打/无回显 RCE:已有侧信道线索但缺直接回显。沿同一注入点把命令结果坐实 —— " +
			"用稳定 time-based(sleep 递增验证时间差线性)、DNS/HTTP 带外回连(dnslog/interactsh/ceye)、" +
			"或把命令输出写入可回读的业务字段/落地文件后访问,拿到明确执行结果证据。确认无任何侧信道差异才收尾。"

	// 配置项泄露:沿配置接口继续挖凭证/后台。
	case configSignal && (authSignal || secretSignal || tokenSignal):
		return "不要停在「配置项泄露」。沿已证实的配置接口继续深挖:枚举更多配置 key/接口地址," +
			"提取 token、secret、默认口令或后台路径,并实证能否登录后台、调用受限 API、读取死规矩敏感数据或执行敏感写操作。"

	// 未授权/越权:去补写操作或规模。
	case (authSignal || idorSignal) && writeSignal:
		return "沿未授权/越权写接口继续深挖,但**禁止删改真实/他人数据**。" + agent.HarmlessProofProtocol

	// 未授权上传:去 getshell 或存储型 XSS。
	case uploadSignal && authSignal:
		return "沿未授权上传入口继续深挖:验证可上传的扩展名、落点路径与访问方式,优先证明脚本可解析执行(getshell)," +
			"或传 HTML/SVG 到目标站自身域名且访问时 Content-Type 为 text/html(即为存储型 XSS 成立)。只能上传并访问 txt 则放弃。"

	// 泄漏的密钥/令牌:去实际使用。
	case secretSignal || tokenSignal:
		return "沿已发现的 key/secret/token 继续深挖:确认它是否可用,尝试伪造签名或携带凭证调用受限 API," +
			"必须打出读取敏感数据、后台权限、配额盗刷或敏感写操作的实证;仅证明字符串存在不算洞。"

	// 注册无验证码:去补下游危害。
	case registerSignal:
		return "不要把「可批量注册」单独当洞。注册一个低影响测试账号并登录,枚举表单/用户/导出/后台 API," +
			"验证能否读取或修改他人数据、批量导出、越权访问管理接口,或链到改密/账号接管。只能注册空账号且无下游危害则放弃。"

	// 疑似注入但没注出数据:去注出实际数据。
	case injectSignal && !sideChannel:
		return "疑似注入但还没注出实际数据。沿同一注入点继续:注出库名/表名,再脱 user 表的账号+密码哈希或身份证" +
			"(盲注就逐位提,提出完整哈希才算数);能写则试 into outfile 落 webshell。"

	// 企业标准下的未授权:去证明业务影响。
	case !isEduSrcType(srcType) && authSignal:
		return "该未授权线索尚未打出企业可收影响。继续验证能否读取客户/员工/订单/审批/财务等受限数据," +
			"或执行权限、配置、业务状态类敏感写操作。无实际影响则放弃。"
	}
	return ""
}

func looksLikeRCEText(head string) bool {
	for _, k := range []string{"rce", "command_injection", "command_exec", "code_injection", "ssti", "deserialization", "命令执行", "命令注入", "代码执行", "反序列化"} {
		if strings.Contains(head, k) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// 自动回炉:把 deepen 结论落成一条 worker 意图(架构关键差异)
// ---------------------------------------------------------------------------

// autoDeepenFinding 把一条 verdict=deepen 的漏洞转成高优先级回炉意图,让规划者/
// worker 带着定向指令再挖一轮。与人工 deepen(deepenFinding)走同一条落库路径
// (AddFindingFollowUpIntent),只是发起者从人变成审核层。
//
// 任何一步失败都只记日志、不阻断审核流程:审核结论已经写库,回炉是增强而非必需。
func (s *Server) autoDeepenFinding(ctx context.Context, f *db.DBFinding, rev *db.FindingReview) {
	if f == nil || f.TaskID == nil || f.NodeID == nil || *f.TaskID <= 0 {
		return
	}
	t, ok := s.m.Task(i64s(*f.TaskID))
	if !ok || t == nil {
		log.Printf("[review] 自动回炉跳过:finding=%d 无法取到任务 %d(任务已删除?)", f.ID, *f.TaskID)
		return
	}
	directive := strings.TrimSpace(rev.DeepenDirective)
	if directive == "" {
		directive = strings.TrimSpace(rev.Reasons)
	}
	if directive == "" {
		log.Printf("[review] 自动回炉跳过:finding=%d 没有可用的定向指令", f.ID)
		return
	}
	desc := fmt.Sprintf("【审核自动回炉】漏洞 #%d(%s / %s):%s\n"+
		"要求:针对上面的定向指令把利用打穿 —— 只有拿到真实证据(请求+响应或命令回显)才算完成;"+
		"打不穿就把它作为 inferred 事实记录并把结论写清,不要重复提交同一个半成品。",
		f.ID, f.VulnClass, f.Name, directive)

	if !s.engine.beginTaskOperation(t.ID) {
		log.Printf("[review] 自动回炉跳过:task %s 正在删除", t.ID)
		return
	}
	defer s.engine.decInflight(t.ID)

	audit := db.Activity{
		Worker:  "reviewer",
		Kind:    "text",
		Summary: fmt.Sprintf("AI 审核判定需回炉深挖(漏洞 #%d)", f.ID),
		Detail:  directive,
	}
	intentID, audit, err := t.Store.AddFindingFollowUpIntent(f.ID, *f.NodeID, desc, audit)
	if err != nil {
		log.Printf("[review] 自动回炉建意图失败 finding=%d: %v", f.ID, err)
		return
	}
	_ = audit
	if queued, err := s.admitTask(t, "resume"); err != nil {
		log.Printf("[review] 自动回炉唤醒任务失败 finding=%d: %v", f.ID, err)
	} else {
		log.Printf("[review] 自动回炉已建意图 intent=%d finding=%d queued=%v", intentID, f.ID, queued)
	}
}

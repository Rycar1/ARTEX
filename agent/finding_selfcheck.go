package agent

// FindingSelfCheck 是 worker 提交漏洞前的结构化自检 —— 对照当前 SRC 模式的忽略清单,
// 逐项如实回答。移植自 StanleyNull/AutoHunter 的 SelfCheck(7 个布尔位)。
//
// 为什么让 worker 自己填:它最清楚这条东西是怎么来的。填了 true 的项会成为
// 挖掘期闸门(agent/finding_gate.go)与二次审核的**一票否决依据**;填得不实,
// reviewer 会以证据为准反查 —— 所以自检不是装饰,是被消费的。
type FindingSelfCheck struct {
	// IsReflectedXSS 反射型 XSS / Self-XSS(主流 SRC 均不收)。
	IsReflectedXSS bool `json:"is_reflected_xss,omitempty"`
	// NeedsAdminLogin 需要先登录管理员后台才能触发(不收)。
	NeedsAdminLogin bool `json:"needs_admin_login,omitempty"`
	// NeedsMITM 需要中间人攻击才能触发(不收)。
	NeedsMITM bool `json:"needs_mitm,omitempty"`
	// IsPureInfoLeak 无实际利用的信息泄露(phpinfo/内网IP/版本号等,不收)。
	IsPureInfoLeak bool `json:"is_pure_info_leak,omitempty"`
	// ScannerOnlyNoPoc 只有扫描器结果、给不出利用方法(不收)。
	ScannerOnlyNoPoc bool `json:"scanner_only_no_poc,omitempty"`
	// IsPublicInterface 该接口本就面向公众公开(访问它通常不构成漏洞)。
	IsPublicInterface bool `json:"is_public_interface,omitempty"`
	// InfoLeakHitsStrictList 若属信息泄露类:泄露数据是否命中当前 SRC 的敏感数据口径
	// (EduSRC 四类:身份证照片/人脸照片/身份证号/密码哈希;企业标准见提示词)。
	InfoLeakHitsStrictList bool `json:"info_leak_hits_strict_list,omitempty"`
}

// AnyIgnoreHit 报告自检是否命中「明确不收」的项。用于日志/统计与审核侧提示。
func (s *FindingSelfCheck) AnyIgnoreHit() bool {
	if s == nil {
		return false
	}
	return s.IsReflectedXSS || s.NeedsAdminLogin || s.NeedsMITM ||
		s.IsPureInfoLeak || s.ScannerOnlyNoPoc || s.IsPublicInterface
}

// SelfCheckHint 是提示词里给 worker 的自检填报说明(单一事实源,worker 与
// pentest 独立 agent 共用),避免两处提示词各写一份而漂移。
const SelfCheckHint = "**提交前必须做结构化自检(self_check 字段,7 个布尔位如实填)**:\n" +
	"- is_reflected_xss:是否反射型 XSS / Self-XSS(主流 SRC 均不收)\n" +
	"- needs_admin_login:是否必须先登录管理员后台才能触发(不收)\n" +
	"- needs_mitm:是否需要中间人攻击才能触发(不收)\n" +
	"- is_pure_info_leak:是否是无实际利用的信息泄露(phpinfo/内网IP/版本号/内部域名,不收)\n" +
	"- scanner_only_no_poc:是否只有扫描器结果、给不出利用方法(不收)\n" +
	"- is_public_interface:该接口是否本就面向公众公开(是则访问它不构成漏洞)\n" +
	"- info_leak_hits_strict_list:若属信息泄露类,泄露数据是否命中本 SRC 的敏感数据口径\n" +
	"这些位填 true 会被系统直接拒收,别抱侥幸 —— 填得不实,审核会以证据为准反查,反而更浪费时间。\n" +
	"**提交前自问三句**(答不上就别提交):① 我用它实际干成了什么?② 有原始请求+响应(或命令回显)证据吗?③ 这个证据能证明危害,而不是只证明了某处存在缺陷?"

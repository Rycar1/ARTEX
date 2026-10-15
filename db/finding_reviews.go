package db

import "strings"

// ---------------------------------------------------------------------------
// 漏洞 AI 二次审核(参考 StanleyNull/AutoHunter 的 Reviewer)。
//
// 一个任务开启二次审核(tasks.review_enabled)后,worker 新登记的每条漏洞都会进入
// 审核:先过规则层(零成本),规则没结论才调该任务自己的 LLM 做证据链审查。结论落在
// findings.review_* 六列上;verdict=ignored 时由 server 侧自动把 findings.status 置为
// ignored 并写明原因(见 server/finding_review.go)。
//
// 本文件只负责「数据」:审核结论读写 + 任务级开关查询 + 待审队列查询。
// ---------------------------------------------------------------------------

// 审核结论(findings.review_verdict)。空串 = 尚未审核。
const (
	ReviewVerdictAccepted = "accepted" // 通过:符合所选 SRC 收录标准,进最终列表
	ReviewVerdictIgnored  = "ignored"  // 忽略:垃圾洞/不收,自动置 status=ignored 并注明原因
	// ReviewVerdictDeepen 是第三种裁决(参考 AutoHunter 的 deepen):线索真实有价值、
	// 下一步利用路径明确,但 worker 这一轮没把利用打穿。既不该 accepted(危害没实锤),
	// 也不该 ignored(白白丢掉好线索)—— 打回让 worker 带着定向指令再挖一轮。
	// 与人工 deepen(server/findings_groups.go 的 deepenFinding)互补:这条由审核自动
	// 发起,人工那条由人在漏洞详情页发起。
	ReviewVerdictDeepen = "deepen"
)

// 审核标准类型(tasks.review_src_type)。
const (
	ReviewSrcEduSRC     = "edusrc"     // 教育行业 SRC:严格收录标准
	ReviewSrcEnterprise = "enterprise" // 企业 SRC:按高价值影响判定
)

// ValidReviewVerdict reports whether v is a known 二次审核结论。
func ValidReviewVerdict(v string) bool {
	switch v {
	case ReviewVerdictAccepted, ReviewVerdictIgnored, ReviewVerdictDeepen:
		return true
	}
	return false
}

// ReviewVerdictDeferred reports whether a verdict is "not terminal, needs a
// follow-up action". deepen 会被自动转成一条回炉意图,因此它不把 status 置成
// 终态(ignored 才置 ignored),漏洞保持在待处理/已确认,等回炉结果再定。
func ReviewVerdictDeferred(v string) bool { return v == ReviewVerdictDeepen }

// NormalizeReviewSrcType 把前端/API 传入的标准收敛为两个受支持取值:
// enterprise / enterprise_src / corp / company / 企业 / 企业src → enterprise;
// 其余(含空串) → edusrc。默认 edusrc 是因为它更严 —— 误按企业标准审会放过垃圾洞。
func NormalizeReviewSrcType(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "enterprise", "enterprise_src", "corp", "company", "src", "企业", "企业src", "企业src标准":
		return ReviewSrcEnterprise
	default:
		return ReviewSrcEduSRC
	}
}

// ReviewEnabled reports whether a task has AI 二次审核 turned on(tasks.review_enabled)。
// 缺行/读失败/taskID<=0 → false(默认关):审核是可选增强,读不到开关时宁可不审,
// 也不能把没打算审的任务卷进来。
func (d *DB) ReviewEnabled(taskID int64) bool {
	if taskID <= 0 {
		return false
	}
	var enabled bool
	if err := d.QueryRow(`SELECT COALESCE(review_enabled,false) FROM tasks WHERE id=$1`, taskID).Scan(&enabled); err != nil {
		return false
	}
	return enabled
}

// ReviewSrcType returns a task's SRC 收录标准(空/读失败 → edusrc)。
func (d *DB) ReviewSrcType(taskID int64) string {
	if taskID <= 0 {
		return ReviewSrcEduSRC
	}
	var raw string
	if err := d.QueryRow(`SELECT COALESCE(review_src_type,'edusrc') FROM tasks WHERE id=$1`, taskID).Scan(&raw); err != nil {
		return ReviewSrcEduSRC
	}
	return NormalizeReviewSrcType(raw)
}

// FindingReview 是一次二次审核的完整结论,整体写回 findings 的 review_* 列。
type FindingReview struct {
	Verdict  string   // accepted | ignored
	Severity string   // 审核后的严重度(critical|high|medium|low);空=不改
	Score    *float64 // 0-10 价值分;nil=未给
	Reasons  string   // 忽略/降级原因(多条以换行连接);ignored 时必填
	Notes    string   // 审核员备注
	// DuplicateOf 是审核模型指认的重复目标 finding id(四层去重第三层)。
	// 非空时只打 suspected_dup_of 标记,不自动合并;nil = 模型没指认。
	DuplicateOf *int64
	// DeeperDirective 是 verdict=deepen 时的定向回炉指令:一句话说清下一轮去打
	// 哪个接口/参数/动作。由审核模型给出;为空时回炉层会用兜底话术(AutoHunter 的
	// _ignored_deepen_directive 就是同一角色的确定性兜底)。
	DeepenDirective string
}

// SetFindingReview 写入一次审核结论,并把 reviewed_at 置为 now()。
// 刻意不改 status:状态流转由调用方走 SetFindingStatusWithNotify 单独完成,这样
// 「审核结论」与「状态变更推送」两件事解耦,推送事件也不会被绕过。
// 也不镜像到探索节点 payload —— 那是 worker 写的漏洞原始事实,审核结论只属于审核层。
func (d *DB) SetFindingReview(id int64, r FindingReview) error {
	// deepen 的定向指令存进 review_notes 之外的单列会需要再加一列;这里复用
	// review_reasons(ignored 时放原因、deepen 时放回炉指令),语义由 verdict 区分,
	// 避免为第三种裁决再加一列。指令本身也写进 notes 便于人工看。
	reasons := r.Reasons
	if r.Verdict == ReviewVerdictDeepen && strings.TrimSpace(r.DeepenDirective) != "" {
		if strings.TrimSpace(reasons) == "" {
			reasons = r.DeepenDirective
		} else {
			reasons = reasons + "\n" + r.DeepenDirective
		}
	}
	_, err := d.Exec(`UPDATE findings SET review_verdict=$1, review_severity=$2, review_score=$3,
		review_reasons=$4, review_notes=$5, reviewed_at=now() WHERE id=$6`,
		r.Verdict, r.Severity, r.Score, reasons, r.Notes, id)
	return err
}

// ListFindingsAwaitingReview 返回「所属任务开了二次审核、但还没审过」的漏洞,按登记
// 时间升序(先来先审)。limit<=0 → 20。
// 只收仍处在 待处理/处理中/已确认 的行:人工已把状态改成 误报/重复/风险接受 的漏洞
// 不再自动复审,免得审核结论盖掉人工判断。
func (d *DB) ListFindingsAwaitingReview(limit int) ([]*DBFinding, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := d.Query(`
		SELECT `+findingSelectCols+`
		FROM findings f
		JOIN tasks rt ON rt.id = f.task_id AND COALESCE(rt.review_enabled,false)
		LEFT JOIN tasks t ON f.task_id = t.id
		WHERE COALESCE(f.review_verdict,'') = ''
		  AND COALESCE(f.status,'pending') IN ('pending','in_progress','confirmed')
		ORDER BY f.created_at ASC, f.id ASC
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanFindings(rows)
}

// ReviewStats 是二次审核页顶部卡片用的整表计数。
type ReviewStats struct {
	Total    int `json:"total"` // 已审(有结论)
	Accepted int `json:"accepted"`
	Ignored  int `json:"ignored"`
	Deepen   int `json:"deepen"`  // 打回深挖(回炉中,非终态)
	Pending  int `json:"pending"` // 开了审核但尚未审的
}

// FindingReviewStats 统计审核结论分布(整表)。
func (d *DB) FindingReviewStats() (*ReviewStats, error) {
	s := &ReviewStats{}
	if err := d.QueryRow(`
		SELECT
			COUNT(*) FILTER (WHERE COALESCE(review_verdict,'') <> ''),
			COUNT(*) FILTER (WHERE review_verdict='accepted'),
			COUNT(*) FILTER (WHERE review_verdict='ignored'),
			COUNT(*) FILTER (WHERE review_verdict='deepen')
		FROM findings`).Scan(&s.Total, &s.Accepted, &s.Ignored, &s.Deepen); err != nil {
		return nil, err
	}
	if err := d.QueryRow(`
		SELECT COUNT(*) FROM findings f
		JOIN tasks rt ON rt.id = f.task_id AND COALESCE(rt.review_enabled,false)
		WHERE COALESCE(f.review_verdict,'') = ''`).Scan(&s.Pending); err != nil {
		return nil, err
	}
	return s, nil
}

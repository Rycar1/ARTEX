package db

import "fmt"

// ---------------------------------------------------------------------------
// 危害升级(参考 StanleyNull/AutoHunter 的「扩大危害 Hunter」)。
//
// 问题:审核判 accepted 的低危/中危漏洞在旧架构里是**终态** —— 之后没有任何东西会
// 去尝试把危害做大。审核只能纠正标签(把 worker 自评的 low 重定级),不会派人去把
// 「能读一条数据」变成「能批量拖库」。
//
// 本文件只负责「数据」:升级状态读写 + 结果回写。触发与派单在
// server/finding_escalate.go,升级手册在 agent/finding_escalate.go。
//
// 状态机:
//   ''          未派升级(默认)
//   dispatched  已派「扩大危害」意图,等 worker 结果
//   done        升级结果已交回(严重度已写回,等待复核确认)
//   failed      worker 确认打不动 —— **保留原级**,不做任何降级
// ---------------------------------------------------------------------------

const (
	EscalateDispatched = "dispatched"
	EscalateDone       = "done"
	EscalateFailed     = "failed"
)

// MarkFindingEscalated 记录「已为该漏洞派出升级意图」。
// baseSeverity 保存升级前的严重度,升级不成立时用它回退。
// 只在尚未派过时生效(escalated_at IS NULL),天然实现「每个漏洞最多升级一轮」。
// 返回是否真的标记成功(false = 已经派过,调用方不要重复派单)。
func (d *DB) MarkFindingEscalated(id int64, baseSeverity string) (bool, error) {
	res, err := d.Exec(`UPDATE findings
		SET escalated_at = now(), escalate_status = $2, base_severity = $3
		WHERE id = $1 AND escalated_at IS NULL`, id, EscalateDispatched, baseSeverity)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// ApplyEscalationSuccess 把升级结果写回原漏洞(不新建 finding):
// 追加证据链、抬升严重度、置 escalate_status=done,并清空 review_verdict 让它
// **重新进入复核队列** —— 升级声明必须经审核确认,不能让 worker 自己把级别抬上去。
//
// severity 只在高于 base_severity 时才采纳(升级只做加法,不降级)。比较用**数值
// 等级**而不是字符串:Postgres 的 GREATEST 对 text 是字典序,'low' > 'critical',
// 直接 GREATEST 会把升级结果吞掉(实测踩到过)。
func (d *DB) ApplyEscalationSuccess(id int64, severity, evidence, note string) error {
	const sevRank = `CASE %s WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END`
	_, err := d.Exec(`UPDATE findings
		SET evidence = CASE WHEN $2 = '' THEN evidence ELSE evidence || E'\n\n' || $2 END,
		    severity = CASE
		        WHEN $3 = '' THEN severity
		        WHEN base_severity = '' THEN $3
		        WHEN `+fmt.Sprintf(sevRank, "$3")+` >= `+fmt.Sprintf(sevRank, "base_severity")+` THEN $3
		        ELSE base_severity END,
		    escalate_status = $4,
		    review_verdict = '',
		    review_notes = CASE WHEN $5 = '' THEN review_notes
		                        ELSE COALESCE(review_notes,'') || E'\n' || $5 END,
		    reviewed_at = NULL
		WHERE id = $1`, id, evidence, severity, EscalateDone, note)
	return err
}

// ApplyEscalationFailure 记录「升级未成立」:**保留原级**,只记一条说明。
// 升级失败不等于原漏洞不成立 —— 绝不因此降级或忽略。
func (d *DB) ApplyEscalationFailure(id int64, note string) error {
	_, err := d.Exec(`UPDATE findings
		SET escalate_status = $2,
		    severity = CASE WHEN base_severity <> '' THEN base_severity ELSE severity END,
		    review_notes = CASE WHEN $3 = '' THEN review_notes
		                        ELSE COALESCE(review_notes,'') || E'\n' || $3 END
		WHERE id = $1`, id, EscalateFailed, note)
	return err
}

// RevertFindingSeverity 把严重度回退到升级前(复核判定升级不成立时用)。
func (d *DB) RevertFindingSeverity(id int64) error {
	_, err := d.Exec(`UPDATE findings
		SET severity = CASE WHEN base_severity <> '' THEN base_severity ELSE severity END
		WHERE id = $1`, id)
	return err
}

// ClearFindingEscalation 撤销升级占位(人工发起升级但派单失败时用,让用户能重试)。
// 与 ApplyEscalationFailure 的区别:后者是「升级跑过但没成立」的终态,本函数是
// 「升级根本没跑起来」的回滚 —— 必须把 escalated_at 清掉,否则「每个漏洞一轮」的
// 原子占位会把这个漏洞永久锁死。
func (d *DB) ClearFindingEscalation(id int64) error {
	_, err := d.Exec(`UPDATE findings
		SET escalated_at = NULL, escalate_status = '', base_severity = ''
		WHERE id = $1`, id)
	return err
}

// FindingEscalationState 是一次升级的当前状态(供 API/UI 展示)。
type FindingEscalationState struct {
	EscalatedAt    *string `json:"escalated_at,omitempty"`
	EscalateStatus string  `json:"escalate_status"`
	BaseSeverity   string  `json:"base_severity,omitempty"`
}

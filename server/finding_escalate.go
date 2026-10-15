package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

// ---------------------------------------------------------------------------
// 危害升级的触发与派单(参考 StanleyNull/AutoHunter 的「扩大危害 Hunter」)。
//
// 缺口:审核判 accepted 的低危/中危漏洞在旧架构里是终态 —— 没有任何东西会去尝试把
// 危害做大。审核只能纠正标签,不会派人把「能读一条数据」变成「能批量拖库」。
//
// 本文件补上这一环:审核采纳一个 low/medium 漏洞后,自动派一条「扩大危害」意图,
// worker 按 agent/finding_escalate.go 的 A–I 手册在已确认据点上继续打;结果写回
// **原漏洞**(不新建),并重新送审复核。
//
// 收敛条件(三条,缺一不可):
//  1. 每个漏洞最多升级一轮 —— MarkFindingEscalated 用 escalated_at IS NULL 原子保证;
//  2. 剩余预算不足则不派 —— 升级要真正发包验证,剩几分钟派出去只会白跑;
//  3. 升级不成立**保留原级** —— 打不动不等于原漏洞不成立,绝不因此降级或忽略。
// ---------------------------------------------------------------------------

const (
	// escalateMinRemaining 是派升级所需的最小剩余预算。低于它就不派 —— 一次升级
	// 至少要能完成"读原证据 → 试一条升级路径 → 写回"这个最小闭环。
	escalateMinRemaining = 5 * time.Minute
	// escalateBudgetShare 是升级最多占用的剩余预算比例。升级是增强而非主任务,
	// 不能让一个低危漏洞的升级把收尾预算吃光。
	escalateBudgetShare = 0.3
)

// escalateEligibleSeverity 判断某个级别是否值得升级:low/medium 才有升级空间,
// high/critical 已经够高(再往上要么无意义、要么该走人工)。
func escalateEligibleSeverity(sev string) bool {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "low", "medium":
		return true
	}
	return false
}

// effectiveSeverity 取「审核后的级别」为准,没审出级别时退回漏洞自身级别。
func effectiveSeverity(f *db.DBFinding, rev *db.FindingReview) string {
	if rev != nil && strings.TrimSpace(rev.Severity) != "" {
		return rev.Severity
	}
	if f != nil && strings.TrimSpace(f.ReviewSeverity) != "" {
		return f.ReviewSeverity
	}
	if f != nil {
		return f.Severity
	}
	return ""
}

// autoEscalateFinding 对「已采纳的低危/中危漏洞」派一条「扩大危害」意图。
// 任何一步不满足都只记日志、不阻断审核流程:升级是增强,不是审核的必需环节。
func (s *Server) autoEscalateFinding(ctx context.Context, f *db.DBFinding, rev *db.FindingReview) {
	if f == nil || f.TaskID == nil || f.NodeID == nil || *f.TaskID <= 0 {
		return
	}
	if rev == nil || rev.Verdict != db.ReviewVerdictAccepted {
		return
	}
	// 重复漏洞没有升级价值(升级的应该是那条被留下的主记录)。
	if rev.DuplicateOf != nil && *rev.DuplicateOf > 0 {
		return
	}
	sev := effectiveSeverity(f, rev)
	if !escalateEligibleSeverity(sev) {
		return
	}
	// 已经在升级流程里(done/failed)的不再派 —— 每个漏洞一轮。
	if f.EscalatedAt != nil {
		return
	}
	t, ok := s.m.Task(i64s(*f.TaskID))
	if !ok || t == nil {
		log.Printf("[escalate] 跳过:finding=%d 取不到任务 %d(任务已删除?)", f.ID, *f.TaskID)
		return
	}
	if !s.escalationBudgetOK(t) {
		log.Printf("[escalate] 跳过:finding=%d 任务 %s 剩余预算不足", f.ID, t.ID)
		return
	}
	// 原子占位:只有抢到才派,避免并发审核重复派单(也保证「每个漏洞一轮」)。
	claimed, err := s.m.pg.MarkFindingEscalated(f.ID, sev)
	if err != nil {
		log.Printf("[escalate] 标记失败 finding=%d: %v", f.ID, err)
		return
	}
	if !claimed {
		return // 已被别处派过
	}
	if err := s.dispatchEscalationChecked(t, f, sev); err != nil {
		// 区分「意图是否真的建起来了」:
		//   - 意图没建成 → 回滚占位,让这个漏洞以后还有机会升级;
		//   - 意图已建成、只是唤醒任务失败(如任务生命周期 CAS 冲突)→ **保持
		//     dispatched**。意图已经 durable 落在探索图里,任务下次运行(或本轮
		//     planner)就会领取它;此时若标 failed,worker 稍后交回的升级结果会被
		//     状态守卫拒收,白干一轮(真机实测踩到过)。
		if !escalationIntentCreated(err) {
			if uerr := s.m.pg.ApplyEscalationFailure(f.ID, "升级派单失败,已回滚升级标记"); uerr != nil {
				log.Printf("[escalate] 回滚标记也失败 finding=%d: %v", f.ID, uerr)
			}
			log.Printf("[escalate] 派单失败 finding=%d: %v", f.ID, err)
			return
		}
		log.Printf("[escalate] 升级意图已建但唤醒失败 finding=%d(保持 dispatched,由下次运行领取): %v", f.ID, err)
	}
}

// escalationIntentCreated 判断派单错误是「意图没建成」还是「建成后唤醒失败」。
// 用哨兵错误区分,避免靠字符串匹配。
func escalationIntentCreated(err error) bool {
	return err != nil && errors.Is(err, errEscalationIntentCreated)
}

// errEscalationIntentCreated 表示升级意图已经落库,只是后续唤醒任务失败。
var errEscalationIntentCreated = errors.New("escalation intent created but task wake failed")

// escalationBudgetOK 判断任务是否还有足够预算跑一轮升级。
// DeadlineAt=0 表示不限时(或尚未开跑)→ 放行。
func (s *Server) escalationBudgetOK(t *Task) bool {
	deadline := t.lifecycleSnapshot().DeadlineAt
	if deadline <= 0 {
		return true
	}
	remaining := time.Until(time.Unix(deadline, 0))
	if remaining < escalateMinRemaining {
		return false
	}
	// 升级占用的预算上限:剩余时间的 escalateBudgetShare。低于最小闭环所需时也放弃。
	return remaining.Seconds()*escalateBudgetShare >= escalateMinRemaining.Seconds()
}

// dispatchEscalationChecked 建意图并唤醒任务。唤醒失败时用 errEscalationIntentCreated
// 包装,让调用方能区分「意图没建成」与「建成后唤醒失败」。
func (s *Server) dispatchEscalationChecked(t *Task, f *db.DBFinding, sev string) error {
	if !s.engine.beginTaskOperation(t.ID) {
		return fmt.Errorf("任务正在删除")
	}
	defer s.engine.decInflight(t.ID)

	desc := buildEscalationIntent(f, sev)
	audit := db.Activity{
		Worker:  "reviewer",
		Kind:    "text",
		Summary: fmt.Sprintf("AI 审核采纳低危/中危漏洞,自动派发「扩大危害」(漏洞 #%d)", f.ID),
		Detail:  fmt.Sprintf("当前级别 %s;任务:在已确认据点上继续利用,把评级顶上去。", sev),
	}
	intentID, _, err := t.Store.AddFindingFollowUpIntentEx(f.ID, *f.NodeID, desc,
		map[string]any{"escalate": true}, audit)
	if err != nil {
		return fmt.Errorf("建升级意图: %w", err)
	}
	// 意图已落库 —— 从这里开始,失败都只是「没唤醒成功」,不能回滚升级占位。
	queued, err := s.admitTask(t, "resume")
	if err != nil {
		return fmt.Errorf("%w: intent=%d: %v", errEscalationIntentCreated, intentID, err)
	}
	log.Printf("[escalate] 已派升级意图 intent=%d finding=%d sev=%s queued=%v", intentID, f.ID, sev, queued)
	return nil
}

// buildEscalationIntent 组装升级意图正文:先给具体据点,再附 A–I 升级手册。
func buildEscalationIntent(f *db.DBFinding, sev string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "【扩大危害】已采纳漏洞 #%d,当前级别 %s\n", f.ID, sev)
	fmt.Fprintf(&sb, "漏洞类型:%s\n漏洞名称:%s\n", f.VulnClass, f.Name)
	if s := strings.TrimSpace(f.Summary); s != "" {
		fmt.Fprintf(&sb, "原摘要:%s\n", s)
	}
	if e := strings.TrimSpace(f.Evidence); e != "" {
		const head = 1200
		if len(e) > head {
			e = e[:head] + "…(完整证据见漏洞详情)"
		}
		fmt.Fprintf(&sb, "原证据(节选):\n%s\n", e)
	}
	sb.WriteString("\n")
	sb.WriteString(agent.EscalationManual)
	return sb.String()
}

// writeEscalationResult 是 report_escalation 的落地实现(worker 侧调用)。
//
// success=true :追加证据链 + 抬升严重度 + 清空 review_verdict 送回复核
//
//	(升级声明必须经审核确认,不能让 worker 自己把级别抬上去)。
//
// success=false:记录「升级未成立」,**保留原级**。
func (s *Server) writeEscalationResult(ctx context.Context, r agent.EscalationResult) error {
	if r.FindingID <= 0 {
		return fmt.Errorf("finding_id 无效")
	}
	f, err := s.m.pg.GetFinding(r.FindingID)
	if err != nil {
		return fmt.Errorf("读取漏洞失败: %w", err)
	}
	if f == nil {
		return fmt.Errorf("漏洞 #%d 不存在", r.FindingID)
	}
	// 归属校验:只允许改写本任务下的漏洞,避免 worker 越界改别的任务的成果。
	if r.TaskID > 0 && (f.TaskID == nil || *f.TaskID != r.TaskID) {
		return fmt.Errorf("漏洞 #%d 不属于本任务,拒绝改写", r.FindingID)
	}
	// 只在「升级流程中」才接受写回:防止普通 worker 误调 report_escalation 改级别。
	// failed 也放行 —— 它可能是「派单时唤醒失败」留下的状态,而升级意图其实已经
	// 在跑;此时拒收会把 worker 真打出来的结果丢掉。escalated_at 已经保证每个漏洞
	// 只升级一轮,所以这里放宽不会造成重复升级。
	if f.EscalateStatus == "" {
		return fmt.Errorf("漏洞 #%d 不在升级流程中,不能通过 report_escalation 改写", r.FindingID)
	}

	if !r.Success {
		note := strings.TrimSpace(r.Summary)
		if note == "" {
			note = "升级未成立(worker 未给出原因)"
		}
		if err := s.m.pg.ApplyEscalationFailure(f.ID, "[扩大危害] "+note); err != nil {
			return fmt.Errorf("记录升级失败: %w", err)
		}
		log.Printf("[escalate] finding=%d 升级未成立,保留原级 %s", f.ID, f.BaseSeverity)
		return nil
	}

	sev := strings.ToLower(strings.TrimSpace(r.Severity))
	if !db.ValidSeverity(sev) {
		return fmt.Errorf("severity 无效: %q", r.Severity)
	}
	// 升级只做加法:新级别不得低于升级前。
	if f.BaseSeverity != "" && severityRank(sev) < severityRank(f.BaseSeverity) {
		return fmt.Errorf("升级后的级别 %s 低于升级前的 %s:升级只做加法,若要下调请走人工改级", sev, f.BaseSeverity)
	}
	note := "[扩大危害] " + strings.TrimSpace(r.Summary)
	if err := s.m.pg.ApplyEscalationSuccess(f.ID, sev, strings.TrimSpace(r.Evidence), note); err != nil {
		return fmt.Errorf("写回升级结果: %w", err)
	}
	log.Printf("[escalate] finding=%d 升级已写回:%s → %s,已送回复核", f.ID, f.BaseSeverity, sev)
	return nil
}

// severityRank 给严重度排序,用于「升级只做加法」的比较。未知级别按最低处理。
func severityRank(sev string) int {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

// ---------------------------------------------------------------------------
// 人工发起「扩大危害」(POST /api/exploration/findings/{id}/escalate)
//
// 与自动升级的分工:
//   - 自动:审核采纳 low/medium 后按 severity + 预算 + 原子占位自动派单;
//   - 人工:不受 severity / 预算 / 审核状态限制(人判断该挖),但**仍遵守
//     「每个漏洞最多一轮」** —— 已升级过的返回 409,想继续深入请用「深入利用」。
//
// 派单失败会把升级占位一起回滚,否则该漏洞会被永久锁死再也升不了。
// ---------------------------------------------------------------------------

func (s *Server) escalateFindingManual(w http.ResponseWriter, r *http.Request) {
	id := int64(atoiDefault(r.PathValue("id"), 0))
	if id <= 0 {
		writeErr(w, 400, "bad finding id")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	var req struct {
		Notes string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeErr(w, http.StatusRequestEntityTooLarge, "请求正文过大")
		} else {
			writeErr(w, 400, "bad json: "+err.Error())
		}
		return
	}
	notes := strings.TrimSpace(req.Notes)
	if utf8.RuneCountInString(notes) > maxFindingFollowUpRunes {
		writeErr(w, 400, fmt.Sprintf("补充说明最多 %d 个字符", maxFindingFollowUpRunes))
		return
	}

	finding, err := s.m.pg.GetFinding(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if finding == nil {
		writeErr(w, 404, "finding not found")
		return
	}
	if finding.TaskID == nil || finding.NodeID == nil {
		writeErr(w, 409, "finding origin task or node is no longer available")
		return
	}
	t, ok := s.m.Task(i64s(*finding.TaskID))
	if !ok || t == nil {
		writeErr(w, 409, "finding origin task is no longer available")
		return
	}
	// 已经升级过一轮的拒绝再派(与自动路径同一套「每个漏洞一轮」规则)。
	if finding.EscalatedAt != nil {
		writeErr(w, 409, "该漏洞已发起过「扩大危害」(每个漏洞最多一轮);如需继续深入请用「深入利用」")
		return
	}
	if !s.engine.beginTaskOperation(t.ID) {
		writeErr(w, 409, "task is being deleted")
		return
	}
	defer s.engine.decInflight(t.ID)

	sev := effectiveSeverity(finding, nil)
	// 原子占位:抢不到说明并发已派过。
	claimed, err := s.m.pg.MarkFindingEscalated(finding.ID, sev)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if !claimed {
		writeErr(w, 409, "该漏洞已发起过「扩大危害」")
		return
	}

	desc := buildEscalationIntent(finding, sev)
	if notes != "" {
		desc += "\n\n# 人工补充的升级方向(优先考虑)\n" + notes
	}
	audit := db.Activity{
		Worker:  "human",
		Kind:    "text",
		Summary: fmt.Sprintf("人工发起「扩大危害」(漏洞 #%d)", finding.ID),
		Detail:  notes,
	}
	intentID, audit, err := t.Store.AddFindingFollowUpIntentEx(finding.ID, *finding.NodeID, desc,
		map[string]any{"escalate": true}, audit)
	if err != nil {
		if rbErr := s.m.pg.ClearFindingEscalation(finding.ID); rbErr != nil {
			err = errors.Join(err, fmt.Errorf("回滚升级占位: %w", rbErr))
		}
		writeErr(w, 500, err.Error())
		return
	}
	queued, err := s.admitTask(t, "resume")
	if err != nil {
		// 派单没跑起来:丢弃意图 + 回滚占位,让用户能重试。
		if rbErr := t.Store.DiscardOpenIntent(intentID); rbErr != nil {
			err = errors.Join(err, fmt.Errorf("discard escalation intent %d: %w", intentID, rbErr))
		}
		if rbErr := s.m.pg.ClearFindingEscalation(finding.ID); rbErr != nil {
			err = errors.Join(err, fmt.Errorf("回滚升级占位: %w", rbErr))
		}
		writeErr(w, 500, err.Error())
		return
	}
	s.engine.Broadcaster().Publish(t.ID, audit)
	s.engine.touch(t.ID)
	state := "open"
	if cur, stateErr := t.Store.GetNode(intentID); stateErr == nil && cur != nil {
		state = cur.State
	}
	writeJSON(w, 200, map[string]any{
		"task_id":   t.ID,
		"intent_id": i64s(intentID),
		"state":     state,
		"queued":    queued,
		"severity":  sev,
	})
}

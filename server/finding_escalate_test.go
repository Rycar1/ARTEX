package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

// 升级资格:只有 low/medium 值得升级(high/critical 已够高,再升无意义)。
func TestEscalateEligibleSeverity(t *testing.T) {
	yes := []string{"low", "medium", "LOW", " Medium "}
	no := []string{"high", "critical", "", "unknown"}
	for _, s := range yes {
		if !escalateEligibleSeverity(s) {
			t.Errorf("%q 应可升级", s)
		}
	}
	for _, s := range no {
		if escalateEligibleSeverity(s) {
			t.Errorf("%q 不应升级", s)
		}
	}
}

// severityRank 必须严格有序(「升级只做加法」靠它比较)。
func TestSeverityRankOrdering(t *testing.T) {
	order := []string{"low", "medium", "high", "critical"}
	for i := 1; i < len(order); i++ {
		if severityRank(order[i]) <= severityRank(order[i-1]) {
			t.Fatalf("%s 应高于 %s", order[i], order[i-1])
		}
	}
	if severityRank("") != 0 || severityRank("bogus") != 0 {
		t.Fatal("未知级别应排最低")
	}
}

// 预算闸门:不限时放行;剩余不足不派;剩余虽多但要留 30% 余量。
func TestEscalationBudgetGate(t *testing.T) {
	unlimited := &Task{}
	if !(&Server{}).escalationBudgetOK(unlimited) {
		t.Error("DeadlineAt=0(不限时)应放行")
	}
	cases := []struct {
		name   string
		remain time.Duration
		want   bool
	}{
		{"已过期", -time.Minute, false},
		{"剩 2 分钟", 2 * time.Minute, false},
		{"剩 10 分钟", 10 * time.Minute, false}, // 30% = 3min < 5min 最小闭环
		{"剩 20 分钟", 20 * time.Minute, true},  // 30% = 6min ≥ 5min
		{"剩 2 小时", 2 * time.Hour, true},
	}
	for _, c := range cases {
		tk := &Task{}
		tk.DeadlineAt = time.Now().Add(c.remain).Unix()
		if got := (&Server{}).escalationBudgetOK(tk); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

// 升级意图正文必须带具体据点 + A–I 手册,否则 worker 不知道打什么。
func TestBuildEscalationIntentCarriesManual(t *testing.T) {
	f := &db.DBFinding{
		ID: 42, VulnClass: "idor", Name: "越权读取他人订单",
		Summary: "换 orderId 即可读他人订单", Evidence: "GET /api/order/8821 -> 200 {\"idcard\":\"...\"}",
	}
	got := buildEscalationIntent(f, "medium")
	for _, want := range []string{
		"【扩大危害】", "#42", "medium", "越权读取他人订单", "换 orderId 即可读他人订单",
		// 手册关键段落
		"扩大危害", "【B. IDOR", "【E. SQL 注入", "【H. SSRF", "report_escalation", "保留原级别",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("升级意图缺少 %q", want)
		}
	}
}

// escalate=true 的意图必须被识别为升级任务(决定是否挂 report_escalation 工具)。
func TestIntentIsEscalation(t *testing.T) {
	esc := &db.Node{Payload: []byte(`{"summary":"x","escalate":true}`)}
	normal := &db.Node{Payload: []byte(`{"summary":"x"}`)}
	deepen := &db.Node{Payload: []byte(`{"summary":"x","source_finding_id":7}`)}
	if !agent.IntentIsEscalation(esc) {
		t.Error("escalate=true 应识别为升级任务")
	}
	if agent.IntentIsEscalation(normal) {
		t.Error("普通意图不应识别为升级任务")
	}
	if agent.IntentIsEscalation(deepen) {
		t.Error("回炉意图(只有 source_finding_id)不应识别为升级任务")
	}
	if agent.IntentIsEscalation(nil) {
		t.Error("nil 不应识别为升级任务")
	}
}

// ---- DB 支撑的行为 ----

func escalateFixture(t *testing.T) (*Server, *db.DBFinding) {
	t.Helper()
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { m.Close() })
	task, err := m.CreateTask("escalate test", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	tid, _ := strconv.ParseInt(task.ID, 10, 64)
	t.Cleanup(func() { m.pg.DeleteTask(tid) })
	// 升级是审核采纳后的动作,任务必须开着二次审核 —— 否则待审队列不会收它。
	if _, err := m.pg.Exec(`UPDATE tasks SET review_enabled=true, review_src_type='edusrc' WHERE id=$1`, tid); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	f, err := s.evidenceStore().Record(context.Background(), db.RecordFindingInput{
		TaskID: tid, ExplorationID: task.ExpID, Worker: "test",
		VulnClass: "idor", Name: "越权读取他人订单", Severity: "low",
		Summary: "换 orderId 可读他人订单", Evidence: "GET /api/order/8821 -> 200",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.pg.GetFinding(f.FindingID)
	if err != nil || got == nil {
		t.Fatalf("读回 finding 失败: %v", err)
	}
	return s, got
}

// 「每个漏洞最多升级一轮」靠 MarkFindingEscalated 的原子占位保证。
func TestMarkFindingEscalatedIsOnceOnly(t *testing.T) {
	_, f := escalateFixture(t)
	pg := (&Server{}).m
	_ = pg
	// 直接用 fixture 的 pg:重新取一次 server 里的 pg。
	s, f2 := escalateFixture(t)
	first, err := s.m.pg.MarkFindingEscalated(f2.ID, "low")
	if err != nil {
		t.Fatal(err)
	}
	if !first {
		t.Fatal("首次标记应成功")
	}
	second, err := s.m.pg.MarkFindingEscalated(f2.ID, "low")
	if err != nil {
		t.Fatal(err)
	}
	if second {
		t.Fatal("第二次标记必须失败(每个漏洞最多升级一轮)")
	}
	_ = f
}

// 升级成功:追加证据、抬升严重度、清空 review_verdict 送回复核。
func TestApplyEscalationSuccessWritesBackAndRequeues(t *testing.T) {
	s, f := escalateFixture(t)
	if _, err := s.m.pg.MarkFindingEscalated(f.ID, "low"); err != nil {
		t.Fatal(err)
	}
	// 先给一个已采纳结论,验证升级会把它清空(送回复核)。
	if err := s.m.pg.SetFindingReview(f.ID, db.FindingReview{
		Verdict: db.ReviewVerdictAccepted, Severity: "low", Reasons: "",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.m.pg.ApplyEscalationSuccess(f.ID, "critical",
		"新增证据:用他人 orderId 直接导出全部订单(含身份证号)", "[扩大危害] low→critical"); err != nil {
		t.Fatal(err)
	}
	got, err := s.m.pg.GetFinding(f.ID)
	if err != nil || got == nil {
		t.Fatal(err)
	}
	if got.Severity != "critical" {
		t.Fatalf("严重度应抬到 critical, got %s", got.Severity)
	}
	if got.EscalateStatus != db.EscalateDone {
		t.Fatalf("escalate_status 应为 done, got %s", got.EscalateStatus)
	}
	if !strings.Contains(got.Evidence, "导出全部订单") {
		t.Fatalf("证据链未追加: %s", got.Evidence)
	}
	if got.ReviewVerdict != "" {
		t.Fatalf("应清空 review_verdict 送回复核, got %q", got.ReviewVerdict)
	}
	// 送回复核后必须能被待审队列捞到。
	pend, err := s.m.pg.ListFindingsAwaitingReview(50)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range pend {
		if p.ID == f.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("升级后的漏洞应重新进入待审队列")
	}
}

// 升级只做加法:不得把级别降下来。
func TestEscalationIsAdditiveOnly(t *testing.T) {
	s, f := escalateFixture(t)
	if _, err := s.m.pg.MarkFindingEscalated(f.ID, "medium"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.m.pg.Exec(`UPDATE findings SET severity='medium' WHERE id=$1`, f.ID); err != nil {
		t.Fatal(err)
	}
	f2, _ := s.m.pg.GetFinding(f.ID)
	err := s.writeEscalationResult(context.Background(), agent.EscalationResult{
		TaskID: *f2.TaskID, FindingID: f2.ID, Success: true, Severity: "low",
		Evidence: "x", Summary: "试图降级",
	})
	if err == nil {
		t.Fatal("低于升级前的级别必须被拒绝")
	}
	if !strings.Contains(err.Error(), "只做加法") {
		t.Fatalf("错误信息应说明只做加法: %v", err)
	}
}

// 升级失败:保留原级,不改采纳结论。
func TestEscalationFailureKeepsOriginalSeverity(t *testing.T) {
	s, f := escalateFixture(t)
	if _, err := s.m.pg.MarkFindingEscalated(f.ID, "low"); err != nil {
		t.Fatal(err)
	}
	if err := s.m.pg.SetFindingReview(f.ID, db.FindingReview{
		Verdict: db.ReviewVerdictAccepted, Severity: "low",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.writeEscalationResult(context.Background(), agent.EscalationResult{
		TaskID: *f.TaskID, FindingID: f.ID, Success: false, Summary: "试过写接口,返回 403",
	}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.m.pg.GetFinding(f.ID)
	if got.EscalateStatus != db.EscalateFailed {
		t.Fatalf("应为 failed, got %s", got.EscalateStatus)
	}
	if got.Severity != "low" {
		t.Fatalf("失败必须保留原级 low, got %s", got.Severity)
	}
	if got.ReviewVerdict != db.ReviewVerdictAccepted {
		t.Fatalf("失败不得改动采纳结论, got %q", got.ReviewVerdict)
	}
	if !strings.Contains(got.ReviewNotes, "403") {
		t.Fatalf("失败原因应记入 notes: %s", got.ReviewNotes)
	}
}

// 归属与状态守卫:不能改别的任务的漏洞,也不接受不在升级流程中的写回。
func TestWriteEscalationGuards(t *testing.T) {
	s, f := escalateFixture(t)
	ctx := context.Background()

	// 未进入升级流程 → 拒绝。
	err := s.writeEscalationResult(ctx, agent.EscalationResult{
		TaskID: *f.TaskID, FindingID: f.ID, Success: true, Severity: "high", Evidence: "x", Summary: "y",
	})
	if err == nil || !strings.Contains(err.Error(), "不在升级流程") {
		t.Fatalf("未派升级就写回应被拒, got %v", err)
	}

	if _, err := s.m.pg.MarkFindingEscalated(f.ID, "low"); err != nil {
		t.Fatal(err)
	}
	// 跨任务改写 → 拒绝。
	err = s.writeEscalationResult(ctx, agent.EscalationResult{
		TaskID: *f.TaskID + 9999, FindingID: f.ID, Success: true, Severity: "high", Evidence: "x", Summary: "y",
	})
	if err == nil || !strings.Contains(err.Error(), "不属于本任务") {
		t.Fatalf("跨任务改写应被拒, got %v", err)
	}
	// 非法级别 → 拒绝。
	err = s.writeEscalationResult(ctx, agent.EscalationResult{
		TaskID: *f.TaskID, FindingID: f.ID, Success: true, Severity: "bogus", Evidence: "x", Summary: "y",
	})
	if err == nil || !strings.Contains(err.Error(), "severity 无效") {
		t.Fatalf("非法级别应被拒, got %v", err)
	}
}

// 复核保护:升级后复核判 ignored,不能把已采纳的漏洞降级/忽略。
func TestEscalatedFindingSurvivesIgnoringReReview(t *testing.T) {
	s, f := escalateFixture(t)
	ctx := context.Background()
	if _, err := s.m.pg.MarkFindingEscalated(f.ID, "low"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.m.pg.Exec(`UPDATE findings SET severity='critical', escalate_status=$2 WHERE id=$1`,
		f.ID, db.EscalateDone); err != nil {
		t.Fatal(err)
	}
	cur, _ := s.m.pg.GetFinding(f.ID)
	if err := s.applyFindingReview(ctx, cur, db.FindingReview{
		Verdict: db.ReviewVerdictIgnored, Reasons: "升级证据不足",
	}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.m.pg.GetFinding(f.ID)
	if got.ReviewVerdict != db.ReviewVerdictAccepted {
		t.Fatalf("升级复核未通过不得改为 ignored, got %q", got.ReviewVerdict)
	}
	if got.Severity != "low" {
		t.Fatalf("应回退到升级前的 low, got %s", got.Severity)
	}
	if got.Status == db.FindingIgnored {
		t.Fatal("已采纳漏洞不得被置为 ignored")
	}
	if !strings.Contains(got.ReviewNotes, "保留升级前的严重度") {
		t.Fatalf("应留下保留说明: %s", got.ReviewNotes)
	}
}

// 端到端:审核采纳一个 low 漏洞 → 自动派升级意图(payload escalate=true)并唤醒任务。
func TestAcceptedLowFindingDispatchesEscalationIntent(t *testing.T) {
	s, f := escalateFixture(t)
	ctx := context.Background()
	if err := s.applyFindingReview(ctx, f, db.FindingReview{
		Verdict: db.ReviewVerdictAccepted, Severity: "low", Score: fptr(3),
	}); err != nil {
		t.Fatal(err)
	}
	got, err := s.m.pg.GetFinding(f.ID)
	if err != nil || got == nil {
		t.Fatal(err)
	}
	if got.EscalatedAt == nil || got.EscalateStatus != db.EscalateDispatched {
		t.Fatalf("应已派升级, got status=%q escalated_at=%v", got.EscalateStatus, got.EscalatedAt)
	}
	if got.BaseSeverity != "low" {
		t.Fatalf("base_severity 应记录升级前级别, got %q", got.BaseSeverity)
	}
	// 意图必须带 escalate=true 且含手册。
	var n int
	if err := s.m.pg.QueryRow(`SELECT count(*) FROM exploration_nodes
		WHERE exploration_id=(SELECT exploration_id FROM tasks WHERE id=$1)
		  AND kind='intent' AND payload->>'escalate' = 'true'`, *f.TaskID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("应恰好建 1 条升级意图, got %d", n)
	}
	var payload string
	if err := s.m.pg.QueryRow(`SELECT payload::text FROM exploration_nodes
		WHERE exploration_id=(SELECT exploration_id FROM tasks WHERE id=$1)
		  AND kind='intent' AND payload->>'escalate' = 'true' LIMIT 1`, *f.TaskID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(payload, "扩大危害") || !strings.Contains(payload, "report_escalation") {
		t.Fatalf("升级意图正文不完整: %.200s", payload)
	}
	// 再审一次不得重复派单(每个漏洞一轮)。
	if err := s.applyFindingReview(ctx, got, db.FindingReview{
		Verdict: db.ReviewVerdictAccepted, Severity: "low", Score: fptr(3),
	}); err != nil {
		t.Fatal(err)
	}
	var n2 int
	if err := s.m.pg.QueryRow(`SELECT count(*) FROM exploration_nodes
		WHERE exploration_id=(SELECT exploration_id FROM tasks WHERE id=$1)
		  AND kind='intent' AND payload->>'escalate' = 'true'`, *f.TaskID).Scan(&n2); err != nil {
		t.Fatal(err)
	}
	if n2 != 1 {
		t.Fatalf("重复审核不得重复派单, got %d", n2)
	}
}

// high/critical 不派升级。
func TestHighSeverityNotEscalated(t *testing.T) {
	s, f := escalateFixture(t)
	ctx := context.Background()
	if err := s.applyFindingReview(ctx, f, db.FindingReview{
		Verdict: db.ReviewVerdictAccepted, Severity: "high", Score: fptr(8),
	}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.m.pg.GetFinding(f.ID)
	if got.EscalatedAt != nil {
		t.Fatal("high 级别不应派升级")
	}
}

// 唤醒失败必须与「意图没建成」区分开:意图已落库时保持 dispatched,
// 否则 worker 真跑出来的升级结果会被状态守卫拒收(真机实测踩到过)。
func TestEscalationWakeFailureIsDistinguishable(t *testing.T) {
	if escalationIntentCreated(fmt.Errorf("建升级意图: 数据库不可用")) {
		t.Fatal("普通错误不应被当成「意图已建」")
	}
	wrapped := fmt.Errorf("%w: intent=99: task lifecycle changed before admission", errEscalationIntentCreated)
	if !escalationIntentCreated(wrapped) {
		t.Fatal("唤醒失败(哨兵)应被识别为「意图已建」")
	}
}

// failed 是 worker 自己上报的失败终态:同一轮先报失败再报成功属自相矛盾,
// 不该被采纳(否则「每漏洞一轮」只约束派单、没约束写回)。
// 注意:「派单时唤醒失败」不会再产生 failed —— 那条路径已改为完整回滚占位
// (ClearFindingEscalation),见 TestEscalationWakeFailureIsDistinguishable。
func TestFailedEscalationRejectsLaterSuccess(t *testing.T) {
	s, f := escalateFixture(t)
	ctx := context.Background()
	if _, err := s.m.pg.MarkFindingEscalated(f.ID, "medium"); err != nil {
		t.Fatal(err)
	}
	// worker 上报「打不动」→ failed 终态。
	if err := s.writeEscalationResult(ctx, agent.EscalationResult{
		TaskID: *f.TaskID, FindingID: f.ID, Success: false, Summary: "试过写接口,返回 403",
	}); err != nil {
		t.Fatal(err)
	}
	cur, _ := s.m.pg.GetFinding(f.ID)
	if cur.EscalateStatus != db.EscalateFailed {
		t.Fatalf("前置状态应为 failed, got %s", cur.EscalateStatus)
	}
	// 同一轮再报成功 → 必须拒绝。
	err := s.writeEscalationResult(ctx, agent.EscalationResult{
		TaskID: *cur.TaskID, FindingID: cur.ID, Success: true, Severity: "high",
		Evidence: "x", Summary: "又成功了",
	})
	if err == nil || !strings.Contains(err.Error(), "不在升级流程中") {
		t.Fatalf("failed 后不得再采纳成功上报, got %v", err)
	}
	// 失败终态必须保留原级。
	after, _ := s.m.pg.GetFinding(f.ID)
	if after.Severity != "low" {
		t.Fatalf("失败应保留原级 low, got %s", after.Severity)
	}
}

// 升级失败不得篡改 severity 列(base_severity 是审核级别,severity 列可能是
// worker 自评的更高值 —— 早期实现会把 critical 悄悄写成 low)。
func TestEscalationFailureDoesNotTouchSeverityColumn(t *testing.T) {
	s, f := escalateFixture(t)
	if _, err := s.m.pg.Exec(`UPDATE findings SET severity='critical' WHERE id=$1`, f.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.m.pg.MarkFindingEscalated(f.ID, "low"); err != nil {
		t.Fatal(err)
	}
	if err := s.writeEscalationResult(context.Background(), agent.EscalationResult{
		TaskID: *f.TaskID, FindingID: f.ID, Success: false, Summary: "打不动",
	}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.m.pg.GetFinding(f.ID)
	if got.Severity != "critical" {
		t.Fatalf("失败不得改 severity 列(应保持 critical), got %s", got.Severity)
	}
}

// 升级成功必须把 status 从 ignored 拉回来,否则待审队列过滤掉它,
// 「已送回复核」永远不生效。
func TestEscalationSuccessRevivesIgnoredFindingForReview(t *testing.T) {
	s, f := escalateFixture(t)
	ctx := context.Background()
	if _, err := s.m.pg.MarkFindingEscalated(f.ID, "medium"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.m.pg.SetFindingStatusWithNotify(ctx, f.ID, db.FindingIgnored); err != nil {
		t.Fatal(err)
	}
	if err := s.writeEscalationResult(ctx, agent.EscalationResult{
		TaskID: *f.TaskID, FindingID: f.ID, Success: true, Severity: "high",
		Evidence: "升级证据:越权写打通到批量篡改", Summary: "medium→high",
	}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.m.pg.GetFinding(f.ID)
	if got.Status == db.FindingIgnored {
		t.Fatal("升级后 status 不应仍是 ignored(否则永远进不了待审队列)")
	}
	pend, err := s.m.pg.ListFindingsAwaitingReview(50)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range pend {
		if p.ID == f.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("升级后的 ignored 漏洞必须重新进入待审队列")
	}
}

// 从未派过升级的漏洞,不得被 report_escalation 改写(普通 worker 无此能力)。
func TestNeverEscalatedFindingRejectsWrite(t *testing.T) {
	s, f := escalateFixture(t)
	err := s.writeEscalationResult(context.Background(), agent.EscalationResult{
		TaskID: *f.TaskID, FindingID: f.ID, Success: true, Severity: "critical",
		Evidence: "x", Summary: "y",
	})
	if err == nil || !strings.Contains(err.Error(), "不在升级流程中") {
		t.Fatalf("未派升级的漏洞应拒绝改写, got %v", err)
	}
}

// ---- 人工发起「扩大危害」(POST /findings/{id}/escalate) ----

func escalateCall(t *testing.T, s *Server, id int64, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/exploration/findings/x/escalate", strings.NewReader(body))
	req.SetPathValue("id", strconv.FormatInt(id, 10))
	w := httptest.NewRecorder()
	s.escalateFindingManual(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w, out
}

// 人工发起:不受 severity/审核状态限制,但同样派一条 escalate=true 的意图并占位。
func TestManualEscalateDispatchesIntent(t *testing.T) {
	s, f := escalateFixture(t)
	// 刻意不审核、不设 low/medium —— 人工路径不看这些。
	w, out := escalateCall(t, s, f.ID, `{"notes":"优先试把读接口换成写接口"}`)
	if w.Code != 200 {
		t.Fatalf("人工升级应成功, got %d %s", w.Code, w.Body.String())
	}
	if out["intent_id"] == nil || out["intent_id"] == "" {
		t.Fatalf("应返回 intent_id, got %+v", out)
	}
	got, err := s.m.pg.GetFinding(f.ID)
	if err != nil || got == nil {
		t.Fatal(err)
	}
	if got.EscalatedAt == nil || got.EscalateStatus != db.EscalateDispatched {
		t.Fatalf("应已占位, got status=%q escalated_at=%v", got.EscalateStatus, got.EscalatedAt)
	}
	if got.BaseSeverity != "low" {
		t.Fatalf("base_severity 应为当前级别 low, got %q", got.BaseSeverity)
	}
	// 意图必须带 escalate=true + 手册 + 人工补充方向。
	var payload string
	if err := s.m.pg.QueryRow(`SELECT payload::text FROM exploration_nodes
		WHERE exploration_id=(SELECT exploration_id FROM tasks WHERE id=$1)
		  AND kind='intent' AND payload->>'escalate'='true' LIMIT 1`, *f.TaskID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"扩大危害", "report_escalation", "人工补充的升级方向", "读接口换成写接口"} {
		if !strings.Contains(payload, want) {
			t.Errorf("人工升级意图缺少 %q", want)
		}
	}
}

// 人工发起也遵守「每个漏洞最多一轮」。
func TestManualEscalateIsOnceOnly(t *testing.T) {
	s, f := escalateFixture(t)
	if w, _ := escalateCall(t, s, f.ID, `{}`); w.Code != 200 {
		t.Fatalf("首次应成功, got %d %s", w.Code, w.Body.String())
	}
	w, _ := escalateCall(t, s, f.ID, `{}`)
	if w.Code != 409 {
		t.Fatalf("重复发起应 409, got %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "最多一轮") {
		t.Fatalf("错误信息应说明最多一轮: %s", w.Body.String())
	}
}

// 边界:漏洞不存在 / 无节点 / id 非法。
func TestManualEscalateGuards(t *testing.T) {
	s, f := escalateFixture(t)
	if w, _ := escalateCall(t, s, 99999999, `{}`); w.Code != 404 {
		t.Fatalf("不存在的漏洞应 404, got %d", w.Code)
	}
	if w, _ := escalateCall(t, s, 0, `{}`); w.Code != 400 {
		t.Fatalf("非法 id 应 400, got %d", w.Code)
	}
	// 去掉 node_id -> 意图无处锚定,应 409。
	if _, err := s.m.pg.Exec(`UPDATE findings SET node_id=NULL WHERE id=$1`, f.ID); err != nil {
		t.Fatal(err)
	}
	if w, _ := escalateCall(t, s, f.ID, `{}`); w.Code != 409 {
		t.Fatalf("无节点应 409, got %d %s", w.Code, w.Body.String())
	}
	// 超长补充说明应 400。
	other, err := s.evidenceStore().Record(context.Background(), db.RecordFindingInput{
		TaskID: *f.TaskID, ExplorationID: 0, Worker: "test", VulnClass: "x", Name: "y", Severity: "low",
	}, nil)
	if err == nil && other != nil {
		long := strings.Repeat("a", 4001)
		if w, _ := escalateCall(t, s, other.FindingID, `{"notes":"`+long+`"}`); w.Code != 400 {
			t.Fatalf("超长 notes 应 400, got %d", w.Code)
		}
	}
}

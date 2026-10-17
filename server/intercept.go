package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/guard"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/artex/llmpool"
	"github.com/Autumn-27/artex/llmrec"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

// judgeWorkerLane is the usage-ledger "worker" label for intercept fallback-judge
// calls, so judge spend can be queried apart from the worker/planner/main lanes.
const judgeWorkerLane = "judge"

// chatGuard returns a guard wired with the manager's interceptor, used for chat
// conversations. Called once per applyLLM so a new LLM config always gets a fresh guard.
func (s *Server) chatGuard() *guard.Guard {
	return guard.NewWithInterceptor(s.m.interceptor)
}

// settingRoEEnforcement is the settings 键 for the RoE scope-enforcement mode:
// "off" | "warn"(默认) | "strict". See guard.RoEConfig.
const settingRoEEnforcement = "roe_enforcement"

// agentGuard returns a fresh guard wired with the manager's interceptor, used
// for chat conversations and for the planner / main-agent. Each agent build
// gets its own guard instance so a new LLM config never shares audit state with
// the old one.
func (s *Server) agentGuard() *guard.Guard {
	g := guard.NewWithInterceptor(s.m.interceptor)
	g.SetRoE(newRoEConfig(s.m.pg))
	g.SetIsolation(newIsolationConfig(s.m.dir)) // 跨任务数据隔离:禁止读兄弟任务的 tasks/transcripts/drafts
	g.SetEgress(s.m.egress)                     // 批 5 B2 出口审查:chat/planner/mainagent 同样过敏感指纹拦截
	return g
}

// newIsolationConfig wires the guard's per-task data isolation check against the
// server's data root. taskID comes from the same run attribution as RoE, so a
// non-task run (chat) is skipped by the check itself.
func newIsolationConfig(dataDir string) guard.IsolationConfig {
	return guard.IsolationConfig{
		DataRoot: func() string { return dataDir },
		TaskIDOf: func(ctx context.Context) int64 {
			return agent.RunInfoFrom(ctx).TaskID
		},
	}
}

// newRoEConfig builds the guard RoE wiring backed by pg: mode from the
// roe_enforcement settings 键, scope rules lazily read from task_scope per call
// (范围随 add_task_scope 即时生效,guard 不缓存)。
func newRoEConfig(pg *db.DB) guard.RoEConfig {
	return guard.RoEConfig{
		Mode: func() string {
			v, _, _ := pg.GetSetting(settingRoEEnforcement)
			return v
		},
		Scope: func(taskID int64) []guard.ScopeRule {
			rows, err := pg.Assets().ListTaskScope(taskID)
			if err != nil {
				// 读取失败按未登记范围处理(Unknown → 放行),与覆盖度 fail-open 一致。
				return nil
			}
			return scopeRulesFromRows(rows)
		},
		TaskIDOf: func(ctx context.Context) int64 {
			return agent.RunInfoFrom(ctx).TaskID
		},
	}
}

// scopeRulesFromRows normalizes db task_scope rows into guard scope rules:
// root_domain/subdomain → domain;ip(/32、/128 网段)与 cidr → cidr;icp 原样;
// company/keyword 无可匹配的主机值,跳过(keyword 本来就是死规则)。
func scopeRulesFromRows(rows []db.TaskScope) []guard.ScopeRule {
	out := make([]guard.ScopeRule, 0, len(rows))
	for _, r := range rows {
		switch r.Kind {
		case "root_domain", "subdomain":
			if r.Domain != "" {
				out = append(out, guard.ScopeRule{Kind: "domain", Value: r.Domain})
			}
		case "ip", "cidr":
			if r.Net != "" {
				out = append(out, guard.ScopeRule{Kind: "cidr", Value: r.Net})
			}
		case "icp":
			if r.Value != "" {
				out = append(out, guard.ScopeRule{Kind: "icp", Value: r.Value})
			}
		}
	}
	return out
}

// wireInterceptReviewer installs the LLM fallback judge into the interceptor. The
// judge runs only on tool calls that matched no rule (see intercept.Judge). It
// resolves the configured judge profile (0 → active/default), builds a provider,
// runs a one-shot JSON classification with an explanation for every verdict.
func (s *Server) wireInterceptReviewer() {
	s.m.interceptor.SetReviewer(func(ctx context.Context, profileID int64, prompt string, input intercept.ReviewInput) (intercept.Decision, error) {
		if profileID == 0 {
			if p, err := s.m.pg.ActiveProfile(); err == nil && p != nil {
				profileID = p.ID
			}
		}
		if profileID == 0 {
			return intercept.Decision{}, fmt.Errorf("未配置可用的裁判模型")
		}
		prov, cfg, ok := s.providerForProfile(profileID)
		if !ok {
			return intercept.Decision{ProfileID: profileID}, fmt.Errorf("裁判模型 profile %d 不可用", profileID)
		}
		// Tag this call's usage as the "judge" lane so the config page can report
		// how much the fallback approval has spent, separate from model profiles.
		ctx = llmrec.WithWorker(ctx, judgeWorkerLane)
		// 裁判走的是 provider 的裸 Stream 路径:tool hook 的 ctx 通常已带 worker/planner
		// 的 session id(transcript.WithSessionID),但目标拆解 / 压缩等一次性调用没有。
		// 某些网关(profile 的 session_header_key / session_body_field 机制)缺少会话
		// 标识会直接 400,所以这里兜底补一个一次性 id。
		if transcript.SessionIDFrom(ctx) == "" {
			ctx = transcript.WithSessionID(ctx, "judge-"+transcript.NewSessionID())
		}
		dec, err := judgeWithRetry(ctx, prov, profileID, prompt, input, s.m.interceptor.GetJudgeConfig().RetryAttempts)
		if err == nil {
			return dec, nil
		}
		// 裁判是最后一道门:单个上游故障不该直接变成「按失败策略 deny」。主配置这一轮
		// 全失败后,按轮询链换到下一个可用配置再判一轮(链上只有它自己时保持原语义)。
		if next := s.judgeFailoverMember(profileID, prov, cfg); next != nil {
			log.Printf("[judge] 裁判配置 %d 失败(%s),故障转移到 %q(%s)",
				profileID, classifyJudgeErr(err), next.Name, next.Model)
			if d2, err2 := judgeWithRetry(ctx, next.Prov, next.ID, prompt, input, s.m.interceptor.GetJudgeConfig().RetryAttempts); err2 == nil {
				return d2, nil
			}
		}
		return dec, err
	})
}

// judgeFailoverMember picks the next member of the LLM failover chain to judge
// with after headID already failed this round. Returns nil when failover is off,
// when the chain has no other usable member, or when the only candidate is the
// head itself (in which case the caller keeps the original failure semantics).
func (s *Server) judgeFailoverMember(headID int64, headProv llm.Provider, headCfg agent.Config) *llmpool.Member {
	if s == nil || s.m == nil {
		return nil
	}
	pool := s.poolChain(headID, headProv, headCfg)
	if pool == nil {
		return nil
	}
	for _, m := range pool.Members() {
		if m.ID != headID {
			return m
		}
	}
	return nil
}

// judgeWithRetry runs the fallback-judge completion and returns the first
// parseable verdict. Models routinely drift on the mandated explanation
// separator (observed: "。" instead of "；" on ~60% of live replies), which the
// output contract asks for literally. A corrective re-ask recovers nearly all
// of them. The retry only restates the output format; it never reclassifies, so
// it cannot turn a DENY into an allow (see intercept.ParseVerdict, which
// validates the decision and the explanation independently).
//
// retries is the number of extra attempts after the first; 0 disables retries.
// A canceled or deadline-exceeded context stops the loop immediately (it cannot
// recover), while transient upstream errors and unparseable replies are retried.
func judgeWithRetry(ctx context.Context, prov llm.Provider, profileID int64, prompt string, input intercept.ReviewInput, retries int) (intercept.Decision, error) {
	attempts := 1 + retries
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			// Back off between attempts. The dominant live failure is the relay
			// throttling a burst of judge calls (HTTP 400 "no valid ... subscription",
			// 429, 5xx); firing the retry immediately just re-hits the same wall, so
			// each retry waits longer (capped, jittered) before trying again.
			if err := sleepJudgeBackoff(ctx, attempt); err != nil {
				lastErr = err
				break
			}
		}
		attemptPrompt := prompt
		if attempt > 0 {
			attemptPrompt = prompt + judgeRepairInstruction
		}
		text, err := reviewCompletion(ctx, prov, attemptPrompt, input)
		if err != nil {
			lastErr = err
			if !isJudgeRetryableErr(err) {
				break
			}
			continue
		}
		v := intercept.ParseVerdict(text)
		if v.Action == "" {
			// 原始返回此前完全不可见(llm_records 默认关闭),线上只能看到
			// 「格式无效」四个字,无法判断是截断、串格式还是模型跑偏。打一条带上
			// 返回原文预览的日志,让这类失败可复盘。
			log.Printf("[judge] 第 %d/%d 次裁决无法解析(返回 %d 字符): %s",
				attempt+1, attempts, len(text), judgeReplyPreview(text))
			lastErr = fmt.Errorf("模型裁决格式无效，必须包含裁决、实际操作、成功后的后果和命中规则")
			continue // an unparseable reply is always worth a corrective re-ask
		}
		return intercept.Decision{Action: v.Action, Message: v.Reason, ProfileID: profileID}, nil
	}
	log.Printf("[judge] 连续 %d 次未取得有效裁决: %s", attempts, classifyJudgeErr(lastErr))
	return intercept.Decision{ProfileID: profileID}, finalJudgeErr(attempts, lastErr)
}

// judgeReplyPreview renders a bounded single-line preview of a raw judge reply for
// the log (maxJudgeReplyPreview bytes, then a truncation note with the full size).
func judgeReplyPreview(text string) string {
	s := strings.Join(strings.Fields(text), " ")
	if len(s) <= maxJudgeReplyPreview {
		return s
	}
	return s[:maxJudgeReplyPreview] + "…(截断,原文 " + strconv.Itoa(len(s)) + " 字符)"
}

// maxJudgeReplyPreview bounds the raw judge reply echoed into the server log.
const maxJudgeReplyPreview = 400

// judgeRepairInstruction is appended to the judge system prompt on a retry
// after an unparseable reply. It restates the mandated output format without
// changing the classification task, so a retry can only repair formatting — it
// cannot flip a verdict.
const judgeRepairInstruction = "\n\n# 上一次输出不合规，请重试\n上一次回复不是合规的 JSON 裁决。请重新输出且只输出一个 JSON 对象：第一个字符是 {、最后一个字符是 }；恰好含 decision 和 comment 两个字符串字段。comment 严格为三段、顺序固定，用全角分号连接：实际操作：…；成功后的后果：…；命中规则：…（不要用句号/逗号/换行分隔，三段都不能为空）。"

// Judge retry backoff bounds. The first retry waits judgeBackoffBase; each
// further retry doubles it, capped at judgeBackoffMax. The delay is jittered
// ±20% so many concurrent judges do not retry in lockstep.
var (
	judgeBackoffBase = 700 * time.Millisecond
	judgeBackoffMax  = 8 * time.Second
)

// sleepJudgeBackoff waits before the (attempt+1)-th judge call, where attempt is
// the zero-based retry index about to be made (attempt >= 1). It never spends
// more than a third of the context's remaining time sleeping, so backoff alone
// cannot eat the retry budget, and returns the context error if the context ends
// while waiting.
func sleepJudgeBackoff(ctx context.Context, attempt int) error {
	d := judgeBackoffBase
	for i := 1; i < attempt && d < judgeBackoffMax; i++ {
		d *= 2
	}
	if d > judgeBackoffMax {
		d = judgeBackoffMax
	}
	if dl, ok := ctx.Deadline(); ok {
		remaining := time.Until(dl)
		if remaining <= 0 {
			return ctx.Err()
		}
		if d > remaining/3 {
			d = remaining / 3
		}
	}
	if span := int64(d) / 5; span > 0 {
		d += time.Duration(rand.Int64N(2*span+1)) - time.Duration(span)
	}
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// judgeHTTPStatus extracts the HTTP status a provider reports in its error
// string (e.g. "openai: status 400: {...}"). 0 means no status was reported
// (transport failure, empty reply, ...).
func judgeHTTPStatus(err error) int {
	if err == nil {
		return 0
	}
	msg := err.Error()
	i := strings.Index(msg, "status ")
	if i < 0 {
		return 0
	}
	j := i + len("status ")
	k := j
	for k < len(msg) && msg[k] >= '0' && msg[k] <= '9' {
		k++
	}
	if k == j {
		return 0
	}
	n, convErr := strconv.Atoi(msg[j:k])
	if convErr != nil {
		return 0
	}
	return n
}

// judgeTransientMarkers are substrings that mark a nominally client-side status
// (400) as actually transient: the relay throttling a burst, or an upstream
// account whose quota/subscription lapsed, recovers on its own — unlike a
// genuinely malformed request.
var judgeTransientMarkers = []string{
	"subscription", "agentplan", "quota", "rate limit", "rate-limit",
	"too many requests", "concurrency", "overloaded", "temporarily", "try again",
	"额度", "订阅", "并发", "限流", "繁忙", "稍后重试",
}

func hasJudgeTransientMarker(msg string) bool {
	lower := strings.ToLower(msg)
	for _, m := range judgeTransientMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

// isJudgeRetryableErr reports whether a judge call error is worth another
// attempt.
//
//   - A canceled or deadline-exceeded context will not recover: stop at once.
//   - A reported 5xx, 408/409/425/429, or a transport error (no status) is
//     transient: retry.
//   - A 400 is retried only when its body carries a transient marker (relay
//     throttling / lapsed upstream quota); a genuinely malformed request is not.
//   - Every other 4xx (401/403/404/422, ...) is permanent: do not retry.
func isJudgeRetryableErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	switch code := judgeHTTPStatus(err); {
	case code == 0:
		return true // transport failure / empty reply
	case code == 408, code == 409, code == 425, code == 429:
		return true
	case code >= 500:
		return true
	case code == 400:
		return hasJudgeTransientMarker(err.Error())
	default:
		return false
	}
}

// classifyJudgeErr turns a judge error into a short, log-friendly label.
func classifyJudgeErr(err error) string {
	if err == nil {
		return "未知错误"
	}
	if errors.Is(err, context.Canceled) {
		return "调用已取消"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "调用超时"
	}
	msg := err.Error()
	if hasJudgeTransientMarker(msg) && judgeHTTPStatus(err) == 400 {
		return "上游账号额度/订阅不可用(400)"
	}
	switch {
	case strings.Contains(msg, "status 429"):
		return "上游限流(429)"
	case strings.Contains(msg, "status 5"):
		return "上游服务错误(5xx)"
	}
	return msg
}

// finalJudgeErr wraps the last judge error after every attempt failed. Judge()
// turns this into the configured fail_action fallback (deny by default).
func finalJudgeErr(attempts int, last error) error {
	return fmt.Errorf("裁判模型连续 %d 次未返回有效裁决，按失败策略处理: %s", attempts, classifyJudgeErr(last))
}

func reviewCompletion(ctx context.Context, prov llm.Provider, prompt string, input intercept.ReviewInput) (string, error) {
	user, err := json.Marshal(input)
	if err != nil {
		return "", err
	}
	// 整个 ReviewInput(工具参数/历史/任务背景)都含目标侧可控文本,按不可信数据
	// 包裹后再喂给裁判模型,防止其中的注入文本被当成指令。
	return streamCollectText(ctx, prov, prompt, agent.WrapUntrustedData("tool-input", string(user)))
}

// streamCollectText runs a single non-streaming-style completion (thinking off,
// low temperature, bounded output) and returns the concatenated text. The
// budget includes the explanation and complete closing JSON delimiters.
//
// judgeMaxTokens must be large enough for the mandated three-part explanation:
// at 1024 the longest live verdicts were cut mid-JSON (1930 of 56018 judge calls
// in one 30h window hit the old ceiling exactly), which surfaced as
// "模型裁决格式无效" and then as a fail-action deny.
const judgeMaxTokens = 2048

func streamCollectText(ctx context.Context, prov llm.Provider, system, user string) (string, error) {
	temp := 0.0
	req := llm.CompletionRequest{
		System:      []string{system},
		Messages:    []llm.Message{llm.UserText(user)},
		MaxTokens:   judgeMaxTokens,
		Temperature: &temp,
		Thinking:    "disabled",
	}
	var sb strings.Builder
	for ev, err := range prov.Stream(ctx, req) {
		if err != nil {
			return "", err
		}
		if ev.Type == llm.SETextDelta {
			sb.WriteString(ev.Text)
		}
	}
	return sb.String(), nil
}

// --- intercept rule CRUD ---

func (s *Server) interceptListRules(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	rules, err := pg.ListInterceptRules()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if rules == nil {
		rules = []db.InterceptRule{}
	}
	writeJSON(w, 200, map[string]any{"rules": rules})
}

func (s *Server) interceptCreateRule(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req interceptRuleReq
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := validateInterceptRuleReq(req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	rule, err := pg.CreateInterceptRule(req.Name, req.MatchTarget, req.MatchType, req.Pattern, req.Action, req.Message, req.Priority, req.Enabled, req.TimeoutEnabled, req.TimeoutSeconds, req.TimeoutAction)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.m.interceptor.Invalidate()
	writeJSON(w, 200, rule)
}

func (s *Server) interceptUpdateRule(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "bad rule id")
		return
	}
	var req interceptRuleReq
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := validateInterceptRuleReq(req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	rule, err := pg.UpdateInterceptRule(id, req.Name, req.MatchTarget, req.MatchType, req.Pattern, req.Action, req.Message, req.Priority, req.Enabled, req.TimeoutEnabled, req.TimeoutSeconds, req.TimeoutAction)
	if err != nil {
		if errors.Is(err, db.ErrBuiltinRule) {
			writeErr(w, 400, err.Error())
			return
		}
		writeErr(w, 500, err.Error())
		return
	}
	s.m.interceptor.Invalidate()
	writeJSON(w, 200, rule)
}

func (s *Server) interceptDeleteRule(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "bad rule id")
		return
	}
	if err := pg.DeleteInterceptRule(id); err != nil {
		if errors.Is(err, db.ErrBuiltinRule) {
			writeErr(w, 400, err.Error())
			return
		}
		writeErr(w, 500, err.Error())
		return
	}
	s.m.interceptor.Invalidate()
	writeJSON(w, 200, map[string]any{"deleted": id})
}

func (s *Server) interceptToggleRule(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "bad rule id")
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := pg.ToggleInterceptRule(id, req.Enabled); err != nil {
		if errors.Is(err, db.ErrBuiltinRule) {
			writeErr(w, 400, err.Error())
			return
		}
		writeErr(w, 500, err.Error())
		return
	}
	s.m.interceptor.Invalidate()
	writeJSON(w, 200, map[string]any{"ok": true, "enabled": req.Enabled})
}

// --- pending (ask) ---

func (s *Server) interceptListPending(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	pending, err := pg.ListPendingIntercepts()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if pending == nil {
		pending = []db.InterceptPending{}
	}
	writeJSON(w, 200, map[string]any{"pending": pending})
}

func (s *Server) interceptGetOne(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "bad pending id")
		return
	}
	p, err := pg.GetInterceptPending(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if p == nil {
		writeErr(w, 404, "not found")
		return
	}
	writeJSON(w, 200, p)
}

func (s *Server) interceptListTaskItems(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	taskID := r.PathValue("taskID")
	if taskID == "" {
		writeErr(w, 400, "bad task id")
		return
	}
	q := r.URL.Query()
	filter, err := interceptFilterParams(q)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if q.Get("page") == "" && q.Get("size") == "" && filter == (db.InterceptApprovalFilter{}) {
		items, err := pg.ListTaskIntercepts(taskID)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		if items == nil {
			items = []db.InterceptApprovalRow{}
		}
		writeJSON(w, 200, map[string]any{"items": items, "total": len(items)})
		return
	}
	page, size := interceptPageParams(q)
	items, total, err := pg.ListTaskInterceptsPage(taskID, page, size, filter)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if items == nil {
		items = []db.InterceptApprovalRow{}
	}
	writeJSON(w, 200, map[string]any{"items": items, "total": total, "page": page, "page_size": size})
}

func (s *Server) interceptHistory(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	q := r.URL.Query()
	filter, err := interceptFilterParams(q)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if q.Get("page") == "" && q.Get("size") == "" && filter == (db.InterceptApprovalFilter{}) {
		items, err := pg.ListAllIntercepts(200)
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		if items == nil {
			items = []db.InterceptApprovalRow{}
		}
		writeJSON(w, 200, map[string]any{"items": items, "total": len(items)})
		return
	}
	page, size := interceptPageParams(q)
	items, total, err := pg.ListAllInterceptsPage(page, size, filter)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if items == nil {
		items = []db.InterceptApprovalRow{}
	}
	writeJSON(w, 200, map[string]any{"items": items, "total": total, "page": page, "page_size": size})
}

func interceptFilterParams(q url.Values) (db.InterceptApprovalFilter, error) {
	filter := db.InterceptApprovalFilter{Status: q.Get("status"), DecisionSource: q.Get("decision_source")}
	switch filter.Status {
	case "", "pending", "allowed", "denied", "timeout":
	default:
		return filter, fmt.Errorf("status 必须是 pending、allowed、denied 或 timeout")
	}
	switch filter.DecisionSource {
	case "", "model", "rule", "builtin", "unknown", "aggressive", "aggressive_bypass", "auto_allow":
	default:
		return filter, fmt.Errorf("decision_source 必须是 model、rule、builtin、unknown、aggressive、aggressive_bypass 或 auto_allow")
	}
	return filter, nil
}

func interceptPageParams(q url.Values) (int, int) {
	page := atoiDefault(q.Get("page"), 1)
	size := atoiDefault(q.Get("size"), 20)
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 20
	}
	if size > 100 {
		size = 100
	}
	return page, size
}

func (s *Server) interceptDecide(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "bad pending id")
		return
	}
	var req struct {
		Decision string `json:"decision"` // "allowed" | "denied"
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.Decision != "allowed" && req.Decision != "denied" {
		writeErr(w, 400, "decision 必须是 allowed 或 denied")
		return
	}
	if err := s.m.interceptor.Decide(id, req.Decision == "allowed"); err != nil {
		if errors.Is(err, intercept.ErrAlreadyDecided) {
			writeErr(w, 409, err.Error())
			return
		}
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// --- guard auto-allow (一键放行) ---

// guardAutoAllowGet returns the current auto-allow status, including the
// remaining validity seconds. Expiry is enforced lazily on read.
func (s *Server) guardAutoAllowGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.m.interceptor.AutoAllowStatus())
}

// guardAutoAllowSet enables/disables the one-click auto-allow switch. When
// enabling, hours 夹逼到 {2,4,8};when disabling, hours is ignored.
func (s *Server) guardAutoAllowSet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
		Hours   int  `json:"hours"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := s.m.interceptor.SetAutoAllow(req.Enabled, req.Hours); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, s.m.interceptor.AutoAllowStatus())
}

// --- tool-config (全局工具拦截范围) ---

// interceptGetToolConfig returns the list of tool names that are currently
// configured to enter the intercept rule system.
func (s *Server) interceptGetToolConfig(w http.ResponseWriter, r *http.Request) {
	tools, err := s.m.interceptor.GetEnabledTools()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"enabled_tools": tools})
}

// interceptSetToolConfig replaces the list of tool names that should enter
// the intercept rule system.
func (s *Server) interceptSetToolConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		EnabledTools []string `json:"enabled_tools"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.EnabledTools == nil {
		req.EnabledTools = []string{}
	}
	if err := s.m.interceptor.SetEnabledTools(req.EnabledTools); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// --- LLM fallback judge config (全局模型兜底) ---

// interceptGetJudgeConfig returns the resolved judge configuration. Prompt is the
// effective prompt (built-in template when unset), so the UI can prefill it.
func (s *Server) interceptGetJudgeConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.m.interceptor.GetJudgeConfig())
}

// interceptSetJudgeConfig persists the judge configuration.
func (s *Server) interceptSetJudgeConfig(w http.ResponseWriter, r *http.Request) {
	var req intercept.JudgeConfig
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	switch req.FailAction {
	case "allow", "ask", "deny":
	default:
		writeErr(w, 400, "fail_action 必须是 allow、ask 或 deny")
		return
	}
	switch req.AskTimeoutAction {
	case "allow", "deny":
	default:
		writeErr(w, 400, "ask_timeout_action 必须是 allow 或 deny")
		return
	}
	if err := s.m.interceptor.SetJudgeConfig(req); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// interceptGetMode returns the active interception chain. judge_available tells
// the UI whether pure-model mode can be selected at all (it needs a judge).
func (s *Server) interceptGetMode(w http.ResponseWriter, r *http.Request) {
	ic := s.m.interceptor
	writeJSON(w, 200, map[string]any{
		"mode":            ic.RuleMode(),
		"judge_available": ic.GetJudgeConfig().Enabled,
	})
}

// interceptSetMode switches between rule-first and pure-model review. Pure-model
// mode is rejected while no judge is enabled: without rules AND without a judge
// the platform would have no decision layer at all.
func (s *Server) interceptSetMode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Mode string `json:"mode"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	switch req.Mode {
	case intercept.RuleModeRules, intercept.RuleModeJudgeOnly:
	default:
		writeErr(w, 400, "mode 必须是 rules 或 judge_only")
		return
	}
	if err := s.m.interceptor.SetRuleMode(req.Mode); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "mode": s.m.interceptor.RuleMode()})
}

// interceptJudgeUsage returns the fallback judge's cumulative token spend plus a
// recent daily series, for the config page. ?days bounds the daily series (default 30).
func (s *Server) interceptJudgeUsage(w http.ResponseWriter, r *http.Request) {
	pg := s.m.PG()
	if pg == nil {
		writeJSON(w, 200, db.JudgeUsage{Daily: []db.JudgeDayUsage{}})
		return
	}
	days := atoiDefault(r.URL.Query().Get("days"), 30)
	usage, err := pg.JudgeUsageStats(days)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, usage)
}

// --- helpers ---

type interceptRuleReq struct {
	Name           string `json:"name"`
	Enabled        bool   `json:"enabled"`
	Priority       int    `json:"priority"`
	MatchTarget    string `json:"match_target"`
	MatchType      string `json:"match_type"`
	Pattern        string `json:"pattern"`
	Action         string `json:"action"`
	Message        string `json:"message"`
	TimeoutEnabled bool   `json:"timeout_enabled"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	TimeoutAction  string `json:"timeout_action"`
}

func validateInterceptRuleReq(req interceptRuleReq) error {
	if req.Name == "" {
		return fmt.Errorf("name 不能为空")
	}
	switch req.MatchTarget {
	case "tool_name", "tool_input":
	default:
		return fmt.Errorf("match_target 必须是 tool_name 或 tool_input")
	}
	switch req.MatchType {
	case "string", "regex":
	default:
		return fmt.Errorf("match_type 必须是 string 或 regex")
	}
	if req.Pattern == "" {
		return fmt.Errorf("pattern 不能为空")
	}
	switch req.Action {
	case "allow", "deny", "ask":
	default:
		return fmt.Errorf("action 必须是 allow、deny 或 ask")
	}
	if req.MatchType == "regex" {
		if _, err := regexp.Compile(req.Pattern); err != nil {
			return fmt.Errorf("pattern 不是有效正则：%w", err)
		}
	}
	return nil
}

func (s *Server) interceptDetail(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "bad approval id")
		return
	}
	detail, err := pg.GetInterceptDetail(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if detail == nil {
		writeErr(w, 404, "not found")
		return
	}
	writeJSON(w, 200, detail)
}

// The navigation endpoint returns only the original call and its paired result.
func (s *Server) interceptExecution(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "bad approval id")
		return
	}
	target, err := pg.GetInterceptExecution(id)
	if errors.Is(err, db.ErrInterceptTaskDeleted) || errors.Is(err, db.ErrInterceptSessionDeleted) {
		writeErr(w, http.StatusGone, err.Error())
		return
	}
	if errors.Is(err, db.ErrInterceptExecutionUnavailable) {
		writeErr(w, 409, err.Error())
		return
	}
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if target == nil {
		// Conversation deletion cascades approval rows. A stale source link still
		// carries its conversation ID, allowing a precise message without retaining
		// deleted conversations or changing their deletion semantics.
		if convID, parseErr := strconv.ParseInt(r.URL.Query().Get("conversation"), 10, 64); parseErr == nil && convID > 0 {
			conv, getErr := pg.GetConversation(convID)
			if getErr != nil {
				writeErr(w, 500, getErr.Error())
				return
			}
			if conv == nil {
				writeErr(w, http.StatusGone, "对话已被删除")
				return
			}
		}
		writeErr(w, 404, "审批记录已被删除或不存在")
		return
	}
	writeJSON(w, 200, map[string]any{"conversation_id": target.ConversationID, "task_id": target.TaskID, "session": target.Session, "seq": target.Seq, "items": activityDTOs(target.Items)})
}

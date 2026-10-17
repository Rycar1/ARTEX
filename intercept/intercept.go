// Package intercept implements the user-configurable tool-call interception layer.
// Rules are loaded from the database, cached in memory, and evaluated in priority
// order (highest first) on every PreToolUse event. Three actions are supported:
//
//   - allow: immediately permits the call, skipping lower-priority rules.
//   - deny:  blocks the call and returns a message to the model.
//   - ask:   blocks the call, creates an intercept_pending record, writes an
//     activity to the active conversation, then waits for the user to approve or
//     deny via the /api/intercept/pending/{id}/decide endpoint.
//
// The timeout behaviour is configurable at runtime via SetTimeoutConfig.
package intercept

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
)

// ctxKey is the unexported context key type to avoid collisions.
type ctxKey int

// ConvIDKey stores the active conversation ID in a context.Context so the
// interceptor can associate "ask" pending records with the right conversation.
const ConvIDKey ctxKey = 0

// WithConvID returns a child context carrying convID.
func WithConvID(ctx context.Context, convID int64) context.Context {
	return context.WithValue(ctx, ConvIDKey, convID)
}

// ConvIDFromContext extracts the conversation ID (0 if absent).
func ConvIDFromContext(ctx context.Context) int64 {
	v, _ := ctx.Value(ConvIDKey).(int64)
	return v
}

// taskCtxKey is a separate unexported key type for task context values.
type taskCtxKey int

const (
	taskInfoCtxKey taskCtxKey = 1
	taskEmitCtxKey taskCtxKey = 2
)

type taskCtxInfo struct{ taskID, agentName string }

// WithTaskContext injects task metadata and an emit function into ctx so that
// HandleAsk can tag pending records and write intercept_request activities to
// the task's exploration stream (making them appear inline in session transcripts).
func WithTaskContext(ctx context.Context, taskID, agentName string, emit func(db.Activity)) context.Context {
	ctx = context.WithValue(ctx, taskInfoCtxKey, taskCtxInfo{taskID, agentName})
	if emit != nil {
		ctx = context.WithValue(ctx, taskEmitCtxKey, emit)
	}
	return ctx
}

func taskInfoFromCtx(ctx context.Context) (taskID, agentName string) {
	if v, ok := ctx.Value(taskInfoCtxKey).(taskCtxInfo); ok {
		return v.taskID, v.agentName
	}
	return "", ""
}

func taskEmitFromCtx(ctx context.Context) func(db.Activity) {
	f, _ := ctx.Value(taskEmitCtxKey).(func(db.Activity))
	return f
}

// compiledRule is an InterceptRule with the regex pre-compiled (nil for string rules).
type compiledRule struct {
	db.InterceptRule
	re *regexp.Regexp
}

// pendingManager tracks in-flight "ask" requests via per-request channels.
type pendingManager struct {
	mu sync.Mutex
	ch map[int64]chan bool
}

func newPendingManager() *pendingManager { return &pendingManager{ch: map[int64]chan bool{}} }

func (p *pendingManager) add(id int64) chan bool {
	ch := make(chan bool, 1)
	p.mu.Lock()
	p.ch[id] = ch
	p.mu.Unlock()
	return ch
}

func (p *pendingManager) resolve(id int64, allowed bool) {
	p.mu.Lock()
	ch, ok := p.ch[id]
	delete(p.ch, id)
	p.mu.Unlock()
	if ok {
		ch <- allowed
	}
}

func (p *pendingManager) remove(id int64) {
	p.mu.Lock()
	delete(p.ch, id)
	p.mu.Unlock()
}

// Reviewer runs the LLM fallback judge for one tool call and returns its verdict
// as a Decision (Action ∈ allow|ask|deny; empty Action means the reply could not
// be parsed). It is injected by the server layer so the intercept package stays
// free of any llm dependency. profileID == 0 means "use the active/default profile".
type Reviewer func(ctx context.Context, profileID int64, prompt string, input ReviewInput) (Decision, error)

// Interceptor loads intercept rules from the database and evaluates them on
// tool calls. It is safe for concurrent use.
type Interceptor struct {
	db           *db.DB
	mu           sync.RWMutex
	cached       []compiledRule  // sorted by priority DESC; nil means not loaded yet
	enabledTools map[string]bool // nil means not loaded yet
	pending      *pendingManager
	reviewer     Reviewer // nil = LLM fallback judge not wired
	// taskOpMode 由 server 层注入:按任务 id 解析作战模式("standard"|"aggressive")。
	// nil → 一律按 standard。见 SetTaskOpMode。
	taskOpMode func(taskID string) string
	// taskUnattended 由 server 层注入:按任务 id 解析任务级无人值守开关。nil → false。
	// 全局开关(settings 表 intercept_unattended)优先于它。见 SetTaskUnattended。
	taskUnattended func(taskID string) bool
	// policy 是拦截策略缓存(规则模式 + 裁判是否启用);nil 表示未加载。
	// 见 reviewPolicy()。
	policy *reviewPolicy
	// 裁判熔断状态(见 judgeBreakerTripped):连续失败次数 + 熔断截止时间。
	judgeFailStreak int
	judgeOpenUntil  time.Time
}

// SettingInterceptUnattended 是无人值守的全局开关(settings 表键)。开启后所有任务的
// judge ask 都走「禁止 ask 的强制二次裁决」,不再进入人工审批队列;关闭(默认)时以
// 任务级开关(tasks.unattended)为准。RoE 范围强制 / 用户自建审批规则 / 编码无法解码
// 三条硬编码 ask 不经过 Judge(),不受本开关影响。
const SettingInterceptUnattended = "intercept_unattended"

// settingInterceptUnattended 是包内使用的短别名。
const settingInterceptUnattended = SettingInterceptUnattended

// UnattendedContract 是无人值守模式下强制二次裁决追加到 judge prompt 的输出契约:
// 禁止 ask,必须在 allow/deny 中二选一;无法判断安全性时选 deny(与人工审批超时的
// 默认动作语义对齐 —— 宁可错杀不误放)。ParseVerdict 仍认 ask:若模型违反契约,
// 调用方按 FailAction(deny)兜底,链路上不存在「等人」的可能。
const UnattendedContract = "\n\n# 无人值守模式(强制输出契约)\n" +
	"当前平台处于无人值守状态,本次裁决不会有任何人工复核。" +
	"因此不允许输出 ask:你必须在 allow 与 deny 中二选一。" +
	"如果无法确信该操作是安全的,选择 deny 并在 comment 里说明不确定的原因。" +
	"这是你的最终裁决,直接生效。"

// SetTaskUnattended installs the task→unattended resolver used by Judge() to decide
// whether an ask verdict should be re-asked under the forced-output contract instead
// of entering the human approval queue. Passing nil disables the task-level switch
// (the global setting still applies).
func (i *Interceptor) SetTaskUnattended(fn func(taskID string) bool) {
	i.mu.Lock()
	i.taskUnattended = fn
	i.mu.Unlock()
}

// unattendedEnabled 报告无人值守是否对当前上下文生效:全局开关开 → 一律生效;
// 否则看任务级开关(无任务上下文/chat → false,保守)。
func (i *Interceptor) unattendedEnabled(ctx context.Context) bool {
	if i.db != nil && i.db.GetBool(settingInterceptUnattended, false) {
		return true
	}
	taskID, _ := taskInfoFromCtx(ctx)
	if taskID == "" {
		return false
	}
	i.mu.RLock()
	fn := i.taskUnattended
	i.mu.RUnlock()
	if fn == nil {
		return false
	}
	return fn(taskID)
}

// SetReviewer installs the LLM fallback judge callback. Passing nil disables it.
func (i *Interceptor) SetReviewer(r Reviewer) {
	i.mu.Lock()
	i.reviewer = r
	i.mu.Unlock()
}

// SetTaskOpMode installs the task→op_mode resolver used by HandleAsk to auto-approve asks
// for tasks running in aggressive mode. Passing nil disables the aggressive auto-approve.
func (i *Interceptor) SetTaskOpMode(fn func(taskID string) string) {
	i.mu.Lock()
	i.taskOpMode = fn
	i.mu.Unlock()
}

// defaultEnabledTools is the hard-coded set of tools that enter the intercept
// rule system when no intercept_enabled_tools setting has been saved.
var defaultEnabledTools = []string{
	"Bash", "WebFetch", "web_search",
	"shell_open", "shell_send",
	"Write", "Edit", "MultiEdit",
	// 立足点会话工具(期 1a):登记 webshell 与目标侧命令/文件操作,默认进拦截规则体系。
	"register_session", "session_exec", "session_read", "session_write",
}

// New creates an Interceptor backed by d. The rule cache is lazy-loaded on
// first use.
func New(d *db.DB) *Interceptor {
	return &Interceptor{db: d, pending: newPendingManager()}
}

// Invalidate clears the in-memory rule cache and the enabled-tools cache.
// The next call to Match or IsToolEnabled will reload from the database.
// Call this after any CRUD operation on rules or tool config.
func (i *Interceptor) Invalidate() {
	i.mu.Lock()
	i.cached = nil
	i.enabledTools = nil
	i.policy = nil
	i.mu.Unlock()
}

// settingRuleMode 选择拦截判定链:命中规则即终态(默认),还是把每一次调用都交给
// LLM 裁判(纯模型审核)。
const settingRuleMode = "intercept_rule_mode"

const (
	// RuleModeRules:规则优先,命中即终态,未命中才交裁判(历史行为)。
	RuleModeRules = "rules"
	// RuleModeJudgeOnly:纯 LLM 审核 —— 跳过全部拦截规则(含内置规则),每一次
	// 进入拦截范围的调用都由裁判模型判定。规则仍在库里,切回即可恢复。
	RuleModeJudgeOnly = "judge_only"
)

// reviewPolicy is the cached interception policy: which decision chain to run and
// 当前只有 mode 一个字段(裁判可用性由 Judge() 自己判,不在这里重复缓存 —— 早期
// 版本存了一个 judgeEnabled 但从没被读过,属于「注释声称它是可用性来源」的死字段)。
type reviewPolicy struct {
	mode string
}

// reviewPolicy loads (and caches) the interception policy. It is invalidated by
// Invalidate() — called by the rule/tool/judge config writers — so a settings
// change takes effect without a restart.
func (i *Interceptor) reviewPolicy() reviewPolicy {
	i.mu.RLock()
	if p := i.policy; p != nil {
		out := *p
		i.mu.RUnlock()
		return out
	}
	i.mu.RUnlock()

	i.mu.Lock()
	defer i.mu.Unlock()
	if p := i.policy; p != nil {
		return *p
	}
	p := reviewPolicy{mode: RuleModeRules}
	if v, ok, err := i.db.GetSetting(settingRuleMode); err == nil && ok && strings.TrimSpace(v) == RuleModeJudgeOnly {
		p.mode = RuleModeJudgeOnly
	}
	i.policy = &p
	return p
}

// RuleMode reports the active interception chain ("rules" | "judge_only").
func (i *Interceptor) RuleMode() string { return i.reviewPolicy().mode }

// SetRuleMode persists the interception chain. Unknown values fall back to
// RuleModeRules. Pure-judge mode is refused when no judge is enabled: without
// rules AND without a judge the platform would have no decision layer at all.
func (i *Interceptor) SetRuleMode(mode string) error {
	switch strings.TrimSpace(mode) {
	case RuleModeJudgeOnly:
		if !i.db.GetBool(settingJudgeEnabled, false) {
			return fmt.Errorf("纯模型审核需要先启用裁判模型（系统 → 拦截审批 → 模型配置）")
		}
		mode = RuleModeJudgeOnly
	default:
		mode = RuleModeRules
	}
	if err := i.db.SetSetting(settingRuleMode, mode); err != nil {
		return err
	}
	i.Invalidate()
	return nil
}

func (i *Interceptor) loadLocked() error {
	rules, err := i.db.ListInterceptRules()
	if err != nil {
		return err
	}
	var out []compiledRule
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		cr := compiledRule{InterceptRule: r}
		if r.MatchType == "regex" {
			re, err := regexp.Compile(r.Pattern)
			if err != nil {
				continue // skip rules with bad regex rather than crashing
			}
			cr.re = re
		}
		out = append(out, cr)
	}
	i.cached = out

	// Load enabled-tools set from settings, falling back to hard-coded defaults.
	val, ok, _ := i.db.GetSetting("intercept_enabled_tools")
	if !ok {
		m := make(map[string]bool, len(defaultEnabledTools))
		for _, n := range defaultEnabledTools {
			m[n] = true
		}
		i.enabledTools = m
	} else {
		var names []string
		if json.Unmarshal([]byte(val), &names) != nil {
			i.enabledTools = map[string]bool{}
		} else {
			m := make(map[string]bool, len(names))
			for _, n := range names {
				m[n] = true
			}
			i.enabledTools = m
		}
	}
	return nil
}

func (i *Interceptor) rules() ([]compiledRule, error) {
	i.mu.RLock()
	if i.cached != nil {
		out := i.cached
		i.mu.RUnlock()
		return out, nil
	}
	i.mu.RUnlock()

	i.mu.Lock()
	defer i.mu.Unlock()
	if i.cached != nil {
		return i.cached, nil
	}
	if err := i.loadLocked(); err != nil {
		return nil, err
	}
	return i.cached, nil
}

// IsToolEnabled returns true if the named tool is in the intercept-enabled set
// (i.e. it should enter the rule-matching path). Uses the same double-check lock
// pattern as rules(). Fail-closed: if the configuration cannot be loaded the
// tool is NOT exempted — it enters the intercept flow, where Match fails closed
// on the same load error.
func (i *Interceptor) IsToolEnabled(name string) bool {
	i.mu.RLock()
	if i.enabledTools != nil {
		v := i.enabledTools[name]
		i.mu.RUnlock()
		return v
	}
	i.mu.RUnlock()

	i.mu.Lock()
	defer i.mu.Unlock()
	if i.enabledTools == nil {
		if err := i.loadLocked(); err != nil {
			log.Printf("[intercept] 启用工具列表加载失败,工具 %s 按 fail-closed 进入拦截流程: %v", name, err)
			return true
		}
	}
	return i.enabledTools[name]
}

// GetEnabledTools returns the ordered list of tool names that are currently
// configured to enter the intercept rule system. When the setting has never been
// saved the hard-coded default list is returned.
func (i *Interceptor) GetEnabledTools() ([]string, error) {
	val, ok, err := i.db.GetSetting("intercept_enabled_tools")
	if err != nil {
		return nil, err
	}
	if !ok {
		out := make([]string, len(defaultEnabledTools))
		copy(out, defaultEnabledTools)
		return out, nil
	}
	var names []string
	if err := json.Unmarshal([]byte(val), &names); err != nil {
		return []string{}, nil
	}
	return names, nil
}

// SetEnabledTools persists the list of tool names that should enter the intercept
// rule system, then invalidates the cache so the next call picks up the new list.
func (i *Interceptor) SetEnabledTools(tools []string) error {
	b, err := json.Marshal(tools)
	if err != nil {
		return err
	}
	if err := i.db.SetSetting("intercept_enabled_tools", string(b)); err != nil {
		return err
	}
	i.Invalidate()
	return nil
}

// Decision is the outcome of a successful rule match.
type Decision struct {
	ModelInput       json.RawMessage
	ModelInputDigest string
	ModelFallback    bool
	RuleName         string
	ConfigDigest     string
	ProfileID        int64
	Action           string // "allow" | "deny" | "ask"
	Message          string
	RuleID           int64
	TimeoutEnabled   bool
	TimeoutSeconds   int
	TimeoutAction    string // "deny" | "allow"
	// NoAutoAllow 为 true 时该 ask 不受「一键放行 / 激进模式」自动批准豁免,仍需人工裁决。
	// 用于 RoE 授权范围强制 —— 激进模式放宽技术限制,但资产范围边界不能自动放行。
	NoAutoAllow bool
	// Source 是该裁决的来源,写入 intercept_pending.decision_source 供审核页筛选:
	// "rule"(命中拦截规则)| "model"(LLM 裁判)| "builtin"(平台内置兜底:
	// 编码无法解码转人工、RoE 范围强制、规则加载失败 fail-closed)| "aggressive"|
	// "auto_allow"。空值回退到按 ruleID / 消息前缀的旧推断。
	Source string
}

// --- LLM fallback judge ---

// Judge settings keys (stored in the settings KV table). See docs §3.
const (
	settingJudgeEnabled          = "llm_judge_enabled"
	settingJudgeProfileID        = "llm_judge_profile_id"
	settingJudgePrompt           = "llm_judge_prompt"
	settingJudgeTimeoutSecs      = "llm_judge_timeout_seconds"
	settingJudgeFailAction       = "llm_judge_fail_action"
	settingJudgeAskTimeoutSecs   = "llm_judge_ask_timeout_seconds"
	settingJudgeAskTimeoutAction = "llm_judge_ask_timeout_action"
	// settingJudgeRetryAttempts bounds how many extra judge calls are made
	// when a reply is unparseable or the call fails for a retryable reason.
	settingJudgeRetryAttempts = "llm_judge_retry_attempts"
)

// Judge default values. Fail-closed: a judge failure defaults to "ask" (a human
// decides; unattended asks time out to deny — see defaultJudgeAskTimeoutAction),
// never silently to "allow".
const (
	// defaultJudgeTimeoutSecs 是「整段裁判流程」的墙钟预算:Judge 用它建一个总
	// deadline,重试与退避都从这个预算里扣(见 Judge/judgeWithRetry)。15s 时
	// 纠格式的重试被饿死,超时被记成「调用超时」→ 按失败策略 deny(单 30 小时窗口
	// 1317 条)。60s 足够覆盖 3 次尝试 × 实测 3–10s 的调用延迟。
	defaultJudgeTimeoutSecs      = 60
	defaultJudgeFailAction       = "ask"
	defaultJudgeAskTimeoutSecs   = 300
	defaultJudgeAskTimeoutAction = "deny"
	// defaultJudgeRetryAttempts is the number of extra attempts after the first
	// when the judge reply is unparseable or the call errors. Models routinely
	// drift on the explanation separator; one corrective re-ask recovers almost
	// all of them, and the retry cannot change the verdict (see JudgeRepairInstruction).
	defaultJudgeRetryAttempts = 2
	// maxJudgeRetryAttempts caps the setting so a misconfiguration cannot turn a
	// blocked tool call into an unbounded number of judge calls.
	maxJudgeRetryAttempts = 5
)

// JudgeConfig is the resolved LLM-fallback-judge configuration. Prompt is always
// non-empty (falls back to DefaultJudgePrompt).
type JudgeConfig struct {
	Enabled           bool   `json:"enabled"`
	ProfileID         int64  `json:"profile_id"` // 0 = follow active/default
	Prompt            string `json:"prompt"`
	TimeoutSeconds    int    `json:"timeout_seconds"`
	FailAction        string `json:"fail_action"` // allow|ask|deny
	AskTimeoutSeconds int    `json:"ask_timeout_seconds"`
	AskTimeoutAction  string `json:"ask_timeout_action"` // allow|deny
	// RetryAttempts is the number of extra judge calls after an unparseable
	// reply or a retryable call error (0 disables retries). Bounded by
	// maxJudgeRetryAttempts.
	RetryAttempts int `json:"retry_attempts"`
}

// judgeConfig reads the judge configuration from settings, applying defaults for
// missing/invalid keys. Read fresh on each fallback judgement — the LLM call that
// follows dwarfs a few KV reads, and freshness avoids a cache-invalidation path.
func (i *Interceptor) judgeConfig() JudgeConfig {
	c := JudgeConfig{
		Enabled:           i.db.GetBool(settingJudgeEnabled, false),
		ProfileID:         int64(i.getSettingInt(settingJudgeProfileID, 0)),
		TimeoutSeconds:    i.getSettingInt(settingJudgeTimeoutSecs, defaultJudgeTimeoutSecs),
		FailAction:        i.getSettingChoice(settingJudgeFailAction, defaultJudgeFailAction, "allow", "ask", "deny"),
		AskTimeoutSeconds: i.getSettingInt(settingJudgeAskTimeoutSecs, defaultJudgeAskTimeoutSecs),
		AskTimeoutAction:  i.getSettingChoice(settingJudgeAskTimeoutAction, defaultJudgeAskTimeoutAction, "allow", "deny"),
		RetryAttempts:     clampJudgeRetryAttempts(i.getSettingInt(settingJudgeRetryAttempts, defaultJudgeRetryAttempts)),
	}
	// Prompt: stored value if non-empty, else the built-in template.
	if v, ok, _ := i.db.GetSetting(settingJudgePrompt); ok && strings.TrimSpace(v) != "" {
		c.Prompt = v
	} else {
		c.Prompt = DefaultJudgePrompt
	}
	if c.TimeoutSeconds <= 0 {
		c.TimeoutSeconds = defaultJudgeTimeoutSecs
	}
	if c.AskTimeoutSeconds <= 0 {
		c.AskTimeoutSeconds = defaultJudgeAskTimeoutSecs
	}
	return c
}

func (i *Interceptor) getSettingInt(key string, def int) int {
	v, ok, err := i.db.GetSetting(key)
	if err != nil || !ok {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	return n
}

// clampJudgeRetryAttempts keeps the retry setting inside [0, maxJudgeRetryAttempts].
func clampJudgeRetryAttempts(n int) int {
	if n < 0 {
		return 0
	}
	if n > maxJudgeRetryAttempts {
		return maxJudgeRetryAttempts
	}
	return n
}

func (i *Interceptor) getSettingChoice(key, def string, allowed ...string) string {
	v, ok, err := i.db.GetSetting(key)
	if err != nil || !ok {
		return def
	}
	v = strings.TrimSpace(v)
	for _, a := range allowed {
		if v == a {
			return v
		}
	}
	return def
}

// GetJudgeConfig returns the resolved judge configuration for the API/UI. Prompt
// is the effective prompt (built-in template when unset), so the UI can prefill.
func (i *Interceptor) GetJudgeConfig() JudgeConfig { return i.judgeConfig() }

// SetJudgeConfig persists the judge configuration. An empty Prompt clears the
// override (the built-in template is used again).
func (i *Interceptor) SetJudgeConfig(c JudgeConfig) error {
	if err := i.db.SetBool(settingJudgeEnabled, c.Enabled); err != nil {
		return err
	}
	if err := i.db.SetSetting(settingJudgeProfileID, strconv.FormatInt(c.ProfileID, 10)); err != nil {
		return err
	}
	// Store the prompt only when it differs from the built-in template, so version
	// updates to DefaultJudgePrompt flow through for users who never customized it.
	promptToStore := ""
	if strings.TrimSpace(c.Prompt) != "" && strings.TrimSpace(c.Prompt) != strings.TrimSpace(DefaultJudgePrompt) {
		promptToStore = c.Prompt
	}
	if err := i.db.SetSetting(settingJudgePrompt, promptToStore); err != nil {
		return err
	}
	if err := i.db.SetSetting(settingJudgeTimeoutSecs, strconv.Itoa(c.TimeoutSeconds)); err != nil {
		return err
	}
	if err := i.db.SetSetting(settingJudgeFailAction, c.FailAction); err != nil {
		return err
	}
	if err := i.db.SetSetting(settingJudgeAskTimeoutSecs, strconv.Itoa(c.AskTimeoutSeconds)); err != nil {
		return err
	}
	if err := i.db.SetSetting(settingJudgeAskTimeoutAction, c.AskTimeoutAction); err != nil {
		return err
	}
	if err := i.db.SetSetting(settingJudgeRetryAttempts, strconv.Itoa(clampJudgeRetryAttempts(c.RetryAttempts))); err != nil {
		return err
	}
	// 关掉裁判时,纯模型审核模式会失去唯一判定层 —— 此时 Review() 对每一次工具调用
	// 都返回内置 ask,而 ask 超时默认 deny,等于把整个平台的工具调用冻死。所以在
	// 关闭裁判的同时强制回落到「规则优先」:要么有模型判,要么有规则判,不能两个都没有。
	if !c.Enabled && i.RuleMode() == RuleModeJudgeOnly {
		if err := i.db.SetSetting(settingRuleMode, RuleModeRules); err != nil {
			return err
		}
	}
	// 裁判开关是审核策略的一部分(纯模型审核模式要求裁判可用),缓存必须失效。
	i.Invalidate()
	return nil
}

// Judge runs the LLM fallback judge for a tool call that matched no rule. It
// returns (Decision, true) when the judge produced a terminal verdict, or
// (Decision{}, false) when the fallback is disabled or not wired (caller then
// keeps the current behavior: allow). On model error or an unparseable reply it
// falls back to the configured FailAction. Ask verdicts carry the human-approval
// timeout so the existing HandleAsk consumes them unchanged.
func (i *Interceptor) Judge(ctx context.Context, tool string, arguments json.RawMessage) (Decision, bool) {
	cfg := i.judgeConfig()
	i.mu.RLock()
	rv := i.reviewer
	i.mu.RUnlock()
	if !cfg.Enabled || rv == nil {
		return Decision{}, false
	}

	cctx := ctx
	if cfg.TimeoutSeconds > 0 {
		var cancel context.CancelFunc
		cctx, cancel = context.WithTimeout(ctx, time.Duration(cfg.TimeoutSeconds)*time.Second)
		defer cancel()
	}

	input, contextErr := BuildReviewInput(cctx, tool, arguments)
	cfg.Prompt = EffectiveJudgePrompt(cfg.Prompt)
	var out Decision
	var err error
	var modelInput []byte
	if contextErr != nil {
		// Invalid current arguments cannot be reviewed faithfully, regardless of
		// the configured model-failure strategy. A human must resolve the input.
		out = Decision{Action: "ask", ModelFallback: true, Message: "审查上下文不完整，需要人工确认：" + contextErr.Error()}
	} else {
		modelInput, _ = json.Marshal(input)
		out, err = rv(cctx, cfg.ProfileID, cfg.Prompt, input)
	}
	if err != nil {
		out = Decision{ProfileID: out.ProfileID, ModelFallback: true, Action: cfg.FailAction, Message: "模型审批失败,按失败策略处理: " + err.Error()}
	}
	// 无人值守:judge 给出 ask(拿不准)时不再进入人工审批队列 —— 追加「禁止 ask」的
	// 强制输出契约重问一次,让模型在 allow/deny 中二选一(无法判断安全则 deny,与人工
	// 审批超时的默认动作语义对齐)。二次仍 ask/调用失败 → 硬兜底 deny(不取 FailAction:
	// 它的默认值就是 ask,会绕回审批队列,恰好复现本开关要消灭的冻结),链路上不存在
	// 「等人」的可能。
	//
	// 覆盖范围:J1(模型裁决 ask)与 J2(入参无法解析时的强制 ask,见上面的 contextErr
	// 分支)。J2 的入参本身不可解析,拿不到可信审查材料,所以**不再发起二次模型调用**
	// (喂空上下文只会得到噪声),直接按安全默认拒绝 —— 关键是它同样不能进审批队列。
	// RoE 范围强制 / 用户自建审批规则 / 编码无法解码三条硬编码 ask 不经过 Judge(),
	// 不受影响。
	if out.Action == "ask" && i.unattendedEnabled(ctx) {
		switch {
		case contextErr != nil:
			out = Decision{ProfileID: out.ProfileID, ModelFallback: true, Action: "deny",
				Message: "无人值守:工具入参无法解析,无法审查,按安全默认拒绝: " + contextErr.Error()}
		case err == nil:
			askReason := out.Message
			reOut, reErr := rv(cctx, cfg.ProfileID, cfg.Prompt+UnattendedContract, input)
			switch {
			case reErr != nil:
				out = Decision{ProfileID: out.ProfileID, ModelFallback: true, Action: "deny",
					Message: "无人值守:强制裁决调用失败,按安全默认拒绝: " + reErr.Error()}
			case reOut.Action == "allow" || reOut.Action == "deny":
				out = reOut
				out.Message = "[无人值守强制裁决] judge 首次裁决为 ask(" + askReason + "),已按无人值守契约强制二选一: " + out.Message
			default:
				// 二次仍 ask(违反契约)或其它非法动作 → 硬兜底 deny。
				out = Decision{ProfileID: out.ProfileID, ModelFallback: true, Action: "deny",
					Message: "无人值守:强制裁决仍未能给出 allow/deny,按安全默认拒绝"}
			}
		}
		log.Printf("[intercept] 无人值守:工具 %s 的 ask 裁决已强制落地 → %s", tool, out.Action)
	}
	switch out.Action {
	case "allow", "ask", "deny":
		// valid verdict
	default:
		out = Decision{ProfileID: out.ProfileID, ModelFallback: true, Action: cfg.FailAction, Message: "模型输出无法解析,按失败策略处理"}
	}
	// A model verdict never carries a rule; keep RuleID 0 (→ NULL) for history.
	out.RuleID = 0
	if len(modelInput) > 0 {
		out.ModelInput = modelInput
		out.ModelInputDigest = digestInput(modelInput)
	}
	if out.ProfileID != 0 {
		cfg.ProfileID = out.ProfileID
	}
	out.ProfileID = cfg.ProfileID
	configJSON, _ := json.Marshal(cfg)
	out.ConfigDigest = digestInput(configJSON)
	if out.Message == "" {
		out.Message = "[模型] " + judgeActionLabel(out.Action)
	} else if !strings.HasPrefix(out.Message, "[模型]") {
		out.Message = "[模型] " + out.Message
	}
	if out.Action == "ask" {
		out.TimeoutEnabled = true
		out.TimeoutSeconds = cfg.AskTimeoutSeconds
		out.TimeoutAction = cfg.AskTimeoutAction
	}
	// Every verdict out of Judge() is a model decision (including the model-failure
	// fallback), so the history row is attributed to the judge, not "unknown".
	out.Source = "model"
	// 熔断记账:ModelFallback 覆盖「上游报错」与「输出无法解析」两种失败。连续失败到
	// 阈值即熔断,让 Review 改走规则兜底 —— 否则 judge_only 模式下每一次工具调用都会
	// 按 fail_action(deny)被拦掉,把整条任务链冻死在平台侧的上游故障上。
	i.noteJudgeOutcome(out.ModelFallback)
	return out, true
}

func judgeActionLabel(action string) string {
	switch action {
	case "allow":
		return "放行"
	case "deny":
		return "拦截"
	case "ask":
		return "转人工审批"
	default:
		return action
	}
}

// Match evaluates the rule list (priority DESC) against a tool call.
// Returns (Decision, true) for the first matching enabled rule, or
// (Decision{}, false) if no rule matches. Fail-closed: a rule-load error is NOT
// treated as "no rules" — it returns an explicit deny decision (and logs),
// while an empty rule list (len==0, no error) still falls through to the LLM
// judge / caller default. An encoded payload that no decoder can recover is
// NOT auto-escalated here; it falls through to the judge like any other
// unmatched call (the guard keeps a fail-closed human ask only when no judge
// is available).
func (i *Interceptor) Match(toolName string, input []byte) (Decision, bool) {
	rules, err := i.rules()
	if err != nil {
		log.Printf("[intercept] 规则加载失败,工具 %s 按 fail-closed 拒绝: %v", toolName, err)
		return Decision{
			RuleName: "rule-load-error",
			Action:   "deny",
			Message:  "拦截规则加载失败,平台按 fail-closed 策略禁止执行此工具",
			Source:   "builtin",
		}, true
	}
	if len(rules) == 0 {
		return Decision{}, false
	}

	// 编码/变换规避:把参数里藏进 base64/hex/URL/HTML/转义/反转等编码的载荷
	// 先解码还原,再让规则在「原文 + 各解码候选」上匹配。这样「?c=<hex>」这类
	// 明文正则看不到的写法,会以还原后的真实命令命中对应规则。
	raw := string(input)
	subjects, kindOf := matchSubjects(raw)

	for _, r := range rules {
		if r.MatchTarget == "tool_name" {
			if ruleMatchesSubject(r, toolName, toolName) {
				return i.decisionForRule(r, ""), true
			}
			continue
		}
		for _, subj := range subjects {
			if !ruleMatchesSubject(r, toolName, subj) {
				continue
			}
			kind := ""
			if subj != raw {
				kind = kindOf[subj]
			}
			return i.decisionForRule(r, kind), true
		}
	}

	// 编码载荷无法解码时不再直接转人工:保持「未命中」,由调用方走 Judge(),
	// 让 LLM 裁判自行判定(guard 层仅在无裁判可用时才用
	// UndecodableEncodedPayload 兜底转人工)。
	return Decision{}, false
}

// matchSubjects returns the texts every rule is evaluated against, in order, plus
// the transform kind that produced each non-raw subject ("" for the raw input).
//
// The first entry is the raw tool_input JSON, then its JSON-unescaped view, then
// the decoding/obfuscation variants. The unescaped view exists because rules are
// authored against the *logical* command text, while the wire form escapes it —
// see jsonUnescapeView for the two ways that silently disabled rules on live
// traffic. It is only added when it actually differs from the raw input.
func matchSubjects(raw string) ([]string, map[string]string) {
	variants := DecodeVariants(raw, decodeMaxDepth)
	subjects := make([]string, 0, len(variants)+2)
	kindOf := make(map[string]string, len(variants)+1)
	subjects = append(subjects, raw)
	if unescaped, ok := jsonUnescapeView(raw); ok && unescaped != raw {
		subjects = append(subjects, unescaped)
		kindOf[unescaped] = "json_unescape"
	}
	for _, v := range variants {
		subjects = append(subjects, v.Text)
		if _, ok := kindOf[v.Text]; !ok {
			kindOf[v.Text] = v.Kind
		}
	}
	return subjects, kindOf
}

// Review is the single decision entry point for one tool call. It runs the
// configured interception chain:
//
//   - RuleModeRules (default): Match() first — the first matching rule is
//     terminal — and only an unmatched call goes to Judge().
//   - RuleModeJudgeOnly (纯模型审核): every call goes straight to Judge();
//     the rule table is skipped entirely (rules stay in the DB, so switching
//     back restores them).
//
// 裁判熔断(见 judgeBreakerTripped)打开时,模型失败不再按 fail_action 落地:
//   - rules 模式:当作「没有判定层」返回 decided=false,交回调用方既有的 fail-open 兜底;
//   - judge_only 模式:降级为规则兜底 —— 命中规则照拦,未命中放行(不再冻住任务)。
//
// decided=false means no decision layer produced a verdict (rules matched
// nothing and no judge is wired). Callers keep their own fail-closed fallback.
func (i *Interceptor) Review(ctx context.Context, toolName string, input []byte) (Decision, bool) {
	dec, decided := i.review(ctx, toolName, input)
	// 激进模式「全放行」(任务级,见 aggressiveBypassAll):规则/judge 的 deny 一律转
	// allow 并留痕 —— ask 在 HandleAsk 里已被激进模式自动放行,这里补齐 deny 侧。
	// 出口审查(凭据外泄)与跨任务隔离在 guard 的前置层,不经过 Review,不受影响;
	// RoE 范围强制走 guard 前置层的 HandleAsk 且带 NoAutoAllow,同样不受影响。
	if decided && dec.Action == "deny" && i.aggressiveBypassAll(ctx) {
		dec.Action = "allow"
		dec.Source = "aggressive_bypass"
		dec.Message = "[激进模式·全放行] " + dec.Message
		log.Printf("[intercept] 激进模式全放行:工具 %s 的 deny 裁决已转为 allow(审计源 aggressive_bypass)", toolName)
	}
	return dec, decided
}

// aggressiveBypassAll 报告当前上下文的任务是否处于激进模式且应放行一切拦截
// (规则 deny / judge deny 均转 allow)。ask 的自动放行在 HandleAsk 里已有
// (decision_source="aggressive")。无任务上下文或未装配解析器 → false(保守)。
func (i *Interceptor) aggressiveBypassAll(ctx context.Context) bool {
	taskID, _ := taskInfoFromCtx(ctx)
	if taskID == "" {
		return false
	}
	i.mu.RLock()
	fn := i.taskOpMode
	i.mu.RUnlock()
	if fn == nil {
		return false
	}
	return db.IsAggressiveOpMode(fn(taskID))
}

// review 是 Review 的判定主体(原 Review 逻辑),被 Review 包裹以统一施加
// 激进模式「全放行」映射。
func (i *Interceptor) review(ctx context.Context, toolName string, input []byte) (Decision, bool) {
	if i.reviewPolicy().mode == RuleModeJudgeOnly {
		if dec, judged := i.Judge(ctx, toolName, input); judged {
			if dec.ModelFallback && i.judgeBreakerTripped() {
				return i.rulesFallbackDecision(toolName, input), true
			}
			return dec, true
		}
		// 纯模型审核模式下裁判不可用 = 平台没有任何判定层。fail-closed 转人工:
		// 既不能放行(等于零审核),也不直接 deny(那会把整条任务链硬停)。
		return Decision{
			RuleName: "[内置] 纯模型审核:裁判不可用",
			Action:   "ask",
			Message:  JudgeUnavailableHint,
			Source:   "builtin",
		}, true
	}
	if dec, matched := i.Match(toolName, input); matched {
		return dec, true
	}
	dec, judged := i.Judge(ctx, toolName, input)
	if judged && dec.ModelFallback && i.judgeBreakerTripped() {
		// 规则模式下未命中任何规则、裁判又熔断 —— 按「无判定层」处理(与裁判未接线
		// 时的历史行为一致:guard 侧只对强编码特征做 fail-closed 转人工)。
		log.Printf("[intercept] 裁判熔断中,%s 未命中规则且裁判不可用,按无判定层放行", toolName)
		return Decision{}, false
	}
	return dec, judged
}

// rulesFallbackDecision 是 judge_only 模式下裁判熔断后的降级判定:规则表照常评估,
// 命中即用规则结论;未命中则显式放行(带 JudgeBreakerHint 文案,历史页可筛选追溯)。
// 出口审查 / RoE 范围检查是 guard 里独立的前置层,不经过这里,因此硬边界不受影响。
func (i *Interceptor) rulesFallbackDecision(toolName string, input []byte) Decision {
	if dec, matched := i.Match(toolName, input); matched {
		dec.Message = strings.TrimSpace(dec.Message + "（裁判熔断降级中:本次由规则判定）")
		return dec
	}
	return Decision{
		RuleName: "[内置] 裁判熔断降级",
		Action:   "allow",
		Message:  JudgeBreakerHint,
		Source:   "builtin",
	}
}

// JudgeUnavailableHint 是「纯模型审核模式已开启但裁判模型不可用」时给人工的提示。
const JudgeUnavailableHint = "平台已切换为纯模型审核(拦截规则不参与判定),但裁判模型当前不可用(未启用 / 未配置 / 调用失败)。" +
	"此时没有任何判定层能给出结论,按 fail-closed 转人工。请到 系统 → 拦截审批 → 模型配置 启用裁判模型,或把审核模式切回「规则 + 模型」。"

// JudgeBreakerHint 是「裁判连续失败触发熔断降级」时写入历史的原因文案。
const JudgeBreakerHint = "[内置] 裁判熔断降级:裁判模型连续调用失败,平台在冷却期内改按「规则兜底」判定 —— " +
	"命中拦截规则照常拦截,未命中的调用直接放行(出口审查 / RoE 范围检查等硬边界不受影响)。" +
	"冷却结束后平台会自动重试裁判;若持续出现请检查裁判模型配置与上游可用性。"

// 裁判熔断参数:连续 judgeBreakerFailures 次模型失败(上游错误 / 无法解析)即熔断,
// 冷却 judgeBreakerCooldown;冷却结束自动半开(下一次调用重新交给裁判,成功即恢复)。
// 取 5 次是为了不把偶发抖动当成故障,5 分钟是为了让上游恢复后能自动回来。
const (
	judgeBreakerFailures = 5
	judgeBreakerCooldown = 5 * time.Minute
)

// noteJudgeOutcome 记录一次裁判调用的结果,维护熔断状态。失败计数按「连续」语义:
// 任何一次成功都清零,避免长期低频失败把熔断器慢慢推到阈值。
func (i *Interceptor) noteJudgeOutcome(failed bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if !failed {
		i.judgeFailStreak = 0
		i.judgeOpenUntil = time.Time{}
		return
	}
	i.judgeFailStreak++
	if i.judgeFailStreak >= judgeBreakerFailures && time.Now().After(i.judgeOpenUntil) {
		i.judgeOpenUntil = time.Now().Add(judgeBreakerCooldown)
		log.Printf("[intercept] 裁判熔断:连续 %d 次模型失败,冷却 %s 内改按规则兜底(命中规则照拦,未命中放行)",
			i.judgeFailStreak, judgeBreakerCooldown)
	}
}

// judgeBreakerTripped 报告裁判熔断是否处于打开状态。冷却结束后自动关闭(半开):
// 下一次调用仍会交给裁判,由 noteJudgeOutcome 决定恢复还是重新熔断。
func (i *Interceptor) judgeBreakerTripped() bool {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return !i.judgeOpenUntil.IsZero() && time.Now().Before(i.judgeOpenUntil)
}

// JudgeBreakerState 供运维页/日志查询熔断状态:是否打开、连续失败次数、剩余冷却秒数。
func (i *Interceptor) JudgeBreakerState() (open bool, failStreak int, cooldownLeft time.Duration) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	open = !i.judgeOpenUntil.IsZero() && time.Now().Before(i.judgeOpenUntil)
	if open {
		cooldownLeft = time.Until(i.judgeOpenUntil)
	}
	return open, i.judgeFailStreak, cooldownLeft
}

// decisionForRule builds the Decision for a matched rule. kind is the encoding
// that had to be decoded before the rule matched ("" when the raw input matched),
// and is appended to the message so the operator can see why it fired.
func (i *Interceptor) decisionForRule(r compiledRule, kind string) Decision {
	msg := r.Message
	if msg == "" {
		msg = defaultMessage(r.Action, r.Name)
	}
	if kind != "" {
		msg += "(命中经解码还原后的内容,编码方式:" + kind + ")"
	}
	configJSON, _ := json.Marshal(r.InterceptRule)
	return Decision{
		RuleName: r.Name, ConfigDigest: digestInput(configJSON),
		Action:         r.Action,
		Message:        msg,
		RuleID:         r.ID,
		TimeoutEnabled: r.TimeoutEnabled,
		TimeoutSeconds: r.TimeoutSeconds,
		TimeoutAction:  r.TimeoutAction,
		Source:         "rule",
	}
}

func ruleMatches(r compiledRule, toolName string, input []byte) bool {
	return ruleMatchesSubject(r, toolName, string(input))
}

func ruleMatchesSubject(r compiledRule, toolName, subject string) bool {
	switch r.MatchTarget {
	case "tool_name":
		subject = toolName
	case "tool_input":
		// subject already holds the tool input (raw or decoded)
	default:
		return false
	}
	if r.MatchType == "regex" {
		return r.re != nil && r.re.MatchString(subject)
	}
	return strings.Contains(subject, r.Pattern)
}

func defaultMessage(action, name string) string {
	switch action {
	case "deny":
		return "拦截规则 [" + name + "] 禁止执行此工具"
	case "ask":
		return "拦截规则 [" + name + "] 要求用户审批，请等待"
	default:
		return ""
	}
}

// Log records an allow/deny rule or model decision into intercept_pending as an ALREADY-decided
// row (status = "allowed" | "denied"), for observability. Unlike HandleAsk it does NOT
// block and needs no user action — it makes explicit review decisions visible on the history
// page (GET /api/intercept/history) and the task's intercept list. Best-effort: a DB
// error is swallowed so logging never changes the tool call's outcome. The pending list
// (status='pending') is unaffected, so it still shows only asks awaiting a decision.
func (i *Interceptor) Log(ctx context.Context, convID int64, dec Decision, toolName string, input []byte, status string) {
	taskID, agentName := taskInfoFromCtx(ctx)
	audit := auditFor(ctx, dec, input, status)
	id, err := i.db.CreateDecidedInterceptWithSource(dec.RuleID, convID, taskID, agentName, toolName, input, status, dec.Message, decisionSource(dec), audit)
	if err == nil {
		i.bindResult(ctx, id, audit)
	}
}

// decisionSource resolves the decision_source column value for a Decision: an
// explicit Source set at the decision site wins (builtin/model/rule/aggressive/
// auto_allow), otherwise it falls back to the legacy ruleID/message inference so
// older callers keep their previous labeling.
func decisionSource(dec Decision) string {
	if dec.Source != "" {
		return dec.Source
	}
	if dec.RuleID != 0 {
		return "rule"
	}
	if strings.HasPrefix(dec.Message, "[模型]") {
		return "model"
	}
	return "unknown"
}

// HandleAsk creates a pending approval record and blocks until the user decides
// (via /api/intercept/pending/{id}/decide) or the per-rule timeout elapses.
// Returns true if the user approved.
//
// 一键放行(guard_auto_allow)启用中时不创建 pending 记录,直接批准并写历史
// (decision_source = "auto_allow");到期后自动恢复人工审批。
//
// convID == 0 means no active conversation (background pentest task). The
// pending record is still created (conversation_id = NULL) so the approvals
// page shows it and the sidebar badge lights up. The worker thread blocks just
// like in a chat session — the user must visit the approvals page to unblock it.
func (i *Interceptor) HandleAsk(ctx context.Context, convID int64, dec Decision, toolName string, input []byte) bool {
	// 一键放行(带时限):启用中直接放行,不进 pending;历史记 decision_source=
	// "auto_allow"。每次裁决前 AutoAllowStatus 做惰性到期检查,过期自动关闭。
	// 仅作用于 ask 审批;deny 规则在 guard 的 deny 分支拦截,不经过这里。
	if i.AutoAllowStatus().Enabled {
		i.autoAllowApprove(ctx, convID, dec, toolName, input)
		return true
	}

	// 激进模式(任务级):该任务的所有 ask 审批直接放行,不进 pending,历史记
	// decision_source=aggressive。资产范围(RoE)强制审批带 NoAutoAllow 标记,不受此豁免,
	// 保证「资产不打偏」的底线不被激进模式绕过。deny 规则同样不经过这里。
	if !dec.NoAutoAllow && i.aggressiveTask(ctx) {
		i.autoApproveAs(ctx, convID, dec, toolName, input, "aggressive", "激进模式自动批准")
		return true
	}

	ruleID := dec.RuleID
	taskID, agentName := taskInfoFromCtx(ctx)
	taskEmit := taskEmitFromCtx(ctx)

	audit := auditFor(ctx, dec, input, "pending")
	pendingID, err := i.db.CreateInterceptPendingWithSource(ruleID, convID, taskID, agentName, toolName, input, dec.Message, decisionSource(dec), audit)
	if err != nil {
		return false
	}

	i.bindResult(ctx, pendingID, audit)
	ch := i.pending.add(pendingID)
	defer i.pending.remove(pendingID)
	// Polling clients can decide after INSERT commits but before the channel is
	// registered. Re-read after registration so that decision cannot be lost;
	// later decisions will be delivered through ch.
	if saved, err := i.db.GetInterceptDetail(pendingID); err == nil && saved != nil && saved.Status != "pending" {
		return saved.Status == "allowed" || (saved.Audit != nil && saved.Audit.EffectiveAction == "allow")
	}

	detail, _ := json.Marshal(map[string]any{
		"pending_id": pendingID,
		"tool":       toolName,
		"input":      json.RawMessage(input),
	})
	activity := db.Activity{
		Kind:    "intercept_request",
		Summary: fmt.Sprintf("工具 %s 请求审批 (#%d)", toolName, pendingID),
		Detail:  string(detail),
	}

	if convID != 0 {
		// Chat session: write inline card to the conversation stream.
		_, _ = i.db.AppendConvActivity(convID, activity)
	} else if taskEmit != nil {
		// Task worker: emit to the exploration activity stream so it appears
		// inline in the session transcript (the emit fn stamps NodeID + Worker).
		taskEmit(activity)
	}

	if !dec.TimeoutEnabled {
		if i.unattendedEnabled(ctx) {
			// 无人值守:规则本身没配超时(内置 ask 规则就是 timeout_enabled=false)时
			// **不能无限期等人** —— 否则无人值守任务会一直挂在这条审批上;若任务级
			// timeout_seconds 又是 0(不限时),那就是永不结束。这里按全局 ask 超时策略
			// 兜底,语义与 judge ask 的超时完全一致(默认 300s → deny)。
			dec.TimeoutEnabled = true
			dec.TimeoutSeconds = i.getSettingInt(settingJudgeAskTimeoutSecs, defaultJudgeAskTimeoutSecs)
			dec.TimeoutAction = i.getSettingChoice(settingJudgeAskTimeoutAction, defaultJudgeAskTimeoutAction, "allow", "deny")
			log.Printf("[intercept] 无人值守:规则 #%d 未配超时,按全局 ask 超时兜底(%ds → %s)",
				dec.RuleID, dec.TimeoutSeconds, dec.TimeoutAction)
		} else {
			// No timeout: wait indefinitely until user decides or worker stops.
			select {
			case allowed := <-ch:
				return allowed
			case <-ctx.Done():
				_, _ = i.db.ResolveIntercept(pendingID, "denied", "deny", "工作已取消")
				_ = i.db.CompleteIntercept(pendingID, audit.RunID, audit.ToolUseID, "not_executed", "执行前工作已取消", false)
				return false
			}
		}
	}

	secs := dec.TimeoutSeconds
	if secs <= 0 {
		secs = 60
	}
	timer := time.NewTimer(time.Duration(secs) * time.Second)
	defer timer.Stop()
	select {
	case allowed := <-ch:
		return allowed
	case <-timer.C:
		allowed := dec.TimeoutAction == "allow"
		action := "deny"
		if allowed {
			action = "allow"
		}
		resolved, err := i.db.ResolveIntercept(pendingID, "timeout", action, "审批超时，按超时策略处理")
		if err != nil {
			return false
		}
		if !resolved {
			detail, err := i.db.GetInterceptDetail(pendingID)
			return err == nil && detail != nil && (detail.Status == "allowed" || (detail.Audit != nil && detail.Audit.EffectiveAction == "allow"))
		}
		return allowed
	case <-ctx.Done():
		_, _ = i.db.ResolveIntercept(pendingID, "denied", "deny", "工作已取消")
		_ = i.db.CompleteIntercept(pendingID, audit.RunID, audit.ToolUseID, "not_executed", "执行前工作已取消", false)
		return false
	}
}

var ErrAlreadyDecided = errors.New("审批已处理或不存在，请刷新记录")

// Decide resolves a pending request. Called by the HTTP decide endpoint.
func (i *Interceptor) Decide(pendingID int64, allowed bool) error {
	status := "denied"
	if allowed {
		status = "allowed"
	}
	action, reason := "deny", "人工拒绝执行"
	if allowed {
		action, reason = "allow", "人工允许执行"
	}
	resolved, err := i.db.ResolveIntercept(pendingID, status, action, reason)
	if err != nil {
		return err
	}
	if !resolved {
		return ErrAlreadyDecided
	}
	i.pending.resolve(pendingID, allowed)
	return nil
}

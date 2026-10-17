package intercept

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

// unattendedEnv 提供任务级无人值守开关的测试桩(全局开关用真实 DB settings 验证)。
type unattendedEnv struct {
	task map[string]bool
}

func (e *unattendedEnv) taskUnattended(taskID string) bool { return e.task[taskID] }

// forceJudgeEnabled 把裁判开关置为启用,并在测试结束后恢复原值。
//
// 共享 dev DB 里 llm_judge_enabled 会被其它测试(以及迁移后真正跑到写接口的 HTTP 测试)
// 改掉;Judge() 在 Enabled=false 时直接返回 (Decision{}, false),本组用例就会全部失效。
// 显式钉住开关,让用例只依赖自身前提。
func forceJudgeEnabled(t *testing.T, ic *Interceptor) {
	t.Helper()
	prev := ic.GetJudgeConfig()
	cfg := prev
	cfg.Enabled = true
	if err := ic.SetJudgeConfig(cfg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ic.SetJudgeConfig(prev) })
}

// newUnattendedInterceptor 组装一个开了 judge、带可编程 reviewer 的拦截器。
// reviewer 按调用次数依次返回预置裁决:第 1 次裁决 + (ask 时)第 2 次强制裁决。
func newUnattendedInterceptor(t *testing.T, env *unattendedEnv, verdicts []Decision, errs []error) *Interceptor {
	t.Helper()
	d := openTestDB(t)
	ic := New(d)
	return wireUnattendedReviewer(t, ic, env, verdicts, errs)
}

// wireUnattendedReviewer 是 newUnattendedInterceptor 的共用装配部分(也供复用已有 DB 的
// 用例使用)。
func wireUnattendedReviewer(t *testing.T, ic *Interceptor, env *unattendedEnv, verdicts []Decision, errs []error) *Interceptor {
	t.Helper()
	forceJudgeEnabled(t, ic)
	ic.mu.Lock()
	ic.taskUnattended = env.taskUnattended
	ic.mu.Unlock()
	call := 0
	ic.SetReviewer(func(ctx context.Context, profileID int64, prompt string, input ReviewInput) (Decision, error) {
		idx := call
		call++
		if idx < len(errs) && errs[idx] != nil {
			return Decision{}, errs[idx]
		}
		if idx >= len(verdicts) {
			return Decision{}, errors.New("no more scripted verdicts")
		}
		return verdicts[idx], nil
	})
	return ic
}

func unattendedCtx(taskID string) context.Context {
	return WithTaskContext(context.Background(), taskID, "work#test", nil)
}

// setGlobalUnattended 设置全局开关并在测试结束后还原为关(不污染共享 dev DB)。
func setGlobalUnattended(t *testing.T, ic *Interceptor, on bool) {
	t.Helper()
	if err := ic.db.SetBool(SettingInterceptUnattended, on); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ic.db.SetBool(SettingInterceptUnattended, false) })
}

// ─── J1:judge 正常给出 ask ───────────────────────────────────────────────

// 开关全关 → ask 原样返回(进 HandleAsk 等人,行为不变)。
func TestUnattendedOffAskStaysAsk(t *testing.T) {
	d := openTestDB(t)
	setGlobalUnattended(t, New(d), false) // 保证全局关
	env := &unattendedEnv{task: map[string]bool{"52": false}}
	ic := newUnattendedInterceptor(t, env, []Decision{{Action: "ask", Message: "拿不准"}}, nil)
	dec, judged := ic.Judge(unattendedCtx("52"), "Bash", []byte(`{"command":"ls"}`))
	if !judged || dec.Action != "ask" {
		t.Fatalf("开关全关时 ask 应原样透传: judged=%v action=%s", judged, dec.Action)
	}
}

// 任务级开 → 强制二次裁决给出 allow → 落地 allow,不再 ask。
func TestUnattendedForcedVerdictAllow(t *testing.T) {
	env := &unattendedEnv{task: map[string]bool{"52": true}}
	ic := newUnattendedInterceptor(t, env, []Decision{
		{Action: "ask", Message: "拿不准"},
		{Action: "allow", Message: "只读命令,安全"},
	}, nil)
	dec, judged := ic.Judge(unattendedCtx("52"), "Bash", []byte(`{"command":"ls"}`))
	if !judged || dec.Action != "allow" {
		t.Fatalf("无人值守下 ask 应被强制二次裁决为 allow: action=%s", dec.Action)
	}
	if !strings.Contains(dec.Message, "无人值守强制裁决") {
		t.Errorf("裁决应带无人值守标记: %s", dec.Message)
	}
	if !strings.Contains(dec.Message, "拿不准") {
		t.Errorf("裁决应保留首次 ask 的原因: %s", dec.Message)
	}
}

// 任务级开 → 强制二次裁决给出 deny → 落地 deny。
func TestUnattendedForcedVerdictDeny(t *testing.T) {
	env := &unattendedEnv{task: map[string]bool{"52": true}}
	ic := newUnattendedInterceptor(t, env, []Decision{
		{Action: "ask", Message: "拿不准"},
		{Action: "deny", Message: "删除类操作,不确定影响"},
	}, nil)
	dec, _ := ic.Judge(unattendedCtx("52"), "Bash", []byte(`{"command":"rm -rf /"}`))
	if dec.Action != "deny" {
		t.Fatalf("强制二次裁决 deny 应落地: action=%s", dec.Action)
	}
}

// 任务级开 → 二次裁决仍 ask(违反契约)→ FailAction(deny)兜底,不建审批单。
func TestUnattendedSecondAskFallsBackToFailAction(t *testing.T) {
	env := &unattendedEnv{task: map[string]bool{"52": true}}
	ic := newUnattendedInterceptor(t, env, []Decision{
		{Action: "ask", Message: "拿不准"},
		{Action: "ask", Message: "还是拿不准"},
	}, nil)
	dec, _ := ic.Judge(unattendedCtx("52"), "Bash", []byte(`{"command":"x"}`))
	if dec.Action != "deny" {
		t.Fatalf("二次仍 ask 应按 FailAction(deny) 兜底: action=%s", dec.Action)
	}
	if !strings.Contains(dec.Message, "无人值守") {
		t.Errorf("兜底文案应说明无人值守: %s", dec.Message)
	}
}

// 任务级开 → 二次调用失败(上游挂)→ FailAction(deny)兜底。
func TestUnattendedSecondCallErrorFallsBack(t *testing.T) {
	env := &unattendedEnv{task: map[string]bool{"52": true}}
	ic := newUnattendedInterceptor(t, env, []Decision{
		{Action: "ask", Message: "拿不准"},
	}, []error{nil, errors.New("upstream 500")})
	dec, _ := ic.Judge(unattendedCtx("52"), "Bash", []byte(`{"command":"x"}`))
	if dec.Action != "deny" {
		t.Fatalf("二次调用失败应按 FailAction(deny) 兜底: action=%s", dec.Action)
	}
}

// 全局开关开、任务级关 → 仍无人值守(全局优先于任务级)。
func TestUnattendedGlobalOverridesTaskOff(t *testing.T) {
	d := openTestDB(t)
	ic := New(d)
	setGlobalUnattended(t, ic, true)
	env := &unattendedEnv{task: map[string]bool{"52": false}}
	ic2 := newUnattendedInterceptorWithDB(t, d, env, []Decision{
		{Action: "ask", Message: "拿不准"},
		{Action: "deny", Message: "拒绝"},
	}, nil)
	_ = ic
	dec, _ := ic2.Judge(unattendedCtx("52"), "Bash", []byte(`{"command":"x"}`))
	if dec.Action != "deny" {
		t.Fatalf("全局开应短路任务级关: action=%s", dec.Action)
	}
}

// 无任务上下文(chat)且全局关 → 无人值守不生效,ask 原样透传。
func TestUnattendedNoTaskContextStaysAsk(t *testing.T) {
	d := openTestDB(t)
	setGlobalUnattended(t, New(d), false)
	env := &unattendedEnv{task: map[string]bool{}}
	ic := newUnattendedInterceptor(t, env, []Decision{{Action: "ask", Message: "拿不准"}}, nil)
	dec, _ := ic.Judge(context.Background(), "Bash", []byte(`{"command":"x"}`))
	if dec.Action != "ask" {
		t.Fatalf("无任务上下文且全局关不应进入无人值守: action=%s", dec.Action)
	}
}

// newUnattendedInterceptorWithDB 复用已有 DB(全局开关测试用,避免重复 open)。
func newUnattendedInterceptorWithDB(t *testing.T, d *db.DB, env *unattendedEnv, verdicts []Decision, errs []error) *Interceptor {
	t.Helper()
	return wireUnattendedReviewer(t, New(d), env, verdicts, errs)
}

// ─── 激进模式全放行 ──────────────────────────────────────────────────────

// aggressiveBypassAll:aggressive 任务 → true;standard → false;无解析器 → false。
func TestAggressiveBypassAllResolver(t *testing.T) {
	ic := New(openTestDB(t))
	ctx := unattendedCtx("52")

	// 无解析器 → false
	if ic.aggressiveBypassAll(ctx) {
		t.Fatal("未装配解析器时应为 false")
	}
	// aggressive 任务 → true
	ic.SetTaskOpMode(func(taskID string) string {
		if taskID == "52" {
			return "aggressive"
		}
		return "standard"
	})
	if !ic.aggressiveBypassAll(ctx) {
		t.Fatal("aggressive 任务应放行一切拦截")
	}
	// standard 任务 → false
	if ic.aggressiveBypassAll(unattendedCtx("53")) {
		t.Fatal("standard 任务不应全放行")
	}
	// 无任务上下文 → false
	if ic.aggressiveBypassAll(context.Background()) {
		t.Fatal("无任务上下文不应全放行")
	}
}

// Review 出口:aggressive 任务下 judge 的 deny 被转为 allow,并带 aggressive_bypass 审计源。
func TestReviewAggressiveBypassesJudgeDeny(t *testing.T) {
	d := openTestDB(t)
	ic := New(d)
	ic.SetTaskOpMode(func(taskID string) string { return "aggressive" })
	ic.SetReviewer(func(ctx context.Context, profileID int64, prompt string, input ReviewInput) (Decision, error) {
		return Decision{Action: "deny", Message: "危险命令"}, nil
	})
	dec, decided := ic.Review(unattendedCtx("52"), "Bash", []byte(`{"command":"rm -rf /"}`))
	if !decided {
		t.Fatal("应有判定")
	}
	if dec.Action != "allow" {
		t.Fatalf("激进模式全放行下 judge deny 应转为 allow: action=%s", dec.Action)
	}
	if dec.Source != "aggressive_bypass" {
		t.Errorf("审计源应为 aggressive_bypass: %s", dec.Source)
	}
	if !strings.Contains(dec.Message, "激进模式·全放行") {
		t.Errorf("消息应标注全放行: %s", dec.Message)
	}
}

// Review 出口:standard 任务下 judge 的 deny 保持 deny(不受影响)。
func TestReviewStandardKeepsDeny(t *testing.T) {
	d := openTestDB(t)
	ic := New(d)
	ic.SetTaskOpMode(func(taskID string) string { return "standard" })
	ic.SetReviewer(func(ctx context.Context, profileID int64, prompt string, input ReviewInput) (Decision, error) {
		return Decision{Action: "deny", Message: "危险命令"}, nil
	})
	dec, decided := ic.Review(unattendedCtx("52"), "Bash", []byte(`{"command":"rm -rf /"}`))
	if !decided || dec.Action != "deny" {
		t.Fatalf("standard 下 deny 应保持: decided=%v action=%s", decided, dec.Action)
	}
}

// ─── 契约常量 ────────────────────────────────────────────────────────────

// UnattendedContract 必须禁止 ask 并给出 deny 偏置。
func TestUnattendedContractContent(t *testing.T) {
	if !strings.Contains(UnattendedContract, "不允许输出 ask") {
		t.Error("契约应禁止 ask")
	}
	if !strings.Contains(UnattendedContract, "deny") {
		t.Error("契约应说明无法判断时选 deny")
	}
	if !strings.Contains(UnattendedContract, "allow") {
		t.Error("契约应要求二选一")
	}
}

// ─── 硬边界不变:激进模式不得吞掉 RoE 的 NoAutoAllow ─────────────────────

// 激进模式全放行只作用于 Review() 的 deny;RoE 范围强制(带 NoAutoAllow)走
// HandleAsk 的既有豁免判定,必须仍然等人 —— 这是「资产不打偏」的底线。
func TestAggressiveDoesNotBypassNoAutoAllowAsk(t *testing.T) {	d := openTestDB(t)
	ic := New(d)
	_ = ic.SetAutoAllow(false, 0) // 排除一键放行干扰
	ic.SetTaskOpMode(func(taskID string) string { return "aggressive" })

	marker := fmt.Sprintf("noautoallow-test-%d", time.Now().UnixNano())
	input := []byte(fmt.Sprintf(`{"command":%q}`, marker))
	// RoE 范围强制的决策带 NoAutoAllow;激进模式不得自动批准,应进入等待。
	ctx, cancel := context.WithTimeout(unattendedCtx("52"), 2*time.Second)
	defer cancel()
	start := time.Now()
	ok := ic.HandleAsk(ctx, 0, Decision{Action: "ask", Message: "RoE 范围外目标", NoAutoAllow: true}, "Bash", input)
	if ok {
		t.Fatal("NoAutoAllow 的 ask 不得被激进模式自动批准")
	}
	if time.Since(start) < time.Second {
		t.Fatal("NoAutoAllow 的 ask 应立即进入等待(而非快速放行/拒绝)")
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM intercept_pending WHERE tool_input::text LIKE '%' || $1 || '%'`, marker)
	})
	// 必须留下了 pending 记录 —— 证明它走的是「等人」而不是自动批准。
	var status string
	if err := d.QueryRow(`SELECT status FROM intercept_pending
		WHERE tool_name='Bash' AND tool_input::text LIKE '%' || $1 || '%' ORDER BY id DESC LIMIT 1`, marker).Scan(&status); err != nil {
		t.Fatalf("NoAutoAllow 的 ask 应写入审批记录: %v", err)
	}
	if status != "pending" && status != "denied" {
		t.Fatalf("审批记录状态应为 pending/denied(ctx 取消), got %s", status)
	}
}

// 对照:同样激进模式下,不带 NoAutoAllow 的 ask 会被自动批准(既有行为不变)。
func TestAggressiveStillAutoApprovesPlainAsk(t *testing.T) {
	d := openTestDB(t)
	ic := New(d)
	_ = ic.SetAutoAllow(false, 0)
	ic.SetTaskOpMode(func(taskID string) string { return "aggressive" })

	marker := fmt.Sprintf("aggr-autoapprove-test-%d", time.Now().UnixNano())
	input := []byte(fmt.Sprintf(`{"command":%q}`, marker))
	ctx, cancel := context.WithTimeout(unattendedCtx("52"), 5*time.Second)
	defer cancel()
	start := time.Now()
	ok := ic.HandleAsk(ctx, 0, Decision{Action: "ask", Message: "普通询问"}, "Bash", input)
	if !ok {
		t.Fatal("激进模式下普通 ask 应自动批准")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("自动批准应立即返回,不应等待")
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM intercept_pending WHERE tool_input::text LIKE '%' || $1 || '%'`, marker)
	})
	var source string
	if err := d.QueryRow(`SELECT decision_source FROM intercept_pending
		WHERE tool_name='Bash' AND tool_input::text LIKE '%' || $1 || '%' ORDER BY id DESC LIMIT 1`, marker).Scan(&source); err != nil {
		t.Fatalf("自动批准应写入历史: %v", err)
	}
	if source != "aggressive" {
		t.Fatalf("审计源应为 aggressive, got %s", source)
	}
}

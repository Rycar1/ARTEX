package intercept

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// setAskTimeout 把全局 ask 超时钉成指定秒数/动作,并在测试结束后恢复原配置。
func setAskTimeout(t *testing.T, ic *Interceptor, secs int, action string) {
	t.Helper()
	prev := ic.GetJudgeConfig()
	cfg := prev
	cfg.AskTimeoutSeconds = secs
	cfg.AskTimeoutAction = action
	if err := ic.SetJudgeConfig(cfg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ic.SetJudgeConfig(prev) })
}

// 无人值守 + 规则 ask **没有配超时**(内置 ask 规则就是 timeout_enabled=false):
// 必须按全局 ask 超时兜底返回,不能无限期等人 —— 否则无人值守任务会一直挂在这条
// 审批上;任务级 timeout_seconds=0(不限时)时更是永不结束。
func TestUnattendedBoundsRuleAskWithoutTimeout(t *testing.T) {
	d := openTestDB(t)
	ic := New(d)
	forceJudgeEnabled(t, ic)
	_ = ic.SetAutoAllow(false, 0)
	setGlobalUnattended(t, ic, true)
	setAskTimeout(t, ic, 1, "deny")

	marker := fmt.Sprintf("askbound-test-%d", time.Now().UnixNano())
	input := []byte(fmt.Sprintf(`{"command":%q}`, marker))
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM intercept_pending WHERE tool_input::text LIKE '%' || $1 || '%'`, marker)
	})

	ctx, cancel := context.WithTimeout(unattendedCtx("52"), 30*time.Second)
	defer cancel()
	start := time.Now()
	// TimeoutEnabled=false = 规则没配超时(内置 ask 规则的真实形态)
	allowed := ic.HandleAsk(ctx, 0, Decision{RuleID: 1, Action: "ask", Message: "规则要求人工确认"}, "Bash", input)
	elapsed := time.Since(start)

	if allowed {
		t.Fatalf("超时动作是 deny,不应放行")
	}
	if elapsed > 10*time.Second {
		t.Fatalf("无人值守应在上限内兜底返回,实际等了 %v(说明仍在无限期等人)", elapsed)
	}
}

// 对照:无人值守关 → 未配超时的规则 ask 仍按原语义无限期等(由 ctx 取消结束)。
// 这条保证「有人在盯的交互场景」行为不被改动。
func TestRuleAskWithoutTimeoutStillWaitsWhenInteractive(t *testing.T) {
	d := openTestDB(t)
	ic := New(d)
	forceJudgeEnabled(t, ic)
	_ = ic.SetAutoAllow(false, 0)
	setGlobalUnattended(t, ic, false)
	setAskTimeout(t, ic, 1, "deny") // 即使全局配了 1s,未开无人值守也不该套用

	marker := fmt.Sprintf("askwait-test-%d", time.Now().UnixNano())
	input := []byte(fmt.Sprintf(`{"command":%q}`, marker))
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM intercept_pending WHERE tool_input::text LIKE '%' || $1 || '%'`, marker)
	})

	ctx, cancel := context.WithTimeout(unattendedCtx("52"), 2*time.Second)
	defer cancel()
	start := time.Now()
	allowed := ic.HandleAsk(ctx, 0, Decision{RuleID: 1, Action: "ask", Message: "规则要求人工确认"}, "Bash", input)
	elapsed := time.Since(start)

	if allowed {
		t.Fatal("没人批准不应放行")
	}
	if elapsed < time.Second {
		t.Fatalf("未开无人值守时应一直等到 ctx 取消,实际只等了 %v", elapsed)
	}
}

package intercept

import (
	"testing"
	"time"
)

// 裁判熔断的回归测试。事故原型:中转按请求长度把一部分请求路由到严格通道,返回
// upstream 400 "conversation id missing";judge_only 模式下每次失败都按 fail_action=deny
// 落地,于是 worker 的每一次 Bash 调用都被拦掉(task 52 里 196 次),整条任务链冻死。

func TestJudgeBreakerTripsAfterConsecutiveFailures(t *testing.T) {
	ic := &Interceptor{}
	if ic.judgeBreakerTripped() {
		t.Fatal("初始状态不应熔断")
	}
	for i := 0; i < judgeBreakerFailures-1; i++ {
		ic.noteJudgeOutcome(true)
		if ic.judgeBreakerTripped() {
			t.Fatalf("第 %d 次失败不应熔断(阈值 %d)", i+1, judgeBreakerFailures)
		}
	}
	ic.noteJudgeOutcome(true)
	if !ic.judgeBreakerTripped() {
		t.Fatalf("连续 %d 次失败应熔断", judgeBreakerFailures)
	}
	open, streak, left := ic.JudgeBreakerState()
	if !open || streak != judgeBreakerFailures || left <= 0 || left > judgeBreakerCooldown {
		t.Fatalf("熔断状态异常: open=%v streak=%d left=%s", open, streak, left)
	}
}

func TestJudgeBreakerSuccessResetsStreak(t *testing.T) {
	ic := &Interceptor{}
	for i := 0; i < judgeBreakerFailures-1; i++ {
		ic.noteJudgeOutcome(true)
	}
	ic.noteJudgeOutcome(false) // 一次成功清零
	for i := 0; i < judgeBreakerFailures-1; i++ {
		ic.noteJudgeOutcome(true)
	}
	if ic.judgeBreakerTripped() {
		t.Fatal("成功后计数应清零,不该熔断")
	}
	if _, streak, _ := ic.JudgeBreakerState(); streak != judgeBreakerFailures-1 {
		t.Fatalf("streak=%d, want %d", streak, judgeBreakerFailures-1)
	}
}

func TestJudgeBreakerHalfOpenAfterCooldown(t *testing.T) {
	ic := &Interceptor{}
	for i := 0; i < judgeBreakerFailures; i++ {
		ic.noteJudgeOutcome(true)
	}
	// 冷却结束后自动半开:下一次调用仍交给裁判(由 noteJudgeOutcome 决定恢复还是重熔)。
	ic.mu.Lock()
	ic.judgeOpenUntil = time.Now().Add(-time.Second)
	ic.mu.Unlock()
	if ic.judgeBreakerTripped() {
		t.Fatal("冷却结束后应自动关闭熔断")
	}
	// 半开状态下再失败一次:计数已 >= 阈值 → 立即重新熔断。
	ic.noteJudgeOutcome(true)
	if !ic.judgeBreakerTripped() {
		t.Fatal("半开后再失败应立即重新熔断")
	}
}

func TestJudgeBreakerHintMentionsRulesFallback(t *testing.T) {
	if JudgeBreakerHint == "" || !contains(JudgeBreakerHint, "规则") {
		t.Fatalf("降级文案应说明改按规则判定, got: %s", JudgeBreakerHint)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

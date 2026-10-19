package intercept

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// askRowsByMarker 统计 tool_input 里带该 marker 的审批相关行:
//   - waiting = 仍在等人(pending)或被超时兜底(timeout)的行 —— 这两种都说明
//     「走了人工审批那条路」;
//   - total   = 所有行(含已裁决的审计记录)。
//
// 无人值守下 waiting 必须为 0:既不能建 pending,也不能靠超时被动收场。
func askRowsByMarker(t *testing.T, ic *Interceptor, marker string) (waiting, total int) {
	t.Helper()
	if err := ic.db.QueryRow(
		`SELECT count(*) FILTER (WHERE status IN ('pending','timeout')), count(*)
		   FROM intercept_pending WHERE tool_input::text LIKE '%' || $1 || '%'`, marker,
	).Scan(&waiting, &total); err != nil {
		t.Fatalf("统计审批行失败: %v", err)
	}
	return waiting, total
}

// TestUnattendedNeverCreatesPending 复现「开了无人值守仍有 ask」的根因:
//
// 无人值守只覆盖了 Judge() 内部产生的 ask(J1/J2),而规则命中、编码兜底、
// RoE 范围强制这三类 ask 直接走 HandleAsk,**照样建 pending 等人** ——
// 于是页面上仍然能看到「待审批」。
//
// 断言:无人值守开启时,任何来源的 ask 都不得创建审批单。
func TestUnattendedNeverCreatesPending(t *testing.T) {
	cases := []struct {
		name string
		dec  Decision
	}{
		{"规则命中 ask", Decision{RuleID: 1, Action: "ask", Message: "规则要求人工确认"}},
		{"编码载荷无法解码", Decision{Action: "ask", Message: "编码载荷无法解码(疑似规避检测)", Source: "builtin"}},
		{"RoE 范围强制", Decision{Action: "ask", Message: "目标不在授权范围", NoAutoAllow: true, Source: "builtin"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := openTestDB(t)
			ic := New(d)
			forceJudgeEnabled(t, ic)
			_ = ic.SetAutoAllow(false, 0)
			setGlobalUnattended(t, ic, true)
			setAskTimeout(t, ic, 1, "deny")

			// 裁判始终判 allow,验证「强制裁决」这条路真的被调用到。
			ic.SetReviewer(func(ctx context.Context, profileID int64, prompt string, input ReviewInput) (Decision, error) {
				return Decision{Action: "allow", Message: "强制裁决:只读操作"}, nil
			})

			marker := fmt.Sprintf("unattended-nopending-%s-%d", tc.name, time.Now().UnixNano())
			input := []byte(fmt.Sprintf(`{"command":%q}`, marker))
			t.Cleanup(func() {
				_, _ = d.Exec(`DELETE FROM intercept_pending WHERE tool_input::text LIKE '%' || $1 || '%'`, marker)
			})

			ctx, cancel := context.WithTimeout(unattendedCtx("52"), 30*time.Second)
			defer cancel()
			start := time.Now()
			_ = ic.HandleAsk(ctx, 0, tc.dec, "Bash", input)
			elapsed := time.Since(start)

			if waiting, total := askRowsByMarker(t, ic, marker); waiting != 0 || total == 0 {
				t.Fatalf("无人值守下不应走人工审批:待审批/超时行=%d,总审计行=%d(耗时 %v)", waiting, total, elapsed)
			}
		})
	}
}

// TestUnattendedRuleAskUsesForcedVerdict 规则类 ask 在无人值守下应交给裁判强制二选一,
// 而不是直接 deny:裁判说 allow 就放行,说 deny 就拦。
func TestUnattendedRuleAskUsesForcedVerdict(t *testing.T) {
	for _, tc := range []struct {
		name        string
		verdict     string
		wantAllowed bool
	}{
		{"裁判判 allow", "allow", true},
		{"裁判判 deny", "deny", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := openTestDB(t)
			ic := New(d)
			forceJudgeEnabled(t, ic)
			_ = ic.SetAutoAllow(false, 0)
			setGlobalUnattended(t, ic, true)
			setAskTimeout(t, ic, 1, "deny")
			ic.SetReviewer(func(ctx context.Context, profileID int64, prompt string, input ReviewInput) (Decision, error) {
				return Decision{Action: tc.verdict, Message: "强制裁决"}, nil
			})
			marker := fmt.Sprintf("unattended-verdict-%d", time.Now().UnixNano())
			t.Cleanup(func() {
				_, _ = d.Exec(`DELETE FROM intercept_pending WHERE tool_input::text LIKE '%' || $1 || '%'`, marker)
			})
			got := ic.HandleAsk(unattendedCtx("52"), 0,
				Decision{RuleID: 1, Action: "ask", Message: "规则要求人工确认"},
				"Bash", []byte(fmt.Sprintf(`{"command":%q}`, marker)))
			if got != tc.wantAllowed {
				t.Fatalf("裁判 %s 时 HandleAsk 应返回 %v,实际 %v", tc.verdict, tc.wantAllowed, got)
			}
		})
	}
}

// TestUnattendedRoENeverAutoAllows 无论裁判怎么说,RoE 范围强制在无人值守下都不得放行
// (资产不出范围是硬边界),且不得创建审批单。
func TestUnattendedRoENeverAutoAllows(t *testing.T) {
	d := openTestDB(t)
	ic := New(d)
	forceJudgeEnabled(t, ic)
	_ = ic.SetAutoAllow(false, 0)
	setGlobalUnattended(t, ic, true)
	setAskTimeout(t, ic, 1, "deny")
	called := 0
	ic.SetReviewer(func(ctx context.Context, profileID int64, prompt string, input ReviewInput) (Decision, error) {
		called++
		return Decision{Action: "allow", Message: "裁判想放行"}, nil
	})
	marker := fmt.Sprintf("unattended-roe-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM intercept_pending WHERE tool_input::text LIKE '%' || $1 || '%'`, marker)
	})
	got := ic.HandleAsk(unattendedCtx("52"), 0,
		Decision{Action: "ask", Message: "目标不在授权范围", NoAutoAllow: true, Source: "builtin"},
		"Bash", []byte(fmt.Sprintf(`{"command":%q}`, marker)))
	if got {
		t.Fatal("RoE 范围强制在无人值守下不得被放行")
	}
	if waiting, total := askRowsByMarker(t, ic, marker); waiting != 0 || total == 0 {
		t.Fatalf("RoE 无人值守下不应走人工审批:待审批/超时行=%d,总审计行=%d", waiting, total)
	}
	_ = called
}

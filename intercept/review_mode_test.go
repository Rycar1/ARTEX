package intercept

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// Review 是唯一判定入口:默认规则优先,纯模型模式下跳过全部规则。
func TestReviewChainByMode(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	ic := New(d)
	if !ic.IsToolEnabled("Bash") {
		t.Skip("Bash 不在拦截范围内")
	}
	// 保存并恢复现场:审核模式 + 裁判开关。
	prevMode := ic.RuleMode()
	prevJudge := ic.GetJudgeConfig()
	t.Cleanup(func() {
		_ = ic.SetJudgeConfig(prevJudge)
		_ = d.SetSetting(settingRuleMode, prevMode)
		ic.Invalidate()
	})

	// 一条必然命中的 deny 规则。
	marker := "reviewmode-test-marker"
	rule, err := d.CreateInterceptRule("reviewmode-test", "tool_input", "string", marker, "deny", "测试规则", 1<<30, true, false, 0, "deny")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteInterceptRule(rule.ID) })
	ic.Invalidate()

	// 裁判:记录是否被调用,并固定返回 allow。
	judgeCalls := 0
	ic.SetReviewer(func(ctx context.Context, profileID int64, prompt string, in ReviewInput) (Decision, error) {
		judgeCalls++
		return Decision{Action: "allow", Message: "[模型] 放行", ProfileID: 1}, nil
	})
	cfg := ic.GetJudgeConfig()
	cfg.Enabled = true
	if err := ic.SetJudgeConfig(cfg); err != nil {
		t.Fatal(err)
	}

	input, _ := json.Marshal(map[string]string{"command": "echo " + marker})

	// --- 规则模式:规则命中即终态,裁判不参与 ---
	if err := ic.SetRuleMode(RuleModeRules); err != nil {
		t.Fatal(err)
	}
	judgeCalls = 0
	dec, ok := ic.Review(context.Background(), "Bash", input)
	if !ok || dec.Action != "deny" {
		t.Fatalf("规则模式应命中 deny 规则, got ok=%v action=%q", ok, dec.Action)
	}
	if dec.Source != "rule" {
		t.Fatalf("规则模式来源应为 rule, got %q", dec.Source)
	}
	if judgeCalls != 0 {
		t.Fatalf("规则模式下裁判不应被调用, got %d 次", judgeCalls)
	}

	// --- 纯模型模式:同一输入绕过规则,直接由裁判判 ---
	if err := ic.SetRuleMode(RuleModeJudgeOnly); err != nil {
		t.Fatal(err)
	}
	if ic.RuleMode() != RuleModeJudgeOnly {
		t.Fatalf("模式未生效: %s", ic.RuleMode())
	}
	judgeCalls = 0
	dec, ok = ic.Review(context.Background(), "Bash", input)
	if !ok {
		t.Fatal("纯模型模式应给出结论")
	}
	if dec.Action != "allow" {
		t.Fatalf("纯模型模式应采信裁判的 allow, got %q", dec.Action)
	}
	if dec.Source != "model" {
		t.Fatalf("纯模型模式来源应为 model, got %q", dec.Source)
	}
	if judgeCalls != 1 {
		t.Fatalf("纯模型模式裁判应被调用一次, got %d", judgeCalls)
	}

	// --- 纯模型模式 + 裁判不可用:fail-closed 转人工,绝不放行 ---
	ic.SetReviewer(nil)
	dec, ok = ic.Review(context.Background(), "Bash", input)
	if !ok {
		t.Fatal("裁判不可用时纯模型模式仍需给出结论(fail-closed)")
	}
	if dec.Action != "ask" {
		t.Fatalf("裁判不可用应转人工, got %q", dec.Action)
	}
	if dec.Source != "builtin" {
		t.Fatalf("fail-closed 兜底来源应为 builtin, got %q", dec.Source)
	}
}

// 没有启用裁判时不允许切到纯模型模式:否则平台会同时失去规则和模型两层判定。
func TestSetRuleModeRequiresJudge(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	ic := New(d)
	prevMode := ic.RuleMode()
	prevJudge := ic.GetJudgeConfig()
	t.Cleanup(func() {
		_ = ic.SetJudgeConfig(prevJudge)
		_ = d.SetSetting(settingRuleMode, prevMode)
		ic.Invalidate()
	})

	cfg := ic.GetJudgeConfig()
	cfg.Enabled = false
	if err := ic.SetJudgeConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if err := ic.SetRuleMode(RuleModeJudgeOnly); err == nil {
		t.Fatal("未启用裁判时应拒绝纯模型模式")
	}
	if ic.RuleMode() != RuleModeRules {
		t.Fatalf("拒绝后模式应保持 rules, got %s", ic.RuleMode())
	}

	cfg.Enabled = true
	if err := ic.SetJudgeConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if err := ic.SetRuleMode(RuleModeJudgeOnly); err != nil {
		t.Fatalf("启用裁判后应允许纯模型模式: %v", err)
	}
	if ic.RuleMode() != RuleModeJudgeOnly {
		t.Fatalf("模式应为 judge_only, got %s", ic.RuleMode())
	}
	// 未知值回落到 rules。
	if err := ic.SetRuleMode("bogus"); err != nil {
		t.Fatal(err)
	}
	if ic.RuleMode() != RuleModeRules {
		t.Fatalf("未知模式应回落 rules, got %s", ic.RuleMode())
	}
}

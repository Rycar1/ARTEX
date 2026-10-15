package guard

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
)

// 纯模型审核模式必须真正绕过拦截规则:同一输入在规则模式下被 deny 规则拦下,
// 切到纯模型模式后由裁判放行,且历史来源标注为 model。
func TestPureLLMModeBypassesRules(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	ic := intercept.New(d)
	if !ic.IsToolEnabled("Bash") {
		t.Skip("Bash 不在拦截范围内")
	}
	prevMode := ic.RuleMode()
	prevJudge := ic.GetJudgeConfig()
	t.Cleanup(func() {
		_ = ic.SetJudgeConfig(prevJudge)
		_ = d.SetSetting("intercept_rule_mode", prevMode)
		ic.Invalidate()
	})

	marker := "guard-purellm-marker"
	rule, err := d.CreateInterceptRule("purellm-test-deny", "tool_input", "string", marker, "deny", "纯模型模式应绕过我", 1<<30, true, false, 0, "deny")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = d.DeleteInterceptRule(rule.ID)
		_, _ = d.Exec(`DELETE FROM intercept_pending WHERE tool_input::text LIKE '%' || $1 || '%'`, marker)
	})
	ic.Invalidate()

	ic.SetReviewer(func(ctx context.Context, profileID int64, prompt string, in intercept.ReviewInput) (intercept.Decision, error) {
		return intercept.Decision{Action: "allow", Message: "[模型] 只读命令", ProfileID: 1}, nil
	})
	cfg := ic.GetJudgeConfig()
	cfg.Enabled = true
	if err := ic.SetJudgeConfig(cfg); err != nil {
		t.Fatal(err)
	}

	g := NewWithInterceptor(ic)
	call := func() bool {
		input, _ := json.Marshal(map[string]string{"command": "echo " + marker})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		blocked, _, _ := g.Hooks().PreToolUse(ctx, "Bash", input)
		return blocked
	}

	// 规则模式:deny 规则拦下。
	if err := ic.SetRuleMode(intercept.RuleModeRules); err != nil {
		t.Fatal(err)
	}
	if !call() {
		t.Fatal("规则模式下 deny 规则应拦截")
	}

	// 纯模型模式:同一命令不再被规则拦,由裁判放行。
	if err := ic.SetRuleMode(intercept.RuleModeJudgeOnly); err != nil {
		t.Fatal(err)
	}
	if call() {
		t.Fatal("纯模型模式下规则不应再拦截(应采信裁判的 allow)")
	}
	var source string
	if err := d.QueryRow(`SELECT decision_source FROM intercept_pending
		WHERE tool_input::text LIKE '%' || $1 || '%' ORDER BY id DESC LIMIT 1`, marker).Scan(&source); err != nil {
		t.Fatalf("纯模型模式应写审批历史: %v", err)
	}
	if source != "model" {
		t.Fatalf("decision_source = %s, want model", source)
	}
}

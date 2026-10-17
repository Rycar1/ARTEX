package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

func names(tools []actool.CoreTool) map[string]actool.CoreTool {
	m := map[string]actool.CoreTool{}
	for _, t := range tools {
		m[t.Name()] = t
	}
	return m
}

// TestWireTools verifies end-to-end against the live dev PG: wireTools seeds the
// catalog, ToolResolve keeps record_fact for worker but drops it for planner (not
// bound), and an edited description + injected default flow through.
func TestWireTools(t *testing.T) {
	dsn, _, err := db.DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer pg.Close()

	wireTools(pg, nil) // nil domainReg: test only covers filter/decoration, not injection
	t.Cleanup(func() { agent.ToolResolve = nil })
	// 关掉交互式 shell 注入(norma 的 InteractiveShellDisabled 读这个变量),否则
	// worker 的 Bash 描述会再叠加一段"交互程序改用 shell_open"的说明。
	t.Setenv("AGENT_CORE_DISABLE_INTERACTIVE_SHELL", "1")

	// Seeding populated the catalog.
	rf, err := pg.GetTool("record_fact")
	if err != nil || rf == nil {
		t.Fatalf("record_fact not seeded: %v", err)
	}

	// Build a base as the worker does: its domain tools + defaults, resolved for
	// "worker" then for "planner".
	ts := agent.NewToolSet(nil, "")
	base := append(ts.WorkerTools(), actool.DefaultTools()...)
	ctx := context.Background()

	worker := names(agent.ToolResolve(ctx, "worker", base))
	if _, ok := worker["record_fact"]; !ok {
		t.Error("worker lost record_fact")
	}
	// SDK generic tools aren't seeded → ToolResolve 不改它们的绑定关系;但 worker 的
	// Bash 描述会被**有意**追加 UA 纪律(bashUANote,批 5 B4 的反蜜罐纪律),这是设计
	// 行为,不是"装饰泄漏"。所以这里断言:前缀仍是 SDK 原始描述、且以 UA 纪律结尾。
	if bash, ok := worker["Bash"]; !ok {
		t.Error("worker lost Bash (should pass through)")
	} else {
		desc := bash.Description()
		if !strings.HasPrefix(desc, actool.NewBash().Description()) {
			t.Errorf("worker Bash 描述应保留 SDK 原文前缀,got %q", desc)
		}
		if !strings.HasSuffix(desc, bashUANote) {
			t.Errorf("worker Bash 描述应以 UA 纪律结尾,got %q", desc)
		}
	}
	// planner is not bound to record_fact → resolving a base that contains it drops it.
	planner := names(agent.ToolResolve(ctx, "planner", base))
	if _, ok := planner["record_fact"]; ok {
		t.Error("planner should not get record_fact (not bound)")
	}

	// Edit description + add a default to a scalar param, then confirm the resolved
	// worker tool reflects both. Restore from code default on cleanup.
	t.Cleanup(func() { _ = pg.UpsertToolForce(rf.Key, rf.Description, rf.Schema, mustJSON(rf.Agents)) })
	var schema map[string]any
	_ = json.Unmarshal(rf.Schema, &schema)
	if props, ok := schema["properties"].(map[string]any); ok {
		if conf, ok := props["confidence"].(map[string]any); ok {
			conf["default"] = "inferred"
		}
	}
	edited := mustJSON(schema)
	if err := pg.UpdateTool(rf.Key, "EDITED DESC", edited, mustJSON([]string{"worker"}), true); err != nil {
		t.Fatal(err)
	}

	worker2 := names(agent.ToolResolve(ctx, "worker", base))
	got := worker2["record_fact"]
	if got == nil {
		t.Fatal("record_fact missing after edit")
	}
	if got.Description() != "EDITED DESC" {
		t.Errorf("description = %q, want EDITED DESC", got.Description())
	}
	// Default injection: omit confidence → handler input should carry the default.
	// We can't run the real handler (nil store), but InputSchema must show the default.
	sc := got.InputSchema()
	props := sc["properties"].(map[string]any)
	conf := props["confidence"].(map[string]any)
	if conf["default"] != "inferred" {
		t.Errorf("confidence.default = %v, want inferred", conf["default"])
	}
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

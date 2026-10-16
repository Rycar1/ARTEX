package server

import (
	"context"
	"iter"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/norma/llm"
)

// adviserStubProvider 是停滞顾问的假 provider:返回固定建议,并记录被调用次数。
type adviserStubProvider struct {
	calls int
	reply string
	err   error
}

func (p *adviserStubProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(y func(llm.StreamEvent, error) bool) {}
}

func (p *adviserStubProvider) Complete(_ context.Context, _ llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.calls++
	if p.err != nil {
		return llm.Message{}, "", llm.Usage{}, p.err
	}
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(p.reply)}}, "end_turn", llm.Usage{}, nil
}

// hook 级集成测试:覆盖「PostToolUse 喂检测器 → 触发 onStuck → 顾问产出建议 →
// UpgradeLastPending 替换 → PreToolUse 注入」这条完整接线(engine.go 的 onStuck 闭包
// 做的就是这件事)。单测覆盖了顾问本身与检测器本身,这里补的是两者之间的接线。
func TestSteerHooksStuckFiresAdviserAndInjectsAdvice(t *testing.T) {
	ctx := context.Background()
	det := agent.NewStuckDetector(agent.StuckConfig{
		Window: 10, SigPrefix: 200, SameSigTrigger: 3, FailTrigger: 4,
		FailSimilarity: 0.8, Cooldown: 2, MaxFires: 3,
	})
	det.PivotHint = "【转向建议】换信道"
	prov := &adviserStubProvider{reply: "【判断】被统一拦截层挡住。\n【下一步】把注入点从 query 换到 JSON body 再验一次。"}
	adviser := agent.NewStuckAdviser(prov)

	var fires int
	h := steerHooks{
		drain:  func() (string, bool) { return "", false },
		nudges: &atomic.Int64{},
		label:  "test",
		det:    det,
		onStuck: func(c context.Context, ev *agent.StuckEvent) {
			fires++
			advice, err := adviser.Advise(c, agent.StuckAdviceRequest{
				Goal: "g", Intent: "i", Stuck: *ev,
				PivotHint: det.PivotHint, RecentTools: det.RecentTools(12), PriorFires: ev.N,
			})
			if err != nil || advice == "" {
				return // 保留固定干预
			}
			det.UpgradeLastPending(advice)
		},
	}

	// 喂 3 次完全相同的 tool_result → 触发。
	for i := 0; i < 3; i++ {
		h.PostToolUse(ctx, "Bash", nil, []byte("identical output"), false)
	}
	if fires == 0 {
		t.Fatal("同质响应应触发 onStuck")
	}
	if prov.calls == 0 {
		t.Fatal("触发后应唤起顾问")
	}
	// 下一次工具调用前必须被拦住并注入顾问建议(而不是固定纪律)。
	blocked, msg, _ := h.PreToolUse(ctx, "Bash", nil)
	if !blocked {
		t.Fatal("停滞干预应拦住下一次工具调用")
	}
	if !strings.Contains(msg, "停滞顾问") || !strings.Contains(msg, "JSON body") {
		t.Fatalf("应注入顾问建议, got %q", msg)
	}
	if strings.Contains(msg, "立即停止同轴重试") {
		t.Fatalf("顾问建议应替换固定纪律而非拼接, got %q", msg)
	}
	// 干预只注入一次,第二次不再拦。
	if blocked, _, _ := h.PreToolUse(ctx, "Bash", nil); blocked {
		t.Fatal("干预 drain 后不应重复注入")
	}
}

// 顾问不可用时:照常触发停滞检测,但注入的是**固定转向纪律**(干预不丢)。
func TestSteerHooksStuckKeepsFixedTextWhenAdviserFails(t *testing.T) {
	ctx := context.Background()
	det := agent.NewStuckDetector(agent.StuckConfig{
		Window: 10, SigPrefix: 200, SameSigTrigger: 3, FailTrigger: 4,
		FailSimilarity: 0.8, Cooldown: 2, MaxFires: 3,
	})
	prov := &adviserStubProvider{err: context.DeadlineExceeded}
	adviser := agent.NewStuckAdviser(prov)

	h := steerHooks{
		drain:  func() (string, bool) { return "", false },
		nudges: &atomic.Int64{},
		label:  "test",
		det:    det,
		onStuck: func(c context.Context, ev *agent.StuckEvent) {
			advice, err := adviser.Advise(c, agent.StuckAdviceRequest{Stuck: *ev})
			if err != nil || advice == "" {
				return // 关键:失败就什么都不做,保留 Observe 排入的固定纪律
			}
			det.UpgradeLastPending(advice)
		},
	}
	for i := 0; i < 3; i++ {
		h.PostToolUse(ctx, "Bash", nil, []byte("identical output"), false)
	}
	if prov.calls == 0 {
		t.Fatal("应尝试过顾问")
	}
	blocked, msg, _ := h.PreToolUse(ctx, "Bash", nil)
	if !blocked {
		t.Fatal("顾问失败时仍必须干预")
	}
	if !strings.Contains(msg, "停滞检测") {
		t.Fatalf("顾问失败应保留固定转向纪律, got %q", msg)
	}
}

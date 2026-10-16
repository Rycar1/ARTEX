package agent

import (
	"context"
	"errors"
	"iter"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

// stuckFakeProvider 记录请求并返回固定文本(或错误/空),用于顾问的单测。
type stuckFakeProvider struct {
	reqs  []llm.CompletionRequest
	reply string
	err   error
	calls int
}

func (p *stuckFakeProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(y func(llm.StreamEvent, error) bool) {
		msg, _, _, err := p.Complete(ctx, req)
		if err != nil {
			y(llm.StreamEvent{}, err)
			return
		}
		for _, b := range msg.Content {
			y(llm.StreamEvent{Type: llm.SETextDelta, Text: b.Text}, nil)
		}
	}
}

func (p *stuckFakeProvider) Complete(_ context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.calls++
	p.reqs = append(p.reqs, req)
	if p.err != nil {
		return llm.Message{}, "", llm.Usage{}, p.err
	}
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(p.reply)}}, "end_turn", llm.Usage{}, nil
}

// 顾问拿到的输入必须带齐「判据」需要的事实:目标、意图、卡住形态与次数、
// 试过的工具、平台预给的转向建议、第几次触发。缺一项,建议质量就会掉。
func TestBuildStuckAdviceInputCarriesAllFacts(t *testing.T) {
	got := buildStuckAdviceInput(StuckAdviceRequest{
		Goal:        "拿下 example.edu 的教务系统",
		Intent:      "测试 /api/student 的 id 参数是否可注入",
		Stuck:       StuckEvent{Tool: "Bash", Kind: "same_signature", Count: 12, Signature: "abcd1234", N: 2},
		PivotHint:   "【转向建议】换编码/换信道",
		RecentTools: []string{"Bash", "Bash", "http_request"},
		PriorFires:  2,
		Coverage:    "in-scope 资产 3/7 已测",
	})
	for _, want := range []string{
		"拿下 example.edu 的教务系统",
		"测试 /api/student 的 id 参数是否可注入",
		"连续多次响应完全同质",
		"12", "Bash", "abcd1234", "第 2 次触发",
		"Bash → Bash → http_request",
		"换编码/换信道",
		"in-scope 资产 3/7 已测",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("顾问输入缺少 %q\n---\n%s", want, got)
		}
	}
	// 连续失败形态要用另一句描述,别把两种卡住混为一谈。
	fail := buildStuckAdviceInput(StuckAdviceRequest{Stuck: StuckEvent{Kind: "same_tool_failure", Count: 15}})
	if !strings.Contains(fail, "连续失败") {
		t.Errorf("same_tool_failure 应描述为连续失败: %s", fail)
	}
	// 空字段显式标「(未知)」,避免顾问把"没给"当成"没有"。
	empty := buildStuckAdviceInput(StuckAdviceRequest{})
	if strings.Count(empty, "(未知)") < 3 {
		t.Errorf("空上下文应显式标注未知: %s", empty)
	}
}

func TestStuckAdviserRequiresProvider(t *testing.T) {
	if NewStuckAdviser(nil).Available() {
		t.Fatal("nil provider 应报告不可用")
	}
	if _, err := NewStuckAdviser(nil).Advise(context.Background(), StuckAdviceRequest{}); err == nil {
		t.Fatal("nil provider 调 Advise 应报错(调用方据此保留固定干预)")
	}
	var a *StuckAdviser
	if a.Available() {
		t.Fatal("nil 顾问应报告不可用")
	}
}

func TestStuckAdviserAdvise(t *testing.T) {
	p := &stuckFakeProvider{reply: "【判断】被统一拦截层挡住。\n【换维度】1) 把注入点从 query 换到 JSON body;2) 换 HTTP 方法。\n【下一步】先用 curl 验证 body 注入是否返回不同响应。"}
	a := NewStuckAdviser(p)
	got, err := a.Advise(context.Background(), StuckAdviceRequest{
		Goal: "g", Intent: "i", Stuck: StuckEvent{Tool: "Bash", Count: 12, Signature: "s", N: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "换维度") {
		t.Fatalf("应返回顾问建议, got %q", got)
	}
	// 顾问调用必须:带顾问系统提示词、thinking 关闭(只要结论省 token)、有输出上限。
	if len(p.reqs) != 1 {
		t.Fatalf("应恰好调用一次, got %d", len(p.reqs))
	}
	req := p.reqs[0]
	if len(req.System) != 1 || !strings.Contains(req.System[0], "高级顾问") {
		t.Fatalf("系统提示词未带上顾问角色: %+v", req.System)
	}
	if req.Thinking != "disabled" {
		t.Fatalf("顾问应关闭 thinking, got %q", req.Thinking)
	}
	if req.MaxTokens <= 0 {
		t.Fatalf("应设置输出上限, got %d", req.MaxTokens)
	}
	if len(req.Messages) != 1 || !strings.Contains(req.Messages[0].Text(), "卡住事实") {
		t.Fatalf("用户消息应包含卡住事实: %+v", req.Messages)
	}
}

func TestStuckAdviserErrorsKeepCallerFallback(t *testing.T) {
	// 调用失败 → 返回错误(调用方保留固定干预)。
	p := &stuckFakeProvider{err: errors.New("boom")}
	if _, err := NewStuckAdviser(p).Advise(context.Background(), StuckAdviceRequest{}); err == nil {
		t.Fatal("provider 报错时应返回错误")
	}
	// 空回复也算失败:空建议会把固定纪律替换成空文本。
	empty := &stuckFakeProvider{reply: "   "}
	if _, err := NewStuckAdviser(empty).Advise(context.Background(), StuckAdviceRequest{}); err == nil {
		t.Fatal("空回复应返回错误")
	}
}

// RecentTools 新到旧,保留重复(重复本身就是同轴空转的证据)。
func TestStuckDetectorRecentTools(t *testing.T) {
	d := NewStuckDetector(testStuckConfig())
	d.Observe("Bash", "a", false)
	d.Observe("http_request", "b", false)
	d.Observe("Bash", "c", false)
	got := d.RecentTools(3)
	want := []string{"Bash", "http_request", "Bash"}
	if len(got) != len(want) {
		t.Fatalf("RecentTools(3) = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("RecentTools(3) = %v, want %v(新到旧)", got, want)
		}
	}
	if n := len(d.RecentTools(2)); n != 2 {
		t.Fatalf("RecentTools(2) 应返回 2 条, got %d", n)
	}
	if d.RecentTools(0) != nil || d.RecentTools(-1) != nil {
		t.Fatal("n<=0 应返回 nil")
	}
}

// UpgradeLastPending:替换最近一条待注入干预;无 pending 时追加;空建议不动。
func TestStuckDetectorUpgradeLastPending(t *testing.T) {
	d := NewStuckDetector(testStuckConfig())
	// 先制造一次触发,拿到固定干预。
	for i := 0; i < 3; i++ {
		d.Observe("Bash", "same output", false)
	}
	fixed, ok := d.Drain()
	if !ok || !strings.Contains(fixed, "停滞检测") {
		t.Fatalf("应先排入固定干预, got %q ok=%v", fixed, ok)
	}

	// 再触发一次,然后用顾问建议替换。
	var fired bool
	for i := 0; i < 12 && !fired; i++ {
		if d.Observe("Bash", "same output", false) != nil {
			fired = true
		}
	}
	if !fired {
		t.Fatal("冷却后应能再次触发")
	}
	d.UpgradeLastPending("【判断】方向已榨干。\n【下一步】改用接口 B。")
	got, ok := d.Drain()
	if !ok {
		t.Fatal("替换后应仍有一条待注入干预")
	}
	if !strings.Contains(got, "停滞顾问") || !strings.Contains(got, "改用接口 B") {
		t.Fatalf("应注入顾问建议, got %q", got)
	}
	if strings.Contains(got, "立即停止同轴重试") {
		t.Fatalf("顾问建议应替换掉固定纪律,而不是拼接, got %q", got)
	}

	// 无 pending 时追加,不丢干预。
	d2 := NewStuckDetector(testStuckConfig())
	d2.UpgradeLastPending("只有顾问、没有固定纪律")
	if msg, ok := d2.Drain(); !ok || !strings.Contains(msg, "只有顾问") {
		t.Fatalf("无 pending 时应追加, got %q ok=%v", msg, ok)
	}
	// 空建议不得改动队列。
	d3 := NewStuckDetector(testStuckConfig())
	d3.UpgradeLastPending("   ")
	if _, ok := d3.Drain(); ok {
		t.Fatal("空建议不应产生注入")
	}
}

package server

import (
	"context"
	"errors"
	"iter"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/norma/llm"
)

// scriptedJudgeProvider replays a scripted reply/error per Stream call and
// records the system prompt each call was asked with.
type scriptedJudgeProvider struct {
	replies []string
	errs    []error
	calls   int
	systems []string
}

func (p *scriptedJudgeProvider) Stream(_ context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	i := p.calls
	p.calls++
	if len(req.System) > 0 {
		p.systems = append(p.systems, req.System[0])
	}
	return func(yield func(llm.StreamEvent, error) bool) {
		if i < len(p.errs) && p.errs[i] != nil {
			yield(llm.StreamEvent{}, p.errs[i])
			return
		}
		if i < len(p.replies) {
			yield(llm.StreamEvent{Type: llm.SETextDelta, Text: p.replies[i]}, nil)
		}
	}
}

func (p *scriptedJudgeProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	return accumulateStreamForTest(ctx, p.Stream, req)
}

const (
	goodVerdict   = "{\"decision\":\"deny\",\"comment\":\"实际操作：删除数据库；成功后的后果：业务数据丢失；命中规则：D1\"}"
	periodVerdict = "{\"decision\":\"deny\",\"comment\":\"实际操作：删除数据库。成功后的后果：业务数据丢失。命中规则：D1\"}"
	junkVerdict   = "not json at all"
)

// A reply that uses "。" instead of "；" must still parse (root-cause fix) and
// therefore must NOT trigger a retry.
func TestJudgeRetryAcceptsPeriodSeparatorWithoutRetry(t *testing.T) {
	p := &scriptedJudgeProvider{replies: []string{periodVerdict}}
	got, err := judgeWithRetry(context.Background(), p, 7, "sys", intercept.ReviewInput{}, 2)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got.Action != "deny" {
		t.Fatalf("action=%q want deny", got.Action)
	}
	if p.calls != 1 {
		t.Fatalf("calls=%d want 1 (period separator must not retry)", p.calls)
	}
}

// An unparseable first reply must be retried with the repair instruction and
// recover on the second attempt.
func TestJudgeRetryRecoversFromUnparseableReply(t *testing.T) {
	p := &scriptedJudgeProvider{replies: []string{junkVerdict, goodVerdict}}
	got, err := judgeWithRetry(context.Background(), p, 7, "sys", intercept.ReviewInput{}, 2)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got.Action != "deny" {
		t.Fatalf("action=%q want deny", got.Action)
	}
	if p.calls != 2 {
		t.Fatalf("calls=%d want 2", p.calls)
	}
	if len(p.systems) != 2 || !strings.Contains(p.systems[1], "上一次输出不合规") {
		t.Fatalf("second attempt did not carry the repair instruction: %#v", p.systems)
	}
	if strings.Contains(p.systems[0], "上一次输出不合规") {
		t.Fatal("first attempt must use the unmodified prompt")
	}
}

// When every attempt fails to parse, the error is surfaced (Judge turns it into
// the fail_action fallback).
func TestJudgeRetryExhaustsAndReturnsError(t *testing.T) {
	p := &scriptedJudgeProvider{replies: []string{junkVerdict, junkVerdict, junkVerdict}}
	got, err := judgeWithRetry(context.Background(), p, 7, "sys", intercept.ReviewInput{}, 2)
	if err == nil {
		t.Fatal("expected error after exhausting retries")
	}
	if got.Action != "" {
		t.Fatalf("action=%q want empty", got.Action)
	}
	if p.calls != 3 {
		t.Fatalf("calls=%d want 3 (1 + 2 retries)", p.calls)
	}
	if !strings.Contains(err.Error(), "连续 3 次") {
		t.Fatalf("err=%v", err)
	}
}

// A transient upstream error is retried and can recover.
func TestJudgeRetryRecoversFromTransientError(t *testing.T) {
	p := &scriptedJudgeProvider{errs: []error{errors.New("upstream: status 503")}, replies: []string{"", goodVerdict}}
	got, err := judgeWithRetry(context.Background(), p, 7, "sys", intercept.ReviewInput{}, 1)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got.Action != "deny" || p.calls != 2 {
		t.Fatalf("action=%q calls=%d", got.Action, p.calls)
	}
}

// A canceled context is not retryable: the loop must stop after one attempt.
func TestJudgeRetryStopsOnCanceledContext(t *testing.T) {
	p := &scriptedJudgeProvider{errs: []error{context.Canceled}, replies: []string{"", goodVerdict}}
	_, err := judgeWithRetry(context.Background(), p, 7, "sys", intercept.ReviewInput{}, 3)
	if err == nil {
		t.Fatal("expected error")
	}
	if p.calls != 1 {
		t.Fatalf("calls=%d want 1 (canceled must not retry)", p.calls)
	}
	if !strings.Contains(err.Error(), "调用已取消") {
		t.Fatalf("err=%v", err)
	}
}

// isJudgeRetryableErr must retry only genuinely transient errors, so a permanent
// 4xx (bad key / forbidden / not found) fails fast instead of burning retries.
// The relay's quota/subscription 400 is transient and must be retried.
func TestJudgeRetryClassifiesUpstreamErrors(t *testing.T) {
	cases := []struct {
		msg  string
		want bool
	}{
		{"openai: status 503: upstream down", true},
		{"openai: status 429: slow down", true},
		{"openai: status 408: request timeout", true},
		{"openai: status 500: internal", true},
		{`openai: status 400: {"error":{"message":"Your account (2131789517) does not have a valid AgentPlan subscription; or your subscription has expired"}}`, true},
		{`openai: status 400: {"error":{"message":"请求必须是 JSON"}}`, false},
		{"openai: status 401: invalid api key", false},
		{"openai: status 403: forbidden", false},
		{"openai: status 404: not found", false},
		{"openai: status 422: unprocessable entity", false},
		{"transport: connection reset by peer", true},
	}
	for _, c := range cases {
		if got := isJudgeRetryableErr(errors.New(c.msg)); got != c.want {
			t.Errorf("isJudgeRetryableErr(%q)=%v want %v", c.msg, got, c.want)
		}
	}
}

func TestJudgeRetryStopsOnPermanentClientError(t *testing.T) {
	p := &scriptedJudgeProvider{errs: []error{errors.New("openai: status 401: invalid api key")}, replies: []string{"", goodVerdict}}
	_, err := judgeWithRetry(context.Background(), p, 7, "sys", intercept.ReviewInput{}, 3)
	if err == nil {
		t.Fatal("expected error")
	}
	if p.calls != 1 {
		t.Fatalf("calls=%d want 1 (401 must not retry)", p.calls)
	}
}

func TestJudgeRetryRecoversFromTransient400(t *testing.T) {
	quota := errors.New(`openai: status 400: {"error":{"message":"Your account (2131789517) does not have a valid AgentPlan subscription"}}`)
	p := &scriptedJudgeProvider{errs: []error{quota}, replies: []string{"", goodVerdict}}
	got, err := judgeWithRetry(context.Background(), p, 7, "sys", intercept.ReviewInput{}, 2)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got.Action != "deny" || p.calls != 2 {
		t.Fatalf("action=%q calls=%d", got.Action, p.calls)
	}
}

func TestClassifyJudgeErrLabelsRelayQuota(t *testing.T) {
	quota := errors.New(`openai: status 400: {"error":{"message":"does not have a valid AgentPlan subscription"}}`)
	if got := classifyJudgeErr(quota); got != "上游账号额度/订阅不可用(400)" {
		t.Fatalf("got %q", got)
	}
}

// Backoff must stop immediately on a canceled context and must never sleep past
// the context deadline.
func TestSleepJudgeBackoffHonorsContext(t *testing.T) {
	oldBase, oldMax := judgeBackoffBase, judgeBackoffMax
	judgeBackoffBase, judgeBackoffMax = 10*time.Second, 10*time.Second
	defer func() { judgeBackoffBase, judgeBackoffMax = oldBase, oldMax }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sleepJudgeBackoff(ctx, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v want context.Canceled", err)
	}
	dctx, dcancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer dcancel()
	start := time.Now()
	if err := sleepJudgeBackoff(dctx, 1); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 90*time.Millisecond {
		t.Fatalf("backoff overshot the deadline fraction: %v", elapsed)
	}
}

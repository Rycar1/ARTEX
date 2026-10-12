package server

import (
	"context"
	"errors"
	"iter"
	"strings"
	"testing"

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

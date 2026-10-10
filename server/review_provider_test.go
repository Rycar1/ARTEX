package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
)

// reviewVariant must strip BOTH reasoning knobs: norma sends reasoning_effort
// unconditionally, so leaving it set re-enables hidden reasoning even when the
// request asks for thinking=disabled and burns the whole max_tokens budget.
func TestReviewVariantStripsReasoningParams(t *testing.T) {
	got := reviewVariant(agent.Config{ThinkingType: "enabled", ReasoningEffort: "max", Model: "m"})
	if got.ReasoningEffort != "" {
		t.Errorf("ReasoningEffort=%q, want empty", got.ReasoningEffort)
	}
	if got.ThinkingType != "disabled" {
		t.Errorf("ThinkingType=%q, want disabled", got.ThinkingType)
	}
	if got.Model != "m" {
		t.Errorf("Model=%q, unrelated fields must survive", got.Model)
	}
}

// TestReviewProviderDropsReasoningEffort locks the wire behaviour end to end: a
// profile with reasoning_effort=max keeps that field on the shared provider (the
// bug), while the reviewer's variant sends thinking=disabled and no effort at all.
func TestReviewProviderDropsReasoningEffort(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	pg := m.PG()

	var mu sync.Mutex
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		mu.Lock()
		bodies = append(bodies, body)
		mu.Unlock()
		w.Header().Set("content-type", "application/json")
		_, _ = io.WriteString(w, `{"id":"x","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`)
	}))
	defer srv.Close()

	id, err := pg.SaveProfile(&db.LLMProfile{
		Name:            "review-effort-test",
		Format:          string(llm.FormatOpenAI),
		BaseURL:         srv.URL,
		Model:           "m",
		APIKey:          "k",
		ThinkingType:    "enabled",
		ReasoningEffort: "max",
		MaxTokensField:  "",
	})
	if err != nil {
		t.Fatalf("SaveProfile: %v", err)
	}
	defer func() { _ = pg.DeleteProfile(id) }()

	s := New(context.Background(), m, t.TempDir(), t.TempDir(), t.TempDir())

	req := llm.CompletionRequest{
		Messages:  []llm.Message{llm.UserText("hi")},
		MaxTokens: 512,
		Thinking:  "disabled",
	}

	shared, _, ok := s.providerForProfile(id)
	if !ok {
		t.Fatal("providerForProfile failed")
	}
	if _, _, _, err := shared.Complete(context.Background(), req); err != nil {
		t.Fatalf("shared Complete: %v", err)
	}

	review, _, ok := s.reviewProviderForProfile(id)
	if !ok {
		t.Fatal("reviewProviderForProfile failed")
	}
	if _, _, _, err := review.Complete(context.Background(), req); err != nil {
		t.Fatalf("review Complete: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 2 {
		t.Fatalf("captured %d request bodies, want 2", len(bodies))
	}
	if got := bodies[0]["reasoning_effort"]; got != "max" {
		t.Errorf("shared provider reasoning_effort=%v, want \"max\" (bug fixture)", got)
	}
	if _, present := bodies[1]["reasoning_effort"]; present {
		t.Errorf("review provider must not send reasoning_effort, got %v", bodies[1]["reasoning_effort"])
	}
	th, _ := bodies[1]["thinking"].(map[string]any)
	if th["type"] != "disabled" {
		t.Errorf("review provider thinking=%v, want type=disabled", bodies[1]["thinking"])
	}
}

// TestReviewVariantWireDropsReasoningEffort proves the mechanism without a
// database: the plain profile config puts reasoning_effort on the wire (which is
// what starved the reviewer's JSON budget), while reviewVariant's config does not.
func TestReviewVariantWireDropsReasoningEffort(t *testing.T) {
	var mu sync.Mutex
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		mu.Lock()
		bodies = append(bodies, body)
		mu.Unlock()
		w.Header().Set("content-type", "application/json")
		_, _ = io.WriteString(w, `{"id":"x","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`)
	}))
	defer srv.Close()

	base := agent.Config{
		Format:          llm.FormatOpenAI,
		BaseURL:         srv.URL,
		APIKey:          "k",
		Model:           "m",
		ThinkingType:    "enabled",
		ReasoningEffort: "max",
	}
	req := llm.CompletionRequest{Messages: []llm.Message{llm.UserText("hi")}, MaxTokens: 512, Thinking: "disabled"}

	plain, err := base.NewProvider()
	if err != nil {
		t.Fatalf("plain NewProvider: %v", err)
	}
	if _, _, _, err := plain.Complete(context.Background(), req); err != nil {
		t.Fatalf("plain Complete: %v", err)
	}
	reviewed, err := reviewVariant(base).NewProvider()
	if err != nil {
		t.Fatalf("review NewProvider: %v", err)
	}
	if _, _, _, err := reviewed.Complete(context.Background(), req); err != nil {
		t.Fatalf("review Complete: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 2 {
		t.Fatalf("captured %d request bodies, want 2", len(bodies))
	}
	if got := bodies[0]["reasoning_effort"]; got != "max" {
		t.Errorf("plain config reasoning_effort=%v, want \"max\"", got)
	}
	if _, present := bodies[1]["reasoning_effort"]; present {
		t.Errorf("reviewVariant config must not send reasoning_effort, got %v", bodies[1]["reasoning_effort"])
	}
	th, _ := bodies[1]["thinking"].(map[string]any)
	if th["type"] != "disabled" {
		t.Errorf("reviewVariant thinking=%v, want type=disabled", bodies[1]["thinking"])
	}
}

package agent

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Autumn-27/norma/transcript"
)

// 会话体字段注入的回归测试。事故原型:某中转按请求长度把一部分请求路由到严格通道,
// 返回 upstream 400 code 11-128 "conversation id missing";同样的请求体里加上
// conversation_id 后 100% 成功(实测 8 个必失败长度 + 8 个正常长度 + 流式)。

func bodyRequest(body string) *http.Request {
	r, err := http.NewRequest("POST", "https://relay.example/v1/chat/completions", bytes.NewReader([]byte(body)))
	if err != nil {
		panic(err)
	}
	return r
}

func decodeBody(t *testing.T, req *http.Request) map[string]any {
	t.Helper()
	b, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("注入后不是合法 JSON: %v (%s)", err, b)
	}
	return got
}

func TestInjectSessionBodyFieldAddsFieldAndKeepsOthers(t *testing.T) {
	req := bodyRequest(`{"model":"workbuddy/deepseek-v4.1-flash","messages":[{"role":"user","content":"hi"}],"max_tokens":256}`)
	if err := injectSessionBodyField(req, "conversation_id", "exp52-worker-i8648"); err != nil {
		t.Fatal(err)
	}
	got := decodeBody(t, req)
	if got["conversation_id"] != "exp52-worker-i8648" {
		t.Errorf("conversation_id=%v", got["conversation_id"])
	}
	if got["model"] != "workbuddy/deepseek-v4.1-flash" || got["max_tokens"] != float64(256) {
		t.Errorf("原有字段被破坏: %v", got)
	}
	if _, ok := got["messages"]; !ok {
		t.Error("messages 丢失")
	}
	if req.ContentLength <= 0 {
		t.Errorf("ContentLength 未更新: %d", req.ContentLength)
	}
	// GetBody 必须跟着更新:llmrec 的抓包走 GetBody,否则录到的还是注入前的请求体。
	rc, err := req.GetBody()
	if err != nil {
		t.Fatalf("GetBody: %v", err)
	}
	defer rc.Close()
	snap, _ := io.ReadAll(rc)
	if !bytes.Contains(snap, []byte("conversation_id")) {
		t.Errorf("GetBody 快照未包含注入字段: %s", snap)
	}
	if int64(len(snap)) != req.ContentLength {
		t.Errorf("ContentLength=%d 与快照长度 %d 不一致", req.ContentLength, len(snap))
	}
}

func TestInjectSessionBodyFieldDoesNotOverwriteExisting(t *testing.T) {
	req := bodyRequest(`{"conversation_id":"caller-owned","model":"m"}`)
	if err := injectSessionBodyField(req, "conversation_id", "exp1-worker-i2"); err != nil {
		t.Fatal(err)
	}
	if got := decodeBody(t, req); got["conversation_id"] != "caller-owned" {
		t.Errorf("不应覆盖调用方已填的值, got %v", got["conversation_id"])
	}
}

func TestInjectSessionBodyFieldRejectsNonJSONBody(t *testing.T) {
	req := bodyRequest(`not json at all`)
	if err := injectSessionBodyField(req, "conversation_id", "sid"); err == nil {
		t.Fatal("非 JSON 体应报错(由调用方按原请求发送)")
	}
	b, _ := io.ReadAll(req.Body)
	if string(b) != "not json at all" {
		t.Errorf("失败时不应改动请求体: %s", b)
	}
}

func TestInjectSessionBodyFieldEmptyFieldIsNoop(t *testing.T) {
	// 空字段名由 transport 侧拦住(只有配置了 session_body_field 才会调用),
	// 这里固定住「不加空键」的语义,避免以后有人把判断挪进来。
	req := bodyRequest(`{"model":"m"}`)
	if err := injectSessionBodyField(req, "", "sid"); err != nil {
		t.Fatal(err)
	}
	got := decodeBody(t, req)
	if _, ok := got[""]; ok {
		t.Error("不应写入空字段名")
	}
}

// 传输层端到端:配置了 sessionBodyField 且 ctx 带 session id 时,真正发出去的请求体
// 里必须带该字段 —— 这正是中转要求 conversation id 的那条通路。
func TestTransportInjectsSessionBodyFieldOnTheWire(t *testing.T) {
	got := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- string(b)
		w.Header().Set("content-type", "text/event-stream")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer srv.Close()

	client, err := quotaAwareHTTPClient("", "", "conversation_id")
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, srv.URL, bytes.NewReader([]byte(`{"model":"m","messages":[]}`)))
	if err != nil {
		t.Fatal(err)
	}
	req = req.WithContext(transcript.WithSessionID(req.Context(), "exp52-worker-i8648"))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	_ = resp.Body.Close()

	select {
	case body := <-got:
		var m map[string]any
		if err := json.Unmarshal([]byte(body), &m); err != nil {
			t.Fatalf("wire body: %v (%s)", err, body)
		}
		if m["conversation_id"] != "exp52-worker-i8648" {
			t.Errorf("线上请求体缺会话字段: %s", body)
		}
	default:
		t.Fatal("服务端没收到请求")
	}
}

// 未配置时不注入(旧配置行为不变)。
func TestTransportSkipsSessionBodyFieldWhenUnset(t *testing.T) {
	got := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- string(b)
		w.Header().Set("content-type", "text/event-stream")
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer srv.Close()

	client, err := quotaAwareHTTPClient("", "", "")
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL, bytes.NewReader([]byte(`{"model":"m"}`)))
	req = req.WithContext(transcript.WithSessionID(req.Context(), "sid-1"))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	_ = resp.Body.Close()
	if body := <-got; body != `{"model":"m"}` {
		t.Errorf("未配置时请求体不应被改动, got: %s", body)
	}
}

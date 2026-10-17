package server

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestNewRoutesSmoke 逐条打 dev 相对 main 新增的 HTTP 路由,确认:
//   - 认证后不再是 401(接线正确、认证中间件放行);
//   - 任何一条都不返回 500(没有未处理的错误/nil 解引用);
//   - 记录每条的返回码,便于人工核对语义。
//
// 认证用 testauth_test.go 里的 baAuth(BA 会话 Cookie):既有 HTTP 测试原先发 Bearer,
// 认证改造后全 401,HTTP 层失去回归保护;这里与迁移后的既有测试走同一套认证。
func TestNewRoutesSmoke(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	s.archiveWG.Wait()

	task, err := m.CreateTask("smoke", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.DeleteTask(mustI64(task.ID)) })

	type route struct {
		method, path, body string
		wantNoAuth         bool // true = 该路由本就允许未认证(如 /api/auth/*)
	}
	routes := []route{
		// —— dev 新增的 25 条路由 ——
		{"POST", "/api/auth/refresh", "", true},
		{"POST", "/api/auth/logout", "", true},
		{"POST", "/api/sse-ticket", "", false},
		{"GET", "/api/tasks/" + task.ID + "/pending-scope", "", false},
		{"GET", "/api/exploration/reviews/stats", "", false},
		{"GET", "/api/exploration/findings/duplicates", "", false},
		{"POST", "/api/exploration/findings/merge", `{"ids":[]}`, false},
		{"POST", "/api/exploration/findings/1/escalate", `{}`, false},
		{"POST", "/api/exploration/findings/1/review", `{}`, false},
		{"POST", "/api/exploration/findings/1/dismiss-duplicate", `{}`, false},
		{"GET", "/api/exploration/findings/1/checks", "", false},
		{"POST", "/api/exploration/findings/1/checks", `{}`, false},
		{"GET", "/api/intercept/mode", "", false},
		{"GET", "/api/guard/auto-allow", "", false},
		{"PUT", "/api/guard/auto-allow", `{"enabled":false,"hours":2}`, false},
		{"POST", "/api/stage", `{}`, false},
		{"GET", "/api/stage", "", false},
		{"DELETE", "/api/stage/nonexistent-token", "", false},
		{"GET", "/api/sessions", "", false},
		{"GET", "/api/sessions/1", "", false},
		{"POST", "/api/sessions/1/exec", `{"command":"id"}`, false},
		{"POST", "/api/sessions/1/probe", `{}`, false},
		{"POST", "/api/sessions/1/list", `{"path":"/"}`, false},
		{"POST", "/api/sessions/1/read", `{"path":"/etc/hosts"}`, false},
		{"POST", "/api/sessions/1/write", `{"path":"/tmp/x","content":"x"}`, false},
		{"DELETE", "/api/sessions/1", "", false},
		{"POST", "/api/sessions/1/handoff", `{}`, false},
		{"POST", "/api/tunnels/1/teardown", "", false},
		{"GET", "/api/credentials", "", false},
		{"GET", "/api/intranet/topology", "", false},
		// —— 对照组:改造前就存在的路由,用来确认 baAuth 本身有效 ——
		{"GET", "/api/tasks", "", false},
		{"GET", "/api/settings", "", false},
		{"GET", "/api/health", "", true},
	}

	var noAuth401, unexpected401, serverErr []string
	for _, rt := range routes {
		var body *strings.Reader
		if rt.body != "" {
			body = strings.NewReader(rt.body)
		} else {
			body = strings.NewReader("")
		}
		req := httptest.NewRequest(rt.method, rt.path, body)
		if rt.body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		baAuth(s, req)
		rec := httptest.NewRecorder()
		func() {
			defer func() {
				if p := recover(); p != nil {
					t.Errorf("PANIC %s %s: %v", rt.method, rt.path, p)
				}
			}()
			s.Handler().ServeHTTP(rec, req)
		}()
		code := rec.Code
		t.Logf("%-6s %-48s -> %d  %s", rt.method, rt.path, code, truncate(rec.Body.String(), 120))

		if code == 401 {
			if rt.wantNoAuth {
				noAuth401 = append(noAuth401, rt.method+" "+rt.path)
			} else {
				unexpected401 = append(unexpected401, rt.method+" "+rt.path)
			}
		}
		if code >= 500 {
			serverErr = append(serverErr, rt.method+" "+rt.path)
		}
	}

	if len(unexpected401) > 0 {
		t.Errorf("带会话 Cookie 仍 401(认证/接线问题): %v", unexpected401)
	}
	if len(serverErr) > 0 {
		t.Errorf("返回 5xx(未处理错误/nil 解引用): %v", serverErr)
	}
}

func mustI64(s string) int64 {
	var v int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		v = v*10 + int64(c-'0')
	}
	return v
}

// truncate 截断响应体用于日志,避免刷屏。
func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// TestNewRoutesEdgeCases 针对新增路由做输入校验/语义边界探测,重点找:
//   - 不存在的资源返回 5xx 而不是 4xx(状态码语义错误)
//   - 无效入参被静默接受(缺校验)
//   - 兄弟端点语义不一致(幂等性)
func TestNewRoutesEdgeCases(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	s.archiveWG.Wait()

	do := func(method, path, body string) (int, string) {
		var rd *strings.Reader
		if body != "" {
			rd = strings.NewReader(body)
		} else {
			rd = strings.NewReader("")
		}
		req := httptest.NewRequest(method, path, rd)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		baAuth(s, req)
		rec := httptest.NewRecorder()
		defer func() {
			if p := recover(); p != nil {
				t.Errorf("PANIC %s %s: %v", method, path, p)
			}
		}()
		s.Handler().ServeHTTP(rec, req)
		return rec.Code, truncate(rec.Body.String(), 110)
	}

	cases := []struct {
		name, method, path, body string
		want5xxBad               bool // true = 该用例若返回 5xx 就是 bug
		wantCode                 int  // 非 0 = 期望的精确状态码(修复前应为红)
	}{
		// 不存在的资源:期望 4xx(404/409),不该是 502/500
		{"teardown 不存在的隧道", "POST", "/api/tunnels/999999/teardown", "", true, 404},
		{"teardown 非数字 id", "POST", "/api/tunnels/abc/teardown", "", true, 400},
		{"会话不存在时 exec", "POST", "/api/sessions/999999/exec", `{"command":"id"}`, true, 404},
		{"dismiss 不存在的 finding", "POST", "/api/exploration/findings/999999/dismiss-duplicate", `{}`, true, 404},
		{"checks 不存在的 finding", "POST", "/api/exploration/findings/999999/checks", `{"name":"x"}`, true, 404},
		{"merge 不存在的 target", "POST", "/api/exploration/findings/merge", `{"target_id":"999999","member_ids":["1"]}`, true, 400},
		{"escalate 不存在的 finding", "POST", "/api/exploration/findings/999999/escalate", `{}`, true, 404},
		// 无效入参:期望 400,不该被静默接受
		{"会话 exec 空命令", "POST", "/api/sessions/999999/exec", `{"command":""}`, true, 400},
		{"会话 write 缺 content", "POST", "/api/sessions/999999/write", `{"path":"/tmp/x"}`, true, 0},
		{"stage 非法 base64", "POST", "/api/stage", `{"content_base64":"!!!not-base64!!!"}`, true, 400},
		{"stage 两者都缺", "POST", "/api/stage", `{}`, true, 400},
		{"auto-allow 非法小时数", "PUT", "/api/guard/auto-allow", `{"enabled":true,"hours":99}`, true, 200},
		{"pending-scope 不存在任务", "GET", "/api/tasks/999999/pending-scope", "", true, 404},
		{"merge 空 ids", "POST", "/api/exploration/findings/merge", `{"target_id":"1"}`, true, 400},
		// 幂等性对照
		{"重复 delete 会话", "DELETE", "/api/sessions/999999", "", true, 200},
		{"重复 delete stage", "DELETE", "/api/stage/nope", "", true, 404},
	}
	for _, c := range cases {
		code, body := do(c.method, c.path, c.body)
		t.Logf("%-24s %-6s %-46s -> %d  %s", c.name, c.method, c.path, code, body)
		if c.want5xxBad && code >= 500 {
			t.Errorf("「%s」返回 %d(期望 4xx):%s", c.name, code, body)
		}
		if c.wantCode != 0 && code != c.wantCode {
			t.Errorf("「%s」状态码 = %d,期望 %d:%s", c.name, code, c.wantCode, body)
		}
	}
}

// TestNewRoutesEdgeCases2 第二批边界探测:入参解析、id 溢出、未知字段、幂等性、
// 以及"不存在的目标是否被静默当成功"这一类最容易漏的失败路径。
func TestNewRoutesEdgeCases2(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	s.archiveWG.Wait()

	task, err := m.CreateTask("edge2", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.pg.DeleteTask(mustI64(task.ID)) })

	do := func(method, path, body string) (int, string) {
		var rd *strings.Reader
		if body != "" {
			rd = strings.NewReader(body)
		} else {
			rd = strings.NewReader("")
		}
		req := httptest.NewRequest(method, path, rd)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		baAuth(s, req)
		rec := httptest.NewRecorder()
		defer func() {
			if p := recover(); p != nil {
				t.Errorf("PANIC %s %s: %v", method, path, p)
			}
		}()
		s.Handler().ServeHTTP(rec, req)
		return rec.Code, truncate(rec.Body.String(), 110)
	}

	type c2 struct {
		name, method, path, body string
		wantCode                 int
	}
	cases := []c2{
		// —— id 解析/溢出:必须是 4xx,不能 5xx 也不能当成功 ——
		{"teardown 超大 id", "POST", "/api/tunnels/999999999999999999999/teardown", "", 400},
		{"teardown 负数 id", "POST", "/api/tunnels/-1/teardown", "", 400},
		{"会话 exec id=0", "POST", "/api/sessions/0/exec", `{"command":"id"}`, 400},
		{"review 不存在的 finding", "POST", "/api/exploration/findings/999999/review", `{}`, 0},
		{"checks 超大 finding id", "POST", "/api/exploration/findings/999999999999999999999/checks", `{}`, 400},
		// —— 查询参数校验 ——
		{"credentials task_id 非数字", "GET", "/api/credentials?task_id=abc", "", 400},
		// 曾经:atoiDefault 把非法 task_id 静默变成 0 = 全平台,返回 200 全量重复组。
		{"findings/duplicates task_id 非数字", "GET", "/api/exploration/findings/duplicates?task_id=abc", "", 400},
		{"pending-scope task_id 非数字", "GET", "/api/tasks/abc/pending-scope", "", 404},
		// —— 未知字段/空体 ——
		{"PATCH 任务 未知字段", "PATCH", "/api/tasks/" + task.ID, `{"nope":1}`, 400},
		{"PATCH 任务 空体", "PATCH", "/api/tasks/" + task.ID, `{}`, 400},
		{"PATCH 不存在任务", "PATCH", "/api/tasks/999999", `{"name":"x"}`, 404},
		// —— auto-allow 语义 ——
		{"auto-allow hours=0", "PUT", "/api/guard/auto-allow", `{"enabled":true,"hours":0}`, 200},
		{"auto-allow hours=-5", "PUT", "/api/guard/auto-allow", `{"enabled":true,"hours":-5}`, 200},
		{"auto-allow 关闭", "PUT", "/api/guard/auto-allow", `{"enabled":false}`, 200},
		// —— stage 生命周期(用 base64 内容,不依赖本机路径) ——
		{"stage 建合法条目", "POST", "/api/stage", `{"content_base64":"aGVsbG8=","name":"t.txt"}`, 200},
		{"stage 列表", "GET", "/api/stage", "", 200},
		// —— merge 自指(目标=成员)被过滤后应报 source_ids required ——
		{"merge 目标=成员", "POST", "/api/exploration/findings/merge", `{"target_id":"1","source_ids":["1"]}`, 400},
		// —— review 先查存在性,不存在时 404 优先于 body 校验 ——
		{"review 非法 body", "POST", "/api/exploration/findings/1/review", `not-json`, 404},
	}
	for _, c := range cases {
		code, body := do(c.method, c.path, c.body)
		t.Logf("%-26s %-6s %-48s -> %d  %s", c.name, c.method, c.path, code, body)
		if code >= 500 {
			t.Errorf("「%s」返回 %d(不应 5xx):%s", c.name, code, body)
		}
		if c.wantCode != 0 && code != c.wantCode {
			t.Errorf("「%s」状态码 = %d,期望 %d:%s", c.name, code, c.wantCode, body)
		}
	}
}

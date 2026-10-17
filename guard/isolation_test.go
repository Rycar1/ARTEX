package guard

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// 跨任务数据隔离的回归测试。事故原型:task 52(建任务时丢了靶机入口)用
// `Read /app/data/tasks/50/i8639/HANDOFF.md`、`cat /app/data/transcripts/exp51-planner.jsonl`
// 读到兄弟任务的数据,从里面翻出平台宿主 IP,然后 nmap 扫自家宿主机。

func isolationGuard(taskID int64) *Guard {
	g := New()
	g.SetIsolation(IsolationConfig{
		DataRoot: func() string { return "/app/data" },
		TaskIDOf: func(ctx context.Context) int64 { return taskID },
	})
	return g
}

func TestIsolationBlocksSiblingTaskData(t *testing.T) {
	g := isolationGuard(52)
	cases := []struct {
		name  string
		tool  string
		input string
	}{
		{"读兄弟任务 handoff", "Read", `{"file_path":"/app/data/tasks/50/i8639/HANDOFF.md"}`},
		{"列兄弟任务目录", "Bash", `{"command":"ls -la /app/data/tasks/51/i8643/"}`},
		{"列全部任务", "Bash", `{"command":"ls /app/data/tasks/"}`},
		{"读全部 transcript", "Bash", `{"command":"cat /app/data/transcripts/exp51-planner.jsonl"}`},
		{"grep 全部 transcript", "Bash", `{"command":"grep -h \"ezrce\" /app/data/transcripts/*.jsonl | head -5"}`},
		{"读草稿目录", "Bash", `{"command":"ls -la /app/data/drafts/dmurth5yx14dbevo3/"}`},
		{"读 chat 会话", "Read", `{"file_path":"/app/data/sessions/conv-1499.jsonl"}`},
		{"读任务归档", "Bash", `{"command":"ls /app/data/archives/tasks/"}`},
		{"读兄弟任务流量", "Bash", `{"command":"ls /app/data/traffic/46/"}`},
		{"shell 循环遍历兄弟任务", "Bash", `{"command":"for t in 42 43 44 45 46; do ls /app/data/tasks/$t/*/; done"}`},
		{"路径出现在 heredoc 里", "Bash", `{"command":"cat > /tmp/x.sh <<'EOF'\nhead -50 /app/data/tasks/51/i8643/run_batch.sh\nEOF"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			blocked, msg, _ := g.Hooks().PreToolUse(context.Background(), c.tool, json.RawMessage(c.input))
			if !blocked {
				t.Fatalf("应拦截: %s", c.input)
			}
			if !strings.Contains(msg, "其它任务的数据") {
				t.Errorf("拦截文案应说明跨任务数据, got: %s", msg)
			}
		})
	}
}

func TestIsolationAllowsOwnTaskAndSharedSurface(t *testing.T) {
	g := isolationGuard(52)
	allowed := []string{
		`{"command":"cd /app/data/tasks/52/i8648 && ls -la"}`,
		`{"command":"ls /app/data/tasks/52/"}`,
		`{"command":"cat /app/data/tasks/52/i8648/uploads/main.zip"}`,
		`{"file_path":"/app/data/tasks/52/i8648/notes.md"}`,
		`{"command":"ls /app/skills/ctf-toolbox/"}`,
		`{"command":"python3 /app/data/tools/penelope.py"}`,
		`{"command":"ls /app/data/traffic/52/"}`,
		`{"command":"cat /app/data/stage/job.json"}`,
		`{"command":"ls -la /tmp"}`,
	}
	for _, in := range allowed {
		blocked, msg, _ := g.Hooks().PreToolUse(context.Background(), "Bash", json.RawMessage(in))
		if blocked {
			t.Errorf("不应拦截: %s (%s)", in, msg)
		}
	}
	// 520 是另一个任务:前缀与本任务 id 相同但目录不同,必须拦(逐段比较,不是前缀匹配)。
	if blocked, _, _ := g.Hooks().PreToolUse(context.Background(), "Bash",
		json.RawMessage(`{"command":"ls /app/data/tasks/520/"}`)); !blocked {
		t.Error("tasks/520 不是本任务目录,应拦截")
	}
}

func TestIsolationSkippedForNonTaskRuns(t *testing.T) {
	// taskID=0(chat / 一次性调用)没有「本任务目录」概念 → 本层不判定。
	g := isolationGuard(0)
	blocked, msg, _ := g.Hooks().PreToolUse(context.Background(), "Read",
		json.RawMessage(`{"file_path":"/app/data/transcripts/conv-1.jsonl"}`))
	if blocked {
		t.Errorf("非任务运行不应由隔离层拦截, got: %s", msg)
	}
}

func TestIsolationDisabledWhenNoDataRoot(t *testing.T) {
	g := New() // 未 SetIsolation
	blocked, _, _ := g.Hooks().PreToolUse(context.Background(), "Bash",
		json.RawMessage(`{"command":"cat /app/data/transcripts/exp1.jsonl"}`))
	if blocked {
		t.Error("未装配隔离配置时不应拦截")
	}
}

func TestSharedDataPathsExtraction(t *testing.T) {
	got := sharedDataPaths(`cd /app/data/tasks/51 && cat /app/data/transcripts/x.jsonl; ls /app/data`, "/app/data")
	want := []string{"/app/data/tasks/51", "/app/data/transcripts/x.jsonl", "/app/data"}
	if len(got) != len(want) {
		t.Fatalf("paths=%v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("paths[%d]=%q, want %q", i, got[i], want[i])
		}
	}
}

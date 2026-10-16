package guard

import (
	"context"
	"log"
	"strconv"
	"strings"

	"github.com/Autumn-27/norma/hook"
)

// IsolationConfig wires the per-task data-isolation check.
//
// 背景(实测事故):平台所有任务的工作目录、会话 transcript、草稿都放在同一个容器
// 的同一个数据根下 —— /app/data/tasks/<id>、/app/data/transcripts、/app/data/drafts。
// worker 的 shell 与宿主进程同容器同权限,于是 `cat /app/data/transcripts/exp51-planner.jsonl`
// 就能读到兄弟任务的完整对话。task 52(建任务时丢了靶机入口)正是这样从兄弟任务里
// 翻到平台宿主 IP 172.22.160.164,然后 nmap 全端口扫了自家宿主机(Home Assistant /
// AstrBot OneBot / MariaDB / 自家靶场)45 分钟、0 产出。
//
// 这道检查把「共享数据根」下的路径按任务切分:只允许本任务自己的目录,其余一律拦截。
// 它是平台侧的隔离边界(与目标无关),所以走 block 而不是 ask —— 没有人工审批的余地。
type IsolationConfig struct {
	// DataRoot 返回共享数据根(如 /app/data)。空 = 关闭本检查。
	DataRoot func() string
	// TaskIDOf 从 hook ctx 取当前任务 id(与 RoE 共用同一实现)。
	TaskIDOf func(ctx context.Context) int64
}

// SetIsolation installs the per-task data isolation check. Zero value disables it.
func (g *Guard) SetIsolation(cfg IsolationConfig) {
	g.mu.Lock()
	g.isolation = cfg
	g.mu.Unlock()
}

// 共享数据根下按任务切分的子树:只允许本任务自己的那一段(其余任务的数据是别人的)。
var isolationPartitioned = []string{"tasks", "traffic"}

// 共享数据根下对任务 shell 完全不可读的子树:
//
//	transcripts = 所有任务的完整对话(含目标、payload、发现的凭据)
//	drafts      = 各任务的草稿
//	sessions    = chat 会话目录
//	archives    = 任务归档包(内含其它任务的文件树)
var isolationForbidden = []string{"transcripts", "drafts", "sessions", "archives"}

// checkIsolation is the PreToolUse data-isolation gate. It runs before RoE /
// intercept so a leaked path never reaches the model as a tool result.
//
// 规则(刻意做成定向拒绝而非「只准进自己目录」的白名单,避免误伤平台的合法共享面):
//   - <root>/transcripts|drafts|sessions|archives/**  → 一律拦
//   - <root>/tasks/<id>/**、<root>/traffic/<id>/**   → 只放本任务 id,兄弟任务拦
func (g *Guard) checkIsolation(ctx context.Context, ev hook.Event, cmd string) (hook.Result, bool) {
	g.mu.Lock()
	cfg := g.isolation
	g.mu.Unlock()
	if cfg.DataRoot == nil {
		return hook.Result{}, false
	}
	root := strings.TrimRight(strings.TrimSpace(cfg.DataRoot()), "/")
	if root == "" {
		return hook.Result{}, false
	}
	var taskID int64
	if cfg.TaskIDOf != nil {
		taskID = cfg.TaskIDOf(ctx)
	}
	if taskID <= 0 {
		// 非任务运行(chat / 一次性调用)没有「本任务目录」的概念,不在此层判定。
		return hook.Result{}, false
	}
	own := strconv.FormatInt(taskID, 10)

	subject := cmd
	if subject == "" {
		// Read/Write/Edit/Grep/Glob 等工具的入参是 JSON,路径就在原文里 —— 直接扫原始
		// 输入即可,不必为每个工具单独解析字段(漏一个字段就等于漏一条通路)。
		subject = string(ev.Input)
	}
	for _, p := range sharedDataPaths(subject, root) {
		rel := strings.TrimPrefix(p, root)
		rel = strings.Trim(rel, "/")
		if rel == "" {
			continue
		}
		seg, rest, _ := strings.Cut(rel, "/")
		switch {
		case containsString(isolationForbidden, seg):
			// 命中:整棵子树都不可读
		case containsString(isolationPartitioned, seg):
			owner, _, _ := strings.Cut(rest, "/")
			if owner == own {
				continue // 本任务自己的目录
			}
		default:
			continue // 平台共享面(tools/ stage/ reverse/ …)照旧放行
		}
		log.Printf("[guard][isolation] task %d 越界访问共享数据根: %s(%s)", taskID, p, ev.ToolName)
		return g.block(ev.ToolName, systemBlockMessage(
			"访问了其它任务的数据("+p+")。每个任务只能读写自己的工作目录 "+root+"/tasks/"+own+
				";跨任务读取会泄漏其它任务的对话、目标与凭据,平台一律禁止。请改用本任务目录下的文件。"), ""), true
	}
	return hook.Result{}, false
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// sharedDataPaths returns every path-looking token in text that starts at root.
// The scan is textual on purpose: it must also catch paths buried inside a shell
// pipeline, a heredoc, or a JSON tool argument.
func sharedDataPaths(text, root string) []string {
	var out []string
	for off := 0; off < len(text); {
		i := strings.Index(text[off:], root)
		if i < 0 {
			break
		}
		start := off + i
		end := start
		for end < len(text) && isPathByte(text[end]) {
			end++
		}
		if p := strings.TrimRight(text[start:end], ".,:;)]}\"'"); p != "" {
			out = append(out, p)
		}
		if end <= start {
			end = start + 1 // 理论上不会发生(root 非空);保险起见不原地打转
		}
		off = end
	}
	return out
}

// isPathByte reports whether b may continue a path token. Anything else — shell
// metacharacters, quotes, whitespace, and every non-ASCII byte — ends the token.
// Truncating early is safe: the check only needs the ASCII prefix that decides
// which task's directory the path lands in.
func isPathByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	case b == '/', b == '.', b == '-', b == '_', b == '~', b == '+', b == '=', b == '@', b == '%':
		return true
	}
	return false
}

package server

import (
	"strings"
	"testing"
)

// TestSetWorkersRejectsOutOfRange workers 必须有上界:填 999 会拉起 999 条并发
// agent 循环,打爆内存/上游配额/目标侧承载。超限要明确报错而不是静默接受。
func TestSetWorkersRejectsOutOfRange(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()

	for _, bad := range []int{0, -1, maxWorkers + 1, 999} {
		if err := m.SetWorkers(bad); err == nil {
			t.Fatalf("workers=%d 应被拒绝,实际接受了", bad)
		}
	}
	for _, ok := range []int{1, 3, maxWorkers} {
		if err := m.SetWorkers(ok); err != nil {
			t.Fatalf("workers=%d 应被接受,实际报错: %v", ok, err)
		}
		if got := m.Workers(); got != ok {
			t.Fatalf("workers 读回 = %d,期望 %d", got, ok)
		}
	}
	// 收尾恢复默认,避免污染共享库。
	t.Cleanup(func() { _ = m.SetWorkers(3) })
}

// TestSetConcurrencyRejectsOutOfRange 任务并发上限同样必须有上界。
//
// 注意:这个用例会真的写 settings.task_concurrency_enabled=true。共享 dev 库上
// 别的用例(任务准入/生命周期)依赖它是关的,所以必须在**每个**退出路径上恢复,
// 否则整包跑时会因"新任务被排队 → planner 不跑 → goal 节点为 0"而连累无关用例。
func TestSetConcurrencyRejectsOutOfRange(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	// 先登记恢复,再开始改值 —— 中途 t.Fatalf 也能保证清理。
	t.Cleanup(func() { _ = m.SetConcurrency(false, defaultConcurrencyLimit) })

	for _, bad := range []int{maxConcurrencyLimit + 1, 999} {
		if err := m.SetConcurrency(true, bad); err == nil {
			t.Fatalf("并发上限=%d 应被拒绝,实际接受了", bad)
		}
	}
	for _, ok := range []int{1, 5, maxConcurrencyLimit} {
		if err := m.SetConcurrency(true, ok); err != nil {
			t.Fatalf("并发上限=%d 应被接受,实际报错: %v", ok, err)
		}
		on, got := m.ConcurrencyLimit()
		if !on || got != ok {
			t.Fatalf("并发上限读回 = (%v,%d),期望 (true,%d)", on, got, ok)
		}
	}
	// <1 仍按原语义回落默认值,不是错误。
	if err := m.SetConcurrency(true, 0); err != nil {
		t.Fatalf("并发上限=0 应回落默认值而非报错: %v", err)
	}
}

// TestSetWebSearchRejectsUnknownBackend 后端名必须白名单校验:写坏后 UI 照原样回显,
// 而搜索工具要到真正调用时才失败(配置看起来成功、功能静默不可用)。
func TestSetWebSearchRejectsUnknownBackend(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()

	for _, bad := range []string{"brave", "bogus_backend", "DDGS", "brave free"} {
		if err := m.SetWebSearch(false, bad, nil, nil, nil); err == nil {
			t.Fatalf("后端 %q 应被拒绝,实际接受了", bad)
		} else if !strings.Contains(err.Error(), "未知的网络搜索后端") {
			t.Fatalf("后端 %q 的错误信息应说明未知后端,实际: %v", bad, err)
		}
	}
	for _, ok := range webSearchBackends {
		if err := m.SetWebSearch(false, ok, nil, nil, nil); err != nil {
			t.Fatalf("后端 %q 应被接受,实际报错: %v", ok, err)
		}
	}
	// 空值仍回落默认后端,保持旧行为。
	if err := m.SetWebSearch(false, "", nil, nil, nil); err != nil {
		t.Fatalf("空后端应回落默认值: %v", err)
	}
}

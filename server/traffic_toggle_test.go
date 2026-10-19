package server

import (
	"testing"
)

// TestTrafficRecordingFollowsToggle 关闭流量捕获必须真的停止落库。
//
// 代理端口本身保持监听(容器端口映射 + 浏览器 MCP 都依赖它),但"关闭时不记录任何
// 流量"这条承诺要由录制器的门控保证 —— 否则关闭前就启动的 agent 仍持 HTTP_PROXY,
// 其流量会继续被录下来,与 UI 文案不符。
func TestTrafficRecordingFollowsToggle(t *testing.T) {
	m, err := NewManager(t.TempDir(), "127.0.0.1:0")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	if m.traffic == nil {
		t.Skip("traffic subsystem not started in this environment")
	}

	// 开 → 录制器开
	if err := m.SetTrafficEnabled(true); err != nil {
		t.Fatal(err)
	}
	if !m.traffic.Recording() {
		t.Fatal("traffic_capture=true 时录制器应为开启状态")
	}
	if !m.TrafficEnabled() {
		t.Fatal("TrafficEnabled() 应为 true")
	}

	// 关 → 录制器关
	if err := m.SetTrafficEnabled(false); err != nil {
		t.Fatal(err)
	}
	if m.traffic.Recording() {
		t.Fatal("traffic_capture=false 时录制器必须停止落库(端口可继续监听)")
	}
	if m.TrafficEnabled() {
		t.Fatal("TrafficEnabled() 应为 false")
	}

	t.Cleanup(func() { _ = m.SetTrafficEnabled(false) })
}

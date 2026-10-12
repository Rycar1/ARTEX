package dispatch

import (
	"testing"
	"time"
)

func TestEnabledFor(t *testing.T) {
	cfg := Config{PendingLimit: 3, DeadThreshold: 3}
	if !cfg.EnabledFor(false) {
		t.Fatalf("标准模式应启用聚类限流")
	}
	if cfg.EnabledFor(true) {
		t.Fatalf("激进模式应关闭聚类限流")
	}
	off := Config{PendingLimit: 0, DeadThreshold: 0}
	if off.EnabledFor(false) {
		t.Fatalf("上限与阈值都为 0 时视为关闭")
	}
}

func TestEvaluateCooldown(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := Config{PendingLimit: 3, DeadThreshold: 3, Cooldown: time.Minute}
	cool := map[string]time.Time{"a.com|portal": now.Add(30 * time.Second)}
	v := Evaluate([]string{"a.com|portal"}, cool, nil, cfg, now)
	if !v.Skip || v.Reason == "" {
		t.Fatalf("冷却中的 cluster 应被跳过, got %+v", v)
	}
	// 冷却已过期 → 放行
	expired := map[string]time.Time{"a.com|portal": now.Add(-time.Second)}
	if v := Evaluate([]string{"a.com|portal"}, expired, nil, cfg, now); v.Skip {
		t.Fatalf("过期冷却不应拦截: %+v", v)
	}
}

func TestEvaluatePendingLimit(t *testing.T) {
	now := time.Now()
	cfg := Config{PendingLimit: 3, DeadThreshold: 3}
	// 同簇已有 3 条在跑 → 第 4 条被拦
	v := Evaluate([]string{"a.com"}, nil, map[string]int{"a.com": 3}, cfg, now)
	if !v.Skip {
		t.Fatalf("达到并发上限应被跳过: %+v", v)
	}
	// 只有 2 条在跑 → 放行
	if v := Evaluate([]string{"a.com"}, nil, map[string]int{"a.com": 2}, cfg, now); v.Skip {
		t.Fatalf("未达上限不应拦截: %+v", v)
	}
	// 无聚类信息 → 永不拦
	if v := Evaluate(nil, nil, nil, cfg, now); v.Skip {
		t.Fatalf("无聚类信息不应拦截")
	}
	// 多聚类:任一超限即拦
	if v := Evaluate([]string{"a.com", "b.com"}, nil, map[string]int{"a.com": 1, "b.com": 9}, cfg, now); !v.Skip {
		t.Fatalf("任一聚类超限即应拦截")
	}
}

func TestEvaluateDedup(t *testing.T) {
	now := time.Now()
	cfg := Config{PendingLimit: 2, DeadThreshold: 3}
	// 重复聚类不重复计数
	if v := Evaluate([]string{"a.com", "a.com"}, nil, map[string]int{"a.com": 1}, cfg, now); v.Skip {
		t.Fatalf("重复聚类不应被误判超限")
	}
}

func TestShouldCooldown(t *testing.T) {
	cfg := Config{DeadThreshold: 3}
	if ShouldCooldown(2, cfg) {
		t.Fatalf("未达阈值不应冷却")
	}
	if !ShouldCooldown(3, cfg) {
		t.Fatalf("达到阈值应冷却")
	}
	if ShouldCooldown(3, Config{DeadThreshold: 0}) {
		t.Fatalf("阈值为 0 表示关闭冷却")
	}
}

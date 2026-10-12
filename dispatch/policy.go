// Package dispatch 是派发闸门(policy-only,无状态):
// 同一套系统(同款聚类 cluster)的并发上限 + 连续失败冷却。
//
// 动机:一个资产/一套系统被 FOFA 式地铺开成几百条意图后,worker 会在同一簇上
// 反复空转;而持续 5xx/不通的目标又会占满派发水位,把真正有戏的目标挤在后面。
// 这里给出确定性的判据(纯函数),由 engine 在领取意图前调用。
package dispatch

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultDeadThreshold = 3
	defaultPendingLimit  = 3
	defaultCooldownSec   = 900
)

// Config 是派发闸门参数。全部可由环境变量覆盖,便于不同部署调优。
type Config struct {
	// DeadThreshold:同一 cluster 连续失败达到该值 → 冷却。
	DeadThreshold int
	// PendingLimit:同一 cluster 同时 running 的意图上限(<=0 表示不限)。
	PendingLimit int
	// Cooldown:冷却时长(期间该 cluster 的意图不参与派发)。
	Cooldown time.Duration
	// Enterprise:企业 SRC 是否也按同款聚类限流。默认 false —— 企业资产面广、
	// 同名系统多,同款限流容易误伤;EDU/CTF 等默认开启。
	Enterprise bool
}

func envInt(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func envBool(key string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}

// DefaultConfig 读环境变量并给出默认值。
func DefaultConfig() Config {
	return Config{
		DeadThreshold: envInt("ARTEX_CLUSTER_DEAD_THRESHOLD", defaultDeadThreshold),
		PendingLimit:  envInt("ARTEX_CLUSTER_PENDING_LIMIT", defaultPendingLimit),
		Cooldown:      time.Duration(envInt("ARTEX_CLUSTER_COOLDOWN_SEC", defaultCooldownSec)) * time.Second,
		Enterprise:    envBool("ARTEX_CLUSTER_LIMIT_ENTERPRISE", false),
	}
}

// EnabledFor 判断当前是否启用同款聚类限流。
// 激进模式(aggressive)一律关闭:此时以"不择一切手段拿到结果"为先,不按同款降速。
func (c Config) EnabledFor(aggressive bool) bool {
	if aggressive {
		return false
	}
	return c.PendingLimit > 0 || c.DeadThreshold > 0
}

// Verdict 描述一条意图是否被闸门拦下。
type Verdict struct {
	Skip   bool   `json:"skip"`
	Reason string `json:"reason,omitempty"`
}

// Evaluate 判定携带 clusters 的意图此刻是否应当跳过派发。
//   - cooldowns: cluster → 冷却截止时间(仅未过期的需要传入)
//   - running:   cluster → 当前 running 意图数
//
// 任一 cluster 处于冷却中 → 跳过;任一 cluster 的 running 已达上限 → 跳过。
func Evaluate(clusters []string, cooldowns map[string]time.Time, running map[string]int, cfg Config, now time.Time) Verdict {
	seen := map[string]bool{}
	for _, c := range clusters {
		c = strings.TrimSpace(c)
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		if until, ok := cooldowns[c]; ok && until.After(now) {
			return Verdict{Skip: true, Reason: CooldownReason(c, until, now)}
		}
	}
	if cfg.PendingLimit > 0 {
		for _, c := range clusters {
			c = strings.TrimSpace(c)
			if c == "" {
				continue
			}
			if running[c] >= cfg.PendingLimit {
				return Verdict{Skip: true, Reason: PendingLimitReason(c, running[c], cfg.PendingLimit)}
			}
		}
	}
	return Verdict{}
}

// ShouldCooldown 判断连续失败计数是否达到冷却阈值。
func ShouldCooldown(dead int, cfg Config) bool {
	return cfg.DeadThreshold > 0 && dead >= cfg.DeadThreshold
}

// CooldownReason 给出人读的冷却说明(进 planner 视野/日志)。
func CooldownReason(cluster string, until, now time.Time) string {
	left := until.Sub(now)
	if left < 0 {
		left = 0
	}
	return fmt.Sprintf("同款聚类 %s 处于冷却中(连续失败触发),剩余 %s;换同簇其他入口收益低,先打别的簇",
		cluster, left.Round(time.Second))
}

// PendingLimitReason 给出人读的并发上限说明。
func PendingLimitReason(cluster string, running, limit int) string {
	return fmt.Sprintf("同款聚类 %s 当前已有 %d 条意图在跑(上限 %d),先等它们出结果,避免同簇空转",
		cluster, running, limit)
}

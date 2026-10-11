package db

import "strings"

// 任务作战模式(tasks.op_mode)。standard 是默认的稳健模式;aggressive 是「激进模式」:
// 平台侧放宽一切技术性限制(见 server/op_mode.go),仅保留两条底线 —— ①资产范围边界
// (不越权打偏到未授权目标)②破坏性/自毁操作(不影响目标正常业务)。
const (
	OpModeStandard   = "standard"
	OpModeAggressive = "aggressive"
)

// NormalizeOpMode 归一化作战模式:aggressive(含 aggressive/激进 等别名)→ aggressive;
// 其余(含空串)→ standard。默认 standard 是安全取向 —— 读不到/写错一律按最保守处理。
func NormalizeOpMode(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "aggressive", "aggr", "激进", "激进模式":
		return OpModeAggressive
	default:
		return OpModeStandard
	}
}

// IsAggressiveOpMode 便捷判断某模式串是否等价于 aggressive。
func IsAggressiveOpMode(raw string) bool { return NormalizeOpMode(raw) == OpModeAggressive }

// TaskOpMode 读取任务的作战模式(tasks.op_mode)。缺行/读失败/taskID<=0 → standard
// (默认稳健):激进模式必须显式开启,读不到就绝不激进。
func (d *DB) TaskOpMode(taskID int64) string {
	if taskID <= 0 {
		return OpModeStandard
	}
	var m string
	if err := d.QueryRow(`SELECT COALESCE(op_mode,'standard') FROM tasks WHERE id=$1`, taskID).Scan(&m); err != nil {
		return OpModeStandard
	}
	return NormalizeOpMode(m)
}

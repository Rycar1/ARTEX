package server

import (
	"strconv"

	"github.com/Autumn-27/artex/db"
)

// wireTaskOpMode 把「任务作战模式」解析器装进进程级拦截器:HandleAsk 在创建 pending 审批
// 前先问一次该任务是不是激进模式,是则直接放行(历史记 decision_source=aggressive)。
// 见 intercept.HandleAsk / intercept.SetTaskOpMode 与 db/op_mode.go。
func (s *Server) wireTaskOpMode() {
	s.m.interceptor.SetTaskOpMode(func(taskID string) string {
		if t, ok := s.m.Task(taskID); ok {
			return t.OpMode
		}
		if id, err := strconv.ParseInt(taskID, 10, 64); err == nil && s.m.pg != nil {
			return s.m.pg.TaskOpMode(id)
		}
		return ""
	})
}

// aggressiveTaskOpMode 报告任务是否处于激进模式(供 server 侧其它放宽点判断,避免各处
// 重复 IsAggressiveOpMode(t.OpMode))。
func aggressiveTaskOpMode(t *Task) bool {
	return t != nil && db.IsAggressiveOpMode(t.OpMode)
}

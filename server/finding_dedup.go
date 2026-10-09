package server

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// =====================================================================
// 四层去重第四层:人工合并 / 疑似重复视图 API(数据层见 db/finding_merge_manual.go)
//   1) POST /api/exploration/findings/merge                 勾选多条 → 合并到一条
//   2) GET  /api/exploration/findings/duplicates            疑似重复 / 已合并分组
//   3) POST /api/exploration/findings/{id}/dismiss-duplicate 人工判定「不是重复」
// =====================================================================

// parseFindingIDRaw 解析 body 里的 id 字段:容忍 JSON 数字(123)与字符串("123")。
// 解析不出正整数返回 0(调用方据此忽略或报错)。
func parseFindingIDRaw(raw json.RawMessage) int64 {
	txt := strings.TrimSpace(string(raw))
	if txt == "" || txt == "null" {
		return 0
	}
	txt = strings.TrimSpace(strings.Trim(txt, "\""))
	id, err := strconv.ParseInt(txt, 10, 64)
	if err != nil || id <= 0 {
		return 0
	}
	return id
}

// mergeFindings 把勾选的漏洞合并进目标漏洞。
// body: {"source_ids":[...],"target_id":123};两个字段都容忍字符串写法。
// 目标不存在 → 404;source 不存在或已并到同一目标 → 计入 skipped(幂等,不报错)。
func (s *Server) mergeFindings(w http.ResponseWriter, r *http.Request) {
	if s.m == nil || s.m.pg == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	var body struct {
		SourceIDs []json.RawMessage `json:"source_ids"`
		TargetID  json.RawMessage   `json:"target_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	targetID := parseFindingIDRaw(body.TargetID)
	if targetID <= 0 {
		writeErr(w, 400, "target_id required")
		return
	}
	var sources []int64
	seen := map[int64]bool{targetID: true}
	for _, raw := range body.SourceIDs {
		id := parseFindingIDRaw(raw)
		if id <= 0 || seen[id] {
			continue
		}
		seen[id] = true
		sources = append(sources, id)
	}
	if len(sources) == 0 {
		writeErr(w, 400, "source_ids required")
		return
	}
	res, err := s.m.pg.MergeFindings(r.Context(), sources, targetID)
	if err != nil {
		if errors.Is(err, db.ErrFindingNotFound) {
			writeErr(w, 404, "finding not found")
			return
		}
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, res)
}

// findingsDuplicates 返回「疑似重复 / 已合并」分组视图(发现页徽标与合并面板用)。
// query: task_id(可选,独立 findings 表任务 id;<=0 表示全部)、limit。
func (s *Server) findingsDuplicates(w http.ResponseWriter, r *http.Request) {
	if s.m == nil || s.m.pg == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	q := r.URL.Query()
	taskID := int64(atoiDefault(q.Get("task_id"), 0))
	limit := findingPaginationParam(q.Get("limit"), 100, 500)
	groups, err := s.m.pg.ListFindingDuplicateGroups(taskID, limit)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"items": groups})
}

// dismissDuplicate 人工判定「这条不是重复」:清掉 suspected_dup_of / score 标记。
// 只清标记,不动状态(用户可再单独改 status)。
func (s *Server) dismissDuplicate(w http.ResponseWriter, r *http.Request) {
	if s.m == nil || s.m.pg == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	id := int64(atoiDefault(r.PathValue("id"), 0))
	if id <= 0 {
		writeErr(w, 400, "bad finding id")
		return
	}
	if err := s.m.pg.ClearFindingSuspectedDuplicate(id); err != nil {
		log.Printf("[dedup] 清除疑似重复标记失败 finding=%d: %v", id, err)
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "id": id})
}

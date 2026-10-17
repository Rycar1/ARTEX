package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestTaskMetadataPatchReturnsRenameAndPin(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	task, err := m.CreateTask("metadata patch", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	taskID, _ := strconv.ParseInt(task.ID, 10, 64)
	defer func() { _ = m.pg.DeleteTask(taskID) }()
	s := New(context.Background(), m, t.TempDir(), t.TempDir(), t.TempDir())

	body, _ := json.Marshal(map[string]any{"name": "  renamed task  ", "pinned": true})
	req := httptest.NewRequest(http.MethodPatch, "/api/tasks/"+task.ID, bytes.NewReader(body))
	baAuth(s, req)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch status=%d body=%s", rec.Code, rec.Body.String())
	}
	var updated struct {
		Name     string `json:"name"`
		Pinned   bool   `json:"pinned"`
		PinnedAt string `json:"pinned_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &updated); err != nil {
		t.Fatal(err)
	}
	if updated.Name != "renamed task" || !updated.Pinned || updated.PinnedAt == "" {
		t.Fatalf("unexpected task patch response: %+v", updated)
	}

	body, _ = json.Marshal(map[string]any{"name": strings.Repeat("任", maxTaskNameRunes+1)})
	req = httptest.NewRequest(http.MethodPatch, "/api/tasks/"+task.ID, bytes.NewReader(body))
	baAuth(s, req)
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("overlong task name status=%d body=%s", rec.Code, rec.Body.String())
	}
}

// 无人值守开关:任务创建后可单独切换,DB 列 / TaskPatch / 内存 Task / DTO 四处必须一致。
// 走 Manager 直连(不经 HTTP):本环境的 HTTP 认证路径在测试里恒返回 401
// (既有的 TestTaskMetadataPatchReturnsRenameAndPin 同样 401),属环境问题,
// 与本改动无关;这里覆盖的是本次新增的字段接线。
func TestTaskUnattendedPatchRoundtrip(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	task, err := m.CreateTask("unattended patch", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	taskID, _ := strconv.ParseInt(task.ID, 10, 64)
	defer func() { _ = m.pg.DeleteTask(taskID) }()

	// 默认关(建任务不带 unattended)。
	if task.Unattended {
		t.Fatal("新建任务默认应为非无人值守")
	}
	if m.pg.TaskUnattended(taskID) {
		t.Fatal("DB 默认应为 false")
	}

	// 开启 → 内存 Task、DB、DTO 三处都为 true。
	on := true
	updated, err := m.UpdateTaskMetadata(task.ID, db.TaskPatch{Unattended: &on})
	if err != nil {
		t.Fatal(err)
	}
	if updated == nil || !updated.Unattended {
		t.Fatalf("开启后内存 Task 应为 true: %+v", updated)
	}
	if !m.pg.TaskUnattended(taskID) {
		t.Fatal("开启后 DB 应为 true")
	}
	if dto := taskDTO(updated, updated.Status); !dto.Unattended {
		t.Fatal("开启后 DTO 应为 true")
	}
	// 重新从 DB 载入也要是 true(scanTask 列顺序与 taskCols 对齐)。
	if reloaded, ok := m.Task(task.ID); !ok || !reloaded.Unattended {
		t.Fatalf("重新载入后应为 true: ok=%v task=%+v", ok, reloaded)
	}

	// 关闭 → 全部回到 false。
	off := false
	updated, err = m.UpdateTaskMetadata(task.ID, db.TaskPatch{Unattended: &off})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Unattended || m.pg.TaskUnattended(taskID) || taskDTO(updated, updated.Status).Unattended {
		t.Fatalf("关闭后应全为 false: mem=%v db=%v", updated.Unattended, m.pg.TaskUnattended(taskID))
	}

	// 不带 unattended 的 patch 不得把它改回默认值(只改 name)。
	name := "renamed"
	updated, err = m.UpdateTaskMetadata(task.ID, db.TaskPatch{Name: &name})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Unattended {
		t.Fatal("未提供 unattended 时不应被重置")
	}
}

func TestConversationBatchDeleteReportsMissing(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	s := New(context.Background(), m, t.TempDir(), t.TempDir(), t.TempDir())
	first, err := m.pg.CreateConversation("mainagent", "batch-http-first", nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.pg.CreateConversation("mainagent", "batch-http-second", nil)
	if err != nil {
		_ = m.pg.DeleteConversation(first.ID)
		t.Fatal(err)
	}
	defer func() {
		_ = m.pg.DeleteConversation(first.ID)
		_ = m.pg.DeleteConversation(second.ID)
	}()
	missing := int64(1<<62 - 1)
	body, _ := json.Marshal(map[string]any{"ids": []int64{first.ID, missing, second.ID}})
	req := httptest.NewRequest(http.MethodPost, "/api/conversations/delete/batch", bytes.NewReader(body))
	baAuth(s, req)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("batch delete status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Items []conversationDeleteItem `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Items) != 3 || !response.Items[0].OK || response.Items[1].OK || !response.Items[2].OK {
		t.Fatalf("batch delete response=%+v", response.Items)
	}
	for _, id := range []int64{first.ID, second.ID} {
		if conversation, err := m.pg.GetConversation(id); err != nil || conversation != nil {
			t.Fatalf("conversation %d still exists: %+v err=%v", id, conversation, err)
		}
	}
	if response.Items[1].Error == "" {
		t.Fatalf("missing conversation %s must include an error", fmt.Sprint(missing))
	}
}

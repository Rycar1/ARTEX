package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

// 端到端:report_finding 工具在挖掘期就拒收垃圾,并且**不落库**;真洞照常落库
// 且 self_check 原样存下来。这是「挖的时候就少报」的核心保证。
func TestReportFindingGateEndToEnd(t *testing.T) {
	d := testDB(t)
	task, err := d.CreateTask("finding-gate-e2e", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM tasks WHERE id=$1`, task.ID) })

	es := d.Exploration(task.ExplorationID)
	intentID, err := es.AddIntent(map[string]any{"summary": "test intent"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	tools := NewToolSet(es, "work#1")
	tools.SetTaskID(task.ID)
	tools.SetFindingSrcType("edusrc")

	findingTool := findToolByName(t, tools.WorkerTools(), "report_finding")
	countFindings := func() int {
		var n int
		if err := d.QueryRow(`SELECT count(*) FROM findings WHERE task_id=$1`, task.ID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// ---- 1) 垃圾洞:必须被拒收,且不落库 ----
	junk := map[string]any{
		"vulnclass": "信息泄露（响应头泄露内网/节点 IP）",
		"name":      "信息泄露（响应头泄露内网/节点 IP） gamerobot.qq.com",
		"severity":  "low",
		"summary":   "响应头 CSP 白名单暴露内网地址",
		"evidence":  "img-src http://9.130.160.194:9000",
		"intent_id": intentID,
	}
	raw, _ := json.Marshal(junk)
	res, err := findingTool.Call(context.Background(), raw, nil)
	if err != nil {
		t.Fatalf("工具调用本身不应报错: %v", err)
	}
	out := res.Flatten()
	if !strings.Contains(out, "拒收") {
		t.Fatalf("垃圾洞应被拒收, got: %s", out)
	}
	if !strings.Contains(out, GateInfoExposure) {
		t.Fatalf("拒收文本应带类别 %s, got: %s", GateInfoExposure, out)
	}
	if n := countFindings(); n != 0 {
		t.Fatalf("被拒收的提交不应落库, 但 findings=%d", n)
	}

	// ---- 2) 带 self_check 自认的垃圾:同样拒收 ----
	reflected := map[string]any{
		"vulnclass": "xss", "name": "反射型 XSS", "severity": "medium",
		"summary": "参数回显", "evidence": "payload 回显到页面", "intent_id": intentID,
		"self_check": map[string]any{"is_reflected_xss": true},
	}
	raw2, _ := json.Marshal(reflected)
	res2, _ := findingTool.Call(context.Background(), raw2, nil)
	if !strings.Contains(res2.Flatten(), GateSelfDeclaredIgnore) {
		t.Fatalf("自检自认的反射 XSS 应被拒收, got: %s", res2.Flatten())
	}
	if n := countFindings(); n != 0 {
		t.Fatalf("自检拒收也不应落库, 但 findings=%d", n)
	}

	// ---- 3) 真洞:照常落库,且 self_check 原样存下来 ----
	real := map[string]any{
		"vulnclass": "sql_injection", "name": "教务系统 SQL 注入可 UNION 拖库",
		"severity": "critical", "summary": "id 参数可 UNION 注入读出 users 表",
		"evidence":  "GET /list?id=1' UNION SELECT username,password FROM users-- HTTP/1.1\nHTTP/1.1 200 OK\nadmin:$2y$10$...",
		"intent_id": intentID,
		"self_check": map[string]any{
			"info_leak_hits_strict_list": true,
			"is_public_interface":        false,
		},
	}
	raw3, _ := json.Marshal(real)
	res3, err := findingTool.Call(context.Background(), raw3, nil)
	if err != nil {
		t.Fatalf("真洞上报出错: %v", err)
	}
	if strings.Contains(res3.Flatten(), "拒收") {
		t.Fatalf("真洞不应被拒收: %s", res3.Flatten())
	}
	if n := countFindings(); n != 1 {
		t.Fatalf("真洞应落库, 但 findings=%d", n)
	}
	var stored []byte
	if err := d.QueryRow(`SELECT self_check FROM findings WHERE task_id=$1`, task.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	var sc map[string]bool
	if err := json.Unmarshal(stored, &sc); err != nil {
		t.Fatalf("self_check 未按 JSON 存: %v (%s)", err, string(stored))
	}
	if !sc["info_leak_hits_strict_list"] {
		t.Fatalf("self_check 内容未落库: %s", string(stored))
	}
}

// 闸门说明段必须真的进了 worker 系统提示词(否则 worker 不知道要填 self_check)。
func TestWorkerPromptCarriesFindingGate(t *testing.T) {
	got := workerSystem("", "", "/data", "/data/tasks/1/i2", false)
	for _, want := range []string{"提交闸门", "self_check", "is_reflected_xss", "info_leak_hits_strict_list", "提交前自问三句"} {
		if !strings.Contains(got, want) {
			t.Errorf("worker 系统提示词缺少 %q", want)
		}
	}
}

func findToolByName(t *testing.T, tools []actool.CoreTool, name string) actool.CoreTool {
	t.Helper()
	for _, tl := range tools {
		if tl.Name() == name {
			return tl
		}
	}
	t.Fatalf("工具 %q 不在集合里", name)
	return nil
}

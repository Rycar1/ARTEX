package db

import (
	"database/sql"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestNormalizeVulnClass(t *testing.T) {
	cases := map[string]string{
		"SQLi":                           "sqli",
		"sql-injection":                  "sqli",
		"SQL Injection":                  "sqli",
		" sql_injection ":                "sqli",
		"XSS":                            "xss",
		"Cross-Site Scripting":           "xss",
		"SSRF":                           "ssrf",
		"SSTI":                           "ssti",
		"Server-Side Template Injection": "ssti",
		"XXE":                            "xxe",
		"RCE":                            "cmdi",
		"cmdi":                           "cmdi",
		"Command Injection":              "cmdi",
		"remote code execution":          "cmdi",
		"File Upload":                    "upload",
		"Auth Bypass":                    "auth-bypass",
		"business_logic":                 "logic",
		"Deserialization":                "deser",
		"Insecure Deserialization":       "deser",
		"Information Disclosure":         "info-leak",
		"privilege escalation":           "privesc",
		"other":                          "other",
		// 模糊段:实战漂移字符串对(归一后必须相等,才能互相合并)
		"Stored Cross-Site Scripting (XSS)": "xss",
		"XSS (Stored)":                      "xss",
		// blind sqli 归到 sqli(与现有粗类一致,盲注是利用手法而非新类目)
		"SQL Injection (Blind)": "sqli",
		"Blind SQL Injection":   "sqli",
		"SQL 盲注":                "sqli",
		// 中文 / 带 CVE 号 / 括号内缩写
		"任意文件上传 (CVE-2017-12615)": "upload",
		"任意文件上传":                  "upload",
		"远程代码执行":                  "cmdi",
		"远程命令执行":                  "cmdi",
		"跨站脚本":                    "xss",
		"本地文件包含 (LFI)":            "lfi",
		"敏感信息泄露":                  "info-leak",
		"业务逻辑漏洞":                  "logic",
		"密码爆破":                    "brute-force",
		// 保守:含 "injection" 不等于 sqli,SSTI 由 template-injection 关键词收敛
		"Template Injection":                      "ssti",
		"Jinja2 模板注入":                             "ssti",
		"Insecure Deserialization (Java)":         "deser",
		"Vertical Privilege Escalation (PrivEsc)": "privesc",
		"OS Command Injection (RCE)":              "cmdi",
		"Authentication Bypass (MFA)":             "auth-bypass",
		// 未知名目:原样小写、折叠后保留
		"csrf":             "csrf",
		"Weird  New_Class": "weird-new-class",
		"":                 "",
	}
	for in, want := range cases {
		if got := NormalizeVulnClass(in); got != want {
			t.Errorf("NormalizeVulnClass(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMaxSeverity(t *testing.T) {
	cases := []struct {
		a, b, want string
	}{
		{"low", "medium", "medium"},
		{"critical", "high", "critical"},
		{"high", "high", "high"},
		{"medium", "low", "medium"},
		{"", "low", "low"},
		{"weird", "", "weird"},        // 都未知:返回 a
		{"medium", "weird", "medium"}, // 未知按 0 处理
	}
	for _, c := range cases {
		if got := MaxSeverity(c.a, c.b); got != c.want {
			t.Errorf("MaxSeverity(%q,%q) = %q, want %q", c.a, c.b, got, c.want)
		}
	}
}

func TestMergeFindingFields(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	old := DBFinding{Severity: "medium", Summary: "旧摘要", Evidence: "旧证据正文"}

	// summary 不同:替换,旧摘要归档进 evidence;severity 取高;新证据追加带标记
	sev, sum, ev := mergeFindingFields(old, RecordFindingInput{
		Severity: "high", Summary: "更深度利用摘要", Evidence: "新 PoC", IntentID: 77, Worker: "w2",
	}, now)
	if sev != "high" || sum != "更深度利用摘要" {
		t.Fatalf("severity/summary: got (%q,%q)", sev, sum)
	}
	for _, want := range []string{"旧证据正文", "[原摘要]", "旧摘要", "[新证据]", "新 PoC", "intent #77", "by w2", "2026-09-13T12:00:00Z"} {
		if !strings.Contains(ev, want) {
			t.Errorf("merged evidence missing %q:\n%s", want, ev)
		}
	}
	if !strings.HasPrefix(ev, "旧证据正文") {
		t.Errorf("原 evidence 必须保留在最前:\n%s", ev)
	}

	// summary 相同:不替换、不归档;severity 平级保留旧值;空 evidence 不追加
	sev, sum, ev = mergeFindingFields(old, RecordFindingInput{Severity: "low", Summary: "旧摘要"}, now)
	if sev != "medium" || sum != "旧摘要" || ev != "旧证据正文" {
		t.Fatalf("no-op merge: got (%q,%q,%q)", sev, sum, ev)
	}

	// 新 summary 为空:保留旧 summary,不动 evidence
	_, sum, ev = mergeFindingFields(old, RecordFindingInput{Severity: "medium", Evidence: "  "}, now)
	if sum != "旧摘要" || ev != "旧证据正文" {
		t.Fatalf("empty summary/evidence merge: got (%q,%q)", sum, ev)
	}

	// 旧 summary 为空、新 summary 非空:替换但不产生"原摘要"归档段
	emptyOld := DBFinding{Severity: "low", Summary: "", Evidence: "E"}
	_, sum, ev = mergeFindingFields(emptyOld, RecordFindingInput{Severity: "low", Summary: "S", Evidence: "E2", IntentID: 0}, now)
	if sum != "S" || strings.Contains(ev, "[原摘要]") || !strings.Contains(ev, "E2") {
		t.Fatalf("empty old summary merge: got (%q,%q)", sum, ev)
	}

	// vulnclass 措辞漂移(归一化后才相等):追加段标注本次原文,便于审计模型漂移
	oldX := DBFinding{VulnClass: "XSS (Stored)", Severity: "medium", Summary: "S", Evidence: "E"}
	_, _, ev = mergeFindingFields(oldX, RecordFindingInput{
		VulnClass: "Stored Cross-Site Scripting (XSS)", Severity: "medium", Summary: "S", Evidence: "新证据",
	}, now)
	if !strings.Contains(ev, `本次 vulnclass 原文 "Stored Cross-Site Scripting (XSS)"`) {
		t.Errorf("drift annotation missing:\n%s", ev)
	}

	// vulnclass 原文相同:不标注
	_, _, ev = mergeFindingFields(oldX, RecordFindingInput{
		VulnClass: "XSS (Stored)", Severity: "medium", Summary: "S", Evidence: "新证据",
	}, now)
	if strings.Contains(ev, "vulnclass 原文") {
		t.Errorf("no drift expected:\n%s", ev)
	}

	// 无新证据且 summary 不变,但有漂移:单独留审计段,痕迹不丢
	_, _, ev = mergeFindingFields(oldX, RecordFindingInput{
		VulnClass: "Stored Cross-Site Scripting (XSS)", Severity: "medium", Summary: "S",
	}, now)
	if !strings.Contains(ev, "vulnclass 原文") || !strings.Contains(ev, "仅 vulnclass 措辞漂移") {
		t.Errorf("drift-only segment missing:\n%s", ev)
	}
}

// --- PG 依赖路径(本机无 ARTEX_PG_DSN 时自动 skip;需在有 PG 的环境实测) ---

// TestRecordFindingTxMerge 端到端验证档 A 合并:命中 confirmed/pending 同入口
// finding 时不新增行/节点,evidence 追加、severity 取高、summary 替换并归档、
// 血缘边指向既有节点;异类/异主资产/终态/无资产均不合并。
// 需要 PG(testDSN 无配置即 skip)。
func TestRecordFindingTxMerge(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	tk, err := d.CreateTask("合并测试", "目标", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(tk.ID)
	es := d.Exploration(tk.ExplorationID)

	mkAsset := func(domain string) int64 {
		t.Helper()
		var id int64
		if err := d.QueryRow(`INSERT INTO assets(type,domain,root_domain,task_ids,last_seen)
			VALUES ('root_domain',$1,$1,ARRAY[$2]::bigint[],now()) RETURNING id`, domain, tk.ID).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	assetA := mkAsset("merge-a.invalid")
	assetB := mkAsset("merge-b.invalid")
	defer func() { _, _ = d.Exec(`DELETE FROM assets WHERE id=ANY($1::bigint[])`, []int64{assetA, assetB}) }()

	mkFinding := func(vulnclass, status string, assets []int64) (fid, nodeID int64) {
		t.Helper()
		var err error
		nodeID, err = es.AddNode(KindFinding, map[string]any{
			"vulnclass": vulnclass, "severity": "medium", "summary": "旧摘要",
			"evidence": map[string]any{"by": "w1", "poc": "旧证据"},
		}, 9, "confirmed", "w1", nil)
		if err != nil {
			t.Fatal(err)
		}
		fid, err = d.AddFinding(tk.ID, nodeID, vulnclass, "", "medium", "旧摘要", "旧证据", "w1", assets)
		if err != nil {
			t.Fatal(err)
		}
		if status != FindingPending {
			if _, err = d.SetFindingStatus(fid, status); err != nil {
				t.Fatal(err)
			}
		}
		return
	}
	record := func(in RecordFindingInput) *RecordedFinding {
		t.Helper()
		in.TaskID, in.ExplorationID = tk.ID, tk.ExplorationID
		var out *RecordedFinding
		err := d.WithEvidenceTx(t.Context(), func(tx *sql.Tx) error {
			var e error
			out, e = RecordFindingTx(t.Context(), tx, in, nil)
			return e
		})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	intentID, err := es.AddNode(KindIntent, map[string]any{"summary": "深入利用"}, 5, "open", "planner", nil)
	if err != nil {
		t.Fatal(err)
	}

	// 1) 命中:同任务、confirmed、"SQL-Injection"≈"sqli"、主资产相同 → 合并
	fid, nodeID := mkFinding("SQL-Injection", FindingConfirmed, []int64{assetA})
	out := record(RecordFindingInput{
		VulnClass: "sqli", Severity: "critical", Summary: "拿到凭据的深度利用",
		Evidence: "新 PoC 输出", Worker: "w2", IntentID: intentID, AssetIDs: []int64{assetA},
	})
	if !out.Merged || out.FindingID != fid || out.NodeID != nodeID {
		t.Fatalf("want merge into (%d,%d), got %+v", fid, nodeID, out)
	}
	if out.MergedIntoFindingID != fid || out.MergedIntoNodeID != nodeID {
		t.Fatalf("merged_into fields: %+v", out)
	}
	f, err := d.GetFinding(fid)
	if err != nil || f == nil {
		t.Fatal(err)
	}
	if f.Severity != "critical" || f.Summary != "拿到凭据的深度利用" {
		t.Fatalf("merged fields: severity=%q summary=%q", f.Severity, f.Summary)
	}
	for _, want := range []string{"旧证据", "[原摘要]", "旧摘要", "[新证据]", "新 PoC 输出", "intent #"} {
		if !strings.Contains(f.Evidence, want) {
			t.Errorf("merged evidence missing %q:\n%s", want, f.Evidence)
		}
	}
	// 血缘边 intent --yields--> 既有节点
	var edges int
	if err := d.QueryRow(`SELECT count(*) FROM exploration_edges
		WHERE exploration_id=$1 AND src_id=$2 AND rel=$3 AND dst_id=$4`,
		tk.ExplorationID, intentID, RelYields, nodeID).Scan(&edges); err != nil || edges != 1 {
		t.Fatalf("yields edge: count=%d err=%v", edges, err)
	}
	// 节点 payload 同步
	var payload string
	if err := d.QueryRow(`SELECT payload::text FROM exploration_nodes WHERE id=$1`, nodeID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(payload, "拿到凭据的深度利用") || !strings.Contains(payload, "critical") {
		t.Errorf("node payload not synced: %s", payload)
	}
	// 再次上报同 intent:边幂等,仍合并
	out2 := record(RecordFindingInput{
		VulnClass: "SQLi", Severity: "high", Summary: "拿到凭据的深度利用",
		Evidence: "又一次证据", Worker: "w2", IntentID: intentID, AssetIDs: []int64{assetA},
	})
	if !out2.Merged || out2.FindingID != fid {
		t.Fatalf("re-merge: %+v", out2)
	}
	if err := d.QueryRow(`SELECT count(*) FROM exploration_edges
		WHERE exploration_id=$1 AND src_id=$2 AND rel=$3 AND dst_id=$4`,
		tk.ExplorationID, intentID, RelYields, nodeID).Scan(&edges); err != nil || edges != 1 {
		t.Fatalf("edge idempotency: count=%d err=%v", edges, err)
	}

	// 2) pending 占位也参与合并(压测 0 触发的根因修复):同主资产较新的
	// pending 行被命中(ORDER BY id DESC),证据聚合进去,status 保持 pending
	// 由验证管线(C2 增量重验)裁决,不在合并处提前判真伪。
	pfid, _ := mkFinding("sqli", FindingPending, []int64{assetA})
	out3 := record(RecordFindingInput{
		VulnClass: "SQL Injection (Blind)", Severity: "low", Summary: "另一条",
		Evidence: "pending 合并证据", AssetIDs: []int64{assetA},
	})
	if !out3.Merged || out3.FindingID != pfid {
		t.Fatalf("pending must merge into %d: %+v", pfid, out3)
	}
	pf, err := d.GetFinding(pfid)
	if err != nil || pf == nil {
		t.Fatal(err)
	}
	if pf.Status != FindingPending {
		t.Fatalf("merge must not change status, got %q", pf.Status)
	}
	if !strings.Contains(pf.Evidence, "pending 合并证据") ||
		!strings.Contains(pf.Evidence, `本次 vulnclass 原文 "SQL Injection (Blind)"`) {
		t.Errorf("pending merged evidence missing segment/drift note:\n%s", pf.Evidence)
	}

	// 3) 归一化后不同类别 → 新建
	mkFinding("xss", FindingConfirmed, []int64{assetA})
	out4 := record(RecordFindingInput{
		VulnClass: "ssrf", Severity: "low", Summary: "ssrf", AssetIDs: []int64{assetA},
	})
	if out4.Merged {
		t.Fatalf("different class must not merge: %+v", out4)
	}
	defer func() { _, _ = d.DeleteFinding(out4.FindingID) }()

	// 4) 终态排除 + 主资产不同:assetB 上有一条 false_positive 的 sqli,
	// 终态不参与合并;assetB 上无 confirmed/pending sqli → 新建
	fpfid, _ := mkFinding("sqli", FindingFalsePositive, []int64{assetB})
	out5 := record(RecordFindingInput{
		VulnClass: "sqli", Severity: "low", Summary: "别的资产", AssetIDs: []int64{assetB},
	})
	if out5.Merged || out5.FindingID == fpfid {
		t.Fatalf("terminal state must not merge (fp fid=%d): %+v", fpfid, out5)
	}
	defer func() { _, _ = d.DeleteFinding(out5.FindingID) }()

	// 5) 无资产 → 合并键不完整,新建
	out6 := record(RecordFindingInput{VulnClass: "sqli", Severity: "low", Summary: "无资产"})
	if out6.Merged {
		t.Fatalf("asset-less report must not merge: %+v", out6)
	}
	defer func() { _, _ = d.DeleteFinding(out6.FindingID) }()

	// 6) 合并键为主资产对等(asset_ids->0),不是包含:
	// (a) 候选 [ep,svc] vs 输入 [svc] —— svc 只是候选的次资产,主资产不同,不合并;
	// (b) 候选 [ep,svc] vs 输入 [ep] —— 主资产相同,合并。
	epAsset := mkAsset("merge-ep.invalid")
	svcAsset := mkAsset("merge-svc.invalid")
	defer func() { _, _ = d.Exec(`DELETE FROM assets WHERE id=ANY($1::bigint[])`, []int64{epAsset, svcAsset}) }()

	mfid, _ := mkFinding("csrf", FindingConfirmed, []int64{epAsset, svcAsset})
	out7 := record(RecordFindingInput{
		VulnClass: "csrf", Severity: "low", Summary: "挂在 service 上的另一条",
		AssetIDs: []int64{svcAsset},
	})
	if out7.Merged {
		t.Fatalf("secondary-asset containment must not merge (candidate fid=%d): %+v", mfid, out7)
	}
	defer func() { _, _ = d.DeleteFinding(out7.FindingID) }()

	out8 := record(RecordFindingInput{
		VulnClass: "CSRF", Severity: "medium", Summary: "同入口加深",
		AssetIDs: []int64{epAsset},
	})
	if !out8.Merged || out8.FindingID != mfid {
		t.Fatalf("same primary asset must merge into %d: %+v", mfid, out8)
	}
}

// --- 四层去重:纯函数(键 / 归一化 / 指纹 / 相似度) ---

func TestFindingDedupPure(t *testing.T) {
	// 键:有主资产 -> |a + 主资产 id(次资产不参与,避免异入口误并)
	if got := FindingDedupKey("SQL Injection", []int64{7, 9}, "x"); got != "sqli|a7" {
		t.Errorf("asset key: %q", got)
	}
	// 键:无资产 + 正文带 scheme 的 URL -> |h + host(去端口、小写)
	if got := FindingDedupKey("xss", nil, "payload at https://A.Example.com:8443/a?b=1"); got != "xss|ha.example.com" {
		t.Errorf("host key: %q", got)
	}
	// 键:无资产 + 裸 IPv4 -> |h + ip
	if got := FindingDedupKey("ssrf", nil, "curl http://10.0.0.5/x"); got != "ssrf|h10.0.0.5" {
		t.Errorf("ip key: %q", got)
	}
	// 键:既无资产也无锚 -> 空(不参与自动合并)
	if got := FindingDedupKey("sqli", nil, "no anchor here"); got != "" {
		t.Errorf("empty key: %q", got)
	}

	// 归一化:抹时间戳 / 长 hex / 长随机串 / 数字,但保留 URL 路径(最强身份信号)
	norm := NormalizeFindingText("2026-09-13T12:00:00Z id=0123456789abcdef0123 token=abcdefghijklmnopqrstuvwxyz012345 path=/admin/login?id=42")
	for _, gone := range []string{"2026", "0123456789abcdef", "abcdefghijklmnopqrstuvwxyz", "42"} {
		if strings.Contains(norm, gone) {
			t.Errorf("norm must scrub %q: %q", gone, norm)
		}
	}
	if !strings.Contains(norm, "/admin/login") {
		t.Errorf("norm must keep url path: %q", norm)
	}

	// 指纹:只有时间戳不同 -> 同指纹
	a := FindingFingerprint("sqli", "SQL注入", "id=1 可注入", "2026-09-13T12:00:00Z dump ok")
	b := FindingFingerprint("sqli", "SQL注入", "id=1 可注入", "2026-09-14T03:21:00Z dump ok")
	if a == "" || a != b {
		t.Errorf("fingerprint: %q vs %q", a, b)
	}

	// 相似度:重述过线;异接口不过线
	same := FindingSimilarity("sqli /login 布尔盲注 可拖库", "sqli /login 布尔盲注 可拖库 (已确认)")
	diff := FindingSimilarity("sqli /login 布尔盲注 可拖库", "xss /search 反射型 弹窗")
	if same < FindingDupSimilarityThreshold {
		t.Errorf("restatement must pass threshold: %.3f", same)
	}
	if diff >= FindingDupSimilarityThreshold {
		t.Errorf("different endpoint must not pass threshold: %.3f", diff)
	}
}

// TestRecordFindingDedupLayers 端到端验证四层去重的落库侧:
//   1) 写入即落 dedup_key / fingerprint;
//   2) 无资产但正文带 URL -> 弱锚键,第二次上报合并;
//   3) 终态行(误报)不自动合并,但在新行打 suspected_dup_of + 分数;
//   4) 跨任务默认不自动合并,改为打疑似标记(同资产同类别)。
// 需要 PG(testDSN 无配置即 skip)。
func TestRecordFindingDedupLayers(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	tk, err := d.CreateTask("去重分层测试", "目标", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(tk.ID)
	es := d.Exploration(tk.ExplorationID)

	mkAsset := func(domain string, taskID int64) int64 {
		t.Helper()
		var id int64
		if err := d.QueryRow(`INSERT INTO assets(type,domain,root_domain,task_ids,last_seen)
			VALUES ('root_domain',$1,$1,ARRAY[$2]::bigint[],now()) RETURNING id`, domain, taskID).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	assetA := mkAsset("dedup-a.invalid", tk.ID)
	assetB := mkAsset("dedup-b.invalid", tk.ID)
	defer func() { _, _ = d.Exec(`DELETE FROM assets WHERE id=ANY($1::bigint[])`, []int64{assetA, assetB}) }()

	record := func(taskID, expID int64, in RecordFindingInput) *RecordedFinding {
		t.Helper()
		in.TaskID, in.ExplorationID = taskID, expID
		var out *RecordedFinding
		err := d.WithEvidenceTx(t.Context(), func(tx *sql.Tx) error {
			var e error
			out, e = RecordFindingTx(t.Context(), tx, in, nil)
			return e
		})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	mkFinding := func(vulnclass, status, summary, evidence string, assets []int64) (fid, nodeID int64) {
		t.Helper()
		nodeID, err = es.AddNode(KindFinding, map[string]any{
			"vulnclass": vulnclass, "severity": "medium", "summary": summary,
			"evidence": map[string]any{"by": "w1", "poc": evidence},
		}, 9, "confirmed", "w1", nil)
		if err != nil {
			t.Fatal(err)
		}
		fid, err = d.AddFinding(tk.ID, nodeID, vulnclass, "", "medium", summary, evidence, "w1", assets)
		if err != nil {
			t.Fatal(err)
		}
		if status != FindingPending {
			if _, err = d.SetFindingStatus(fid, status); err != nil {
				t.Fatal(err)
			}
		}
		return
	}

	// 1) 写入即落结构化键与指纹
	out1 := record(tk.ID, tk.ExplorationID, RecordFindingInput{
		VulnClass: "sqli", Severity: "high", Summary: "id=1 可注入", Evidence: "poc", AssetIDs: []int64{assetA},
	})
	var gotKey, gotFP string
	if err := d.QueryRow(`SELECT dedup_key, fingerprint FROM findings WHERE id=$1`, out1.FindingID).Scan(&gotKey, &gotFP); err != nil {
		t.Fatal(err)
	}
	if want := "sqli|a" + strconv.FormatInt(assetA, 10); gotKey != want || gotFP == "" {
		t.Fatalf("layer1 persisted: key=%q want=%q fp=%q", gotKey, want, gotFP)
	}

	// 2) 弱锚:无 asset,正文带 URL,两次上报合并到同一行
	outW1 := record(tk.ID, tk.ExplorationID, RecordFindingInput{
		VulnClass: "xss", Severity: "low", Summary: "在 https://weak-anchor.invalid/p?q=1 反射", Evidence: "e1",
	})
	outW2 := record(tk.ID, tk.ExplorationID, RecordFindingInput{
		VulnClass: "XSS", Severity: "low", Summary: "在 https://weak-anchor.invalid/p?q=2 反射", Evidence: "e2",
	})
	if !outW2.Merged || outW2.FindingID != outW1.FindingID {
		t.Fatalf("weak anchor must merge: %+v vs %+v", outW1, outW2)
	}

	// 3) 终态行不自动合并,但在新行打疑似标记
	fpFID, _ := mkFinding("sqli", FindingFalsePositive, "旧摘要", "旧证据", []int64{assetB})
	outT := record(tk.ID, tk.ExplorationID, RecordFindingInput{
		VulnClass: "SQL Injection", Severity: "low", Summary: "同入口再次上报", Evidence: "新证据", AssetIDs: []int64{assetB},
	})
	if outT.Merged || outT.FindingID == fpFID {
		t.Fatalf("terminal row must not auto-merge (fp=%d): %+v", fpFID, outT)
	}
	var suspOf *int64
	var suspScore *float64
	if err := d.QueryRow(`SELECT suspected_dup_of, suspected_dup_score FROM findings WHERE id=$1`, outT.FindingID).Scan(&suspOf, &suspScore); err != nil {
		t.Fatal(err)
	}
	if suspOf == nil || *suspOf != fpFID {
		t.Fatalf("terminal must mark suspected_dup_of=%d, got %v", fpFID, suspOf)
	}
	if suspScore == nil || *suspScore < FindingDupSimilarityThreshold {
		t.Fatalf("suspected score: %v", suspScore)
	}

	// 4) 跨任务默认不自动合并,改为疑似标记
	tk2, err := d.CreateTask("去重分层测试2", "目标", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(tk2.ID)
	outX := record(tk2.ID, tk2.ExplorationID, RecordFindingInput{
		VulnClass: "sqli", Severity: "high", Summary: "id=1 可注入", Evidence: "poc", AssetIDs: []int64{assetA},
	})
	if outX.Merged {
		t.Fatalf("cross-task must not auto-merge by default: %+v", outX)
	}
	var xOf *int64
	if err := d.QueryRow(`SELECT suspected_dup_of FROM findings WHERE id=$1`, outX.FindingID).Scan(&xOf); err != nil {
		t.Fatal(err)
	}
	if xOf == nil || *xOf != out1.FindingID {
		t.Fatalf("cross-task must mark suspected_dup_of=%d, got %v", out1.FindingID, xOf)
	}
}

// TestListFindingDupCandidates 验证二次审核判重清单的 SQL:同任务命中、资产交集
// 命中,自身 / 已合并 / 已判重复排除。
func TestListFindingDupCandidates(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	tk, err := d.CreateTask("判重清单测试", "目标", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(tk.ID)
	es := d.Exploration(tk.ExplorationID)

	mkAsset := func(domain string, taskID int64) int64 {
		t.Helper()
		var id int64
		if err := d.QueryRow(`INSERT INTO assets(type,domain,root_domain,task_ids,last_seen)
			VALUES ('root_domain',$1,$1,ARRAY[$2]::bigint[],now()) RETURNING id`, domain, taskID).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	assetA := mkAsset("dupctx-a.invalid", tk.ID)
	assetB := mkAsset("dupctx-b.invalid", tk.ID)
	defer func() { _, _ = d.Exec(`DELETE FROM assets WHERE id=ANY($1::bigint[])`, []int64{assetA, assetB}) }()

	mk := func(vulnclass, summary string, assets []int64) int64 {
		t.Helper()
		nodeID, err := es.AddNode(KindFinding, map[string]any{"vulnclass": vulnclass, "summary": summary}, 9, "confirmed", "w1", nil)
		if err != nil {
			t.Fatal(err)
		}
		fid, err := d.AddFinding(tk.ID, nodeID, vulnclass, "", "medium", summary, "ev", "w1", assets)
		if err != nil {
			t.Fatal(err)
		}
		return fid
	}
	self := mk("sqli", "自身", []int64{assetA})
	sameTask := mk("xss", "同任务不同资产", []int64{assetB})
	sameAsset := mk("ssrf", "同资产不同任务口径", []int64{assetA})
	merged := mk("rce", "已被合并", []int64{assetA})
	if _, err := d.Exec(`UPDATE findings SET merged_into=$1 WHERE id=$2`, self, merged); err != nil {
		t.Fatal(err)
	}
	dup := mk("lfi", "已判重复", []int64{assetA})
	if _, err := d.Exec(`UPDATE findings SET status=$1 WHERE id=$2`, FindingDuplicate, dup); err != nil {
		t.Fatal(err)
	}

	got, err := d.ListFindingDupCandidates(tk.ID, self, []int64{assetA}, 20)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[int64]bool{}
	for _, c := range got {
		ids[c.ID] = true
	}
	if !ids[sameTask] || !ids[sameAsset] {
		t.Fatalf("同任务 / 资产交集都应命中: %v", ids)
	}
	if ids[self] || ids[merged] || ids[dup] {
		t.Fatalf("自身 / 已合并 / 已判重复不该命中: %v", ids)
	}
}

// TestMergeFindingsManual 验证第四层人工合并:MergeFindings 迁移 source、升级目标严重度、
// 幂等跳过、拒绝已被合并的目标,以及 ListFindingDuplicateGroups 的分组视图与 dismiss 清标记。
func TestMergeFindingsManual(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	tk, err := d.CreateTask("人工合并测试", "目标", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(tk.ID)
	es := d.Exploration(tk.ExplorationID)

	mkAsset := func(domain string) int64 {
		t.Helper()
		var id int64
		if err := d.QueryRow(`INSERT INTO assets(type,domain,root_domain,task_ids,last_seen)
			VALUES ('root_domain',$1,$1,ARRAY[$2]::bigint[],now()) RETURNING id`, domain, tk.ID).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	assetA := mkAsset("manualmerge-a.invalid")
	assetB := mkAsset("manualmerge-b.invalid")
	defer func() { _, _ = d.Exec(`DELETE FROM assets WHERE id=ANY($1::bigint[])`, []int64{assetA, assetB}) }()

	mk := func(vulnclass, summary, severity string, assets []int64) int64 {
		t.Helper()
		nodeID, err := es.AddNode(KindFinding, map[string]any{
			"vulnclass": vulnclass, "severity": severity, "summary": summary,
		}, 9, "confirmed", "w1", nil)
		if err != nil {
			t.Fatal(err)
		}
		fid, err := d.AddFinding(tk.ID, nodeID, vulnclass, "", severity, summary, "ev-"+summary, "w1", assets)
		if err != nil {
			t.Fatal(err)
		}
		return fid
	}

	target := mk("sqli", "目标", "medium", []int64{assetA})
	src := mk("sqli", "重复条目", "critical", []int64{assetB})
	other := mk("xss", "疑似条目", "low", []int64{assetA})

	res, err := d.MergeFindings(t.Context(), []int64{src, 999999}, target)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Merged) != 1 || res.Merged[0] != src {
		t.Fatalf("merged: %+v", res)
	}
	if len(res.Skipped) != 1 || res.Skipped[0] != 999999 {
		t.Fatalf("不存在的 source 应计入 skipped: %+v", res)
	}

	var status string
	var mergedInto sql.NullInt64
	if err := d.QueryRow(`SELECT COALESCE(status,''), merged_into FROM findings WHERE id=$1`, src).
		Scan(&status, &mergedInto); err != nil {
		t.Fatal(err)
	}
	if status != FindingDuplicate || !mergedInto.Valid || mergedInto.Int64 != target {
		t.Fatalf("source 合并后状态: status=%q merged_into=%+v", status, mergedInto)
	}

	tf, err := d.GetFinding(target)
	if err != nil || tf == nil {
		t.Fatalf("GetFinding(target): %v %v", tf, err)
	}
	if tf.Severity != "critical" {
		t.Fatalf("target severity = %q, want critical", tf.Severity)
	}
	if !strings.Contains(tf.Evidence, "ev-重复条目") {
		t.Fatalf("target evidence 未吸收 source: %q", tf.Evidence)
	}

	// 幂等:再合一次 → 全部跳过
	res2, err := d.MergeFindings(t.Context(), []int64{src}, target)
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.Merged) != 0 || len(res2.Skipped) != 1 {
		t.Fatalf("幂等合并应跳过: %+v", res2)
	}

	// 已被合并的 finding 不能再作为目标
	if _, err := d.MergeFindings(t.Context(), []int64{other}, src); err == nil {
		t.Fatalf("已被合并的目标应报错")
	}

	// 疑似重复标记 → 分组视图可见,再 dismiss 清掉
	if err := d.MarkFindingSuspectedDuplicate(other, target, 0.9); err != nil {
		t.Fatal(err)
	}
	groups, err := d.ListFindingDuplicateGroups(tk.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	var grp *FindingDupGroup
	for i := range groups {
		if groups[i].TargetID == target {
			grp = &groups[i]
			break
		}
	}
	if grp == nil {
		t.Fatalf("未找到目标分组: %+v", groups)
	}
	members := map[int64]FindingDupMember{}
	for _, m := range grp.Members {
		members[m.ID] = m
	}
	if m, ok := members[src]; !ok || !m.Merged {
		t.Fatalf("已合并的 source 应是 Merged 成员: %+v", grp.Members)
	}
	if m, ok := members[other]; !ok || m.Merged || m.Score == nil || *m.Score != 0.9 {
		t.Fatalf("疑似重复成员应带 score 且未合并: %+v", grp.Members)
	}

	if err := d.ClearFindingSuspectedDuplicate(other); err != nil {
		t.Fatal(err)
	}
	groups, err = d.ListFindingDuplicateGroups(tk.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range groups {
		for _, m := range g.Members {
			if m.ID == other {
				t.Fatalf("dismiss 后不应再出现在分组里: %+v", g)
			}
		}
	}
}

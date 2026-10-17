package db

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// 档 A 同入口 finding 自动合并(FIXPLAN 需求一 / ROADMAP C2·C4)。
//
// RecordFindingTx 在插入前按 (task_id, 归一化 vulnclass, 主 asset_id) 查同任务
// 未关闭且 status IN ('confirmed','pending') 的既有 finding;命中则不新增
// 行/节点,改为追加 evidence、severity 取最高、summary 以最新深度利用为准
// (旧的挪进 evidence 存档)、新 intent 的 yields 边指向既有节点,流量快照绑到
// 既有 finding。查重与插入同处任务级证据锁(LockTaskEvidenceTx)内,天然串行化,
// 无并发双插窗口。
//
// pending 也参与合并的依据:压测中第二条上报到达时第一条往往还在 pending,
// 仅认 confirmed 会导致合并 0 触发。未验证结论先聚合、再由验证管线裁决——
// C2 已有合并后增量重验兜底(evidence.Store.OnMerged →
// server.RequestFindingCheck);若后被裁为误报,false_positive 处置时其合并
// 进来的证据段仍留在 evidence 里可审计。终态(fixed/false_positive/duplicate
// 等)仍排除,不污染聚合。
//
// 合并键(四层方案第一层,见 db/finding_dedup.go):
//   dedup_key = 归一化 vulnclass + "|a" + 主资产 id,主资产缺失时退化为
//               + "|h" + 正文里第一个 URL 的 host(弱锚,只认带 scheme 的 URL 或裸 IP)。
//   因此 AssetIDs 为空不再让合并整体失效 —— 只要正文里出现过目标 URL 就能判等。
//
// 终态行(已修复/误报/重复/忽略/风险接受)不自动合并(避免把人工结论反复推翻),
// 但会在新行上打 suspected_dup_of「疑似重复」标记,由人工或二次审核裁决。
// 跨任务默认不自动合并(见 FindingDedupCrossTask):静默跨任务合并会让漏洞从原
// 任务的发现页消失,风险高于收益。
//
// 不参与合并的情形(均落回原有新建路径):
//   - 无 task(TaskID<=0)——合并键不完整;
//   - 既无主资产、正文里也抽不出弱锚——合并键为空;
//   - 候选 status 为终态(fixed/false_positive/duplicate 等);
//   - 候选无探索节点(node_id IS NULL)——合并必须保持 1节点↔1行 契约。

// vulnClassAliases 把常见漏洞类目收敛到粗类;未知名目原样小写保留(仍参与判等,
// 只是不做跨名目合并)。键必须先经 normalizeVulnClassKey 同款折叠(小写、空白/
// 下划线/连字符折叠为单连字符)。
var vulnClassAliases = map[string]string{
	"sqli":                           "sqli",
	"sql-injection":                  "sqli",
	"sql-inj":                        "sqli",
	"sql":                            "sqli",
	"xss":                            "xss",
	"cross-site-scripting":           "xss",
	"ssrf":                           "ssrf",
	"server-side-request-forgery":    "ssrf",
	"ssti":                           "ssti",
	"template-injection":             "ssti",
	"server-side-template-injection": "ssti",
	"xxe":                            "xxe",
	"xml-external-entity":            "xxe",
	"cmdi":                           "cmdi",
	"rce":                            "cmdi",
	"command-injection":              "cmdi",
	"os-command-injection":           "cmdi",
	"remote-code-execution":          "cmdi",
	"code-execution":                 "cmdi",
	"upload":                         "upload",
	"file-upload":                    "upload",
	"arbitrary-file-upload":          "upload",
	"unrestricted-upload":            "upload",
	"auth-bypass":                    "auth-bypass",
	"authentication-bypass":          "auth-bypass",
	"broken-auth":                    "auth-bypass",
	"broken-authentication":          "auth-bypass",
	"logic":                          "logic",
	"business-logic":                 "logic",
	"deser":                          "deser",
	"deserialization":                "deser",
	"insecure-deserialization":       "deser",
	"info-leak":                      "info-leak",
	"information-disclosure":         "info-leak",
	"info-disclosure":                "info-leak",
	"sensitive-data-exposure":        "info-leak",
	"privesc":                        "privesc",
	"privilege-escalation":           "privesc",
	"priv-esc":                       "privesc",
	"other":                          "other",
}

// normalizeVulnClassKey 折叠 vulnclass:小写、去首尾空白,空白/下划线/连字符/
// 斜杠折叠为单连字符。别名表的键与模糊段的关键词都是同款折叠后的形式。
func normalizeVulnClassKey(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	return strings.Join(strings.FieldsFunc(v, func(r rune) bool {
		return r == ' ' || r == '_' || r == '-' || r == '/'
	}), "-")
}

// vulnClassFuzzyKeywords 模糊段关键词表,按优先级顺序从上到下匹配,命中即收敛
// 到规范粗类。保守原则:刻意不收裸 "injection"——SSTI 等含 "injection" 但不
// 是 SQLi;"sql" 词根才是 sqli 的强信号。blind sqli 归到 sqli 而非独立
// sqli-blind:与既有粗类保持一致,盲注是 sqli 的利用手法而非新类目。
var vulnClassFuzzyKeywords = []struct {
	keys  []string
	class string
}{
	{[]string{"sql", "盲注"}, "sqli"},
	{[]string{"xss", "cross-site-script", "跨站脚本"}, "xss"},
	{[]string{"ssrf"}, "ssrf"},
	{[]string{"ssti", "template-injection", "模板注入"}, "ssti"},
	{[]string{"xxe"}, "xxe"},
	{[]string{"command-injection", "命令注入", "rce", "code-execution", "远程代码执行", "远程命令执行", "代码执行", "命令执行"}, "cmdi"},
	{[]string{"file-upload", "文件上传", "上传"}, "upload"},
	{[]string{"file-inclusion", "lfi", "rfi", "文件包含"}, "lfi"},
	{[]string{"deserial", "反序列化"}, "deser"},
	{[]string{"csrf"}, "csrf"},
	{[]string{"auth-bypass", "authentication-bypass", "认证绕过", "鉴权绕过"}, "auth-bypass"},
	{[]string{"brute", "爆破"}, "brute-force"},
	{[]string{"info-leak", "information-leak", "泄露", "泄漏"}, "info-leak"},
	{[]string{"privesc", "privilege-escalation", "提权"}, "privesc"},
	{[]string{"logic", "逻辑"}, "logic"},
}

// fuzzyVulnClass 对折叠后的 key 做关键词包含扫描,命中返回粗类。
func fuzzyVulnClass(key string) (string, bool) {
	for _, kw := range vulnClassFuzzyKeywords {
		for _, k := range kw.keys {
			if strings.Contains(key, k) {
				return kw.class, true
			}
		}
	}
	return "", false
}

// parenContents 提取折叠后 key 中各对(半角/全角)括号内的内容,用于模型惯用的
// "Stored Cross-Site Scripting (XSS)" / "任意文件上传 (CVE-2017-12615)" 写法。
func parenContents(key string) []string {
	var out []string
	for _, pair := range [][2]rune{{'(', ')'}, {'（', '）'}} {
		rest := key
		for {
			i := strings.IndexRune(rest, pair[0])
			if i < 0 {
				break
			}
			rest = rest[i+1:]
			j := strings.IndexRune(rest, pair[1])
			if j < 0 {
				break
			}
			if inner := strings.TrimSpace(rest[:j]); inner != "" {
				out = append(out, inner)
			}
			rest = rest[j+1:]
		}
	}
	return out
}

// NormalizeVulnClass 归一化漏洞类别到粗类,两段式:
//  1. 别名表:大小写/空白/连字符折叠后精确命中 vulnClassAliases;
//  2. 模糊段:未命中时,先取括号内内容、再取折叠后全文,各自先回查别名表、
//     再做关键词包含扫描(优先级见 vulnClassFuzzyKeywords);
//  3. 都不中:保持折叠后原样小写(仍参与判等,只是不做跨名目合并)。
func NormalizeVulnClass(v string) string {
	key := normalizeVulnClassKey(v)
	if canon, ok := vulnClassAliases[key]; ok {
		return canon
	}
	candidates := append(parenContents(key), key)
	for _, c := range candidates {
		if canon, ok := vulnClassAliases[c]; ok {
			return canon
		}
	}
	for _, c := range candidates {
		if canon, ok := fuzzyVulnClass(c); ok {
			return canon
		}
	}
	return key
}

// severityRank 把 severity 映射为可比大小;未知/空为 0(最低)。
func severityRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	}
	return 0
}

// MaxSeverity 返回两者中更高的 severity;平级或都未知时返回 a。
func MaxSeverity(a, b string) string {
	if severityRank(b) > severityRank(a) {
		return b
	}
	return a
}

// appendMergeSegment 在 evidence 尾部追加一个带来源标记的段落;note 非空时
// 附加到段标记里(目前用于 vulnclass 措辞漂移审计)。
func appendMergeSegment(evidence, label, body string, now time.Time, intentID int64, worker, note string) string {
	marker := fmt.Sprintf("\n\n--- [%s] 合并于 %s", label, now.UTC().Format(time.RFC3339))
	if intentID > 0 {
		marker += fmt.Sprintf(", intent #%d", intentID)
	}
	if worker = strings.TrimSpace(worker); worker != "" {
		marker += ", by " + worker
	}
	if note != "" {
		marker += note
	}
	return evidence + marker + " ---\n" + body
}

// mergeFindingFields 计算合并后的 severity/summary/evidence(纯函数,可测):
// severity 取最高;新 summary 与旧不同则以"最新深度利用"为准替换,旧的挪进
// evidence 存档;新 evidence 作为带时间戳与 intent 标记的段落追加,原文保留。
// 若本次上报 vulnclass 原文与既有行不同(归一化后才相等,纯属模型措辞漂移),
// 在追加的段标记里标注原文,便于审计。
func mergeFindingFields(old DBFinding, in RecordFindingInput, now time.Time) (severity, summary, evidence string) {
	severity = MaxSeverity(old.Severity, in.Severity)
	summary = old.Summary
	evidence = old.Evidence
	drift := ""
	if iv, ov := strings.TrimSpace(in.VulnClass), strings.TrimSpace(old.VulnClass); iv != "" && ov != "" && iv != ov {
		drift = fmt.Sprintf(", 本次 vulnclass 原文 %q", iv)
	}
	// 跨任务自动合并(ARTEX_FINDING_DEDUP_CROSS_TASK=1)时把来源任务写进段标记,
	// 否则「这条漏洞到底是谁报的」在合并后无从追溯。
	if old.TaskID != nil && *old.TaskID != in.TaskID {
		drift += fmt.Sprintf(", 来源任务 #%d", in.TaskID)
	}
	appended := false
	if ns := strings.TrimSpace(in.Summary); ns != "" && ns != strings.TrimSpace(old.Summary) {
		if s := strings.TrimSpace(old.Summary); s != "" {
			evidence = appendMergeSegment(evidence, "原摘要", s, now, in.IntentID, in.Worker, drift)
			appended = true
		}
		summary = in.Summary
	}
	if e := strings.TrimSpace(in.Evidence); e != "" {
		evidence = appendMergeSegment(evidence, "新证据", in.Evidence, now, in.IntentID, in.Worker, drift)
		appended = true
	}
	// 无段落可挂但确有措辞漂移:单独留一个审计段,避免漂移痕迹丢失。
	if drift != "" && !appended {
		evidence = appendMergeSegment(evidence, "新证据", "(仅 vulnclass 措辞漂移,无新证据正文)", now, in.IntentID, in.Worker, drift)
	}
	return
}

// findMergeCandidateTx 在事务内查可自动合并的既有 finding。
// 调用方须已持任务级证据锁(LockTaskEvidenceTx)与合并键咨询锁(见 RecordFindingTx)。
//
// 判定顺序(命中即返回;同任务优先,其次最新):
//   - 结构化合并键相同 + 活跃(pending/confirmed) + 有探索节点 → 合并;
//     跨任务命中仅当 FindingDedupCrossTask 打开;
//   - 旧行兼容:同任务 + 归一化类别相同 + 主资产对等 + 活跃 + 有探索节点 → 合并
//     (dedup_key 是后加的列,历史行可能为空,靠这条兜住)。
//
// 终态行(已修复/误报/重复/忽略/风险接受)不自动合并,作为第二个返回值交给调用方
// 在新行上打 suspected_dup_of 标记。
func findMergeCandidateTx(tx *sql.Tx, in RecordFindingInput, key string) (*DBFinding, *DBFinding, error) {
	if in.TaskID <= 0 {
		return nil, nil, nil
	}
	want := NormalizeVulnClass(in.VulnClass)
	var merge, terminal *DBFinding

	if key != "" {
		rows, err := tx.Query(`SELECT id, task_id, node_id, vulnclass, severity, summary, evidence, COALESCE(status,'pending')
FROM findings
WHERE dedup_key = $1 AND node_id IS NOT NULL
ORDER BY (task_id IS NOT DISTINCT FROM $2::bigint) DESC, id DESC
LIMIT 20
FOR UPDATE`, key, in.TaskID)
		if err != nil {
			return nil, nil, err
		}
		for rows.Next() {
			var f DBFinding
			if err := rows.Scan(&f.ID, &f.TaskID, &f.NodeID, &f.VulnClass, &f.Severity, &f.Summary, &f.Evidence, &f.Status); err != nil {
				rows.Close()
				return nil, nil, err
			}
			sameTask := f.TaskID != nil && *f.TaskID == in.TaskID
			active := f.Status == FindingPending || f.Status == FindingConfirmed
			if active && (sameTask || FindingDedupCrossTask) {
				if merge == nil {
					cp := f
					merge = &cp
				}
				continue
			}
			if terminal == nil {
				cp := f
				terminal = &cp
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, nil, err
		}
		if merge != nil {
			return merge, terminal, nil
		}
	}

	// 旧行兼容:同任务 + 同归一化类别 + 主资产对等。
	// 主资产对等而非包含:候选 [ep,svc] 与输入 [svc] 不是同一入口(svc 只是候选的
	// 次资产),包含判等会把挂在 service 上的异入口漏洞误并进来。
	if len(in.AssetIDs) > 0 {
		rows, err := tx.Query(`SELECT id, task_id, node_id, vulnclass, severity, summary, evidence, COALESCE(status,'pending')
FROM findings
WHERE task_id=$1 AND status IN ($2, $3) AND node_id IS NOT NULL
  AND asset_ids->0 = to_jsonb($4::bigint)
ORDER BY id DESC
FOR UPDATE`, in.TaskID, FindingConfirmed, FindingPending, in.AssetIDs[0])
		if err != nil {
			return nil, nil, err
		}
		for rows.Next() {
			var f DBFinding
			if err := rows.Scan(&f.ID, &f.TaskID, &f.NodeID, &f.VulnClass, &f.Severity, &f.Summary, &f.Evidence, &f.Status); err != nil {
				rows.Close()
				return nil, nil, err
			}
			if merge == nil && NormalizeVulnClass(f.VulnClass) == want {
				cp := f
				merge = &cp
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, nil, err
		}
	}
	return merge, terminal, nil
}

// markSuspectedDuplicateTx 在新插入的行上打「疑似重复」标记(只标记,不合并)。
//
// 候选来源两处,取相似度最高的一条:
//   - 结构化同键的终态行(已修复/误报/忽略/风险接受/重复)——结构上确定同入口,
//     分数取 max(正文相似度, 阈值),保证一定过线;
//   - 同任务或同主资产、同 dedup_key 的近期行,按归一化正文的 bigram Dice 取最高。
//
// 这是启发式增强:任何失败都只放弃标记、返回错误由调用方忽略,绝不因此丢掉刚写入
// 的漏洞。命中阈值见 FindingDupSimilarityThreshold。
func markSuspectedDuplicateTx(tx *sql.Tx, findingID int64, in RecordFindingInput, key string, terminal *DBFinding) (int64, float64, error) {
	myText := FindingComparableText(in.VulnClass, in.Name, in.Summary, in.Evidence)
	bestID, bestScore := int64(0), 0.0
	consider := func(id int64, text string, floor float64) {
		if id <= 0 || id == findingID {
			return
		}
		score := FindingSimilarity(myText, text)
		if score < floor {
			score = floor
		}
		if id == bestID && score <= bestScore {
			return
		}
		if score > bestScore {
			bestID, bestScore = id, score
		}
	}
	if terminal != nil && terminal.ID != findingID {
		consider(terminal.ID, FindingComparableText(terminal.VulnClass, terminal.Name, terminal.Summary, terminal.Evidence), FindingDupSimilarityThreshold)
	}

	var primary int64
	if len(in.AssetIDs) > 0 {
		primary = in.AssetIDs[0]
	}
	rows, err := tx.Query(`SELECT id, vulnclass, name, summary, evidence
FROM findings
WHERE id <> $1
  AND COALESCE(status,'') <> $4
  AND merged_into IS NULL
  AND ( ($2::bigint > 0 AND asset_ids @> to_jsonb(ARRAY[$2::bigint]))
     OR ($3::bigint > 0 AND task_id = $3)
     OR ($5 <> '' AND dedup_key = $5) )
ORDER BY created_at DESC, id DESC
LIMIT $6`, findingID, primary, in.TaskID, FindingDuplicate, key, findingDupCandidateLimit)
	if err != nil {
		return 0, 0, err
	}
	for rows.Next() {
		var id int64
		var vc, nm, sum, ev string
		if err := rows.Scan(&id, &vc, &nm, &sum, &ev); err != nil {
			rows.Close()
			return 0, 0, err
		}
		consider(id, FindingComparableText(vc, nm, sum, ev), 0)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, 0, err
	}
	if bestID == 0 || bestScore < FindingDupSimilarityThreshold {
		return 0, 0, nil
	}
	if _, err := tx.Exec(`UPDATE findings SET suspected_dup_of=$2, suspected_dup_score=$3 WHERE id=$1`,
		findingID, bestID, bestScore); err != nil {
		return 0, 0, err
	}
	return bestID, bestScore, nil
}


// mergeFindingTx 执行合并:更新既有 finding 行与节点 payload,追加血缘边与
// 流量快照,返回指向既有记录的 RecordedFinding(Merged=true)。
func mergeFindingTx(tx *sql.Tx, cand *DBFinding, in RecordFindingInput, prepared []PreparedTrafficEvidence) (*RecordedFinding, error) {
	severity, summary, evidence := mergeFindingFields(*cand, in, time.Now())
	key := FindingDedupKey(in.VulnClass, in.AssetIDs, FindingComparableText(in.VulnClass, in.Name, in.Summary, in.Evidence))
	fp := FindingFingerprint(in.VulnClass, in.Name, in.Summary, in.Evidence)
	// 合并键/指纹只在非空时覆盖,避免把既有键冲成空(合并进来的一次上报可能
	// 没有 asset_ids 也没有 URL)。
	if _, err := tx.Exec(`UPDATE findings SET severity=$2, summary=$3, evidence=$4,
		dedup_key = CASE WHEN $5 <> '' THEN $5 ELSE dedup_key END,
		fingerprint = CASE WHEN $6 <> '' THEN $6 ELSE fingerprint END
		WHERE id=$1`,
		cand.ID, severity, summary, evidence, key, fp); err != nil {
		return nil, err
	}
	// 节点 payload 同步(与 setFindingCol 同款 jsonb_set),保持按任务 发现 Tab
	// (读节点 payload)与 findings 表一致。
	if _, err := tx.Exec(`UPDATE exploration_nodes
SET payload = jsonb_set(jsonb_set(jsonb_set(payload, '{severity}', to_jsonb($2::text)),
	'{summary}', to_jsonb($3::text)), '{evidence,poc}', to_jsonb($4::text))
WHERE id=$1 AND kind='finding'`, *cand.NodeID, severity, summary, evidence); err != nil {
		return nil, err
	}
	// 血缘:新 intent 的 yields 边指向既有节点(保留"同一入口被反复加深"的历史)。
	// 目标节点必须属于本 exploration;边主键天然幂等。
	if in.IntentID > 0 {
		if _, err := tx.Exec(`INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id)
SELECT $1,$2,$3,$4 WHERE EXISTS(SELECT 1 FROM exploration_nodes WHERE id=$4 AND exploration_id=$1)
ON CONFLICT DO NOTHING`, in.ExplorationID, in.IntentID, RelYields, *cand.NodeID); err != nil {
			return nil, err
		}
	}
	if err := AddFindingTrafficTx(tx, cand.ID, prepared); err != nil {
		return nil, err
	}
	// 文本证据/summary 变化同样使既有报告过期(与流量绑定共用一个版本列)。
	if err := bumpEvidenceVersionTx(tx, cand.ID); err != nil {
		return nil, err
	}
	traffic, err := FindingTrafficTx(tx, cand.ID)
	if err != nil {
		return nil, err
	}
	return &RecordedFinding{
		FindingID:           cand.ID,
		NodeID:              *cand.NodeID,
		Traffic:             traffic,
		Merged:              true,
		MergedIntoFindingID: cand.ID,
		MergedIntoNodeID:    *cand.NodeID,
	}, nil
}

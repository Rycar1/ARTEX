package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// 公司声明范围(company_scope) → 本任务待测资产的【物化】层。
//
// 背景:add_company_scope 允许把一个企业的资产范围声明成上万条 domain/IP 规则
// (实测腾讯 11390 条)。但这些规则过去只用于"归属认领"——即某资产碰巧被发现时,
// 系统才知道它属于该企业。于是任务范围里写着"整个公司",实际可测资产却只有碰巧
// 被发现的那么几个,覆盖度分母极小 → 明明没测几个域名就显示 100%,planner 据此
// 提前收官。本文件把"声明范围"真正展开成 assets 行,让声明即待测工作。

const (
	// DefaultCompanyMaterializeBatch 是单次物化的规则条数上限(一批)。
	DefaultCompanyMaterializeBatch = 500
	// MaxCompanyMaterializeBatch 是调用方可请求的上限,防止一次吃掉上万条。
	MaxCompanyMaterializeBatch = 5000
)

// materializableCompanyScopePredicate 只挑选"能落成一条资产"的规则:
//   - kind='domain'                                 → 一条 root_domain 资产;
//   - kind='ip'/'cidr' 且掩码为单主机(/32 或 /128)  → 一条 ip 资产。
//
// 真正的网段(如 /24)不逐地址展开——展开几万个地址没有意义。网段靠覆盖度里的
// kind='cidr' 匹配谓词(ts.net >>= try_inet(a.ip))去认领"范围内被发现/被插入的资产",
// 不需要也不应该物化。keyword/icp 同理无法物化(keyword 是给 agent 的提示,icp 依赖
// 资产自带的备案号),不在此列。
const materializableCompanyScopePredicate = `(
     cs.kind = 'domain'
  OR (cs.kind IN ('ip','cidr') AND (
        (family(cs.net) = 4 AND masklen(cs.net) = 32)
     OR (family(cs.net) = 6 AND masklen(cs.net) = 128)
  ))
)`

// unmaterializedCompanyScopePredicate 判断某条可物化规则【尚未并入本任务】:
// 已存在同名资产但 task_ids 里没有本任务,同样算"未并入"——这样物化会把资产并进
// 本任务的 task_ids,而不是被别的任务先建过就永远跳过。
const unmaterializedCompanyScopePredicate = `NOT EXISTS (
    SELECT 1 FROM assets a
    WHERE $2 = ANY(a.task_ids)
      AND ((cs.kind = 'domain' AND a.type = 'root_domain' AND a.domain = cs.domain)
        OR (cs.kind IN ('ip','cidr') AND a.type = 'ip' AND a.ip = host(cs.net::inet)))
) AND NOT EXISTS (
    SELECT 1 FROM company_scope_materialize_skip msk
    WHERE msk.task_id = $2
      AND msk.company_id = cs.company_id
      AND msk.kind = cs.kind
      AND msk.key = COALESCE(cs.domain, host(cs.net::inet))
)`

// CompanyMaterializeResult 汇总一次物化的结果。
type CompanyMaterializeResult struct {
	TaskID    int64  `json:"task_id"`
	CompanyID int64  `json:"company_id"`
	Company   string `json:"company,omitempty"`
	// Rules 本次处理(新建或并入本任务)的声明规则数。
	Rules int `json:"rules"`
	// Domains / IPs 其中新建的资产行数(不含已存在只并 task_ids 的)。
	Domains int `json:"domains_created"`
	IPs     int `json:"ips_created"`
	// Blocked 命中资产拦截/不在任务白名单而【未物化】的规则数,BlockedSample 给样例。
	Blocked       int      `json:"blocked"`
	BlockedSample []string `json:"blocked_sample,omitempty"`
	// Remaining 本批之后,该公司还有多少条可物化规则没并入本任务。
	Remaining int `json:"remaining"`
}

// Pending 是否还有未展开的声明规则(用于收尾闸门与 planner 提示)。
func (r *CompanyMaterializeResult) Pending() bool { return r != nil && r.Remaining > 0 }

// MaterializeCompanyScope 把某企业声明的范围(domain / 单主机 IP)按 batch 条一批
// 展开成本任务的 assets 行。幂等:已存在的资产只并入 task_ids 与 company 归属。
//
// RoE 门控:命中全局/任务级资产拦截(或不在任务允许白名单内)的规则不物化,
// 只计数并返回样例——声明范围不等于绕过边界。
func (s *AssetStore) MaterializeCompanyScope(taskID, companyID int64, batch int) (*CompanyMaterializeResult, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("asset store 未初始化")
	}
	if taskID <= 0 || companyID <= 0 {
		return nil, nil
	}
	if batch <= 0 {
		batch = DefaultCompanyMaterializeBatch
	}
	if batch > MaxCompanyMaterializeBatch {
		batch = MaxCompanyMaterializeBatch
	}
	res := &CompanyMaterializeResult{TaskID: taskID, CompanyID: companyID}
	_ = s.db.QueryRow(`SELECT name FROM companies WHERE id=$1`, companyID).Scan(&res.Company)

	blockRules, _ := s.ListAssetInterceptRules()
	var allowRules []AssetInterceptRule
	if tb, ta, err := s.TaskInterceptRulesSplit(taskID); err == nil {
		blockRules = append(blockRules, tb...)
		allowRules = ta
	}

	// 规则可能被改过:先把此前记下的跳过重新判一遍,不再被拦截的重新纳入物化。
	if err := s.refreshMaterializeSkips(taskID, companyID, blockRules, allowRules); err != nil {
		return nil, err
	}

	rows, err := s.db.Query(`SELECT cs.kind, COALESCE(cs.domain,''), COALESCE(host(cs.net::inet),'')
FROM company_scope cs
WHERE cs.company_id=$1
  AND `+materializableCompanyScopePredicate+`
  AND `+unmaterializedCompanyScopePredicate+`
ORDER BY cs.id
LIMIT $3`, companyID, taskID, batch)
	if err != nil {
		return nil, fmt.Errorf("读取企业声明范围失败: %w", err)
	}
	domains := make([]string, 0, batch)
	ips := make([]string, 0, batch)
	seenD := map[string]bool{}
	seenI := map[string]bool{}
	skips := make([]materializeSkip, 0, 8)
	for rows.Next() {
		var kind, domain, host string
		if err := rows.Scan(&kind, &domain, &host); err != nil {
			rows.Close()
			return nil, err
		}
		// 闸门:先拦截后允许。被拒的规则不物化(声明范围不能覆盖任务边界)。
		if kind == "domain" {
			if d := EvaluateAssetGate(blockRules, allowRules, []string{domain}, nil, nil); !d.Allowed {
				res.Blocked++
				if len(res.BlockedSample) < 5 {
					res.BlockedSample = append(res.BlockedSample, domain+" → "+d.Reason)
				}
				skips = append(skips, materializeSkip{Kind: kind, Key: domain, Reason: d.Reason})
				continue
			}
			if domain != "" && !seenD[domain] {
				seenD[domain] = true
				domains = append(domains, domain)
			}
			continue
		}
		if host == "" {
			continue
		}
		if d := EvaluateAssetGate(blockRules, allowRules, nil, []string{host}, nil); !d.Allowed {
			res.Blocked++
			if len(res.BlockedSample) < 5 {
				res.BlockedSample = append(res.BlockedSample, host+" → "+d.Reason)
			}
			skips = append(skips, materializeSkip{Kind: kind, Key: host, Reason: d.Reason})
			continue
		}
		if !seenI[host] {
			seenI[host] = true
			ips = append(ips, host)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	if len(domains) > 0 || len(ips) > 0 {
		createdD, createdI, err := s.insertMaterializedAssets(taskID, domains, ips)
		if err != nil {
			return nil, err
		}
		res.Domains, res.IPs = createdD, createdI
		res.Rules = len(domains) + len(ips)
	}

	// 被 RoE 挡下的规则记账,否则「未物化规则数」永远 >0,收尾闸门关不上。
	if len(skips) > 0 {
		if err := s.recordMaterializeSkips(taskID, companyID, skips); err != nil {
			return nil, err
		}
	}

	remaining, err := s.CountPendingCompanyScope(taskID, companyID)
	if err != nil {
		return nil, err
	}
	res.Remaining = remaining
	return res, nil
}

// CountPendingCompanyScope 返回某企业还有多少条可物化规则尚未并入本任务。
func (s *AssetStore) CountPendingCompanyScope(taskID, companyID int64) (int, error) {
	if s == nil || s.db == nil || taskID <= 0 || companyID <= 0 {
		return 0, nil
	}
	var n int
	err := s.db.QueryRow(`SELECT count(*) FROM company_scope cs
WHERE cs.company_id=$1
  AND `+materializableCompanyScopePredicate+`
  AND `+unmaterializedCompanyScopePredicate, companyID, taskID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("统计待物化声明范围失败: %w", err)
	}
	return n, nil
}

// insertMaterializedAssets 在同一个事务里批量写入 root_domain / ip 资产。
// 复用 company_scope 变更那把锁(声明规则变更会全量重算归属),保证归属结果与规则一致。
func (s *AssetStore) insertMaterializedAssets(taskID int64, domains, ips []string) (createdDomains, createdIPs int, err error) {
	if s.tx != nil {
		return insertMaterializedTx(s.tx, taskID, domains, ips)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := lockCompanyScopeMutation(tx); err != nil {
		return 0, 0, err
	}
	createdDomains, createdIPs, err = insertMaterializedTx(tx, taskID, domains, ips)
	if err != nil {
		return 0, 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	return createdDomains, createdIPs, nil
}

func insertMaterializedTx(tx *sql.Tx, taskID int64, domains, ips []string) (createdDomains, createdIPs int, err error) {
	if len(domains) > 0 {
		n, err := insertMaterializedRootDomains(tx, taskID, domains)
		if err != nil {
			return 0, 0, err
		}
		createdDomains = n
	}
	if len(ips) > 0 {
		n, err := insertMaterializedIPs(tx, taskID, ips)
		if err != nil {
			return 0, 0, err
		}
		createdIPs = n
	}
	return createdDomains, createdIPs, nil
}

// countInserted 消费 INSERT ... ON CONFLICT ... RETURNING (xmax = 0) 的结果,
// 返回其中真正新建的行数(与 db 里 UpsertCompany 的 (xmax = 0) 判定一致)。
func countInserted(rows *sql.Rows) (int, error) {
	created := 0
	for rows.Next() {
		var inserted bool
		if err := rows.Scan(&inserted); err != nil {
			rows.Close()
			return 0, err
		}
		if inserted {
			created++
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()
	return created, nil
}

func jsonTextArray(items []string) (string, error) {
	b, err := json.Marshal(items)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// insertMaterializedRootDomains 批量落 root_domain 资产。
// company_id 由 company_scope 现算(与 resolveCompanyWithICP 同口径:同名规则取
// 最长匹配、再按 company_id 定序),保证多企业声明同一域名时结果与插入路径一致。
func insertMaterializedRootDomains(tx *sql.Tx, taskID int64, domains []string) (int, error) {
	payload, err := jsonTextArray(domains)
	if err != nil {
		return 0, err
	}
	rows, err := tx.Query(`
INSERT INTO assets(type, domain, root_domain, company_id, company_source, task_ids)
SELECT 'root_domain', t.d, t.d,
       (SELECT cs.company_id FROM company_scope cs
         WHERE cs.kind='domain' AND cs.domain = t.d
         ORDER BY length(cs.domain) DESC, cs.company_id
         LIMIT 1),
       'scope', ARRAY[$2::bigint]
FROM (SELECT DISTINCT value AS d FROM jsonb_array_elements_text($1::jsonb)) t
ON CONFLICT (domain) WHERE type = 'root_domain' DO UPDATE SET
    company_id = CASE
        WHEN assets.company_source = 'explicit' AND assets.company_id IS NOT NULL THEN assets.company_id
        ELSE COALESCE(EXCLUDED.company_id, assets.company_id)
    END,
    company_source = CASE
        WHEN assets.company_source = 'explicit' AND assets.company_id IS NOT NULL THEN 'explicit'
        WHEN EXCLUDED.company_id IS NOT NULL THEN 'scope'
        ELSE assets.company_source
    END,
    task_ids  = (SELECT ARRAY(SELECT DISTINCT unnest(assets.task_ids || EXCLUDED.task_ids))),
    last_seen = now()
RETURNING (xmax = 0)`, payload, taskID)
	if err != nil {
		return 0, fmt.Errorf("物化声明域名失败: %w", err)
	}
	return countInserted(rows)
}

// insertMaterializedIPs 批量落单主机 ip 资产(c_segment 与 UpsertIP 同口径:
// IPv4 取 /24、IPv6 取 /48)。
func insertMaterializedIPs(tx *sql.Tx, taskID int64, ips []string) (int, error) {
	payload, err := jsonTextArray(ips)
	if err != nil {
		return 0, err
	}
	rows, err := tx.Query(`
INSERT INTO assets(type, ip, c_segment, company_id, company_source, task_ids)
SELECT 'ip', t.h,
       CASE WHEN family(t.h::inet) = 4
            THEN network(set_masklen(t.h::inet, 24))
            ELSE network(set_masklen(t.h::inet, 48)) END,
       (SELECT cs.company_id FROM company_scope cs
         WHERE cs.kind IN ('ip','cidr') AND cs.net >>= t.h::inet
         ORDER BY masklen(cs.net) DESC, cs.company_id
         LIMIT 1),
       'scope', ARRAY[$2::bigint]
FROM (SELECT DISTINCT value AS h FROM jsonb_array_elements_text($1::jsonb)) t
ON CONFLICT (ip) WHERE type = 'ip' DO UPDATE SET
    company_id = CASE
        WHEN assets.company_source = 'explicit' AND assets.company_id IS NOT NULL THEN assets.company_id
        ELSE COALESCE(EXCLUDED.company_id, assets.company_id)
    END,
    company_source = CASE
        WHEN assets.company_source = 'explicit' AND assets.company_id IS NOT NULL THEN 'explicit'
        WHEN EXCLUDED.company_id IS NOT NULL THEN 'scope'
        ELSE assets.company_source
    END,
    c_segment = COALESCE(assets.c_segment, EXCLUDED.c_segment),
    task_ids  = (SELECT ARRAY(SELECT DISTINCT unnest(assets.task_ids || EXCLUDED.task_ids))),
    last_seen = now()
RETURNING (xmax = 0)`, payload, taskID)
	if err != nil {
		return 0, fmt.Errorf("物化声明 IP 失败: %w", err)
	}
	return countInserted(rows)
}

// TaskCompanyScopePending 汇总本任务(含直接关联任务)名下所有 company 范围里
// 尚未物化的规则数,供 graph_overview / 收尾闸门判断"声明范围是否已全部展开"。
// 第二个返回值是涉及的企业名列表(用于提示)。
func (s *AssetStore) TaskCompanyScopePending(taskID int64) (int, []string, error) {
	if s == nil || s.db == nil || taskID <= 0 {
		return 0, nil, nil
	}
	comps, err := s.taskCompanyScopeCompanies(taskID)
	if err != nil {
		return 0, nil, err
	}

	total := 0
	var names []string
	for _, c := range comps {
		n, err := s.CountPendingCompanyScope(taskID, c.id)
		if err != nil {
			return 0, nil, err
		}
		if n > 0 {
			total += n
			if c.name != "" {
				names = append(names, c.name)
			} else {
				names = append(names, fmt.Sprintf("#%d", c.id))
			}
		}
	}
	return total, names, nil
}

// CompanyScopeKeywords 取本任务范围内企业声明的关键词规则(给 agent 的提示,
// 不参与覆盖度分母),供 graph_overview 汇总。
func (s *AssetStore) CompanyScopeKeywords(taskID int64) ([]string, error) {
	if s == nil || s.db == nil || taskID <= 0 {
		return nil, nil
	}
	rows, err := s.db.Query(`WITH `+directTaskContextCTE+`
SELECT DISTINCT COALESCE(NULLIF(cs.raw,''), cs.value)
FROM company_scope cs
JOIN task_scope ts ON ts.kind='company' AND ts.company_id = cs.company_id
JOIN context_tasks ctx ON ctx.task_id = ts.task_id
WHERE cs.kind = 'keyword'`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out, rows.Err()
}

// materializeSkip 是一条被 RoE 挡下、未物化的声明规则。
type materializeSkip struct {
	Kind   string `json:"kind"`
	Key    string `json:"key"`
	Reason string `json:"reason"`
}

// recordMaterializeSkips 把被拦截的规则记入台账(幂等覆盖)。
func (s *AssetStore) recordMaterializeSkips(taskID, companyID int64, skips []materializeSkip) error {
	payload, err := json.Marshal(skips)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO company_scope_materialize_skip(task_id, company_id, kind, key, reason)
SELECT $1, $2, t.kind, t.key, t.reason
FROM jsonb_to_recordset($3::jsonb) AS t(kind text, key text, reason text)
ON CONFLICT (task_id, company_id, kind, key) DO UPDATE SET
    reason = EXCLUDED.reason,
    updated_at = now()`, taskID, companyID, string(payload))
	if err != nil {
		return fmt.Errorf("记录声明范围跳过失败: %w", err)
	}
	return nil
}

// refreshMaterializeSkips 重估本任务已记账的跳过规则:规则已不再被拦截(拦截规则
// 被删/被禁/白名单放宽)时删除跳过记录,让它重新回到待物化队列。
func (s *AssetStore) refreshMaterializeSkips(taskID, companyID int64, blockRules, allowRules []AssetInterceptRule) error {
	rows, err := s.db.Query(`SELECT msk.kind, msk.key
FROM company_scope_materialize_skip msk
JOIN company_scope cs
  ON cs.company_id = msk.company_id
 AND cs.kind = msk.kind
 AND COALESCE(cs.domain, host(cs.net::inet)) = msk.key
WHERE msk.task_id = $1 AND msk.company_id = $2`, taskID, companyID)
	if err != nil {
		return err
	}
	var stale []materializeSkip
	for rows.Next() {
		var k materializeSkip
		if err := rows.Scan(&k.Kind, &k.Key); err != nil {
			rows.Close()
			return err
		}
		if k.Kind == "domain" {
			if d := EvaluateAssetGate(blockRules, allowRules, []string{k.Key}, nil, nil); d.Allowed {
				stale = append(stale, k)
			}
			continue
		}
		if d := EvaluateAssetGate(blockRules, allowRules, nil, []string{k.Key}, nil); d.Allowed {
			stale = append(stale, k)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, k := range stale {
		if _, err := s.db.Exec(`DELETE FROM company_scope_materialize_skip
WHERE task_id=$1 AND company_id=$2 AND kind=$3 AND key=$4`, taskID, companyID, k.Kind, k.Key); err != nil {
			return err
		}
	}
	return nil
}

// companyRef 是本任务范围内声明了资产范围的企业。
type companyRef struct {
	id   int64
	name string
}

// taskCompanyScopeCompanies 列出本任务(含直接关联任务)范围内声明的企业。
func (s *AssetStore) taskCompanyScopeCompanies(taskID int64) ([]companyRef, error) {
	rows, err := s.db.Query(`WITH `+directTaskContextCTE+`
SELECT DISTINCT ts.company_id, COALESCE(c.name,'')
FROM task_scope ts
LEFT JOIN companies c ON c.id = ts.company_id
JOIN context_tasks ctx ON ctx.task_id = ts.task_id
WHERE ts.kind='company' AND ts.company_id IS NOT NULL`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var comps []companyRef
	for rows.Next() {
		var c companyRef
		if err := rows.Scan(&c.id, &c.name); err != nil {
			return nil, err
		}
		comps = append(comps, c)
	}
	return comps, rows.Err()
}

// MaterializeTaskCompanyScopes 把本任务范围内所有企业声明按 batch 条一批展开成
// 待测资产,返回每家企业本批的结果。供 planner 每轮前调用 / agent 工具调用。
func (s *AssetStore) MaterializeTaskCompanyScopes(taskID int64, batch int) ([]CompanyMaterializeResult, error) {
	if s == nil || s.db == nil || taskID <= 0 {
		return nil, nil
	}
	comps, err := s.taskCompanyScopeCompanies(taskID)
	if err != nil {
		return nil, err
	}
	var out []CompanyMaterializeResult
	for _, c := range comps {
		r, err := s.MaterializeCompanyScope(taskID, c.id, batch)
		if err != nil {
			return out, err
		}
		if r == nil {
			continue
		}
		if r.Company == "" {
			r.Company = c.name
		}
		out = append(out, *r)
	}
	return out, nil
}

// CompanyMaterializeEnabled 报告「声明范围物化」总开关是否打开。
// 默认打开;ARTEX_COMPANY_MATERIALIZE=0/false 关闭。关闭时物化与收尾闸门一并失效,
// 便于操作员在个别部署上退回「声明范围只做归属认领」的旧行为。
func CompanyMaterializeEnabled() bool {
	v := strings.TrimSpace(os.Getenv("ARTEX_COMPANY_MATERIALIZE"))
	return v != "0" && !strings.EqualFold(v, "false")
}

// CountPendingTaskCompanyScope 统计本任务范围内【所有企业】还有多少条可物化声明
// 规则尚未并入本任务。收尾闸门用它判断「任务能不能判完成」:声明范围即待测工作,
// 只要还有可物化的规则没展开,就不允许收官(否则又回到「9000 资产只测几百个」)。
func (s *AssetStore) CountPendingTaskCompanyScope(taskID int64) (int, error) {
	if s == nil || s.db == nil || taskID <= 0 {
		return 0, nil
	}
	comps, err := s.taskCompanyScopeCompanies(taskID)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, c := range comps {
		n, err := s.CountPendingCompanyScope(taskID, c.id)
		if err != nil {
			return 0, err
		}
		total += n
	}
	return total, nil
}

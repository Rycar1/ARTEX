package db

// intel.go —— 全局情报库(schema.sql §O)。参考 AutoHunter 的 intel 库:
// 一个任务里验证过的凭据、确认的漏洞特征、发现的端点,沉淀成 (kind,key)
// 唯一的全局条目,后续任务先查库再开打,不必从零开始。
//
// 设计约束:
//   - 只存可复用的说明/证据,不存明文密钥:凭据条目只记 cred_type + 主机 + credential id。
//   - (kind,key) 上唯一;写入用 ON CONFLICT 合并(保留更长 value、取最大 confidence、去重追加 source)。
//   - 可全局关:ARTEX_INTEL=0/false/off/no/disabled 关闭,默认开。

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// 情报类型(schema §O CHECK 同源)。
const (
	IntelCred        = "cred"        // 凭据线索(已验证或已登记的用户名@域/类型/主机)
	IntelFingerprint = "fingerprint" // 漏洞特征(归一化 vulnclass)
	IntelEndpoint    = "endpoint"    // 端点(方法+URL/主机标识)
	IntelProfile     = "profile"     // 目标画像(技术栈/ICP/标签)
)

// ValidIntelKind 校验情报类型。
func ValidIntelKind(k string) bool {
	switch k {
	case IntelCred, IntelFingerprint, IntelEndpoint, IntelProfile:
		return true
	}
	return false
}

// IntelEnabled 报告全局情报库是否启用。未设置=开;
// ARTEX_INTEL 为 0/false/off/no/disabled 时关闭。
func IntelEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ARTEX_INTEL"))) {
	case "0", "false", "off", "no", "disabled":
		return false
	}
	return true
}

// IntelRecord 是 intel 表一行。
type IntelRecord struct {
	ID           int64     `json:"id"`
	Kind         string    `json:"kind"`
	Key          string    `json:"key"`
	Value        string    `json:"value"`
	SourceTaskID int64     `json:"source_task_id,omitempty"`
	Source       string    `json:"source,omitempty"`
	Confidence   float64   `json:"confidence"`
	Hits         int64     `json:"hits"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// IntelStore 是 intel 表的访问层。
type IntelStore struct{ d *DB }

// Intel 返回全局情报库。
func (d *DB) Intel() *IntelStore { return &IntelStore{d: d} }

const intelCols = `id, kind, key, value, COALESCE(source_task_id,0), source,
	confidence, hits, created_at, updated_at`

func scanIntel(row interface{ Scan(...any) error }) (*IntelRecord, error) {
	var r IntelRecord
	if err := row.Scan(&r.ID, &r.Kind, &r.Key, &r.Value, &r.SourceTaskID, &r.Source,
		&r.Confidence, &r.Hits, &r.CreatedAt, &r.UpdatedAt); err != nil {
		return nil, err
	}
	return &r, nil
}

// NormalizeIntelKey 归一化去重键:去首尾空白、转小写、内部连续空白压成单空格。
// 让 "漏洞 X" / " 漏洞  x " 合并同一条。
func NormalizeIntelKey(s string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(s))), " ")
}

func truncateIntel(s string, n int) string {
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// UpsertIntel 插入或合并一条 (kind,key) 情报。冲突时:
// 保留更长的 value、取最大 confidence、合并 source(去重),推进 updated_at。
func (s *IntelStore) UpsertIntel(ctx context.Context, rec *IntelRecord) error {
	if s == nil || s.d == nil {
		return fmt.Errorf("intel store 未初始化")
	}
	return upsertIntel(ctx, s.d, rec)
}

// UpsertIntelTx 在事务内插入/合并情报(确认漏洞时与状态更新同事务)。
func (s *IntelStore) UpsertIntelTx(ctx context.Context, tx *sql.Tx, rec *IntelRecord) error {
	if tx == nil {
		return fmt.Errorf("intel tx 为空")
	}
	return upsertIntel(ctx, tx, rec)
}

type intelExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func upsertIntel(ctx context.Context, ex intelExecer, rec *IntelRecord) error {
	if rec == nil {
		return nil
	}
	rec.Kind = strings.TrimSpace(rec.Kind)
	rec.Key = NormalizeIntelKey(rec.Key)
	if !ValidIntelKind(rec.Kind) {
		return fmt.Errorf("非法 intel kind %q", rec.Kind)
	}
	if rec.Key == "" {
		return fmt.Errorf("intel key 不能为空")
	}
	if rec.Confidence <= 0 {
		rec.Confidence = 0.5
	}
	if rec.Confidence > 1 {
		rec.Confidence = 1
	}
	_, err := ex.ExecContext(ctx, `
INSERT INTO intel(kind, key, value, source_task_id, source, confidence, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, now())
ON CONFLICT (kind, key) DO UPDATE SET
    value = CASE WHEN length(EXCLUDED.value) > length(intel.value)
                 THEN EXCLUDED.value ELSE intel.value END,
    source_task_id = COALESCE(EXCLUDED.source_task_id, intel.source_task_id),
    source = CASE
        WHEN EXCLUDED.source = '' THEN intel.source
        WHEN intel.source = '' THEN EXCLUDED.source
        WHEN position(EXCLUDED.source in intel.source) > 0 THEN intel.source
        ELSE intel.source || '; ' || EXCLUDED.source
    END,
    confidence = GREATEST(intel.confidence, EXCLUDED.confidence),
    updated_at = now()`,
		rec.Kind, rec.Key, rec.Value, nilIfZero(rec.SourceTaskID), rec.Source, rec.Confidence)
	return err
}

// UpsertIntelBatch 批量写入(同一连接,非事务)。
func (s *IntelStore) UpsertIntelBatch(ctx context.Context, recs []*IntelRecord) error {
	if s == nil || s.d == nil {
		return fmt.Errorf("intel store 未初始化")
	}
	var firstErr error
	for _, r := range recs {
		if err := upsertIntel(ctx, s.d, r); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// UpsertIntelTxBatch 在事务内批量写入。
func UpsertIntelTxBatch(ctx context.Context, tx *sql.Tx, recs []*IntelRecord) error {
	if tx == nil {
		return fmt.Errorf("intel tx 为空")
	}
	for _, r := range recs {
		if err := upsertIntel(ctx, tx, r); err != nil {
			return err
		}
	}
	return nil
}

// intelLimit 归一化分页参数:默认 20,上限 100。
func intelLimit(n int) int {
	if n <= 0 {
		return 20
	}
	if n > 100 {
		return 100
	}
	return n
}

// SearchIntel 按类型+关键词检索情报。q 为空时返回最近更新的条目;
// 否则在 key/value 上做大小写不敏感子串匹配。结果按 confidence、hits、updated_at 降序。
func (s *IntelStore) SearchIntel(ctx context.Context, kind, q string, limit int) ([]*IntelRecord, error) {
	if s == nil || s.d == nil {
		return nil, fmt.Errorf("intel store 未初始化")
	}
	kind = strings.TrimSpace(kind)
	if kind != "" && !ValidIntelKind(kind) {
		return nil, fmt.Errorf("非法 intel kind %q", kind)
	}
	lim := intelLimit(limit)
	q = strings.TrimSpace(q)
	rows, err := s.d.QueryContext(ctx, `
SELECT `+intelCols+` FROM intel
WHERE ($1 = '' OR kind = $1)
  AND ($2 = '' OR key ILIKE '%'||$2||'%' OR value ILIKE '%'||$2||'%')
ORDER BY confidence DESC, hits DESC, updated_at DESC
LIMIT $3`, kind, q, lim)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectIntel(rows)
}

// ListIntel 列出某类情报(类型空=全部),按热度降序。
func (s *IntelStore) ListIntel(ctx context.Context, kind string, limit int) ([]*IntelRecord, error) {
	return s.SearchIntel(ctx, kind, "", limit)
}

// TouchIntel 批量上调命中次数(检索命中后调用,最佳努力)。
func (s *IntelStore) TouchIntel(ctx context.Context, ids []int64) error {
	if s == nil || s.d == nil || len(ids) == 0 {
		return nil
	}
	_, err := s.d.ExecContext(ctx, `UPDATE intel SET hits = hits + 1 WHERE id = ANY($1)`, ids)
	return err
}

// CountIntel 返回总数与各类型计数。
func (s *IntelStore) CountIntel(ctx context.Context) (int64, map[string]int64, error) {
	if s == nil || s.d == nil {
		return 0, nil, fmt.Errorf("intel store 未初始化")
	}
	rows, err := s.d.QueryContext(ctx, `SELECT kind, count(*) FROM intel GROUP BY kind`)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()
	byKind := map[string]int64{}
	var total int64
	for rows.Next() {
		var k string
		var n int64
		if err := rows.Scan(&k, &n); err != nil {
			return 0, nil, err
		}
		byKind[k] = n
		total += n
	}
	return total, byKind, rows.Err()
}

func collectIntel(rows *sql.Rows) ([]*IntelRecord, error) {
	out := []*IntelRecord{}
	for rows.Next() {
		r, err := scanIntel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AssetIdentity 是一个受影响资产的可读标识(id + url/domain/ip)。
type AssetIdentity struct {
	ID    int64
	Value string
}

// CredentialIntel 把一条凭据投影为全局情报条目(kind=cred)。
// key=username@domain(无用户名则用 credential#id),value 只含类型+主机+credential id —— 不含明文密钥。
func CredentialIntel(rec *CredentialRecord) *IntelRecord {
	if rec == nil {
		return nil
	}
	key := strings.TrimSpace(rec.Username)
	if rec.Domain != "" {
		if key != "" {
			key += "@" + rec.Domain
		} else {
			key = rec.Domain
		}
	}
	if key == "" {
		key = fmt.Sprintf("credential#%d", rec.ID)
	}
	v := "cred_type=" + rec.CredType
	if rec.HostAssetID > 0 {
		v += fmt.Sprintf(" host_asset=%d", rec.HostAssetID)
	}
	if rec.Source != "" {
		v += " source=" + truncateIntel(rec.Source, 80)
	}
	v += fmt.Sprintf(" credential_id=%d", rec.ID)
	conf := 0.6
	if rec.Verified {
		conf = 0.9
	}
	src := "credential_added"
	if rec.Verified {
		src = "credential_verified"
	}
	return &IntelRecord{
		Kind: IntelCred, Key: key, Value: v,
		SourceTaskID: rec.TaskID, Source: src, Confidence: conf,
	}
}

// FindingIntel 从一条已确认漏洞推导全局情报:
//   - kind=fingerprint,key=归一化 vulnclass(或 name):记录该类漏洞在目标上确认过;
//   - kind=endpoint,key=受影响资产标识:记录该资产上的漏洞类型,后续任务碰到同一资产直接可见。
//
// 类型与名称都为空时返回 nil。
func FindingIntel(vulnclass, name, severity, summary string, taskID int64, assets []AssetIdentity) []*IntelRecord {
	pattern := NormalizeIntelKey(vulnclass)
	label := strings.TrimSpace(vulnclass)
	if pattern == "" {
		pattern = NormalizeIntelKey(name)
		label = strings.TrimSpace(name)
	}
	if pattern == "" {
		return nil
	}
	if nm := strings.TrimSpace(name); nm != "" && NormalizeIntelKey(nm) != pattern {
		label = label + " / " + nm
	}
	val := "confirmed"
	if severity != "" {
		val += " severity=" + severity
	}
	if label != "" {
		val += " name=" + label
	}
	if s := truncateIntel(summary, 160); s != "" {
		val += " | " + s
	}
	out := []*IntelRecord{{
		Kind: IntelFingerprint, Key: pattern, Value: val,
		SourceTaskID: taskID, Source: "finding_confirmed", Confidence: 0.8,
	}}
	for _, a := range assets {
		v := strings.TrimSpace(a.Value)
		if v == "" {
			continue
		}
		ev := "vulnclass=" + label
		if severity != "" {
			ev += " severity=" + severity
		}
		if a.ID > 0 {
			ev += fmt.Sprintf(" asset=%d", a.ID)
		}
		out = append(out, &IntelRecord{
			Kind: IntelEndpoint, Key: v, Value: ev,
			SourceTaskID: taskID, Source: "finding_confirmed", Confidence: 0.75,
		})
	}
	return out
}

// recordFindingIntelTx 将一条已确认漏洞沉淀到全局情报库(在状态更新同事务内完成)。
// 最佳努力:失败不应阻断状态转换,调用方可忽略返回值。
func recordFindingIntelTx(ctx context.Context, tx *sql.Tx, findingID int64) error {
	if tx == nil || !IntelEnabled() {
		return nil
	}
	var (
		vulnclass, name, severity, summary string
		taskID                             sql.NullInt64
		assetIDs                           []byte
	)
	err := tx.QueryRowContext(ctx, `SELECT vulnclass, name, severity, summary, task_id, asset_ids
FROM findings WHERE id=$1`, findingID).
		Scan(&vulnclass, &name, &severity, &summary, &taskID, &assetIDs)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	var ids []int64
	_ = json.Unmarshal(assetIDs, &ids)
	assets := assetIdentitiesTx(ctx, tx, ids)
	return UpsertIntelTxBatch(ctx, tx, FindingIntel(vulnclass, name, severity, summary, taskID.Int64, assets))
}

// assetIdentitiesTx 读取受影响资产的可读标识(url/domain/ip/app/service)。
func assetIdentitiesTx(ctx context.Context, tx *sql.Tx, ids []int64) []AssetIdentity {
	if len(ids) == 0 {
		return nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,
		COALESCE(NULLIF(url,''), NULLIF(domain,''), NULLIF(ip,''), NULLIF(app_name,''), NULLIF(service_name,''), '')
	FROM assets WHERE id = ANY($1)`, ids)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []AssetIdentity{}
	for rows.Next() {
		var a AssetIdentity
		if err := rows.Scan(&a.ID, &a.Value); err != nil {
			return out
		}
		out = append(out, a)
	}
	return out
}

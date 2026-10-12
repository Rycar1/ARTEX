package db

// intel_test.go —— 全局情报库(schema §O)。纯函数测试不需 PG;
// 存储层 roundtrip 需 dev PG(无 DSN 时 skip)。

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestValidIntelKind(t *testing.T) {
	for _, k := range []string{IntelCred, IntelFingerprint, IntelEndpoint, IntelProfile} {
		if !ValidIntelKind(k) {
			t.Fatalf("%q 应合法", k)
		}
	}
	for _, k := range []string{"", "CRED", "foo", "cred "} {
		if ValidIntelKind(k) {
			t.Fatalf("%q 应非法", k)
		}
	}
}

func TestIntelEnabledEnv(t *testing.T) {
	t.Setenv("ARTEX_INTEL", "")
	if !IntelEnabled() {
		t.Fatal("默认应启用")
	}
	for _, off := range []string{"0", "false", "off", "no", "disabled", "OFF"} {
		t.Setenv("ARTEX_INTEL", off)
		if IntelEnabled() {
			t.Fatalf("ARTEX_INTEL=%q 应关闭", off)
		}
	}
	t.Setenv("ARTEX_INTEL", "1")
	if !IntelEnabled() {
		t.Fatal("ARTEX_INTEL=1 应启用")
	}
}

func TestNormalizeIntelKey(t *testing.T) {
	cases := map[string]string{
		"  SQL  Injection ": "sql injection",
		"SQL\tInjection":    "sql injection",
		"":                  "",
		"\u6f0f\u6d1e  X":   "",
	}
	// 中文不受 lower 影响,仅压空白。
	cases["\u6f0f\u6d1e  X"] = "\u6f0f\u6d1e x"
	for in, want := range cases {
		if got := NormalizeIntelKey(in); got != want {
			t.Fatalf("NormalizeIntelKey(%q)=%q want %q", in, got, want)
		}
	}
}

func TestCredentialIntelNoSecretLeak(t *testing.T) {
	rec := &CredentialRecord{
		ID: 7, TaskID: 3, HostAssetID: 42, Username: "admin",
		CredType: CredPassword, Secret: "SuperSecret!23", Domain: "corp.local",
		Source: "sqli dump users", Verified: true,
	}
	ir := CredentialIntel(rec)
	if ir == nil || ir.Kind != IntelCred {
		t.Fatalf("bad intel: %+v", ir)
	}
	if ir.Key != "admin@corp.local" {
		t.Fatalf("key=%q", ir.Key)
	}
	if strings.Contains(ir.Value, "SuperSecret") {
		t.Fatalf("value 不得含明文密钥: %q", ir.Value)
	}
	if !strings.Contains(ir.Value, "credential_id=7") || !strings.Contains(ir.Value, "cred_type=password") {
		t.Fatalf("value 缺关键信息: %q", ir.Value)
	}
	if ir.Confidence < 0.9 {
		t.Fatalf("verified 凭据 confidence 应高: %v", ir.Confidence)
	}
	// 未验证凭据 confidence 更低。
	ir2 := CredentialIntel(&CredentialRecord{ID: 8, Username: "u", CredType: CredHashNT})
	if ir2 == nil || ir2.Confidence >= ir.Confidence {
		t.Fatalf("unverified confidence 应低于 verified: %+v", ir2)
	}
}

func TestFindingIntel(t *testing.T) {
	assets := []AssetIdentity{{ID: 5, Value: "https://a.example/x?id=1"}, {ID: 0, Value: "  "}}
	recs := FindingIntel("SQL Injection", "SQLi in id", "high", "union-based, dump users", 11, assets)
	if len(recs) != 2 { // fingerprint + 1 endpoint(空标识被跳过)
		t.Fatalf("want 2 entries, got %d: %+v", len(recs), recs)
	}
	if recs[0].Kind != IntelFingerprint || recs[0].Key != "sql injection" {
		t.Fatalf("fingerprint entry bad: %+v", recs[0])
	}
	if recs[1].Kind != IntelEndpoint || recs[1].Key != "https://a.example/x?id=1" {
		t.Fatalf("endpoint entry bad: %+v", recs[1])
	}
	// 类型与名称都为空 ⇒ 无条目。
	if got := FindingIntel("", "", "", "", 1, nil); got != nil {
		t.Fatalf("want nil, got %+v", got)
	}
}

func TestIntelStoreRoundtrip(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	ctx := context.Background()
	st := d.Intel()

	// 隔离测试数据:用带标记的 kind 不行(kind 受限),改用独特 key 前缀并清理。
	const pref = "zzinteltest-"
	cleanup := func() {
		d.Exec(`DELETE FROM intel WHERE key LIKE $1`, pref+"%")
	}
	cleanup()
	defer cleanup()

	if err := st.UpsertIntel(ctx, &IntelRecord{
		Kind: IntelFingerprint, Key: pref + "SQL  Injection", Value: "short",
		SourceTaskID: 101, Source: "task-a", Confidence: 0.5,
	}); err != nil {
		t.Fatal(err)
	}
	// 同键(归一化后相等)合并:保留更长 value、取最大 confidence、合并 source。
	if err := st.UpsertIntel(ctx, &IntelRecord{
		Kind: IntelFingerprint, Key: pref + "sql injection", Value: "a much longer reusable description",
		SourceTaskID: 202, Source: "task-b", Confidence: 0.9,
	}); err != nil {
		t.Fatal(err)
	}
	got, err := st.SearchIntel(ctx, IntelFingerprint, pref+"sql injection", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 merged row, got %d: %+v", len(got), got)
	}
	r := got[0]
	if !strings.Contains(r.Value, "much longer") {
		t.Fatalf("value 应保留更长的: %q", r.Value)
	}
	if r.Confidence < 0.9 {
		t.Fatalf("confidence 应取最大: %v", r.Confidence)
	}
	if !strings.Contains(r.Source, "task-a") || !strings.Contains(r.Source, "task-b") {
		t.Fatalf("source 应合并去重: %q", r.Source)
	}

	// TouchIntel 上调 hits。
	if err := st.TouchIntel(ctx, []int64{r.ID}); err != nil {
		t.Fatal(err)
	}
	got, _ = st.SearchIntel(ctx, IntelFingerprint, pref+"sql injection", 10)
	if len(got) != 1 || got[0].Hits != 1 {
		t.Fatalf("hits 应为 1: %+v", got)
	}

	// 类型过滤:用另一类型写一条,按 cred 查不到 fingerprint。
	if err := st.UpsertIntel(ctx, &IntelRecord{Kind: IntelCred, Key: pref + "admin@corp.local", Value: "cred_type=password"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.SearchIntel(ctx, IntelCred, pref+"admin", 10); len(got) != 1 || got[0].Kind != IntelCred {
		t.Fatalf("cred 过滤失败: %+v", got)
	}
	if got, _ := st.SearchIntel(ctx, IntelFingerprint, pref+"admin", 10); len(got) != 0 {
		t.Fatalf("fingerprint 不应匹配 cred 条目: %+v", got)
	}

	// 非法 kind 拒绝。
	if err := st.UpsertIntel(ctx, &IntelRecord{Kind: "bogus", Key: pref + "x"}); err == nil {
		t.Fatal("非法 kind 应拒绝")
	}
	if _, err := st.SearchIntel(ctx, "bogus", "", 5); err == nil {
		t.Fatal("非法 kind 检索应拒绝")
	}
	// 空 key 拒绝。
	if err := st.UpsertIntel(ctx, &IntelRecord{Kind: IntelProfile, Key: "   "}); err == nil {
		t.Fatal("空 key 应拒绝")
	}
}

func TestIntelDisabledSkipsHook(t *testing.T) {
	// 关闭时 IntelEnabled 为 false,钩子不会写库(这里只验证开关本身)。
	t.Setenv("ARTEX_INTEL", "off")
	defer os.Unsetenv("ARTEX_INTEL")
	if IntelEnabled() {
		t.Fatal("应关闭")
	}
}

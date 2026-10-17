package assetscreen

import (
	"strings"
	"testing"
)

func TestPrefilterSkips(t *testing.T) {
	cases := []struct {
		name string
		in   Input
		want string
	}{
		{"loopback", Input{Host: "localhost"}, "loopback_or_unspecified"},
		{"loopback ip", Input{Host: "127.0.0.1"}, "loopback_or_unspecified"},
		{"empty", Input{}, "loopback_or_unspecified"},
		{"gov", Input{Host: "mail.abc.gov.cn"}, "sensitive_domain"},
		{"mil", Input{Host: "portal.army.mil"}, "sensitive_domain"},
		{"platform", Input{Host: "foo.github.io"}, "platform_default_domain"},
		{"vercel", Input{Host: "bar.vercel.app"}, "platform_default_domain"},
		{"bare host kept by default", Input{Host: "intranet"}, ""},
		{"keep normal", Input{Host: "www.example.com"}, ""},
		{"keep bucket", Input{Host: "mybucket.oss-cn-hangzhou.aliyuncs.com"}, ""},
		{"keep ip", Input{Host: "10.0.0.5"}, ""},
	}
	for _, c := range cases {
		if got := Prefilter(c.in); got != c.want {
			t.Errorf("%s: Prefilter=%q want %q", c.name, got, c.want)
		}
	}
}

func TestPrefilterBareHostOptIn(t *testing.T) {
	p := Policy{SkipBareHost: true}
	if got := PrefilterWithPolicy(Input{Host: "intranet"}, p); got != "no_registrable_domain" {
		t.Errorf("bare host should be skipped when opted in, got %q", got)
	}
	if got := PrefilterWithPolicy(Input{Host: "10.0.0.5"}, p); got != "" {
		t.Errorf("IP must not be treated as bare host, got %q", got)
	}
}

func TestPrefilterPolicyOff(t *testing.T) {
	p := Policy{SkipSensitive: false, SkipPlatformDefaults: false}
	if got := PrefilterWithPolicy(Input{Host: "mail.abc.gov.cn"}, p); got != "" {
		t.Errorf("sensitive skip should be off, got %q", got)
	}
	if got := PrefilterWithPolicy(Input{Host: "foo.github.io"}, p); got != "" {
		t.Errorf("platform skip should be off, got %q", got)
	}
}

func TestScoreAdminPositive(t *testing.T) {
	score, reasons := Score(Input{Host: "admin.example.com", Title: "后台管理系统"})
	if score <= 0 {
		t.Fatalf("expected positive score, got %v (%v)", score, reasons)
	}
	if !contains(reasons, "admin_backend") {
		t.Errorf("expected admin_backend reason, got %v", reasons)
	}
}

func TestScoreAuthGatewayNegative(t *testing.T) {
	score, reasons := Score(Input{Host: "sso.example.com", Title: "统一认证中心"})
	if score >= 0 {
		t.Fatalf("expected negative score, got %v (%v)", score, reasons)
	}
	if !contains(reasons, "auth_gateway") {
		t.Errorf("expected auth_gateway reason, got %v", reasons)
	}
}

func TestScoreNonstandardPort(t *testing.T) {
	score, reasons := Score(Input{Host: "app.example.com", Port: 8443})
	if !contains(reasons, "nonstandard_port") {
		t.Errorf("expected nonstandard_port, got %v (%v)", score, reasons)
	}
	_, reasons2 := Score(Input{Host: "app.example.com", Port: 443})
	if contains(reasons2, "nonstandard_port") {
		t.Errorf("443 should not be nonstandard, got %v", reasons2)
	}
}

func TestProductKey(t *testing.T) {
	if got := ProductKey("后台管理系统 - 登录"); got == "" {
		t.Errorf("expected product key, got empty")
	}
	if got := ProductKey("登录"); got != "" {
		t.Errorf("short title should yield empty, got %q", got)
	}
	if got := ProductKey(""); got != "" {
		t.Errorf("empty title should yield empty, got %q", got)
	}
}

func TestClusterKeyGroupsSameProduct(t *testing.T) {
	a := ClusterKey(Input{Host: "a.example.com", Title: "某某管理系统 - 登录"})
	b := ClusterKey(Input{Host: "b.example.com", Title: "某某管理系统 - 登录"})
	if a == "" || a != b {
		t.Errorf("expected same cluster, got %q vs %q", a, b)
	}
	c := ClusterKey(Input{Host: "a.example.com", Title: "完全不同的产品名称"})
	if c == a {
		t.Errorf("different products should differ: %q vs %q", c, a)
	}
}

func TestClusterKeyRootDomain(t *testing.T) {
	if got := ClusterKey(Input{Host: "deep.sub.tencent.com"}); got != "tencent.com" {
		t.Errorf("expected tencent.com, got %q", got)
	}
	if got := ClusterKey(Input{Host: "www.tsinghua.edu.cn"}); got != "tsinghua.edu.cn" {
		t.Errorf("expected tsinghua.edu.cn, got %q", got)
	}
}

func TestEvaluateCombines(t *testing.T) {
	d := Evaluate(Input{Host: "admin.example.com", Title: "后台管理系统"})
	if d.Skip {
		t.Fatalf("should not skip: %s", d.SkipReason)
	}
	if d.Score <= 0 || d.Cluster == "" {
		t.Errorf("unexpected decision: %+v", d)
	}
	skipped := Evaluate(Input{Host: "localhost"})
	if !skipped.Skip || skipped.SkipReason == "" {
		t.Errorf("localhost should be skipped: %+v", skipped)
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if strings.EqualFold(x, want) {
			return true
		}
	}
	return false
}

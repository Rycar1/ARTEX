// Package assetscreen 提供资产进入测试队列前的机械预筛、优先级评分与同款聚类。
// 纯函数实现：不访问数据库、不发起网络请求，便于单测与在引擎侧任意复用。
package assetscreen

import (
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"unicode/utf8"
)

// Input 描述一个待筛选的资产。
type Input struct {
	Kind         string   `json:"kind,omitempty"`
	Host         string   `json:"host,omitempty"`
	URL          string   `json:"url,omitempty"`
	IP           string   `json:"ip,omitempty"`
	Title        string   `json:"title,omitempty"`
	ServerHeader string   `json:"server_header,omitempty"`
	Technologies []string `json:"technologies,omitempty"`
	Port         int      `json:"port,omitempty"`
	StatusCode   int      `json:"status_code,omitempty"`
}

// Decision 是筛选结果。
type Decision struct {
	Skip         bool     `json:"skip"`
	SkipReason   string   `json:"skip_reason,omitempty"`
	Score        float64  `json:"score"`
	ScoreReasons []string `json:"score_reasons,omitempty"`
	Cluster      string   `json:"cluster,omitempty"`
}

// Policy 控制预筛的开关。零值 = 全部关闭(只过滤回环/未指定地址这类纯噪声)。
type Policy struct {
	// SkipSensitive 跳过 .gov/.mil 等敏感域名。
	SkipSensitive bool
	// SkipPlatformDefaults 跳过 github.io / vercel.app 等第三方托管平台默认域。
	SkipPlatformDefaults bool
	// SkipBareHost 跳过不含点且非 IP 的裸主机名(内网 NetBIOS 名会被误伤，默认关闭)。
	SkipBareHost bool
}

var (
	defaultPolicyOnce sync.Once
	defaultPolicy     Policy
)

// DefaultPolicy 读取环境变量（默认全部开启）。
// ARTEX_SCREEN_SKIP_SENSITIVE / ARTEX_SCREEN_SKIP_PLATFORM 置 0/false 可关闭对应预筛。
func DefaultPolicy() Policy {
	defaultPolicyOnce.Do(func() {
		defaultPolicy = Policy{
			SkipSensitive:        envBool("ARTEX_SCREEN_SKIP_SENSITIVE", true),
			SkipPlatformDefaults: envBool("ARTEX_SCREEN_SKIP_PLATFORM", true),
			SkipBareHost:         envBool("ARTEX_SCREEN_SKIP_BARE_HOST", false),
		}
	})
	return defaultPolicy
}

func envBool(key string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "":
		return def
	case "1", "true", "yes", "on", "y":
		return true
	case "0", "false", "no", "off", "n":
		return false
	default:
		return def
	}
}

// Disabled 报告是否通过环境变量 ARTEX_SCREEN_DISABLE 全局关闭预筛(评分/聚类不受影响)。
func Disabled() bool { return envBool("ARTEX_SCREEN_DISABLE", false) }

// Evaluate 使用默认策略给出综合判定。
func Evaluate(in Input) Decision { return EvaluateWithPolicy(in, DefaultPolicy()) }

// EvaluateWithPolicy 组合预筛、评分与聚类。
func EvaluateWithPolicy(in Input, p Policy) Decision {
	d := Decision{}
	if reason := PrefilterWithPolicy(in, p); reason != "" {
		d.Skip = true
		d.SkipReason = reason
		return d
	}
	d.Score, d.ScoreReasons = Score(in)
	d.Cluster = ClusterKey(in)
	return d
}

// Prefilter 使用默认策略返回跳过原因，空字符串表示保留。
func Prefilter(in Input) string { return PrefilterWithPolicy(in, DefaultPolicy()) }

// PrefilterWithPolicy 机械预筛：命中即返回非空原因。
func PrefilterWithPolicy(in Input, p Policy) string {
	host := normalizeHost(hostOf(in))
	if isLoopbackOrUnspecified(host) {
		return "loopback_or_unspecified"
	}
	if p.SkipSensitive && isSensitiveHost(host) {
		return "sensitive_domain"
	}
	if p.SkipPlatformDefaults && isPlatformDefaultHost(host) {
		return "platform_default_domain"
	}
	if p.SkipBareHost && host != "" && !strings.Contains(host, ".") && net.ParseIP(host) == nil {
		return "no_registrable_domain"
	}
	return ""
}

type scoreRule struct {
	delta  float64
	reason string
	keys   []string
}

var positiveRules = []scoreRule{
	{3, "admin_backend", []string{"admin", "administrator", "后台", "管理", "登录", "login", "signin", "sign-in", "console", "dashboard", "portal", "cms", "运维", "控制台"}},
	{3, "data_interactive", []string{"search", "查询", "上传", "upload", "接口", "留言", "评论", "form", "submit", "editor", "编辑"}},
	{2, "api_gateway", []string{"/api", "swagger", "graphql", "actuator", "openapi", "rest", "api."}},
	{2, "wechat_platform", []string{"微信", "wechat", "公众号", "小程序", "企业微信", "wecom"}},
	{2, "cloud_storage", []string{"bucket", "oss", "cos.", "s3", "storage", "存储", "网盘"}},
	{1, "edu_industry", []string{"edu", "school", "教育", "学校", "医院", "hospital", "学院", "大学", "政务"}},
}

var negativeRules = []scoreRule{
	{-4, "auth_gateway", []string{"sso", "oauth", "cas.", "idp", "统一认证", "单点登录", "login.microsoftonline", "auth0", "okta"}},
	{-2, "placeholder_page", []string{"建设中", "默认页", "welcome to nginx", "apache2 default", "iis windows server", "index of /", "域名已过期", "未备案", "coming soon", "it works!"}},
	{-2, "cdn_edge", []string{"cloudflare", "cdn", "akamai", "fastly", "加速", "incapsula", "edgecast"}},
}

// Score 返回优先级评分与理由。只降权不禁止，负分资产仍会被测试，只是排序靠后。
func Score(in Input) (float64, []string) {
	blob := strings.ToLower(strings.Join([]string{
		in.Title, in.ServerHeader, strings.Join(in.Technologies, " "), in.URL, in.Host, in.IP,
	}, " "))

	var score float64
	var reasons []string
	add := func(delta float64, reason string) {
		score += delta
		reasons = append(reasons, reason)
	}

	for _, r := range positiveRules {
		for _, k := range r.keys {
			if strings.Contains(blob, k) {
				add(r.delta, r.reason)
				break
			}
		}
	}
	for _, r := range negativeRules {
		for _, k := range r.keys {
			if strings.Contains(blob, k) {
				add(r.delta, r.reason)
				break
			}
		}
	}
	if in.Port != 0 && in.Port != 80 && in.Port != 443 {
		add(1, "nonstandard_port")
	}
	return score, reasons
}

// ClusterKey 生成同款系统聚类键：根域 + 产品名。取不到产品名时退化为根域。
func ClusterKey(in Input) string {
	root := registrableFallback(normalizeHost(hostOf(in)))
	if product := ProductKey(in.Title); product != "" {
		return root + "|" + product
	}
	return root
}

// ProductKey 从标题中提取产品名前缀，用于把同一套系统的多个域名聚成一簇。
func ProductKey(title string) string {
	t := strings.TrimSpace(title)
	if t == "" {
		return ""
	}
	cut := func(r rune) bool {
		switch r {
		case '-', '—', '–', '－', ':', '：', '_', '|', '丨', '【', '】', '[', ']', '(', ')', '（', '）', '/', '\\', ',', '，':
			return true
		}
		return false
	}
	first := t
	if idx := strings.IndexFunc(t, cut); idx > 0 {
		first = t[:idx]
	}
	fields := strings.Fields(first)
	if len(fields) == 0 {
		return ""
	}
	norm := normalizeText(fields[0])
	if utf8.RuneCountInString(norm) < 6 {
		return ""
	}
	return norm
}

var sensitiveSuffixes = []string{".gov", ".gov.cn", ".mil", ".mil.cn", ".army", ".police"}

var sensitiveKeywords = []string{
	"gov", "government", "police", "army", "military", "mil",
	"公安", "军队", "部队", "涉密", "保密", "国防", "武警", "检察院", "法院", "政务内网",
}

func isSensitiveHost(host string) bool {
	if host == "" {
		return false
	}
	for _, s := range sensitiveSuffixes {
		if strings.HasSuffix(host, s) {
			return true
		}
	}
	for _, kw := range sensitiveKeywords {
		if strings.Contains(host, kw) {
			return true
		}
	}
	return false
}

var platformDefaultSuffixes = []string{
	"github.io", "gitlab.io", "gitee.io", "vercel.app", "netlify.app",
	"pages.dev", "herokuapp.com", "herokudns.com", "azurewebsites.net",
	"cloudfront.net", "amazonaws.com", "aliyuncs.com", "myqcloud.com",
	"bcebos.com", "qiniucdn.com", "qiniudns.com", "clouddn.com",
	"wordpress.com", "blogspot.com", "tumblr.com", "wixsite.com",
	"zendesk.com", "statuspage.io", "readthedocs.io", "surge.sh",
	"firebaseapp.com", "web.app", "trafficmanager.net", "chinacloudapp.cn",
}

func isPlatformDefaultHost(host string) bool {
	if host == "" {
		return false
	}
	// 用户自建 bucket / 存储桶仍可能有配置类漏洞，放行。
	if strings.Contains(host, "oss-") || strings.Contains(host, "cos.") || strings.Contains(host, "bucket") {
		return false
	}
	for _, s := range platformDefaultSuffixes {
		if strings.HasSuffix(host, s) {
			return true
		}
	}
	return false
}

func isLoopbackOrUnspecified(host string) bool {
	if host == "" {
		return true
	}
	switch host {
	case "localhost", "localhost.localdomain", "ip6-localhost", "unspecified":
		return true
	}
	if strings.HasPrefix(host, "127.") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsUnspecified() {
			return true
		}
	}
	return false
}

func hostOf(in Input) string {
	if strings.TrimSpace(in.URL) != "" {
		if u, err := url.Parse(strings.TrimSpace(in.URL)); err == nil && u.Host != "" {
			return u.Host
		}
	}
	if strings.TrimSpace(in.Host) != "" {
		return in.Host
	}
	return in.IP
}

func normalizeHost(h string) string {
	h = strings.TrimSpace(strings.ToLower(h))
	if h == "" {
		return ""
	}
	if strings.Contains(h, "://") {
		if u, err := url.Parse(h); err == nil && u.Host != "" {
			h = u.Host
		}
	}
	h = strings.Trim(h, "[]")
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.Trim(h, "[]")
	return strings.TrimSuffix(strings.TrimSpace(h), ".")
}

func normalizeText(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r >= 0x4e00 && r <= 0x9fff:
			b.WriteRune(r)
		default:
			b.WriteRune(' ')
		}
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

var secondLevelSuffixes = map[string]bool{
	"com.cn": true, "net.cn": true, "org.cn": true, "gov.cn": true,
	"edu.cn": true, "ac.cn": true, "mil.cn": true,
	"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true,
	"com.hk": true, "com.tw": true, "com.au": true, "co.jp": true,
	"com.sg": true, "com.my": true, "co.kr": true, "com.br": true,
}

// registrableFallback 近似取可注册根域，处理 com.cn / edu.cn 等二级后缀。
func registrableFallback(host string) string {
	if host == "" {
		return ""
	}
	if ip := net.ParseIP(host); ip != nil {
		return host
	}
	labels := strings.Split(host, ".")
	n := len(labels)
	if n <= 2 {
		return host
	}
	lastTwo := labels[n-2] + "." + labels[n-1]
	if secondLevelSuffixes[lastTwo] && n >= 3 {
		return labels[n-3] + "." + lastTwo
	}
	return lastTwo
}

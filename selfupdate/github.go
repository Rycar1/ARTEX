package selfupdate

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"
)

// Repo 是发布源。**故意不做成运行时配置**：更新源可配等于给任何能改配置的人一条
// 远程代码执行通道(把源指到自己的仓库 → 平台下载并执行对方二进制)，对一个渗透
// 测试平台来说这个口子开不得。
//
// 默认指向本二开仓库(Rycar1/ARTEX)。若你的部署用别的发布源，可在**构建期**覆盖：
//
//	go build -ldflags "-X github.com/Autumn-27/artex/selfupdate.Repo=owner/repo"
//
// 构建者本来就能决定这个二进制跑什么代码，因此这不扩大信任边界；而运行时改配置
// 做不到，RCE 通道仍然是关闭的。
var Repo = "Rycar1/ARTEX"

// latestURL 是 GitHub 的"最新正式版"接口。它会自动跳过 prerelease 和 draft。
// 用函数而不是 const:Repo 现在可在构建期被 -X 覆盖。
func latestURL() string {
	return "https://api.github.com/repos/" + Repo + "/releases/latest"
}

// allowedHosts 限定升级链路能访问的域名。配合下面的 checkRedirect，
// 任何一跳被重定向到名单外的主机都会直接失败——这是防止 DNS 污染 / 中间人
// 把二进制换掉的第一道闸门，第二道是 SHA256SUMS 比对。
var allowedHosts = map[string]bool{
	"api.github.com":                       true,
	"github.com":                           true,
	"objects.githubusercontent.com":        true, // release 资产实际落地的对象存储
	"release-assets.githubusercontent.com": true,
	"raw.githubusercontent.com":            true,
}

// Release 是 GitHub Release 里我们关心的字段。
type Release struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	Body        string    `json:"body"`
	Draft       bool      `json:"draft"`
	Prerelease  bool      `json:"prerelease"`
	PublishedAt time.Time `json:"published_at"`
	HTMLURL     string    `json:"html_url"`
	Assets      []Asset   `json:"assets"`
}

// Asset 是 Release 上挂的一个文件。
type Asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

// NewClient 构造一个只认 GitHub 域名的 HTTP 客户端。proxy 为空则直连。
//
// 刻意不复用默认 Transport：升级链路必须强制走 TLS 且校验证书，不能被别处
// 设置的 InsecureSkipVerify 之类影响到。
func NewClient(proxy string) *http.Client {
	tr := &http.Transport{
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 15 * time.Second,
	}
	if p := strings.TrimSpace(proxy); p != "" {
		if pu, err := url.Parse(p); err == nil {
			tr.Proxy = http.ProxyURL(pu)
		}
	}
	return &http.Client{
		Transport: tr,
		Timeout:   30 * time.Minute, // 下载整包，不能按请求级超时卡死
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("重定向次数过多")
			}
			return checkURL(req.URL)
		},
	}
}

// checkURL 强制 https + 域名白名单。
func checkURL(u *url.URL) error {
	if u.Scheme != "https" {
		return fmt.Errorf("拒绝非 HTTPS 地址: %s", u.Scheme+"://"+u.Host)
	}
	if !allowedHosts[strings.ToLower(u.Hostname())] {
		return fmt.Errorf("拒绝非 GitHub 域名: %s", u.Hostname())
	}
	return nil
}

// repoExists 探测发布源仓库本身是否存在(用于把 /releases/latest 的 404 区分成
// 「仓库没有 Release」和「仓库根本不存在」)。任何异常都按"存在"处理:此时更可能是
// 网络/限流问题,不该误导用户去改构建参数。
func repoExists(ctx context.Context, c *http.Client) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/"+Repo, nil)
	if err != nil {
		return true
	}
	if err := checkURL(req.URL); err != nil {
		return true
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "artex-selfupdate")
	resp, err := c.Do(req)
	if err != nil {
		return true
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// FetchLatest 查询最新正式版。
func FetchLatest(ctx context.Context, c *http.Client) (*Release, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, latestURL(), nil)
	if err != nil {
		return nil, err
	}
	if err := checkURL(req.URL); err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "artex-selfupdate")

	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("访问 GitHub 失败（可在系统设置里配置全局代理）: %w", err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusForbidden, resp.StatusCode == http.StatusTooManyRequests:
		// 未认证的 GitHub API 是每 IP 每小时 60 次，共用出口 IP 时很容易撞上。
		return nil, fmt.Errorf("GitHub 接口限流（每小时 60 次），请稍后再试")
	case resp.StatusCode == http.StatusNotFound:
		// 404 有两种原因:仓库存在但还没发过正式 Release,或发布源指向了不存在的仓库。
		// 多打一次 /repos/{repo} 区分开,给出可执行的下一步,而不是让用户对着
		// "尚未发布版本"猜(本仓库默认指向二开源,首次使用时几乎必然是这个状态)。
		if repoExists(ctx, c) {
			return nil, fmt.Errorf("仓库 %s 存在但还没有发布正式版(Release);"+
				"请在 GitHub 上发布一个 Release,并附上 %s 与 %s",
				Repo, AssetName("vX.Y.Z", runtime.GOOS, runtime.GOARCH), sumsAsset)
		}
		return nil, fmt.Errorf("发布源仓库 %s 不存在;发布源是构建期固定的,"+
			"如需指向别的仓库请用 -X .../selfupdate.Repo=owner/repo 重新构建", Repo)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("GitHub 返回 %d", resp.StatusCode)
	}

	var rel Release
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("解析 Release 失败: %w", err)
	}
	if strings.TrimSpace(rel.TagName) == "" {
		return nil, fmt.Errorf("Release 缺少 tag")
	}
	return &rel, nil
}

// AssetName 返回当前平台对应的发布包名，与 build.sh 的 package_binary 保持一致：
// artex-<版本>-<os>-<arch>.zip（版本号不带 v 前缀）。
func AssetName(tag, goos, goarch string) string {
	return fmt.Sprintf("artex-%s-%s-%s.zip", strings.TrimPrefix(tag, "v"), goos, goarch)
}

// FindAsset 在 Release 里按名字找资产。
func (r *Release) FindAsset(name string) (Asset, bool) {
	for _, a := range r.Assets {
		if strings.EqualFold(a.Name, name) {
			return a, true
		}
	}
	return Asset{}, false
}

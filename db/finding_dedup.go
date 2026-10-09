package db

import (
	"crypto/sha1"
	"encoding/hex"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// 漏洞去重(四层方案)公共件:结构化合并键、文本指纹、文本相似度。
//
// 三个纯函数,不碰数据库,便于单测:
//   - FindingDedupKey    写入时的结构化合并键(归一化类别 + 主资产 / 文本弱锚)
//   - FindingFingerprint 归一化正文的 SHA-1(等值快判 + 近似候选预筛)
//   - FindingSimilarity  归一化正文的 bigram Dice 相似度(0~1,1 = 完全一致)
//
// 归一化刻意比 agent/stuck.go 保守:只抹时间戳、长 hex、长随机串、数字与空白,
// 不抹 URL 路径 —— 对漏洞而言路径是最强的身份信号,抹掉会把「同一站点两个不同
// 接口的同一个洞」误判成重复。
// ---------------------------------------------------------------------------

// FindingDedupCrossTask 控制「跨任务自动合并」(默认关)。
//
// 同任务内自动合并是安全的:合并目标与原上报同属一个任务,任务发现页照常可见。
// 跨任务静默合并会让漏洞从原任务的发现页消失(任务发现页按 task_id 归属),风险
// 高于收益,所以默认只跨任务标记 suspected_dup_of「疑似重复」,由人工或二次审核
// 裁决。置 ARTEX_FINDING_DEDUP_CROSS_TASK=1 打开跨任务自动合并。
var FindingDedupCrossTask = os.Getenv("ARTEX_FINDING_DEDUP_CROSS_TASK") == "1"

// FindingDupSimilarityThreshold 是判定「疑似重复」的 bigram Dice 阈值。0.82 是
// 实测取值:同一漏洞换措辞重述一般在 0.85 以上,不同接口的同类漏洞通常在 0.7 以下。
const FindingDupSimilarityThreshold = 0.82

// findingDupCandidateLimit 是单次相似度扫描最多比对的候选行数(按新到旧)。
const findingDupCandidateLimit = 50

var (
	dedupReURL       = regexp.MustCompile(`(?i)https?://([^\s/?#"'<>()\[\]]+)`)
	dedupReIP        = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
	dedupReTimestamp = regexp.MustCompile(`\d{4}[-/]\d{1,2}[-/]\d{1,2}([t ]\d{1,2}:\d{2}(:\d{2})?(\.\d+)?(z|[+-]\d{2}:?\d{2})?)?|\d{1,2}:\d{2}:\d{2}(\.\d+)?`)
	dedupReHex       = regexp.MustCompile(`\b[0-9a-f]{8,}\b`)
	dedupReRand      = regexp.MustCompile(`\b[\w+-]{24,}\b`)
	dedupReDigits    = regexp.MustCompile(`\d+`)
	dedupReSpace     = regexp.MustCompile(`\s+`)
)

// FindingComparableText 是相似度/指纹比较用的正文(类别 + 名称 + 摘要 + 证据)。
func FindingComparableText(vulnclass, name, summary, evidence string) string {
	return strings.Join([]string{vulnclass, name, summary, evidence}, "\n")
}

// FindingDedupKey 计算写入时的结构化合并键:
//
//	归一化类别 + "|a" + 主资产 id      (asset_ids 非空)
//	归一化类别 + "|h" + 文本里的 host  (asset_ids 为空但正文含 URL/IP)
//	""                                (既无主资产也无弱锚 —— 不参与自动合并)
//
// 弱锚只认带 scheme 的 URL 的 host 或裸 IPv4:正文里的裸域名/文件名太容易误认,
// 拿来当合并键会把两个不相干的洞并到一起。两条键的前缀不同,不会互相碰撞。
func FindingDedupKey(vulnclass string, assetIDs []int64, text string) string {
	class := NormalizeVulnClass(vulnclass)
	if class == "" {
		return ""
	}
	if len(assetIDs) > 0 {
		return class + "|a" + strconv.FormatInt(assetIDs[0], 10)
	}
	if h := findingAnchorHost(text); h != "" {
		return class + "|h" + h
	}
	return ""
}

// findingAnchorHost 从正文里抽第一个 URL 的 host(或裸 IPv4)作为弱锚。
func findingAnchorHost(text string) string {
	if m := dedupReURL.FindStringSubmatch(text); m != nil {
		if h := normalizeHostToken(m[1]); h != "" {
			return h
		}
	}
	return dedupReIP.FindString(text)
}

// normalizeHostToken 去掉 userinfo / 端口 / 首尾点,统一小写。
func normalizeHostToken(raw string) string {
	h := strings.ToLower(strings.TrimSpace(raw))
	if i := strings.IndexByte(h, '@'); i >= 0 {
		h = h[i+1:]
	}
	if i := strings.IndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	return strings.Trim(h, ".")
}

// NormalizeFindingText 归一化正文:小写 → 抹时间戳 → 抹长 hex → 抹长随机串 →
// 抹数字 → 折叠空白。顺序敏感:先抹长串再抹数字,避免把 hex 拆成一堆短数字。
func NormalizeFindingText(s string) string {
	s = strings.ToLower(s)
	s = dedupReTimestamp.ReplaceAllString(s, " ")
	s = dedupReHex.ReplaceAllString(s, " ")
	s = dedupReRand.ReplaceAllString(s, " ")
	s = dedupReDigits.ReplaceAllString(s, " ")
	s = dedupReSpace.ReplaceAllString(s, " ")
	return strings.TrimSpace(s)
}

// FindingFingerprint 是归一化正文的 SHA-1(hex);全空返回 ""。
func FindingFingerprint(vulnclass, name, summary, evidence string) string {
	norm := NormalizeFindingText(FindingComparableText(vulnclass, name, summary, evidence))
	if norm == "" {
		return ""
	}
	sum := sha1.Sum([]byte(norm))
	return hex.EncodeToString(sum[:])
}

// FindingSimilarity 返回两段正文的归一化 bigram Dice 相似度(0~1)。
func FindingSimilarity(a, b string) float64 {
	return bigramDice(NormalizeFindingText(a), NormalizeFindingText(b))
}

// bigramDice 是多重集 bigram Dice 系数:2*|交集| / (|A|+|B|),按 rune 切双字。
// 空串/单字符返回 0(没有可比的双字)。
func bigramDice(a, b string) float64 {
	if a == "" || b == "" {
		return 0
	}
	if a == b {
		return 1
	}
	ga, gb := bigramCounts(a), bigramCounts(b)
	if len(ga) == 0 || len(gb) == 0 {
		return 0
	}
	inter, total := 0, 0
	for g, c := range ga {
		total += c
		if d, ok := gb[g]; ok {
			if d < c {
				inter += d
			} else {
				inter += c
			}
		}
	}
	for _, c := range gb {
		total += c
	}
	if total == 0 {
		return 0
	}
	return 2 * float64(inter) / float64(total)
}

func bigramCounts(s string) map[string]int {
	r := []rune(s)
	if len(r) < 2 {
		return nil
	}
	out := make(map[string]int, len(r))
	for i := 0; i+1 < len(r); i++ {
		out[string(r[i:i+2])]++
	}
	return out
}
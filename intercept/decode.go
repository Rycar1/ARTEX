package intercept

import (
	"encoding/base64"
	"encoding/hex"
	"html"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// DecodedVariant is one canonicalized view of a tool-call input produced by the
// encoding/obfuscation decoders. Kind records the transform chain that produced
// it ("hex", "url", "base64", "unicode_escape", ...) so the judge, the audit
// trail and the operator can see where the readable content came from.
type DecodedVariant struct {
	Kind string `json:"kind"`
	Text string `json:"text"`
}

const (
	decodeMaxDepth     = 3
	decodeMaxInput     = 64 * 1024
	decodeMaxVariants  = 24
	decodeMaxVariant   = 8 * 1024
	decodeMaxPerStep   = 6
	decodeReviewLimit  = 8
	decodeReviewMaxLen = 2048
)

// Signature patterns. The *Run/*Token patterns find an embedded encoded token;
// the *Gate patterns are the stricter subset that may trigger the fail-closed
// "undecodable payload" ask (see LooksEncoded). Go's regexp (RE2) has no
// lookaround, so the gates are deliberately conservative rather than exact.
var (
	rePercentRun = regexp.MustCompile(`(?:%[0-9A-Fa-f]{2}){2,}`)
	reUnicodeRun = regexp.MustCompile(`(?:\\u[0-9A-Fa-f]{4}){2,}`)
	reHexEscRun  = regexp.MustCompile(`(?:\\x[0-9A-Fa-f]{2}){2,}`)
	reOctalRun   = regexp.MustCompile(`(?:\\[0-7]{3}){2,}`)
	reHTMLEntRun = regexp.MustCompile(`(?:&#x?[0-9A-Fa-f]{2,6};|&[a-zA-Z]{2,8};){2,}`)

	reHexToken = regexp.MustCompile(`(?i)(?:0x)?[0-9a-f]{8,}`)
	reB64Token = regexp.MustCompile(`[A-Za-z0-9+/_-]{16,}={0,2}`)

	reHexGate = regexp.MustCompile(`(?i)(?:0x)?[0-9a-f]{24,}`)
	reB64Gate = regexp.MustCompile(`[A-Za-z0-9+/]{24,}={0,2}`)

	reUniOne    = regexp.MustCompile(`\\u([0-9A-Fa-f]{4})`)
	reHexEscOne = regexp.MustCompile(`\\x([0-9A-Fa-f]{2})`)
	reOctalOne  = regexp.MustCompile(`\\([0-7]{3})`)

	reDangerWord = regexp.MustCompile(`(?i)\b(rm|drop|delete|truncate|shutdown|reboot|halt|poweroff|mkfs|dd|chmod|chown|chattr|format|del|erase|remove|unlink|kill|pkill|iptables|nft|flushall|purge|destroy|wipe|truncate)\b`)
)

// DecodeVariants returns up to decodeMaxVariants canonicalized views of raw,
// applying every supported decoder (whole-string and embedded-token) recursively
// up to depth levels. The raw input itself is not included; results are unique.
// It returns nil for empty or oversized input.
func DecodeVariants(raw string, depth int) []DecodedVariant {
	if depth <= 0 || depth > decodeMaxDepth {
		depth = decodeMaxDepth
	}
	if raw == "" || len(raw) > decodeMaxInput {
		return nil
	}
	seen := map[string]bool{raw: true}
	var out []DecodedVariant
	frontier := []string{raw}
	for d := 0; d < depth && len(out) < decodeMaxVariants; d++ {
		var next []string
		for _, s := range frontier {
			for _, v := range oneStep(s) {
				if v.Text == "" || len(v.Text) > decodeMaxVariant || seen[v.Text] {
					continue
				}
				seen[v.Text] = true
				out = append(out, v)
				next = append(next, v.Text)
				if len(out) >= decodeMaxVariants {
					break
				}
			}
			if len(out) >= decodeMaxVariants {
				break
			}
		}
		if len(next) == 0 {
			break
		}
		frontier = next
	}
	return out
}

// oneStep applies every decoder once, to the whole string and to each embedded
// encoded token, returning the distinct results that differ from the input.
func oneStep(s string) []DecodedVariant {
	var out []DecodedVariant
	add := func(kind, text string) {
		if text == "" || text == s || len(text) > decodeMaxVariant {
			return
		}
		out = append(out, DecodedVariant{Kind: kind, Text: text})
	}
	if d, ok := decodeBackslashEscapes(s); ok {
		add("backslash_escape", d)
	}
	if d, ok := decodeBase64String(s); ok {
		add("base64", d)
	}
	if d, ok := decodeHexString(s); ok {
		add("hex", d)
	}
	if d, ok := decodePercentString(s); ok {
		add("url", d)
	}
	if d, ok := htmlDecode(s); ok {
		add("html", d)
	}
	if d, ok := decodeUnicodeEscapes(s); ok {
		add("unicode_escape", d)
	}
	if d, ok := decodeHexEscapes(s); ok {
		add("hex_escape", d)
	}
	if d, ok := decodeOctalEscapes(s); ok {
		add("octal_escape", d)
	}
	if d := reverseString(s); d != s && reDangerWord.MatchString(d) {
		add("rev", d)
	}

	out = append(out, substTokens(s, rePercentRun, "url", decodePercentString)...)
	out = append(out, substTokens(s, reUnicodeRun, "unicode_escape", decodeUnicodeEscapes)...)
	out = append(out, substTokens(s, reHexEscRun, "hex_escape", decodeHexEscapes)...)
	out = append(out, substTokens(s, reOctalRun, "octal_escape", decodeOctalEscapes)...)
	out = append(out, substTokens(s, reHTMLEntRun, "html", htmlDecode)...)
	out = append(out, substTokens(s, reB64Token, "base64", decodeBase64String)...)
	out = append(out, substTokens(s, reHexToken, "hex", decodeHexString)...)
	return out
}

// substTokens rewrites up to decodeMaxPerStep embedded tokens in s to their
// decoded form, one variant per token.
func substTokens(s string, re *regexp.Regexp, kind string, fn func(string) (string, bool)) []DecodedVariant {
	locs := re.FindAllStringIndex(s, -1)
	if len(locs) == 0 {
		return nil
	}
	var out []DecodedVariant
	for _, loc := range locs {
		tok := s[loc[0]:loc[1]]
		dec, ok := fn(tok)
		if !ok || dec == "" || dec == tok {
			continue
		}
		text := s[:loc[0]] + dec + s[loc[1]:]
		if len(text) > decodeMaxVariant {
			continue
		}
		out = append(out, DecodedVariant{Kind: kind, Text: text})
		if len(out) >= decodeMaxPerStep {
			break
		}
	}
	return out
}

// LooksEncoded reports whether raw contains a strong encoding/obfuscation
// signature (an encoded token whose plaintext we should be able to recover).
// It is intentionally conservative: only clear signatures may force a
// fail-closed ask when decoding fails.
func LooksEncoded(raw string) bool {
	cands := []string{raw}
	if strings.Contains(raw, `\\`) {
		cands = append(cands, strings.ReplaceAll(raw, `\\`, `\`))
	}
	for _, s := range cands {
		if rePercentRun.MatchString(s) || reUnicodeRun.MatchString(s) ||
			reHexEscRun.MatchString(s) || reOctalRun.MatchString(s) ||
			reHTMLEntRun.MatchString(s) {
			return true
		}
		for _, m := range reHexGate.FindAllString(s, -1) {
			h := strings.TrimPrefix(strings.TrimPrefix(m, "0x"), "0X")
			if len(h) >= 24 && len(h)%2 == 0 {
				return true
			}
		}
		for _, loc := range reB64Gate.FindAllStringIndex(s, -1) {
			m := s[loc[0]:loc[1]]
			if !plausibleB64Blob(m) || !standaloneB64Token(s, loc[0]) {
				continue
			}
			if strings.ContainsAny(m, "+/=") || len(m) >= 32 {
				return true
			}
		}
	}
	return false
}

// plausibleB64Blob filters out tokens that only match the base64 charset but are
// actually filesystem paths (or other non-encoded strings). The fail-closed ask is
// reserved for strong signatures, so a candidate must look like real base64 output:
// mixed case plus digits, and not a path-like token (leading "/", "~" or ".").
func plausibleB64Blob(m string) bool {
	if m == "" {
		return false
	}
	switch m[0] {
	case '/', '~', '.':
		return false
	}
	var upper, lower, digit bool
	for _, r := range m {
		switch {
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= '0' && r <= '9':
			digit = true
		}
	}
	return upper && lower && digit
}

// standaloneB64Token reports whether the base64-charset match that starts at
// index start in s begins a whole shell token rather than a fragment of a
// larger URL or filesystem path. URL path segments such as
// ".../v1/basic.account.account_web.Account/GetAidListByUidV2" match the base64
// charset but are not encoded payloads, so a match preceded by a path or URL
// separator must not trigger the fail-closed ask.
func standaloneB64Token(s string, start int) bool {
	if start <= 0 {
		return true
	}
	switch s[start-1] {
	case '/', '.', '~', ':', '\\':
		return false
	}
	return true
}

// hasReadableDecode reports whether any variant recovered readable text. The
// "rev" variant is excluded: a reversed string is always printable, so it must
// not satisfy the decode check that gates the fail-closed ask.
func hasReadableDecode(vs []DecodedVariant) bool {
	for _, v := range vs {
		if v.Kind == "rev" {
			continue
		}
		if readableText(v.Text) {
			return true
		}
	}
	return false
}

// UndecodableEncodedPayload reports whether raw carries a strong encoding
// signature whose plaintext no decoder can recover. Callers use it as a
// fail-closed fallback ONLY when no LLM judge is available: the normal path
// routes such calls to the judge, which decides allow/ask/deny itself.
func UndecodableEncodedPayload(raw string) bool {
	if len(raw) > decodeMaxInput || !LooksEncoded(raw) {
		return false
	}
	return !hasReadableDecode(DecodeVariants(raw, decodeMaxDepth))
}

// ObfuscationUndecodableHint 是「参数含编码特征但无法还原」时给人工的提示。
// 仅在没有任何 LLM 裁判可用时兜底使用(正常路径由裁判自行判定)。
const ObfuscationUndecodableHint = "检测到参数中存在编码/变换后的载荷(base64/hex/URL/HTML/转义等特征),但平台解码后仍无法还原出可读内容(疑似加密、压缩或自定义编码)。" +
	"无法判读真实执行内容时按 fail-closed 转人工。请让 worker 以可读的明文形式重发命令,或说明该编码载荷的真实内容与用途。"

// SelectVariantsForReview returns the variants worth sending to the judge,
// preferring recoverable encodings over the low-confidence "rev" transform.
func SelectVariantsForReview(vs []DecodedVariant) []DecodedVariant {
	if len(vs) == 0 {
		return nil
	}
	out := make([]DecodedVariant, 0, decodeReviewLimit)
	for _, v := range vs {
		if v.Kind == "rev" {
			continue
		}
		if !readableText(v.Text) {
			continue
		}
		t := v.Text
		if len(t) > decodeReviewMaxLen {
			t = t[:decodeReviewMaxLen]
		}
		out = append(out, DecodedVariant{Kind: v.Kind, Text: t})
		if len(out) >= decodeReviewLimit {
			break
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func readableText(s string) bool {
	if s == "" || !utf8.ValidString(s) {
		return false
	}
	printable, total := 0, 0
	for _, r := range s {
		total++
		if r == '\n' || r == '\t' || r == '\r' || unicode.IsPrint(r) {
			printable++
		}
	}
	return total > 0 && float64(printable)/float64(total) >= 0.9
}

func isB64Charset(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '+', r == '/', r == '=', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

func isHexDigit(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
}

func decodeBase64String(s string) (string, bool) {
	t := strings.TrimSpace(s)
	if len(t) < 8 || len(t)%4 == 1 || !isB64Charset(t) {
		return "", false
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		b, err := enc.DecodeString(t)
		if err != nil || len(b) == 0 {
			continue
		}
		if out := string(b); readableText(out) {
			return out, true
		}
	}
	return "", false
}

func decodeHexString(s string) (string, bool) {
	t := strings.TrimSpace(s)
	t = strings.TrimPrefix(strings.TrimPrefix(t, "0x"), "0X")
	if len(t) < 8 || len(t)%2 != 0 {
		return "", false
	}
	for _, r := range t {
		if !isHexDigit(r) {
			return "", false
		}
	}
	b, err := hex.DecodeString(t)
	if err != nil || len(b) == 0 {
		return "", false
	}
	if out := string(b); readableText(out) {
		return out, true
	}
	return "", false
}

func decodePercentString(s string) (string, bool) {
	if !strings.Contains(s, "%") {
		return "", false
	}
	var b strings.Builder
	b.Grow(len(s))
	changed := false
	for i := 0; i < len(s); {
		if s[i] == '%' && i+2 < len(s) && isHexDigit(rune(s[i+1])) && isHexDigit(rune(s[i+2])) {
			v, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
			if err == nil {
				b.WriteByte(byte(v))
				i += 3
				changed = true
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	if !changed {
		return "", false
	}
	out := b.String()
	if !utf8.ValidString(out) {
		return "", false
	}
	return out, true
}

// decodeBackslashEscapes collapses C/JSON-style doubled backslashes so an escape
// sequence embedded in a JSON tool argument (for example "\u0072") becomes the
// single-backslash form ("\u0072") that the escape decoders understand. Only the
// escapes it recognises are rewritten; octal and hex escapes are left untouched.
func decodeBackslashEscapes(s string) (string, bool) {
	if !strings.Contains(s, `\\`) {
		return "", false
	}
	var b strings.Builder
	b.Grow(len(s))
	changed := false
	for i := 0; i < len(s); {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case '\\', '"', '\'', '/':
				b.WriteByte(s[i+1])
				i += 2
				changed = true
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	if !changed {
		return "", false
	}
	out := b.String()
	if !utf8.ValidString(out) {
		return "", false
	}
	return out, true
}

// jsonUnescapeView rewrites the JSON string escapes that the tool_input JSON
// envelope puts around the command text (\n \" \\ \t \r \b \f \/ \uXXXX) into the
// characters they denote — the "logical text" a rule author reads when looking at
// a command.
//
// Rules are written against that text, but Match() feeds them the raw JSON wire
// form, where two things silently break:
//
//   - a preceding \n escape ends in the word character "n", so a `\b` anchor can
//     never fire: `\brequests\.delete\(` misses
//     {"content":"import requests\nrequests.delete(...)"} entirely;
//   - a following \" is a backslash, not a quote, so separator classes miss:
//     rule 20's `[/?#"'\s]` never sees the `"` after `"$B/command/delete"`.
//
// Both were measured on live traffic: 6 of 16 real destructive calls had no rule
// coverage at all against the JSON view, versus 2 of 16 against this view.
func jsonUnescapeView(raw string) (string, bool) {
	if !strings.Contains(raw, `\`) {
		return "", false
	}
	var b strings.Builder
	b.Grow(len(raw))
	changed := false
	for i := 0; i < len(raw); {
		if raw[i] != '\\' || i+1 >= len(raw) {
			b.WriteByte(raw[i])
			i++
			continue
		}
		switch raw[i+1] {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case 'b':
			b.WriteByte('\b')
		case 'f':
			b.WriteByte('\f')
		case '"', '\\', '/':
			b.WriteByte(raw[i+1])
		case 'u':
			// \uXXXX: skip surrogate halves (a lone \uD800 is not a valid rune).
			if i+5 < len(raw) {
				if v, err := strconv.ParseUint(raw[i+2:i+6], 16, 32); err == nil && !(v >= 0xD800 && v <= 0xDFFF) {
					b.WriteRune(rune(v))
					i += 6
					changed = true
					continue
				}
			}
			b.WriteByte(raw[i])
			i++
			continue
		default:
			b.WriteByte(raw[i])
			i++
			continue
		}
		i += 2
		changed = true
	}
	if !changed {
		return "", false
	}
	out := b.String()
	if !utf8.ValidString(out) {
		return "", false
	}
	return out, true
}

func decodeUnicodeEscapes(s string) (string, bool) {
	if !strings.Contains(s, `\u`) {
		return "", false
	}
	out := reUniOne.ReplaceAllStringFunc(s, func(m string) string {
		v, err := strconv.ParseUint(m[2:], 16, 32)
		if err != nil || (v >= 0xD800 && v <= 0xDFFF) {
			return m
		}
		return string(rune(v))
	})
	if out == s || !utf8.ValidString(out) {
		return "", false
	}
	return out, true
}

func decodeHexEscapes(s string) (string, bool) {
	if !strings.Contains(s, `\x`) {
		return "", false
	}
	out := reHexEscOne.ReplaceAllStringFunc(s, func(m string) string {
		v, err := strconv.ParseUint(m[2:], 16, 8)
		if err != nil {
			return m
		}
		return string([]byte{byte(v)})
	})
	if out == s || !utf8.ValidString(out) {
		return "", false
	}
	return out, true
}

func decodeOctalEscapes(s string) (string, bool) {
	if !strings.Contains(s, `\`) {
		return "", false
	}
	out := reOctalOne.ReplaceAllStringFunc(s, func(m string) string {
		v, err := strconv.ParseUint(m[1:], 8, 16)
		if err != nil || v > 0xFF {
			return m
		}
		return string([]byte{byte(v)})
	})
	if out == s || !utf8.ValidString(out) {
		return "", false
	}
	return out, true
}

func htmlDecode(s string) (string, bool) {
	if !strings.Contains(s, "&") {
		return "", false
	}
	out := html.UnescapeString(s)
	if out == s {
		return "", false
	}
	return out, true
}

func reverseString(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

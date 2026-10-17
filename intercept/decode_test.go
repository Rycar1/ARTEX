package intercept

import (
	"regexp"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func anyVariantContains(vs []DecodedVariant, sub string) bool {
	for _, v := range vs {
		if strings.Contains(v.Text, sub) {
			return true
		}
	}
	return false
}

func TestDecodeVariantsEmbeddedEncodings(t *testing.T) {
	const want = "rm -rf /var/www/html"
	cases := []struct {
		name string
		raw  string
	}{
		{"hex_param", `{"command":"curl -s \"http://10.213.0.9/diag?c=726d202d7266202f7661722f7777772f68746d6c\""}`},
		{"url_param", `{"command":"curl -s \"http://10.213.0.9/diag?c=%72%6d%20%2d%72%66%20%2f%76%61%72%2f%77%77%77%2f%68%74%6d%6c\""}`},
		{"base64_body", `{"command":"curl -X POST http://10.213.0.9/api -d cm0gLXJmIC92YXIvd3d3L2h0bWw="}`},
		{"unicode_escape", `{"command":"curl -s \"http://10.213.0.9/diag?cmd=\u0072\u006d\u0020-rf\u0020/var/www/html\""}`},
		{"hex_escape", `{"command":"printf '\x72\x6d\x20-rf\x20/var/www/html' | sh"}`},
		{"octal_escape", `{"command":"printf '\162\155\040-rf\040/var/www/html' | sh"}`},
		// JSON tool arguments carry a doubled backslash, so the escape decoders
		// only see the payload after the JSON unescape step has run.
		{"json_unicode_escape", `{"command":"curl -s \"http://10.213.0.9/diag?c=\\u0072\\u006d\\u0020-rf\\u0020/var/www/html\""}`},
		{"json_hex_escape", `{"command":"printf '\\x72\\x6d\\x20-rf\\x20/var/www/html' | sh"}`},
		{"json_octal_escape", `{"command":"printf '\\162\\155\\040-rf\\040/var/www/html' | sh"}`},
		{"html_entity", `{"command":"curl -s \"http://10.213.0.9/diag?cmd=&#x72;&#x6d;&#32;-rf&#32;/var/www/html\""}`},
		{"nested_pct_then_b64", `{"command":"echo cm0gLXJmIC92YXIvd3d3L2h0bWw%3D | base64 -d"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vs := DecodeVariants(tc.raw, decodeMaxDepth)
			if !anyVariantContains(vs, want) {
				t.Fatalf("no variant decoded to %q; got %d variants: %+v", want, len(vs), vs)
			}
		})
	}
}

func TestLooksEncodedSignatures(t *testing.T) {
	encoded := []string{
		`?c=726d202d7266202f7661722f7777772f68746d6c`,
		`?c=%72%6d%20-rf`,
		`-d cm0gLXJmIC92YXIvd3d3L2h0bWw=`,
		`cmd=\u0072\u006d\u0020-rf`,
		`printf '\x72\x6d\x20'`,
		`printf '\162\155\040'`,
		// doubled-backslash (JSON-escaped) forms must also be recognised
		`cmd=\\u0072\\u006d\\u0020-rf`,
		`printf '\\x72\\x6d\\x20'`,
		`printf '\\162\\155\\040'`,
		`cmd=&#x72;&#x6d;`,
		`echo AAECAwQFBgcICQoLDA0ODxAREhMUFRYX`,
	}
	for _, s := range encoded {
		if !LooksEncoded(s) {
			t.Errorf("LooksEncoded(%q) = false, want true", s)
		}
	}
	benign := []string{
		`cat /etc/passwd`,
		`nmap -sV -p 80,443 10.213.0.9`,
		`curl -s https://shop.example.com/api/order/list?page=1`,
		`sqlmap -u http://t/item?id=1 --batch --dump`,
		`ls -la /tmp`,
		// path-like tokens that match the base64 charset must NOT be treated as payloads
		`{"command": "ls -la /app/data/tasks/40/i6295 2>/dev/null; which curl"}`,
		`cd /app/data/tasks/40/i6296 && curl -sk -m 25 -A "$ARTEX_UA" -D paozi_hdr.txt "https://paozi.qq.com/"`,
		`echo "UA=$ARTEX_UA"; which curl httpx nmap whatweb jq python3 2>/dev/null; pwd`,
		// URL path segments that happen to match the base64 charset must NOT be flagged
		`cd /app/data/tasks/40/i6295 && echo "=== GetAidListByUidV2 no-param ==="; curl -sS -k -m 25 -A "$ARTEX_UA" -D - "https://gateway.qidian.qq.com/v1/basic.account.account_web.Account/GetAidListByUidV2" 2>&1 | head -50`,
		`curl -s https://gateway.qidian.qq.com/v1/basic.account.account_web.Account/GetAidListByUidV2`,
		`curl -sk "https://api.example.com/v1/basic.account.account_web.Account/GetAidListByUidV2" -D -`,
	}
	for _, s := range benign {
		if LooksEncoded(s) {
			t.Errorf("LooksEncoded(%q) = true, want false", s)
		}
	}
}

func TestUndecodableEncodedPayloadFallback(t *testing.T) {
	// A strong base64 signature that decodes to non-printable bytes: no decoder
	// recovers readable text, so the no-judge fail-closed fallback must fire.
	raw := `{"command":"curl -d AAECAwQFBgcICQoLDA0ODxAREhMUFRYX http://t/x"}`
	if !UndecodableEncodedPayload(raw) {
		t.Fatal("expected undecodable encoded payload to be detected")
	}
	if UndecodableEncodedPayload(`{"command":"ls -la /tmp"}`) {
		t.Fatal("benign command must not be flagged")
	}
}

func TestUndecodableEncodedPayloadIsNotReadable(t *testing.T) {
	// base64 of the 24 bytes 0x00..0x17: a clear base64 signature that decodes to
	// non-printable bytes, so the fail-closed ask must trigger.
	raw := `{"command":"curl -d AAECAwQFBgcICQoLDA0ODxAREhMUFRYX http://t/x"}`
	vs := DecodeVariants(raw, decodeMaxDepth)
	if !LooksEncoded(raw) {
		t.Fatal("expected an encoding signature")
	}
	if hasReadableDecode(vs) {
		t.Fatalf("expected no readable decode, got %+v", vs)
	}
}

func TestDecodedVariantMatchesRule(t *testing.T) {
	rule := compiledRule{
		InterceptRule: db.InterceptRule{MatchTarget: "tool_input", MatchType: "regex"},
		re:            regexp.MustCompile(`rm -rf`),
	}
	for _, raw := range []string{
		`{"command":"curl -s \"http://10.213.0.9/diag?c=726d202d7266202f7661722f7777772f68746d6c\""}`,
		`{"command":"curl -s \"http://10.213.0.9/diag?c=\\u0072\\u006d\\u0020-rf\\u0020/var/www/html\""}`,
		`{"command":"printf '\\x72\\x6d\\x20-rf\\x20/var/www/html' | sh"}`,
		`{"command":"printf '\\162\\155\\040-rf\\040/var/www/html' | sh"}`,
	} {
		if ruleMatchesSubject(rule, "Bash", raw) {
			t.Fatalf("raw encoded input must not match the plaintext rule: %s", raw)
		}
		matched := false
		for _, v := range DecodeVariants(raw, decodeMaxDepth) {
			if ruleMatchesSubject(rule, "Bash", v.Text) {
				matched = true
				break
			}
		}
		if !matched {
			t.Fatalf("a decoded variant must match the plaintext rule: %s", raw)
		}
	}
}

func TestSelectVariantsForReview(t *testing.T) {
	raw := `{"command":"curl -s \"http://10.213.0.9/diag?c=726d202d7266202f7661722f7777772f68746d6c\""}`
	got := SelectVariantsForReview(DecodeVariants(raw, decodeMaxDepth))
	if len(got) == 0 {
		t.Fatal("expected at least one review variant")
	}
	if len(got) > decodeReviewLimit {
		t.Fatalf("review variants exceed limit: %d", len(got))
	}
	for _, v := range got {
		if v.Kind == "rev" {
			t.Fatal("rev variants must not be sent to the judge")
		}
	}
}

// --- JSON 反转义视图:规则在「逻辑文本」上匹配,而不是 JSON 线格式 ---

func TestJSONUnescapeView(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{"newline", `{"content":"a\nb"}`, "{\"content\":\"a\nb\"}", true},
		{"escaped quote", `{"command":"echo \"x\""}`, `{"command":"echo "x""}`, true},
		{"tab/cr/bs/f", `a\tb\rc\bd\fe`, "a\tb\rc\bd\fe", true},
		{"unicode", `\u0072m -rf /`, "rm -rf /", true},
		{"doubled backslash stays literal", `\\n`, `\n`, true},
		{"nothing to do", `{"command":"ls -la"}`, "", false},
		{"lone surrogate untouched", `\uD800`, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := jsonUnescapeView(tc.in)
			if ok != tc.ok {
				t.Fatalf("jsonUnescapeView(%q) ok=%v, want %v", tc.in, ok, tc.ok)
			}
			if ok && got != tc.want {
				t.Fatalf("jsonUnescapeView(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// 线上实测的 4 条「真实破坏性调用」样本:它们此前对规则完全隐形,因为规则吃到的是
// JSON 转义文本 —— \n 转义让 \b 词边界失效, \" 让分隔符类失效。
func TestRuleMatchesThroughJSONEscapeView(t *testing.T) {
	r15 := compiledRule{ // [内置] Python HTTP 客户端 DELETE
		InterceptRule: db.InterceptRule{MatchTarget: "tool_input", MatchType: "regex"},
		re:            regexp.MustCompile(`(?:\b(?:requests|httpx|aiohttp|urllib\.request)\.delete\s*\(|session\.delete\s*\(|client\.delete\s*\()`),
	}
	r20 := compiledRule{ // [内置] 删除类接口路径
		InterceptRule: db.InterceptRule{MatchTarget: "tool_input", MatchType: "regex"},
		re:            regexp.MustCompile(`(?i)/(?:(?:delete|remove|unlink|erase|destroy)[-\w]*|del)(?:[/?#"'\s]|$)`),
	}
	cases := []struct {
		name string
		rule compiledRule
		raw  string
	}{
		{"write 脚本里的 requests.delete", r15,
			`{"content":"import requests\nrequests.delete('https://api.target.com/api/users/10231')"}`},
		{"heredoc 里的 requests.delete", r15,
			`{"command":"python3 - <<'EOF'\nimport requests\nrequests.delete(\"https://api.target.com/api/v1/projects/7788\")\nEOF"}`},
		{"引号结尾的删除接口路径", r20,
			`{"command":"B=\"https://cpcmd.tencent.com/api\"; curl -sk -X POST -d '{}' \"$B/command/delete\""}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if ruleMatchesSubject(tc.rule, "Bash", tc.raw) {
				t.Fatal("precondition: 原始 JSON 视图本不该命中(这正是被修的 bug)")
			}
			subjects, kindOf := matchSubjects(tc.raw)
			hitKind := ""
			for _, s := range subjects {
				if ruleMatchesSubject(tc.rule, "Bash", s) {
					hitKind = kindOf[s]
					break
				}
			}
			// 必须命中**反转义视图**本身:只断言「命中了某个视图」的话,任何解码变体
			// 也能让用例通过,就验不到本次修的东西了。
			if hitKind != "json_unescape" {
				t.Fatalf("命中来源必须是 json_unescape(反转义视图),实际=%q", hitKind)
			}
		})
	}
}

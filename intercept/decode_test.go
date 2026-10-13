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

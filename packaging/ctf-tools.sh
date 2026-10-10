#!/bin/sh
# ============================================================================
# ARTEX CTF 工具箱安装层
# ----------------------------------------------------------------------------
# 由根目录 Dockerfile / Dockerfile.source / Dockerfile.fork 共用（一份脚本三处
# 复用，避免三份 Dockerfile 的包清单各自漂移）。
#
# 装什么（按 CTF 三块分，全部为 Debian bookworm 官方源可得，已实测）：
#   misc/取证：file xxd binwalk foremost sleuthkit testdisk steghide outguess
#              pngcheck exiftool zbar poppler qpdf pdfcrack fcrackzip 7z bzip2
#              xz cpio hashcat john tshark tcpdump ffmpeg sox imagemagick
#              sqlite3 gawk
#   RE      ：binutils(objdump/readelf/strings/nm) gdb gdb-multiarch strace
#              ltrace nasm patchelf
#              + pip: capstone keystone-engine unicorn z3-solver sympy
#   Pwn     ：build-essential(编 exp) qemu-user qemu-user-static patchelf
#              + pip: pwntools ROPgadget ropper
#              + gem: one_gadget seccomp-tools zsteg
#
# 环境变量（全部可选，默认走官方源；国内构建强烈建议给 APT_MIRROR/PIP_MIRROR）：
#   APT_MIRROR   apt 镜像主机名，例 mirrors.tuna.tsinghua.edu.cn
#   PIP_MIRROR   pip index-url，例 https://mirrors.aliyun.com/pypi/simple
#   GEM_SOURCE   gem source，例 https://mirrors.tuna.tsinghua.edu.cn/rubygems/
#   CTF_EXTRA    1 = 额外装 radare2 / upx（见下）
#   GH_PROXY     GitHub 加速前缀，例 https://ghfast.top/（github.com 直连不通时用）
#
# radare2 / upx 为什么单独走 GitHub：
#   Debian bookworm 里两者都没有候选版本（apt-cache policy 的 Candidate 为空），
#   只能取上游 release 的钉版二进制。sha256 写死在下面，校验不过就跳过；
#   下载/校验失败只告警、不中断构建——核心层已经够用，装了没装以
#   `command -v r2 / command -v upx` 为准。
#
# 哈希出处（不得凭记忆改）：
#   radare2_6.2.4_amd64.deb：取自上游 release 附件 checksums.txt 同名行
#     （2026-10-10 经 api.github.com 拉取 checksums.txt 核对：
#      7019eedc… == 上游值；容器内 dpkg -i 后 `r2 -v` 输出 6.2.4，实测可用）
#   upx-5.2.1-amd64_linux.tar.xz：上游未提供校验文件，哈希为 2026-10-10 从官方
#     asset（id 532383358，664048 字节）实测计算，并以 `unxz -t` 验证 xz 流完整。
#   两个钉版 asset id（radare2 613512350 / upx 532383358）作为第二下载源写在下文，
#   因为 GitHub 加速镜像（ghfast.top 之类）实测会偶发返回与官方不同内容的同名文件，
#   只靠单一 URL 会「下载成功但哈希不符」。换版本时必须重新下载、重新计算、重新核对。
#   下载失败只告警不中断：装了没装以 `command -v r2 / command -v upx` 为准。
# ============================================================================
set -eu

APT_MIRROR="${APT_MIRROR:-}"
PIP_MIRROR="${PIP_MIRROR:-}"
GEM_SOURCE="${GEM_SOURCE:-}"
CTF_EXTRA="${CTF_EXTRA:-0}"
GH_PROXY="${GH_PROXY:-}"

R2_VER="6.2.4"
R2_SHA="7019eedc0e0e87d1f53d6b8f5fc62b898567679c5efdce7fbfc557c9e7655e90"
UPX_VER="5.2.1"
UPX_SHA="402162aad30af47e60dbd767fb2e64ca394ace9727ba1f40283641f1d1b91657"
# 官方 release asset id（api.github.com 第二下载源用；随版本固定，换版本需重取）
R2_ASSET_ID="613512350"
UPX_ASSET_ID="532383358"

export DEBIAN_FRONTEND=noninteractive
log() { echo "[ctf-tools] $*"; }

# ---------- 1. apt 层 ----------
if [ -n "$APT_MIRROR" ]; then
  if [ -f /etc/apt/sources.list.d/debian.sources ]; then
    sed -i "s|deb.debian.org|${APT_MIRROR}|g; s|security.debian.org|${APT_MIRROR}|g" \
      /etc/apt/sources.list.d/debian.sources
  fi
  if [ -f /etc/apt/sources.list ]; then
    sed -i "s|deb.debian.org|${APT_MIRROR}|g; s|security.debian.org|${APT_MIRROR}|g" \
      /etc/apt/sources.list
  fi
fi

apt-get update
# tshark 装的时候 debconf 会问「是否允许非 root 抓包」，非交互构建必须预设，
# 否则 build 会卡在提示上（CI 里表现为莫名超时）。
echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections

log "安装 apt 层（misc/取证 + RE + Pwn 命令行件）"
apt-get install -y --no-install-recommends \
  file xxd binutils strace ltrace gdb gdb-multiarch \
  binwalk foremost sleuthkit testdisk steghide outguess pngcheck \
  libimage-exiftool-perl zbar-tools poppler-utils qpdf pdfcrack fcrackzip \
  p7zip-full bzip2 xz-utils cpio tshark hashcat john \
  build-essential nasm patchelf qemu-user qemu-user-static \
  ruby ruby-dev ffmpeg sox sqlite3 gawk imagemagick \
  tcpdump socat

# ---------- 2. Python 层 ----------
PIP_ARGS="--no-cache-dir --disable-pip-version-check"
if [ -n "$PIP_MIRROR" ]; then
  PIP_ARGS="$PIP_ARGS -i $PIP_MIRROR"
fi
log "安装 python 层（pwntools / z3 / capstone / keystone / unicorn / ropper …）"
# shellcheck disable=SC2086
python3 -m pip install $PIP_ARGS \
  pwntools ROPgadget ropper \
  z3-solver capstone keystone-engine unicorn \
  pycryptodome pillow sympy numpy gmpy2

# ---------- 3. Ruby 层（图片/BPF 隐写与 gadget）----------
if [ -n "$GEM_SOURCE" ]; then
  gem sources --add "$GEM_SOURCE" >/dev/null 2>&1 || true
  gem sources --remove https://rubygems.org/ >/dev/null 2>&1 || true
fi
log "安装 gem 层（zsteg / one_gadget / seccomp-tools）"
gem install --no-document zsteg one_gadget seccomp-tools
rm -rf /usr/local/lib/ruby/gems/*/cache/* 2>/dev/null || true

# ---------- 4. 可选：radare2 / upx（bookworm 无候选包）----------
# 两个下载源：① GitHub release 直链（可加 GH_PROXY 前缀）② api.github.com 的
# asset 端点（用固定 asset id，Accept: application/octet-stream）。每个源各重试
# 3 次，任何一次 sha256 对上就停；全失败只告警不中断构建。
try_fetch() {  # try_fetch <out> <sha256> <url>...
  _out="$1"; _sha="$2"; shift 2
  for _u in "$@"; do
    for _a in 1 2 3; do
      if curl -fsSL --retry 3 --retry-all-errors --retry-delay 3 --max-time 900 \
           -H "Accept: application/octet-stream" -o "$_out" "$_u" \
         && echo "${_sha}  ${_out}" | sha256sum -c - >/dev/null 2>&1; then
        return 0
      fi
      log "下载或 sha256 校验未过（第 ${_a} 次）：${_u}"
      rm -f "$_out"
    done
  done
  return 1
}

if [ "$CTF_EXTRA" = "1" ]; then
  if [ "$(dpkg --print-architecture)" != "amd64" ]; then
    log "警告：CTF_EXTRA 目前只提供 amd64 二进制，当前架构 $(dpkg --print-architecture)，跳过"
  else
    TMPD="$(mktemp -d)"
    log "CTF_EXTRA=1：取 radare2 ${R2_VER} / upx ${UPX_VER}（钉版 sha256）"

    R2_URL="${GH_PROXY}https://github.com/radareorg/radare2/releases/download/${R2_VER}/radare2_${R2_VER}_amd64.deb"
    R2_API_URL="https://api.github.com/repos/radareorg/radare2/releases/assets/${R2_ASSET_ID}"
    if try_fetch "$TMPD/r2.deb" "$R2_SHA" "$R2_URL" "$R2_API_URL"; then
      if dpkg -i "$TMPD/r2.deb" >/dev/null 2>&1; then
        log "radare2 已装：$(r2 -v 2>/dev/null | head -1)"
      else
        apt-get -f install -y >/dev/null 2>&1 || true
        if command -v r2 >/dev/null 2>&1; then
          log "radare2 已装（补依赖后）：$(r2 -v 2>/dev/null | head -1)"
        else
          log "警告：radare2 deb 安装失败，跳过"
        fi
      fi
    else
      log "警告：radare2 下载或 sha256 校验失败，跳过（不影响其余工具）"
    fi

    UPX_URL="${GH_PROXY}https://github.com/upx/upx/releases/download/v${UPX_VER}/upx-${UPX_VER}-amd64_linux.tar.xz"
    UPX_API_URL="https://api.github.com/repos/upx/upx/releases/assets/${UPX_ASSET_ID}"
    if try_fetch "$TMPD/upx.tar.xz" "$UPX_SHA" "$UPX_URL" "$UPX_API_URL" \
       && tar -xJf "$TMPD/upx.tar.xz" -C "$TMPD"; then
      install -m 0755 "$TMPD"/upx-${UPX_VER}-amd64_linux/upx /usr/local/bin/upx
      log "upx 已装：$(upx --version 2>/dev/null | head -1)"
    else
      log "警告：upx 下载或 sha256 校验失败，跳过（不影响其余工具）"
    fi
    rm -rf "$TMPD"
  fi
fi

# ---------- 5. 收尾 ----------
rm -rf /var/lib/apt/lists/* /root/.cache/pip 2>/dev/null || true

log "完成。自检："
for t in file xxd strings objdump gdb r2 upx binwalk zsteg hashcat john tshark ffmpeg patchelf qemu-x86_64 sqlite3 ruby; do
  if command -v "$t" >/dev/null 2>&1; then printf '  [ok] %s\n' "$t"; else printf '  [--] %s\n' "$t"; fi
done
python3 -c "import pwn, z3, capstone, keystone, unicorn; print('  [ok] python: pwntools/z3/capstone/keystone/unicorn')" \
  || echo "  [--] python ctf 库自检失败"

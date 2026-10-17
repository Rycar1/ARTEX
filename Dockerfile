# syntax=docker/dockerfile:1
#
# 多阶段构建：前端静态导出 → Go 单二进制（内嵌前端）→ 运行镜像。
# 原 Docker Hub 镜像源（autumn27/artex）已失效，本仓库自此支持从纯源码自助构建：
#   docker compose build        # 或 docker build -t artex:local .
# TARGETARCH 由 buildx 自动注入（amd64/arm64），Go 交叉编译无需 QEMU；
# 运行层只装工具，编译全部在构建阶段完成。
# 国内网络可覆盖模块源（默认已对国内友好）：
#   --build-arg GOPROXY=https://goproxy.cn,direct
#   --build-arg NPM_REGISTRY=https://registry.npmmirror.com

########## 阶段 1：前端静态导出 ##########
FROM node:20-bookworm AS web
ARG NPM_REGISTRY=https://registry.npmmirror.com
WORKDIR /web
# --ignore-scripts：跳过 prepare(husky)——容器里没有 .git，husky 会失败；
# Next.js/Biome 的平台二进制走 optionalDependencies，不依赖生命周期脚本。
COPY web/package.json web/package-lock.json ./
RUN npm config set registry "$NPM_REGISTRY" && npm ci --ignore-scripts
COPY web/ ./
RUN NEXT_EXPORT=1 npm run build:static

########## 阶段 2：Go 后端（内嵌前端，静态编译）##########
FROM golang:1.26-bookworm AS gobuild
ARG TARGETARCH
ARG GOPROXY=https://goproxy.cn,https://proxy.golang.org,direct
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# 前端静态产物从 web 阶段拷入（.dockerignore 已排除宿主 dist，不会冲突）
COPY --from=web /web/out/ server/webui/dist/
RUN CGO_ENABLED=0 GOARCH="${TARGETARCH}" go build -tags embedui -trimpath -o /out/artex ./cmd/artex

########## 阶段 3：运行镜像（同原版：工具 + Playwright 预装）##########
FROM python:3.12-slim-bookworm
ARG NPM_REGISTRY=https://registry.npmmirror.com
# 运行层的全局 npm 装包与 chromium 下载同样走国内源（对全球网络同样可达）
ENV npm_config_registry=$NPM_REGISTRY \
    PLAYWRIGHT_DOWNLOAD_HOST=https://cdn.npmmirror.com/binaries/playwright
# 常用工具：ripgrep / curl / vim，加一批 recon 常备件（按需增删）。
# Node 从 NodeSource 装 20.x：bookworm 自带的 apt nodejs 是 18，Playwright 要求 >=20。
# setup_20.x 是 NodeSource 的**可变脚本**（内容会随上游更新而变），直接管道执行
# 等于每次构建都盲信上游。这里先落盘、比对钉死的 SHA256 再执行，fail-closed：
# 哈希不符说明上游改了脚本，先审计 diff 再决定是否更新哈希，不要盲目刷新。
# 哈希取值日期 2026-09-13。回退方案：改用 nodejs 官方 tarball（nodejs.org，固定
# 版本 + 官方 SHA256SUMS 签名文件），彻底绕开第三方仓库脚本。
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates ripgrep curl wget vim git jq unzip \
      dnsutils iputils-ping netcat-openbsd inetutils-telnet whois nmap \
    && curl -fsSL https://deb.nodesource.com/setup_20.x -o /tmp/nodesource_setup.sh \
    && echo "2c4c6683a17b6f4128898a7b521e3c8bb725a99ffaf1b5e32ac97c6fa7d381be  /tmp/nodesource_setup.sh" | sha256sum -c - \
    && bash /tmp/nodesource_setup.sh \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -f /tmp/nodesource_setup.sh \
    && rm -rf /var/lib/apt/lists/*
# 预装 Playwright MCP 与 CLI（全局），运行时不再 npx 联网下载。
# 版本钉死（2026-09-13 自 npm registry 的 latest 取值）：@latest 会让同一 Dockerfile
# 在不同时间构建出不同镜像，升级时应有意识地 bump 并记录，而不是被隐式漂移。
# @playwright/mcp：browser MCP 直接 `npx @playwright/mcp`（已全局装好，无需 -y/@latest）。
# @playwright/cli：提供 playwright-cli，装完顺带 --help 验证可执行。
# 再装 playwright（提供浏览器管理），装完用 --with-deps 预置 chromium 及其系统依赖，
# 这样容器内 MCP/CLI 首次启动即可用，不再联网下载浏览器。
RUN npm install -g @playwright/mcp@0.0.80 @playwright/cli@0.1.19 playwright@1.63.0 \
    && playwright-cli --help \
    && playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/*

# ---------- CTF 工具层（misc / RE / pwn 常用件）----------
# 一份脚本三处复用（Dockerfile / Dockerfile.source / Dockerfile.fork），包清单不漂移。
# 构建参数（全部可选，默认官方源；国内构建强烈建议传镜像源）：
#   docker build --build-arg APT_MIRROR=mirrors.tuna.tsinghua.edu.cn \
#                --build-arg PIP_MIRROR=https://mirrors.aliyun.com/pypi/simple \
#                --build-arg CTF_EXTRA=1 -t artex:local .
# CTF_EXTRA=1 才额外装 radare2 / upx（GitHub 钉版 sha256）与 angr（pip）。
ARG APT_MIRROR=
ARG PIP_MIRROR=
ARG GEM_SOURCE=
ARG CTF_EXTRA=0
ARG GH_PROXY=
COPY packaging/ctf-tools.sh /tmp/ctf-tools.sh
RUN sh /tmp/ctf-tools.sh && rm -f /tmp/ctf-tools.sh

WORKDIR /app
# 构建阶段产出的单二进制（内嵌前端）
COPY --from=gobuild /out/artex /app/artex
# 守护启动脚本：进程退出后按退出码决定是否重新拉起，页面一键更新靠它完成换装。
# 它同时负责把 SIGTERM 转发给 artex —— docker stop 只把信号发给 PID 1，
# 不转发的话 artex 收不到、做不了优雅关闭，10 秒后被 SIGKILL 硬杀。
COPY start.sh /app/start.sh
RUN chmod +x /app/artex /app/start.sh
COPY skills/ /app/skills/
# data/（SQLite + jwt.key）持久化点
VOLUME ["/app/data"]
EXPOSE 8787 8788
ENTRYPOINT ["/app/start.sh"]
CMD ["-addr", ":8787", "-proxy", ":8788"]

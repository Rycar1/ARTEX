"use client";

import * as React from "react";

import type { Graph as G6Graph } from "@antv/g6";
import { ChevronDown, ChevronUp, Maximize2, Minimize2, RefreshCw } from "lucide-react";

import { Button } from "@/components/ui/button";
import type { Credential, IntranetSegment, IntranetTopology, ShellSession, TunnelInfo } from "@/lib/types";
import { cn } from "@/lib/utils";

// 网段配色盘：按 segments 顺序取色，超出循环复用。
// 配色刻意避开绿色与正红：绿 = 服务未拿下、红 = 已拿下，网段色不能再撞这两个语义色。
const SEGMENT_PALETTE = [
  "#3b82f6",
  "#6366f1",
  "#f59e0b",
  "#8b5cf6",
  "#06b6d4",
  "#ec4899",
  "#f97316",
  "#0ea5e9",
  "#a855f7",
  "#eab308",
];

// 与资产覆盖图同一套做法：lucide 图标（v1.22 路径）渲染成白色 data URI 作节点图标，
// 手写内嵌以避免 react-dom/server 在 React19/Next 客户端打包的问题。
function svgUri(inner: string, filled = false): string {
  const attrs = filled
    ? 'fill="#fff" stroke="none"'
    : 'fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"';
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" ${attrs}>${inner}</svg>`;
  return `data:image/svg+xml,${encodeURIComponent(svg)}`;
}

// 普通主机 = 显示器；平台自身（回连端）= 实心五角星。
const HOST_ICON = svgUri(
  '<rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" x2="16" y1="21" x2="21"/><line x1="12" x2="12" y1="17" y2="21"/>',
);
const CALLBACK_ICON = svgUri(
  '<path d="M12 2.5l2.9 6.1 6.6.8-4.9 4.6 1.3 6.6-5.9-3.3-5.9 3.3 1.3-6.6-4.9-4.6 6.6-.8z"/>',
  true,
);

export function segmentColor(segments: IntranetSegment[], segment: string): string {
  const idx = Math.max(
    0,
    segments.findIndex((s) => s.name === segment),
  );
  return SEGMENT_PALETTE[idx % SEGMENT_PALETTE.length];
}

// G6 的类型把自定义字段归在 data 下，但官方 force 示例（及运行时）按顶层读 d.<field>。
// 回调形参用 unknown 满足 G6 签名，内部用 nd()/ed() 强转回我们的顶层结构。
/** 主机上的一个服务（来自资产 open_ports）。compromised = 已拿下该服务，见 buildModel 的判定规则。 */
type ServiceDatum = { port: number; service: string; compromised: boolean };

type G6NodeDatum = {
  id: string;
  lbl: string;
  segment: string;
  hasSession: boolean;
  alive: number;
  isCallback: boolean;
  size: number;
  /** 主机平台：windows / linux / ""（未知，可能由开放端口启发式推断）。 */
  platform: string;
  /** 主机是否已拿下（有会话记录或已验证凭据）→ 圆点显示红色。 */
  compromised: boolean;
  /** 主机上探测到的服务；服务小圆点从这个点向外延展一圈。 */
  services: ServiceDatum[];
  /** 服务小圆点（不是主机）：不参与网段框排版、不触发主机过滤。 */
  svc?: boolean;
  svcCompromised?: boolean;
  /** 服务小圆点归属的主机节点 id。 */
  hostId?: string;
  /** 网段框（不是主机）：只画底框 + 标题，不画图标、不带角标。 */
  frame?: boolean;
  fw?: number;
  fh?: number;
  frameFill?: string;
  frameStroke?: string;
  /** G6 节点图形类型：主机/服务 circle，网段框 rect。 */
  type?: string;
  style?: { x?: number; y?: number };
};
type G6EdgeDatum = {
  id: string;
  source: string;
  target: string;
  state: string;
  /** state === "svc" 的主机→服务短连线：决定线色（红=已拿下）。 */
  svcCompromised?: boolean;
};

/** 节点角标：会话数（right-top）与平台 W/L（left-top）。placement 收窄成字面量，满足 G6 类型。 */
type BadgeSpec = {
  text: string;
  placement: "right-top" | "left-top";
  fontSize: number;
  fontWeight: number;
  fill: string;
  padding: number[];
  backgroundFill: string;
  backgroundRadius: number;
  backgroundStroke: string;
  backgroundLineWidth: number;
};

const nd = (d: unknown) => d as G6NodeDatum;
const ed = (d: unknown) => d as G6EdgeDatum;

// 已取得权限（有会话记录）的主机明显放大；平台自身保持星形中等尺寸。
const SESSION_SIZE = 44;
const CALLBACK_SIZE = 32;
const HOST_SIZE = 26;

function nodeSizeFor(n: { has_session: boolean; is_callback: boolean }): number {
  if (n.has_session) return SESSION_SIZE;
  if (n.is_callback) return CALLBACK_SIZE;
  return HOST_SIZE;
}

// 服务小圆点：绕主机点排一圈，红 = 已拿下、绿 = 未拿下。
const SVC_SIZE = 11;
const SVC_MAX = 12; // 单机服务过多时只画前 N 个（先已拿下、再按端口），避免整圈糊成一团。
/** 服务外圈半径：跟着主机点大小放大，保证主机→服务的枝杈露得出来。 */
const ringRFor = (size: number) => size / 2 + 20;
// ---------------------------------------------------------------------------
// 数据组装：主机点 + 服务小圆点 + 隧道边。
// 判定规则集中在这里，便于核对：
//   主机平台：优先取会话 secret 里的 platform；无会话时按开放端口启发式推断。
//   主机已拿下：有会话记录（含已停止的历史马）或存在已验证凭据。
//   服务已拿下：有存活隧道把该 host:port 打通，或有存活会话的 URL 正落在该 host:port 上。
// ---------------------------------------------------------------------------
const WINDOWS_HINT_PORTS = new Set([135, 139, 445, 3389, 5985, 5986]);
const LINUX_HINT_PORTS = new Set([22]);

/** 拆 URL 的 host:port；无显式端口时按协议补 80/443。 */
function urlHostPort(raw: string): { host: string; port: number } {
  try {
    const u = new URL(raw);
    const port = Number(u.port) || (u.protocol === "https:" ? 443 : 80);
    return { host: u.hostname, port };
  } catch {
    return { host: "", port: 0 };
  }
}

/** 平台角标文案：Windows / Linux / 未知（未知平台也给用户一个明确说法）。 */
function platformLabel(platform: string): string {
  if (platform === "windows") return "Windows";
  if (platform === "linux") return "Linux";
  return "平台未知";
}

/** 平台角标配色：与图上 W/L 角标同色，未知平台用中性灰。 */
function platformBadgeClass(platform: string): string {
  if (platform === "windows") return "bg-sky-600";
  if (platform === "linux") return "bg-amber-600";
  return "bg-slate-400";
}

/** host_asset_id 既可能是资产数字 id，也可能是 IP / 主机名：两种写法都生成别名。 */
function assetAliases(v: unknown): string[] {
  const s = String(v ?? "").trim();
  if (!s || s === "0") return [];
  return s.startsWith("asset-") ? [s, s.slice(6)] : [s, `asset-${s}`];
}

function buildModel(
  data: IntranetTopology,
  sessions: ShellSession[],
  tunnels: TunnelInfo[],
  credentials: Credential[],
): { nodes: G6NodeDatum[]; edges: G6EdgeDatum[] } {
  const platformByAlias = new Map<string, string>();
  for (const s of sessions) {
    const plat = (s.platform || "").toLowerCase();
    if (!plat) continue;
    for (const key of [...assetAliases(s.host_asset_id), urlHostPort(s.url).host]) {
      if (key && !platformByAlias.has(key)) platformByAlias.set(key, plat);
    }
  }
  const verifiedHosts = new Set<string>();
  for (const c of credentials) {
    if (!c.verified) continue;
    for (const key of assetAliases(c.host_asset_id)) verifiedHosts.add(key);
  }
  // 服务已拿下：存活隧道 target_host:port，或存活会话 URL 的 host:port。
  const tunnelHits = new Set<string>();
  for (const t of tunnels) {
    if (t.state !== "alive" || !t.target_host || !t.target_port) continue;
    tunnelHits.add(`${t.target_host}:${t.target_port}`);
  }
  const shellHits = new Set<string>();
  for (const s of sessions) {
    if (s.status !== "alive") continue;
    const { host, port } = urlHostPort(s.url);
    if (host && port) shellHits.add(`${host}:${port}`);
  }

  const hosts: G6NodeDatum[] = (data.nodes ?? []).map((n) => {
    const aliases = [n.ip, n.id, ...assetAliases(n.id)];
    const services: ServiceDatum[] = (n.services ?? [])
      .filter((s) => s && s.port > 0)
      .map((s) => ({
        port: s.port,
        service: (s.service ?? "").trim(),
        compromised: tunnelHits.has(`${n.ip}:${s.port}`) || shellHits.has(`${n.ip}:${s.port}`),
      }));
    let platform = "";
    for (const key of aliases) {
      const hit = platformByAlias.get(key);
      if (hit) {
        platform = hit;
        break;
      }
    }
    if (!platform) {
      // 没有会话指纹时用开放端口猜平台，帮助区分 Linux / Windows。
      const ports = new Set(services.map((s) => s.port));
      if ([...ports].some((p) => WINDOWS_HINT_PORTS.has(p))) platform = "windows";
      else if ([...ports].some((p) => LINUX_HINT_PORTS.has(p))) platform = "linux";
    }
    return {
      id: n.id,
      lbl: n.alive_sessions > 0 ? `${n.ip} (${n.alive_sessions})` : n.ip || n.id,
      segment: n.segment,
      hasSession: n.has_session,
      alive: n.alive_sessions,
      isCallback: n.is_callback,
      size: nodeSizeFor(n),
      platform,
      compromised: n.has_session || aliases.some((key) => verifiedHosts.has(key)),
      services,
      type: "circle",
    };
  });

  // 服务小圆点：先已拿下、再按端口排序，单机最多 SVC_MAX 个。
  const svcNodes: G6NodeDatum[] = [];
  const svcEdges: G6EdgeDatum[] = [];
  for (const host of hosts) {
    const list = [...host.services]
      .sort((a, b) => Number(b.compromised) - Number(a.compromised) || a.port - b.port)
      .slice(0, SVC_MAX);
    for (const s of list) {
      const id = `svc::${host.id}::${s.port}`;
      svcNodes.push({
        id,
        lbl: s.service || String(s.port),
        segment: host.segment,
        hasSession: false,
        alive: 0,
        isCallback: false,
        size: SVC_SIZE,
        platform: "",
        compromised: false,
        services: [],
        svc: true,
        svcCompromised: s.compromised,
        hostId: host.id,
        type: "circle",
      });
      svcEdges.push({
        id: `svce::${host.id}::${s.port}`,
        source: host.id,
        target: id,
        state: "svc",
        svcCompromised: s.compromised,
      });
    }
  }

  return {
    nodes: [...hosts, ...svcNodes],
    edges: [
      ...(data.edges ?? []).map((e) => ({ id: e.id, source: e.from, target: e.to, state: e.state })),
      ...svcEdges,
    ],
  };
}
// 布局：按 /24 网段分组，一个网段一个框，主机装在框里；框与框之间按货架方式紧凑码放。
// 这样「哪几台同段」「哪几台已经拿到权限」一眼可见，也不会像力导向那样撒得到处都是。
// 单元格要装下「主机点 + 外圈服务点」和下方标签：半径 30 的圈 + IP 标签宽度。
const CELL_W = 136;
const CELL_H = 112;
const GAP_X = 24;
const GAP_Y = 20;
const FRAME_PAD_X = 16;
const FRAME_PAD_TOP = 30;
const FRAME_PAD_BOTTOM = 14;
const FRAME_GAP_X = 22;
const FRAME_GAP_Y = 22;

type Frame = {
  id: string;
  segment: string;
  count: number;
  w: number;
  h: number;
  cells: { id: string; x: number; y: number }[];
};

// 一个网段一个框：框内主机排成方阵，框顶留出标题栏高度。
function pickCols(count: number): number {
  let best = 1;
  let bestScore = Number.POSITIVE_INFINITY;
  for (let c = 1; c <= count; c++) {
    const r = Math.ceil(count / c);
    const empty = c * r - count;
    const w = c * CELL_W + (c - 1) * GAP_X;
    const h = r * CELL_H + (r - 1) * GAP_Y;
    const score = empty * 0.9 + Math.abs(Math.log(w / h / 1.7));
    if (score < bestScore) { bestScore = score; best = c; }
  }
  return best;
}

function frameFor(segment: string, ids: string[]): Frame {
  const count = ids.length;
  const cols = pickCols(count);
  const rows = Math.ceil(count / cols);
  const innerW = cols * CELL_W + (cols - 1) * GAP_X;
  const innerH = rows * CELL_H + (rows - 1) * GAP_Y;
  const cells = ids.map((id, i) => ({
    id,
    x: FRAME_PAD_X + CELL_W / 2 + (i % cols) * (CELL_W + GAP_X),
    y: FRAME_PAD_TOP + CELL_H / 2 + Math.floor(i / cols) * (CELL_H + GAP_Y),
  }));
  return {
    id: `seg::${segment}`,
    segment,
    count,
    w: innerW + FRAME_PAD_X * 2,
    h: innerH + FRAME_PAD_TOP + FRAME_PAD_BOTTOM,
    cells,
  };
}

// 货架码放：框按高度降序逐行铺；行宽上限试多个候选值，取「内容框最贴容器长宽比」的那个，
// 这样 fitView 的缩放比最小，节点在屏幕上最大。
function packFrames(frames: Frame[], width: number, height: number) {
  const W = width > 0 ? width : 1200;
  const H = height > 0 ? height : 420;
  const ordered = [...frames].sort((a, b) => b.h - a.h || b.w - a.w);
  const maxW = ordered.reduce((acc, f) => Math.max(acc, f.w), CELL_W);
  const area = ordered.reduce((sum, f) => sum + f.w * f.h, 0);
  const base = Math.max(maxW, Math.sqrt(area));
  let best: { frame: Frame; x: number; y: number }[] = [];
  let bestScore = Number.POSITIVE_INFINITY;
  for (let k = 0; k < 24; k++) {
    const limit = base * (1 + k * 0.25);
    const placed: { frame: Frame; x: number; y: number }[] = [];
    let x = 0;
    let y = 0;
    let rowH = 0;
    let contentW = 0;
    for (const frame of ordered) {
      if (x > 0 && x + frame.w > limit) {
        y += rowH + FRAME_GAP_Y;
        x = 0;
        rowH = 0;
      }
      placed.push({ frame, x, y });
      x += frame.w + FRAME_GAP_X;
      rowH = Math.max(rowH, frame.h);
      contentW = Math.max(contentW, x - FRAME_GAP_X);
    }
    const score = Math.max(contentW / W, (y + rowH) / H);
    if (score < bestScore) {
      bestScore = score;
      best = placed;
    }
  }
  return best;
}

// 计算坐标：按网段分框（有权限的主机排在框内靠前）→ 码放框 → 摊平成 主机 id → {x, y}。
// 服务小圆点不占格子，位置由所属主机按极坐标另算（见 applyData）。
function computeLayout(
  nodes: G6NodeDatum[],
  width: number,
  height: number,
  segments: IntranetSegment[],
) {
  const pos = new Map<string, { x: number; y: number }>();
  const bySegment = new Map<string, G6NodeDatum[]>();
  for (const n of nodes) {
    if (n.svc) continue; // 服务小圆点不参与网格排版
    const key = n.segment || "未知网段";
    const list = bySegment.get(key);
    if (list) list.push(n);
    else bySegment.set(key, [n]);
  }
  const frames = [...bySegment.entries()]
    .sort(([a], [b]) => a.localeCompare(b, undefined, { numeric: true }))
    .map(([segment, list]) => {
    const ordered = [...list].sort(
      (a, b) => Number(b.hasSession) - Number(a.hasSession) || a.lbl.localeCompare(b.lbl),
    );
    return frameFor(segment, ordered.map((n) => n.id));
  });
  const placed = packFrames(frames, width, height).map((item) => ({
    ...item.frame,
    x: item.x,
    y: item.y,
    color: segmentColor(segments, item.frame.segment),
  }));
  for (const frame of placed) {
    for (const cell of frame.cells) pos.set(cell.id, { x: frame.x + cell.x, y: frame.y + cell.y });
  }
  return { frames: placed, pos };
}
type TopologyStats = {
  hosts: number;
  compromised: number;
  services: number;
  servicesTaken: number;
  aliveEdges: number;
  segments: number;
};

function TopologyLegend({
  data,
  stats,
  loading,
  onRefresh,
  showAllEdges,
  onToggleAllEdges,
}: {
  data: IntranetTopology | null;
  stats: TopologyStats;
  loading: boolean;
  onRefresh: () => void;
  showAllEdges: boolean;
  onToggleAllEdges: () => void;
}) {
  // 默认收起，先把画布让出来；需要看网段配色时再展开。
  const [open, setOpen] = React.useState(false);
  const segments = data?.segments ?? [];
  return (
    <div className="bg-card/95 pointer-events-auto absolute top-3 left-3 flex max-w-[min(92%,460px)] flex-col gap-2 rounded-lg border p-2.5 text-xs shadow-sm backdrop-blur">
      <div className="flex items-center gap-2">
        {data ? (
          <span className="text-muted-foreground inline-flex flex-wrap items-center gap-x-2.5 gap-y-1">
            <span className="whitespace-nowrap">
              主机 <span className="text-foreground font-semibold tabular-nums">{stats.hosts}</span>
            </span>
            <span className="inline-flex items-center gap-1 whitespace-nowrap">
              <span className="size-2.5 rounded-full bg-red-500 ring-2 ring-red-500/30" />
              已拿下
              <span className="font-semibold tabular-nums text-red-600 dark:text-red-400">
                {stats.compromised}
              </span>
            </span>
            <span className="inline-flex items-center gap-1 whitespace-nowrap">
              <span className="size-2.5 rounded-full bg-emerald-500 ring-2 ring-emerald-500/30" />
              服务
              <span className="text-foreground font-semibold tabular-nums">
                {stats.servicesTaken}/{stats.services}
              </span>
            </span>
            <span className="whitespace-nowrap">
              链路{" "}
              <span className="font-semibold tabular-nums text-emerald-600 dark:text-emerald-400">{stats.aliveEdges}</span>
            </span>
            <span className="whitespace-nowrap">
              网段 <span className="text-foreground font-semibold tabular-nums">{stats.segments}</span>
            </span>
          </span>
        ) : (
          <span className="text-muted-foreground">{loading ? "加载中…" : "暂无拓扑数据"}</span>
        )}
        <Button
          variant="ghost"
          size="sm"
          className={cn(
            "ml-auto h-6 shrink-0 px-1.5 text-[11px]",
            showAllEdges && "text-emerald-600 dark:text-emerald-400",
          )}
          onClick={onToggleAllEdges}
          title={
            showAllEdges
              ? "当前显示全部链路（含已停止），点击只看存活链路"
              : "当前只显示存活链路，点击显示全部链路"
          }
        >
          {showAllEdges ? "全部链路" : "仅存活"}
        </Button>
        <Button
          variant="ghost"
          size="icon"
          className="size-6 shrink-0"
          onClick={() => setOpen((v) => !v)}
          title={open ? "收起图例" : "展开图例"}
        >
          {open ? <ChevronUp className="size-3.5" /> : <ChevronDown className="size-3.5" />}
        </Button>
        <Button variant="ghost" size="icon" className="size-6 shrink-0" onClick={onRefresh} title="刷新">
          <RefreshCw className={cn("size-3.5", loading && "animate-spin")} />
        </Button>
      </div>
      {open && (
        <>
          {segments.length > 0 && (
            <div className="flex flex-wrap gap-x-3 gap-y-1.5">
              {segments.map((s) => (
                <span key={s.name} className="text-foreground inline-flex items-center gap-1.5">
                  <span className="size-3 rounded-full" style={{ backgroundColor: segmentColor(segments, s.name) }} />
                  {s.name}
                </span>
              ))}
            </div>
          )}
          <div className="border-border/60 text-muted-foreground flex flex-wrap gap-x-3 gap-y-1.5 border-t pt-2">
            <span className="inline-flex items-center gap-1.5">
              <span className="size-3 rounded-full border-2 border-red-700 bg-red-500 ring-2 ring-red-500/40" /> 主机已拿下
            </span>
            <span className="inline-flex items-center gap-1.5">
              <span className="size-3 rounded-full border border-white/70 bg-neutral-400" /> 主机未拿下
            </span>
            <span className="inline-flex items-center gap-1.5">
              <span className="size-2.5 rounded-full bg-red-500" /> 服务已拿下
            </span>
            <span className="inline-flex items-center gap-1.5">
              <span className="size-2.5 rounded-full bg-emerald-500" /> 服务未拿下
            </span>
            <span className="inline-flex items-center gap-1.5">
              <span className="flex size-3.5 items-center justify-center rounded-full bg-sky-600 text-[8px] font-bold text-white">
                W
              </span>
              <span className="flex size-3.5 items-center justify-center rounded-full bg-amber-600 text-[8px] font-bold text-white">
                L
              </span>
              Windows / Linux
            </span>
            <span className="inline-flex items-center gap-1.5">
              <span className="flex size-3 items-center justify-center rounded-full bg-slate-500">
                <svg viewBox="0 0 24 24" className="size-2 fill-white" aria-hidden="true">
                  <path d="M12 2.5l2.9 6.1 6.6.8-4.9 4.6 1.3 6.6-5.9-3.3-5.9 3.3 1.3-6.6-4.9-4.6 6.6-.8z" />
                </svg>
              </span>
              平台自身
            </span>
            <span className="inline-flex items-center gap-1.5">
              <span className="h-0.5 w-4 rounded-full bg-emerald-500" /> 存活隧道
            </span>
            <span className="inline-flex items-center gap-1.5">
              <span className="h-0 w-4 border-t-2 border-dashed border-neutral-400" /> 停止/失败
            </span>
            <span className="inline-flex items-center gap-1.5">
              <span className="h-0.5 w-4 rounded-full bg-neutral-300" /> 主机→服务
            </span>
          </div>
          <p className="text-muted-foreground/80 border-border/60 border-t pt-2 leading-relaxed">
            每个圆点是一台主机，外圈小点是它开放的服务（红=已拿下、绿=未拿下），主机被拿下时整点变红；W/L 角标区分 Windows /
            Linux。鼠标移到主机上会高亮它的一跳链路、其余自动淡出；点击主机可在下方「会话」页签过滤；支持拖拽节点、滚轮缩放，右上角可全屏。
          </p>
        </>
      )}
    </div>
  );
}
// TopologyGraph：内网拓扑画布。数据变化时重灌数据；全屏状态变化时重建画布，
// 保证全屏后节点按新尺寸重新铺开，而不是缩在角落。
export function TopologyGraph({
  data,
  sessions,
  tunnels,
  credentials,
  loading,
  onRefresh,
  onSelectHost,
}: {
  data: IntranetTopology | null;
  sessions: ShellSession[];
  tunnels: TunnelInfo[];
  credentials: Credential[];
  loading: boolean;
  onRefresh: () => void;
  onSelectHost: (nodeId: string) => void;
}) {
  const wrapRef = React.useRef<HTMLDivElement>(null);
  const containerRef = React.useRef<HTMLDivElement>(null);
  // 默认只显示存活链路（停止的隧道横穿全网段，很乱），可按需切回全部。
  const [showAllEdges, setShowAllEdges] = React.useState(false);
  const graphRef = React.useRef<G6Graph | null>(null);
  const gDataRef = React.useRef<{ nodes: G6NodeDatum[]; edges: G6EdgeDatum[] }>({ nodes: [], edges: [] });
  const dataRef = React.useRef<IntranetTopology | null>(null);
  const onSelectHostRef = React.useRef(onSelectHost);
  const [isFullscreen, setIsFullscreen] = React.useState(false);
  // 当前悬停的节点 id（主机或服务小圆点）→ 左下角明细面板。
  const [hovered, setHovered] = React.useState<string | null>(null);
  onSelectHostRef.current = onSelectHost;
  dataRef.current = data;
  // 建图回调（闭包）里读最新 segments 顺序解析网段色，保证图与图例同色。
  const segmentsRef = React.useRef<IntranetSegment[]>([]);
  segmentsRef.current = data?.segments ?? [];
  // applyData 是空依赖回调，用 ref 读最新开关值。
  const showAllRef = React.useRef(false);
  showAllRef.current = showAllEdges;

  // 主机点 + 服务小圆点 + 隧道边（平台 / 是否已拿下都在 buildModel 里判定）。
  const model = React.useMemo(
    () =>
      data
        ? buildModel(data, sessions, tunnels, credentials)
        : { nodes: [] as G6NodeDatum[], edges: [] as G6EdgeDatum[] },
    [data, sessions, tunnels, credentials],
  );

  // 结构签名：节点/边集合或其关键状态（平台、服务、是否已拿下）变化时才重灌数据重跑布局，
  // 避免轮询期无谓抖动。
  const sig = React.useMemo(() => {
    const ns = model.nodes
      .map(
        (n) =>
          `${n.id}:${n.compromised ? "c" : "-"}${n.platform}:${n.services
            .map((s) => `${s.port}${s.compromised ? "!" : ""}`)
            .join("/")}`,
      )
      .sort()
      .join(",");
    const es = model.edges
      .map((e) => `${e.source}>${e.target}:${e.state}${e.svcCompromised ? "!" : ""}`)
      .sort()
      .join(",");
    return `${ns}|${es}`;
  }, [model]);

  const stats = React.useMemo<TopologyStats>(() => {
    const hosts = model.nodes.filter((n) => !n.svc && !n.frame);
    const svc = model.nodes.filter((n) => n.svc);
    return {
      hosts: hosts.length,
      compromised: hosts.filter((h) => h.compromised).length,
      services: svc.length,
      servicesTaken: svc.filter((n) => n.svcCompromised).length,
      aliveEdges: data?.edges.filter((e) => e.state === "alive").length ?? 0,
      segments: data?.segments.length ?? 0,
    };
  }, [model, data]);

  // 悬停到服务小圆点时回溯到所属主机，面板始终按主机展示。
  const hoveredHost = React.useMemo(() => {
    if (!hovered) return null;
    const hit = model.nodes.find((n) => n.id === hovered);
    if (!hit) return null;
    if (hit.svc) return hit.hostId ? (model.nodes.find((n) => n.id === hit.hostId) ?? null) : null;
    return hit.frame ? null : hit;
  }, [hovered, model]);

  gDataRef.current = model;

  const applyData = React.useCallback(() => {
    const graph = graphRef.current;
    if (!graph || graph.destroyed) return;
    // 坐标自己算（图不配置 layout，G6 会保留数据里的坐标）：按网段分框 + 框内方阵 + 框间码放。
    const el = containerRef.current;
    const layout = computeLayout(
      gDataRef.current.nodes,
      el?.clientWidth ?? 0,
      el?.clientHeight ?? 0,
      segmentsRef.current,
    );
    const frameNodes: G6NodeDatum[] = layout.frames.map((f) => ({
      id: f.id,
      lbl: f.segment + " · " + f.count + " 台",
      segment: f.segment,
      hasSession: false,
      alive: 0,
      isCallback: false,
      size: 0,
      platform: "",
      compromised: false,
      services: [],
      frame: true,
      fw: f.w,
      fh: f.h,
      frameFill: f.color + "12",
      frameStroke: f.color + "73",
      type: "rect",
      style: { x: f.x + f.w / 2, y: f.y + f.h / 2 },
    }));
    // 默认只画存活链路：已停止的隧道是虚线且横穿全网段，是「线很乱」的主要来源。
    // 主机→服务的小枝杈（state "svc"）是本机内部连线，任何模式下都保留。
    const edges = showAllRef.current
      ? gDataRef.current.edges
      : gDataRef.current.edges.filter((e) => e.state === "alive" || e.state === "svc");
    // 主机坐标已定：服务小圆点绕主机按极坐标排一圈，从正上方开始顺时针。
    const svcByHost = new Map<string, string[]>();
    for (const n of gDataRef.current.nodes) {
      if (!n.svc || !n.hostId) continue;
      const list = svcByHost.get(n.hostId);
      if (list) list.push(n.id);
      else svcByHost.set(n.hostId, [n.id]);
    }
    const svcPos = new Map<string, { x: number; y: number }>();
    for (const [hostId, ids] of svcByHost) {
      const center = layout.pos.get(hostId);
      if (!center) continue;
      const hostSize = gDataRef.current.nodes.find((n) => n.id === hostId)?.size ?? HOST_SIZE;
      const ringR = ringRFor(hostSize);
      ids.forEach((id, i) => {
        const angle = -Math.PI / 2 + (i / ids.length) * Math.PI * 2;
        svcPos.set(id, {
          x: center.x + Math.cos(angle) * ringR,
          y: center.y + Math.sin(angle) * ringR,
        });
      });
    }
    graph.setData({
      nodes: [
        ...frameNodes,
        ...gDataRef.current.nodes.map((n) => ({
          ...n,
          style: { ...n.style, ...(layout.pos.get(n.id) ?? svcPos.get(n.id) ?? {}) },
        })),
      ],
      edges,
    });
    // render() 异步跑布局；组件在布局落地前卸载时 G6 会在已清空的 context 中
    // 访问 transform 抛错（纯 teardown 竞态），吞掉即可；真正的渲染错误仍打日志。
    void graph.render().catch((err) => {
      if (!graph.destroyed) console.error("[intranet-topology] render:", err);
    });
  }, []);

  // 容器尺寸变化（进出全屏）后重新适配视口。
  const refit = React.useCallback(() => {
    const graph = graphRef.current;
    if (!graph || graph.destroyed) return;
    try {
      graph.resize();
    } catch {
      /* 容器尺寸未变时忽略 */
    }
    void graph.fitView({ when: "always", direction: "both" }).catch(() => {
      /* 布局尚未落地时忽略 */
    });
  }, []);
  // 建图：用真实容器像素算坐标；进出全屏（容器尺寸变化）时重建。
  // biome-ignore lint/correctness/useExhaustiveDependencies: isFullscreen 是刻意的重建触发依赖（坐标依赖容器尺寸）
  React.useEffect(() => {
    let destroyed = false;
    let graph: G6Graph | null = null;
    const el = containerRef.current;
    void (async () => {
      const { Graph } = await import("@antv/g6");
      if (destroyed || !el) return;
      graph = new Graph({
        container: el,
        autoResize: true,
        autoFit: { type: "view", options: { when: "always", direction: "both" } },
        padding: 48,
        background: "#f0f2f7",
        node: {
          style: {
            // 网段框用 [宽, 高]；主机/服务用直径。
            size: (d: unknown) => (nd(d).frame ? [nd(d).fw ?? 0, nd(d).fh ?? 0] : nd(d).size),
            // 框画在主机下面。
            zIndex: (d: unknown) => (nd(d).frame ? 0 : 1),
            radius: (d: unknown) => (nd(d).frame ? 12 : undefined),
            lineDash: (d: unknown) => (nd(d).frame ? [5, 4] : [0]),
            // 红 = 已拿下（主机 / 服务），绿 = 未拿下的服务；未拿下的主机保留网段色。
            fill: (d: unknown) => {
              const n = nd(d);
              if (n.frame) return n.frameFill;
              if (n.svc) return n.svcCompromised ? "#ef4444" : "#22c55e";
              if (n.isCallback) return "#475569";
              return n.compromised ? "#ef4444" : segmentColor(segmentsRef.current, n.segment);
            },
            stroke: (d: unknown) => {
              const n = nd(d);
              if (n.frame) return n.frameStroke;
              if (n.svc) return n.svcCompromised ? "#b91c1c" : "#15803d";
              if (n.compromised) return "#991b1b";
              return "rgba(255,255,255,0.9)";
            },
            lineWidth: (d: unknown) => {
              const n = nd(d);
              if (n.frame) return 1.2;
              if (n.svc) return 1.2;
              return n.compromised ? 4 : 1.5;
            },
            // 已拿下的主机加红色光晕，远看也能一眼区分。
            halo: (d: unknown) => !nd(d).frame && !nd(d).svc && nd(d).compromised,
            haloStroke: (d: unknown) => (nd(d).compromised ? "#ef4444" : "#2563eb"),
            haloLineWidth: 8,
            haloStrokeOpacity: 0.32,
            iconSrc: (d: unknown) => (nd(d).isCallback ? CALLBACK_ICON : HOST_ICON),
            iconWidth: (d: unknown) => (nd(d).frame || nd(d).svc ? 0 : Math.max(12, nd(d).size * 0.55)),
            iconHeight: (d: unknown) => (nd(d).frame || nd(d).svc ? 0 : Math.max(12, nd(d).size * 0.55)),
            // 服务小圆点不写标签（标签会把外圈糊满），明细看左下角悬停面板。
            labelText: (d: unknown) => (nd(d).svc ? "" : nd(d).lbl),
            labelPlacement: (d: unknown) => (nd(d).frame ? "left-top" : "bottom"),
            // 有服务的主机：标签让到外圈之下；没服务的紧贴圆点。
            labelOffsetY: (d: unknown) => {
              const n = nd(d);
              if (n.frame || n.svc) return 0;
              return n.services.length > 0 ? ringRFor(n.size) + 15 : n.size / 2 + 8;
            },
            labelFontSize: (d: unknown) => {
              const n = nd(d);
              if (n.frame) return 11;
              return n.compromised ? 12 : 11;
            },
            labelFontWeight: (d: unknown) => {
              const n = nd(d);
              if (n.frame) return 600;
              return n.compromised ? 700 : 500;
            },
            labelFill: (d: unknown) => {
              const n = nd(d);
              if (n.frame) return n.frameStroke;
              return n.compromised ? "#991b1b" : "#475569";
            },
            labelBackground: true,
            labelBackgroundFill: (d: unknown) => {
              const n = nd(d);
              if (n.frame) return "rgba(255,255,255,0.92)";
              return n.compromised ? "rgba(254,226,226,0.95)" : "rgba(255,255,255,0.85)";
            },
            labelBackgroundStroke: (d: unknown) => {
              const n = nd(d);
              if (n.frame) return n.frameStroke;
              return n.compromised ? "#ef4444" : "rgba(255,255,255,0.85)";
            },
            labelBackgroundLineWidth: 1,
            labelBackgroundRadius: 4,
            labelPadding: [1, 4],
            badge: true,
            badges: (d: unknown) => {
              const n = nd(d);
              if (n.frame || n.svc) return [];
              // 会话数角标：存活会话为绿色，仅剩历史记录（已停止）为琥珀色。
              const list: BadgeSpec[] = n.hasSession
                ? [
                    {
                      text: n.alive > 0 ? String(n.alive) : "!",
                      placement: "right-top",
                      fontSize: 10,
                      fontWeight: 700,
                      fill: "#fff",
                      padding: [1, 5],
                      backgroundFill: n.alive > 0 ? "#059669" : "#f59e0b",
                      backgroundRadius: 8,
                      backgroundStroke: "#ffffff",
                      backgroundLineWidth: 1.5,
                    },
                  ]
                : [];
              // 平台角标：W = Windows，L = Linux（会话指纹优先，其次开放端口启发式）。
              if (n.platform === "windows" || n.platform === "linux") {
                list.push({
                  text: n.platform === "windows" ? "W" : "L",
                  placement: "left-top",
                  fontSize: 9,
                  fontWeight: 700,
                  fill: "#fff",
                  padding: [1, 4],
                  backgroundFill: n.platform === "windows" ? "#0284c7" : "#d97706",
                  backgroundRadius: 6,
                  backgroundStroke: "#ffffff",
                  backgroundLineWidth: 1.5,
                });
              }
              return list;
            },
          },
          state: {
            // 悬停聚焦：命中的元素加深，其余元素整体变淡。
            active: { stroke: "#2563eb", lineWidth: 4, halo: true },
            dim: { opacity: 0.18 },
          },
        },        edge: {
          style: {
            // svc = 主机→服务短连线（红=该服务已拿下）；alive = 存活隧道；其余 = 已停止/失败。
            stroke: (d: unknown) => {
              const e = ed(d);
              if (e.state === "svc") return e.svcCompromised ? "#f87171" : "#cbd5e1";
              return e.state === "alive" ? "#10b981" : "#cbd5e1";
            },
            lineWidth: (d: unknown) => {
              const e = ed(d);
              if (e.state === "svc") return e.svcCompromised ? 1.5 : 1.1;
              return e.state === "alive" ? 1.8 : 1.2;
            },
            lineDash: (d: unknown) => (ed(d).state === "alive" || ed(d).state === "svc" ? [0] : [4, 4]),
            strokeOpacity: (d: unknown) => {
              const s = ed(d).state;
              if (s === "svc") return 0.65;
              return s === "alive" ? 0.72 : 0.5;
            },
            endArrow: false,
          },
          state: {
            active: { stroke: "#2563eb", lineWidth: 3.2, strokeOpacity: 1, lineDash: [0] },
            dim: { strokeOpacity: 0.06 },
          },
        },
        behaviors: ["drag-element", "drag-canvas", "zoom-canvas"],
      });
      graph.on("node:click", (evt: unknown) => {
        const id = (evt as { target?: { id?: string } }).target?.id;
        // 网段框、服务小圆点都不是主机，点它们不触发主机过滤。
        if (!id || id.startsWith("seg::") || id.startsWith("svc::")) return;
        // 全屏时先退出全屏，再按该主机过滤下方会话表。
        if (document.fullscreenElement === wrapRef.current) {
          void document.exitFullscreen().finally(() => onSelectHostRef.current(id));
        } else {
          onSelectHostRef.current(id);
        }
      });
      // 悬停聚焦：留住该主机的一跳链路（含外圈服务点）与所在网段框，其余整体变淡。
      // 悬停到服务小圆点时回溯到所属主机，等价于聚焦整台主机。
      const focusNeighborhood = (raw: string | null) => {
        if (!graph || graph.destroyed) return;
        const anchor = (() => {
          if (!raw || raw.startsWith("seg::")) return null;
          if (raw.startsWith("svc::")) {
            const rest = raw.slice(5);
            const sep = rest.indexOf("::");
            return sep >= 0 ? rest.slice(0, sep) : null;
          }
          return raw;
        })();
        const nodeIds = graph.getNodeData().map((n) => String(n.id));
        const edgeIds = graph.getEdgeData().map((e) => String(e.id));
        const edgeIdSet = new Set(edgeIds);
        const all = [...nodeIds, ...edgeIds];
        const states: Record<string, string[]> = {};
        for (const k of all) states[k] = [];
        if (anchor) {
          const keep = new Set<string>([anchor]);
          for (const e of gDataRef.current.edges) {
            if (e.source === anchor) keep.add(e.target);
            else if (e.target === anchor) keep.add(e.source);
          }
          const seg = gDataRef.current.nodes.find((n) => n.id === anchor)?.segment;
          if (seg) keep.add("seg::" + seg);
          for (const k of all) if (!keep.has(k)) states[k] = ["dim"];
          if (states[anchor]) states[anchor] = ["active"];
          if (raw && states[raw]) states[raw] = ["active"];
          for (const e of gDataRef.current.edges) {
            if ((e.source === anchor || e.target === anchor) && edgeIdSet.has(e.id)) {
              states[e.id] = ["active"];
            }
          }
        }
        void graph.setElementState(states).catch(() => {
          /* 图已销毁时忽略 */
        });
      };
      // 悬停高亮：进入主机/服务点即聚焦，落到空白画布或网段框上则淡出。
      // 注意 G6 在指针移到空白画布时不会触发 node:pointerleave，
      // 必须靠画布级的 canvas:pointermove / canvas:pointerleave 兜底，否则高亮会卡住不还原。
      let hoverTimer = 0;
      let hoveredId: string | null = null;
      const nodeIdOf = (evt: unknown): string | null => {
        const e = evt as { targetType?: string; target?: { id?: string } };
        const id = e.targetType === "node" ? e.target?.id : undefined;
        return id && !id.startsWith("seg::") ? id : null;
      };
      const setHover = (id: string | null) => {
        if (id === hoveredId) return;
        hoveredId = id;
        setHovered(id);
        focusNeighborhood(id);
      };
      // 延迟清空：避免在主机圆点与其标签之间移动时反复闪烁。
      const queueClear = () => {
        window.clearTimeout(hoverTimer);
        hoverTimer = window.setTimeout(() => setHover(null), 60);
      };
      graph.on("node:pointerenter", (evt: unknown) => {
        const id = nodeIdOf(evt);
        if (!id) {
          queueClear();
          return;
        }
        window.clearTimeout(hoverTimer);
        setHover(id);
      });
      graph.on("canvas:pointermove", () => queueClear());
      graph.on("canvas:pointerleave", () => {
        window.clearTimeout(hoverTimer);
        setHover(null);
      });
      graphRef.current = graph;
      applyData();
    })();
    return () => {
      destroyed = true;
      // 先停布局再销毁：尽量缩短「布局在飞、context 被清空」的竞态窗口。
      try {
        graph?.stopLayout();
      } catch {
        /* 图可能尚未建成或已无布局上下文 */
      }
      graph?.destroy();
      graphRef.current = null;
    };
  }, [applyData, isFullscreen]);
  // 全屏状态同步；尺寸稳定后再适配一次，避免浏览器全屏动画期间量到旧尺寸。
  React.useEffect(() => {
    const onChange = () => {
      setIsFullscreen(document.fullscreenElement === wrapRef.current);
      window.setTimeout(refit, 160);
    };
    document.addEventListener("fullscreenchange", onChange);
    return () => document.removeEventListener("fullscreenchange", onChange);
  }, [refit]);

  const toggleFullscreen = React.useCallback(() => {
    const el = wrapRef.current;
    if (!el) return;
    if (document.fullscreenElement === el) {
      void document.exitFullscreen();
      return;
    }
    void el.requestFullscreen().catch(() => {
      /* 浏览器拒绝全屏时保持原状 */
    });
  }, []);

  // 数据变化 → 重新灌数据 + 布局。sig 只作重排触发器（applyData 读 gDataRef）。
  // biome-ignore lint/correctness/useExhaustiveDependencies: sig 是刻意的重排触发依赖
  React.useEffect(() => {
    applyData();
  }, [sig, applyData]);

  const empty = !data || data.nodes.length === 0;

  return (
    <div
      ref={wrapRef}
      className={cn("relative bg-[#f0f2f7]", isFullscreen ? "h-screen w-screen" : "h-full w-full")}
    >
      <div ref={containerRef} className="h-full w-full" />
      {empty && (
        <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
          <span className="text-muted-foreground text-sm">
            {loading ? "加载中…" : "暂无内网拓扑数据，内网探测到主机后会在这里显示"}
          </span>
        </div>
      )}
      {hoveredHost && (
        <div className="bg-card/95 pointer-events-none absolute bottom-3 left-3 max-w-[min(92%,320px)] rounded-lg border p-2.5 text-xs shadow-sm backdrop-blur">
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <span className="text-foreground font-semibold">{hoveredHost.lbl}</span>
            <span
              className={cn(
                "inline-flex items-center rounded px-1 py-px text-[10px] font-semibold text-white",
                platformBadgeClass(hoveredHost.platform),
              )}
            >
              {platformLabel(hoveredHost.platform)}
            </span>
            <span
              className={cn(
                "inline-flex items-center gap-1",
                hoveredHost.compromised ? "text-red-600 dark:text-red-400" : "text-muted-foreground",
              )}
            >
              <span
                className={cn(
                  "size-2 rounded-full",
                  hoveredHost.compromised ? "bg-red-500" : "bg-neutral-400",
                )}
              />
              {hoveredHost.compromised ? "主机已拿下" : "主机未拿下"}
            </span>
          </div>
          {hoveredHost.services.length > 0 ? (
            <ul className="mt-1.5 flex flex-wrap gap-x-3 gap-y-1">
              {hoveredHost.services.map((s) => (
                <li key={s.port} className="inline-flex items-center gap-1 whitespace-nowrap">
                  <span
                    className={cn("size-2 rounded-full", s.compromised ? "bg-red-500" : "bg-emerald-500")}
                  />
                  <span className="text-muted-foreground">
                    {s.service || "端口"}
                    <span className="text-foreground/70">:{s.port}</span>
                  </span>
                  <span
                    className={cn(
                      s.compromised
                        ? "text-red-600 dark:text-red-400"
                        : "text-emerald-600 dark:text-emerald-500",
                    )}
                  >
                    {s.compromised ? "已拿下" : "未拿下"}
                  </span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-muted-foreground mt-1">未探测到开放服务</p>
          )}
        </div>
      )}
      <div className="pointer-events-auto absolute top-3 right-3 flex items-center gap-1.5">
        <Button
          variant="outline"
          size="sm"
          className="bg-card/95 h-7 gap-1 px-2 text-xs shadow-sm backdrop-blur"
          onClick={toggleFullscreen}
          title={isFullscreen ? "退出全屏（Esc）" : "全屏查看拓扑"}
        >
          {isFullscreen ? <Minimize2 className="size-3.5" /> : <Maximize2 className="size-3.5" />}
          {isFullscreen ? "退出全屏" : "全屏"}
        </Button>
      </div>
      <TopologyLegend
        data={data}
        stats={stats}
        loading={loading}
        onRefresh={onRefresh}
        showAllEdges={showAllEdges}
        onToggleAllEdges={() => setShowAllEdges((v) => !v)}
      />
    </div>
  );
}
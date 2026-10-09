"use client";

import * as React from "react";

import type { Graph as G6Graph } from "@antv/g6";
import { ChevronDown, ChevronUp, Maximize2, Minimize2, RefreshCw } from "lucide-react";

import { Button } from "@/components/ui/button";
import type { IntranetSegment, IntranetTopology } from "@/lib/types";
import { cn } from "@/lib/utils";

// 网段配色盘：按 segments 顺序取色，超出循环复用。
const SEGMENT_PALETTE = [
  "#3b82f6",
  "#10b981",
  "#f59e0b",
  "#8b5cf6",
  "#f43f5e",
  "#06b6d4",
  "#84cc16",
  "#f97316",
  "#ec4899",
  "#14b8a6",
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
type G6NodeDatum = {
  id: string;
  lbl: string;
  segment: string;
  hasSession: boolean;
  alive: number;
  isCallback: boolean;
  size: number;
  /** 网段框（不是主机）：只画底框 + 标题，不画图标、不带角标。 */
  frame?: boolean;
  fw?: number;
  fh?: number;
  frameFill?: string;
  frameStroke?: string;
  /** G6 节点图形类型：主机 circle，网段框 rect。 */
  type?: string;
  style?: { x?: number; y?: number };
};
type G6EdgeDatum = { source: string; target: string; state: string };

const nd = (d: unknown) => d as G6NodeDatum;
const ed = (d: unknown) => d as G6EdgeDatum;

// 已取得权限（有会话记录）的主机明显放大 + 绿色光晕；平台自身保持星形中等尺寸。
const SESSION_SIZE = 44;
const CALLBACK_SIZE = 32;
const HOST_SIZE = 26;

function nodeSizeFor(n: { has_session: boolean; is_callback: boolean }): number {
  if (n.has_session) return SESSION_SIZE;
  if (n.is_callback) return CALLBACK_SIZE;
  return HOST_SIZE;
}

function toG6(data: IntranetTopology): { nodes: G6NodeDatum[]; edges: G6EdgeDatum[] } {
  return {
    nodes: (data.nodes ?? []).map((n) => ({
      id: n.id,
      lbl: n.alive_sessions > 0 ? `${n.ip} (${n.alive_sessions})` : n.ip || n.id,
      segment: n.segment,
      hasSession: n.has_session,
      alive: n.alive_sessions,
      isCallback: n.is_callback,
      size: nodeSizeFor(n),
      type: "circle",
    })),
    edges: (data.edges ?? []).map((e) => ({ source: e.from, target: e.to, state: e.state })),
  };
}

// 布局策略：有链路时按层级排（dagre），无链路时按容器长宽比排成规整网格。
// 布局：按 /24 网段分组，一个网段一个框，主机装在框里；框与框之间按货架方式紧凑码放。
// 这样「哪几台同段」「哪几台已经拿到权限」一眼可见，也不会像力导向那样撒得到处都是。
const CELL_W = 132;
const CELL_H = 92;
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
    id: "seg::" + segment,
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
function computeLayout(
  nodes: G6NodeDatum[],
  width: number,
  height: number,
  segments: IntranetSegment[],
) {
  const pos = new Map<string, { x: number; y: number }>();
  const bySegment = new Map<string, G6NodeDatum[]>();
  for (const n of nodes) {
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

function TopologyLegend({
  data,
  loading,
  onRefresh,
}: {
  data: IntranetTopology | null;
  loading: boolean;
  onRefresh: () => void;
}) {
  // 默认收起，先把画布让出来；需要看网段配色时再展开。
  const [open, setOpen] = React.useState(false);
  const segments = data?.segments ?? [];
  const nodeCount = data?.nodes.length ?? 0;
  const aliveEdges = data?.edges.filter((e) => e.state === "alive").length ?? 0;
  const sessionHosts = data?.nodes.filter((n) => n.has_session).length ?? 0;
  return (
    <div className="bg-card/95 pointer-events-auto absolute top-3 left-3 flex max-w-[min(92%,420px)] flex-col gap-2 rounded-lg border p-2.5 text-xs shadow-sm backdrop-blur">
      <div className="flex items-center gap-2">
        {data ? (
          <span className="text-muted-foreground inline-flex flex-wrap items-center gap-x-2.5 gap-y-1">
            <span className="whitespace-nowrap">
              主机 <span className="text-foreground font-semibold tabular-nums">{nodeCount}</span>
            </span>
            <span className="inline-flex items-center gap-1 whitespace-nowrap">
              <span className="size-2.5 rounded-full bg-emerald-500 ring-2 ring-emerald-500/30" />
              有权限
              <span className="font-semibold tabular-nums text-emerald-600 dark:text-emerald-400">
                {sessionHosts}
              </span>
            </span>
            <span className="whitespace-nowrap">
              链路{" "}
              <span className="font-semibold tabular-nums text-emerald-600 dark:text-emerald-400">{aliveEdges}</span>
            </span>
            <span className="whitespace-nowrap">
              网段 <span className="text-foreground font-semibold tabular-nums">{segments.length}</span>
            </span>
          </span>
        ) : (
          <span className="text-muted-foreground">{loading ? "加载中…" : "暂无拓扑数据"}</span>
        )}
        <Button
          variant="ghost"
          size="icon"
          className="ml-auto size-6 shrink-0"
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
              <span className="size-3 rounded-full border-2 border-emerald-600 bg-emerald-500/30 ring-2 ring-emerald-500/40" />{" "}
              有存活会话
            </span>
            <span className="inline-flex items-center gap-1.5">
              <span className="size-3 rounded-full border border-white/70 bg-neutral-400" /> 无会话
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
          </div>
          <p className="text-muted-foreground/80 border-border/60 border-t pt-2 leading-relaxed">
            点击主机节点可在下方「会话」页签中过滤该主机的会话；支持拖拽节点、滚轮缩放，右上角可全屏。
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
  loading,
  onRefresh,
  onSelectHost,
}: {
  data: IntranetTopology | null;
  loading: boolean;
  onRefresh: () => void;
  onSelectHost: (nodeId: string) => void;
}) {
  const wrapRef = React.useRef<HTMLDivElement>(null);
  const containerRef = React.useRef<HTMLDivElement>(null);
  const graphRef = React.useRef<G6Graph | null>(null);
  const gDataRef = React.useRef<{ nodes: G6NodeDatum[]; edges: G6EdgeDatum[] }>({ nodes: [], edges: [] });
  const dataRef = React.useRef<IntranetTopology | null>(null);
  const onSelectHostRef = React.useRef(onSelectHost);
  const [isFullscreen, setIsFullscreen] = React.useState(false);
  onSelectHostRef.current = onSelectHost;
  dataRef.current = data;
  // 建图回调（闭包）里读最新 segments 顺序解析网段色，保证图与图例同色。
  const segmentsRef = React.useRef<IntranetSegment[]>([]);
  segmentsRef.current = data?.segments ?? [];

  // 结构签名：节点/边集合或其关键状态变化时才重灌数据重跑布局，避免轮询期无谓抖动。
  const sig = React.useMemo(() => {
    if (!data) return "";
    const ns = data.nodes
      .map((n) => `${n.id}:${n.has_session ? "s" : "-"}${n.alive_sessions}${n.is_callback ? "c" : ""}`)
      .sort()
      .join(",");
    const es = data.edges
      .map((e) => `${e.from}>${e.to}:${e.state}`)
      .sort()
      .join(",");
    return `${ns}|${es}`;
  }, [data]);

  gDataRef.current = data ? toG6(data) : { nodes: [], edges: [] };

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
      frame: true,
      fw: f.w,
      fh: f.h,
      frameFill: f.color + "12",
      frameStroke: f.color + "73",
      type: "rect",
      style: { x: f.x + f.w / 2, y: f.y + f.h / 2 },
    }));
    graph.setData({
      nodes: [
        ...frameNodes,
        ...gDataRef.current.nodes.map((n) => ({
          ...n,
          style: { ...n.style, ...(layout.pos.get(n.id) ?? {}) },
        })),
      ],
      edges: gDataRef.current.edges,
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
            // 网段框用 [宽, 高]；主机用直径。
            size: (d: unknown) => (nd(d).frame ? [nd(d).fw ?? 0, nd(d).fh ?? 0] : nd(d).size),
            // 框画在主机下面。
            zIndex: (d: unknown) => (nd(d).frame ? 0 : 1),
            radius: (d: unknown) => (nd(d).frame ? 12 : undefined),
            lineDash: (d: unknown) => (nd(d).frame ? [5, 4] : [0]),
            fill: (d: unknown) => {
              const n = nd(d);
              if (n.frame) return n.frameFill;
              return n.isCallback ? "#475569" : segmentColor(segmentsRef.current, n.segment);
            },
            stroke: (d: unknown) => {
              const n = nd(d);
              if (n.frame) return n.frameStroke;
              return n.hasSession ? "#047857" : "rgba(255,255,255,0.9)";
            },
            lineWidth: (d: unknown) => {
              const n = nd(d);
              if (n.frame) return 1.2;
              return n.hasSession ? 4 : 1.5;
            },
            // 已取得权限的主机加绿色光晕，远看也能一眼区分。
            halo: (d: unknown) => !nd(d).frame && nd(d).hasSession,
            haloStroke: "#10b981",
            haloLineWidth: 14,
            haloStrokeOpacity: 0.35,
            iconSrc: (d: unknown) => (nd(d).isCallback ? CALLBACK_ICON : HOST_ICON),
            iconWidth: (d: unknown) => (nd(d).frame ? 0 : Math.max(12, nd(d).size * 0.55)),
            iconHeight: (d: unknown) => (nd(d).frame ? 0 : Math.max(12, nd(d).size * 0.55)),
            labelText: (d: unknown) => nd(d).lbl,
            labelPlacement: (d: unknown) => (nd(d).frame ? "left-top" : "bottom"),
            labelFontSize: (d: unknown) => (nd(d).frame ? 11 : nd(d).hasSession ? 12 : 11),
            labelFontWeight: (d: unknown) => (nd(d).frame ? 600 : nd(d).hasSession ? 700 : 500),
            labelFill: (d: unknown) => {
              const n = nd(d);
              if (n.frame) return n.frameStroke;
              return n.hasSession ? "#065f46" : "#475569";
            },
            labelBackground: true,
            labelBackgroundFill: (d: unknown) => {
              const n = nd(d);
              if (n.frame) return "rgba(255,255,255,0.92)";
              return n.hasSession ? "rgba(209,250,229,0.95)" : "rgba(255,255,255,0.85)";
            },
            labelBackgroundStroke: (d: unknown) => {
              const n = nd(d);
              if (n.frame) return n.frameStroke;
              return n.hasSession ? "#10b981" : "rgba(255,255,255,0.85)";
            },
            labelBackgroundLineWidth: 1,
            labelBackgroundRadius: 4,
            labelPadding: [1, 4],
            // 会话数角标：存活会话为绿色，仅剩历史记录（已停止）为琥珀色。
            badge: true,
            badges: (d: unknown) => {
              const n = nd(d);
              if (n.frame || !n.hasSession) return [];
              return [
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
              ];
            },
          },
        },

        edge: {
          style: {
            stroke: (d: unknown) => (ed(d).state === "alive" ? "#10b981" : "#94a3b8"),
            lineWidth: (d: unknown) => (ed(d).state === "alive" ? 2 : 1.6),
            lineDash: (d: unknown) => (ed(d).state === "alive" ? [0] : [5, 4]),
            endArrow: false,
          },
        },
        behaviors: ["drag-element", "drag-canvas", "zoom-canvas"],
      });
      graph.on("node:click", (evt: unknown) => {
        const id = (evt as { target?: { id?: string } }).target?.id;
        // 网段框不是主机，点它不触发主机过滤。
        if (!id || id.startsWith("seg::")) return;
        // 全屏时先退出全屏，再按该主机过滤下方会话表。
        if (document.fullscreenElement === wrapRef.current) {
          void document.exitFullscreen().finally(() => onSelectHostRef.current(id));
        } else {
          onSelectHostRef.current(id);
        }
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
      <TopologyLegend data={data} loading={loading} onRefresh={onRefresh} />
    </div>
  );
}

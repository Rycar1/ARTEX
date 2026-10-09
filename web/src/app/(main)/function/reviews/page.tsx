"use client";

import * as React from "react";

import Link from "next/link";

import { RefreshCwIcon } from "lucide-react";
import { toast } from "sonner";

import { TablePagination } from "@/components/table-pagination";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Spinner } from "@/components/ui/spinner";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api } from "@/lib/api";
import { statusMeta, toneClasses, type Tone } from "@/lib/status";
import type { Finding, ReviewStats, ReviewVerdict } from "@/lib/types";
import { cn } from "@/lib/utils";

// 二次审核页:展示 AI 二次审核的结论分布,按结论筛选发现,并支持手动重审。
// 审核结论由后端写入 findings.review_* 列(见 server/finding_review.go)。
type ReviewFilter = "all" | "pending" | ReviewVerdict;

const REVIEW_TABS: { value: ReviewFilter; label: string }[] = [
  { value: "all", label: "全部" },
  { value: "pending", label: "待审核" },
  { value: "accepted", label: "已收录" },
  { value: "ignored", label: "已忽略" },
  { value: "deepen", label: "建议深挖" },
];

const VERDICT_META: Record<ReviewVerdict, { label: string; tone: Tone }> = {
  accepted: { label: "收录", tone: "green" },
  ignored: { label: "忽略", tone: "neutral" },
  deepen: { label: "深挖", tone: "violet" },
};

function fmtTime(ts?: string): string {
  if (!ts) return "-";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toLocaleString();
}

export default function FindingReviewsPage() {
  const [stats, setStats] = React.useState<ReviewStats | null>(null);
  const [filter, setFilter] = React.useState<ReviewFilter>("all");
  const [page, setPage] = React.useState(1);
  const [pageSize, setPageSize] = React.useState(20);
  const [items, setItems] = React.useState<Finding[]>([]);
  const [total, setTotal] = React.useState(0);
  const [loading, setLoading] = React.useState(true);
  const [busy, setBusy] = React.useState<string | null>(null);

  const loadStats = React.useCallback(() => {
    api
      .reviewStats()
      .then(setStats)
      .catch(() => setStats(null));
  }, []);

  const loadList = React.useCallback(() => {
    setLoading(true);
    api
      .findingsPage({ page, pageSize, review: filter })
      .then((r) => {
        setItems(r.items ?? []);
        setTotal(r.total ?? 0);
      })
      .catch((e) => toast.error("加载失败：" + (e as Error).message))
      .finally(() => setLoading(false));
  }, [page, pageSize, filter]);

  React.useEffect(() => {
    loadStats();
  }, [loadStats]);

  React.useEffect(() => {
    loadList();
  }, [loadList]);

  async function reReview(f: Finding) {
    const id = f.finding_id ?? f.id;
    setBusy(id);
    try {
      const r = await api.reviewFinding(id);
      const meta = r.verdict ? VERDICT_META[r.verdict] : undefined;
      toast.success("审核完成：" + (meta?.label ?? r.verdict ?? "已审核"));
      loadList();
      loadStats();
    } catch (e) {
      toast.error("审核失败：" + (e as Error).message);
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="p-4 md:p-6">
      <div className="mb-4">
        <h1 className="font-semibold text-xl">二次审核</h1>
        <p className="text-muted-foreground text-sm">
          AI 按企业 SRC / EduSRC 收录标准复核每条漏洞；不符合标准的自动标记为「忽略」并注明原因。
        </p>
      </div>

      <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-5">
        <StatCard label="已审核" value={stats?.total ?? 0} />
        <StatCard label="收录" value={stats?.accepted ?? 0} />
        <StatCard label="忽略" value={stats?.ignored ?? 0} />
        <StatCard label="建议深挖" value={stats?.deepen ?? 0} />
        <StatCard label="待审核" value={stats?.pending ?? 0} highlight />
      </div>

      <Tabs
        value={filter}
        onValueChange={(v) => {
          setFilter(v as ReviewFilter);
          setPage(1);
        }}
      >
        <TabsList>
          {REVIEW_TABS.map((t) => (
            <TabsTrigger key={t.value} value={t.value}>
              {t.label}
            </TabsTrigger>
          ))}
        </TabsList>
      </Tabs>

      <Card className="mt-4 gap-0 overflow-hidden py-0">
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-20">严重度</TableHead>
                  <TableHead>漏洞</TableHead>
                  <TableHead className="w-40">任务</TableHead>
                  <TableHead className="w-24">审核结论</TableHead>
                  <TableHead className="w-16">评分</TableHead>
                  <TableHead>原因 / 备注</TableHead>
                  <TableHead className="w-36">审核时间</TableHead>
                  <TableHead className="w-24 text-right">操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {loading ? (
                  <TableRow>
                    <TableCell colSpan={8} className="h-32 text-center">
                      <Spinner className="mx-auto" />
                    </TableCell>
                  </TableRow>
                ) : items.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={8} className="text-muted-foreground h-32 text-center text-sm">
                      暂无数据
                    </TableCell>
                  </TableRow>
                ) : (
                  items.map((f) => {
                    const rowId = f.finding_id ?? f.id;
                    const sev = statusMeta("severity", f.severity);
                    const verdict = (f.review_verdict ?? "") as ReviewVerdict | "";
                    const vm = verdict ? VERDICT_META[verdict] : undefined;
                    return (
                      <TableRow key={rowId}>
                        <TableCell>
                          <span className={cn("inline-flex rounded-md border px-2 py-0.5 text-xs", toneClasses[sev.tone])}>
                            {sev.label}
                          </span>
                        </TableCell>
                        <TableCell>
                          <Link
                            href={`/function/findings/detail?id=${encodeURIComponent(rowId)}`}
                            className="font-medium hover:underline"
                          >
                            {f.name || f.vulnclass || "(未命名)"}
                          </Link>
                          <div className="text-muted-foreground line-clamp-1 text-xs">{f.summary}</div>
                        </TableCell>
                        <TableCell className="text-muted-foreground max-w-40 truncate text-xs">
                          {f.task_description || f.task_id || "-"}
                        </TableCell>
                        <TableCell>
                          {vm ? (
                            <span className={cn("inline-flex rounded-md border px-2 py-0.5 text-xs", toneClasses[vm.tone])}>
                              {vm.label}
                            </span>
                          ) : (
                            <span className="text-muted-foreground text-xs">未审核</span>
                          )}
                        </TableCell>
                        <TableCell className="tabular-nums text-xs">
                          {typeof f.review_score === "number" ? f.review_score.toFixed(1) : "-"}
                        </TableCell>
                        <TableCell className="max-w-72 text-xs">
                          <span className="text-muted-foreground line-clamp-2">
                            {f.review_reasons || f.review_notes || "-"}
                          </span>
                        </TableCell>
                        <TableCell className="text-muted-foreground text-xs">{fmtTime(f.reviewed_at)}</TableCell>
                        <TableCell className="text-right">
                          <Button size="sm" variant="outline" disabled={busy === rowId} onClick={() => reReview(f)}>
                            {busy === rowId ? (
                              <Spinner data-icon="inline-start" />
                            ) : (
                              <RefreshCwIcon data-icon="inline-start" />
                            )}
                            重审
                          </Button>
                        </TableCell>
                      </TableRow>
                    );
                  })
                )}
              </TableBody>
            </Table>
          </div>
          <TablePagination
            page={page}
            pageSize={pageSize}
            total={total}
            onPageChange={setPage}
            onPageSizeChange={(s) => {
              setPageSize(s);
              setPage(1);
            }}
          />
        </CardContent>
      </Card>
    </div>
  );
}

function StatCard({ label, value, highlight }: { label: string; value: number; highlight?: boolean }) {
  return (
    <Card className="py-3">
      <CardContent className="px-4">
        <div className="text-muted-foreground text-xs">{label}</div>
        <div
          className={cn(
            "mt-1 font-semibold text-2xl tabular-nums",
            highlight && value > 0 && "text-amber-600 dark:text-amber-400",
          )}
        >
          {value}
        </div>
      </CardContent>
    </Card>
  );
}
"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useScans } from "@/hooks/useScans";
import { cn } from "@/lib/utils";
import { formatDistanceToNow } from "date-fns";

const STATUS_CONFIG = {
  completed: { icon: "check_circle",  color: "#008a44",           label: "COMPLETED" },
  running:   { icon: "sync",          color: "var(--sc-brand)",   label: "RUNNING"   },
  pending:   { icon: "hourglass_top", color: "var(--sc-warn)",    label: "QUEUED"    },
  failed:    { icon: "cancel",        color: "var(--sc-error)",   label: "FAILED"    },
} as const;

const ICON_FOR_TARGET = (t: string) => {
  if (t.includes("http") || t.includes(".")) return "language";
  if (/^\d+\.\d+/.test(t)) return "dns";
  return "router";
};

function severityBadges(scan: { risk_score: number | null; status: string }) {
  const score = scan.risk_score ?? 0;
  if (scan.status !== "completed" || score === 0) return null;
  const crit = score >= 80 ? 1 : 0;
  const high = score >= 60 ? 1 : 0;
  const med  = score >= 40 ? 1 : 0;
  return (
    <div className="flex flex-wrap gap-1.5">
      {crit > 0 && (
        <span
          className="flex items-center gap-1 px-2 py-0.5 rounded font-mono"
          style={{
            fontSize: 10, fontWeight: 700,
            background: "var(--sc-err-bg)", color: "var(--sc-err-on)",
            border: "1px solid rgba(186,26,26,0.2)",
          }}
        >
          <span className="w-1.5 h-1.5 rounded-full inline-block" style={{ background: "var(--sc-error)" }} />
          CRITICAL
        </span>
      )}
      {high > 0 && !crit && (
        <span
          className="flex items-center gap-1 px-2 py-0.5 rounded font-mono"
          style={{
            fontSize: 10, fontWeight: 700,
            background: "var(--sc-warn-bg)", color: "var(--sc-warn)",
            border: "1px solid rgba(217,95,0,0.2)",
          }}
        >
          HIGH
        </span>
      )}
      {med > 0 && !high && !crit && (
        <span
          className="px-2 py-0.5 rounded font-mono"
          style={{
            fontSize: 10, fontWeight: 700,
            background: "var(--sc-low)", color: "var(--sc-on-v)",
            border: "1px solid var(--sc-border)",
          }}
        >
          MEDIUM
        </span>
      )}
      <span
        className="px-2 py-0.5 rounded font-mono"
        style={{
          fontSize: 10,
          background: "var(--sc-low)", color: "var(--sc-on-v)",
          border: "1px solid var(--sc-border)",
        }}
      >
        SCORE: {score}
      </span>
    </div>
  );
}

const PAGE_SIZE = 10;

export default function HistoryPage() {
  const [search, setSearch]       = useState("");
  const [statusFilter, setFilter] = useState("all");
  const [page, setPage]           = useState(0);
  const { data, isLoading, error, refetch, isFetching } = useScans(0, 200);

  const scans    = data?.items ?? [];
  const filtered = scans.filter((s) => {
    const matchSearch = s.target.toLowerCase().includes(search.toLowerCase()) ||
                        s.id.toLowerCase().includes(search.toLowerCase());
    const matchStatus = statusFilter === "all" || s.status === statusFilter;
    return matchSearch && matchStatus;
  });

  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const paginated = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  const avgTime   = "-";
  const success   = scans.length > 0
    ? Math.round((scans.filter((s) => s.status === "completed").length / scans.length) * 1000) / 10
    : 0;
  const openVulns = scans.filter((s) => s.status === "completed" && (s.risk_score ?? 0) >= 70).length;

  return (
    <div
      className="min-h-full"
      style={{ background: "var(--sc-bg)", fontFamily: "'Geist', sans-serif", color: "var(--sc-on)" }}
    >
      {/* Top bar */}
      <header
        className="sticky top-0 h-16 flex justify-between items-center px-4 z-40"
        style={{ background: "var(--sc-bg)", borderBottom: "1px solid var(--sc-border)" }}
      >
        <span className="font-bold tracking-tight" style={{ fontSize: 20, color: "var(--sc-on)" }}>
          Aegis Pentest
        </span>
        <div className="flex items-center gap-4">
          {["notifications", "wifi_tethering", "account_tree"].map((icon) => (
            <button
              key={icon}
              className="transition-colors"
              style={{ color: "var(--sc-on-v)" }}
              onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.color = "var(--sc-brand)")}
              onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.color = "var(--sc-on-v)")}
            >
              <span className="material-symbols-outlined" style={{ fontSize: 20 }}>{icon}</span>
            </button>
          ))}
        </div>
      </header>

      <div className="p-4 max-w-[1400px] mx-auto space-y-6">

        {/* Page header */}
        <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 pt-2">
          <div>
            <h2 className="font-black tracking-tight" style={{ fontSize: 32, letterSpacing: "-0.02em" }}>
              Scan History
            </h2>
            <p style={{ fontSize: 14, color: "var(--sc-on-v)" }}>
              Audit trail of all executed security assessments.
            </p>
          </div>
          <div className="flex flex-wrap gap-3">
            {/* Search */}
            <div className="relative min-w-[280px]">
              <span
                className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2"
                style={{ fontSize: 18, color: "var(--sc-outline)" }}
              >
                search
              </span>
              <input
                type="text"
                value={search}
                onChange={(e) => { setSearch(e.target.value); setPage(0); }}
                placeholder="Search target, URL or scan ID..."
                className="w-full rounded-lg pl-10 pr-4 py-2 text-sm outline-none transition-all"
                style={{
                  background: "#ffffff",
                  border: "1px solid var(--sc-border)",
                  color: "var(--sc-on)",
                  fontFamily: "'Geist', sans-serif",
                }}
                onFocus={(e) => { e.currentTarget.style.borderColor = "var(--sc-brand)"; e.currentTarget.style.boxShadow = "0 0 0 3px rgba(0,81,213,0.08)"; }}
                onBlur={(e) =>  { e.currentTarget.style.borderColor = "var(--sc-border)"; e.currentTarget.style.boxShadow = "none"; }}
              />
            </div>

            {/* Status filter */}
            <div className="flex gap-2">
              {["all", "completed", "running", "failed"].map((f) => (
                <button
                  key={f}
                  onClick={() => { setFilter(f); setPage(0); }}
                  className={cn(
                    "flex items-center gap-1.5 px-3 py-2 rounded-lg font-mono font-bold uppercase tracking-widest transition-all",
                  )}
                  style={{
                    fontSize: 11,
                    background: statusFilter === f ? "var(--sc-brand)" : "#ffffff",
                    color:      statusFilter === f ? "#ffffff" : "var(--sc-on-v)",
                    border:     statusFilter === f ? "1px solid var(--sc-brand)" : "1px solid var(--sc-border)",
                  }}
                >
                  {f}
                </button>
              ))}
            </div>

            {/* Refresh */}
            <button
              onClick={() => refetch()}
              disabled={isFetching}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg font-bold transition-all disabled:opacity-50"
              style={{
                fontSize: 12,
                background: "var(--sc-brand)",
                color: "#ffffff",
                border: "1px solid var(--sc-brand)",
              }}
            >
              <span
                className={cn("material-symbols-outlined", isFetching && "animate-spin")}
                style={{ fontSize: 16 }}
              >
                refresh
              </span>
              REFRESH
            </button>
          </div>
        </div>

        {/* Table */}
        <div
          className="rounded-xl overflow-hidden shadow-sm"
          style={{ background: "#ffffff", border: "1px solid var(--sc-border)" }}
        >
          <table className="w-full text-left border-collapse">
            <thead>
              <tr style={{ background: "var(--sc-low)", borderBottom: "1px solid var(--sc-border)" }}>
                {["Target Entity", "Execution Date", "Duration", "Risk / Score", "Status", "Actions"].map((h, i) => (
                  <th
                    key={h}
                    className="px-6 py-4 font-mono font-semibold uppercase tracking-wider"
                    style={{ fontSize: 11, color: "var(--sc-on-v)", textAlign: i === 5 ? "right" : "left" }}
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {isLoading && [...Array(5)].map((_, i) => (
                <tr key={i}>
                  <td colSpan={6} className="px-6 py-4">
                    <div className="stitch-skeleton h-8 rounded-lg" />
                  </td>
                </tr>
              ))}
              {error && (
                <tr>
                  <td colSpan={6} className="px-6 py-8 text-center">
                    <span className="material-symbols-outlined" style={{ fontSize: 28, color: "var(--sc-error)" }}>error</span>
                    <p style={{ fontSize: 13, color: "var(--sc-error)", marginTop: 8 }}>
                      Failed to load scans
                    </p>
                  </td>
                </tr>
              )}
              {!isLoading && !error && paginated.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-6 py-12 text-center">
                    <span className="material-symbols-outlined" style={{ fontSize: 36, color: "var(--sc-border)" }}>
                      history
                    </span>
                    <p style={{ fontSize: 14, color: "var(--sc-outline)", marginTop: 8 }}>
                      {search ? `No results for "${search}"` : "No scans yet"}
                    </p>
                    <Link
                      href="/dashboard/scans/new"
                      style={{ fontSize: 12, color: "var(--sc-brand)", marginTop: 8, display: "block" }}
                    >
                      Launch your first scan →
                    </Link>
                  </td>
                </tr>
              )}
              {!isLoading && paginated.map((scan) => {
                const cfg = STATUS_CONFIG[scan.status as keyof typeof STATUS_CONFIG] ?? STATUS_CONFIG.pending;
                const ago = formatDistanceToNow(new Date(scan.created_at), { addSuffix: true });
                const date = new Date(scan.created_at);
                return (
                  <tr
                    key={scan.id}
                    className="cursor-pointer transition-colors"
                    style={{ borderBottom: "1px solid rgba(198,198,205,0.3)" }}
                    onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.background = "var(--sc-low)")}
                    onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.background = "transparent")}
                    onClick={() => window.location.href = `/dashboard/scans/${scan.id}`}
                  >
                    {/* Target */}
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-3">
                        <div
                          className="w-10 h-10 rounded flex items-center justify-center shrink-0"
                          style={{ background: "var(--sc-brand-bg)", color: "var(--sc-brand)" }}
                        >
                          <span className="material-symbols-outlined" style={{ fontSize: 20 }}>
                            {ICON_FOR_TARGET(scan.target)}
                          </span>
                        </div>
                        <div>
                          <div className="font-semibold font-mono" style={{ fontSize: 14, color: "var(--sc-on)" }}>
                            {scan.target}
                          </div>
                          <div className="font-mono" style={{ fontSize: 10, color: "var(--sc-outline)" }}>
                            SCAN-ID: {scan.id.slice(0, 8).toUpperCase()}
                          </div>
                        </div>
                      </div>
                    </td>
                    {/* Date */}
                    <td className="px-6 py-4">
                      <div style={{ fontSize: 13, color: "var(--sc-on)" }}>
                        {date.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })}
                      </div>
                      <div className="font-mono" style={{ fontSize: 11, color: "var(--sc-outline)" }}>
                        {ago}
                      </div>
                    </td>
                    {/* Duration placeholder */}
                    <td className="px-6 py-4 font-mono" style={{ fontSize: 12, color: "var(--sc-on-v)" }}>
                      --
                    </td>
                    {/* Risk */}
                    <td className="px-6 py-4">
                      {severityBadges(scan) ?? (
                        <span className="italic" style={{ fontSize: 12, color: "var(--sc-outline)" }}>
                          {scan.status === "running" ? "In progress..." : "No data"}
                        </span>
                      )}
                    </td>
                    {/* Status */}
                    <td className="px-6 py-4">
                      <div
                        className="flex items-center gap-2 font-mono font-bold"
                        style={{ fontSize: 11, color: cfg.color }}
                      >
                        <span
                          className={cn("material-symbols-outlined", scan.status === "running" && "animate-spin")}
                          style={{ fontSize: 16 }}
                        >
                          {cfg.icon}
                        </span>
                        {cfg.label}
                      </div>
                    </td>
                    {/* Actions */}
                    <td className="px-6 py-4 text-right">
                      <button
                        className="p-2 rounded-full transition-colors"
                        style={{ color: "var(--sc-on-v)" }}
                        onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.background = "var(--sc-high)")}
                        onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.background = "transparent")}
                        onClick={(e) => {
                          e.stopPropagation();
                          window.location.href = `/dashboard/scans/${scan.id}`;
                        }}
                      >
                        <span className="material-symbols-outlined" style={{ fontSize: 20 }}>open_in_new</span>
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>

          {/* Pagination */}
          <div
            className="px-6 py-4 flex items-center justify-between"
            style={{ background: "var(--sc-low)", borderTop: "1px solid var(--sc-border)" }}
          >
            <span style={{ fontSize: 13, color: "var(--sc-on-v)" }}>
              Showing {paginated.length > 0 ? page * PAGE_SIZE + 1 : 0}--{Math.min((page + 1) * PAGE_SIZE, filtered.length)} of {filtered.length} scans
            </span>
            <div className="flex items-center gap-2">
              <button
                disabled={page === 0}
                onClick={() => setPage((p) => Math.max(0, p - 1))}
                className="p-2 rounded transition-colors disabled:opacity-30"
                style={{ border: "1px solid var(--sc-border)", color: "var(--sc-on-v)" }}
              >
                <span className="material-symbols-outlined" style={{ fontSize: 20 }}>chevron_left</span>
              </button>
              {Array.from({ length: Math.min(5, pageCount) }).map((_, i) => (
                <button
                  key={i}
                  onClick={() => setPage(i)}
                  className="w-8 h-8 rounded font-mono font-bold transition-all"
                  style={{
                    fontSize: 13,
                    background: page === i ? "var(--sc-brand)" : "transparent",
                    color:      page === i ? "#ffffff" : "var(--sc-on)",
                  }}
                >
                  {i + 1}
                </button>
              ))}
              <button
                disabled={page >= pageCount - 1}
                onClick={() => setPage((p) => Math.min(pageCount - 1, p + 1))}
                className="p-2 rounded transition-colors disabled:opacity-30"
                style={{ border: "1px solid var(--sc-border)", color: "var(--sc-on-v)" }}
              >
                <span className="material-symbols-outlined" style={{ fontSize: 20 }}>chevron_right</span>
              </button>
            </div>
          </div>
        </div>

        {/* Stats summary */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 pb-6">
          {[
            { label: "AVG SCAN TIME",       value: avgTime,            color: "var(--sc-brand)" },
            { label: "SUCCESS RATE",         value: `${success}%`,     color: "#008a44" },
            { label: "OPEN VULNERABILITIES", value: String(openVulns), color: "var(--sc-error)", highlight: true },
            { label: "TOTAL SCANS",          value: String(scans.length), color: "var(--sc-on)" },
          ].map(({ label, value, color, highlight }) => (
            <div
              key={label}
              className="p-6 rounded-xl shadow-sm"
              style={{
                background: "#ffffff",
                border: `1px solid ${highlight ? "rgba(186,26,26,0.3)" : "var(--sc-border)"}`,
                borderLeft: highlight ? "4px solid var(--sc-error)" : `1px solid var(--sc-border)`,
              }}
            >
              <p className="font-mono font-medium uppercase tracking-wide" style={{ fontSize: 11, color: "var(--sc-on-v)" }}>
                {label}
              </p>
              <p className="font-black mt-2" style={{ fontSize: 28, color }}>
                {value}
              </p>
            </div>
          ))}
        </div>
      </div>

      {/* Status bar */}
      <div
        className="fixed bottom-4 left-1/2 -translate-x-1/2 flex items-center px-4 py-2 gap-3 rounded-full shadow-lg pointer-events-none z-50"
        style={{
          background: "#ffffff",
          border: "1px solid rgba(0,81,213,0.2)",
          boxShadow: "0 4px 16px rgba(0,81,213,0.08)",
        }}
      >
        <div className="w-2 h-2 rounded-full animate-pulse" style={{ background: "var(--sc-brand)" }} />
        <p className="font-mono font-bold" style={{ fontSize: 11, color: "var(--sc-brand)" }}>
          SYSTEM MONITORING ACTIVE
        </p>
      </div>

      {/* FAB */}
      <Link
        href="/dashboard/scans/new"
        className="fixed bottom-8 right-8 w-14 h-14 rounded-full flex items-center justify-center shadow-xl transition-all active:scale-95 z-50 group"
        style={{ background: "var(--sc-brand)", color: "#ffffff" }}
        onMouseEnter={(e) => (e.currentTarget.style.transform = "scale(1.1)")}
        onMouseLeave={(e) => (e.currentTarget.style.transform = "scale(1)")}
      >
        <span className="material-symbols-outlined" style={{ fontSize: 28 }}>add</span>
        <div
          className="absolute right-16 px-3 py-1 rounded font-mono opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none whitespace-nowrap shadow-md"
          style={{ background: "var(--sc-on)", color: "#ffffff", fontSize: 11 }}
        >
          NEW SCAN
        </div>
      </Link>
    </div>
  );
}

"use client";

import React from "react";
import Link from "next/link";
import { useScan, useRetryScan } from "@/hooks/useScans";
import ProgressTracker from "@/components/ProgressTracker";
import LiveLogs from "@/components/LiveLogs";
import ScanResults from "@/components/ScanResults";
import RiskScore from "@/components/RiskScore";
import {
  ArrowLeft, RefreshCw, ShieldAlert, Shield,
  RotateCcw, CheckCircle2, XCircle, Clock, Brain,
  AlertTriangle, Target, Zap,
} from "lucide-react";
import { cn, formatDate } from "@/lib/utils";
import type { Scan } from "@/lib/api";

interface PageProps { params: { id: string } }

function hasAnyResults(scan: Scan): boolean {
  return !!(scan.shodan_data || scan.virustotal_data || scan.abuseipdb_data ||
            scan.nmap_data   || scan.nuclei_data     || scan.zap_data);
}

const ST_CONFIG: Record<string, { label: string; dot: string; badge: string }> = {
  completed: { label: "Completed", dot: "bg-emerald-400",    badge: "bg-emerald-950/60 text-emerald-400 border-emerald-800/60" },
  running:   { label: "Running",   dot: "bg-blue-400 animate-pulse", badge: "bg-blue-950/60 text-blue-400 border-blue-800/60" },
  pending:   { label: "Queued",    dot: "bg-amber-400",      badge: "bg-amber-950/60 text-amber-400 border-amber-800/60"    },
  failed:    { label: "Failed",    dot: "bg-red-400",        badge: "bg-red-950/60 text-red-400 border-red-800/60"          },
};

export default function ScanDetailPage({ params }: PageProps) {
  const { id } = params;
  const { data: scan, isLoading, error, refetch, isFetching } = useScan(id);
  const retryScan = useRetryScan();

  /* ── Loading ── */
  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-3">
        <RefreshCw className="w-6 h-6 text-blue-500 animate-spin" />
        <p className="text-[12px] text-[#2a5070]">Loading scan report…</p>
      </div>
    );
  }

  /* ── Error ── */
  if (error || !scan) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-4">
        <ShieldAlert className="w-10 h-10 text-red-500/60" />
        <p className="text-[13px] text-[#2a5070]">{error?.message ?? "Scan not found"}</p>
        <Link href="/dashboard" className="text-[12px] text-blue-400 hover:text-blue-300">
          ← Back to Dashboard
        </Link>
      </div>
    );
  }

  const isRunning   = scan.status === "running" || scan.status === "pending";
  const isCompleted = scan.status === "completed";
  const isFailed    = scan.status === "failed";
  const showResults = isCompleted || (isRunning && hasAnyResults(scan));
  const cfg         = ST_CONFIG[scan.status] ?? ST_CONFIG.pending;
  const socReport   = (scan as any).soc_report as Record<string, any> | null;

  return (
    <div className="flex flex-col h-full overflow-auto">

      {/* ── Top bar ── */}
      <div className="shrink-0 flex items-center justify-between px-6 py-3 border-b border-[#0f1e30] bg-[#060d1a]">
        <div className="flex items-center gap-3 min-w-0">
          <Link
            href="/dashboard"
            className="flex items-center gap-1.5 text-[11px] text-[#2a5070] hover:text-blue-400 transition-colors shrink-0"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            Dashboard
          </Link>
          <span className="text-[#0f1e30]">/</span>
          <Target className="w-3.5 h-3.5 text-[#2a5070] shrink-0" />
          <span className="text-[13px] font-mono text-[#8ab8d8] truncate">{scan.target}</span>
          <span
            className={cn(
              "shrink-0 text-[10px] font-bold px-2 py-0.5 rounded-[3px] border tracking-widest uppercase",
              cfg.badge
            )}
          >
            <span className={cn("inline-block w-1.5 h-1.5 rounded-full mr-1.5 align-middle", cfg.dot)} />
            {cfg.label}
          </span>
        </div>

        <div className="flex items-center gap-2 shrink-0 ml-4">
          {isFailed && (
            <button
              onClick={() => retryScan.mutate(id)}
              disabled={retryScan.isPending}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-[5px] text-[11px] font-semibold text-blue-400 bg-blue-950/50 border border-blue-800/60 hover:bg-blue-950 transition-colors disabled:opacity-50"
            >
              <RotateCcw className={cn("w-3.5 h-3.5", retryScan.isPending && "animate-spin")} />
              Retry
            </button>
          )}
          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-[5px] text-[11px] text-[#3d6080] bg-[#080f1e] border border-[#0f1e30] hover:border-blue-900/60 hover:text-blue-400 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={cn("w-3.5 h-3.5", isFetching && "animate-spin")} />
            Refresh
          </button>
        </div>
      </div>

      {/* ── Meta strip ── */}
      <div className="shrink-0 flex items-center gap-6 px-6 py-2.5 bg-[#060d1a] border-b border-[#0f1e30] text-[10px] text-[#1e3a55] font-mono">
        <span>Started: {formatDate(scan.created_at)}</span>
        <span>ID: {scan.id}</span>
        {isRunning && <span className="text-blue-400 animate-pulse">● Live — {scan.progress}%</span>}
      </div>

      {/* ── Body ── */}
      <div className="flex-1 p-5 grid lg:grid-cols-3 gap-5 max-w-[1400px] w-full mx-auto">

        {/* ── Left (2 cols) ── */}
        <div className="lg:col-span-2 space-y-4">

          {/* Progress tracker */}
          {isRunning && (
            <div className="bg-[#080f1e] border border-[#0f1e30] rounded-[7px] p-5">
              <div className="flex items-center gap-2 mb-4">
                <Clock className="w-4 h-4 text-blue-400 animate-pulse" />
                <h2 className="text-[12px] font-semibold text-[#4a8ab5] uppercase tracking-wide">
                  Live Scan Pipeline
                </h2>
              </div>
              <ProgressTracker
                progress={scan.progress}
                status={scan.status}
                message={scan.error_message ?? undefined}
              />
            </div>
          )}

          {/* Failed banner */}
          {isFailed && (
            <div className="flex items-start gap-3 p-4 bg-red-950/30 border border-red-900/60 rounded-[7px]">
              <XCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
              <div>
                <p className="text-[13px] font-semibold text-red-400">Scan Failed</p>
                <p className="text-[11px] text-red-300/70 mt-0.5">
                  {scan.error_message ?? "An unexpected error occurred. Check the logs below."}
                </p>
              </div>
            </div>
          )}

          {/* SOC Executive Summary (completed only) */}
          {isCompleted && socReport?.executive_summary && (
            <div className="bg-[#080f1e] border border-[#0f1e30] rounded-[7px] p-5">
              <div className="flex items-center gap-2 mb-3">
                <Zap className="w-4 h-4 text-blue-400" />
                <h2 className="text-[12px] font-semibold text-[#4a8ab5] uppercase tracking-wide">
                  Executive Summary
                </h2>
              </div>
              <p className="text-[12px] text-[#7aa8cc] leading-relaxed">
                {socReport.executive_summary}
              </p>

              {/* Recommendations */}
              {socReport.recommendations?.length > 0 && (
                <div className="mt-4 space-y-2">
                  <p className="text-[10px] font-semibold text-[#2a5070] uppercase tracking-widest">
                    Recommendations
                  </p>
                  {socReport.recommendations.map((rec: string, i: number) => (
                    <div key={i} className="flex items-start gap-2 text-[11px] text-[#3d6080]">
                      <span className="text-blue-500 shrink-0 mt-0.5">›</span>
                      {rec}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Results */}
          {showResults && (
            <div className="bg-[#080f1e] border border-[#0f1e30] rounded-[7px] p-5">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <Shield className="w-4 h-4 text-emerald-400" />
                  <h2 className="text-[12px] font-semibold text-[#4a8ab5] uppercase tracking-wide">
                    {isCompleted ? "Reconnaissance Findings" : "Partial Results"}
                  </h2>
                </div>
                {isRunning && (
                  <span className="text-[10px] font-mono text-blue-400 animate-pulse tracking-widest">
                    LIVE
                  </span>
                )}
              </div>
              <ScanResults scan={scan} />
            </div>
          )}

          {/* Logs */}
          <div>
            <p className="text-[11px] font-semibold text-[#2a5070] uppercase tracking-wide mb-2">
              Audit Logs
            </p>
            <LiveLogs logs={scan.logs ?? []} isLive={isRunning} />
          </div>
        </div>

        {/* ── Right (1 col) ── */}
        <div className="space-y-4">

          {/* Risk Score card */}
          <div className="bg-[#080f1e] border border-[#0f1e30] rounded-[7px] p-5 flex flex-col items-center text-center gap-4">
            <p className="text-[10px] font-semibold text-[#2a5070] uppercase tracking-widest">
              Risk Assessment
            </p>
            <RiskScore score={scan.risk_score} size="lg" />
            {scan.risk_score !== null && scan.risk_score !== undefined && (
              <p className="text-[11px] text-[#2a5070]">
                {scan.risk_score >= 80 ? "Immediate action required"  :
                 scan.risk_score >= 60 ? "High priority remediation"  :
                 scan.risk_score >= 40 ? "Schedule remediation"        :
                 "Low — monitor regularly"}
              </p>
            )}
          </div>

          {/* Component scores (completed) */}
          {isCompleted && socReport?.component_scores && (
            <div className="bg-[#080f1e] border border-[#0f1e30] rounded-[7px] p-4">
              <p className="text-[10px] font-semibold text-[#2a5070] uppercase tracking-widest mb-3">
                Score Breakdown
              </p>
              <div className="space-y-2.5">
                {Object.entries(socReport.component_scores as Record<string, number>).map(([key, val]) => (
                  <div key={key}>
                    <div className="flex justify-between text-[10px] mb-1">
                      <span className="text-[#2a5070] capitalize">{key.replace(/_/g, " ")}</span>
                      <span className="font-mono text-[#4a8ab5]">{Math.round(val)}</span>
                    </div>
                    <div className="h-[3px] bg-[#0f1e30] rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full bg-blue-600/70"
                        style={{ width: `${Math.min(val, 100)}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Phase summary (running) */}
          {isRunning && (
            <div className="bg-[#080f1e] border border-[#0f1e30] rounded-[7px] p-4">
              <div className="flex items-center gap-2 mb-3">
                <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                <p className="text-[10px] font-semibold text-[#2a5070] uppercase tracking-widest">
                  Pipeline Progress
                </p>
              </div>
              {[
                { label: "Asset Discovery",    start: 0,  end: 12 },
                { label: "Active Recon",       start: 12, end: 27 },
                { label: "Fingerprinting",     start: 27, end: 44 },
                { label: "Vuln Scanning",      start: 44, end: 60 },
                { label: "Threat Intel",       start: 60, end: 78 },
                { label: "Correlation",        start: 78, end: 88 },
                { label: "Risk Scoring",       start: 88, end: 94 },
                { label: "SOC Output",         start: 94, end: 100 },
              ].map(({ label, start, end }) => {
                const done   = scan.progress >= end;
                const active = scan.progress >= start && scan.progress < end;
                const pct    = done ? 100 : active
                  ? Math.round(((scan.progress - start) / (end - start)) * 100)
                  : 0;
                return (
                  <div key={label} className="mb-2">
                    <div className="flex justify-between text-[10px] mb-0.5">
                      <span className={cn(
                        done ? "text-emerald-400" : active ? "text-blue-300" : "text-[#1a3550]"
                      )}>
                        {done ? "✓" : active ? "▶" : "○"} {label}
                      </span>
                      <span className="font-mono text-[#1a3550]">{pct}%</span>
                    </div>
                    <div className="h-[2px] bg-[#0f1e30] rounded-full overflow-hidden">
                      <div
                        className={cn(
                          "h-full rounded-full transition-all duration-500",
                          done ? "bg-emerald-500" : "bg-blue-500"
                        )}
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* Completed checklist */}
          {isCompleted && (
            <div className="bg-[#080f1e] border border-[#0f1e30] rounded-[7px] p-4">
              <div className="flex items-center gap-2 mb-3">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                <p className="text-[10px] font-semibold text-[#2a5070] uppercase tracking-widest">
                  Pipeline Complete
                </p>
              </div>
              <div className="space-y-1.5">
                {[
                  "Asset Discovery (Shodan)",
                  "Active Recon (ZAP)",
                  "Fingerprinting (Nmap)",
                  "Vuln Scanning (Nuclei)",
                  "Threat Intelligence",
                  "Correlation Engine",
                  "Risk Scoring",
                  "SOC Dashboard",
                ].map((phase) => (
                  <div key={phase} className="flex items-center gap-2 text-[11px] text-[#2a5070]">
                    <CheckCircle2 className="w-3 h-3 text-emerald-500 shrink-0" />
                    {phase}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* AI analysis */}
          {scan.ai_analysis && (
            <div className="bg-[#080f1e] border border-[#0f1e30] rounded-[7px] p-4">
              <div className="flex items-center gap-2 mb-3">
                <Brain className="w-3.5 h-3.5 text-blue-400" />
                <p className="text-[10px] font-semibold text-[#2a5070] uppercase tracking-widest">
                  AI Analysis
                </p>
              </div>
              <p className="text-[11px] text-[#3d6080] leading-relaxed whitespace-pre-wrap">
                {scan.ai_analysis}
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

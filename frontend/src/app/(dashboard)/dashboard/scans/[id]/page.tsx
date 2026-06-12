"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { useScan, useRetryScan, useStopScan } from "@/hooks/useScans";
import ProgressTracker from "@/components/ProgressTracker";
import LiveLogs from "@/components/LiveLogs";
import ScanResults from "@/components/ScanResults";
import RiskScore from "@/components/RiskScore";
import {
  ArrowLeft, RefreshCw, ShieldAlert, Shield,
  RotateCcw, CheckCircle2, XCircle, Clock, Brain,
  AlertTriangle, Target, Zap, Square, FlaskConical, Crosshair,
} from "lucide-react";
import { cn, formatDate } from "@/lib/utils";
import type { Scan } from "@/lib/api";

interface PageProps { params: { id: string } }

function hasAnyResults(scan: Scan): boolean {
  return !!(scan.shodan_data || scan.virustotal_data || scan.abuseipdb_data ||
            scan.nmap_data   || scan.nuclei_data     || scan.zap_data);
}

const ST_CONFIG: Record<string, { label: string; dot: string; badge: string }> = {
  completed: { label: "Completed", dot: "bg-emerald-500",              badge: "bg-emerald-950/50 text-emerald-400 border-emerald-900/50" },
  running:   { label: "Running",   dot: "bg-indigo-400 animate-pulse live-ring", badge: "bg-indigo-950/50 text-indigo-400 border-indigo-900/50" },
  pending:   { label: "Queued",    dot: "bg-amber-500",                badge: "bg-amber-950/50  text-amber-400  border-amber-900/50" },
  failed:    { label: "Failed",    dot: "bg-red-500",                  badge: "bg-red-950/50    text-red-400    border-red-900/50" },
};

const PIPELINE_PHASES = [
  { label: "Asset Discovery",  start: 0,  end: 12 },
  { label: "Active Recon",     start: 12, end: 27 },
  { label: "Fingerprinting",   start: 27, end: 44 },
  { label: "Vuln Scanning",    start: 44, end: 60 },
  { label: "Threat Intel",     start: 60, end: 78 },
  { label: "Correlation",      start: 78, end: 88 },
  { label: "Risk Scoring",     start: 88, end: 94 },
  { label: "SOC Output",       start: 94, end: 100 },
];

export default function ScanDetailPage({ params }: PageProps) {
  const { id } = params;
  const { data: scan, isLoading, error, refetch, isFetching } = useScan(id);
  const retryScan = useRetryScan();
  const stopScan  = useStopScan();
  const [stopConfirm, setStopConfirm] = useState(false);

  useEffect(() => {
    if (!stopConfirm) return;
    const t = setTimeout(() => setStopConfirm(false), 3000);
    return () => clearTimeout(t);
  }, [stopConfirm]);

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-3 bg-zinc-950">
        <RefreshCw className="w-6 h-6 text-indigo-400 animate-spin" />
        <p className="text-[12px] text-zinc-600 font-mono">Loading scan report…</p>
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-4 bg-zinc-950">
        <ShieldAlert className="w-10 h-10 text-red-500" />
        <p className="text-[13px] text-zinc-500">{error?.message ?? "Scan not found"}</p>
        <Link href="/dashboard" className="text-[12px] text-indigo-400 hover:text-indigo-300 transition-colors">
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
  const socReport   = (scan as unknown as Record<string, unknown>).soc_report as Record<string, unknown> | null;

  return (
    <div className="flex flex-col h-full overflow-auto bg-zinc-950">

      {/* Top bar */}
      <div className="shrink-0 flex items-center justify-between px-6 py-3 border-b border-zinc-800/60 fade-in-down">
        <div className="flex items-center gap-3 min-w-0">
          <Link href="/dashboard" className="flex items-center gap-1.5 text-[11px] text-zinc-600 hover:text-indigo-400 transition-colors shrink-0">
            <ArrowLeft className="w-3.5 h-3.5" />
            Dashboard
          </Link>
          <span className="text-zinc-800">/</span>
          <Target className="w-3.5 h-3.5 text-zinc-700 shrink-0" />
          <span className="text-[13px] font-mono text-zinc-400 truncate">{scan.target}</span>
          <span className={cn(
            "shrink-0 text-[10px] font-bold px-2 py-0.5 rounded-md border tracking-widest uppercase",
            cfg.badge
          )}>
            <span className={cn("inline-block w-1.5 h-1.5 rounded-full mr-1.5 align-middle", cfg.dot)} />
            {cfg.label}
          </span>
        </div>

        <div className="flex items-center gap-2 shrink-0 ml-4">
          {/* Stop scan button */}
          {isRunning && (
            <button
              onClick={() => {
                if (stopConfirm) { stopScan.mutate(id); setStopConfirm(false); }
                else setStopConfirm(true);
              }}
              disabled={stopScan.isPending}
              className={cn(
                "flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-semibold transition-all duration-150 disabled:opacity-50",
                stopConfirm
                  ? "bg-red-600 text-white border border-red-500 shadow-lg shadow-red-950/40"
                  : "bg-transparent text-zinc-500 border border-zinc-700 hover:border-red-700/50 hover:text-red-400 hover:bg-red-950/20"
              )}
            >
              <Square className={cn("w-3.5 h-3.5", stopScan.isPending && "animate-spin")} />
              {stopConfirm ? "Confirm stop?" : "Stop scan"}
            </button>
          )}

          {isFailed && (
            <button
              onClick={() => retryScan.mutate(id)}
              disabled={retryScan.isPending}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-semibold text-indigo-400 bg-indigo-950/40 border border-indigo-900/50 hover:bg-indigo-950/60 transition-colors disabled:opacity-50"
            >
              <RotateCcw className={cn("w-3.5 h-3.5", retryScan.isPending && "animate-spin")} />
              Retry
            </button>
          )}

          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] text-zinc-500 border border-zinc-800 hover:border-indigo-800/40 hover:text-indigo-400 transition-all disabled:opacity-50"
          >
            <RefreshCw className={cn("w-3.5 h-3.5", isFetching && "animate-spin")} />
            Refresh
          </button>
        </div>
      </div>

      {/* Meta strip */}
      <div className="shrink-0 flex items-center gap-6 px-6 py-2 border-b border-zinc-800/40 text-[10px] text-zinc-700 font-mono">
        <span>Started: {formatDate(scan.created_at)}</span>
        <span>ID: {scan.id}</span>
        {/* Detection mode badge */}
        {scan.lab_mode ? (
          <span className="flex items-center gap-1 text-violet-500/80 font-semibold">
            <FlaskConical className="w-3 h-3" />
            LAB MODE
          </span>
        ) : (
          <span className="flex items-center gap-1 text-amber-500/80 font-semibold">
            <Crosshair className="w-3 h-3" />
            ACTIVE MODE
          </span>
        )}
        {isRunning && (
          <span className="text-indigo-400 font-semibold flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-indigo-400 animate-pulse" />
            LIVE · {scan.progress}%
          </span>
        )}
      </div>

      {/* Body */}
      <div className="flex-1 p-5 grid lg:grid-cols-3 gap-5 max-w-[1400px] w-full mx-auto">

        <div className="lg:col-span-2 space-y-4">

          {/* Live pipeline */}
          {isRunning && (
            <div className="bg-zinc-900 border border-indigo-900/30 rounded-xl p-5 fade-in-up">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-indigo-400 animate-pulse" />
                  <h2 className="text-[11px] font-semibold text-indigo-400 uppercase tracking-widest">Live Scan Pipeline</h2>
                </div>
                <span className="text-[10px] font-mono text-indigo-600 font-semibold tracking-widest">LIVE</span>
              </div>
              <ProgressTracker progress={scan.progress} status={scan.status} message={scan.error_message ?? undefined} />
            </div>
          )}

          {isFailed && (
            <div className="flex items-start gap-3 p-4 bg-red-950/30 border border-red-900/50 rounded-xl fade-in">
              <XCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
              <div>
                <p className="text-[13px] font-semibold text-red-400">Scan Failed</p>
                <p className="text-[11px] text-red-400/60 mt-0.5">
                  {scan.error_message ?? "An unexpected error occurred."}
                </p>
              </div>
            </div>
          )}

          {isCompleted && !!socReport?.executive_summary && (
            <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5 card-hover fade-in-up">
              <div className="flex items-center gap-2 mb-3">
                <Zap className="w-4 h-4 text-indigo-400" />
                <h2 className="text-[11px] font-semibold text-zinc-500 uppercase tracking-widest">Executive Summary</h2>
              </div>
              <p className="text-[12px] text-zinc-400 leading-relaxed">{String(socReport.executive_summary)}</p>
              {Array.isArray(socReport.recommendations) && socReport.recommendations.length > 0 && (
                <div className="mt-4 space-y-2">
                  <p className="text-[10px] font-semibold text-zinc-600 uppercase tracking-widest">Recommendations</p>
                  {(socReport.recommendations as string[]).map((rec: string, i: number) => (
                    <div key={i} className="flex items-start gap-2 text-[11px] text-zinc-500">
                      <span className="text-indigo-500 shrink-0 mt-0.5">›</span>
                      {rec}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {showResults && (
            <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5 card-hover fade-in-up">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <Shield className="w-4 h-4 text-emerald-500" />
                  <h2 className="text-[11px] font-semibold text-zinc-500 uppercase tracking-widest">
                    {isCompleted ? "Reconnaissance Findings" : "Partial Results"}
                  </h2>
                </div>
                {isRunning && <span className="text-[10px] font-mono text-indigo-500 font-semibold tracking-widest">LIVE</span>}
              </div>
              <ScanResults scan={scan} />
            </div>
          )}

          <div>
            <p className="text-[10px] font-semibold text-zinc-700 uppercase tracking-widest mb-2">Audit Logs</p>
            <LiveLogs logs={scan.logs ?? []} isLive={isRunning} />
          </div>
        </div>

        <div className="space-y-4">

          <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5 flex flex-col items-center text-center gap-4 card-hover fade-in-up">
            <p className="text-[10px] font-semibold text-zinc-600 uppercase tracking-widest">Risk Assessment</p>
            <RiskScore score={scan.risk_score} size="lg" />
            {scan.risk_score !== null && scan.risk_score !== undefined && (
              <p className="text-[11px] text-zinc-600">
                {scan.risk_score >= 80 ? "Immediate action required"  :
                 scan.risk_score >= 60 ? "High priority remediation"  :
                 scan.risk_score >= 40 ? "Schedule remediation"        :
                 "Low — monitor regularly"}
              </p>
            )}
          </div>

          {isCompleted && !!socReport?.component_scores && (
            <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4 card-hover fade-in-up" style={{ animationDelay: "60ms" }}>
              <p className="text-[10px] font-semibold text-zinc-600 uppercase tracking-widest mb-3">Score Breakdown</p>
              <div className="space-y-2.5">
                {Object.entries(socReport.component_scores as Record<string, number>).map(([key, val]) => {
                  const pct = Math.min(Math.round(val), 100);
                  const barColor = pct >= 70 ? "bg-red-500" : pct >= 40 ? "bg-amber-500" : "bg-indigo-500";
                  return (
                    <div key={key}>
                      <div className="flex justify-between text-[10px] mb-1">
                        <span className="text-zinc-500 capitalize">{key.replace(/_/g, " ")}</span>
                        <span className="font-mono text-zinc-400 font-semibold">{pct}</span>
                      </div>
                      <div className="h-[2px] bg-zinc-800 rounded-full overflow-hidden">
                        <div className={cn("h-full rounded-full prog-fill", barColor)} style={{ width: `${pct}%` }} />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {isRunning && (
            <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4 fade-in-up" style={{ animationDelay: "80ms" }}>
              <div className="flex items-center gap-2 mb-3">
                <Clock className="w-3.5 h-3.5 text-indigo-400" />
                <p className="text-[10px] font-semibold text-zinc-600 uppercase tracking-widest">Pipeline Progress</p>
              </div>
              <div className="space-y-2">
                {PIPELINE_PHASES.map(({ label, start, end }) => {
                  const done   = scan.progress >= end;
                  const active = scan.progress >= start && scan.progress < end;
                  const pct    = done ? 100 : active
                    ? Math.round(((scan.progress - start) / (end - start)) * 100) : 0;
                  return (
                    <div key={label}>
                      <div className="flex justify-between text-[10px] mb-0.5">
                        <span className={cn("font-mono transition-colors duration-300",
                          done ? "text-emerald-500" : active ? "text-indigo-400 font-medium" : "text-zinc-700")}>
                          {done ? "✓" : active ? "▶" : "○"} {label}
                        </span>
                        <span className="font-mono text-zinc-700 tabular-nums">{pct}%</span>
                      </div>
                      <div className="h-[2px] bg-zinc-800 rounded-full overflow-hidden">
                        <div className={cn("h-full rounded-full prog-fill", done ? "bg-emerald-500" : "bg-indigo-500")}
                          style={{ width: `${pct}%` }} />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {isCompleted && (
            <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4 card-hover fade-in-up" style={{ animationDelay: "100ms" }}>
              <div className="flex items-center gap-2 mb-3">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500" />
                <p className="text-[10px] font-semibold text-zinc-600 uppercase tracking-widest">Pipeline Complete</p>
              </div>
              <div className="space-y-1.5">
                {["Asset Discovery (Shodan)","Active Recon (ZAP)","Fingerprinting (Nmap)","Vuln Scanning (Nuclei)","Threat Intelligence","Correlation Engine","Risk Scoring","SOC Dashboard"].map((phase) => (
                  <div key={phase} className="flex items-center gap-2 text-[11px] text-zinc-600">
                    <CheckCircle2 className="w-3 h-3 text-emerald-600 shrink-0" />
                    {phase}
                  </div>
                ))}
              </div>
            </div>
          )}

          {scan.ai_analysis && (
            <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4 card-hover fade-in-up" style={{ animationDelay: "120ms" }}>
              <div className="flex items-center gap-2 mb-3">
                <Brain className="w-3.5 h-3.5 text-indigo-400" />
                <p className="text-[10px] font-semibold text-zinc-600 uppercase tracking-widest">AI Analysis</p>
              </div>
              <p className="text-[11px] text-zinc-500 leading-relaxed whitespace-pre-wrap">{scan.ai_analysis}</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

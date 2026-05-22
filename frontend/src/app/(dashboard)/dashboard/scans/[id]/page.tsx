"use client";

import React from "react";
import Link from "next/link";
import { useScan, useRetryScan } from "@/hooks/useScans";
import ProgressTracker from "@/components/ProgressTracker";
import LiveLogs from "@/components/LiveLogs";
import ScanResults from "@/components/ScanResults";
import RiskScore from "@/components/RiskScore";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  ArrowLeft, RefreshCw, AlertTriangle, ShieldAlert,
  Brain, Terminal, CheckCircle2, XCircle, Clock, Shield, RotateCcw,
} from "lucide-react";
import { cn, formatDate } from "@/lib/utils";
import type { Scan } from "@/lib/api";

interface PageProps {
  params: { id: string };
}

function hasAnyResults(scan: Scan): boolean {
  return !!(
    scan.shodan_data ||
    scan.virustotal_data ||
    scan.abuseipdb_data ||
    scan.nmap_data ||
    scan.nuclei_data ||
    scan.zap_data
  );
}

export default function ScanDetailPage({ params }: PageProps) {
  const { id } = params;
  const { data: scan, isLoading, error, refetch, isFetching } = useScan(id);
  const retryScan = useRetryScan();

  if (isLoading) {
    return (
      <div className="min-h-[70vh] flex flex-col items-center justify-center gap-4">
        <RefreshCw className="h-8 w-8 text-cyan-400 animate-spin" />
        <p className="text-sm text-slate-500 font-medium animate-pulse">Loading scan report…</p>
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="p-6 max-w-xl mx-auto mt-20 text-center">
        <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-full inline-block mb-4">
          <ShieldAlert className="h-10 w-10 text-red-500" />
        </div>
        <h1 className="text-xl font-bold text-slate-200">Scan Report Not Found</h1>
        <p className="text-sm text-slate-500 mt-2">
          {error?.message ||
            "We could not find the requested security scan report. It might have been deleted."}
        </p>
        <Link
          href="/dashboard"
          className="inline-flex items-center gap-2 mt-6 bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm font-semibold px-4 py-2 rounded-lg transition-colors"
        >
          <ArrowLeft size={16} />
          Back to Dashboard
        </Link>
      </div>
    );
  }

  const isRunning  = scan.status === "running" || scan.status === "pending";
  const isCompleted = scan.status === "completed";
  const isFailed   = scan.status === "failed";
  const showResults = isCompleted || (isRunning && hasAnyResults(scan));

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">

      {/* ── Header ── */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div className="space-y-1">
          <Link
            href="/dashboard"
            className="inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-cyan-400 transition-colors mb-2"
          >
            <ArrowLeft size={14} />
            Back to Dashboard
          </Link>
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-bold text-slate-100 font-mono tracking-tight truncate max-w-md">
              {scan.target}
            </h1>
            <Badge
              variant={
                scan.status === "completed" ? "success" :
                scan.status === "failed"    ? "danger"  :
                scan.status === "running"   ? "info"    : "warning"
              }
              className="capitalize"
            >
              {scan.status}
            </Badge>
          </div>
          <p className="text-xs text-slate-500">
            Started: {formatDate(scan.created_at)} · ID:{" "}
            <span className="font-mono">{scan.id}</span>
          </p>
        </div>

        <div className="flex items-center gap-2">
          {isFailed && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => retryScan.mutate(id)}
              disabled={retryScan.isPending}
              className="border-cyan-500/30 bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20 hover:text-cyan-300"
            >
              <RotateCcw size={14} className={cn("mr-2", retryScan.isPending && "animate-spin")} />
              Retry Scan
            </Button>
          )}
          <Button
            variant="outline"
            size="sm"
            onClick={() => refetch()}
            disabled={isFetching}
            className="border-slate-800 bg-slate-900/50 text-slate-300 hover:text-white"
          >
            <RefreshCw size={14} className={cn("mr-2", isFetching && "animate-spin")} />
            Refresh
          </Button>
        </div>
      </div>

      {/* ── Main grid ── */}
      <div className="grid lg:grid-cols-3 gap-6">

        {/* Left column */}
        <div className="lg:col-span-2 space-y-6">

          {/* Progress tracker — running / pending */}
          {isRunning && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
              <h2 className="text-sm font-semibold text-slate-200 mb-4 flex items-center gap-2">
                <Clock className="h-4 w-4 text-cyan-400 animate-spin" />
                Live Scan Pipeline
              </h2>
              <ProgressTracker
                progress={scan.progress}
                status={scan.status}
                message={scan.error_message || undefined}
              />
            </div>
          )}

          {/* Failed banner */}
          {isFailed && (
            <div className="bg-red-950/20 border border-red-500/20 rounded-xl p-5 flex items-start gap-4">
              <XCircle className="h-8 w-8 text-red-500 flex-shrink-0" />
              <div>
                <h3 className="font-bold text-red-400">Scan Operation Failed</h3>
                <p className="text-xs text-red-300/80 mt-1">
                  {scan.error_message ||
                    "An unexpected error occurred during execution. Check the logs below for details."}
                </p>
              </div>
            </div>
          )}

          {/* Results panel — shown when complete or when partial data is available during run */}
          {showResults && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div className="flex items-center gap-2">
                  <Shield className="h-5 w-5 text-green-400" />
                  <h2 className="font-bold text-slate-200">
                    {isCompleted ? "Reconnaissance Findings" : "Partial Results"}
                  </h2>
                </div>
                {isRunning && (
                  <Badge variant="info" className="text-xs animate-pulse">
                    Live
                  </Badge>
                )}
              </div>
              <ScanResults scan={scan} />
            </div>
          )}

          {/* Logs */}
          <div className="space-y-2">
            <h2 className="text-sm font-semibold text-slate-300 flex items-center gap-2">
              <Terminal className="h-4 w-4 text-slate-400" />
              Audit Logs
            </h2>
            <LiveLogs logs={scan.logs ?? []} isLive={isRunning} />
          </div>
        </div>

        {/* Right column */}
        <div className="space-y-6">

          {/* Risk score */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg flex flex-col items-center justify-center text-center space-y-4">
            <h2 className="text-sm font-semibold text-slate-300">Target Risk Assessment</h2>
            <RiskScore score={scan.risk_score} size="lg" />
            <div className="space-y-1">
              <p className="text-xs text-slate-400 font-medium">
                {scan.risk_score === null
                  ? "Awaiting completion"
                  : scan.risk_score >= 70
                  ? "Critical Threat Level Detected"
                  : scan.risk_score >= 40
                  ? "Medium Vulnerability Level"
                  : "Low Security Risk"}
              </p>
              <p className="text-[10px] text-slate-600 max-w-[200px]">
                Weighted across Nuclei CVEs, ZAP alerts, abuse confidence, VirusTotal detections &
                port exposure.
              </p>
            </div>
          </div>

          {/* Pipeline summary while running */}
          {isRunning && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-3">
              <h2 className="text-sm font-semibold text-slate-300 flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-yellow-400" />
                Pipeline Phases
              </h2>
              {[
                { range: [0, 45],   label: "Threat Intelligence", color: "bg-cyan-500"   },
                { range: [45, 60],  label: "Network Scan",        color: "bg-blue-500"   },
                { range: [60, 100], label: "Active Detection",    color: "bg-orange-500" },
              ].map(({ range, label, color }) => {
                const phaseProgress = Math.min(
                  Math.max(((scan.progress - range[0]) / (range[1] - range[0])) * 100, 0),
                  100
                );
                const done = scan.progress >= range[1];
                const active = scan.progress >= range[0] && scan.progress < range[1];
                return (
                  <div key={label}>
                    <div className="flex justify-between text-xs mb-1">
                      <span className={cn(
                        done ? "text-green-400" : active ? "text-slate-200" : "text-slate-600"
                      )}>
                        {done ? "✓" : active ? "▶" : "○"} {label}
                      </span>
                      <span className="text-slate-600 tabular-nums">
                        {done ? "100" : active ? Math.round(phaseProgress) : "0"}%
                      </span>
                    </div>
                    <div className="h-1 bg-slate-700 rounded-full overflow-hidden">
                      <div
                        className={cn("h-full rounded-full transition-all duration-500", color)}
                        style={{ width: `${done ? 100 : active ? phaseProgress : 0}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* AI analysis */}
          {scan.ai_analysis && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
              <div className="flex items-center gap-2 text-cyan-400 border-b border-slate-800 pb-3">
                <Brain className="h-5 w-5" />
                <h2 className="font-bold text-slate-200">AI Threat Analysis</h2>
              </div>
              <div className="prose prose-invert max-w-none text-xs text-slate-300 leading-relaxed font-sans whitespace-pre-wrap">
                {scan.ai_analysis}
              </div>
            </div>
          )}

          {/* Completed summary */}
          {isCompleted && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg space-y-3">
              <h2 className="text-sm font-semibold text-slate-300 flex items-center gap-2">
                <CheckCircle2 className="h-4 w-4 text-green-400" />
                Scan Summary
              </h2>
              {[
                { label: "Threat Intel",      icon: "🔍", done: true },
                { label: "Network Scan",      icon: "🌐", done: true },
                { label: "Active Detection",  icon: "⚡", done: true },
                { label: "Risk Aggregation",  icon: "📊", done: true },
              ].map(({ label, icon, done }) => (
                <div key={label} className="flex items-center gap-2 text-xs">
                  <span>{icon}</span>
                  <span className={done ? "text-green-400" : "text-slate-500"}>{label}</span>
                  {done && <CheckCircle2 className="h-3 w-3 text-green-400 ml-auto" />}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

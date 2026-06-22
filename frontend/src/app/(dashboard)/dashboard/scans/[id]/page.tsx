"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useScan, useRetryScan, useStopScan } from "@/hooks/useScans";
import ProgressTracker from "@/components/ProgressTracker";
import LiveLogs from "@/components/LiveLogs";
import ScanResults from "@/components/ScanResults";
import { cn, formatDate } from "@/lib/utils";
import type { Scan } from "@/lib/api";

interface PageProps { params: { id: string } }

function hasAnyResults(scan: Scan): boolean {
  return !!(scan.shodan_data || scan.virustotal_data || scan.abuseipdb_data ||
            scan.nmap_data   || scan.nuclei_data     || scan.zap_data);
}

const SEV_CFG = {
  critical: { color: "#EF4444", bg: "#FEF2F2", border: "rgba(239,68,68,0.2)",  label: "CRITICAL", icon: "report" },
  high:     { color: "#F97316", bg: "#FFF7ED", border: "rgba(249,115,22,0.2)", label: "HIGH",     icon: "warning" },
  medium:   { color: "var(--sc-brand)", bg: "var(--sc-brand-bg)", border: "rgba(0,81,213,0.2)", label: "MEDIUM", icon: "error_outline" },
  low:      { color: "var(--sc-outline)", bg: "var(--sc-low)", border: "var(--sc-border)", label: "LOW", icon: "info" },
};

interface VulnFinding {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low";
  description?: string;
  url?: string;
  evidence?: string;
  cve?: string;
  cvss_score?: number;
  type?: string;
  remediation?: string | string[];
  status?: string;
  confidence?: number;
  payload?: string;
}

function extractVulnerabilities(scan: Scan): VulnFinding[] {
  const socReport = scan.soc_report as Record<string, unknown> | null;
  if (!socReport) return [];
  const vulns = (socReport.vulnerabilities ?? socReport.findings) as unknown[] | undefined;
  if (!Array.isArray(vulns)) return [];
  return vulns.slice(0, 20).map((v, i) => {
    const vv = v as Record<string, unknown>;
    const sev = (String(vv.severity ?? "medium")).toLowerCase() as VulnFinding["severity"];
    return {
      id:          String(vv.id ?? `vuln-${i}`),
      title:       String(vv.title ?? vv.name ?? vv.type ?? "Finding"),
      severity:    ["critical","high","medium","low"].includes(sev) ? sev : "medium",
      description: vv.description as string | undefined,
      url:         (vv.url ?? vv.endpoint ?? vv.path) as string | undefined,
      evidence:    (vv.evidence ?? vv.payload) as string | undefined,
      cve:         vv.cve as string | undefined,
      cvss_score:  vv.cvss_score as number | undefined,
      type:        vv.type as string | undefined,
      remediation: vv.remediation as string | string[] | undefined,
      status:      vv.status as string | undefined,
      payload:     (vv.payload ?? vv.evidence) as string | undefined,
    };
  });
}

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
  const [expandedVuln, setExpandedVuln] = useState<string | null>(null);

  if (isLoading) {
    return (
      <div
        className="flex flex-col items-center justify-center h-full gap-3"
        style={{ background: "var(--sc-bg)", fontFamily: "'Geist', sans-serif" }}
      >
        <span className="material-symbols-outlined animate-spin" style={{ fontSize: 28, color: "var(--sc-brand)" }}>
          sync
        </span>
        <p className="font-mono" style={{ fontSize: 12, color: "var(--sc-outline)" }}>
          Loading scan report...
        </p>
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div
        className="flex flex-col items-center justify-center h-full gap-4"
        style={{ background: "var(--sc-bg)", fontFamily: "'Geist', sans-serif" }}
      >
        <span className="material-symbols-outlined" style={{ fontSize: 40, color: "var(--sc-error)" }}>
          shield_x
        </span>
        <p style={{ fontSize: 13, color: "var(--sc-on-v)" }}>
          {error?.message ?? "Scan not found"}
        </p>
        <Link href="/dashboard" style={{ fontSize: 12, color: "var(--sc-brand)" }}>
          Back to Dashboard
        </Link>
      </div>
    );
  }

  const isRunning   = scan.status === "running" || scan.status === "pending";
  const isCompleted = scan.status === "completed";
  const isFailed    = scan.status === "failed";
  const showResults = isCompleted || (isRunning && hasAnyResults(scan));

  const socReport    = scan.soc_report as Record<string, unknown> | null;
  const vulns        = extractVulnerabilities(scan);
  const criticalCount = vulns.filter((v) => v.severity === "critical").length;
  const highCount     = vulns.filter((v) => v.severity === "high").length;
  const mediumCount   = vulns.filter((v) => v.severity === "medium").length;
  const lowCount      = vulns.filter((v) => v.severity === "low").length;

  const scanLogs = scan.logs ?? [];

  return (
    <div
      className="h-full flex flex-col overflow-hidden"
      style={{ background: "var(--sc-bg)", fontFamily: "'Geist', sans-serif", color: "var(--sc-on)" }}
    >
      {/* Top app bar */}
      <header
        className="shrink-0 h-16 flex justify-between items-center px-4 z-40"
        style={{ background: "var(--sc-bg)", borderBottom: "1px solid var(--sc-border)" }}
      >
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined" style={{ fontSize: 20, color: "var(--sc-brand)", fontVariationSettings: "'FILL' 1" }}>
              verified_user
            </span>
            <span className="font-bold" style={{ fontSize: 18, color: "var(--sc-on)" }}>
              Aegis Pentest
            </span>
          </div>
          <div className="h-5 w-px" style={{ background: "var(--sc-border)" }} />
          <div className="flex items-center gap-2" style={{ color: "var(--sc-outline)" }}>
            <span className="font-mono" style={{ fontSize: 12 }}>SCAN_ID:</span>
            <span className="font-mono font-bold" style={{ fontSize: 12, color: "var(--sc-brand)" }}>
              #{scan.id.slice(0, 8).toUpperCase()}
            </span>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {/* Search filter */}
          <div
            className="flex items-center gap-2 px-3 py-1.5 rounded border w-56"
            style={{ background: "var(--sc-low)", borderColor: "var(--sc-border)" }}
          >
            <span className="material-symbols-outlined" style={{ fontSize: 16, color: "var(--sc-outline)" }}>search</span>
            <span className="text-xs font-mono" style={{ color: "var(--sc-outline)" }}>Filter vulnerabilities...</span>
            <kbd className="ml-auto font-mono" style={{ fontSize: 10, color: "var(--sc-outline)" }}>^K</kbd>
          </div>

          {/* Stop/Retry/Refresh */}
          {isRunning && (
            <button
              onClick={() => {
                if (stopConfirm) { stopScan.mutate(id); setStopConfirm(false); }
                else setStopConfirm(true);
              }}
              disabled={stopScan.isPending}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all disabled:opacity-50"
              style={{
                background: stopConfirm ? "var(--sc-error)" : "transparent",
                color:      stopConfirm ? "#ffffff" : "var(--sc-on-v)",
                border:     stopConfirm ? "1px solid var(--sc-error)" : "1px solid var(--sc-border)",
              }}
            >
              <span className="material-symbols-outlined" style={{ fontSize: 14 }}>
                {stopScan.isPending ? "sync" : "stop"}
              </span>
              {stopConfirm ? "Confirm stop?" : "Stop scan"}
            </button>
          )}

          {isFailed && (
            <button
              onClick={() => retryScan.mutate(id)}
              disabled={retryScan.isPending}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors disabled:opacity-50"
              style={{
                background: "var(--sc-brand-bg)", color: "var(--sc-brand)",
                border: "1px solid rgba(0,81,213,0.3)",
              }}
            >
              <span className={cn("material-symbols-outlined", retryScan.isPending && "animate-spin")} style={{ fontSize: 14 }}>
                refresh
              </span>
              Retry
            </button>
          )}

          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all disabled:opacity-50"
            style={{ color: "var(--sc-on-v)", border: "1px solid var(--sc-border)" }}
            onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.borderColor = "var(--sc-brand)"; }}
            onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.borderColor = "var(--sc-border)"; }}
          >
            <span className={cn("material-symbols-outlined", isFetching && "animate-spin")} style={{ fontSize: 14 }}>
              refresh
            </span>
            Refresh
          </button>

          <div className="flex items-center gap-2">
            <button style={{ color: "var(--sc-on-v)" }}
              onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.color = "var(--sc-brand)")}
              onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.color = "var(--sc-on-v)")}
            >
              <span className="material-symbols-outlined" style={{ fontSize: 20 }}>notifications</span>
            </button>
            <div
              className="w-8 h-8 rounded-full flex items-center justify-center text-white font-bold"
              style={{ fontSize: 11, background: "var(--sc-brand)" }}
            >
              OP
            </div>
          </div>
        </div>
      </header>

      {/* Content canvas */}
      <div className="flex-1 overflow-y-auto p-4" style={{ background: "var(--sc-bg)" }}>

        {/* Scan target & status strip */}
        <div className="flex items-center gap-4 mb-4 text-xs font-mono" style={{ color: "var(--sc-outline)" }}>
          <Link href="/dashboard" style={{ color: "var(--sc-brand)" }}>
            Dashboard
          </Link>
          <span>/</span>
          <span style={{ color: "var(--sc-on)" }}>{scan.target}</span>
          <span
            className="flex items-center gap-1.5 px-2 py-0.5 rounded-full font-bold uppercase tracking-wide"
            style={{
              fontSize: 10,
              background: isCompleted ? "#dcfce7" : isRunning ? "var(--sc-brand-bg)" : "var(--sc-err-bg)",
              color:      isCompleted ? "#008a44"  : isRunning ? "var(--sc-brand)"   : "var(--sc-error)",
            }}
          >
            <span
              className={cn("w-1.5 h-1.5 rounded-full", isRunning && "animate-pulse")}
              style={{ background: isCompleted ? "#008a44" : isRunning ? "var(--sc-brand)" : "var(--sc-error)" }}
            />
            {isCompleted ? "COMPLETED" : isRunning ? `LIVE ${scan.progress}%` : isFailed ? "FAILED" : "QUEUED"}
          </span>
          <span style={{ color: "var(--sc-outline)" }}>
            Started: {formatDate(scan.created_at)}
          </span>
          {scan.lab_mode && (
            <span style={{ color: "#7c3aed", fontWeight: 700 }}>LAB MODE</span>
          )}
        </div>

        {/* Hero stats */}
        <div className="grid grid-cols-12 gap-4 mb-4 fade-in-up">
          {/* Severity bento */}
          <div className="col-span-12 lg:col-span-8 grid grid-cols-4 gap-4">
            {(["critical","high","medium","low"] as const).map((sev) => {
              const cfg = SEV_CFG[sev];
              const count = sev === "critical" ? criticalCount : sev === "high" ? highCount : sev === "medium" ? mediumCount : lowCount;
              return (
                <div
                  key={sev}
                  className="p-5 flex flex-col justify-between rounded-lg stitch-card"
                  style={{ background: cfg.bg, border: `1px solid ${cfg.border}` }}
                >
                  <div className="flex justify-between items-start">
                    <span
                      className="font-mono font-bold uppercase"
                      style={{ fontSize: 11, color: cfg.color, letterSpacing: "0.05em", opacity: 0.8 }}
                    >
                      {sev}
                    </span>
                    <span className="material-symbols-outlined" style={{ fontSize: 20, color: cfg.color, fontVariationSettings: "'FILL' 1" }}>
                      {cfg.icon}
                    </span>
                  </div>
                  <div>
                    <div className="font-black tabular-nums" style={{ fontSize: 32, color: "var(--sc-on)" }}>
                      {String(count).padStart(2, "0")}
                    </div>
                    <div style={{ fontSize: 11, color: "var(--sc-on-v)" }}>
                      {sev === "critical" ? "Instant remediation" : sev === "high" ? "Potential compromise" : sev === "medium" ? "Internal risks" : "Minor hygiene"}
                    </div>
                  </div>
                </div>
              );
            })}

            {/* Risk score bar chart */}
            <div
              className="col-span-4 h-48 relative overflow-hidden flex items-end p-6 rounded-lg"
              style={{ background: "var(--sc-low)", border: "1px solid var(--sc-border)" }}
            >
              <div
                className="absolute inset-0 opacity-10"
                style={{ background: "radial-gradient(circle at center, var(--sc-brand) 1px, transparent 1px)", backgroundSize: "16px 16px" }}
              />
              <div className="w-full h-full border-b flex items-end gap-1 pb-2" style={{ borderColor: "var(--sc-border)" }}>
                {PIPELINE_PHASES.map(({ label, start, end }) => {
                  const done   = scan.progress >= end;
                  const active = scan.progress >= start && scan.progress < end;
                  const pct    = done ? 100 : active ? Math.round(((scan.progress - start) / (end - start)) * 100) : 10;
                  return (
                    <div
                      key={label}
                      title={`${label} ${pct}%`}
                      className="flex-1 rounded-t-sm chart-bar transition-all"
                      style={{
                        height: `${Math.max(10, pct)}%`,
                        background: done ? "rgba(0,81,213,0.4)" : active ? "rgba(0,81,213,0.6)" : "rgba(0,81,213,0.15)",
                        borderTop: `2px solid ${done ? "rgba(0,81,213,0.7)" : active ? "var(--sc-brand)" : "rgba(0,81,213,0.3)"}`,
                      }}
                    />
                  );
                })}
              </div>
              <div
                className="absolute top-3 right-3 font-mono uppercase tracking-wider"
                style={{ fontSize: 9, color: "var(--sc-outline)" }}
              >
                PIPELINE_PROGRESS
              </div>
            </div>
          </div>

          {/* Attack vector radar */}
          <div
            className="col-span-12 lg:col-span-4 rounded-lg p-6 relative overflow-hidden flex flex-col justify-center items-center stitch-card"
            style={{ background: "#ffffff", border: "1px solid var(--sc-border)", minHeight: 300 }}
          >
            <div className="absolute inset-0" style={{ background: "linear-gradient(135deg, rgba(0,81,213,0.04) 0%, transparent 100%)" }} />
            {/* Radar rings */}
            <div className="relative w-48 h-48">
              {[1, 0.75, 0.5, 0.25].map((scale, i) => (
                <div
                  key={i}
                  className="absolute inset-0 rounded-full border"
                  style={{
                    transform: `scale(${scale})`,
                    borderColor: "rgba(198,198,205,0.5)",
                  }}
                />
              ))}
              {/* Sweep */}
              <div
                className="absolute inset-0 rounded-full origin-center animate-spin"
                style={{
                  background: "linear-gradient(to right, rgba(0,81,213,0.12) 0%, transparent 70%)",
                  animationDuration: "4s",
                  animationTimingFunction: "linear",
                }}
              />
              {/* Data points */}
              <div
                className="absolute w-2.5 h-2.5 rounded-full shadow-lg"
                style={{ top: "10%", left: "50%", transform: "translateX(-50%)", background: "#EF4444" }}
              />
              <div
                className="absolute w-2.5 h-2.5 rounded-full shadow-lg"
                style={{ bottom: "20%", right: "10%", background: "#F97316" }}
              />
              <div
                className="absolute w-2.5 h-2.5 rounded-full shadow-lg"
                style={{ top: "50%", left: "8%", background: "var(--sc-brand)" }}
              />
              {/* Center */}
              <div
                className="absolute inset-0 flex items-center justify-center font-black"
                style={{ fontSize: 20, color: "var(--sc-on)" }}
              >
                {scan.risk_score !== null ? scan.risk_score : "--"}
              </div>
            </div>
            <div className="mt-5 w-full flex justify-between font-mono uppercase" style={{ fontSize: 10, color: "var(--sc-outline)", padding: "0 16px" }}>
              <span>NETWORK</span>
              <span>APP_LOGIC</span>
              <span>DATA</span>
            </div>
          </div>
        </div>

        {/* Toolbar */}
        <div
          className="flex justify-between items-center mb-4 py-2 sticky top-0 z-30"
          style={{ background: "var(--sc-bg)", borderBottom: "1px solid var(--sc-border)" }}
        >
          <div className="flex gap-2">
            {["ALL LEVELS", "OWASP TOP 10"].map((label) => (
              <button
                key={label}
                className="flex items-center gap-2 px-3 py-1.5 rounded-lg transition-all text-xs font-bold"
                style={{ background: "var(--sc-high)", border: "1px solid var(--sc-border)", color: "var(--sc-on)" }}
              >
                <span className="material-symbols-outlined" style={{ fontSize: 14 }}>
                  {label === "ALL LEVELS" ? "filter_list" : "category"}
                </span>
                {label}
              </button>
            ))}
          </div>
          <div className="flex gap-2">
            <button
              className="flex items-center gap-2 px-4 py-1.5 rounded-lg transition-all active:scale-95 text-xs font-bold"
              style={{ background: "#ffffff", border: "1px solid var(--sc-border)", color: "var(--sc-on)" }}
              onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.borderColor = "var(--sc-brand)")}
              onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.borderColor = "var(--sc-border)")}
            >
              <span className="material-symbols-outlined" style={{ fontSize: 14 }}>file_download</span>
              EXPORT JSON
            </button>
            <button
              className="flex items-center gap-2 px-4 py-1.5 rounded-lg font-bold shadow-md transition-all active:scale-95 text-xs uppercase"
              style={{ background: "var(--sc-on)", color: "#ffffff" }}
            >
              <span className="material-symbols-outlined" style={{ fontSize: 14 }}>picture_as_pdf</span>
              Generate Report
            </button>
          </div>
        </div>

        {/* Live pipeline (running) */}
        {isRunning && (
          <div
            className="rounded-xl p-5 mb-4 fade-in-up"
            style={{ background: "#ffffff", border: "1px solid rgba(0,81,213,0.3)" }}
          >
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full animate-pulse" style={{ background: "var(--sc-brand)" }} />
                <h2 className="font-semibold uppercase tracking-widest" style={{ fontSize: 11, color: "var(--sc-brand)" }}>
                  Live Scan Pipeline
                </h2>
              </div>
              <span className="font-mono font-semibold tracking-widest" style={{ fontSize: 10, color: "var(--sc-brand)" }}>
                LIVE {scan.progress}%
              </span>
            </div>
            <ProgressTracker progress={scan.progress} status={scan.status} message={scan.error_message ?? undefined} />
          </div>
        )}

        {/* Failed state */}
        {isFailed && (
          <div
            className="flex items-start gap-3 p-4 rounded-xl mb-4 fade-in"
            style={{ background: "var(--sc-err-bg)", border: "1px solid rgba(186,26,26,0.2)" }}
          >
            <span className="material-symbols-outlined" style={{ fontSize: 20, color: "var(--sc-error)" }}>cancel</span>
            <div>
              <p className="font-semibold" style={{ fontSize: 13, color: "var(--sc-error)" }}>Scan Failed</p>
              <p style={{ fontSize: 11, color: "var(--sc-err-on)", marginTop: 4 }}>
                {scan.error_message ?? "An unexpected error occurred."}
              </p>
            </div>
          </div>
        )}

        {/* Executive Summary */}
        {isCompleted && !!socReport?.executive_summary && (
          <div
            className="rounded-xl p-5 mb-4 stitch-card fade-in-up"
            style={{ background: "#ffffff", border: "1px solid var(--sc-border)" }}
          >
            <div className="flex items-center gap-2 mb-3">
              <span className="material-symbols-outlined" style={{ fontSize: 18, color: "var(--sc-brand)" }}>bolt</span>
              <h2 className="font-semibold uppercase tracking-widest" style={{ fontSize: 11, color: "var(--sc-on-v)" }}>
                Executive Summary
              </h2>
            </div>
            <p style={{ fontSize: 13, color: "var(--sc-on-v)", lineHeight: 1.7 }}>
              {String(socReport.executive_summary)}
            </p>
            {Array.isArray(socReport.recommendations) && socReport.recommendations.length > 0 && (
              <div className="mt-4 space-y-1.5">
                <p className="font-semibold uppercase tracking-widest" style={{ fontSize: 10, color: "var(--sc-outline)" }}>
                  Recommendations
                </p>
                {(socReport.recommendations as string[]).map((rec, i) => (
                  <div key={i} className="flex items-start gap-2" style={{ fontSize: 12, color: "var(--sc-on-v)" }}>
                    <span style={{ color: "var(--sc-brand)", marginTop: 2 }}>›</span>
                    {rec}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Vulnerability List */}
        {vulns.length > 0 && (
          <div className="space-y-3 mb-4">
            {vulns.map((vuln) => {
              const cfg = SEV_CFG[vuln.severity];
              const expanded = expandedVuln === vuln.id;
              return (
                <div
                  key={vuln.id}
                  className="rounded-xl overflow-hidden shadow-sm stitch-card"
                  style={{ background: "#ffffff", border: "1px solid var(--sc-border)" }}
                >
                  <div className="flex items-stretch min-h-[80px]">
                    {/* Severity bar */}
                    <div className="w-2 shrink-0" style={{ background: cfg.color }} />
                    {/* Main row */}
                    <div
                      className="flex-1 p-4 flex items-center justify-between gap-6 cursor-pointer"
                      onClick={() => setExpandedVuln(expanded ? null : vuln.id)}
                    >
                      <div className="flex items-center gap-5 flex-1 min-w-0">
                        {/* CVE / type badge */}
                        <div
                          className="px-2 py-1 rounded font-mono text-xs shrink-0"
                          style={{
                            background: `${cfg.bg}`,
                            color: cfg.color,
                            border: `1px solid ${cfg.border}`,
                          }}
                        >
                          {vuln.cve ?? vuln.type ?? vuln.severity.toUpperCase()}
                        </div>
                        {/* Title + URL */}
                        <div className="flex-1 min-w-0">
                          <h3 className="font-semibold truncate" style={{ fontSize: 14, color: "var(--sc-on)" }}>
                            {vuln.title}
                          </h3>
                          {vuln.url && (
                            <p className="text-xs mt-0.5 truncate font-mono" style={{ color: "var(--sc-on-v)" }}>
                              Found in <span style={{ color: "var(--sc-brand)" }}>{vuln.url}</span>
                            </p>
                          )}
                        </div>
                      </div>
                      {/* CVSS + status */}
                      <div className="flex items-center gap-6 pr-2 shrink-0">
                        {vuln.cvss_score !== undefined && (
                          <div className="text-center">
                            <div className="font-mono uppercase" style={{ fontSize: 9, color: "var(--sc-outline)" }}>CVSS</div>
                            <div className="font-bold font-mono" style={{ fontSize: 18, color: cfg.color }}>
                              {vuln.cvss_score.toFixed(1)}
                            </div>
                          </div>
                        )}
                        <div className="text-center">
                          <div className="font-mono uppercase" style={{ fontSize: 9, color: "var(--sc-outline)" }}>STATUS</div>
                          <div
                            className="px-2 py-0.5 rounded-full font-mono font-bold uppercase"
                            style={{
                              fontSize: 9,
                              background: vuln.status === "active" ? cfg.color : "var(--sc-high)",
                              color: vuln.status === "active" ? "#ffffff" : "var(--sc-on-v)",
                            }}
                          >
                            {vuln.status ?? "OPEN"}
                          </div>
                        </div>
                        <span
                          className="material-symbols-outlined transition-transform"
                          style={{
                            fontSize: 20,
                            color: "var(--sc-border)",
                            transform: expanded ? "rotate(180deg)" : "rotate(0deg)",
                          }}
                        >
                          expand_more
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Expanded details */}
                  {expanded && (
                    <div
                      className="border-t p-6"
                      style={{ background: "var(--sc-low)", borderColor: "var(--sc-border)" }}
                    >
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <div className="space-y-4">
                          {vuln.description && (
                            <div>
                              <h4 className="font-bold uppercase tracking-widest mb-2" style={{ fontSize: 10, color: "var(--sc-on)" }}>
                                Description
                              </h4>
                              <p style={{ fontSize: 13, color: "var(--sc-on-v)", lineHeight: 1.7 }}>
                                {vuln.description}
                              </p>
                            </div>
                          )}
                          {vuln.remediation && (
                            <div>
                              <h4 className="font-bold uppercase tracking-widest mb-2" style={{ fontSize: 10, color: "var(--sc-on)" }}>
                                Remediation
                              </h4>
                              {Array.isArray(vuln.remediation) ? (
                                <ul className="space-y-1" style={{ fontSize: 13, color: "var(--sc-on-v)" }}>
                                  {vuln.remediation.map((r, i) => <li key={i}>• {r}</li>)}
                                </ul>
                              ) : (
                                <p style={{ fontSize: 13, color: "var(--sc-on-v)" }}>{vuln.remediation}</p>
                              )}
                            </div>
                          )}
                        </div>
                        <div className="space-y-4">
                          {vuln.payload && (
                            <div
                              className="rounded p-4"
                              style={{ background: "#ffffff", border: "1px solid var(--sc-border)" }}
                            >
                              <h4
                                className="flex items-center gap-2 font-bold uppercase tracking-widest mb-2"
                                style={{ fontSize: 10, color: "var(--sc-outline)" }}
                              >
                                <span className="material-symbols-outlined" style={{ fontSize: 14 }}>code</span>
                                PAYLOAD / EVIDENCE
                              </h4>
                              <pre
                                className="font-mono overflow-x-auto"
                                style={{ fontSize: 12, color: cfg.color }}
                              >
                                {vuln.payload}
                              </pre>
                            </div>
                          )}
                          <div className="flex gap-3">
                            <button
                              className="flex-1 py-2 text-xs font-bold rounded transition-all"
                              style={{
                                background: "#ffffff",
                                border: "1px solid var(--sc-border)",
                                color: "var(--sc-on)",
                              }}
                              onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.borderColor = "var(--sc-brand)")}
                              onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.borderColor = "var(--sc-border)")}
                            >
                              RE-SCAN TARGET
                            </button>
                            <button
                              className="flex-1 py-2 text-xs font-bold rounded transition-all"
                              style={{
                                background: "#ffffff",
                                border: "1px solid var(--sc-border)",
                                color: "var(--sc-on)",
                              }}
                              onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.borderColor = "var(--sc-brand)")}
                              onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.borderColor = "var(--sc-border)")}
                            >
                              FALSE POSITIVE
                            </button>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}

        {/* Existing ScanResults when completed but no structured vulns extracted */}
        {isCompleted && vulns.length === 0 && (
          <div
            className="rounded-xl p-5 mb-4"
            style={{ background: "#ffffff", border: "1px solid var(--sc-border)" }}
          >
            <div className="flex items-center gap-2 mb-4">
              <span className="material-symbols-outlined" style={{ fontSize: 18, color: "#008a44", fontVariationSettings: "'FILL' 1" }}>
                verified
              </span>
              <h2 className="font-semibold uppercase tracking-widest" style={{ fontSize: 11, color: "var(--sc-on-v)" }}>
                {isCompleted ? "Reconnaissance Findings" : "Partial Results"}
              </h2>
            </div>
            <ScanResults scan={scan} />
          </div>
        )}

        {/* Scanner output terminal */}
        <div
          className="rounded-lg overflow-hidden shadow-xl mt-4 mb-4"
          style={{ background: "#151c27" }}
        >
          <div
            className="px-4 py-2 flex justify-between items-center"
            style={{ background: "var(--sc-high)", borderBottom: "1px solid var(--sc-border)" }}
          >
            <div className="flex gap-1.5">
              {["#EF4444","#F97316","var(--sc-brand)"].map((c, i) => (
                <div key={i} className="w-2.5 h-2.5 rounded-full" style={{ background: c, opacity: 0.6 }} />
              ))}
            </div>
            <span
              className="font-mono uppercase tracking-wider"
              style={{ fontSize: 10, color: "var(--sc-on-v)" }}
            >
              SCANNER_OUTPUT_STREAM
            </span>
            <span className="material-symbols-outlined" style={{ fontSize: 14, color: "var(--sc-outline)" }}>close</span>
          </div>
          <div className="h-40 overflow-y-auto">
            {scanLogs.length > 0 ? (
              <LiveLogs logs={scanLogs} isLive={isRunning} />
            ) : (
              <div className="p-4 font-mono space-y-1" style={{ fontSize: 12 }}>
                <p style={{ color: "rgba(0,81,213,0.7)" }}>
                  [{scan.created_at.slice(11, 19)}] INFO: Scan initialized for {scan.target}
                </p>
                <p style={{ color: "#4ede9c" }}>
                  [{scan.created_at.slice(11, 19)}] SCAN: Pipeline phase: {scan.current_phase ?? "initializing"}
                </p>
                {isCompleted && (
                  <p style={{ color: "#4ede9c" }}>
                    SCAN COMPLETED. Risk Score: {scan.risk_score ?? "N/A"}
                  </p>
                )}
                {isRunning && (
                  <p className="animate-pulse" style={{ color: "rgba(0,81,213,0.7)" }}>
                    PROCESS: {scan.current_phase ?? "Processing"}... {scan.progress}%
                    <span className="inline-block w-2 h-4 ml-1 align-middle animate-pulse" style={{ background: "var(--sc-brand)" }} />
                  </p>
                )}
              </div>
            )}
          </div>
        </div>

      </div>

      {/* Floating status bar */}
      <div
        className="fixed bottom-5 right-5 flex items-center gap-3 px-4 py-2 rounded-full shadow-lg z-50"
        style={{
          background: "#ffffff",
          border: "1px solid rgba(0,81,213,0.2)",
          boxShadow: "0 4px 16px rgba(0,81,213,0.08)",
        }}
      >
        <div
          className={cn("w-2 h-2 rounded-full", isRunning && "animate-ping")}
          style={{ background: isCompleted ? "#008a44" : isRunning ? "var(--sc-brand)" : "var(--sc-error)" }}
        />
        <span className="font-mono font-bold" style={{ fontSize: 10, color: "var(--sc-brand)" }}>
          {isRunning ? "MONITOR_ACTIVE" : isCompleted ? "SCAN_COMPLETE" : "SCAN_FAILED"}
        </span>
        <div className="h-3 w-px" style={{ background: "var(--sc-border)" }} />
        <span className="font-mono" style={{ fontSize: 10, color: "var(--sc-on-v)" }}>
          ID: {scan.id.slice(0, 8).toUpperCase()}
        </span>
      </div>
    </div>
  );
}

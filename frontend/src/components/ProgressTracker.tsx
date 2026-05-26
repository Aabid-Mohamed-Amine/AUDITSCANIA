"use client";

import React from "react";
import { CheckCircle2, Circle, Loader2, XCircle } from "lucide-react";
import { cn } from "@/lib/utils";

/* ── Pipeline — mirrors scan_tasks.py 8-phase order ─────────────────────── */

interface Step {
  id: string;
  label: string;
  desc: string;
  start: number;
  end: number;
}

interface Phase {
  id: string;
  label: string;
  phaseNum: number;
  steps: Step[];
}

const PHASES: Phase[] = [
  {
    id: "asset", label: "Asset Discovery", phaseNum: 1,
    steps: [
      { id: "shodan",  label: "Shodan",       desc: "Passive recon — public index, banners, CVEs",   start: 0,  end: 12 },
    ],
  },
  {
    id: "recon", label: "Active Recon", phaseNum: 2,
    steps: [
      { id: "zap",     label: "OWASP ZAP",    desc: "Web spider — endpoints, ports, vulnerabilities", start: 12, end: 27 },
    ],
  },
  {
    id: "fingerprint", label: "Fingerprinting", phaseNum: 3,
    steps: [
      { id: "nmap",    label: "Nmap",          desc: "Active port & service discovery",              start: 27, end: 44 },
    ],
  },
  {
    id: "vulnscan", label: "Vulnerability Scanning", phaseNum: 4,
    steps: [
      { id: "nuclei",  label: "Nuclei",        desc: "CVE template scan, targeted by Nmap services", start: 44, end: 60 },
    ],
  },
  {
    id: "threatintel", label: "Threat Intelligence", phaseNum: 5,
    steps: [
      { id: "vt",      label: "VirusTotal",    desc: "Malware & reputation analysis",                start: 60, end: 69 },
      { id: "abuse",   label: "AbuseIPDB",     desc: "Abuse confidence & blacklist check",           start: 69, end: 78 },
    ],
  },
  {
    id: "correlation", label: "Correlation Engine", phaseNum: 6,
    steps: [
      { id: "corr",    label: "Correlator",    desc: "Fuse Nmap + ZAP + Nuclei + Threat Intel",      start: 78, end: 88 },
    ],
  },
  {
    id: "riskscore", label: "Risk Scoring", phaseNum: 7,
    steps: [
      { id: "score",   label: "Risk Engine",   desc: "Multi-factor weighted scoring",                start: 88, end: 94 },
    ],
  },
  {
    id: "soc", label: "SOC Dashboard", phaseNum: 8,
    steps: [
      { id: "soc",     label: "SOC Report",    desc: "Executive summary & recommendations",          start: 94, end: 100 },
    ],
  },
];

/* ── Helpers ─────────────────────────────────────────────────────────────── */

type S = "done" | "active" | "pending" | "failed";

function stepStatus(start: number, end: number, prog: number, scanStatus: string): S {
  if (scanStatus === "failed") {
    if (prog >= end)   return "done";
    if (prog >= start) return "failed";
    return "pending";
  }
  if (prog >= end)   return "done";
  if (prog >= start) return "active";
  return "pending";
}

function phaseStatus(phase: Phase, prog: number, scanStatus: string): S {
  return stepStatus(
    phase.steps[0].start,
    phase.steps[phase.steps.length - 1].end,
    prog, scanStatus
  );
}

/* ── Status icon ─────────────────────────────────────────────────────────── */

function Icon({ s }: { s: S }) {
  if (s === "done")   return <CheckCircle2 className="w-[15px] h-[15px] text-emerald-400 shrink-0" />;
  if (s === "active") return <Loader2      className="w-[15px] h-[15px] text-blue-400 animate-spin shrink-0" />;
  if (s === "failed") return <XCircle      className="w-[15px] h-[15px] text-red-400 shrink-0" />;
  return                     <Circle       className="w-[15px] h-[15px] text-[#1a3550] shrink-0" />;
}

/* ── Component ───────────────────────────────────────────────────────────── */

interface Props { progress: number; status: string; message?: string }

export default function ProgressTracker({ progress, status, message }: Props) {
  const pct = Math.min(progress, 100);
  const barColor =
    status === "failed"    ? "bg-red-500"     :
    status === "completed" ? "bg-emerald-500" :
    "bg-blue-500";

  return (
    <div className="space-y-4">

      {/* ── Global progress bar ─────────────────────────────── */}
      <div>
        <div className="flex items-center justify-between mb-1.5">
          <span className="text-[12px] text-[#7aa8cc] truncate">
            {status === "completed" ? "Scan complete"
             : status === "failed"  ? "Scan failed"
             : message || "Scanning…"}
          </span>
          <span className="text-[12px] font-mono text-[#3d6080] shrink-0 ml-2 tabular-nums">
            {pct}%
          </span>
        </div>
        <div className="h-[3px] bg-[#0f1e30] rounded-full overflow-hidden">
          <div
            className={cn("h-full rounded-full transition-all duration-500", barColor)}
            style={{ width: `${pct}%` }}
          />
        </div>
      </div>

      {/* ── Phase stepper ───────────────────────────────────── */}
      <div className="space-y-[2px]">
        {PHASES.map((phase) => {
          const ps   = phaseStatus(phase, progress, status);
          const show = ps !== "pending";

          return (
            <div
              key={phase.id}
              className={cn(
                "rounded-[5px] border transition-all duration-200 overflow-hidden",
                ps === "done"    && "border-[#0f2a1a] bg-emerald-950/20",
                ps === "active"  && "border-blue-800/50 bg-blue-950/20",
                ps === "failed"  && "border-red-900/50 bg-red-950/20",
                ps === "pending" && "border-[#0a1828] bg-transparent opacity-40"
              )}
            >
              {/* Phase header */}
              <div className="flex items-center gap-2.5 px-3 py-2">
                {/* Phase number */}
                <span
                  className={cn(
                    "text-[10px] font-bold w-5 h-5 rounded-full flex items-center justify-center shrink-0 font-mono",
                    ps === "done"    ? "bg-emerald-500/20 text-emerald-400" :
                    ps === "active"  ? "bg-blue-500/20 text-blue-400"      :
                    ps === "failed"  ? "bg-red-500/20 text-red-400"        :
                    "bg-[#0a1828] text-[#1a3550]"
                  )}
                >
                  {phase.phaseNum}
                </span>

                <Icon s={ps} />

                <span
                  className={cn(
                    "text-[12px] font-semibold flex-1",
                    ps === "done"    ? "text-emerald-400" :
                    ps === "active"  ? "text-blue-300"    :
                    ps === "failed"  ? "text-red-400"     :
                    "text-[#1e3a55]"
                  )}
                >
                  {phase.label}
                </span>

                <span
                  className={cn(
                    "text-[9px] font-bold px-1.5 py-0.5 rounded-[3px] border tracking-widest uppercase shrink-0",
                    ps === "done"    ? "text-emerald-400 bg-emerald-950/60 border-emerald-800/60"  :
                    ps === "active"  ? "text-blue-400 bg-blue-950/60 border-blue-800/60"          :
                    ps === "failed"  ? "text-red-400 bg-red-950/60 border-red-800/60"             :
                    "text-[#1a3550] bg-transparent border-[#0a1828]"
                  )}
                >
                  {ps === "done" ? "Done" : ps === "active" ? "Running" : ps === "failed" ? "Failed" : "Pending"}
                </span>
              </div>

              {/* Sub-steps (shown when active or done) */}
              {show && phase.steps.length > 1 && (
                <div className="border-t border-[#0f1e30]/60 px-3 pt-1.5 pb-2 space-y-1.5">
                  {phase.steps.map((step) => {
                    const ss = stepStatus(step.start, step.end, progress, status);
                    return (
                      <div key={step.id} className="flex items-center gap-2.5 pl-7">
                        <Icon s={ss} />
                        <span
                          className={cn(
                            "text-[11px]",
                            ss === "done"    ? "text-[#4a8ab5]"  :
                            ss === "active"  ? "text-blue-300"   :
                            ss === "failed"  ? "text-red-400"    :
                            "text-[#1e3a55]"
                          )}
                        >
                          {step.label}
                        </span>
                        <span className="text-[10px] text-[#1a3550] ml-auto font-mono">
                          {step.end}%
                        </span>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

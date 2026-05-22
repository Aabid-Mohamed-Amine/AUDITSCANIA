"use client";

import React from "react";
import { CheckCircle2, Circle, Loader2, XCircle } from "lucide-react";
import { Progress } from "@/components/ui/progress";
import { cn } from "@/lib/utils";

// ---------------------------------------------------------------------------
// Pipeline definition — must mirror scan_tasks.py progress ranges
// ---------------------------------------------------------------------------

interface SubStep {
  id: string;
  label: string;
  description: string;
  progressStart: number;
  progressEnd: number;
}

interface Phase {
  id: string;
  label: string;
  steps: SubStep[];
}

const PHASES: Phase[] = [
  {
    id: "threat-intel",
    label: "Threat Intelligence",
    steps: [
      {
        id: "shodan",
        label: "Shodan",
        description: "Passive recon — open ports, banners, CVEs",
        progressStart: 0,
        progressEnd: 15,
      },
      {
        id: "virustotal",
        label: "VirusTotal",
        description: "Malware & reputation analysis",
        progressStart: 15,
        progressEnd: 30,
      },
      {
        id: "abuseipdb",
        label: "AbuseIPDB",
        description: "Abuse database & blacklist check",
        progressStart: 30,
        progressEnd: 45,
      },
    ],
  },
  {
    id: "network",
    label: "Network Scan",
    steps: [
      {
        id: "nmap",
        label: "Nmap",
        description: "Active port & service fingerprinting",
        progressStart: 45,
        progressEnd: 60,
      },
    ],
  },
  {
    id: "active-detection",
    label: "Active Detection",
    steps: [
      {
        id: "nuclei",
        label: "Nuclei",
        description: "CVE & vulnerability template scan",
        progressStart: 60,
        progressEnd: 76,
      },
      {
        id: "zap",
        label: "OWASP ZAP",
        description: "Web application security scan",
        progressStart: 76,
        progressEnd: 92,
      },
      {
        id: "score",
        label: "Risk Aggregation",
        description: "Computing final risk score",
        progressStart: 92,
        progressEnd: 100,
      },
    ],
  },
];

// ---------------------------------------------------------------------------
// Status helpers
// ---------------------------------------------------------------------------

type StepStatus = "done" | "active" | "pending" | "failed";

function computeStepStatus(
  progressStart: number,
  progressEnd: number,
  progress: number,
  scanStatus: string
): StepStatus {
  if (scanStatus === "failed") {
    if (progress >= progressEnd) return "done";
    if (progress >= progressStart) return "failed";
    return "pending";
  }
  if (progress >= progressEnd) return "done";
  if (progress >= progressStart) return "active";
  return "pending";
}

function computePhaseStatus(phase: Phase, progress: number, scanStatus: string): StepStatus {
  const first = phase.steps[0];
  const last = phase.steps[phase.steps.length - 1];
  return computeStepStatus(first.progressStart, last.progressEnd, progress, scanStatus);
}

// ---------------------------------------------------------------------------
// Icons
// ---------------------------------------------------------------------------

function StepIcon({ status }: { status: StepStatus }) {
  if (status === "done")
    return <CheckCircle2 className="h-4 w-4 text-green-400 flex-shrink-0" />;
  if (status === "active")
    return <Loader2 className="h-4 w-4 text-cyan-400 animate-spin flex-shrink-0" />;
  if (status === "failed")
    return <XCircle className="h-4 w-4 text-red-400 flex-shrink-0" />;
  return <Circle className="h-4 w-4 text-slate-600 flex-shrink-0" />;
}

// ---------------------------------------------------------------------------
// Phase colour tokens
// ---------------------------------------------------------------------------

const PHASE_COLORS: Record<string, { border: string; bg: string; label: string; badge: string; badgeBg: string }> = {
  "threat-intel": {
    border: "border-cyan-500/20",
    bg: "bg-cyan-500/5",
    label: "text-cyan-400",
    badge: "text-cyan-400",
    badgeBg: "bg-cyan-400/10 border-cyan-400/20",
  },
  network: {
    border: "border-blue-500/20",
    bg: "bg-blue-500/5",
    label: "text-blue-400",
    badge: "text-blue-400",
    badgeBg: "bg-blue-400/10 border-blue-400/20",
  },
  "active-detection": {
    border: "border-orange-500/20",
    bg: "bg-orange-500/5",
    label: "text-orange-400",
    badge: "text-orange-400",
    badgeBg: "bg-orange-400/10 border-orange-400/20",
  },
};

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

interface ProgressTrackerProps {
  progress: number;
  status: string;
  message?: string;
}

export default function ProgressTracker({ progress, status, message }: ProgressTrackerProps) {
  return (
    <div className="space-y-5">
      {/* ── Global bar ── */}
      <div className="space-y-1.5">
        <div className="flex justify-between items-center">
          <span className="text-sm text-slate-300 font-medium">
            {status === "completed"
              ? "Scan complete"
              : status === "failed"
              ? "Scan failed"
              : message || "Scanning…"}
          </span>
          <span className="text-sm text-slate-400 tabular-nums font-mono">{progress}%</span>
        </div>
        <Progress
          value={progress}
          className={cn(
            "h-2 bg-slate-700",
            status === "failed" && "[&>div]:bg-red-500",
            status === "completed" && "[&>div]:bg-green-500"
          )}
        />
      </div>

      {/* ── Phases ── */}
      <div className="space-y-3">
        {PHASES.map((phase) => {
          const ps = computePhaseStatus(phase, progress, status);
          const colors = PHASE_COLORS[phase.id];
          const isVisible = ps !== "pending";

          return (
            <div
              key={phase.id}
              className={cn(
                "rounded-lg border transition-all",
                ps === "done" && "border-green-500/20 bg-green-500/5",
                ps === "active" && cn("border-2", colors.border, colors.bg),
                ps === "failed" && "border-red-500/20 bg-red-500/5",
                ps === "pending" && "border-slate-700/40 bg-slate-800/20 opacity-50"
              )}
            >
              {/* Phase header */}
              <div className="flex items-center justify-between px-4 py-3">
                <div className="flex items-center gap-2">
                  <StepIcon status={ps} />
                  <span
                    className={cn(
                      "text-sm font-semibold",
                      ps === "done" && "text-green-400",
                      ps === "active" && colors.label,
                      ps === "failed" && "text-red-400",
                      ps === "pending" && "text-slate-500"
                    )}
                  >
                    {phase.label}
                  </span>
                </div>
                <span
                  className={cn(
                    "text-[10px] font-medium px-2 py-0.5 rounded-full border",
                    ps === "done" && "text-green-400 bg-green-400/10 border-green-400/20",
                    ps === "active" && cn(colors.badge, colors.badgeBg),
                    ps === "failed" && "text-red-400 bg-red-400/10 border-red-400/20",
                    ps === "pending" && "text-slate-600 bg-slate-700/20 border-slate-700"
                  )}
                >
                  {ps === "done"
                    ? "Done"
                    : ps === "active"
                    ? "Running"
                    : ps === "failed"
                    ? "Failed"
                    : "Pending"}
                </span>
              </div>

              {/* Sub-steps — only shown when phase is active or done */}
              {isVisible && (
                <div className="border-t border-slate-700/30 px-4 pt-2 pb-3 space-y-2">
                  {phase.steps.map((step) => {
                    const ss = computeStepStatus(
                      step.progressStart,
                      step.progressEnd,
                      progress,
                      status
                    );
                    return (
                      <div key={step.id} className="flex items-center gap-3">
                        <StepIcon status={ss} />
                        <div className="flex-1 min-w-0">
                          <span
                            className={cn(
                              "text-xs font-medium",
                              ss === "done" && "text-slate-300",
                              ss === "active" && "text-cyan-300",
                              ss === "failed" && "text-red-400",
                              ss === "pending" && "text-slate-600"
                            )}
                          >
                            {step.label}
                          </span>
                          <span className="text-xs text-slate-600 ml-2 hidden sm:inline">
                            {step.description}
                          </span>
                        </div>
                        <span className="text-[10px] text-slate-600 tabular-nums flex-shrink-0">
                          {step.progressEnd}%
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

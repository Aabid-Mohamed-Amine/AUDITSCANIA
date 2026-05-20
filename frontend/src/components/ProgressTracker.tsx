"use client";

import React from "react";
import { CheckCircle2, Circle, Loader2, XCircle } from "lucide-react";
import { Progress } from "@/components/ui/progress";
import { cn } from "@/lib/utils";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface Step {
  id: string;
  label: string;
  description: string;
  progressStart: number;
  progressEnd: number;
}

const STEPS: Step[] = [
  {
    id: "shodan",
    label: "Shodan",
    description: "Passive recon – ports, services, CVEs",
    progressStart: 0,
    progressEnd: 25,
  },
  {
    id: "virustotal",
    label: "VirusTotal",
    description: "Malware & reputation check",
    progressStart: 25,
    progressEnd: 50,
  },
  {
    id: "abuseipdb",
    label: "AbuseIPDB",
    description: "Abuse & threat intelligence",
    progressStart: 50,
    progressEnd: 75,
  },
  {
    id: "nmap",
    label: "Nmap",
    description: "Active port & service scan",
    progressStart: 75,
    progressEnd: 100,
  },
];

function getStepStatus(
  step: Step,
  progress: number,
  scanStatus: string
): "done" | "active" | "pending" | "failed" {
  if (scanStatus === "failed") {
    if (progress >= step.progressEnd) return "done";
    if (progress >= step.progressStart) return "failed";
    return "pending";
  }
  if (progress >= step.progressEnd) return "done";
  if (progress >= step.progressStart) return "active";
  return "pending";
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

interface ProgressTrackerProps {
  progress: number;
  status: string;
  message?: string;
}

export default function ProgressTracker({
  progress,
  status,
  message,
}: ProgressTrackerProps) {
  const isFinished = status === "completed" || status === "failed";

  return (
    <div className="space-y-6">
      {/* Overall bar */}
      <div className="space-y-2">
        <div className="flex justify-between items-center text-sm">
          <span className="text-slate-300 font-medium">
            {status === "completed"
              ? "Scan complete"
              : status === "failed"
              ? "Scan failed"
              : message || "Scanning…"}
          </span>
          <span className="text-slate-400 tabular-nums">{progress}%</span>
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

      {/* Step list */}
      <div className="space-y-3">
        {STEPS.map((step, idx) => {
          const stepStatus = getStepStatus(step, progress, status);

          return (
            <div key={step.id} className="flex items-start gap-3">
              {/* Icon */}
              <div className="flex-shrink-0 mt-0.5">
                {stepStatus === "done" && (
                  <CheckCircle2 className="h-5 w-5 text-green-400" />
                )}
                {stepStatus === "active" && (
                  <Loader2 className="h-5 w-5 text-blue-400 animate-spin" />
                )}
                {stepStatus === "failed" && (
                  <XCircle className="h-5 w-5 text-red-400" />
                )}
                {stepStatus === "pending" && (
                  <Circle className="h-5 w-5 text-slate-600" />
                )}
              </div>

              {/* Text */}
              <div className="flex-1 min-w-0">
                <p
                  className={cn(
                    "text-sm font-medium",
                    stepStatus === "done" && "text-green-400",
                    stepStatus === "active" && "text-blue-400",
                    stepStatus === "failed" && "text-red-400",
                    stepStatus === "pending" && "text-slate-500"
                  )}
                >
                  {step.label}
                </p>
                <p className="text-xs text-slate-500 mt-0.5">{step.description}</p>
              </div>

              {/* Progress range */}
              <span className="text-xs text-slate-600 flex-shrink-0 tabular-nums">
                {step.progressStart}–{step.progressEnd}%
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

"use client";

import React from "react";
import Link from "next/link";
import { Trash2, ChevronRight, Square } from "lucide-react";
import { Scan } from "@/lib/api";
import { formatDate } from "@/lib/utils";
import { useDeleteScan, useStopScan } from "@/hooks/useScans";
import RiskScore from "@/components/RiskScore";
import { cn } from "@/lib/utils";

interface Props { scan: Scan }

const STATUS_CONFIG: Record<string, { dot: string; label: string; text: string }> = {
  completed: { dot: "bg-emerald-500",              label: "bg-emerald-950/50 text-emerald-400 border-emerald-900/50", text: "Completed" },
  running:   { dot: "bg-indigo-400 animate-pulse", label: "bg-indigo-950/50  text-indigo-400  border-indigo-900/50",  text: "Running"   },
  pending:   { dot: "bg-amber-500",                label: "bg-amber-950/50   text-amber-400   border-amber-900/50",   text: "Queued"    },
  failed:    { dot: "bg-red-500",                  label: "bg-red-950/50     text-red-400     border-red-900/50",     text: "Failed"    },
};

export default function ScanCard({ scan }: Props) {
  const deleteScan = useDeleteScan();
  const stopScan   = useStopScan();
  const cfg      = STATUS_CONFIG[scan.status] ?? STATUS_CONFIG.pending;
  const isActive = scan.status === "running" || scan.status === "pending";
  const progress = scan.progress ?? 0;

  const handleDelete = (e: React.MouseEvent) => {
    e.preventDefault(); e.stopPropagation();
    if (confirm(`Delete scan for ${scan.target}?`)) deleteScan.mutate(scan.id);
  };

  const handleStop = (e: React.MouseEvent) => {
    e.preventDefault(); e.stopPropagation();
    if (confirm(`Stop scan for ${scan.target}?`)) stopScan.mutate(scan.id);
  };

  return (
    <Link
      href={`/dashboard/scans/${scan.id}`}
      className="group flex items-center gap-4 px-4 py-3 rounded-xl bg-zinc-900 border border-zinc-800 card-hover hover:bg-zinc-800/40 transition-all"
    >
      <span className={cn(
        "w-2 h-2 rounded-full shrink-0 mt-0.5 transition-transform duration-200 group-hover:scale-125",
        cfg.dot
      )} />

      <div className="flex-1 min-w-0">
        <p className="text-[13px] font-mono font-medium text-zinc-400 truncate group-hover:text-zinc-100 transition-colors duration-150">
          {scan.target}
        </p>
        <div className="flex items-center gap-3 mt-0.5">
          <span className="text-[11px] text-zinc-700">{formatDate(scan.created_at)}</span>
          <span className="text-[11px] font-mono text-zinc-800">{scan.id.slice(0, 8)}</span>
        </div>

        {isActive && (
          <div className="mt-2 flex items-center gap-2">
            <div className="flex-1 h-[2px] bg-zinc-800 rounded-full overflow-hidden">
              {scan.status === "running" ? (
                <div className="h-full bg-indigo-500 rounded-full prog-fill" style={{ width: `${progress}%` }} />
              ) : (
                <div className="h-full w-1/3 bg-indigo-500/40 rounded-full scan-sweep" />
              )}
            </div>
            <span className="text-[10px] font-mono text-zinc-700 shrink-0 tabular-nums">{progress}%</span>
          </div>
        )}
      </div>

      <span className={cn(
        "shrink-0 text-[10px] font-semibold px-2 py-0.5 rounded-md border tracking-wide uppercase",
        cfg.label
      )}>
        {cfg.text}
      </span>

      {scan.risk_score !== null && scan.risk_score !== undefined && (
        <div className="shrink-0"><RiskScore score={scan.risk_score} size="sm" /></div>
      )}

      <div className="flex items-center gap-1 shrink-0 opacity-0 group-hover:opacity-100 transition-opacity duration-150">
        {isActive && (
          <button onClick={handleStop} disabled={stopScan.isPending}
            className="w-7 h-7 flex items-center justify-center rounded-lg text-zinc-600 hover:text-red-400 hover:bg-red-950/30 transition-all"
            title="Stop scan">
            <Square className="w-3.5 h-3.5" />
          </button>
        )}
        <button onClick={handleDelete} disabled={deleteScan.isPending}
          className="w-7 h-7 flex items-center justify-center rounded-lg text-zinc-700 hover:text-red-400 hover:bg-red-950/30 transition-all"
          title="Delete">
          <Trash2 className="w-3.5 h-3.5" />
        </button>
      </div>

      <ChevronRight className="w-4 h-4 text-zinc-800 group-hover:text-indigo-400 group-hover:translate-x-0.5 transition-all duration-150 shrink-0" />
    </Link>
  );
}

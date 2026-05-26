"use client";

import React from "react";
import Link from "next/link";
import { Trash2, ChevronRight } from "lucide-react";
import { Scan } from "@/lib/api";
import { formatDate } from "@/lib/utils";
import { useDeleteScan } from "@/hooks/useScans";
import RiskScore from "@/components/RiskScore";
import { cn } from "@/lib/utils";

interface Props { scan: Scan }

const STATUS_CONFIG: Record<string, { dot: string; label: string; text: string }> = {
  completed: { dot: "bg-emerald-400",    label: "bg-emerald-950/60 text-emerald-400 border-emerald-800/60",  text: "Completed" },
  running:   { dot: "bg-blue-400 animate-pulse", label: "bg-blue-950/60 text-blue-400 border-blue-800/60",   text: "Running"   },
  pending:   { dot: "bg-amber-400",      label: "bg-amber-950/60 text-amber-400 border-amber-800/60",        text: "Queued"    },
  failed:    { dot: "bg-red-400",        label: "bg-red-950/60 text-red-400 border-red-800/60",              text: "Failed"    },
};

export default function ScanCard({ scan }: Props) {
  const deleteScan = useDeleteScan();
  const cfg = STATUS_CONFIG[scan.status] ?? STATUS_CONFIG.pending;
  const isActive = scan.status === "running" || scan.status === "pending";

  const handleDelete = (e: React.MouseEvent) => {
    e.preventDefault(); e.stopPropagation();
    if (confirm(`Delete scan for ${scan.target}?`)) deleteScan.mutate(scan.id);
  };

  return (
    <Link
      href={`/dashboard/scans/${scan.id}`}
      className="group flex items-center gap-4 px-4 py-3 rounded-[6px] bg-[#080f1e] border border-[#0f1e30] hover:border-blue-800/60 hover:bg-[#0a1428] transition-all duration-150"
    >
      {/* Status dot */}
      <span className={cn("w-2 h-2 rounded-full shrink-0 mt-0.5", cfg.dot)} />

      {/* Target + meta */}
      <div className="flex-1 min-w-0">
        <p className="text-[13px] font-mono font-medium text-[#c0d8f0] truncate group-hover:text-white transition-colors">
          {scan.target}
        </p>
        <div className="flex items-center gap-3 mt-0.5">
          <span className="text-[11px] text-[#2a5070]">{formatDate(scan.created_at)}</span>
          <span className="text-[11px] font-mono text-[#1e3a55]">{scan.id.slice(0, 8)}</span>
        </div>
        {isActive && (
          <div className="mt-2 flex items-center gap-2">
            <div className="flex-1 h-[3px] bg-[#0f1e30] rounded-full overflow-hidden">
              <div
                className="h-full bg-blue-500 rounded-full transition-all duration-500"
                style={{ width: `${scan.progress}%` }}
              />
            </div>
            <span className="text-[10px] font-mono text-[#2a5070] shrink-0">{scan.progress}%</span>
          </div>
        )}
      </div>

      {/* Status badge */}
      <span
        className={cn(
          "shrink-0 text-[10px] font-semibold px-2 py-0.5 rounded-[3px] border tracking-wide uppercase",
          cfg.label
        )}
      >
        {cfg.text}
      </span>

      {/* Risk score */}
      {scan.risk_score !== null && scan.risk_score !== undefined && (
        <div className="shrink-0">
          <RiskScore score={scan.risk_score} size="sm" />
        </div>
      )}

      {/* Actions */}
      <div className="flex items-center gap-1 shrink-0 opacity-0 group-hover:opacity-100 transition-opacity">
        <button
          onClick={handleDelete}
          disabled={deleteScan.isPending}
          className="w-7 h-7 flex items-center justify-center rounded-[4px] text-[#2a5070] hover:text-red-400 hover:bg-red-500/10 transition-colors"
          title="Delete"
        >
          <Trash2 className="w-3.5 h-3.5" />
        </button>
      </div>

      <ChevronRight className="w-4 h-4 text-[#1a3550] group-hover:text-blue-400 transition-colors shrink-0" />
    </Link>
  );
}

"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useScans } from "@/hooks/useScans";
import ScanCard from "@/components/ScanCard";
import {
  History, Shield, PlusCircle, Search, RefreshCw,
  CheckCircle2, Activity, XCircle, AlertTriangle,
} from "lucide-react";
import { cn } from "@/lib/utils";

const FILTERS = [
  { id: "all",       label: "All",       icon: Shield       },
  { id: "completed", label: "Completed", icon: CheckCircle2 },
  { id: "running",   label: "Active",    icon: Activity     },
  { id: "failed",    label: "Failed",    icon: XCircle      },
];

export default function HistoryPage() {
  const [search, setSearch]           = useState("");
  const [statusFilter, setFilter]     = useState("all");
  const { data, isLoading, error, refetch, isFetching } = useScans(0, 100);

  const scans    = data?.items ?? [];
  const filtered = scans.filter((s) => {
    const matchSearch = s.target.toLowerCase().includes(search.toLowerCase()) ||
                        s.id.toLowerCase().includes(search.toLowerCase());
    const matchStatus = statusFilter === "all" || s.status === statusFilter;
    return matchSearch && matchStatus;
  });

  return (
    <div className="flex flex-col h-full overflow-auto">

      {/* ── Top bar ── */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-[#0f1e30] bg-[#060d1a] shrink-0">
        <div>
          <div className="flex items-center gap-1.5 text-[10px] text-[#1a3550] mb-1">
            <Link href="/dashboard" className="hover:text-blue-400 transition-colors">Dashboard</Link>
            <span>/</span>
            <span className="text-[#2a5070]">Scan History</span>
          </div>
          <h1 className="text-[15px] font-semibold text-[#c0d8f0] flex items-center gap-2">
            <History className="w-4 h-4 text-[#2a5070]" />
            Scan Operations History
          </h1>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-[5px] text-[11px] text-[#3d6080] bg-[#080f1e] border border-[#0f1e30] hover:border-blue-900/60 hover:text-blue-400 transition-all disabled:opacity-50"
          >
            <RefreshCw className={cn("w-3 h-3", isFetching && "animate-spin")} />
            Refresh
          </button>
          <Link
            href="/dashboard/scans/new"
            className="flex items-center gap-1.5 bg-blue-600 hover:bg-blue-500 text-white font-semibold text-[12px] px-3.5 py-1.5 rounded-[5px] transition-colors"
          >
            <PlusCircle className="w-3.5 h-3.5" />
            New Scan
          </Link>
        </div>
      </div>

      <div className="flex-1 p-6 space-y-4 max-w-7xl w-full mx-auto">

        {/* ── Toolbar ── */}
        <div className="flex flex-col sm:flex-row gap-3">
          {/* Search */}
          <div className="relative flex-1 max-w-sm">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#1a3550]" />
            <input
              type="text"
              placeholder="Search by target or scan ID…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-[#080f1e] border border-[#0f1e30] rounded-[5px] pl-9 pr-3 py-2 text-[12px] text-[#8ab8d8] placeholder-[#1a3550] focus:outline-none focus:border-blue-800/60 focus:ring-1 focus:ring-blue-800/30 transition font-mono"
            />
          </div>

          {/* Filters */}
          <div className="flex gap-1.5">
            {FILTERS.map((f) => (
              <button
                key={f.id}
                onClick={() => setFilter(f.id)}
                className={cn(
                  "flex items-center gap-1.5 px-3 py-2 rounded-[5px] text-[11px] font-semibold border transition-all uppercase tracking-wide",
                  statusFilter === f.id
                    ? "bg-blue-950/60 text-blue-400 border-blue-800/60"
                    : "bg-[#080f1e] text-[#2a5070] border-[#0f1e30] hover:text-[#4a8ab5] hover:border-[#1a3550]"
                )}
              >
                <f.icon className="w-3 h-3" />
                {f.label}
              </button>
            ))}
          </div>
        </div>

        {/* ── Results count ── */}
        <div className="flex items-center gap-2">
          <span className="text-[11px] text-[#1a3550]">
            {filtered.length} {filtered.length === 1 ? "result" : "results"}
            {search && ` for "${search}"`}
          </span>
        </div>

        {/* ── List ── */}
        {isLoading && (
          <div className="space-y-2">
            {[...Array(6)].map((_, i) => (
              <div key={i} className="h-14 bg-[#080f1e] border border-[#0f1e30] rounded-[6px] animate-pulse" />
            ))}
          </div>
        )}

        {error && (
          <div className="flex items-center gap-3 p-4 bg-red-950/30 border border-red-900/60 rounded-[6px]">
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
            <p className="text-[12px] text-red-400">Failed to load scans: {(error as Error).message}</p>
          </div>
        )}

        {!isLoading && !error && (
          <div className="space-y-1.5">
            {filtered.length > 0 ? (
              filtered.map((scan) => <ScanCard key={scan.id} scan={scan} />)
            ) : (
              <div className="flex flex-col items-center justify-center py-16 gap-3">
                <History className="w-10 h-10 text-[#0f1e30]" />
                <p className="text-[13px] text-[#1a3550]">No scans match your filters</p>
                <Link
                  href="/dashboard/scans/new"
                  className="text-[12px] text-blue-400 hover:text-blue-300 transition-colors"
                >
                  Start a new scan →
                </Link>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

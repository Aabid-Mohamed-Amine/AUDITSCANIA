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
  const [search, setSearch]       = useState("");
  const [statusFilter, setFilter] = useState("all");
  const { data, isLoading, error, refetch, isFetching } = useScans(0, 100);

  const scans    = data?.items ?? [];
  const filtered = scans.filter((s) => {
    const matchSearch = s.target.toLowerCase().includes(search.toLowerCase()) ||
                        s.id.toLowerCase().includes(search.toLowerCase());
    const matchStatus = statusFilter === "all" || s.status === statusFilter;
    return matchSearch && matchStatus;
  });

  return (
    <div className="flex flex-col h-full overflow-auto bg-zinc-950">

      <div className="flex items-center justify-between px-6 py-3.5 border-b border-zinc-800/60 bg-zinc-950 shrink-0 fade-in-down">
        <div>
          <div className="flex items-center gap-1.5 text-[10px] text-zinc-700 font-mono mb-1">
            <Link href="/dashboard" className="hover:text-indigo-400 transition-colors">Dashboard</Link>
            <span>/</span>
            <span className="text-zinc-600">History</span>
          </div>
          <h1 className="text-[15px] font-semibold text-zinc-100 flex items-center gap-2">
            <History className="w-4 h-4 text-zinc-600" />
            Scan History
          </h1>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] text-zinc-500 border border-zinc-800 hover:border-indigo-800/40 hover:text-indigo-400 transition-all disabled:opacity-50"
          >
            <RefreshCw className={cn("w-3 h-3", isFetching && "animate-spin")} />
            Refresh
          </button>
          <Link
            href="/dashboard/scans/new"
            className="flex items-center gap-1.5 bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-[12px] px-3.5 py-1.5 rounded-lg transition-all btn-glow active:scale-95"
          >
            <PlusCircle className="w-3.5 h-3.5" />
            New Scan
          </Link>
        </div>
      </div>

      <div className="flex-1 p-5 space-y-4 max-w-5xl w-full mx-auto">

        <div className="flex flex-col sm:flex-row gap-3 fade-in-up">
          <div className="relative flex-1 max-w-sm">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-zinc-600" />
            <input
              type="text"
              placeholder="Search by target or ID…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-zinc-800/50 border border-zinc-700 rounded-lg pl-9 pr-3 py-2 text-[12px] text-zinc-300 placeholder-zinc-600 outline-none input-glow transition font-mono"
            />
          </div>

          <div className="flex gap-1.5">
            {FILTERS.map((f) => (
              <button
                key={f.id}
                onClick={() => setFilter(f.id)}
                className={cn(
                  "flex items-center gap-1.5 px-3 py-2 rounded-lg text-[11px] font-semibold border transition-all uppercase tracking-wide",
                  statusFilter === f.id
                    ? "bg-indigo-500/10 text-indigo-400 border-indigo-900/50"
                    : "bg-transparent text-zinc-600 border-zinc-800 hover:text-zinc-400 hover:border-zinc-700"
                )}
              >
                <f.icon className="w-3 h-3" />
                {f.label}
              </button>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-[11px] text-zinc-700 font-mono">
            {filtered.length} {filtered.length === 1 ? "result" : "results"}
            {search && ` matching "${search}"`}
          </span>
        </div>

        {isLoading && (
          <div className="space-y-2">
            {[...Array(6)].map((_, i) => (
              <div key={i} className="h-14 skeleton rounded-xl" style={{ animationDelay: `${i * 40}ms` }} />
            ))}
          </div>
        )}

        {error && (
          <div className="flex items-center gap-3 p-4 bg-red-950/40 border border-red-900/50 rounded-xl">
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
            <p className="text-[12px] text-red-400">Failed to load scans: {(error as Error).message}</p>
          </div>
        )}

        {!isLoading && !error && (
          <div className="space-y-2 stagger">
            {filtered.length > 0 ? (
              filtered.map((scan) => <ScanCard key={scan.id} scan={scan} />)
            ) : (
              <div className="flex flex-col items-center justify-center py-20 gap-3">
                <div className="w-12 h-12 rounded-xl bg-zinc-900 border border-zinc-800 flex items-center justify-center">
                  <History className="w-5 h-5 text-zinc-700" />
                </div>
                <p className="text-[13px] text-zinc-600">No scans match your filters</p>
                <Link
                  href="/dashboard/scans/new"
                  className="text-[12px] text-indigo-400 hover:text-indigo-300 transition-colors"
                >
                  Launch a new scan →
                </Link>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

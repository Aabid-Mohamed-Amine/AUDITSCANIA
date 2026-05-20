"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useScans } from "@/hooks/useScans";
import ScanCard from "@/components/ScanCard";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { 
  History, Shield, PlusCircle, Search, RefreshCw,
  Filter, CheckCircle2, Activity, AlertTriangle, XCircle
} from "lucide-react";
import { cn } from "@/lib/utils";

export default function HistoryPage() {
  const [searchTerm, setSearchTerm] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  
  const { data, isLoading, error, refetch, isFetching } = useScans(0, 100);

  const scans = data?.items ?? [];
  const total = data?.total ?? 0;

  // Filter scans
  const filteredScans = scans.filter((scan) => {
    const matchesSearch = scan.target.toLowerCase().includes(searchTerm.toLowerCase()) || 
                          scan.id.toLowerCase().includes(searchTerm.toLowerCase());
    
    const matchesStatus = statusFilter === "all" || scan.status === statusFilter;
    
    return matchesSearch && matchesStatus;
  });

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs text-slate-400 mb-2">
            <Link href="/dashboard" className="hover:text-cyan-400 transition-colors">
              Dashboard
            </Link>
            <span>/</span>
            <span className="text-slate-300">History</span>
          </div>
          <div className="flex items-center gap-3">
            <div className="p-2 bg-slate-900 border border-slate-800 rounded-lg text-slate-400">
              <History size={20} />
            </div>
            <div>
              <h1 className="text-xl font-bold text-slate-100">Scan Operations History</h1>
              <p className="text-xs text-slate-500 mt-0.5">
                Overview of all historical passive and active security audits.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 self-start sm:self-center">
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
          <Link
            href="/dashboard/scans/new"
            className="flex items-center gap-2 bg-cyan-500 hover:bg-cyan-400 text-slate-900 font-semibold text-xs px-3.5 py-2 rounded-lg transition-colors"
          >
            <PlusCircle size={14} />
            New Scan
          </Link>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col md:flex-row gap-4 items-center justify-between shadow-lg">
        {/* Search */}
        <div className="relative w-full md:max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
          <Input
            type="text"
            placeholder="Search by target IP, domain, or ID..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="pl-9 bg-slate-950 border-slate-800 text-slate-300 placeholder:text-slate-600 focus:border-cyan-500 focus:ring-cyan-500 text-xs h-9"
          />
        </div>

        {/* Filters */}
        <div className="flex flex-wrap gap-2 w-full md:w-auto">
          {[
            { id: "all", label: "All Scans", icon: Shield },
            { id: "completed", label: "Completed", icon: CheckCircle2 },
            { id: "running", label: "Active", icon: Activity },
            { id: "failed", label: "Failed", icon: XCircle },
          ].map((filter) => (
            <button
              key={filter.id}
              onClick={() => setStatusFilter(filter.id)}
              className={cn(
                "flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all duration-200",
                statusFilter === filter.id
                  ? "bg-cyan-500/10 text-cyan-400 border-cyan-500/20 shadow-sm"
                  : "bg-slate-950/40 border-slate-800/80 text-slate-400 hover:bg-slate-800 hover:text-slate-200"
              )}
            >
              <filter.icon size={12} />
              {filter.label}
            </button>
          ))}
        </div>
      </div>

      {/* Scans Grid / List */}
      <div className="space-y-3">
        {isLoading && (
          <div className="grid md:grid-cols-2 gap-4">
            {[...Array(6)].map((_, i) => (
              <div key={i} className="h-28 bg-slate-900 border border-slate-800 rounded-xl animate-pulse" />
            ))}
          </div>
        )}

        {error && (
          <div className="bg-red-500/10 border border-red-500/20 text-red-400 p-5 rounded-xl text-center">
            <AlertTriangle className="h-8 w-8 mx-auto mb-2" />
            <h3 className="font-bold">Failed to load history</h3>
            <p className="text-xs text-red-300/80 mt-1">{error.message}</p>
          </div>
        )}

        {!isLoading && !error && filteredScans.length > 0 && (
          <div className="grid md:grid-cols-2 gap-4">
            {filteredScans.map((scan) => (
              <ScanCard key={scan.id} scan={scan} />
            ))}
          </div>
        )}

        {!isLoading && !error && filteredScans.length === 0 && (
          <div className="bg-slate-900 border border-slate-800 p-12 rounded-xl text-center">
            <History className="h-10 w-10 text-slate-600 mx-auto mb-3" />
            <h3 className="font-bold text-slate-300">No scans matching filters</h3>
            <p className="text-xs text-slate-500 mt-1">
              Try adjusting your search criteria or starting a new security scan operation.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

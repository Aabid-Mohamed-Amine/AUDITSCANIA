"use client";

import Link from "next/link";
import { useScans } from "@/hooks/useScans";
import { useAuth } from "@/contexts/AuthContext";
import RiskScore from "@/components/RiskScore";
import RiskChart from "@/components/charts/RiskChart";
import {
  Shield, PlusCircle, Activity, CheckCircle2,
  XCircle, Clock, AlertTriangle, ArrowRight
} from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { cn } from "@/lib/utils";

function StatCard({ label, value, icon: Icon, color }: { label: string; value: number | string; icon: React.ElementType; color: string }) {
  return (
    <div className={cn("bg-slate-900 border rounded-xl p-5 flex items-center gap-4", `border-slate-800`)}>
      <div className={cn("p-2.5 rounded-lg", color)}>
        <Icon size={20} />
      </div>
      <div>
        <p className="text-2xl font-bold text-slate-100">{value}</p>
        <p className="text-xs text-slate-500 mt-0.5">{label}</p>
      </div>
    </div>
  );
}

const statusIcon: Record<string, React.ElementType> = {
  completed: CheckCircle2,
  running: Activity,
  pending: Clock,
  failed: XCircle,
};

const statusColor: Record<string, string> = {
  completed: "text-green-400",
  running: "text-cyan-400",
  pending: "text-yellow-400",
  failed: "text-red-400",
};

export default function DashboardPage() {
  const { user } = useAuth();
  const { data, isLoading } = useScans(0, 100);

  const scans = data?.items ?? [];
  const total = data?.total ?? 0;
  const completed = scans.filter((s) => s.status === "completed").length;
  const running = scans.filter((s) => s.status === "running").length;
  const failed = scans.filter((s) => s.status === "failed").length;
  const highRisk = scans.filter((s) => (s.risk_score ?? 0) >= 70).length;

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-100">
            Welcome back{user ? `, ${user.email.split("@")[0]}` : ""}
          </h1>
          <p className="text-sm text-slate-500 mt-0.5">Security Operations Dashboard</p>
        </div>
        <Link
          href="/dashboard/scans/new"
          className="flex items-center gap-2 bg-cyan-500 hover:bg-cyan-400 text-slate-900 font-semibold text-sm px-4 py-2.5 rounded-lg transition-colors"
        >
          <PlusCircle size={16} />
          New Scan
        </Link>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Total Scans" value={total} icon={Shield} color="bg-slate-800 text-slate-400" />
        <StatCard label="Completed" value={completed} icon={CheckCircle2} color="bg-green-500/10 text-green-400" />
        <StatCard label="Active" value={running} icon={Activity} color="bg-cyan-500/10 text-cyan-400" />
        <StatCard label="High Risk" value={highRisk} icon={AlertTriangle} color="bg-red-500/10 text-red-400" />
      </div>

      {/* Chart + Recent */}
      <div className="grid lg:grid-cols-5 gap-6">
        {/* Risk chart */}
        <div className="lg:col-span-3 bg-slate-900 border border-slate-800 rounded-xl p-5">
          <h2 className="text-sm font-semibold text-slate-300 mb-4">Risk Score — Last 10 Scans</h2>
          <RiskChart scans={scans} />
        </div>

        {/* Recent scans */}
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-slate-300">Recent Scans</h2>
            <Link href="/dashboard/history" className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1">
              View all <ArrowRight size={12} />
            </Link>
          </div>
          <div className="space-y-2">
            {isLoading && (
              <div className="space-y-2">
                {[...Array(5)].map((_, i) => (
                  <div key={i} className="h-12 bg-slate-800 rounded-lg animate-pulse" />
                ))}
              </div>
            )}
            {!isLoading && scans.slice(0, 6).map((scan) => {
              const Icon = statusIcon[scan.status] || Activity;
              const col = statusColor[scan.status] || "text-slate-400";
              return (
                <Link
                  key={scan.id}
                  href={`/dashboard/scans/${scan.id}`}
                  className="flex items-center gap-3 p-2.5 rounded-lg hover:bg-slate-800 transition-colors group"
                >
                  <Icon size={14} className={cn(col, scan.status === "running" && "animate-pulse")} />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-medium text-slate-300 truncate">{scan.target}</p>
                    <p className="text-xs text-slate-600">{formatDistanceToNow(new Date(scan.created_at), { addSuffix: true })}</p>
                  </div>
                  {scan.risk_score !== null && (
                    <RiskScore score={scan.risk_score} size="sm" />
                  )}
                </Link>
              );
            })}
            {!isLoading && scans.length === 0 && (
              <p className="text-xs text-slate-600 text-center py-6">No scans yet</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

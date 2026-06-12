"use client";

import Link from "next/link";
import { useScans } from "@/hooks/useScans";
import { useAuth } from "@/contexts/AuthContext";
import { useAnimatedCounter } from "@/hooks/useAnimatedCounter";
import RiskScore from "@/components/RiskScore";
import RiskChart from "@/components/charts/RiskChart";
import {
  Shield, PlusCircle, Activity, CheckCircle2,
  AlertTriangle, ArrowRight, Target, TrendingUp,
} from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { cn } from "@/lib/utils";

/* ── Animated KPI card ── */
function KpiCard({
  label, value, icon: Icon, color, border, delay = 0,
}: {
  label: string; value: number; icon: React.ElementType;
  color: string; border?: string; delay?: number;
}) {
  const animated = useAnimatedCounter(value, 900, delay);
  return (
    <div className={cn(
      "group flex items-center gap-4 px-5 py-4 rounded-xl bg-zinc-900 border card-hover cursor-default",
      border ?? "border-zinc-800"
    )}>
      <div className={cn("w-8 h-8 rounded-lg flex items-center justify-center shrink-0 transition-transform duration-200 group-hover:scale-110", color)}>
        <Icon className="w-4 h-4" />
      </div>
      <div>
        <p className={cn(
          "text-[24px] font-bold leading-none tabular-nums font-mono transition-all",
          animated !== value ? "" : "counter-pop"
        )}>
          {animated}
        </p>
        <p className="text-[10px] text-zinc-600 mt-1 uppercase tracking-widest">{label}</p>
      </div>
    </div>
  );
}

const ST_DOT: Record<string, string> = {
  completed: "bg-emerald-500", running: "bg-indigo-400 animate-pulse",
  pending:   "bg-amber-500",   failed:  "bg-red-500",
};

export default function DashboardPage() {
  const { user }            = useAuth();
  const { data, isLoading } = useScans(0, 100);

  const scans     = data?.items ?? [];
  const total     = data?.total ?? 0;
  const completed = scans.filter((s) => s.status === "completed").length;
  const running   = scans.filter((s) => s.status === "running").length;
  const critical  = scans.filter((s) => (s.risk_score ?? 0) >= 80).length;
  const scoredScans = scans.filter(s => s.risk_score !== null);
  const avgRisk   = scoredScans.length
    ? Math.round(scoredScans.reduce((a, s) => a + (s.risk_score ?? 0), 0) / scoredScans.length)
    : 0;
  const highRisk  = scans.filter((s) => (s.risk_score ?? 0) >= 60).length;
  const failed    = scans.filter(s => s.status === "failed").length;

  return (
    <div className="flex flex-col h-full overflow-auto bg-zinc-950">

      {/* Top bar */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-zinc-800/60 shrink-0 fade-in-down">
        <div>
          <h1 className="text-[15px] font-semibold text-zinc-100">Security Overview</h1>
          <p className="text-[11px] text-zinc-600 mt-0.5 font-mono">
            {user ? `${user.email.split("@")[0]}` : "dashboard"}
          </p>
        </div>
        <Link
          href="/dashboard/scans/new"
          className="flex items-center gap-2 bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-[12px] px-3.5 py-2 rounded-lg transition-all btn-glow"
        >
          <PlusCircle className="w-3.5 h-3.5" />
          New Scan
        </Link>
      </div>

      <div className="flex-1 p-6 space-y-5 max-w-7xl w-full mx-auto">

        {/* KPIs — stagger in */}
        <div className="grid grid-cols-2 lg:grid-cols-5 gap-3 stagger">
          <KpiCard label="Total Scans"    value={total}     icon={Target}        color="bg-zinc-800 text-zinc-400"               delay={0}   />
          <KpiCard label="Completed"      value={completed} icon={CheckCircle2}  color="bg-emerald-950/60 text-emerald-400"      delay={50}  />
          <KpiCard label="Active"         value={running}   icon={Activity}      color="bg-indigo-950/60 text-indigo-400"
            border={running  > 0 ? "border-indigo-800/50" : undefined}           delay={100} />
          <KpiCard label="Critical"       value={critical}  icon={AlertTriangle} color="bg-red-950/60 text-red-400"
            border={critical > 0 ? "border-red-900/50"    : undefined}           delay={150} />
          <KpiCard label="Avg Risk Score" value={avgRisk}   icon={TrendingUp}    color="bg-orange-950/60 text-orange-400"        delay={200} />
        </div>

        {/* Main grid */}
        <div className="grid lg:grid-cols-5 gap-5">

          {/* Chart */}
          <div className="lg:col-span-3 bg-zinc-900 border border-zinc-800 rounded-xl p-5 card-hover fade-in-up" style={{ animationDelay: "80ms" }}>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-[11px] font-semibold text-zinc-500 uppercase tracking-widest">Risk Score — Last Scans</h2>
              <Shield className="w-4 h-4 text-zinc-700" />
            </div>
            <RiskChart scans={scans} />
          </div>

          {/* Recent scans */}
          <div className="lg:col-span-2 bg-zinc-900 border border-zinc-800 rounded-xl p-5 card-hover fade-in-up" style={{ animationDelay: "120ms" }}>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-[11px] font-semibold text-zinc-500 uppercase tracking-widest">Recent Scans</h2>
              <Link href="/dashboard/history" className="flex items-center gap-1 text-[11px] text-zinc-600 hover:text-indigo-400 transition-colors">
                View all <ArrowRight className="w-3 h-3" />
              </Link>
            </div>
            <div className="space-y-0.5">
              {isLoading && [...Array(5)].map((_, i) => <div key={i} className="h-11 skeleton rounded-lg" />)}
              {!isLoading && scans.slice(0, 8).map((scan) => (
                <Link
                  key={scan.id}
                  href={`/dashboard/scans/${scan.id}`}
                  className="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-zinc-800/60 transition-colors group"
                >
                  <span className={cn("w-1.5 h-1.5 rounded-full shrink-0", ST_DOT[scan.status] ?? "bg-zinc-600")} />
                  <div className="flex-1 min-w-0">
                    <p className="text-[12px] font-mono text-zinc-400 truncate group-hover:text-zinc-200 transition-colors">{scan.target}</p>
                    <p className="text-[10px] text-zinc-700">{formatDistanceToNow(new Date(scan.created_at), { addSuffix: true })}</p>
                  </div>
                  {scan.risk_score !== null && scan.risk_score !== undefined && (
                    <RiskScore score={scan.risk_score} size="sm" />
                  )}
                </Link>
              ))}
              {!isLoading && scans.length === 0 && (
                <div className="py-8 text-center">
                  <Shield className="w-8 h-8 text-zinc-800 mx-auto mb-2" />
                  <p className="text-[12px] text-zinc-600">No scans yet</p>
                  <Link href="/dashboard/scans/new" className="mt-3 inline-block text-[11px] text-indigo-400 hover:text-indigo-300 transition-colors">
                    Start your first scan →
                  </Link>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Stats row */}
        {scans.length > 0 && (
          <div className="grid grid-cols-3 gap-3 stagger">
            {[
              { label: "High Risk (60+)",   value: highRisk, color: "text-orange-400" },
              { label: "Failed Scans",      value: failed,   color: "text-red-400" },
              { label: "Avg CVSS Exposure", value: avgRisk,  color: "text-indigo-400", suffix: "/100" },
            ].map(({ label, value, color, suffix }) => (
              <div key={label} className="flex items-center justify-between px-4 py-3 bg-zinc-900 border border-zinc-800 rounded-xl card-hover">
                <span className="text-[11px] text-zinc-600 uppercase tracking-wide">{label}</span>
                <span className={cn("text-[14px] font-bold font-mono", color)}>
                  {value}{suffix ?? ""}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

"use client";

import Link from "next/link";
import { useScans } from "@/hooks/useScans";
import { useAuth } from "@/contexts/AuthContext";
import RiskScore from "@/components/RiskScore";
import RiskChart from "@/components/charts/RiskChart";
import {
  Shield, PlusCircle, Activity, CheckCircle2,
  XCircle, Clock, AlertTriangle, ArrowRight,
  Target, TrendingUp,
} from "lucide-react";
import { formatDistanceToNow } from "date-fns";
import { cn } from "@/lib/utils";

/* ── KPI card ──────────────────────────────────────────────────────────── */

interface KpiProps {
  label: string;
  value: number | string;
  icon: React.ElementType;
  accent: string;      /* Tailwind color class for icon bg */
  iconColor: string;
  border?: string;
}

function KpiCard({ label, value, icon: Icon, accent, iconColor, border }: KpiProps) {
  return (
    <div
      className={cn(
        "flex items-center gap-4 px-5 py-4 rounded-[7px] bg-[#080f1e] border",
        border ?? "border-[#0f1e30]"
      )}
    >
      <div className={cn("w-10 h-10 rounded-[6px] flex items-center justify-center shrink-0", accent)}>
        <Icon className={cn("w-5 h-5", iconColor)} />
      </div>
      <div>
        <p className="text-[22px] font-bold text-white leading-none tabular-nums">{value}</p>
        <p className="text-[11px] text-[#2a5070] mt-1 uppercase tracking-wide">{label}</p>
      </div>
    </div>
  );
}

/* ── Status config ─────────────────────────────────────────────────────── */

const ST_ICON: Record<string, React.ElementType> = {
  completed: CheckCircle2, running: Activity, pending: Clock, failed: XCircle,
};
const ST_COLOR: Record<string, string> = {
  completed: "text-emerald-400", running: "text-blue-400 animate-pulse",
  pending: "text-amber-400",    failed:  "text-red-400",
};
const ST_DOT: Record<string, string> = {
  completed: "bg-emerald-400", running: "bg-blue-400 animate-pulse",
  pending:   "bg-amber-400",   failed:  "bg-red-400",
};

/* ── Page ──────────────────────────────────────────────────────────────── */

export default function DashboardPage() {
  const { user }    = useAuth();
  const { data, isLoading } = useScans(0, 100);

  const scans     = data?.items ?? [];
  const total     = data?.total ?? 0;
  const completed = scans.filter((s) => s.status === "completed").length;
  const running   = scans.filter((s) => s.status === "running").length;
  const critical  = scans.filter((s) => (s.risk_score ?? 0) >= 80).length;
  const highRisk  = scans.filter((s) => (s.risk_score ?? 0) >= 60).length;
  const avgRisk   = scans.length
    ? Math.round(scans.filter(s => s.risk_score !== null).reduce((a, s) => a + (s.risk_score ?? 0), 0) / (scans.filter(s => s.risk_score !== null).length || 1))
    : 0;

  return (
    <div className="flex flex-col h-full overflow-auto">

      {/* ── Top bar ─────────────────────────────────────────── */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-[#0f1e30] bg-[#060d1a] shrink-0">
        <div>
          <h1 className="text-[15px] font-semibold text-[#c0d8f0]">
            Security Overview
          </h1>
          <p className="text-[11px] text-[#2a5070] mt-0.5">
            Welcome back{user ? `, ${user.email.split("@")[0]}` : ""}
          </p>
        </div>
        <Link
          href="/dashboard/scans/new"
          className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 text-white font-semibold text-[12px] px-3.5 py-2 rounded-[5px] transition-colors"
        >
          <PlusCircle className="w-3.5 h-3.5" />
          New Scan
        </Link>
      </div>

      <div className="flex-1 p-6 space-y-5 max-w-7xl w-full mx-auto">

        {/* ── KPI row ─────────────────────────────────────────── */}
        <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
          <KpiCard
            label="Total Scans" value={total}
            icon={Target}        accent="bg-[#0a1828]"    iconColor="text-[#3d6080]"
          />
          <KpiCard
            label="Completed"   value={completed}
            icon={CheckCircle2} accent="bg-emerald-950/50" iconColor="text-emerald-400"
          />
          <KpiCard
            label="Active"      value={running}
            icon={Activity}     accent="bg-blue-950/50"   iconColor="text-blue-400"
            border={running > 0 ? "border-blue-900/60" : undefined}
          />
          <KpiCard
            label="Critical"    value={critical}
            icon={AlertTriangle} accent="bg-red-950/50"   iconColor="text-red-400"
            border={critical > 0 ? "border-red-900/60" : undefined}
          />
          <KpiCard
            label="Avg Risk Score" value={avgRisk || "—"}
            icon={TrendingUp}   accent="bg-orange-950/50" iconColor="text-orange-400"
          />
        </div>

        {/* ── Main content ────────────────────────────────────── */}
        <div className="grid lg:grid-cols-5 gap-5">

          {/* Risk chart */}
          <div className="lg:col-span-3 bg-[#080f1e] border border-[#0f1e30] rounded-[7px] p-5">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-[12px] font-semibold text-[#4a8ab5] uppercase tracking-wide">
                Risk Score — Last Scans
              </h2>
              <Shield className="w-4 h-4 text-[#1a3550]" />
            </div>
            <RiskChart scans={scans} />
          </div>

          {/* Recent scans */}
          <div className="lg:col-span-2 bg-[#080f1e] border border-[#0f1e30] rounded-[7px] p-5">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-[12px] font-semibold text-[#4a8ab5] uppercase tracking-wide">
                Recent Scans
              </h2>
              <Link
                href="/dashboard/history"
                className="flex items-center gap-1 text-[11px] text-[#2a5070] hover:text-blue-400 transition-colors"
              >
                View all <ArrowRight className="w-3 h-3" />
              </Link>
            </div>

            <div className="space-y-1">
              {isLoading && [...Array(5)].map((_, i) => (
                <div key={i} className="h-11 bg-[#060d1a] rounded-[5px] animate-pulse" />
              ))}

              {!isLoading && scans.slice(0, 8).map((scan) => {
                const Icon  = ST_ICON[scan.status]  ?? Activity;
                const col   = ST_COLOR[scan.status] ?? "text-slate-400";
                const dot   = ST_DOT[scan.status]   ?? "bg-slate-400";
                return (
                  <Link
                    key={scan.id}
                    href={`/dashboard/scans/${scan.id}`}
                    className="flex items-center gap-3 px-3 py-2 rounded-[5px] hover:bg-[#060d1a] transition-colors group"
                  >
                    <span className={cn("w-1.5 h-1.5 rounded-full shrink-0", dot)} />
                    <div className="flex-1 min-w-0">
                      <p className="text-[12px] font-mono text-[#8ab8d8] truncate group-hover:text-white transition-colors">
                        {scan.target}
                      </p>
                      <p className="text-[10px] text-[#1a3550]">
                        {formatDistanceToNow(new Date(scan.created_at), { addSuffix: true })}
                      </p>
                    </div>
                    {scan.risk_score !== null && scan.risk_score !== undefined && (
                      <RiskScore score={scan.risk_score} size="sm" />
                    )}
                  </Link>
                );
              })}

              {!isLoading && scans.length === 0 && (
                <div className="py-8 text-center">
                  <Shield className="w-8 h-8 text-[#0f1e30] mx-auto mb-2" />
                  <p className="text-[12px] text-[#1a3550]">No scans yet</p>
                  <Link
                    href="/dashboard/scans/new"
                    className="mt-3 inline-block text-[11px] text-blue-400 hover:text-blue-300"
                  >
                    Start your first scan →
                  </Link>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* ── Stats summary bar ─────────────────────────────── */}
        {scans.length > 0 && (
          <div className="grid grid-cols-3 gap-3">
            {[
              { label: "High Risk (60+)",    value: highRisk,  color: "text-orange-400" },
              { label: "Failed Scans",       value: scans.filter(s => s.status === "failed").length, color: "text-red-400" },
              { label: "Avg CVSS Exposure",  value: `${avgRisk}/100`, color: "text-[#4a8ab5]" },
            ].map(({ label, value, color }) => (
              <div
                key={label}
                className="flex items-center justify-between px-4 py-3 bg-[#080f1e] border border-[#0f1e30] rounded-[6px]"
              >
                <span className="text-[11px] text-[#2a5070] uppercase tracking-wide">{label}</span>
                <span className={cn("text-[14px] font-bold font-mono", color)}>{value}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

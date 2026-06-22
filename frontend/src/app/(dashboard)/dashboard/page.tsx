"use client";

import Link from "next/link";
import { useState } from "react";
import { useScans } from "@/hooks/useScans";
import { useAuth } from "@/contexts/AuthContext";
import { formatDistanceToNow } from "date-fns";

const ST_ICON: Record<string, string> = {
  completed: "check_circle",
  running:   "sync",
  pending:   "hourglass_top",
  failed:    "cancel",
};
const ST_COLOR: Record<string, string> = {
  completed: "#008a44",
  running:   "var(--sc-brand)",
  pending:   "#d95f00",
  failed:    "var(--sc-error)",
};

function TopBar({ user }: { user: { email: string } | null }) {
  return (
    <header
      className="fixed top-0 right-0 h-16 flex justify-between items-center px-4 z-40"
      style={{
        left: 0,
        marginLeft: "inherit",
        background: "var(--sc-bg)",
        borderBottom: "1px solid var(--sc-border)",
      }}
    >
      <div className="flex items-center gap-4" style={{ marginLeft: "240px" }}>
        <span className="font-bold tracking-tight" style={{ fontSize: 20, color: "var(--sc-on)" }}>
          Aegis Pentest
        </span>
        <div className="h-5 w-px" style={{ background: "var(--sc-border)" }} />
        <span
          className="px-2 py-0.5 rounded font-mono uppercase tracking-wider"
          style={{
            fontSize: 10,
            background: "var(--sc-brand-bg)",
            color: "var(--sc-brand)",
          }}
        >
          PROD_ENV_SECURED
        </span>
      </div>
      <div className="flex items-center gap-4" style={{ marginRight: 16 }}>
        <span style={{ fontSize: 12, color: "var(--sc-on-v)" }} className="font-mono">
          {user?.email?.split("@")[0] ?? "analyst"}
        </span>
        {["notifications", "wifi_tethering", "account_tree"].map((icon) => (
          <button
            key={icon}
            className="transition-colors"
            style={{ color: "var(--sc-on-v)" }}
            onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.color = "var(--sc-brand)")}
            onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.color = "var(--sc-on-v)")}
          >
            <span className="material-symbols-outlined" style={{ fontSize: 20 }}>{icon}</span>
          </button>
        ))}
      </div>
    </header>
  );
}

function SeverityCard({
  label, count, color, bg, border, sub,
}: {
  label: string; count: number; color: string; bg: string; border: string; sub: string;
}) {
  return (
    <div
      className="p-4 rounded-lg stitch-card"
      style={{ background: bg, border: `1px solid ${border}` }}
    >
      <p className="font-mono font-bold uppercase" style={{ fontSize: 11, color, letterSpacing: "0.05em" }}>{label}</p>
      <p className="font-black tabular-nums mt-1" style={{ fontSize: 32, color, lineHeight: 1 }}>
        {String(count).padStart(2, "0")}
      </p>
      <p className="font-mono font-bold mt-1" style={{ fontSize: 9, color, opacity: 0.7 }}>{sub}</p>
    </div>
  );
}

export default function DashboardPage() {
  const { user }            = useAuth();
  const { data, isLoading } = useScans(0, 100);
  const [terminalOpen, setTerminalOpen] = useState(false);

  const scans      = data?.items ?? [];
  const total      = data?.total ?? 0;
  const completed  = scans.filter((s) => s.status === "completed").length;
  const running    = scans.filter((s) => s.status === "running");
  const failed     = scans.filter((s) => s.status === "failed").length;
  const critical   = scans.filter((s) => (s.risk_score ?? 0) >= 80).length;
  const high       = scans.filter((s) => (s.risk_score ?? 0) >= 60 && (s.risk_score ?? 0) < 80).length;
  const medium     = scans.filter((s) => (s.risk_score ?? 0) >= 40 && (s.risk_score ?? 0) < 60).length;
  const low        = scans.filter((s) => (s.risk_score ?? 0) > 0 && (s.risk_score ?? 0) < 40).length;
  const scoredScans = scans.filter((s) => s.risk_score !== null);
  const avgRisk    = scoredScans.length
    ? Math.round(scoredScans.reduce((a, s) => a + (s.risk_score ?? 0), 0) / scoredScans.length)
    : 0;
  const recentScans = scans.slice(0, 5);

  const postureLabel = avgRisk >= 70 ? "At Risk" : avgRisk >= 40 ? "Caution" : avgRisk > 0 ? "Secure" : "No Data";
  const posturePct   = 100 - avgRisk;
  const postureColor = avgRisk >= 70 ? "var(--sc-error)" : avgRisk >= 40 ? "var(--sc-warn)" : "var(--sc-brand)";

  return (
    <div
      className="min-h-full"
      style={{ background: "var(--sc-bg)", fontFamily: "'Geist', sans-serif", color: "var(--sc-on)" }}
    >
      {/* Sticky header */}
      <header
        className="sticky top-0 h-16 flex justify-between items-center px-4 z-40"
        style={{ background: "var(--sc-bg)", borderBottom: "1px solid var(--sc-border)" }}
      >
        <div className="flex items-center gap-4">
          <span className="font-bold tracking-tight" style={{ fontSize: 20, color: "var(--sc-on)" }}>
            Aegis Pentest
          </span>
          <div className="h-5 w-px" style={{ background: "var(--sc-border)" }} />
          <span
            className="px-2 py-0.5 rounded font-mono uppercase tracking-wider"
            style={{ fontSize: 10, background: "var(--sc-brand-bg)", color: "var(--sc-brand)" }}
          >
            PROD_ENV_SECURED
          </span>
        </div>
        <div className="flex items-center gap-4">
          <span style={{ fontSize: 12, color: "var(--sc-on-v)" }} className="font-mono">
            {user?.email?.split("@")[0] ?? "analyst"}
          </span>
          {["notifications", "wifi_tethering", "account_tree"].map((icon) => (
            <button
              key={icon}
              className="transition-colors"
              style={{ color: "var(--sc-on-v)" }}
              onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.color = "var(--sc-brand)")}
              onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.color = "var(--sc-on-v)")}
            >
              <span className="material-symbols-outlined" style={{ fontSize: 20 }}>{icon}</span>
            </button>
          ))}
        </div>
      </header>

      <div className="p-4 max-w-[1400px] mx-auto space-y-4">

        {/* Page title */}
        <div className="flex justify-between items-end pt-2">
          <div>
            <h2 className="font-black tracking-tight" style={{ fontSize: 32, letterSpacing: "-0.02em" }}>
              Security Overview
            </h2>
            <p style={{ fontSize: 14, color: "var(--sc-on-v)" }}>
              Real-time threat intelligence and vulnerability analysis
              {total > 0 && (
                <span className="font-bold" style={{ color: "var(--sc-brand)" }}>
                  {" "}({total} scans)
                </span>
              )}
            </p>
          </div>
          <Link
            href="/dashboard/scans/new"
            className="flex items-center gap-2 px-4 py-2 rounded-lg font-bold shadow-sm transition-all active:scale-95"
            style={{ background: "var(--sc-on)", color: "#ffffff", fontSize: 13 }}
            onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.background = "var(--sc-pc)")}
            onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.background = "var(--sc-on)")}
          >
            <span className="material-symbols-outlined" style={{ fontSize: 16 }}>add</span>
            NEW ANALYSIS TASK
          </Link>
        </div>

        {/* Bento row 1 */}
        <div className="grid grid-cols-12 gap-4">

          {/* Security posture */}
          <div
            className="col-span-12 md:col-span-4 rounded-xl p-6 relative overflow-hidden stitch-card"
            style={{ background: "#ffffff", border: "1px solid var(--sc-border)" }}
          >
            <p
              className="uppercase tracking-widest mb-4 font-mono"
              style={{ fontSize: 11, color: "var(--sc-on-v)" }}
            >
              Overall Security Posture
            </p>
            <div className="flex items-center gap-4">
              {/* Ring chart */}
              <div className="relative w-24 h-24 shrink-0">
                <svg viewBox="0 0 96 96" className="w-full h-full -rotate-90">
                  <circle cx="48" cy="48" r="40" fill="none" strokeWidth="8" stroke="var(--sc-brand-bg)" />
                  <circle
                    cx="48" cy="48" r="40" fill="none" strokeWidth="8"
                    stroke={postureColor}
                    strokeLinecap="round"
                    strokeDasharray={`${2 * Math.PI * 40 * posturePct / 100} ${2 * Math.PI * 40}`}
                    style={{ transition: "stroke-dasharray 1s ease" }}
                  />
                </svg>
                <div
                  className="absolute inset-0 flex items-center justify-center font-black"
                  style={{ fontSize: 22, color: postureColor }}
                >
                  {posturePct}
                </div>
              </div>
              <div>
                <h3 className="font-bold" style={{ fontSize: 20, color: "var(--sc-on)" }}>
                  {postureLabel}
                </h3>
                <p style={{ fontSize: 13, color: "var(--sc-brand)" }}>
                  {total > 0 ? `${completed} / ${total} completed` : "No scans yet"}
                </p>
              </div>
            </div>
            {/* Bg icon */}
            <div className="absolute -right-4 -bottom-4 opacity-5 pointer-events-none">
              <span className="material-symbols-outlined" style={{ fontSize: 96, color: "var(--sc-on)" }}>
                verified_user
              </span>
            </div>
          </div>

          {/* Severity breakdown */}
          <div
            className="col-span-12 md:col-span-8 rounded-xl p-6 stitch-card"
            style={{ background: "#ffffff", border: "1px solid var(--sc-border)" }}
          >
            <p
              className="uppercase tracking-widest mb-4 font-mono"
              style={{ fontSize: 11, color: "var(--sc-on-v)" }}
            >
              Active Vulnerabilities by Severity
            </p>
            <div className="grid grid-cols-4 gap-4">
              <SeverityCard
                label="Critical" count={critical}
                color="var(--sc-error)" bg="var(--sc-err-bg)"
                border="rgba(186,26,26,0.2)"
                sub={critical > 0 ? "+UNRESOLVED" : "NONE"}
              />
              <SeverityCard
                label="High" count={high}
                color="var(--sc-warn)" bg="var(--sc-warn-bg)"
                border="rgba(217,95,0,0.2)"
                sub="MONITOR"
              />
              <SeverityCard
                label="Medium" count={medium}
                color="var(--sc-on)" bg="var(--sc-low)"
                border="var(--sc-border)"
                sub="STABLE"
              />
              <SeverityCard
                label="Low" count={low}
                color="var(--sc-brand)" bg="var(--sc-brand-bg)"
                border="rgba(0,81,213,0.2)"
                sub="TRACKED"
              />
            </div>
          </div>
        </div>

        {/* Bento row 2 */}
        <div className="grid grid-cols-12 gap-4">

          {/* Active scans */}
          <div
            className="col-span-12 lg:col-span-7 rounded-xl p-6 stitch-card"
            style={{ background: "#ffffff", border: "1px solid var(--sc-border)" }}
          >
            <div className="flex justify-between items-center mb-6">
              <h3 className="font-semibold" style={{ fontSize: 18, color: "var(--sc-on)" }}>
                Active Scan Progress
              </h3>
              <span className="flex items-center gap-2 font-mono font-bold" style={{ fontSize: 11, color: "var(--sc-brand)" }}>
                <span className="w-2 h-2 rounded-full scan-pulse" style={{ background: "var(--sc-brand)" }} />
                {running.length} RUNNING
              </span>
            </div>

            {isLoading && (
              <div className="space-y-4">
                {[...Array(3)].map((_, i) => (
                  <div key={i} className="stitch-skeleton h-8 rounded-lg" />
                ))}
              </div>
            )}

            {!isLoading && running.length === 0 && (
              <div className="text-center py-8">
                <span className="material-symbols-outlined" style={{ fontSize: 32, color: "var(--sc-border)" }}>
                  radar
                </span>
                <p style={{ fontSize: 13, color: "var(--sc-outline)", marginTop: 8 }}>No active scans</p>
                <Link
                  href="/dashboard/scans/new"
                  style={{ fontSize: 12, color: "var(--sc-brand)", marginTop: 4, display: "block" }}
                >
                  Launch a scan →
                </Link>
              </div>
            )}

            {!isLoading && running.slice(0, 3).map((scan) => (
              <div key={scan.id} className="mb-5">
                <div className="flex justify-between items-center mb-2">
                  <Link
                    href={`/dashboard/scans/${scan.id}`}
                    className="flex items-center gap-2 font-mono hover:underline"
                    style={{ fontSize: 13, color: "var(--sc-on)" }}
                  >
                    <span className="material-symbols-outlined" style={{ fontSize: 14, color: "var(--sc-brand)" }}>
                      cloud
                    </span>
                    {scan.target}
                  </Link>
                  <span className="font-mono font-bold" style={{ fontSize: 13, color: "var(--sc-brand)" }}>
                    {scan.progress}%
                  </span>
                </div>
                <div
                  className="w-full h-2 rounded-full overflow-hidden"
                  style={{ background: "var(--sc-surface)" }}
                >
                  <div
                    className="h-full rounded-full prog-fill"
                    style={{
                      width: `${scan.progress}%`,
                      background: scan.progress > 80 ? "var(--sc-brand)" : "var(--sc-brand)",
                    }}
                  />
                </div>
              </div>
            ))}

            {/* Completed scans preview */}
            {!isLoading && running.length === 0 && completed > 0 && (
              <div className="space-y-3">
                {recentScans.slice(0, 3).map((scan) => (
                  <div key={scan.id} className="flex items-center gap-3">
                    <span
                      className="material-symbols-outlined"
                      style={{ fontSize: 16, color: ST_COLOR[scan.status] ?? "var(--sc-outline)" }}
                    >
                      {ST_ICON[scan.status] ?? "circle"}
                    </span>
                    <div className="flex-1 min-w-0">
                      <Link
                        href={`/dashboard/scans/${scan.id}`}
                        className="font-mono hover:underline truncate block"
                        style={{ fontSize: 12, color: "var(--sc-on)" }}
                      >
                        {scan.target}
                      </Link>
                    </div>
                    {scan.risk_score !== null && (
                      <span
                        className="font-mono font-bold"
                        style={{
                          fontSize: 11,
                          color: (scan.risk_score ?? 0) >= 70 ? "var(--sc-error)" : "var(--sc-brand)",
                        }}
                      >
                        {scan.risk_score}
                      </span>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Threat Intelligence / Recent Alerts */}
          <div
            className="col-span-12 lg:col-span-5 rounded-xl flex flex-col overflow-hidden stitch-card"
            style={{ background: "#ffffff", border: "1px solid var(--sc-border)" }}
          >
            <div
              className="p-4 flex justify-between items-center"
              style={{ background: "var(--sc-low)", borderBottom: "1px solid var(--sc-border)" }}
            >
              <h3 className="font-semibold flex items-center gap-2" style={{ fontSize: 18, color: "var(--sc-on)" }}>
                <span className="material-symbols-outlined" style={{ fontSize: 18, color: "var(--sc-error)" }}>emergency</span>
                Threat Intelligence
              </h3>
              <Link href="/dashboard/history" className="font-mono font-bold" style={{ fontSize: 11, color: "var(--sc-brand)" }}>
                VIEW ALL
              </Link>
            </div>
            <div className="flex-1 overflow-y-auto max-h-[260px] divide-y" style={{ borderColor: "var(--sc-border)" }}>
              {isLoading && [...Array(4)].map((_, i) => (
                <div key={i} className="p-4 stitch-skeleton h-14 mx-4 my-2 rounded-lg" />
              ))}
              {!isLoading && scans.length === 0 && (
                <div className="p-8 text-center">
                  <span className="material-symbols-outlined" style={{ fontSize: 28, color: "var(--sc-border)" }}>inbox</span>
                  <p style={{ fontSize: 12, color: "var(--sc-outline)", marginTop: 8 }}>No scan data yet</p>
                </div>
              )}
              {!isLoading && scans.slice(0, 6).map((scan) => (
                <Link
                  key={scan.id}
                  href={`/dashboard/scans/${scan.id}`}
                  className="p-4 flex gap-4 transition-colors block"
                  style={{ borderBottom: "1px solid var(--sc-border)" }}
                  onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.background = "var(--sc-low)")}
                  onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.background = "transparent")}
                >
                  <div
                    className="w-1.5 h-1.5 rounded-full mt-2 shrink-0"
                    style={{
                      background: (scan.risk_score ?? 0) >= 70
                        ? "var(--sc-error)"
                        : (scan.risk_score ?? 0) >= 40
                          ? "var(--sc-warn)"
                          : "var(--sc-brand)",
                    }}
                  />
                  <div className="flex-1 min-w-0">
                    <p className="font-mono truncate" style={{ fontSize: 13, color: "var(--sc-on)" }}>
                      {scan.target}
                    </p>
                    <p
                      className="font-mono uppercase mt-0.5"
                      style={{ fontSize: 10, color: "var(--sc-outline)" }}
                    >
                      {formatDistanceToNow(new Date(scan.created_at), { addSuffix: true })}
                      {scan.risk_score !== null && ` | RISK: ${scan.risk_score}`}
                    </p>
                  </div>
                </Link>
              ))}
            </div>
          </div>
        </div>

        {/* Stats / KPI row */}
        <div className="grid grid-cols-12 gap-4">
          <div
            className="col-span-12 rounded-xl p-6 stitch-card"
            style={{ background: "#ffffff", border: "1px solid var(--sc-border)" }}
          >
            <div className="flex justify-between items-center mb-6">
              <div>
                <h3 className="font-semibold" style={{ fontSize: 18, color: "var(--sc-on)" }}>
                  Pipeline Statistics
                </h3>
                <p style={{ fontSize: 13, color: "var(--sc-on-v)" }}>
                  Scanning performance and outcomes
                </p>
              </div>
              <div
                className="flex gap-1 p-1 rounded-lg"
                style={{ background: "var(--sc-low)", border: "1px solid var(--sc-border)" }}
              >
                {["Total", "Completed", "Failed"].map((label) => (
                  <span
                    key={label}
                    className="px-3 py-1 rounded font-mono font-bold"
                    style={{ fontSize: 11, color: "var(--sc-on-v)" }}
                  >
                    {label}
                  </span>
                ))}
              </div>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
              {[
                { label: "Total Scans",    value: total,     color: "var(--sc-on)" },
                { label: "Completed",      value: completed, color: "#008a44" },
                { label: "Running",        value: running.length, color: "var(--sc-brand)" },
                { label: "Failed",         value: failed,    color: "var(--sc-error)" },
                { label: "Avg Risk Score", value: avgRisk,   color: avgRisk >= 70 ? "var(--sc-error)" : "var(--sc-brand)" },
              ].map(({ label, value, color }) => (
                <div key={label} className="text-center">
                  <p
                    className="font-black tabular-nums"
                    style={{ fontSize: 32, color, lineHeight: 1 }}
                  >
                    {value}
                  </p>
                  <p
                    className="font-mono uppercase mt-1"
                    style={{ fontSize: 10, color: "var(--sc-on-v)", letterSpacing: "0.05em" }}
                  >
                    {label}
                  </p>
                </div>
              ))}
            </div>
          </div>
        </div>

      </div>

      {/* Floating terminal button */}
      <div className="fixed bottom-8 right-8 z-50 flex flex-col items-end gap-3">
        {terminalOpen && (
          <div
            className="w-[480px] h-72 rounded-lg overflow-hidden flex flex-col shadow-2xl"
            style={{
              background: "var(--sc-pc)",
              border: "1px solid var(--sc-border)",
            }}
          >
            <div
              className="flex justify-between items-center px-4 py-2"
              style={{ background: "var(--sc-top)", borderBottom: "1px solid var(--sc-border)" }}
            >
              <span className="flex items-center gap-2 font-mono" style={{ fontSize: 11, color: "var(--sc-on-v)" }}>
                <span className="w-2.5 h-2.5 rounded-full" style={{ background: "var(--sc-error)" }} />
                <span className="w-2.5 h-2.5 rounded-full" style={{ background: "var(--sc-warn)" }} />
                <span className="w-2.5 h-2.5 rounded-full" style={{ background: "var(--sc-brand)" }} />
                aegis-shell -- root@ops-01
              </span>
              <button onClick={() => setTerminalOpen(false)} style={{ color: "var(--sc-outline)" }}>
                <span className="material-symbols-outlined" style={{ fontSize: 16 }}>close</span>
              </button>
            </div>
            <div className="flex-1 p-4 overflow-y-auto space-y-1 font-mono" style={{ fontSize: 12, color: "#a8e6cf" }}>
              <p style={{ color: "var(--sc-brand-bg)" }}>[ok] AEGIS scanner session started</p>
              <p style={{ color: "var(--sc-top)" }}>$ status</p>
              <p>{total} total scans | {completed} completed | {running.length} running</p>
              {running.length > 0 && running.slice(0, 2).map((s) => (
                <p key={s.id} style={{ color: "var(--sc-brand-bg)" }}>
                  LIVE [{s.progress}%] {s.target}
                </p>
              ))}
              <p>
                $ <span className="inline-block w-2 h-4 align-middle animate-pulse" style={{ background: "var(--sc-brand)" }} />
              </p>
            </div>
          </div>
        )}
        <button
          onClick={() => setTerminalOpen((v) => !v)}
          className="w-14 h-14 rounded-full flex items-center justify-center shadow-lg transition-all active:scale-95"
          style={{ background: "var(--sc-on)", color: "#ffffff" }}
          onMouseEnter={(e) => {
            (e.currentTarget as HTMLElement).style.transform = "scale(1.1)";
            (e.currentTarget as HTMLElement).style.background = "var(--sc-pc)";
          }}
          onMouseLeave={(e) => {
            (e.currentTarget as HTMLElement).style.transform = "scale(1)";
            (e.currentTarget as HTMLElement).style.background = "var(--sc-on)";
          }}
        >
          <span className="material-symbols-outlined" style={{ fontSize: 24 }}>terminal</span>
        </button>
      </div>
    </div>
  );
}

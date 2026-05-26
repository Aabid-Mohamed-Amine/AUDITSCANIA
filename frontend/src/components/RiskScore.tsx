"use client";

import { cn } from "@/lib/utils";

interface Props {
  score: number | null;
  size?: "sm" | "md" | "lg";
}

function getRisk(score: number) {
  if (score >= 80) return { label: "CRITICAL", color: "text-red-400",    bg: "bg-red-950/60    border-red-800/60",    ring: "#ef4444", dot: "bg-red-400" };
  if (score >= 60) return { label: "HIGH",     color: "text-orange-400", bg: "bg-orange-950/60 border-orange-800/60", ring: "#f97316", dot: "bg-orange-400" };
  if (score >= 40) return { label: "MEDIUM",   color: "text-amber-400",  bg: "bg-amber-950/60  border-amber-800/60",  ring: "#f59e0b", dot: "bg-amber-400" };
  if (score >= 20) return { label: "LOW",      color: "text-blue-400",   bg: "bg-blue-950/60   border-blue-800/60",   ring: "#3b82f6", dot: "bg-blue-400" };
  return             { label: "INFO",      color: "text-slate-400",  bg: "bg-slate-800/60  border-slate-700/60",  ring: "#64748b", dot: "bg-slate-400" };
}

export default function RiskScore({ score, size = "md" }: Props) {
  if (score === null || score === undefined)
    return <span className="text-[#2a5070] text-xs font-mono">—</span>;

  const risk = getRisk(score);
  const r    = 20;
  const circ = 2 * Math.PI * r;
  const off  = circ - (score / 100) * circ;

  /* ── sm : inline pill ── */
  if (size === "sm") {
    return (
      <span
        className={cn(
          "inline-flex items-center gap-1.5 text-[11px] font-semibold px-2 py-0.5 rounded-[4px] border font-mono tracking-wide",
          risk.bg, risk.color
        )}
      >
        <span className={cn("w-1.5 h-1.5 rounded-full shrink-0", risk.dot)} />
        {score} · {risk.label}
      </span>
    );
  }

  /* ── lg : SVG gauge ── */
  if (size === "lg") {
    return (
      <div className="flex flex-col items-center gap-3">
        <div className="relative w-[110px] h-[110px]">
          <svg viewBox="0 0 50 50" className="w-full h-full -rotate-90">
            {/* Track */}
            <circle cx="25" cy="25" r={r} fill="none" stroke="#0f1e30" strokeWidth="4.5" />
            {/* Score arc */}
            <circle
              cx="25" cy="25" r={r}
              fill="none"
              stroke={risk.ring}
              strokeWidth="4.5"
              strokeDasharray={circ}
              strokeDashoffset={off}
              strokeLinecap="round"
              style={{ transition: "stroke-dashoffset 1.2s ease" }}
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className={cn("text-[26px] font-bold leading-none font-mono", risk.color)}>
              {score}
            </span>
            <span className="text-[10px] text-[#2a5070] tracking-wider">/100</span>
          </div>
        </div>
        <span
          className={cn(
            "text-[11px] font-bold px-3 py-1 rounded-[4px] border tracking-widest",
            risk.bg, risk.color
          )}
        >
          {risk.label} RISK
        </span>
      </div>
    );
  }

  /* ── md : compact badge ── */
  return (
    <div
      className={cn(
        "inline-flex items-center gap-2 px-3 py-1.5 rounded-[5px] border",
        risk.bg, risk.color
      )}
    >
      <span className={cn("w-2 h-2 rounded-full shrink-0", risk.dot)} />
      <span className="text-[15px] font-bold font-mono leading-none">{score}</span>
      <span className="text-[10px] font-semibold tracking-widest opacity-80">{risk.label}</span>
    </div>
  );
}

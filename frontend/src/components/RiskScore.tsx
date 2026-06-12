"use client";

import { cn } from "@/lib/utils";

interface Props {
  score: number | null;
  size?: "sm" | "md" | "lg";
}

function getRisk(score: number) {
  if (score >= 80) return { label: "CRITICAL", color: "text-red-400",    bg: "bg-red-950/50    border-red-900/50",    ring: "#f87171", dot: "bg-red-500" };
  if (score >= 60) return { label: "HIGH",     color: "text-orange-400", bg: "bg-orange-950/50 border-orange-900/50", ring: "#fb923c", dot: "bg-orange-500" };
  if (score >= 40) return { label: "MEDIUM",   color: "text-amber-400",  bg: "bg-amber-950/50  border-amber-900/50",  ring: "#fbbf24", dot: "bg-amber-500" };
  if (score >= 20) return { label: "LOW",      color: "text-indigo-400", bg: "bg-indigo-950/50 border-indigo-900/50", ring: "#818cf8", dot: "bg-indigo-500" };
  return             { label: "INFO",      color: "text-zinc-500",   bg: "bg-zinc-800      border-zinc-700",      ring: "#52525b", dot: "bg-zinc-600" };
}

export default function RiskScore({ score, size = "md" }: Props) {
  if (score === null || score === undefined)
    return <span className="text-zinc-700 text-xs font-mono">—</span>;

  const risk = getRisk(score);
  const r    = 20;
  const circ = 2 * Math.PI * r;
  const off  = circ - (score / 100) * circ;

  if (size === "sm") {
    return (
      <span className={cn(
        "inline-flex items-center gap-1.5 text-[11px] font-semibold px-2 py-0.5 rounded-md border font-mono tracking-wide",
        risk.bg, risk.color
      )}>
        <span className={cn("w-1.5 h-1.5 rounded-full shrink-0", risk.dot)} />
        {score} · {risk.label}
      </span>
    );
  }

  if (size === "lg") {
    return (
      <div className="flex flex-col items-center gap-3">
        <div className="relative w-[110px] h-[110px]">
          <svg viewBox="0 0 50 50" className="w-full h-full -rotate-90">
            <circle cx="25" cy="25" r={r} fill="none" stroke="#27272a" strokeWidth="4.5" />
            <circle
              cx="25" cy="25" r={r}
              fill="none"
              stroke={risk.ring}
              strokeWidth="4.5"
              strokeDasharray={circ}
              strokeDashoffset={off}
              strokeLinecap="round"
              style={{ transition: "stroke-dashoffset 1.2s cubic-bezier(0.4,0,0.2,1)" }}
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className={cn("text-[26px] font-bold leading-none font-mono", risk.color)}>{score}</span>
            <span className="text-[10px] text-zinc-700 tracking-wider">/100</span>
          </div>
        </div>
        <span className={cn("text-[11px] font-bold px-3 py-1 rounded-md border tracking-widest", risk.bg, risk.color)}>
          {risk.label} RISK
        </span>
      </div>
    );
  }

  return (
    <div className={cn("inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border", risk.bg, risk.color)}>
      <span className={cn("w-2 h-2 rounded-full shrink-0", risk.dot)} />
      <span className="text-[15px] font-bold font-mono leading-none">{score}</span>
      <span className="text-[10px] font-semibold tracking-widest opacity-80">{risk.label}</span>
    </div>
  );
}

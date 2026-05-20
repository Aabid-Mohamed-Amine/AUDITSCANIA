"use client";

import { cn } from "@/lib/utils";

interface Props {
  score: number | null;
  size?: "sm" | "md" | "lg";
}

export default function RiskScore({ score, size = "md" }: Props) {
  if (score === null) return <span className="text-slate-600 text-xs">N/A</span>;

  const label = score >= 70 ? "Critical" : score >= 50 ? "High" : score >= 30 ? "Medium" : "Low";
  const color = score >= 70 ? "text-red-400" : score >= 50 ? "text-orange-400" : score >= 30 ? "text-yellow-400" : "text-green-400";
  const bg = score >= 70 ? "bg-red-500/10 border-red-500/30" : score >= 50 ? "bg-orange-500/10 border-orange-500/30" : score >= 30 ? "bg-yellow-500/10 border-yellow-500/30" : "bg-green-500/10 border-green-500/30";
  const ringColor = score >= 70 ? "#ef4444" : score >= 50 ? "#f97316" : score >= 30 ? "#eab308" : "#22c55e";

  const circumference = 2 * Math.PI * 20;
  const offset = circumference - (score / 100) * circumference;

  if (size === "sm") {
    return (
      <span className={cn("inline-flex items-center gap-1.5 text-xs font-medium px-2 py-0.5 rounded-full border", bg, color)}>
        <span className="font-bold">{score}</span>
        <span className="opacity-70">{label}</span>
      </span>
    );
  }

  if (size === "lg") {
    return (
      <div className="flex flex-col items-center gap-2">
        <div className="relative w-28 h-28">
          <svg viewBox="0 0 50 50" className="w-full h-full -rotate-90">
            <circle cx="25" cy="25" r="20" fill="none" stroke="#1e293b" strokeWidth="5" />
            <circle
              cx="25" cy="25" r="20" fill="none"
              stroke={ringColor} strokeWidth="5"
              strokeDasharray={circumference}
              strokeDashoffset={offset}
              strokeLinecap="round"
              style={{ transition: "stroke-dashoffset 1s ease" }}
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className={cn("text-2xl font-bold", color)}>{score}</span>
            <span className="text-xs text-slate-500">/100</span>
          </div>
        </div>
        <span className={cn("text-sm font-semibold px-3 py-1 rounded-full border", bg, color)}>
          {label} Risk
        </span>
      </div>
    );
  }

  return (
    <div className={cn("inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border text-sm font-medium", bg, color)}>
      <span className="text-lg font-bold">{score}</span>
      <span className="text-xs opacity-80">{label}</span>
    </div>
  );
}

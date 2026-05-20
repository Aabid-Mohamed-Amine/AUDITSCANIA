"use client";

import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";
import { type Scan } from "@/lib/api";

interface Props {
  scans: Scan[];
}

export default function RiskChart({ scans }: Props) {
  const completed = scans.filter((s) => s.status === "completed" && s.risk_score !== null);
  const data = completed.slice(0, 10).reverse().map((s) => ({
    name: s.target.length > 20 ? s.target.slice(0, 18) + "…" : s.target,
    score: s.risk_score ?? 0,
  }));

  const getColor = (score: number) => {
    if (score >= 70) return "#ef4444";
    if (score >= 40) return "#f59e0b";
    return "#22c55e";
  };

  if (data.length === 0) {
    return (
      <div className="h-48 flex items-center justify-center text-slate-600 text-sm">
        No completed scans yet
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={180}>
      <BarChart data={data} margin={{ top: 4, right: 4, bottom: 24, left: 0 }}>
        <XAxis
          dataKey="name"
          tick={{ fontSize: 10, fill: "#64748b" }}
          angle={-35}
          textAnchor="end"
          interval={0}
        />
        <YAxis domain={[0, 100]} tick={{ fontSize: 10, fill: "#64748b" }} width={28} />
        <Tooltip
          contentStyle={{ background: "#1e293b", border: "1px solid #334155", borderRadius: 8 }}
          labelStyle={{ color: "#94a3b8", fontSize: 12 }}
          itemStyle={{ color: "#e2e8f0", fontSize: 12 }}
          formatter={(v: number) => [`${v}/100`, "Risk Score"]}
        />
        <Bar dataKey="score" radius={[4, 4, 0, 0]}>
          {data.map((entry, i) => (
            <Cell key={i} fill={getColor(entry.score)} fillOpacity={0.85} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

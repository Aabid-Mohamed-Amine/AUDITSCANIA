"use client";

import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";
import { type Scan } from "@/lib/api";

interface Props { scans: Scan[] }

function getColor(score: number) {
  if (score >= 80) return "#ef4444";
  if (score >= 60) return "#f97316";
  if (score >= 40) return "#f59e0b";
  if (score >= 20) return "#3b82f6";
  return "#22c55e";
}

const CustomTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload?.length) return null;
  const score = payload[0].value;
  return (
    <div className="bg-[#080f1e] border border-[#0f1e30] rounded-[5px] px-3 py-2 text-[11px] font-mono shadow-xl">
      <p className="text-[#4a8ab5] mb-1 truncate max-w-[160px]">{label}</p>
      <p style={{ color: getColor(score) }} className="font-bold">{score} / 100</p>
    </div>
  );
};

export default function RiskChart({ scans }: Props) {
  const completed = scans.filter((s) => s.status === "completed" && s.risk_score !== null);
  const data = completed.slice(0, 10).reverse().map((s) => ({
    name:  s.target.length > 16 ? s.target.slice(0, 14) + "…" : s.target,
    score: s.risk_score ?? 0,
  }));

  if (data.length === 0) {
    return (
      <div className="h-48 flex flex-col items-center justify-center gap-2">
        <p className="text-[12px] text-[#1a3550]">No completed scans to display</p>
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={180}>
      <BarChart data={data} margin={{ top: 4, right: 4, bottom: 24, left: -8 }}>
        <XAxis
          dataKey="name"
          tick={{ fontSize: 9, fill: "#1e3a55", fontFamily: "monospace" }}
          angle={-35}
          textAnchor="end"
          interval={0}
          axisLine={{ stroke: "#0f1e30" }}
          tickLine={false}
        />
        <YAxis
          domain={[0, 100]}
          tick={{ fontSize: 9, fill: "#1e3a55", fontFamily: "monospace" }}
          width={28}
          axisLine={false}
          tickLine={false}
          tickCount={5}
        />
        <Tooltip content={<CustomTooltip />} cursor={{ fill: "rgba(30,58,85,0.15)" }} />
        <Bar dataKey="score" radius={[3, 3, 0, 0]} maxBarSize={36}>
          {data.map((entry, i) => (
            <Cell key={i} fill={getColor(entry.score)} fillOpacity={0.80} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

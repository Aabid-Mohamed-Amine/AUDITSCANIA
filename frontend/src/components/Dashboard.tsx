"use client";

import React from "react";
import { Activity, CheckCircle2, Clock, XCircle, Zap } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import ScanCard from "@/components/ScanCard";
import { useScans } from "@/hooks/useScans";
import { Scan } from "@/lib/api";

// ---------------------------------------------------------------------------
// Stat card
// ---------------------------------------------------------------------------

interface StatCardProps {
  title: string;
  value: number | string;
  icon: React.ReactNode;
  color: string;
}

function StatCard({ title, value, icon, color }: StatCardProps) {
  return (
    <Card className="bg-slate-800/50 border-slate-700">
      <CardContent className="p-5">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm text-slate-400">{title}</p>
            <p className={`text-3xl font-bold mt-1 ${color}`}>{value}</p>
          </div>
          <div className={`p-3 rounded-lg bg-slate-700/50 ${color}`}>{icon}</div>
        </div>
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

export default function Dashboard() {
  const { data, isLoading, isError } = useScans();

  const scans: Scan[] = data?.items ?? [];
  const total = data?.total ?? 0;

  const stats = React.useMemo(() => {
    const items = data?.items ?? [];
    const completed = items.filter((s) => s.status === "completed").length;
    const running = items.filter((s) => s.status === "running").length;
    const pending = items.filter((s) => s.status === "pending").length;
    const failed = items.filter((s) => s.status === "failed").length;
    return { completed, running, pending, failed };
  }, [data]);

  return (
    <div className="space-y-8">
      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <StatCard
          title="Total Scans"
          value={total}
          icon={<Activity className="h-5 w-5" />}
          color="text-cyan-400"
        />
        <StatCard
          title="Completed"
          value={stats.completed}
          icon={<CheckCircle2 className="h-5 w-5" />}
          color="text-green-400"
        />
        <StatCard
          title="Running"
          value={stats.running + stats.pending}
          icon={<Zap className="h-5 w-5" />}
          color="text-blue-400"
        />
        <StatCard
          title="Failed"
          value={stats.failed}
          icon={<XCircle className="h-5 w-5" />}
          color="text-red-400"
        />
      </div>

      <Separator className="bg-slate-700/50" />

      {/* Scan list */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-slate-200">Recent Scans</h2>
          {total > 0 && (
            <span className="text-sm text-slate-500">{total} total</span>
          )}
        </div>

        {isLoading && (
          <div className="space-y-3">
            {[1, 2, 3].map((i) => (
              <div
                key={i}
                className="h-20 rounded-lg bg-slate-800/50 border border-slate-700 animate-pulse"
              />
            ))}
          </div>
        )}

        {isError && (
          <div className="text-center py-12 text-slate-500">
            <XCircle className="h-12 w-12 mx-auto mb-3 text-red-400/50" />
            <p>Failed to load scans. Make sure the backend is running.</p>
          </div>
        )}

        {!isLoading && !isError && scans.length === 0 && (
          <div className="text-center py-16 text-slate-500">
            <Clock className="h-12 w-12 mx-auto mb-3 opacity-30" />
            <p className="text-lg">No scans yet</p>
            <p className="text-sm mt-1">Enter an IP or URL above to start your first scan</p>
          </div>
        )}

        {!isLoading && !isError && scans.length > 0 && (
          <div className="space-y-3">
            {scans.map((scan) => (
              <ScanCard key={scan.id} scan={scan} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

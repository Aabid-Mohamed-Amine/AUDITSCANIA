"use client";

import React from "react";
import Link from "next/link";
import { ExternalLink, Trash2, Clock, Globe } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Scan } from "@/lib/api";
import { formatDate, getStatusColor, getStatusDot } from "@/lib/utils";
import { useDeleteScan } from "@/hooks/useScans";

interface ScanCardProps {
  scan: Scan;
}

function statusLabel(status: string): string {
  switch (status) {
    case "completed": return "Completed";
    case "running":   return "Running";
    case "pending":   return "Pending";
    case "failed":    return "Failed";
    default:          return status;
  }
}

function badgeVariantForStatus(status: string): "success" | "info" | "warning" | "danger" | "outline" {
  switch (status) {
    case "completed": return "success";
    case "running":   return "info";
    case "pending":   return "warning";
    case "failed":    return "danger";
    default:          return "outline";
  }
}

export default function ScanCard({ scan }: ScanCardProps) {
  const deleteScan = useDeleteScan();

  const handleDelete = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (confirm(`Delete scan for ${scan.target}?`)) {
      deleteScan.mutate(scan.id);
    }
  };

  const isActive = scan.status === "running" || scan.status === "pending";

  return (
    <Link href={`/dashboard/scans/${scan.id}`} className="block group">
      <Card className="bg-slate-800/50 border-slate-700 hover:border-slate-500 hover:bg-slate-800 transition-all duration-200 cursor-pointer">
        <CardContent className="p-4">
          <div className="flex items-start justify-between gap-3">
            {/* Left: target + meta */}
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <Globe className="h-4 w-4 text-slate-400 flex-shrink-0" />
                <span className="font-mono text-slate-100 font-medium truncate text-sm">
                  {scan.target}
                </span>
              </div>

              <div className="flex items-center gap-3 text-xs text-slate-500">
                <span className="flex items-center gap-1">
                  <Clock className="h-3 w-3" />
                  {formatDate(scan.created_at)}
                </span>
                <span className="font-mono opacity-60 truncate max-w-[120px]">
                  {scan.id.slice(0, 8)}…
                </span>
              </div>

              {/* Progress bar for active scans */}
              {isActive && (
                <div className="mt-3 space-y-1">
                  <Progress
                    value={scan.progress}
                    className="h-1.5 bg-slate-700"
                  />
                  <span className="text-xs text-slate-400">{scan.progress}% complete</span>
                </div>
              )}
            </div>

            {/* Right: status badge + actions */}
            <div className="flex items-center gap-2 flex-shrink-0">
              <Badge variant={badgeVariantForStatus(scan.status)} className="capitalize">
                <span className={`w-1.5 h-1.5 rounded-full mr-1.5 ${getStatusDot(scan.status)}`} />
                {statusLabel(scan.status)}
              </Badge>

              <Button
                variant="ghost"
                size="icon"
                className="h-7 w-7 text-slate-500 hover:text-red-400 hover:bg-red-400/10 opacity-0 group-hover:opacity-100 transition-opacity"
                onClick={handleDelete}
                disabled={deleteScan.isPending}
                title="Delete scan"
              >
                <Trash2 className="h-3.5 w-3.5" />
              </Button>

              <ExternalLink className="h-4 w-4 text-slate-500 group-hover:text-slate-300 transition-colors flex-shrink-0" />
            </div>
          </div>
        </CardContent>
      </Card>
    </Link>
  );
}

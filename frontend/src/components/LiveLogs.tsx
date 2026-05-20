"use client";

import { useEffect, useRef } from "react";
import { Terminal } from "lucide-react";
import { type ScanLog } from "@/lib/api";
import { cn } from "@/lib/utils";
import { format } from "date-fns";

interface Props {
  logs: ScanLog[];
  isLive?: boolean;
}

const levelColor: Record<string, string> = {
  info: "text-slate-400",
  warning: "text-yellow-400",
  error: "text-red-400",
};

const levelPrefix: Record<string, string> = {
  info: "[INFO] ",
  warning: "[WARN] ",
  error: "[ERR!] ",
};

export default function LiveLogs({ logs, isLive = false }: Props) {
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  return (
    <div className="bg-slate-950 border border-slate-800 rounded-xl overflow-hidden">
      {/* Header */}
      <div className="flex items-center gap-2.5 px-4 py-2.5 bg-slate-900 border-b border-slate-800">
        <Terminal size={14} className="text-cyan-400" />
        <span className="text-xs font-medium text-slate-300">Live Logs</span>
        {isLive && (
          <span className="ml-auto flex items-center gap-1.5 text-xs text-green-400">
            <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
            LIVE
          </span>
        )}
      </div>

      {/* Log lines */}
      <div className="h-64 overflow-y-auto p-3 font-mono text-xs space-y-0.5 scroll-smooth">
        {logs.length === 0 ? (
          <span className="text-slate-600">Waiting for logs...</span>
        ) : (
          logs.map((log) => (
            <div key={log.id} className="flex gap-2 group">
              <span className="text-slate-700 flex-shrink-0 w-20 select-none">
                {format(new Date(log.created_at), "HH:mm:ss")}
              </span>
              <span className={cn("flex-shrink-0 w-14 font-semibold", levelColor[log.level] || "text-slate-400")}>
                {levelPrefix[log.level] || "[LOG] "}
              </span>
              <span className={cn(levelColor[log.level] || "text-slate-300")}>
                {log.message}
              </span>
            </div>
          ))
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}

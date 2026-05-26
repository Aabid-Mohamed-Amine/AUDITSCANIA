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

const LEVEL_STYLE: Record<string, { prefix: string; color: string }> = {
  info:    { prefix: "INFO ", color: "text-[#4a8ab5]" },
  warning: { prefix: "WARN ", color: "text-amber-400"  },
  error:   { prefix: "ERR! ", color: "text-red-400"    },
};

export default function LiveLogs({ logs, isLive = false }: Props) {
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  return (
    <div className="rounded-[6px] overflow-hidden border border-[#0f1e30] bg-[#030810]">
      {/* Header */}
      <div className="flex items-center gap-2.5 px-3 py-2 bg-[#060e1c] border-b border-[#0f1e30]">
        {/* Terminal dots */}
        <span className="w-2.5 h-2.5 rounded-full bg-red-500/70" />
        <span className="w-2.5 h-2.5 rounded-full bg-amber-500/70" />
        <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/70" />
        <Terminal className="w-3.5 h-3.5 text-[#2a5070] ml-1" />
        <span className="text-[11px] font-mono text-[#2a5070] tracking-wide">scan.log</span>
        {isLive && (
          <span className="ml-auto flex items-center gap-1.5 text-[10px] font-mono text-emerald-400 tracking-widest">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            LIVE
          </span>
        )}
      </div>

      {/* Log output */}
      <div className="h-64 overflow-y-auto p-3 font-mono text-[11px] leading-5 space-y-0.5">
        {/* Prompt line */}
        <div className="text-[#1e3a55] select-none mb-1">
          auditscan@scanner:~$ tail -f scan.log
        </div>

        {logs.length === 0 ? (
          <span className="text-[#1e3a55] animate-pulse">Waiting for output...</span>
        ) : (
          logs.map((log, idx) => {
            const lvl = LEVEL_STYLE[log.level] ?? { prefix: "LOG  ", color: "text-[#4a8ab5]" };
            return (
              <div key={log.id} className="flex gap-2 group hover:bg-white/[0.02] rounded px-1 -mx-1">
                {/* Line number */}
                <span className="text-[#1a3550] select-none w-6 text-right shrink-0 text-[10px] mt-px">
                  {idx + 1}
                </span>
                {/* Timestamp */}
                <span className="text-[#1e3a55] shrink-0 w-[52px]">
                  {format(new Date(log.created_at), "HH:mm:ss")}
                </span>
                {/* Level */}
                <span className={cn("shrink-0 w-[36px] font-bold", lvl.color)}>
                  {lvl.prefix}
                </span>
                {/* Message */}
                <span className={cn(
                  "break-all",
                  log.level === "error"   ? "text-red-300"   :
                  log.level === "warning" ? "text-amber-300" :
                  "text-[#6fa8d0]"
                )}>
                  {log.message}
                </span>
              </div>
            );
          })
        )}
        <div ref={bottomRef} />
      </div>

      {/* Footer */}
      <div className="px-3 py-1.5 bg-[#060e1c] border-t border-[#0f1e30] flex items-center justify-between">
        <span className="text-[10px] font-mono text-[#1e3a55]">{logs.length} lines</span>
        {isLive && (
          <span className="text-[10px] font-mono text-emerald-500/60">streaming...</span>
        )}
      </div>
    </div>
  );
}

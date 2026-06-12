"use client";

import { useEffect, useState, useCallback, useRef } from "react";
import { useRouter } from "next/navigation";
import { useScans } from "@/hooks/useScans";
import {
  LayoutDashboard, PlusCircle, History, Target,
  ArrowRight, Search, Command,
} from "lucide-react";
import { cn } from "@/lib/utils";

const NAV_ITEMS = [
  { id: "overview",  label: "Overview",     desc: "Security dashboard",   href: "/dashboard",           icon: LayoutDashboard },
  { id: "new-scan",  label: "New Scan",      desc: "Start a new scan",     href: "/dashboard/scans/new", icon: PlusCircle },
  { id: "history",   label: "Scan History",  desc: "Browse all scans",     href: "/dashboard/history",   icon: History },
];

interface Props {
  open: boolean;
  onClose: () => void;
}

export default function CommandPalette({ open, onClose }: Props) {
  const router   = useRouter();
  const [query, setQuery]   = useState("");
  const [sel, setSel]       = useState(0);
  const inputRef            = useRef<HTMLInputElement>(null);
  const { data }            = useScans(0, 10);

  const recentItems = (data?.items ?? []).slice(0, 5).map((s) => ({
    id:    s.id,
    label: s.target,
    desc:  `${s.status} · ${s.id.slice(0, 8)}`,
    href:  `/dashboard/scans/${s.id}`,
    icon:  Target,
  }));

  const allItems  = [...NAV_ITEMS, ...recentItems];
  const filtered  = query.trim()
    ? allItems.filter((i) =>
        i.label.toLowerCase().includes(query.toLowerCase()) ||
        i.desc.toLowerCase().includes(query.toLowerCase())
      )
    : allItems;

  useEffect(() => {
    if (open) {
      setQuery(""); setSel(0);
      const t = setTimeout(() => inputRef.current?.focus(), 40);
      return () => clearTimeout(t);
    }
  }, [open]);

  const go = useCallback(
    (href: string) => { router.push(href); onClose(); },
    [router, onClose]
  );

  useEffect(() => {
    if (!open) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === "ArrowDown") { e.preventDefault(); setSel((s) => Math.min(s + 1, filtered.length - 1)); }
      if (e.key === "ArrowUp")   { e.preventDefault(); setSel((s) => Math.max(s - 1, 0)); }
      if (e.key === "Enter")     { e.preventDefault(); if (filtered[sel]) go(filtered[sel].href); }
      if (e.key === "Escape")    { e.preventDefault(); onClose(); }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [open, filtered, sel, go, onClose]);

  if (!open) return null;

  const showNavSection   = !query.trim() && NAV_ITEMS.length > 0;
  const showRecentSection = !query.trim() && recentItems.length > 0;

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-[14vh] px-4"
      onClick={onClose}
    >
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm animate-[fade-in_0.12s_ease]" />

      {/* Panel */}
      <div
        className="relative w-full max-w-[540px] bg-zinc-900 border border-zinc-800 rounded-xl shadow-2xl shadow-black/60 overflow-hidden animate-[cmd-enter_0.15s_cubic-bezier(0.16,1,0.3,1)]"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Search */}
        <div className="flex items-center gap-3 px-4 py-3.5 border-b border-zinc-800/80">
          <Search className="w-4 h-4 text-zinc-500 shrink-0" />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => { setQuery(e.target.value); setSel(0); }}
            placeholder="Search pages, scans…"
            className="flex-1 bg-transparent text-[14px] text-zinc-100 placeholder-zinc-600 outline-none"
          />
          <kbd className="hidden sm:flex items-center px-1.5 py-0.5 rounded text-[10px] text-zinc-600 border border-zinc-800 font-mono">
            ESC
          </kbd>
        </div>

        {/* Results */}
        <div className="max-h-[360px] overflow-y-auto p-2">
          {showNavSection && (
            <p className="px-2 pt-1 pb-1.5 text-[10px] font-semibold text-zinc-600 uppercase tracking-widest">
              Navigation
            </p>
          )}

          {showRecentSection && recentItems.length > 0 && !query && (
            <>
              {NAV_ITEMS.map((item, i) => (
                <CmdItem key={item.id} item={item} active={sel === i} onHover={() => setSel(i)} onClick={() => go(item.href)} />
              ))}
              <p className="px-2 pt-3 pb-1.5 text-[10px] font-semibold text-zinc-600 uppercase tracking-widest">
                Recent Scans
              </p>
              {recentItems.map((item, i) => (
                <CmdItem
                  key={item.id} item={item}
                  active={sel === NAV_ITEMS.length + i}
                  onHover={() => setSel(NAV_ITEMS.length + i)}
                  onClick={() => go(item.href)}
                />
              ))}
            </>
          )}

          {(!showRecentSection || query.trim()) &&
            filtered.map((item, i) => (
              <CmdItem key={item.id} item={item} active={sel === i} onHover={() => setSel(i)} onClick={() => go(item.href)} />
            ))
          }

          {filtered.length === 0 && (
            <div className="py-10 text-center text-[13px] text-zinc-600">
              No results for &ldquo;{query}&rdquo;
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center gap-4 px-4 py-2.5 border-t border-zinc-800/80 text-[10px] text-zinc-600 font-mono select-none">
          <span><span className="text-zinc-500 mr-0.5">↑↓</span> navigate</span>
          <span><span className="text-zinc-500 mr-0.5">↵</span> open</span>
          <span className="ml-auto flex items-center gap-1 text-zinc-700">
            <Command className="w-3 h-3" /> K
          </span>
        </div>
      </div>
    </div>
  );
}

function CmdItem({
  item, active, onHover, onClick,
}: {
  item: { label: string; desc: string; icon: React.ElementType };
  active: boolean;
  onHover: () => void;
  onClick: () => void;
}) {
  const Icon = item.icon;
  return (
    <button
      onMouseEnter={onHover}
      onClick={onClick}
      className={cn(
        "w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-left transition-colors duration-75",
        active ? "bg-indigo-500/10 text-indigo-300" : "text-zinc-300 hover:bg-zinc-800/70"
      )}
    >
      <Icon className={cn("w-4 h-4 shrink-0", active ? "text-indigo-400" : "text-zinc-600")} />
      <div className="flex-1 min-w-0">
        <p className="text-[13px] font-medium truncate">{item.label}</p>
        <p className={cn("text-[11px] truncate", active ? "text-indigo-400/60" : "text-zinc-600")}>{item.desc}</p>
      </div>
      {active && <ArrowRight className="w-3.5 h-3.5 text-indigo-400 shrink-0" />}
    </button>
  );
}

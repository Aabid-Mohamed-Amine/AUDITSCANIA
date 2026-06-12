"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  Shield, LayoutDashboard, PlusCircle, History,
  LogOut, ChevronLeft, ChevronRight, Activity, Command,
} from "lucide-react";
import { useState } from "react";
import { useAuth } from "@/contexts/AuthContext";
import { cn } from "@/lib/utils";

const NAV = [
  { href: "/dashboard",            icon: LayoutDashboard, label: "Overview",    exact: true },
  { href: "/dashboard/scans/new",  icon: PlusCircle,      label: "New Scan"               },
  { href: "/dashboard/history",    icon: History,         label: "Scan History"            },
];

interface Props {
  onCmdK?: () => void;
}

export default function Sidebar({ onCmdK }: Props) {
  const pathname = usePathname();
  const router   = useRouter();
  const { user, logout } = useAuth();
  const [collapsed, setCollapsed] = useState(false);

  const isActive = (href: string, exact?: boolean) =>
    exact ? pathname === href : pathname.startsWith(href);

  const handleLogout = () => { logout(); router.push("/login"); };

  return (
    <aside
      className={cn(
        "relative flex flex-col h-screen shrink-0 select-none",
        "bg-zinc-950 border-r border-zinc-800/60",
        "transition-[width] duration-200 ease-out",
        collapsed ? "w-[56px]" : "w-[216px]"
      )}
    >
      {/* ── Logo ── */}
      <div className={cn(
        "flex items-center gap-2.5 px-3 py-[17px] border-b border-zinc-800/60",
        collapsed && "justify-center"
      )}>
        <div className="w-7 h-7 bg-indigo-600 rounded-[6px] flex items-center justify-center shrink-0">
          <Shield className="w-3.5 h-3.5 text-white" />
        </div>
        {!collapsed && (
          <div className="leading-none">
            <span className="block text-[13px] font-semibold text-zinc-100 tracking-tight">AuditScan</span>
            <span className="block text-[9px] text-zinc-600 uppercase tracking-[0.15em] mt-0.5">Security Platform</span>
          </div>
        )}
      </div>

      {/* ── Nav ── */}
      <nav className="flex-1 px-2 pt-3 pb-2 space-y-0.5">
        {NAV.map(({ href, icon: Icon, label, exact }) => {
          const active = isActive(href, exact);
          return (
            <Link
              key={href}
              href={href}
              title={collapsed ? label : undefined}
              className={cn(
                "group flex items-center gap-2.5 rounded-md text-[13px] transition-all duration-100",
                collapsed ? "justify-center px-0 py-2.5" : "px-2.5 py-2",
                active
                  ? "bg-indigo-500/10 text-indigo-300"
                  : "text-zinc-500 hover:bg-zinc-800/70 hover:text-zinc-200"
              )}
            >
              <Icon className={cn(
                "w-4 h-4 shrink-0 transition-transform duration-150 group-hover:scale-105",
                active ? "text-indigo-400" : "text-zinc-600"
              )} />
              {!collapsed && <span className="truncate">{label}</span>}
              {!collapsed && active && (
                <span className="ml-auto w-1 h-1 rounded-full bg-indigo-400 shrink-0" />
              )}
            </Link>
          );
        })}
      </nav>

      {/* ── Cmd+K hint ── */}
      {!collapsed && (
        <div className="px-2 pb-2">
          <button
            onClick={onCmdK}
            className="w-full flex items-center gap-2 px-2.5 py-2 rounded-md text-zinc-600 hover:text-zinc-400 hover:bg-zinc-800/50 transition-colors duration-100 group"
          >
            <Command className="w-3.5 h-3.5 shrink-0" />
            <span className="text-[12px] flex-1 text-left">Quick search</span>
            <kbd className="flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[10px] border border-zinc-800 font-mono text-zinc-700 group-hover:border-zinc-700 transition-colors">
              ⌘K
            </kbd>
          </button>
        </div>
      )}

      {/* ── User + Status ── */}
      <div className="border-t border-zinc-800/60 px-2 py-3 space-y-1.5">
        {!collapsed && (
          <>
            <div className="flex items-center gap-2 px-2.5 py-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 shrink-0" />
              <span className="text-[10px] text-zinc-600 uppercase tracking-widest truncate">Operational</span>
            </div>
            <div className="flex items-center gap-2 px-2.5 py-1.5 rounded-md bg-zinc-800/40">
              <Activity className="w-3 h-3 text-zinc-600 shrink-0" />
              <span className="text-[11px] text-zinc-500 truncate flex-1 font-mono">{user?.email}</span>
            </div>
          </>
        )}
        <button
          onClick={handleLogout}
          title={collapsed ? "Sign out" : undefined}
          className={cn(
            "w-full flex items-center gap-2 rounded-md text-[12px] text-zinc-600",
            "hover:text-red-400 hover:bg-red-950/20 transition-colors py-1.5",
            collapsed ? "justify-center px-0" : "px-2.5"
          )}
        >
          <LogOut className="w-3.5 h-3.5 shrink-0" />
          {!collapsed && "Sign out"}
        </button>
      </div>

      {/* ── Collapse toggle ── */}
      <button
        onClick={() => setCollapsed(!collapsed)}
        className={cn(
          "absolute -right-[10px] top-[20px] w-[20px] h-[20px] rounded-full z-20",
          "bg-zinc-900 border border-zinc-700/60 flex items-center justify-center",
          "text-zinc-600 hover:text-indigo-400 hover:border-indigo-700/50 transition-all duration-150"
        )}
      >
        {collapsed ? <ChevronRight className="w-3 h-3" /> : <ChevronLeft className="w-3 h-3" />}
      </button>
    </aside>
  );
}

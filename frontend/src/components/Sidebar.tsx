"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  Shield, LayoutDashboard, PlusCircle, History,
  LogOut, ChevronLeft, ChevronRight, Activity,
} from "lucide-react";
import { useState } from "react";
import { useAuth } from "@/contexts/AuthContext";
import { cn } from "@/lib/utils";

const NAV = [
  { href: "/dashboard",            icon: LayoutDashboard, label: "Overview",    exact: true },
  { href: "/dashboard/scans/new",  icon: PlusCircle,      label: "New Scan"               },
  { href: "/dashboard/history",    icon: History,         label: "Scan History"            },
];

export default function Sidebar() {
  const pathname   = usePathname();
  const router     = useRouter();
  const { user, logout } = useAuth();
  const [collapsed, setCollapsed] = useState(false);

  const isActive = (href: string, exact?: boolean) =>
    exact ? pathname === href : pathname.startsWith(href);

  const handleLogout = () => { logout(); router.push("/login"); };

  return (
    <aside
      className={cn(
        "relative flex flex-col h-screen shrink-0 transition-all duration-200",
        "bg-[#060d1a] border-r border-[#0f1e30]",
        collapsed ? "w-[58px]" : "w-[220px]"
      )}
    >
      {/* ── Logo ─────────────────────────────────────────────── */}
      <div
        className={cn(
          "flex items-center gap-3 px-3 py-[18px] border-b border-[#0f1e30]",
          collapsed && "justify-center"
        )}
      >
        <div className="shrink-0 w-8 h-8 bg-blue-600 rounded-[6px] flex items-center justify-center">
          <Shield className="w-4 h-4 text-white" />
        </div>
        {!collapsed && (
          <div className="leading-none">
            <span className="block text-[13px] font-bold text-white tracking-wide">
              AuditScan
            </span>
            <span className="block text-[10px] text-[#3d6080] uppercase tracking-widest mt-0.5">
              Security Platform
            </span>
          </div>
        )}
      </div>

      {/* ── Nav ──────────────────────────────────────────────── */}
      <nav className="flex-1 px-2 pt-4 pb-2 space-y-[2px]">
        {!collapsed && (
          <p className="px-2 mb-2 text-[10px] font-semibold text-[#2a4a6b] uppercase tracking-widest select-none">
            Menu
          </p>
        )}
        {NAV.map(({ href, icon: Icon, label, exact }) => {
          const active = isActive(href, exact);
          return (
            <Link
              key={href}
              href={href}
              title={collapsed ? label : undefined}
              className={cn(
                "flex items-center gap-3 rounded-[5px] text-[13px] transition-all duration-100 select-none",
                collapsed ? "justify-center px-0 py-2.5" : "px-2.5 py-2",
                active
                  ? "bg-blue-600/12 text-blue-400 border-l-[2px] border-blue-500"
                  : "text-[#5a7a99] hover:bg-white/[0.04] hover:text-[#8fb0d0] border-l-[2px] border-transparent"
              )}
            >
              <Icon
                className={cn(
                  "w-[17px] h-[17px] shrink-0",
                  active ? "text-blue-400" : "text-[#3d6080]"
                )}
              />
              {!collapsed && <span className="truncate">{label}</span>}
            </Link>
          );
        })}
      </nav>

      {/* ── Status + User ────────────────────────────────────── */}
      <div className="border-t border-[#0f1e30] px-3 py-3 space-y-2">
        {!collapsed && (
          <>
            <div className="flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse shrink-0" />
              <span className="text-[10px] text-[#2a5070] uppercase tracking-widest truncate">
                All systems operational
              </span>
            </div>
            <div className="flex items-center gap-2 px-1 py-1.5 rounded-[5px] bg-white/[0.02] border border-[#0f1e30]">
              <Activity className="w-3.5 h-3.5 text-[#2a5070] shrink-0" />
              <span className="text-[11px] text-[#3d6080] truncate flex-1">{user?.email}</span>
            </div>
          </>
        )}
        <button
          onClick={handleLogout}
          title={collapsed ? "Sign out" : undefined}
          className={cn(
            "w-full flex items-center gap-2.5 rounded-[5px] text-[12px] text-[#3d6080]",
            "hover:text-red-400 hover:bg-red-500/8 transition-colors py-1.5",
            collapsed ? "justify-center px-0" : "px-2"
          )}
        >
          <LogOut className="w-3.5 h-3.5 shrink-0" />
          {!collapsed && "Sign out"}
        </button>
      </div>

      {/* ── Collapse toggle ───────────────────────────────────── */}
      <button
        onClick={() => setCollapsed(!collapsed)}
        className={cn(
          "absolute -right-[11px] top-[22px] w-[22px] h-[22px] rounded-full",
          "bg-[#0a1828] border border-[#0f1e30] flex items-center justify-center",
          "text-[#2a5070] hover:text-blue-400 transition-colors z-20"
        )}
      >
        {collapsed
          ? <ChevronRight className="w-3 h-3" />
          : <ChevronLeft  className="w-3 h-3" />}
      </button>
    </aside>
  );
}

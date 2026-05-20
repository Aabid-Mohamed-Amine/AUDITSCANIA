"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  Shield, LayoutDashboard, Search, History,
  PlusCircle, Settings, LogOut, Activity, ChevronLeft, ChevronRight
} from "lucide-react";
import { useState } from "react";
import { useAuth } from "@/contexts/AuthContext";
import { cn } from "@/lib/utils";

const navItems = [
  { href: "/dashboard", icon: LayoutDashboard, label: "Dashboard" },
  { href: "/dashboard/scans/new", icon: PlusCircle, label: "New Scan" },
  { href: "/dashboard/history", icon: History, label: "History" },
];

export default function Sidebar() {
  const pathname = usePathname();
  const router = useRouter();
  const { user, logout } = useAuth();
  const [collapsed, setCollapsed] = useState(false);

  const handleLogout = () => {
    logout();
    router.push("/login");
  };

  return (
    <aside className={cn(
      "flex flex-col bg-slate-900 border-r border-slate-800 transition-all duration-300 min-h-screen",
      collapsed ? "w-16" : "w-60"
    )}>
      {/* Logo */}
      <div className={cn(
        "flex items-center gap-3 px-4 py-5 border-b border-slate-800",
        collapsed && "justify-center px-2"
      )}>
        <div className="p-1.5 bg-cyan-500/10 rounded-lg border border-cyan-500/20 flex-shrink-0">
          <Shield className="h-5 w-5 text-cyan-400" />
        </div>
        {!collapsed && (
          <span className="font-bold text-slate-100 text-sm">
            AuditScan <span className="text-cyan-400">IA</span>
          </span>
        )}
      </div>

      {/* Nav */}
      <nav className="flex-1 px-2 py-4 space-y-1">
        {navItems.map(({ href, icon: Icon, label }) => {
          const active = pathname === href || (href !== "/dashboard" && pathname.startsWith(href));
          return (
            <Link
              key={href}
              href={href}
              className={cn(
                "flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-colors group",
                active
                  ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/20"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-800",
                collapsed && "justify-center px-2"
              )}
              title={collapsed ? label : undefined}
            >
              <Icon size={18} className="flex-shrink-0" />
              {!collapsed && <span>{label}</span>}
            </Link>
          );
        })}
      </nav>

      {/* Live indicator */}
      {!collapsed && (
        <div className="px-4 py-3 mx-3 mb-3 bg-slate-800/60 rounded-lg border border-slate-700">
          <div className="flex items-center gap-2">
            <Activity size={12} className="text-green-400 animate-pulse" />
            <span className="text-xs text-slate-400">System operational</span>
          </div>
        </div>
      )}

      {/* User + collapse */}
      <div className="border-t border-slate-800 p-3 space-y-1">
        {!collapsed && user && (
          <div className="px-2 py-2 mb-1">
            <p className="text-xs font-medium text-slate-300 truncate">{user.email}</p>
            <p className="text-xs text-slate-600">Analyst</p>
          </div>
        )}

        <button
          onClick={handleLogout}
          className={cn(
            "w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm text-slate-400 hover:text-red-400 hover:bg-red-500/10 transition-colors",
            collapsed && "justify-center"
          )}
          title={collapsed ? "Logout" : undefined}
        >
          <LogOut size={16} />
          {!collapsed && <span>Logout</span>}
        </button>

        <button
          onClick={() => setCollapsed(!collapsed)}
          className={cn(
            "w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm text-slate-500 hover:text-slate-300 hover:bg-slate-800 transition-colors",
            collapsed && "justify-center"
          )}
        >
          {collapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
          {!collapsed && <span>Collapse</span>}
        </button>
      </div>
    </aside>
  );
}

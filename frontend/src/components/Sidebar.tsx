"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useState } from "react";
import { useAuth } from "@/contexts/AuthContext";
import { cn } from "@/lib/utils";

const NAV_MAIN = [
  { href: "/dashboard",            icon: "dashboard",      label: "Dashboard",    exact: true },
  { href: "/dashboard/history",    icon: "history",        label: "Scan History", exact: false },
  { href: "/dashboard/scans/new",  icon: "rocket_launch",  label: "Launch Scan",  exact: true },
];

const NAV_BOTTOM = [
  { href: "/dashboard/health",  icon: "monitor_heart", label: "System Health" },
  { href: "/dashboard/settings", icon: "settings",     label: "Settings"      },
];

interface Props { onCmdK?: () => void }

export default function Sidebar({ onCmdK }: Props) {
  const pathname = usePathname();
  const router   = useRouter();
  const { user, logout } = useAuth();
  const [collapsed, setCollapsed] = useState(false);

  const isActive = (item: typeof NAV_MAIN[0]) => {
    if (item.exact) return pathname === item.href;
    return pathname?.startsWith(item.href) ?? false;
  };

  const handleLogout = () => { logout(); router.push("/login"); };

  const initials = user?.email?.slice(0, 2).toUpperCase() ?? "OP";
  const analystLabel = user?.email?.split("@")[0] ?? "ANALYST_01";

  return (
    <aside
      className={cn(
        "relative flex flex-col h-screen shrink-0 border-r",
        "transition-[width] duration-200 ease-out"
      )}
      style={{
        width: collapsed ? 56 : 240,
        background: "var(--sc-surface)",
        borderColor: "var(--sc-border)",
        fontFamily: "'Geist', sans-serif",
      }}
    >
      {/* Logo / Brand */}
      <div
        className={cn("flex items-center gap-2 border-b px-3 py-4", collapsed && "justify-center")}
        style={{ borderColor: "var(--sc-border)" }}
      >
        <span
          className="material-symbols-outlined shrink-0"
          style={{
            fontSize: 22,
            color: "var(--sc-brand)",
            fontVariationSettings: "'FILL' 1, 'wght' 400",
          }}
        >
          shield_lock
        </span>
        {!collapsed && (
          <div className="leading-none overflow-hidden">
            <span
              className="block font-bold tracking-tighter truncate"
              style={{ fontSize: 15, color: "var(--sc-on)" }}
            >
              CYBER-OPS
            </span>
            <span
              className="block mt-0.5 uppercase font-mono tracking-widest opacity-60"
              style={{ fontSize: 9, color: "var(--sc-outline)" }}
            >
              v2.4.0-STABLE
            </span>
          </div>
        )}
      </div>

      {/* Main nav */}
      <nav className="flex-1 px-2 pt-3 pb-2 space-y-0.5 overflow-hidden">
        {NAV_MAIN.map((item) => {
          const active = isActive(item);
          return (
            <Link
              key={item.href}
              href={item.href}
              title={collapsed ? item.label : undefined}
              className={cn(
                "flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all duration-200",
                collapsed && "justify-center"
              )}
              style={{
                background:   active ? "var(--sc-high)" : "transparent",
                color:        active ? "var(--sc-brand)" : "var(--sc-on-v)",
                borderRight:  active ? `2px solid var(--sc-brand)` : "2px solid transparent",
                fontWeight:   active ? 700 : 400,
              }}
              onMouseEnter={(e) => {
                if (!active) {
                  (e.currentTarget as HTMLElement).style.background = "var(--sc-top)";
                  (e.currentTarget as HTMLElement).style.color = "var(--sc-on)";
                }
              }}
              onMouseLeave={(e) => {
                if (!active) {
                  (e.currentTarget as HTMLElement).style.background = "transparent";
                  (e.currentTarget as HTMLElement).style.color = "var(--sc-on-v)";
                }
              }}
            >
              <span
                className="material-symbols-outlined shrink-0"
                style={{ fontSize: 20 }}
              >
                {item.icon}
              </span>
              {!collapsed && (
                <span style={{ fontSize: 14 }}>{item.label}</span>
              )}
            </Link>
          );
        })}
      </nav>

      {/* Cmd+K search hint */}
      {!collapsed && (
        <div className="px-2 pb-2">
          <button
            onClick={onCmdK}
            className="w-full flex items-center gap-2 px-3 py-2 rounded-lg transition-colors duration-100"
            style={{ color: "var(--sc-outline)" }}
            onMouseEnter={(e) => {
              (e.currentTarget as HTMLElement).style.background = "var(--sc-top)";
              (e.currentTarget as HTMLElement).style.color = "var(--sc-on)";
            }}
            onMouseLeave={(e) => {
              (e.currentTarget as HTMLElement).style.background = "transparent";
              (e.currentTarget as HTMLElement).style.color = "var(--sc-outline)";
            }}
          >
            <span className="material-symbols-outlined" style={{ fontSize: 18 }}>search</span>
            <span style={{ fontSize: 12, flex: 1, textAlign: "left" }}>Quick search</span>
            <kbd
              className="flex items-center gap-0.5 px-1.5 py-0.5 rounded font-mono"
              style={{
                fontSize: 10,
                border: "1px solid var(--sc-border)",
                color: "var(--sc-outline)",
              }}
            >
              ^K
            </kbd>
          </button>
        </div>
      )}

      {/* Bottom nav */}
      <div
        className="border-t px-2 pt-3 pb-2 space-y-0.5"
        style={{ borderColor: "var(--sc-border)" }}
      >
        {NAV_BOTTOM.map((item) => (
          <Link
            key={item.href}
            href={item.href}
            title={collapsed ? item.label : undefined}
            className={cn(
              "flex items-center gap-3 px-3 py-2 rounded-lg transition-all duration-200",
              collapsed && "justify-center"
            )}
            style={{ color: "var(--sc-on-v)" }}
            onMouseEnter={(e) => {
              (e.currentTarget as HTMLElement).style.background = "var(--sc-top)";
              (e.currentTarget as HTMLElement).style.color = "var(--sc-on)";
            }}
            onMouseLeave={(e) => {
              (e.currentTarget as HTMLElement).style.background = "transparent";
              (e.currentTarget as HTMLElement).style.color = "var(--sc-on-v)";
            }}
          >
            <span className="material-symbols-outlined shrink-0" style={{ fontSize: 20 }}>{item.icon}</span>
            {!collapsed && <span style={{ fontSize: 14 }}>{item.label}</span>}
          </Link>
        ))}

        {/* User info card */}
        {!collapsed && (
          <div
            className="flex items-center gap-2.5 px-3 py-2 mt-2 rounded-lg"
            style={{ background: "var(--sc-low)" }}
          >
            <div
              className="w-8 h-8 rounded-full flex items-center justify-center shrink-0 text-white font-bold border"
              style={{ fontSize: 11, background: "var(--sc-brand)", borderColor: "var(--sc-border)" }}
            >
              {initials}
            </div>
            <div className="overflow-hidden flex-1">
              <p
                className="truncate font-semibold uppercase"
                style={{ fontSize: 11, color: "var(--sc-on)" }}
              >
                {analystLabel}
              </p>
              <p
                className="truncate uppercase"
                style={{ fontSize: 9, color: "var(--sc-outline)" }}
              >
                L3 Security
              </p>
            </div>
            <button
              onClick={handleLogout}
              title="Sign out"
              className="transition-colors duration-100"
              style={{ color: "var(--sc-outline)" }}
              onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.color = "var(--sc-error)")}
              onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.color = "var(--sc-outline)")}
            >
              <span className="material-symbols-outlined" style={{ fontSize: 18 }}>logout</span>
            </button>
          </div>
        )}

        {/* Collapsed logout */}
        {collapsed && (
          <button
            onClick={handleLogout}
            title="Sign out"
            className="w-full flex items-center justify-center py-2 rounded-lg transition-colors duration-100"
            style={{ color: "var(--sc-outline)" }}
            onMouseEnter={(e) => {
              (e.currentTarget as HTMLElement).style.color = "var(--sc-error)";
              (e.currentTarget as HTMLElement).style.background = "var(--sc-err-bg)";
            }}
            onMouseLeave={(e) => {
              (e.currentTarget as HTMLElement).style.color = "var(--sc-outline)";
              (e.currentTarget as HTMLElement).style.background = "transparent";
            }}
          >
            <span className="material-symbols-outlined" style={{ fontSize: 20 }}>logout</span>
          </button>
        )}
      </div>

      {/* Collapse toggle */}
      <button
        onClick={() => setCollapsed(!collapsed)}
        className="absolute -right-[11px] top-[22px] w-[22px] h-[22px] rounded-full z-20 flex items-center justify-center transition-all duration-150"
        style={{
          background: "var(--sc-surface)",
          border: "1px solid var(--sc-border)",
          color: "var(--sc-outline)",
        }}
        onMouseEnter={(e) => {
          (e.currentTarget as HTMLElement).style.borderColor = "var(--sc-brand)";
          (e.currentTarget as HTMLElement).style.color = "var(--sc-brand)";
        }}
        onMouseLeave={(e) => {
          (e.currentTarget as HTMLElement).style.borderColor = "var(--sc-border)";
          (e.currentTarget as HTMLElement).style.color = "var(--sc-outline)";
        }}
      >
        <span className="material-symbols-outlined" style={{ fontSize: 14 }}>
          {collapsed ? "chevron_right" : "chevron_left"}
        </span>
      </button>
    </aside>
  );
}

"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/contexts/AuthContext";
import { tokenStore } from "@/lib/api";
import Sidebar from "@/components/Sidebar";
import CommandPalette from "@/components/CommandPalette";

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading } = useAuth();
  const router = useRouter();
  const [cmdOpen, setCmdOpen] = useState(false);

  useEffect(() => {
    // Only redirect if no stored token — prevents race condition where React
    // hasn't committed setUser() yet but the token is already in storage
    if (!isLoading && !isAuthenticated && !tokenStore.getAccess()) {
      router.replace("/login");
    }
  }, [isAuthenticated, isLoading, router]);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setCmdOpen((v) => !v);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  if (isLoading || !isAuthenticated) {
    return (
      <div className="min-h-screen flex items-center justify-center" style={{ background: "var(--sc-bg)" }}>
        <div className="flex items-center gap-3">
          <span className="material-symbols-outlined text-[#0051d5] animate-pulse" style={{ fontSize: 28 }}>
            shield_lock
          </span>
          <span className="text-sm text-[#45464c]" style={{ fontFamily: "'Geist', sans-serif" }}>
            Loading AEGIS...
          </span>
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-screen overflow-hidden" style={{ background: "var(--sc-bg)" }}>
      <Sidebar onCmdK={() => setCmdOpen(true)} />
      <main className="flex-1 overflow-auto" style={{ background: "var(--sc-bg)" }}>
        {children}
      </main>
      <CommandPalette open={cmdOpen} onClose={() => setCmdOpen(false)} />
    </div>
  );
}

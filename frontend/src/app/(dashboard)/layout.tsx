"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/contexts/AuthContext";
import Sidebar from "@/components/Sidebar";
import { Shield } from "lucide-react";

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      router.replace("/login");
    }
  }, [isAuthenticated, isLoading, router]);

  if (isLoading || !isAuthenticated) {
    return (
      <div className="min-h-screen bg-[#050c18] flex items-center justify-center">
        <div className="flex items-center gap-3">
          <Shield className="w-5 h-5 text-blue-500 animate-pulse" />
          <span className="text-[13px] text-[#2a5070]">Loading AuditScan…</span>
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-screen bg-[#050c18] overflow-hidden">
      <Sidebar />
      <main className="flex-1 overflow-auto">
        {children}
      </main>
    </div>
  );
}

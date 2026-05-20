"use client";

import React, { useState } from "react";
import { useRouter } from "next/navigation";
import { Shield, Search, AlertCircle, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useCreateScan } from "@/hooks/useScans";

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

const IP_RE =
  /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
const DOMAIN_RE =
  /^(?:https?:\/\/)?(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|localhost|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?(?:\/?|[/?]\S+)?$/i;

function validateTarget(value: string): string | null {
  if (!value.trim()) return "Please enter an IP address or URL";
  if (!IP_RE.test(value.trim()) && !DOMAIN_RE.test(value.trim())) {
    return "Please enter a valid IPv4 address or URL (e.g. 8.8.8.8 or example.com)";
  }
  return null;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function ScanForm() {
  const router = useRouter();
  const [target, setTarget] = useState("");
  const [validationError, setValidationError] = useState<string | null>(null);

  const createScan = useCreateScan();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    const error = validateTarget(target);
    if (error) {
      setValidationError(error);
      return;
    }
    setValidationError(null);

    try {
      const scan = await createScan.mutateAsync({ target: target.trim() });
      setTarget("");
      router.push(`/dashboard/scans/${scan.id}`);
    } catch (err) {
      // Error shown via mutation state
    }
  };

  const isLoading = createScan.isPending;

  return (
    <div className="w-full max-w-2xl mx-auto">
      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="flex gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
            <Input
              type="text"
              placeholder="Enter IP address or URL (e.g. 8.8.8.8 or example.com)"
              value={target}
              onChange={(e) => {
                setTarget(e.target.value);
                if (validationError) setValidationError(null);
              }}
              className="pl-10 bg-slate-800 border-slate-600 text-slate-100 placeholder:text-slate-500 focus:border-cyan-500 focus:ring-cyan-500 h-12 text-base"
              disabled={isLoading}
              autoFocus
            />
          </div>
          <Button
            type="submit"
            disabled={isLoading || !target.trim()}
            className="h-12 px-6 bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-base transition-all duration-200 disabled:opacity-50"
          >
            {isLoading ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Scanning…
              </>
            ) : (
              <>
                <Shield className="mr-2 h-4 w-4" />
                Scan
              </>
            )}
          </Button>
        </div>

        {/* Validation error */}
        {validationError && (
          <div className="flex items-center gap-2 text-red-400 text-sm bg-red-400/10 border border-red-400/20 rounded-md px-3 py-2">
            <AlertCircle className="h-4 w-4 flex-shrink-0" />
            {validationError}
          </div>
        )}

        {/* API error */}
        {createScan.isError && (
          <div className="flex items-center gap-2 text-red-400 text-sm bg-red-400/10 border border-red-400/20 rounded-md px-3 py-2">
            <AlertCircle className="h-4 w-4 flex-shrink-0" />
            {createScan.error?.message || "Failed to start scan. Please try again."}
          </div>
        )}
      </form>

      <p className="mt-3 text-center text-xs text-slate-500">
        Supported: IPv4 addresses, domains, URLs — passive + active recon
      </p>
    </div>
  );
}

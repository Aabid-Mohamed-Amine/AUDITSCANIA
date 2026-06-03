"use client";

import React, { useState } from "react";
import { useRouter } from "next/navigation";
import { Shield, Search, AlertCircle, Loader2, Lock } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useCreateScan } from "@/hooks/useScans";

// ---------------------------------------------------------------------------
// Target validation + normalization
// ---------------------------------------------------------------------------

const _LABEL_RE = /^[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?$/;

/**
 * Returns true for any of:
 *   8.8.8.8             bare IPv4
 *   8.8.8.8:8080        IPv4 + port
 *   example.com         domain
 *   example.com:3000    domain + port
 *   http(s)://...       full URL
 *   juiceshop           Docker service name (single label, no TLD required)
 *   localhost:3000      local dev target
 */
function isValidTarget(value: string): boolean {
  if (!value.trim()) return false;

  let rest = value.trim();

  // Scheme check
  if (rest.includes("://")) {
    const scheme = rest.split("://")[0].toLowerCase();
    if (scheme !== "http" && scheme !== "https") return false;
    rest = rest.split("://")[1];
  }

  // Strip path + query
  rest = rest.split("/")[0].split("?")[0].split("#")[0];

  // Port
  let host = rest;
  if (rest.split(":").length === 2) {
    const [h, portStr] = rest.split(":");
    if (/^\d+$/.test(portStr)) {
      const p = parseInt(portStr, 10);
      if (p < 1 || p > 65535) return false;
      host = h;
    }
  }

  if (!host) return false;

  // IPv4
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
    return host.split(".").every((seg) => {
      const n = parseInt(seg, 10);
      return !isNaN(n) && n >= 0 && n <= 255;
    });
  }

  // Hostname / domain / Docker service name
  return host.split(".").every((lbl) => _LABEL_RE.test(lbl));
}

/**
 * Add http:// when no scheme is present and target is not a bare IPv4.
 * Bare IPs stay as-is (Nmap and other network tools need them without scheme).
 */
function normalizeTarget(value: string): string {
  const v = value.trim();
  if (!v) return v;
  if (v.toLowerCase().startsWith("http://") || v.toLowerCase().startsWith("https://")) {
    return v;
  }
  // Bare IPv4 (with or without port) → no scheme
  const bareHost = v.split(":")[0];
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(bareHost)) return v;
  // Domain / Docker hostname → add http://
  return `http://${v}`;
}

function validateTarget(value: string): string | null {
  if (!value.trim()) return "Please enter an IP, domain, or URL";
  if (!isValidTarget(value.trim())) {
    return "Invalid target — accepted: 8.8.8.8 · example.com · http://host:3000 · juiceshop";
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
      // Authentication is fully automatic server-side (Phase 1.5):
      // auto-detect + auto-register a random account + default credentials.
      // No manual credentials sent from the UI.
      const scan = await createScan.mutateAsync({
        target: normalizeTarget(target.trim()),
      });
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
              placeholder="8.8.8.8 · example.com · http://host:3000"
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

        {/* ── Authentication: fully automatic (no manual input) ── */}
        <div className="flex items-start gap-2.5 px-3 py-2.5 rounded-md border border-cyan-500/20 bg-cyan-500/5">
          <Lock className="h-4 w-4 text-cyan-400 flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-sm text-slate-200">Authentification automatique</p>
            <p className="text-[11px] text-slate-400 mt-0.5 leading-relaxed">
              Le scanner détecte le type d'auth, crée un compte de test aléatoire ou
              teste des identifiants par défaut, puis propage la session à ZAP, Nuclei,
              FFUF et SQLMap. Aucune saisie requise.
            </p>
          </div>
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
        IPv4 · domaine · URL · hostname Docker (juiceshop) · port optionnel (:3000)
      </p>
    </div>
  );
}

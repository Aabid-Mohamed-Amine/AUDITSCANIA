"use client";

import React, { useState } from "react";
import { useRouter } from "next/navigation";
import { Shield, Search, AlertCircle, Loader2, Lock, FlaskConical } from "lucide-react";
import { useCreateScan } from "@/hooks/useScans";
import { cn } from "@/lib/utils";

const _LABEL_RE = /^[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?$/;

function isValidTarget(value: string): boolean {
  if (!value.trim()) return false;
  let rest = value.trim();
  if (rest.includes("://")) {
    const scheme = rest.split("://")[0].toLowerCase();
    if (scheme !== "http" && scheme !== "https") return false;
    rest = rest.split("://")[1];
  }
  rest = rest.split("/")[0].split("?")[0].split("#")[0];
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
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
    return host.split(".").every((seg) => {
      const n = parseInt(seg, 10);
      return !isNaN(n) && n >= 0 && n <= 255;
    });
  }
  return host.split(".").every((lbl) => _LABEL_RE.test(lbl));
}

function normalizeTarget(value: string): string {
  const v = value.trim();
  if (!v) return v;
  if (v.toLowerCase().startsWith("http://") || v.toLowerCase().startsWith("https://")) return v;
  const bareHost = v.split(":")[0];
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(bareHost)) return v;
  return `http://${v}`;
}

function validateTarget(value: string): string | null {
  if (!value.trim()) return "Please enter an IP, domain, or URL";
  if (!isValidTarget(value.trim()))
    return "Invalid target — accepted: 8.8.8.8 · example.com · http://host:3000 · juiceshop";
  return null;
}

export default function ScanForm() {
  const router = useRouter();
  const [target, setTarget]           = useState("");
  const [validationError, setVError]  = useState<string | null>(null);
  const [labMode, setLabMode]         = useState(true);
  const createScan = useCreateScan();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const err = validateTarget(target);
    if (err) { setVError(err); return; }
    setVError(null);
    try {
      const scan = await createScan.mutateAsync({ target: normalizeTarget(target.trim()), lab_mode: labMode });
      setTarget("");
      router.push(`/dashboard/scans/${scan.id}`);
    } catch (_) { /* shown via mutation state */ }
  };

  const isLoading = createScan.isPending;

  return (
    <div className="w-full max-w-2xl mx-auto">
      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="flex gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-zinc-600" />
            <input
              type="text"
              placeholder="8.8.8.8 · example.com · http://host:3000"
              value={target}
              onChange={(e) => { setTarget(e.target.value); if (validationError) setVError(null); }}
              className={cn(
                "w-full pl-10 pr-3 h-11 rounded-lg text-[13px] font-mono",
                "bg-zinc-800/50 border text-zinc-100 placeholder-zinc-600",
                "transition-all duration-150 outline-none",
                validationError
                  ? "border-red-700/60 focus:border-red-600/50 focus:ring-1 focus:ring-red-500/15"
                  : "border-zinc-700 input-glow"
              )}
              disabled={isLoading}
              autoFocus
            />
          </div>
          <button
            type="submit"
            disabled={isLoading || !target.trim()}
            className="h-11 px-5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-[13px] transition-all disabled:opacity-50 btn-glow flex items-center gap-2"
          >
            {isLoading ? (
              <><Loader2 className="w-4 h-4 animate-spin" />Scanning…</>
            ) : (
              <><Shield className="w-4 h-4" />Scan</>
            )}
          </button>
        </div>

        <div className="flex items-start gap-2.5 px-3 py-2.5 rounded-lg border border-indigo-900/40 bg-indigo-950/20">
          <Lock className="w-3.5 h-3.5 text-indigo-500 shrink-0 mt-0.5" />
          <div>
            <p className="text-[12px] text-indigo-400 font-medium">Authentification automatique</p>
            <p className="text-[11px] text-indigo-400/50 mt-0.5 leading-relaxed">
              Le scanner détecte le type d&apos;auth, crée un compte de test aléatoire ou teste des identifiants
              par défaut, puis propage la session à ZAP, Nuclei, FFUF et SQLMap.
            </p>
          </div>
        </div>

        {/* Lab mode toggle */}
        <div className="flex items-center justify-between px-3 py-2.5 rounded-lg border border-zinc-800 bg-zinc-900/40">
          <div className="flex items-center gap-2.5">
            <FlaskConical className={cn("w-3.5 h-3.5 shrink-0", labMode ? "text-violet-400" : "text-zinc-600")} />
            <div>
              <p className={cn("text-[12px] font-medium", labMode ? "text-violet-300" : "text-zinc-500")}>
                Lab Challenge API
              </p>
              <p className="text-[11px] text-zinc-600 mt-0.5">
                {labMode
                  ? "Hints de vulnérabilités via l'API de la cible (Juice Shop, DVWA…)"
                  : "Détection 100% active — aucun hint applicatif"}
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={() => setLabMode((v) => !v)}
            className={cn(
              "relative shrink-0 w-9 h-5 rounded-full transition-colors duration-200",
              labMode ? "bg-violet-600" : "bg-zinc-700"
            )}
          >
            <span className={cn(
              "absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform duration-200",
              labMode ? "translate-x-4" : "translate-x-0"
            )} />
          </button>
        </div>

        {validationError && (
          <div className="flex items-center gap-2 text-red-400 text-[12px] bg-red-950/40 border border-red-900/50 rounded-lg px-3 py-2 fade-in">
            <AlertCircle className="w-3.5 h-3.5 shrink-0" />
            {validationError}
          </div>
        )}
        {createScan.isError && (
          <div className="flex items-center gap-2 text-red-400 text-[12px] bg-red-950/40 border border-red-900/50 rounded-lg px-3 py-2 fade-in">
            <AlertCircle className="w-3.5 h-3.5 shrink-0" />
            {createScan.error?.message || "Failed to start scan."}
          </div>
        )}
      </form>
      <p className="mt-3 text-center text-[11px] text-zinc-700">
        IPv4 · domaine · URL · hostname Docker (juiceshop) · port optionnel (:3000)
      </p>
    </div>
  );
}

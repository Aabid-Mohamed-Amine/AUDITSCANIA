"use client";

import React, { useState, useRef, useEffect } from "react";
import { useRouter } from "next/navigation";
import { useCreateScan } from "@/hooks/useScans";

/* ---- Validation (same logic as ScanForm) ---- */
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

const SCAN_PROFILES = [
  {
    id: "quick",
    icon: "bolt",
    label: "Quick",
    desc: "Top 100 ports, common CVEs, SSL check.",
    est: "Est. 5m",
  },
  {
    id: "deep",
    icon: "troubleshoot",
    label: "Deep",
    desc: "Full port scan, OS fingerprinting, script engine.",
    est: "Est. 45m",
  },
  {
    id: "pentest",
    icon: "shield_with_heart",
    label: "Pentest",
    desc: "Intrusive payloads, fuzzer, IDOR, lateral movement.",
    est: "Est. 4h+",
  },
];

const BOOT_LOGS = [
  "[SYSTEM] Aegis Command-Line Interface loaded.",
  "[SYSTEM] Initializing scan modules...",
  "[INFO] Resolving target DNS...",
  "[INFO] Routing packets through secure nodes...",
  "[WARN] Target firewall detected. Adjusting evasion techniques...",
  "[SYSTEM] Loading plugin: vulnerability-scanner.so",
  "[SYSTEM] Loading plugin: port-mapper.so",
  "[INFO] Handshake established. Beginning scan...",
];

export default function NewScanPage() {
  const router     = useRouter();
  const createScan = useCreateScan();

  const [target, setTarget]       = useState("");
  const [profile, setProfile]     = useState("quick");
  const [labMode, setLabMode]     = useState(true);
  const [advOpen, setAdvOpen]     = useState(false);
  const [ports, setPorts]         = useState("80, 443, 8080, 22, 21");
  const [stealth, setStealth]     = useState(false);
  const [error, setError]         = useState("");
  const [launching, setLaunching] = useState(false);

  const consoleRef = useRef<HTMLDivElement>(null);
  const [consoleLogs, setConsoleLogs] = useState([
    "[SYSTEM] Aegis Command-Line Interface loaded.",
    "[SYSTEM] Initializing scan modules...",
    "[SYSTEM] Waiting for target identification...",
  ]);
  const logTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  /* Animate console logs when target is entered */
  useEffect(() => {
    if (target.length > 3 && !launching) {
      setConsoleLogs([
        "[SYSTEM] Aegis Command-Line Interface loaded.",
        "[SYSTEM] Initializing scan modules...",
        `[INFO] Target identified: ${target}`,
        "[INFO] Pre-flight checks running...",
      ]);
    }
  }, [target, launching]);

  const handleLaunch = async () => {
    if (!isValidTarget(target)) {
      setError("Invalid target -- accepted: 8.8.8.8 · example.com · http://host:3000");
      return;
    }
    setError("");
    setLaunching(true);

    /* Animate console */
    let i = 0;
    const logs: string[] = [
      `[INFO] Target: ${normalizeTarget(target)}`,
      "[INFO] Resolving target DNS...",
      "[WARN] Target firewall detected. Adjusting evasion techniques...",
      "[SYSTEM] Loading plugin: vulnerability-scanner.so",
      "[SYSTEM] Loading plugin: port-mapper.so",
      "[INFO] Handshake established. Beginning scan...",
    ];
    setConsoleLogs(["[SYSTEM] Aegis CL Interface loaded."]);
    const animate = () => {
      if (i < logs.length) {
        setConsoleLogs((prev) => [...prev, logs[i]]);
        i++;
        logTimerRef.current = setTimeout(animate, 550);
      }
    };
    logTimerRef.current = setTimeout(animate, 200);

    try {
      const scan = await createScan.mutateAsync({
        target: normalizeTarget(target.trim()),
        lab_mode: labMode,
      });
      if (logTimerRef.current) clearTimeout(logTimerRef.current);
      router.push(`/dashboard/scans/${scan.id}`);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to start scan.");
      setLaunching(false);
      if (logTimerRef.current) clearTimeout(logTimerRef.current);
    }
  };

  /* Auto-scroll console */
  useEffect(() => {
    if (consoleRef.current) {
      consoleRef.current.scrollTop = consoleRef.current.scrollHeight;
    }
  }, [consoleLogs]);

  return (
    <div
      className="min-h-full"
      style={{ background: "var(--sc-bg)", fontFamily: "'Geist', sans-serif", color: "var(--sc-on)" }}
    >
      {/* Top bar */}
      <header
        className="sticky top-0 h-16 flex justify-between items-center px-4 z-40"
        style={{ background: "var(--sc-bg)", borderBottom: "1px solid var(--sc-border)" }}
      >
        <span className="font-bold tracking-tight" style={{ fontSize: 20, color: "var(--sc-on)" }}>
          Aegis Pentest
        </span>
        <div className="flex items-center gap-4">
          {["notifications", "wifi_tethering", "account_tree"].map((icon) => (
            <button
              key={icon}
              className="transition-colors"
              style={{ color: "var(--sc-on-v)" }}
              onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.color = "var(--sc-brand)")}
              onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.color = "var(--sc-on-v)")}
            >
              <span className="material-symbols-outlined" style={{ fontSize: 20 }}>{icon}</span>
            </button>
          ))}
        </div>
      </header>

      {/* Background decorations */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none opacity-40" aria-hidden>
        <div
          className="absolute top-1/4 -left-20 w-96 h-96 rounded-full blur-[120px]"
          style={{ background: "rgba(0,0,0,0.04)" }}
        />
        <div
          className="absolute bottom-1/4 -right-20 w-96 h-96 rounded-full blur-[120px]"
          style={{ background: "rgba(0,81,213,0.04)" }}
        />
      </div>

      <div className="relative z-10 flex flex-col items-center justify-center p-8 min-h-[calc(100vh-64px)]">
        <div className="w-full max-w-4xl space-y-8">

          {/* Header */}
          <div className="text-center space-y-2">
            <h2
              className="font-black tracking-tight"
              style={{ fontSize: 36, letterSpacing: "-0.02em", color: "var(--sc-on)" }}
            >
              Initiate Security Reconnaissance
            </h2>
            <p className="max-w-2xl mx-auto" style={{ fontSize: 16, color: "var(--sc-on-v)" }}>
              Deploy a specialized automated probe against your target. Choose your profile and
              configure parameters for a precision audit.
            </p>
          </div>

          {/* Main input card */}
          <div
            className="p-8 rounded-xl shadow-sm"
            style={{
              background: "#ffffff",
              border: "1px solid var(--sc-border)",
              boxShadow: "0 4px 20px rgba(0,81,213,0.08)",
            }}
          >
            <div className="space-y-6">

              {/* Target input */}
              <div className="space-y-2">
                <label
                  className="font-mono uppercase tracking-wider"
                  style={{ fontSize: 11, color: "var(--sc-outline)" }}
                >
                  Target Identity (URL or IP)
                </label>
                <div className="relative">
                  <span
                    className="material-symbols-outlined absolute left-4 top-1/2 -translate-y-1/2"
                    style={{ fontSize: 20, color: "var(--sc-outline)" }}
                  >
                    language
                  </span>
                  <input
                    type="text"
                    value={target}
                    onChange={(e) => { setTarget(e.target.value); if (error) setError(""); }}
                    placeholder="https://api.example.com or 192.168.1.1"
                    disabled={launching}
                    autoFocus
                    className="w-full rounded-lg pl-12 pr-4 py-4 outline-none transition-all"
                    style={{
                      background: "var(--sc-low)",
                      border: `1px solid ${error ? "var(--sc-error)" : "var(--sc-border)"}`,
                      color: "var(--sc-on)",
                      fontSize: 15,
                      fontFamily: "'JetBrains Mono', monospace",
                    }}
                    onFocus={(e) => {
                      e.currentTarget.style.borderColor = error ? "var(--sc-error)" : "var(--sc-brand)";
                      e.currentTarget.style.boxShadow = "0 0 0 3px rgba(0,81,213,0.1)";
                    }}
                    onBlur={(e) => {
                      e.currentTarget.style.borderColor = error ? "var(--sc-error)" : "var(--sc-border)";
                      e.currentTarget.style.boxShadow = "none";
                    }}
                  />
                </div>
                {error && (
                  <div
                    className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs"
                    style={{
                      background: "var(--sc-err-bg)",
                      border: "1px solid rgba(186,26,26,0.2)",
                      color: "var(--sc-err-on)",
                    }}
                  >
                    <span className="material-symbols-outlined" style={{ fontSize: 14 }}>error</span>
                    {error}
                  </div>
                )}
              </div>

              {/* Scan profile selection */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {SCAN_PROFILES.map((p) => (
                  <label key={p.id} className="cursor-pointer group">
                    <input
                      type="radio"
                      name="scan-profile"
                      value={p.id}
                      checked={profile === p.id}
                      onChange={() => setProfile(p.id)}
                      className="sr-only"
                    />
                    <div
                      className="h-full p-4 rounded-lg transition-all shadow-sm"
                      style={{
                        border: `1px solid ${profile === p.id ? "var(--sc-brand)" : "var(--sc-border)"}`,
                        background: profile === p.id ? "rgba(0,81,213,0.04)" : "var(--sc-low)",
                        boxShadow: profile === p.id ? "0 0 0 2px rgba(0,81,213,0.1)" : "none",
                      }}
                    >
                      <div className="flex items-center gap-3 mb-2">
                        <span
                          className="material-symbols-outlined"
                          style={{ fontSize: 20, color: "var(--sc-brand)" }}
                        >
                          {p.icon}
                        </span>
                        <span className="font-semibold" style={{ fontSize: 18, color: "var(--sc-on)" }}>
                          {p.label}
                        </span>
                      </div>
                      <p style={{ fontSize: 11, color: "var(--sc-on-v)", lineHeight: 1.5 }}>
                        {p.desc}
                      </p>
                      <p
                        className="font-mono mt-1"
                        style={{ fontSize: 10, color: "var(--sc-outline)" }}
                      >
                        {p.est}
                      </p>
                    </div>
                  </label>
                ))}
              </div>

              {/* Advanced parameters accordion */}
              <div style={{ borderTop: "1px solid var(--sc-border)", paddingTop: 16 }}>
                <button
                  type="button"
                  onClick={() => setAdvOpen((v) => !v)}
                  className="flex items-center gap-2 w-full transition-colors"
                  style={{ color: "var(--sc-on-v)" }}
                  onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.color = "var(--sc-on)")}
                  onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.color = "var(--sc-on-v)")}
                >
                  <span
                    className="material-symbols-outlined transition-transform"
                    style={{
                      fontSize: 18,
                      color: "var(--sc-outline)",
                      transform: advOpen ? "rotate(90deg)" : "rotate(0deg)",
                    }}
                  >
                    chevron_right
                  </span>
                  <span className="font-mono uppercase tracking-wider" style={{ fontSize: 11 }}>
                    Advanced Parameters
                  </span>
                  <div className="h-px flex-1 mx-4" style={{ background: "var(--sc-border)" }} />
                </button>

                {advOpen && (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-4 mt-6">
                    <div className="space-y-1">
                      <label
                        className="font-mono uppercase tracking-wider"
                        style={{ fontSize: 10, color: "var(--sc-outline)" }}
                      >
                        Target Ports
                      </label>
                      <input
                        type="text"
                        value={ports}
                        onChange={(e) => setPorts(e.target.value)}
                        className="w-full rounded px-3 py-2 outline-none"
                        style={{
                          background: "#ffffff",
                          border: "1px solid var(--sc-border)",
                          color: "var(--sc-on)",
                          fontSize: 13,
                          fontFamily: "'JetBrains Mono', monospace",
                        }}
                        onFocus={(e) => { e.currentTarget.style.borderColor = "var(--sc-brand)"; }}
                        onBlur={(e)  => { e.currentTarget.style.borderColor = "var(--sc-border)"; }}
                      />
                    </div>
                    <div className="space-y-1">
                      <label
                        className="font-mono uppercase tracking-wider"
                        style={{ fontSize: 10, color: "var(--sc-outline)" }}
                      >
                        User-Agent Spoofer
                      </label>
                      <select
                        className="w-full rounded px-3 py-2 outline-none appearance-none"
                        style={{
                          background: "#ffffff",
                          border: "1px solid var(--sc-border)",
                          color: "var(--sc-on)",
                          fontSize: 13,
                          fontFamily: "'Geist', sans-serif",
                        }}
                      >
                        <option>Chrome/119.0.0.0 (Windows)</option>
                        <option>Nmap Scripting Engine</option>
                        <option>Aegis-Scanner/2.4 (Security Audit)</option>
                      </select>
                    </div>
                    <div className="flex items-center gap-3">
                      <input
                        type="checkbox"
                        id="stealth"
                        checked={stealth}
                        onChange={(e) => setStealth(e.target.checked)}
                        className="w-4 h-4 rounded"
                        style={{ accentColor: "var(--sc-brand)" }}
                      />
                      <label htmlFor="stealth" style={{ fontSize: 14, color: "var(--sc-on-v)" }}>
                        Enable Stealth Mode (Adaptive Timings)
                      </label>
                    </div>
                    <div className="flex items-center gap-3">
                      <input
                        type="checkbox"
                        id="labmode"
                        checked={labMode}
                        onChange={(e) => setLabMode(e.target.checked)}
                        className="w-4 h-4 rounded"
                        style={{ accentColor: "var(--sc-brand)" }}
                      />
                      <label htmlFor="labmode" style={{ fontSize: 14, color: "var(--sc-on-v)" }}>
                        Lab Challenge API (Juice Shop / DVWA hints)
                      </label>
                    </div>
                  </div>
                )}
              </div>

              {/* Launch button */}
              <div className="pt-2">
                <button
                  type="button"
                  onClick={handleLaunch}
                  disabled={launching || !target.trim()}
                  className="w-full py-5 rounded-lg flex items-center justify-center gap-3 font-bold transition-all active:scale-[0.98] uppercase tracking-wide disabled:opacity-50"
                  style={{
                    background: "var(--sc-on)",
                    color: "#ffffff",
                    fontSize: 18,
                    boxShadow: "0 4px 16px rgba(0,0,0,0.15)",
                    fontFamily: "'Geist', sans-serif",
                  }}
                  onMouseEnter={(e) => {
                    if (!launching) (e.currentTarget as HTMLElement).style.background = "var(--sc-pc)";
                  }}
                  onMouseLeave={(e) => {
                    if (!launching) (e.currentTarget as HTMLElement).style.background = "var(--sc-on)";
                  }}
                >
                  <span
                    className={`material-symbols-outlined ${launching ? "animate-spin" : ""}`}
                    style={{ fontSize: 24 }}
                  >
                    {launching ? "sync" : "rocket_launch"}
                  </span>
                  {launching ? "DEPLOYING PROBES..." : "LAUNCH SECURITY SCAN"}
                </button>
              </div>
            </div>
          </div>

          {/* Live terminal preview */}
          <div
            className="rounded-lg overflow-hidden shadow-2xl"
            style={{ background: "#111827", border: "1px solid var(--sc-border)" }}
          >
            {/* Terminal header */}
            <div
              className="px-4 py-2 flex items-center justify-between"
              style={{ background: "#1f2937", borderBottom: "1px solid rgba(255,255,255,0.05)" }}
            >
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full" style={{ background: "rgba(239,68,68,0.6)" }} />
                <div className="w-3 h-3 rounded-full" style={{ background: "rgba(234,179,8,0.6)" }} />
                <div className="w-3 h-3 rounded-full" style={{ background: "rgba(34,197,94,0.6)" }} />
                <span className="font-mono ml-2" style={{ fontSize: 11, color: "#9ca3af" }}>
                  Console :: Pre-Flight Readiness
                </span>
              </div>
              <span className="font-mono" style={{ fontSize: 11, color: "#6b7280" }}>
                Terminal v0.98
              </span>
            </div>

            {/* Console output */}
            <div
              ref={consoleRef}
              className="p-4 h-40 overflow-y-auto font-mono space-y-0.5"
              style={{ fontSize: 12, color: "rgba(74,222,163,0.9)" }}
            >
              {consoleLogs.map((log, i) => (
                <p
                  key={i}
                  className={i === consoleLogs.length - 1 ? "animate-pulse" : ""}
                  style={{
                    color: log.startsWith("[WARN]")
                      ? "#f59e0b"
                      : log.startsWith("[INFO]")
                        ? "rgba(74,222,163,0.9)"
                        : "#9ca3af",
                  }}
                >
                  {log}
                  {i === consoleLogs.length - 1 && (
                    <span
                      className="inline-block w-2 h-4 ml-1 align-middle animate-pulse"
                      style={{ background: "var(--sc-brand)" }}
                    />
                  )}
                </p>
              ))}
            </div>
          </div>

          {/* Footer disclaimer */}
          <p className="text-center text-xs pb-4" style={{ color: "var(--sc-outline)" }}>
            By scanning a target you confirm you have explicit written authorization.
            Unauthorized scanning is illegal.
          </p>
        </div>
      </div>
    </div>
  );
}

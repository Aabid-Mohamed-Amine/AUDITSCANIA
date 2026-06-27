"use client";

import React from "react";
import {
  Globe,
  Shield,
  AlertTriangle,
  Terminal,
  ChevronDown,
  ChevronUp,
  Zap,
  ShieldCheck,
  ExternalLink,
  Network,
  Brain,
  Search,
  Database,
  Key,
  GitBranch,
  Filter,
  Layers,
  Sparkles,
  FileJson,
  FileText,
  Loader2,
} from "lucide-react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Scan, tokenStore } from "@/lib/api";

// ---------------------------------------------------------------------------
// Generic helpers
// ---------------------------------------------------------------------------

function JsonBlock({ data }: { data: unknown }) {
  return (
    <pre className="text-xs text-slate-300 bg-slate-900 rounded-md p-4 overflow-auto max-h-96 font-mono leading-relaxed">
      {JSON.stringify(data, null, 2)}
    </pre>
  );
}

function Section({
  title,
  defaultOpen = true,
  children,
}: {
  title: string;
  defaultOpen?: boolean;
  children: React.ReactNode;
}) {
  const [open, setOpen] = React.useState(defaultOpen);
  return (
    <div className="border border-[#e5e7eb] rounded-lg overflow-hidden">
      <button
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center justify-between px-4 py-3 bg-[#f5f7fa] hover:bg-[#eff2f7] text-left transition-colors"
      >
        <span className="text-sm font-semibold text-slate-800">{title}</span>
        {open ? (
          <ChevronUp className="h-4 w-4 text-slate-400" />
        ) : (
          <ChevronDown className="h-4 w-4 text-slate-400" />
        )}
      </button>
      {open && <div className="p-4">{children}</div>}
    </div>
  );
}

function EmptyState({ message }: { message: string }) {
  return <p className="text-slate-500 text-sm">{message}</p>;
}

function ErrorBanner({ message }: { message: string }) {
  return (
    <div className="text-red-400 text-sm bg-red-400/10 border border-red-400/20 rounded p-3">
      {message}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Severity / Risk badge helpers
// ---------------------------------------------------------------------------

const SEVERITY_VARIANT: Record<string, "danger" | "warning" | "info" | "secondary" | "success"> = {
  critical: "danger",
  high:     "danger",
  medium:   "warning",
  low:      "info",
  info:     "secondary",
  unknown:  "secondary",
};

const RISK_VARIANT: Record<string, "danger" | "warning" | "info" | "secondary"> = {
  Critical:      "danger",
  High:          "danger",
  Medium:        "warning",
  Low:           "info",
  Informational: "secondary",
};

// ---------------------------------------------------------------------------
// Download bar — JSON + PDF export (authenticated)
// ---------------------------------------------------------------------------

type DownloadState = "idle" | "loading" | "error";

function useDownload(scanId: string, format: "json" | "pdf") {
  const [state, setState] = React.useState<DownloadState>("idle");
  const [errMsg, setErrMsg] = React.useState("");

  const trigger = async () => {
    setState("loading");
    setErrMsg("");
    try {
      const token = tokenStore.getAccess();
      const res = await fetch(`/api/scans/${scanId}/report.${format}`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(text || `HTTP ${res.status}`);
      }
      const blob = await res.blob();
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement("a");
      // Derive filename from Content-Disposition or fallback
      const cd   = res.headers.get("Content-Disposition") ?? "";
      const match = cd.match(/filename="?([^"]+)"?/);
      a.href     = url;
      a.download = match?.[1] ?? `auditscania-report.${format}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      setState("idle");
    } catch (err) {
      setErrMsg(err instanceof Error ? err.message : "Download failed");
      setState("error");
      setTimeout(() => setState("idle"), 4000);
    }
  };

  return { state, errMsg, trigger };
}

function DownloadBar({ scan }: { scan: Scan }) {
  const isCompleted = scan.status === "completed";
  const jsonDl = useDownload(scan.id, "json");
  const pdfDl  = useDownload(scan.id, "pdf");

  if (!isCompleted) return null;

  return (
    <div className="flex items-center gap-3 px-4 py-3 bg-[#f5f7fa] border border-[#e5e7eb] rounded-xl mb-2">
      <div className="flex-1 min-w-0">
        <p className="text-xs font-medium text-slate-700">Export report</p>
        <p className="text-[10px] text-slate-500 mt-0.5">
          JSON structuré  · PDF professionnel BDO
        </p>
      </div>

      {/* JSON button */}
      <button
        onClick={jsonDl.trigger}
        disabled={jsonDl.state === "loading" || pdfDl.state === "loading"}
        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium
                   bg-white hover:bg-[#eff2f7] text-slate-700 border border-[#e5e7eb]
                   disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        title="Télécharger le rapport JSON structuré"
      >
        {jsonDl.state === "loading"
          ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
          : <FileJson className="h-3.5 w-3.5 text-cyan-400" />
        }
        {jsonDl.state === "error" ? (
          <span className="text-red-400">Erreur</span>
        ) : "JSON"}
      </button>

      {/* PDF button */}
      <button
        onClick={pdfDl.trigger}
        disabled={pdfDl.state === "loading" || jsonDl.state === "loading"}
        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium
                   bg-cyan-700 hover:bg-cyan-600 text-white
                   disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        title="Télécharger le rapport PDF BDO"
      >
        {pdfDl.state === "loading"
          ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
          : <FileText className="h-3.5 w-3.5" />
        }
        {pdfDl.state === "error" ? (
          <span>Erreur</span>
        ) : "PDF"}
      </button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Pipeline Overview — 5-phase summary banner
// ---------------------------------------------------------------------------

function PhaseStat({ label, value, color }: { label: string; value: string | number; color: string }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-xs text-slate-500">{label}</span>
      <span className={`text-xs font-semibold ${color}`}>{value}</span>
    </div>
  );
}

const RISK_BADGE_CLS: Record<string, string> = {
  CRITICAL:      "bg-red-500/20 text-red-400 border border-red-500/30",
  HIGH:          "bg-orange-500/20 text-orange-400 border border-orange-500/30",
  MEDIUM:        "bg-yellow-500/20 text-yellow-400 border border-yellow-500/30",
  LOW:           "bg-blue-500/20 text-blue-400 border border-blue-500/30",
  INFORMATIONAL: "bg-[#e8f4f8] text-[#64748b] border border-[#b3d4e0]",
};

function PipelineOverview({ scan }: { scan: Scan }) {
  // Use phases_summary from soc_report when available; fallback to raw fields (scan in progress)
  const socReport = scan.soc_report as Record<string, unknown> | null;
  const ps        = socReport?.phases_summary as Record<string, Record<string, unknown>> | undefined;
  const p1 = ps?.phase_1_recon;
  const p2 = ps?.phase_2_active_scan;
  const p3 = ps?.phase_3_exploitation;
  const p4 = ps?.phase_4_correlation;

  // Raw fallback data
  const nmapData     = scan.nmap_data       as Record<string, unknown> | null;
  const subfData     = scan.subfinder_data  as Record<string, unknown> | null;
  const abuseData    = scan.abuseipdb_data  as Record<string, unknown> | null;
  const vtData       = scan.virustotal_data as Record<string, unknown> | null;
  const nucleiData   = scan.nuclei_data     as Record<string, unknown> | null;
  const zapData      = scan.zap_data        as Record<string, unknown> | null;
  const dalfoxData   = scan.dalfox_data     as Record<string, unknown> | null;
  const ffufData     = scan.ffuf_data       as Record<string, unknown> | null;
  const gitleaksData = scan.gitleaks_data   as Record<string, unknown> | null;
  const sqlmapData   = scan.sqlmap_data     as Record<string, unknown> | null;
  const corrData     = scan.correlated_data as Record<string, unknown> | null;

  // ── Phase 1 values ────────────────────────────────────────────────────────
  const openPortsCount = Number(
    p1?.open_ports ??
    ((nmapData?.summary as Record<string, unknown>)?.ports as number[] | undefined)?.length ??
    0
  );
  const subdomains = Number(p1?.subdomains_found ?? subfData?.subdomains_count ?? 0);
  const abuseScore = Number(
    p1?.abuse_confidence ??
    (abuseData?.data as Record<string, unknown>)?.abuse_confidence_score ??
    0
  );
  const vtMalicious = Number(
    p1?.vt_malicious ??
    (vtData?.data as Record<string, unknown>)?.malicious ??
    Math.max(
      ((vtData?.data as Record<string, unknown>)?.domain as Record<string, number>)?.malicious ?? 0,
      ((vtData?.data as Record<string, unknown>)?.url    as Record<string, number>)?.malicious ?? 0,
    )
  );

  // ── Phase 2 values ────────────────────────────────────────────────────────
  const zapHigh    = Number(p2?.zap_high    ?? (zapData?.by_risk    as Record<string, number>)?.High    ?? 0);
  const zapMed     = Number(p2?.zap_medium  ?? (zapData?.by_risk    as Record<string, number>)?.Medium  ?? 0);
  const nCrit      = Number(p2?.nuclei_critical ?? (nucleiData?.by_severity as Record<string, number>)?.critical ?? 0);
  const nHigh      = Number(p2?.nuclei_high     ?? (nucleiData?.by_severity as Record<string, number>)?.high     ?? 0);
  const xssCount   = Number(p2?.dalfox_xss      ?? dalfoxData?.total ?? 0);

  // ── Phase 3 values ────────────────────────────────────────────────────────
  const ffufSens      = Number(p3 ? (Number(p3.ffuf_critical ?? 0) + Number(p3.ffuf_high ?? 0)) : 0) ||
    Number((ffufData?.by_severity as Record<string, unknown[]>)?.critical?.length ?? 0) +
    Number((ffufData?.by_severity as Record<string, unknown[]>)?.high?.length     ?? 0);
  const secretsTotal  = Number(p3?.secrets_total    ?? gitleaksData?.total ?? 0);
  const secretsCrit   = Number(p3?.secrets_critical ?? (gitleaksData?.by_severity as Record<string, number>)?.critical ?? 0);
  const sqlmapVuln    = Boolean(p3?.sqlmap_vulnerable ?? sqlmapData?.vulnerable ?? false);
  const sqlmapSkipped = Boolean(p3 ? !p3.sqlmap_ran  : sqlmapData?.skipped ?? !sqlmapData);
  const sqlmapFindings = Number(p3?.sqlmap_findings  ?? sqlmapData?.total ?? 0);

  // ── Phase 4 values ────────────────────────────────────────────────────────
  const totalFindings = Number(
    p4?.total_correlated ??
    (corrData?.correlated_findings as unknown[] | undefined)?.length ??
    0
  );
  const fpConfirmed   = Number(p4?.fp_confirmed ?? 0);
  const attackPaths   = Number(
    p4?.attack_paths ??
    (corrData?.attack_paths as unknown[] | undefined)?.length ??
    0
  );
  const riskScore     = Number(p4?.risk_score ?? scan.risk_score ?? 0);

  // ── Phase 5 values ────────────────────────────────────────────────────────
  const riskLevel  = String(socReport?.risk_level ?? "");
  const recsCount  = Number(
    (socReport?.recommendations as unknown[] | undefined)?.length ?? 0
  );

  // Whether threat-intel tools were skipped (internal/private target)
  const abuseSkipped = Boolean((abuseData as Record<string, unknown> | null)?.skipped) || !abuseData;
  const vtSkipped    = Boolean((vtData    as Record<string, unknown> | null)?.skipped) || !vtData;
  const subfSkipped  = Boolean((subfData  as Record<string, unknown> | null)?.skipped) || !subfData;

  // Dynamic Phase 1 subtitle — only list tools that actually ran
  const p1Subtitle = [
    "Nmap",
    !subfSkipped ? "Subfinder" : null,
    !vtSkipped   ? "VT"        : null,
    !abuseSkipped ? "AbuseIPDB" : null,
  ].filter(Boolean).join(" · ");

  // Helpers
  const abuseColor  = abuseScore >= 75 ? "text-red-400" : abuseScore >= 25 ? "text-yellow-400" : "text-green-400";
  const scoreColor  = (s: number) =>
    s >= 80 ? "text-red-500" : s >= 60 ? "text-red-400" : s >= 40 ? "text-yellow-400" : s >= 20 ? "text-blue-400" : "text-green-400";

  const hasAnyData = !!(nmapData || zapData || nucleiData || ffufData || corrData);
  if (!hasAnyData) return null;

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 mb-6">

      {/* ── Phase 1 — Recon ── */}
      <div className="bg-white border border-cyan-500/20 rounded-xl p-4 space-y-1.5">
        <div className="flex items-center gap-2 mb-3">
          <div className="p-1.5 bg-cyan-500/10 rounded-lg">
            <Search className="h-4 w-4 text-cyan-400" />
          </div>
          <div>
            <p className="text-xs font-semibold text-cyan-400">Phase 1 — Recon</p>
            <p className="text-[10px] text-slate-500">{p1Subtitle}</p>
          </div>
        </div>
        <PhaseStat label="Open ports"    value={openPortsCount} color={openPortsCount > 0 ? "text-orange-400" : "text-green-400"} />
        {subdomains > 0 && <PhaseStat label="Subdomains" value={subdomains} color="text-cyan-400" />}
        {!abuseSkipped && <PhaseStat label="Abuse score"  value={`${abuseScore}%`} color={abuseColor} />}
        {!vtSkipped    && <PhaseStat label="VT malicious" value={vtMalicious} color={vtMalicious > 0 ? "text-red-400" : "text-green-400"} />}
      </div>

      {/* ── Phase 2 — Active Scan ── */}
      <div className="bg-white border border-blue-500/20 rounded-xl p-4 space-y-1.5">
        <div className="flex items-center gap-2 mb-3">
          <div className="p-1.5 bg-blue-500/10 rounded-lg">
            <Zap className="h-4 w-4 text-blue-400" />
          </div>
          <div>
            <p className="text-xs font-semibold text-blue-400">Phase 2 — Active Scan</p>
            <p className="text-[10px] text-slate-500">ZAP · Nuclei · Dalfox</p>
          </div>
        </div>
        <PhaseStat label="ZAP high"      value={zapHigh} color={zapHigh > 0 ? "text-red-400" : "text-green-400"} />
        {zapMed > 0 && <PhaseStat label="ZAP medium"  value={zapMed}  color="text-yellow-400" />}
        <PhaseStat label="Nuclei critical" value={nCrit} color={nCrit > 0 ? "text-red-500" : "text-green-400"} />
        {nHigh > 0 && <PhaseStat label="Nuclei high"  value={nHigh}   color="text-orange-400" />}
        {xssCount > 0 && <PhaseStat label="XSS (Dalfox)" value={xssCount} color="text-red-400" />}
      </div>

      {/* ── Phase 3 — Exploitation ── */}
      <div className="bg-white border border-orange-500/20 rounded-xl p-4 space-y-1.5">
        <div className="flex items-center gap-2 mb-3">
          <div className="p-1.5 bg-orange-500/10 rounded-lg">
            <Terminal className="h-4 w-4 text-orange-400" />
          </div>
          <div>
            <p className="text-xs font-semibold text-orange-400">Phase 3 — Exploitation</p>
            <p className="text-[10px] text-slate-500">FFUF · GitLeaks · SQLMap</p>
          </div>
        </div>
        {ffufSens > 0 && <PhaseStat label="Sensitive paths" value={ffufSens} color="text-orange-400" />}
        <PhaseStat
          label="Secrets"
          value={secretsTotal}
          color={secretsCrit > 0 ? "text-red-500" : secretsTotal > 0 ? "text-orange-400" : "text-green-400"}
        />
        <div className="flex items-center justify-between">
          <span className="text-xs text-slate-500">SQLMap</span>
          {sqlmapSkipped
            ? <span className="text-[10px] text-slate-500 italic">skipped</span>
            : sqlmapVuln
              ? <span className="text-xs font-bold text-red-400">VULN ({sqlmapFindings})</span>
              : <span className="text-xs text-green-400">Clean</span>
          }
        </div>
      </div>

      {/* ── Phase 4 — Correlation ── */}
      <div className="bg-white border border-purple-500/20 rounded-xl p-4 space-y-1.5">
        <div className="flex items-center gap-2 mb-3">
          <div className="p-1.5 bg-purple-500/10 rounded-lg">
            <Layers className="h-4 w-4 text-purple-400" />
          </div>
          <div>
            <p className="text-xs font-semibold text-purple-400">Phase 4 — Correlation</p>
            <p className="text-[10px] text-slate-500">Dedup · FP · Risk Scoring</p>
          </div>
        </div>
        <PhaseStat label="Findings"      value={totalFindings} color={totalFindings > 0 ? "text-orange-400" : "text-green-400"} />
        {fpConfirmed > 0 && <PhaseStat label="Confirmed" value={fpConfirmed} color="text-red-400" />}
        {attackPaths > 0 && <PhaseStat label="Attack paths" value={attackPaths} color="text-orange-400" />}
        <PhaseStat label="Risk score"    value={`${riskScore}/100`} color={scoreColor(riskScore)} />
      </div>

      {/* ── Phase 5 — SOC Dashboard ── */}
      <div className="bg-white border border-green-500/20 rounded-xl p-4 space-y-1.5">
        <div className="flex items-center gap-2 mb-3">
          <div className="p-1.5 bg-green-500/10 rounded-lg">
            <ShieldCheck className="h-4 w-4 text-green-400" />
          </div>
          <div>
            <p className="text-xs font-semibold text-green-400">Phase 5 — SOC Report</p>
            <p className="text-[10px] text-slate-500">Rapport final</p>
          </div>
        </div>
        {riskLevel ? (
          <div className={`text-xs font-bold text-center py-1.5 rounded ${RISK_BADGE_CLS[riskLevel] ?? RISK_BADGE_CLS.INFORMATIONAL}`}>
            {riskLevel}
          </div>
        ) : (
          <p className="text-xs text-slate-600 text-center italic">Awaiting…</p>
        )}
        {recsCount > 0 && <PhaseStat label="Recommandations" value={recsCount} color="text-slate-700" />}
        {attackPaths > 0 && <PhaseStat label="Attack paths" value={attackPaths} color="text-orange-400" />}
      </div>

    </div>
  );
}

// ---------------------------------------------------------------------------
// Shodan panel
// ---------------------------------------------------------------------------

function ShodanPanel({ data }: { data: Record<string, unknown> | null }) {
  if (!data) return <EmptyState message="No Shodan data available." />;

  const internetdb = (data.data as Record<string, unknown> | undefined)?.internetdb as Record<string, unknown> | undefined;
  const full = (data.data as Record<string, unknown> | undefined)?.full as Record<string, unknown> | undefined;

  return (
    <div className="space-y-4">
      {!!data.error && <ErrorBanner message={`Error: ${String(data.error)}`} />}
      {!!data.resolved_ip && (
        <p className="text-sm text-slate-600">
          Resolved IP:{" "}
          <span className="font-mono text-slate-800">{String(data.resolved_ip)}</span>
        </p>
      )}
      {internetdb && (
        <Section title="InternetDB (Free Tier)">
          <div className="grid grid-cols-2 gap-4 mb-3">
            {(internetdb.ports as number[] | undefined)?.length ? (
              <div>
                <p className="text-xs text-slate-500 mb-1">Open Ports</p>
                <div className="flex flex-wrap gap-1">
                  {(internetdb.ports as number[]).map((p) => (
                    <Badge key={p} variant="info" className="font-mono text-xs">{p}</Badge>
                  ))}
                </div>
              </div>
            ) : null}
            {(internetdb.vulns as string[] | undefined)?.length ? (
              <div>
                <p className="text-xs text-slate-500 mb-1">CVEs</p>
                <div className="flex flex-wrap gap-1">
                  {(internetdb.vulns as string[]).map((v) => (
                    <Badge key={v} variant="danger" className="font-mono text-xs">{v}</Badge>
                  ))}
                </div>
              </div>
            ) : null}
          </div>
          <JsonBlock data={internetdb} />
        </Section>
      )}
      {full && (
        <Section title="Full Shodan Report" defaultOpen={false}>
          <JsonBlock data={full} />
        </Section>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// VirusTotal panel
// ---------------------------------------------------------------------------

function VirusTotalPanel({ data }: { data: Record<string, unknown> | null }) {
  if (!data) return <EmptyState message="No VirusTotal data available." />;

  const vdata = data.data as Record<string, unknown> | undefined;

  const renderStats = (stats: Record<string, unknown> | undefined, label: string) => {
    if (!stats) return null;
    const malicious = Number(stats.malicious || 0);
    const suspicious = Number(stats.suspicious || 0);
    return (
      <Section title={label}>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
          {[
            { key: "malicious",  color: "text-red-400",    bg: "bg-red-400/10"    },
            { key: "suspicious", color: "text-yellow-400", bg: "bg-yellow-400/10" },
            { key: "harmless",   color: "text-green-400",  bg: "bg-green-400/10"  },
            { key: "undetected", color: "text-slate-600",  bg: "bg-[#f5f7fa]"  },
          ].map(({ key, color, bg }) => (
            <div key={key} className={`${bg} rounded-lg p-3 text-center`}>
              <p className={`text-2xl font-bold ${color}`}>{String(stats[key] ?? 0)}</p>
              <p className="text-xs text-slate-500 capitalize">{key}</p>
            </div>
          ))}
        </div>
        {(malicious > 0 || suspicious > 0) && (
          <Badge variant="danger" className="mb-3">
            Detected by {malicious + suspicious} engines
          </Badge>
        )}
        <JsonBlock data={stats} />
      </Section>
    );
  };

  return (
    <div className="space-y-4">
      {!!data.error && <ErrorBanner message={`Error: ${String(data.error)}`} />}
      {vdata?.malicious !== undefined ? renderStats(vdata, "IP Analysis") : null}
      {vdata?.domain ? renderStats(vdata.domain as Record<string, unknown>, "Domain Analysis") : null}
      {vdata?.url ? renderStats(vdata.url as Record<string, unknown>, "URL Analysis") : null}
    </div>
  );
}

// ---------------------------------------------------------------------------
// AbuseIPDB panel
// ---------------------------------------------------------------------------

function AbuseIPDBPanel({ data }: { data: Record<string, unknown> | null }) {
  if (!data) return <EmptyState message="No AbuseIPDB data available." />;

  const d = data.data as Record<string, unknown> | undefined;
  const score = d ? Number(d.abuse_confidence_score ?? 0) : 0;
  const scoreColor =
    score >= 75 ? "text-red-400" : score >= 25 ? "text-yellow-400" : "text-green-400";

  return (
    <div className="space-y-4">
      {!!data.error && <ErrorBanner message={`Error: ${String(data.error)}`} />}
      {d && (
        <>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-4">
            <div className="bg-[#f5f7fa] border border-[#e5e7eb] rounded-lg p-4 text-center">
              <p className={`text-3xl font-bold ${scoreColor}`}>{score}%</p>
              <p className="text-xs text-slate-500 mt-1">Abuse Score</p>
            </div>
            <div className="bg-[#f5f7fa] border border-[#e5e7eb] rounded-lg p-4 text-center">
              <p className="text-3xl font-bold text-slate-800">{String(d.total_reports ?? 0)}</p>
              <p className="text-xs text-slate-500 mt-1">Total Reports</p>
            </div>
            <div className="bg-[#f5f7fa] border border-[#e5e7eb] rounded-lg p-4 text-center">
              <p className="text-3xl font-bold text-slate-800">{String(d.num_distinct_users ?? 0)}</p>
              <p className="text-xs text-slate-500 mt-1">Distinct Users</p>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-2 text-sm">
            {(
              [["ISP", "isp"], ["Country", "country_code"], ["Usage Type", "usage_type"], ["Domain", "domain"]] as [string, string][]
            ).map(([label, key]) =>
              d[key] ? (
                <div key={label} className="flex gap-2">
                  <span className="text-slate-500">{label}:</span>
                  <span className="text-slate-700">{String(d[key])}</span>
                </div>
              ) : null
            )}
          </div>
          <Section title="Raw Data" defaultOpen={false}>
            <JsonBlock data={d} />
          </Section>
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Nmap panel
// ---------------------------------------------------------------------------

function NmapPanel({ data }: { data: Record<string, unknown> | null }) {
  if (!data) return <EmptyState message="No Nmap data available." />;

  const ndata = data.data as Record<string, unknown> | undefined;
  const hosts = (ndata?.hosts as Array<Record<string, unknown>>) || [];

  return (
    <div className="space-y-4">
      {!!data.error && <ErrorBanner message={`Error: ${String(data.error)}`} />}
      {!!data.scan_method && (
        <p className="text-xs text-slate-500">
          Scan method: <span className="text-slate-700">{String(data.scan_method)}</span>
        </p>
      )}
      {hosts.map((host, i) => {
        const ports = (host.ports as Array<Record<string, unknown>>) || [];
        const openPorts = ports.filter((p) => p.state === "open");
        const osInfo = (host.os as Array<Record<string, unknown>>) || [];
        const addr = (host.addresses as Array<{ addr: string }>)?.[0]?.addr || "unknown";
        return (
          <div key={i} className="space-y-3">
            <Section title={`Host ${i + 1}: ${addr}`}>
              {osInfo.length > 0 && (
                <div className="mb-3">
                  <p className="text-xs text-slate-500 mb-1">OS Detection</p>
                  {osInfo.slice(0, 2).map((o, j) => (
                    <Badge key={j} variant="secondary" className="mr-1">
                      {String(o.name)} ({String(o.accuracy)}%)
                    </Badge>
                  ))}
                </div>
              )}
              {openPorts.length > 0 ? (
                <div className="overflow-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="text-slate-500 border-b border-[#e5e7eb]">
                        <th className="text-left pb-2 pr-4">Port</th>
                        <th className="text-left pb-2 pr-4">Protocol</th>
                        <th className="text-left pb-2 pr-4">Service</th>
                        <th className="text-left pb-2 pr-4">Product</th>
                        <th className="text-left pb-2">Version</th>
                      </tr>
                    </thead>
                    <tbody>
                      {openPorts.map((p, j) => (
                        <tr key={j} className="border-b border-[#f0f0f0] hover:bg-[#f5f7fa]">
                          <td className="py-1.5 pr-4 font-mono text-blue-600">{String(p.port)}</td>
                          <td className="py-1.5 pr-4 text-slate-500 uppercase text-[10px]">{String(p.protocol)}</td>
                          <td className="py-1.5 pr-4 text-slate-700">{String(p.service || "–")}</td>
                          <td className="py-1.5 pr-4 text-slate-600">{String(p.product || "–")}</td>
                          <td className="py-1.5 text-slate-500">{String(p.version || "–")}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <EmptyState message="No open ports found." />
              )}
            </Section>
          </div>
        );
      })}
      {hosts.length === 0 && !data.error && (
        <EmptyState message="No host data in nmap results." />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Nuclei panel
// ---------------------------------------------------------------------------

type NucleiFinding = {
  template_id: string;
  name: string;
  severity: string;
  description: string;
  tags: string[];
  cve_ids: string[];
  cwe_ids: string[];
  reference: string[];
  matched_at: string;
  host: string;
  type: string;
};

function NucleiPanel({ data }: { data: Record<string, unknown> | null }) {
  if (!data) return <EmptyState message="No Nuclei data available." />;

  const findings = (data.findings as NucleiFinding[]) || [];
  const by_severity = (data.by_severity as Record<string, number>) || {};
  const total = Number(data.total ?? findings.length);

  const SEV_ORDER = ["critical", "high", "medium", "low", "info", "unknown"];
  const sorted = [...findings].sort(
    (a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)
  );

  return (
    <div className="space-y-4">
      {!!data.error && <ErrorBanner message={`Error: ${String(data.error)}`} />}

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: "Critical", key: "critical", color: "text-red-500",    bg: "bg-red-500/10"    },
          { label: "High",     key: "high",     color: "text-orange-400", bg: "bg-orange-400/10" },
          { label: "Medium",   key: "medium",   color: "text-yellow-400", bg: "bg-yellow-400/10" },
          { label: "Low",      key: "low",      color: "text-blue-400",   bg: "bg-blue-400/10"   },
        ].map(({ label, key, color, bg }) => (
          <div key={key} className={`${bg} rounded-lg p-3 text-center`}>
            <p className={`text-2xl font-bold ${color}`}>{by_severity[key] ?? 0}</p>
            <p className="text-xs text-slate-500 mt-0.5">{label}</p>
          </div>
        ))}
      </div>

      {total === 0 && !data.error && (
        <div className="flex items-center gap-2 p-3 bg-green-500/10 border border-green-500/20 rounded-lg">
          <ShieldCheck className="h-4 w-4 text-green-400 flex-shrink-0" />
          <p className="text-sm text-green-400">No vulnerabilities detected by Nuclei templates.</p>
        </div>
      )}

      {sorted.length > 0 && (
        <div className="space-y-2">
          {sorted.map((f, i) => (
            <FindingCard key={i} finding={f} />
          ))}
        </div>
      )}
    </div>
  );
}

function FindingCard({ finding }: { finding: NucleiFinding }) {
  const [open, setOpen] = React.useState(
    finding.severity === "critical" || finding.severity === "high"
  );
  const variant = SEVERITY_VARIANT[finding.severity] ?? "secondary";

  return (
    <div className="border border-[#e5e7eb] rounded-lg overflow-hidden">
      <button
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-start gap-3 px-4 py-3 bg-[#f9f9ff] hover:bg-[#f0f4f8] text-left transition-colors"
      >
        <Badge variant={variant} className="mt-0.5 capitalize flex-shrink-0">
          {finding.severity}
        </Badge>
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium text-slate-800 truncate">{finding.name}</p>
          <p className="text-xs text-slate-500 font-mono truncate mt-0.5">
            {finding.matched_at || finding.host}
          </p>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          {finding.cve_ids.slice(0, 2).map((cve) => (
            <Badge key={cve} variant="danger" className="font-mono text-[10px]">
              {cve}
            </Badge>
          ))}
          {open ? (
            <ChevronUp className="h-3.5 w-3.5 text-slate-500" />
          ) : (
            <ChevronDown className="h-3.5 w-3.5 text-slate-500" />
          )}
        </div>
      </button>

      {open && (
        <div className="px-4 py-3 space-y-3 bg-[#f5f7fa] text-xs">
          {finding.description && (
            <p className="text-slate-600 leading-relaxed">{finding.description}</p>
          )}
          <div className="flex flex-wrap gap-2">
            {finding.tags.map((tag) => (
              <span
                key={tag}
                className="bg-[#e8edf5] text-slate-600 px-2 py-0.5 rounded text-[10px]"
              >
                {tag}
              </span>
            ))}
          </div>
          {finding.cve_ids.length > 0 && (
            <div className="flex gap-1 flex-wrap">
              <span className="text-slate-500">CVE:</span>
              {finding.cve_ids.map((cve) => (
                <span key={cve} className="text-red-400 font-mono">
                  {cve}
                </span>
              ))}
            </div>
          )}
          {finding.cwe_ids.length > 0 && (
            <div className="flex gap-1 flex-wrap">
              <span className="text-slate-500">CWE:</span>
              {finding.cwe_ids.map((cwe) => (
                <span key={cwe} className="text-orange-400 font-mono">
                  {cwe}
                </span>
              ))}
            </div>
          )}
          {finding.reference.length > 0 && (
            <div className="space-y-0.5">
              <p className="text-slate-500">References:</p>
              {finding.reference.slice(0, 3).map((ref, i) => (
                <a
                  key={i}
                  href={ref}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-1 text-cyan-400 hover:text-cyan-300 truncate"
                >
                  <ExternalLink className="h-3 w-3 flex-shrink-0" />
                  {ref}
                </a>
              ))}
            </div>
          )}
          <p className="text-slate-600 font-mono">Template: {finding.template_id}</p>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// ZAP panel
// ---------------------------------------------------------------------------

type ZapAlert = {
  name: string;
  risk: string;
  risk_code: number;
  confidence: string;
  description: string;
  solution: string;
  reference: string;
  cwe_id: string;
  wasc_id: string;
  plugin_id: string;
  count: number;
  instances: Array<{ uri: string; method: string; param: string; evidence: string }>;
};

function ZapPanel({ data }: { data: Record<string, unknown> | null }) {
  if (!data) return <EmptyState message="No OWASP ZAP data available." />;

  const alerts = (data.alerts as ZapAlert[]) || [];
  const by_risk = (data.by_risk as Record<string, number>) || {};
  const total = Number(data.total ?? alerts.length);

  return (
    <div className="space-y-4">
      {!!data.error && <ErrorBanner message={`Error: ${String(data.error)}`} />}

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: "High",          key: "High",          color: "text-red-400",    bg: "bg-red-400/10"    },
          { label: "Medium",        key: "Medium",        color: "text-yellow-400", bg: "bg-yellow-400/10" },
          { label: "Low",           key: "Low",           color: "text-blue-400",   bg: "bg-blue-400/10"   },
          { label: "Informational", key: "Informational", color: "text-[#64748b]",  bg: "bg-[#e8f4f8]"    },
        ].map(({ label, key, color, bg }) => (
          <div key={key} className={`${bg} rounded-lg p-3 text-center`}>
            <p className={`text-2xl font-bold ${color}`}>{by_risk[key] ?? 0}</p>
            <p className="text-xs text-slate-500 mt-0.5">{label}</p>
          </div>
        ))}
      </div>

      {total === 0 && !data.error && (
        <div className="flex items-center gap-2 p-3 bg-green-500/10 border border-green-500/20 rounded-lg">
          <ShieldCheck className="h-4 w-4 text-green-400 flex-shrink-0" />
          <p className="text-sm text-green-400">No web vulnerabilities detected by OWASP ZAP.</p>
        </div>
      )}

      {alerts.length > 0 && (
        <div className="space-y-2">
          {alerts.map((alert, i) => (
            <AlertCard key={i} alert={alert} />
          ))}
        </div>
      )}
    </div>
  );
}

function AlertCard({ alert }: { alert: ZapAlert }) {
  const [open, setOpen] = React.useState(alert.risk_code >= 3);
  const variant = RISK_VARIANT[alert.risk] ?? "secondary";

  return (
    <div className="border border-[#e5e7eb] rounded-lg overflow-hidden">
      <button
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-start gap-3 px-4 py-3 bg-[#f9f9ff] hover:bg-[#f0f4f8] text-left transition-colors"
      >
        <Badge variant={variant} className="mt-0.5 flex-shrink-0 capitalize">
          {alert.risk}
        </Badge>
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium text-slate-800 truncate">{alert.name}</p>
          <p className="text-xs text-slate-500 mt-0.5">
            {alert.count} instance{alert.count !== 1 ? "s" : ""}
            {alert.cwe_id ? ` · CWE-${alert.cwe_id}` : ""}
          </p>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          <span className="text-[10px] text-slate-500">Confidence: {alert.confidence}</span>
          {open ? (
            <ChevronUp className="h-3.5 w-3.5 text-slate-500" />
          ) : (
            <ChevronDown className="h-3.5 w-3.5 text-slate-500" />
          )}
        </div>
      </button>

      {open && (
        <div className="px-4 py-3 space-y-3 bg-[#f5f7fa] text-xs">
          {alert.description && (
            <div>
              <p className="text-slate-500 font-semibold mb-1">Description</p>
              <p className="text-slate-700 leading-relaxed">
                {alert.description.replace(/<[^>]*>/g, "")}
              </p>
            </div>
          )}
          {alert.solution && (
            <div>
              <p className="text-slate-500 font-semibold mb-1">Solution</p>
              <p className="text-slate-700 leading-relaxed">
                {alert.solution.replace(/<[^>]*>/g, "")}
              </p>
            </div>
          )}
          {alert.instances.length > 0 && (
            <div>
              <p className="text-slate-500 font-semibold mb-1">
                Affected URLs ({alert.count} total, showing {alert.instances.length})
              </p>
              <div className="space-y-1">
                {alert.instances.map((inst, i) => (
                  <div key={i} className="bg-white border border-[#e5e7eb] rounded p-2">
                    <div className="flex items-center gap-2">
                      <Badge variant="secondary" className="text-[9px] font-mono flex-shrink-0">
                        {inst.method}
                      </Badge>
                      <span className="text-blue-600 font-mono truncate">{inst.uri}</span>
                    </div>
                    {inst.param && (
                      <p className="text-slate-600 mt-1">
                        Param: <span className="text-slate-800 font-medium">{inst.param}</span>
                      </p>
                    )}
                    {inst.evidence && (
                      <p className="text-slate-500 mt-0.5 truncate">
                        Evidence:{" "}
                        <span className="text-orange-400 font-mono">{inst.evidence}</span>
                      </p>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
          <div className="flex gap-4 text-slate-600">
            {alert.cwe_id && <span>CWE-{alert.cwe_id}</span>}
            {alert.wasc_id && <span>WASC-{alert.wasc_id}</span>}
            {alert.plugin_id && <span>Plugin {alert.plugin_id}</span>}
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// FFUF panel
// ---------------------------------------------------------------------------

function FfufPanel({ data }: { data: Record<string, unknown> | null }) {
  if (!data) return <EmptyState message="No FFUF data available." />;
  const endpoints = (data.endpoints as Array<Record<string, unknown>>) || [];
  const byStatus = (data.by_status as Record<string, number>) || {};
  const categorized = (data.categorized as Record<string, Array<Record<string, unknown>>>) || {};

  const statusColor = (s: number) => {
    if (s === 200 || s === 201) return "text-green-400";
    if (s === 301 || s === 302 || s === 307) return "text-blue-400";
    if (s === 401 || s === 403) return "text-yellow-400";
    if (s === 500) return "text-red-400";
    return "text-slate-600";
  };

  return (
    <div className="space-y-4">
      {!!data.error && <ErrorBanner message={`Error: ${String(data.error)}`} />}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {Object.entries(byStatus).map(([status, count]) => (
          <div key={status} className="bg-[#f5f7fa] border border-[#e5e7eb] rounded-lg p-3 text-center">
            <p className={`text-2xl font-bold ${statusColor(Number(status))}`}>{count}</p>
            <p className="text-xs text-slate-500 mt-0.5">HTTP {status}</p>
          </div>
        ))}
      </div>
      {(categorized.sensitive?.length ?? 0) > 0 && (
        <Section title={`Sensitive Paths (${categorized.sensitive!.length})`}>
          <div className="space-y-1">
            {categorized.sensitive!.map((ep, i) => (
              <div key={i} className="flex items-center gap-2 text-xs font-mono">
                <span className={`w-10 text-center rounded px-1 ${statusColor(Number(ep.status))} bg-slate-900`}>{String(ep.status)}</span>
                <span className="text-orange-400 truncate">{String(ep.url)}</span>
              </div>
            ))}
          </div>
        </Section>
      )}
      {endpoints.length > 0 && (
        <Section title={`All Endpoints (${endpoints.length})`} defaultOpen={false}>
          <div className="space-y-1 max-h-80 overflow-auto">
            {endpoints.map((ep, i) => (
              <div key={i} className="flex items-center gap-2 text-xs font-mono">
                <span className={`w-10 text-center rounded px-1 ${statusColor(Number(ep.status))} bg-slate-900`}>{String(ep.status)}</span>
                <span className="text-slate-700 truncate">{String(ep.url)}</span>
                <span className="text-slate-500 flex-shrink-0">{String(ep.length)}b</span>
              </div>
            ))}
          </div>
        </Section>
      )}
      {endpoints.length === 0 && !data.error && (
        <div className="flex items-center gap-2 p-3 bg-green-500/10 border border-green-500/20 rounded-lg">
          <ShieldCheck className="h-4 w-4 text-green-400" />
          <p className="text-sm text-green-400">No interesting endpoints discovered.</p>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// SQLMap panel
// ---------------------------------------------------------------------------

function SqlmapPanel({ data }: { data: Record<string, unknown> | null }) {
  if (!data) return <EmptyState message="No SQLMap data available." />;

  // SQLMap was skipped (no injectable params detected by ZAP)
  if (data.skipped) {
    return (
      <div className="flex items-center gap-3 p-4 rounded-lg border bg-[#f5f7fa] border-[#e5e7eb]">
        <Filter className="h-5 w-5 text-slate-500 flex-shrink-0" />
        <div>
          <p className="text-sm font-semibold text-slate-700">SQLMap non exécuté</p>
          <p className="text-xs text-slate-600 mt-0.5 leading-relaxed">
            {String(data.reason ?? "Aucun paramètre injectable détecté par ZAP — SQLMap skippé (réduction de faux positifs).")}
          </p>
        </div>
      </div>
    );
  }

  const findings = (data.findings as Array<Record<string, unknown>>) || [];
  const vulnerable = Boolean(data.vulnerable);

  return (
    <div className="space-y-4">
      {!!data.error && <ErrorBanner message={`Error: ${String(data.error)}`} />}
      <div className={`flex items-center gap-3 p-4 rounded-lg border ${
        vulnerable ? "bg-red-500/10 border-red-500/30" : "bg-green-500/10 border-green-500/20"
      }`}>
        {vulnerable
          ? <AlertTriangle className="h-5 w-5 text-red-400 flex-shrink-0" />
          : <ShieldCheck className="h-5 w-5 text-green-400 flex-shrink-0" />}
        <div>
          <p className={`font-semibold text-sm ${vulnerable ? "text-red-400" : "text-green-400"}`}>
            {vulnerable ? `SQL Injection DETECTED — ${findings.length} point(s)` : "No SQL Injection detected"}
          </p>
          {!!data.dbms && <p className="text-xs text-slate-500 mt-0.5">DBMS: {String(data.dbms)}</p>}
        </div>
      </div>
      {findings.map((f, i) => (
        <div key={i} className="border border-red-500/20 rounded-lg p-4 bg-red-500/5 space-y-2">
          <div className="flex items-center gap-2">
            <Badge variant="danger">CWE-89</Badge>
            <span className="text-sm font-medium text-slate-800">
              Parameter: <span className="font-mono text-red-500">{String(f.parameter)}</span>
            </span>
          </div>
          <p className="text-xs text-slate-600">{String(f.technique)}</p>
          <p className="text-xs text-slate-500 font-mono bg-slate-900 rounded p-2 truncate">
            {String(f.payload_example || "")}
          </p>
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// GitLeaks panel
// ---------------------------------------------------------------------------

function GitleaksPanel({ data }: { data: Record<string, unknown> | null }) {
  if (!data) return <EmptyState message="No GitLeaks data available." />;
  const findings = (data.findings as Array<Record<string, unknown>>) || [];
  const bySev = (data.by_severity as Record<string, number>) || {};
  const total = Number(data.total ?? 0);

  return (
    <div className="space-y-4">
      {!!data.error && <ErrorBanner message={`Error: ${String(data.error)}`} />}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: "Critical", key: "critical", color: "text-red-500", bg: "bg-red-500/10" },
          { label: "High",     key: "high",     color: "text-orange-400", bg: "bg-orange-400/10" },
          { label: "Medium",   key: "medium",   color: "text-yellow-400", bg: "bg-yellow-400/10" },
          { label: "Low",      key: "low",      color: "text-blue-400",   bg: "bg-blue-400/10"   },
        ].map(({ label, key, color, bg }) => (
          <div key={key} className={`${bg} rounded-lg p-3 text-center`}>
            <p className={`text-2xl font-bold ${color}`}>{bySev[key] ?? 0}</p>
            <p className="text-xs text-slate-500 mt-0.5">{label}</p>
          </div>
        ))}
      </div>
      {total === 0 && !data.error && (
        <div className="flex items-center gap-2 p-3 bg-green-500/10 border border-green-500/20 rounded-lg">
          <ShieldCheck className="h-4 w-4 text-green-400" />
          <p className="text-sm text-green-400">No secrets or credentials detected.</p>
        </div>
      )}
      <div className="space-y-2">
        {findings.map((f, i) => (
          <div key={i} className="border border-[#e5e7eb] rounded-lg p-3 space-y-2 bg-white">
            <div className="flex items-start gap-2">
              <Badge variant={SEVERITY_VARIANT[String(f.severity)] ?? "secondary"} className="capitalize flex-shrink-0">
                {String(f.severity)}
              </Badge>
              <div>
                <p className="text-xs font-mono text-slate-700">{String(f.rule_id)}</p>
                <p className="text-xs text-slate-500 mt-0.5">{String(f.description)}</p>
              </div>
            </div>
            <p className="text-xs text-slate-600 truncate font-mono">{String(f.file)}</p>
            <p className="text-xs bg-slate-900 rounded p-2 font-mono text-orange-400 truncate">
              {String(f.match || "")}
            </p>
            <p className="text-xs text-slate-600">Secret: <span className="text-slate-700 font-medium">{String(f.secret)}</span></p>
          </div>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Correlation panel
// ---------------------------------------------------------------------------

function CorrelationPanel({ data }: { data: Record<string, unknown> | null }) {
  if (!data) return <EmptyState message="No correlation data available." />;
  const findings = (data.correlated_findings as Array<Record<string, unknown>>) || [];
  const bySev = (data.by_severity as Record<string, number>) || {};
  const attackPaths = (data.attack_paths as Array<Record<string, unknown>>) || [];

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: "Critical", key: "critical", color: "text-red-500",    bg: "bg-red-500/10"    },
          { label: "High",     key: "high",     color: "text-orange-400", bg: "bg-orange-400/10" },
          { label: "Medium",   key: "medium",   color: "text-yellow-400", bg: "bg-yellow-400/10" },
          { label: "Low",      key: "low",      color: "text-blue-400",   bg: "bg-blue-400/10"   },
        ].map(({ label, key, color, bg }) => (
          <div key={key} className={`${bg} rounded-lg p-3 text-center`}>
            <p className={`text-2xl font-bold ${color}`}>{bySev[key] ?? 0}</p>
            <p className="text-xs text-slate-500 mt-0.5">{label}</p>
          </div>
        ))}
      </div>
      {attackPaths.length > 0 && (
        <Section title={`Attack Paths (${attackPaths.length})`}>
          <div className="space-y-2">
            {attackPaths.map((ap, i) => (
              <div key={i} className="bg-slate-900 rounded p-3 text-xs">
                <p className="text-orange-400 font-semibold">{String(ap.path_type || ap.type || "Attack path")}</p>
                <p className="text-slate-400 mt-1">{String(ap.description || "")}</p>
              </div>
            ))}
          </div>
        </Section>
      )}
      <Section title={`Correlated Findings (${findings.length})`}>
        <div className="space-y-2">
          {findings.length === 0 && <EmptyState message="No correlated findings." />}
          {findings.map((f, i) => (
            <div key={i} className="border border-[#e5e7eb] rounded-lg p-3 space-y-1 bg-[#f9f9ff]">
              <div className="flex items-center gap-2">
                <Badge variant={SEVERITY_VARIANT[String(f.severity)?.toLowerCase()] ?? "secondary"} className="capitalize">
                  {String(f.severity)}
                </Badge>
                <span className="text-sm text-slate-800">{String(f.title)}</span>
              </div>
              <div className="flex gap-2 flex-wrap">
                {(f.sources as string[] || []).map((s) => (
                  <span key={s} className="text-[10px] bg-[#e8edf5] text-slate-600 px-1.5 rounded">{s}</span>
                ))}
                <span className="text-[10px] text-slate-500">
                  Confidence: {typeof f.confidence_score === "number" ? `${Math.round(f.confidence_score * 100)}%` : String(f.confidence_score)}
                </span>
              </div>
            </div>
          ))}
        </div>
      </Section>
    </div>
  );
}

// ---------------------------------------------------------------------------
// FP Reduction panel
// ---------------------------------------------------------------------------

function FpReductionPanel({ data }: { data: Record<string, unknown> | null }) {
  if (!data) return <EmptyState message="No FP reduction data available." />;
  const byLayer = (data.removed_by_layer as Record<string, number>) || {};
  const rate = Number(data.fp_reduction_rate ?? 0);

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-3 gap-3">
        <div className="bg-[#f5f7fa] border border-[#e5e7eb] rounded-lg p-4 text-center">
          <p className="text-3xl font-bold text-slate-800">{String(data.original_count ?? 0)}</p>
          <p className="text-xs text-slate-500 mt-1">Original</p>
        </div>
        <div className="bg-[#f5f7fa] border border-[#e5e7eb] rounded-lg p-4 text-center">
          <p className="text-3xl font-bold text-green-600">{String(data.final_count ?? 0)}</p>
          <p className="text-xs text-slate-500 mt-1">After Filter</p>
        </div>
        <div className="bg-[#f5f7fa] border border-[#e5e7eb] rounded-lg p-4 text-center">
          <p className="text-3xl font-bold text-orange-500">{Math.round(rate * 100)}%</p>
          <p className="text-xs text-slate-500 mt-1">Reduction</p>
        </div>
      </div>
      <Section title="Removed by Layer">
        <div className="space-y-2">
          {Object.entries(byLayer).map(([layer, count]) => (
            <div key={layer} className="flex items-center justify-between">
              <span className="text-xs text-slate-600 capitalize">{layer.replace(/_/g, " ")}</span>
              <div className="flex items-center gap-2">
                <div className="w-32 bg-[#e5e7eb] rounded-full h-1.5">
                  <div
                    className="bg-orange-400 h-1.5 rounded-full"
                    style={{ width: `${Math.min(100, count * 20)}%` }}
                  />
                </div>
                <span className="text-xs text-slate-700 w-4 text-right">{count}</span>
              </div>
            </div>
          ))}
        </div>
      </Section>
    </div>
  );
}

// ---------------------------------------------------------------------------
// AI Analysis panel
// ---------------------------------------------------------------------------

function AiAnalysisPanel({ data }: { data: Record<string, unknown> | null }) {
  if (!data) return <EmptyState message="No AI analysis available." />;
  if (data.enabled === false) {
    return (
      <div className="p-6 text-center space-y-3">
        <Sparkles className="h-8 w-8 text-slate-600 mx-auto" />
        <p className="text-sm text-slate-500">AI Analysis is disabled.</p>
        <p className="text-xs text-slate-600">
          Set <code className="bg-[#e8edf5] text-slate-700 px-1 rounded">GEMINI_API_KEY</code> and{" "}
          <code className="bg-[#e8edf5] text-slate-700 px-1 rounded">AI_ANALYSIS_ENABLED=true</code> in your .env file.
        </p>
      </div>
    );
  }
  if (data.error) return <ErrorBanner message={`AI Error: ${String(data.error)}`} />;

  const topVulns = (data.top_vulnerabilities as Array<Record<string, unknown>>) || [];
  const actions = (data.immediate_actions as string[]) || [];
  const recs = (data.recommendations as string[]) || [];

  const riskColor = (level: string) => {
    const l = level?.toLowerCase() || "";
    if (l === "critical") return "text-red-500";
    if (l === "high") return "text-orange-400";
    if (l === "medium") return "text-yellow-400";
    if (l === "low") return "text-blue-400";
    return "text-green-400";
  };

  return (
    <div className="space-y-4">
      <div className="bg-gradient-to-r from-cyan-500/10 to-purple-500/10 border border-cyan-500/20 rounded-xl p-4">
        <div className="flex items-center gap-2 mb-3">
          <Sparkles className="h-4 w-4 text-cyan-400" />
          <span className="text-xs text-slate-600">Model: {String(data.model_used || "Claude")}</span>
          {!!data.risk_level && (
            <Badge variant={SEVERITY_VARIANT[String(data.risk_level).toLowerCase()] ?? "secondary"} className="ml-auto">
              {String(data.risk_level)}
            </Badge>
          )}
        </div>
        <p className="text-sm text-slate-800 leading-relaxed">{String(data.executive_summary || "")}</p>
        {!!data.risk_justification && (
          <p className="text-xs text-slate-600 mt-2">{String(data.risk_justification)}</p>
        )}
      </div>

      {topVulns.length > 0 && (
        <Section title="Top Vulnerabilities">
          <div className="space-y-3">
            {topVulns.map((v, i) => (
              <div key={i} className="border border-[#e5e7eb] rounded-lg p-3 space-y-1 bg-[#f9f9ff]">
                <div className="flex items-center gap-2">
                  <Badge variant={v.priority === "immediate" ? "danger" : "warning"} className="text-[10px]">
                    {String(v.priority || "short-term")}
                  </Badge>
                  <p className="text-sm font-medium text-slate-800">{String(v.title)}</p>
                </div>
                <p className="text-xs text-slate-600"><span className="text-slate-500">Impact:</span> {String(v.business_impact ?? v.impact ?? "")}</p>
                <p className="text-xs text-slate-600"><span className="text-slate-500">Fix:</span> {String(v.remediation)}</p>
              </div>
            ))}
          </div>
        </Section>
      )}

      {actions.length > 0 && (
        <Section title="Immediate Actions">
          <ul className="space-y-1.5">
            {actions.map((a, i) => (
              <li key={i} className="flex items-start gap-2 text-xs text-slate-700">
                <span className="text-red-500 flex-shrink-0 mt-0.5">→</span>
                {a}
              </li>
            ))}
          </ul>
        </Section>
      )}

      {recs.length > 0 && (
        <Section title="Recommendations" defaultOpen={false}>
          <ul className="space-y-1.5">
            {recs.map((r, i) => (
              <li key={i} className="flex items-start gap-2 text-xs text-slate-700">
                <span className="text-blue-500 flex-shrink-0 mt-0.5">•</span>
                {r}
              </li>
            ))}
          </ul>
        </Section>
      )}

      {!!data.compliance_notes && (
        <Section title="Compliance Notes" defaultOpen={false}>
          <p className="text-xs text-slate-600">{String(data.compliance_notes)}</p>
        </Section>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

interface ScanResultsProps {
  scan: Scan;
}

export default function ScanResults({ scan }: ScanResultsProps) {
  const hasData = (key: string) =>
    scan[key as keyof Scan] !== null && scan[key as keyof Scan] !== undefined;

  const nucleiTotal = (scan.nuclei_data as Record<string, unknown> | null)?.total as number | undefined;
  const zapTotal    = (scan.zap_data   as Record<string, unknown> | null)?.total as number | undefined;
  const ffufTotal   = (scan.ffuf_data  as Record<string, unknown> | null)?.total as number | undefined;
  const sqliTotal   = (scan.sqlmap_data as Record<string, unknown> | null)?.total as number | undefined;
  const secretsTotal = (scan.gitleaks_data as Record<string, unknown> | null)?.total as number | undefined;
  const corrTotal   = ((scan.correlated_data as Record<string, unknown> | null)?.correlated_findings as unknown[] | undefined)?.length;
  const aiEnabled   = (scan.ai_analysis_data as Record<string, unknown> | null)?.enabled !== false;

  const tabs = [
    // Phase 5 — SOC Report
    { id: "ai",          label: "AI Report",    icon: Sparkles,      dataKey: "ai_analysis_data",  badge: null,         group: "P5" },
    // Phase 4 — Correlation
    { id: "correlation", label: "Correlation",  icon: Layers,        dataKey: "correlated_data",   badge: corrTotal,    group: "P4" },
    { id: "fp",          label: "FP Filter",    icon: Filter,        dataKey: "fp_reduction_data",  badge: null,        group: "P4" },
    // Phase 2 — Active Scan
    { id: "zap",         label: "OWASP ZAP",    icon: ShieldCheck,   dataKey: "zap_data",          badge: zapTotal,     group: "P2" },
    { id: "nuclei",      label: "Nuclei",       icon: Zap,           dataKey: "nuclei_data",       badge: nucleiTotal,  group: "P2" },
    // Phase 3 — Exploitation
    { id: "ffuf",        label: "FFUF",         icon: Search,        dataKey: "ffuf_data",         badge: ffufTotal,    group: "P3" },
    { id: "gitleaks",    label: "GitLeaks",     icon: Key,           dataKey: "gitleaks_data",     badge: secretsTotal, group: "P3" },
    { id: "sqlmap",      label: "SQLMap",       icon: Database,      dataKey: "sqlmap_data",       badge: sqliTotal,    group: "P3" },
    // Phase 1 — Recon
    { id: "nmap",        label: "Nmap",         icon: Terminal,      dataKey: "nmap_data",         badge: null,         group: "P1" },
    { id: "shodan",      label: "Shodan",       icon: Globe,         dataKey: "shodan_data",       badge: null,         group: "P1" },
    { id: "virustotal",  label: "VirusTotal",   icon: Shield,        dataKey: "virustotal_data",   badge: null,         group: "P1" },
    { id: "abuseipdb",   label: "AbuseIPDB",    icon: AlertTriangle, dataKey: "abuseipdb_data",    badge: null,         group: "P1" },
  ] as const;

  // Hide threat-intel tabs for internal/skipped targets or when no meaningful data returned
  const isTabUseful = (tab: (typeof tabs)[number]): boolean => {
    if (!hasData(tab.dataKey)) return false;
    const d = scan[tab.dataKey as keyof Scan] as Record<string, unknown> | null;
    if (!d) return false;
    // Explicitly skipped by backend (internal target)
    if (d.skipped === true) return false;
    switch (tab.id) {
      case "shodan": {
        const inet = (d.data as Record<string, unknown> | undefined)?.internetdb as Record<string, unknown> | undefined;
        return (
          ((inet?.ports as unknown[]) ?? []).length > 0 ||
          ((inet?.vulns as unknown[]) ?? []).length > 0 ||
          ((inet?.cpes  as unknown[]) ?? []).length > 0
        );
      }
      case "virustotal": {
        const vd = d.data as Record<string, unknown> | undefined;
        return Number(vd?.malicious ?? 0) > 0 || Number(vd?.suspicious ?? 0) > 0;
      }
      case "abuseipdb": {
        const ad = d.data as Record<string, unknown> | undefined;
        return Number(ad?.abuse_confidence_score ?? 0) > 0 || Number(ad?.total_reports ?? 0) > 0;
      }
      default:
        return true;
    }
  };

  const visibleTabs = tabs.filter(isTabUseful);

  const badgeColor = (id: string) => {
    if (id === "sqlmap" || id === "gitleaks") return "bg-red-500/20 text-red-400";
    if (id === "nuclei" || id === "zap")      return "bg-orange-500/20 text-orange-400";
    return "bg-cyan-500/20 text-cyan-400";
  };

  const defaultTab = visibleTabs.find((t) => hasData(t.dataKey))?.id ?? "nuclei";

  return (
    <div className="space-y-4">
      <DownloadBar scan={scan} />
      <PipelineOverview scan={scan} />

      <Tabs defaultValue={defaultTab} className="w-full">
        <TabsList className="bg-[#f5f7fa] border border-[#e5e7eb] h-auto p-1 gap-1 flex-wrap">
          {visibleTabs.map(({ id, label, icon: Icon, dataKey, badge }) => (
            <TabsTrigger
              key={id}
              value={id}
              className="data-[state=active]:bg-white data-[state=active]:text-slate-900 text-slate-600 gap-1.5 px-3 py-2"
            >
              <Icon className="h-3.5 w-3.5" />
              {label}
              {hasData(dataKey) && badge == null && (
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 ml-0.5" />
              )}
              {badge != null && badge > 0 && (
                <span className={`text-[10px] font-bold px-1.5 rounded-full ml-0.5 ${badgeColor(id)}`}>
                  {badge}
                </span>
              )}
            </TabsTrigger>
          ))}
        </TabsList>

        <div className="mt-4">
          <TabsContent value="ai">
            <AiAnalysisPanel data={scan.ai_analysis_data} />
          </TabsContent>
          <TabsContent value="correlation">
            <CorrelationPanel data={scan.correlated_data} />
          </TabsContent>
          <TabsContent value="nuclei">
            <NucleiPanel data={scan.nuclei_data} />
          </TabsContent>
          <TabsContent value="zap">
            <ZapPanel data={scan.zap_data} />
          </TabsContent>
          <TabsContent value="ffuf">
            <FfufPanel data={scan.ffuf_data} />
          </TabsContent>
          <TabsContent value="sqlmap">
            <SqlmapPanel data={scan.sqlmap_data} />
          </TabsContent>
          <TabsContent value="gitleaks">
            <GitleaksPanel data={scan.gitleaks_data} />
          </TabsContent>
          <TabsContent value="nmap">
            <NmapPanel data={scan.nmap_data} />
          </TabsContent>
          <TabsContent value="fp">
            <FpReductionPanel data={scan.fp_reduction_data} />
          </TabsContent>
          <TabsContent value="shodan">
            <ShodanPanel data={scan.shodan_data} />
          </TabsContent>
          <TabsContent value="virustotal">
            <VirusTotalPanel data={scan.virustotal_data} />
          </TabsContent>
          <TabsContent value="abuseipdb">
            <AbuseIPDBPanel data={scan.abuseipdb_data} />
          </TabsContent>
        </div>
      </Tabs>
    </div>
  );
}

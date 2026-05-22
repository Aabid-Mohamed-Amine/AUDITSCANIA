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
} from "lucide-react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Scan } from "@/lib/api";

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
    <div className="border border-slate-700 rounded-lg overflow-hidden">
      <button
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center justify-between px-4 py-3 bg-slate-800/60 hover:bg-slate-800 text-left transition-colors"
      >
        <span className="text-sm font-medium text-slate-200">{title}</span>
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
// Pipeline Overview — 3-phase summary banner
// ---------------------------------------------------------------------------

function PhaseStat({ label, value, color }: { label: string; value: string | number; color: string }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-xs text-slate-500">{label}</span>
      <span className={`text-xs font-semibold ${color}`}>{value}</span>
    </div>
  );
}

function PipelineOverview({ scan }: { scan: Scan }) {
  // Phase 1 — Threat Intelligence
  const abuseData = scan.abuseipdb_data as Record<string, unknown> | null;
  const abuseScore = (abuseData?.data as Record<string, unknown> | undefined)?.abuse_confidence_score as number | undefined;
  const abuseReports = (abuseData?.data as Record<string, unknown> | undefined)?.total_reports as number | undefined;

  const vtData = scan.virustotal_data as Record<string, unknown> | null;
  const vtMalicious =
    (vtData?.data as Record<string, unknown> | undefined)?.malicious as number | undefined ??
    Math.max(
      ((vtData?.data as Record<string, unknown> | undefined)?.domain as Record<string, unknown> | undefined)?.malicious as number ?? 0,
      ((vtData?.data as Record<string, unknown> | undefined)?.url as Record<string, unknown> | undefined)?.malicious as number ?? 0,
    );

  const shodanData = scan.shodan_data as Record<string, unknown> | null;
  const shodanPorts = (shodanData?.ports as number[] | undefined)?.length ?? 0;

  // Phase 2 — Network
  const nmapData = scan.nmap_data as Record<string, unknown> | null;
  const nmapHosts = ((nmapData?.data as Record<string, unknown> | undefined)?.hosts as Array<Record<string, unknown>>) ?? [];
  const allPorts = nmapHosts.flatMap((h) => (h.ports as Array<Record<string, unknown>>) ?? []);
  const openPorts = allPorts.filter((p) => p.state === "open");
  const RISKY = new Set([21, 22, 23, 25, 445, 1433, 3306, 3389, 5432, 6379, 27017]);
  const riskyPorts = openPorts.filter((p) => RISKY.has(Number(p.port)));

  // Phase 3 — Active Detection
  const nucleiData = scan.nuclei_data as Record<string, unknown> | null;
  const nucleiBySev = (nucleiData?.by_severity as Record<string, number>) ?? {};
  const nucleiTotal = Number(nucleiData?.total ?? 0);

  const zapData = scan.zap_data as Record<string, unknown> | null;
  const zapByRisk = (zapData?.by_risk as Record<string, number>) ?? {};
  const zapTotal = Number(zapData?.total ?? 0);

  const phase1HasData = !!(abuseData || vtData || shodanData);
  const phase2HasData = !!nmapData;
  const phase3HasData = !!(nucleiData || zapData);

  if (!phase1HasData && !phase2HasData && !phase3HasData) return null;

  const abuseColor =
    (abuseScore ?? 0) >= 75 ? "text-red-400" : (abuseScore ?? 0) >= 25 ? "text-yellow-400" : "text-green-400";

  return (
    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-6">
      {/* Phase 1 */}
      <div className="bg-slate-800/50 border border-cyan-500/20 rounded-xl p-4 space-y-2">
        <div className="flex items-center gap-2 mb-3">
          <div className="p-1.5 bg-cyan-500/10 rounded-lg">
            <Brain className="h-4 w-4 text-cyan-400" />
          </div>
          <div>
            <p className="text-xs font-semibold text-cyan-400">Threat Intelligence</p>
            <p className="text-[10px] text-slate-500">Shodan · VirusTotal · AbuseIPDB</p>
          </div>
        </div>
        {phase1HasData ? (
          <div className="space-y-1.5">
            {abuseScore !== undefined && (
              <PhaseStat label="Abuse confidence" value={`${abuseScore}%`} color={abuseColor} />
            )}
            {abuseReports !== undefined && (
              <PhaseStat label="Abuse reports" value={abuseReports} color={abuseReports > 0 ? "text-orange-400" : "text-slate-400"} />
            )}
            <PhaseStat
              label="VT malicious"
              value={vtMalicious ?? 0}
              color={(vtMalicious ?? 0) > 0 ? "text-red-400" : "text-green-400"}
            />
            {shodanPorts > 0 && (
              <PhaseStat label="Shodan ports" value={shodanPorts} color="text-slate-300" />
            )}
          </div>
        ) : (
          <p className="text-xs text-slate-600">Awaiting data…</p>
        )}
      </div>

      {/* Phase 2 */}
      <div className="bg-slate-800/50 border border-blue-500/20 rounded-xl p-4 space-y-2">
        <div className="flex items-center gap-2 mb-3">
          <div className="p-1.5 bg-blue-500/10 rounded-lg">
            <Network className="h-4 w-4 text-blue-400" />
          </div>
          <div>
            <p className="text-xs font-semibold text-blue-400">Network Scan</p>
            <p className="text-[10px] text-slate-500">Nmap active fingerprinting</p>
          </div>
        </div>
        {phase2HasData ? (
          <div className="space-y-1.5">
            <PhaseStat label="Open ports" value={openPorts.length} color="text-slate-300" />
            <PhaseStat
              label="Risky ports"
              value={riskyPorts.length}
              color={riskyPorts.length > 0 ? "text-orange-400" : "text-green-400"}
            />
            {openPorts.slice(0, 3).map((p) => (
              <div key={String(p.port)} className="flex items-center gap-1.5">
                <span className="font-mono text-[10px] text-cyan-400 bg-slate-900 px-1.5 py-0.5 rounded">
                  {String(p.port)}/{String(p.protocol)}
                </span>
                <span className="text-[10px] text-slate-500 truncate">{String(p.service || "")}</span>
              </div>
            ))}
            {openPorts.length > 3 && (
              <p className="text-[10px] text-slate-600">+{openPorts.length - 3} more</p>
            )}
          </div>
        ) : (
          <p className="text-xs text-slate-600">Awaiting data…</p>
        )}
      </div>

      {/* Phase 3 */}
      <div className="bg-slate-800/50 border border-orange-500/20 rounded-xl p-4 space-y-2">
        <div className="flex items-center gap-2 mb-3">
          <div className="p-1.5 bg-orange-500/10 rounded-lg">
            <Zap className="h-4 w-4 text-orange-400" />
          </div>
          <div>
            <p className="text-xs font-semibold text-orange-400">Active Detection</p>
            <p className="text-[10px] text-slate-500">Nuclei · OWASP ZAP</p>
          </div>
        </div>
        {phase3HasData ? (
          <div className="space-y-1.5">
            {nucleiData && (
              <>
                <PhaseStat
                  label="Nuclei findings"
                  value={nucleiTotal}
                  color={nucleiTotal > 0 ? "text-red-400" : "text-green-400"}
                />
                {(nucleiBySev.critical ?? 0) > 0 && (
                  <PhaseStat label="  Critical" value={nucleiBySev.critical} color="text-red-500" />
                )}
                {(nucleiBySev.high ?? 0) > 0 && (
                  <PhaseStat label="  High" value={nucleiBySev.high} color="text-orange-400" />
                )}
              </>
            )}
            {zapData && (
              <>
                <PhaseStat
                  label="ZAP alerts"
                  value={zapTotal}
                  color={zapTotal > 0 ? "text-orange-400" : "text-green-400"}
                />
                {(zapByRisk.High ?? 0) > 0 && (
                  <PhaseStat label="  High risk" value={zapByRisk.High} color="text-red-400" />
                )}
              </>
            )}
          </div>
        ) : (
          <p className="text-xs text-slate-600">Awaiting data…</p>
        )}
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
        <p className="text-sm text-slate-400">
          Resolved IP:{" "}
          <span className="font-mono text-slate-200">{String(data.resolved_ip)}</span>
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
            { key: "undetected", color: "text-slate-400",  bg: "bg-slate-700/50"  },
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
            <div className="bg-slate-800 rounded-lg p-4 text-center">
              <p className={`text-3xl font-bold ${scoreColor}`}>{score}%</p>
              <p className="text-xs text-slate-500 mt-1">Abuse Score</p>
            </div>
            <div className="bg-slate-800 rounded-lg p-4 text-center">
              <p className="text-3xl font-bold text-slate-200">{String(d.total_reports ?? 0)}</p>
              <p className="text-xs text-slate-500 mt-1">Total Reports</p>
            </div>
            <div className="bg-slate-800 rounded-lg p-4 text-center">
              <p className="text-3xl font-bold text-slate-200">{String(d.num_distinct_users ?? 0)}</p>
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
                  <span className="text-slate-300">{String(d[key])}</span>
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
          Scan method: <span className="text-slate-300">{String(data.scan_method)}</span>
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
                      <tr className="text-slate-500 border-b border-slate-700">
                        <th className="text-left pb-2 pr-4">Port</th>
                        <th className="text-left pb-2 pr-4">Protocol</th>
                        <th className="text-left pb-2 pr-4">Service</th>
                        <th className="text-left pb-2 pr-4">Product</th>
                        <th className="text-left pb-2">Version</th>
                      </tr>
                    </thead>
                    <tbody>
                      {openPorts.map((p, j) => (
                        <tr key={j} className="border-b border-slate-800 hover:bg-slate-800/50">
                          <td className="py-1.5 pr-4 font-mono text-cyan-400">{String(p.port)}</td>
                          <td className="py-1.5 pr-4 text-slate-400 uppercase text-[10px]">{String(p.protocol)}</td>
                          <td className="py-1.5 pr-4 text-slate-300">{String(p.service || "–")}</td>
                          <td className="py-1.5 pr-4 text-slate-400">{String(p.product || "–")}</td>
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
    <div className="border border-slate-700 rounded-lg overflow-hidden">
      <button
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-start gap-3 px-4 py-3 bg-slate-800/40 hover:bg-slate-800 text-left transition-colors"
      >
        <Badge variant={variant} className="mt-0.5 capitalize flex-shrink-0">
          {finding.severity}
        </Badge>
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium text-slate-200 truncate">{finding.name}</p>
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
        <div className="px-4 py-3 space-y-3 bg-slate-900/50 text-xs">
          {finding.description && (
            <p className="text-slate-300 leading-relaxed">{finding.description}</p>
          )}
          <div className="flex flex-wrap gap-2">
            {finding.tags.map((tag) => (
              <span
                key={tag}
                className="bg-slate-700 text-slate-300 px-2 py-0.5 rounded text-[10px]"
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
          { label: "Informational", key: "Informational", color: "text-slate-400",  bg: "bg-slate-700/50"  },
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
    <div className="border border-slate-700 rounded-lg overflow-hidden">
      <button
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-start gap-3 px-4 py-3 bg-slate-800/40 hover:bg-slate-800 text-left transition-colors"
      >
        <Badge variant={variant} className="mt-0.5 flex-shrink-0 capitalize">
          {alert.risk}
        </Badge>
        <div className="flex-1 min-w-0">
          <p className="text-sm font-medium text-slate-200 truncate">{alert.name}</p>
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
        <div className="px-4 py-3 space-y-3 bg-slate-900/50 text-xs">
          {alert.description && (
            <div>
              <p className="text-slate-500 font-semibold mb-1">Description</p>
              <p className="text-slate-300 leading-relaxed">
                {alert.description.replace(/<[^>]*>/g, "")}
              </p>
            </div>
          )}
          {alert.solution && (
            <div>
              <p className="text-slate-500 font-semibold mb-1">Solution</p>
              <p className="text-slate-300 leading-relaxed">
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
                  <div key={i} className="bg-slate-900 rounded p-2">
                    <div className="flex items-center gap-2">
                      <Badge variant="secondary" className="text-[9px] font-mono flex-shrink-0">
                        {inst.method}
                      </Badge>
                      <span className="text-cyan-400 font-mono truncate">{inst.uri}</span>
                    </div>
                    {inst.param && (
                      <p className="text-slate-500 mt-1">
                        Param: <span className="text-slate-300">{inst.param}</span>
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
// Main component
// ---------------------------------------------------------------------------

interface ScanResultsProps {
  scan: Scan;
}

export default function ScanResults({ scan }: ScanResultsProps) {
  const tabs = [
    { id: "nuclei",     label: "Nuclei",     icon: Zap,           dataKey: "nuclei_data"     },
    { id: "zap",        label: "OWASP ZAP",  icon: ShieldCheck,   dataKey: "zap_data"        },
    { id: "nmap",       label: "Nmap",        icon: Terminal,      dataKey: "nmap_data"       },
    { id: "shodan",     label: "Shodan",      icon: Globe,         dataKey: "shodan_data"     },
    { id: "virustotal", label: "VirusTotal",  icon: Shield,        dataKey: "virustotal_data" },
    { id: "abuseipdb",  label: "AbuseIPDB",   icon: AlertTriangle, dataKey: "abuseipdb_data"  },
  ] as const;

  const hasData = (key: string) =>
    scan[key as keyof Scan] !== null && scan[key as keyof Scan] !== undefined;

  const nucleiTotal = (scan.nuclei_data as Record<string, unknown> | null)
    ?.total as number | undefined;
  const zapTotal = (scan.zap_data as Record<string, unknown> | null)
    ?.total as number | undefined;

  // Pick the first tab that has data as the default
  const defaultTab =
    tabs.find((t) => hasData(t.dataKey))?.id ?? "nuclei";

  return (
    <div className="space-y-4">
      {/* Pipeline overview — always shown when any data exists */}
      <PipelineOverview scan={scan} />

      {/* Detailed results tabs */}
      <Tabs defaultValue={defaultTab} className="w-full">
        <TabsList className="bg-slate-800 border border-slate-700 h-auto p-1 gap-1 flex-wrap">
          {tabs.map(({ id, label, icon: Icon, dataKey }) => (
            <TabsTrigger
              key={id}
              value={id}
              className="data-[state=active]:bg-slate-700 data-[state=active]:text-slate-100 text-slate-400 gap-1.5 px-3 py-2"
            >
              <Icon className="h-3.5 w-3.5" />
              {label}
              {hasData(dataKey) && (
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 ml-0.5" />
              )}
              {id === "nuclei" && nucleiTotal != null && nucleiTotal > 0 && (
                <span className="bg-red-500/20 text-red-400 text-[10px] font-bold px-1.5 rounded-full ml-0.5">
                  {nucleiTotal}
                </span>
              )}
              {id === "zap" && zapTotal != null && zapTotal > 0 && (
                <span className="bg-orange-500/20 text-orange-400 text-[10px] font-bold px-1.5 rounded-full ml-0.5">
                  {zapTotal}
                </span>
              )}
            </TabsTrigger>
          ))}
        </TabsList>

        <div className="mt-4">
          <TabsContent value="nuclei">
            <NucleiPanel data={scan.nuclei_data} />
          </TabsContent>
          <TabsContent value="zap">
            <ZapPanel data={scan.zap_data} />
          </TabsContent>
          <TabsContent value="nmap">
            <NmapPanel data={scan.nmap_data} />
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

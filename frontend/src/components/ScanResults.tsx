"use client";

import React from "react";
import {
  Globe,
  Shield,
  AlertTriangle,
  Terminal,
  ChevronDown,
  ChevronUp,
  Server,
} from "lucide-react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Scan } from "@/lib/api";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function JsonBlock({ data }: { data: unknown }) {
  return (
    <pre className="text-xs text-slate-300 bg-slate-900 rounded-md p-4 overflow-auto max-h-96 font-mono leading-relaxed">
      {JSON.stringify(data, null, 2)}
    </pre>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  const [open, setOpen] = React.useState(true);
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

// ---------------------------------------------------------------------------
// Per-source panels
// ---------------------------------------------------------------------------

function ShodanPanel({ data }: { data: Record<string, unknown> | null }) {
  if (!data) return <p className="text-slate-500 text-sm">No Shodan data available.</p>;

  const internetdb = (data.data as Record<string, unknown> | undefined)?.internetdb as Record<string, unknown> | undefined;
  const full = (data.data as Record<string, unknown> | undefined)?.full as Record<string, unknown> | undefined;

  return (
    <div className="space-y-4">
      {!!data.error && (
        <div className="text-red-400 text-sm bg-red-400/10 border border-red-400/20 rounded p-3">
          Error: {String(data.error)}
        </div>
      )}
      {!!data.resolved_ip && (
        <p className="text-sm text-slate-400">
          Resolved IP: <span className="font-mono text-slate-200">{String(data.resolved_ip)}</span>
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
                    <Badge key={p} variant="info" className="font-mono text-xs">
                      {p}
                    </Badge>
                  ))}
                </div>
              </div>
            ) : null}
            {(internetdb.vulns as string[] | undefined)?.length ? (
              <div>
                <p className="text-xs text-slate-500 mb-1">CVEs</p>
                <div className="flex flex-wrap gap-1">
                  {(internetdb.vulns as string[]).map((v) => (
                    <Badge key={v} variant="danger" className="font-mono text-xs">
                      {v}
                    </Badge>
                  ))}
                </div>
              </div>
            ) : null}
          </div>
          <JsonBlock data={internetdb} />
        </Section>
      )}
      {full && (
        <Section title="Full Shodan Report">
          <JsonBlock data={full} />
        </Section>
      )}
    </div>
  );
}

function VirusTotalPanel({ data }: { data: Record<string, unknown> | null }) {
  if (!data) return <p className="text-slate-500 text-sm">No VirusTotal data available.</p>;

  const vdata = data.data as Record<string, unknown> | undefined;

  const renderStats = (stats: Record<string, unknown> | undefined, label: string) => {
    if (!stats) return null;
    const malicious = Number(stats.malicious || 0);
    const suspicious = Number(stats.suspicious || 0);
    return (
      <Section title={label}>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
          {[
            { key: "malicious", color: "text-red-400", bg: "bg-red-400/10" },
            { key: "suspicious", color: "text-yellow-400", bg: "bg-yellow-400/10" },
            { key: "harmless", color: "text-green-400", bg: "bg-green-400/10" },
            { key: "undetected", color: "text-slate-400", bg: "bg-slate-700/50" },
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
      {!!data.error && (
        <div className="text-red-400 text-sm bg-red-400/10 border border-red-400/20 rounded p-3">
          Error: {String(data.error)}
        </div>
      )}
      {vdata?.malicious !== undefined
        ? renderStats(vdata, "IP Analysis")
        : null}
      {vdata?.domain ? renderStats(vdata.domain as Record<string, unknown>, "Domain Analysis") : null}
      {vdata?.url ? renderStats(vdata.url as Record<string, unknown>, "URL Analysis") : null}
    </div>
  );
}

function AbuseIPDBPanel({ data }: { data: Record<string, unknown> | null }) {
  if (!data) return <p className="text-slate-500 text-sm">No AbuseIPDB data available.</p>;

  const d = data.data as Record<string, unknown> | undefined;
  const score = d ? Number(d.abuse_confidence_score ?? 0) : 0;
  const scoreColor =
    score >= 75 ? "text-red-400" : score >= 25 ? "text-yellow-400" : "text-green-400";

  return (
    <div className="space-y-4">
      {!!data.error && (
        <div className="text-red-400 text-sm bg-red-400/10 border border-red-400/20 rounded p-3">
          Error: {String(data.error)}
        </div>
      )}
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
            {([
              ["ISP", d.isp],
              ["Country", d.country_code],
              ["Usage Type", d.usage_type],
              ["Domain", d.domain],
            ] as [string, unknown][]).map(([label, val]) =>
              val ? (
                <div key={label} className="flex gap-2">
                  <span className="text-slate-500">{label}:</span>
                  <span className="text-slate-300">{String(val)}</span>
                </div>
              ) : null
            )}
          </div>

          <Section title="Raw Data">
            <JsonBlock data={d} />
          </Section>
        </>
      )}
    </div>
  );
}

function NmapPanel({ data }: { data: Record<string, unknown> | null }) {
  if (!data) return <p className="text-slate-500 text-sm">No Nmap data available.</p>;

  const ndata = data.data as Record<string, unknown> | undefined;
  const hosts = (ndata?.hosts as Array<Record<string, unknown>>) || [];

  return (
    <div className="space-y-4">
      {!!data.error && (
        <div className="text-red-400 text-sm bg-red-400/10 border border-red-400/20 rounded p-3">
          Error: {String(data.error)}
        </div>
      )}
      {!!data.scan_method && (
        <p className="text-xs text-slate-500">
          Scan method: <span className="text-slate-300">{String(data.scan_method)}</span>
        </p>
      )}
      {hosts.map((host, i) => {
        const ports = (host.ports as Array<Record<string, unknown>>) || [];
        const openPorts = ports.filter((p) => p.state === "open");
        const osInfo = (host.os as Array<Record<string, unknown>>) || [];

        return (
          <div key={i} className="space-y-3">
            <Section title={`Host ${i + 1}: ${(host.addresses as Array<{addr: string}>)?.[0]?.addr || "unknown"}`}>
              {/* OS */}
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

              {/* Ports table */}
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
                          <td className="py-1.5 pr-4 font-mono text-cyan-400">
                            {String(p.port)}
                          </td>
                          <td className="py-1.5 pr-4 text-slate-400 uppercase text-[10px]">
                            {String(p.protocol)}
                          </td>
                          <td className="py-1.5 pr-4 text-slate-300">{String(p.service || "–")}</td>
                          <td className="py-1.5 pr-4 text-slate-400">{String(p.product || "–")}</td>
                          <td className="py-1.5 text-slate-500">{String(p.version || "–")}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="text-slate-500 text-sm">No open ports found.</p>
              )}
            </Section>
          </div>
        );
      })}

      {hosts.length === 0 && !data.error && (
        <p className="text-slate-500 text-sm">No host data in nmap results.</p>
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
    { id: "shodan", label: "Shodan", icon: Globe },
    { id: "virustotal", label: "VirusTotal", icon: Shield },
    { id: "abuseipdb", label: "AbuseIPDB", icon: AlertTriangle },
    { id: "nmap", label: "Nmap", icon: Terminal },
  ];

  const hasData = (key: keyof Scan) => scan[key] !== null && scan[key] !== undefined;

  return (
    <Tabs defaultValue="shodan" className="w-full">
      <TabsList className="bg-slate-800 border border-slate-700 h-auto p-1 gap-1 flex-wrap">
        {tabs.map(({ id, label, icon: Icon }) => (
          <TabsTrigger
            key={id}
            value={id}
            className="data-[state=active]:bg-slate-700 data-[state=active]:text-slate-100 text-slate-400 gap-1.5 px-4 py-2"
          >
            <Icon className="h-3.5 w-3.5" />
            {label}
            {hasData(`${id}_data` as keyof Scan) && (
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 ml-1" />
            )}
          </TabsTrigger>
        ))}
      </TabsList>

      <div className="mt-4">
        <TabsContent value="shodan">
          <ShodanPanel data={scan.shodan_data} />
        </TabsContent>
        <TabsContent value="virustotal">
          <VirusTotalPanel data={scan.virustotal_data} />
        </TabsContent>
        <TabsContent value="abuseipdb">
          <AbuseIPDBPanel data={scan.abuseipdb_data} />
        </TabsContent>
        <TabsContent value="nmap">
          <NmapPanel data={scan.nmap_data} />
        </TabsContent>
      </div>
    </Tabs>
  );
}

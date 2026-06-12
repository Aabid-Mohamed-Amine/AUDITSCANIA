"use client";

import React from "react";
import ScanForm from "@/components/ScanForm";
import { Shield, ArrowLeft, Eye, Radar, Cpu, GitBranch, Bug, BarChart2, FileText } from "lucide-react";
import Link from "next/link";

const PHASES = [
  { n: "01", label: "Asset Discovery",    desc: "Shodan · VirusTotal · AbuseIPDB" },
  { n: "02", label: "Active Recon",       desc: "ZAP Spider · FFUF directory brute" },
  { n: "03", label: "Fingerprinting",     desc: "Nmap port/service/OS scan" },
  { n: "04", label: "Vuln Scanning",      desc: "Nuclei templates · SQLMap · Dalfox" },
  { n: "05", label: "Threat Intelligence",desc: "GitLeaks · Wapiti · Nikto" },
  { n: "06", label: "Correlation Engine", desc: "Dedup · CVE mapping · confidence" },
  { n: "07", label: "Risk Scoring",       desc: "CVSS-based composite score" },
  { n: "08", label: "SOC Report",         desc: "Executive summary + recommendations" },
];

const INFO = [
  { icon: Eye,      title: "Passive OSINT",    desc: "Shodan, VirusTotal, AbuseIPDB — zero target interaction. Reputation, blacklists, and CVE records." },
  { icon: Radar,    title: "Active Recon",      desc: "ZAP web spider + Nmap — lightweight fingerprinting of open attack surface without exploitation." },
  { icon: GitBranch,title: "Secret Detection",  desc: "GitLeaks + Katana crawl exposed credentials, API keys, and sensitive file patterns." },
  { icon: Bug,      title: "Vuln Assessment",   desc: "Nuclei, SQLMap, Dalfox — targeted vulnerability checks based on fingerprinted stack." },
  { icon: BarChart2,title: "Correlation",       desc: "Finds overlapping findings, eliminates duplicates, maps CVEs to confirmed services." },
  { icon: FileText, title: "SOC-Ready Output",  desc: "Risk score + executive summary + ranked remediation list, ready for report delivery." },
];

export default function NewScanPage() {
  return (
    <div className="flex flex-col h-full overflow-auto bg-zinc-950">

      <div className="flex items-center gap-3 px-6 py-3.5 border-b border-zinc-800/60 bg-zinc-950 shrink-0 fade-in-down">
        <Link
          href="/dashboard"
          className="flex items-center gap-1.5 text-[11px] text-zinc-600 hover:text-indigo-400 transition-colors"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          Dashboard
        </Link>
        <span className="text-zinc-800">/</span>
        <span className="text-[11px] text-zinc-600">New Scan</span>
      </div>

      <div className="flex-1 p-5 max-w-3xl mx-auto w-full space-y-5">

        <div className="flex items-center gap-3 fade-in-up">
          <div className="w-10 h-10 bg-indigo-600 rounded-xl flex items-center justify-center">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-[16px] font-semibold text-zinc-100">New Security Scan</h1>
            <p className="text-[11px] text-zinc-600 mt-0.5">
              8-phase pipeline — Asset Discovery through SOC-ready report
            </p>
          </div>
        </div>

        <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6 space-y-5 card-hover fade-in-up" style={{ animationDelay: "45ms" }}>
          <div>
            <h2 className="text-[11px] font-semibold text-zinc-600 uppercase tracking-widest">
              Reconnaissance Target
            </h2>
            <p className="text-[11px] text-zinc-700 mt-1">
              IPv4 · domain · full URL · Docker service hostname (juiceshop, dvwa, localhost:3000).
              http:// is added automatically if omitted.
            </p>
          </div>
          <ScanForm />
        </div>

        {/* 8-phase strip */}
        <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-4 fade-in-up" style={{ animationDelay: "90ms" }}>
          <p className="text-[10px] font-semibold text-zinc-600 uppercase tracking-widest mb-3">Pipeline</p>
          <div className="flex gap-1 flex-wrap">
            {PHASES.map(({ n, label, desc }) => (
              <div key={n} className="group relative flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-zinc-800/60 border border-zinc-800 hover:border-indigo-900/50 hover:bg-indigo-950/20 transition-all cursor-default">
                <span className="text-[9px] font-mono font-bold text-indigo-600">{n}</span>
                <span className="text-[10px] text-zinc-500 font-medium group-hover:text-zinc-300 transition-colors">{label}</span>
                {/* tooltip */}
                <div className="absolute bottom-full left-0 mb-1 px-2 py-1 bg-zinc-800 border border-zinc-700 rounded-md text-[9px] text-zinc-400 whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none z-10">
                  {desc}
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="grid sm:grid-cols-2 md:grid-cols-3 gap-3 stagger fade-in-up" style={{ animationDelay: "135ms" }}>
          {INFO.map(({ icon: Icon, title, desc }) => (
            <div
              key={title}
              className="bg-zinc-900 border border-zinc-800 rounded-xl p-4 card-hover"
            >
              <div className="flex items-center gap-2 mb-2">
                <Icon className="w-3.5 h-3.5 text-indigo-400 shrink-0" />
                <h3 className="text-[11px] font-semibold text-indigo-400 uppercase tracking-wide">{title}</h3>
              </div>
              <p className="text-[11px] text-zinc-600 leading-relaxed">{desc}</p>
            </div>
          ))}
        </div>

        <p className="text-[10px] text-zinc-700 text-center pb-4">
          By scanning a target you confirm you have explicit written authorization. Unauthorized scanning is illegal.
        </p>
      </div>
    </div>
  );
}

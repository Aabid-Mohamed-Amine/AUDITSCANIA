"use client";

import React from "react";
import ScanForm from "@/components/ScanForm";
import { Shield, ArrowLeft, Eye, Radar, Cpu } from "lucide-react";
import Link from "next/link";

const INFO = [
  {
    icon: Eye,
    title: "Passive Analysis",
    desc: "Shodan, VirusTotal, AbuseIPDB — no direct target interaction. Checks blacklists, reputation databases and public vulnerability records.",
  },
  {
    icon: Radar,
    title: "Active Recon",
    desc: "Nmap port mapping + OWASP ZAP web spider — lightweight fingerprinting of open attack surface.",
  },
  {
    icon: Cpu,
    title: "Correlation Engine",
    desc: "Fuses all findings, eliminates duplicates, maps CVEs to services, generates exploitability and confidence scores.",
  },
];

export default function NewScanPage() {
  return (
    <div className="flex flex-col h-full overflow-auto">

      {/* ── Top bar ── */}
      <div className="flex items-center gap-3 px-6 py-4 border-b border-[#0f1e30] bg-[#060d1a] shrink-0">
        <Link
          href="/dashboard"
          className="flex items-center gap-1.5 text-[11px] text-[#2a5070] hover:text-blue-400 transition-colors"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          Dashboard
        </Link>
        <span className="text-[#0f1e30]">/</span>
        <span className="text-[11px] text-[#3d6080]">New Scan</span>
      </div>

      <div className="flex-1 p-6 max-w-3xl mx-auto w-full space-y-6">

        {/* ── Header ── */}
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-blue-600 rounded-[7px] flex items-center justify-center shadow-lg shadow-blue-900/40">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-[16px] font-semibold text-[#c0d8f0]">New Security Scan</h1>
            <p className="text-[11px] text-[#2a5070] mt-0.5">
              8-phase pipeline: Asset Discovery → Vulnerability Scanning → Correlation → SOC Report
            </p>
          </div>
        </div>

        {/* ── Form card ── */}
        <div className="bg-[#080f1e] border border-[#0f1e30] rounded-[8px] p-6 space-y-5">
          <div>
            <h2 className="text-[13px] font-semibold text-[#8ab8d8] uppercase tracking-wide">
              Reconnaissance Target
            </h2>
            <p className="text-[11px] text-[#2a5070] mt-1">
              IPv4, domain, full URL, ou nom de service Docker (ex : juiceshop, dvwa, localhost:3000).
              http:// sera ajouté automatiquement si absent.
            </p>
          </div>
          <ScanForm />
        </div>

        {/* ── Phase info ── */}
        <div className="grid md:grid-cols-3 gap-3">
          {INFO.map(({ icon: Icon, title, desc }) => (
            <div
              key={title}
              className="bg-[#080f1e] border border-[#0f1e30] rounded-[7px] p-4 hover:border-blue-900/60 transition-colors"
            >
              <div className="flex items-center gap-2 mb-2">
                <Icon className="w-3.5 h-3.5 text-blue-400 shrink-0" />
                <h3 className="text-[11px] font-semibold text-[#4a8ab5] uppercase tracking-wide">{title}</h3>
              </div>
              <p className="text-[11px] text-[#1e3a55] leading-relaxed">{desc}</p>
            </div>
          ))}
        </div>

        {/* ── Legal note ── */}
        <p className="text-[10px] text-[#1a3550] text-center">
          By scanning a target you confirm you have explicit authorization. Unauthorized scanning is illegal.
        </p>
      </div>
    </div>
  );
}

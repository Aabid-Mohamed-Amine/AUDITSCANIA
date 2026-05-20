"use client";

import React from "react";
import ScanForm from "@/components/ScanForm";
import { Shield, ArrowLeft } from "lucide-react";
import Link from "next/link";

export default function NewScanPage() {
  return (
    <div className="p-6 space-y-8 max-w-4xl mx-auto">
      {/* Navigation & Header */}
      <div className="space-y-4">
        <Link
          href="/dashboard"
          className="inline-flex items-center gap-2 text-sm text-slate-400 hover:text-cyan-400 transition-colors"
        >
          <ArrowLeft size={16} />
          Back to Dashboard
        </Link>
        
        <div className="flex items-center gap-3">
          <div className="p-3 bg-cyan-500/10 border border-cyan-500/20 rounded-xl">
            <Shield className="h-8 w-8 text-cyan-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-slate-100">Start New Security Scan</h1>
            <p className="text-sm text-slate-400 mt-1">
              Launch passive and active reconnaissance against a target IP address, domain, or URL.
            </p>
          </div>
        </div>
      </div>

      {/* Main Form Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 shadow-xl space-y-6">
        <div>
          <h2 className="text-lg font-semibold text-slate-200">Reconnaissance Target</h2>
          <p className="text-xs text-slate-500 mt-1">
            Specify the IP address or host domain you want to audit. We will perform passive scans using Shodan, VirusTotal, AbuseIPDB, and active port scanning via Nmap.
          </p>
        </div>
        
        <ScanForm />
      </div>
      
      {/* Help / Guidance Grid */}
      <div className="grid md:grid-cols-3 gap-4 text-slate-400">
        <div className="p-4 bg-slate-900/40 border border-slate-800/60 rounded-xl">
          <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">Passive Analysis</h3>
          <p className="text-xs text-slate-500 leading-relaxed">
            Checks target against blacklists, security feeds, reputation databases, and public vulnerability records without direct interaction.
          </p>
        </div>
        <div className="p-4 bg-slate-900/40 border border-slate-800/60 rounded-xl">
          <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">Active Recon</h3>
          <p className="text-xs text-slate-500 leading-relaxed">
            Performs TCP/UDP port mapping and service fingerprinting using lightweight Nmap scans to detect open attack vectors.
          </p>
        </div>
        <div className="p-4 bg-slate-900/40 border border-slate-800/60 rounded-xl">
          <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">AI-Assisted Insights</h3>
          <p className="text-xs text-slate-500 leading-relaxed">
            Runs deep log and scan analysis using advanced LLMs to identify hidden threats and generate actionable mitigation reports.
          </p>
        </div>
      </div>
    </div>
  );
}

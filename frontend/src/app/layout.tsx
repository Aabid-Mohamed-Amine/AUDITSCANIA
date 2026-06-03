import type { Metadata } from "next";
import "./globals.css";
import Providers from "./providers";

export const metadata: Metadata = {
  title: "AuditScan IA – Security Audit Platform",
  description:
    "Perform passive and active reconnaissance on IPs and URLs using Shodan, VirusTotal, AbuseIPDB, and Nmap.",
  keywords: ["security", "audit", "nmap", "shodan", "virustotal", "recon"],
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}

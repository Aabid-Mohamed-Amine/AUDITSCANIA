import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import Providers from "./providers";

const inter = Inter({ subsets: ["latin"] });

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
      <body className={inter.className}>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}

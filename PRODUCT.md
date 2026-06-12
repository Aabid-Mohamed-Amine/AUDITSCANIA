# Product

## Register

product

## Users

Security professionals, developers, and IT teams running active/passive reconnaissance against IP addresses and URLs. They operate in focused, task-driven contexts — often in dim environments or across multiple screens. They understand technical output: ports, CVEs, risk scores, HTTP status codes. They do not need hand-holding; they need fast, dense, legible data.

## Product Purpose

AuditScan IA orchestrates a multi-tool security pipeline (Shodan, VirusTotal, AbuseIPDB, Nmap, Nuclei, ZAP, FFUF, SQLMap, Nikto, Wapiti, DalFox) against a target and surfaces a unified risk picture. Success looks like: a security professional launches a scan, watches it progress in real time, and receives a clear, actionable report with risk score, correlated findings, and severity-ranked vulnerabilities — all without leaving the browser.

## Brand Personality

Precise, Clinical, Expert. The product talks to people who know what a CVSS score means. It earns trust through density and accuracy, not through decoration. It should feel like a professional instrument: Shodan meets Datadog, not a startup SaaS tool.

## Anti-references

- **Generic SaaS dashboards**: Stripe, Vercel, or Linear-cream white-card grids with gradient buttons. Too soft, too marketingy for a tool security professionals will use under pressure.
- **Hacker aesthetic**: Matrix green-on-black, neon glow overload, cyberpunk visual language. Unprofessional and distracting.
- **Legacy enterprise gray**: JIRA-style flat gray corporate dashboards. Depressing, not authoritative.

## Design Principles

1. **Data is the interface.** Scan results, risk scores, and vulnerability findings are the product. Chrome exists only to organize data — never to decorate it.
2. **Expert density.** Don't over-explain or over-space. Trust the user to read a table row. Prioritize information per pixel over breathing room.
3. **Semantic color, not decorative color.** Every color in the UI carries meaning: red means critical, amber means high, green means clean. Using those colors for anything else creates confusion in a tool where color encodes urgency.
4. **Monospace as identity.** IP addresses, CVEs, ports, hashes, and technical strings render in monospace. It's not a style choice — it signals precision and distinguishes data from labels.
5. **State is never ambiguous.** Scan status, error conditions, empty states, and loading states are explicit and informative. A user should always know what the system is doing and why.

## Accessibility & Inclusion

WCAG AA as the floor. Security tools are used in varied lighting (dark offices, terminal rooms, field environments). Both light and dark contexts must be legible. Color alone must never be the only carrier of severity meaning — pair color with icons or labels. Monospace text at small sizes must remain readable; minimum 12px for data rows.

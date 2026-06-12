# AuditScan IA

A full-stack cybersecurity audit platform. Runs a multi-phase pipeline across 14 Docker microservices — from passive recon to active exploitation and AI-generated SOC reports.

## Stack

- **Frontend**: Next.js 14, Tailwind CSS, React Query
- **Backend**: FastAPI, Celery, PostgreSQL, Redis
- **Scanners**: Nmap, Nuclei, ZAP, FFUF, SQLMap, Dalfox, Katana, Subfinder, Gitleaks, Nikto, Wapiti, Trivy
- **AI**: Gemini / Anthropic for SOC report generation

## Prerequisites

- Docker
- Docker Compose

## Installation

```bash
git clone https://github.com/DEVLOPPER17/AUDITSCANIA.git
cd AUDITSCANIA
cp .env.example .env
docker compose up --build
```

Open [http://localhost:3001](http://localhost:3001)

## Usage

**Lab Mode** (default) — calls the target's challenge API to enrich findings (Juice Shop, DVWA…)

**Active Mode** — pure active detection, no hint API, full scanner coverage

Toggle the mode from the scan form before launching a scan.

## Project Structure

```
AUDITSCANIA/
├── backend/          # FastAPI + Celery workers
├── frontend/         # Next.js UI
├── nmap/             # Port scanner microservice
├── nuclei/           # Template-based scanner
├── zap/              # OWASP ZAP (Ajax Spider + Active Scan)
├── ffuf/             # Directory/endpoint fuzzer
├── sqlmap/           # SQL injection scanner
├── dalfox/           # XSS scanner
├── katana/           # Web crawler
├── subfinder/        # Subdomain discovery
├── gitleaks/         # Secret detection
├── nikto/            # Web server scanner
├── wapiti/           # Web vulnerability scanner
├── trivy/            # Container/filesystem scanner
├── docker-compose.yml
└── .env.example
```

## License

MIT

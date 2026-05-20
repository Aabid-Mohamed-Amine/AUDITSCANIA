# AuditScan IA

A full-stack SaaS security audit platform that performs passive and active reconnaissance on IP addresses and URLs.

## Features

- **Passive Recon**: Shodan, VirusTotal, AbuseIPDB
- **Active Scan**: Nmap port/service discovery via Docker
- **Real-time Progress**: WebSocket-powered live updates
- **Modern UI**: Next.js 14, Tailwind CSS, shadcn/ui
- **Scalable Backend**: FastAPI + Celery workers + PostgreSQL + Redis

## Quick Start

```bash
# 1. Clone and enter the project
cd AUDITSCAN

# 2. Create environment file
cp .env.example .env
# Edit .env with your API keys

# 3. Build and start all services
docker compose up --build

# 4. Open the app
open http://localhost:3000
```

## Required API Keys

| Service | Get Key At |
|---------|-----------|
| Shodan | https://account.shodan.io |
| VirusTotal | https://www.virustotal.com/gui/join-us |
| AbuseIPDB | https://www.abuseipdb.com/register |

## Architecture

```
Browser ──WebSocket──┐
   │                 │
   │ HTTP            │
   ▼                 ▼
Next.js 14      FastAPI (port 8000)
                    │
              ┌─────┴─────┐
              │           │
           Celery       PostgreSQL
           Worker          │
              │         (scan data)
         ┌────┼────┐
         │    │    │
      Shodan  VT  Nmap
      API    API  (Docker)
```

## Services

| Service | Port | Description |
|---------|------|-------------|
| Frontend | 3000 | Next.js UI |
| Backend | 8000 | FastAPI REST + WebSocket |
| PostgreSQL | 5432 | Database |
| Redis | 6379 | Cache + Celery broker |

## Development

```bash
# Backend only
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload

# Frontend only
cd frontend
npm install
npm run dev

# Worker only
cd backend
celery -A app.workers.celery_app worker --loglevel=info
```

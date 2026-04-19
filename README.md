<div align="center">

# 🛡️ ShadowTrace

### Automated Attack Surface Mapper & Breach Impact Simulator

[![CI](https://github.com/AtharvaPatil466/TEAM-DOPICODE---PS3/actions/workflows/ci.yml/badge.svg)](https://github.com/AtharvaPatil466/TEAM-DOPICODE---PS3/actions)
![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![React 19](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=black)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white)
![Llama 3.2](https://img.shields.io/badge/Llama_3.2-Ollama-FF6F00?logo=meta&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

**ShadowTrace** discovers your external and internal attack surface, builds a graph of exploitable relationships, ranks multi-hop attack paths by persona-specific time-to-breach estimates, and simulates the financial impact of a breach — all in real time.

[Features](#-features) · [Architecture](#-architecture) · [Quick Start](#-quick-start) · [API](#-api-endpoints) · [Lab Environment](#-lab-environment) · [Team](#-team)

</div>

---

## 🎯 Problem Statement

Organizations lack visibility into how their exposed assets, misconfigurations, and vulnerabilities chain together into real attack paths. Traditional vulnerability scanners produce flat lists of CVEs without answering the critical question: **"If an attacker gets in, what's the path to our crown jewels, and what does it cost us?"**

ShadowTrace answers that question.

---

## ✨ Features

### 🔍 Discovery Engine
- **Subdomain Enumeration** — DNS brute-force + Certificate Transparency log mining
- **Live Host Probing** — HTTP/HTTPS connectivity verification with response fingerprinting
- **Port Scanning** — Nmap-powered service detection and version identification
- **Tech Fingerprinting** — Server headers, powered-by tags, and CMS detection
- **Cloud Bucket Hunting** — S3/GCS/Azure misconfigured storage discovery
- **SSL/TLS Analysis** — Certificate expiry, self-signed detection, hostname mismatch
- **Admin Panel Detection** — Automated discovery of exposed login/admin surfaces
- **Shadow Device Classification** — ML-based anomaly detection flags unmanaged assets

### 🕸️ Intelligence Layer
- **Attack Graph Construction** — NetworkX-powered directed graph with weighted edges
- **Named Rulebook** — 11 rules (NET, EXP, CRED, CONF, CLOUD, SHADOW, DATA, SUPPLY, MISC), each producing edges with:
  - MITRE ATT&CK technique mappings (T1190, T1078, T1530, etc.)
  - Structured evidence dictionaries
  - Compliance control tags (NIST, PCI-DSS, SOC2, CIS)
  - Detection probability scores
- **Attack Path Ranking** — Top-K paths via `shortest_simple_paths` with category deduplication
- **Persona-Based Time-to-Breach** — Script Kiddie / Criminal / APT profiles with per-hop timing from a CVSS × Attack Vector × Complexity matrix
- **Remediation Candidates** — Fixes ranked by how many modeled paths they break
- **CISA KEV Integration** — Known Exploited Vulnerabilities flagged with ransomware campaign data

### 💰 Breach Impact Simulator
- **Asset Classification** — Automatic tiering (Crown Jewel → Customer Data Store → Business Logic → Generic)
- **Regulatory Exposure** — India DPDP Act 2023 penalty calculations (₹5 Cr – ₹250 Cr range)
- **Operational Loss Modeling** — Downtime (MTTR-scaled), incident response costs, customer churn
- **Attack Scenario Matrix** — 8 scenario categories with per-scenario financial exposure and prevention ROI

### 🤖 AI-Enhanced Analysis
- **Local LLM via Ollama + Llama 3.2** — Fully offline, no API keys required
- **Per-Hop Rationale** — "Why this hop?" generates contextual attack explanations
- **Executive Summaries** — CISO-level board briefings generated from scan data
- **Rule Explanations** — Plain-English MITRE ATT&CK technique breakdowns

### 📊 Frontend Dashboard
- **Real-Time Scan Feed** — WebSocket-powered live progress during scans
- **Executive CTO View** — Plain-English summaries and priority actions devoid of security jargon
- **Interactive Attack Surface Graph** — D3.js visualization with risk-colored nodes
- **Kill Chain Timeline** — Step-by-step attack narrative with AI-enhanced executive rationale
- **Impact Dashboard** — Financial exposure ranges with scenario breakdowns
- **Executive PDF Report** — Professional business-focused threat letter and analyst appendices
- **"What If" Simulation** — Patch assets/CVEs and watch attack paths break in real time

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Frontend (React 19 + Vite)           │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────────┐  │
│  │ CTO View  │ │ Landing  │ │Kill Chain│ │    Impact     │  │
│  │   Page    │ │ & Scan   │ │   Page   │ │   Dashboard   │  │
│  └──────────┘ └──────────┘ └──────────┘ └───────────────┘  │
│         ↕ REST + WebSocket          ↕ Ollama (localhost)    │
├─────────────────────────────────────────────────────────────┤
│                    Nginx Reverse Proxy                      │
│              /api/* → backend    /ws → WebSocket            │
├─────────────────────────────────────────────────────────────┤
│                   Backend (FastAPI + Python 3.12)           │
│  ┌─────────────────────┐  ┌──────────────────────────────┐ │
│  │   Scanner Engine     │  │     Intelligence Layer       │ │
│  │  ├ subdomain.py      │  │  ├ graph_builder.py          │ │
│  │  ├ nmap_scanner.py   │  │  ├ edge_rules.py (11 rules)  │ │
│  │  ├ tech_fingerprint  │  │  ├ attack_path.py            │ │
│  │  ├ cloud_buckets.py  │  │  ├ impact_simulator.py       │ │
│  │  ├ ssl_analyzer.py   │  │  ├ cve_fetcher.py + kev.py   │ │
│  │  ├ admin_panel.py    │  │  ├ risk_scorer.py            │ │
│  │  └ arp_scanner.py    │  │  ├ report.py (PDF gen)       │ │
│  └─────────────────────┘  │  └ simulate.py + diff.py      │ │
│                            └──────────────────────────────┘ │
│                         SQLite (aiosqlite)                   │
├─────────────────────────────────────────────────────────────┤
│                   Docker Lab (6 containers)                  │
│  Apache 2.4.49  MySQL 5.7   IoT busybox   Rogue SSH          │
│  .10 (gateway)  .20 👑      .30           .40                │
│  Redis 5.0.5    Flask API                                    │
│  .50 (no-auth)  .60 (leaks DB creds via env)                 │
│                   172.28.0.0/24 (shadowlab)                  │
└─────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Python | 3.12.x | Backend runtime |
| Node.js | 20+ | Frontend build |
| Docker | 24+ | Lab environment & containerized deployment |
| nmap | 7.x | Port scanning (backend dependency) |
| Ollama | latest | Local LLM inference (optional) |

### Option A: Local Development

```bash
# 1. Clone
git clone https://github.com/AtharvaPatil466/TEAM-DOPICODE---PS3.git
cd TEAM-DOPICODE---PS3

# 2. Backend
make install                  # Creates venv + installs deps (requires Python 3.12)
make demo                     # Resets DB → seeds demo data → starts server on :8000

# 3. Frontend (new terminal)
cd frontend
npm install
npm run dev                   # Vite dev server on :5173

# 4. (Optional) Local LLM for AI features
brew install ollama           # or: curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.2
ollama serve                  # Runs on :11434, frontend connects automatically
```

### Option B: Docker (Production-like)

```bash
# 1. Start the vulnerable lab network
cd lab && docker compose up -d

# 2. Build and start the full stack
cd ../infra && docker compose up --build
```

| Service | URL |
|---------|-----|
| Frontend | http://localhost:8090 |
| Backend API | http://localhost:8000 |
| API via Proxy | http://localhost:8090/api/ |
| WebSocket | ws://localhost:8090/ws |
| API Docs (Swagger) | http://localhost:8000/docs |

### Option C: VPS Deployment

```bash
make install PY=/path/to/python3.12
make run HOST=0.0.0.0 PORT=8000
```

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Liveness probe |
| `POST` | `/scan/start` | Start a scan — `{domain, subnet?, company_size?, industry_sector?, processes_pii?}` |
| `GET` | `/scan/status/{id}` | Poll scan progress |
| `GET` | `/scan/latest` | Latest scan metadata |
| `GET` | `/scan/diff?before=A&after=B` | Asset/risk delta between two scans |
| `WS` | `/scan/live` | Real-time event stream (10 event types) |
| `POST` | `/demo/replay/latest` | Replay a persisted scan over WebSocket |
| `GET` | `/assets` | All assets in latest scan |
| `GET` | `/asset/{id}` | Detailed asset view (ports, CVEs, tech stack, TLS, admin panels) |
| `GET` | `/graph` | D3-ready nodes + edges with rule metadata |
| `GET` | `/rulebook` | Named rule catalog with MITRE ATT&CK tags |
| `GET` | `/attack-path?persona=criminal` | Ranked attack chain with alternates and remediations |
| `POST` | `/attack-path/simulate` | What-if: patch assets/CVEs, see paths break |
| `POST` | `/lab/validate` | Fire safe probes against lab containers |
| `GET` | `/report/pdf` | Download full PDF threat report |
| `GET` | `/impact` | Breach impact with regulatory + operational exposure |
| `GET` | `/impact/scenarios` | Attack scenario matrix with financial estimates |

---

## 🧪 Lab Environment

The project ships with a **self-contained vulnerable network** for safe, repeatable demonstrations.

| Container | IP | Role | Vulnerability |
|-----------|-----|------|---------------|
| `shadowlab-apache` | 172.28.0.10 | Internet-exposed gateway | Apache 2.4.49 — CVE-2021-41773 (path traversal → RCE) |
| `shadowlab-mysql` | 172.28.0.20 | Crown Jewel 👑 | MySQL 5.7 with weak credentials |
| `shadowlab-iot` | 172.28.0.30 | Shadow Device | Busybox HTTP, zero authentication |
| `shadowlab-rogue` | 172.28.0.40 | Rogue Laptop | OpenSSH `PermitRootLogin yes` |
| `shadowlab-redis` | 172.28.0.50 | Unauth cache | Redis 5.0.5, `--protected-mode no`, CVE-2022-0543 |
| `shadowlab-api` | 172.28.0.60 | API pivot | Flask 2.0.1, leaks MySQL root creds via env |

Six containers surface **8+ distinct attack-path categories** — EXP-001 chains through Apache, CRED-001 via the API, CLOUD-001 through Redis, SHADOW-001 via the rogue laptop, DATA-001 into MySQL, and lateral combinations of each. The graph isn't one canonical kill-chain — it's a fan of plausible routes.

```bash
cd lab && docker compose up -d     # Start
cd lab && docker compose down -v   # Teardown
```

---

## 📐 Edge Rulebook

Every edge in the attack graph is produced by a named rule with full provenance:

| Rule ID | Name | Relationship | MITRE ATT&CK | Compliance |
|---------|------|-------------|---------------|------------|
| `NET-002` | Internet Reachability | `internet_reachable` | T1595, T1590 | NIST AC-17, CIS 12.2 |
| `MISC-001` | Exposed Admin Panel | `admin_exposure` | T1190, T1133 | PCI 1.2.1, SOC2 CC6.1 |
| `CONF-001` | Weak TLS Posture | `tls_weakness` | T1557, T1040 | PCI 4.1, NIST SC-8 |
| `SUPPLY-001` | Outdated Dependency | `outdated_software` | T1195.002 | NIST SI-2, PCI 6.2 |
| `CLOUD-001` | Public Bucket Exposure | `public_bucket` | T1530, T1619 | SOC2 CC6.1, ISO 27001 A.9.4 |
| `EXP-001` | Remote Exploit | `rce_exploit` | T1190, T1210 | NIST SI-2, PCI 6.2 |
| `CRED-001` | Credential Path | `credential_access` | T1078, T1110, T1556 | PCI 8.3.1, NIST IA-2 |
| `EXP-002` | Privilege Escalation | `priv_escalation` | T1068, T1548 | NIST AC-6 |
| `NET-001` | Lateral Reachability | `lateral_move` | T1021, T1570 | PCI 1.2, NIST SC-7 |
| `SHADOW-001` | Shadow Device Pivot | `shadow_pivot` | T1200, T1021 | NIST CM-8, CIS 1.1 |
| `DATA-001` | Crown Jewel Access | `crown_jewel_access` | T1213, T1005, T1041 | PCI 3.4, NIST SC-7 |

---

## 🧬 Attacker Personas

Time-to-breach estimates scale with attacker sophistication:

| Persona | Profile | Speed Modifier | Hard-Complexity Modifier |
|---------|---------|---------------|--------------------------|
| 🧒 Script Kiddie | Uses public exploits, no custom tooling | 2.0× slower | 3.0× slower |
| 💀 Criminal Operator | Organized, uses commercial exploit kits | 1.0× (baseline) | 1.2× slower |
| 🎯 Nation-State / APT | Custom 0-days, unlimited time and resources | 0.55× faster | 0.8× faster |

---

## 📁 Project Structure

```
project/
├── backend/
│   ├── api/                  # FastAPI routes, orchestrator, WebSocket events
│   ├── scanner/              # Discovery modules (nmap, subdomain, SSL, cloud, etc.)
│   ├── intelligence/         # Graph builder, attack paths, impact sim, PDF reports
│   ├── lab/                  # Live validation probes against lab containers
│   ├── db/                   # SQLAlchemy models + session management
│   ├── scripts/              # seed_demo.py — offline demo data seeder
│   ├── tests/                # pytest rulebook suite (24 tests)
│   └── config.py             # Environment config (.env loading)
├── frontend/
│   ├── src/
│   │   ├── pages/            # Landing, CTO, Overview, Scan, KillChain, Impact, SurfaceMap, Report
│   │   ├── components/       # Cards, Findings, Graph (D3), Layout, Reports
│   │   ├── services/         # api.js (REST/WS client), llm.js (Ollama integration)
│   │   └── styles/           # Global CSS
│   └── vite.config.js
├── shared/
│   └── api_schema.json       # API contract between backend and frontend
├── lab/
│   ├── docker-compose.yml    # 6-container vulnerable network
│   ├── apache/               # Custom httpd.conf for CVE-2021-41773
│   └── api/                  # Flask stub (leaky-env-vars pivot target)
├── infra/
│   ├── backend.Dockerfile    # Python 3.12 + nmap, non-root, tini
│   ├── frontend.Dockerfile   # Multi-stage: Node build → Nginx serve
│   ├── nginx.conf            # SPA fallback + API/WS reverse proxy
│   └── docker-compose.yml    # Full-stack orchestration
├── .github/workflows/
│   └── ci.yml                # Backend smoke test, frontend build, Docker image build
├── Makefile                  # install, run, seed, demo, lab-up/down, clean
└── README.md
```

---

## ⚙️ Environment Variables

Create `backend/.env` (see `.env.example`):

```env
DATABASE_URL=sqlite:///./shadowtrace.db
NVD_API_KEY=                   # Optional: NVD API key for CVE lookups
ANTHROPIC_API_KEY=             # Optional: Not required if using Ollama
LAB_SUBNET=172.28.0.0/24
LAB_ENTRY_HOST=172.28.0.10
LAB_CROWN_JEWEL=172.28.0.20
LOG_LEVEL=INFO
```

---

## 🔄 CI/CD

GitHub Actions pipeline runs on every push to `main` and on all PRs:

1. **Backend** — Python 3.12 + nmap install → pip install → import smoke test → `pytest` rulebook suite (24 tests covering topology gate + EXP-001/NET-002/CRED-001/DATA-001/SHADOW-001)
2. **Frontend** — Node 20 → `npm ci` → `npm run build`
3. **Docker** — Builds both `backend.Dockerfile` and `frontend.Dockerfile` (no push)

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend Framework | FastAPI 0.115 + Uvicorn |
| Data Models | Pydantic 2.9 + SQLAlchemy 2.0 |
| Database | SQLite via aiosqlite |
| Graph Engine | NetworkX 3.3 |
| Port Scanning | python-nmap + Nmap binary |
| Packet Crafting | Scapy 2.6 |
| CVE Intelligence | NVD API + CISA KEV cache (1.1MB, offline-ready) |
| PDF Generation | ReportLab 4.2 |
| ML / Anomaly | scikit-learn 1.5 |
| Local LLM | Ollama + Llama 3.2 (fully offline) |
| Frontend | React 19 + React Router 7 |
| Build Tool | Vite 7 |
| Reverse Proxy | Nginx 1.27 |
| Containerization | Docker + Docker Compose |
| CI | GitHub Actions |

---

## 👥 Team

**TEAM DOPICODE** — PS3

---

<div align="center">

*Built with ☕ and a healthy disrespect for unpatched Apache servers.*

</div>

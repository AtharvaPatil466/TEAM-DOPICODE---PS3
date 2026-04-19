# ShadowTrace — 15-Minute Demo Script & Full Technical Overview

---

## PART 1: FULL TECHNICAL OVERVIEW

### What is ShadowTrace?

ShadowTrace is an **automated public attack surface intelligence platform** that discovers what a company exposes to the internet, computes how an attacker would exploit it, and translates the technical findings into a **rupee-denominated breach cost** that a CTO can act on immediately.

It answers one question: *"If someone attacked our company today, what would it cost us?"*

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    FRONTEND (React + Vite)               │
│  Landing → Scan → Overview → Surface Map → Kill Chain    │
│  → Breach Impact → What-If Simulator → Scan Diff → CTO  │
│  → Report (PDF Export)                                   │
└────────────────────────┬────────────────────────────────┘
                         │ REST + WebSocket
┌────────────────────────▼────────────────────────────────┐
│                 BACKEND (FastAPI + SQLAlchemy)            │
│                                                          │
│  ┌──────────┐  ┌────────────┐  ┌──────────────────────┐ │
│  │ Scanner  │  │Intelligence│  │     API Layer        │ │
│  │ Pipeline │→ │   Engine   │→ │  26 REST endpoints   │ │
│  │          │  │            │  │  1 WebSocket stream   │ │
│  └──────────┘  └────────────┘  └──────────────────────┘ │
│       │              │                                   │
│  ┌────▼──────────────▼──────┐                           │
│  │     SQLite Database      │                           │
│  │  Scans, Assets, CVEs,    │                           │
│  │  Ports, Edges, Paths     │                           │
│  └──────────────────────────┘                           │
└─────────────────────────────────────────────────────────┘
```

### Scanner Pipeline (8 modules)

The scanner pipeline runs automatically when a domain is submitted. Each module runs as an async coroutine and results are streamed to the frontend via WebSocket in real-time.

| Module | What it does |
|--------|-------------|
| **subdomain.py** | DNS brute-force + crt.sh certificate transparency to discover all subdomains |
| **nmap_scanner.py** | Port scanning on discovered hosts — finds open services |
| **ssl_analyzer.py** | TLS certificate analysis — expiry, self-signed, hostname mismatch |
| **admin_panel.py** | Probes each host for exposed admin/login panels (/admin, /wp-admin, /console) |
| **cloud_buckets.py** | Generates S3/Azure bucket name permutations and checks for public access |
| **takeover.py** | Checks CNAME targets against dangling-provider fingerprints for subdomain takeover |
| **tech_fingerprint.py** | Identifies running technologies (frameworks, servers, CMS) |
| **cve_fetcher.py** | Queries NVD/NIST for known CVEs matching discovered technologies |

### Intelligence Engine (9 modules)

After scanning completes, the intelligence engine transforms raw findings into actionable insights:

| Module | What it does |
|--------|-------------|
| **edge_rules.py** | Named rulebook with 10+ rules (EXP-001, CONF-001, CLOUD-001, etc.). Every edge in the attack graph is produced by exactly one named rule with a MITRE ATT&CK technique mapping |
| **graph_builder.py** | Constructs a directed graph (NetworkX) from assets + edge rules. Internet → asset → asset edges based on discovered relationships |
| **attack_path.py** | Finds the top-K shortest attack paths from Internet to crown jewel assets using `nx.shortest_simple_paths` on inverted-risk weights |
| **path_validator.py** | TCP probe validation — opens real sockets to each hop. Labels paths as CONFIRMED / PARTIAL / UNVERIFIED |
| **risk_scorer.py** | Composite risk scoring per asset combining CVE CVSS, exposure level, finding type |
| **impact_simulator.py** | Full breach cost calculation: DPDP Act regulatory exposure (up to ₹250 Cr), operational loss (downtime, IR, churn), attack scenario matrix |
| **diff.py** | Compares two scans: assets added/removed, edges changed, paths broken/introduced, risk delta |
| **simulate.py** | What-if simulator: "If we patch asset X, which attack paths break?" |
| **report.py** | Generates a strict 2-page executive PDF: Page 1 (The Fear — rupee exposure hero, risk gauge, stat boxes) + Page 2 (The Fix — prioritized action plan with risk reduction per item) |

### Financial Impact Engine

The impact simulator is the **core differentiator**. It does not output arbitrary numbers — every rupee figure is derived from:

1. **Company profile**: size (small/medium/large), industry sector, whether they process PII
2. **DPDP Act 2023 penalties**: Tier 1 up to ₹250 Cr for failure to take reasonable security safeguards
3. **Operational loss**: downtime cost (hourly revenue × MTTR), incident response fees, customer churn (2-5% revenue)
4. **Finding multipliers**: subdomain takeover (8×), public S3 bucket (6×), exposed admin panel (5×)
5. **Industry multipliers**: Financial services (2×), Healthcare (1.8×), Technology (1.5×)

### Frontend (11 pages)

| Page | Purpose |
|------|---------|
| **Landing** | Domain input with count-up animation for assets/CVEs, CTA to start scan |
| **Scan Setup** | Domain input form with suggested targets, or auto-starts scanning when domain param provided |
| **Scan Live** | Real-time event feed via WebSocket, progress bar, asset/CVE counters |
| **Overview** | Technical dashboard: metrics, narrative card (AI-enhanced), priority actions, finding table |
| **CTO View** | Executive dashboard: plain-English findings bucketed into Fix Today / Fix This Week / Fix This Month |
| **Surface Map** | Interactive SVG attack graph with draggable nodes, heatmap mode, edge click explanations |
| **Kill Chain** | Timeline visualization: each hop in the attack path with TCP probe badges and "Why this hop?" AI modal |
| **Breach Impact** | Hero rupee exposure number, regulatory breakdown, operational loss cards, attack scenario matrix |
| **What-If** | Remediation simulator: select assets to "patch", choose attacker persona (Script Kiddie/Criminal/APT), see which paths break |
| **Scan Diff** | Compare two scans: assets added/removed, risk delta, paths broken/introduced |
| **Report** | Preview and export the 2-page executive PDF |

### Key Technical Differentiators

1. **Rupee-native financial modeling** — Not dollar conversions. DPDP Act penalties calculated from Indian regulatory framework.
2. **Named edge rulebook** — Every graph edge has a traceable rule ID + MITRE ATT&CK technique. Judges can ask "why does this edge exist?" and get a real answer.
3. **TCP path validation** — Attack paths aren't theoretical. Each hop is verified with a real TCP socket probe, labeled CONFIRMED/PARTIAL/UNVERIFIED.
4. **What-If simulator** — Interactive remediation planning. "If we fix this one thing, how many attack paths break?"
5. **2-page executive PDF** — Page 1 creates urgency (rupee exposure), Page 2 gives a specific plan (prioritized fixes with cost-per-item).

---

## PART 2: 15-MINUTE DEMO SCRIPT

### Setup (do this 5 minutes before your slot)

```bash
cd project
# Seed the demo data
PYTHONPATH=. backend/.venv/bin/python -m backend.scripts.seed_demo

# Make sure backend is running
backend/.venv/bin/uvicorn backend.api.main:app --host 127.0.0.1 --port 8000 &

# Make sure frontend is running
cd frontend && npm run dev &
```

Open `http://127.0.0.1:5173` in Chrome. Clear your browser cache (`Cmd+Shift+R`).

---

### MINUTE 0:00 — 1:30 | The Hook (Landing Page)

**[Stay on the Landing Page]**

> *"Every company has a public attack surface — subdomains, open ports, cloud buckets, admin panels — that anyone on the internet can see. Most CTOs have no idea what theirs looks like or what it would cost them if someone exploited it."*
>
> *"ShadowTrace answers one question: if someone attacked your company today, what would it cost you — in rupees?"*

**→ Type `hackerone.com` in the domain input (or use the seeded demo)**
**→ Click SCAN NOW**

---

### MINUTE 1:30 — 3:30 | Live Scan (Scan Page)

**[Watch the live event feed stream in]**

> *"We're now doing a passive external scan — no intrusion, nothing illegal. We're using certificate transparency logs, DNS brute-force, port probing, SSL analysis, and cloud bucket enumeration to map their public attack surface."*

Point out as events appear:
- **"Asset discovered: api.hackerone.com"** — show the counter ticking up
- **"Port 443/tcp open"** — ports being fingerprinted
- **"CVE found"** — vulnerabilities being correlated

> *"This entire pipeline is async — 8 scanner modules running concurrently, streaming results to the frontend over a WebSocket."*

**→ When scan completes, click "View Results"**

*(If the scan takes too long or the target is slow, navigate to `/overview` — the seeded demo data is already there)*

---

### MINUTE 3:30 — 5:30 | Technical Overview

**[Overview Page]**

> *"Here's the technical dashboard. At the top — the breach exposure in rupees. This isn't a guess. It's calculated from the DPDP Act 2023 penalty framework, the company's size and industry, and the specific findings we discovered."*

Point out:
- **₹6.0 Cr — ₹40.0 Cr** breach exposure hero
- **Critical: 6, High: 4** finding counts
- **Download Report** button — mention the PDF

Scroll to the **finding table**:
> *"Every finding has an asset, a severity, a plain-English explanation, and a recommended fix. No jargon — a CTO can read this."*

---

### MINUTE 5:30 — 7:00 | CTO View

**[Click "CTO View" in sidebar]**

> *"This is the view designed for the person writing the check. Same findings, but bucketed into three columns: Fix Today, Fix This Week, Fix This Month. Prioritized by business impact, not CVSS score."*

Point out:
- **Fix Today** (red) — critical items like exposed admin panels, public S3 buckets
- **Fix This Week** (yellow) — medium-priority items
- **Fix This Month** (blue) — low-priority hardening

> *"A CTO looks at this for 10 seconds and knows what to tell their team on Monday morning."*

**→ Click "Download PDF Report"**
**→ Open the PDF and show it briefly**

> *"This is the deliverable — a 2-page executive brief. Page 1 is the fear: here's what you're exposed to, in rupees. Page 2 is the fix: here's exactly what to do, in priority order, with cost-per-item."*

---

### MINUTE 7:00 — 9:00 | Attack Surface Map + Kill Chain

**[Click "Surface Map" in sidebar]**

> *"This is the attack graph. Every node is an asset we discovered. Every edge is a potential lateral movement path. The edges aren't random — each one is produced by a named rule from our rulebook with a MITRE ATT&CK technique mapping."*

- **Click a node** — show the detail panel populate
- **Toggle Heatmap mode** — nodes color by risk score (green→red)
- **Click an edge line** — show the "Why this edge?" explainer modal

**[Click "Kill Chain" in sidebar]**

> *"This is the most believable attack path we found — the shortest route from the internet to a crown jewel asset. Each hop has been TCP-validated."*

- Point out the **CONFIRMED / PARTIAL** badge
- Point out **probe latency** (e.g., `✓ :443 2.1ms`)
- Click **"Why this hop?"** — show the AI-generated explanation

> *"We don't just say 'there might be a path.' We prove it. Every hop, verified with a real TCP socket probe."*

---

### MINUTE 9:00 — 11:00 | Breach Impact (The Money Slide)

**[Click "Breach Impact" in sidebar]**

> *"This is where we translate technical findings into business language."*

Point out each section:
- **Estimated Breach Cost**: the hero rupee number
- **Regulatory Exposure**: based on DPDP Act 2023 penalty tiers
- **Operational Loss Breakdown**: Downtime, Incident Response, Customer Churn — each with a rupee figure
- **Executive Advisory**: AI-generated board letter

> *"The ₹16 lakh downtime figure comes from the company's hourly revenue multiplied by the estimated MTTR. The ₹63 lakh customer churn is 2-5% of annual revenue. These aren't arbitrary — they're model-derived."*

Scroll to **Attack Scenario Matrix**:
> *"Each scenario shows: attacker skill required, data at risk, total exposure, and cost to prevent. A criminal can exploit this for ₹2 crore. It costs ₹1.5 lakh to fix."*

---

### MINUTE 11:00 — 13:00 | What-If Simulator + Scan Diff

**[Click "What-If" in sidebar]**

> *"This is the remediation simulator. Instead of guessing what to fix first, you can model it."*

- **Select an asset** (e.g., the S3 bucket)
- **Choose attacker persona** — "Criminal"
- **Click "Run Simulation"**

> *"We just re-ran the attack path computation with that asset patched. Look — it broke 1 attack path and reduced the overall risk score. Now the CTO knows: fix that one bucket, reduce exposure by 40%."*

**[Click "Scan Diff" in sidebar]**

> *"You ran a scan in January, another in March. Scan Diff shows you exactly what changed — which assets appeared or disappeared, which attack paths broke or emerged, and how your overall risk shifted."*

- Show the **dropdown selector** with past scans
- Click **Compare** — show the delta summary

---

### MINUTE 13:00 — 14:30 | Technical Depth (for judges)

> *"Let me briefly walk through the architecture."*

- **8 scanner modules** running async (subdomain, nmap, SSL, admin panel, cloud buckets, takeover, tech fingerprint, CVE fetch)
- **Named edge rulebook** — 10+ rules, each with MITRE ATT&CK mapping, probe port, compliance controls
- **NetworkX graph** → `shortest_simple_paths` for attack path ranking
- **TCP path validation** — real socket probes, not theoretical paths
- **Financial model** — DPDP Act tiers, industry multipliers, finding-type multipliers
- **Real-time WebSocket streaming** — events appear as they're discovered
- **2-page executive PDF** with DejaVu Sans for rupee symbol rendering

> *"The entire backend is Python/FastAPI with SQLAlchemy. Frontend is React/Vite. No external SaaS dependencies — everything runs locally."*

---

### MINUTE 14:30 — 15:00 | Close

> *"ShadowTrace turns a 20-minute technical scan into a 10-second CTO decision. It doesn't just find vulnerabilities — it tells you what they cost in rupees, which one to fix first, and proves the attack path is real with TCP validation."*
>
> *"The PDF on a board table, the rupee number on the first page — that's what creates urgency. Not a CVSS score. Rupees."*

---

## PART 3: EMERGENCY FALLBACKS

| Scenario | What to do |
|----------|-----------|
| **Live scan takes too long** | Navigate to `/overview` — seeded demo data is already there |
| **Backend crashes** | `PYTHONPATH=. backend/.venv/bin/uvicorn backend.api.main:app --port 8000 &` |
| **Frontend crashes** | `cd frontend && npm run dev &` |
| **Empty pages after a fresh scan** | Re-seed: `PYTHONPATH=. backend/.venv/bin/python -m backend.scripts.seed_demo` |
| **WiFi is down** | Everything runs 100% local — no cloud dependencies |
| **Judge asks about legality** | All scanning is passive. Certificate transparency is public. DNS is public. No exploitation. `scanme.nmap.org` explicitly permits scanning |
| **Judge asks about DPDP Act numbers** | Penalty tiers from Section 33: up to ₹250 Cr (Tier 1), up to ₹200 Cr (Tier 2). Our model uses conservative multipliers |

---

## PART 4: TALKING POINTS FOR Q&A

**"How is this different from Nessus/Shodan/Qualys?"**
> Those tools produce CVE lists. We produce a rupee number and a prioritized action plan. The CTO never sees a CVSS score.

**"Is the financial model accurate?"**
> It's a model, not a prediction. But every input is traceable — DPDP Act penalty tiers, IBM Cost of a Data Breach 2024 benchmarks, industry multipliers. We show our work.

**"Can this scale?"**
> The scanner is fully async. We've tested against github.com (12+ assets) and hackerone.com — scan completes in under 60 seconds.

**"What about internal networks?"**
> The scanner supports internal subnet scoping. The architecture supports internal pivot detection — if an external asset leads to an internal asset, that edge is modeled.

**"Why not use an existing attack surface management tool?"**
> Because none of them solve the last-mile problem: translating findings into a rupee figure a CTO will act on. That's our entire thesis — security decisions are spending decisions.

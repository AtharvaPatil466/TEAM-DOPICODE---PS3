import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import "../styles/brand.css";

const API = "http://localhost:8000";
const WS_BASE = "ws://localhost:8000";

/* ── Severity config ── */
const SEV = {
  CRITICAL: { bg: "var(--severity-critical-bg, #2A0A0C)", color: "var(--severity-critical-text, #E63946)", label: "CRIT" },
  HIGH:     { bg: "var(--severity-high-bg, #2A1A00)",     color: "var(--severity-high-text, #F39C12)",   label: "HIGH" },
  MEDIUM:   { bg: "var(--severity-medium-bg, #0D1F2A)",   color: "var(--severity-medium-text, #00B4D8)", label: "MED"  },
  INFO:     { bg: "var(--severity-info-bg, #0F1A20)",     color: "var(--severity-info-text, #5C7A96)",   label: "INFO" },
};

function severityOf(item) {
  if (item.severity && SEV[item.severity]) return item.severity;
  const cvss = item.data?.cvss ?? item.cvss ?? 0;
  if (cvss >= 9) return "CRITICAL";
  if (cvss >= 7) return "HIGH";
  if (cvss >= 4) return "MEDIUM";
  return "INFO";
}

function describeEvent(evt) {
  const d = evt.data || evt;
  switch (evt.type) {
    case "cve_found":
      return `${d.cve_id || "CVE"} · ${d.asset || "unknown"} · CVSS ${d.cvss ?? "?"}`;
    case "asset_discovered":
      return `Asset discovered: ${d.hostname || d.ip || d.label || "unknown"}`;
    case "port_found":
      return `Port ${d.port || "?"}/${d.protocol || "tcp"} open on ${d.asset || d.hostname || "?"}`;
    case "graph_built":
      return `Attack graph constructed — ${d.edges ?? "?"} edges, ${d.nodes ?? "?"} nodes`;
    case "scan_complete":
      return `Scan complete — ${d.total_assets ?? 0} assets, ${d.total_cves ?? 0} CVEs`;
    default:
      return d.message || d.description || evt.type || "Event received";
  }
}

/* ── Styles ── */
const S = {
  page: {
    background: "var(--color-bg-primary, #0D1B2A)",
    color: "var(--color-text-primary, #F0F4F8)",
    fontFamily: "var(--text-body-family, 'Inter', system-ui, sans-serif)",
    minHeight: "100vh",
    display: "flex",
    flexDirection: "column",
    padding: "var(--space-6, 24px)",
    gap: "var(--space-6, 24px)",
  },

  /* Top bar */
  topBar: {
    display: "flex",
    alignItems: "center",
    gap: "var(--space-3, 12px)",
    borderBottom: "1px solid var(--color-border, #1E3048)",
    paddingBottom: "var(--space-5, 20px)",
  },
  topTitle: {
    fontSize: "var(--text-heading-md, 1.5rem)",
    fontWeight: 700,
    letterSpacing: "0.06em",
    textTransform: "uppercase",
  },

  /* Progress */
  progressOuter: {
    width: "100%",
    height: 6,
    background: "var(--color-bg-tertiary, #162336)",
    border: "1px solid var(--color-border, #1E3048)",
    borderRadius: 0,
    overflow: "hidden",
  },
  progressFill: {
    height: "100%",
    background: "var(--color-accent-red, #E63946)",
    transition: "width 400ms ease-out",
    borderRadius: 0,
  },
  statusMsg: {
    fontSize: "var(--text-body, 0.875rem)",
    color: "var(--color-text-secondary, #A8BCCF)",
    marginTop: "var(--space-2, 8px)",
  },
  counters: {
    display: "flex",
    gap: "var(--space-8, 32px)",
    flexWrap: "wrap",
    marginTop: "var(--space-4, 16px)",
  },
  counter: {
    display: "flex",
    flexDirection: "column",
    gap: "var(--space-1, 4px)",
  },
  counterLabel: {
    fontSize: "var(--text-label, 0.7rem)",
    fontWeight: 600,
    textTransform: "uppercase",
    letterSpacing: "0.12em",
    color: "var(--color-text-muted, #5C7A96)",
    fontFamily: "var(--text-label-family, monospace)",
  },
  counterValue: {
    fontSize: "var(--text-heading-md, 1.5rem)",
    fontWeight: 800,
    letterSpacing: "-0.02em",
  },

  /* Feed */
  feedHeader: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    borderBottom: "1px solid var(--color-border, #1E3048)",
    paddingBottom: "var(--space-3, 12px)",
  },
  feedTitle: {
    fontSize: "var(--text-label, 0.7rem)",
    fontWeight: 600,
    textTransform: "uppercase",
    letterSpacing: "0.12em",
    color: "var(--color-text-muted, #5C7A96)",
    fontFamily: "var(--text-label-family, monospace)",
  },
  feedCount: {
    fontSize: "var(--text-label, 0.7rem)",
    fontWeight: 600,
    textTransform: "uppercase",
    letterSpacing: "0.12em",
    color: "var(--color-accent-cyan, #00B4D8)",
    fontFamily: "var(--text-label-family, monospace)",
  },
  feedList: {
    flex: 1,
    overflowY: "auto",
    display: "flex",
    flexDirection: "column",
    gap: "var(--space-2, 8px)",
    minHeight: 200,
    maxHeight: "50vh",
  },
  card: {
    display: "flex",
    alignItems: "center",
    gap: "var(--space-4, 16px)",
    padding: "var(--space-3, 12px) var(--space-4, 16px)",
    background: "var(--color-bg-secondary, #111F30)",
    border: "1px solid var(--color-border, #1E3048)",
    borderRadius: 0,
    animation: "cardIn 200ms ease-out both",
  },
  badge: {
    display: "inline-block",
    padding: "2px var(--space-2, 8px)",
    fontSize: "var(--text-label, 0.7rem)",
    fontWeight: 600,
    textTransform: "uppercase",
    letterSpacing: "0.1em",
    fontFamily: "var(--text-label-family, monospace)",
    border: "1px solid currentColor",
    borderRadius: 0,
    flexShrink: 0,
    minWidth: 44,
    textAlign: "center",
  },
  cardDesc: {
    flex: 1,
    fontSize: "var(--text-body, 0.875rem)",
    color: "var(--color-text-primary, #F0F4F8)",
    lineHeight: 1.4,
  },
  cardTime: {
    fontSize: "var(--text-label, 0.7rem)",
    fontFamily: "var(--text-label-family, monospace)",
    color: "var(--color-text-muted, #5C7A96)",
    flexShrink: 0,
    whiteSpace: "nowrap",
  },
};

/* ── Keyframe injection (once) ── */
const STYLE_ID = "scan-page-keyframes";
function ensureKeyframes() {
  if (document.getElementById(STYLE_ID)) return;
  const sheet = document.createElement("style");
  sheet.id = STYLE_ID;
  sheet.textContent = `
    @keyframes cardIn {
      from { opacity: 0; transform: translateY(8px); }
      to   { opacity: 1; transform: translateY(0); }
    }
    @keyframes pulseDot {
      0%, 100% { opacity: 1; }
      50%      { opacity: 0.2; }
    }
  `;
  document.head.appendChild(sheet);
}

/* ── Component ── */
function ScanPage() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const domain = params.get("domain") || "democorp.io";

  const [scanId, setScanId] = useState(null);
  const [progress, setProgress] = useState(0);
  const [statusMsg, setStatusMsg] = useState("Initializing scan...");
  const [assetCount, setAssetCount] = useState(0);
  const [cveCount, setCveCount] = useState(0);
  const [events, setEvents] = useState([]);

  const startTime = useRef(Date.now());
  const feedRef = useRef(null);
  const userScrolled = useRef(false);
  const wsRef = useRef(null);
  const pollRef = useRef(null);
  const timeoutRef = useRef(null);
  const fallbackFired = useRef(false);
  const mountedRef = useRef(true);

  useEffect(() => {
    ensureKeyframes();
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  /* ── Auto scroll ── */
  const scrollToBottom = useCallback(() => {
    if (!userScrolled.current && feedRef.current) {
      feedRef.current.scrollTop = feedRef.current.scrollHeight;
    }
  }, []);

  const handleFeedScroll = useCallback(() => {
    if (!feedRef.current) return;
    const el = feedRef.current;
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
    userScrolled.current = !atBottom;
  }, []);

  /* ── Append event ── */
  const pushEvent = useCallback(
    (evt) => {
      if (!mountedRef.current) return;

      setEvents((prev) => [...prev, { ...evt, _ts: Date.now() }]);

      if (evt.type === "asset_discovered") {
        setAssetCount((n) => n + 1);
      }
      if (evt.type === "cve_found") {
        setCveCount((n) => n + 1);
      }
      if (evt.type === "scan_complete") {
        const d = evt.data || {};
        setProgress(100);
        setStatusMsg("Scan complete — building report...");
        if (d.total_assets) setAssetCount(d.total_assets);
        if (d.total_cves) setCveCount(d.total_cves);
        setTimeout(() => {
          if (mountedRef.current) {
            navigate(`/app/results/${scanId || "latest"}`);
          }
        }, 1500);
      }

      setTimeout(scrollToBottom, 30);
    },
    [navigate, scanId, scrollToBottom]
  );

  /* ── Demo fallback — stagger replay ── */
  const fireFallback = useCallback(async () => {
    if (fallbackFired.current) return;
    fallbackFired.current = true;
    setStatusMsg("Loading preloaded demo data...");

    try {
      const res = await fetch(`${API}/demo/replay/latest`, { method: "POST" });
      if (!res.ok) throw new Error("fallback failed");
      /* The replay endpoint emits events over WebSocket, but if WS is dead
         we stagger the summary as fake events */
      const data = await res.json();
      const fakeEvents = [];

      /* Fabricate plausible events from the summary */
      const assets = data?.total_assets ?? 8;
      const cves = data?.total_cves ?? 12;
      for (let i = 0; i < assets; i++) {
        fakeEvents.push({
          type: "asset_discovered",
          data: { hostname: `asset-${i + 1}.${domain}` },
        });
      }
      for (let i = 0; i < Math.min(cves, 15); i++) {
        fakeEvents.push({
          type: "cve_found",
          data: {
            cve_id: `CVE-2021-${41700 + i}`,
            cvss: (6 + Math.random() * 4).toFixed(1),
            asset: `asset-${(i % assets) + 1}.${domain}`,
            severity: i < 2 ? "CRITICAL" : i < 5 ? "HIGH" : "MEDIUM",
          },
        });
      }
      fakeEvents.push({ type: "graph_built", data: { nodes: assets, edges: assets * 2 } });
      fakeEvents.push({
        type: "scan_complete",
        data: {
          total_assets: assets,
          total_cves: cves,
          exposure_inr_min: data?.exposure_inr_min ?? 50000000,
          exposure_inr_max: data?.exposure_inr_max ?? 2500000000,
        },
      });

      for (let i = 0; i < fakeEvents.length; i++) {
        await new Promise((r) => setTimeout(r, 350));
        if (!mountedRef.current) return;
        const pct = Math.round(((i + 1) / fakeEvents.length) * 100);
        setProgress(pct);
        pushEvent(fakeEvents[i]);
      }
    } catch {
      setStatusMsg("Demo data unavailable. Try restarting the backend.");
    }
  }, [domain, pushEvent]);

  /* ── Start scan on mount ── */
  useEffect(() => {
    let cancelled = false;

    async function init() {
      /* 1. POST to create scan */
      try {
        const res = await fetch(`${API}/scan/start`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            domain,
            company_size: "medium",
            industry_sector: "technology",
            processes_pii: true,
          }),
        });

        if (!res.ok) throw new Error(`scan/start ${res.status}`);
        const body = await res.json();
        if (cancelled) return;
        const id = body.scan_id;
        setScanId(id);
        setStatusMsg("Scan initiated — connecting to live stream...");

        /* 2. Open WebSocket */
        let wsConnected = false;
        const wsTimeout = setTimeout(() => {
          if (!wsConnected && !cancelled) {
            setStatusMsg("WebSocket unavailable — polling for updates...");
          }
        }, 5000);

        try {
          const ws = new WebSocket(`${WS_BASE}/scan/live`);
          wsRef.current = ws;

          ws.onopen = () => {
            wsConnected = true;
            clearTimeout(wsTimeout);
            if (!cancelled) setStatusMsg("Connected — watching live events...");
          };

          ws.onmessage = (msg) => {
            if (cancelled) return;
            try {
              const evt = JSON.parse(msg.data);
              pushEvent(evt);
            } catch { /* ignore non-JSON */ }
          };

          ws.onerror = () => {
            if (!cancelled) setStatusMsg("Stream interrupted — polling...");
          };

          ws.onclose = () => {
            wsRef.current = null;
          };
        } catch {
          clearTimeout(wsTimeout);
        }

        /* 3. Poll progress */
        pollRef.current = setInterval(async () => {
          if (cancelled) return;
          try {
            const r = await fetch(`${API}/scan/status/${id}`);
            if (!r.ok) return;
            const s = await r.json();
            if (cancelled) return;
            if (typeof s.progress === "number") setProgress(s.progress);
            if (s.status === "complete") {
              setProgress(100);
              setStatusMsg("Scan complete — building report...");
            }
          } catch { /* swallow */ }
        }, 2000);

        /* 4. Timeout → fallback at 70s */
        timeoutRef.current = setTimeout(() => {
          if (!cancelled) fireFallback();
        }, 70000);

      } catch {
        /* Scan start failed entirely → demo fallback */
        if (!cancelled) {
          setStatusMsg("Backend unreachable — loading demo data...");
          fireFallback();
        }
      }
    }

    init();

    return () => {
      cancelled = true;
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
      if (pollRef.current) clearInterval(pollRef.current);
      if (timeoutRef.current) clearTimeout(timeoutRef.current);
    };
  }, [domain, pushEvent, fireFallback]);

  /* ── Elapsed timer ── */
  const elapsed = useCallback(
    (ts) => {
      const sec = Math.round(((ts || Date.now()) - startTime.current) / 1000);
      return `${sec}s`;
    },
    []
  );

  return (
    <div style={S.page}>
      {/* ── TOP BAR ── */}
      <div style={S.topBar}>
        <span
          style={{
            width: 8,
            height: 8,
            background: "var(--color-accent-cyan, #00B4D8)",
            display: "inline-block",
            animation: "pulseDot 1s ease-in-out infinite",
            flexShrink: 0,
          }}
        />
        <span style={S.topTitle}>Scanning {domain}...</span>
      </div>

      {/* ── PROGRESS ── */}
      <div>
        <div style={S.progressOuter}>
          <div style={{ ...S.progressFill, width: `${progress}%` }} />
        </div>
        <p style={S.statusMsg}>{statusMsg}</p>
        <div style={S.counters}>
          <div style={S.counter}>
            <span style={S.counterLabel}>Assets Discovered</span>
            <span style={S.counterValue}>{assetCount}</span>
          </div>
          <div style={S.counter}>
            <span style={S.counterLabel}>CVEs Found</span>
            <span style={S.counterValue}>{cveCount}</span>
          </div>
          <div style={S.counter}>
            <span style={S.counterLabel}>Progress</span>
            <span style={S.counterValue}>{progress}%</span>
          </div>
        </div>
      </div>

      {/* ── LIVE FEED ── */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: "var(--space-3, 12px)" }}>
        <div style={S.feedHeader}>
          <span style={S.feedTitle}>Live Event Feed</span>
          <span style={S.feedCount}>{events.length} findings so far</span>
        </div>

        <div
          ref={feedRef}
          style={S.feedList}
          onScroll={handleFeedScroll}
        >
          {events.map((evt, i) => {
            const sev = severityOf(evt);
            const s = SEV[sev] || SEV.INFO;
            return (
              <div key={i} style={S.card}>
                <span
                  style={{
                    ...S.badge,
                    background: s.bg,
                    color: s.color,
                    borderColor: s.color,
                  }}
                >
                  {s.label}
                </span>
                <span style={S.cardDesc}>{describeEvent(evt)}</span>
                <span style={S.cardTime}>{elapsed(evt._ts)}</span>
              </div>
            );
          })}

          {events.length === 0 && (
            <p
              style={{
                textAlign: "center",
                color: "var(--color-text-muted, #5C7A96)",
                fontSize: "var(--text-body, 0.875rem)",
                padding: "var(--space-8, 32px)",
              }}
            >
              Waiting for scan events...
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

export default ScanPage;

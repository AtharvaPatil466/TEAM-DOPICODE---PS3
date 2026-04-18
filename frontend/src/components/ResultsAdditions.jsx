/* ============================================================
   ShadowTrace — Results Page Additions
   Drop these two components into your results page JSX.
   Import them and place:
     <StickyResultsBar ... />   at the TOP of the page
     <TopFixesCard ... />       BELOW the graph section
   ============================================================ */

import { useCallback, useState } from "react";
import "../styles/brand.css";

const API = "http://localhost:8000";

/* ── INR formatter ── */
function formatINR(value) {
  if (value == null) return "—";
  const num = Number(value);
  if (num >= 1e7) return `₹${(num / 1e7).toFixed(1)}Cr`;
  if (num >= 1e5) return `₹${(num / 1e5).toFixed(1)}L`;
  return `₹${num.toLocaleString("en-IN")}`;
}

/* ════════════════════════════════════════════════════════════
   PART A — StickyResultsBar
   Props: { results }
   results shape: { scan_id, domain, assets, impact }
   ════════════════════════════════════════════════════════════ */

const barStyles = {
  bar: {
    position: "sticky",
    top: 0,
    zIndex: 100,
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    gap: "var(--space-6, 24px)",
    padding: "var(--space-4, 16px) var(--space-6, 24px)",
    background: "var(--color-bg-primary, #0D1B2A)",
    borderBottom: "1px solid var(--color-border, #1E3048)",
    flexWrap: "wrap",
  },
  section: {
    display: "flex",
    flexDirection: "column",
    gap: "var(--space-1, 4px)",
  },
  label: {
    fontSize: "var(--text-label, 0.7rem)",
    fontWeight: 600,
    textTransform: "uppercase",
    letterSpacing: "0.12em",
    color: "var(--color-text-muted, #5C7A96)",
    fontFamily: "var(--text-label-family, monospace)",
  },
  bigRed: {
    fontSize: 48,
    fontWeight: 800,
    color: "var(--color-accent-red, #E63946)",
    letterSpacing: "-0.04em",
    lineHeight: 1,
  },
  bigAmber: {
    fontSize: "var(--text-heading-md, 1.5rem)",
    fontWeight: 800,
    color: "var(--color-accent-amber, #F39C12)",
    lineHeight: 1,
  },
  bigRedSmall: {
    fontSize: "var(--text-heading-md, 1.5rem)",
    fontWeight: 800,
    color: "var(--color-accent-red, #E63946)",
    lineHeight: 1,
  },
  btn: {
    display: "inline-flex",
    alignItems: "center",
    gap: "var(--space-2, 8px)",
    padding: "var(--space-3, 12px) var(--space-5, 20px)",
    background: "var(--color-accent-red, #E63946)",
    color: "#fff",
    fontSize: "var(--text-body, 0.875rem)",
    fontWeight: 700,
    textTransform: "uppercase",
    letterSpacing: "0.06em",
    border: "1px solid var(--color-accent-red, #E63946)",
    borderRadius: 0,
    cursor: "pointer",
    fontFamily: "inherit",
    transition: "background 120ms ease-out",
    whiteSpace: "nowrap",
  },
  btnDisabled: {
    opacity: 0.6,
    cursor: "not-allowed",
  },
  spinner: {
    display: "inline-block",
    width: 14,
    height: 14,
    border: "2px solid rgba(255,255,255,0.3)",
    borderTopColor: "#fff",
    borderRadius: "50%",
    animation: "barSpin 0.6s linear infinite",
  },
};

/* Inject spinner keyframe once */
const SPIN_ID = "sticky-bar-spin";
function ensureSpinKeyframe() {
  if (document.getElementById(SPIN_ID)) return;
  const el = document.createElement("style");
  el.id = SPIN_ID;
  el.textContent = `@keyframes barSpin { to { transform: rotate(360deg); } }`;
  document.head.appendChild(el);
}

export function StickyResultsBar({ results }) {
  const [loading, setLoading] = useState(false);
  ensureSpinKeyframe();

  const allCves = (results?.assets || []).flatMap((a) => a.cves || []);
  const critCount = allCves.filter((c) => c.severity === "CRITICAL").length;
  const highCount = allCves.filter((c) => c.severity === "HIGH").length;
  const minInr = results?.impact?.total_exposure_min_inr;
  const maxInr = results?.impact?.total_exposure_max_inr;

  const handleDownload = useCallback(async () => {
    if (loading) return;
    setLoading(true);
    try {
      const res = await fetch(`${API}/report/pdf`);
      if (!res.ok) throw new Error(`PDF download failed: ${res.status}`);
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `shadowtrace-${results?.domain || "scan"}-report.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      window.dispatchEvent(
        new CustomEvent("shadowtrace:apierror", {
          detail: { message: err.message || "Failed to download report" },
        })
      );
    } finally {
      setLoading(false);
    }
  }, [loading, results?.domain]);

  return (
    <div style={barStyles.bar}>
      {/* 1 — Breach Exposure */}
      <div style={barStyles.section}>
        <span style={barStyles.label}>Breach Exposure</span>
        <span style={barStyles.bigRed}>
          {formatINR(minInr)} – {formatINR(maxInr)}
        </span>
      </div>

      {/* 2 — Critical Findings */}
      <div style={barStyles.section}>
        <span style={barStyles.label}>Critical Findings</span>
        <span style={barStyles.bigRedSmall}>{critCount}</span>
      </div>

      {/* 3 — High Findings */}
      <div style={barStyles.section}>
        <span style={barStyles.label}>High Findings</span>
        <span style={barStyles.bigAmber}>{highCount}</span>
      </div>

      {/* 4 — Download */}
      <button
        type="button"
        style={{
          ...barStyles.btn,
          ...(loading ? barStyles.btnDisabled : {}),
        }}
        onClick={handleDownload}
        disabled={loading}
        onMouseEnter={(e) => {
          if (!loading) e.currentTarget.style.background = "var(--color-accent-red-dim, #7A1A1F)";
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.background = "var(--color-accent-red, #E63946)";
        }}
      >
        {loading && <span style={barStyles.spinner} />}
        {loading ? "Generating..." : "Download Report"}
      </button>
    </div>
  );
}


/* ════════════════════════════════════════════════════════════
   PART B — TopFixesCard
   Props: { fixes }
   fixes shape: [{ asset_id, fix_description, paths_broken }]
   ════════════════════════════════════════════════════════════ */

const fixStyles = {
  card: {
    background: "var(--color-bg-secondary, #111F30)",
    border: "1px solid var(--color-border, #1E3048)",
    borderRadius: 0,
    padding: "var(--space-6, 24px)",
  },
  title: {
    fontSize: "var(--text-label, 0.7rem)",
    fontWeight: 600,
    textTransform: "uppercase",
    letterSpacing: "0.12em",
    color: "var(--color-text-muted, #5C7A96)",
    fontFamily: "var(--text-label-family, monospace)",
    margin: "0 0 var(--space-5, 20px) 0",
  },
  row: {
    display: "flex",
    alignItems: "center",
    gap: "var(--space-5, 20px)",
    padding: "var(--space-4, 16px) 0",
    borderBottom: "1px solid var(--color-border, #1E3048)",
  },
  rank: {
    fontSize: "var(--text-heading-lg, 2rem)",
    fontWeight: 800,
    color: "var(--color-text-muted, #5C7A96)",
    opacity: 0.4,
    minWidth: 48,
    fontFamily: "var(--text-label-family, monospace)",
    lineHeight: 1,
    flexShrink: 0,
  },
  desc: {
    flex: 1,
    fontSize: "var(--text-body, 0.875rem)",
    color: "var(--color-text-primary, #F0F4F8)",
    lineHeight: 1.5,
  },
  badge: {
    display: "inline-block",
    padding: "2px var(--space-3, 12px)",
    fontSize: "var(--text-label, 0.7rem)",
    fontWeight: 600,
    textTransform: "uppercase",
    letterSpacing: "0.1em",
    fontFamily: "var(--text-label-family, monospace)",
    color: "var(--color-accent-cyan, #00B4D8)",
    background: "var(--severity-medium-bg, #0D1F2A)",
    border: "1px solid var(--color-accent-cyan, #00B4D8)",
    borderRadius: 0,
    whiteSpace: "nowrap",
    flexShrink: 0,
  },
};

export function TopFixesCard({ fixes }) {
  const top3 = (fixes || []).slice(0, 3);

  if (!top3.length) return null;

  return (
    <div style={fixStyles.card}>
      <p style={fixStyles.title}>Recommended Fixes</p>
      {top3.map((fix, i) => (
        <div
          key={fix.asset_id ?? i}
          style={{
            ...fixStyles.row,
            borderBottom: i === top3.length - 1 ? "none" : fixStyles.row.borderBottom,
          }}
        >
          <span style={fixStyles.rank}>
            {String(i + 1).padStart(2, "0")}
          </span>
          <span style={fixStyles.desc}>{fix.fix_description}</span>
          <span style={fixStyles.badge}>
            Breaks {fix.paths_broken} path{fix.paths_broken !== 1 ? "s" : ""}
          </span>
        </div>
      ))}
    </div>
  );
}

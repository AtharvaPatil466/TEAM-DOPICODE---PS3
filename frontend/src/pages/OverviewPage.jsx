import { useEffect, useState } from "react";
import MetricCard from "../components/cards/MetricCard";
import NarrativeCard from "../components/cards/NarrativeCard";
import PriorityActionsCard from "../components/cards/PriorityActionsCard";
import FindingTable from "../components/findings/FindingTable";
import { fetchDashboardData, fetchCtoSummary } from "../services/api";
import { StickyResultsBar, TopFixesCard } from "../components/ResultsAdditions";
import { SkeletonLine, SkeletonCard } from "../components/LoadingStates";

function CtoCard({ row }) {
  const cleanReason = (row.reason || "").replace(/via CVE-\d{4}-\d+/gi, "").replace(/CVSS [\d.]+|exploit/gi, "").trim();
  const cleanAction = (row.action || "").replace(/CVE-\d{4}-\d+/gi, "").trim();

  return (
    <div style={{ background: "var(--panel)", border: "1px solid var(--panel-border)", borderRadius: 0, padding: "1rem", marginBottom: "0.75rem" }}>
      <h4 style={{ margin: "0 0 0.5rem 0", fontSize: "1rem", color: "var(--text)" }}>{row.asset}</h4>
      <p style={{ margin: "0 0 0.5rem 0", fontSize: "0.85rem", color: "var(--muted)" }}>{cleanReason}</p>
      <p style={{ margin: "0", fontSize: "0.85rem", color: "#2ECC71" }}>Fix: {cleanAction}</p>
    </div>
  );
}

function OverviewPage() {
  const [data, setData] = useState(null);
  const [ctoSummary, setCtoSummary] = useState(null);
  const [viewMode, setViewMode] = useState("cto");

  useEffect(() => {
    async function init() {
      const dbData = await fetchDashboardData();
      setData(dbData);
      
      const summary = await fetchCtoSummary(
        dbData.domain,
        dbData.totalFindings,
        dbData.criticalFindings,
        dbData.findingRows
      );
      setCtoSummary(summary);
    }
    init();
  }, []);

  if (!data || !ctoSummary) {
    return (
      <section className="page">
        <div className="panel" style={{ textAlign: "center", padding: "4rem", borderColor: "var(--accent)" }}>
          <h3 style={{ color: "var(--text)" }}>Generating executive summary...</h3>
          <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem", marginTop: "1.5rem", maxWidth: 400, margin: "1.5rem auto 0" }}>
            <SkeletonLine width="100%" height={16} />
            <SkeletonLine width="80%" height={14} />
            <SkeletonLine width="60%" height={14} />
          </div>
        </div>
      </section>
    );
  }

  const criticalCount = data.findingRows.filter(r => r.severity === 'Critical').length;
  const highCount = data.findingRows.filter(r => r.severity === 'High').length;

  /* Adapter for StickyResultsBar — maps dashboard data to expected shape */
  const resultsForBar = {
    domain: data.latestScan?.domain,
    assets: data.findingRows.map(r => ({
      cves: [{ severity: r.severity.toUpperCase() }]
    })),
    impact: {
      total_exposure_min_inr: data.impactData?.regulatory_exposure?.min_inr,
      total_exposure_max_inr: data.impactData?.regulatory_exposure?.max_inr,
    }
  };

  /* Adapter for TopFixesCard — maps topActions to expected shape */
  const fixesForCard = (data.topActions || []).slice(0, 3).map((a, i) => ({
    asset_id: i,
    fix_description: a.detail || a.title,
    paths_broken: Math.max(1, 3 - i),
  }));

  const today = data.findingRows.filter(r => r.severity === 'Critical' || r.severity === 'High');
  const thisWeek = data.findingRows.filter(r => r.severity === 'Medium');
  const thisMonth = data.findingRows.filter(r => r.severity === 'Neutral');

  return (
    <section className="page overview-page">
      <StickyResultsBar results={resultsForBar} />

      <section className="hero-card page-intro" style={{ position: "relative" }}>
        <div style={{ position: "absolute", top: "1.5rem", right: "1.5rem", display: "flex", gap: "0.5rem" }}>
          <button 
            type="button" 
            className={`chip ${viewMode === "cto" ? "chip-live" : ""}`}
            onClick={() => setViewMode("cto")}
            style={{ cursor: "pointer", borderColor: viewMode === "cto" ? "var(--accent)" : undefined }}
          >
            CTO View
          </button>
          <button 
            type="button" 
            className={`chip ${viewMode === "tech" ? "chip-live" : ""}`}
            onClick={() => setViewMode("tech")}
            style={{ cursor: "pointer", borderColor: viewMode === "tech" ? "rgba(255,255,255,0.4)" : undefined }}
          >
            Technical View
          </button>
        </div>
        <div>
          <p className="eyebrow">{viewMode === "cto" ? "Executive dashboard" : "Technical dashboard"}</p>
          <h2>Here’s the shortest path from exposure to action.</h2>
          <p>
            {viewMode === "cto" 
              ? "The overview compresses technical scan output into the handful of signals a CTO or judge can absorb quickly: risk posture, urgency, and what to fix first."
              : "Deep dive into the raw technical findings, paths, and severity metrics."}
          </p>
        </div>
      </section>

      {viewMode === "cto" ? (
        <div style={{ marginTop: "2rem" }}>
          <div className="panel" style={{ marginBottom: "2rem", borderColor: "var(--accent)" }}>
            <p className="eyebrow">Executive Summary</p>
            <p style={{ fontSize: "1.1rem", lineHeight: 1.6, color: "#e6f0ff", margin: 0 }}>
              {ctoSummary}
            </p>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "1.5rem" }}>
            <div>
              <h3 style={{ color: "var(--critical)", borderBottom: "1px solid var(--critical)", paddingBottom: "0.5rem", marginBottom: "1rem" }}>Fix Today</h3>
              {today.map(r => <CtoCard key={r.id} row={r} />)}
              {today.length === 0 && <p style={{color: "#4ade80", fontSize: "0.9rem"}}>All clear!</p>}
            </div>
            <div>
              <h3 style={{ color: "#fbbf24", borderBottom: "1px solid #fbbf24", paddingBottom: "0.5rem", marginBottom: "1rem" }}>Fix This Week</h3>
              {thisWeek.map(r => <CtoCard key={r.id} row={r} />)}
              {thisWeek.length === 0 && <p style={{color: "#4ade80", fontSize: "0.9rem"}}>All clear!</p>}
            </div>
            <div>
              <h3 style={{ color: "#60a5fa", borderBottom: "1px solid #60a5fa", paddingBottom: "0.5rem", marginBottom: "1rem" }}>Fix This Month</h3>
              {thisMonth.map(r => <CtoCard key={r.id} row={r} />)}
              {thisMonth.length === 0 && <p style={{color: "#4ade80", fontSize: "0.9rem"}}>All clear!</p>}
            </div>
          </div>
        </div>
      ) : (
        <>
          <div className="metric-grid">
            {data.summaryMetrics.map((metric) => (
              <MetricCard key={metric.label} {...metric} />
            ))}
          </div>

          <NarrativeCard narrative={data.narrative} />
          <PriorityActionsCard actions={data.topActions} />
          <FindingTable rows={data.findingRows} />
        </>
      )}

      <TopFixesCard fixes={fixesForCard} />
    </section>
  );
}

export default OverviewPage;

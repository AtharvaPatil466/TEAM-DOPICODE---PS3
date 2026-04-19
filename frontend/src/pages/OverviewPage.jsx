import { useEffect, useState } from "react";
import MetricCard from "../components/cards/MetricCard";
import NarrativeCard from "../components/cards/NarrativeCard";
import PriorityActionsCard from "../components/cards/PriorityActionsCard";
import FindingTable from "../components/findings/FindingTable";
import { fetchDashboardData } from "../services/api";
import { StickyResultsBar, TopFixesCard } from "../components/ResultsAdditions";
import { SkeletonLine } from "../components/LoadingStates";

function OverviewPage() {
  const [data, setData] = useState(null);

  useEffect(() => {
    fetchDashboardData().then(setData);
  }, []);

  if (!data) {
    return (
      <section className="page">
        <div className="panel" style={{ textAlign: "center", padding: "4rem", borderColor: "var(--accent)" }}>
          <h3 style={{ color: "var(--text)" }}>Loading dashboard...</h3>
          <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem", marginTop: "1.5rem", maxWidth: 400, margin: "1.5rem auto 0" }}>
            <SkeletonLine width="100%" height={16} />
            <SkeletonLine width="80%" height={14} />
            <SkeletonLine width="60%" height={14} />
          </div>
        </div>
      </section>
    );
  }

  if (!data.findingRows || data.findingRows.length === 0) {
    return (
      <section className="page">
        <div className="panel" style={{ textAlign: "center", padding: "4rem" }}>
          <h3 style={{ color: "var(--text)" }}>No scan data available</h3>
          <p className="section-copy" style={{ marginTop: "1rem" }}>
            Go to <a href="/scan" style={{ color: "var(--accent)" }}>Scan Setup</a> and run a scan against a domain to see results here.
          </p>
        </div>
      </section>
    );
  }

  /* Adapter for StickyResultsBar */
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

  /* Adapter for TopFixesCard */
  const fixesForCard = (data.topActions || []).slice(0, 3).map((a, i) => ({
    asset_id: i,
    fix_description: a.detail || a.title,
    paths_broken: a.blocks_paths || 1,
  }));

  return (
    <section className="page overview-page">
      <StickyResultsBar results={resultsForBar} />

      <section className="hero-card page-intro">
        <div>
          <p className="eyebrow">Technical dashboard</p>
          <h2>Full scan results for {data.latestScan?.domain || "your target"}.</h2>
          <p>
            Deep dive into every finding, severity metric, and recommended remediation.
            For the executive summary, use the <a href="/cto" style={{ color: "var(--accent)" }}>CTO View</a>.
          </p>
        </div>
      </section>

      <div className="metric-grid">
        {data.summaryMetrics.map((metric) => (
          <MetricCard key={metric.label} {...metric} />
        ))}
      </div>

      <NarrativeCard narrative={data.narrative} />
      <PriorityActionsCard actions={data.topActions} />
      <FindingTable rows={data.findingRows} />
      <TopFixesCard fixes={fixesForCard} />
    </section>
  );
}

export default OverviewPage;

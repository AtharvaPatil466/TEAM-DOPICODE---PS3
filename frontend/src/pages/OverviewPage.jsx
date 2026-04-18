import { useEffect, useState } from "react";
import MetricCard from "../components/cards/MetricCard";
import NarrativeCard from "../components/cards/NarrativeCard";
import PriorityActionsCard from "../components/cards/PriorityActionsCard";
import FindingTable from "../components/findings/FindingTable";
import { fetchDashboardData } from "../services/api";

function OverviewPage() {
  const [data, setData] = useState(null);

  useEffect(() => {
    fetchDashboardData().then(setData);
  }, []);

  if (!data) {
    return <section className="page">Loading dashboard...</section>;
  }

  return (
    <section className="page overview-page">
      <section className="hero-card page-intro">
        <div>
          <p className="eyebrow">Executive dashboard</p>
          <h2>Here’s the shortest path from exposure to action.</h2>
          <p>
            The overview compresses technical scan output into the handful of signals a CTO or
            judge can absorb quickly: risk posture, urgency, and what to fix first.
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
    </section>
  );
}

export default OverviewPage;

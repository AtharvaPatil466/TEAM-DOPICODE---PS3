import { useEffect, useState } from "react";
import ReportSectionList from "../components/reports/ReportSectionList";
import { fetchDashboardData, reportPdfUrl } from "../services/api";

function ReportPage() {
  const [data, setData] = useState(null);

  useEffect(() => {
    fetchDashboardData().then(setData);
  }, []);

  if (!data) {
    return <section className="page">Preparing report view...</section>;
  }

  return (
    <section className="page">
      <section className="hero-card page-intro">
        <div>
          <p className="eyebrow">Deliverable layer</p>
          <h2>Export the story in a format leadership can act on quickly.</h2>
          <p>
            This final step translates the surfaced evidence, top risks, and recommended next
            steps into a compact remediation brief.
          </p>
        </div>
      </section>

      <div className="report-header">
        <div>
          <p className="eyebrow">Deliverable</p>
          <h2>CTO-ready remediation report</h2>
        </div>
        <button
          type="button"
          className="button primary"
          onClick={() => window.open(reportPdfUrl(), "_blank", "noopener,noreferrer")}
        >
          Export PDF
        </button>
      </div>

      <ReportSectionList sections={data.reportSections} />
    </section>
  );
}

export default ReportPage;

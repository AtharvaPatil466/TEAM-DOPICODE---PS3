import { useEffect, useState } from "react";
import ReportSectionList from "../components/reports/ReportSectionList";
import { fetchDashboardData } from "../services/api";

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
      <div className="report-header">
        <div>
          <p className="eyebrow">Deliverable</p>
          <h2>CTO-ready remediation report</h2>
        </div>
        <button type="button" className="button primary">
          Export PDF
        </button>
      </div>

      <ReportSectionList sections={data.reportSections} />
    </section>
  );
}

export default ReportPage;

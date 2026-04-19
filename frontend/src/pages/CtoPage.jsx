import { useEffect, useState } from "react";
import { fetchDashboardData, reportPdfUrl } from "../services/api";

const BUCKETS = [
  {
    id: "today",
    label: "Fix Today",
    sub: "Critical findings — exploitable right now. Page an engineer.",
    severities: ["Critical"],
    tint: "var(--critical)",
  },
  {
    id: "week",
    label: "Fix This Week",
    sub: "High-severity exposures — schedule a sprint item.",
    severities: ["High"],
    tint: "#fbbf24",
  },
  {
    id: "month",
    label: "Fix This Month",
    sub: "Medium-severity hardening work — queue for the next maintenance window.",
    severities: ["Medium", "Moderate"],
    tint: "#60a5fa",
  },
];

function Section({ bucket, rows }) {
  return (
    <div
      className="panel"
      style={{
        borderLeft: `4px solid ${bucket.tint}`,
        marginBottom: "1.25rem",
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
        <div>
          <p className="eyebrow" style={{ margin: 0 }}>{bucket.id.toUpperCase()}</p>
          <h2 style={{ marginTop: "0.25rem" }}>{bucket.label}</h2>
          <p className="section-copy" style={{ margin: 0 }}>{bucket.sub}</p>
        </div>
        <strong style={{ fontSize: "2rem", color: bucket.tint }}>{rows.length}</strong>
      </div>

      {rows.length === 0 ? (
        <p className="section-copy" style={{ marginTop: "1rem", opacity: 0.7 }}>
          Nothing in this bucket. Good.
        </p>
      ) : (
        <ol style={{ marginTop: "1rem", paddingLeft: "1.25rem" }}>
          {rows.map((row, i) => (
            <li key={row.id || i} style={{ marginBottom: "0.85rem", lineHeight: 1.5 }}>
              <div style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem", alignItems: "baseline" }}>
                <strong>{row.asset}</strong>
                <span className="chip" style={{ fontSize: "0.75rem" }}>{row.kind}</span>
                {row.in_kev && (
                  <span className="chip" style={{ fontSize: "0.75rem", borderColor: "var(--critical)", color: "var(--critical)" }}>
                    KEV
                  </span>
                )}
              </div>
              <p className="section-copy" style={{ margin: "0.25rem 0 0" }}>{row.action || row.reason}</p>
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}

function CtoPage() {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchDashboardData().then(setData).catch((e) => setError(e.message));
  }, []);

  if (error) {
    return <section className="page"><div className="panel">Failed to load: {error}</div></section>;
  }
  if (!data) {
    return <section className="page"><div className="panel">Loading CTO view…</div></section>;
  }

  if (!data.findingRows || data.findingRows.length === 0) {
    return (
      <section className="page">
        <div className="panel" style={{ textAlign: "center", padding: "4rem" }}>
          <h3 style={{ color: "var(--text)" }}>No findings to show</h3>
          <p className="section-copy" style={{ marginTop: "1rem" }}>
            Run a scan from <a href="/scan" style={{ color: "var(--accent)" }}>Scan Setup</a> to populate the CTO view with actionable insights.
          </p>
        </div>
      </section>
    );
  }

  const rows = data.findingRows || [];
  const buckets = BUCKETS.map((b) => ({
    ...b,
    rows: rows.filter((r) => b.severities.includes(r.severity)),
  }));
  const totalActionable = buckets.reduce((acc, b) => acc + b.rows.length, 0);

  return (
    <section className="page">
      <section className="hero-card page-intro">
        <div>
          <p className="eyebrow">CTO view</p>
          <h2>What to fix, in order.</h2>
          <p>
            {totalActionable === 0
              ? "Nothing actionable right now. Rerun a scan when your surface changes."
              : `${totalActionable} finding(s) grouped by urgency — start at the top and work down.`}
          </p>
          <div className="cta-row" style={{ marginTop: "0.75rem" }}>
            <a
              className="button primary"
              href={`${reportPdfUrl()}?style=executive`}
              target="_blank"
              rel="noreferrer"
            >
              Download 2-page executive PDF
            </a>
          </div>
        </div>
      </section>

      {buckets.map((b) => (
        <Section key={b.id} bucket={b} rows={b.rows} />
      ))}
    </section>
  );
}

export default CtoPage;

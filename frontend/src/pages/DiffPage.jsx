import { useEffect, useState } from "react";
import { fetchScanDiff, fetchScanHistory } from "../services/api";

function DiffPage() {
  const [scans, setScans] = useState([]);
  const [beforeId, setBeforeId] = useState("");
  const [afterId, setAfterId] = useState("");
  const [diff, setDiff] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchScanHistory().then((history) => {
      setScans(history || []);
      if (history && history.length >= 2) {
        setBeforeId(String(history[1].scan_id));
        setAfterId(String(history[0].scan_id));
      }
    }).catch(() => {});
  }, []);

  const handleCompare = async (e) => {
    e.preventDefault();
    if (!beforeId || !afterId) return;
    setLoading(true);
    setError(null);
    try {
      const result = await fetchScanDiff(parseInt(beforeId), parseInt(afterId));
      setDiff(result);
    } catch (err) {
      setError(err.message || "Failed to fetch diff.");
    }
    setLoading(false);
  };

  const scanLabel = (s) =>
    `#${s.scan_id} — ${s.domain} (${s.total_assets} assets)`;

  return (
    <section className="page">
      <section className="hero-card page-intro">
        <div>
          <p className="eyebrow">Posture tracking</p>
          <h2>Scan Diff Timeline</h2>
          <p>
            Compare two scans side-by-side. See which assets appeared or disappeared,
            which attack paths broke or emerged, and how overall risk shifted.
          </p>
        </div>
      </section>

      <div className="panel">
        <form className="scan-form" onSubmit={handleCompare}>
          <div className="toggle-row">
            <label>
              Before Scan
              <select value={beforeId} onChange={(e) => setBeforeId(e.target.value)} required>
                <option value="">Select a scan...</option>
                {scans.map((s) => (
                  <option key={s.scan_id} value={s.scan_id}>{scanLabel(s)}</option>
                ))}
              </select>
            </label>
            <label>
              After Scan
              <select value={afterId} onChange={(e) => setAfterId(e.target.value)} required>
                <option value="">Select a scan...</option>
                {scans.map((s) => (
                  <option key={s.scan_id} value={s.scan_id}>{scanLabel(s)}</option>
                ))}
              </select>
            </label>
          </div>
          <div className="cta-row">
            <button type="submit" className="button primary" disabled={loading || !beforeId || !afterId}>
              {loading ? "Comparing..." : "Compare Scans"}
            </button>
            {scans.length < 2 && (
              <span className="chip" style={{ borderColor: "#fbbf24", color: "#fbbf24" }}>
                Run at least 2 scans to use this feature
              </span>
            )}
          </div>
        </form>
      </div>

      {error && (
        <div className="panel" style={{ borderColor: "var(--critical)" }}>
          <p style={{ color: "var(--critical)" }}>{error}</p>
        </div>
      )}

      {diff && (
        <>
          <div className="panel">
            <p className="eyebrow">Summary</p>
            <h2 style={{ fontSize: "1.4rem" }}>{diff.summary}</h2>

            <div
              className="metric-grid"
              style={{ marginTop: "1.25rem", gridTemplateColumns: "repeat(4, 1fr)" }}
            >
              <div className="metric-card">
                <p>Assets Added</p>
                <strong style={{ color: "#4ade80" }}>{diff.assets_added?.length || 0}</strong>
              </div>
              <div className="metric-card">
                <p>Assets Removed</p>
                <strong style={{ color: "var(--critical)" }}>{diff.assets_removed?.length || 0}</strong>
              </div>
              <div className="metric-card">
                <p>Risk Delta</p>
                <strong
                  style={{
                    color: diff.risk_delta > 0 ? "var(--critical)" : diff.risk_delta < 0 ? "#4ade80" : "var(--muted)",
                  }}
                >
                  {diff.risk_delta > 0 ? "+" : ""}{diff.risk_delta?.toFixed(1) || "0.0"}
                </strong>
              </div>
              <div className="metric-card">
                <p>TTB Delta (min)</p>
                <strong>
                  {diff.time_to_breach_delta_minutes
                    ? `${diff.time_to_breach_delta_minutes > 0 ? "+" : ""}${diff.time_to_breach_delta_minutes}`
                    : "—"}
                </strong>
              </div>
            </div>
          </div>

          <div className="metric-grid" style={{ gridTemplateColumns: "1fr 1fr" }}>
            <div className="panel">
              <p className="eyebrow">Paths Broken</p>
              {diff.paths_broken?.length > 0 ? (
                <div style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem", marginTop: "0.75rem" }}>
                  {diff.paths_broken.map((pid) => (
                    <span key={pid} className="chip" style={{ borderColor: "#4ade80", color: "#4ade80" }}>
                      ✓ {pid}
                    </span>
                  ))}
                </div>
              ) : (
                <p className="section-copy">No paths broken.</p>
              )}
            </div>
            <div className="panel">
              <p className="eyebrow">Paths Introduced</p>
              {diff.paths_introduced?.length > 0 ? (
                <div style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem", marginTop: "0.75rem" }}>
                  {diff.paths_introduced.map((pid) => (
                    <span key={pid} className="chip" style={{ borderColor: "var(--critical)", color: "var(--critical)" }}>
                      ⚠ {pid}
                    </span>
                  ))}
                </div>
              ) : (
                <p className="section-copy">No new paths introduced.</p>
              )}
            </div>
          </div>

          {diff.assets_removed?.length > 0 && (
            <div className="panel">
              <p className="eyebrow">Assets Removed ({diff.assets_removed.length})</p>
              <div className="action-list" style={{ marginTop: "0.75rem" }}>
                {diff.assets_removed.slice(0, 8).map((asset, i) => (
                  <div key={i} className="action-card">
                    <h3>{asset.label}</h3>
                    <p className="section-copy">Risk {asset.risk_score} · {asset.asset_type} · {asset.exposure}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {diff.edges_added?.length > 0 && (
            <div className="panel">
              <p className="eyebrow">New Edges ({diff.edges_added.length})</p>
              <div className="action-list" style={{ marginTop: "0.75rem" }}>
                {diff.edges_added.slice(0, 8).map((edge, i) => (
                  <div key={i} className="action-card">
                    <h3>{edge.relationship || "edge"}</h3>
                    <p className="section-copy">{edge.rationale || `${edge.source_id} → ${edge.target_id}`}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </section>
  );
}

export default DiffPage;

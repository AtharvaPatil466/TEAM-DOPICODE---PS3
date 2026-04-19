import { useEffect, useState } from "react";
import { fetchDashboardData, fetchSimulate } from "../services/api";

function ValidationCard({ title, summary, highlight }) {
  const s = summary || { confirmed: 0, partial: 0, unverified: 0, total: 0 };
  return (
    <div
      style={{
        border: `1px solid ${highlight ? "#22c55e" : "#1f3a5c"}`,
        borderRadius: "10px",
        padding: "1rem 1.25rem",
        background: highlight ? "rgba(34,197,94,0.08)" : "rgba(11,18,32,0.5)"
      }}
    >
      <p className="eyebrow" style={{ margin: 0 }}>
        {title}
      </p>
      <div style={{ display: "flex", alignItems: "baseline", gap: "0.5rem", marginTop: "0.35rem" }}>
        <strong style={{ fontSize: "1.6rem", color: "#e6f0ff" }}>{s.total}</strong>
        <span style={{ color: "#93a3b8" }}>path{s.total === 1 ? "" : "s"}</span>
      </div>
      <div style={{ marginTop: "0.5rem", fontFamily: "monospace", fontSize: "0.85rem" }}>
        <span style={{ color: "#22c55e" }}>{s.confirmed} CONFIRMED</span>
        <br />
        <span style={{ color: "#fbbf24" }}>{s.partial} PARTIAL</span>
        <br />
        <span style={{ color: "#6b7280" }}>{s.unverified} UNVERIFIED</span>
      </div>
    </div>
  );
}

function SimulatePage() {
  const [data, setData] = useState(null);
  const [selectedAssets, setSelectedAssets] = useState([]);
  const [selectedCves, setSelectedCves] = useState([]);
  const [persona, setPersona] = useState("criminal");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchDashboardData().then(setData);
  }, []);

  const toggleAsset = (id) => {
    setSelectedAssets((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]
    );
  };

  const toggleCve = (cveId) => {
    setSelectedCves((prev) =>
      prev.includes(cveId) ? prev.filter((x) => x !== cveId) : [...prev, cveId]
    );
  };

  const handleSimulate = async () => {
    setLoading(true);
    try {
      const res = await fetchSimulate({
        patchedAssetIds: selectedAssets,
        patchedCveIds: selectedCves,
        persona,
      });
      setResult(res);
    } catch (err) {
      console.error(err);
    }
    setLoading(false);
  };

  if (!data || !data.latestScan) {
    return <section className="page">Loading asset inventory...</section>;
  }

  if (!data.findingRows || data.findingRows.length === 0) {
    return (
      <section className="page">
        <div className="panel" style={{ textAlign: "center", padding: "4rem" }}>
          <h3 style={{ color: "var(--text)" }}>No assets to simulate</h3>
          <p className="section-copy" style={{ marginTop: "1rem" }}>
            Run a scan from <a href="/scan" style={{ color: "var(--accent)" }}>Scan Setup</a> first, then come back to simulate remediation effects.
          </p>
        </div>
      </section>
    );
  }

  // Collect all CVEs from findings
  const allCves = [];
  data.findingRows.forEach((row) => {
    const match = row.reason?.match(/CVE-\d{4}-\d+/);
    if (match && !allCves.includes(match[0])) allCves.push(match[0]);
  });

  return (
    <section className="page">
      <section className="hero-card page-intro">
        <div>
          <p className="eyebrow">What-if analysis</p>
          <h2>Remediation Simulator</h2>
          <p>
            Select assets to "patch" or CVEs to "fix", then simulate the effect on
            modeled attack paths. See which paths break and how time-to-breach shifts.
          </p>
        </div>
      </section>

      <div className="panel">
        <p className="eyebrow">Select assets to patch</p>
        <div style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem", marginTop: "0.75rem" }}>
          {data.findingRows.map((row) => {
            const assetId = parseInt(row.id.replace("F-", "")) - 100;
            const isSelected = selectedAssets.includes(assetId);
            return (
              <button
                key={row.id}
                type="button"
                className={`chip ${isSelected ? "chip-live" : ""}`}
                onClick={() => toggleAsset(assetId)}
                style={{
                  cursor: "pointer",
                  background: isSelected ? "rgba(255,255,255,0.12)" : undefined,
                  borderColor: isSelected ? "var(--accent)" : undefined,
                }}
              >
                {isSelected ? "✓ " : ""}{row.asset}
              </button>
            );
          })}
        </div>
      </div>

      {allCves.length > 0 && (
        <div className="panel">
          <p className="eyebrow">Select CVEs to patch</p>
          <div style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem", marginTop: "0.75rem" }}>
            {allCves.map((cveId) => {
              const isSelected = selectedCves.includes(cveId);
              return (
                <button
                  key={cveId}
                  type="button"
                  className={`chip ${isSelected ? "chip-live" : ""}`}
                  onClick={() => toggleCve(cveId)}
                  style={{
                    cursor: "pointer",
                    background: isSelected ? "rgba(255,93,93,0.15)" : undefined,
                    borderColor: isSelected ? "var(--critical)" : undefined,
                    color: isSelected ? "var(--critical)" : undefined,
                  }}
                >
                  {isSelected ? "✓ " : ""}{cveId}
                </button>
              );
            })}
          </div>
        </div>
      )}

      <div className="panel">
        <p className="eyebrow">Attacker persona</p>
        <div style={{ display: "flex", gap: "0.75rem", marginTop: "0.75rem" }}>
          {["script_kiddie", "criminal", "apt"].map((p) => (
            <button
              key={p}
              type="button"
              className={`chip ${persona === p ? "chip-live" : ""}`}
              onClick={() => setPersona(p)}
              style={{ cursor: "pointer" }}
            >
              {p === "script_kiddie" ? "🧒 Script Kiddie" : p === "criminal" ? "💀 Criminal" : "🎯 APT"}
            </button>
          ))}
        </div>
      </div>

      <div className="cta-row">
        <button
          type="button"
          className="button primary"
          onClick={handleSimulate}
          disabled={loading || (selectedAssets.length === 0 && selectedCves.length === 0)}
        >
          {loading ? "Simulating..." : "Run Simulation"}
        </button>
        {selectedAssets.length + selectedCves.length > 0 && (
          <span className="chip">
            {selectedAssets.length} asset(s), {selectedCves.length} CVE(s) selected
          </span>
        )}
      </div>

      {result && (
        <div className="panel" style={{ borderColor: "var(--accent)" }}>
          <p className="eyebrow">Simulation results</p>
          <h2 style={{ fontSize: "1.8rem" }}>{result.summary}</h2>

          {(result.before || result.after) && (
            <div style={{ marginTop: "1.25rem" }}>
              <p className="eyebrow">Path validation — before vs. after</p>
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "1fr auto 1fr",
                  alignItems: "center",
                  gap: "1rem",
                  marginTop: "0.75rem"
                }}
              >
                <ValidationCard title="Before patch" summary={result.before} />
                <span style={{ fontSize: "1.5rem", color: "#93a3b8" }}>→</span>
                <ValidationCard title="After patch" summary={result.after} highlight />
              </div>
              {result.delta_summary && (
                <p
                  style={{
                    marginTop: "1rem",
                    fontWeight: 600,
                    fontSize: "1rem",
                    color: "#e6f0ff",
                    lineHeight: 1.5
                  }}
                >
                  {result.delta_summary}
                </p>
              )}
            </div>
          )}

          <div className="metric-grid" style={{ marginTop: "1.25rem", gridTemplateColumns: "repeat(3, 1fr)" }}>
            <div className="metric-card">
              <p>Paths blocked</p>
              <strong style={{ color: "#4ade80" }}>{result.blocked_path_ids?.length || 0}</strong>
            </div>
            <div className="metric-card">
              <p>New paths introduced</p>
              <strong style={{ color: result.introduced_path_ids?.length > 0 ? "var(--critical)" : "#4ade80" }}>
                {result.introduced_path_ids?.length || 0}
              </strong>
            </div>
            <div className="metric-card">
              <p>Time-to-breach delta</p>
              <strong>
                {result.time_to_breach_delta_minutes
                  ? `${result.time_to_breach_delta_minutes > 0 ? "+" : ""}${result.time_to_breach_delta_minutes} min`
                  : "N/A"}
              </strong>
            </div>
          </div>

          {result.blocked_path_ids?.length > 0 && (
            <div style={{ marginTop: "1rem" }}>
              <p className="eyebrow">Blocked paths</p>
              <div style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem", marginTop: "0.5rem" }}>
                {result.blocked_path_ids.map((pid) => (
                  <span key={pid} className="chip" style={{ borderColor: "#4ade80", color: "#4ade80" }}>
                    ✓ {pid}
                  </span>
                ))}
              </div>
            </div>
          )}

          {result.simulated && result.simulated.hops?.length > 0 && (
            <div style={{ marginTop: "1.5rem" }}>
              <p className="eyebrow">Remaining attack path</p>
              <div className="timeline" style={{ marginTop: "0.75rem" }}>
                {result.simulated.hops.map((hop, i) => (
                  <article key={i} className="timeline-step">
                    <span>{String(i + 1).padStart(2, "0")}</span>
                    <div>
                      <h3>{hop.label}</h3>
                      <p>{hop.rationale || hop.relationship || "—"}</p>
                      {hop.vulnerability && (
                        <p style={{ fontSize: "0.85rem", color: "var(--critical)" }}>
                          {hop.vulnerability} {hop.cvss ? `(CVSS ${hop.cvss})` : ""}
                        </p>
                      )}
                    </div>
                  </article>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </section>
  );
}

export default SimulatePage;

import { useState } from "react";
import { useNavigate } from "react-router-dom";

const scanHighlights = [
  { label: "Coverage", value: "DNS, ports, storage, panels" },
  { label: "Output", value: "Risk-ranked executive digest" },
  { label: "Time to insight", value: "Under 2 minutes in demo mode" }
];

const scanModes = [
  { title: "Fast sweep", detail: "Enumerate public assets and spotlight the loudest exposures first." },
  { title: "Attack-path view", detail: "Translate exposed internet assets into likely internal business impact." }
];

function ScanPage() {
  const [target, setTarget] = useState("shadowtrace-demo.xyz");
  const [isScanning, setIsScanning] = useState(false);
  const navigate = useNavigate();

  const handleScan = (e) => {
    e.preventDefault();
    setIsScanning(true);
    // Simulate a scan delay then redirect
    setTimeout(() => {
      setIsScanning(false);
      navigate("/overview");
    }, 1500);
  };

  return (
    <section className="page scan-page">
      <section className="hero-card hero-grid scan-hero">
        <div className="hero-copy">
          <p className="eyebrow">Launch scan</p>
          <h2>DEFINE THE TRACE VECTOR.</h2>
          <p>
            Atlas maps exposed internet assets, spots the dangerous footholds, and reframes raw
            scan noise into a remediation sequence that feels decisive.
          </p>

          <div className="hero-stat-row">
            {scanHighlights.map((item) => (
              <article key={item.label} className="hero-stat">
                <span>{item.label}</span>
                <strong>{item.value}</strong>
              </article>
            ))}
          </div>
        </div>

        <div className="hero-side">
          <div className="scan-stack">
            {scanModes.map((mode) => (
              <article key={mode.title} className="scan-mode-card">
                <p className="eyebrow">Mode</p>
                <h3>{mode.title}</h3>
                <p>{mode.detail}</p>
              </article>
            ))}
          </div>
        </div>
      </section>

      <div className="scan-grid">
        <section className="panel scan-panel">
          <div className="panel-header">
            <div>
              <p className="eyebrow">Target configuration</p>
              <h2>Initiate external mapping</h2>
            </div>
            <span className="chip chip-live">Demo-ready</span>
          </div>

          <form onSubmit={handleScan} className="scan-form">
            <label>
              Primary domain
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="example.com"
              />
            </label>

            <div className="toggle-row">
              <article className="toggle-card">
                <div className="toggle-icon">01</div>
                <div>
                  <strong>External footprint</strong>
                  <p>Subdomains, exposed services, storage, and admin surfaces.</p>
                </div>
              </article>

              <article className="toggle-card">
                <div className="toggle-icon">02</div>
                <div>
                  <strong>Impact projection</strong>
                  <p>Generate a plausible path from exposure to business-side blast radius.</p>
                </div>
              </article>
            </div>

            <div className="cta-row">
              <button type="submit" className="button primary" disabled={isScanning}>
                {isScanning ? "Scanning target..." : "Start scan"}
              </button>
              <button type="button" className="button secondary" onClick={() => navigate("/overview")}>
                View seeded dashboard
              </button>
            </div>
          </form>
        </section>

        <aside className="panel scan-brief">
          <p className="eyebrow">What you’ll get</p>
          <h2>Outputs built for speed and clarity</h2>
          <div className="brief-list">
            <article className="brief-item">
              <strong>Surface map</strong>
              <p>Visualize exposed assets and the paths linking internet presence to crown-jewel systems.</p>
            </article>
            <article className="brief-item">
              <strong>Prioritized findings</strong>
              <p>Rank issues by practical risk, not just raw technical severity labels.</p>
            </article>
            <article className="brief-item">
              <strong>CTO-ready report</strong>
              <p>Package the narrative into an exportable summary with recommended first moves.</p>
            </article>
          </div>
        </aside>
      </div>
    </section>
  );
}

export default ScanPage;

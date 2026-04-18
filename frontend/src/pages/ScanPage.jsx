import { Link } from "react-router-dom";

function ScanPage() {
  return (
    <section className="page scan-page">
      <div className="hero-card">
        <p className="eyebrow">Root Domain Intake</p>
        <h2>Map the public footprint first, then show the likely blast radius.</h2>
        <p>
          This frontend is built for the organiser brief: start with a root domain, discover public
          exposure, explain the risk clearly, and extend that into an internal impact story.
        </p>

        <form className="scan-form">
          <label>
            Root domain
            <input type="text" value="atlas-demo.com" readOnly />
          </label>

          <label>
            Scan depth
            <select defaultValue="full">
              <option value="quick">Quick</option>
              <option value="standard">Standard</option>
              <option value="full">Full</option>
            </select>
          </label>

          <div className="toggle-row">
            <label className="toggle-card">
              <input type="checkbox" defaultChecked readOnly />
              <span>Check storage exposure</span>
            </label>

            <label className="toggle-card">
              <input type="checkbox" defaultChecked readOnly />
              <span>Project internal impact</span>
            </label>
          </div>
        </form>

        <div className="cta-row">
          <Link className="button primary" to="/overview">
            View overview
          </Link>
          <Link className="button secondary" to="/surface-map">
            Open surface map
          </Link>
        </div>
      </div>
    </section>
  );
}

export default ScanPage;

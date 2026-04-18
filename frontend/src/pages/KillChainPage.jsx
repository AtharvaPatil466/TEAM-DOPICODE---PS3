import { useEffect, useState } from "react";
import { fetchDashboardData } from "../services/api";

function KillChainPage() {
  const [data, setData] = useState(null);

  useEffect(() => {
    fetchDashboardData().then(setData);
  }, []);

  if (!data) {
    return <section className="page">Projecting attack chain...</section>;
  }

  return (
    <section className="page">
      <section className="hero-card page-intro">
        <div>
          <p className="eyebrow">Impact projection</p>
          <h2>Move from isolated findings to a believable attack story.</h2>
          <p>
            The goal here is not fearmongering. It is showing a plausible progression from exposed
            asset to operational consequence so remediation feels urgent and concrete.
          </p>
        </div>
      </section>

      <div className="panel">
        <p className="eyebrow">Innovation layer</p>
        <h2>External exposure to internal impact</h2>
        <p className="section-copy">
          This page is where your demo differentiates itself: the frontend turns a list of exposed
          assets into a plausible business-impact narrative.
        </p>

        <div className="timeline">
          {data.killChainSteps.map((step, index) => (
            <article key={step.title} className="timeline-step">
              <span>{String(index + 1).padStart(2, "0")}</span>
              <div>
                <h3>{step.title}</h3>
                <p>{step.summary}</p>
              </div>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}

export default KillChainPage;

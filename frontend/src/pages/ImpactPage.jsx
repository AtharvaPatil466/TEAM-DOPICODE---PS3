import { useEffect, useState } from "react";
import { fetchDashboardData, replayLatestDemo } from "../services/api";

function ImpactPage() {
  const [data, setData] = useState(null);
  const [expandedScenario, setExpandedScenario] = useState(null);

  useEffect(() => {
    fetchDashboardData().then(setData);
  }, []);

  if (!data) {
    return <section className="page">Projecting financial impact...</section>;
  }

  const impact = data.impactData;
  const scenarios = data.impactScenarios;

  if (!impact || !scenarios) {
    return (
      <section className="page">
        <div className="panel">
          <h2>No impact data available.</h2>
          <p className="section-copy">Ensure you have run the latest demo seed.</p>
        </div>
      </section>
    );
  }

  const { regulatory_exposure, operational_loss, executive_advisory } = impact;

  return (
    <section className="page">
      <div className="impact-grid">
        <div className="hero-card breach-hero">
          <p className="eyebrow">Estimated Breach Cost</p>
          <div className="rupee-big">{impact.total_formatted}</div>
          <p>If the discovered public attack surface is exploited.</p>
        </div>
      </div>

      <div className="impact-grid">
        <div className="panel">
          <p className="eyebrow">Regulatory Exposure</p>
          <h2>{regulatory_exposure.min_formatted} - {regulatory_exposure.max_formatted}</h2>
          <p className="section-copy">Based on {regulatory_exposure.applicable_law}. Tier: {regulatory_exposure.penalty_tier}</p>
        </div>
      </div>

      <div className="panel">
        <p className="eyebrow">Operational Loss Breakdown</p>
        <div className="metric-grid">
          <div className="metric-card">
            <p>Downtime</p>
            <strong>₹{(operational_loss.downtime.max_inr / 100000).toFixed(1)}L</strong>
            <p className="section-copy">Est. MTTR: {operational_loss.downtime.mttr_hours_high} hrs</p>
          </div>
          <div className="metric-card">
            <p>Incident Response</p>
            <strong>₹{(operational_loss.incident_response.max_inr / 100000).toFixed(1)}L</strong>
          </div>
          <div className="metric-card">
            <p>Customer Churn</p>
            <strong>₹{(operational_loss.customer_churn.max_inr / 100000).toFixed(1)}L</strong>
          </div>
        </div>
      </div>

      <div className="panel advisory-panel">
        <p className="eyebrow">Executive Advisory</p>
        <div className="section-copy">
          {executive_advisory ? executive_advisory.split("\n").map((line, i) => <p key={i}>{line}</p>) : "Analyzing..."}
        </div>
      </div>

      <div className="panel">
        <p className="eyebrow">Attack Scenario Matrix</p>
        <div className="action-list">
          {scenarios.scenarios.map((scenario) => (
            <div key={scenario.scenario_id} className="action-card scenario-card" onClick={() => setExpandedScenario(expandedScenario === scenario.scenario_id ? null : scenario.scenario_id)}>
              <div className="cta-row">
                <div>
                  <h3>{scenario.name}</h3>
                  <p className="section-copy">{scenario.path_count} possible paths</p>
                </div>
                <div style={{textAlign: "right"}}>
                  <strong style={{color: "var(--critical)"}}>₹{(scenario.total_exposure_max_inr / 10000000).toFixed(2)} Cr risk</strong><br />
                  <span className="section-copy" style={{fontSize: "0.85rem"}}>Vs ₹{(scenario.prevention_cost_inr / 100000).toFixed(1)}L fix</span>
                </div>
              </div>
              {expandedScenario === scenario.scenario_id && (
                <div className="detail-list" style={{marginTop: "1rem"}}>
                  <p><strong>Attacker Skill:</strong> {scenario.attacker_skill}</p>
                  <p><strong>Description:</strong> {scenario.description}</p>
                  <p><strong>Data at Risk:</strong> {scenario.data_at_risk.join(", ")}</p>
                  <p><strong>Prevention:</strong> {scenario.prevention_summary}</p>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

export default ImpactPage;

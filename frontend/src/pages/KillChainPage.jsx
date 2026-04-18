import { useEffect, useState } from "react";
import { fetchDashboardData } from "../services/api";
import { generateNarrative, buildRuleExplanationPrompt } from "../services/llm";

function KillChainPage() {
  const [data, setData] = useState(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [modalContent, setModalContent] = useState(null);
  const [modalLoading, setModalLoading] = useState(false);

  useEffect(() => {
    fetchDashboardData().then(setData);
  }, []);

  const openWhyThisHop = async (step) => {
    if (!step.ruleId || !step.technique) return;

    setModalOpen(true);
    setModalLoading(true);
    setModalContent(null);

    const prompt = buildRuleExplanationPrompt(step.ruleId, step.technique);
    const explanation = await generateNarrative(prompt);

    // Fallback if LLM fails
    const fallback = `Rule ${step.ruleId} maps to ${step.technique}. This edge is valid when the target condition is met, enabling lateral movement or privilege escalation in an attack chain.`;

    setModalContent({
      title: `Why ${step.ruleId}?`,
      technique: step.technique,
      explanation: explanation || fallback
    });
    setModalLoading(false);
  };

  const closeModal = () => {
    setModalOpen(false);
    setModalContent(null);
  };

  if (!data) {
    return <section className="page">Projecting attack chain...</section>;
  }

  const pathConfidence = data.killChainSteps.find((s) => s.pathConfidence)?.pathConfidence || null;
  const confidenceStyle = {
    CONFIRMED: { color: "#86efac", bg: "rgba(34, 197, 94, 0.12)", border: "rgba(34, 197, 94, 0.4)", label: "TCP-verified end-to-end" },
    PARTIAL:   { color: "#fbbf24", bg: "rgba(251, 191, 36, 0.12)", border: "rgba(251, 191, 36, 0.4)", label: "Partially reachable" },
    UNVERIFIED:{ color: "#f87171", bg: "rgba(248, 113, 113, 0.12)", border: "rgba(248, 113, 113, 0.4)", label: "Unverified — lab unreachable" }
  };
  const pathBadge = pathConfidence ? confidenceStyle[pathConfidence] : null;

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
        {pathBadge && (
          <div
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "8px",
              marginBottom: "12px",
              padding: "6px 12px",
              borderRadius: "6px",
              background: pathBadge.bg,
              border: `1px solid ${pathBadge.border}`,
              color: pathBadge.color,
              fontSize: "0.8rem",
              fontWeight: 600,
              letterSpacing: "0.02em"
            }}
          >
            <span>●</span>
            <span>{pathConfidence}</span>
            <span style={{ fontWeight: 400, opacity: 0.8 }}>— {pathBadge.label}</span>
          </div>
        )}
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
                {step.ruleId && step.technique && (
                  <button
                    type="button"
                    className="link-button"
                    onClick={() => openWhyThisHop(step)}
                    style={{
                      marginTop: "8px",
                      background: "none",
                      border: "none",
                      color: "#5d9eff",
                      cursor: "pointer",
                      fontSize: "0.85rem",
                      textDecoration: "underline",
                      padding: 0
                    }}
                  >
                    Why this hop? ({step.ruleId} → {step.technique})
                  </button>
                )}
                {step.probeSuccess !== undefined && step.probeSuccess !== null && (
                  <span
                    title={step.probeError || "TCP probe succeeded"}
                    style={{
                      marginLeft: "12px",
                      fontSize: "0.7rem",
                      color: step.probeSuccess ? "#86efac" : "#f87171",
                      background: step.probeSuccess ? "rgba(34,197,94,0.1)" : "rgba(248,113,113,0.1)",
                      border: `1px solid ${step.probeSuccess ? "rgba(34,197,94,0.35)" : "rgba(248,113,113,0.35)"}`,
                      padding: "2px 8px",
                      borderRadius: "4px",
                      fontFamily: "monospace"
                    }}
                  >
                    {step.probeSuccess ? "✓" : "✗"} :{step.probePort ?? "?"}
                    {step.probeLatencyMs != null && ` ${step.probeLatencyMs.toFixed(1)}ms`}
                  </span>
                )}
                {step.hasLlmRationale && (
                  <span
                    style={{
                      marginLeft: "12px",
                      fontSize: "0.75rem",
                      color: "#7dd3fc",
                      background: "rgba(125, 211, 252, 0.1)",
                      padding: "2px 8px",
                      borderRadius: "4px"
                    }}
                  >
                    AI-enhanced
                  </span>
                )}
              </div>
            </article>
          ))}
        </div>
      </div>

      {/* Why This Hop Modal */}
      {modalOpen && (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: "rgba(0, 0, 0, 0.7)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 1000
          }}
          onClick={closeModal}
        >
          <div
            style={{
              background: "#0b1220",
              border: "1px solid #1f3a5c",
              borderRadius: "12px",
              padding: "24px",
              maxWidth: "480px",
              width: "90%",
              boxShadow: "0 20px 60px rgba(0, 0, 0, 0.5)"
            }}
            onClick={(e) => e.stopPropagation()}
          >
            {modalLoading ? (
              <div style={{ textAlign: "center", padding: "20px" }}>
                <p>Analyzing rule context...</p>
              </div>
            ) : modalContent ? (
              <>
                <h3 style={{ margin: "0 0 8px 0", color: "#e6f0ff" }}>{modalContent.title}</h3>
                <p
                  style={{
                    margin: "0 0 16px 0",
                    fontSize: "0.85rem",
                    color: "#7dd3fc",
                    background: "rgba(125, 211, 252, 0.1)",
                    padding: "4px 12px",
                    borderRadius: "4px",
                    display: "inline-block"
                  }}
                >
                  MITRE {modalContent.technique}
                </p>
                <p style={{ margin: "0 0 20px 0", lineHeight: "1.6", color: "#cfd8e6" }}>
                  {modalContent.explanation}
                </p>
                <button
                  type="button"
                  className="button primary"
                  onClick={closeModal}
                  style={{ width: "100%" }}
                >
                  Close
                </button>
              </>
            ) : null}
          </div>
        </div>
      )}
    </section>
  );
}

export default KillChainPage;

import { useState, useEffect } from "react";
import { generateNarrative } from "../../services/llm";

function NarrativeCard({ narrative }) {
  const [data, setData] = useState({ text: narrative?.fallback || narrative, loading: !!narrative?.prompt });

  useEffect(() => {
    let mounted = true;
    if (narrative?.prompt) {
      generateNarrative(narrative.prompt).then((res) => {
        if (mounted && res) {
          setData({ text: res, loading: false });
        } else if (mounted) {
          setData(prev => ({ ...prev, loading: false })); // Use fallback
        }
      });
    }
    return () => { mounted = false; };
  }, [narrative]);

  return (
    <section className="panel narrative-card">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
        <p className="eyebrow">Threat Narrative</p>
        {data.loading && (
          <span style={{ fontSize: "0.75rem", color: "#7dd3fc", background: "rgba(125, 211, 252, 0.1)", padding: "2px 8px", borderRadius: "4px", animation: "pulse 2s infinite" }}>
            AI generating...
          </span>
        )}
      </div>
      <h2>The story judges should understand in 10 seconds</h2>
      <p style={{ minHeight: "60px", opacity: data.loading ? 0.6 : 1, transition: "opacity 0.3s" }}>
        {data.text}
      </p>
      <div className="narrative-points">
        <span>Exposure</span>
        <span>Evidence</span>
        <span>Recommended move</span>
      </div>
    </section>
  );
}

export default NarrativeCard;

import { useState, useEffect } from "react";
import { generateNarrative } from "../../services/llm";

function ReportSectionBlock({ section }) {
  const [data, setData] = useState({ text: section.body, loading: !!section.prompt });

  useEffect(() => {
    let mounted = true;
    if (section.prompt) {
      generateNarrative(section.prompt).then((res) => {
        if (mounted && res) {
          setData({ text: res, loading: false });
        } else if (mounted) {
          setData(prev => ({ ...prev, loading: false }));
        }
      });
    }
    return () => { mounted = false; };
  }, [section]);

  return (
    <article className="panel report-card">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
        <p className="eyebrow">Report block</p>
        {data.loading && (
          <span style={{ fontSize: "0.75rem", color: "#7dd3fc", background: "rgba(125, 211, 252, 0.1)", padding: "2px 8px", borderRadius: "4px", animation: "pulse 2s infinite" }}>
            AI rewriting narrative...
          </span>
        )}
      </div>
      <h2>{section.heading}</h2>
      <p style={{ opacity: data.loading ? 0.6 : 1, transition: "opacity 0.3s" }}>{data.text}</p>
    </article>
  );
}

function ReportSectionList({ sections }) {
  return (
    <section className="report-stack">
      {sections.map((section) => (
        <ReportSectionBlock key={section.heading} section={section} />
      ))}
    </section>
  );
}

export default ReportSectionList;

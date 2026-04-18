import { useCallback, useEffect, useState } from "react";
import useToast from "../hooks/useToast";

const API = "http://localhost:8000";

const STYLE_ID = "pdf-btn-spin";
function ensureSpinKeyframe() {
  if (document.getElementById(STYLE_ID)) return;
  const el = document.createElement("style");
  el.id = STYLE_ID;
  el.textContent = `@keyframes pdfSpin { to { transform: rotate(360deg); } }`;
  document.head.appendChild(el);
}

function PdfDownloadButton({ scanId, domain }) {
  const { showToast } = useToast();
  const [loading, setLoading] = useState(false);

  useEffect(ensureSpinKeyframe, []);

  const handleClick = useCallback(async () => {
    if (loading) return;
    setLoading(true);
    try {
      const res = await fetch(`${API}/report/pdf`);
      if (!res.ok) throw new Error(`Server returned ${res.status}`);
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `shadowtrace-${domain || "scan"}-report.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      showToast(
        err.message || "Report generation failed. Try again.",
        "error"
      );
    } finally {
      setLoading(false);
    }
  }, [loading, domain, showToast]);

  return (
    <button
      type="button"
      disabled={loading}
      onClick={handleClick}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "var(--space-2, 8px)",
        padding: "var(--space-3, 12px) var(--space-5, 20px)",
        background: loading
          ? "var(--color-accent-red-dim, #7A1A1F)"
          : "var(--color-accent-red, #E63946)",
        color: "#fff",
        fontSize: "var(--text-body, 0.875rem)",
        fontWeight: 700,
        textTransform: "uppercase",
        letterSpacing: "0.06em",
        border: "1px solid var(--color-accent-red, #E63946)",
        borderRadius: 0,
        cursor: loading ? "not-allowed" : "pointer",
        fontFamily: "inherit",
        transition: "background 120ms ease-out",
        opacity: loading ? 0.7 : 1,
      }}
      onMouseEnter={(e) => {
        if (!loading) {
          e.currentTarget.style.background = "var(--color-accent-red-dim, #7A1A1F)";
        }
      }}
      onMouseLeave={(e) => {
        if (!loading) {
          e.currentTarget.style.background = "var(--color-accent-red, #E63946)";
        }
      }}
    >
      {loading && (
        <span
          style={{
            display: "inline-block",
            width: 16,
            height: 16,
            border: "2px solid rgba(255,255,255,0.3)",
            borderTopColor: "#fff",
            borderRadius: "50%",
            animation: "pdfSpin 0.6s linear infinite",
            flexShrink: 0,
          }}
        />
      )}
      {loading ? "Generating..." : "Download Report ↓"}
    </button>
  );
}

export default PdfDownloadButton;

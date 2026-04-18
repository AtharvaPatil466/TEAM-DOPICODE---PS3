import { useEffect } from "react";
import useToast from "../hooks/useToast";

const BORDER_COLOR = {
  error:   "var(--color-accent-red, #E63946)",
  success: "var(--color-accent-green, #2ECC71)",
  info:    "var(--color-accent-cyan, #00B4D8)",
};

const STYLE_ID = "toast-mgr-keyframes";
function ensureKeyframes() {
  if (document.getElementById(STYLE_ID)) return;
  const el = document.createElement("style");
  el.id = STYLE_ID;
  el.textContent = `
    @keyframes toastEnter {
      from { transform: translateX(110%); }
      to   { transform: translateX(0); }
    }
  `;
  document.head.appendChild(el);
}

function ToastManager() {
  const { toasts, dismiss } = useToast();

  useEffect(ensureKeyframes, []);

  if (!toasts.length) return null;

  return (
    <div
      style={{
        position: "fixed",
        bottom: 20,
        right: 20,
        zIndex: 9999,
        display: "flex",
        flexDirection: "column-reverse",
        gap: 8,
        maxWidth: 380,
        width: "100%",
        pointerEvents: "none",
      }}
    >
      {toasts.map((toast) => {
        const borderColor = BORDER_COLOR[toast.type] || BORDER_COLOR.info;
        return (
          <div
            key={toast.id}
            style={{
              display: "flex",
              alignItems: "flex-start",
              gap: "var(--space-3, 12px)",
              padding: "var(--space-3, 12px) var(--space-4, 16px)",
              background: "#0F2236",
              border: `1px solid ${borderColor}`,
              borderRadius: 0,
              color: "var(--color-text-primary, #F0F4F8)",
              fontSize: "var(--text-body, 0.875rem)",
              fontFamily: "var(--text-body-family, 'Inter', system-ui, sans-serif)",
              lineHeight: 1.5,
              pointerEvents: "auto",
              animation: toast.exiting ? "none" : "toastEnter 200ms ease both",
              opacity: toast.exiting ? 0 : 1,
              transition: "opacity 200ms ease",
            }}
          >
            {/* Left accent bar */}
            <span
              style={{
                width: 3,
                alignSelf: "stretch",
                background: borderColor,
                flexShrink: 0,
              }}
            />

            {/* Message */}
            <span style={{ flex: 1 }}>{toast.message}</span>

            {/* Dismiss */}
            <button
              type="button"
              onClick={() => dismiss(toast.id)}
              style={{
                background: "none",
                border: "none",
                color: "var(--color-text-muted, #5C7A96)",
                cursor: "pointer",
                fontSize: 16,
                fontFamily: "monospace",
                padding: 0,
                lineHeight: 1,
                flexShrink: 0,
              }}
              aria-label="Dismiss"
            >
              ×
            </button>
          </div>
        );
      })}
    </div>
  );
}

export default ToastManager;

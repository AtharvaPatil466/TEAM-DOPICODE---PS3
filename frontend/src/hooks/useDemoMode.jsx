/*
 * useDemoMode — ShadowTrace demo mode hook
 *
 * Toggle: Ctrl+Shift+D anywhere in the app
 * Persists: sessionStorage "shadowtrace_demo_mode" / "shadowtrace_demo_data"
 *
 * ── INTEGRATION POINT 1 — ScanPage.jsx ──────────────────────
 *
 *   import useDemoMode from "../hooks/useDemoMode";
 *
 *   function ScanPage() {
 *     const { isDemoMode, getDemoResults } = useDemoMode();
 *
 *     // Inside your scan init logic, BEFORE the POST /api/scan call:
 *     if (isDemoMode) {
 *       const demoData = await getDemoResults();
 *       // Skip POST /api/scan entirely.
 *       // Feed demoData into your event feed staggered 350ms apart,
 *       // or set it directly as the results state.
 *       return;
 *     }
 *     // ...existing POST /api/scan logic...
 *   }
 *
 * ── INTEGRATION POINT 2 — ResultsPage.jsx ───────────────────
 *
 *   // At the top of your data-loading useEffect, BEFORE fetching:
 *   const cached = sessionStorage.getItem("shadowtrace_demo_data");
 *   if (cached) {
 *     try {
 *       const demoData = JSON.parse(cached);
 *       setResults(demoData);
 *       return; // skip the real fetch
 *     } catch { /* corrupt cache, fall through to real fetch *\/ }
 *   }
 *   // ...existing GET /api/results/... logic...
 *
 */

import { useCallback, useEffect, useState } from "react";

const API = "http://localhost:8000";
const KEY_MODE = "shadowtrace_demo_mode";
const KEY_DATA = "shadowtrace_demo_data";

function readFlag() {
  try {
    return sessionStorage.getItem(KEY_MODE) === "1";
  } catch {
    return false;
  }
}

export default function useDemoMode() {
  const [isDemoMode, setIsDemoMode] = useState(readFlag);

  /* ── Ctrl+Shift+D listener ── */
  useEffect(() => {
    function onKey(e) {
      if (e.ctrlKey && e.shiftKey && e.key === "D") {
        e.preventDefault();
        setIsDemoMode((prev) => {
          const next = !prev;
          try {
            if (next) {
              sessionStorage.setItem(KEY_MODE, "1");
            } else {
              sessionStorage.removeItem(KEY_MODE);
              sessionStorage.removeItem(KEY_DATA);
            }
          } catch { /* storage full or unavailable */ }
          return next;
        });
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  /* ── Manual toggle ── */
  const toggleDemoMode = useCallback(() => {
    setIsDemoMode((prev) => {
      const next = !prev;
      try {
        if (next) {
          sessionStorage.setItem(KEY_MODE, "1");
        } else {
          sessionStorage.removeItem(KEY_MODE);
          sessionStorage.removeItem(KEY_DATA);
        }
      } catch { /* */ }
      return next;
    });
  }, []);

  /* ── Fetch + cache demo results ── */
  const getDemoResults = useCallback(async () => {
    /* Return cached first */
    try {
      const cached = sessionStorage.getItem(KEY_DATA);
      if (cached) return JSON.parse(cached);
    } catch { /* */ }

    const res = await fetch(`${API}/demo/replay/latest`, { method: "POST" });
    if (!res.ok) throw new Error(`Demo preload failed: ${res.status}`);
    const data = await res.json();

    try {
      sessionStorage.setItem(KEY_DATA, JSON.stringify(data));
    } catch { /* */ }

    return data;
  }, []);

  return { isDemoMode, toggleDemoMode, getDemoResults };
}

/* ── DemoBadge — fixed bottom-left indicator ── */
export function DemoBadge() {
  const { isDemoMode } = useDemoMode();
  if (!isDemoMode) return null;

  return (
    <span
      style={{
        position: "fixed",
        bottom: 8,
        left: 8,
        zIndex: 9999,
        fontSize: 10,
        fontWeight: 700,
        fontFamily: "monospace",
        letterSpacing: "0.16em",
        textTransform: "uppercase",
        color: "#8BA4BE",
        opacity: 0.2,
        pointerEvents: "none",
        userSelect: "none",
      }}
    >
      DEMO
    </span>
  );
}

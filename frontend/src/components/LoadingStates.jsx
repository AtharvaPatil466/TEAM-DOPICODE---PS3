import "../styles/interactions.css";

/* ── InlineSpinner ─────────────────────────────────────────── */
export function InlineSpinner({ size = 16 }) {
  return (
    <span
      className="inline-spinner"
      style={{ width: size, height: size }}
      role="status"
      aria-label="Loading"
    />
  );
}

/* ── SkeletonLine ──────────────────────────────────────────── */
export function SkeletonLine({ width = "100%", height = 14 }) {
  return (
    <div
      className="skeleton"
      style={{
        width,
        height,
        display: "block",
      }}
      aria-hidden="true"
    />
  );
}

/* ── SkeletonCard ──────────────────────────────────────────── */
export function SkeletonCard() {
  return (
    <div
      style={{
        background: "var(--color-bg-secondary, #111F30)",
        border: "1px solid var(--color-border, #1E3048)",
        borderRadius: 0,
        padding: "var(--space-4, 16px)",
        display: "flex",
        flexDirection: "column",
        gap: "var(--space-3, 12px)",
      }}
      aria-hidden="true"
    >
      {/* Severity badge placeholder */}
      <SkeletonLine width={52} height={18} />
      {/* Title line */}
      <SkeletonLine width="75%" height={16} />
      {/* Description lines */}
      <SkeletonLine width="100%" height={12} />
      <SkeletonLine width="60%" height={12} />
      {/* Bottom row: asset + cvss */}
      <div style={{ display: "flex", gap: "var(--space-4, 16px)", marginTop: "var(--space-1, 4px)" }}>
        <SkeletonLine width={100} height={12} />
        <SkeletonLine width={48} height={12} />
      </div>
    </div>
  );
}

/* ── ScanningDot ───────────────────────────────────────────── */
export function ScanningDot() {
  return (
    <span
      className="scanning-dot"
      role="status"
      aria-label="Scanning"
    />
  );
}

/* ── ProgressBar ───────────────────────────────────────────── */
export function ProgressBar({ value = 0, color = "red" }) {
  const clamped = Math.max(0, Math.min(100, value));
  const colorClass =
    color === "green"
      ? "progress-bar-fill--green"
      : color === "amber"
        ? "progress-bar-fill--amber"
        : "progress-bar-fill--red";

  return (
    <div className="progress-bar-track" role="progressbar" aria-valuenow={clamped} aria-valuemin={0} aria-valuemax={100}>
      <div
        className={`progress-bar-fill ${colorClass}`}
        style={{ width: `${clamped}%` }}
      />
    </div>
  );
}

import { useEffect, useState } from "react";

const COLORS = {
  confirmed: "#22c55e",
  partial: "#fbbf24",
  unverified: "#6b7280"
};

function ValidationHUD({ phase, summary }) {
  // phase: "idle" | "verifying" | "done"
  // summary: { confirmed, partial, unverified, total } | null
  const [fill, setFill] = useState(0);

  useEffect(() => {
    if (phase === "verifying") {
      setFill(0);
      const id = setInterval(() => {
        setFill((f) => (f >= 95 ? 95 : f + 7));
      }, 120);
      return () => clearInterval(id);
    }
    if (phase === "done") setFill(100);
  }, [phase]);

  if (phase === "idle") return null;

  const total = summary?.total ?? 0;
  const confirmed = summary?.confirmed ?? 0;
  const partial = summary?.partial ?? 0;
  const unverified = summary?.unverified ?? 0;

  const segPct = (n) => (total > 0 ? (n / total) * 100 : 0);

  const caption =
    phase === "verifying"
      ? "Verifying TCP connectivity across attack paths..."
      : total === 0
      ? "No attack paths computed."
      : `${confirmed} of ${total} paths confirmed via live TCP probe`;

  return (
    <div
      className="validation-hud"
      style={{
        marginTop: "1.5rem",
        padding: "1rem 1.25rem",
        border: "1px solid #1f3a5c",
        borderRadius: "10px",
        background: "rgba(11, 18, 32, 0.6)"
      }}
    >
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "baseline",
          marginBottom: "0.6rem"
        }}
      >
        <p className="eyebrow" style={{ margin: 0 }}>
          Path Validation
        </p>
        <div style={{ fontFamily: "monospace", fontSize: "0.85rem", color: "#cfd8e6" }}>
          <span style={{ color: COLORS.confirmed }}>{confirmed} CONFIRMED</span>
          {" / "}
          <span style={{ color: COLORS.partial }}>{partial} PARTIAL</span>
          {" / "}
          <span style={{ color: COLORS.unverified }}>{unverified} UNVERIFIED</span>
        </div>
      </div>

      <div
        style={{
          width: "100%",
          height: "10px",
          background: "rgba(107, 114, 128, 0.15)",
          borderRadius: "5px",
          overflow: "hidden",
          display: "flex"
        }}
      >
        {phase === "verifying" ? (
          <div
            style={{
              width: `${fill}%`,
              background:
                "linear-gradient(90deg, rgba(34,197,94,0.6), rgba(251,191,36,0.6), rgba(107,114,128,0.6))",
              transition: "width 120ms linear"
            }}
          />
        ) : (
          <>
            <div style={{ width: `${segPct(confirmed)}%`, background: COLORS.confirmed }} />
            <div style={{ width: `${segPct(partial)}%`, background: COLORS.partial }} />
            <div style={{ width: `${segPct(unverified)}%`, background: COLORS.unverified }} />
          </>
        )}
      </div>

      <p style={{ margin: "0.6rem 0 0", fontSize: "0.85rem", color: "#93a3b8" }}>{caption}</p>
    </div>
  );
}

export default ValidationHUD;

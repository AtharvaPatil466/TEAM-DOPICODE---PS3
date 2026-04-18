function ShadowTraceLogo({ size = 32, color = "currentColor" }) {
  const aspect = 200 / 40;
  const width = typeof size === "number" ? size * aspect : size;
  const height = size;

  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 200 40"
      width={width}
      height={height}
      fill="none"
      stroke={color}
      aria-label="ShadowTrace logo"
      role="img"
    >
      {/* ── Icon: crosshair / radar target ── */}

      {/* Outer ring */}
      <circle cx="20" cy="20" r="16" strokeWidth="1.5" />

      {/* Inner ring */}
      <circle cx="20" cy="20" r="8" strokeWidth="1" />

      {/* Center dot */}
      <circle cx="20" cy="20" r="2" fill={color} strokeWidth="0" />

      {/* Crosshair lines — extend past outer ring */}
      {/* Top */}
      <line x1="20" y1="1" x2="20" y2="10" strokeWidth="1.2" />
      {/* Bottom */}
      <line x1="20" y1="30" x2="20" y2="39" strokeWidth="1.2" />
      {/* Left */}
      <line x1="1" y1="20" x2="10" y2="20" strokeWidth="1.2" />
      {/* Right */}
      <line x1="30" y1="20" x2="39" y2="20" strokeWidth="1.2" />

      {/* Radar sweep tick marks at 45° diagonals */}
      <line x1="8.7" y1="8.7" x2="12" y2="12" strokeWidth="0.8" />
      <line x1="31.3" y1="8.7" x2="28" y2="12" strokeWidth="0.8" />
      <line x1="8.7" y1="31.3" x2="12" y2="28" strokeWidth="0.8" />
      <line x1="31.3" y1="31.3" x2="28" y2="28" strokeWidth="0.8" />

      {/* ── Wordmark: SHADOWTRACE ── */}
      <text
        x="48"
        y="26"
        fill={color}
        stroke="none"
        fontFamily="'Inter', 'DM Sans', system-ui, sans-serif"
        fontWeight="700"
        fontSize="16"
        letterSpacing="0.14em"
      >
        SHADOWTRACE
      </text>

      {/* Accent underline beneath wordmark */}
      <line x1="48" y1="32" x2="196" y2="32" strokeWidth="1" opacity="0.25" />

      {/* Red accent tick on the underline */}
      <line
        x1="48"
        y1="32"
        x2="72"
        y2="32"
        stroke="#E63946"
        strokeWidth="1.5"
      />
    </svg>
  );
}

export default ShadowTraceLogo;

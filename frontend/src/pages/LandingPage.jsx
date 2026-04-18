import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import ShadowTraceLogo from "../assets/ShadowTraceLogo";
import "../styles/brand.css";

/* ── Count-up animation hook ── */
function useCountUp(target, durationMs = 2000) {
  const [value, setValue] = useState(0);
  const raf = useRef(null);
  const start = useRef(null);

  useEffect(() => {
    function tick(timestamp) {
      if (!start.current) start.current = timestamp;
      const elapsed = timestamp - start.current;
      const t = Math.min(elapsed / durationMs, 1);
      const eased = 1 - Math.pow(1 - t, 3); /* ease-out cubic */
      setValue(parseFloat((eased * target).toFixed(1)));
      if (t < 1) raf.current = requestAnimationFrame(tick);
    }
    raf.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf.current);
  }, [target, durationMs]);

  return value;
}

/* ── Styles ── */
const S = {
  page: {
    background: "var(--color-bg-primary, #0D1B2A)",
    color: "var(--color-text-primary, #F0F4F8)",
    fontFamily: "var(--text-body-family, 'Inter', system-ui, sans-serif)",
    minHeight: "100vh",
    display: "flex",
    flexDirection: "column",
  },

  /* ── HERO ── */
  hero: {
    minHeight: "100vh",
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    justifyContent: "center",
    padding: "var(--space-8, 32px) var(--space-6, 24px)",
    textAlign: "center",
    borderBottom: "1px solid var(--color-border, #1E3048)",
  },
  h1: {
    fontSize: "clamp(1.8rem, 5vw, 3.2rem)",
    fontWeight: 700,
    letterSpacing: "-0.03em",
    lineHeight: 1.1,
    margin: "0 0 var(--space-5, 20px) 0",
    maxWidth: 720,
  },
  sub: {
    fontSize: "var(--text-body-lg, 1rem)",
    color: "var(--color-text-secondary, #A8BCCF)",
    margin: "0 0 var(--space-8, 32px) 0",
    maxWidth: 540,
    lineHeight: 1.6,
  },
  form: {
    display: "flex",
    gap: 0,
    width: "100%",
    maxWidth: 560,
  },
  input: {
    flex: 1,
    padding: "14px var(--space-5, 20px)",
    background: "var(--color-bg-tertiary, #162336)",
    color: "var(--color-text-primary, #F0F4F8)",
    border: "1px solid var(--color-border, #1E3048)",
    borderRight: "none",
    borderRadius: 0,
    fontSize: "var(--text-body, 0.875rem)",
    fontFamily: "inherit",
    outline: "none",
  },
  cta: {
    padding: "14px var(--space-6, 24px)",
    background: "var(--color-accent-red, #E63946)",
    color: "#fff",
    border: "1px solid var(--color-accent-red, #E63946)",
    borderRadius: 0,
    fontSize: "var(--text-body, 0.875rem)",
    fontWeight: 700,
    letterSpacing: "0.08em",
    textTransform: "uppercase",
    cursor: "pointer",
    whiteSpace: "nowrap",
    fontFamily: "inherit",
    transition: "background var(--transition-fast, 120ms ease-out)",
  },
  stat: {
    marginTop: "var(--space-8, 32px)",
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    gap: "var(--space-1, 4px)",
  },
  statNumber: {
    fontSize: "var(--text-display, 4rem)",
    fontWeight: 800,
    letterSpacing: "-0.04em",
    lineHeight: 1,
    color: "var(--color-accent-red, #E63946)",
  },
  statLabel: {
    fontSize: "var(--text-label, 0.7rem)",
    fontWeight: 600,
    textTransform: "uppercase",
    letterSpacing: "0.12em",
    color: "var(--color-text-muted, #5C7A96)",
    fontFamily: "var(--text-label-family, monospace)",
  },

  /* ── TRUST SIGNALS ── */
  trust: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))",
    gap: 0,
    borderBottom: "1px solid var(--color-border, #1E3048)",
  },
  trustCard: {
    padding: "var(--space-8, 32px) var(--space-6, 24px)",
    borderRight: "1px solid var(--color-border, #1E3048)",
    borderBottom: "none",
  },
  trustTitle: {
    fontSize: "var(--text-heading-sm, 1.125rem)",
    fontWeight: 700,
    margin: "0 0 var(--space-3, 12px) 0",
    letterSpacing: "-0.01em",
  },
  trustDesc: {
    fontSize: "var(--text-body, 0.875rem)",
    color: "var(--color-text-secondary, #A8BCCF)",
    margin: 0,
    lineHeight: 1.6,
  },
  trustTag: {
    display: "inline-block",
    marginBottom: "var(--space-3, 12px)",
    fontSize: "var(--text-label, 0.7rem)",
    fontWeight: 600,
    textTransform: "uppercase",
    letterSpacing: "0.12em",
    fontFamily: "var(--text-label-family, monospace)",
  },

  /* ── HOW IT WORKS ── */
  how: {
    padding: "var(--space-10, 40px) var(--space-6, 24px)",
    borderBottom: "1px solid var(--color-border, #1E3048)",
    textAlign: "center",
  },
  howHeading: {
    fontSize: "var(--text-label, 0.7rem)",
    fontWeight: 600,
    textTransform: "uppercase",
    letterSpacing: "0.12em",
    color: "var(--color-text-muted, #5C7A96)",
    fontFamily: "var(--text-label-family, monospace)",
    margin: "0 0 var(--space-8, 32px) 0",
  },
  steps: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
    gap: "var(--space-6, 24px)",
    maxWidth: 720,
    margin: "0 auto",
  },
  step: {
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    gap: "var(--space-2, 8px)",
  },
  stepNum: {
    fontSize: "var(--text-heading-lg, 2rem)",
    fontWeight: 800,
    color: "var(--color-accent-red, #E63946)",
    lineHeight: 1,
  },
  stepText: {
    fontSize: "var(--text-body, 0.875rem)",
    fontWeight: 600,
    letterSpacing: "0.02em",
  },
  stepArrow: {
    fontSize: "var(--text-heading-md, 1.5rem)",
    color: "var(--color-text-muted, #5C7A96)",
    alignSelf: "center",
  },

  /* ── FOOTER ── */
  footer: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    flexWrap: "wrap",
    gap: "var(--space-4, 16px)",
    padding: "var(--space-5, 20px) var(--space-6, 24px)",
    fontSize: "var(--text-label, 0.7rem)",
    fontWeight: 600,
    textTransform: "uppercase",
    letterSpacing: "0.1em",
    color: "var(--color-text-muted, #5C7A96)",
    fontFamily: "var(--text-label-family, monospace)",
    borderTop: "1px solid var(--color-border, #1E3048)",
    marginTop: "auto",
  },
  footerLink: {
    color: "var(--color-accent-cyan, #00B4D8)",
    textDecoration: "none",
  },
};

/* ── Trust signal data ── */
const TRUST_CARDS = [
  {
    tag: "Discovery",
    tagColor: "var(--color-accent-cyan, #00B4D8)",
    title: "Real Findings, Not Simulated",
    desc: "Live DNS enumeration, Nmap port scanning, CVE cross-reference against CISA KEV. Every finding is verified with a TCP probe.",
  },
  {
    tag: "Impact",
    tagColor: "var(--color-accent-red, #E63946)",
    title: "₹-Denominated Risk",
    desc: "DPDP Act 2023 penalty calculator built in. See regulatory exposure from ₹5 Cr to ₹250 Cr mapped to your exact asset classification.",
  },
  {
    tag: "Report",
    tagColor: "var(--color-accent-green, #2ECC71)",
    title: "CTO-Ready PDF Report",
    desc: "Full kill chain narrative, financial exposure, and remediation checklist. No security knowledge required to act on it.",
  },
];

/* ── Component ── */
function LandingPage() {
  const navigate = useNavigate();
  const [domain, setDomain] = useState("");
  const breachValue = useCountUp(2.4, 2000);

  const handleSubmit = useCallback(
    (e) => {
      e.preventDefault();
      const trimmed = domain.trim();
      if (!trimmed) return;
      navigate(`/scan?domain=${encodeURIComponent(trimmed)}`);
    },
    [domain, navigate]
  );

  return (
    <div style={S.page}>
      {/* ════ HERO ════ */}
      <section style={S.hero}>
        <div style={{ marginBottom: "var(--space-8, 32px)" }}>
          <ShadowTraceLogo size={36} color="var(--color-text-primary, #F0F4F8)" />
        </div>

        <h1 style={S.h1}>
          Know Your Attack Surface
          <br />
          Before Attackers Do.
        </h1>

        <p style={S.sub}>
          Scan any domain. Get a rupee-denominated risk report in 60 seconds.
          Purpose-built for Indian enterprises under DPDP Act 2023.
        </p>

        <form style={S.form} onSubmit={handleSubmit}>
          <input
            id="domain-input"
            type="text"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="Enter your domain — e.g. yourcompany.com"
            style={S.input}
            autoComplete="off"
            spellCheck="false"
          />
          <button
            id="scan-cta"
            type="submit"
            style={S.cta}
            onMouseEnter={(e) => {
              e.currentTarget.style.background = "var(--color-accent-red-dim, #7A1A1F)";
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.background = "var(--color-accent-red, #E63946)";
            }}
          >
            SCAN NOW →
          </button>
        </form>

        <div style={S.stat}>
          <span style={S.statNumber}>₹{breachValue}Cr</span>
          <span style={S.statLabel}>
            Average breach exposure found per scan
          </span>
        </div>
      </section>

      {/* ════ TRUST SIGNALS ════ */}
      <section style={S.trust}>
        {TRUST_CARDS.map((card, i) => (
          <div
            key={card.title}
            style={{
              ...S.trustCard,
              borderRight:
                i === TRUST_CARDS.length - 1
                  ? "none"
                  : S.trustCard.borderRight,
            }}
          >
            <span style={{ ...S.trustTag, color: card.tagColor }}>
              {card.tag}
            </span>
            <h3 style={S.trustTitle}>{card.title}</h3>
            <p style={S.trustDesc}>{card.desc}</p>
          </div>
        ))}
      </section>

      {/* ════ HOW IT WORKS ════ */}
      <section style={S.how}>
        <p style={S.howHeading}>How It Works</p>
        <div style={S.steps}>
          <div style={S.step}>
            <span style={S.stepNum}>1</span>
            <span style={S.stepText}>Enter Domain</span>
          </div>
          <span style={S.stepArrow}>→</span>
          <div style={S.step}>
            <span style={S.stepNum}>2</span>
            <span style={S.stepText}>60-Second Scan</span>
          </div>
          <span style={S.stepArrow}>→</span>
          <div style={S.step}>
            <span style={S.stepNum}>3</span>
            <span style={S.stepText}>Get Your Report</span>
          </div>
        </div>
      </section>

      {/* ════ FOOTER ════ */}
      <footer style={S.footer}>
        <span>SHADOWTRACE</span>
        <span>Built for Hackathon · PS3</span>
        <a
          href="https://github.com/AtharvaPatil466/TEAM-DOPICODE---PS3"
          target="_blank"
          rel="noopener noreferrer"
          style={S.footerLink}
        >
          GitHub ↗
        </a>
      </footer>
    </div>
  );
}

export default LandingPage;

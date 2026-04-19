import { NavLink, Outlet } from "react-router-dom";
import { useEffect, useState } from "react";
import { fetchLatestScan, connectLiveScan } from "../../services/api";
import ShadowTraceLogo from "../../assets/ShadowTraceLogo";

const links = [
  { to: "/scan", label: "Scan Setup" },
  { to: "/cto", label: "CTO View" },
  { to: "/overview", label: "Overview" },
  { to: "/surface-map", label: "Surface Map" },
  { to: "/kill-chain", label: "Kill Chain" },
  { to: "/impact", label: "Breach Impact" },
  { to: "/simulate", label: "What-If" },
  { to: "/diff", label: "Scan Diff" },
  { to: "/report", label: "Report" }
];

function AppLayout() {
  const [telemetry, setTelemetry] = useState([
    { label: "Signal Health", value: "Waiting..." },
    { label: "Last Snapshot", value: "None" },
    { label: "Threat Mode", value: "Unknown" }
  ]);
  const [events, setEvents] = useState([
    "System idle. Standing by for scan data."
  ]);
  const [scanInfo, setScanInfo] = useState(null);
  const [isLive, setIsLive] = useState(false);

  useEffect(() => {
    fetchLatestScan().then((scan) => {
      if (scan && scan.domain) {
        setTelemetry([
          { label: "Signal Health", value: "Stable" },
          { label: "Last Snapshot", value: scan.domain },
          { label: "Threat Mode", value: scan.internal_scope ? "Internal Pivot" : "External" }
        ]);
        setEvents([`Loaded scan data for ${scan.domain}`]);
        setScanInfo(scan);
      }
    }).catch(e => console.error(e));

    const socket = connectLiveScan({
      onOpen: () => {
        setIsLive(true);
        setTelemetry(prev => prev.map(t => t.label === "Signal Health" ? { ...t, value: "Live" } : t));
      },
      onEvent: (event) => {
        let text = event.type;
        if (event.type === "progress") { text = `Scan phase: ${event.payload.phase} (${event.payload.percent}%)`; }
        else if (event.type === "host_discovered") { text = `Computer found: ${event.payload.hostname || event.payload.ip}`; }
        else if (event.type === "attack_path_computed") { text = `Issues confirmed: ${event.payload.validation_summary?.confirmed || 0} paths`; }
        else if (event.type === "impact_computed") { text = `Impact scenario: ${event.payload.top_scenario}`; }
        else if (event.type === "scan_completed") { text = `Scan successfully completed`; }
        
        const timestamp = new Date(event.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        const msg = `[${timestamp}] ${text}`;
        setEvents(prev => [msg, ...prev].slice(0, 10));
      },
      onClose: () => setIsLive(false),
      onError: (err) => console.error(err)
    });

    return () => socket.close();
  }, []);

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="sidebar-top">
          <div>
            <ShadowTraceLogo size={32} color="#F0F4F8" />
          </div>
          <p className="sidebar-copy">
            Public attack surface intelligence for a CTO who needs action, not noisy scan logs.
          </p>
        </div>

        <nav className="nav">
          {links.map((link) => (
            <NavLink
              key={link.to}
              to={link.to}
              end={link.to === "/"}
              className={({ isActive }) => (isActive ? "nav-link active" : "nav-link")}
            >
              <span>{link.label}</span>
              <small>View</small>
            </NavLink>
          ))}
        </nav>

        <div className="sidebar-foot panel-inset">
          <p className="eyebrow">Scan workflow</p>
          <p style={{ color: scanInfo ? "#4ade80" : "var(--muted)" }}>✓ Discovery {scanInfo ? `(${scanInfo.total_assets} assets)` : ""}</p>
          <p style={{ color: scanInfo?.total_cves ? "#4ade80" : "var(--muted)" }}>✓ Vulnerability mapping {scanInfo ? `(${scanInfo.total_cves} CVEs)` : ""}</p>
          <p style={{ color: scanInfo?.status === "completed" ? "#4ade80" : "var(--muted)" }}>✓ Impact & reporting</p>
        </div>
      </aside>

      <main className="content">
        <header className="topbar">
          <div>
            <p className="eyebrow">Live workspace</p>
            <strong>Security operations console</strong>
          </div>
          <div className="topbar-metrics" aria-label="Workspace status">
            <span>{scanInfo ? scanInfo.domain : "No scan loaded"}</span>
            <span>{scanInfo ? `${scanInfo.total_assets} assets` : "—"}</span>
            <span style={{ color: isLive ? "#22c55e" : undefined }}>{isLive ? "● Scanning" : scanInfo ? "● Ready" : "○ Idle"}</span>
          </div>
        </header>
        <Outlet />
      </main>

      <aside className="telemetry">
        <section className="telemetry-section">
          <p className="eyebrow">Telemetry</p>
          <h2>Runtime status</h2>
          <div className="telemetry-grid">
            {telemetry.map((item) => (
              <article key={item.label} className="telemetry-card">
                <span>{item.label}</span>
                <strong style={{ color: item.value === "Live" ? "#22c55e" : undefined }}>{item.value}</strong>
              </article>
            ))}
          </div>
        </section>

        <section className="telemetry-section">
          <div className="telemetry-header">
            <p className="eyebrow">Signal feed</p>
            <span className="chip" style={isLive ? { borderColor: "#22c55e", color: "#22c55e" } : {}}>
              {isLive ? "Live" : "Idle"}
            </span>
          </div>
          <div className="event-list">
            {events.map((event, i) => (
              <p key={i}>{event}</p>
            ))}
          </div>
        </section>
      </aside>
    </div>
  );
}

export default AppLayout;

import { NavLink, Outlet } from "react-router-dom";
import ShadowTraceLogo from "../../assets/ShadowTraceLogo";

const links = [
  { to: "/scan", label: "Scan Setup" },
  { to: "/overview", label: "Overview" },
  { to: "/surface-map", label: "Surface Map" },
  { to: "/kill-chain", label: "Kill Chain" },
  { to: "/impact", label: "Breach Impact" },
  { to: "/simulate", label: "What-If" },
  { to: "/diff", label: "Scan Diff" },
  { to: "/report", label: "Report" }
];

const telemetryItems = [
  { label: "Signal Health", value: "Stable" },
  { label: "Last Snapshot", value: "2m ago" },
  { label: "Threat Mode", value: "External" }
];

const eventFeed = [
  "Admin surface fingerprint refreshed",
  "Storage exposure path correlated",
  "Narrative layer ready for export"
];

function AppLayout() {
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
          <p className="eyebrow">Mission flow</p>
          <p>Phase 1: public exposure discovery</p>
          <p>Phase 2: internal impact modeling</p>
          <p>Phase 3: financial risk matrix</p>
        </div>
      </aside>

      <main className="content">
        <header className="topbar">
          <div>
            <p className="eyebrow">Live workspace</p>
            <strong>Security operations console</strong>
          </div>
          <div className="topbar-metrics" aria-label="Workspace status">
            <span>Monochrome interface</span>
            <span>Executive framing</span>
            <span>Telemetry active</span>
          </div>
        </header>
        <Outlet />
      </main>

      <aside className="telemetry">
        <section className="telemetry-section">
          <p className="eyebrow">Telemetry</p>
          <h2>Runtime status</h2>
          <div className="telemetry-grid">
            {telemetryItems.map((item) => (
              <article key={item.label} className="telemetry-card">
                <span>{item.label}</span>
                <strong>{item.value}</strong>
              </article>
            ))}
          </div>
        </section>

        <section className="telemetry-section">
          <div className="telemetry-header">
            <p className="eyebrow">Signal feed</p>
            <span className="chip">Live</span>
          </div>
          <div className="event-list">
            {eventFeed.map((event) => (
              <p key={event}>{event}</p>
            ))}
          </div>
        </section>
      </aside>
    </div>
  );
}

export default AppLayout;

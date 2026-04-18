import { NavLink, Outlet } from "react-router-dom";

const links = [
  { to: "/", label: "Scan Setup" },
  { to: "/overview", label: "Overview" },
  { to: "/surface-map", label: "Surface Map" },
  { to: "/kill-chain", label: "Kill Chain" },
  { to: "/report", label: "Report" }
];

function AppLayout() {
  return (
    <div className="shell">
      <aside className="sidebar">
        <div>
          <p className="eyebrow">PS3 Frontend</p>
          <h1>Atlas Surface Mapper</h1>
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
              {link.label}
            </NavLink>
          ))}
        </nav>

        <div className="sidebar-foot">
          <p>Phase 1: public exposure</p>
          <p>Phase 2: internal impact projection</p>
        </div>
      </aside>

      <main className="content">
        <Outlet />
      </main>
    </div>
  );
}

export default AppLayout;

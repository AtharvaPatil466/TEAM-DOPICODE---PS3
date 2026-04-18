import { useState, useEffect } from "react";
import { startScan, replayLatestDemo, connectLiveScan } from "../services/api";
import { useNavigate } from "react-router-dom";
import ValidationHUD from "../components/ValidationHUD";

function ScanPage() {
  const [domain, setDomain] = useState("shadowtrace-demo.xyz");
  const [subnet, setSubnet] = useState("172.28.0.0/24");
  const [companySize, setCompanySize] = useState("medium");
  const [industrySector, setIndustrySector] = useState("technology");
  const [processesPii, setProcessesPii] = useState(true);
  
  const [status, setStatus] = useState("idle");
  const [events, setEvents] = useState([]);
  const [progress, setProgress] = useState(0);
  const [metrics, setMetrics] = useState({ assets: 0, cves: 0, portals: 0 });
  const [validationPhase, setValidationPhase] = useState("idle");
  const [validationSummary, setValidationSummary] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    if (status !== "running") return;
    
    const socket = connectLiveScan({
      onOpen: () => console.log("Live scan connected"),
      onEvent: (event) => {
        if (event.type === "progress") {
          setProgress(event.payload.percent);
          if (event.payload.phase === "attack_path") {
            setValidationPhase("verifying");
          }
        } else if (event.type === "attack_path_computed") {
          setValidationSummary(event.payload.validation_summary || null);
          setValidationPhase("done");
          setEvents(e => [`[${new Date(event.timestamp).toLocaleTimeString()}] Attack paths validated: ${(event.payload.validation_summary?.confirmed) ?? 0}/${(event.payload.validation_summary?.total) ?? 0} confirmed`, ...e]);
        } else if (event.type === "host_discovered") {
          setMetrics(m => ({ ...m, assets: m.assets + 1 }));
          setEvents(e => [`[${new Date(event.timestamp).toLocaleTimeString()}] Host discovered: ${event.payload.hostname || event.payload.ip}`, ...e]);
        } else if (event.type === "cve_found") {
          setMetrics(m => ({ ...m, cves: m.cves + 1 }));
        } else if (event.type === "scan_completed") {
          setStatus("completed");
        } else if (event.type === "impact_computed") {
          setEvents(e => [`[${new Date(event.timestamp).toLocaleTimeString()}] Impact computed: ${event.payload.top_scenario}`, ...e]);
        }
      },
      onClose: () => {
        if (status === "running") setStatus("idle");
      },
      onError: (err) => console.error("WS Error:", err)
    });

    return () => socket.close();
  }, [status]);

  const handleStart = async (e) => {
    e.preventDefault();
    setEvents([]);
    setProgress(0);
    setMetrics({ assets: 0, cves: 0, portals: 0 });
    setValidationPhase("idle");
    setValidationSummary(null);
    setStatus("running");

    try {
      await startScan({ domain, subnet, companySize, industrySector, processesPii });
    } catch (error) {
      console.error(error);
      setStatus("failed");
    }
  };

  const handleDemo = async () => {
    setEvents([]);
    setProgress(0);
    setMetrics({ assets: 0, cves: 0, portals: 0 });
    setValidationPhase("idle");
    setValidationSummary(null);
    setStatus("running");

    try {
      await replayLatestDemo();
    } catch (error) {
      console.error(error);
      setStatus("failed");
    }
  };

  return (
    <section className="page scan-page">
      <div className="panel">
        <p className="eyebrow">Initialize</p>
        <h2>Configure Scan & Impact Profile</h2>
        <p className="section-copy">Define the technical scope and the business profile for financial modeling.</p>
        
        <form className="scan-form" onSubmit={handleStart}>
          <div className="toggle-row">
            <label>
              Root Domain
              <input value={domain} onChange={e => setDomain(e.target.value)} required />
              <div style={{ display: "flex", gap: "0.75rem", flexWrap: "wrap", marginTop: "0.25rem" }}>
                <span className="section-copy" style={{ fontSize: "0.8rem", alignSelf: "center" }}>Suggested:</span>
                <span style={{cursor: "pointer", fontSize: "0.8rem", color: "var(--accent)"}} onClick={() => setDomain("shadowtrace-demo.xyz")}>shadowtrace-demo.xyz</span>
                <span style={{cursor: "pointer", fontSize: "0.8rem", color: "var(--accent)"}} onClick={() => setDomain("hooli.com")}>hooli.com</span>
                <span style={{cursor: "pointer", fontSize: "0.8rem", color: "var(--accent)"}} onClick={() => setDomain("example.com")}>example.com</span>
              </div>
            </label>
            <label>
              Internal Subnet (Optional)
              <input value={subnet} onChange={e => setSubnet(e.target.value)} />
            </label>
          </div>
          
          <div className="toggle-row">
            <label>
              Company Size
              <select value={companySize} onChange={e => setCompanySize(e.target.value)}>
                <option value="small">Small ({"<"}50 emp)</option>
                <option value="medium">Medium (50-500 emp)</option>
                <option value="large">Large (500+ emp)</option>
              </select>
            </label>
            <label>
              Industry Sector
              <select value={industrySector} onChange={e => setIndustrySector(e.target.value)}>
                <option value="technology">Technology</option>
                <option value="financial_services">Financial Services</option>
                <option value="healthcare">Healthcare</option>
                <option value="retail">Retail</option>
                <option value="manufacturing">Manufacturing</option>
                <option value="other">Other</option>
              </select>
            </label>
          </div>
          
          <div className="toggle-row">
            <label className="toggle-card" style={{flexDirection: "row"}}>
              <input type="checkbox" checked={processesPii} onChange={e => setProcessesPii(e.target.checked)} style={{width: "auto"}} />
              <div>
                <strong>Processes PII</strong>
                <p className="section-copy" style={{margin: 0, fontSize: "0.85rem"}}>Subject to DPDP Act baseline</p>
              </div>
            </label>
          </div>

          <div className="cta-row" style={{marginTop: "1rem"}}>
            <button type="submit" className="button primary" disabled={status === "running"}>Begin Scan</button>
            <button type="button" className="button secondary" onClick={handleDemo} disabled={status === "running"}>Replay Cached Demo</button>
          </div>
        </form>

        {(status === "running" || status === "completed") && (
          <div style={{marginTop: "2rem"}}>
            <div className="progress-shell">
              <div className="progress-bar" style={{width: `${progress}%`}} />
            </div>
            
            <div className="scan-metrics">
              <div className="status-tile">
                <span>Assets Discovered</span>
                <strong>{metrics.assets}</strong>
              </div>
              <div className="status-tile">
                <span>CVEs Found</span>
                <strong>{metrics.cves}</strong>
              </div>
              <div className="status-tile">
                <span>Status</span>
                <strong>{status === "running" ? `${progress}%` : "Complete"}</strong>
              </div>
            </div>
            
            <ValidationHUD phase={validationPhase} summary={validationSummary} />

            <div className="event-panel">
              <p className="eyebrow" style={{marginBottom: "1rem"}}>Event Stream</p>
              <div className="event-list" style={{maxHeight: "200px", overflowY: "auto"}}>
                {events.map((ev, i) => <p key={i} style={{fontSize: "0.9rem"}}>{ev}</p>)}
              </div>
            </div>
            
            {status === "completed" && (
              <div className="cta-row" style={{marginTop: "1.5rem"}}>
                <button type="button" className="button primary" onClick={() => navigate("/overview")}>View Results</button>
              </div>
            )}
          </div>
        )}
      </div>
    </section>
  );
}

export default ScanPage;

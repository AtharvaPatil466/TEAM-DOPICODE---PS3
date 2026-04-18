import SeverityBadge from "./SeverityBadge";

function FindingTable({ rows }) {
  return (
    <section className="panel">
      <div className="panel-header">
        <div>
          <p className="eyebrow">Findings</p>
          <h2>Prioritized exposures</h2>
        </div>
      </div>

      <div className="table-wrap">
        <table className="findings-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Asset</th>
              <th>Type</th>
              <th>Severity</th>
              <th>Why it matters</th>
              <th>Recommended action</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.id}>
                <td>{row.id}</td>
                <td>{row.asset}</td>
                <td>{row.kind}</td>
                <td>
                  <SeverityBadge severity={row.severity} />
                </td>
                <td>
                  {row.reason}
                  {row.in_kev && (
                    <span
                      title="CISA Known Exploited Vulnerability — confirmed active exploitation"
                      style={{
                        display: "inline-block",
                        marginLeft: "8px",
                        padding: "2px 8px",
                        borderRadius: "4px",
                        fontSize: "0.75rem",
                        fontWeight: 700,
                        background: row.kev_ransomware ? "rgba(255,93,93,0.2)" : "rgba(255,140,66,0.2)",
                        color: row.kev_ransomware ? "#ff5d5d" : "#ff8c42",
                        border: `1px solid ${row.kev_ransomware ? "rgba(255,93,93,0.4)" : "rgba(255,140,66,0.4)"}`,
                      }}
                    >
                      {row.kev_ransomware ? "☠ Ransomware" : "🔥 Actively Exploited"}
                    </span>
                  )}
                </td>
                <td>{row.action}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export default FindingTable;

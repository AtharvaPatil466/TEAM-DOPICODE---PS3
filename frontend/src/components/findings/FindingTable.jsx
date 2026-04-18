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
                <td>{row.reason}</td>
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

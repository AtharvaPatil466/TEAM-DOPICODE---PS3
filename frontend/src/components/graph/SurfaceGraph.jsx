import { useMemo, useState } from "react";
import { severityColors } from "../../utils/theme";

function SurfaceGraph({ graph, details }) {
  const [selectedNodeId, setSelectedNodeId] = useState("admin");

  const selected = details[selectedNodeId];

  const nodeMap = useMemo(() => {
    return Object.fromEntries(graph.nodes.map((node) => [node.id, node]));
  }, [graph.nodes]);

  return (
    <div className="graph-layout">
      <section className="panel graph-panel">
        <div className="panel-header">
          <div>
            <p className="eyebrow">Visual map</p>
            <h2>Public attack surface</h2>
          </div>
        </div>

        <svg viewBox="0 0 720 470" className="surface-graph" role="img" aria-label="Attack surface map">
          {graph.edges.map((edge) => {
            const from = nodeMap[edge.from];
            const to = nodeMap[edge.to];

            return (
              <line
                key={`${edge.from}-${edge.to}`}
                x1={from.x}
                y1={from.y}
                x2={to.x}
                y2={to.y}
                stroke="rgba(187, 214, 234, 0.35)"
                strokeWidth="2"
              />
            );
          })}

          {graph.nodes.map((node) => (
            <g
              key={node.id}
              onClick={() => setSelectedNodeId(node.id)}
              className={selectedNodeId === node.id ? "graph-node active" : "graph-node"}
            >
              <circle
                cx={node.x}
                cy={node.y}
                r={selectedNodeId === node.id ? 38 : 30}
                fill={severityColors[node.severity] || severityColors.Neutral}
                opacity={selectedNodeId === node.id ? 1 : 0.88}
              />
              <text x={node.x} y={node.y + 4} textAnchor="middle">
                {node.type}
              </text>
            </g>
          ))}
        </svg>
      </section>

      <aside className="panel detail-panel">
        <p className="eyebrow">Selected asset</p>
        <h2>{selected?.title}</h2>
        <p>{selected?.summary}</p>
        <ul className="detail-list">
          {selected?.bullets.map((bullet) => (
            <li key={bullet}>{bullet}</li>
          ))}
        </ul>
      </aside>
    </div>
  );
}

export default SurfaceGraph;

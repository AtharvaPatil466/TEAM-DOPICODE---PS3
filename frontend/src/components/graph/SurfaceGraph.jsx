import { useEffect, useMemo, useRef, useState } from "react";
import { severityColors } from "../../utils/theme";
import { generateNarrative, buildRuleExplanationPrompt } from "../../services/llm";

const VIEWBOX = { width: 720, height: 470 };

function SurfaceGraph({ graph, details }) {
  const [selectedNodeId, setSelectedNodeId] = useState(graph.nodes[0]?.id ?? null);
  const [positions, setPositions] = useState(graph.nodes);
  const [draggingNodeId, setDraggingNodeId] = useState(null);
  const [selectedEdge, setSelectedEdge] = useState(null);
  const [edgeExplanation, setEdgeExplanation] = useState(null);
  const [modalLoading, setModalLoading] = useState(false);
  const svgRef = useRef(null);

  const handleEdgeClick = async (edge) => {
    setSelectedEdge(edge);
    setModalLoading(true);
    setEdgeExplanation(null);

    // Extract technique from edge (example: T1595 from attack_techniques)
    const technique = edge.technique || edge.attackTechniques?.[0] || "T1190";

    const prompt = buildRuleExplanationPrompt(edge.ruleId, technique);
    const explanation = await generateNarrative(prompt);

    // Fallback explanation
    const fallback = `Rule ${edge.ruleId} (${edge.relationship}) maps to ${technique}. This edge becomes valid when the target condition matches the rule predicate, enabling attacker progression toward crown jewel assets.`;

    setEdgeExplanation(explanation || fallback);
    setModalLoading(false);
  };

  const closeModal = () => {
    setSelectedEdge(null);
    setEdgeExplanation(null);
  };

  useEffect(() => {
    setPositions(graph.nodes);
    setSelectedNodeId((current) => current ?? graph.nodes[0]?.id ?? null);
  }, [graph.nodes]);

  const selected = selectedNodeId == null ? null : details[selectedNodeId];

  const nodeMap = useMemo(() => {
    return Object.fromEntries(positions.map((node) => [node.id, node]));
  }, [positions]);

  function projectPointer(event) {
    const svg = svgRef.current;
    if (!svg) {
      return null;
    }

    const rect = svg.getBoundingClientRect();
    if (!rect.width || !rect.height) {
      return null;
    }

    const x = ((event.clientX - rect.left) / rect.width) * VIEWBOX.width;
    const y = ((event.clientY - rect.top) / rect.height) * VIEWBOX.height;

    return {
      x: Math.max(36, Math.min(VIEWBOX.width - 36, x)),
      y: Math.max(36, Math.min(VIEWBOX.height - 36, y))
    };
  }

  function handlePointerDown(event, nodeId) {
    event.preventDefault();
    event.stopPropagation();
    setSelectedNodeId(nodeId);
    setDraggingNodeId(nodeId);
    event.currentTarget.setPointerCapture?.(event.pointerId);
  }

  function handlePointerMove(event) {
    if (!draggingNodeId) {
      return;
    }

    const point = projectPointer(event);
    if (!point) {
      return;
    }

    setPositions((current) =>
      current.map((node) => (node.id === draggingNodeId ? { ...node, ...point } : node))
    );
  }

  function handlePointerEnd(event) {
    if (!draggingNodeId) {
      return;
    }

    event.currentTarget.releasePointerCapture?.(event.pointerId);
    setDraggingNodeId(null);
  }

  if (!positions.length) {
    return (
      <div className="graph-layout">
        <section className="panel graph-panel">
          <div className="panel-header">
            <div>
              <p className="eyebrow">Visual map</p>
              <h2>Public attack surface</h2>
            </div>
          </div>
          <p className="section-copy">No cached graph is available yet. Seed the backend demo and replay it first.</p>
        </section>
      </div>
    );
  }

  return (
    <div className="graph-layout">
      <section className="panel graph-panel">
        <div className="panel-header">
          <div>
            <p className="eyebrow">Visual map</p>
            <h2>Public attack surface</h2>
          </div>
          <span className="chip">Click a node for context</span>
        </div>

        <svg
          ref={svgRef}
          viewBox={`0 0 ${VIEWBOX.width} ${VIEWBOX.height}`}
          className="surface-graph"
          role="img"
          aria-label="Attack surface map"
          onPointerMove={handlePointerMove}
          onPointerUp={handlePointerEnd}
          onPointerLeave={handlePointerEnd}
        >
          {graph.edges.map((edge) => {
            const from = nodeMap[edge.from];
            to = nodeMap[edge.to];
            if (!from || !to) {
              return null;
            }

            const isSelected = selectedEdge?.from === edge.from && selectedEdge?.to === edge.to;

            return (
              <g key={`${edge.from}-${edge.to}`} style={{ cursor: edge.ruleId ? "pointer" : "default" }}>
                <line
                  x1={from.x}
                  y1={from.y}
                  x2={to.x}
                  y2={to.y}
                  stroke={isSelected ? "#7dd3fc" : "rgba(187, 214, 234, 0.35)"}
                  strokeWidth={isSelected ? "3" : "2"}
                  onClick={() => edge.ruleId && handleEdgeClick(edge)}
                />
                {/* Invisible wider line for easier clicking */}
                {edge.ruleId && (
                  <line
                    x1={from.x}
                    y1={from.y}
                    x2={to.x}
                    y2={to.y}
                    stroke="transparent"
                    strokeWidth="12"
                    onClick={() => handleEdgeClick(edge)}
                  />
                )}
              </g>
            );
          })}

          {positions.map((node) => (
            <g
              key={node.id}
              onClick={() => setSelectedNodeId(node.id)}
              onPointerDown={(event) => handlePointerDown(event, node.id)}
              className={
                selectedNodeId === node.id
                  ? `graph-node active${draggingNodeId === node.id ? " dragging" : ""}`
                  : `graph-node${draggingNodeId === node.id ? " dragging" : ""}`
              }
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
        <h2>{selected?.title || "Select a node"}</h2>
        <p>{selected?.summary || "Choose a node to inspect the seeded evidence behind it."}</p>
        <ul className="detail-list">
          {(selected?.bullets || []).map((bullet) => (
            <li key={bullet}>{bullet}</li>
          ))}
        </ul>
        <p style={{ marginTop: "16px", fontSize: "0.8rem", color: "#7dd3fc" }}>
          Tip: Click an edge line to see why that attack path exists.
        </p>
      </aside>

      {/* Why This Edge Modal */}
      {selectedEdge && (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: "rgba(0, 0, 0, 0.7)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 1000
          }}
          onClick={closeModal}
        >
          <div
            style={{
              background: "#0b1220",
              border: "1px solid #1f3a5c",
              borderRadius: "12px",
              padding: "24px",
              maxWidth: "480px",
              width: "90%",
              boxShadow: "0 20px 60px rgba(0, 0, 0, 0.5)"
            }}
            onClick={(e) => e.stopPropagation()}
          >
            {modalLoading ? (
              <div style={{ textAlign: "center", padding: "20px" }}>
                <p>Analyzing edge context...</p>
              </div>
            ) : (
              <>
                <h3 style={{ margin: "0 0 8px 0", color: "#e6f0ff" }}>
                  Why this edge? ({selectedEdge.ruleId})
                </h3>
                {selectedEdge.technique && (
                  <p
                    style={{
                      margin: "0 0 16px 0",
                      fontSize: "0.85rem",
                      color: "#7dd3fc",
                      background: "rgba(125, 211, 252, 0.1)",
                      padding: "4px 12px",
                      borderRadius: "4px",
                      display: "inline-block"
                    }}
                  >
                    MITRE {selectedEdge.technique}
                  </p>
                )}
                <p style={{ margin: "0 0 20px 0", lineHeight: "1.6", color: "#cfd8e6" }}>
                  {edgeExplanation}
                </p>
                <button
                  type="button"
                  className="button primary"
                  onClick={closeModal}
                  style={{ width: "100%" }}
                >
                  Close
                </button>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default SurfaceGraph;

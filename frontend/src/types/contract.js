export const scanContract = {
  scanInput: {
    rootDomain: "string",
    scanDepth: "enum: quick | standard | full",
    includeStorageChecks: "boolean",
    includeInternalProjection: "boolean"
  },
  summary: {
    metrics: "Metric[]",
    narrative: "string",
    actions: "Action[]"
  },
  graph: {
    nodes: "GraphNode[]",
    edges: "GraphEdge[]"
  },
  findings: "Finding[]",
  report: "ReportSection[]"
};

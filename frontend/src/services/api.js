import {
  findingRows,
  graphEdges,
  graphNodes,
  killChainSteps,
  narrative,
  nodeDetails,
  reportSections,
  summaryMetrics,
  topActions
} from "../data/mockData";

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export async function fetchDashboardData() {
  await delay(180);

  return {
    summaryMetrics,
    narrative,
    topActions,
    findingRows,
    graph: {
      nodes: graphNodes,
      edges: graphEdges
    },
    nodeDetails,
    killChainSteps,
    reportSections
  };
}

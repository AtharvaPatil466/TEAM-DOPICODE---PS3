import {
  generateNarrative,
  buildExecutiveSummaryPrompt,
  buildAnalystReportPrompt,
  buildHopRationalePrompt,
} from "./llm";

const API_BASE = (import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000").replace(/\/$/, "");
const WS_BASE = API_BASE.replace(/^http/, "ws");

const severityOrder = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Neutral: 3
};

function assetLabel(asset) {
  return asset?.hostname || asset?.ip || `asset-${asset?.id || "unknown"}`;
}

function riskSeverity(score = 0) {
  if (score >= 80) {
    return "Critical";
  }
  if (score >= 60) {
    return "High";
  }
  if (score >= 30) {
    return "Medium";
  }
  return "Neutral";
}

function graphSeverity(level) {
  switch (level) {
    case "critical":
      return "Critical";
    case "high":
      return "High";
    case "medium":
      return "Medium";
    default:
      return "Neutral";
  }
}

function shortType(type) {
  switch (type) {
    case "internet":
      return "net";
    case "storage":
      return "s3";
    case "workstation":
      return "ws";
    default:
      return (type || "asset").slice(0, 6);
  }
}

function typeLabel(type) {
  switch (type) {
    case "api":
      return "API";
    case "db":
      return "Database";
    case "iot":
      return "IoT";
    case "web":
      return "Web app";
    case "storage":
      return "S3 bucket";
    case "internet":
      return "Internet";
    default:
      return type || "Asset";
  }
}

function topCve(asset) {
  return [...(asset?.cves || [])].sort((left, right) => (right.cvss || 0) - (left.cvss || 0))[0] || null;
}

function describeTls(sslInfo) {
  if (!sslInfo) {
    return null;
  }
  if (sslInfo.expired) {
    return "Certificate is expired.";
  }
  if (sslInfo.self_signed) {
    return "Certificate is self-signed.";
  }
  if (sslInfo.hostname_match === false) {
    return "Certificate hostname does not match the exposed service.";
  }
  if (sslInfo.expiring_soon) {
    return "Certificate is close to expiry.";
  }
  return null;
}

function summarizeExposure(asset) {
  const tech = asset.tech_stack || {};
  const tlsIssue = describeTls(asset.ssl_info);
  const adminPanels = asset.admin_panels || [];
  const exposedPanels = adminPanels.filter((panel) => !panel.auth);
  const strongest = topCve(asset);

  if (asset.asset_type === "storage" && tech.issue === "public_listing") {
    const files = (tech.sample_files || []).slice(0, 3).join(", ");
    return {
      kind: "S3 bucket",
      reason: `Public object listing exposes ${files}.`,
      action: tech.remediation_summary || "Disable public listing and rotate any exposed keys immediately."
    };
  }

  if (exposedPanels.length > 0) {
    const paths = exposedPanels.slice(0, 2).map((panel) => panel.path).join(", ");
    return {
      kind: "Admin surface",
      reason: `Unauthenticated panel exposure at ${paths}.`,
      action: tech.remediation_summary || "Move the admin surface behind VPN or IP allowlists."
    };
  }

  if (strongest) {
    return {
      kind: "Known CVE",
      reason: `${strongest.cve_id}${strongest.cvss ? ` (CVSS ${strongest.cvss})` : ""} is mapped to this asset.`,
      action: strongest.remediation || tech.remediation_summary || "Patch the affected service to a fixed version."
    };
  }

  if (tlsIssue) {
    return {
      kind: "TLS posture",
      reason: tlsIssue,
      action: tech.remediation_summary || "Replace the certificate with a trusted cert that matches the host."
    };
  }

  return {
    kind: typeLabel(asset.asset_type),
    reason: tech.issue_summary || "This host broadens the public attack surface and needs ownership review.",
    action: tech.remediation_summary || "Reduce exposure and assign an owning team."
  };
}

function buildFindingRows(assets) {
  return [...assets]
    .sort((left, right) => (right.risk_score || 0) - (left.risk_score || 0))
    .map((asset, index) => {
      const exposure = summarizeExposure(asset);
      const strongest = topCve(asset);
      return {
        id: `F-${String(101 + index)}`,
        asset: assetLabel(asset),
        kind: exposure.kind,
        severity: riskSeverity(asset.risk_score),
        reason: exposure.reason,
        action: exposure.action,
        in_kev: strongest?.in_kev || false,
        kev_ransomware: strongest?.kev_ransomware || false,
      };
    });
}

function buildTopActions(findingRows) {
  return findingRows.slice(0, 3).map((row) => ({
    title: `${row.asset}: ${row.kind}`,
    detail: row.action
  }));
}

function layoutRow(nodes, y) {
  if (!nodes.length) {
    return [];
  }
  const gap = 720 / (nodes.length + 1);
  return nodes.map((node, index) => ({
    ...node,
    x: Math.round(gap * (index + 1)),
    y
  }));
}

function buildGraphModel(graph, assetsById) {
  const internetNode = graph.nodes.find((node) => node.id === 0);
  const assetNodes = graph.nodes.filter((node) => node.id !== 0);

  const externalNodes = [];
  const storageNodes = [];
  const internalNodes = [];

  assetNodes.forEach((node) => {
    const asset = assetsById[node.id];
    if (!asset) {
      return;
    }
    if (asset.exposure === "internal") {
      internalNodes.push(node);
    } else if (asset.asset_type === "storage") {
      storageNodes.push(node);
    } else {
      externalNodes.push(node);
    }
  });

  const laidOutNodes = [];
  if (internetNode) {
    laidOutNodes.push({
      ...internetNode,
      x: 360,
      y: 70,
      severity: "Neutral",
      type: "net"
    });
  }

  const sortByRisk = (left, right) => {
    const leftAsset = assetsById[left.id];
    const rightAsset = assetsById[right.id];
    return (rightAsset?.risk_score || 0) - (leftAsset?.risk_score || 0);
  };

  layoutRow([...externalNodes].sort(sortByRisk), 185).forEach((node) => {
    laidOutNodes.push({
      ...node,
      severity: graphSeverity(node.risk_level),
      type: shortType(node.asset_type)
    });
  });

  layoutRow([...storageNodes].sort(sortByRisk), 320).forEach((node) => {
    laidOutNodes.push({
      ...node,
      severity: graphSeverity(node.risk_level),
      type: shortType(node.asset_type)
    });
  });

  layoutRow([...internalNodes].sort(sortByRisk), 420).forEach((node) => {
    laidOutNodes.push({
      ...node,
      severity: graphSeverity(node.risk_level),
      type: shortType(node.asset_type)
    });
  });

  return {
    nodes: laidOutNodes,
    edges: graph.edges.map((edge) => ({
      from: edge.source,
      to: edge.target,
      relationship: edge.relationship,
      rationale: edge.rationale,
      ruleId: edge.rule_id
    }))
  };
}

function buildNodeDetails(graphModel, assetsById, latestScan) {
  const details = {
    0: {
      title: "Public internet",
      summary: `Replay entry point for ${latestScan.domain}. The cached demo starts here every time.`,
      bullets: [
        `${latestScan.total_assets} seeded findings in scope`,
        latestScan.internal_scope ? "Internal pivot layer enabled" : "External-only scope seeded by default",
        "WebSocket replay is deterministic and served from SQLite"
      ]
    }
  };

  graphModel.nodes.forEach((node) => {
    if (node.id === 0) {
      return;
    }
    const asset = assetsById[node.id];
    if (!asset) {
      return;
    }
    const strongest = topCve(asset);
    const bullets = [
      `${riskSeverity(asset.risk_score)} risk score ${asset.risk_score.toFixed(1)}`,
      `${asset.cves.length} mapped CVE${asset.cves.length === 1 ? "" : "s"}`,
      asset.exposure === "internal" ? "Internal impact layer" : "Internet-facing"
    ];
    const summaryParts = [];
    if (asset.tech_stack?.issue_summary) {
      summaryParts.push(asset.tech_stack.issue_summary);
    }
    if (strongest) {
      summaryParts.push(`${strongest.cve_id}${strongest.cvss ? ` (CVSS ${strongest.cvss})` : ""} is the highest-value exploit on this asset.`);
    }
    if (!summaryParts.length) {
      summaryParts.push(`${assetLabel(asset)} is part of the seeded attack surface and contributes to overall exposure.`);
    }
    details[node.id] = {
      title: assetLabel(asset),
      summary: summaryParts.join(" "),
      bullets
    };
  });

  return details;
}

async function buildKillChainSteps(attackPath, assetsById, latestScan) {
  // Helper to get LLM rationale for a hop
  const getHopRationale = async (hop, index) => {
    const asset = assetsById[hop.asset_id];
    if (!asset || !hop.rule_id) return null;

    const prompt = buildHopRationalePrompt(
      assetLabel(asset),
      hop.rule_id,
      hop.cve_id,
      hop.cvss
    );
    return generateNarrative(prompt);
  };

  const steps = [
    {
      title: "External discovery",
      summary: `The replay starts from ${latestScan.domain} and walks the ${latestScan.total_assets}-asset cached surface in deterministic order.`
    }
  ];

  if (!attackPath.hops?.length) {
    steps.push({
      title: "Priority exposure",
      summary: "No full attack path is cached for this scan, so the demo falls back to the highest-risk public finding."
    });
    return steps;
  }

  // Generate LLM rationales for each hop in parallel
  const hopRationales = await Promise.all(
    attackPath.hops.map((hop, index) => getHopRationale(hop, index))
  );

  attackPath.hops.forEach((hop, index) => {
    const asset = assetsById[hop.asset_id];
    const exposure = asset ? summarizeExposure(asset) : null;
    const llmRationale = hopRationales[index];

    // Use LLM rationale if available, otherwise fallback to static explanation
    const summary = llmRationale || (exposure
      ? `${assetLabel(asset)} becomes the next step because ${exposure.reason.toLowerCase()}`
      : `${hop.label} is included in the cached attack path.`);

    steps.push({
      title: index === attackPath.hops.length - 1 ? "Objective reached" : `Hop ${index + 1}`,
      summary,
      ruleId: hop.rule_id,
      technique: hop.attack_techniques?.[0],
      cveId: hop.cve_id,
      hasLlmRationale: !!llmRationale
    });
  });

  const finalHop = attackPath.hops[attackPath.hops.length - 1];
  const finalAsset = assetsById[finalHop.asset_id];
  if (finalAsset?.asset_type === "storage") {
    const files = (finalAsset.tech_stack?.sample_files || []).slice(0, 3).join(", ");
    steps.push({
      title: "Data exposure",
      summary: `The path terminates at a public bucket where ${files} are directly listable without authentication.`
    });
  }

  return steps.slice(0, 4);
}

async function buildReportSections(latestScan, findingRows, attackPath, impactData, assets) {
  const criticalCount = findingRows.filter((row) => row.severity === "Critical").length;
  const lead = findingRows[0];

  // Build critical CVEs list for LLM prompt
  const criticalCves = findingRows
    .filter((row) => row.severity === "Critical")
    .map((row) => row.reason?.match(/CVE-\d{4}-\d+/)?.[0])
    .filter(Boolean);

  // Find crown jewel asset
  const crownJewel = assets?.find((a) => a.is_crown_jewel);
  const crownJewelLabel = crownJewel ? assetLabel(crownJewel) : null;

  // Generate LLM analyst narrative
  const reportPrompt = buildAnalystReportPrompt(
    latestScan.total_assets,
    criticalCves,
    crownJewelLabel
  );
  const analystNarrative = await generateNarrative(reportPrompt);

  const sections = [
    {
      heading: "Executive summary",
      body: `${latestScan.domain} is running as a cached ${latestScan.internal_scope ? "external plus internal" : "external-only"} demo with ${latestScan.total_assets} assets and ${criticalCount} critical findings.`
    }
  ];

  if (impactData && impactData.executive_advisory) {
    sections.push({
      heading: "Financial Risk Advisory",
      body: impactData.executive_advisory
    });
  }

  sections.push({
    heading: "Critical exposures",
    body: lead
      ? `${lead.asset} is the highest-priority issue because ${lead.reason.toLowerCase()}`
      : "No prioritized findings are cached yet."
  });

  // Use LLM-generated analyst narrative or fallback to server narrative
  sections.push({
    heading: "Analyst narrative",
    body: analystNarrative || attackPath.narrative || "No attack path narrative has been computed for the current cached scan."
  });

  sections.push({
    heading: "Recommended next steps",
    body: findingRows.slice(0, 3).map((row) => row.action).join(" ")
  });

  return sections;
}

async function buildNarrative(latestScan, attackPath, findingRows) {
  // Fallback if LLM is unavailable
  const fallback = () => {
    if (attackPath.narrative) {
      return attackPath.narrative;
    }
    if (findingRows[0]) {
      return `${latestScan.domain} is currently dominated by ${findingRows[0].asset}, which is the highest-risk public finding in the cached demo.`;
    }
    return `No cached scan is available for ${latestScan.domain}.`;
  };

  // Build LLM prompt for executive summary
  const criticalCount = findingRows.filter((row) => row.severity === "Critical").length;
  const hopCount = attackPath.hops?.length || 0;
  const topCve = findingRows[0]?.reason?.match(/CVE-\d{4}-\d+/)?.[0];

  const prompt = buildExecutiveSummaryPrompt(
    latestScan.total_assets,
    criticalCount,
    hopCount,
    topCve
  );

  const llmResponse = await generateNarrative(prompt);
  return llmResponse || fallback();
}

function buildEmptyDashboard(message) {
  return {
    latestScan: null,
    summaryMetrics: [
      { label: "Exposed assets", value: "0", tone: "neutral" },
      { label: "Critical findings", value: "0", tone: "neutral" },
      { label: "Misconfigured storage", value: "0", tone: "neutral" },
      { label: "Executive risk", value: "0.0 / 10", tone: "neutral" }
    ],
    narrative: message,
    topActions: [],
    findingRows: [],
    graph: { nodes: [], edges: [] },
    nodeDetails: {},
    killChainSteps: [
      {
        title: "Seed the demo",
        summary: "Run the backend seed script so the UI has deterministic scan data to render."
      }
    ],
    reportSections: [
      {
        heading: "Demo status",
        body: message
      }
    ]
  };
}

async function fetchJson(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {})
    }
  });

  if (!response.ok) {
    const error = new Error(`Request failed for ${path} with ${response.status}`);
    error.status = response.status;
    throw error;
  }

  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    return response.json();
  }
  return response.text();
}

export async function fetchLatestScan() {
  try {
    return await fetchJson("/scan/latest");
  } catch (error) {
    if (error.status === 404) {
      return null;
    }
    throw error;
  }
}

export async function startScan({ domain, subnet, companySize, industrySector, processesPii }) {
  return fetchJson("/scan/start", {
    method: "POST",
    body: JSON.stringify({
      domain,
      subnet,
      company_size: companySize,
      industry_sector: industrySector,
      processes_pii: processesPii === undefined ? true : processesPii
    })
  });
}

export async function fetchImpact() {
  try {
    return await fetchJson("/impact");
  } catch (error) {
    if (error.status === 404) return null;
    throw error;
  }
}

export async function fetchImpactScenarios() {
  try {
    return await fetchJson("/impact/scenarios");
  } catch (error) {
    if (error.status === 404) return null;
    throw error;
  }
}

export function connectLiveScan({ onOpen, onEvent, onClose, onError }) {
  const MAX_RETRIES = 5;
  let retryCount = 0;
  let socket = null;
  let closed = false;

  function connect() {
    socket = new WebSocket(`${WS_BASE}/scan/live`);
    socket.addEventListener("open", () => {
      retryCount = 0;
      onOpen?.(socket);
    });
    socket.addEventListener("message", (event) => {
      try {
        onEvent?.(JSON.parse(event.data));
      } catch (error) {
        onError?.(error);
      }
    });
    socket.addEventListener("close", () => {
      if (closed) {
        onClose?.();
        return;
      }
      if (retryCount < MAX_RETRIES) {
        const delay = Math.min(1000 * Math.pow(2, retryCount), 16000);
        retryCount++;
        console.log(`WebSocket reconnecting in ${delay}ms (attempt ${retryCount}/${MAX_RETRIES})`);
        setTimeout(connect, delay);
      } else {
        onClose?.();
      }
    });
    socket.addEventListener("error", (event) => onError?.(event));
  }

  connect();

  // Return a proxy with a close() that prevents reconnection
  return {
    close() {
      closed = true;
      socket?.close();
    },
    get readyState() {
      return socket?.readyState;
    }
  };
}

export async function replayLatestDemo() {
  return fetchJson("/demo/replay/latest", { method: "POST" });
}

export function reportPdfUrl() {
  return `${API_BASE}/report/pdf`;
}

export async function fetchDashboardData() {
  try {
    const latestScan = await fetchLatestScan();
    if (!latestScan) {
      return buildEmptyDashboard("No cached demo scan found. Run `python -m backend.scripts.seed_demo` first.");
    }

    const [assetSummaries, graph, attackPath, impactData, impactScenarios] = await Promise.all([
      fetchJson("/assets"),
      fetchJson("/graph"),
      fetchJson("/attack-path"),
      fetchImpact(),
      fetchImpactScenarios()
    ]);
    const assets = await Promise.all(assetSummaries.map((asset) => fetchJson(`/asset/${asset.id}`)));
    const assetsById = Object.fromEntries(assets.map((asset) => [asset.id, asset]));
    const findingRows = buildFindingRows(assets).sort(
      (left, right) => severityOrder[left.severity] - severityOrder[right.severity]
    );
    const graphModel = buildGraphModel(graph, assetsById);
    const storageFindings = assets.filter((asset) => asset.asset_type === "storage").length;
    const maxRisk = Math.max(...assets.map((asset) => asset.risk_score || 0), 0);

    // Build LLM-enhanced content in parallel
    const [narrative, killChainSteps, reportSections] = await Promise.all([
      buildNarrative(latestScan, attackPath, findingRows),
      buildKillChainSteps(attackPath, assetsById, latestScan),
      buildReportSections(latestScan, findingRows, attackPath, impactData, assets)
    ]);

    return {
      latestScan,
      summaryMetrics: [
        { label: "Exposed assets", value: String(latestScan.total_assets), tone: "neutral" },
        {
          label: "Critical findings",
          value: String(findingRows.filter((row) => row.severity === "Critical").length),
          tone: "critical"
        },
        {
          label: "Misconfigured storage",
          value: String(storageFindings),
          tone: storageFindings ? "warning" : "neutral"
        },
        { label: "Breach Exposure", value: impactData ? impactData.total_formatted.split(" - ")[1] : "Calculating...", tone: "critical" },
        { label: "Executive risk", value: `${(maxRisk / 10).toFixed(1)} / 10`, tone: "critical" }
      ],
      narrative,
      topActions: buildTopActions(findingRows),
      findingRows,
      graph: graphModel,
      nodeDetails: buildNodeDetails(graphModel, assetsById, latestScan),
      assetsById,
      killChainSteps,
      reportSections,
      impactData,
      impactScenarios
    };
  } catch (error) {
    console.error(error);
    return buildEmptyDashboard("The frontend could not reach the backend demo API. Start the API and seed a cached scan.");
  }
}

export async function fetchSimulate({ patchedAssetIds = [], patchedCveIds = [], persona = null }) {
  return fetchJson("/attack-path/simulate", {
    method: "POST",
    body: JSON.stringify({
      patched_asset_ids: patchedAssetIds,
      patched_cve_ids: patchedCveIds,
      persona,
    }),
  });
}

export async function fetchCompliance() {
  try {
    return await fetchJson("/compliance");
  } catch (error) {
    if (error.status === 404) return null;
    throw error;
  }
}

export async function fetchScanDiff(beforeId, afterId) {
  return fetchJson(`/scan/diff?before=${beforeId}&after=${afterId}`);
}

export async function fetchRulebook() {
  return fetchJson("/rulebook");
}


// Build: 1776543142
import {
  generateNarrative,
  buildExecutiveSummaryPrompt,
  buildAnalystReportPrompt,
  buildHopRationalePrompt,
  buildCtoSummaryPrompt,
} from "./llm";

// API_BASE can be:
//   - absolute ("http://host:port") for local dev hitting the backend directly
//   - path-relative ("/api") for deployed builds that go through nginx
//   - "" for same-origin with no prefix
const API_BASE = (import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000").replace(/\/$/, "");

function resolveWsBase() {
  if (/^https?:/i.test(API_BASE)) {
    return API_BASE.replace(/^http/i, "ws");
  }
  if (typeof window === "undefined") {
    return API_BASE;
  }
  const scheme = window.location.protocol === "https:" ? "wss" : "ws";
  return `${scheme}://${window.location.host}${API_BASE}`;
}

const WS_BASE = resolveWsBase();

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

function graphRiskRank(level) {
  switch ((level || "").toLowerCase()) {
    case "critical":
      return 3;
    case "high":
      return 2;
    case "medium":
      return 1;
    default:
      return 0;
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
  if (!graph || !graph.nodes) {
    return { nodes: [], edges: [] };
  }
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
    edges: (graph.edges || []).map((edge) => ({
      from: edge.source,
      to: edge.target,
      relationship: edge.relationship,
      rationale: edge.rationale,
      ruleId: edge.rule_id
    }))
  };
}

function buildSurfaceGraphModel(graph) {
  const apiNodes = Array.isArray(graph?.nodes) ? graph.nodes : [];
  const apiEdges = Array.isArray(graph?.edges) ? graph.edges : [];

  const normalizedNodes = apiNodes.map((node) => ({
    ...node,
    id: Number(node.id),
    severity: graphSeverity(node.risk_level),
    type: shortType(node.asset_type),
    label: node.label || typeLabel(node.asset_type)
  }));

  const internetNode = normalizedNodes.find(
    (node) => node.id === 0 || node.asset_type === "internet"
  );
  const assetNodes = normalizedNodes.filter((node) => node.id !== internetNode?.id);

  const sortByRisk = (left, right) => graphRiskRank(right.risk_level) - graphRiskRank(left.risk_level);
  const externalNodes = assetNodes.filter((node) => node.asset_type !== "storage").sort(sortByRisk);
  const storageNodes = assetNodes.filter((node) => node.asset_type === "storage").sort(sortByRisk);

  const laidOutNodes = [];
  if (internetNode) {
    laidOutNodes.push({
      ...internetNode,
      x: 360,
      y: 90
    });
  }

  layoutRow(externalNodes, 235).forEach((node) => laidOutNodes.push(node));
  layoutRow(storageNodes, 380).forEach((node) => laidOutNodes.push(node));

  const details = Object.fromEntries(
    laidOutNodes.map((node) => [
      node.id,
      {
        title: node.label || typeLabel(node.asset_type),
        summary:
          node.asset_type === "internet"
            ? "Entry node representing the public internet-facing attack surface."
            : `${typeLabel(node.asset_type)} node with ${node.risk_level || "low"} risk in the current graph response.`,
        bullets: [
          `Asset type: ${typeLabel(node.asset_type)}`,
          `Risk level: ${node.risk_level || "low"}`,
          node.is_crown_jewel ? "Marked as crown jewel" : "Not marked as crown jewel"
        ]
      }
    ])
  );

  const assetsById = Object.fromEntries(
    normalizedNodes.map((node) => [
      node.id,
      {
        id: node.id,
        asset_type: node.asset_type,
        risk_score: graphRiskRank(node.risk_level) * 33.3,
        is_crown_jewel: Boolean(node.is_crown_jewel),
        is_shadow_device: Boolean(node.is_shadow_device),
        label: node.label
      }
    ])
  );

  return {
    graph: {
      nodes: laidOutNodes,
      edges: apiEdges.map((edge) => ({
        from: Number(edge.source),
        to: Number(edge.target),
        relationship: edge.relationship,
        rationale: edge.rationale,
        ruleId: edge.rule_id,
        attackTechniques: edge.attack_techniques,
        evidence: edge.evidence
      }))
    },
    nodeDetails: details,
    assetsById
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

function buildKillChainSteps(attackPath, assetsById, latestScan) {
  const pathConfidence = attackPath.validation?.confidence || null;
  const hopResults = attackPath.validation?.hop_results || [];

  const steps = [
    {
      title: "External discovery",
      summary: `The replay starts from ${latestScan.domain} and walks the ${latestScan.total_assets}-asset cached surface in deterministic order.`,
      pathConfidence
    }
  ];

  if (!attackPath?.hops?.length) {
    steps.push({
      title: "Priority exposure",
      summary: "No full attack path is cached for this scan, so the demo falls back to the highest-risk public finding."
    });
    return steps;
  }

  attackPath.hops.forEach((hop, index) => {
    const asset = assetsById[hop.asset_id];
    const exposure = asset ? summarizeExposure(asset) : null;

    // Use deterministic fallback as the base summary
    const summary = (exposure
      ? `${assetLabel(asset)} becomes the next step because ${exposure.reason.toLowerCase()}`
      : `${hop.label} is included in the cached attack path.`);

    const probe = hopResults[index];
    steps.push({
      title: index === attackPath.hops.length - 1 ? "Objective reached" : `Hop ${index + 1}`,
      summary,
      ruleId: hop.rule_id,
      technique: hop.attack_techniques?.[0],
      cveId: hop.cve_id,
      hasLlmRationale: false,
      probeSuccess: probe?.success ?? null,
      probePort: probe?.port ?? null,
      probeLatencyMs: probe?.latency_ms ?? null,
      probeError: probe?.error ?? null
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

function buildReportSections(latestScan, findingRows, attackPath, impactData, assets) {
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

  const reportPrompt = buildAnalystReportPrompt(
    latestScan.total_assets,
    criticalCves,
    crownJewelLabel
  );

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

  sections.push({
    heading: "Analyst narrative",
    body: attackPath.narrative || "No attack path narrative has been computed for the current cached scan.",
    prompt: reportPrompt
  });

  sections.push({
    heading: "Recommended next steps",
    body: findingRows.slice(0, 3).map((row) => row.action).join(" ")
  });

  return sections;
}

function buildNarrative(latestScan, attackPath, findingRows) {
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

  return {
    fallback: fallback(),
    prompt: prompt
  };
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

export async function fetchSurfaceGraphData() {
  try {
    const response = await fetch(`${API_BASE}/graph`, {
      headers: {
        "Content-Type": "application/json"
      }
    });

    console.log("[SurfaceMap] /graph raw response", {
      ok: response.ok,
      status: response.status,
      url: response.url
    });

    if (!response.ok) {
      throw new Error(`Request failed for /graph with ${response.status}`);
    }

    const rawData = await response.json();
    console.log("[SurfaceMap] /graph parsed JSON", rawData);

    const { nodes = [], edges = [] } = rawData || {};
    return buildSurfaceGraphModel({ nodes, edges });
  } catch (error) {
    console.error("[SurfaceMap] Failed to load graph", error);
    throw error;
  }
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
    const criticalFindings = findingRows.filter(r => r.severity === "Critical").length;
    const totalFindings = findingRows.length;

    const allPathValidations = [
      attackPath.validation,
      ...(attackPath.alternates || []).map((p) => p.validation)
    ].filter(Boolean);
    const validationCounts = allPathValidations.reduce(
      (acc, v) => {
        const c = v.confidence;
        if (c === "CONFIRMED") acc.confirmed += 1;
        else if (c === "PARTIAL") acc.partial += 1;
        else acc.unverified += 1;
        acc.total += 1;
        return acc;
      },
      { confirmed: 0, partial: 0, unverified: 0, total: 0 }
    );

    // Build LLM-enhanced content synchronously (pass promises/prompts down)
    const narrative = buildNarrative(latestScan, attackPath, findingRows);
    const killChainSteps = buildKillChainSteps(attackPath, assetsById, latestScan);
    const reportSections = buildReportSections(latestScan, findingRows, attackPath, impactData, assets);

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
        { label: "Executive risk", value: `${(maxRisk / 10).toFixed(1)} / 10`, tone: "critical" },
        {
          label: "Paths verified",
          value: `${validationCounts.confirmed} / ${validationCounts.total}`,
          tone: validationCounts.confirmed === validationCounts.total && validationCounts.total > 0 ? "positive" : "warning"
        }
      ],
      validationCounts,
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

export async function fetchCtoSummary(domain, issueCount, criticalCount, findingRows) {
  const topFinding = findingRows && findingRows.length > 0 ? findingRows[0].reason : null;
  const prompt = buildCtoSummaryPrompt(domain, issueCount, criticalCount, topFinding);
  
  const narrative = await generateNarrative(prompt);
  if (narrative) return narrative;

  // Fallback
  return `We found ${issueCount} issues with ${domain}. ${criticalCount} are critical and need immediate attention. The most urgent issue is ${topFinding || 'an exposed area'} which anyone on the internet can access.`;
}


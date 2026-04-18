export const summaryMetrics = [
  { label: "Exposed assets", value: "37", tone: "neutral" },
  { label: "Critical findings", value: "6", tone: "critical" },
  { label: "Misconfigured storage", value: "2", tone: "warning" },
  { label: "Executive risk", value: "8.4 / 10", tone: "critical" }
];

export const topActions = [
  {
    title: "Restrict `admin.atlas-demo.com` immediately",
    detail:
      "Public admin portal exposes a legacy login page and should be moved behind VPN or IP allowlists."
  },
  {
    title: "Close public object storage",
    detail:
      "Two storage buckets allow unauthenticated listing of internal exports and staging assets."
  },
  {
    title: "Patch outdated CMS on `portal.atlas-demo.com`",
    detail:
      "Version fingerprinting indicates known high-severity CVEs with reliable exploit paths."
  }
];

export const narrative =
  "Atlas mapped the full public attack surface from a single root domain, then translated the noisy findings into a prioritized action plan a CTO can act on this week.";

export const findingRows = [
  {
    id: "F-101",
    asset: "admin.atlas-demo.com",
    kind: "Admin panel",
    severity: "Critical",
    reason: "Public login panel + exposed version header",
    action: "Restrict access and rotate credentials"
  },
  {
    id: "F-102",
    asset: "storage-atlas-demo",
    kind: "S3 bucket",
    severity: "Critical",
    reason: "Unauthenticated listing enabled",
    action: "Disable public listing and audit objects"
  },
  {
    id: "F-103",
    asset: "portal.atlas-demo.com",
    kind: "Web app",
    severity: "High",
    reason: "Outdated CMS with mapped CVEs",
    action: "Patch and place behind WAF rules"
  },
  {
    id: "F-104",
    asset: "staging.atlas-demo.com",
    kind: "Subdomain",
    severity: "High",
    reason: "Exposed test environment with debug endpoints",
    action: "Remove public exposure and disable debug mode"
  },
  {
    id: "F-105",
    asset: "blob.atlas-demo.net",
    kind: "Azure blob",
    severity: "Medium",
    reason: "Predictable naming pattern suggests open snapshots",
    action: "Require signed URLs and rotate container names"
  }
];

export const graphNodes = [
  { id: "root", label: "atlas-demo.com", x: 360, y: 100, severity: "Neutral", type: "domain" },
  { id: "portal", label: "portal.atlas-demo.com", x: 160, y: 220, severity: "High", type: "web" },
  { id: "admin", label: "admin.atlas-demo.com", x: 360, y: 260, severity: "Critical", type: "admin" },
  { id: "staging", label: "staging.atlas-demo.com", x: 580, y: 220, severity: "High", type: "staging" },
  { id: "s3", label: "storage-atlas-demo", x: 250, y: 390, severity: "Critical", type: "storage" },
  { id: "blob", label: "blob.atlas-demo.net", x: 470, y: 400, severity: "Medium", type: "storage" }
];

export const graphEdges = [
  { from: "root", to: "portal" },
  { from: "root", to: "admin" },
  { from: "root", to: "staging" },
  { from: "admin", to: "s3" },
  { from: "staging", to: "blob" }
];

export const nodeDetails = {
  root: {
    title: "Root domain",
    summary: "Seed asset used to enumerate the public-facing attack surface.",
    bullets: ["Subdomain enumeration", "Certificate inspection", "DNS resolution history"]
  },
  portal: {
    title: "Customer portal",
    summary: "Production-facing web asset fingerprinted with an outdated CMS stack.",
    bullets: ["High CVE exposure", "Login surface", "User data proximity"]
  },
  admin: {
    title: "Admin portal",
    summary: "Most dangerous public foothold because it pairs authentication with old software.",
    bullets: ["Legacy admin page", "No IP restrictions", "Credential attack surface"]
  },
  staging: {
    title: "Staging site",
    summary: "Internal testing environment accidentally indexed and publicly reachable.",
    bullets: ["Debug routes", "Verbose headers", "Potential secret leakage"]
  },
  s3: {
    title: "Open bucket",
    summary: "Storage bucket exposes internal exports without authentication.",
    bullets: ["Public listing", "Data leak risk", "Immediate remediation required"]
  },
  blob: {
    title: "Blob container",
    summary: "Likely backup or reporting storage reachable through predictable naming.",
    bullets: ["Snapshot exposure", "Access token weakness", "Review container ACLs"]
  }
};

export const killChainSteps = [
  {
    title: "External discovery",
    summary: "Attacker enumerates the root domain and finds `admin.atlas-demo.com` within minutes."
  },
  {
    title: "Initial foothold",
    summary: "Legacy admin page reveals version information and expands the exploit path."
  },
  {
    title: "Data exposure",
    summary: "Linked storage reveals exports and configuration clues that increase blast radius."
  },
  {
    title: "Internal hypothesis",
    summary: "The model projects a likely route from exposed admin tooling to internal finance systems."
  }
];

export const reportSections = [
  {
    heading: "Executive summary",
    body:
      "Atlas translates scattered internet exposure into a prioritized remediation plan tuned for a 50-person company."
  },
  {
    heading: "Critical exposures",
    body:
      "Six findings require immediate action because they combine external reachability with direct compromise paths."
  },
  {
    heading: "Recommended next steps",
    body:
      "Lock down public admin surfaces, close unauthenticated storage, patch outdated software, and add ownership tags to every discovered asset."
  }
];

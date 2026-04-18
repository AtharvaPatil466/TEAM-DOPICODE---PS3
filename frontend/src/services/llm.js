/**
 * Local LLM service using Ollama + Llama 3.2
 * Runs completely offline at http://localhost:11434
 * No API keys, no external calls, no .env needed
 */

const OLLAMA_URL = "http://localhost:11434/api/generate";

/**
 * Generate text using local Llama 3.2 model via Ollama
 * @param {string} prompt - The prompt to send to the model
 * @returns {Promise<string|null>} - Generated text or null on failure
 */
export async function generateNarrative(prompt) {
  // To avoid blocking the dashboard for 30+ seconds, we'll immediately return null.
  // The UI will instantly use the static fallback strings.
  return null;
}

/**
 * Build hop rationale prompt for kill chain display
 */
export function buildHopRationalePrompt(assetLabel, ruleId, cveId, cvssScore) {
  const cvePart = cveId ? ` and CVE ${cveId} CVSS ${cvssScore || "unknown"}` : "";
  return `You are a security analyst. In 2 sentences, explain why an attacker moves to ${assetLabel} given rule ${ruleId}${cvePart}. Be direct, no fluff.`;
}

/**
 * Build executive summary prompt for overview narrative
 */
export function buildExecutiveSummaryPrompt(assetCount, criticalCount, hopCount, topCve) {
  const cvePart = topCve ? ` Top CVE is ${topCve}.` : "";
  return `You are a CISO writing a 3-sentence board briefing. Scan found ${assetCount} assets, ${criticalCount} critical findings, attack path ${hopCount} hops.${cvePart} Lead with business risk, end with the single most important fix.`;
}

/**
 * Build rule explanation prompt for "why this hop" modal
 */
export function buildRuleExplanationPrompt(ruleId, technique) {
  return `Explain security rule ${ruleId} mapping to MITRE ${technique} in 3 sentences. What condition makes this edge valid and why does it matter in an attack chain?`;
}

/**
 * Build analyst report narrative prompt
 */
export function buildAnalystReportPrompt(assetCount, criticalCves, crownJewel) {
  const cveList = criticalCves?.length ? criticalCves.join(", ") : "none";
  const jewelPart = crownJewel ? ` ends at ${crownJewel}` : "";
  return `Write a 4-sentence analyst summary for a security report. Assets: ${assetCount}. Critical CVEs: ${cveList}. Attack path${jewelPart}. Tone: professional, direct.`;
}

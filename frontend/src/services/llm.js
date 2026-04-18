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
  try {
    const res = await fetch(OLLAMA_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "llama3.2",
        prompt,
        stream: false,
      }),
    });

    if (!res.ok) {
      return null;
    }

    const data = await res.json();
    return data.response?.trim() || null;
  } catch {
    return null;
  }
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

/**
 * Build CTO plain English summary prompt
 */
export function buildCtoSummaryPrompt(domain, issueCount, criticalCount, topFindingTitle) {
  return `Write a 1-paragraph plain English summary for a business executive. Start exactly with "We found ${issueCount} issues with ${domain}. ${criticalCount} are critical and need immediate attention." The most urgent issue is: ${topFindingTitle || 'none'}. Summarize the urgent issue in one plain English sentence without any technical jargon or CVE IDs. That is the entire summary.`;
}

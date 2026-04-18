import { generateNarrative } from './llm.js';

async function runTests() {
  console.log("Starting tests...\n");

  // Test 1: Connectivity
  try {
    const res = await fetch("http://localhost:11434/");
    if (!res.ok && res.status !== 200) {
      throw new Error("Ollama not responding properly");
    }
    console.log("[1/5] Ollama connectivity... PASS");
  } catch (err) {
    console.log("FAIL: Ollama is not running. Run 'ollama serve' first.");
    process.exit(1);
  }

  // Test 2: Model availability
  try {
    const res = await fetch("http://localhost:11434/api/tags");
    const data = await res.json();
    const modelNames = data.models.map(m => m.name);
    if (!modelNames.some(name => name.startsWith("llama3.2"))) {
      console.log("FAIL: llama3.2 not found. Run 'ollama pull llama3.2' first.");
      process.exit(1);
    }
    console.log("[2/5] llama3.2 model available... PASS");
  } catch (err) {
    console.log("FAIL: Could not check models.");
    process.exit(1);
  }

  // Test 3: Kill chain narrative
  try {
    const prompt = "You are a security analyst. In 2 sentences, explain why an attacker moves to legacy.democorp.io given rule MISC-001 and CVE CVE-2021-41773 CVSS 9.8. Be direct, no fluff.";
    const response = await generateNarrative(prompt);
    if (!response || typeof response.length !== 'number' || response.length <= 20) {
      console.log("FAIL: Empty response");
      process.exit(1);
    }
    console.log(`[3/5] Kill chain narrative... PASS\n      → "${response.replace(/\n+/g, " ").trim()}"`);
  } catch (err) {
    console.log("FAIL: Empty response");
    process.exit(1);
  }

  // Test 4: Executive summary
  try {
    const prompt = "You are a CISO writing a 3-sentence board briefing. Scan found 8 assets, 3 critical findings, attack path 4 hops, top CVE is CVE-2021-41773. Lead with business risk, end with the single most important fix.";
    const response = await generateNarrative(prompt);
    if (!response || typeof response.length !== 'number' || response.length <= 20) {
      console.log("FAIL: Empty response");
      process.exit(1);
    }
    console.log(`[4/5] Executive summary... PASS\n      → "${response.replace(/\n+/g, " ").trim()}"`);
  } catch (err) {
    console.log("FAIL: Empty response");
    process.exit(1);
  }

  // Test 5: Fallback behavior
  try {
    const originalFetch = global.fetch;
    global.fetch = async (url, options) => {
      // Temporarily point to INVALID if it's the generate endpoint
      if (typeof url === 'string' && url.includes("/api/generate")) {
        return originalFetch("http://localhost:11434/api/INVALID", options);
      }
      return originalFetch(url, options);
    };

    const response = await generateNarrative("test fallback");
    global.fetch = originalFetch;

    if (response === null) {
      console.log("[5/5] Fallback on error... PASS");
    } else {
      console.log("FAIL: Fallback did not return null");
      process.exit(1);
    }
  } catch (err) {
    console.log("FAIL: Fallback did not return null, threw an error instead");
    process.exit(1);
  }

  console.log("All tests passed. LLM integration is ready.");
}

runTests();

const TIMEOUT_MS = 15000;
const MAX_RETRIES = 2;
const RETRY_DELAYS = [1000, 2000];

function emitError(endpoint, status, message) {
  window.dispatchEvent(
    new CustomEvent("shadowtrace:apierror", {
      detail: { endpoint, status, message },
    })
  );
}

function isNetworkError(err) {
  return (
    err instanceof TypeError ||
    err.name === "TypeError" ||
    err.message === "Failed to fetch" ||
    err.message === "NetworkError when attempting to fetch resource." ||
    err.message === "Load failed" ||
    err.name === "AbortError"
  );
}

async function request(url, options = {}, retriesLeft = MAX_RETRIES) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const res = await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        "Content-Type": "application/json",
        ...(options.headers || {}),
      },
    });

    clearTimeout(timer);

    if (!res.ok) {
      const body = await res.text().catch(() => "");
      const msg = `${res.status} ${res.statusText}: ${body}`.trim();
      emitError(url, res.status, msg);
      throw new Error(msg);
    }

    return res;
  } catch (err) {
    clearTimeout(timer);

    /* Retry only on network / abort errors, not HTTP 4xx/5xx */
    if (isNetworkError(err) && retriesLeft > 0) {
      const delay = RETRY_DELAYS[MAX_RETRIES - retriesLeft] || 1000;
      await new Promise((r) => setTimeout(r, delay));
      return request(url, options, retriesLeft - 1);
    }

    /* Unrecoverable */
    if (!err.message?.startsWith("4") && !err.message?.startsWith("5")) {
      emitError(url, 0, err.message || "Network error");
    }

    throw err;
  }
}

export async function get(url) {
  const res = await request(url, { method: "GET" });
  return res.json();
}

export async function post(url, body) {
  const res = await request(url, {
    method: "POST",
    body: JSON.stringify(body),
  });
  return res.json();
}

export async function downloadBlob(url, filename) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  let res;
  let retriesLeft = MAX_RETRIES;

  while (true) {
    try {
      res = await fetch(url, { signal: controller.signal });
      clearTimeout(timer);

      if (!res.ok) {
        const msg = `Download failed: ${res.status} ${res.statusText}`;
        emitError(url, res.status, msg);
        throw new Error(msg);
      }

      break;
    } catch (err) {
      clearTimeout(timer);

      if (isNetworkError(err) && retriesLeft > 0) {
        const delay = RETRY_DELAYS[MAX_RETRIES - retriesLeft] || 1000;
        retriesLeft--;
        await new Promise((r) => setTimeout(r, delay));
        continue;
      }

      emitError(url, 0, err.message || "Download failed");
      throw err;
    }
  }

  const blob = await res.blob();
  const objectUrl = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = objectUrl;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(objectUrl);
}

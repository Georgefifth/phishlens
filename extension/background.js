
 // PhishLens service worker: risk badges + local scan history.

const COLORS = {
  dangerous: "#dc2626",
  suspicious: "#ea580c",
  caution: "#ca8a04",
  "likely safe": "#16a34a",
  unknown: "#6b7280",
};

const HISTORY_KEY = "phishlensScanHistory";
const MAX_HISTORY = 100;
const DEDUP_WINDOW_MS = 30_000;

let saveQueue = Promise.resolve();

function updateBadge(msg, tabId) {
  const short = msg.score >= 70 ? "!" : msg.score >= 40 ? "!" : String(msg.score);

  chrome.action.setBadgeText({
    tabId,
    text: msg.score >= 40 ? "!" : msg.score > 0 ? short : "",
  });

  chrome.action.setBadgeBackgroundColor({
    tabId,
    color: COLORS[msg.level] || COLORS.unknown,
  });

  chrome.action.setTitle({
    tabId,
    title: `PhishLens: ${msg.score}/100 - ${msg.level}`,
  });
}

// Remove URL credentials and redact common sensitive query values.
function sanitizeUrl(value) {
  try {
    const url = new URL(value);

    if (!["http:", "https:"].includes(url.protocol)) return null;

    url.username = "";
    url.password = "";

    const sensitive = /token|auth|password|passwd|secret|session|api.?key|access.?key|credential|otp|verification.?code/i;

    for (const key of url.searchParams.keys()) {
      if (sensitive.test(key)) {
        url.searchParams.set(key, "[REDACTED]");
      }
    }

    // Fragments can contain authentication tokens or other private values.
    url.hash = "";

    return url.href;
  } catch {
    return null;
  }
}

function normalizeScan(scan) {
  if (!scan || typeof scan !== "object") return null;

  const url = sanitizeUrl(scan.url);
  const score = Number(scan.score);

  if (!url || !Number.isFinite(score) || score < 0 || score > 100) {
    return null;
  }

  const signals = Array.isArray(scan.signals)
    ? scan.signals.slice(0, 8).map((signal) => ({
        id: String(signal?.id || "").slice(0, 100),
        title: String(signal?.title || "Warning signal").slice(0, 200),
        detail: String(signal?.detail || "").slice(0, 500),
      }))
    : [];

  return {
    url,
    score: Math.round(score),
    level: String(scan.level || "unknown").slice(0, 30),
    signals,
  };
}

async function saveScanNow(scan, tabId) {


  const record = normalizeScan(scan);
  if (!record) {
    throw new Error("Invalid scan record.");
  }

  const stored = await chrome.storage.local.get(HISTORY_KEY);
  const history = Array.isArray(stored[HISTORY_KEY])
    ? stored[HISTORY_KEY]
    : [];

  const now = Date.now();
  const signalIds = record.signals.map((s) => s.id).sort().join(",");

  const duplicate = history.find((item) => {
    const sameScan =
      item.url === record.url &&
      item.score === record.score &&
      item.level === record.level &&
      (item.signalIds || "") === signalIds &&
      item.tabId === (Number.isInteger(tabId) ? tabId : null);

    return sameScan && now - item.timestamp < DEDUP_WINDOW_MS;
  });

  if (duplicate) {
    return { saved: false, reason: "duplicate" };
  }

  const entry = {
    id: `${now}-${Math.random().toString(36).slice(2, 9)}`,
    ...record,
    timestamp: now,
    signalIds,
    tabId: Number.isInteger(tabId) ? tabId : null,
  };

  await chrome.storage.local.set({
    [HISTORY_KEY]: [entry, ...history].slice(0, MAX_HISTORY),
  });

  return { saved: true };
}

function saveScan(scan, tabId) {
  const operation = saveQueue.then(() => saveScanNow(scan, tabId));
  saveQueue = operation.catch(() => {});
  return operation;
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.type === "pl-score" && Number.isInteger(sender.tab?.id)) {
    updateBadge(msg, sender.tab.id);
    return;
  }

  if (msg?.type === "pl-save-scan") {
    saveScan(msg.scan, sender.tab?.id)
      .then(sendResponse)
      .catch((error) => {
        console.error("PhishLens: failed to save scan history.", error);
        sendResponse({ saved: false, error: "Could not save scan." });
      });

    return true;
  }
});

// Clear the badge when a tab starts navigating.
chrome.tabs.onUpdated.addListener((tabId, info) => {
  if (info.status === "loading") {
    chrome.action.setBadgeText({ tabId, text: "" });
  }
});

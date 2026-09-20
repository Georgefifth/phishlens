// PhishLens service worker: per-tab risk badge driven by content-script reports.
const COLORS = {
  dangerous: "#dc2626",
  suspicious: "#ea580c",
  caution: "#ca8a04",
  "likely safe": "#16a34a",
  unknown: "#6b7280",
};

chrome.runtime.onMessage.addListener((msg, sender) => {
  if (msg.type !== "pl-score" || !sender.tab) return;
  const tabId = sender.tab.id;
  const short = msg.score >= 70 ? "!" : msg.score >= 40 ? "!" : String(msg.score);
  chrome.action.setBadgeText({ tabId, text: msg.score >= 40 ? "!" : msg.score > 0 ? short : "" });
  chrome.action.setBadgeBackgroundColor({
    tabId,
    color: COLORS[msg.level] || COLORS.unknown,
  });
  chrome.action.setTitle({
    tabId,
    title: `PhishLens: ${msg.score}/100 — ${msg.level}`,
  });
});

// Clear badge when the tab navigates away.
chrome.tabs.onUpdated.addListener((tabId, info) => {
  if (info.status === "loading") {
    chrome.action.setBadgeText({ tabId, text: "" });
  }
});

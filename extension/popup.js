
 // PhishLens popup: active-tab verdict, URL analyzer, and scan history.

const COLORS = {
  dangerous: "#dc2626",
  suspicious: "#ea580c",
  caution: "#ca8a04",
  "likely safe": "#16a34a",
  unknown: "#6b7280",
};

const HISTORY_KEY = "phishlensScanHistory";

function paint(result) {
  const ring = document.getElementById("ring");
  const lvl = document.getElementById("lvl");
  const host = document.getElementById("host");
  const sigs = document.getElementById("sigs");

  if (!result || !result.ok) {
    ring.textContent = "?";
    lvl.textContent = "no data";
    ring.style.background = "#1e293b";
    ring.style.border = "0";
    host.textContent = "";
    sigs.replaceChildren();
    return;
  }

  const color = COLORS[result.level] || COLORS.unknown;
  ring.textContent = result.score;
  ring.style.background = color + "33";
  ring.style.border = `3px solid ${color}`;
  lvl.textContent = result.level;
  lvl.style.color = color;
  host.textContent = result.host || "";
  sigs.replaceChildren();

  for (const signal of (result.signals || []).slice(0, 6)) {
    const li = document.createElement("li");
    li.className = signal.severity || "";

    const title = document.createElement("b");
    title.textContent = signal.title || "Warning signal";

    const detail = document.createElement("span");
    detail.textContent = signal.detail || "";

    li.append(title, detail);
    sigs.appendChild(li);
  }
}

async function currentTabResult() {
  try {
    const [tab] = await chrome.tabs.query({
      active: true,
      currentWindow: true,
    });

    if (!tab) return;

    const result = await chrome.tabs.sendMessage(tab.id, {
      type: "pl-get-result",
    });

    paint(result);
  } catch {
    paint({ ok: false });
  }
}

function addHistoryText(parent, tag, className, value) {
  const element = document.createElement(tag);
  element.className = className;
  element.textContent = value;
  parent.appendChild(element);
  return element;
}

function formatTime(timestamp) {
  const date = new Date(timestamp);

  if (Number.isNaN(date.getTime())) return "Unknown time";

  return date.toLocaleString([], {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}


function exportScanReport(scan) {
  const report = {
    reportTitle: "PhishLens Scan Report",
    generatedAt: new Date().toISOString(),
    scan: {
      url: scan.url,
      scannedAt: new Date(scan.timestamp).toISOString(),
      score: scan.score,
      verdict: scan.level,
      signals: (scan.signals || []).map((signal) => ({
        title: signal.title,
        detail: signal.detail,
      })),
    },
    disclaimer:
      "PhishLens uses client-side heuristic analysis. Its verdict is an indicator, not a guarantee that a website is safe or malicious.",
  };

  const blob = new Blob(
    [JSON.stringify(report, null, 2)],
    { type: "application/json" }
  );

  const downloadUrl = URL.createObjectURL(blob);
  const link = document.createElement("a");

  link.href = downloadUrl;
  link.download = `phishlens-report-${Date.now()}.json`;
  link.click();

  setTimeout(() => URL.revokeObjectURL(downloadUrl), 1000);
}



function exportHtmlReport(scan) {
  const escapeHtml = (value) =>
    String(value ?? "").replace(/[&<>"']/g, (char) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    })[char]);

  const colors = {
    dangerous: "#dc2626",
    suspicious: "#ea580c",
    caution: "#ca8a04",
    "likely safe": "#16a34a",
    unknown: "#64748b",
  };

  const level = String(scan.level || "unknown");
  const color = colors[level] || colors.unknown;
  const signals = Array.isArray(scan.signals) ? scan.signals : [];

  const signalHtml = signals.length
    ? signals.map((signal) => `
        <article class="signal">
          <h3>${escapeHtml(signal.title || "Warning signal")}</h3>
          <p>${escapeHtml(signal.detail || "")}</p>
        </article>
      `).join("")
    : "<p>No detection signals were recorded.</p>";

  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PhishLens Scan Report</title>
<style>
  body{font:15px/1.6 Arial,sans-serif;max-width:760px;margin:40px auto;padding:0 20px;color:#1e293b}
  header{border-bottom:2px solid #e2e8f0;padding-bottom:16px}
  h1{margin-bottom:4px}
  .muted{color:#64748b;font-size:13px}
  .summary{margin:24px 0;padding:20px;border-radius:10px;background:#f8fafc;border-left:5px solid ${color}}
  .score{font-size:32px;font-weight:bold;color:${color}}
  .url{overflow-wrap:anywhere}
  .signal{padding:12px 16px;margin:12px 0;border:1px solid #e2e8f0;border-radius:8px}
  .signal h3{margin:0 0 6px;font-size:16px}
  .signal p{margin:0;color:#475569}
  footer{margin-top:28px;padding-top:16px;border-top:1px solid #e2e8f0;color:#64748b;font-size:12px}
</style>
</head>
<body>
<header>
  <h1>PhishLens Scan Report</h1>
  <div class="muted">Generated ${escapeHtml(new Date().toLocaleString())}</div>
</header>
<section class="summary">
  <div class="score">${escapeHtml(scan.score)}/100</div>
  <strong>Verdict: ${escapeHtml(level)}</strong>
  <p class="url"><strong>Scanned URL:</strong> ${escapeHtml(scan.url)}</p>
  <p><strong>Scan time:</strong> ${escapeHtml(new Date(scan.timestamp).toLocaleString())}</p>
</section>
<h2>Detection signals</h2>
${signalHtml}
<footer>
  PhishLens uses client-side heuristic analysis. This verdict is an indicator, not a guarantee that a website is safe or malicious. HTTPS alone does not establish trustworthiness.
</footer>
</body>
</html>`;

  const blob = new Blob([html], { type: "text/html;charset=utf-8" });
  const downloadUrl = URL.createObjectURL(blob);
  const link = document.createElement("a");

  link.href = downloadUrl;
  link.download = `phishlens-report-${Date.now()}.html`;
  link.click();

  setTimeout(() => URL.revokeObjectURL(downloadUrl), 1000);
}


async function loadHistory() {
  const list = document.getElementById("history-list");
  list.replaceChildren();

  try {
    const stored = await chrome.storage.local.get(HISTORY_KEY);
    const history = Array.isArray(stored[HISTORY_KEY])
      ? stored[HISTORY_KEY]
      : [];

    if (history.length === 0) {
      addHistoryText(
        list,
        "div",
        "history-empty",
        "No scans saved yet."
      );
      return;
    }

    for (const scan of history) {
      const item = document.createElement("div");
      item.className = "history-item";

      addHistoryText(item, "div", "history-url", scan.url || "Unknown URL");

      const meta = document.createElement("div");
      meta.className = "history-meta";

      const color = COLORS[scan.level] || COLORS.unknown;

      const verdict = addHistoryText(
        meta,
        "span",
        "",
        `${Number(scan.score) || 0}/100 · ${scan.level || "unknown"}`
      );
      verdict.style.color = color;

      addHistoryText(meta, "span", "", formatTime(scan.timestamp));

      
      item.append(meta);

      const exportButton = document.createElement("button");
      exportButton.className = "export-button secondary";
      exportButton.textContent = "Export report";

      exportButton.addEventListener("click", () => {
        exportScanReport(scan);
      });

      
const htmlButton = document.createElement("button");
htmlButton.className = "export-button secondary";
htmlButton.textContent = "Export HTML";

htmlButton.addEventListener("click", () => {
  exportHtmlReport(scan);
});


      item.append(exportButton, htmlButton);
list.appendChild(item);
    }
  } catch (error) {
    console.error("PhishLens: could not load scan history.", error);
    addHistoryText(
      list,
      "div",
      "history-empty",
      "Could not load history. Try refreshing."
    );
  }
}

document.getElementById("refresh-history").addEventListener("click", () => {
  loadHistory();
});

document.getElementById("clear-history").addEventListener("click", async () => {
  const confirmed = confirm(
    "Clear all saved scan history? This cannot be undone."
  );

  if (!confirmed) return;

  try {
    await chrome.storage.local.set({ [HISTORY_KEY]: [] });
    await loadHistory();
  } catch (error) {
    console.error("PhishLens: could not clear scan history.", error);
    alert("Could not clear history. Please try again.");
  }
});

document.getElementById("go").addEventListener("click", async () => {
  const input = document.getElementById("url");
  const output = document.getElementById("res");
  const value = input.value.trim();

  if (!value) return;

  try {
    const result = window.PhishLens.analyzeUrl(value);
    const color = COLORS[result.level] || COLORS.unknown;

    output.replaceChildren();

    const gauge = document.createElement("div");
    gauge.className = "gauge";
    gauge.style.marginTop = "8px";

    const ring = document.createElement("div");
    ring.className = "ring";
    ring.textContent = result.score;
    ring.style.background = color + "33";
    ring.style.border = `3px solid ${color}`;

    const info = document.createElement("div");

    const level = addHistoryText(
      info,
      "div",
      "lvl",
      result.level || "unknown"
    );
    level.style.color = color;

    addHistoryText(info, "div", "host", result.host || "");
    gauge.append(ring, info);
    output.appendChild(gauge);

    const signalsList = document.createElement("ul");

    for (const signal of (result.signals || []).slice(0, 6)) {
      const li = document.createElement("li");
      li.className = signal.severity || "";

      addHistoryText(li, "b", "", signal.title || "Warning signal");
      addHistoryText(li, "span", "", signal.detail || "");

      signalsList.appendChild(li);
    }

    output.appendChild(signalsList);

    // Save manually analyzed URLs to local history too.
    try {
      await chrome.runtime.sendMessage({
        type: "pl-save-scan",
        scan: {
          url: value,
          score: result.score,
          level: result.level,
          signals: result.signals || [],
        },
      });
    } catch (error) {
      console.error("PhishLens: could not save analyzed URL.", error);
    }

    await loadHistory();
  } catch (error) {
    console.error("PhishLens: URL analysis failed.", error);
    output.textContent = "Could not analyze this URL. Check the link and try again.";
  }
});

document.getElementById("url").addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    document.getElementById("go").click();
  }
});

currentTabResult();
loadHistory();

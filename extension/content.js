// PhishLens content script: snapshots page signals, runs the local engine,
// reports the score to the badge, and injects an explainable warning banner.
(function () {
  "use strict";
  if (window.__phishlensLoaded) return;
  window.__phishlensLoaded = true;

  function snapshot() {
    const host = location.hostname.toLowerCase();
    const forms = Array.from(document.querySelectorAll("form")).map((f) => ({
      action: f.getAttribute("action") || "",
      method: (f.getAttribute("method") || "get").toLowerCase(),
      hasPassword: !!f.querySelector('input[type="password"]'),
    }));
    const inputs = Array.from(document.querySelectorAll("input,select,textarea"));
    const inputNames = inputs
      .flatMap((i) => [i.name, i.id, i.placeholder, i.getAttribute("aria-label")])
      .filter(Boolean);
    const iframes = Array.from(document.querySelectorAll("iframe"));
    const hiddenIframes = iframes.filter((f) => {
      const r = f.getBoundingClientRect();
      const s = getComputedStyle(f);
      return r.width < 5 || r.height < 5 || s.display === "none" || s.visibility === "hidden";
    }).length;
    const anchors = Array.from(document.querySelectorAll("a[href]"));
    const externalLinks = anchors.filter((a) => {
      try {
        const h = new URL(a.href, location.href).hostname.toLowerCase();
        return h && h !== host && /^https?$/i.test(new URL(a.href, location.href).protocol);
      } catch (e) { return false; }
    }).length;
    return {
      url: location.href,
      passwordFields: document.querySelectorAll('input[type="password"]').length,
      forms,
      inputNames,
      hiddenIframes,
      externalLinks,
      totalLinks: anchors.length,
      text: (document.body ? document.body.innerText : "").slice(0, 60000),
    };
  }

  const LEVEL_COLOR = {
    dangerous: "#dc2626",
    suspicious: "#ea580c",
    caution: "#ca8a04",
    "likely safe": "#16a34a",
  };

  let lastResult = null;
  let bannerEl = null;

  function injectBanner(result) {
    if (bannerEl) bannerEl.remove();
    const color = LEVEL_COLOR[result.level] || "#ca8a04";
    const host = document.createElement("div");
    host.id = "phishlens-banner";
    const shadow = host.attachShadow({ mode: "open" });
    const top = result.signals.filter((s) => s.weight > 0).slice(0, 4);
    shadow.innerHTML = `
      <style>
        .bar{position:fixed;top:0;left:0;right:0;z-index:2147483647;
          background:${color};color:#fff;font:14px/1.45 -apple-system,Segoe UI,Roboto,sans-serif;
          padding:10px 16px;box-shadow:0 2px 12px rgba(0,0,0,.35);}
        .row{display:flex;align-items:center;gap:10px;max-width:1100px;margin:0 auto}
        .score{font-weight:800;font-size:18px;white-space:nowrap}
        .lvl{text-transform:uppercase;font-weight:700;letter-spacing:.5px;
          border:1px solid rgba(255,255,255,.6);border-radius:4px;padding:1px 6px;font-size:11px}
        ul{margin:6px 0 0;padding-left:18px;max-width:1100px}
        li{margin:2px 0}
        .title{flex:1}
        button{background:rgba(0,0,0,.25);border:0;color:#fff;border-radius:4px;
          padding:4px 10px;cursor:pointer;font-size:12px}
        .brand{font-weight:800}
      </style>
      <div class="bar">
        <div class="row">
          <span class="brand">PhishLens</span>
          <span class="score">${result.score}/100</span>
          <span class="lvl">${result.level}</span>
          <span class="title">This page shows ${top.length} phishing signal${top.length === 1 ? "" : "s"}:</span>
          <button id="pl-close">dismiss</button>
        </div>
        <ul>${top.map((s) => `<li><b>${s.title}</b> — ${s.detail}</li>`).join("")}</ul>
      </div>`;
    shadow.getElementById("pl-close").onclick = () => host.remove();
    (document.documentElement || document.body).appendChild(host);
    bannerEl = host;
    // push page content down so the banner doesn't cover the site header
    document.documentElement.style.marginTop = "0px";
    document.body && (document.body.style.paddingTop = "90px");
  }

  function run() {
    if (!window.PhishLens) return;
    const snap = snapshot();
    lastResult = window.PhishLens.analyze(location.href, snap);
    lastResult.pageSignals = lastResult.signals.filter((s) =>
      ["form-http", "form-xdomain", "form-noaction", "cred-lookalike",
       "sensitive-fields", "hidden-iframe", "ext-links", "urgency"].includes(s.id));
    try {
      chrome.runtime.sendMessage({
        type: "pl-score", score: lastResult.score, level: lastResult.level,
      });
    } catch (e) {}
    if (lastResult.score >= 40) injectBanner(lastResult);
  }

  // Re-run when SPA content settles; also answer popup queries.
  run();
  let t;
  new MutationObserver(() => {
    clearTimeout(t);
    t = setTimeout(() => {
      const prev = lastResult && lastResult.score;
      run();
      if (lastResult.score < 40 && prev >= 40 && bannerEl) { bannerEl.remove(); bannerEl = null; }
    }, 1200);
  }).observe(document.documentElement, { childList: true, subtree: true });

  chrome.runtime.onMessage.addListener((msg, _s, reply) => {
    if (msg.type === "pl-get-result") reply(lastResult);
    if (msg.type === "pl-rescan") { run(); reply(lastResult); }
    return true;
  });
})();

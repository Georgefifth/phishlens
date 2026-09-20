// PhishLens popup: shows the active tab's verdict + a paste-a-link analyzer.
const COLORS = {
  dangerous: "#dc2626", suspicious: "#ea580c",
  caution: "#ca8a04", "likely safe": "#16a34a", unknown: "#6b7280",
};

function paint(result) {
  const ring = document.getElementById("ring");
  const lvl = document.getElementById("lvl");
  const host = document.getElementById("host");
  const sigs = document.getElementById("sigs");
  if (!result || !result.ok) {
    ring.textContent = "?"; lvl.textContent = "no data";
    ring.style.background = "#1e293b"; return;
  }
  const c = COLORS[result.level] || COLORS.unknown;
  ring.textContent = result.score;
  ring.style.background = c + "33";
  ring.style.border = `3px solid ${c}`;
  lvl.textContent = result.level;
  lvl.style.color = c;
  host.textContent = result.host || "";
  sigs.innerHTML = "";
  for (const s of result.signals.slice(0, 6)) {
    const li = document.createElement("li");
    li.className = s.severity;
    li.innerHTML = `<b>${s.title}</b><span>${s.detail}</span>`;
    sigs.appendChild(li);
  }
}

async function currentTabResult() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) return;
    const res = await chrome.tabs.sendMessage(tab.id, { type: "pl-get-result" });
    paint(res);
  } catch (e) {
    paint({ ok: false });
  }
}

document.getElementById("go").onclick = () => {
  const v = document.getElementById("url").value.trim();
  if (!v) return;
  const r = window.PhishLens.analyzeUrl(v);
  const c = COLORS[r.level] || COLORS.unknown;
  document.getElementById("res").innerHTML =
    `<div class="gauge" style="margin-top:8px">
       <div class="ring" style="background:${c}33;border:3px solid ${c}">${r.score}</div>
       <div><div class="lvl" style="color:${c}">${r.level}</div>
       <div class="host">${r.host || ""}</div></div></div>
     <ul>${r.signals.slice(0, 6).map((s) =>
       `<li class="${s.severity}"><b>${s.title}</b><span>${s.detail}</span></li>`).join("")}</ul>`;
};
document.getElementById("url").addEventListener("keydown", (e) => {
  if (e.key === "Enter") { e.preventDefault(); document.getElementById("go").click(); }
});

currentTabResult();

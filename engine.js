/*
 * PhishLens engine — client-side phishing risk analysis.
 * Pure JavaScript, zero dependencies, zero network calls.
 * Runs identically inside the browser extension (content script / popup)
 * and the web demo page. Also loadable in Node for testing.
 *
 * Every check returns an explainable signal — education is part of the product.
 */
(function (global) {
  "use strict";

  // ---- reference data -------------------------------------------------------

  // Brands commonly impersonated in phishing, mapped to their real domains.
  const BRANDS = {
    paypal: ["paypal.com"],
    amazon: ["amazon.com"],
    apple: ["apple.com", "icloud.com"],
    google: ["google.com", "accounts.google.com"],
    microsoft: ["microsoft.com", "live.com", "outlook.com", "office.com"],
    netflix: ["netflix.com"],
    facebook: ["facebook.com", "fb.com", "meta.com"],
    instagram: ["instagram.com"],
    twitter: ["twitter.com", "x.com"],
    linkedin: ["linkedin.com"],
    chase: ["chase.com"],
    wellsfargo: ["wellsfargo.com"],
    bankofamerica: ["bankofamerica.com"],
    coinbase: ["coinbase.com"],
    binance: ["binance.com"],
    dhl: ["dhl.com"],
    fedex: ["fedex.com"],
    usps: ["usps.com"],
    irs: ["irs.gov"],
    steam: ["steampowered.com", "steamcommunity.com"],
    discord: ["discord.com", "discordapp.com"],
    roblox: ["roblox.com"],
    tiktok: ["tiktok.com"],
    whatsapp: ["whatsapp.com"],
    dropbox: ["dropbox.com"],
    adobe: ["adobe.com"],
    zoom: ["zoom.us"],
    ebay: ["ebay.com"],
    spotify: ["spotify.com"],
  };

  // Free/disposable and frequently-abused TLDs (Freenom + low-cost stats).
  const SUS_TLDS = new Set([
    "tk", "ml", "ga", "cf", "gq", "top", "buzz", "cam", "rest", "quest",
    "monster", "icu", "click", "country", "stream", "download", "loan",
    "racing", "win", "bid", "date", "review", "party", "gdn", "men",
    "work", "zip", "mov",
  ]);

  const SHORTENERS = new Set([
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly",
    "s.id", "bit.do", "soo.gd", "clck.ru", "v.gd",
  ]);

  // Credential-theft vocabulary in URL paths.
  const PATH_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification", "secure",
    "account", "update", "billing", "confirm", "suspend", "unlock",
    "wallet", "recover", "password", "credential", "authenticate",
    "webscr", "oauth", "validate", "reauth",
  ];

  // Scare/urgency phrases scanned in visible page text.
  const URGENCY_PHRASES = [
    "verify your account", "account suspended", "account has been suspended",
    "unusual activity", "suspicious activity", "confirm your identity",
    "immediately", "within 24 hours", "24 hours", "limited time",
    "act now", "urgent", "final notice", "last warning", "will be closed",
    "will be suspended", "legal action", "avoid suspension", "restricted",
    "unauthorized", "locked your account", "verify now", "update your payment",
    "payment declined", "claim your prize", "you have won", "congratulations",
    "wire transfer", "gift card", "bitcoin", "crypto", "refund",
  ];

  // Keyboard-order / random-looking SLDs score high on this cheap entropy test.
  const COMMON_SLD_WORDS = /^(mail|email|shop|store|news|blog|app|web|site|online|cloud|data|tech|media|group|inc|corp|home|my|the|get|go)/;

  // Confusable character map: visually-similar chars folded to ASCII.
  const CONFUSABLES = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "6": "g", "7": "t",
    "8": "b", "9": "g", "@": "a", "$": "s", "!": "i", "|": "l",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "і": "i",
    "ј": "j", "ѕ": "s", "һ": "h", "ո": "n", "օ": "o", "α": "a", "ο": "o",
    "ρ": "p", "τ": "t", "υ": "u", "ν": "v", "κ": "k", "μ": "m", "χ": "x",
  };
  const MULTI_CONFUSABLES = [
    [/rn/g, "m"], [/vv/g, "w"], [/cl/g, "d"], [/nn/g, "n"],
  ];

  const IP_HOST = /^(\d{1,3}\.){3}\d{1,3}$|^\[?[0-9a-f:]+\]?$/i;

  // ---- helpers --------------------------------------------------------------

  function levenshtein(a, b) {
    if (a === b) return 0;
    const m = a.length, n = b.length;
    if (!m) return n;
    if (!n) return m;
    let prev = Array.from({ length: n + 1 }, (_, i) => i);
    for (let i = 1; i <= m; i++) {
      const cur = [i];
      for (let j = 1; j <= n; j++) {
        cur[j] = Math.min(
          prev[j] + 1,
          cur[j - 1] + 1,
          prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
        );
      }
      prev = cur;
    }
    return prev[n];
  }

  function shannon(s) {
    if (!s.length) return 0;
    const freq = {};
    for (const c of s) freq[c] = (freq[c] || 0) + 1;
    return Object.values(freq).reduce(
      (e, f) => e - (f / s.length) * Math.log2(f / s.length), 0
    );
  }

  // Fold confusables to a canonical ASCII-ish form for brand comparison.
  function deobfuscate(sld) {
    let out = "";
    for (const ch of sld.toLowerCase()) out += CONFUSABLES[ch] || ch;
    for (const [re, rep] of MULTI_CONFUSABLES) out = out.replace(re, rep);
    return out;
  }

  const EXEC_EXTS = [".exe", ".msi", ".apk", ".scr", ".bat", ".cmd", ".ps1",
    ".jar", ".vbs", ".js", ".iso", ".dmg", ".pkg", ".hta"];

  const EMAIL_RE = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i;

  // Best-effort registrable domain (SLD + public suffix, no PSL dependency).
  function registrable(host) {
    const parts = host.split(".");
    if (parts.length < 2) return host;
    const last = parts[parts.length - 1];
    const second = parts[parts.length - 2];
    // crude two-level suffix handling (co.uk, com.au, ...)
    if (second.length <= 3 && ["co", "com", "net", "org", "gov", "ac", "edu"].includes(second)) {
      return parts.slice(-3).join(".");
    }
    return parts.slice(-2).join(".");
  }

  function sldOf(host) {
    const reg = registrable(host);
    return reg.split(".")[0];
  }

  function tldOf(host) {
    const parts = host.split(".");
    return parts.length > 1 ? parts[parts.length - 1].toLowerCase() : "";
  }

  function isBrandDomain(host) {
    return Object.values(BRANDS).flat().some(
      (d) => host === d || host.endsWith("." + d)
    );
  }

  function signal(id, weight, severity, title, detail) {
    return { id, weight, severity, title, detail };
  }

  // ---- URL analysis -----------------------------------------------------------

  function analyzeUrl(raw) {
    const signals = [];
    let url;
    const input = String(raw || "").trim();
    if (!input) {
      return { ok: false, error: "empty input", score: 0, level: "unknown", signals };
    }
    try {
      // has explicit scheme (incl. non-HTTP like data:/javascript:) → parse as-is
      url = new URL(/^[a-z][a-z0-9+.-]*:/i.test(input) ? input : "http://" + input);
    } catch (e) {
      return { ok: false, error: "unparseable URL", score: 0, level: "unknown", signals, input };
    }

    // Non-HTTP(S) schemes are checked before host parsing.
    if (url.protocol === "data:") {
      signals.push(signal("data-uri", 55, "high", "data: URI link",
        "data: URLs smuggle a whole payload inside the link itself — a known phishing channel that bypasses domain checks."));
      return finalize(signals, input, url);
    }
    if (["javascript:", "vbscript:", "file:", "about:", "blob:"].includes(url.protocol)) {
      signals.push(signal("danger-scheme", 55, "high", `Dangerous scheme "${url.protocol}"`,
        "This link executes content directly — never part of a legitimate login flow."));
      return finalize(signals, input, url);
    }

    const host = url.hostname.toLowerCase();
    const path = (url.pathname + url.search).toLowerCase();
    const sld = sldOf(host);
    const tld = tldOf(host);
    const reg = registrable(host);
    const subCount = host.split(".").length - reg.split(".").length;

    // Transport & scheme
    if (url.protocol === "http:") {
      signals.push(signal("http", 12, "med", "No encryption (HTTP)",
        "Credentials sent over HTTP are transmitted in plaintext."));
    } else if (!/^https?:$/.test(url.protocol)) {
      signals.push(signal("scheme", 15, "med", `Unusual scheme "${url.protocol}"`,
        "Non-HTTP(S) schemes in links are rare in legitimate messages."));
    }
    if (url.protocol === "https:") {
      signals.push(signal("https", -5, "good", "Encrypted connection (HTTPS)",
        "HTTPS is baseline hygiene — but does not by itself prove legitimacy."));
    }

    // Host shape
    if (IP_HOST.test(host)) {
      signals.push(signal("ip-host", 35, "high", "Raw IP address as hostname",
        "Legitimate services almost never ask you to log in on a bare IP."));
    }
    if (url.username || url.password) {
      signals.push(signal("at-sign", 50, "high", "Credentials embedded in URL",
        `The 'user@host' trick hides the real destination — everything before '@' is ignored; the true host is '${host}'.`));
    }
    if (host.includes("xn--") || url.href.includes("xn--")) {
      signals.push(signal("punycode", 40, "high", "Punycode/IDN hostname",
        "Internationalized domains can render lookalike characters (e.g. 'аррӏе.com')."));
    }
    if (SUS_TLDS.has(tld)) {
      signals.push(signal("tld", 18, "med", `High-abuse TLD ".${tld}"`,
        "This TLD is cheap/free and statistically over-represented in phishing."));
    }
    if (SHORTENERS.has(reg)) {
      signals.push(signal("shortener", 15, "med", "URL shortener",
        "Short links hide the true destination — expand before trusting."));
    }
    if (subCount >= 3) {
      signals.push(signal("subdomains", 15, "med", `${subCount} nested subdomains`,
        "Long chains like 'paypal.com.secure.login.evil.com' bury the real domain."));
    } else if (subCount === 2) {
      signals.push(signal("subdomains", 6, "low", "Multiple subdomains",
        "Slightly unusual nesting — check the registrable domain carefully."));
    }
    const hyphens = (sld.match(/-/g) || []).length;
    if (hyphens >= 2) {
      signals.push(signal("hyphens", 10, "low", `${hyphens} hyphens in domain`,
        "Stuffing like 'secure-login-verify' is a classic phishing tell."));
    }
    if (input.length > 100) {
      signals.push(signal("length", 8, "low", `Very long URL (${input.length} chars)`,
        "Overlong URLs are often used to push the real domain out of view."));
    }
    if ((host.match(/\d/g) || []).length >= 4 && !IP_HOST.test(host)) {
      signals.push(signal("digits", 8, "low", "Many digits in hostname",
        "Random-looking digit strings are common in disposable phishing domains."));
    }

    // Brand impersonation
    if (!isBrandDomain(host)) {
      const deob = deobfuscate(sld);
      for (const [brand] of Object.entries(BRANDS)) {
        const dist = levenshtein(deob, brand);
        if (deob !== brand && dist <= 2 && dist > 0) {
          signals.push(signal("typosquat", 45, "high",
            `Lookalike of "${brand}" (edit distance ${dist})`,
            `'${host}' differs subtly from the real ${BRANDS[brand][0]} — a typosquat.`));
          break;
        }
        if (dist === 0 && deob !== sld) {
          signals.push(signal("homoglyph", 45, "high",
            `Homoglyph impersonation of "${brand}"`,
            `'${sld}' uses lookalike characters to spell '${brand}'.`));
          break;
        }
      }
      // brand name embedded in hostname while real domain is something else
      for (const [brand, domains] of Object.entries(BRANDS)) {
        const owned = domains.some((d) => host === d || host.endsWith("." + d));
        if (!owned && host.includes(brand)) {
          signals.push(signal("brand-in-host", 35, "high",
            `"${brand}" appears in hostname but domain is '${reg}'`,
            "Attackers prepend brand names as subdomains to look legitimate."));
          break;
        }
      }
    }

    // Path keywords (only suspicious off-brand)
    const kwHits = PATH_KEYWORDS.filter((k) => path.includes(k));
    if (kwHits.length && !isBrandDomain(host)) {
      signals.push(signal("path-kw", Math.min(20, 6 + kwHits.length * 4), "med",
        `Credential-bait keywords in path (${kwHits.slice(0, 4).join(", ")})`,
        "Login/verify/billing lures on an unrelated domain are a phishing pattern."));
    }

    // Executable download in path
    const execExt = EXEC_EXTS.find((e) => url.pathname.toLowerCase().endsWith(e));
    if (execExt) {
      signals.push(signal("exec-download", 40, "high",
        `Direct download of executable (${execExt})`,
        "Links that download programs are drive-by malware bait — especially from messages."));
    }

    // Victim email embedded in URL (pre-filled phishing lures)
    if (EMAIL_RE.test(path) || EMAIL_RE.test(url.search)) {
      signals.push(signal("email-in-url", 25, "med",
        "An email address is embedded in the URL",
        "Phishers pre-fill lures with your address to make the page look personal."));
    }

    // Non-standard port
    if (url.port && !["80", "443"].includes(url.port)) {
      signals.push(signal("odd-port", 15, "med", `Non-standard port :${url.port}`,
        "Legitimate login pages almost never live on alternate ports."));
    }

    // Random-looking domain
    if (sld.length >= 12 && shannon(sld) > 3.6 && !COMMON_SLD_WORDS.test(sld)) {
      signals.push(signal("entropy", 12, "med", "Random-looking domain name",
        `High character entropy (${shannon(sld).toFixed(1)} bits) suggests a generated domain.`));
    }

    // Benign bonus
    if (isBrandDomain(host)) {
      signals.push(signal("brand-official", -20, "good",
        "Official brand domain", `Hostname belongs to a known legitimate domain.`));
    }

    return finalize(signals, input, url);
  }

  // ---- page/DOM analysis ------------------------------------------------------

  // snapshot: {url, passwordFields, forms:[{action,method,hasPassword}],
  //            inputNames:[], hiddenIframes, externalLinks, totalLinks, text}
  function analyzePage(snap) {
    const signals = [];
    let pageHost = "";
    try { pageHost = new URL(snap.url).hostname.toLowerCase(); } catch (e) {}

    for (const f of snap.forms || []) {
      if (!f.hasPassword) continue;
      if (!f.action) {
        signals.push(signal("form-noaction", 15, "med",
          "Password form with no declared destination",
          "The submit target is set dynamically — a common credential-harvest pattern."));
        continue;
      }
      let a;
      try { a = new URL(f.action, snap.url); } catch (e) { continue; }
      if (a.protocol === "http:") {
        signals.push(signal("form-http", 45, "high",
          "Password submitted over plaintext HTTP",
          "Anything you type here is sent unencrypted."));
      } else if (a.hostname.toLowerCase() !== pageHost &&
                 registrable(a.hostname.toLowerCase()) !== registrable(pageHost)) {
        signals.push(signal("form-xdomain", 45, "high",
          `Password form posts to a different domain (${a.hostname})`,
          "Legitimate login forms almost never send credentials cross-site."));
      }
    }
    if ((snap.passwordFields || 0) > 0 && pageHost && !isBrandDomain(pageHost)) {
      const sld = sldOf(pageHost);
      const deob = deobfuscate(sld);
      for (const [brand] of Object.entries(BRANDS)) {
        if (levenshtein(deob, brand) <= 2 && deob !== brand) {
          signals.push(signal("cred-lookalike", 30, "high",
            `Login form on a ${brand}-lookalike domain`,
            "A password box on an impersonation domain is the endgame of phishing."));
          break;
        }
      }
    }

    const sensitive = (snap.inputNames || []).filter((n) =>
      /ssn|social.?sec|cvv|cvc|card.?num|otp|one.?time|pin|seed.?phrase|private.?key/i.test(n));
    if (sensitive.length) {
      signals.push(signal("sensitive-fields", 25, "high",
        `Page asks for high-value data (${sensitive.slice(0, 3).join(", ")})`,
        "Requests for SSNs, card CVVs, OTPs or seed phrases deserve scrutiny."));
    }

    if ((snap.hiddenIframes || 0) > 0) {
      signals.push(signal("hidden-iframe", 20, "med",
        `${snap.hiddenIframes} hidden iframe(s)`,
        "Invisible frames are used for clickjacking and silent redirects."));
    }

    if ((snap.totalLinks || 0) >= 10 && (snap.externalLinks || 0) / snap.totalLinks > 0.9) {
      signals.push(signal("ext-links", 10, "low",
        "Nearly all links point off-site",
        "Throwaway phishing pages often link out instead of hosting real content."));
    }

    const text = (snap.text || "").toLowerCase();
    const hits = URGENCY_PHRASES.filter((p) => text.includes(p));
    if (hits.length) {
      signals.push(signal("urgency", Math.min(30, 8 + hits.length * 5), "med",
        `Pressure language detected (${hits.length} phrases)`,
        `e.g. "${hits[0]}" — urgency and fear are core social-engineering levers.`));
    }

    return signals;
  }

  // ---- scoring ---------------------------------------------------------------

  function finalize(signals, input, url) {
    const raw = signals.reduce((s, x) => s + x.weight, 0);
    const score = Math.max(0, Math.min(100, Math.round(raw)));
    const level =
      score >= 70 ? "dangerous" :
      score >= 40 ? "suspicious" :
      score >= 15 ? "caution" : "likely safe";
    return {
      ok: true, input, score, level,
      host: url ? url.hostname : undefined,
      signals: signals.sort((a, b) => b.weight - a.weight),
    };
  }

  function analyze(raw, snap) {
    const urlResult = analyzeUrl(raw);
    if (snap) {
      const extra = analyzePage(snap);
      urlResult.signals = urlResult.signals.concat(extra)
        .sort((a, b) => b.weight - a.weight);
      const re = finalize(urlResult.signals, urlResult.input,
        (() => { try { return new URL(urlResult.input); } catch (e) { return null; } })());
      urlResult.score = re.score;
      urlResult.level = re.level;
    }
    return urlResult;
  }

  const api = { analyzeUrl, analyzePage, analyze, BRANDS, levenshtein, deobfuscate };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else global.PhishLens = api;
})(typeof window !== "undefined" ? window : globalThis);

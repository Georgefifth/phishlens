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
    paypal: ["paypal.com", "paypal-objects.com"],
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
    ledger: ["ledger.com"],
    trezor: ["trezor.io"],
    metamask: ["metamask.io"],
    trustwallet: ["trustwallet.com"],
    kraken: ["kraken.com"],
    blockchain: ["blockchain.com"],
    revolut: ["revolut.com"],
    wise: ["wise.com"],
    citibank: ["citibank.com", "citi.com"],
    capitalone: ["capitalone.com"],
    americanexpress: ["americanexpress.com", "aexp.com"],
    venmo: ["venmo.com"],
    cashapp: ["cash.app"],
    telegram: ["telegram.org", "t.me"],
    snapchat: ["snapchat.com"],
    protonmail: ["protonmail.com", "proton.me"],
    openai: ["openai.com", "chatgpt.com"],
    github: ["github.com"],
    etsy: ["etsy.com"],
    telstra: ["telstra.com", "telstra.com.au"],
    shopee: ["shopee.com", "shopee.sg", "shopee.com.my", "shopee.co.id", "shopee.vn"],
    kucoin: ["kucoin.com"],
    comcast: ["comcast.com", "xfinity.com"],
    att: ["att.com"],
    verizon: ["verizon.com"],
    spectrum: ["spectrum.net", "spectrum.com"],
    coinsquare: ["coinsquare.com"],
    bitget: ["bitget.com"],
    okx: ["okx.com"],
    bybit: ["bybit.com"],
    exodus: ["exodus.com", "exodus.io"],
    walmart: ["walmart.com"],
    costco: ["costco.com"],
    target: ["target.com"],
    homedepot: ["homedepot.com"],
    lowes: ["lowes.com"],
    allegro: ["allegro.pl", "allegro.com"],
    amex: ["americanexpress.com", "aexp.com", "amex.com"],
    icloud: ["icloud.com"],
    visa: ["visa.com"],
    mastercard: ["mastercard.com"],
    bradesco: ["bradesco.com.br"],
    itau: ["itau.com.br"],
    santander: ["santander.com", "santander.com.br", "santander.co.uk"],
    natwest: ["natwest.com"],
    deutsche: ["deutsche-bank.de", "db.com"],
    commerzbank: ["commerzbank.de"],
    smbc: ["smbc.co.jp"],
    mufg: ["mufg.jp"],
    mizuho: ["mizuho.co.jp"],
    jcb: ["jcb.co.jp"],
    docusign: ["docusign.com"],
    bt: ["bt.com"],
    optus: ["optus.com.au"],
    vodafone: ["vodafone.com"],
    orange: ["orange.fr", "orange.com"],
    sfr: ["sfr.fr"],
    bouygues: ["bouyguestelecom.fr"],
    laposte: ["laposte.fr", "laposte.net"],
    cdiscount: ["cdiscount.com"],
    fnac: ["fnac.com"],
    carrefour: ["carrefour.fr", "carrefour.com"],
    auchan: ["auchan.fr"],
    bnp: ["bnpparibas.com", "bnpparibas.net"],
    creditagricole: ["credit-agricole.fr", "ca-cb.com"],
    societegenerale: ["societegenerale.fr", "socgen.com"],
    labanquepostale: ["labanquepostale.fr"],
    ameli: ["ameli.fr", "assurance-maladie.fr"],
    impots: ["impots.gouv.fr"],
    sncf: ["sncf.com", "sncf-connect.com"],
    chronopost: ["chronopost.fr"],
    colissimo: ["colissimo.fr"],
    mondialrelay: ["mondialrelay.fr"],
    rakuten: ["rakuten.com", "rakuten.co.jp"],
    ups: ["ups.com"],
    dpd: ["dpd.com", "dpdgroup.com"],
    gls: ["gls-group.com"],
    hermes: ["hermesworld.com", "evri.com"],
    correos: ["correos.es"],
    anpost: ["anpost.com"],
    posteitaliane: ["poste.it"],
    intesasanpaolo: ["intesasanpaolo.com"],
    unicredit: ["unicredit.it"],
    lloyds: ["lloydsbank.com", "lloyds.com"],
    barclays: ["barclays.co.uk", "barclays.com"],
    hsbc: ["hsbc.com", "hsbc.co.uk"],
    tsb: ["tsb.co.uk"],
    halifax: ["halifax.co.uk"],
    nationwide: ["nationwide.co.uk"],
    monzo: ["monzo.com"],
    starling: ["starlingbank.com"],
    xfinity: ["xfinity.com", "comcast.com"],
    mediamarkt: ["mediamarkt.com", "mediamarkt.de"],
    inpost: ["inpost.pl"],
    vinted: ["vinted.com", "vinted.fr"],
    leboncoin: ["leboncoin.fr"],
    booking: ["booking.com"],
    airbnb: ["airbnb.com"],
    uber: ["uber.com"],
    doordash: ["doordash.com"],
    revolut: ["revolut.com"],
    n26: ["n26.com"],
  };

  // Does a normalized host label (hyphens stripped) contain the brand?
  // Short brands need prefix match ('otherwise'→wise, 'first'→irs are FPs).
  function labelHasBrand(norm, b) {
    if (norm === b) return true;
    if (norm === b + "s") return false; // dictionary plural (apples.com)
    if (b.length <= 4) {
      if (norm.startsWith(b)) return true;
      // brand at end only when the lead is credential bait: loginwise ✓, otherwise ✗
      return norm.endsWith(b) && PATH_KEYWORDS.includes(norm.slice(0, -b.length));
    }
    if (norm.length >= b.length + 2 && norm.includes(b)) return true;
    // leetspeak folded inside a label: m1cr0soft-login, paypa1x
    const dn = deobfuscate(norm);
    if (dn !== norm && dn.length >= b.length + 2 && dn.includes(b)) return true;
    // doubled-letter scrambling: meetamassklogaiin → metamasklogin
    const sq = (s) => s.replace(/(.)\1+/g, "$1");
    const sb = sq(b);
    return sq(norm).length >= sb.length + 2 && sq(norm).includes(sb);
  }

  // Free/disposable and frequently-abused TLDs (Freenom + low-cost stats).
  const SUS_TLDS = new Set([
    "tk", "ml", "ga", "cf", "gq", "top", "buzz", "cam", "rest", "quest",
    "monster", "icu", "click", "country", "stream", "download", "loan",
    "racing", "win", "bid", "date", "review", "party", "gdn", "men",
    "work", "zip", "mov", "cfd", "info", "help", "live", "site", "online",
    "store", "shop", "app", "sbs", "mom", "lol", "pics", "skin", "deals",
    "agency", "bar", "quest", "cc",
  ]);

  const SHORTENERS = new Set([
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly",
    "s.id", "bit.do", "soo.gd", "clck.ru", "v.gd",
    "goo.su", "qrco.de", "s4w.in", "g5.lu", "hotm.io", "ln.run", "short.io",
    "gt.tc", "fr.gd", "ur.ly", "zi.ht",
  ]);

  // Credential-theft vocabulary in URL paths.
  const PATH_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification", "secure",
    "account", "update", "billing", "confirm", "suspend", "unlock",
    "wallet", "recover", "password", "credential", "authenticate",
    "webscr", "oauth", "validate", "reauth", "websc",
    "wp-admin", "wp-content", "wp-includes", "components/com_", "myaccount",
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

  // Bait words that are suspicious inside a hostname (not just the path).
  const DOMAIN_BAIT = ["login", "signin", "signon", "verify", "account",
    "secure", "support", "billing", "confirm", "auth", "wallet", "webscr",
    "password", "credential", "update", "recovery", "unlock", "suspend",
    "secur", "client", "compte", "banque", "colis", "livraison", "suivi",
    "facture", "impot", "remboursement", "expir", "oferta",
    "oferte", "verific", "atendimento", "acesso", "empresa",
    "payee", "transfer", "cancel", "sms", "gift", "limitedtime", "myaccount",
    "signatur", "dokumen", "invoice", "refund", "payout"];

  // Free hosting / PaaS domains heavily abused by phishing kits.
  const FREE_HOSTS = ["github.io", "blogspot.com", "weebly.com", "amplifyapp.com",
    "workers.dev", "pages.dev", "web.app", "firebaseapp.com", "netlify.app",
    "vercel.app", "herokuapp.com", "wordpress.com", "wixsite.com", "glitch.me",
    "replit.app", "repl.co", "surge.sh", "fly.dev", "onrender.com", "trycloudflare.com",
    "ngrok.io", "ngrok-free.app", "000webhostapp.com", "sites.google.com",
    "godaddysites.com", "tripod.com", "angelfire.com", "blogspot.ae", "blogspot.in",
    "blogspot.co.uk", "blogspot.de", "blogspot.fr", "blogspot.com.br",
    "webflow.io", "framer.website", "gitbook.io", "wix.com", "site123.me",
    "carrd.co", "zyrosite.com", "ucraft.site", "mystrikingly.com", "jimdosite.com",
    "yolasite.com", "weeblysite.com", "bravesites.com", "webnode.page",
    "canva.site", "notion.site", "linktr.ee", "beacons.ai", "bio.site",
    "googleapis.com", "appspot.com", "cloudfront.net", "amazonaws.com",
    "azurewebsites.net", "windows.net", "r2.dev", "fleek.co",
    "cloudflare-ipfs.com", "ipfs.io", "dweb.link", "w3s.link", "arweave.net",
    "plesk.page", "4everland.io", "spheron.app", "surge.sh", "edgecompute.app"];

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
    // subdomain labels + free-host detection (used by several checks below)
    const subs = host.slice(0, host.length - reg.length - 1).split(".").filter(Boolean);
    const freeHost = FREE_HOSTS.find((f) => host === f || host.endsWith("." + f));
    // labels eligible for brand matching: on free hosts the SLD is the platform,
    // not an impersonation target (myname.github.io must not flag 'github').
    const brandLabels = (freeHost ? [] : [sld]).concat(subs).map((l) => l.replace(/-/g, ""));

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
    if (/^\d+$/.test(sld) && sld.length >= 6) {
      signals.push(signal("numeric-domain", 25, "med", `All-numeric domain "${sld}"`,
        "Random number domains are throwaway phishing infrastructure."));
    } else if ((host.match(/\d/g) || []).length >= 4 && !IP_HOST.test(host)) {
      signals.push(signal("digits", 8, "low", "Many digits in hostname",
        "Random-looking digit strings are common in disposable phishing domains."));
    }

    // Brand impersonation
    if (!isBrandDomain(host)) {
      const deob = deobfuscate(sld);
      for (const [brand] of Object.entries(BRANDS)) {
        if (brand.length <= 3) continue; // 2-3 char brands are FP machines (bit→bt)
        if (deob === brand + "s") continue; // dictionary plural (apples.com)
        if (deob.length < brand.length && brand.includes(deob)) continue; // fragment, not squat (bit.ly⊂bybit)
        const dist = levenshtein(deob, brand);
        // dist 2 only pays off on long brands ('cafe'→'chase', 'etsy'→'ebay' are legit)
        if (deob !== brand && dist > 0 && dist <= (brand.length <= 6 ? 1 : 2)) {
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
        if (!owned && brandLabels.some((l) => labelHasBrand(l, brand))) {
          signals.push(signal("brand-in-host", 35, "high",
            `"${brand}" appears in hostname but domain is '${reg}'`,
            "Attackers prepend brand names as subdomains to look legitimate."));
          break;
        }
      }
    }

    // Credential-bait words inside the domain itself (app-supportecloud.info, login.foo.com)
    // exempt gov/edu/mil — 'login.gov' is institutional naming, not bait
    const INSTITUTIONAL = ["gov", "edu", "mil", "govt", "ac"];
    if (!isBrandDomain(host) && !INSTITUTIONAL.includes(tld)) {
      const hostBait = brandLabels.filter((l) => DOMAIN_BAIT.some((k) =>
        l.includes(k) && !(l.startsWith(k) && l.length <= k.length + 3) &&
        !(k === "banque" && l.startsWith("banquet"))));
      if (hostBait.length) {
        signals.push(signal("domain-bait", Math.min(24, 8 + hostBait.length * 8), "med",
          `Credential-bait words in domain (${hostBait.slice(0, 3).join(", ")})`,
          "Words like 'login/verify/support' baked into the hostname are phishing scaffolding."));
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

    // Brand name hidden inside a subdomain label (ledger-x.blogspot.com, paypal.secure.foo.com)
    if (!isBrandDomain(host)) {
      outer: for (const lbl of subs) {
        const norm = lbl.toLowerCase().replace(/-/g, "");
        if (norm.length < 4) continue;
        for (const b of Object.keys(BRANDS)) {
          if (norm === b + "s") continue; // dictionary plural
          if (labelHasBrand(norm, b) ||
              (norm.length >= b.length - 1 && norm.length <= b.length + 4 &&
               levenshtein(deobfuscate(norm), b) <= 1)) {
            signals.push(signal("brand-sub", 35, "high",
              `Brand "${b}" hidden in subdomain "${lbl}"`,
              "Phishing kits park lookalike brands in subdomains on unrelated or free-host domains."));
            break outer;
          }
        }
      }
    }

    // High-entropy subdomain label (main.d3thcdi1mb7dsr.amplifyapp.com)
    const rnd = subs.find((s) => s.length >= 12 && shannon(s) > 3.8);
    if (rnd) {
      signals.push(signal("rand-sub", 15, "med", `Random-looking subdomain "${rnd.slice(0, 18)}…"`,
        "Auto-generated hostnames are typical of disposable phishing infrastructure."));
    }

    // Vowel-less label — generated gibberish (jfvlqz.top, wvltnsd.x)
    const noVowel = (freeHost ? subs : [sld, ...subs]).find(
      (l) => l.length >= 5 && /^[b-df-hj-np-tv-z0-9-]+$/.test(l) && !IP_HOST.test(l));
    if (noVowel) {
      signals.push(signal("vowelless", 15, "med", `Consonant-only label "${noVowel.slice(0, 16)}"`,
        "Real words have vowels — vowel-less labels are machine-generated."));
    }

    // Digit-stuffed label (hub4571132.pro, qwo231sdx.club)
    const digLabel = subs.find((l) => (l.match(/\d/g) || []).length >= 3 && l.length >= 7);
    if (digLabel) {
      signals.push(signal("diglabel", 15, "med", `Digit-stuffed label "${digLabel.slice(0, 16)}"`,
        "Numbers smuggled into hostnames are disposable-infra markers."));
    }

    // Fake TLD labels parked as subdomains (rauketnen.co.jp.evil.top)
    const FAKE_TLD = new Set(["co", "com", "net", "org", "or", "edu", "gov",
      "jp", "uk", "kr", "cn", "de", "fr", "au", "us", "br", "in"]);
    if (!freeHost) {
      const fake = subs.filter((l) => FAKE_TLD.has(l));
      if (fake.length >= 2 || (fake.length && subs.length >= 2)) {
        signals.push(signal("fake-tld", 18, "med",
          `Fake suffix "${fake.join(".")}" parked in subdomains`,
          "Abusing 'co.jp'-style labels makes a random domain look like a regional site."));
      }
    }

    // IP address hidden in subdomain labels (91-218-65-223.host.tld)
    if (subs.some((l) => /^(\d{1,3}[-.]){3}\d{1,3}$/.test(l))) {
      signals.push(signal("ip-in-sub", 25, "med", "IP address hidden inside hostname",
        "Encoding the server IP in the domain is a botnet/phishing-kit tell."));
    }

    // Credential bait on a free host
    const brandInPath = Object.keys(BRANDS).find((b) => path.includes(b));
    // brand name in the path on a domain that doesn't own it (fingersh.com/amex_...)
    if (!isBrandDomain(host) && brandInPath && !freeHost) {
      signals.push(signal("brand-path", 20, "med",
        `Brand "${brandInPath}" in path on unrelated domain '${reg}'`,
        "Real brands don't park their login pages on strangers' domains."));
    }
    if (freeHost && (kwHits.length || brandInPath)) {
      signals.push(signal("freehost-bait", brandInPath ? 40 : 30, "med",
        brandInPath
          ? `Brand "${brandInPath}" in path on free host "${freeHost}"`
          : `Credential bait on free host "${freeHost}"`,
        "Phishing overwhelmingly lives on free hosting — disposable, zero cost, looks like a real site."));
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

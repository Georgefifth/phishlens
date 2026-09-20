# PhishLens 🎣🔍

**Real-time, private, explainable phishing protection — running 100% in your browser.**

Built for the [TLN Cybersecurity Challenge 2026](https://tln-cybersecurity-challenge.devpost.com/).

## The problem

Phishing is the #1 delivery mechanism for credential theft and fraud, and AI has
made it worse: LLMs let attackers generate fluent, personalized lures and spin up
lookalike domains at scale. The people most exposed — students, seniors, non-native
speakers — are the least equipped to spot a `paypa1-secure-login.tk` in a sea of
links. Existing tools either ship your browsing data to the cloud (privacy problem)
or give a mute red/green verdict that teaches users nothing.

## What we built

PhishLens is a phishing-detection toolkit with **zero network dependencies** —
every check runs locally, so nothing about your browsing ever leaves the machine:

- **A browser extension** (Manifest V3, Chrome + Firefox) that scores every page
  in real time: a badge shows the risk level, and dangerous pages get an in-page
  warning banner that lists *exactly which signals fired*.
- **A web analyzer** (live demo — see below) where anyone can paste a suspicious
  link and get an instant, explained verdict. Same engine, no install needed.

Every signal carries a human-readable explanation, so the tool **teaches** users
what phishing looks like instead of just blocking it — detection + education.

## Detection engine (`engine.js`, pure JS, no deps)

**URL forensics**
- Typosquatting via Levenshtein distance vs. a brand registry (`paypa1`, `g00gle`)
- Homoglyph folding — Cyrillic/Greek lookalikes + multi-char tricks (`rn`→`m`, `vv`→`w`)
- Punycode/IDN detection (`xn--pple-43d.com`)
- `user@host` deception, raw-IP hosts, URL shorteners, abused TLDs
- Subdomain stuffing (`paypal.com.secure.evil.top`), hyphen spam, URL entropy
- Credential-bait path keywords (`/verify`, `/billing`, `/webscr`)

**Page-content signals** (extension content script)
- Password forms posting cross-site or over plaintext HTTP
- Requests for CVV/SSN/OTP/seed-phrase fields
- Hidden iframes (clickjacking / silent redirects)
- Urgency & scare language ("suspended", "within 24 hours", "final notice")

Signals are weighted into a 0–100 score → `likely safe / caution / suspicious /
dangerous`, always with the reasons attached.

## Live demo

👉 **https://georgefifth.github.io/phishlens/** — paste-a-link analyzer + two
bait pages (a fake "PayPal suspended" page and a control bank page) you can open
with the extension installed to watch the warning fire.

📹 **Demo video:** [`assets/demo-video.mp4`](assets/demo-video.mp4) (33s)
📊 **Slides:** [`assets/slides.pdf`](assets/slides.pdf) · cover + gallery PNGs in [`assets/`](assets/)

## Install the extension (2 min)

```bash
git clone https://github.com/Georgefifth/phishlens.git
```

- **Chrome/Edge**: `chrome://extensions` → Developer mode → *Load unpacked* →
  select `phishlens/extension/`
- **Firefox**: `about:debugging` → This Firefox → *Load Temporary Add-on* →
  select `phishlens/extension/manifest.json`

Then open `web/demo/paypal-verify.html` on the live site — the banner fires even
though the URL is innocent, because the **page content** is the smoking gun.

## Repo layout

```
engine.js          shared analysis engine (URL + page signals, pure JS)
extension/         Manifest V3 extension (badge, content script, popup analyzer)
web/               live demo site (analyzer + bait pages)
```

## Tech

Vanilla JavaScript (ES2020), WebExtension APIs (MV3), GitHub Pages. No frameworks,
no build step, no dependencies — clone and load.

## AI & external tools disclosure

Developed with an AI pair programmer (Devin by Cognition) under human direction.
All detection logic is deterministic local heuristics — no LLM calls at runtime,
no third-party APIs, no external datasets.

## What's next

- Optional on-device ML layer (compact URL classifier) on top of the heuristics
- Community brand/TLD registry updates + user report feedback loop
- Safari port (WebExtensions make this nearly free)

> **Firefox note:** Firefox's MV3 implementation uses event pages rather than
> `service_worker`. To load in Firefox (`about:debugging`), swap
> `manifest.json` with `manifest.firefox.json` (same code, different
> `background` block). Chrome/Edge/Brave use `manifest.json` as-is.

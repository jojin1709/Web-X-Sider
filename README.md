#  <img width="1254" height="1254" alt="favicon" src="https://github.com/user-attachments/assets/2e32121d-e68f-4561-82a1-8aef66bcbbf2" />
Web X Sider V2.5 - Advanced JavaScript Crawler, Endpoint Discovery & Bug Bounty Toolkit

---

## Live Demo

**[https://web-x-sider.mmkoji856.workers.dev](https://web-x-sider.mmkoji856.workers.dev)**

---

## What's New in V2.5

### Bug Bounty Toolkit (9 new tools)
- **JS Diff Monitor** — Watch JS/page URLs for changes over time. Detects new endpoints/secrets between snapshots. Auto-check mode + Discord/Slack alerts.
- **JWT Lab** — Decode header/payload, check expiry, brute-force weak HMAC secrets (35 common keys), forge `alg:none` token, fire it at a target URL — all in-browser.
- **Subdomain Takeover Scanner** — 65-service fingerprint DB (GitHub Pages, Heroku, S3, Azure, Netlify, Vercel, Render, Fly.io…). DNS-over-HTTPS CNAME lookups + dangling NXDOMAIN detection.
- **CVE Correlator** — Maps Server/X-Powered-By headers or pasted tech strings against 28 high-signal CVEs (Log4Shell, Spring4Shell, Drupalgeddon2, ProxyShell, MOVEit, Heartbleed…) with NVD links.
- **Batch Scanner** — 50+ subdomains at once. Quick mode (title/server/tech) or Prober mode (+ 8 sensitive paths). CSV export.
- **IDOR / Range Tester** — `https://api.target.com/orders/{id}` style fuzzing. Up to 300 IDs, anomaly detection by status+length signature diff. CSV export.
- **Auth Matrix Tester** — Same request, multiple role headers (Anonymous/User/Admin). Flags identical responses as possible authorization bypass.
- **Webhook Alerts** — Discord/Slack incoming webhook. Auto-send on JS changes, takeovers, auth-order findings. Manual scan summary.
- **Visual Snapshot** — WordPress mshots screenshots of targets. Re-capture and compare over time. No API key needed.

### Bug fixes in V2.5
- **CORS fix** — Worker strips upstream `Access-Control-*` headers so its own CORS policy always wins.
- **Proxy deploy fix** — `run_worker_first: true` + `env.ASSETS` binding so the Worker runs on every request, static files served via assets binding.
- **SSRF fix** — IP/DNS block check was dead code in the wrong function; now actually runs.
- **PDF export** — Print any scan to PDF directly from the browser.

---

## Features

### Core Scanner
- Deep JS crawling with configurable depth and concurrency
- Endpoint extraction (REST paths, GraphQL, WebSocket)
- Secret detection (AWS keys, JWTs, Bearer tokens, API keys, passwords)
- File discovery (.env, .git, config files, source maps)
- Parameter extraction from URLs, forms, JS
- Severity scoring (Critical / High / Medium / Low)
- Scope rules with wildcard support
- Wayback Machine URL import
- HAR / Burp proxy history import

### Smart Prober
- 700+ sensitive paths across 44 categories
- Live title/status checks
- Tech stack fingerprinting
- Subdomain takeover detection

### Bug Bounty Recon Suite
- CORS misconfiguration detection
- CSP / security headers audit
- Cookie flags checker (Secure, HttpOnly, SameSite)
- Open redirect detection
- Clickjacking / HSTS analysis
- DNS record lookup (A, AAAA, CNAME, MX, TXT, NS)

### Export Formats
- Markdown · JSON · CSV · TXT · Burp XML · **PDF**

---

## Proxy Setup

Live proxy: `https://web-x-sider.mmkoji856.workers.dev/?url=TARGET`

Deploy your own:
```bash
git clone https://github.com/jojin1709/Web-X-Sider.git
cd Web-X-Sider
npm install -g wrangler
wrangler login
wrangler deploy
```

Local dev:
```bash
python server.py 5501
# then open index.html — tool auto-detects localhost:5501
```

---

## Architecture

```
Browser (index.html + script.js + toolkit.js)
    ↓ ?url=TARGET
Cloudflare Worker (workers/cloudflare-worker-proxy.js)
    ├─ ?url= present → proxy request to target, strip upstream CORS headers
    └─ no ?url= → serve static assets via env.ASSETS binding
```

No backend database, no server-side state — everything runs client-side with localStorage for persistence (JS monitor watchlists, webhook settings, snapshots, IDOR results).

---

## Stack

- **Frontend**: Vanilla JS (ES2022), CSS3 glassmorphism
- **Proxy**: Cloudflare Workers (no KV/D1 needed)
- **Local proxy**: Python 3 (optional)
- **DNS**: DNS-over-HTTPS (Cloudflare + Google)

---

## Credits

Built by [@jojin1709](https://github.com/jojin1709) — bug bounty hunter & full-stack developer.

HackerOne · Bugcrowd · YesWeHack · Intigriti

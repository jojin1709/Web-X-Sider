#  <img width="1254" height="1254" alt="favicon" src="https://github.com/user-attachments/assets/2e32121d-e68f-4561-82a1-8aef66bcbbf2" />
Web X Sider V3.0 - Advanced JavaScript Crawler, Endpoint Discovery & Bug Bounty Toolkit

---

## Live Demo

**[https://web-x-sider.mmkoji856.workers.dev](https://web-x-sider.mmkoji856.workers.dev)**

---

## What's New in V3.0

### Bug Bounty Toolkit (17 tools total)
- **JS Diff Monitor** — Watch JS/page URLs for changes over time. Detects new endpoints/secrets between snapshots. Auto-check mode + Discord/Slack alerts.
- **JWT Lab** — Decode header/payload, check expiry, brute-force weak HMAC secrets (35 common keys), forge `alg:none` token, fire it at a target URL — all in-browser.
- **Subdomain Takeover Scanner** — 65-service fingerprint DB (GitHub Pages, Heroku, S3, Azure, Netlify, Vercel, Render, Fly.io…). DNS-over-HTTPS CNAME lookups + dangling NXDOMAIN detection.
- **CVE Correlator** — Maps Server/X-Powered-By headers or pasted tech strings against 28 high-signal CVEs (Log4Shell, Spring4Shell, Drupalgeddon2, ProxyShell, MOVEit, Heartbleed…) with NVD links.
- **Batch Scanner** — 50+ subdomains at once. Quick mode (title/server/tech) or Prober mode (+ 8 sensitive paths). CSV export.
- **IDOR / Range Tester** — `https://api.target.com/orders/{id}` style fuzzing. Up to 300 IDs, anomaly detection by status+length signature diff. CSV export.
- **Auth Matrix Tester** — Same request, multiple role headers (Anonymous/User/Admin). Flags identical responses as possible authorization bypass.
- **Webhook Alerts** — Discord/Slack incoming webhook. Auto-send on JS changes, takeovers, auth-order findings. Manual scan summary.
- **Visual Snapshot** — WordPress mshots screenshots of targets. Re-capture and compare over time. No API key needed.
- **Race Condition Tester** — Fire N concurrent requests to detect race conditions and TOCTOU bugs.
- **GraphQL Explorer** — Execute queries, run full introspection, test for exposed schemas.
- **OAuth/PKCE Tester** — Generate authorization URLs with PKCE code challenges for OAuth flow testing.
- **Request Smuggling Tester** — Test CL.TE, TE.CL, and TE.TE smuggling vectors.
- **Prototype Pollution Tester** — Send `__proto__` payloads to detect JS prototype pollution vulnerabilities.
- **Cache Poisoning Tester** — Test for web cache poisoning via header injection.
- **Bucket Enumeration** — Test S3, GCS, and Azure Blob storage for accessible/existing buckets.
- **Nuclei Template Builder** — Generate Nuclei YAML templates from discovered paths.

### Bug Fixes in V3.0
- **SSRF protection** — Worker now blocks private IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, etc.)
- **WAF bypass** — User-Agent rotation pool with 5 real browser UAs + browser-like headers (Sec-Fetch-*, Accept-Language, etc.)
- **CORS fix** — Worker strips upstream `Access-Control-*` headers so its own CORS policy always wins.
- **Proxy deploy fix** — `run_worker_first: true` + `env.ASSETS` binding so the Worker runs on every request, static files served via assets binding.
- **FlareSolverr fix** — Proper status checking, cookie forwarding with domain/path/secure attributes.
- **Mobile nav sync** — Toolkit tab now correctly syncs between desktop and mobile navigation.
- **PDF export** — Print any scan to PDF directly from the browser.

### UI/UX Improvements in V3.0
- **Enhanced glassmorphism** — Better backdrop blur, border glow, and hover effects on all cards
- **Button ripple effects** — Material-design-inspired click animations on all buttons
- **Smooth transitions** — Cubic-bezier easing on all interactive elements
- **Stat card animations** — Lift-on-hover with subtle scale effect
- **Prober result styling** — Left-border color coding by HTTP status (green=200, orange=403, red=404)
- **Export button 3D effects** — Lift-and-rotate icon animation on hover
- **Tab underline animation** — Animated underline indicator on active tabs
- **Toast notifications** — Slide-in animation for toast messages
- **Custom scrollbars** — Styled scrollbars matching the glassmorphism theme
- **Print styles** — Clean print layout hiding navigation and UI controls
- **Reduced motion support** — Respects `prefers-reduced-motion` for accessibility

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
- Markdown · JSON · CSV · TXT · Burp XML · Nuclei YAML · ffuf commands · **PDF**

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
Browser (index.html + script.js + toolkit.js + toolkit2.js)
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

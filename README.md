#  <img width="1254" height="1254" alt="favicon" src="https://github.com/user-attachments/assets/2e32121d-e68f-4561-82a1-8aef66bcbbf2" />
Web X Sider V4.0 - Advanced JavaScript Crawler, Endpoint Discovery & Complete Bug Bounty Toolkit

---

## Live Demo

**[https://web-x-sider.mmkoji856.workers.dev](https://web-x-sider.mmkoji856.workers.dev)**

---

## What's New in V4.0

### Complete Bug Bounty Toolkit (42 Tools!)

#### Core Scanner Tools (9 tools)
- **JS Diff Monitor** — Watch JS/page URLs for changes over time
- **JWT Lab** — Decode, brute-force, forge alg:none tokens
- **Subdomain Takeover Scanner** — 65-service fingerprint DB
- **CVE Correlator** — Maps tech against 28 high-signal CVEs
- **Batch Scanner** — 50+ subdomains at once
- **IDOR / Range Tester** — `{id}` style fuzzing
- **Auth Matrix Tester** — Multi-role authorization testing
- **Webhook Alerts** — Discord/Slack notifications
- **Visual Snapshot** — WordPress mshots screenshots

#### Advanced Toolkit Tools (8 tools)
- **Race Condition Tester** — Fire N concurrent requests
- **GraphQL Explorer** — Execute queries, introspection
- **OAuth/PKCE Tester** — Generate authorization URLs
- **Request Smuggling Tester** — CL.TE, TE.CL, TE.TE
- **Prototype Pollution Tester** — `__proto__` payloads
- **Cache Poisoning Tester** — Header injection testing
- **Bucket Enumeration** — S3, GCS, Azure, DigitalOcean
- **Nuclei Template Builder** — Generate YAML templates

#### Security Testing Tools (25 tools)
1. **WAF Detection & Fingerprinting** — Detect Cloudflare, Akamai, AWS WAF, Imperva, Sucuri, ModSecurity, etc.
2. **Subdomain Enumeration** — DNS brute-force, Certificate Transparency, DNS records
3. **Open Redirect Scanner** — Parameter fuzzing with bypass payloads
4. **Rate Limiting Detection** — Detect throttle behavior and thresholds
5. **Port Scanning** — Common ports via fetch timeouts
6. **Backup File Finder** — .bak, .old, .swp, .sql.gz patterns
7. **HTTP Method Testing** — OPTIONS, TRACE, PUT, DELETE discovery
8. **Clickjacking Test** — iframe embedding, X-Frame-Options, CSP
9. **Sensitive Header Analysis** — Server version, X-Powered-By, internal IPs
10. **Cache Poisoning Deep Test** — Header injection for cache keys
11. **SQL Injection Detection** — Error-based, time-based, boolean-blind
12. **XSS Detection** — Reflected parameter testing
13. **Command Injection** — OS command injection indicators
14. **Directory Traversal** — Path traversal with encoding bypass
15. **WebSocket Testing** — Endpoint discovery, message injection
16. **API Versioning Discovery** — REST/GraphQL version detection
17. **JWT Analysis Enhancements** — JWKS discovery, algorithm confusion
18. **OAuth Security Testing** — Redirect URI bypass, state parameter
19. **DNS Security Analysis** — Zone transfer, SPF/DMARC
20. **Email Security (SPF/DKIM/DMARC)** — Email spoofing protection
21. **Cloud Storage Enumeration** — S3, GCS, Azure, DigitalOcean
22. **Container/Docker Exposure** — Docker socket, Kubernetes API
23. **CI/CD Pipeline Exposure** — Jenkins, GitLab CI, GitHub Actions
24. **Mobile App Analysis** — Deep links, manifests, service workers
25. **Real-time Collaboration** — Export/import sessions, notes

### Bug Fixes in V4.0
- **SSRF protection** — Worker blocks private IP ranges
- **WAF bypass** — User-Agent rotation + browser-like headers
- **CORS fix** — Worker strips upstream CORS headers
- **FlareSolverr fix** — Proper cookie forwarding
- **Mobile nav sync** — Toolkit tabs sync correctly
- **PDF export** — Print any scan to PDF

### UI/UX Improvements in V4.0
- Enhanced glassmorphism effects
- Button ripple and hover animations
- Stat card lift-on-hover effects
- Prober result left-border color coding
- Export button 3D effects
- Tab underline animations
- Toast notification slide-in
- Custom scrollbars
- Print styles
- Reduced motion support

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
Browser (index.html + script.js + toolkit.js + toolkit2.js + toolkit3.js)
    ↓ ?url=TARGET
Cloudflare Worker (workers/cloudflare-worker-proxy.js)
    ├─ ?url= present → proxy request to target, strip upstream CORS headers
    └─ no ?url= → serve static assets via env.ASSETS binding
```

No backend database, no server-side state — everything runs client-side with localStorage for persistence.

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

#  <img width="1254" height="1254" alt="favicon" src="https://github.com/user-attachments/assets/2e32121d-e68f-4561-82a1-8aef66bcbbf2" />
Web X Sider V5.0 - Advanced JavaScript Crawler, Endpoint Discovery & Complete Bug Bounty Toolkit

---

## Live Demo

**[https://web-x-sider.mmkoji856.workers.dev](https://web-x-sider.mmkoji856.workers.dev)**

---

## What's New in V5.0

### 56 Total Tools!

#### Core Scanner Tools (9)
- JS Diff Monitor, JWT Lab, Subdomain Takeover Scanner, CVE Correlator, Batch Scanner, IDOR/Range Tester, Auth Matrix Tester, Webhook Alerts, Visual Snapshot

#### Advanced Toolkit Tools (8)
- Race Condition Tester, GraphQL Explorer, OAuth/PKCE Tester, Request Smuggling Tester, Prototype Pollution Tester, Cache Poisoning Tester, Bucket Enumeration, Nuclei Template Builder

#### Security Testing Tools (25)
- WAF Detection, Subdomain Enumeration, Open Redirect Scanner, Rate Limiting Detection, Port Scanning, Backup File Finder, HTTP Method Testing, Clickjacking Test, Sensitive Header Analysis, Cache Poisoning Deep Test, SQL Injection Detection, XSS Detection, Command Injection, Directory Traversal, WebSocket Testing, API Versioning Discovery, JWT Analysis Enhancements, OAuth Security Testing, DNS Security Analysis, Email Security (SPF/DKIM/DMARC), Cloud Storage Enumeration, Container/Docker Exposure, CI/CD Pipeline Exposure, Mobile App Analysis, Real-time Collaboration

#### Productivity Tools (14)
- **Unified Dashboard** — Consolidated view of all scan results
- **Enhanced Report Generation** — HTML, Executive Summary, PDF reports
- **Scan History & Comparison** — Save and compare scans over time
- **Target Management** — Save targets with notes, tags, priority levels
- **Keyboard Shortcuts** — Ctrl+1-5 for navigation, Ctrl+F for filter, Ctrl+E for export
- **Offline Support** — Service Worker caching for offline use
- **Custom Wordlist Upload** — Upload and manage custom wordlists
- **Scan Profiles** — Stealth/Normal/Aggressive presets
- **Email/Webhook Alerts** — Discord/Slack notifications for findings
- **Compliance Checks** — OWASP Top 10 assessment
- **API Integration** — REST API for external tool integration
- **Multi-language Support** — English, Spanish, French, German, Portuguese, Arabic
- **Dark/Light Theme Toggle** — Switch between themes
- **Accessibility** — High contrast, large text, reduced motion options

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
- Markdown · JSON · CSV · TXT · Burp XML · Nuclei YAML · ffuf commands · **HTML Report** · **Executive Summary**

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+1` | Crawler |
| `Ctrl+2` | Prober |
| `Ctrl+3` | Recon Suite |
| `Ctrl+4` | Settings |
| `Ctrl+5` | Toolkit |
| `Ctrl+F` | Focus filter |
| `Ctrl+E` | Export results |
| `Ctrl+Enter` | Start scan |
| `Ctrl+S` | Save session |
| `Escape` | Stop scan |

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
Browser (index.html + script.js + toolkit*.js + sw.js)
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
- **Offline**: Service Worker for caching

---

## Credits

Built by [@jojin1709](https://github.com/jojin1709) — bug bounty hunter & full-stack developer.

HackerOne · Bugcrowd · YesWeHack · Intigriti

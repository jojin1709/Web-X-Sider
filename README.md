<div align="center">

<img src="./Web-X-Sider-cover.png" alt="Web X Sider - Advanced JavaScript Crawler & Endpoint Discovery" width="100%">

# Web X Sider

**Advanced JavaScript Crawler, Endpoint Discovery & Bug Bounty Toolkit**

[![Version](https://img.shields.io/badge/version-5.0-blue.svg)](https://github.com/jojin1709/Web-X-Sider)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/jojin1709/Web-X-Sider?style=social)](https://github.com/jojin1709/Web-X-Sider)
[![Issues](https://img.shields.io/github/issues/jojin1709/Web-X-Sider)](https://github.com/jojin1709/Web-X-Sider/issues)

The ultimate client-side reconnaissance tool for security researchers. Extract hidden API routes, sensitive parameters, and hardcoded secrets instantly from any website — directly in your browser.

**[Live Demo](https://web-x-sider.mmkoji856.workers.dev)** · **[Report Bug](https://github.com/jojin1709/Web-X-Sider/issues)** · **[Request Feature](https://github.com/jojin1709/Web-X-Sider/issues)**

---

</div>

## Table of Contents

- [What is Web X Sider?](#what-is-web-x-sider)
- [Features](#features)
- [Quick Start](#quick-start)
- [56 Tools Overview](#56-tools-overview)
- [Architecture](#architecture)
- [Proxy Setup](#proxy-setup)
- [Keyboard Shortcuts](#keyboard-shortcuts)
- [Supported Languages](#supported-languages)
- [Contributing](#contributing)
- [License](#license)
- [Credits](#credits)

---

## What is Web X Sider?

Web X Sider is a **100% client-side** reconnaissance tool designed for bug bounty hunters and security researchers. It runs entirely in your browser — no data is sent to external servers.

### Why Web X Sider Exists

In bug bounty hunting, reconnaissance is 80% of the work. Web X Sider automates the tedious parts:

- **JavaScript Analysis** — Extract endpoints, secrets, and parameters from JS files
- **Sensitive Path Discovery** — 700+ paths across 44 categories
- **Security Testing** — SQL injection, XSS, command injection, and more
- **WAF Detection** — Identify which protection is in place before testing

All **56 tools** run instantly in your browser with zero external dependencies.

---

## Features

| Category | Tools | Description |
|----------|-------|-------------|
| **Core Scanner** | 9 | JS crawling, endpoint discovery, secret detection, file discovery |
| **Smart Prober** | 1 | 700+ sensitive paths across 44 categories |
| **Recon Suite** | 1 | CORS, CSP, headers, tech fingerprint, JWT analysis |
| **Advanced Toolkit** | 8 | Race testing, GraphQL, OAuth/PKCE, smuggling, prototype pollution |
| **Security Testing** | 25 | WAF detection, SQLi, XSS, CMDi, traversal, port scanning |
| **Productivity** | 14 | Dashboard, reports, history, targets, i18n, themes |

### Key Capabilities

- **100% Client-Side** — No data leaves your browser
- **56 Integrated Tools** — Complete bug bounty toolkit
- **12 Languages** — Full UI translation support
- **Dark/Light Themes** — Customize your workspace
- **Offline Support** — Works without internet (Service Worker)
- **Export Multiple Formats** — JSON, CSV, HTML, PDF, Nuclei YAML

---

## Quick Start

### Option 1: Live Demo (Recommended)

Just visit **[web-x-sider.mmkoji856.workers.dev](https://web-x-sider.mmkoji856.workers.dev)** and start scanning!

### Option 2: Local Development

```bash
# Clone the repository
git clone https://github.com/jojin1709/Web-X-Sider.git
cd Web-X-Sider

# Start local server
python server.py 5501

# Open in browser
# http://localhost:5501
```

### Option 3: Deploy Your Own Proxy

```bash
# Install Wrangler
npm install -g wrangler

# Login to Cloudflare
wrangler login

# Deploy
wrangler deploy
```

---

## 56 Tools Overview

### Core Scanner (9 Tools)

| Tool | Description |
|------|-------------|
| JS Diff Monitor | Watch JS/page URLs for changes |
| JWT Lab | Decode, brute-force, forge tokens |
| Subdomain Takeover | 65-service fingerprint detection |
| CVE Correlator | Map tech against 28 high-signal CVEs |
| Batch Scanner | 50+ subdomains at once |
| IDOR Range Tester | `{id}` style fuzzing |
| Auth Matrix | Multi-role authorization testing |
| Webhook Alerts | Discord/Slack notifications |
| Visual Snapshot | WordPress mshots screenshots |

### Security Testing (25 Tools)

| Tool | Description |
|------|-------------|
| WAF Detection | Identify Cloudflare, Akamai, AWS WAF, etc. |
| Subdomain Enumeration | DNS brute-force, Certificate Transparency |
| Open Redirect Scanner | Parameter fuzzing with bypass payloads |
| Rate Limiting Detection | Detect throttle behavior |
| Port Scanning | Common ports via fetch |
| Backup File Finder | .bak, .old, .swp patterns |
| HTTP Method Testing | OPTIONS, TRACE, PUT, DELETE |
| Clickjacking Test | iframe embedding, X-Frame-Options |
| Sensitive Header Analysis | Server version, X-Powered-By leaks |
| Cache Poisoning Test | Header injection testing |
| SQL Injection Detection | Error-based, time-based |
| XSS Detection | Reflected parameter testing |
| Command Injection | OS command injection |
| Directory Traversal | Path traversal with encoding bypass |
| WebSocket Testing | Endpoint discovery, message injection |
| API Version Discovery | REST/GraphQL version detection |
| JWT Enhancements | JWKS discovery, algorithm confusion |
| OAuth Testing | Redirect URI bypass, state parameter |
| DNS Security | Zone transfer, SPF/DMARC |
| Email Security | SPF/DKIM/DMARC analysis |
| Cloud Storage | S3, GCS, Azure, DigitalOcean |
| Container Exposure | Docker socket, Kubernetes API |
| CI/CD Exposure | Jenkins, GitLab CI, GitHub Actions |
| Mobile App Analysis | Deep links, manifests |
| Real-time Collaboration | Export/import sessions |

### Productivity Tools (14 Tools)

| Tool | Description |
|------|-------------|
| Unified Dashboard | Consolidated view of all findings |
| Enhanced Reports | HTML, Executive Summary, PDF |
| Scan History | Save and compare scans over time |
| Target Management | Save targets with notes, priority |
| Keyboard Shortcuts | Ctrl+1-5, Ctrl+F, Ctrl+E |
| Offline Support | Service Worker caching |
| Custom Wordlists | Upload and manage wordlists |
| Scan Profiles | Stealth/Normal/Aggressive presets |
| Email/Webhook Alerts | Discord/Slack notifications |
| Compliance Checks | OWASP Top 10 assessment |
| API Integration | REST API for external tools |
| Multi-language (i18n) | 12 languages supported |
| Theme Toggle | Dark/Light/Auto themes |
| Accessibility | High contrast, large text |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Browser (Client)                       │
├─────────────────────────────────────────────────────────────┤
│  index.html  │  script.js  │  toolkit*.js  │  i18n.js  │ sw.js │
└──────────────────────────┬──────────────────────────────────┘
                           │
                    ┌──────▼──────┐
                    │  ?url=TARGET │
                    └──────┬──────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│              Cloudflare Worker (Proxy)                      │
├─────────────────────────────────────────────────────────────┤
│  • SSRF Protection (blocks private IPs)                     │
│  • User-Agent Rotation (5 real browser UAs)                 │
│  • CORS Headers (own policy wins)                           │
│  • FlareSolverr Integration (bot bypass)                    │
└─────────────────────────────────────────────────────────────┘
```

**No backend database. No server-side state. Everything runs client-side with localStorage.**

---

## Proxy Setup

| Option | URL | Notes |
|--------|-----|-------|
| **Live Proxy** | `https://web-x-sider.mmkoji856.workers.dev/?url=TARGET` | Public, free |
| **Local Proxy** | `http://localhost:5501/proxy?url=TARGET` | Run server.py |
| **Custom Worker** | Deploy your own | See below |

### Deploy Your Own Worker

```bash
git clone https://github.com/jojin1709/Web-X-Sider.git
cd Web-X-Sider
npm install -g wrangler
wrangler login
wrangler deploy
```

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+1` | Switch to Scanner |
| `Ctrl+2` | Switch to Prober |
| `Ctrl+3` | Switch to Recon Suite |
| `Ctrl+4` | Switch to Settings |
| `Ctrl+5` | Switch to Toolkit |
| `Ctrl+F` | Focus filter input |
| `Ctrl+E` | Jump to export section |
| `Ctrl+Enter` | Start scan |
| `Ctrl+S` | Save session |
| `Escape` | Stop scan |

---

## Supported Languages

| Tier | Languages |
|------|-----------|
| **Tier 1 (Global)** | English, 中文, Español, العربية |
| **Tier 2 (Economic)** | Deutsch, 日本語, Français, Português |
| **Tier 3 (Audience)** | हिन्दी, বাংলা, Русский, Bahasa Indonesia |

Full UI translation — all buttons, labels, and messages change when you select a language.

---

## Contributing

Contributions are welcome! Here's how:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## Credits

Built by **[@jojin1709](https://github.com/jojin1709)** — Bug Bounty Hunter & Full-Stack Developer

<a href="https://www.linkedin.com/in/jojin-john-74386b34a/" target="_blank">
  <img src="https://img.shields.io/badge/LinkedIn-Connect-blue?style=flat&logo=linkedin" alt="LinkedIn">
</a>
<a href="https://github.com/jojin1709" target="_blank">
  <img src="https://img.shields.io/badge/GitHub-Follow-black?style=flat&logo=github" alt="GitHub">
</a>

---

<div align="center">

**Built for the Bug Bounty Community**

[HackerOne](https://hackerone.com) · [Bugcrowd](https://bugcrowd.com) · [YesWeHack](https://yeswehack.com) · [Intigriti](https://intigriti.com)

</div>

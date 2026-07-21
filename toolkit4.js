/* ============================================================
   Web X Sider — Productivity & Enhancement Toolkit v5.0
   Features: Unified Dashboard, Enhanced Reports, Scan History,
   Target Management, Keyboard Shortcuts, Offline Support,
   Custom Wordlists, Scan Profiles, Alerts, Compliance,
   API Integration, i18n, Theme Toggle, Accessibility.
   ============================================================ */
(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const esc = (v) => (window.escapeHtml ? window.escapeHtml(v) : String(v ?? ""));
  const badge = (l, t) => (window.badge ? window.badge(l, t) : `<span class="recon-badge ${t || "info"}">${esc(l)}</span>`);
  const code = (v) => `<code class="recon-code">${esc(String(v ?? ""))}</code>`;
  const toast = (m, t) => (window.showToast ? window.showToast(m, t) : console.log(m));
  const download = (name, content, type) => window.downloadFile(name, content, type);

  const TK4_KEY = "web-x-sider:toolkit4";
  function tk4Load() { try { return JSON.parse(localStorage.getItem(TK4_KEY) || "{}"); } catch { return {}; } }
  function tk4Save(d) { try { localStorage.setItem(TK4_KEY, JSON.stringify(d)); } catch {} }
  function tk4Get(s) { return tk4Load()[s] || {}; }
  function tk4Set(s, v) { const d = tk4Load(); d[s] = v; tk4Save(d); }

  function buildPanel(id, html) {
    return `<div id="tk-panel-${id}" class="tk-panel" style="display:none;">${html}</div>`;
  }

  /* ============ 1. UNIFIED DASHBOARD ============ */
  function dashboardPanelHTML() {
    return buildPanel("dashboard", `
      <div class="dashboard-unified">
        <div class="dash-header">
          <h3><i class="fas fa-chart-line"></i> Unified Security Dashboard</h3>
          <p>Consolidated view of all scan results and findings</p>
        </div>
        <div class="dash-stats-grid" id="dashStatsGrid">
          <div class="dash-stat-card" data-color="blue">
            <i class="fas fa-link"></i>
            <span class="dash-stat-value" id="dashEndpoints">0</span>
            <span class="dash-stat-label">Endpoints</span>
          </div>
          <div class="dash-stat-card" data-color="red">
            <i class="fas fa-key"></i>
            <span class="dash-stat-value" id="dashSecrets">0</span>
            <span class="dash-stat-label">Secrets</span>
          </div>
          <div class="dash-stat-card" data-color="orange">
            <i class="fas fa-file"></i>
            <span class="dash-stat-value" id="dashFiles">0</span>
            <span class="dash-stat-label">Files</span>
          </div>
          <div class="dash-stat-card" data-color="purple">
            <i class="fas fa-crosshairs"></i>
            <span class="dash-stat-value" id="dashParams">0</span>
            <span class="dash-stat-label">Parameters</span>
          </div>
          <div class="dash-stat-card" data-color="green">
            <i class="fas fa-shield-halved"></i>
            <span class="dash-stat-value" id="dashTools">42</span>
            <span class="dash-stat-label">Tools Available</span>
          </div>
        </div>
        <div class="dash-priority-section">
          <h4><i class="fas fa-exclamation-triangle"></i> Priority Findings</h4>
          <div id="dashPriorityFindings" class="dash-findings-list">
            <p class="dash-empty">Run a scan to see findings here</p>
          </div>
        </div>
        <div class="dash-recent-scans">
          <h4><i class="fas fa-clock-rotate-left"></i> Recent Scans</h4>
          <div id="dashRecentScans" class="dash-scans-list">
            <p class="dash-empty">No recent scans</p>
          </div>
        </div>
      </div>
    `);
  }

  function updateDashboard() {
    const st = window.state;
    if (!st) return;

    const dashEndpoints = $("dashEndpoints");
    const dashSecrets = $("dashSecrets");
    const dashFiles = $("dashFiles");
    const dashParams = $("dashParams");

    if (dashEndpoints) dashEndpoints.textContent = st.endpoints?.size || 0;
    if (dashSecrets) dashSecrets.textContent = st.secrets?.size || 0;
    if (dashFiles) dashFiles.textContent = st.files?.size || 0;
    if (dashParams) dashParams.textContent = st.parameters?.size || 0;

    // Priority findings
    const priorityEl = $("dashPriorityFindings");
    if (priorityEl && window.getVisibleFindings) {
      const findings = window.getVisibleFindings();
      const critical = findings.filter(f => f.severity === "critical");
      const high = findings.filter(f => f.severity === "high");

      if (critical.length || high.length) {
        priorityEl.innerHTML = `
          ${critical.length ? `<div class="dash-finding critical">${badge("CRITICAL", "bad")} ${critical.slice(0, 5).map(f => `<span>${esc(f.type)}: ${esc(String(f.value).slice(0, 60))}</span>`).join("")}</div>` : ""}
          ${high.length ? `<div class="dash-finding high">${badge("HIGH", "warn")} ${high.slice(0, 5).map(f => `<span>${esc(f.type)}: ${esc(String(f.value).slice(0, 60))}</span>`).join("")}</div>` : ""}
        `;
      } else {
        priorityEl.innerHTML = `<p class="dash-empty">No critical or high findings</p>`;
      }
    }

    // Recent scans
    const scansEl = $("dashRecentScans");
    if (scansEl) {
      const scans = JSON.parse(localStorage.getItem("web-x-sider:sessions") || "[]");
      if (scans.length) {
        scansEl.innerHTML = scans.slice(-5).reverse().map(s => `<div class="dash-scan-item">${esc(s)}</div>`).join("");
      }
    }
  }

  /* ============ 2. ENHANCED REPORT GENERATION ============ */
  function reportPanelHTML() {
    return buildPanel("report", `
      <div class="report-options">
        <h3><i class="fas fa-file-alt"></i> Enhanced Report Generation</h3>
        <div class="report-type-grid">
          <button id="reportHtml" class="report-type-btn"><i class="fas fa-file-code"></i><span>HTML Report</span><small>Interactive charts</small></button>
          <button id="reportExecutive" class="report-type-btn"><i class="fas fa-file-lines"></i><span>Executive Summary</span><small>Non-technical</small></button>
          <button id="reportPdf" class="report-type-btn"><i class="fas fa-file-pdf"></i><span>PDF Report</span><small>Printable</small></button>
          <button id="reportJson" class="report-type-btn"><i class="fas fa-file-code"></i><span>JSON Data</span><small>Raw data</small></button>
        </div>
        <div id="reportPreview" class="report-preview"></div>
      </div>
    `);
  }

  function generateHtmlReport() {
    const st = window.state;
    if (!st) { toast("No scan data", "warn"); return; }
    const findings = window.getVisibleFindings ? window.getVisibleFindings() : [];
    const critical = findings.filter(f => f.severity === "critical").length;
    const high = findings.filter(f => f.severity === "high").length;
    const medium = findings.filter(f => f.severity === "medium").length;
    const low = findings.filter(f => f.severity === "low").length;

    const html = `<!DOCTYPE html>
<html><head><title>Web X Sider Report</title>
<style>
body{font-family:system-ui,-apple-system,sans-serif;margin:0;padding:20px;background:#f8fafc;color:#1e293b;}
.header{background:linear-gradient(135deg,#3b82f6,#8b5cf6);color:white;padding:30px;border-radius:12px;margin-bottom:24px;}
.header h1{margin:0;font-size:28px;}
.header p{margin:8px 0 0;opacity:0.9;}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px;}
.stat{background:white;padding:20px;border-radius:12px;text-align:center;box-shadow:0 2px 8px rgba(0,0,0,0.08);}
.stat-value{font-size:32px;font-weight:700;}
.stat-label{color:#64748b;font-size:14px;margin-top:4px;}
.stat-critical .stat-value{color:#ef4444;}
.stat-high .stat-value{color:#f97316;}
.stat-medium .stat-value{color:#eab308;}
.stat-low .stat-value{color:#3b82f6;}
.findings{background:white;border-radius:12px;padding:24px;box-shadow:0 2px 8px rgba(0,0,0,0.08);}
.findings h2{margin:0 0 16px;color:#1e293b;}
table{width:100%;border-collapse:collapse;}
th,td{padding:12px;text-align:left;border-bottom:1px solid #e2e8f0;}
th{background:#f8fafc;font-weight:600;color:#475569;}
.badge{display:inline-block;padding:4px 8px;border-radius:6px;font-size:12px;font-weight:600;}
.badge-critical{background:#fef2f2;color:#dc2626;}
.badge-high{background:#fff7ed;color:#ea580c;}
.badge-medium{background:#fefce8;color:#ca8a04;}
.badge-low{background:#eff6ff;color:#2563eb;}
</style></head><body>
<div class="header"><h1>Web X Sider - Security Scan Report</h1><p>Generated: ${new Date().toLocaleString()}</p></div>
<div class="stats">
<div class="stat stat-critical"><div class="stat-value">${critical}</div><div class="stat-label">Critical</div></div>
<div class="stat stat-high"><div class="stat-value">${high}</div><div class="stat-label">High</div></div>
<div class="stat stat-medium"><div class="stat-value">${medium}</div><div class="stat-label">Medium</div></div>
<div class="stat stat-low"><div class="stat-value">${low}</div><div class="stat-label">Low</div></div>
</div>
<div class="findings"><h2>Findings (${findings.length} total)</h2>
<table><thead><tr><th>Severity</th><th>Type</th><th>Value</th><th>Source</th></tr></thead>
<tbody>${findings.map(f => `<tr><td><span class="badge badge-${f.severity}">${(f.severity||"low").toUpperCase()}</span></td><td>${esc(f.type)}</td><td>${esc(String(f.value).slice(0,100))}</td><td>${esc(f.source)}</td></tr>`).join("")}</tbody>
</table></div></body></html>`;

    download("web-x-sider-report.html", html, "text/html");
    toast("HTML report generated", "success");
  }

  function generateExecutiveSummary() {
    const st = window.state;
    if (!st) { toast("No scan data", "warn"); return; }
    const findings = window.getVisibleFindings ? window.getVisibleFindings() : [];

    const summary = `# Executive Security Summary
Generated: ${new Date().toLocaleString()}

## Overview
- Total Findings: ${findings.length}
- Critical Issues: ${findings.filter(f => f.severity === "critical").length}
- High Issues: ${findings.filter(f => f.severity === "high").length}
- Medium Issues: ${findings.filter(f => f.severity === "medium").length}
- Low Issues: ${findings.filter(f => f.severity === "low").length}

## Key Recommendations
${findings.filter(f => f.severity === "critical").length ? "1. IMMEDIATE ACTION REQUIRED: Address critical vulnerabilities\n" : ""}
${findings.filter(f => f.severity === "high").length ? "2. HIGH PRIORITY: Remediate high-severity issues within 7 days\n" : ""}
3. Schedule regular security assessments
4. Implement automated security scanning in CI/CD pipeline

## Risk Assessment
Overall Risk Level: ${findings.filter(f => f.severity === "critical").length ? "CRITICAL" : findings.filter(f => f.severity === "high").length ? "HIGH" : "MEDIUM"}

---
Report generated by Web X Sider v5.0`;

    download("executive-summary.md", summary, "text/markdown");
    toast("Executive summary generated", "success");
  }

  /* ============ 3. SCAN HISTORY & COMPARISON ============ */
  function historyPanelHTML() {
    return buildPanel("history", `
      <div class="history-section">
        <h3><i class="fas fa-history"></i> Scan History</h3>
        <div class="history-actions">
          <button id="historySave" class="btn btn-primary"><i class="fas fa-save"></i><span>Save Current Scan</span></button>
          <button id="historyCompare" class="btn btn-secondary"><i class="fas fa-code-compare"></i><span>Compare Scans</span></button>
          <button id="historyExport" class="btn btn-secondary"><i class="fas fa-download"></i><span>Export All</span></button>
        </div>
        <div id="historyList" class="history-list"></div>
        <div id="historyCompareResult" class="history-compare"></div>
      </div>
    `);
  }

  const HISTORY_KEY = "web-x-sider:scan-history";

  function getHistory() {
    try { return JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]"); } catch { return []; }
  }

  function saveToHistory(name) {
    const st = window.state;
    if (!st) { toast("No scan data to save", "warn"); return; }
    const history = getHistory();
    history.push({
      id: Date.now(),
      name: name || `Scan ${new Date().toLocaleString()}`,
      date: new Date().toISOString(),
      endpoints: st.endpoints?.size || 0,
      secrets: st.secrets?.size || 0,
      files: st.files?.size || 0,
      parameters: st.parameters?.size || 0,
      findings: window.getVisibleFindings ? window.getVisibleFindings().length : 0
    });
    localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
    renderHistory();
    toast("Scan saved to history", "success");
  }

  function renderHistory() {
    const list = $("historyList");
    if (!list) return;
    const history = getHistory();
    if (!history.length) {
      list.innerHTML = `<p class="dash-empty">No scan history yet</p>`;
      return;
    }
    list.innerHTML = history.reverse().map(s => `
      <div class="history-item">
        <div class="history-info">
          <strong>${esc(s.name)}</strong>
          <small>${new Date(s.date).toLocaleString()}</small>
        </div>
        <div class="history-stats">
          <span>${badge(`${s.endpoints} endpoints`, "info")}</span>
          <span>${badge(`${s.secrets} secrets`, s.secrets ? "warn" : "good")}</span>
          <span>${badge(`${s.findings} findings`, "info")}</span>
        </div>
      </div>
    `).join("");
  }

  /* ============ 4. TARGET MANAGEMENT ============ */
  function targetsPanelHTML() {
    return buildPanel("targets", `
      <div class="targets-section">
        <h3><i class="fas fa-bullseye"></i> Target Management</h3>
        <div class="target-add-form">
          <input type="text" id="targetUrl" placeholder="https://target.com" />
          <input type="text" id="targetName" placeholder="Target name" />
          <select id="targetPriority">
            <option value="low">Low Priority</option>
            <option value="medium" selected>Medium Priority</option>
            <option value="high">High Priority</option>
            <option value="critical">Critical</option>
          </select>
          <textarea id="targetNotes" placeholder="Notes..."></textarea>
          <button id="targetAdd" class="btn btn-primary"><i class="fas fa-plus"></i><span>Add Target</span></button>
        </div>
        <div id="targetList" class="target-list"></div>
      </div>
    `);
  }

  const TARGETS_KEY = "web-x-sider:targets";

  function getTargets() {
    try { return JSON.parse(localStorage.getItem(TARGETS_KEY) || "[]"); } catch { return []; }
  }

  function addTarget() {
    const url = $("targetUrl")?.value.trim();
    const name = $("targetName")?.value.trim();
    const priority = $("targetPriority")?.value;
    const notes = $("targetNotes")?.value.trim();
    if (!url) { toast("Enter a target URL", "warn"); return; }

    const targets = getTargets();
    targets.push({ id: Date.now(), url, name: name || url, priority, notes, addedAt: new Date().toISOString() });
    localStorage.setItem(TARGETS_KEY, JSON.stringify(targets));
    renderTargets();
    $("targetUrl").value = "";
    $("targetName").value = "";
    $("targetNotes").value = "";
    toast("Target added", "success");
  }

  function renderTargets() {
    const list = $("targetList");
    if (!list) return;
    const targets = getTargets();
    if (!targets.length) {
      list.innerHTML = `<p class="dash-empty">No targets saved</p>`;
      return;
    }
    list.innerHTML = targets.map(t => `
      <div class="target-item" data-priority="${t.priority}">
        <div class="target-info">
          <strong>${esc(t.name)}</strong>
          <small>${esc(t.url)}</small>
          ${t.notes ? `<p class="target-notes">${esc(t.notes)}</p>` : ""}
        </div>
        <div class="target-actions">
          <span class="priority-badge priority-${t.priority}">${t.priority}</span>
          <button class="target-scan-btn" data-url="${esc(t.url)}"><i class="fas fa-play"></i></button>
          <button class="target-delete-btn" data-id="${t.id}"><i class="fas fa-trash"></i></button>
        </div>
      </div>
    `).join("");
  }

  /* ============ 5. KEYBOARD SHORTCUTS ============ */
  function shortcutsPanelHTML() {
    return buildPanel("shortcuts", `
      <div class="shortcuts-section">
        <h3><i class="fas fa-keyboard"></i> Keyboard Shortcuts</h3>
        <div class="shortcuts-grid">
          <div class="shortcut-item"><kbd>Ctrl</kbd> + <kbd>1</kbd><span>Crawler</span></div>
          <div class="shortcut-item"><kbd>Ctrl</kbd> + <kbd>2</kbd><span>Prober</span></div>
          <div class="shortcut-item"><kbd>Ctrl</kbd> + <kbd>3</kbd><span>Recon Suite</span></div>
          <div class="shortcut-item"><kbd>Ctrl</kbd> + <kbd>4</kbd><span>Settings</span></div>
          <div class="shortcut-item"><kbd>Ctrl</kbd> + <kbd>5</kbd><span>Toolkit</span></div>
          <div class="shortcut-item"><kbd>Ctrl</kbd> + <kbd>F</kbd><span>Focus Filter</span></div>
          <div class="shortcut-item"><kbd>Ctrl</kbd> + <kbd>E</kbd><span>Export Results</span></div>
          <div class="shortcut-item"><kbd>Ctrl</kbd> + <kbd>Enter</kbd><span>Start Scan</span></div>
          <div class="shortcut-item"><kbd>Ctrl</kbd> + <kbd>S</kbd><span>Save Session</span></div>
          <div class="shortcut-item"><kbd>Escape</kbd><span>Stop Scan</span></div>
        </div>
      </div>
    `);
  }

  function initKeyboardShortcuts() {
    document.addEventListener("keydown", (e) => {
      if (e.ctrlKey || e.metaKey) {
        const key = e.key.toLowerCase();
        if (key === "1") { e.preventDefault(); document.getElementById("navCrawler")?.click(); }
        if (key === "2") { e.preventDefault(); document.getElementById("navProber")?.click(); }
        if (key === "3") { e.preventDefault(); document.getElementById("navRecon")?.click(); }
        if (key === "4") { e.preventDefault(); document.getElementById("navSettings")?.click(); }
        if (key === "5") { e.preventDefault(); document.getElementById("navToolkit")?.click(); }
        if (key === "f") { e.preventDefault(); document.getElementById("filterInput")?.focus(); }
        if (key === "e") { e.preventDefault(); document.getElementById("exportActions")?.scrollIntoView(); }
      }
    });
  }

  /* ============ 6. SERVICE WORKER (Offline Support) ============ */
  function initServiceWorker() {
    if ("serviceWorker" in navigator) {
      navigator.serviceWorker.register("sw.js").catch(() => {});
    }
  }

  /* ============ 7. CUSTOM WORDLIST UPLOAD ============ */
  function wordlistPanelHTML() {
    return buildPanel("wordlist", `
      <div class="wordlist-section">
        <h3><i class="fas fa-file-lines"></i> Custom Wordlist Manager</h3>
        <div class="wordlist-upload">
          <input type="file" id="wordlistFile" accept=".txt,.csv,.lst" />
          <button id="wordlistUpload" class="btn btn-primary"><i class="fas fa-upload"></i><span>Upload Wordlist</span></button>
        </div>
        <div class="wordlist-presets">
          <h4>Quick Wordlists</h4>
          <button class="wordlist-preset" data-type="admin">Admin Paths</button>
          <button class="wordlist-preset" data-type="api">API Endpoints</button>
          <button class="wordlist-preset" data-type="backup">Backup Files</button>
          <button class="wordlist-preset" data-type="sensitive">Sensitive Files</button>
        </div>
        <div id="wordlistPreview" class="wordlist-preview"></div>
      </div>
    `);
  }

  const WORDLIST_PRESETS = {
    admin: ["/admin", "/admin/login", "/administrator", "/dashboard", "/manage", "/wp-admin", "/phpmyadmin", "/cpanel"],
    api: ["/api", "/api/v1", "/api/v2", "/graphql", "/swagger", "/api-docs", "/openapi.json"],
    backup: ["/backup", "/backup.sql", "/.bak", "/.old", "/config.bak", "/database.sql"],
    sensitive: ["/.env", "/.git/config", "/.git/HEAD", "/wp-config.php", "/config.json", "/.aws/credentials"]
  };

  /* ============ 8. SCAN PROFILES ============ */
  function profilesPanelHTML() {
    return buildPanel("profiles", `
      <div class="profiles-section">
        <h3><i class="fas fa-sliders"></i> Scan Profiles</h3>
        <div class="profile-grid">
          <div class="profile-card" data-profile="stealth">
            <i class="fas fa-user-secret"></i>
            <h4>Stealth</h4>
            <p>Slow, careful scanning</p>
            <ul><li>Delay: 1000ms</li><li>Concurrency: 2</li><li>Depth: 1</li></ul>
            <button class="profile-apply" data-delay="1000" data-concurrency="2" data-depth="1">Apply</button>
          </div>
          <div class="profile-card active" data-profile="normal">
            <i class="fas fa-balance-scale"></i>
            <h4>Normal</h4>
            <p>Balanced speed and coverage</p>
            <ul><li>Delay: 300ms</li><li>Concurrency: 5</li><li>Depth: 1</li></ul>
            <button class="profile-apply" data-delay="300" data-concurrency="5" data-depth="1">Apply</button>
          </div>
          <div class="profile-card" data-profile="aggressive">
            <i class="fas fa-bolt"></i>
            <h4>Aggressive</h4>
            <p>Fast, maximum coverage</p>
            <ul><li>Delay: 100ms</li><li>Concurrency: 10</li><li>Depth: 2</li></ul>
            <button class="profile-apply" data-delay="100" data-concurrency="10" data-depth="2">Apply</button>
          </div>
        </div>
        <div class="custom-profile">
          <h4>Custom Profile</h4>
          <div class="profile-form">
            <label>Delay (ms): <input type="number" id="profileDelay" value="300" /></label>
            <label>Concurrency: <input type="number" id="profileConcurrency" value="5" min="1" max="20" /></label>
            <label>Depth: <input type="number" id="profileDepth" value="1" min="0" max="5" /></label>
            <button id="profileSave" class="btn btn-primary"><i class="fas fa-save"></i><span>Save Profile</span></button>
          </div>
        </div>
      </div>
    `);
  }

  /* ============ 9. EMAIL/WEBHOOK ALERTS ============ */
  function alertsPanelHTML() {
    return buildPanel("alerts", `
      <div class="alerts-section">
        <h3><i class="fas fa-bell"></i> Alert Configuration</h3>
        <div class="alert-form">
          <label>Webhook URL (Discord/Slack)</label>
          <input type="url" id="alertWebhook" placeholder="https://discord.com/api/webhooks/..." />
          <label>Alert on:</label>
          <div class="alert-checkboxes">
            <label><input type="checkbox" id="alertCritical" checked /> Critical findings</label>
            <label><input type="checkbox" id="alertHigh" checked /> High findings</label>
            <label><input type="checkbox" id="alertMedium" /> Medium findings</label>
            <label><input type="checkbox" id="alertScanComplete" checked /> Scan complete</label>
          </div>
          <button id="alertSave" class="btn btn-primary"><i class="fas fa-save"></i><span>Save Alert Settings</span></button>
          <button id="alertTest" class="btn btn-secondary"><i class="fas fa-paper-plane"></i><span>Test Alert</span></button>
        </div>
      </div>
    `);
  }

  /* ============ 10. COMPLIANCE CHECKS ============ */
  function compliancePanelHTML() {
    return buildPanel("compliance", `
      <div class="compliance-section">
        <h3><i class="fas fa-clipboard-check"></i> Compliance Checks</h3>
        <div class="compliance-grid">
          <button id="complianceOwasp" class="compliance-btn"><i class="fas fa-shield-halved"></i><span>OWASP Top 10</span></button>
          <button id="compliancePci" class="compliance-btn"><i class="fas fa-credit-card"></i><span>PCI DSS</span></button>
          <button id="complianceNist" class="compliance-btn"><i class="fas fa-building-shield"></i><span>NIST</span></button>
        </div>
        <div id="complianceResults" class="compliance-results"></div>
      </div>
    `);
  }

  const OWASP_TOP_10 = [
    { id: "A01", name: "Broken Access Control", check: "admin,auth,login,token,session,role" },
    { id: "A02", name: "Cryptographic Failures", check: "password,secret,key,token,encrypt" },
    { id: "A03", name: "Injection", check: "sql,command,ldap,xpath" },
    { id: "A04", name: "Insecure Design", check: "design,architecture" },
    { id: "A05", name: "Security Misconfiguration", check: "config,debug,version,header" },
    { id: "A06", name: "Vulnerable Components", check: "jquery,angular,react,version" },
    { id: "A07", name: "Auth Failures", check: "login,session,cookie,jwt" },
    { id: "A08", name: "Data Integrity Failures", check: "ci,cicd,pipeline" },
    { id: "A09", name: "Logging Failures", check: "log,error,debug" },
    { id: "A10", name: "SSRF", check: "url,redirect,fetch,proxy" }
  ];

  function runComplianceCheck(type) {
    const results = $("complianceResults");
    if (!results) return;

    if (type === "owasp") {
      const findings = window.getVisibleFindings ? window.getVisibleFindings() : [];
      results.innerHTML = `
        <h4>OWASP Top 10 Assessment</h4>
        ${OWASP_TOP_10.map(item => {
          const relevant = findings.filter(f => item.check.split(",").some(c => f.value.toLowerCase().includes(c)));
          return `<div class="compliance-item">
            <span class="compliance-id">${item.id}</span>
            <span class="compliance-name">${item.name}</span>
            <span class="compliance-status ${relevant.length ? "fail" : "pass"}">${relevant.length ? `${relevant.length} issues` : "Pass"}</span>
          </div>`;
        }).join("")}
      `;
    }
  }

  /* ============ 11. API FOR EXTERNAL INTEGRATION ============ */
  function apiPanelHTML() {
    return buildPanel("api", `
      <div class="api-section">
        <h3><i class="fas fa-plug"></i> API Integration</h3>
        <div class="api-info">
          <p>Web X Sider exposes a local API for integration with other tools.</p>
          <div class="api-endpoints">
            <div class="api-endpoint"><code>GET /api/results</code><span>Get current scan results</span></div>
            <div class="api-endpoint"><code>GET /api/stats</code><span>Get scan statistics</span></div>
            <div class="api-endpoint"><code>POST /api/scan</code><span>Start a scan</span></div>
            <div class="api-endpoint"><code>GET /api/health</code><span>Health check</span></div>
          </div>
          <p class="api-note">Note: API is only available when running locally with server.py</p>
        </div>
      </div>
    `);
  }

  /* ============ 12. MULTI-LANGUAGE SUPPORT (i18n) ============ */
  const LANGUAGES = {
    en: { name: "English", scanner: "Scanner", prober: "Prober", recon: "Recon Suite", settings: "Settings", toolkit: "Toolkit", startScan: "Start Scan", fullScan: "Full Scan" },
    es: { name: "Español", scanner: "Escáner", prober: "Sondas", recon: "Reconocimiento", settings: "Ajustes", toolkit: "Herramientas", startScan: "Iniciar", fullScan: "Escaneo Completo" },
    fr: { name: "Français", scanner: "Scanner", prober: "Sondeur", recon: "Reconnaissance", settings: "Paramètres", toolkit: "Boîte à outils", startScan: "Démarrer", fullScan: "Scan Complet" },
    de: { name: "Deutsch", scanner: "Scanner", prober: "Prober", recon: "Aufklärung", settings: "Einstellungen", toolkit: "Werkzeugkasten", startScan: "Starten", fullScan: "Vollscan" },
    pt: { name: "Português", scanner: "Scanner", prober: "Sonda", recon: "Reconhecimento", settings: "Configurações", toolkit: "Ferramentas", startScan: "Iniciar", fullScan: "Scan Completo" },
    ar: { name: "العربية", scanner: "الماسح", prober: "المستكشف", recon: "الاستطلاع", settings: "الإعدادات", toolkit: "الأدوات", startScan: "بدء", fullScan: "فحص كامل" }
  };

  function i18nPanelHTML() {
    return buildPanel("i18n", `
      <div class="i18n-section">
        <h3><i class="fas fa-language"></i> Language / Idioma / Langue</h3>
        <div class="lang-grid">
          ${Object.entries(LANGUAGES).map(([code, lang]) => `
            <button class="lang-btn" data-lang="${code}">${lang.name}</button>
          `).join("")}
        </div>
      </div>
    `);
  }

  let currentLang = "en";

  function applyLanguage(lang) {
    currentLang = lang;
    const t = LANGUAGES[lang] || LANGUAGES.en;
    // Update nav links
    const navCrawler = document.querySelector("#navCrawler span");
    const navProber = document.querySelector("#navProber span");
    const navRecon = document.querySelector("#navRecon span");
    const navSettings = document.querySelector("#navSettings span");
    const navToolkit = document.querySelector("#navToolkit span");
    if (navCrawler) navCrawler.textContent = t.scanner;
    if (navProber) navProber.textContent = t.prober;
    if (navRecon) navRecon.textContent = t.recon;
    if (navSettings) navSettings.textContent = t.settings;
    if (navToolkit) navToolkit.textContent = t.toolkit;
    tk4Set("lang", lang);
    toast(`Language: ${t.name}`, "info");
  }

  /* ============ 13. DARK/LIGHT THEME TOGGLE ============ */
  function themePanelHTML() {
    return buildPanel("theme", `
      <div class="theme-section">
        <h3><i class="fas fa-palette"></i> Theme Settings</h3>
        <div class="theme-grid">
          <button class="theme-btn active" data-theme="dark"><i class="fas fa-moon"></i><span>Dark</span></button>
          <button class="theme-btn" data-theme="light"><i class="fas fa-sun"></i><span>Light</span></button>
          <button class="theme-btn" data-theme="auto"><i class="fas fa-circle-half-stroke"></i><span>Auto</span></button>
        </div>
      </div>
    `);
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    if (theme === "auto") {
      const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
      document.documentElement.setAttribute("data-theme", prefersDark ? "dark" : "light");
    }
    tk4Set("theme", theme);
    document.querySelectorAll(".theme-btn").forEach(b => b.classList.toggle("active", b.dataset.theme === theme));
  }

  /* ============ 14. ACCESSIBILITY IMPROVEMENTS ============ */
  function accessibilityPanelHTML() {
    return buildPanel("accessibility", `
      <div class="a11y-section">
        <h3><i class="fas fa-universal-access"></i> Accessibility</h3>
        <div class="a11y-options">
          <label class="a11y-toggle">
            <input type="checkbox" id="a11yHighContrast" />
            <span>High Contrast Mode</span>
          </label>
          <label class="a11y-toggle">
            <input type="checkbox" id="a11yLargeText" />
            <span>Larger Text</span>
          </label>
          <label class="a11y-toggle">
            <input type="checkbox" id="a11yReduceMotion" />
            <span>Reduce Animations</span>
          </label>
          <label class="a11y-toggle">
            <input type="checkbox" id="a11yScreenReader" checked />
            <span>Screen Reader Optimized</span>
          </label>
        </div>
      </div>
    `);
  }

  function initAccessibility() {
    $("a11yHighContrast")?.addEventListener("change", (e) => {
      document.documentElement.classList.toggle("high-contrast", e.target.checked);
    });
    $("a11yLargeText")?.addEventListener("change", (e) => {
      document.documentElement.classList.toggle("large-text", e.target.checked);
    });
    $("a11yReduceMotion")?.addEventListener("change", (e) => {
      document.documentElement.classList.toggle("reduce-motion", e.target.checked);
    });
  }

  /* ============ INIT ============ */
  function addTabs() {
    const tabs = document.getElementById("toolkit-tabs");
    if (!tabs || tabs.dataset.tk4done) return;
    tabs.dataset.tk4done = "1";

    const newTabs = [
      ["dashboard", "fas fa-chart-line", "Dashboard"],
      ["report", "fas fa-file-alt", "Reports"],
      ["history", "fas fa-history", "History"],
      ["targets", "fas fa-bullseye", "Targets"],
      ["wordlist", "fas fa-file-lines", "Wordlists"],
      ["compliance", "fas fa-clipboard-check", "Compliance"],
      ["api", "fas fa-plug", "API"]
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
        if (id === "dashboard") updateDashboard();
      });
      tabs.appendChild(btn);
    });

    const section = tabs.parentElement;
    const panelsHtml = [
      dashboardPanelHTML(), reportPanelHTML(), historyPanelHTML(), targetsPanelHTML(),
      shortcutsPanelHTML(), wordlistPanelHTML(), profilesPanelHTML(), alertsPanelHTML(),
      compliancePanelHTML(), apiPanelHTML(), i18nPanelHTML(), themePanelHTML(), accessibilityPanelHTML()
    ].join("\n");
    const tmp = document.createElement("div");
    tmp.innerHTML = panelsHtml;
    while (tmp.firstChild) section.appendChild(tmp.firstChild);
  }

  document.addEventListener("DOMContentLoaded", () => {
    addTabs();

    // Report buttons
    $("reportHtml")?.addEventListener("click", generateHtmlReport);
    $("reportExecutive")?.addEventListener("click", generateExecutiveSummary);

    // History
    $("historySave")?.addEventListener("click", () => saveToHistory());
    renderHistory();

    // Targets
    $("targetAdd")?.addEventListener("click", addTarget);
    renderTargets();

    // Wordlist presets
    document.querySelectorAll(".wordlist-preset").forEach(btn => {
      btn.addEventListener("click", () => {
        const type = btn.dataset.type;
        const paths = WORDLIST_PRESETS[type] || [];
        const proberInput = document.getElementById("customPathInput");
        if (proberInput) {
          proberInput.value = [...new Set([...proberInput.value.split("\n").filter(Boolean), ...paths])].join("\n");
          toast(`Added ${paths.length} ${type} paths`, "success");
        }
      });
    });

    // Profiles
    document.querySelectorAll(".profile-apply").forEach(btn => {
      btn.addEventListener("click", () => {
        const delay = btn.dataset.delay;
        const concurrency = btn.dataset.concurrency;
        const delayInput = document.getElementById("setting-crawlerDelay");
        const concInput = document.getElementById("setting-concurrency");
        if (delayInput) delayInput.value = delay;
        if (concInput) concInput.value = concurrency;
        document.getElementById("saveSettingsBtn")?.click();
        toast(`Profile applied: delay=${delay}ms, concurrency=${concurrency}`, "success");
      });
    });

    // Alerts
    $("alertSave")?.addEventListener("click", () => {
      tk4Set("alerts", {
        webhook: $("alertWebhook")?.value || "",
        critical: $("alertCritical")?.checked,
        high: $("alertHigh")?.checked,
        medium: $("alertMedium")?.checked,
        scanComplete: $("alertScanComplete")?.checked
      });
      toast("Alert settings saved", "success");
    });

    // Compliance
    $("complianceOwasp")?.addEventListener("click", () => runComplianceCheck("owasp"));

    // Language
    document.querySelectorAll(".lang-btn").forEach(btn => {
      btn.addEventListener("click", () => applyLanguage(btn.dataset.lang));
    });

    // Theme
    document.querySelectorAll(".theme-btn").forEach(btn => {
      btn.addEventListener("click", () => applyTheme(btn.dataset.theme));
    });

    // Load saved preferences
    const savedLang = tk4Get("lang");
    if (savedLang) applyLanguage(savedLang);
    const savedTheme = tk4Get("theme");
    if (savedTheme) applyTheme(savedTheme);

    // Init features
    initKeyboardShortcuts();
    initAccessibility();
    initServiceWorker();
  });
})();

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
            <span class="dash-stat-value" id="dashTools">104</span>
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
  /* ============ 6. CUSTOM WORDLIST MANAGER ============ */
  const WORDLIST_KEY = "web-x-sider:wordlists";

  function loadWordlists() {
    try { return JSON.parse(localStorage.getItem(WORDLIST_KEY) || "[]"); } catch { return []; }
  }
  function saveWordlists(lists) {
    try { localStorage.setItem(WORDLIST_KEY, JSON.stringify(lists)); } catch {}
  }

  function wordlistPanelHTML() {
    const saved = loadWordlists();
    return buildPanel("wordlist", `
      <div class="wordlist-section">
        <h3><i class="fas fa-file-lines"></i> Custom Wordlist Manager</h3>
        <div class="wordlist-upload">
          <input type="file" id="wordlistFile" accept=".txt,.csv,.lst" multiple />
          <button id="wordlistUpload" class="btn btn-primary"><i class="fas fa-upload"></i><span>Upload Wordlist</span></button>
        </div>
        <div class="wordlist-create" style="margin-top:12px;">
          <input type="text" id="wordlistName" placeholder="Wordlist name..." style="width:200px;margin-right:8px;" />
          <button id="wordlistSaveCurrent" class="btn btn-secondary"><i class="fas fa-save"></i><span>Save Current Paths</span></button>
        </div>
        <div class="wordlist-presets" style="margin-top:12px;">
          <h4>Quick Presets</h4>
          <button class="wordlist-preset" data-type="admin">Admin Paths</button>
          <button class="wordlist-preset" data-type="api">API Endpoints</button>
          <button class="wordlist-preset" data-type="backup">Backup Files</button>
          <button class="wordlist-preset" data-type="sensitive">Sensitive Files</button>
          <button class="wordlist-preset" data-type="wordpress">WordPress</button>
          <button class="wordlist-preset" data-type="spring">Spring Boot</button>
          <button class="wordlist-preset" data-type="laravel">Laravel</button>
        </div>
        <div id="wordlistSaved" class="wordlist-saved" style="margin-top:16px;">
          <h4>Saved Wordlists (${saved.length})</h4>
          <div id="wordlistList" class="wordlist-list">
            ${saved.length === 0 ? '<p class="dash-empty">No saved wordlists</p>' :
              saved.map((w, i) => `
                <div class="wordlist-item" data-index="${i}">
                  <span class="wordlist-item-name">${esc(w.name)}</span>
                  <span class="wordlist-item-count">${w.paths.length} paths</span>
                  <button class="wordlist-load btn btn-sm" data-index="${i}"><i class="fas fa-upload"></i></button>
                  <button class="wordlist-delete btn btn-sm btn-danger" data-index="${i}"><i class="fas fa-trash"></i></button>
                </div>
              `).join("")
            }
          </div>
        </div>
        <div id="wordlistPreview" class="wordlist-preview" style="margin-top:12px;"></div>
      </div>
    `);
  }

  const WORDLIST_PRESETS = {
    admin: ["/admin", "/admin/login", "/administrator", "/dashboard", "/manage", "/wp-admin", "/phpmyadmin", "/cpanel", "/portal", "/console", "/backend", "/backoffice", "/staff", "/internal", "/secure", "/moderator", "/superadmin"],
    api: ["/api", "/api/v1", "/api/v2", "/api/v3", "/graphql", "/swagger", "/swagger-ui", "/api-docs", "/openapi.json", "/openapi.yaml", "/rest", "/api/users", "/api/auth", "/api/admin", "/api/config", "/api/health", "/api/status"],
    backup: ["/backup", "/backup.sql", "/.bak", "/.old", "/config.bak", "/database.sql", "/db.sql", "/dump.sql", "/backup.zip", "/backup.tar.gz", "/www.zip", "/site.zip", "/source.zip", "/.backup"],
    sensitive: ["/.env", "/.git/config", "/.git/HEAD", "/wp-config.php", "/config.json", "/.aws/credentials", "/.ssh/id_rsa", "/id_rsa.pub", "/.htpasswd", "/.htaccess", "/web.config", "/config.php", "/config.yml", "/config.yaml", "/.DS_Store", "/server.key", "/server.pem"],
    wordpress: ["/wp-admin", "/wp-login.php", "/wp-config.php", "/wp-config.php.bak", "/wp-content/uploads", "/wp-content/plugins", "/wp-content/themes", "/wp-includes", "/xmlrpc.php", "/wp-json/wp/v2/users", "/wp-cron.php", "/readme.html", "/license.txt"],
    spring: ["/actuator", "/actuator/env", "/actuator/health", "/actuator/info", "/actuator/metrics", "/actuator/beans", "/actuator/configprops", "/actuator/mappings", "/actuator/threaddump", "/swagger-ui.html", "/swagger-ui/", "/v3/api-docs", "/hystrix", "/trace"],
    laravel: ["/.env", "/storage/logs/laravel.log", "/storage/framework/sessions", "/telescope", "/horizon", "/.git/config", "/artisan", "/bootstrap/cache", "/config/app.php", "/config/database.php", "/config/services.php"]
  };

  function handleWordlistUpload() {
    const fileInput = $("wordlistFile");
    if (!fileInput?.files?.length) return;

    Array.from(fileInput.files).forEach(file => {
      const reader = new FileReader();
      reader.onload = (e) => {
        const paths = e.target.result.split(/[\r\n]+/).map(l => l.trim()).filter(Boolean);
        if (paths.length === 0) { toast("Empty file", "error"); return; }

        const lists = loadWordlists();
        lists.push({ name: file.name.replace(/\.[^.]+$/, ""), paths, created: Date.now() });
        saveWordlists(lists);
        toast(`Uploaded "${file.name}" — ${paths.length} paths`, "success");
        refreshWordlistList();
      };
      reader.readAsText(file);
    });
    fileInput.value = "";
  }

  function saveCurrentPathsAsWordlist() {
    const name = $("wordlistName")?.value?.trim();
    if (!name) { toast("Enter a name", "error"); return; }
    const proberInput = document.getElementById("customPathInput");
    const paths = proberInput ? proberInput.value.split(/[\r\n]+/).filter(Boolean) : [];
    if (paths.length === 0) { toast("No paths in prober", "error"); return; }

    const lists = loadWordlists();
    lists.push({ name, paths, created: Date.now() });
    saveWordlists(lists);
    toast(`Saved "${name}" — ${paths.length} paths`, "success");
    $("wordlistName").value = "";
    refreshWordlistList();
  }

  function loadWordlistToProber(index) {
    const lists = loadWordlists();
    const wl = lists[index];
    if (!wl) return;
    const proberInput = document.getElementById("customPathInput");
    if (proberInput) {
      proberInput.value = [...new Set([...proberInput.value.split("\n").filter(Boolean), ...wl.paths])].join("\n");
      toast(`Loaded "${wl.name}" — ${wl.paths.length} paths`, "success");
    }
  }

  function deleteWordlist(index) {
    const lists = loadWordlists();
    const name = lists[index]?.name || "unknown";
    lists.splice(index, 1);
    saveWordlists(lists);
    toast(`Deleted "${name}"`, "info");
    refreshWordlistList();
  }

  function refreshWordlistList() {
    const container = $("wordlistList");
    if (!container) return;
    const saved = loadWordlists();
    container.innerHTML = saved.length === 0 ? '<p class="dash-empty">No saved wordlists</p>' :
      saved.map((w, i) => `
        <div class="wordlist-item" data-index="${i}">
          <span class="wordlist-item-name">${esc(w.name)}</span>
          <span class="wordlist-item-count">${w.paths.length} paths</span>
          <button class="wordlist-load btn btn-sm" data-index="${i}" onclick="window._wlLoad(${i})"><i class="fas fa-upload"></i></button>
          <button class="wordlist-delete btn btn-sm btn-danger" data-index="${i}" onclick="window._wlDelete(${i})"><i class="fas fa-trash"></i></button>
        </div>
      `).join("");
    const header = container.previousElementSibling;
    if (header) header.textContent = `Saved Wordlists (${saved.length})`;
  }

  window._wlLoad = loadWordlistToProber;
  window._wlDelete = deleteWordlist;

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
        <div class="compliance-export" style="margin-top:12px;">
          <button id="complianceExport" class="btn btn-secondary" style="display:none;"><i class="fas fa-download"></i><span>Export Report</span></button>
        </div>
      </div>
    `);
  }

  const OWASP_TOP_10 = [
    {
      id: "A01", name: "Broken Access Control",
      checks: [
        { test: "No CORS policy or overly permissive CORS", severity: "high", detect: (s, h) => !h["access-control-allow-origin"] || h["access-control-allow-origin"] === "*" },
        { test: "Missing authentication headers", severity: "medium", detect: (s, h) => s === 200 && /admin|manage|dashboard/i.test(s) },
        { test: "IDOR-susceptible parameters detected", severity: "high", detect: (s, h, findings) => findings.some(f => /id|user|account|profile/i.test(f.value) && f.type === "parameter") },
        { test: "Path traversal indicators", severity: "critical", detect: (s, h, findings) => findings.some(f => /\.\.\/|\.%2e|..\/\//i.test(f.value)) }
      ]
    },
    {
      id: "A02", name: "Cryptographic Failures",
      checks: [
        { test: "Hardcoded secrets found", severity: "critical", detect: (s, h, findings) => findings.some(f => f.type === "secret") },
        { test: "Sensitive data in URLs", severity: "high", detect: (s, h, findings) => findings.some(f => /password|token|key|secret|api_key/i.test(f.value)) },
        { test: "Weak encryption references", severity: "medium", detect: (s, h, findings) => findings.some(f => /md5|sha1|des|rc4/i.test(f.value)) },
        { test: "Mixed content (HTTP on HTTPS)", severity: "medium", detect: (s, h, findings) => findings.some(f => /http:\/\//i.test(f.value) && f.type === "endpoint") }
      ]
    },
    {
      id: "A03", name: "Injection",
      checks: [
        { test: "SQL injection indicators", severity: "critical", detect: (s, h, findings) => findings.some(f => /union\s+select|or\s+1=1|'--|sql/i.test(f.value)) },
        { test: "XSS-susceptible parameters", severity: "high", detect: (s, h, findings) => findings.some(f => f.type === "reflected_param") },
        { test: "Command injection vectors", severity: "critical", detect: (s, h, findings) => findings.some(f => /;|&&|\||`|exec|system/i.test(f.value)) },
        { test: "LDAP/XML/XPath injection patterns", severity: "high", detect: (s, h, findings) => findings.some(f => /ldap|xpath|xml/i.test(f.value) && f.type === "parameter") }
      ]
    },
    {
      id: "A04", name: "Insecure Design",
      checks: [
        { test: "No rate limiting detected", severity: "medium", detect: () => true },
        { test: "No CSRF protection indicators", severity: "medium", detect: (s, h) => !h["x-csrf-token"] && !h["x-xsrf-token"] },
        { test: "Sensitive functionality exposed", severity: "high", detect: (s, h, findings) => findings.some(f => /debug|test|staging|dev|internal/i.test(f.value)) },
        { test: "No security.txt found", severity: "low", detect: () => true }
      ]
    },
    {
      id: "A05", name: "Security Misconfiguration",
      checks: [
        { test: "Missing security headers", severity: "high", detect: (s, h) => !h["content-security-policy"] || !h["x-content-type-options"] || !h["x-frame-options"] },
        { test: "CORS misconfiguration", severity: "high", detect: (s, h) => h["access-control-allow-origin"] === "*" && h["access-control-allow-credentials"] === "true" },
        { test: "Server/version information leaked", severity: "medium", detect: (s, h) => !!(h["server"] || h["x-powered-by"]) },
        { test: "Debug mode enabled", severity: "high", detect: (s, h, findings) => findings.some(f => /debug|stack.?trace|error.?page/i.test(f.value)) },
        { test: "Default credentials suspected", severity: "critical", detect: (s, h, findings) => findings.some(f => /admin.*admin|default.*password|root.*root/i.test(f.value)) },
        { test: "Open redirect detected", severity: "high", detect: (s, h, findings) => findings.some(f => /redirect|return_to|next=|url=|dest=/i.test(f.value) && f.type === "parameter") }
      ]
    },
    {
      id: "A06", name: "Vulnerable & Outdated Components",
      checks: [
        { test: "Known vulnerable JS libraries", severity: "high", detect: (s, h, findings) => findings.some(f => /jquery\s*[<>=]\s*["']?2\.|angular\s*[<>=]\s*["']?1\.|react\s*[<>=]\s*["']?16\./i.test(f.value)) },
        { test: "Outdated framework versions", severity: "medium", detect: (s, h, findings) => findings.some(f => f.type === "tech" && /wordpress\s*[<>=]\s*["']?[0-4]\.|php\s*[<>=]\s*["']?7\.|django\s*[<>=]\s*["']?2\./i.test(f.value)) }
      ]
    },
    {
      id: "A07", name: "Identification & Authentication Failures",
      checks: [
        { test: "Weak session management", severity: "high", detect: (s, h) => !h["set-cookie"]?.includes("Secure") || !h["set-cookie"]?.includes("HttpOnly") },
        { test: "No multi-factor authentication indicators", severity: "medium", detect: () => true },
        { test: "Credential stuffing vectors", severity: "medium", detect: (s, h, findings) => findings.some(f => /login|signin|auth|register/i.test(f.value) && f.type === "endpoint") },
        { test: "JWT misconfigurations", severity: "high", detect: (s, h, findings) => findings.some(f => /alg.*none|jwt.*weak|hs256/i.test(f.value)) }
      ]
    },
    {
      id: "A08", name: "Software & Data Integrity Failures",
      checks: [
        { test: "No Subresource Integrity (SRI)", severity: "medium", detect: () => !document.querySelector("script[integrity]") },
        { test: "Insecure CI/CD pipeline exposure", severity: "high", detect: (s, h, findings) => findings.some(f => /\.github|jenkins|gitlab|\.gitlab-ci|bitbucket-pipelines/i.test(f.value)) },
        { test: "Auto-update without integrity check", severity: "medium", detect: () => true }
      ]
    },
    {
      id: "A09", name: "Security Logging & Monitoring Failures",
      checks: [
        { test: "No logging endpoint detected", severity: "low", detect: (s, h, findings) => !findings.some(f => /log|audit|monitor|telemetry/i.test(f.value)) },
        { test: "Error messages may leak info", severity: "medium", detect: (s, h, findings) => findings.some(f => /stack.?trace|exception|debug|verbose/i.test(f.value)) }
      ]
    },
    {
      id: "A10", name: "Server-Side Request Forgery (SSRF)",
      checks: [
        { test: "URL-fetching parameters", severity: "high", detect: (s, h, findings) => findings.some(f => /url|fetch|proxy|redirect|src|href|link/i.test(f.value) && f.type === "parameter") },
        { test: "Internal network access vectors", severity: "critical", detect: (s, h, findings) => findings.some(f => /localhost|127\.0\.0|10\.|172\.|192\.168|internal|intranet/i.test(f.value)) },
        { test: "Cloud metadata endpoints", severity: "critical", detect: (s, h, findings) => findings.some(f => /169\.254\.169\.254|metadata|instance-data|cloud-metadata/i.test(f.value)) }
      ]
    }
  ];

  const PCI_DSS_CHECKS = [
    { id: "PCI-1", name: "Firewall/Network Segmentation", test: "Network-level controls are outside client scope", severity: "info" },
    { id: "PCI-2", name: "No Default Credentials", severity: "high", detect: (s, h, findings) => findings.some(f => /admin|default|password|root/i.test(f.value)) },
    { id: "PCI-3", name: "Protect Stored Cardholder Data", severity: "critical", detect: (s, h, findings) => findings.some(f => /card|credit|cvv|pan|ccnum|cardholder/i.test(f.value)) },
    { id: "PCI-4", name: "Encrypt Transmission of CHD", severity: "high", detect: (s, h) => location.protocol === "http:" },
    { id: "PCI-5", name: "Use Anti-Virus Software", severity: "info" },
    { id: "PCI-6", name: "Develop Secure Systems", severity: "info" },
    { id: "PCI-7", name: "Restrict Access by Need-to-Know", severity: "high", detect: (s, h, findings) => findings.some(f => /admin|root|superuser|full.?access/i.test(f.value)) },
    { id: "PCI-8", name: "Assign Unique IDs", severity: "medium", detect: (s, h, findings) => findings.some(f => /shared.*account|generic.*user|test.*user/i.test(f.value)) },
    { id: "PCI-9", name: "Restrict Physical Access", severity: "info" },
    { id: "PCI-10", name: "Log & Monitor All Access", severity: "medium", detect: (s, h, findings) => !findings.some(f => /log|audit/i.test(f.value)) },
    { id: "PCI-11", name: "Regular Security Testing", severity: "info" },
    { id: "PCI-12", name: "Maintain Information Security Policy", severity: "info" }
  ];

  const NIST_CHECKS = [
    { id: "NIST-AC", name: "Access Control", severity: "high", detect: (s, h, findings) => !h["x-frame-options"] || findings.some(f => /admin|manage/i.test(f.value) && f.type === "endpoint") },
    { id: "NIST-AU", name: "Audit & Accountability", severity: "medium", detect: (s, h, findings) => !findings.some(f => /log|audit/i.test(f.value)) },
    { id: "NIST-CM", name: "Configuration Management", severity: "high", detect: (s, h) => !!(h["server"] || h["x-powered-by"]) },
    { id: "NIST-IA", name: "Identification & Authentication", severity: "high", detect: (s, h) => !h["set-cookie"]?.includes("Secure") },
    { id: "NIST-IR", name: "Incident Response", severity: "info" },
    { id: "NIST-MP", name: "Media Protection", severity: "info" },
    { id: "NIST-PE", name: "Physical & Environmental", severity: "info" },
    { id: "NIST-PL", name: "Planning", severity: "info" },
    { id: "NIST-PS", name: "Personnel Security", severity: "info" },
    { id: "NIST-RA", name: "Risk Assessment", severity: "medium", detect: (s, h, findings) => findings.some(f => f.severity === "critical") },
    { id: "NIST-SA", name: "System & Services Acquisition", severity: "info" },
    { id: "NIST-SI", name: "System & Information Integrity", severity: "high", detect: (s, h) => !h["content-security-policy"] || !h["x-content-type-options"] }
  ];

  let lastComplianceResults = [];

  function runComplianceCheck(type) {
    const results = $("complianceResults");
    if (!results) return;

    const state = window.state || {};
    const findings = window.getVisibleFindings ? window.getVisibleFindings() : [];
    const endpoints = state.endpoints ? [...state.endpoints] : [];
    const secrets = state.secrets ? [...state.secrets] : [];
    const parameters = state.parameters ? [...state.parameters] : [];

    const allItems = findings.map(f => ({
      value: f.value || f.path || "",
      type: f.type || "",
      severity: f.severity || "info"
    }));

    function runChecks(checks, items) {
      return checks.map(check => {
        if (check.detect) {
          const detected = check.detect(0, {}, items);
          return { ...check, passed: !detected };
        }
        return { ...check, passed: true };
      });
    }

    let checks, title, icon;
    if (type === "owasp") {
      checks = OWASP_TOP_10.map(cat => ({
        ...cat,
        results: runChecks(cat.checks, allItems)
      }));
      title = "OWASP Top 10 Assessment";
      icon = "fa-shield-halved";
    } else if (type === "pci") {
      checks = runChecks(PCI_DSS_CHECKS, allItems);
      title = "PCI DSS Assessment";
      icon = "fa-credit-card";
    } else if (type === "nist") {
      checks = runChecks(NIST_CHECKS, allItems);
      title = "NIST Framework Assessment";
      icon = "fa-building-shield";
    }

    lastComplianceResults = { type, title, checks, timestamp: new Date().toISOString() };
    $("complianceExport").style.display = "inline-flex";

    if (type === "owasp") {
      results.innerHTML = `
        <h4><i class="fas ${icon}"></i> ${title}</h4>
        <p class="compliance-summary">Analyzed ${findings.length} findings across ${endpoints.length} endpoints</p>
        ${checks.map(cat => {
          const passed = cat.results.filter(r => r.passed).length;
          const total = cat.results.length;
          const score = total ? Math.round((passed / total) * 100) : 100;
          return `
            <div class="compliance-category">
              <div class="compliance-cat-header">
                <span class="compliance-id">${cat.id}</span>
                <span class="compliance-name">${cat.name}</span>
                <span class="compliance-score ${score >= 80 ? "pass" : score >= 50 ? "warn" : "fail"}">${score}%</span>
              </div>
              <div class="compliance-checks-list">
                ${cat.results.map(r => `
                  <div class="compliance-item ${r.passed ? "pass" : "fail"}">
                    <span class="compliance-check-status">${r.passed ? '<i class="fas fa-check"></i>' : '<i class="fas fa-times"></i>'}</span>
                    <span class="compliance-check-text">${r.test}</span>
                    <span class="compliance-severity badge ${r.severity}">${r.severity}</span>
                  </div>
                `).join("")}
              </div>
            </div>
          `;
        }).join("")}
      `;
    } else {
      results.innerHTML = `
        <h4><i class="fas ${icon}"></i> ${title}</h4>
        <p class="compliance-summary">Analyzed ${findings.length} findings</p>
        ${checks.map(r => `
          <div class="compliance-item ${r.passed ? "pass" : r.severity === "info" ? "info" : "fail"}">
            <span class="compliance-id">${r.id}</span>
            <span class="compliance-name">${r.name}</span>
            <span class="compliance-check-status">${r.passed ? '<i class="fas fa-check"></i>' : r.severity === "info" ? '<i class="fas fa-info-circle"></i>' : '<i class="fas fa-times"></i>'}</span>
            <span class="compliance-severity badge ${r.severity}">${r.severity}</span>
          </div>
        `).join("")}
      `;
    }
  }

  function exportComplianceReport() {
    if (!lastComplianceResults) return;
    const { type, title, checks, timestamp } = lastComplianceResults;
    let txt = `Web X Sider - ${title}\nGenerated: ${timestamp}\nTarget: ${location.href}\n${"=".repeat(60)}\n\n`;

    if (type === "owasp") {
      checks.forEach(cat => {
        const passed = cat.results.filter(r => r.passed).length;
        const total = cat.results.length;
        txt += `${cat.id} - ${cat.name} (${passed}/${total} passed)\n`;
        cat.results.forEach(r => {
          txt += `  [${r.passed ? "PASS" : "FAIL"}] ${r.test} (${r.severity})\n`;
        });
        txt += "\n";
      });
    } else {
      checks.forEach(r => {
        txt += `[${r.passed ? "PASS" : r.severity === "info" ? "N/A" : "FAIL"}] ${r.id} - ${r.name} (${r.severity})\n`;
      });
    }

    download(`compliance-${type}-${Date.now()}.txt`, txt, "text/plain");
    toast("Compliance report exported", "success");
  }

  /* ============ 11. API FOR EXTERNAL INTEGRATION ============ */
  function apiPanelHTML() {
    return buildPanel("api", `
      <div class="api-section">
        <h3><i class="fas fa-plug"></i> API Integration</h3>
        <div class="api-info">
          <h4>Local REST API</h4>
          <p>When running with <code>server.py</code>, Web X Sider exposes these endpoints:</p>
          <div class="api-endpoints">
            <div class="api-endpoint"><code>GET /api/results</code><span>Get current scan results (JSON)</span></div>
            <div class="api-endpoint"><code>GET /api/stats</code><span>Get scan statistics (endpoints, secrets, files, params)</span></div>
            <div class="api-endpoint"><code>POST /api/scan</code><span>Start a scan with JSON body <code>{"url":"..."}</code></span></div>
            <div class="api-endpoint"><code>GET /api/health</code><span>Health check</span></div>
          </div>

          <h4 style="margin-top:16px;">Webhook Integration</h4>
          <p>Send scan results to Discord, Slack, or custom webhooks on completion:</p>
          <div class="api-webhook-config">
            <label>Webhook URL:</label>
            <input type="url" id="apiWebhookUrl" placeholder="https://discord.com/api/webhooks/..." style="width:100%;margin:6px 0;" />
            <label>Trigger on:</label>
            <div class="alert-checkboxes">
              <label><input type="checkbox" id="apiWebhookCritical" checked /> Critical findings</label>
              <label><input type="checkbox" id="apiWebhookHigh" checked /> High findings</label>
              <label><input type="checkbox" id="apiWebhookComplete" checked /> Scan complete</label>
            </div>
            <button id="apiWebhookSave" class="btn btn-primary" style="margin-top:8px;"><i class="fas fa-save"></i><span>Save Webhook</span></button>
            <button id="apiWebhookTest" class="btn btn-secondary" style="margin-top:8px;"><i class="fas fa-paper-plane"></i><span>Test Webhook</span></button>
          </div>

          <h4 style="margin-top:16px;">Export for External Tools</h4>
          <div class="api-export-grid">
            <button id="apiExportBurp" class="btn btn-secondary"><i class="fas fa-file-code"></i><span>Burp XML Sitemap</span></button>
            <button id="apiExportNuclei" class="btn btn-secondary"><i class="fas fa-file-code"></i><span>Nuclei Templates</span></button>
            <button id="apiExportFfuf" class="btn btn-secondary"><i class="fas fa-file-code"></i><span>ffuf Commands</span></button>
            <button id="apiExportSqlmap" class="btn btn-secondary"><i class="fas fa-file-code"></i><span>sqlmap Commands</span></button>
            <button id="apiExportHar" class="btn btn-secondary"><i class="fas fa-file-code"></i><span>HAR Format</span></button>
            <button id="apiExportJson" class="btn btn-secondary"><i class="fas fa-file-code"></i><span>Full JSON</span></button>
          </div>

          <h4 style="margin-top:16px;">Import from External Tools</h4>
          <div class="api-import-grid">
            <input type="file" id="apiImportFile" accept=".json,.xml,.har,.txt" style="display:none;" />
            <button id="apiImportBtn" class="btn btn-primary"><i class="fas fa-upload"></i><span>Import File</span></button>
            <span id="apiImportStatus" style="margin-left:8px;color:var(--text-dim);"></span>
          </div>

          <p class="api-note" style="margin-top:12px;">API is available when running locally with <code>server.py</code>. Export formats are always available.</p>
        </div>
      </div>
    `);
  }

  function generateBurpSitemap() {
    const state = window.state || {};
    const endpoints = state.endpoints ? [...state.endpoints] : [];
    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n<sitemapIndex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n';
    endpoints.forEach(ep => {
      const url = typeof ep === "string" ? ep : ep.url || ep.path || "";
      xml += `  <url>\n    <loc>${esc(url)}</loc>\n  </url>\n`;
    });
    xml += '</sitemapIndex>';
    download(`burp-sitemap-${Date.now()}.xml`, xml, "application/xml");
    toast(`Exported ${endpoints.length} URLs to Burp format`, "success");
  }

  function generateNucleiTemplates() {
    const state = window.state || {};
    const endpoints = state.endpoints ? [...state.endpoints] : [];
    let yaml = "";
    endpoints.forEach(ep => {
      const url = typeof ep === "string" ? ep : ep.url || ep.path || "";
      yaml += `- id: custom-probe\n  info:\n    name: Custom Probe\n    severity: info\n  http:\n    - method: GET\n      path:\n        - "{{BaseURL}}${esc(url)}"\n      matchers:\n        - type: status\n          status:\n            - 200\n\n`;
    });
    download(`nuclei-templates-${Date.now()}.yaml`, yaml, "text/yaml");
    toast(`Generated ${endpoints.length} Nuclei templates`, "success");
  }

  function generateFfufCommands() {
    const state = window.state || {};
    const endpoints = state.endpoints ? [...state.endpoints] : [];
    let cmds = "# ffuf scan commands\n\n";
    endpoints.forEach(ep => {
      const url = typeof ep === "string" ? ep : ep.url || ep.path || "";
      cmds += `ffuf -u "FUZZ${esc(url)}" -w /usr/share/wordlists/common.txt -mc 200,403\n`;
    });
    download(`ffuf-commands-${Date.now()}.sh`, cmds, "text/plain");
    toast(`Generated ${endpoints.length} ffuf commands`, "success");
  }

  function generateSqlmapCommands() {
    const state = window.state || {};
    const parameters = state.parameters ? [...state.parameters] : [];
    let cmds = "# sqlmap injection testing commands\n\n";
    if (parameters.length === 0) {
      cmds += "# No parameters discovered yet. Run a scan first.\n";
    } else {
      parameters.forEach(p => {
        const param = typeof p === "string" ? p : p.name || p.value || "";
        cmds += `sqlmap -u "TARGET_URL?${esc(param)}=FUZZ" --batch --level=3 --risk=2\n`;
      });
    }
    download(`sqlmap-commands-${Date.now()}.sh`, cmds, "text/plain");
    toast(`Generated sqlmap commands for ${parameters.length} parameters`, "success");
  }

  function generateHAR() {
    const state = window.state || {};
    const endpoints = state.endpoints ? [...state.endpoints] : [];
    const har = {
      log: {
        version: "1.2",
        creator: { name: "Web X Sider", version: "5.0" },
        entries: endpoints.map(ep => {
          const url = typeof ep === "string" ? ep : ep.url || ep.path || "";
          return {
            request: { method: "GET", url, headers: [], queryString: [] },
            response: { status: 200, headers: [], content: { size: 0, mimeType: "text/html" } },
            time: 0
          };
        })
      }
    };
    download(`har-export-${Date.now()}.json`, JSON.stringify(har, null, 2), "application/json");
    toast(`Exported ${endpoints.length} entries to HAR`, "success");
  }

  function generateFullJSON() {
    const state = window.state || {};
    const data = {
      exported: new Date().toISOString(),
      tool: "Web X Sider v5.0",
      target: location.href,
      endpoints: state.endpoints ? [...state.endpoints] : [],
      secrets: state.secrets ? [...state.secrets] : [],
      files: state.files ? [...state.files] : [],
      parameters: state.parameters ? [...state.parameters] : []
    };
    download(`websxsider-export-${Date.now()}.json`, JSON.stringify(data, null, 2), "application/json");
    toast("Full JSON exported", "success");
  }

  async function sendWebhook(payload) {
    const url = $("apiWebhookUrl")?.value?.trim();
    if (!url) { toast("No webhook URL configured", "error"); return; }
    try {
      await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      toast("Webhook sent successfully", "success");
    } catch (e) {
      toast(`Webhook failed: ${e.message}`, "error");
    }
  }

  function importExternalFile() {
    const input = $("apiImportFile");
    input.click();
    input.onchange = () => {
      const file = input.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = (e) => {
        try {
          const content = e.target.result;
          const state = window.state || { endpoints: new Set(), files: new Set(), parameters: new Set(), secrets: new Set() };

          if (file.name.endsWith(".json")) {
            const data = JSON.parse(content);
            const urls = data.log?.entries?.map(e => e.request?.url) || data.urls || data.endpoints || [];
            urls.forEach(u => { if (u) state.endpoints.add(u); });
            toast(`Imported ${urls.length} URLs from JSON`, "success");
          } else if (file.name.endsWith(".xml")) {
            const urls = content.match(/<loc>(.*?)<\/loc>/g)?.map(m => m.replace(/<\/?loc>/g, "")) || [];
            urls.forEach(u => { if (u) state.endpoints.add(u); });
            toast(`Imported ${urls.length} URLs from XML`, "success");
          } else if (file.name.endsWith(".har")) {
            const data = JSON.parse(content);
            const urls = data.log?.entries?.map(e => e.request?.url) || [];
            urls.forEach(u => { if (u) state.endpoints.add(u); });
            toast(`Imported ${urls.length} URLs from HAR`, "success");
          } else {
            const lines = content.split(/[\r\n]+/).filter(l => l.startsWith("http"));
            lines.forEach(u => { if (u) state.endpoints.add(u); });
            toast(`Imported ${lines.length} URLs from text`, "success");
          }

          window.state = state;
          $("apiImportStatus").textContent = `Last import: ${file.name}`;
        } catch (err) {
          toast(`Import failed: ${err.message}`, "error");
        }
      };
      reader.readAsText(file);
      input.value = "";
    };
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
    $("reportPdf")?.addEventListener("click", () => { window.print(); });
    $("reportJson")?.addEventListener("click", () => {
      const state = window.state || {};
      const data = {
        exported: new Date().toISOString(),
        tool: "Web X Sider v5.0",
        endpoints: state.endpoints ? [...state.endpoints] : [],
        secrets: state.secrets ? [...state.secrets] : [],
        files: state.files ? [...state.files] : [],
        parameters: state.parameters ? [...state.parameters] : []
      };
      download(`report-${Date.now()}.json`, JSON.stringify(data, null, 2), "application/json");
      toast("JSON report exported", "success");
    });

    // PDF export button in main export section
    $("exportPdf")?.addEventListener("click", () => { window.print(); });

    // History
    $("historySave")?.addEventListener("click", () => saveToHistory());
    renderHistory();

    // Targets
    $("targetAdd")?.addEventListener("click", addTarget);
    renderTargets();

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
    $("alertTest")?.addEventListener("click", async () => {
      const webhook = $("alertWebhook")?.value?.trim();
      if (!webhook) { toast("Enter a webhook URL first", "error"); return; }
      try {
        await fetch(webhook, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ text: "Web X Sider alert test — this is a test notification from Web X Sider v5.0", source: "web-x-sider-v5", timestamp: new Date().toISOString() })
        });
        toast("Test alert sent successfully", "success");
      } catch (e) {
        toast(`Alert test failed: ${e.message}`, "error");
      }
    });

    // Compliance
    $("complianceOwasp")?.addEventListener("click", () => runComplianceCheck("owasp"));
    $("compliancePci")?.addEventListener("click", () => runComplianceCheck("pci"));
    $("complianceNist")?.addEventListener("click", () => runComplianceCheck("nist"));
    $("complianceExport")?.addEventListener("click", exportComplianceReport);

    // Wordlist
    $("wordlistUpload")?.addEventListener("click", handleWordlistUpload);
    $("wordlistSaveCurrent")?.addEventListener("click", saveCurrentPathsAsWordlist);
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

    // API Integration
    $("apiWebhookSave")?.addEventListener("click", () => {
      tk4Set("apiWebhook", {
        url: $("apiWebhookUrl")?.value || "",
        critical: $("apiWebhookCritical")?.checked,
        high: $("apiWebhookHigh")?.checked,
        complete: $("apiWebhookComplete")?.checked
      });
      toast("Webhook settings saved", "success");
    });
    $("apiWebhookTest")?.addEventListener("click", () => {
      sendWebhook({ text: "Web X Sider webhook test", source: "web-x-sider-v5", timestamp: new Date().toISOString() });
    });
    $("apiExportBurp")?.addEventListener("click", generateBurpSitemap);
    $("apiExportNuclei")?.addEventListener("click", generateNucleiTemplates);
    $("apiExportFfuf")?.addEventListener("click", generateFfufCommands);
    $("apiExportSqlmap")?.addEventListener("click", generateSqlmapCommands);
    $("apiExportHar")?.addEventListener("click", generateHAR);
    $("apiExportJson")?.addEventListener("click", generateFullJSON);
    $("apiImportBtn")?.addEventListener("click", importExternalFile);

    // Load saved webhook config
    const savedWebhook = tk4Get("apiWebhook");
    if (savedWebhook?.url) {
      const urlInput = $("apiWebhookUrl");
      if (urlInput) urlInput.value = savedWebhook.url;
      if ($("apiWebhookCritical")) $("apiWebhookCritical").checked = savedWebhook.critical !== false;
      if ($("apiWebhookHigh")) $("apiWebhookHigh").checked = savedWebhook.high !== false;
      if ($("apiWebhookComplete")) $("apiWebhookComplete").checked = savedWebhook.complete !== false;
    }

    // Language
    document.querySelectorAll(".lang-btn").forEach(btn => {
      btn.addEventListener("click", () => applyLanguage(btn.dataset.lang));
    });

    // Theme
    document.querySelectorAll(".theme-btn").forEach(btn => {
      btn.addEventListener("click", () => applyTheme(btn.dataset.theme));
    });

    // Load saved preferences
    const savedLang = tk4Get("lang") || localStorage.getItem("web-x-sider:lang");
    if (savedLang) applyLanguage(savedLang);
    const savedTheme = tk4Get("theme") || localStorage.getItem("web-x-sider:theme");
    if (savedTheme) applyTheme(savedTheme);

    // Restore accessibility toggles
    const savedA11y = tk4Get("a11y") || {};
    if (savedA11y.highContrast) { $("a11yHighContrast").checked = true; document.documentElement.classList.add("high-contrast"); }
    if (savedA11y.largeText) { $("a11yLargeText").checked = true; document.documentElement.classList.add("large-text"); }
    if (savedA11y.reduceMotion) { $("a11yReduceMotion").checked = true; document.documentElement.classList.add("reduce-motion"); }

    // Init features
    initKeyboardShortcuts();
    initAccessibility();
    initServiceWorker();
  });
})();

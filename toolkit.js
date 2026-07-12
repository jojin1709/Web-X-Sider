/* ============================================================
   Web X Sider — Bug Bounty Toolkit v1.0
   JS diff monitor, JWT lab, takeover scanner, CVE correlator,
   batch scanner, IDOR range tester, auth matrix, webhook alerts,
   visual snapshot diffing.
   Self-contained: reads globals from script.js (fetchTarget,
   escapeHtml, badge, codeValue, showToast, downloadFile,
   mapWithConcurrency, hashText, extractEndpointsWithLines,
   extractSecretsWithLines) but never modifies them.
   ============================================================ */
(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const esc = (v) => (window.escapeHtml ? window.escapeHtml(v) : String(v ?? ""));
  const badgeFn = (l, t) => (window.badge ? window.badge(l, t) : `<span>${esc(l)}</span>`);
  const codeFn = (v, o) => (window.codeValue ? window.codeValue(v, o) : `<code>${esc(String(v ?? ""))}</code>`);
  const toast = (m, t) => (window.showToast ? window.showToast(m, t) : console.log(m));
  const urlLineSafe = (url) => (window.urlLine ? window.urlLine(url) : `<div class="recon-code">${esc(url)}</div>`);
  const download = (name, content, type) => window.downloadFile(name, content, type);
  const concurrency = () => (window._REQUEST_CONCURRENCY || 5);

  async function fetchT(url, options) {
    return window.fetchTarget(url, options);
  }

  const TK_KEY = "web-x-sider:toolkit";
  function tkLoad() {
    try { return JSON.parse(localStorage.getItem(TK_KEY) || "{}"); } catch { return {}; }
  }
  function tkSave(data) {
    try { localStorage.setItem(TK_KEY, JSON.stringify(data)); } catch { /* quota */ }
  }
  function tkGet(section) { return tkLoad()[section] || {}; }
  function tkSet(section, value) { const d = tkLoad(); d[section] = value; tkSave(d); }

  function notify(title, body) {
    try {
      if (!("Notification" in window)) return;
      if (Notification.permission === "granted") new Notification(title, { body });
      else if (Notification.permission !== "denied") {
        Notification.requestPermission().then((p) => { if (p === "granted") new Notification(title, { body }); });
      }
    } catch { /* notifications unavailable */ }
  }

  /* ================= NAV WIRING ================= */
  function initNav() {
    const navToolkit = $("navToolkit");
    const toolkitSection = $("toolkit-section");
    if (!navToolkit || !toolkitSection) return;

    const otherSectionIds = ["crawler-section", "prober-section", "recon-section", "settings-panel"];
    const otherNavIds = ["navCrawler", "navProber", "navRecon", "navSettings"];

    navToolkit.addEventListener("click", () => {
      otherSectionIds.forEach((id) => { const el = $(id); if (el) el.style.display = "none"; });
      toolkitSection.style.display = "block";
      otherNavIds.forEach((id) => $(id)?.classList.remove("active"));
      navToolkit.classList.add("active");
    });

    otherNavIds.forEach((id) => {
      $(id)?.addEventListener("click", () => {
        toolkitSection.style.display = "none";
        navToolkit.classList.remove("active");
      });
    });

    const navToolkitMobile = $("navToolkitMobile");
    navToolkitMobile?.addEventListener("click", () => {
      navToolkit.click();
      document.querySelectorAll(".mobile-nav-link").forEach((el) => el.classList.remove("active"));
      navToolkitMobile.classList.add("active");
      $("mobileMenu")?.classList.remove("active");
      $("mobileMenuBtn")?.classList.remove("active");
    });
    document.querySelectorAll(".mobile-nav-link").forEach((el) => {
      if (el.id !== "navToolkitMobile") {
        el.addEventListener("click", () => {
          toolkitSection.style.display = "none";
          navToolkit.classList.remove("active");
        });
      }
    });

    document.querySelectorAll("#toolkit-tabs .tab-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        document.querySelectorAll("#toolkit-tabs .tab-btn").forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");
        const tab = btn.dataset.tkTab;
        document.querySelectorAll(".tk-panel").forEach((p) => {
          p.style.display = p.id === `tk-panel-${tab}` ? "block" : "none";
        });
      });
    });
  }

  /* ================= WEBHOOK ALERTS (shared by other tools) ================= */
  function webhookSettings() { return tkGet("webhook"); }
  function saveWebhookSettings(s) { tkSet("webhook", s); }

  async function sendWebhook(message) {
    const s = webhookSettings();
    if (!s.url) return false;
    try {
      const body = /discord/i.test(s.url)
        ? JSON.stringify({ content: message.slice(0, 1900) })
        : JSON.stringify({ text: message.slice(0, 1900), content: message.slice(0, 1900) });
      await fetchT(s.url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body
      });
      return true;
    } catch (e) {
      console.warn("Webhook send failed", e.message);
      return false;
    }
  }

  function maybeWebhook(message) {
    const s = webhookSettings();
    if (s.url && s.autoSend) sendWebhook(message);
  }

  function renderWebhookPanel() {
    const s = webhookSettings();
    if ($("tkWebhookUrl")) $("tkWebhookUrl").value = s.url || "";
    if ($("tkWebhookAuto")) $("tkWebhookAuto").checked = !!s.autoSend;
  }

  function initWebhookPanel() {
    renderWebhookPanel();
    $("tkWebhookSave")?.addEventListener("click", () => {
      saveWebhookSettings({
        url: $("tkWebhookUrl")?.value.trim() || "",
        autoSend: !!$("tkWebhookAuto")?.checked
      });
      toast("Webhook settings saved", "success");
    });
    $("tkWebhookTest")?.addEventListener("click", async () => {
      saveWebhookSettings({
        url: $("tkWebhookUrl")?.value.trim() || "",
        autoSend: !!$("tkWebhookAuto")?.checked
      });
      const ok = await sendWebhook("🕷️ Web X Sider — test alert. If you can see this, alerts are wired up correctly.");
      toast(ok ? "Test alert sent" : "Failed to send — check the URL", ok ? "success" : "error");
    });
    $("tkWebhookSendSummary")?.addEventListener("click", async () => {
      const st = window.state;
      if (!st) { toast("No scan data in memory yet", "warn"); return; }
      const critical = (st.allData || []).filter((i) => i.severity === "critical").length;
      const high = (st.allData || []).filter((i) => i.severity === "high").length;
      const msg = `📊 **Web X Sider scan summary**\nEndpoints: ${st.endpoints.size}\nSecrets: ${st.secrets.size}\nFiles: ${st.files.size}\nParameters: ${st.parameters.size}\nCritical findings: ${critical}\nHigh findings: ${high}`;
      const ok = await sendWebhook(msg);
      toast(ok ? "Summary sent" : "Failed to send — set a webhook URL first", ok ? "success" : "error");
    });
  }

  /* ================= 1. JS DIFF MONITOR ================= */
  function monitorAll() { return tkGet("monitor"); }
  function monitorSaveAll(m) { tkSet("monitor", m); }

  async function monitorFetchAndExtract(url) {
    const res = await fetchT(url);
    const body = await res.text();
    const hash = window.hashText ? window.hashText(body) : String(body.length);
    const endpoints = [...new Set((window.extractEndpointsWithLines ? window.extractEndpointsWithLines(body) : []).map((e) => e.value))];
    const secrets = [...new Set((window.extractSecretsWithLines ? window.extractSecretsWithLines(body) : []).map((e) => e.value))];
    return { hash, endpoints, secrets, length: body.length };
  }

  async function monitorAdd() {
    const raw = $("tkMonitorInput")?.value || "";
    const urls = raw.split("\n").map((l) => l.trim()).filter(Boolean);
    if (!urls.length) { toast("Paste at least one URL to watch", "warn"); return; }
    const store = monitorAll();
    for (const url of urls) {
      try {
        const data = await monitorFetchAndExtract(url);
        store[url] = { ...data, lastChecked: new Date().toISOString(), addedAt: store[url]?.addedAt || new Date().toISOString(), changed: false, newEndpoints: [], newSecrets: [] };
      } catch (e) {
        toast(`Failed to add ${url}: ${e.message}`, "error");
      }
    }
    monitorSaveAll(store);
    if ($("tkMonitorInput")) $("tkMonitorInput").value = "";
    renderMonitor();
    toast("Added to watchlist", "success");
  }

  async function monitorCheckAll() {
    const store = monitorAll();
    const urls = Object.keys(store);
    if (!urls.length) { toast("Watchlist is empty", "warn"); return; }
    toast(`Checking ${urls.length} watched file(s)...`, "info");
    await window.mapWithConcurrency(urls, concurrency(), async (url) => {
      const prev = store[url];
      try {
        const data = await monitorFetchAndExtract(url);
        const changed = data.hash !== prev.hash;
        const newEndpoints = changed ? data.endpoints.filter((e) => !(prev.endpoints || []).includes(e)) : [];
        const newSecrets = changed ? data.secrets.filter((s) => !(prev.secrets || []).includes(s)) : [];
        store[url] = { ...data, lastChecked: new Date().toISOString(), addedAt: prev.addedAt, changed, newEndpoints, newSecrets, error: null };
        if (changed) {
          notify(`Web X Sider: ${url} changed`, `${newEndpoints.length} new endpoint(s), ${newSecrets.length} new secret(s)`);
          maybeWebhook(`🔔 **JS change detected**\n${url}\nNew endpoints: ${newEndpoints.length}\nNew secrets: ${newSecrets.length}`);
        }
      } catch (e) {
        store[url] = { ...prev, lastChecked: new Date().toISOString(), error: e.message };
      }
    });
    monitorSaveAll(store);
    renderMonitor();
    toast("Check complete", "success");
  }

  function monitorRemove(url) {
    const store = monitorAll();
    delete store[url];
    monitorSaveAll(store);
    renderMonitor();
  }

  let monitorAutoTimer = null;
  function monitorToggleAuto(enabled) {
    if (monitorAutoTimer) { clearInterval(monitorAutoTimer); monitorAutoTimer = null; }
    if (enabled) {
      const minutes = Math.max(1, parseInt($("tkMonitorInterval")?.value, 10) || 15);
      monitorAutoTimer = setInterval(monitorCheckAll, minutes * 60 * 1000);
      toast(`Auto-check every ${minutes} min while this tab stays open`, "info");
    }
  }

  function renderMonitor() {
    const el = $("tkMonitorResults");
    if (!el) return;
    const store = monitorAll();
    const urls = Object.keys(store);
    if (!urls.length) { el.innerHTML = `<div class="field-status">No watched files yet. Add a JS or page URL above.</div>`; return; }
    el.innerHTML = urls.map((url) => {
      const item = store[url];
      const status = item.error ? badgeFn("error", "bad") : item.changed ? badgeFn("changed", "warn") : badgeFn("unchanged", "good");
      return `
        <div class="recon-list-item">
          <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;">
            ${urlLineSafe(url)}
            <button type="button" class="mini-action-btn tk-monitor-remove" data-url="${esc(url)}"><i class="fas fa-trash"></i></button>
          </div>
          <div>${status} <span class="recon-code">last checked ${item.lastChecked ? new Date(item.lastChecked).toLocaleString() : "never"}</span></div>
          ${item.error ? `<div>${codeFn(item.error, { limit: 200 })}</div>` : ""}
          ${item.changed && item.newEndpoints?.length ? `<div>${badgeFn(`${item.newEndpoints.length} new endpoint(s)`, "warn")}${item.newEndpoints.slice(0, 6).map((e) => codeFn(e, { limit: 110 })).join("")}</div>` : ""}
          ${item.changed && item.newSecrets?.length ? `<div>${badgeFn(`${item.newSecrets.length} new secret(s)`, "bad")}${item.newSecrets.slice(0, 6).map((e) => codeFn(e, { limit: 110 })).join("")}</div>` : ""}
        </div>`;
    }).join("");
    el.querySelectorAll(".tk-monitor-remove").forEach((btn) => btn.addEventListener("click", () => monitorRemove(btn.dataset.url)));
  }

  function initMonitorPanel() {
    $("tkMonitorAddBtn")?.addEventListener("click", monitorAdd);
    $("tkMonitorCheckBtn")?.addEventListener("click", monitorCheckAll);
    $("tkMonitorAutoToggle")?.addEventListener("change", (e) => monitorToggleAuto(e.target.checked));
    renderMonitor();
  }

  /* ================= 2. JWT LAB ================= */
  const JWT_COMMON_SECRETS = [
    "secret", "Secret", "SECRET", "secretkey", "secret_key", "your-256-bit-secret",
    "jwt_secret", "jwtsecret", "changeme", "password", "123456", "admin", "test",
    "key", "supersecret", "mysecretkey", "private", "development", "production",
    "local", "qwerty", "letmein", "topsecret", "jwtSecretKey", "auth_secret",
    "session_secret", "app_secret", "default", "0123456789", "abcdef", "shhh",
    "jwtkey", "signingkey", "hmacsecret", "your-secret-key", "webtoken", "s3cr3t"
  ];

  function b64urlToBytes(str) {
    const padded = str.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(str.length / 4) * 4, "=");
    const bin = atob(padded);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }
  function bytesToB64url(bytes) {
    let bin = "";
    bytes.forEach((b) => { bin += String.fromCharCode(b); });
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function strToB64url(str) { return bytesToB64url(new TextEncoder().encode(str)); }

  function jwtDecode(token) {
    const parts = token.trim().split(".");
    if (parts.length < 2) return null;
    try {
      const header = JSON.parse(new TextDecoder().decode(b64urlToBytes(parts[0])));
      const payload = JSON.parse(new TextDecoder().decode(b64urlToBytes(parts[1])));
      return { header, payload, signaturePart: parts[2] || "", raw: parts };
    } catch { return null; }
  }

  function jwtForgeAlgNone(decoded) {
    const header = { ...decoded.header, alg: "none" };
    const headerPart = strToB64url(JSON.stringify(header));
    const payloadPart = strToB64url(JSON.stringify(decoded.payload));
    return `${headerPart}.${payloadPart}.`;
  }

  async function jwtBruteSecret(token, decoded) {
    const alg = (decoded.header.alg || "").toUpperCase();
    if (!["HS256", "HS384", "HS512"].includes(alg)) {
      return { supported: false, alg };
    }
    const hashName = { HS256: "SHA-256", HS384: "SHA-384", HS512: "SHA-512" }[alg];
    const parts = token.trim().split(".");
    const signingInput = `${parts[0]}.${parts[1]}`;
    const targetSig = b64urlToBytes(parts[2] || "");
    for (const secret of JWT_COMMON_SECRETS) {
      try {
        const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: hashName }, false, ["sign"]);
        const sigBuf = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(signingInput));
        const sigBytes = new Uint8Array(sigBuf);
        if (sigBytes.length === targetSig.length && sigBytes.every((b, i) => b === targetSig[i])) {
          return { supported: true, alg, cracked: true, secret };
        }
      } catch { /* skip */ }
    }
    return { supported: true, alg, cracked: false, tried: JWT_COMMON_SECRETS.length };
  }

  function jwtExpiryNote(payload) {
    if (!payload.exp) return { tone: "warn", text: "No exp claim — token never expires" };
    const expMs = Number(payload.exp) * 1000;
    const now = Date.now();
    if (expMs < now) return { tone: "good", text: `Expired ${new Date(expMs).toLocaleString()}` };
    const days = (expMs - now) / 86400000;
    if (days > 365) return { tone: "warn", text: `Expires in ${Math.round(days)} days — excessively long-lived` };
    return { tone: "info", text: `Expires ${new Date(expMs).toLocaleString()}` };
  }

  async function jwtAnalyze() {
    const token = ($("tkJwtInput")?.value || "").trim();
    const out = $("tkJwtResults");
    if (!out) return;
    if (!token) { toast("Paste a JWT first", "warn"); return; }
    const decoded = jwtDecode(token);
    if (!decoded) { out.innerHTML = `<div class="field-status">Could not decode — not a valid JWT.</div>`; return; }

    out.innerHTML = `<div class="field-status"><i class="fas fa-spinner fa-spin"></i> Testing weak secrets against ${esc(decoded.header.alg || "?")}...</div>`;
    const brute = await jwtBruteSecret(token, decoded);
    const expiry = jwtExpiryNote(decoded.payload);
    const forged = jwtForgeAlgNone(decoded);

    tkSet("jwtLast", { token, forged });

    out.innerHTML = `
      <div class="recon-list-item">
        <div>${badgeFn(`alg ${decoded.header.alg || "unknown"}`, decoded.header.alg?.toLowerCase() === "none" ? "bad" : "info")} ${badgeFn(decoded.header.typ || "JWT", "info")}</div>
        <div style="margin-top:6px;"><strong>Header</strong> ${codeFn(JSON.stringify(decoded.header), { limit: 240 })}</div>
        <div><strong>Payload</strong> ${codeFn(JSON.stringify(decoded.payload), { limit: 400 })}</div>
        <div>${badgeFn(expiry.text, expiry.tone)}</div>
      </div>
      <div class="recon-list-item">
        <strong>Weak-secret brute force (HMAC)</strong><br/>
        ${!brute.supported ? badgeFn(`alg ${brute.alg} is asymmetric — cannot brute a shared secret client-side`, "info") :
          brute.cracked ? `${badgeFn("CRACKED", "bad")} secret = ${codeFn(brute.secret)}` :
          badgeFn(`no match against ${brute.tried} common secrets`, "good")}
      </div>
      <div class="recon-list-item">
        <strong>Forged alg:none token</strong><br/>
        ${codeFn(forged, { limit: 300 })}
        <div style="margin-top:6px;">
          <button type="button" class="mini-action-btn" id="tkJwtCopyForged"><i class="fas fa-copy"></i> Copy forged token</button>
        </div>
      </div>
      <div class="advanced-scan-field glass-input" style="margin-top:12px;">
        <label>Send forged token as Authorization: Bearer to a target URL</label>
        <input type="url" id="tkJwtTestUrl" placeholder="https://api.example.com/me" />
        <button type="button" class="mini-action-btn" id="tkJwtSendBtn" style="margin-top:6px;"><i class="fas fa-paper-plane"></i> Send test request</button>
        <div id="tkJwtSendResult" class="field-status"></div>
      </div>
    `;

    $("tkJwtCopyForged")?.addEventListener("click", () => {
      navigator.clipboard?.writeText(forged);
      toast("Forged token copied", "success");
    });
    $("tkJwtSendBtn")?.addEventListener("click", async () => {
      const url = $("tkJwtTestUrl")?.value.trim();
      const resultEl = $("tkJwtSendResult");
      if (!url) { toast("Enter a target URL", "warn"); return; }
      resultEl.innerText = "Sending...";
      try {
        const res = await fetchT(url, { headers: { Authorization: `Bearer ${forged}` } });
        const body = await res.text();
        resultEl.innerHTML = `${badgeFn(`HTTP ${res.status}`, res.status < 400 ? "warn" : "good")} <span class="recon-code">${esc(body.length)} bytes</span>`;
      } catch (e) {
        resultEl.innerText = `Failed: ${e.message}`;
      }
    });
  }

  function initJwtPanel() {
    $("tkJwtAnalyzeBtn")?.addEventListener("click", jwtAnalyze);
  }

  /* ================= 3. SUBDOMAIN TAKEOVER SCANNER ================= */
  const TK_TAKEOVER_FP = [
    { service: "GitHub Pages", cname: /github\.io$/i, body: /there isn't a github pages site here|404.*github pages/i },
    { service: "Heroku", cname: /herokuapp\.com$/i, body: /no such app/i },
    { service: "AWS S3", cname: /s3.*amazonaws\.com$/i, body: /nosuchbucket|the specified bucket does not exist/i },
    { service: "AWS CloudFront", cname: /cloudfront\.net$/i, body: /the request could not be satisfied|bad request/i },
    { service: "Azure / Cloudapp", cname: /(cloudapp\.net|azurewebsites\.net|trafficmanager\.net|azure-api\.net)$/i, body: /404 web site not found/i },
    { service: "Shopify", cname: /myshopify\.com$/i, body: /sorry, this shop is currently unavailable/i },
    { service: "Fastly", cname: /fastly\.net$/i, body: /fastly error: unknown domain/i },
    { service: "Ghost (Ghost.io)", cname: /ghost\.io$/i, body: /the thing you were looking for is no longer here/i },
    { service: "Pantheon", cname: /pantheonsite\.io$/i, body: /404 error unknown site/i },
    { service: "Tumblr", cname: /tumblr\.com$/i, body: /there's nothing here|whatever you were looking for doesn't currently exist/i },
    { service: "Zendesk", cname: /zendesk\.com$/i, body: /help center closed/i },
    { service: "Surge.sh", cname: /surge\.sh$/i, body: /project not found/i },
    { service: "Netlify", cname: /netlify\.app$/i, body: /not found - request id/i },
    { service: "Bitbucket", cname: /bitbucket\.io$/i, body: /repository not found/i },
    { service: "Cargo Collective", cname: /cargocollective\.com$/i, body: /404 not found/i },
    { service: "Desk.com", cname: /desk\.com$/i, body: /please try again or try desk\.com/i },
    { service: "Help Scout", cname: /helpscoutdocs\.com$/i, body: /no settings were found for this company/i },
    { service: "HatenaBlog", cname: /hatenablog\.com$/i, body: /404 blog is not found/i },
    { service: "Helpjuice", cname: /helpjuice\.com$/i, body: /we could not find what you're looking for/i },
    { service: "Intercom", cname: /intercom\.help$/i, body: /uh oh\. that page doesn't exist/i },
    { service: "JetBrains", cname: /myjetbrains\.com$/i, body: /is not a registered inCloud YouTrack/i },
    { service: "Kajabi", cname: /kajabi\.com$/i, body: /the site you were looking for couldn't be found/i },
    { service: "LaunchRock", cname: /launchrock\.com$/i, body: /it looks like you may have taken a wrong turn somewhere/i },
    { service: "Mashery", cname: /mashery\.com$/i, body: /error 404 page not found/i },
    { service: "Readme.io", cname: /readme\.io$/i, body: /project doesnt exist.*yet/i },
    { service: "Smartling", cname: /smartling\.com$/i, body: /smartling internationalization/i },
    { service: "Squarespace", cname: /squarespace\.com$/i, body: /no such account/i },
    { service: "Statuspage.io", cname: /statuspage\.io$/i, body: /you are being.*redirected|statuspage/i },
    { service: "Strikingly", cname: /strikinglydns\.com$/i, body: /but does not have a site here/i },
    { service: "Surveygizmo", cname: /surveygizmo\.com$/i, body: /this survey is no longer available/i },
    { service: "Tictail", cname: /tictail\.com$/i, body: /to connect your domain/i },
    { service: "Uptimerobot", cname: /uptimerobot\.com$/i, body: /page not found/i },
    { service: "UserVoice", cname: /uservoice\.com$/i, body: /this uservoice subdomain is currently available/i },
    { service: "Webflow", cname: /webflow\.io$/i, body: /the page you are looking for doesn't exist or has been moved/i },
    { service: "Wishpond", cname: /wishpond\.com$/i, body: /https:\/\/www\.wishpond\.com\/404/i },
    { service: "WordPress.com", cname: /wordpress\.com$/i, body: /do you want to register.*\.wordpress\.com/i },
    { service: "Unbounce", cname: /unbouncepages\.com$/i, body: /the requested url was not found on this server/i },
    { service: "Aftership", cname: /aftership\.com$/i, body: /oops.*page not found/i },
    { service: "Bigcartel", cname: /bigcartel\.com$/i, body: /oops! we couldn't find that page/i },
    { service: "Brightcove", cname: /brightcove\.com$/i, body: /error code: 404/i },
    { service: "Feedpress", cname: /feedpress\.me$/i, body: /the feed has not been found/i },
    { service: "Getresponse", cname: /gr8\.com$/i, body: /with this address/i },
    { service: "Gitbook", cname: /gitbook\.io$/i, body: /404.*page not found/i },
    { service: "Gemfury", cname: /furyns\.com$/i, body: /account not found/i },
    { service: "Kinsta", cname: /kinsta\.cloud$/i, body: /no site configured at this address/i },
    { service: "Ngrok", cname: /ngrok\.io$/i, body: /tunnel .*not found/i },
    { service: "Pingdom", cname: /pingdom\.com$/i, body: /404 not found/i },
    { service: "Simplebooklet", cname: /simplebooklet\.com$/i, body: /we can't find this simplebooklet/i },
    { service: "Teamwork", cname: /teamwork\.com$/i, body: /oops - we didn't find your site/i },
    { service: "Thinkific", cname: /thinkific\.com$/i, body: /you may have mistyped the address/i },
    { service: "Vercel / Now", cname: /vercel\.app$/i, body: /the deployment could not be found|404: not_found/i },
    { service: "Wufoo", cname: /wufoo\.com$/i, body: /the form you are looking for is unavailable/i },
    { service: "Anima", cname: /animaapp\.io$/i, body: /project not found/i },
    { service: "Cargo", cname: /cargo\.site$/i, body: /if you're moving your domain away from cargo/i },
    { service: "Digital Ocean", cname: /digitaloceanspaces\.com$/i, body: /nosuchbucket/i },
    { service: "Firebase", cname: /firebaseapp\.com$/i, body: /404.*page not found.*firebase/i },
    { service: "Flywheel", cname: /flywheelsites\.com$/i, body: /this site is registered with a\.i\. flywheel/i },
    { service: "Frontify", cname: /frontify\.com$/i, body: /page not found.*frontify/i },
    { service: "Hubspot", cname: /hubspot\.net$/i, body: /domain not configured/i },
    { service: "Ngrok Free", cname: /ngrok-free\.app$/i, body: /tunnel .*not found/i },
    { service: "Proposify", cname: /proposify\.biz$/i, body: /if you are trying to reach a client/i },
    { service: "Short.io", cname: /short\.io$/i, body: /link does not exist/i },
    { service: "Tilda", cname: /tilda\.ws$/i, body: /please renew your domain/i },
    { service: "Wix", cname: /wixdns\.net$/i, body: /connect this domain to wix/i },
    { service: "Instapage", cname: /pageserve\.co$/i, body: /this page could not be found/i },
    { service: "Landingi", cname: /landingi\.com$/i, body: /nie znaleziono strony|page not found/i },
    { service: "Fly.io", cname: /fly\.dev$/i, body: /404 not found/i },
    { service: "Render", cname: /onrender\.com$/i, body: /no such app/i }
  ];

  async function dohLookupCname(host) {
    const endpoints = [
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=CNAME`,
      `https://dns.google/resolve?name=${encodeURIComponent(host)}&type=CNAME`
    ];
    for (const ep of endpoints) {
      try {
        const res = await fetch(ep, { headers: { Accept: "application/dns-json" } });
        if (!res.ok) continue;
        const json = await res.json();
        const answers = (json.Answer || []).filter((a) => a.type === 5);
        if (answers.length) return answers[answers.length - 1].data.replace(/\.$/, "");
        if (json.Status === 3) return "__NXDOMAIN__";
      } catch { /* try next resolver */ }
    }
    return null;
  }

  async function takeoverCheckHost(host) {
    const cname = await dohLookupCname(host);
    let bodySample = "";
    let httpStatus = null;
    try {
      const url = host.startsWith("http") ? host : `https://${host}/`;
      const res = await fetchT(url);
      httpStatus = res.status;
      bodySample = await res.text();
    } catch { /* unreachable */ }

    const matches = TK_TAKEOVER_FP.filter((fp) => (cname && fp.cname.test(cname)) || fp.body.test(bodySample || ""));
    return { host, cname, httpStatus, matches, nxdomain: cname === "__NXDOMAIN__" };
  }

  async function takeoverScan() {
    const raw = $("tkTakeoverInput")?.value || "";
    const hosts = raw.split("\n").map((l) => l.trim().replace(/^https?:\/\//, "").replace(/\/.*$/, "")).filter(Boolean);
    const out = $("tkTakeoverResults");
    if (!hosts.length) { toast("Paste at least one hostname", "warn"); return; }
    out.innerHTML = `<div class="field-status"><i class="fas fa-spinner fa-spin"></i> Checking ${hosts.length} host(s)...</div>`;
    const results = await window.mapWithConcurrency(hosts, concurrency(), (h) => takeoverCheckHost(h).catch((e) => ({ host: h, error: e.message })));
    out.innerHTML = results.map((r) => {
      if (r.error) return `<div class="recon-list-item">${urlLineSafe(r.host)} ${badgeFn("error", "bad")} ${codeFn(r.error, { limit: 160 })}</div>`;
      const risky = r.matches.length > 0 || r.nxdomain;
      return `
        <div class="recon-list-item">
          ${urlLineSafe(r.host)}
          <div>
            ${r.cname && r.cname !== "__NXDOMAIN__" ? badgeFn(`CNAME ${r.cname}`, "info") : ""}
            ${r.nxdomain ? badgeFn("CNAME resolves to NXDOMAIN — dangling record", "bad") : ""}
            ${r.httpStatus ? badgeFn(`HTTP ${r.httpStatus}`, "info") : ""}
            ${r.matches.length ? r.matches.map((m) => badgeFn(`possible ${m.service} takeover`, "bad")).join("") : (risky ? "" : badgeFn("no fingerprint match", "good"))}
          </div>
        </div>`;
    }).join("");
    const findings = results.filter((r) => r.matches?.length || r.nxdomain);
    if (findings.length) maybeWebhook(`🏚️ **Possible subdomain takeover(s)**: ${findings.map((f) => f.host).join(", ")}`);
    toast("Takeover scan complete", "success");
  }

  function initTakeoverPanel() {
    $("tkTakeoverBtn")?.addEventListener("click", takeoverScan);
  }

  /* ================= 4. CVE / TECH CORRELATOR ================= */
  const TK_CVE_DB = [
    { match: /wordpress[\s/]*[4-5]\.[0-7]\b/i, cve: "CVE-2022-21661", desc: "WordPress core SQLi via WP_Query" },
    { match: /jquery[\s/]*[1-2]\.\d/i, cve: "CVE-2020-11022/11023", desc: "jQuery <3.5.0 XSS via html()/htmlPrefilter" },
    { match: /jquery[\s/]*3\.[0-4]\./i, cve: "CVE-2020-11023", desc: "jQuery <3.5.0 XSS via <option> attribute" },
    { match: /drupal[\s/]*7\./i, cve: "CVE-2018-7600 (Drupalgeddon2)", desc: "Drupal 7/8 RCE via render API" },
    { match: /drupal[\s/]*8\.[0-4]\./i, cve: "CVE-2019-6340", desc: "Drupal 8 REST module RCE" },
    { match: /apache[\s/]*2\.4\.(4[0-9]|[0-3][0-9])\b/i, cve: "CVE-2021-41773 / CVE-2021-42013", desc: "Apache 2.4.49/50 path traversal & RCE" },
    { match: /nginx[\s/]*1\.(1[0-6]|[0-9])\./i, cve: "CVE-2019-9511/9513", desc: "nginx HTTP/2 DoS family" },
    { match: /php[\s/]*[5-7]\.[0-3]\b/i, cve: "Multiple EOL CVEs", desc: "EOL PHP branch, no security patches" },
    { match: /openssl[\s/]*1\.0\.1[a-f]?\b/i, cve: "CVE-2014-0160 (Heartbleed)", desc: "OpenSSL Heartbleed memory disclosure" },
    { match: /struts[\s/]*2\.[0-4]\./i, cve: "CVE-2017-5638", desc: "Apache Struts2 Jakarta Multipart RCE" },
    { match: /log4j[\s/]*2\.(0|1[0-6])\b/i, cve: "CVE-2021-44228 (Log4Shell)", desc: "Log4j JNDI lookup RCE" },
    { match: /spring[\s/-]*(framework)?[\s/]*5\.[0-3]\b/i, cve: "CVE-2022-22965 (Spring4Shell)", desc: "Spring MVC/WebFlux RCE via data binding" },
    { match: /exchange.*20(13|16|19)/i, cve: "CVE-2021-34473/34523/31207 (ProxyShell)", desc: "Exchange Server RCE chain" },
    { match: /gitlab[\s/]*1[3-5]\./i, cve: "CVE-2021-22205", desc: "GitLab ExifTool RCE via image upload" },
    { match: /jenkins[\s/]*2\.[0-2]\d\d\b/i, cve: "CVE-2018-1000861", desc: "Jenkins Stapler RCE" },
    { match: /phpmyadmin[\s/]*4\./i, cve: "CVE-2018-12613", desc: "phpMyAdmin LFI via preg_replace" },
    { match: /elasticsearch[\s/]*1\./i, cve: "CVE-2015-1427", desc: "Elasticsearch Groovy scripting RCE" },
    { match: /redis[\s/]*[1-4]\./i, cve: "Unauth Redis exposure", desc: "Older/unauthenticated Redis often RCE via module load or cron write" },
    { match: /confluence[\s/]*7\.[0-9]\.\d/i, cve: "CVE-2022-26134", desc: "Confluence OGNL injection RCE" },
    { match: /fortios[\s/]*[6-7]\.[0-2]\b/i, cve: "CVE-2022-40684", desc: "FortiOS auth bypass" },
    { match: /citrix.*(adc|gateway)/i, cve: "CVE-2019-19781 / CVE-2023-3519", desc: "Citrix ADC/Gateway RCE family" },
    { match: /moveit/i, cve: "CVE-2023-34362", desc: "MOVEit Transfer SQLi to RCE" },
    { match: /vcenter/i, cve: "CVE-2021-21985", desc: "vCenter Server RCE via vSAN plugin" },
    { match: /laravel[\s/]*[5-8]\./i, cve: "CVE-2021-3129", desc: "Laravel debug mode RCE via Ignition" },
    { match: /magento[\s/]*[12]\./i, cve: "Multiple (2.3.x/1.x EOL)", desc: "Magento EOL / known unauth RCE chains" },
    { match: /joomla[\s/]*3\.[0-4]\./i, cve: "CVE-2023-23752", desc: "Joomla improper access check to sensitive API" },
    { match: /iis[\s/]*[67]\./i, cve: "EOL IIS branch", desc: "Legacy IIS with known unpatched vulns" },
    { match: /openssh[\s/]*[1-7]\.\d/i, cve: "CVE-2018-15473", desc: "OpenSSH username enumeration" }
  ];

  function cveScanText(text) {
    return TK_CVE_DB.filter((entry) => entry.match.test(text));
  }

  async function cveRun() {
    const out = $("tkCveResults");
    const urlInput = $("tkCveUrl")?.value.trim();
    const textInput = $("tkCveText")?.value || "";
    let combined = textInput;
    if (urlInput) {
      out.innerHTML = `<div class="field-status"><i class="fas fa-spinner fa-spin"></i> Fetching ${esc(urlInput)}...</div>`;
      try {
        const res = await fetchT(urlInput);
        const body = await res.text();
        const server = res.headers.get("server") || "";
        const poweredBy = res.headers.get("x-powered-by") || "";
        const generator = (body.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i) || [])[1] || "";
        combined += ` ${server} ${poweredBy} ${generator}`;
      } catch (e) {
        toast(`Fetch failed: ${e.message}`, "error");
      }
    }
    if (!combined.trim()) { out.innerHTML = `<div class="field-status">Paste a tech string (e.g. "jQuery 1.8.3, Apache 2.4.29") or a URL to fetch.</div>`; return; }
    const hits = cveScanText(combined);
    out.innerHTML = `
      <div class="field-status">Scanned: ${codeFn(combined.trim(), { limit: 200 })}</div>
      ${hits.length
        ? hits.map((h) => `<div class="recon-list-item">${badgeFn(h.cve, "bad")} ${escHtmlSafe(h.desc)}<div><a href="https://nvd.nist.gov/vuln/search/results?query=${encodeURIComponent(h.cve.split(" ")[0])}" target="_blank" rel="noopener noreferrer">NVD lookup</a></div></div>`).join("")
        : `<div class="field-status">${badgeFn("no known-CVE version strings matched", "good")} — this is a curated high-signal list, not exhaustive. Always verify manually.</div>`}
    `;
  }
  function escHtmlSafe(v) { return esc(v); }

  function initCvePanel() {
    $("tkCveBtn")?.addEventListener("click", cveRun);
  }

  /* ================= 5. BATCH SCANNER ================= */
  const DEFAULT_BATCH_PATHS = ["/.env", "/.git/config", "/admin", "/api/docs", "/.well-known/security.txt", "/wp-login.php", "/server-status", "/.aws/credentials"];

  async function batchCheckHost(host, mode) {
    const base = host.startsWith("http") ? host : `https://${host}/`;
    const row = { host: base, status: null, title: "", server: "", takeover: null, paths: [] };
    try {
      const res = await fetchT(base);
      const body = await res.text();
      row.status = res.status;
      row.title = (body.match(/<title>([^<]*)<\/title>/i) || [])[1]?.trim().slice(0, 80) || "";
      row.server = res.headers.get("server") || "";
      row.takeover = window.checkTakeover ? window.checkTakeover(body, res.status) : null;
    } catch (e) {
      row.error = e.message;
      return row;
    }
    if (mode === "prober") {
      await window.mapWithConcurrency(DEFAULT_BATCH_PATHS, concurrency(), async (p) => {
        try {
          const url = new URL(p, base).href;
          const res = await fetchT(url);
          if (res.status !== 404) row.paths.push({ path: p, status: res.status });
        } catch { /* skip */ }
      });
    }
    return row;
  }

  let batchRows = [];
  async function batchRun() {
    const raw = $("tkBatchInput")?.value || "";
    const hosts = raw.split("\n").map((l) => l.trim()).filter(Boolean);
    const mode = $("tkBatchMode")?.value || "quick";
    const out = $("tkBatchResults");
    if (!hosts.length) { toast("Paste at least one host/URL", "warn"); return; }
    out.innerHTML = `<div class="field-status"><i class="fas fa-spinner fa-spin"></i> Scanning ${hosts.length} target(s) in ${mode} mode...</div>`;
    batchRows = await window.mapWithConcurrency(hosts, concurrency(), (h) => batchCheckHost(h, mode));
    renderBatch();
    toast("Batch scan complete", "success");
  }

  function renderBatch() {
    const out = $("tkBatchResults");
    if (!out) return;
    out.innerHTML = batchRows.map((r) => `
      <div class="recon-list-item">
        ${urlLineSafe(r.host)}
        <div>
          ${r.error ? badgeFn("error", "bad") + " " + codeFn(r.error, { limit: 140 }) : ""}
          ${r.status ? badgeFn(`HTTP ${r.status}`, r.status < 400 ? "good" : "warn") : ""}
          ${r.server ? badgeFn(r.server, "info") : ""}
          ${r.title ? codeFn(r.title, { limit: 100 }) : ""}
          ${r.takeover ? badgeFn(`possible ${r.takeover} takeover`, "bad") : ""}
        </div>
        ${r.paths?.length ? `<div>${r.paths.map((p) => badgeFn(`${p.path} → ${p.status}`, "warn")).join("")}</div>` : ""}
      </div>
    `).join("");
  }

  function batchExportCsv() {
    if (!batchRows.length) { toast("Run a batch scan first", "warn"); return; }
    const csv = "Host,Status,Server,Title,Takeover,InterestingPaths\n" + batchRows.map((r) =>
      `"${r.host}",${r.status || ""},"${(r.server || "").replace(/"/g, '""')}","${(r.title || "").replace(/"/g, '""')}","${r.takeover || ""}","${(r.paths || []).map((p) => `${p.path}:${p.status}`).join("; ")}"`
    ).join("\n");
    download("web-x-sider-batch.csv", csv, "text/csv");
  }

  function initBatchPanel() {
    $("tkBatchBtn")?.addEventListener("click", batchRun);
    $("tkBatchExportBtn")?.addEventListener("click", batchExportCsv);
  }

  /* ================= 6. IDOR / RANGE TESTER ================= */
  let idorRows = [];
  async function idorRun() {
    const template = $("tkIdorTemplate")?.value.trim();
    const start = parseInt($("tkIdorStart")?.value, 10);
    const end = parseInt($("tkIdorEnd")?.value, 10);
    const step = Math.max(1, parseInt($("tkIdorStep")?.value, 10) || 1);
    const out = $("tkIdorResults");
    if (!template || !template.includes("{id}")) { toast("URL template must contain {id}", "warn"); return; }
    if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) { toast("Set a valid ID range", "warn"); return; }
    const ids = [];
    for (let i = start; i <= end; i += step) ids.push(i);
    if (ids.length > 300) { toast("Range too large — max 300 IDs per run", "warn"); return; }
    out.innerHTML = `<div class="field-status"><i class="fas fa-spinner fa-spin"></i> Testing ${ids.length} ID(s)...</div>`;
    idorRows = await window.mapWithConcurrency(ids, concurrency(), async (id) => {
      const url = template.replace(/\{id\}/g, id);
      try {
        const res = await fetchT(url);
        const body = await res.text();
        return { id, url, status: res.status, length: body.length, sig: `${res.status}:${body.length}` };
      } catch (e) {
        return { id, url, error: e.message, sig: "error" };
      }
    });
    const sigCounts = {};
    idorRows.forEach((r) => { sigCounts[r.sig] = (sigCounts[r.sig] || 0) + 1; });
    const majoritySig = Object.entries(sigCounts).sort((a, b) => b[1] - a[1])[0]?.[0];
    out.innerHTML = idorRows.map((r) => {
      const anomaly = r.sig !== majoritySig && r.sig !== "error";
      return `<div class="recon-list-item">
        ${anomaly ? badgeFn(`ID ${r.id} — anomalous response`, "bad") : badgeFn(`ID ${r.id}`, "info")}
        ${r.error ? codeFn(r.error, { limit: 120 }) : `${badgeFn(`HTTP ${r.status}`, "info")} <span class="recon-code">${r.length} bytes</span>`}
      </div>`;
    }).join("");
    const anomalies = idorRows.filter((r) => r.sig !== majoritySig && r.sig !== "error");
    if (anomalies.length) toast(`${anomalies.length} anomalous response(s) found — review manually`, "warn");
    else toast("All responses share the same signature — no obvious IDOR from status/length alone", "info");
  }

  function idorExportCsv() {
    if (!idorRows.length) { toast("Run a range test first", "warn"); return; }
    const csv = "ID,URL,Status,Length,Error\n" + idorRows.map((r) => `${r.id},"${r.url}",${r.status || ""},${r.length || ""},"${(r.error || "").replace(/"/g, '""')}"`).join("\n");
    download("web-x-sider-idor.csv", csv, "text/csv");
  }

  function initIdorPanel() {
    $("tkIdorBtn")?.addEventListener("click", idorRun);
    $("tkIdorExportBtn")?.addEventListener("click", idorExportCsv);
  }

  /* ================= 7. AUTH MATRIX TESTER ================= */
  function parseAuthRoles(raw) {
    return raw.split("\n").map((line) => line.trim()).filter(Boolean).map((line) => {
      const [name, ...rest] = line.split("|").map((p) => p.trim());
      const headers = {};
      rest.forEach((h) => {
        const idx = h.indexOf(":");
        if (idx > -1) headers[h.slice(0, idx).trim()] = h.slice(idx + 1).trim();
      });
      return { name: name || "Unnamed", headers };
    });
  }

  let authRows = [];
  async function authMatrixRun() {
    const url = $("tkAuthUrl")?.value.trim();
    const rolesRaw = $("tkAuthRoles")?.value || "";
    const out = $("tkAuthResults");
    if (!url) { toast("Enter a target URL", "warn"); return; }
    const roles = parseAuthRoles(rolesRaw);
    if (!roles.length) { toast("Add at least one role line (Name | Header: Value)", "warn"); return; }
    out.innerHTML = `<div class="field-status"><i class="fas fa-spinner fa-spin"></i> Testing ${roles.length} role(s)...</div>`;
    authRows = await window.mapWithConcurrency(roles, concurrency(), async (role) => {
      try {
        const res = await fetchT(url, { headers: role.headers });
        const body = await res.text();
        const hash = window.hashText ? window.hashText(body) : String(body.length);
        return { role: role.name, status: res.status, length: body.length, hash };
      } catch (e) {
        return { role: role.name, error: e.message };
      }
    });
    const byHash = {};
    authRows.forEach((r) => { if (r.hash) { byHash[r.hash] = byHash[r.hash] || []; byHash[r.hash].push(r.role); } });
    const collisions = Object.values(byHash).filter((group) => group.length > 1);
    out.innerHTML = authRows.map((r) => `
      <div class="recon-list-item">
        ${badgeFn(r.role, "info")}
        ${r.error ? codeFn(r.error, { limit: 120 }) : `${badgeFn(`HTTP ${r.status}`, "info")} <span class="recon-code">${r.length} bytes</span> <span class="recon-code">sig ${r.hash}</span>`}
      </div>
    `).join("") + (collisions.length ? `<div class="recon-list-item">${badgeFn("Identical responses across roles — check for authorization bypass", "bad")}<br/>${collisions.map((g) => g.join(" = ")).join("<br/>")}</div>` : `<div class="field-status">${badgeFn("all roles returned distinct responses", "good")}</div>`);
    if (collisions.length) maybeWebhook(`🔓 **Possible auth-order bug**: ${url}\n${collisions.map((g) => g.join(" = ")).join("\n")}`);
  }

  function initAuthMatrixPanel() {
    $("tkAuthBtn")?.addEventListener("click", authMatrixRun);
  }

  /* ================= 8. VISUAL SNAPSHOT ================= */
  function snapshotUrl(target, width) {
    return `https://s0.wp.com/mshots/v1/${encodeURIComponent(target)}?w=${width || 1200}`;
  }

  function snapshotAll() { return tkGet("snapshots"); }
  function snapshotSaveAll(s) { tkSet("snapshots", s); }

  function snapshotAdd() {
    const url = $("tkSnapshotInput")?.value.trim();
    if (!url) { toast("Enter a target URL", "warn"); return; }
    const store = snapshotAll();
    store[url] = { addedAt: new Date().toISOString(), lastImg: snapshotUrl(url) + `&t=${Date.now()}` };
    snapshotSaveAll(store);
    renderSnapshots();
    toast("Snapshot captured — mshots renders async, refresh in ~10s if blank", "info");
  }

  function snapshotRefresh(url) {
    const store = snapshotAll();
    if (!store[url]) return;
    store[url].lastImg = snapshotUrl(url) + `&t=${Date.now()}`;
    store[url].lastChecked = new Date().toISOString();
    snapshotSaveAll(store);
    renderSnapshots();
  }

  function snapshotRemove(url) {
    const store = snapshotAll();
    delete store[url];
    snapshotSaveAll(store);
    renderSnapshots();
  }

  function renderSnapshots() {
    const out = $("tkSnapshotResults");
    if (!out) return;
    const store = snapshotAll();
    const urls = Object.keys(store);
    if (!urls.length) { out.innerHTML = `<div class="field-status">No snapshots yet. Uses WordPress's free mshots service — no API key needed.</div>`; return; }
    out.innerHTML = urls.map((url) => `
      <div class="recon-list-item">
        ${urlLineSafe(url)}
        <div><img src="${esc(store[url].lastImg)}" alt="snapshot" style="max-width:100%;border-radius:8px;margin-top:6px;border:1px solid rgba(255,255,255,0.12);" /></div>
        <div style="margin-top:6px;display:flex;gap:6px;">
          <button type="button" class="mini-action-btn tk-snap-refresh" data-url="${esc(url)}"><i class="fas fa-rotate"></i> Re-capture</button>
          <button type="button" class="mini-action-btn tk-snap-remove" data-url="${esc(url)}"><i class="fas fa-trash"></i></button>
        </div>
      </div>
    `).join("");
    out.querySelectorAll(".tk-snap-refresh").forEach((b) => b.addEventListener("click", () => snapshotRefresh(b.dataset.url)));
    out.querySelectorAll(".tk-snap-remove").forEach((b) => b.addEventListener("click", () => snapshotRemove(b.dataset.url)));
  }

  function initSnapshotPanel() {
    $("tkSnapshotAddBtn")?.addEventListener("click", snapshotAdd);
    renderSnapshots();
  }

  /* ================= PDF EXPORT (existing export section) ================= */
  function exportPdf() {
    const st = window.state;
    if (!st || !window.getVisibleFindings) { toast("No scan data to export yet", "warn"); return; }
    const findings = window.getVisibleFindings();
    const rows = findings.map((f) => `<tr><td>${esc((f.severity || "low").toUpperCase())}</td><td>${esc(f.type)}</td><td>${esc(f.value)}</td><td>${esc(f.source)}</td><td>${esc(f.line ?? "")}</td></tr>`).join("");
    const win = window.open("", "_blank");
    if (!win) { toast("Popup blocked — allow popups to export PDF", "error"); return; }
    win.document.write(`
      <html><head><title>Web X Sider Report</title>
      <style>
        body{font-family:Arial,sans-serif;padding:24px;color:#111;}
        h1{margin-bottom:0;} p{color:#555;margin-top:4px;}
        table{width:100%;border-collapse:collapse;margin-top:16px;font-size:12px;}
        th,td{border:1px solid #ccc;padding:6px 8px;text-align:left;word-break:break-all;}
        th{background:#eee;}
      </style></head><body>
      <h1>Web X Sider — Scan Report</h1>
      <p>Generated ${new Date().toLocaleString()} · Endpoints: ${st.endpoints.size} · Secrets: ${st.secrets.size} · Files: ${st.files.size} · Parameters: ${st.parameters.size}</p>
      <table><thead><tr><th>Severity</th><th>Type</th><th>Value</th><th>Source</th><th>Line</th></tr></thead><tbody>${rows}</tbody></table>
      <script>window.onload = () => window.print();<\/script>
      </body></html>
    `);
    win.document.close();
  }

  function initPdfExport() {
    $("exportPdf")?.addEventListener("click", exportPdf);
  }

  /* ================= INIT ================= */
  document.addEventListener("DOMContentLoaded", () => {
    initNav();
    initMonitorPanel();
    initJwtPanel();
    initTakeoverPanel();
    initCvePanel();
    initBatchPanel();
    initIdorPanel();
    initAuthMatrixPanel();
    initWebhookPanel();
    initSnapshotPanel();
    initPdfExport();
  });
})();

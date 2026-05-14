function showToast(message, type = "info", duration = 4000) {
  const container = document.getElementById("toast-container");
  if (!container) { console.log(message); return; }
  const colors = { info: "#0dcaf0", warn: "#ffc107", error: "#dc3545", success: "#28a745" };
  const toast = document.createElement("div");
  toast.style.cssText = `background:#1a1a2e;border:1px solid ${colors[type] || colors.info};border-radius:8px;padding:12px 16px;color:#fff;font-size:13px;max-width:360px;pointer-events:auto;box-shadow:0 4px 20px rgba(0,0,0,0.4);line-height:1.4;`;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transition = "opacity 0.3s";
    setTimeout(() => toast.remove(), 300);
  }, duration);
}

function showPrompt(title, defaultValue = "", placeholder = "") {
  return new Promise(resolve => {
    const overlay = document.getElementById("modal-overlay");
    const titleEl = document.getElementById("modal-title");
    const inputEl = document.getElementById("modal-input");
    const msgEl = document.getElementById("modal-message");
    const confirmBtn = document.getElementById("modal-confirm");
    const cancelBtn = document.getElementById("modal-cancel");
    if (!overlay || !titleEl || !inputEl || !msgEl || !confirmBtn || !cancelBtn) {
      console.warn("Prompt modal is unavailable:", title);
      resolve(null);
      return;
    }
    titleEl.textContent = title;
    inputEl.style.display = "block";
    inputEl.value = defaultValue;
    inputEl.placeholder = placeholder || "";
    msgEl.textContent = "";
    overlay.style.display = "flex";
    inputEl.focus();
    const cleanup = (value) => {
      overlay.style.display = "none";
      inputEl.style.display = "none";
      confirmBtn.onclick = null;
      cancelBtn.onclick = null;
      inputEl.onkeydown = null;
      resolve(value);
    };
    confirmBtn.onclick = () => cleanup(inputEl.value.trim() || null);
    cancelBtn.onclick = () => cleanup(null);
    inputEl.onkeydown = (e) => {
      if (e.key === "Enter") cleanup(inputEl.value.trim() || null);
      if (e.key === "Escape") cleanup(null);
    };
  });
}

function showConfirm(message) {
  return new Promise(resolve => {
    const overlay = document.getElementById("modal-overlay");
    const titleEl = document.getElementById("modal-title");
    const msgEl = document.getElementById("modal-message");
    const inputEl = document.getElementById("modal-input");
    const confirmBtn = document.getElementById("modal-confirm");
    const cancelBtn = document.getElementById("modal-cancel");
    if (!overlay || !titleEl || !msgEl || !inputEl || !confirmBtn || !cancelBtn) {
      console.warn("Confirm modal is unavailable:", message);
      resolve(false);
      return;
    }
    titleEl.textContent = "Confirm";
    msgEl.textContent = message;
    inputEl.style.display = "none";
    overlay.style.display = "flex";
    const cleanup = (val) => {
      overlay.style.display = "none";
      confirmBtn.onclick = null;
      cancelBtn.onclick = null;
      resolve(val);
    };
    confirmBtn.onclick = () => cleanup(true);
    cancelBtn.onclick = () => cleanup(false);
  });
}

function safeLocalStorageSet(key, value) {
  try {
    localStorage.setItem(key, value);
    return true;
  } catch (e) {
    if (e.name === "QuotaExceededError" || e.code === 22) {
      showToast('Storage full. Use "Export Session" to save as JSON file instead.', "warn");
      return false;
    }
    console.error("localStorage error:", e);
    return false;
  }
}

const scanBtn = document.getElementById("scanBtn");
const urlInput = document.getElementById("urlInput");
const results = document.getElementById("results");
const status = document.getElementById("status");
const exportActions = document.getElementById("actions");
const exportTxt = document.getElementById("exportTxt");
const exportJson = document.getElementById("exportJson");
const scopeInput = document.getElementById("scopeInput");
const importedUrlInput = document.getElementById("importedUrlInput");
const priorityDashboard = document.getElementById("priority-dashboard");
const scopeStatus = document.getElementById("scopeStatus");
const importStatus = document.getElementById("importStatus");
const subdomainInput = document.getElementById("subdomainInput");
const subdomainStatus = document.getElementById("subdomainStatus");
const hostResultsSection = document.getElementById("host-results-section");
const workflowImportInput = document.getElementById("workflowImportInput");
const workflowImportFile = document.getElementById("workflowImportFile");
const workflowImportStatus = document.getElementById("workflowImportStatus");
const applyImportBtn = document.getElementById("applyImportBtn");
const clearImportBtn = document.getElementById("clearImportBtn");
const waybackFetchBtn = document.getElementById("waybackFetchBtn");

const allResults = [];
const scannedJs = new Set(); // avoid duplicate scans across sources
console.log("%c🕷️ Web X Sider V2.0 Initialized", "color: #0dcaf0; font-weight: bold; font-size: 1.2rem;");

const sensitivePaths = [
  // 🌐 Standard .well-known files
  '/.well-known/security.txt',
  '/.well-known/assetlinks.json',
  '/.well-known/apple-app-site-association',
  '/.well-known/openid-configuration',
  '/.well-known/oauth-authorization-server',
  '/.well-known/jwks.json',
  '/.well-known/jwks',
  '/.well-known/change-password',
  '/.well-known/dnt-policy.txt',
  '/.well-known/privacy-policy.txt',
  '/.well-known/terms-of-service.txt',
  '/.well-known/gpc.json',
  '/.well-known/webfinger',
  '/.well-known/ai-plugin.json',
  '/.well-known/csaf/provider-metadata.json',
  '/.well-known/nodeinfo',
  '/.well-known/trust.txt',
  '/.well-known/recovery',
  '/.well-known/host-meta',
  '/.well-known/apple-developer-merchantid-domain-association',
  '/.well-known/microsoft-identity-association.json',
  '/.well-known/pay',
  '/.well-known/acme-challenge',
  '/.well-known/smart-app-banner',
  '/.well-known/matrix/client',
  '/.well-known/matrix/server',
  '/.well-known/did.json',
  '/.well-known/stellar.toml',
  '/.well-known/mta-sts.txt',
  '/.well-known/bugbounty',
  '/.well-known/humans.txt',

  // 🧭 Common metadata & index files
  '/robots.txt',
  '/humans.txt',
  '/sitemap.xml',
  '/sitemap_index.xml',
  '/manifest.json',
  '/ads.txt',
  '/app-ads.txt',
  '/crossdomain.xml',
  '/security.txt',
  '/server-status',
  '/server-info',
  '/status',
  '/health',
  '/healthcheck',
  '/ping',
  '/ready',
  '/live',

  // 🗂️ Version Control & Source Code
  '/.git',
  '/.git/config',
  '/.git/HEAD',
  '/.git/index',
  '/.git/logs/HEAD',
  '/.gitignore',
  '/.gitconfig',
  '/.gitmodules',
  '/.git-credentials',
  '/.svn/entries',
  '/.svn/wc.db',
  '/.hg/requires',
  '/.bzr/branch/branch.conf',
  '/CVS/Root',
  '/CVS/Entries',

  // 💾 Backups & Database Files
  '/backup.sql',
  '/backup.sql.gz',
  '/backup.zip',
  '/backup.tar.gz',
  '/backup.7z',
  '/backup.bak',
  '/backup.old',
  '/backup.rar',
  '/db.sql',
  '/db.sql.gz',
  '/dump.sql',
  '/database.sql',
  '/db_backup.sql',
  '/mysql.sql',
  '/mysqldump.sql',
  '/site.sql',
  '/data.sql',
  '/1.sql',
  '/1.sql.gz',
  '/2.sql',
  '/latest.sql',
  '/dbdump.sql',
  '/sqldump.sql',
  '/export.sql',
  '/backup-db.sql',
  '/database_backup.sql',
  '/www.sql',
  '/backup/',
  '/backups/',
  '/.backup',
  '/old/',
  '/old.zip',
  '/temp/',
  '/tmp/',
  '/site.zip',
  '/site.tar',
  '/site.tar.gz',
  '/www.zip',
  '/www.tar.gz',
  '/public.zip',
  '/public.tar.gz',
  '/public_html.zip',
  '/web.zip',
  '/web.tar.gz',
  '/website.zip',
  '/httpdocs.zip',
  '/html.zip',

  // 🔑 Configuration & Environment Files
  '/.env',
  '/.env.local',
  '/.env.production',
  '/.env.production.local',
  '/.env.dev',
  '/.env.development',
  '/.env.development.local',
  '/.env.staging',
  '/.env.backup',
  '/.env.old',
  '/.env.save',
  '/.env.example',
  '/.env.php',
  '/env',
  '/env.sample',
  '/example.env',
  '/config',
  '/config.json',
  '/config.php',
  '/config.yml',
  '/config.yaml',
  '/config.inc.php',
  '/config.inc',
  '/config.php.bak',
  '/configuration.php',
  '/configuration.php-dist',
  '/settings.php',
  '/settings.json',
  '/settings.py',
  '/local_settings.py',
  '/app/config/parameters.yml',
  '/application/config/database.php',
  '/api/config',
  '/web.config',
  '/Web.config',
  '/wp-config.php',
  '/wp-config.php.bak',
  '/wp-config.old',
  '/db.php',
  '/database.php',
  '/database.yml',
  '/appsettings.json',
  '/appsettings.production.json',
  '/appsettings.Development.json',
  '/secrets.yml',
  '/credentials.json',
  '/config/database.yml',
  '/config/secrets.yml',
  '/config/master.key',
  '/config/credentials.yml.enc',
  '/php.ini',
  '/.user.ini',
  '/php-fpm.conf',

  // 🚨 CRITICAL - API Keys & Secrets
  '/sftp-config.json',
  '/ftpsync.settings',
  '/.ftpconfig',
  '/deployment-config.json',
  '/.vscode/sftp.json',
  '/privatekey.pem',
  '/server.key',
  '/server.crt',
  '/cert.pem',
  '/key.pem',
  '/ssl/private.key',
  '/.pgpass',
  '/.netrc',
  '/token.txt',
  '/access_token',
  '/api_key.txt',
  '/api-keys.txt',
  '/auth.json',
  '/oauth.json',
  '/client_secret.json',
  '/firebase-adminsdk.json',
  '/.google_authenticator',
  '/2fa-recovery-codes.txt',
  '/backup-codes.txt',
  '/proftpdpasswd',
  '/.my.cnf',
  '/mysql_history',
  '/.psql_history',

  // 🔐 Cloud Provider Credentials
  '/.aws/credentials',
  '/.aws/config',
  '/credentials',
  '/service-account-key.json',
  '/.azure/credentials',
  '/.azure-credentials',
  '/.config/gcloud/credentials.db',
  '/gcp-key.json',
  '/firebase-config.json',
  '/.s3cfg',
  '/.rclone.conf',
  '/rclone.conf',
  '/.boto',
  '/s3.yml',
  '/.kube/config',
  '/kubeconfig',
  '/.docker/config.json',
  '/aws.json',
  '/google-services.json',
  '/GoogleService-Info.plist',

  // 🐳 Docker & Container Files
  '/Dockerfile',
  '/docker-compose.yml',
  '/docker-compose.yaml',
  '/.dockerignore',
  '/.docker/',
  '/docker-compose.override.yml',
  '/docker-compose.prod.yml',

  // 📦 Package Manager Files
  '/package.json',
  '/package-lock.json',
  '/yarn.lock',
  '/composer.json',
  '/composer.lock',
  '/Gemfile',
  '/Gemfile.lock',
  '/Pipfile',
  '/Pipfile.lock',
  '/requirements.txt',
  '/pom.xml',
  '/build.gradle',
  '/go.mod',
  '/go.sum',
  '/.npmrc',
  '/.yarnrc',
  '/pnpm-lock.yaml',

  // 📝 Log Files
  '/error_log',
  '/error.log',
  '/errors.log',
  '/access.log',
  '/access_log',
  '/debug.log',
  '/production.log',
  '/app.log',
  '/application.log',
  '/server.log',
  '/npm-debug.log',
  '/yarn-error.log',
  '/php_errors.log',
  '/laravel.log',
  '/storage/logs/laravel.log',
  '/storage/logs/',
  '/log/development.log',
  '/log/production.log',
  '/logs/error.log',
  '/var/log/',

  // 🔧 Server & Application Info
  '/phpinfo.php',
  '/info.php',
  '/test.php',
  '/php.php',
  '/version',
  '/version.txt',
  '/version.json',
  '/VERSION',
  '/CHANGELOG.md',
  '/CHANGELOG.txt',
  '/api/version',
  '/api/info',
  '/api/v1/info',
  '/api/swagger.json',
  '/api/swagger.yaml',
  '/api/swagger',
  '/api/docs',
  '/api.json',
  '/api.yaml',
  '/api/openapi.json',
  '/api-docs',
  '/swagger.json',
  '/swagger.yaml',
  '/swagger-ui.html',
  '/v2/api-docs',
  '/openapi.json',
  '/openapi.yaml',
  '/redoc',
  '/docs.json',
  '/schema.json',
  '/wsdl',
  '/wadl',

  // 🎯 GraphQL Endpoints
  '/graphql',
  '/graphiql',
  '/playground',
  '/api/graphql',
  '/__graphql',
  '/graphql/console',
  '/v1/graphql',
  '/graphql/v1',
  '/query',
  '/graphql?query={__schema{types{name}}}',

  // 🛡️ Admin & Control Panels
  '/admin',
  '/admin/',
  '/admin/login',
  '/administrator',
  '/admin.php',
  '/admin/index.php',
  '/admin/config.php',
  '/wp-admin/',
  '/phpmyadmin/',
  '/phpmyadmin/index.php',
  '/pma/',
  '/mysql/',
  '/dbadmin/',
  '/adminer.php',
  '/adminer/',
  '/cpanel',
  '/cPanel',
  '/plesk',
  '/webadmin',
  '/controlpanel',
  '/management',
  '/manage',
  '/console',
  '/dashboard',
  '/portal',

  // 📊 Monitoring & Metrics
  '/metrics',
  '/actuator',
  '/actuator/health',
  '/actuator/env',
  '/actuator/metrics',
  '/actuator/mappings',
  '/actuator/configprops',
  '/actuator/dump',
  '/actuator/heapdump',
  '/actuator/trace',
  '/actuator/logfile',
  '/jolokia',
  '/hawtio',
  '/prometheus',
  '/debug/pprof',
  '/debug/vars',
  '/_stats',
  '/_status',
  '/_health',

  // 🗄️ Directory Listings & Indexes
  '/uploads/',
  '/images/',
  '/files/',
  '/download/',
  '/downloads/',
  '/media/',
  '/assets/',
  '/static/',
  '/public/',
  '/storage/',
  '/data/',
  '/documents/',
  '/attachments/',

  // 🧪 Test & Development Files
  '/test',
  '/test.php',
  '/test.html',
  '/testing',
  '/dev',
  '/development',
  '/debug',
  '/demo',
  '/example',
  '/examples',
  '/sample',
  '/samples',
  '/temp.php',
  '/tmp.php',
  '/1.php',
  '/shell.php',
  '/upload.php',

  // 📄 Documentation & README
  '/readme.md',
  '/README.md',
  '/README.txt',
  '/README',
  '/license',
  '/LICENSE',
  '/LICENSE.txt',
  '/INSTALL.txt',
  '/INSTALL.md',
  '/CONTRIBUTING.md',
  '/docs/',
  '/documentation/',
  '/help/',

  // 🌍 CMS Specific (WordPress, Joomla, Drupal)
  '/wp-config.php',
  '/wp-content/debug.log',
  '/wp-json/wp/v2/users',
  '/wp-includes/',
  '/xmlrpc.php',
  '/wp-login.php',
  '/license.txt',
  '/readme.html',
  '/configuration.php',
  '/administrator/manifests/files/joomla.xml',
  '/user/login',
  '/install.php',
  '/install/',
  '/setup/',
  '/sites/default/settings.php',
  '/app/etc/local.xml',
  '/app/etc/env.php',
  '/.maintenance',

  // 🔍 Miscellaneous Sensitive Files
  '/favicon.ico',
  '/.htaccess',
  '/.htpasswd',
  '/Thumbs.db',
  '/.bashrc',
  '/.bash_history',
  '/.bash_profile',
  '/.ssh/id_rsa',
  '/.ssh/id_dsa',
  '/.ssh/id_ecdsa',
  '/.ssh/id_ed25519',
  '/.ssh/known_hosts',
  '/.ssh/authorized_keys',
  '/id_rsa',
  '/id_rsa.pub',
  '/id_dsa',
  '/privatekey',
  '/mykey.pem',
  '/prod.key',
  '/production.key',
  '/staging.key',
  '/.DS_Store',
  '/.idea/',
  '/.vscode/',
  '/nbproject/',
  '/.project',
  '/.classpath',
  '/.settings/',

  // 🔓 Common Vulnerable Endpoints
  '/cgi-bin/',
  '/index.php.bak',
  '/.listing',
  '/.perf',
  '/core',
  '/.core',
  '/WEB-INF/web.xml',
  '/META-INF/MANIFEST.MF',

  // 🏗️ CI/CD & Infrastructure as Code
  '/.travis.yml',
  '/.gitlab-ci.yml',
  '/gitlab-ci.yml',
  '/.circleci/config.yml',
  '/Jenkinsfile',
  '/.drone.yml',
  '/.github/workflows/',
  '/azure-pipelines.yml',
  '/bitbucket-pipelines.yml',
  '/cloudbuild.yaml',
  '/buildspec.yml',
  '/wercker.yml',
  '/appveyor.yml',
  '/codefresh.yml',
  '/terraform.tfstate',
  '/terraform.tfstate.backup',
  '/terraform.tfvars',
  '/.terraform/',
  '/ansible.cfg',
  '/inventory.ini',
  '/hosts.yml',
  '/playbook.yml',
  '/Vagrantfile',
  '/ansible/hosts',
  '/pulumi.yaml',
  '/cloudformation.json',
  '/cloudformation.yaml',

  // 🎫 Authentication & Session
  '/api/auth/config',
  '/oauth/token',
  '/token',
  '/oauth2/token',
  '/login.json',
  '/jwks',
  '/auth/jwks',
  '/auth/realms/master/.well-known/openid-configuration',
  '/session.txt',
  '/sess_*',
  '/redis.conf',
  '/memcached.conf',
  '/.redis',

  // 🔍 Source Maps (leak source code)
  '/main.js.map',
  '/app.js.map',
  '/bundle.js.map',
  '/vendor.js.map',
  '/index.js.map',
  '/app.css.map',

  // 📱 Mobile & App Configs
  '/app.json',
  '/eas.json',
  '/config.codekit',
  '/sftp.json',

  // 🔧 Framework Specific
  '/bootstrap.php',
  '/autoload.php',
  '/vendor/autoload.php',
  '/application.properties',
  '/application.yml',

  // 💀 Shell & Backdoors (common names)
  '/c99.php',
  '/r57.php',
  '/webshell.php',
  '/backdoor.php',
  '/cmd.php',
  '/uploader.php',
  '/up.php',
  '/ajax.php',

  // 🔐 SAML & SSO
  '/saml/metadata',
  '/simplesaml/',
  '/sso/metadata',
  '/FederationMetadata/2007-06/FederationMetadata.xml',

  // 📧 Email & SMTP
  '/email.txt',
  '/smtp.txt',
  '/mail.php',
  '/sendmail.php',
  '/mailer.php',
  '/mailconfig.json',

  // 📊 Analytics & Tracking
  '/analytics.js',
  '/_tracking',
  '/tracking.js',
  '/pixel',

  // 🔎 Information Disclosure (.NET, Symfony, Laravel)
  '/elmah.axd',
  '/trace.axd',
  '/glimpse.axd',
  '/_profiler',
  '/_profiler/phpinfo',
  '/telescope',
  '/horizon/dashboard',
  '/__webpack_hmr',

  // 🌐 CDN & Asset Configs
  '/cdn.yml',
  '/cdn.json',
  '/s3_website.yml',

  // 🎯 API Discovery
  '/api/health',
  '/api/debug',
  '/api/settings',
  '/api/users',
  '/api/v1/users',
  '/api/admin',
  '/rest/api/2/serverInfo',
  '/api/now/table/sys_user',

  // 🛡️ Bug Bounty & Security
  '/bugbounty',
  '/security',
  '/responsible-disclosure',
  '/hall-of-fame',
];

const normalizeUrl = (url) => {
  try {
    const u = new URL(url);
    // Preserving trailing slashes for directory fidelity
    return u.origin + u.pathname + u.search;
  } catch { return url; }
};

// Helper to ensure base URL is treated as a directory for relative path resolution
const directoryfyUrl = (url) => {
  if (url.endsWith('/')) return url;
  try {
    const urlObj = new URL(url);
    const lastPart = urlObj.pathname.split('/').pop() || "";
    // If the last part has no extension, treat it as a directory
    if (!lastPart.includes('.')) {
      return url + '/';
    }
  } catch { }
  return url;
};

const REMOTE_PROXY_ENDPOINTS = [
  "https://fragrant-frog-b197.bugbountytestinghacker.workers.dev/?url="
];

const LOCAL_PROXY_HEADER = "x-web-x-sider-proxy";
const CRAWLER_REQUEST_DELAY_MS = 300;
const PROBER_REQUEST_DELAY_MS = 450;
const SETTINGS_KEY = "web-x-sider:settings";

function loadSettings() {
  try {
    return JSON.parse(localStorage.getItem(SETTINGS_KEY) || "{}");
  } catch {
    return {};
  }
}

function saveSettings() {
  const settings = {
    crawlerDelay: parseInt(document.getElementById("setting-crawlerDelay")?.value, 10) || 300,
    proberDelay: parseInt(document.getElementById("setting-proberDelay")?.value, 10) || 450,
    concurrency: Math.max(1, Math.min(20, parseInt(document.getElementById("setting-concurrency")?.value, 10) || 5)),
    proxyUrl: document.getElementById("setting-proxyUrl")?.value?.trim() || "",
    userAgent: document.getElementById("setting-userAgent")?.value?.trim() || "",
    authHeaders: document.getElementById("setting-authHeaders")?.value?.trim() || "",
    customSecrets: document.getElementById("setting-customSecrets")?.value?.trim() || ""
  };
  safeLocalStorageSet(SETTINGS_KEY, JSON.stringify(settings));
  applySettings(settings);
  showToast("Settings saved", "success");
}

function applySettings(settings = {}) {
  window._CRAWLER_DELAY = settings.crawlerDelay !== undefined ? settings.crawlerDelay : CRAWLER_REQUEST_DELAY_MS;
  window._PROBER_DELAY = settings.proberDelay !== undefined ? settings.proberDelay : PROBER_REQUEST_DELAY_MS;
  window._REQUEST_CONCURRENCY = settings.concurrency !== undefined ? Math.max(1, Math.min(20, settings.concurrency)) : 5;
  if (settings.proxyUrl) {
    REMOTE_PROXY_ENDPOINTS[0] = settings.proxyUrl.includes("?url=") || settings.proxyUrl.endsWith("=")
      ? settings.proxyUrl
      : `${settings.proxyUrl.replace(/\?$/, "")}?url=`;
  }
}

function getAuthHeaders() {
  const settings = loadSettings();
  const headers = {};
  (settings.authHeaders || "").split("\n").forEach(line => {
    const idx = line.indexOf(":");
    if (idx > 0) {
      const key = line.slice(0, idx).trim();
      const value = line.slice(idx + 1).trim();
      if (key && value) headers[key] = value;
    }
  });
  return headers;
}

function getRequestConcurrency() {
  return window._REQUEST_CONCURRENCY || 5;
}

function mapWithConcurrency(items, limit, worker) {
  const results = new Array(items.length);
  let nextIndex = 0;
  const runner = async () => {
    while (nextIndex < items.length) {
      const index = nextIndex++;
      results[index] = await worker(items[index], index);
    }
  };
  return Promise.allSettled(Array.from({ length: Math.min(limit, items.length) }, runner)).then(() => results);
}

const _initialSettings = loadSettings();
applySettings(_initialSettings);
document.addEventListener("DOMContentLoaded", () => {
  const s = loadSettings();
  if (s.crawlerDelay !== undefined) document.getElementById("setting-crawlerDelay").value = s.crawlerDelay;
  if (s.proberDelay !== undefined) document.getElementById("setting-proberDelay").value = s.proberDelay;
  if (s.concurrency !== undefined) document.getElementById("setting-concurrency").value = s.concurrency;
  if (s.proxyUrl) document.getElementById("setting-proxyUrl").value = s.proxyUrl;
  if (s.userAgent) document.getElementById("setting-userAgent").value = s.userAgent;
  if (s.authHeaders) document.getElementById("setting-authHeaders").value = s.authHeaders;
  if (s.customSecrets) document.getElementById("setting-customSecrets").value = s.customSecrets;
});
document.getElementById("saveSettingsBtn")?.addEventListener("click", saveSettings);

const isLocalAppHost = () => {
  const host = window.location.hostname;
  return host === "localhost" || host === "127.0.0.1" || host === "::1";
};

const getFetchCandidates = (url, proxyParams = {}) => {
  const encodedUrl = encodeURIComponent(url);
  const extraProxyQuery = Object.entries(proxyParams)
    .filter(([, value]) => value !== undefined && value !== null && String(value).trim() !== "")
    .map(([key, value]) => `&${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
    .join("");
  const candidates = [];

  try {
    const target = new URL(url, window.location.href);
    if (target.origin === window.location.origin) {
      candidates.push({
        url: target.href,
        label: "same-origin fetch",
        viaProxy: false,
        requiresProxyHeader: false
      });
    }
  } catch { }

  if (isLocalAppHost()) {
    candidates.push({
      url: `/proxy?url=${encodedUrl}${extraProxyQuery}`,
      label: "local proxy",
      viaProxy: true,
      requiresProxyHeader: true
    });
  }

  REMOTE_PROXY_ENDPOINTS.forEach(proxy => {
    candidates.push({
      url: `${proxy}${encodedUrl}${extraProxyQuery}`,
      label: "remote proxy",
      viaProxy: true,
      requiresProxyHeader: false
    });
  });

  const seen = new Set();
  return candidates.filter(candidate => {
    if (seen.has(candidate.url)) return false;
    seen.add(candidate.url);
    return true;
  });
};

async function fetchTarget(url, options = {}) {
  const { proxyParams = {}, ...fetchOptions } = options;
  const errors = [];
  const authHeaders = getAuthHeaders();
  if (Object.keys(authHeaders).length > 0) {
    fetchOptions.headers = { ...(fetchOptions.headers || {}), ...authHeaders };
  }

  for (const candidate of getFetchCandidates(url, proxyParams)) {
    try {
      if (candidate.viaProxy) {
        const customUA = loadSettings()?.userAgent;
        if (customUA) {
          fetchOptions.headers = { ...(fetchOptions.headers || {}), "X-Web-X-Sider-User-Agent": customUA };
        }
      }
      const res = await fetch(candidate.url, fetchOptions);

      if (candidate.requiresProxyHeader && res.headers.get(LOCAL_PROXY_HEADER) !== "local") {
        errors.push(`${candidate.label} is not running at ${candidate.url}`);
        continue;
      }

      if (candidate.viaProxy && [502, 504].includes(res.status)) {
        errors.push(`${candidate.label} returned ${res.status}`);
        continue;
      }

      return res;
    } catch (error) {
      const isCorsLikeProxyFailure = candidate.viaProxy && /failed to fetch|networkerror|load failed/i.test(error.message || "");
      const hint = isCorsLikeProxyFailure
        ? "proxy is blocked/offline or missing Access-Control-Allow-Origin"
        : error.message;
      errors.push(`${candidate.label}: ${hint}`);
    }
  }

  const localHint = errors.some(error => /local proxy/i.test(error)) ? " Start server.py to use local proxy." : "";
  throw new Error(`Unable to fetch ${url}.${localHint} ${errors.join(" | ")}. Test proxy: ${REMOTE_PROXY_ENDPOINTS[0]}https%3A%2F%2Fexample.com`);
}

const isCloudflareChallengePage = (text) => (
  /cf_chl|challenge-platform|enable javascript and cookies|just a moment/i.test(text || "")
);

const isBotProtectionPage = (text) => (
  isCloudflareChallengePage(text) ||
  /captcha|bot detection|automated requests?|access denied|request blocked|unusual traffic|security check|verify you are human/i.test(text || "")
);

const isSoft404Page = (text, status = 200) => {
  if (status === 404) return true;
  if (status !== 200) return false;
  const titleMatch = String(text || "").match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  const h1Match = String(text || "").match(/<h1[^>]*>([\s\S]*?)<\/h1>/i);
  const titleText = titleMatch ? titleMatch[1] : "";
  const h1Text = h1Match ? h1Match[1] : "";
  const combined = `${titleText} ${h1Text}`.replace(/\s+/g, " ").trim().slice(0, 300);
  if (!combined) return false;
  return /(?:404|not found|page not found|does not exist|no such file|resource missing|route not found)/i.test(combined);
};

const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

const classifyHttpResponse = (status, text) => {
  if ([401, 403, 429].includes(status) && isBotProtectionPage(text)) {
    return {
      effectiveStatus: status === 401 ? 401 : 403,
      note: "target protection",
      blocked: true
    };
  }

  if (isSoft404Page(text, status)) {
    return {
      effectiveStatus: 404,
      note: status === 404 ? "not found" : "soft 404",
      blocked: false
    };
  }

  return { effectiveStatus: status, note: "", blocked: false };
};

const endpointRegex = new RegExp(
  `(?:"|')((?:[a-zA-Z]{1,10}:\\/\\/|\\/\\/)[^"']*?|(?:\\/|\\.\\/|\\.\\.\\/)[^"'\\s<>]+|[a-zA-Z0-9_\\-/]+\\.[a-z]{1,5}(?:\\?[^"'\\s]*)?)(?:"|')`,
  "g"
);

// Advanced Secret Detection Patterns
const secretPatterns = {
  "AWS Key": /AKIA[0-9A-Z]{16}/g,
  "Google API": /AIza[0-9A-Za-z\-_]{35}/g,
  "Stripe Live": /sk_live_[0-9a-zA-Z]{24,}/g,
  "GitHub PAT": /ghp_[0-9a-zA-Z]{36}/g,
  "Slack Token": /xox[baprs]-[0-9a-zA-Z\-]{10,48}/g,
  "JWT": /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+/g,
  "Private Key": /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g,
  "MongoDB": /mongodb(?:\+srv)?:\/\/[^\s"\'<>]+/g,
  "PostgreSQL": /postgres(?:ql)?:\/\/[^\s"\'<>]+/g,
  "Algolia Admin API Key": /(?:algoliaApiKey|algoliasearch|x-algolia-api-key)\s*[:=]\s*['"]([a-f0-9]{32})['"]/gi,
  "Algolia Application ID": /(?:algoliaAppId|applicationID|x-algolia-application-id)\s*[:=]\s*['"]([A-Z0-9]{10})['"]/gi,
  "Cloudflare API Token": /cloudflare.{0,32}(?:secret|private|access|key|token).{0,32}([a-z0-9_-]{38,42})\b/gi,
  "Cloudflare Service Key": /(?:cloudflare|x-auth-user-service-key).{0,64}(v1\.0-[a-z0-9._-]{160,})\b/gi,
  "MySQL URI with Credentials": /mysql:\/\/[a-z0-9._%+\-]+:[^\s:@]+@(?:\[[0-9a-f:.]+\]|[a-z0-9.-]+)(?::\d{2,5})?(?:\/[^\s"\'?:]+)?(?:\?[^\s"\']*)?/g,
  "Segment Public API Token": /\bsgp_[A-Z0-9_-]{60,70}\b/g,
  "Segment API Key": /(?:segment|sgmt).{0,16}(?:secret|private|access|key|token).{0,16}([A-Z0-9_-]{40,50}\.[A-Z0-9_-]{40,50})/gi,
  "Facebook App ID": /(?:appId|app_id|FB_APP_ID)\s*[:=]\s*['"]?(\d{15,16})['"]?/gi,
  "Facebook Secret Key": /(?:appSecret|app_secret|FB_APP_SECRET|client_secret)\s*[:=]\s*['"]([a-f0-9]{32})['"]/gi,
  "Facebook Access Token": /EAACEdEose0cBA[A-Z0-9]{20,}\b/g,
  "Google OAuth2 Access Token": /\bya29\.[a-z0-9_-]{30,}\b/g,
  "Slack Webhook": /https:\/\/hooks\.slack\.com\/services\/[A-Z0-9]+\/[A-Z0-9]+\/[A-Za-z0-9]+/g,
  "Discord Webhook": /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+/g
};

// Fast-Path Check: Only run detailed regexes if one of these keywords is present
const secretTrigger = /AKIA|AIza|sk_live|ghp_|xox[baprs]|eyJ|-----BEGIN|mongodb|postgres|postgresql|algolia|cloudflare|mysql|sgp_|segment|sgmt|facebook|fb|ya29|hooks\.slack\.com|discord\.com\/api\/webhooks/i;

function parseRegexLiteral(input) {
  const match = String(input || "").match(/^\/([\s\S]*)\/([a-z]*)$/i);
  if (match) return new RegExp(match[1], match[2]);
  return new RegExp(String(input || ""), "gi");
}

function getSecretPatterns() {
  const patterns = { ...secretPatterns };
  const custom = loadSettings().customSecrets;
  if (!custom) return patterns;
  try {
    const parsed = JSON.parse(custom);
    Object.entries(parsed).forEach(([name, regexSource]) => {
      if (name && regexSource) patterns[name] = parseRegexLiteral(regexSource);
    });
  } catch {
    showToast("Custom secret patterns JSON is invalid. Built-in patterns were used.", "warn", 5000);
  }
  return patterns;
}

const blockedSecretKeywords = [
  "defaultNumberingSystem", "defaultOutputCalendar", "twoDigitCutoffYear",
  "module.exports", "prototype", "constructor", "__proto__",
  "invalidExplanation", "DATE_MED", "TIME_WITH", "DATETIME_", "TIME_24"
];

// BLOCK garbage resource extensions
const excludedExtensions = [
  ".woff", ".woff2", ".ttf", ".otf", ".eot", ".sfnt",
  ".png", ".jpg", ".jpeg", ".svg", ".gif", ".ico", ".webp", ".bmp", ".apng", ".tif", ".tiff",
  ".css", ".less", ".sass",
  ".map",
  ".mp4", ".m4v", ".webm", ".mp3", ".wav", ".ogg", ".flac",
  ".xls", ".xlsx", ".csv", ".rtf",
  ".apk", ".ipa", ".dmg", ".bin", ".jar", ".class",
  ".swf", ".log", ".tmp", ".old", ".drag", ".brush", ".zoom", ".time", ".name", ".width", ".calcs"
];

// BLOCK garbage/tracker domains
const externalDomainsToIgnore = [
  "facebook.com", "instagram.com", "twitter.com", "tiktok.com", "linkedin.com",
  "youtube.com", "vimeo.com", "pinterest.com", "cdn.jsdelivr.net", "cdnjs.cloudflare.com",
  "unpkg.com", "bootstrapcdn.com", "maxcdn.bootstrapcdn.com",
  "fonts.googleapis.com", "fonts.gstatic.com",
  "gstatic.com", "google.com", "googleapis.com",
  "googletagmanager.com", "googlesyndication.com", "google-analytics.com", "gtag/js",
  "doubleclick.net", "cookielaw.org", "cdn.adobedtm.com", "scene7.com", "w3.org",
  "akamaihd.net", "brightcove.net", "vidyard.com", "wistia.com",
  "newrelic.com", "datadoghq.com", "cloudflareinsights.com",
  "optimizely.com", "hotjar.com", "segment.com", "intercom.io",
  "salesforce.com", "liveperson.net", "zendesk.com", "helix-rum-js",
  "sentry.io", "mixpanel.com", "disqus.com", "addthis.com", "sharethis.com", "criteo.com",
  "tracking.", "pixel.", "collect.", "recaptcha.net", "lazcdn.com", "alicdn.com"
];

// BLOCK garbage prefixes like markup://, js://, aura://
const disallowedPrefixes = [
  "js://", "markup://", "aura://", "java://", "css://",
  "object://", "text://", "xml://", "apex://", "apexclass://",
  "resource://", "data://", "mailto:", "tel:", "blob:", "file://",
  "intent://", "chrome-extension://", "about:", "chrome://"
];

const stopScanBtn = document.getElementById("stopScanBtn");

// Global State
const state = {
  scanned: 0,
  endpoints: new Set(),
  secrets: new Set(),
  files: new Set(),
  parameters: new Set(),
  allData: [], // { source, type, value, line }
  dedupKeys: new Set(),
  scannedUrls: new Set(),
  totalDiscovered: 0,
  totalToScan: 1,
  probedDomains: new Set(),
  isScanning: false,
  isCrawlerStopped: false,
  fetchFailures: [],
  scanDiagnostic: null,
  scopeRules: [],
  hiddenFindings: new Set(),
  findingNotes: {},
  findingTags: {},
  activeSeverityFilter: "all",
  hostChecks: []
};

const updateStats = () => {
  document.getElementById("stat-scanned").innerText = state.scanned;
  document.getElementById("stat-endpoints").innerText = state.endpoints.size;
  document.getElementById("stat-secrets").innerText = state.secrets.size;
  document.getElementById("stat-files").innerText = state.files.size;
  document.getElementById("stat-parameters").innerText = state.parameters.size;
};

const severityRank = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1
};

function classifyFinding(type, value) {
  const raw = String(value || "");
  const lowered = raw.toLowerCase();

  if (type === "secret") {
    if (/private key|aws key|stripe live|github pat|cloudflare|slack webhook|discord webhook|google oauth2/i.test(raw)) {
      return { severity: "critical", hint: "Validate key scope, ownership, and real impact; rotate only through the program owner." };
    }
    if (/jwt|mongodb|postgresql|mysql|facebook secret|segment/i.test(raw)) {
      return { severity: "high", hint: "Check whether the token/URI is active, privileged, or exposes user or system data." };
    }
    return { severity: "medium", hint: "Review manually for exposed credentials or sensitive configuration." };
  }

  if (type === "file") {
    if (/\/(?:\.env|\.git\/config|\.git\/head|id_rsa|privatekey|server\.key|credentials|service-account|firebase-adminsdk|config\/master\.key)(?:$|[?#/])/i.test(lowered)) {
      return { severity: "critical", hint: "Potential direct secret/source disclosure. Verify status, content length, and readable evidence." };
    }
    if (/\.(?:sql|bak|backup|zip|tar|gz|7z|rar)(?:$|[?#])/i.test(lowered) || /\/(?:backup|backups|dump|database|wp-config|phpinfo|swagger|openapi|api-docs)/i.test(lowered)) {
      return { severity: "high", hint: "Check for backup, config, docs, or database exposure with sensitive content." };
    }
    if (/\.(?:map|json|xml|yml|yaml|config|log|txt)(?:$|[?#])/i.test(lowered)) {
      return { severity: "medium", hint: "Inspect for internal endpoints, stack traces, source paths, or environment data." };
    }
  }

  if (type === "parameter") {
    try {
      const parsed = new URL(raw, "https://placeholder.local");
      const names = [...parsed.searchParams.keys()].map(name => name.toLowerCase());
      if (names.some(name => /^(url|uri|redirect|redirect_uri|return|returnurl|next|callback|continue|dest|destination|target|to)$/.test(name))) {
        return { severity: "high", hint: "Test open redirect, SSRF-style fetches, OAuth redirect abuse, and allowlist bypasses." };
      }
      if (names.some(name => /^(file|path|template|page|view|include|download|document|folder)$/.test(name))) {
        return { severity: "high", hint: "Test LFI/path traversal and unauthorized file download behavior." };
      }
      if (names.some(name => /^(id|user|userid|user_id|account|accountid|account_id|org|orgid|tenant|tenantid|role)$/.test(name))) {
        return { severity: "medium", hint: "Test IDOR/BOLA by changing identifiers between authorized accounts." };
      }
      if (names.some(name => /^(q|query|search|s|keyword|callback|jsonp|debug|test)$/.test(name))) {
        return { severity: "medium", hint: "Test injection, reflected input, debug behavior, and cache poisoning edge cases." };
      }
    } catch { }
  }

  if (type === "endpoint") {
    if (/\/(?:admin|internal|debug|actuator\/env|actuator\/heapdump|graphql|graphiql|playground|oauth\/token|token|jwks|api\/admin)(?:$|[/?#])/i.test(lowered)) {
      return { severity: "high", hint: "Prioritize auth bypass, info disclosure, GraphQL introspection, and sensitive admin behavior." };
    }
    if (/\/(?:api|v1|v2|v3|auth|login|users|account|billing|payment|invoice|upload|download|export)(?:$|[/?#])/i.test(lowered)) {
      return { severity: "medium", hint: "Map authz, IDOR/BOLA, upload/download controls, and rate-limit behavior." };
    }
  }

  return { severity: "low", hint: "Low signal by itself; keep for mapping and chaining with other findings." };
}

function inferHttpMethod(value) {
  const path = String(value || "").toLowerCase();
  if (/\/(?:delete|remove|destroy|disable|revoke|logout)(?:[/?#]|$)/.test(path)) return "DELETE/POST";
  if (/\/(?:update|edit|patch|change|reset)(?:[/?#]|$)/.test(path)) return "PUT/PATCH";
  if (/\/(?:create|add|upload|import|login|register|token|checkout|payment)(?:[/?#]|$)/.test(path)) return "POST";
  if (/\/(?:export|download|report|search|list|users|accounts)(?:[/?#]|$)/.test(path)) return "GET";
  return "";
}

function getFindingConfidence(item) {
  const value = String(item.value || "");
  if (item.type === "secret") return /AKIA|sk_live|ghp_|xox|-----BEGIN|hooks\.slack|discord(?:app)?\.com\/api\/webhooks/i.test(value) ? "high" : "medium";
  if (/^https?:\/\//i.test(value)) return "high";
  if (item.type === "parameter" || value.includes("?")) return "medium";
  return "low";
}

function parseScopeRules(raw) {
  return String(raw || "")
    .split(/\r?\n|,/)
    .map(item => item.trim().toLowerCase())
    .filter(Boolean)
    .map(item => item.replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/^www\./, ""))
    .filter(item => /^[*.a-z0-9-]+(?:\.[a-z0-9-]+)+$/.test(item));
}

function isHostInScope(hostname, rules) {
  if (!rules || rules.length === 0) return true;
  const host = String(hostname || "").toLowerCase().replace(/^www\./, "");
  return rules.some(rule => {
    if (rule.startsWith("*.")) {
      const base = rule.slice(2);
      return host === base || host.endsWith(`.${base}`);
    }
    return host === rule || host.endsWith(`.${rule}`);
  });
}

function parseImportedUrls(raw, baseUrl) {
  const base = new URL(baseUrl);
  const urls = new Set();
  String(raw || "")
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(Boolean)
    .forEach(line => {
      const matches = line.match(/https?:\/\/[^\s"'<>]+|\/[A-Za-z0-9_~./?&=%{}:@-]+/gi) || [];
      matches.forEach(match => {
        try {
          const cleaned = match.replace(/[),.;\]]+$/, "");
          urls.add(normalizeUrl(new URL(cleaned, base.origin).href));
        } catch { }
      });
    });
  return [...urls];
}

function appendUniqueLines(textarea, values) {
  if (!textarea || !values.length) return 0;
  const current = String(textarea.value || "")
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(Boolean);
  const seen = new Set(current);
  let added = 0;
  values.forEach(value => {
    if (!seen.has(value)) {
      seen.add(value);
      current.push(value);
      added++;
    }
  });
  textarea.value = current.join("\n");
  return added;
}

function getImportBaseUrl() {
  const raw = urlInput?.value?.trim() || "https://example.com";
  return /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
}

function extractHostFromHeaderBlock(block) {
  const match = String(block || "").match(/(?:^|\n)\s*Host:\s*([^\s\r\n]+)/i);
  return match ? match[1].trim() : "";
}

function collectWorkflowArtifacts(raw, baseUrl = getImportBaseUrl()) {
  const urls = new Set();
  const hosts = new Set();
  const text = String(raw || "");
  const base = new URL(baseUrl);

  const addUrl = (value, fallbackHost = "") => {
    try {
      const cleaned = String(value || "").trim().replace(/[),.;\]]+$/, "");
      if (!cleaned) return;
      let resolved = cleaned;
      if (cleaned.startsWith("/") && fallbackHost) {
        resolved = `${base.protocol}//${fallbackHost}${cleaned}`;
      }
      const parsed = new URL(resolved, base.origin);
      if (!/^https?:$/i.test(parsed.protocol)) return;
      urls.add(normalizeUrl(parsed.href));
      hosts.add(parsed.origin);
    } catch { }
  };

  try {
    const parsed = JSON.parse(text);
    const entries = parsed?.log?.entries || parsed?.entries || [];
    if (Array.isArray(entries)) {
      entries.forEach(entry => {
        addUrl(entry?.request?.url || entry?.url);
        addUrl(entry?.response?.redirectURL);
        (entry?.request?.headers || []).forEach(header => {
          if (/^(referer|origin)$/i.test(header?.name || "")) addUrl(header.value);
        });
      });
    }
  } catch { }

  (text.match(/https?:\/\/[^\s"'<>\\]+/gi) || []).forEach(addUrl);

  const requestBlocks = text.split(/\n\s*\n/);
  requestBlocks.forEach(block => {
    const fallbackHost = extractHostFromHeaderBlock(block);
    const firstLine = block.match(/^\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+([^\s]+)\s+HTTP\/\d(?:\.\d)?/im);
    if (firstLine) addUrl(firstLine[2], fallbackHost);
  });

  text.split(/\r?\n/).forEach(line => {
    const trimmed = line.trim();
    if (/^\/[A-Za-z0-9_~./?&=%{}:@-]+$/.test(trimmed)) addUrl(trimmed);
  });

  return {
    urls: [...urls].sort(),
    hosts: [...hosts].sort()
  };
}

function applyWorkflowImport(raw = workflowImportInput?.value || "") {
  const artifacts = collectWorkflowArtifacts(raw);
  if (!artifacts.urls.length && !artifacts.hosts.length) {
    if (workflowImportStatus) workflowImportStatus.innerText = "No URLs or hosts were found in the import.";
    return;
  }

  if (!urlInput.value.trim() && artifacts.urls[0]) {
    try {
      urlInput.value = new URL(artifacts.urls[0]).origin;
    } catch { }
  }

  const addedUrls = appendUniqueLines(importedUrlInput, artifacts.urls);
  const addedHosts = appendUniqueLines(subdomainInput, artifacts.hosts);
  if (workflowImportStatus) {
    workflowImportStatus.innerText = `Added ${addedUrls} URL${addedUrls === 1 ? "" : "s"} and ${addedHosts} host${addedHosts === 1 ? "" : "s"} to the scan inputs.`;
  }
  updateInputPreviews();
}

function parseImportedHosts(raw) {
  const hosts = new Set();
  String(raw || "")
    .split(/\r?\n|,|\s+/)
    .map(item => item.trim())
    .filter(Boolean)
    .forEach(item => {
      try {
        const withScheme = /^https?:\/\//i.test(item) ? item : `https://${item}`;
        const parsed = new URL(withScheme);
        if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(parsed.hostname)) {
          hosts.add(parsed.origin);
        }
      } catch { }
    });
  return [...hosts].slice(0, 150);
}

function extractTitle(html) {
  const match = String(html || "").match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  return match ? match[1].replace(/\s+/g, " ").trim().slice(0, 160) : "";
}

function hashText(text) {
  let hash = 0;
  const input = String(text || "").slice(0, 50000);
  for (let i = 0; i < input.length; i++) {
    hash = ((hash << 5) - hash) + input.charCodeAt(i);
    hash |= 0;
  }
  return Math.abs(hash).toString(16);
}

function detectTechFromText(headers, body) {
  const text = `${headers || ""} ${body || ""}`.slice(0, 200000);
  const found = [];
  [
    ["Cloudflare", /cloudflare|cf-ray/i],
    ["Next.js", /_next\/|x-nextjs/i],
    ["React", /react|data-reactroot/i],
    ["Vue", /vue(?:\.runtime)?\.|data-v-/i],
    ["Angular", /ng-version|angular/i],
    ["WordPress", /wp-content|wp-includes/i],
    ["Laravel", /laravel_session|XSRF-TOKEN/i],
    ["Firebase", /firebaseio|firebaseapp|firebaseConfig/i],
    ["GraphQL", /graphql|apollo/i],
    ["Swagger", /swagger-ui|openapi|api-docs/i]
  ].forEach(([name, regex]) => {
    if (regex.test(text)) found.push(name);
  });
  return found;
}

function getFindingKey(item) {
  return `${item.source}|${item.line}|${item.type}|${item.value}`;
}

function getVisibleFindings() {
  return state.allData.filter(item => !state.hiddenFindings.has(getFindingKey(item)));
}

const takeoverFingerprints = [
  { service: "GitHub Pages", pattern: /there isn't a github pages site here|404 there is no github pages site here/i },
  { service: "Heroku", pattern: /no such app|herokucdn\.com.*error/i },
  { service: "AWS S3", pattern: /nosuchbucket|the specified bucket does not exist/i },
  { service: "Azure", pattern: /404 web site not found|azure/i },
  { service: "Shopify", pattern: /sorry, this shop is currently unavailable/i },
  { service: "Fastly", pattern: /fastly error: unknown domain/i },
  { service: "Ghost", pattern: /the thing you were looking for is no longer here/i },
  { service: "Pantheon", pattern: /404 error unknown site!/i },
  { service: "Tumblr", pattern: /there's nothing here|whatever you were looking for doesn't currently exist/i },
  { service: "Zendesk", pattern: /help center closed/i },
  { service: "Surge.sh", pattern: /project not found/i },
  { service: "Netlify", pattern: /not found - request id/i }
];

function checkTakeover(body, status) {
  if (status !== 404 && status !== 200) return null;
  for (const fp of takeoverFingerprints) {
    if (fp.pattern.test(body || "")) return fp.service;
  }
  return null;
}

function updateInputPreviews() {
  const scopeRules = parseScopeRules(scopeInput?.value || "");
  if (scopeStatus) {
    scopeStatus.innerText = scopeRules.length
      ? `${scopeRules.length} scope rule${scopeRules.length === 1 ? "" : "s"} active. Out-of-scope URLs will be skipped.`
      : "Scope is optional. Empty means current target only.";
  }

  if (importStatus) {
    try {
      const baseUrl = urlInput.value.trim() || "https://example.com";
      const normalizedBase = /^https?:\/\//i.test(baseUrl) ? baseUrl : `https://${baseUrl}`;
      const imported = parseImportedUrls(importedUrlInput?.value || "", normalizedBase);
      importStatus.innerText = `${imported.length} imported URL${imported.length === 1 ? "" : "s"} detected.`;
    } catch {
      importStatus.innerText = "Enter a target URL to preview imported URL count.";
    }
  }

  if (subdomainStatus) {
    const hosts = parseImportedHosts(subdomainInput?.value || "");
    subdomainStatus.innerText = `${hosts.length} host${hosts.length === 1 ? "" : "s"} detected for live title/status checks.`;
  }
}

const addResult = (source, type, value, line = 0) => {
  const dedupKey = `${source}|${line}|${type}|${value}`;
  if (state.dedupKeys.has(dedupKey)) return;
  state.dedupKeys.add(dedupKey);

  const risk = classifyFinding(type, value);
  state.allData.push({ source, type, value, line, ...risk });
  if (type === "endpoint") state.endpoints.add(value);
  if (type === "secret") state.secrets.add(value);
  if (type === "file") state.files.add(value);
  if (type === "parameter") state.parameters.add(value);
  updateStats();
};

function renderPriorityDashboard() {
  if (!priorityDashboard) return;
  const groups = { critical: [], high: [], medium: [], low: [] };
  getVisibleFindings().forEach(item => {
    const severity = item.severity || "low";
    if (groups[severity]) groups[severity].push(item);
  });

  const labels = [
    ["critical", "Critical"],
    ["high", "High"],
    ["medium", "Medium"],
    ["low", "Low"]
  ];

  priorityDashboard.innerHTML = labels.map(([key, label]) => {
    const items = groups[key];
    const top = items.slice(0, 4).map(item =>
      `<li>${escapeHtml(item.type)}: ${escapeHtml(String(item.value).slice(0, 120))}</li>`
    ).join("");
    return `
      <div class="priority-card priority-${key}">
        <h3><span>${label}</span><span class="priority-count">${items.length}</span></h3>
        <ul>${top || "<li>No findings in this bucket.</li>"}</ul>
      </div>
    `;
  }).join("");
  priorityDashboard.style.display = getVisibleFindings().length ? "grid" : "none";
}

function renderHostResults() {
  if (!hostResultsSection) return;
  if (!state.hostChecks.length) {
    hostResultsSection.style.display = "none";
    hostResultsSection.innerHTML = "";
    return;
  }

  const rows = state.hostChecks.map(item => `
    <div class="host-row">
      <span class="recon-badge ${item.status >= 200 && item.status < 400 ? "good" : item.status >= 400 ? "warn" : "bad"}">${escapeHtml(item.status)}</span>
      <div>
        <div class="host-title">${escapeHtml(item.title || "No title")}</div>
        <div class="host-url">${escapeHtml(item.url)}</div>
      </div>
      <div class="host-meta">${escapeHtml(item.length)} bytes</div>
      <div class="host-meta">${escapeHtml((item.tech || []).join(", ") || "unknown")}</div>
      <div class="host-meta">${item.takeover ? `<span style="color:#ff4444;font-weight:bold;">TAKEOVER: ${escapeHtml(item.takeover)}</span>` : ""}</div>
    </div>
  `).join("");

  const clusters = buildDuplicateClusters(state.hostChecks)
    .slice(0, 6)
    .map(group => `<div class="host-meta">${escapeHtml(group.key)} - ${group.items.length} hosts</div>`)
    .join("");

  hostResultsSection.innerHTML = `
    <h3>Imported Host Live Check</h3>
    <div class="host-grid">${rows}</div>
    ${clusters ? `<h3 style="margin-top: var(--space-md);">Duplicate Response Clusters</h3>${clusters}` : ""}
  `;
  hostResultsSection.style.display = "block";
}

function buildDuplicateClusters(items) {
  const groups = {};
  items.forEach(item => {
    const key = `${item.status}:${item.length}:${(item.title || "no-title").toLowerCase()}:${item.hash || "no-hash"}`;
    if (!groups[key]) groups[key] = [];
    groups[key].push(item);
  });
  return Object.entries(groups)
    .filter(([, group]) => group.length > 1)
    .map(([key, group]) => ({ key, items: group }))
    .sort((a, b) => b.items.length - a.items.length);
}

async function liveCheckImportedHosts(baseUrl) {
  const hosts = parseImportedHosts(subdomainInput?.value || "")
    .filter(origin => {
      try {
        const host = new URL(origin).hostname;
        return state.scopeRules.length ? isHostInScope(host, state.scopeRules) : true;
      } catch {
        return false;
      }
    })
    .slice(0, 80);

  state.hostChecks = [];
  renderHostResults();

  for (const origin of hosts) {
    if (state.isCrawlerStopped) break;
    try {
      const res = await fetchTarget(origin);
      const body = await res.text();
      const headersText = [...res.headers.entries()].map(([key, value]) => `${key}: ${value}`).join("\n");
      const takeover = checkTakeover(body, res.status);
      state.hostChecks.push({
        url: origin,
        status: res.status,
        title: extractTitle(body),
        length: body.length,
        server: getHeader(res.headers, "server"),
        tech: detectTechFromText(headersText, body),
        hash: hashText(body),
        takeover
      });
    } catch (error) {
      state.hostChecks.push({
        url: origin,
        status: "ERROR",
        title: error.message,
        length: 0,
        server: "",
        tech: [],
        hash: ""
      });
    }
    renderHostResults();
  }
}

const setProgress = (percent) => {
  const p = Math.round(percent);
  document.getElementById("progress-bar").style.width = `${p}%`;
  const textEl = document.getElementById("progress-percent");
  if (textEl) textEl.innerText = `${p}%`;
};

const startScan = async (maxDepth) => {
  let siteUrl = urlInput.value.trim();
  if (!siteUrl) return showToast("Enter a valid URL", "warn");
  if (!/^https?:\/\//i.test(siteUrl)) siteUrl = "https://" + siteUrl;
  siteUrl = normalizeUrl(siteUrl);
  const startHost = new URL(siteUrl).hostname.replace(/^www\./, "");
  state.scopeRules = parseScopeRules(scopeInput?.value || "");
  if (state.scopeRules.length && !isHostInScope(startHost, state.scopeRules)) {
    return showToast("Target URL is outside the scope list.", "warn");
  }

  state.scanned = 0;
  state.totalDiscovered = 0;
  state.totalToScan = 1;
  state.endpoints.clear();
  state.secrets.clear();
  state.files.clear();
  state.parameters.clear();
  state.allData = [];
  state.dedupKeys.clear();
  state.scannedUrls.clear();
  state.fetchFailures = [];
  state.scanDiagnostic = null;
  state.hostChecks = [];
  state.hiddenFindings.clear();
  state.findingNotes = {};
  state.findingTags = {};
  state.activeSeverityFilter = "all";
  document.querySelectorAll("[data-severity-filter]").forEach(btn => {
    btn.classList.toggle("active", btn.dataset.severityFilter === "all");
  });
  scannedJs.clear(); // Reset JS scan cache
  updateStats();
  renderPriorityDashboard();

  results.innerHTML = "";
  scanBtn.style.display = "none";
  document.getElementById("fullScanBtn").style.display = "none";
  stopScanBtn.style.display = "inline-block";
  stopScanBtn.disabled = false;
  state.isCrawlerStopped = false;

  document.getElementById("progress-container").style.display = "block";
  document.getElementById("filter-section").style.display = "none";
  exportActions.style.display = "none";
  status.innerText = maxDepth === 0 ? "Scanning single page..." : "Starting full recursive scan...";
  setProgress(5);

  try {
    await recursiveScan(siteUrl, maxDepth);
    await liveCheckImportedHosts(siteUrl);
    const importedUrls = parseImportedUrls(importedUrlInput?.value || "", siteUrl)
      .filter(importedUrl => {
        try {
          const host = new URL(importedUrl).hostname;
          const normalizedHost = host.replace(/^www\./, "");
          return state.scopeRules.length ? isHostInScope(normalizedHost, state.scopeRules) : (normalizedHost === startHost || normalizedHost.endsWith("." + startHost));
        } catch {
          return false;
        }
      })
      .slice(0, 150);

    for (const importedUrl of importedUrls) {
      if (state.isCrawlerStopped) break;
      await recursiveScan(importedUrl, 0, 0, startHost);
    }

    if (!state.isCrawlerStopped && state.fetchFailures.length && state.allData.length === 0) {
      state.scanDiagnostic = buildScanDiagnostic(siteUrl);
      status.innerText = state.scanDiagnostic.statusText;
    } else if (!state.isCrawlerStopped) {
      status.innerText = state.allData.length
        ? "Scan complete!"
        : "Scan complete, but no endpoints, secrets, parameters, or files were found.";
    } else {
      status.innerText = "Scan stopped manually.";
    }
    setProgress(100);
    document.getElementById("filter-section").style.display = "block";
    exportActions.style.display = "flex";
    renderPriorityDashboard();
    renderResults();
  } catch (e) {
    console.error(e);
    if (!state.isCrawlerStopped) {
      status.innerText = `Scan failed: ${e.message}. Check console for details.`;
    }
  }
  scanBtn.style.display = "inline-block";
  scanBtn.disabled = false;
  document.getElementById("fullScanBtn").style.display = "inline-block";
  document.getElementById("fullScanBtn").disabled = false;
  stopScanBtn.style.display = "none";
};

stopScanBtn.addEventListener("click", () => {
  state.isCrawlerStopped = true;
  stopScanBtn.disabled = true;
  status.innerText = "Stopping scan... Finishing current requests.";
});

scanBtn.addEventListener("click", () => startScan(0));
document.getElementById("fullScanBtn").addEventListener("click", () => startScan(1));

async function recursiveScan(url, maxDepth, currentDepth = 0, targetHost = null) {
  if (state.isCrawlerStopped) return;
  const normUrl = normalizeUrl(url);
  try {
    const currentUrlObj = new URL(normUrl);
    const currentHost = currentUrlObj.hostname.replace(/^www\./, "");
    if (!targetHost) targetHost = currentHost;

    if (state.scopeRules.length && !isHostInScope(currentHost, state.scopeRules)) {
      return;
    }

    if (!state.scopeRules.length && currentHost !== targetHost && !currentHost.endsWith("." + targetHost)) {
      return;
    }

    if (currentDepth > maxDepth || state.scannedUrls.has(normUrl)) return;
    state.scannedUrls.add(normUrl);
    state.scanned++;
    updateStats();

    status.innerText = `Scanning: ${normUrl}`;
    const estimatedTotal = Math.max(state.totalDiscovered, state.scanned + 1, state.totalToScan || 1);
    setProgress(Math.min(94, (state.scanned / estimatedTotal) * 100));

    await delay(window._CRAWLER_DELAY !== undefined ? window._CRAWLER_DELAY : CRAWLER_REQUEST_DELAY_MS);
    const res = await fetchTarget(normUrl);
    const contentType = getHeader(res.headers, "content-type");
    const rawContent = await res.text();
    const isJsAsset = /\.js(?:[?#]|$)/i.test(normUrl) || /javascript|ecmascript/i.test(contentType);
    const content = isJsAsset ? beautifyJavaScriptForScan(rawContent) : rawContent;
    const responseClass = classifyHttpResponse(res.status, content);
    if (!res.ok || responseClass.blocked || responseClass.effectiveStatus === 404) {
      let reason = `Skipped ${normUrl} (${res.status} ${res.statusText || "HTTP error"})`;
      if (responseClass.blocked) {
        reason = `Skipped ${normUrl} (${res.status} target protection blocked automated proxy requests)`;
      } else if (responseClass.note === "soft 404") {
        reason = `Skipped ${normUrl} (soft 404 page)`;
      } else if (responseClass.effectiveStatus === 404) {
        reason = `Skipped ${normUrl} (404 not found)`;
      }
      state.fetchFailures.push(reason);
      status.innerText = reason;
      return;
    }

    // Extract data with line numbers
    const foundEndpoints = extractEndpointsWithLines(content);
    const foundApiCalls = extractApiCallsWithLines(content, normUrl);
    const foundSecrets = extractSecretsWithLines(content);
    const foundFiles = extractFilesWithLines(content);

    [...foundEndpoints, ...foundApiCalls].forEach(e => {
      addResult(normUrl, "endpoint", e.value, e.line);
      // Sync - if endpoint looks like a file, add it to files tab too
      if (isInterestingFile(e.value)) {
        addResult(normUrl, "file", e.value, e.line);
      }
      // Parameter Discovery (Full endpoint with query)
      if (e.value.includes("?")) {
        addResult(normUrl, "parameter", e.value, e.line);
      }
    });

    foundSecrets.forEach(s => addResult(normUrl, "secret", s.value, s.line));

    foundFiles.forEach(f => {
      addResult(normUrl, "file", f.value, f.line);
    });

    // Discover more links/scripts
    const links = extractInternalLinks(content, normUrl);
    const scripts = extractScriptUrls(content, normUrl);
    const webpackChunks = extractWebpackChunks(content, normUrl);
    state.totalDiscovered += links.length + scripts.length + webpackChunks.length;
    state.totalToScan += links.length + scripts.length + webpackChunks.length;
    setProgress(Math.min(94, (state.scannedUrls.size / Math.max(state.totalToScan, 1)) * 100));

    for (const script of [...new Set([...scripts, ...webpackChunks])]) {
      if (state.isCrawlerStopped) break;
      await recursiveScan(script, maxDepth, currentDepth, targetHost);
    }

    if (currentDepth < maxDepth) {
      for (const link of links) {
        if (state.isCrawlerStopped) break;
        await recursiveScan(link, maxDepth, currentDepth + 1, targetHost);
      }
    }
  } catch (e) {
    state.fetchFailures.push(`Failed to scan ${normUrl}. ${e.message}`);
    status.innerText = state.fetchFailures[state.fetchFailures.length - 1];
    console.warn(`Failed to scan ${normUrl}:`, e);
  }
}

function buildLineIndex(content) {
  const index = [0];
  for (let i = 0; i < content.length; i++) {
    if (content[i] === "\n") index.push(i + 1);
  }
  return index;
}

function getLineNumberFast(lineIndex, charPos) {
  let lo = 0, hi = lineIndex.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (lineIndex[mid] <= charPos) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1;
}

function beautifyJavaScriptForScan(content) {
  try {
    if (window.js_beautify && content.length < 2_000_000) {
      return window.js_beautify(content, { indent_size: 2, preserve_newlines: true, max_preserve_newlines: 2 });
    }
  } catch (error) {
    console.warn("JS beautify failed, scanning original content:", error);
  }
  return content;
}

function extractEndpointsWithLines(content) {
  const lineIndex = buildLineIndex(content);
  const matches = [...content.matchAll(endpointRegex)];
  return matches.map(m => ({
    value: m[1],
    line: getLineNumberFast(lineIndex, m.index)
  })).filter(e => {
    // Filter out Webhooks from standard endpoints so they show as Secrets (Warning color)
    if (e.value.includes("hooks.slack.com") || e.value.includes("discord.com/api/webhooks")) return false;
    return filterUrl(e.value);
  });
}

function extractApiCallsWithLines(content, baseUrl) {
  const found = [];
  const lineIndex = buildLineIndex(content);
  const patterns = [
    /\bfetch\s*\(\s*["'`]([^"'`]+)["'`]/gi,
    /\baxios\.(?:get|post|put|patch|delete|request)\s*\(\s*["'`]([^"'`]+)["'`]/gi,
    /\b(?:get|post|put|patch|delete)\s*\(\s*["'`](\/[^"'`]+)["'`]/gi,
    /\.open\s*\(\s*["'`](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)["'`]\s*,\s*["'`]([^"'`]+)["'`]/gi,
    /\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*["'`]([^"'`]+)["'`]/gis
  ];

  patterns.forEach(pattern => {
    let match;
    while ((match = pattern.exec(content)) !== null) {
      const raw = match[2] || match[1];
      if (!raw) continue;
      let processedRaw = raw;
      let isDynamic = false;
      if (raw.includes("${")) {
        processedRaw = raw.split("${")[0];
        isDynamic = true;
        if (processedRaw.length < 2) continue;
      }
      try {
        const value = normalizeUrl(new URL(processedRaw, baseUrl).href);
        const urlValue = isDynamic ? `${value}[DYNAMIC]` : value;
        if (filterUrl(urlValue)) {
          found.push({
            value: urlValue,
            line: getLineNumberFast(lineIndex, match.index)
          });
        }
      } catch { }
    }
  });

  return found;
}

function extractSecretsWithLines(content) {
  // Fast-Path: If nothing looks like a secret, skip 20+ regex scans
  if (!secretTrigger.test(content) && !loadSettings().customSecrets) return [];

  const found = [];
  const lineIndex = buildLineIndex(content);
  for (const [name, regex] of Object.entries(getSecretPatterns())) {
    const matches = [...content.matchAll(regex)];
    matches.forEach(m => {
      // Prefer capture group if present (m[1]), otherwise use whole match (m[0])
      let val = (m[1] || m[0]).trim();

      // Anti-URL & False Positive Filter
      // skip long paths unless it's a URI
      if (val.includes("/") && val.split("/").length > 3 && !val.includes("://")) return;
      if (blockedSecretKeywords.some(bk => val.includes(bk))) return;
      if (val.length < 8 || val.length > 500) return;

      found.push({
        value: `${name}: ${val}`,
        line: getLineNumberFast(lineIndex, m.index)
      });
    });
  }
  return found;
}

function extractFilesWithLines(content) {
  // Path-Fidelity File Detection - Updated to prioritize absolute URLs and avoid internal protocol truncation
  const fileRegex = /["']((?:https?:\/\/)?[^"'\s<>]*\.(?:json|xml|config|env|yaml|yml|sql|db|bak|zip|tar|gz|7z|pdf|doc|docx|js|html|php|asp|aspx|jsp|txt)(?:\?[^"'\s]*)?)["'\s]/gi;
  const matches = [...content.matchAll(fileRegex)];
  const lineIndex = buildLineIndex(content);

  return matches.map(m => ({
    value: m[1],
    line: getLineNumberFast(lineIndex, m.index)
  })).filter(f => {
    if (!f.value || f.value.startsWith(".")) return false;
    // Length check to avoid massive false positives
    if (f.value.length < 4 || f.value.length > 250) return false;
    return true;
  });
}

function extractInternalLinks(html, baseUrl) {
  const directoryBase = directoryfyUrl(baseUrl);
  const currentUrlObj = new URL(directoryBase);
  const targetHost = currentUrlObj.hostname.replace(/^www\./, ""); // Base domain comparison

  const re = /href=["']([^"']+)["']/gi;
  const links = [];
  let match;
  while ((match = re.exec(html)) !== null) {
    try {
      const url = new URL(match[1], directoryBase);
      const linkHost = url.hostname.replace(/^www\./, "");

      // Flexible Domain Matching (Allow subdomains and www)
      if ((linkHost === targetHost || url.hostname.endsWith("." + targetHost)) &&
        !url.pathname.endsWith(".js") && !url.pathname.endsWith(".css")) {
        links.push(normalizeUrl(url.href.split("#")[0]));
      }
    } catch { }
  }
  return [...new Set(links)];
}

function extractScriptUrls(html, baseUrl) {
  const directoryBase = directoryfyUrl(baseUrl);
  const currentUrlObj = new URL(directoryBase);
  const targetHost = currentUrlObj.hostname.replace(/^www\./, "");

  const re = /<script[^>]+src=["']([^"']+)["']/gi;
  const scripts = [];
  let match;
  while ((match = re.exec(html)) !== null) {
    try {
      const url = new URL(match[1], directoryBase);
      const scriptHost = url.hostname.replace(/^www\./, "");

      // Flexible Domain Matching for Scripts
      if (scriptHost === targetHost || url.hostname.endsWith("." + targetHost) || !url.hostname) {
        scripts.push(normalizeUrl(url.href));
      }
    } catch { }
  }
  return [...new Set(scripts)];
}

function extractWebpackChunks(content, baseUrl) {
  const chunks = new Set();
  let origin = "";
  try {
    origin = new URL(baseUrl).origin;
  } catch {
    return [];
  }

  const staticJsRefs = content.match(/["']((?:\/static\/js\/|\/assets\/js\/|\/js\/|static\/js\/|assets\/js\/|chunks\/)[^"'\s]+\.js)["']/gi) || [];
  staticJsRefs.forEach(ref => {
    const clean = ref.replace(/["']/g, "");
    try { chunks.add(new URL(clean, origin).href); } catch { }
  });

  const filenameRefs = content.match(/["']([a-f0-9]{8,}\.[a-f0-9]{8,}\.js)["']/gi) || [];
  filenameRefs.forEach(ref => {
    const clean = ref.replace(/["']/g, "");
    try { chunks.add(new URL(clean, directoryfyUrl(baseUrl)).href); } catch { }
  });

  const chunkMapMatch = content.match(/\{(?:\d+\s*:\s*"[a-f0-9]+"(?:,|\s))+\s*\}/i);
  const jsSuffixMatch = content.match(/\+\s*"([^"]*\.js)"/i);
  if (chunkMapMatch && jsSuffixMatch) {
    const ids = chunkMapMatch[0].match(/"([a-f0-9]+)"/gi) || [];
    ids.slice(0, 60).forEach(id => {
      try { chunks.add(new URL(`${id.replace(/"/g, "")}${jsSuffixMatch[1]}`, directoryfyUrl(baseUrl)).href); } catch { }
    });
  }

  return [...chunks];
}

// Navigation & Tool Switching
const navCrawler = document.getElementById("navCrawler");
const navProber = document.getElementById("navProber");
const navRecon = document.getElementById("navRecon");
const navSettings = document.getElementById("navSettings");
const crawlerSection = document.getElementById("crawler-section");
const proberSection = document.getElementById("prober-section");
const reconSection = document.getElementById("recon-section");
const settingsPanel = document.getElementById("settings-panel");

function showMainPanel(panel) {
  crawlerSection.style.display = panel === "crawler" ? "block" : "none";
  proberSection.style.display = panel === "prober" ? "block" : "none";
  reconSection.style.display = panel === "recon" ? "block" : "none";
  if (settingsPanel) settingsPanel.style.display = panel === "settings" ? "block" : "none";
  navCrawler.classList.toggle("active", panel === "crawler");
  navProber.classList.toggle("active", panel === "prober");
  navRecon.classList.toggle("active", panel === "recon");
  navSettings?.classList.toggle("active", panel === "settings");
}

navCrawler.onclick = () => {
  showMainPanel("crawler");
};

navProber.onclick = () => {
  showMainPanel("prober");
};

navRecon.onclick = () => {
  showMainPanel("recon");
};

navSettings?.addEventListener("click", () => showMainPanel("settings"));

// v2.0: Probing & Parameter Discovery Logic
const probeBtn = document.getElementById("probeBtn");
const stopProbeBtn = document.getElementById("stopProbeBtn");
const proberResults = document.getElementById("prober-results");
const proberUrlInput = document.getElementById("proberUrlInput");
const proberProgressBar = document.getElementById("prober-progress-bar");
const proberProgressContainer = document.getElementById("prober-progress-container");
const proberStatus = document.getElementById("prober-status");

// Prober Stats Elements
const proberStat200 = document.getElementById("prober-stat-200");
const proberStat403 = document.getElementById("prober-stat-403");
const proberStat404 = document.getElementById("prober-stat-404");
const proberFilterSection = document.getElementById("prober-filter-section");

// v2.0 Length Filters
const proberLengthFilters = document.getElementById("prober-length-filters");
const proberIncludeLength = document.getElementById("proberIncludeLength");
const proberExcludeLength = document.getElementById("proberExcludeLength");
const customProberPanel = document.getElementById("custom-prober-panel");
const customPathInput = document.getElementById("customPathInput");
const proberWordlistFile = document.getElementById("proberWordlistFile");

let proberData = []; // v2.0: Store results for filtering
let activeProberFilter = "all";
let isProberStopped = false;

function parseCustomPaths(raw) {
  return String(raw || "")
    .split(/\r?\n|,/)
    .map(path => path.trim())
    .filter(Boolean)
    .filter(path => !/^https?:\/\//i.test(path))
    .map(path => path.startsWith("/") ? path : `/${path}`)
    .filter(path => path.length <= 180 && !/[\s<>]/.test(path));
}

probeBtn.onclick = async () => {
  let url = proberUrlInput.value.trim();
  if (!url) return showToast("Enter a URL to probe", "warn");
  if (!/^https?:\/\//i.test(url)) url = "https://" + url;

  try {
    // v2.0 Fix: Strip trailing slash from origin to prevent // in paths
    const origin = new URL(url).origin.replace(/\/+$/, "");
    proberResults.innerHTML = "";
    proberResults.style.display = "block";
    proberProgressContainer.style.display = "block";
    proberFilterSection.style.display = "flex"; // v2.0: Enable live filtering during scan
    proberLengthFilters.style.display = "flex"; // Show length filters
    customProberPanel.style.display = "block";
    proberProgressBar.style.width = "0%";
    const probPercentEl = document.getElementById("prober-progress-percent");
    if (probPercentEl) probPercentEl.innerText = "0%";

    // Reset Stats & Data
    proberData = [];
    let stats = { 200: 0, 403: 0, 404: 0 };
    proberStat200.innerText = "0";
    proberStat403.innerText = "0";
    proberStat404.innerText = "0";

    probeBtn.style.display = "none";
    stopProbeBtn.style.display = "inline-block";
    stopProbeBtn.disabled = false;
    isProberStopped = false;

    let completed = 0;
    const customPaths = parseCustomPaths(customPathInput.value);
    const pathsToProbe = [...new Set([...sensitivePaths, ...customPaths])];
    const total = pathsToProbe.length;
    let gotAnyProbeResponse = false;
    const recentResults = [];
    let stoppedForProtection = false;

    await mapWithConcurrency(pathsToProbe, getRequestConcurrency(), async (path) => {
      if (isProberStopped || stoppedForProtection) return;
      completed++;
      const percent = Math.round((completed / total) * 100);
      proberProgressBar.style.width = percent + "%";
      const probPercentEl = document.getElementById("prober-progress-percent");
      if (probPercentEl) probPercentEl.innerText = percent + "%";
      proberStatus.innerText = `Probing: ${path} (${completed}/${total})`;

      // Ensure path starts with / but origin doesn't end with it
      const cleanPath = path.startsWith("/") ? path : "/" + path;
      const fullUrl = origin + cleanPath;
      try {
        await delay(window._PROBER_DELAY !== undefined ? window._PROBER_DELAY : PROBER_REQUEST_DELAY_MS);
        const res = await fetchTarget(fullUrl, { method: 'GET' });
        gotAnyProbeResponse = true;
        const text = await res.text();
        const responseClass = classifyHttpResponse(res.status, text);
        const status = responseClass.effectiveStatus;
        const length = text.length;

        // Update stats
        if (status === 200) stats[200]++;
        else if (status === 403 || status === 401) stats[403]++;
        else stats[404]++; // 404 and others

        proberStat200.innerText = stats[200];
        proberStat403.innerText = stats[403];
        proberStat404.innerText = stats[404];

        const resultItem = { path, status, fullUrl, length, note: responseClass.note, body: text };
        proberData.push(resultItem);

        // Live update UI if it matches current filter
        if (doesItemMatchFilters(resultItem)) {
          renderProberLine(path, status, fullUrl, length, responseClass.note, text);
        }

        recentResults.push(responseClass.blocked ? 1 : 0);
        if (recentResults.length > 5) recentResults.shift();
        const recentBlockRate = recentResults.reduce((a, b) => a + b, 0) / recentResults.length;
        if (recentResults.length >= 3 && recentBlockRate >= 0.6) {
          proberStatus.innerText = "Probing paused: target protection is blocking automated requests.";
          stoppedForProtection = true;
        }
      } catch (e) {
        if (!gotAnyProbeResponse) {
          const message = e.message || "Unknown fetch error";
          proberStatus.innerText = `Prober could not fetch the target. ${message}`;
          renderProberLine(path, "ERROR", fullUrl, 0, "fetch failed");
          stoppedForProtection = true;
          return;
        }

        stats[404]++;
        proberStat404.innerText = stats[404];
        const resultItem = { path, status: "ERROR", fullUrl, length: 0, note: "fetch failed" };
        proberData.push(resultItem);

        if (doesItemMatchFilters(resultItem)) {
          renderProberLine(path, "ERROR", fullUrl, 0, "fetch failed");
        }
      }
    });
    if (stoppedForProtection) {
      proberStatus.innerText = `Probing paused after ${completed}/${total} paths because target protection blocked repeated requests.`;
    } else if (isProberStopped) {
      proberStatus.innerText = `Probing stopped manually.`;
    } else if (!isProberStopped) {
      proberStatus.innerText = `Probing complete! ${total} paths checked.`;
    }
    proberFilterSection.style.display = "flex";
  } catch (e) {
    showToast("Invalid URL", "error");
  } finally {
    probeBtn.style.display = "inline-block";
    stopProbeBtn.style.display = "none";
  }
};

stopProbeBtn.onclick = () => {
  isProberStopped = true;
  stopProbeBtn.disabled = true;
  proberStatus.innerText = "Stopping prober... Finishing current request.";
};

const filterProberResults = (filter) => {
  if (filter) activeProberFilter = filter;
  proberResults.innerHTML = "";

  proberData.forEach(item => {
    if (doesItemMatchFilters(item)) {
      renderProberLine(item.path, item.status, item.fullUrl, item.length, item.note, item.body);
    }
  });

  // Update button active state
  document.querySelectorAll("[data-prober-filter]").forEach(btn => {
    btn.classList.toggle("active", btn.getAttribute("data-prober-filter") === activeProberFilter);
  });
};

function doesItemMatchFilters(item) {
  // 1. Check Status Filter
  const statusNum = parseInt(item.status);
  let statusMatch = false;

  if (activeProberFilter === "all") statusMatch = true;
  else if (activeProberFilter === "200" && statusNum === 200) statusMatch = true;
  else if (activeProberFilter === "403" && (statusNum === 403 || statusNum === 401)) statusMatch = true;
  else if (activeProberFilter === "404" && (statusNum === 404 || item.status === "ERROR")) statusMatch = true;

  if (!statusMatch) return false;

  // 2. Check Length Filters (Include / Exclude)
  const incStrings = proberIncludeLength.value.split(',').map(s => s.trim()).filter(s => s !== "");
  const excStrings = proberExcludeLength.value.split(',').map(s => s.trim()).filter(s => s !== "");

  const itemLenStr = String(item.length);

  // If include list has items, item.length MUST be in the list
  if (incStrings.length > 0 && !incStrings.includes(itemLenStr)) {
    return false;
  }

  // If exclude list has items, item.length MUST NOT be in the list
  if (excStrings.length > 0 && excStrings.includes(itemLenStr)) {
    return false;
  }

  return true;
}

// Bind live length filtering
proberIncludeLength.addEventListener('input', () => filterProberResults());
proberExcludeLength.addEventListener('input', () => filterProberResults());

// Prober Filter Click Event
document.querySelectorAll("#prober-filter-section .tab-btn").forEach(btn => {
  btn.onclick = () => filterProberResults(btn.getAttribute("data-prober-filter"));
});

const proberPresetPaths = {
  admin: ["/admin", "/admin/login", "/administrator", "/dashboard", "/manage", "/console"],
  api: ["/swagger.json", "/openapi.json", "/api-docs", "/v3/api-docs", "/swagger-ui.html", "/graphql"],
  cloud: ["/.aws/credentials", "/.aws/config", "/service-account-key.json", "/firebase-config.json", "/.env"],
  backup: ["/backup.zip", "/backup.sql", "/database.sql", "/dump.sql", "/site.tar.gz", "/www.zip"],
  wordpress: ["/wp-config.php", "/wp-admin/", "/wp-json/wp/v2/users", "/xmlrpc.php", "/wp-content/debug.log"],
  spring: ["/actuator", "/actuator/env", "/actuator/heapdump", "/actuator/mappings", "/actuator/configprops"],
  laravel: ["/.env", "/storage/logs/laravel.log", "/telescope", "/horizon/dashboard", "/vendor/composer/installed.json"]
};

document.querySelectorAll(".preset-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    if (!btn.dataset.preset) return;
    const preset = btn.dataset.preset;
    const existing = parseCustomPaths(customPathInput.value);
    const merged = [...new Set([...existing, ...(proberPresetPaths[preset] || [])])];
    customPathInput.value = merged.join("\n");
  });
});

proberWordlistFile?.addEventListener("change", async (event) => {
  const file = event.target.files?.[0];
  if (!file) return;
  try {
    const text = await file.text();
    const imported = parseCustomPaths(text);
    const existing = parseCustomPaths(customPathInput.value);
    customPathInput.value = [...new Set([...existing, ...imported])].join("\n");
    showToast(`Imported ${imported.length} prober paths.`, "success");
  } catch (error) {
    showToast(`Wordlist import failed: ${error.message}`, "error");
  } finally {
    event.target.value = "";
  }
});

function renderProberLine(path, status, fullUrl, length, note = "", body = "") {
  const line = document.createElement("div");
  line.className = "prober-line";

  let statusClass = "status-error"; // Default Red
  if (status === 200) statusClass = "status-200"; // Green
  else if (status === 403) statusClass = "status-403"; // Orange
  else if (status === 401) statusClass = "status-401"; // Dark Orange
  else if (status === 404) statusClass = "status-404"; // Red (Specified)

  const lengthDisplay = length !== undefined ? `<span class="prober-length" style="color:var(--text-dim); font-size:0.85em; font-family: monospace;">[${length}]</span>` : '';
  const noteDisplay = note ? `<span class="prober-note" style="color:var(--text-dim); font-size:0.78em; margin-left: 8px;">${escapeHtml(note)}</span>` : "";

  let openBtnHtml = "";
  if (status === 200) {
    openBtnHtml = `<a href="${escapeHtml(fullUrl)}" target="_blank" class="prober-open-btn-200" style="margin-left: 0;">OPEN🔗</a>`;
  } else if (status === 403 || status === 401) {
    openBtnHtml = `<a href="${escapeHtml(fullUrl)}" target="_blank" class="prober-open-btn-403" style="margin-left: 0;">OPEN🔗</a>`;
  }
  const viewerHtml = body && (status === 200 || status === 403 || status === 401)
    ? `<details style="width:100%;margin-top:8px;"><summary style="cursor:pointer;color:var(--accent-cyan);font-size:0.85em;">Response body</summary><pre style="white-space:pre-wrap;max-height:260px;overflow:auto;background:rgba(0,0,0,0.35);padding:10px;border-radius:8px;margin-top:8px;">${escapeHtml(String(body).slice(0, 12000))}</pre></details>`
    : "";

  line.innerHTML = `
    <span class="prober-path" style="flex: 1; word-break: break-all; padding-right: 15px;">${escapeHtml(path)}${noteDisplay}</span>
    <div style="display: flex; align-items: center; justify-content: flex-end; flex-shrink: 0;">
      <span class="prober-status ${statusClass}" style="width: 50px; text-align: center;">${status}</span>
      <div style="width: 75px; text-align: center; margin-left: 5px;">${openBtnHtml}</div>
      <div style="width: 75px; text-align: right; margin-left: 5px;">${lengthDisplay}</div>
    </div>
    ${viewerHtml}
  `;

  // Remove loading text if first result
  if (proberResults.querySelector(".status")) proberResults.innerHTML = "";
  proberResults.appendChild(line);
}

// Bug Bounty Recon Suite
const reconUrlInput = document.getElementById("reconUrlInput");
const reconUrlList = document.getElementById("reconUrlList");
const startReconBtn = document.getElementById("startReconBtn");
const stopReconBtn = document.getElementById("stopReconBtn");
const reconProgressContainer = document.getElementById("recon-progress-container");
const reconProgressBar = document.getElementById("recon-progress-bar");
const reconProgressPercent = document.getElementById("recon-progress-percent");
const reconStatus = document.getElementById("recon-status");
const reconSummary = document.getElementById("recon-summary");
const reconResults = document.getElementById("recon-results");

let isReconStopped = false;

const riskyParamNames = [
  "url", "uri", "redirect", "redirect_url", "return", "returnurl", "return_url",
  "next", "continue", "dest", "destination", "target", "callback", "callback_url",
  "path", "file", "filename", "template", "page", "debug", "test", "admin",
  "id", "uid", "user", "account", "token", "access_token", "apikey", "api_key",
  "key", "secret", "auth", "jwt", "session", "role", "sort", "q", "query", "search"
];

const interestingBodySignals = [
  { label: "Stack Trace", pattern: /stack trace|traceback|exception|at [\w.$]+\(|\.java:\d+|\.php on line \d+/i },
  { label: "Debug Mode", pattern: /debug\s*[:=]\s*true|debug mode|development mode|devtools/i },
  { label: "SQL Error", pattern: /sql syntax|mysql|postgresql|ora-\d+|sqlite|odbc|jdbc/i },
  { label: "Cloud Key", pattern: /aws_access_key|aws_secret|firebase|s3:\/\/|google_api_key/i },
  { label: "Internal Host", pattern: /\b(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)\b/i },
  { label: "Admin Surface", pattern: /\b(admin|dashboard|panel|superuser|root)\b/i }
];

function setReconProgress(percent) {
  const p = Math.max(0, Math.min(100, Math.round(percent)));
  reconProgressBar.style.width = `${p}%`;
  reconProgressPercent.innerText = `${p}%`;
}

function setReconStatus(message) {
  reconStatus.innerText = message;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function badge(label, tone = "info") {
  return `<span class="recon-badge ${tone}">${escapeHtml(label)}</span>`;
}

function codeValue(value, options = {}) {
  const text = String(value ?? "");
  const limit = options.limit || 160;
  const escaped = escapeHtml(text);

  if (!text) return badge("not set", "warn");
  if (text.length <= limit) {
    return `<span class="recon-code">${escaped}</span>`;
  }

  return `
    <div class="recon-preview recon-code">${escapeHtml(text.slice(0, limit))}...</div>
    <details class="recon-details">
      <summary>Show full value (${text.length} chars)</summary>
      <pre>${escaped}</pre>
    </details>
  `;
}

function urlLine(url) {
  return `<div class="recon-url-line recon-code">${escapeHtml(url)}</div>`;
}

function getHeader(headers, name) {
  return headers.get(name) || headers.get(name.toLowerCase()) || "";
}

function parseReconUrls(raw, baseUrl) {
  const found = new Set();
  const origin = new URL(baseUrl).origin;
  const absoluteMatches = raw.match(/https?:\/\/[^\s"'<>]+/gi) || [];
  absoluteMatches.forEach(url => found.add(normalizeUrl(url.replace(/[),.;\]]+$/, ""))));

  raw.split(/\r?\n/).forEach(line => {
    const trimmed = line.trim();
    if (!trimmed || /^https?:\/\//i.test(trimmed)) return;
    if (trimmed.startsWith("/")) {
      try {
        found.add(normalizeUrl(new URL(trimmed, origin).href));
      } catch { }
    }
  });

  return [...found];
}

function renderReconCard(title, icon, rows, tone = "info") {
  const card = document.createElement("div");
  card.className = `recon-card recon-card-${tone}`;

  const header = document.createElement("h3");
  header.innerHTML = `<i class="${icon}"></i><span>${escapeHtml(title)}</span>`;
  card.appendChild(header);

  rows.forEach(([key, value]) => {
    const row = document.createElement("div");
    row.className = "recon-row";
    row.innerHTML = `
      <div class="recon-key">${escapeHtml(key)}</div>
      <div class="recon-value">${value}</div>
    `;
    card.appendChild(row);
  });

  reconResults.appendChild(card);
}

function renderReconSummary(metrics) {
  reconSummary.innerHTML = metrics.map(item => `
    <div class="recon-metric recon-metric-${escapeHtml(item.tone || "info")}">
      <span class="recon-metric-label">${escapeHtml(item.label)}</span>
      <span class="recon-metric-value">${escapeHtml(item.value)}</span>
      <span class="recon-metric-note">${escapeHtml(item.note || "")}</span>
    </div>
  `).join("");
  reconSummary.style.display = "grid";
}

function analyzeSecurityHeaders(res) {
  const headers = res.headers;
  const checks = [
    ["Content-Security-Policy", getHeader(headers, "content-security-policy")],
    ["Strict-Transport-Security", getHeader(headers, "strict-transport-security")],
    ["X-Frame-Options", getHeader(headers, "x-frame-options")],
    ["X-Content-Type-Options", getHeader(headers, "x-content-type-options")],
    ["Referrer-Policy", getHeader(headers, "referrer-policy")],
    ["Permissions-Policy", getHeader(headers, "permissions-policy")],
    ["Cross-Origin-Opener-Policy", getHeader(headers, "cross-origin-opener-policy")],
    ["Cross-Origin-Resource-Policy", getHeader(headers, "cross-origin-resource-policy")]
  ];

  const missing = checks.filter(([, value]) => !value).map(([name]) => name);
  const presentRows = checks.map(([name, value]) => [
    name,
    value
      ? `${badge("present", "good")} ${codeValue(value)}`
      : badge("missing", "bad")
  ]);

  const csp = getHeader(headers, "content-security-policy");
  const hsts = getHeader(headers, "strict-transport-security");
  const xcto = getHeader(headers, "x-content-type-options");
  const cookieHeaders = [];
  for (let i = 0; i < 20; i++) {
    const h = headers.get(`x-web-x-sider-set-cookie-${i}`);
    if (!h) break;
    cookieHeaders.push(h);
  }
  const cookieHeader = cookieHeaders.join("; ");
  const weak = [];

  const cspWarnings = analyzeCspHeader(csp);
  weak.push(...cspWarnings);
  if (hsts && !/max-age=(?:31536000|[4-9]\d{7,})/i.test(hsts)) weak.push("HSTS max-age looks low");
  if (!hsts) weak.push("HSTS header missing");
  if (xcto && !/nosniff/i.test(xcto)) weak.push("X-Content-Type-Options is not nosniff");
  if (cookieHeader) {
    if (!/;\s*secure/i.test(cookieHeader)) weak.push("Set-Cookie missing Secure");
    if (!/;\s*httponly/i.test(cookieHeader)) weak.push("Set-Cookie missing HttpOnly");
    if (!/;\s*samesite=/i.test(cookieHeader)) weak.push("Set-Cookie missing SameSite");
  }

  const cspRows = csp ? [["CSP Analyzer", renderCspAnalysis(csp, cspWarnings)]] : [];
  renderReconCard("Security Headers", "fas fa-lock", [
    ["Missing", missing.length ? missing.map(item => badge(item, "bad")).join("") : badge("none", "good")],
    ...presentRows,
    ...cspRows,
    ["Weak Signals", weak.length ? weak.map(item => badge(item, "warn")).join("") : badge("none spotted", "good")]
  ], missing.length || weak.length ? "warn" : "good");

  return { missing, weak };
}

function analyzeCspHeader(csp) {
  if (!csp) return ["CSP header missing"];
  const warnings = [];
  if (/unsafe-inline/i.test(csp)) warnings.push("CSP allows unsafe-inline scripts/styles");
  if (/unsafe-eval/i.test(csp)) warnings.push("CSP allows unsafe-eval");
  if (/(^|[\s;])\*(?:[\s;]|$)|https:\/\/\*/i.test(csp)) warnings.push("CSP allows wildcard sources");
  if (/\bdata:/i.test(csp)) warnings.push("CSP allows data: sources");
  if (/\bblob:/i.test(csp)) warnings.push("CSP allows blob: sources");
  if (/\bhttp:/i.test(csp)) warnings.push("CSP allows plain HTTP sources");
  if (!/object-src/i.test(csp)) warnings.push("CSP missing object-src");
  if (!/base-uri/i.test(csp)) warnings.push("CSP missing base-uri");
  if (!/frame-ancestors/i.test(csp)) warnings.push("CSP missing frame-ancestors");
  return warnings;
}

function renderCspAnalysis(csp, warnings) {
  const directives = csp.split(";").map(part => part.trim()).filter(Boolean);
  return `
    <details class="recon-details">
      <summary>${escapeHtml(directives.length)} directives, ${escapeHtml(warnings.length)} weaknesses</summary>
      <pre>${escapeHtml(directives.join("\n"))}</pre>
      ${warnings.length ? `<div>${warnings.map(item => badge(item, "warn")).join("")}</div>` : ""}
    </details>
  `;
}

function buildCorsPoc(url) {
  return `<script>
fetch('${url.replace(/'/g, "%27")}', {credentials:'include'})
  .then(r => r.text())
  .then(d => document.write(d));
<\/script>`;
}

async function analyzeCors(url) {
  const target = new URL(url);
  const bareHost = target.hostname.replace(/^www\./, "");
  const testOrigins = [
    "https://evil.example",
    "null",
    `${target.protocol}//${bareHost}.evil.example`,
    `${target.protocol}//evil-${bareHost}`,
    `http://${target.hostname}`
  ];
  const rows = [];
  const risks = [];

  for (const origin of testOrigins) {
    if (isReconStopped) break;
    try {
      const res = await fetchTarget(url, { proxyParams: { origin } });
      const acao = getHeader(res.headers, "access-control-allow-origin");
      const acac = getHeader(res.headers, "access-control-allow-credentials");
      const exposed = acao || "not set";
      let tone = "good";
      let verdict = "not reflected";

      if (acao === "*" || acao === origin || acao === "null") {
        tone = acac.toLowerCase() === "true" ? "bad" : "warn";
        verdict = acac.toLowerCase() === "true" ? "credential risk" : "open origin";
        risks.push(`${origin}: ${verdict}`);
      }

      rows.push([
        origin,
        `${badge(verdict, tone)} <span class="recon-label-inline">ACAO</span> ${codeValue(exposed, { limit: 80 })} <span class="recon-label-inline">ACAC</span> ${codeValue(acac || "not set", { limit: 80 })}`
      ]);
    } catch (error) {
      rows.push([origin, badge(error.message, "bad")]);
    }
  }

  if (risks.length) {
    rows.push(["HTML PoC", `<pre class="recon-code">${escapeHtml(buildCorsPoc(url))}</pre>`]);
  }
  renderReconCard("CORS Check", "fas fa-share-nodes", rows, risks.length ? "warn" : "good");
  return risks;
}

function detectTech(url, res, body) {
  const headers = res.headers;
  const text = body.slice(0, 250000);
  const found = new Set();
  const checks = [
    ["Cloudflare", /cloudflare/i, `${getHeader(headers, "server")} ${getHeader(headers, "cf-ray")}`],
    ["AWS", /x-amz-|amazonaws|cloudfront/i, `${getHeader(headers, "server")} ${getHeader(headers, "x-amz-cf-id")} ${text}`],
    ["Vercel", /vercel/i, `${getHeader(headers, "server")} ${getHeader(headers, "x-vercel-id")} ${text}`],
    ["Netlify", /netlify/i, `${getHeader(headers, "server")} ${text}`],
    ["Next.js", /_next\/|next-route|x-nextjs/i, `${text} ${getHeader(headers, "x-nextjs-cache")}`],
    ["React", /react(?:\.production)?\.min\.js|data-reactroot|__REACT_DEVTOOLS/i, text],
    ["Vue", /vue(?:\.runtime)?\.|data-v-|__VUE__/i, text],
    ["Angular", /ng-version|angular(?:\.min)?\.js/i, text],
    ["Laravel", /laravel_session|XSRF-TOKEN|\/vendor\/laravel/i, text],
    ["WordPress", /wp-content|wp-includes|wordpress/i, text],
    ["Django", /csrftoken|django/i, text],
    ["Firebase", /firebaseio|firebaseapp|firebaseConfig/i, text],
    ["GraphQL", /graphql|__schema|apollo/i, text],
    ["Swagger/OpenAPI", /swagger-ui|openapi\.json|api-docs/i, text]
  ];

  checks.forEach(([name, pattern, source]) => {
    if (pattern.test(source)) found.add(name);
  });

  const headerRows = [
    ["Server", getHeader(headers, "server") || "not exposed"],
    ["Powered By", getHeader(headers, "x-powered-by") || "not exposed"],
    ["Final URL", url]
  ];

  renderReconCard("Tech Fingerprint", "fas fa-microchip", [
    ["Detected", found.size ? [...found].map(item => badge(item, "info")).join("") : badge("none spotted", "warn")],
    ...headerRows.map(([key, value]) => [key, `<span class="recon-code">${escapeHtml(value)}</span>`])
  ], found.size ? "info" : "warn");

  return [...found];
}

function findRiskyParameters(urls) {
  const risky = [];
  urls.forEach(url => {
    try {
      const parsed = new URL(url);
      parsed.searchParams.forEach((value, key) => {
        const lowered = key.toLowerCase();
        const isRisky = riskyParamNames.includes(lowered) || riskyParamNames.some(name => lowered.includes(name));
        if (isRisky) {
          risky.push({ url, key, value });
        }
      });
    } catch { }
  });

  renderReconCard("Risky Parameters", "fas fa-crosshairs", [
    ["Flagged", risky.length ? badge(`${risky.length} parameters`, "warn") : badge("none", "good")],
    ["Names", risky.length
      ? [...new Set(risky.map(item => item.key))].slice(0, 30).map(item => badge(item, "warn")).join("")
      : badge("none", "good")
    ],
    ["Samples", risky.slice(0, 15).map(item =>
      `<div class="recon-list-item"><strong>${escapeHtml(item.key)}</strong>=<span class="recon-code">${escapeHtml(item.value)}</span>${urlLine(item.url)}</div>`
    ).join("") || "No risky parameters found"]
  ], risky.length ? "warn" : "good");

  return risky;
}

async function detectReflectedParameters(riskyParams) {
  const probe = `webxsider-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const checks = riskyParams.slice(0, 25);
  const reflected = [];
  await mapWithConcurrency(checks, Math.min(5, getRequestConcurrency()), async (item) => {
    if (isReconStopped) return;
    try {
      const url = new URL(item.url);
      url.searchParams.set(item.key, probe);
      const res = await fetchTarget(url.href);
      const text = await res.text();
      if (text.includes(probe)) {
        reflected.push({ ...item, probeUrl: url.href, status: res.status });
      }
    } catch { }
  });

  renderReconCard("Reflected Parameter Detector", "fas fa-mirror", [
    ["Checked", badge(`${checks.length} risky params`, "info")],
    ["Reflected", reflected.length ? reflected.map(item => `<div class="recon-list-item">${badge(item.key, "warn")} ${badge(item.status, "info")}${urlLine(item.probeUrl)}</div>`).join("") : badge("none", "good")]
  ], reflected.length ? "warn" : "good");

  return reflected;
}

function findInterestingSignals(body) {
  const hits = interestingBodySignals
    .filter(signal => signal.pattern.test(body))
    .map(signal => signal.label);

  renderReconCard("Interesting Response Signals", "fas fa-triangle-exclamation", [
    ["Signals", hits.length ? hits.map(item => badge(item, "warn")).join("") : badge("none spotted", "good")]
  ], hits.length ? "warn" : "good");

  return hits;
}

function sameOriginUrl(path, baseUrl) {
  const origin = new URL(baseUrl).origin;
  return new URL(path, origin).href;
}

function extractSitemapLocs(xmlText) {
  try {
    const doc = new DOMParser().parseFromString(xmlText, "text/xml");
    return [...doc.querySelectorAll("loc")]
      .map(node => node.textContent.trim())
      .filter(url => /^https?:\/\//i.test(url));
  } catch {
    return [];
  }
}

async function discoverRobotsAndSitemaps(baseUrl) {
  const origin = new URL(baseUrl).origin;
  const robots = { found: false, paths: [], sitemaps: [] };
  const sitemapUrls = new Set([sameOriginUrl("/sitemap.xml", baseUrl), sameOriginUrl("/sitemap_index.xml", baseUrl)]);
  const discoveredUrls = new Set();

  try {
    const res = await fetchTarget(sameOriginUrl("/robots.txt", baseUrl));
    const text = await res.text();
    if (res.ok && text.trim()) {
      robots.found = true;
      text.split(/\r?\n/).forEach(line => {
        const trimmed = line.trim();
        const sitemapMatch = trimmed.match(/^sitemap:\s*(.+)$/i);
        const pathMatch = trimmed.match(/^(?:allow|disallow):\s*(\/[^\s#]*)/i);
        if (sitemapMatch && /^https?:\/\//i.test(sitemapMatch[1].trim())) {
          sitemapUrls.add(sitemapMatch[1].trim());
          robots.sitemaps.push(sitemapMatch[1].trim());
        }
        if (pathMatch && pathMatch[1] !== "/") {
          robots.paths.push(pathMatch[1]);
          discoveredUrls.add(sameOriginUrl(pathMatch[1], baseUrl));
        }
      });
    }
  } catch { }

  const sitemapHits = [];
  for (const sitemapUrl of [...sitemapUrls].slice(0, 8)) {
    if (isReconStopped) break;
    try {
      const res = await fetchTarget(sitemapUrl);
      const text = await res.text();
      if (!res.ok || !text.trim()) continue;
      const locs = extractSitemapLocs(text);
      locs.forEach(url => {
        try {
          const parsed = new URL(url);
          if (parsed.hostname === new URL(origin).hostname) discoveredUrls.add(normalizeUrl(url));
          if (/\.xml(?:$|\?)/i.test(parsed.pathname)) sitemapUrls.add(url);
        } catch { }
      });
      sitemapHits.push({ url: sitemapUrl, count: locs.length });
    } catch { }
  }

  const urls = [...discoveredUrls].slice(0, 120);
  renderReconCard("Robots & Sitemap Discovery", "fas fa-sitemap", [
    ["robots.txt", robots.found ? badge("found", "info") : badge("not found", "good")],
    ["Robots Paths", robots.paths.length ? robots.paths.slice(0, 35).map(path => badge(path, "warn")).join("") : badge("none", "good")],
    ["Sitemaps", sitemapHits.length ? sitemapHits.map(item => `<div class="recon-list-item">${urlLine(item.url)} ${badge(`${item.count} locs`, "info")}</div>`).join("") : badge("none parsed", "good")],
    ["URLs Added", urls.length ? badge(`${urls.length} URLs`, "info") : badge("none", "good")]
  ], urls.length || robots.paths.length ? "info" : "good");

  return urls;
}

function extractOpenApiPaths(text, contentType = "") {
  const endpoints = new Set();
  if (/json/i.test(contentType) || /^[\s\r\n]*[{[]/.test(text)) {
    try {
      const parsed = JSON.parse(text);
      if (parsed && parsed.paths && typeof parsed.paths === "object") {
        Object.keys(parsed.paths).forEach(path => {
          if (path.startsWith("/")) endpoints.add(path);
        });
      }
      return [...endpoints];
    } catch { }
  }

  text.split(/\r?\n/).forEach(line => {
    const match = line.match(/^\s{0,6}(\/[A-Za-z0-9_~./{}:-]+)\s*:/);
    if (match) endpoints.add(match[1]);
  });
  return [...endpoints];
}

async function findOpenApiSpecs(baseUrl, html) {
  const origin = new URL(baseUrl).origin;
  const candidates = new Set([
    "/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml",
    "/api/swagger.json", "/api/openapi.json", "/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/docs/swagger.json", "/docs/openapi.json"
  ].map(path => origin + path));

  (html.match(/https?:\/\/[^"'<>\s]*(?:swagger|openapi|api-docs)[^"'<>\s]*/gi) || [])
    .forEach(url => candidates.add(url.replace(/[),.;\]]+$/, "")));
  (html.match(/["'](\/[^"']*(?:swagger|openapi|api-docs)[^"']*)["']/gi) || [])
    .forEach(raw => {
      const cleaned = raw.slice(1, -1);
      try { candidates.add(new URL(cleaned, origin).href); } catch { }
    });

  const specs = [];
  const endpointUrls = new Set();
  for (const candidate of [...candidates].slice(0, 18)) {
    if (isReconStopped) break;
    try {
      const res = await fetchTarget(candidate);
      const text = await res.text();
      const paths = res.ok ? extractOpenApiPaths(text.slice(0, 1200000), getHeader(res.headers, "content-type")) : [];
      if (paths.length) {
        paths.slice(0, 120).forEach(path => endpointUrls.add(new URL(path, origin).href));
        specs.push({ url: candidate, status: res.status, paths: paths.length });
      }
    } catch { }
  }

  renderReconCard("OpenAPI & Swagger Parser", "fas fa-book-open", [
    ["Checked", badge(`${Math.min(candidates.size, 18)} candidates`, "info")],
    ["Specs Found", specs.length ? specs.map(item => `<div class="recon-list-item">${badge(item.status, "good")} ${badge(`${item.paths} paths`, "warn")}${urlLine(item.url)}</div>`).join("") : badge("none", "good")],
    ["Endpoints Added", endpointUrls.size ? badge(`${endpointUrls.size} endpoints`, "info") : badge("none", "good")]
  ], specs.length ? "warn" : "good");

  return [...endpointUrls];
}

function decodeBase64UrlJson(part) {
  try {
    const padded = part.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(part.length / 4) * 4, "=");
    return JSON.parse(atob(padded));
  } catch {
    return null;
  }
}

function analyzeJwtTokens(body) {
  const tokens = [...new Set((body.match(/\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\b/g) || []))].slice(0, 20);
  const decoded = tokens
    .map(token => {
      const [head, payload] = token.split(".");
      const header = decodeBase64UrlJson(head);
      const claims = decodeBase64UrlJson(payload);
      if (!header || !claims) return null;
      const exp = Number(claims.exp);
      return {
        alg: header.alg || "unknown",
        typ: header.typ || "JWT",
        iss: claims.iss || "",
        sub: claims.sub || "",
        aud: Array.isArray(claims.aud) ? claims.aud.join(", ") : (claims.aud || ""),
        exp: Number.isFinite(exp) ? new Date(exp * 1000).toISOString() : ""
      };
    })
    .filter(Boolean);

  renderReconCard("JWT Decoder", "fas fa-id-card", [
    ["Tokens", tokens.length ? badge(`${tokens.length} found`, "warn") : badge("none", "good")],
    ["Decoded", decoded.length ? decoded.map(item => `
      <div class="recon-list-item">
        ${badge(`alg ${item.alg}`, item.alg.toLowerCase() === "none" ? "bad" : "info")}
        ${badge(item.typ, "info")}
        ${item.exp ? `<span class="recon-code">exp ${escapeHtml(item.exp)}</span>` : ""}
        ${item.iss ? `<div>iss ${codeValue(item.iss, { limit: 80 })}</div>` : ""}
        ${item.sub ? `<div>sub ${codeValue(item.sub, { limit: 80 })}</div>` : ""}
        ${item.aud ? `<div>aud ${codeValue(item.aud, { limit: 80 })}</div>` : ""}
      </div>
    `).join("") : badge("none decoded", tokens.length ? "warn" : "good")]
  ], tokens.length ? "warn" : "good");

  return decoded;
}

function analyzeClientStorage(body) {
  const patterns = [
    { label: "localStorage", regex: /localStorage\.(?:getItem|setItem|removeItem)|localStorage\s*\[/gi },
    { label: "sessionStorage", regex: /sessionStorage\.(?:getItem|setItem|removeItem)|sessionStorage\s*\[/gi },
    { label: "document.cookie", regex: /document\.cookie/gi },
    { label: "Bearer/Auth Token", regex: /\b(?:bearer|authorization|access_token|refresh_token|id_token|csrf|xsrf)\b/gi }
  ];
  const hits = [];
  patterns.forEach(({ label, regex }) => {
    let match;
    while ((match = regex.exec(body)) !== null && hits.length < 40) {
      hits.push({
        label,
        snippet: body.slice(Math.max(0, match.index - 55), Math.min(body.length, match.index + 115)).replace(/\s+/g, " ").trim()
      });
    }
  });

  renderReconCard("Client Storage & Token Usage", "fas fa-box-archive", [
    ["Signals", hits.length ? hits.slice(0, 20).map(item => `<div class="recon-list-item">${badge(item.label, "warn")} ${codeValue(item.snippet, { limit: 180 })}</div>`).join("") : badge("none", "good")]
  ], hits.length ? "warn" : "good");

  return hits;
}

function analyzeCloudAndBucketSignals(body) {
  const signals = [];
  const patterns = [
    { label: "Firebase Config", regex: /firebaseConfig|apiKey\s*:\s*["']AIza|authDomain\s*:\s*["'][^"']+firebaseapp\.com/gi },
    { label: "Supabase URL", regex: /https:\/\/[a-z0-9-]+\.supabase\.co/gi },
    { label: "S3 URL", regex: /https?:\/\/(?:[a-z0-9.-]+\.)?s3[.-][a-z0-9-]+\.amazonaws\.com\/[^\s"'<>]+|https?:\/\/s3\.amazonaws\.com\/[^\s"'<>]+/gi },
    { label: "CloudFront", regex: /https?:\/\/[a-z0-9-]+\.cloudfront\.net\/[^\s"'<>]*/gi },
    { label: "Google Storage", regex: /https?:\/\/storage\.googleapis\.com\/[^\s"'<>]+|gs:\/\/[^\s"'<>]+/gi },
    { label: "Azure Blob", regex: /https?:\/\/[a-z0-9-]+\.blob\.core\.windows\.net\/[^\s"'<>]+/gi }
  ];

  patterns.forEach(({ label, regex }) => {
    let match;
    while ((match = regex.exec(body)) !== null && signals.length < 60) {
      signals.push({
        label,
        value: match[0].slice(0, 220)
      });
    }
  });

  renderReconCard("Cloud Config & Bucket Signals", "fas fa-cloud", [
    ["Signals", signals.length ? signals.slice(0, 30).map(item => `<div class="recon-list-item">${badge(item.label, "warn")} ${codeValue(item.value, { limit: 180 })}</div>`).join("") : badge("none", "good")]
  ], signals.length ? "warn" : "good");

  return signals;
}

function renderAuthSurfaceMap(urls, baseUrl) {
  const origin = new URL(baseUrl).origin;
  const buckets = {
    Login: /login|signin|sign-in|session/,
    Register: /register|signup|sign-up/,
    Password: /password|reset|forgot|recover/,
    OAuth: /oauth|sso|saml|oidc|callback/,
    Token: /token|jwt|jwks|refresh/,
    MFA: /mfa|2fa|otp|totp/,
    Logout: /logout|signout/
  };
  const mapped = {};
  Object.keys(buckets).forEach(key => mapped[key] = []);

  [...new Set(urls)].forEach(url => {
    try {
      const parsed = new URL(url, origin);
      const haystack = `${parsed.pathname} ${parsed.search}`.toLowerCase();
      Object.entries(buckets).forEach(([label, pattern]) => {
        if (pattern.test(haystack) && mapped[label].length < 12) mapped[label].push(parsed.href);
      });
    } catch { }
  });

  const total = Object.values(mapped).reduce((sum, list) => sum + list.length, 0);
  renderReconCard("Auth Surface Mapper", "fas fa-user-lock", [
    ["Mapped", total ? badge(`${total} auth URLs`, "warn") : badge("none", "good")],
    ...Object.entries(mapped).map(([label, list]) => [
      label,
      list.length ? list.map(url => urlLine(url)).join("") : badge("none", "good")
    ])
  ], total ? "warn" : "good");

  return mapped;
}

function renderResponseDiffSummary(endpointChecks) {
  const groups = {};
  endpointChecks.forEach(item => {
    const key = `${item.status}:${item.length}:${(item.title || "no-title").toLowerCase()}:${item.hash || "no-hash"}`;
    if (!groups[key]) groups[key] = [];
    groups[key].push(item.url);
  });

  const repeated = Object.entries(groups)
    .filter(([, urls]) => urls.length > 1)
    .sort((a, b) => b[1].length - a[1].length)
    .slice(0, 12);

  renderReconCard("Response Diff Helper", "fas fa-not-equal", [
    ["Repeated Pages", repeated.length ? repeated.map(([key, urls]) => `<div class="recon-list-item">${badge(key.split(":").slice(0, 2).join(":"), "info")} ${badge(`${urls.length} URLs`, "warn")}${urls.slice(0, 4).map(url => urlLine(url)).join("")}</div>`).join("") : badge("none", "good")],
    ["Use", badge("same status+length+title+body hash can reveal WAF or shared error pages", "info")]
  ], repeated.length ? "info" : "good");

  return repeated;
}

async function checkGraphqlEndpoints(baseUrl) {
  const origin = new URL(baseUrl).origin;
  const candidates = ["/graphql", "/api/graphql", "/v1/graphql", "/graphql/v1", "/graphiql", "/playground", "/__graphql"]
    .map(path => origin + path);
  const hits = [];
  const introspectionQuery = `query IntrospectionQuery {
    __schema {
      queryType { name }
      mutationType { name }
      subscriptionType { name }
      types { kind name fields { name args { name type { kind name ofType { kind name } } } type { kind name ofType { kind name } } } }
    }
  }`;

  for (const endpoint of candidates) {
    if (isReconStopped) break;
    try {
      const probeUrl = endpoint.includes("?") ? endpoint : `${endpoint}?query=${encodeURIComponent("{__typename}")}`;
      const res = await fetchTarget(probeUrl);
      const text = await res.text();
      const signature = /"data"\s*:|"errors"\s*:|graphql|cannot query field|must provide query|graphiql|playground/i.test(text);
      if ([200, 400, 401, 403, 405].includes(res.status) && signature) {
        hits.push({ url: endpoint, status: res.status, length: text.length });
      }
    } catch { }

    try {
      const res = await fetchTarget(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: introspectionQuery })
      });
      const text = await res.text();
      const introspection = /__schema|queryType|Introspection|SchemaMetaFieldDef|"data"\s*:|"errors"\s*:/i.test(text);
      if ([200, 400, 401, 403].includes(res.status) && introspection) {
        hits.push({ url: `${endpoint} (POST introspection)`, status: res.status, length: text.length, schema: text.slice(0, 50000) });
      }
    } catch { }
  }

  renderReconCard("GraphQL Surface Check", "fas fa-diagram-project", [
    ["Checked", badge(`${candidates.length} endpoints`, "info")],
    ["Signals", hits.length ? hits.map(item => `<div class="recon-list-item">${badge(item.status, item.status === 200 ? "warn" : "info")} <span class="recon-code">[${escapeHtml(item.length)}]</span>${urlLine(item.url)}${item.schema ? `<details class="recon-details"><summary>Show schema/introspection response</summary><pre>${escapeHtml(item.schema)}</pre></details>` : ""}</div>`).join("") : badge("none", "good")]
  ], hits.length ? "warn" : "good");

  return hits;
}

function renderMethodHints(urls, baseUrl) {
  const origin = new URL(baseUrl).origin;
  const hints = [...new Set(urls)].map(url => {
    try {
      const parsed = new URL(url, origin);
      const path = parsed.pathname.toLowerCase();
      let method = "";
      if (/\/(?:delete|remove|destroy|disable|revoke|logout)/.test(path)) method = "DELETE/POST";
      else if (/\/(?:update|edit|patch|change|reset)/.test(path)) method = "PUT/PATCH";
      else if (/\/(?:create|add|upload|import|login|register|token|checkout|payment)/.test(path)) method = "POST";
      else if (/\/(?:export|download|report|search|list|users|accounts)/.test(path)) method = "GET";
      return method ? { url: parsed.href, method } : null;
    } catch {
      return null;
    }
  }).filter(Boolean).slice(0, 40);

  renderReconCard("Endpoint Method Hints", "fas fa-route", [
    ["Heuristic", badge("based only on real discovered URLs", "info")],
    ["Hints", hints.length ? hints.map(item => `<div class="recon-list-item">${badge(item.method, "info")}${urlLine(item.url)}</div>`).join("") : badge("none", "good")]
  ], hints.length ? "info" : "good");

  return hints;
}

async function findSourceMaps(baseUrl, html) {
  const candidates = new Set();
  const scripts = extractScriptUrls(html, baseUrl);
  scripts.forEach(script => {
    candidates.add(`${script}.map`);
    if (script.endsWith(".js")) candidates.add(script.replace(/\.js(?:\?.*)?$/i, ".js.map"));
  });

  const origin = new URL(baseUrl).origin;
  ["/main.js.map", "/app.js.map", "/bundle.js.map", "/vendor.js.map", "/static/js/main.js.map"].forEach(path => {
    candidates.add(origin + path);
  });

  const found = [];
  const limited = [...candidates].slice(0, 35);
  for (const candidate of limited) {
    if (isReconStopped) break;
    try {
      const res = await fetchTarget(candidate);
      const contentType = getHeader(res.headers, "content-type");
      const text = await res.text();
      if (res.ok && (/json|source-map/i.test(contentType) || /"sources"\s*:\s*\[/.test(text))) {
        let sourceCount = 0;
        let sources = [];
        try {
          const parsed = JSON.parse(text);
          sources = Array.isArray(parsed.sources) ? parsed.sources.slice(0, 12) : [];
          sourceCount = Array.isArray(parsed.sources) ? parsed.sources.length : 0;
        } catch { }
        const endpoints = extractEndpointsWithLines(text).slice(0, 80).map(item => {
          try { return new URL(item.value, baseUrl).href; } catch { return item.value; }
        });
        const secrets = extractSecretsWithLines(text).slice(0, 20);
        found.push({ url: candidate, length: text.length, sourceCount, sources, endpoints, secrets });
      }
    } catch { }
  }

  renderReconCard("Source Maps", "fas fa-map", [
    ["Checked", badge(`${limited.length} candidates`, "info")],
    ["Found", found.length ? found.map(item =>
      `<div class="recon-list-item">${urlLine(item.url)} ${badge(`${item.length} bytes`, "warn")} ${badge(`${item.sourceCount} sources`, "info")} ${badge(`${item.endpoints.length} endpoints`, item.endpoints.length ? "warn" : "good")} ${item.secrets.length ? badge(`${item.secrets.length} secrets`, "bad") : ""}${item.sources.length ? `<details class="recon-details"><summary>Show source files</summary><pre>${escapeHtml(item.sources.join("\n"))}</pre></details>` : ""}</div>`
    ).join("") : badge("none", "good")]
  ], found.length ? "warn" : "good");

  return found;
}

async function liveCheckEndpoints(urls, baseUrl) {
  const origin = new URL(baseUrl).origin;
  const sameHost = urls
    .map(url => {
      try {
        return new URL(url, origin).href;
      } catch {
        return null;
      }
    })
    .filter(Boolean)
    .filter(url => {
      try {
        return new URL(url).hostname === new URL(origin).hostname;
      } catch {
        return false;
      }
    });

  const unique = [...new Set(sameHost)].slice(0, 60);
  const checked = [];
  for (const url of unique) {
    if (isReconStopped) break;
    try {
      const res = await fetchTarget(url);
      const text = await res.text();
      checked.push({ url, status: res.status, length: text.length, title: extractTitle(text), hash: hashText(text) });
    } catch {
      checked.push({ url, status: "ERROR", length: 0, title: "", hash: "" });
    }
  }

  const interesting = checked.filter(item => [200, 201, 202, 204, 301, 302, 307, 308, 401, 403].includes(item.status));
  renderReconCard("Endpoint Live Check", "fas fa-link", [
    ["Checked", badge(`${checked.length} URLs`, "info")],
    ["Interesting", interesting.length ? interesting.slice(0, 35).map(item =>
      `<div class="recon-list-item">${badge(item.status, item.status === 200 ? "good" : "warn")} <span class="recon-code">[${escapeHtml(item.length)}]</span>${urlLine(item.url)}</div>`
    ).join("") : badge("none", "good")]
  ], interesting.length ? "info" : "good");

  return checked;
}

startReconBtn.onclick = async () => {
  let url = reconUrlInput.value.trim();
  if (!url) return showToast("Enter a URL to recon", "warn");
  if (!/^https?:\/\//i.test(url)) url = "https://" + url;
  url = normalizeUrl(url);

  reconResults.innerHTML = "";
  reconSummary.innerHTML = "";
  reconResults.style.display = "grid";
  reconSummary.style.display = "none";
  reconProgressContainer.style.display = "block";
  startReconBtn.style.display = "none";
  stopReconBtn.style.display = "inline-block";
  stopReconBtn.disabled = false;
  isReconStopped = false;
  setReconProgress(4);
  setReconStatus("Fetching target...");

  try {
    const res = await fetchTarget(url);
    const body = await res.text();
    if (!res.ok) {
      const blockedByChallenge = [401, 403, 429].includes(res.status) && isBotProtectionPage(body);
      const reason = blockedByChallenge
        ? "Target returned protection against automated proxy requests."
        : `Target returned ${res.status} ${res.statusText || "HTTP error"}.`;

      renderReconSummary([
        { label: "Target Status", value: res.status, tone: "bad", note: blockedByChallenge ? "challenge" : "blocked" },
        { label: "Body Length", value: body.length, tone: "info", note: "bytes" }
      ]);
      renderReconCard("Target Fetch", "fas fa-circle-exclamation", [
        ["Status", badge(`${res.status} ${res.statusText || "HTTP error"}`, "bad")],
        ["Result", badge(reason, "warn")],
        ["Next Step", badge("paste authorized URLs into Recon URL Import or test a target that allows automated requests", "info")]
      ], "bad");
      setReconProgress(100);
      setReconStatus(reason);
      return;
    }

    const importedUrls = parseReconUrls(reconUrlList?.value || "", url);
    const extractedEndpoints = extractEndpointsWithLines(body)
      .map(item => {
        try {
          return new URL(item.value, url).href;
        } catch {
          return null;
        }
      })
      .filter(Boolean);

    let allEndpointUrls = [...new Set([...importedUrls, ...extractedEndpoints])];
    setReconProgress(12);
    setReconStatus("Analyzing headers...");
    const headers = analyzeSecurityHeaders(res);

    setReconProgress(22);
    setReconStatus("Checking CORS...");
    const cors = await analyzeCors(url);

    setReconProgress(32);
    setReconStatus("Fingerprinting tech...");
    const tech = detectTech(url, res, body);

    setReconProgress(40);
    setReconStatus("Parsing robots and sitemaps...");
    const discoveryUrls = await discoverRobotsAndSitemaps(url);
    allEndpointUrls = [...new Set([...allEndpointUrls, ...discoveryUrls])];

    setReconProgress(50);
    setReconStatus("Parsing OpenAPI and Swagger specs...");
    const openApiUrls = await findOpenApiSpecs(url, body);
    allEndpointUrls = [...new Set([...allEndpointUrls, ...openApiUrls])];

    setReconProgress(60);
    setReconStatus("Finding risky parameters...");
    const riskyParams = findRiskyParameters(allEndpointUrls);

    setReconProgress(64);
    setReconStatus("Checking reflected parameters...");
    const reflectedParams = await detectReflectedParameters(riskyParams);

    setReconProgress(68);
    setReconStatus("Checking response signals...");
    const signals = findInterestingSignals(body);

    setReconProgress(74);
    setReconStatus("Decoding JWT and storage signals...");
    const jwtTokens = analyzeJwtTokens(body);
    const storageSignals = analyzeClientStorage(body);
    const cloudSignals = analyzeCloudAndBucketSignals(body);

    setReconProgress(80);
    setReconStatus("Checking GraphQL surfaces...");
    const graphqlHits = await checkGraphqlEndpoints(url);

    setReconProgress(86);
    setReconStatus("Looking for source maps...");
    const maps = await findSourceMaps(url, body);
    const mapEndpoints = maps.flatMap(item => item.endpoints || []);
    allEndpointUrls = [...new Set([...allEndpointUrls, ...mapEndpoints])];

    setReconProgress(92);
    setReconStatus("Generating endpoint method hints...");
    const methodHints = renderMethodHints(allEndpointUrls, url);
    const authSurface = renderAuthSurfaceMap(allEndpointUrls, url);

    setReconProgress(95);
    setReconStatus("Live-checking endpoints...");
    const endpointChecks = await liveCheckEndpoints(allEndpointUrls, url);
    const liveInteresting = endpointChecks.filter(item => [200, 201, 202, 204, 301, 302, 307, 308, 401, 403].includes(item.status));
    const responseDiffs = renderResponseDiffSummary(endpointChecks);
    const authSurfaceCount = Object.values(authSurface).reduce((sum, list) => sum + list.length, 0);

    renderReconSummary([
      { label: "Missing Headers", value: headers.missing.length, tone: headers.missing.length ? "bad" : "good", note: headers.missing.length ? "review" : "clean" },
      { label: "CORS Risks", value: cors.length, tone: cors.length ? "bad" : "good", note: cors.length ? "possible issue" : "none" },
      { label: "Source Maps", value: maps.length, tone: maps.length ? "warn" : "good", note: maps.length ? "exposed" : "none" },
      { label: "OpenAPI Paths", value: openApiUrls.length, tone: openApiUrls.length ? "warn" : "good", note: openApiUrls.length ? "parsed" : "none" },
      { label: "GraphQL", value: graphqlHits.length, tone: graphqlHits.length ? "warn" : "good", note: graphqlHits.length ? "signals" : "none" },
      { label: "JWTs", value: jwtTokens.length, tone: jwtTokens.length ? "warn" : "good", note: jwtTokens.length ? "decoded" : "none" },
      { label: "Risky Params", value: riskyParams.length, tone: riskyParams.length ? "warn" : "good", note: riskyParams.length ? "test manually" : "none" },
      { label: "Reflections", value: reflectedParams.length, tone: reflectedParams.length ? "warn" : "good", note: reflectedParams.length ? "possible XSS" : "none" },
      { label: "Storage Signals", value: storageSignals.length, tone: storageSignals.length ? "warn" : "good", note: storageSignals.length ? "inspect" : "none" },
      { label: "Cloud/Buckets", value: cloudSignals.length, tone: cloudSignals.length ? "warn" : "good", note: cloudSignals.length ? "inspect" : "none" },
      { label: "Auth URLs", value: authSurfaceCount, tone: authSurfaceCount ? "warn" : "good", note: authSurfaceCount ? "mapped" : "none" },
      { label: "Method Hints", value: methodHints.length, tone: methodHints.length ? "info" : "good", note: "heuristic" },
      { label: "Diff Groups", value: responseDiffs.length, tone: responseDiffs.length ? "info" : "good", note: "same length" },
      { label: "Live URLs", value: liveInteresting.length, tone: liveInteresting.length ? "info" : "good", note: "reachable" },
      { label: "Tech Hits", value: tech.length, tone: tech.length ? "info" : "warn", note: tech.length ? "fingerprinted" : "unknown" },
      { label: "Signals", value: signals.length, tone: signals.length ? "warn" : "good", note: signals.length ? "inspect" : "none" }
    ]);

    setReconProgress(100);
    setReconStatus(isReconStopped ? "Recon stopped manually." : "Recon complete.");
  } catch (error) {
    setReconStatus(`Recon failed. ${error.message}`);
  } finally {
    startReconBtn.style.display = "inline-block";
    stopReconBtn.style.display = "none";
  }
};

stopReconBtn.onclick = () => {
  isReconStopped = true;
  stopReconBtn.disabled = true;
  setReconStatus("Stopping recon... Finishing current request.");
};

// Comprehensive helper to identify files (aligned with regex)
function isInterestingFile(url) {
  if (!url) return false;
  const cleaned = url.split("?")[0].toLowerCase();
  const interestingExtensions = [
    ".json", ".xml", ".config", ".env", ".yaml", ".yml", ".sql", ".db", ".bak",
    ".zip", ".tar", ".gz", ".7z", ".pdf", ".doc", ".docx", ".js", ".html",
    ".php", ".asp", ".aspx", ".jsp", ".txt"
  ];
  return interestingExtensions.some(ext => cleaned.endsWith(ext));
}

function filterUrl(url) {
  const lowered = (url || "").toLowerCase();
  return (
    lowered &&
    !excludedExtensions.some(ext => lowered.endsWith(ext)) &&
    !externalDomainsToIgnore.some(domain => lowered.includes(domain)) &&
    !disallowedPrefixes.some(prefix => lowered.startsWith(prefix)) &&
    !lowered.includes("base64") &&
    lowered.length < 300
  );
}

function buildScanDiagnostic(targetUrl) {
  const firstFailure = state.fetchFailures[0] || "";
  const protectionBlocked = /target protection blocked automated proxy requests/i.test(firstFailure);

  if (protectionBlocked) {
    return {
      title: "Target Protection Blocked Scan",
      statusText: "Scan complete: target protection blocked automated proxy requests.",
      tone: "warn",
      lines: [
        `Target: ${targetUrl}`,
        "The site returned an anti-bot or access-control response to the proxy, so browser-based crawling cannot read the page source.",
        "This is target-side protection, not a Web X Sider crash.",
        "Use the Imported URLs field with authorized URLs, ask the owner to allowlist your scanner, or scan a target that allows automated requests."
      ]
    };
  }

  return {
    title: "Target Could Not Be Fetched",
    statusText: `Scan complete: no readable source was fetched. ${firstFailure}`,
    tone: "bad",
    lines: [
      `Target: ${targetUrl}`,
      firstFailure || "No response body could be read.",
      "Check the target URL, scope, proxy availability, and whether the site allows automated requests."
    ]
  };
}

function renderScanDiagnostic() {
  if (!state.scanDiagnostic) return false;
  const diagnostic = state.scanDiagnostic;
  const card = document.createElement("div");
  card.className = `diagnostic-card diagnostic-${diagnostic.tone || "info"}`;

  const title = document.createElement("h3");
  title.innerText = diagnostic.title;
  card.appendChild(title);

  diagnostic.lines.forEach(line => {
    const p = document.createElement("p");
    p.innerText = line;
    card.appendChild(p);
  });

  const actions = document.createElement("div");
  actions.className = "diagnostic-actions";

  const addFallbackBtn = document.createElement("button");
  addFallbackBtn.type = "button";
  addFallbackBtn.className = "diagnostic-action-btn";
  addFallbackBtn.innerHTML = '<i class="fas fa-sitemap"></i><span>Add robots/sitemap</span>';
  addFallbackBtn.onclick = () => {
    try {
      const origin = new URL((urlInput.value || diagnostic.lines[0] || "").replace(/^Target:\s*/i, "")).origin;
      const added = appendUniqueLines(importedUrlInput, [`${origin}/robots.txt`, `${origin}/sitemap.xml`, `${origin}/sitemap_index.xml`]);
      if (workflowImportStatus) workflowImportStatus.innerText = `Added ${added} fallback URL${added === 1 ? "" : "s"} for protected-target discovery.`;
      updateInputPreviews();
    } catch { }
  };

  const proberBtn = document.createElement("button");
  proberBtn.type = "button";
  proberBtn.className = "diagnostic-action-btn";
  proberBtn.innerHTML = '<i class="fas fa-crosshairs"></i><span>Send to Prober</span>';
  proberBtn.onclick = () => {
    proberUrlInput.value = urlInput.value;
    navProber.click();
  };

  actions.appendChild(addFallbackBtn);
  actions.appendChild(proberBtn);
  card.appendChild(actions);

  results.appendChild(card);
  return true;
}

async function validateSecret(item) {
  const value = String(item.value || "");
  const name = value.split(":")[0].trim().toLowerCase();
  let testUrl = "";
  let testOptions = {};
  let expectFn = null;

  if (name.includes("aws key")) {
    showToast("AWS key found. Validate manually via AWS STS GetCallerIdentity.", "warn");
    return;
  }
  if (name.includes("stripe live")) {
    const key = value.split(": ").slice(1).join(": ");
    testUrl = "https://api.stripe.com/v1/balance";
    testOptions = { headers: { Authorization: `Bearer ${key}` } };
    expectFn = (res) => res.status === 200 ? "VALID - active Stripe key!" : res.status === 401 ? "Invalid/expired" : `Status: ${res.status}`;
  }
  if (name.includes("github pat")) {
    const key = value.split(": ").slice(1).join(": ");
    testUrl = "https://api.github.com/user";
    testOptions = { headers: { Authorization: `token ${key}` } };
    expectFn = (res) => res.status === 200 ? "VALID - active GitHub token!" : "Invalid/expired";
  }
  if (name.includes("slack webhook")) {
    testUrl = value.replace(/^Slack Webhook:\s*/i, "").trim();
    testOptions = { method: "GET" };
    expectFn = (res) => res.status !== 404 ? "Webhook URL appears active (not 404)" : "Webhook revoked (404)";
  }

  if (!testUrl) {
    showToast("No automatic validator for this secret type. Validate manually.", "info");
    return;
  }

  showToast("Validating secret...", "info", 2000);
  try {
    const res = await fetchTarget(testUrl, testOptions);
    const result = expectFn ? expectFn(res) : `HTTP ${res.status}`;
    showToast(`Secret validation: ${result}`, result.includes("VALID") ? "success" : "warn", 6000);
  } catch (e) {
    showToast(`Validation failed: ${e.message}`, "error");
  }
}

async function tryAllMethods(item) {
  const methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"];
  let targetUrl;
  try {
    targetUrl = new URL(item.value, item.source).href.replace(/\[DYNAMIC\]$/, "");
  } catch {
    showToast("Could not build a URL for method testing.", "warn");
    return;
  }
  showToast("Testing HTTP methods...", "info", 2000);
  const results = [];
  await mapWithConcurrency(methods, Math.min(4, getRequestConcurrency()), async (method) => {
    try {
      const res = await fetchTarget(targetUrl, { method });
      const text = method === "HEAD" ? "" : await res.text();
      results.push({ method, status: res.status, length: text.length });
    } catch (error) {
      results.push({ method, status: "ERR", length: 0, error: error.message });
    }
  });
  item.methodChecks = results.sort((a, b) => methods.indexOf(a.method) - methods.indexOf(b.method));
  showToast(`Method test: ${item.methodChecks.map(r => `${r.method} ${r.status}`).join(", ")}`, "success", 7000);
  const activeTab = document.querySelector("#crawler-section .tab-btn.active")?.dataset.tab || "all";
  renderResults(document.getElementById("filterInput").value, activeTab);
}

function renderResults(filter = "", category = "all") {
  results.innerHTML = "";
  const grouped = {};

  getVisibleFindings().forEach(item => {
    if (category !== "all" && item.type !== category.slice(0, -1)) return;
    if (state.activeSeverityFilter !== "all" && (item.severity || "low") !== state.activeSeverityFilter) return;
    if (filter && !item.value.toLowerCase().includes(filter.toLowerCase())) return;

    if (!grouped[item.source]) grouped[item.source] = [];
    grouped[item.source].push(item);
  });

  const sourceEntries = Object.entries(grouped);
  if (sourceEntries.length === 0) {
    if (renderScanDiagnostic()) return;
    results.innerHTML = "<div class='status'>No results found matching your criteria.</div>";
    return;
  }

  for (const [source, items] of sourceEntries) {
    const card = document.createElement("div");
    card.className = "card";
    const title = document.createElement("h3");
    title.innerText = source;
    card.appendChild(title);

    const list = document.createElement("ol");
    items
      .sort((a, b) => (severityRank[b.severity] || 0) - (severityRank[a.severity] || 0))
      .forEach(item => {
      const li = document.createElement("li");

      const lineSpan = document.createElement("span");
      lineSpan.className = "line-number";
      lineSpan.innerText = `[L${item.line}]`;

      const detail = document.createElement("div");
      detail.className = "finding-detail";

      const meta = document.createElement("div");
      meta.className = "finding-meta";

      const severity = document.createElement("span");
      severity.className = `severity-badge severity-${item.severity || "low"}`;
      severity.innerText = (item.severity || "low").toUpperCase();

      const typeBadge = document.createElement("span");
      typeBadge.className = "finding-type";
      typeBadge.innerText = item.type;

      meta.appendChild(severity);
      meta.appendChild(typeBadge);

      const confidenceBadge = document.createElement("span");
      confidenceBadge.className = "finding-type";
      confidenceBadge.innerText = `confidence: ${getFindingConfidence(item)}`;
      meta.appendChild(confidenceBadge);

      const methodHint = ["endpoint", "parameter"].includes(item.type) ? inferHttpMethod(item.value) : "";
      if (methodHint) {
        const methodBadge = document.createElement("span");
        methodBadge.className = "finding-type";
        methodBadge.innerText = methodHint;
        meta.appendChild(methodBadge);
      }

      const severitySelect = document.createElement("select");
      severitySelect.className = "severity-override";
      ["critical", "high", "medium", "low"].forEach(level => {
        const option = document.createElement("option");
        option.value = level;
        option.textContent = level.toUpperCase();
        option.selected = (item.severity || "low") === level;
        severitySelect.appendChild(option);
      });
      severitySelect.onchange = () => {
        item.severity = severitySelect.value;
        renderPriorityDashboard();
        const activeTab = document.querySelector("#crawler-section .tab-btn.active")?.dataset.tab || "all";
        renderResults(document.getElementById("filterInput").value, activeTab);
      };
      meta.appendChild(severitySelect);

      const tagSelect = document.createElement("select");
      tagSelect.className = "severity-override";
      ["untagged", "confirmed", "needs-testing", "false-positive", "reported"].forEach(tag => {
        const option = document.createElement("option");
        option.value = tag;
        option.textContent = tag;
        option.selected = (state.findingTags[getFindingKey(item)] || "untagged") === tag;
        tagSelect.appendChild(option);
      });
      tagSelect.onchange = () => {
        const key = getFindingKey(item);
        if (tagSelect.value === "untagged") delete state.findingTags[key];
        else state.findingTags[key] = tagSelect.value;
      };
      meta.appendChild(tagSelect);

      const span = document.createElement("span");
      span.className = `endpoint-text ${item.type === 'secret' ? 'secret-item' : ''}`;
      span.innerText = item.value;

      const hint = document.createElement("span");
      hint.className = "finding-hint";
      hint.innerText = item.hint || "";

      const noteValue = state.findingNotes[getFindingKey(item)] || "";
      const note = document.createElement("span");
      note.className = "finding-note";
      note.innerText = noteValue ? `Note: ${noteValue}` : "";
      const methodChecks = document.createElement("span");
      methodChecks.className = "finding-note";
      methodChecks.innerText = item.methodChecks?.length
        ? `Methods: ${item.methodChecks.map(r => `${r.method} ${r.status} [${r.length}]`).join(" | ")}`
        : "";

      detail.appendChild(meta);
      detail.appendChild(span);
      detail.appendChild(hint);
      detail.appendChild(note);
      detail.appendChild(methodChecks);

      const actions = document.createElement("div");
      actions.className = "finding-actions";

      const copyReportBtn = document.createElement("button");
      copyReportBtn.className = "finding-action-btn";
      copyReportBtn.title = "Copy as report finding";
      copyReportBtn.innerHTML = '<i class="fas fa-clipboard-list"></i>';
      copyReportBtn.onclick = () => copyReportFinding(item, copyReportBtn);

      const noteBtn = document.createElement("button");
      noteBtn.className = "finding-action-btn";
      noteBtn.title = "Add note";
      noteBtn.innerHTML = '<i class="fas fa-pen"></i>';
      noteBtn.onclick = () => addFindingNote(item);

      const hideBtn = document.createElement("button");
      hideBtn.className = "finding-action-btn";
      hideBtn.title = "Hide false positive";
      hideBtn.innerHTML = '<i class="fas fa-eye-slash"></i>';
      hideBtn.onclick = () => hideFinding(item);

      const copyBtn = document.createElement("button");
      copyBtn.className = "copy-btn";
      copyBtn.innerHTML = "📋";
      copyBtn.onclick = () => copyToClipboard(item.value, copyBtn);

      actions.appendChild(copyReportBtn);
      actions.appendChild(noteBtn);
      actions.appendChild(hideBtn);
      if (item.type === "secret") {
        const validateBtn = document.createElement("button");
        validateBtn.className = "finding-action-btn";
        validateBtn.title = "Validate secret";
        validateBtn.innerHTML = '<i class="fas fa-vial"></i>';
        validateBtn.onclick = () => validateSecret(item);
        actions.appendChild(validateBtn);
      }
      if (["endpoint", "parameter"].includes(item.type)) {
        const methodBtn = document.createElement("button");
        methodBtn.className = "finding-action-btn";
        methodBtn.title = "Try all HTTP methods";
        methodBtn.innerHTML = '<i class="fas fa-route"></i>';
        methodBtn.onclick = () => tryAllMethods(item);
        actions.appendChild(methodBtn);
      }
      actions.appendChild(copyBtn);

      li.appendChild(lineSpan);
      li.appendChild(detail);
      li.appendChild(actions);
      list.appendChild(li);
    });
    card.appendChild(list);
    results.appendChild(card);
  }
}

async function copyToClipboard(text, btn) {
  try {
    await navigator.clipboard.writeText(text);
    btn.classList.add("copied");
    btn.innerText = "✅";
    setTimeout(() => {
      btn.classList.remove("copied");
      btn.innerText = "📋";
    }, 2000);
  } catch { }
}

function buildFindingReportText(item) {
  const severity = String(item.severity || "low").toUpperCase();
  const note = state.findingNotes[getFindingKey(item)] || "";
  return [
    `Title: ${severity} ${item.type} finding`,
    `Severity: ${severity}`,
    `Source: ${item.source}`,
    `Line: ${item.line}`,
    `Evidence: ${item.value}`,
    `Why it matters: ${item.hint || "Review manually."}`,
    note ? `Analyst note: ${note}` : "",
    "Validation: Reproduce only on authorized scope, confirm impact, and capture minimal evidence."
  ].filter(Boolean).join("\n");
}

function copyReportFinding(item, btn) {
  copyToClipboard(buildFindingReportText(item), btn);
}

async function addFindingNote(item) {
  const key = getFindingKey(item);
  const current = state.findingNotes[key] || "";
  const note = await showPrompt("Add a note for this finding:", current);
  if (note === null) return;
  const trimmed = note.trim();
  if (trimmed) state.findingNotes[key] = trimmed;
  else delete state.findingNotes[key];
  const activeTab = document.querySelector("#crawler-section .tab-btn.active")?.dataset.tab || "all";
  renderResults(document.getElementById("filterInput").value, activeTab);
}

function hideFinding(item) {
  state.hiddenFindings.add(getFindingKey(item));
  renderPriorityDashboard();
  const activeTab = document.querySelector("#crawler-section .tab-btn.active")?.dataset.tab || "all";
  renderResults(document.getElementById("filterInput").value, activeTab);
}

// Tabs & Filter Logic (Crawler Section)
document.querySelectorAll("#crawler-section .tab-btn").forEach(btn => {
  btn.onclick = () => {
    document.querySelector("#crawler-section .tab-btn.active").classList.remove("active");
    btn.classList.add("active");
    renderResults(document.getElementById("filterInput").value, btn.dataset.tab);
  };
});

document.getElementById("filterInput").oninput = (e) => {
  const activeTab = document.querySelector("#crawler-section .tab-btn.active").dataset.tab;
  renderResults(e.target.value, activeTab);
};

document.querySelectorAll("[data-severity-filter]").forEach(btn => {
  btn.addEventListener("click", () => {
    state.activeSeverityFilter = btn.dataset.severityFilter || "all";
    document.querySelectorAll("[data-severity-filter]").forEach(item => {
      item.classList.toggle("active", item === btn);
    });
    const activeTab = document.querySelector("#crawler-section .tab-btn.active")?.dataset.tab || "all";
    renderResults(document.getElementById("filterInput").value, activeTab);
  });
});

scopeInput?.addEventListener("input", updateInputPreviews);
importedUrlInput?.addEventListener("input", updateInputPreviews);
urlInput?.addEventListener("input", updateInputPreviews);
urlInput?.addEventListener("blur", () => {
  if (!scopeInput || scopeInput.value.trim()) return;
  try {
    let raw = urlInput.value.trim();
    if (!raw) return;
    if (!/^https?:\/\//i.test(raw)) raw = `https://${raw}`;
    const parts = new URL(raw).hostname.replace(/^www\./, "").split(".");
    if (parts.length >= 2) {
      const root = parts.slice(-2).join(".");
      scopeInput.value = `*.${root}`;
      if (subdomainInput && !subdomainInput.value.trim()) {
        const guesses = ["api", "admin", "dev", "staging", "test", "internal", "mail", "vpn", "portal", "app", "dashboard", "beta"];
        subdomainInput.value = guesses.map(prefix => `${prefix}.${root}`).join("\n");
      }
      updateInputPreviews();
    }
  } catch { }
});
applyImportBtn?.addEventListener("click", () => applyWorkflowImport());
clearImportBtn?.addEventListener("click", () => {
  if (workflowImportInput) workflowImportInput.value = "";
  if (workflowImportStatus) workflowImportStatus.innerText = "Workflow import cleared.";
});
workflowImportFile?.addEventListener("change", async (event) => {
  const file = event.target.files?.[0];
  if (!file) return;
  try {
    const text = await file.text();
    if (workflowImportInput) workflowImportInput.value = text;
    applyWorkflowImport(text);
  } catch {
    if (workflowImportStatus) workflowImportStatus.innerText = "Import file could not be read.";
  } finally {
    event.target.value = "";
  }
});
updateInputPreviews();

waybackFetchBtn?.addEventListener("click", async () => {
  let siteUrl = urlInput.value.trim();
  if (!siteUrl) return showToast("Enter a valid URL", "warn");
  if (!/^https?:\/\//i.test(siteUrl)) siteUrl = `https://${siteUrl}`;
  try {
    const host = new URL(siteUrl).hostname.replace(/^www\./, "");
    const api = `https://web.archive.org/cdx/search/cdx?url=*.${encodeURIComponent(host)}/*&output=json&fl=original&collapse=urlkey`;
    showToast("Fetching Wayback URLs...", "info", 2000);
    const res = await fetch(api);
    const rows = await res.json();
    const urls = rows.slice(1).map(row => Array.isArray(row) ? row[0] : row).filter(Boolean);
    const existing = importedUrlInput.value.trim();
    importedUrlInput.value = [existing, ...urls].filter(Boolean).join(existing ? "\n" : "");
    updateInputPreviews();
    showToast(`Imported ${urls.length} Wayback URLs.`, "success");
  } catch (error) {
    showToast(`Wayback fetch failed: ${error.message}`, "error");
  }
});

document.addEventListener("keydown", (event) => {
  const key = event.key.toLowerCase();
  if ((event.ctrlKey || event.metaKey) && key === "enter") {
    event.preventDefault();
    if (crawlerSection.style.display !== "none") startScan(event.shiftKey ? 1 : 0);
    else if (proberSection.style.display !== "none") probeBtn.click();
    else if (reconSection.style.display !== "none") startReconBtn.click();
  }
  if ((event.ctrlKey || event.metaKey) && key === "s") {
    event.preventDefault();
    saveSessionBtn?.click();
  }
  if (event.key === "Escape") {
    state.isCrawlerStopped = true;
    isProberStopped = true;
    isReconStopped = true;
  }
});

// Advanced Exports
const exportCsv = document.getElementById("exportCsv");
const exportMd = document.getElementById("exportMd");
const exportBugReport = document.getElementById("exportBugReport");
const exportUrlList = document.getElementById("exportUrlList");
const exportParamList = document.getElementById("exportParamList");
const exportNuclei = document.getElementById("exportNuclei");
const exportFfuf = document.getElementById("exportFfuf");
const exportBurpXml = document.getElementById("exportBurpXml");
const exportMethodMap = document.getElementById("exportMethodMap");
const saveBaselineBtn = document.getElementById("saveBaselineBtn");
const compareBaselineBtn = document.getElementById("compareBaselineBtn");
const copyHighFindings = document.getElementById("copyHighFindings");
const saveSessionBtn = document.getElementById("saveSessionBtn");
const loadSessionBtn = document.getElementById("loadSessionBtn");
const exportSessionBtn = document.getElementById("exportSessionBtn");
const importSessionBtn = document.getElementById("importSessionBtn");
const importSessionFile = document.getElementById("importSessionFile");
const SESSION_KEY = "web-x-sider:last-session";
const SESSION_INDEX_KEY = "web-x-sider:sessions";
const BASELINE_KEY = "web-x-sider:baseline";

exportCsv.onclick = () => {
  const csv = "Source,Line,Severity,Tag,Type,Value,Hunt Hint,Analyst Note\n" + getVisibleFindings().map(d => `"${d.source}",${d.line},"${d.severity || "low"}","${state.findingTags[getFindingKey(d)] || ""}","${d.type}","${d.value.replace(/"/g, '""')}","${(d.hint || "").replace(/"/g, '""')}","${(state.findingNotes[getFindingKey(d)] || "").replace(/"/g, '""')}"`).join("\n");
  downloadFile("web-x-sider-results.csv", csv, "text/csv");
};

exportMd.onclick = () => {
  let md = "# Web X Sider Scan Results\n\n";
  md += `**Total Endpoints:** ${state.endpoints.size}\n`;
  md += `**Total Secrets:** ${state.secrets.size}\n\n`;

  const grouped = {};
  getVisibleFindings().forEach(d => {
    if (!grouped[d.source]) grouped[d.source] = [];
    grouped[d.source].push(d);
  });

  for (const [src, items] of Object.entries(grouped)) {
    md += `### ${src}\n`;
    items
      .sort((a, b) => (severityRank[b.severity] || 0) - (severityRank[a.severity] || 0))
      .forEach(it => md += `- [${(it.severity || "low").toUpperCase()}] [L${it.line}] [${it.type}] ${it.value}\n  - Hunt hint: ${it.hint || "Review manually."}${state.findingNotes[getFindingKey(it)] ? `\n  - Analyst note: ${state.findingNotes[getFindingKey(it)]}` : ""}\n`);
    md += "\n";
  }
  downloadFile("web-x-sider-report.md", md, "text/markdown");
};

exportTxt.onclick = () => {
  const content = getVisibleFindings().map(d => `[${(d.severity || "low").toUpperCase()}] [L${d.line}] [${d.type}] ${d.value} (Source: ${d.source})\nHint: ${d.hint || "Review manually."}${state.findingNotes[getFindingKey(d)] ? `\nNote: ${state.findingNotes[getFindingKey(d)]}` : ""}`).join("\n\n");
  downloadFile("web-x-sider-endpoints.txt", content, "text/plain");
};

exportBugReport.onclick = () => {
  const sorted = [...getVisibleFindings()]
    .sort((a, b) => (severityRank[b.severity] || 0) - (severityRank[a.severity] || 0))
    .slice(0, 30);

  let report = "# Web X Sider Bug Bounty Triage Report\n\n";
  report += `Generated: ${new Date().toISOString()}\n\n`;
  report += "## Summary\n\n";
  ["critical", "high", "medium", "low"].forEach(level => {
    report += `- ${level.toUpperCase()}: ${getVisibleFindings().filter(item => (item.severity || "low") === level).length}\n`;
  });
  report += "\n## Top Findings\n\n";

  sorted.forEach((item, index) => {
    report += `### ${index + 1}. ${String(item.severity || "low").toUpperCase()} ${item.type}\n\n`;
    report += `- **Target/source:** ${item.source}\n`;
    report += `- **Line:** ${item.line}\n`;
    report += `- **Evidence:** \`${String(item.value).replace(/`/g, "\\`")}\`\n`;
    report += `- **Why it matters:** ${item.hint || "Review manually."}\n`;
    if (state.findingNotes[getFindingKey(item)]) report += `- **Analyst note:** ${state.findingNotes[getFindingKey(item)]}\n`;
    report += "- **Suggested validation:** Reproduce only on authorized scope, confirm access control/impact, capture minimal evidence, and avoid destructive actions.\n\n";
  });

  if (!sorted.length) {
    report += "No findings were collected in this scan.\n";
  }

  downloadFile("web-x-sider-bugbounty-report.md", report, "text/markdown");
};

exportJson.onclick = () => {
  const json = JSON.stringify(getVisibleFindings().map(item => ({
    ...item,
    note: state.findingNotes[getFindingKey(item)] || "",
    tag: state.findingTags[getFindingKey(item)] || ""
  })), null, 2);
  downloadFile("web-x-sider-results.json", json, "application/json");
};

exportUrlList.onclick = () => {
  const urls = new Set();
  getVisibleFindings().forEach(item => {
    if (["endpoint", "file", "parameter"].includes(item.type)) urls.add(item.value);
  });
  state.hostChecks.forEach(item => urls.add(item.url));
  downloadFile("web-x-sider-url-list.txt", [...urls].join("\n"), "text/plain");
};

exportParamList.onclick = () => {
  const rows = ["URL,Parameter,Type"];
  getVisibleFindings()
    .filter(item => item.type === "parameter")
    .forEach(item => {
      try {
        const parsed = new URL(item.value, item.source);
        parsed.searchParams.forEach((value, key) => {
          const risk = classifyFinding("parameter", parsed.href).severity;
          rows.push(`"${parsed.href.replace(/"/g, '""')}","${key.replace(/"/g, '""')}","${risk}"`);
        });
      } catch { }
    });
  downloadFile("web-x-sider-parameters.csv", rows.join("\n"), "text/csv");
};

exportBurpXml.onclick = () => {
  const items = getExportableUrls().map(url => {
    let host = "";
    let path = "";
    let protocol = "";
    try {
      const parsed = new URL(url);
      host = parsed.hostname;
      path = `${parsed.pathname}${parsed.search}`;
      protocol = parsed.protocol.replace(":", "");
    } catch { }
    return [
      "  <item>",
      `    <time>${escapeHtml(new Date().toUTCString())}</time>`,
      `    <url><![CDATA[${url}]]></url>`,
      `    <host ip=\"\">${escapeHtml(host)}</host>`,
      `    <port>${protocol === "https" ? "443" : "80"}</port>`,
      `    <protocol>${escapeHtml(protocol)}</protocol>`,
      `    <path><![CDATA[${path}]]></path>`,
      "    <status>0</status>",
      "    <responselength>0</responselength>",
      "    <mimetype></mimetype>",
      "    <comment>Imported from Web X Sider</comment>",
      "  </item>"
    ].join("\n");
  }).join("\n");
  downloadFile("web-x-sider-burp-sitemap.xml", `<?xml version=\"1.0\"?>\n<items burpVersion=\"Web X Sider\" exportTime=\"${escapeHtml(new Date().toUTCString())}\">\n${items}\n</items>`, "application/xml");
};

exportMethodMap.onclick = () => {
  const rows = ["METHOD,ENDPOINT,PARAMETERS,STATUS,CONFIDENCE"];
  getVisibleFindings()
    .filter(item => ["endpoint", "parameter"].includes(item.type))
    .forEach(item => {
      let url = item.value;
      let params = "";
      try {
        const parsed = new URL(item.value.replace(/\[DYNAMIC\]$/, ""), item.source);
        url = parsed.href;
        params = [...parsed.searchParams.keys()].join("|");
      } catch { }
      const checks = item.methodChecks?.length ? item.methodChecks : [{ method: inferHttpMethod(url) || "GET", status: "", length: "" }];
      checks.forEach(check => {
        rows.push(`"${check.method}","${String(url).replace(/"/g, '""')}","${params.replace(/"/g, '""')}","${check.status || ""}","${getFindingConfidence(item)}"`);
      });
    });
  downloadFile("web-x-sider-method-map.csv", rows.join("\n"), "text/csv");
};

saveBaselineBtn.onclick = () => {
  const payload = buildSessionPayload("Baseline");
  if (safeLocalStorageSet(BASELINE_KEY, JSON.stringify(payload))) {
    showToast("Baseline saved for future diff scans.", "success");
  }
};

compareBaselineBtn.onclick = () => {
  const raw = localStorage.getItem(BASELINE_KEY);
  if (!raw) return showToast("No baseline saved yet.", "warn");
  try {
    const baseline = JSON.parse(raw);
    const oldKeys = new Set((baseline.allData || []).map(item => getFindingKey(item)));
    const newKeys = new Set(state.allData.map(item => getFindingKey(item)));
    const added = state.allData.filter(item => !oldKeys.has(getFindingKey(item)));
    const removed = (baseline.allData || []).filter(item => !newKeys.has(getFindingKey(item)));
    const report = [
      "# Web X Sider Diff",
      "",
      `Baseline: ${baseline.savedAt || "unknown"}`,
      `Current: ${new Date().toISOString()}`,
      "",
      `## New Findings (${added.length})`,
      ...added.map(item => `- [${(item.severity || "low").toUpperCase()}] ${item.type}: ${item.value} (${item.source}:L${item.line})`),
      "",
      `## Removed Findings (${removed.length})`,
      ...removed.map(item => `- [${(item.severity || "low").toUpperCase()}] ${item.type}: ${item.value} (${item.source}:L${item.line})`)
    ].join("\n");
    downloadFile("web-x-sider-diff.md", report, "text/markdown");
    showToast(`Diff ready: ${added.length} new, ${removed.length} removed.`, "success");
  } catch {
    showToast("Baseline could not be loaded.", "error");
  }
};

function getExportableUrls() {
  const urls = new Set();
  getVisibleFindings().forEach(item => {
    if (["endpoint", "file", "parameter"].includes(item.type)) {
      try {
        urls.add(new URL(item.value, item.source).href);
      } catch {
        urls.add(item.value);
      }
    }
  });
  state.hostChecks.forEach(item => {
    if (item.url) urls.add(item.url);
  });
  parseImportedUrls(importedUrlInput?.value || "", getImportBaseUrl()).forEach(url => urls.add(url));
  return [...urls].filter(Boolean).sort();
}

function buildNucleiTemplate() {
  const urls = getExportableUrls();
  const paths = new Set();
  urls.forEach(url => {
    try {
      const parsed = new URL(url);
      paths.add(`${parsed.pathname || "/"}${parsed.search || ""}`);
    } catch { }
  });
  const safePaths = ([...paths].length ? [...paths] : ["/"]).slice(0, 120);
  return [
    "id: web-x-sider-discovered-paths",
    "",
    "info:",
    "  name: Web X Sider Discovered Paths",
    "  author: web-x-sider",
    "  severity: info",
    "  description: Checks paths discovered from authorized Web X Sider scans.",
    "  tags: recon,web-x-sider",
    "",
    "http:",
    "  - method: GET",
    "    path:",
    ...safePaths.map(path => `      - \"{{BaseURL}}${path.replace(/"/g, '\\"')}\"`),
    "",
    "    matchers-condition: or",
    "    matchers:",
    "      - type: status",
    "        status:",
    "          - 200",
    "          - 204",
    "          - 301",
    "          - 302",
    "          - 401",
    "          - 403"
  ].join("\n");
}

function buildFfufCommands() {
  const urls = getExportableUrls();
  const byOrigin = {};
  urls.forEach(url => {
    try {
      const parsed = new URL(url);
      const origin = parsed.origin;
      if (!byOrigin[origin]) byOrigin[origin] = new Set();
      const firstSegment = parsed.pathname.split("/").filter(Boolean)[0];
      if (firstSegment) byOrigin[origin].add(firstSegment);
    } catch { }
  });

  const lines = [
    "# Review scope and authorization before running.",
    "# Replace wordlist path with your local list."
  ];
  Object.entries(byOrigin).forEach(([origin, words]) => {
    const wordlist = [...words].sort();
    if (wordlist.length) {
      lines.push("");
      lines.push(`# ${origin}`);
      lines.push(`printf '${wordlist.map(item => item.replace(/'/g, "'\\''")).join("\\n")}' > web-x-sider-${new URL(origin).hostname}-words.txt`);
      lines.push(`ffuf -u ${origin}/FUZZ -w web-x-sider-${new URL(origin).hostname}-words.txt -mc 200,204,301,302,401,403 -ac`);
    }
  });
  if (lines.length === 2) lines.push("# No exportable URLs were found.");
  return lines.join("\n");
}

function buildHighRiskText() {
  const items = getVisibleFindings()
    .filter(item => ["critical", "high"].includes(item.severity || "low"))
    .sort((a, b) => (severityRank[b.severity] || 0) - (severityRank[a.severity] || 0));
  if (!items.length) return "No high or critical findings are currently visible.";
  return items.map(buildFindingReportText).join("\n\n---\n\n");
}

exportNuclei.onclick = () => {
  downloadFile("web-x-sider-nuclei-template.yaml", buildNucleiTemplate(), "text/yaml");
};

exportFfuf.onclick = () => {
  downloadFile("web-x-sider-ffuf-commands.sh", buildFfufCommands(), "text/plain");
};

copyHighFindings.onclick = async () => {
  try {
    await navigator.clipboard.writeText(buildHighRiskText());
    showToast("High and critical findings copied.", "success");
  } catch {
    showToast("Copy failed. Use an exported report instead.", "error");
  }
};

function buildSessionPayload(name = "Web X Sider Session") {
  return {
    name,
    savedAt: new Date().toISOString(),
    targetUrl: urlInput?.value || "",
    scopeInput: scopeInput?.value || "",
    importedUrlInput: importedUrlInput?.value || "",
    subdomainInput: subdomainInput?.value || "",
    allData: state.allData,
    hostChecks: state.hostChecks,
  hiddenFindings: [...state.hiddenFindings],
  findingNotes: state.findingNotes,
  findingTags: state.findingTags,
  scanDiagnostic: state.scanDiagnostic
  };
}

function restoreSessionPayload(payload) {
  state.allData = Array.isArray(payload.allData) ? payload.allData : [];
  state.dedupKeys = new Set(state.allData.map(item => getFindingKey(item)));
  state.hostChecks = Array.isArray(payload.hostChecks) ? payload.hostChecks : [];
  state.hiddenFindings = new Set(payload.hiddenFindings || []);
  state.findingNotes = payload.findingNotes || {};
  state.findingTags = payload.findingTags || {};
  state.scanDiagnostic = payload.scanDiagnostic || null;
  state.endpoints = new Set(state.allData.filter(item => item.type === "endpoint").map(item => item.value));
  state.secrets = new Set(state.allData.filter(item => item.type === "secret").map(item => item.value));
  state.files = new Set(state.allData.filter(item => item.type === "file").map(item => item.value));
  state.parameters = new Set(state.allData.filter(item => item.type === "parameter").map(item => item.value));
  if (payload.targetUrl !== undefined) urlInput.value = payload.targetUrl || "";
  if (payload.scopeInput !== undefined) scopeInput.value = payload.scopeInput || "";
  if (payload.importedUrlInput !== undefined) importedUrlInput.value = payload.importedUrlInput || "";
  if (payload.subdomainInput !== undefined) subdomainInput.value = payload.subdomainInput || "";
  updateInputPreviews();
  updateStats();
  renderPriorityDashboard();
  renderHostResults();
  document.getElementById("filter-section").style.display = "block";
  exportActions.style.display = "flex";
  renderResults();
}

function getSessionIndex() {
  try {
    return JSON.parse(localStorage.getItem(SESSION_INDEX_KEY) || "[]").filter(Boolean);
  } catch {
    return [];
  }
}

function setSessionIndex(names) {
  safeLocalStorageSet(SESSION_INDEX_KEY, JSON.stringify([...new Set(names)].sort()));
}

saveSessionBtn.onclick = async () => {
  const name = (await showPrompt("Session name:", `Scan ${new Date().toLocaleString()}`) || "").trim();
  if (!name) return;
  const payload = buildSessionPayload(name);
  const serialized = JSON.stringify(payload);
  if (!safeLocalStorageSet(SESSION_KEY, serialized)) return;
  if (!safeLocalStorageSet(`${SESSION_KEY}:${name}`, serialized)) return;
  setSessionIndex([...getSessionIndex(), name]);
  showToast(`Session saved: "${name}"`, "success");
};

loadSessionBtn.onclick = () => {
  const names = getSessionIndex();
  const panel = document.getElementById("session-list-panel");
  const list = document.getElementById("session-list-items");
  if (!names.length) { showToast("No saved sessions found.", "warn"); return; }
  list.innerHTML = "";
  names.forEach(name => {
    const row = document.createElement("div");
    row.style.cssText = "display:flex;align-items:center;gap:8px;padding:6px 10px;background:rgba(255,255,255,0.05);border-radius:8px;";
    const label = document.createElement("span");
    label.style.cssText = "flex:1;font-size:13px;color:rgba(255,255,255,0.85);";
    label.textContent = name;
    const loadBtn = document.createElement("button");
    loadBtn.textContent = "Load";
    loadBtn.style.cssText = "padding:4px 10px;background:#0dcaf0;border:none;border-radius:6px;color:#000;font-size:12px;cursor:pointer;";
    loadBtn.onclick = () => window.loadNamedSession(name);
    const deleteBtn = document.createElement("button");
    deleteBtn.textContent = "Delete";
    deleteBtn.style.cssText = "padding:4px 10px;background:rgba(220,53,69,0.3);border:1px solid rgba(220,53,69,0.5);border-radius:6px;color:#ff6b6b;font-size:12px;cursor:pointer;";
    deleteBtn.onclick = () => window.deleteNamedSession(name);
    row.appendChild(label);
    row.appendChild(loadBtn);
    row.appendChild(deleteBtn);
    list.appendChild(row);
  });
  panel.style.display = panel.style.display === "none" ? "block" : "none";
};

window.loadNamedSession = (name) => {
  const raw = localStorage.getItem(`${SESSION_KEY}:${name}`);
  if (!raw) { showToast(`Session "${name}" not found.`, "error"); return; }
  try {
    restoreSessionPayload(JSON.parse(raw));
    showToast(`Session "${name}" loaded.`, "success");
    document.getElementById("session-list-panel").style.display = "none";
  } catch {
    showToast("Session could not be loaded.", "error");
  }
};

window.deleteNamedSession = async (name) => {
  if (!(await showConfirm(`Delete session "${name}"?`))) return;
  localStorage.removeItem(`${SESSION_KEY}:${name}`);
  setSessionIndex(getSessionIndex().filter(n => n !== name));
  showToast(`Session "${name}" deleted.`, "success");
  loadSessionBtn.click();
};

exportSessionBtn.onclick = async () => {
  const name = (await showPrompt("Export session name:", "Web X Sider Session") || "Web X Sider Session").trim();
  const payload = buildSessionPayload(name);
  downloadFile("web-x-sider-session.json", JSON.stringify(payload, null, 2), "application/json");
};

importSessionBtn.onclick = () => importSessionFile?.click();

importSessionFile?.addEventListener("change", async (event) => {
  const file = event.target.files?.[0];
  if (!file) return;
  try {
    const payload = JSON.parse(await file.text());
    restoreSessionPayload(payload);
  } catch {
    showToast("Session file could not be imported.", "error");
  } finally {
    event.target.value = "";
  }
});

function downloadFile(filename, content, type) {
  const blob = new Blob([content], { type });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  setTimeout(() => {
    URL.revokeObjectURL(link.href);
    document.body.removeChild(link);
  }, 0);
}

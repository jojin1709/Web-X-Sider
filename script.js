const scanBtn = document.getElementById("scanBtn");
const urlInput = document.getElementById("urlInput");
const results = document.getElementById("results");
const status = document.getElementById("status");
const exportActions = document.getElementById("actions");
const exportTxt = document.getElementById("exportTxt");
const exportJson = document.getElementById("exportJson");

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
      url: `${proxy}${encodedUrl}`,
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

  for (const candidate of getFetchCandidates(url, proxyParams)) {
    try {
      const res = await fetch(candidate.url, fetchOptions);

      if (candidate.requiresProxyHeader && res.headers.get(LOCAL_PROXY_HEADER) !== "local") {
        errors.push(`${candidate.label} is not running at ${candidate.url}`);
        continue;
      }

      if (candidate.viaProxy && [403, 502, 504].includes(res.status)) {
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

  throw new Error(`Unable to fetch ${url}. ${errors.join(" | ")}. Test proxy: ${REMOTE_PROXY_ENDPOINTS[0]}https%3A%2F%2Fexample.com`);
}

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
  "Algolia Admin API Key": /algolia.{0,32}([a-z0-9]{32})\b/gi,
  "Algolia Application ID": /algolia.{0,16}([A-Z0-9]{10})\b/gi,
  "Cloudflare API Token": /cloudflare.{0,32}(?:secret|private|access|key|token).{0,32}([a-z0-9_-]{38,42})\b/gi,
  "Cloudflare Service Key": /(?:cloudflare|x-auth-user-service-key).{0,64}(v1\.0-[a-z0-9._-]{160,})\b/gi,
  "MySQL URI with Credentials": /mysql:\/\/[a-z0-9._%+\-]+:[^\s:@]+@(?:\[[0-9a-f:.]+\]|[a-z0-9.-]+)(?::\d{2,5})?(?:\/[^\s"\'?:]+)?(?:\?[^\s"\']*)?/g,
  "Segment Public API Token": /\bsgp_[A-Z0-9_-]{60,70}\b/g,
  "Segment API Key": /(?:segment|sgmt).{0,16}(?:secret|private|access|key|token).{0,16}([A-Z0-9_-]{40,50}\.[A-Z0-9_-]{40,50})/gi,
  "Facebook App ID": /(?:facebook|fb).{0,8}(?:app|application).{0,16}(\d{15})\b/gi,
  "Facebook Secret Key": /(?:facebook|fb).{0,32}(?:api|app|application|client|consumer|secret|key).{0,32}([a-z0-9]{32})\b/gi,
  "Facebook Access Token": /EAACEdEose0cBA[A-Z0-9]{20,}\b/g,
  "Google OAuth2 Access Token": /\bya29\.[a-z0-9_-]{30,}\b/g,
  "Slack Webhook": /https:\/\/hooks\.slack\.com\/services\/[A-Z0-9]+\/[A-Z0-9]+\/[A-Za-z0-9]+/g,
  "Discord Webhook": /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+/g
};

// Fast-Path Check: Only run detailed regexes if one of these keywords is present
const secretTrigger = /AKIA|AIza|sk_live|ghp_|xox[baprs]|eyJ|-----BEGIN|mongodb|postgres|postgresql|algolia|cloudflare|mysql|sgp_|segment|sgmt|facebook|fb|ya29|hooks\.slack\.com|discord\.com\/api\/webhooks/i;

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
  scannedUrls: new Set(),
  probedDomains: new Set(),
  isScanning: false,
  isCrawlerStopped: false,
  fetchFailures: []
};

const updateStats = () => {
  document.getElementById("stat-scanned").innerText = state.scanned;
  document.getElementById("stat-endpoints").innerText = state.endpoints.size;
  document.getElementById("stat-secrets").innerText = state.secrets.size;
  document.getElementById("stat-files").innerText = state.files.size;
  document.getElementById("stat-parameters").innerText = state.parameters.size;
};

const addResult = (source, type, value, line = 0) => {
  // Deduplicate same value at same line in same source ONLY if type is also the same
  if (state.allData.some(d => d.source === source && d.value === value && d.line === line && d.type === type)) return;

  state.allData.push({ source, type, value, line });
  if (type === "endpoint") state.endpoints.add(value);
  if (type === "secret") state.secrets.add(value);
  if (type === "file") state.files.add(value);
  if (type === "parameter") state.parameters.add(value);
  updateStats();
};

const setProgress = (percent) => {
  const p = Math.round(percent);
  document.getElementById("progress-bar").style.width = `${p}%`;
  const textEl = document.getElementById("progress-percent");
  if (textEl) textEl.innerText = `${p}%`;
};

const startScan = async (maxDepth) => {
  let siteUrl = urlInput.value.trim();
  if (!siteUrl) return alert("Enter a valid URL");
  if (!/^https?:\/\//i.test(siteUrl)) siteUrl = "https://" + siteUrl;
  siteUrl = normalizeUrl(siteUrl);

  state.scanned = 0;
  state.endpoints.clear();
  state.secrets.clear();
  state.files.clear();
  state.parameters.clear();
  state.allData = [];
  state.scannedUrls.clear();
  state.fetchFailures = [];
  scannedJs.clear(); // Reset JS scan cache
  updateStats();

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
    if (!state.isCrawlerStopped && state.fetchFailures.length && state.allData.length === 0) {
      status.innerText = `Scan finished, but nothing could be fetched. ${state.fetchFailures[0]}`;
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
    renderResults();
  } catch (e) {
    console.error(e);
    if (!state.isCrawlerStopped) {
      status.innerText = "Scan failed. Check console.";
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
    if (!targetHost) targetHost = currentUrlObj.hostname;

    if (currentUrlObj.hostname !== targetHost && !currentUrlObj.hostname.endsWith("." + targetHost)) {
      return;
    }

    if (currentDepth > maxDepth || state.scannedUrls.has(normUrl)) return;
    state.scannedUrls.add(normUrl);
    state.scanned++;
    updateStats();

    status.innerText = `Scanning: ${normUrl}`;
    setProgress(Math.min(95, (state.scanned / 15) * 100));

    const res = await fetchTarget(normUrl);
    if (!res.ok) {
      const reason = `Skipped ${normUrl} (${res.status} ${res.statusText || "HTTP error"})`;
      state.fetchFailures.push(reason);
      status.innerText = reason;
      return;
    }
    const content = await res.text();

    // Extract data with line numbers
    const foundEndpoints = extractEndpointsWithLines(content);
    const foundSecrets = extractSecretsWithLines(content);
    const foundFiles = extractFilesWithLines(content);

    foundEndpoints.forEach(e => {
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

    for (const script of scripts) {
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

// Optimized Line Counter - O(n) scan instead of O(n) string duplication
function getLineNumber(content, index) {
  let line = 1;
  let pos = 0;
  while ((pos = content.indexOf("\n", pos)) !== -1 && pos < index) {
    line++;
    pos++;
  }
  return line;
}

function extractEndpointsWithLines(content) {
  const matches = [...content.matchAll(endpointRegex)];
  return matches.map(m => ({
    value: m[1],
    line: getLineNumber(content, m.index)
  })).filter(e => {
    // Filter out Webhooks from standard endpoints so they show as Secrets (Warning color)
    if (e.value.includes("hooks.slack.com") || e.value.includes("discord.com/api/webhooks")) return false;
    return filterUrl(e.value);
  });
}

function extractSecretsWithLines(content) {
  // Fast-Path: If nothing looks like a secret, skip 20+ regex scans
  if (!secretTrigger.test(content)) return [];

  const found = [];
  for (const [name, regex] of Object.entries(secretPatterns)) {
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
        line: getLineNumber(content, m.index)
      });
    });
  }
  return found;
}

function extractFilesWithLines(content) {
  // Path-Fidelity File Detection - Updated to prioritize absolute URLs and avoid internal protocol truncation
  const fileRegex = /((?:https?:\/\/|(?<=["']))[^"'\s<>]*\.(?:json|xml|config|env|yaml|yml|sql|db|bak|zip|tar|gz|7z|pdf|doc|docx|js|html|php|asp|aspx|jsp|txt)(?:\?[^"'\s]*)?)(?:["'\s]|$)/gi;
  const matches = [...content.matchAll(fileRegex)];

  return matches.map(m => ({
    value: m[1],
    line: getLineNumber(content, m.index)
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

// Navigation & Tool Switching
const navCrawler = document.getElementById("navCrawler");
const navProber = document.getElementById("navProber");
const navRecon = document.getElementById("navRecon");
const crawlerSection = document.getElementById("crawler-section");
const proberSection = document.getElementById("prober-section");
const reconSection = document.getElementById("recon-section");

navCrawler.onclick = () => {
  navCrawler.classList.add("active");
  navProber.classList.remove("active");
  navRecon.classList.remove("active");
  crawlerSection.style.display = "block";
  proberSection.style.display = "none";
  reconSection.style.display = "none";
};

navProber.onclick = () => {
  navProber.classList.add("active");
  navCrawler.classList.remove("active");
  navRecon.classList.remove("active");
  proberSection.style.display = "block";
  crawlerSection.style.display = "none";
  reconSection.style.display = "none";
};

navRecon.onclick = () => {
  navRecon.classList.add("active");
  navCrawler.classList.remove("active");
  navProber.classList.remove("active");
  reconSection.style.display = "block";
  crawlerSection.style.display = "none";
  proberSection.style.display = "none";
};

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

let proberData = []; // v2.0: Store results for filtering
let activeProberFilter = "all";
let isProberStopped = false;

probeBtn.onclick = async () => {
  let url = proberUrlInput.value.trim();
  if (!url) return alert("Enter a URL to probe");
  if (!/^https?:\/\//i.test(url)) url = "https://" + url;

  try {
    // v2.0 Fix: Strip trailing slash from origin to prevent // in paths
    const origin = new URL(url).origin.replace(/\/+$/, "");
    proberResults.innerHTML = "";
    proberResults.style.display = "block";
    proberProgressContainer.style.display = "block";
    proberFilterSection.style.display = "flex"; // v2.0: Enable live filtering during scan
    proberLengthFilters.style.display = "flex"; // Show length filters
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
    const total = sensitivePaths.length;
    let gotAnyProbeResponse = false;

    for (const path of sensitivePaths) {
      if (isProberStopped) {
        proberStatus.innerText = `Probing stopped manually.`;
        break;
      }
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
        const res = await fetchTarget(fullUrl, { method: 'GET' });
        gotAnyProbeResponse = true;
        const status = res.status;
        const text = await res.text();
        const length = text.length;

        // Update stats
        if (status === 200) stats[200]++;
        else if (status === 403 || status === 401) stats[403]++;
        else stats[404]++; // 404 and others

        proberStat200.innerText = stats[200];
        proberStat403.innerText = stats[403];
        proberStat404.innerText = stats[404];

        const resultItem = { path, status, fullUrl, length };
        proberData.push(resultItem);

        // Live update UI if it matches current filter
        if (doesItemMatchFilters(resultItem)) {
          renderProberLine(path, status, fullUrl, length);
        }
      } catch (e) {
        if (!gotAnyProbeResponse) {
          const message = e.message || "Unknown fetch error";
          proberStatus.innerText = `Prober could not fetch the target. ${message}`;
          renderProberLine(path, "ERROR", fullUrl, 0);
          break;
        }

        stats[404]++;
        proberStat404.innerText = stats[404];
        const resultItem = { path, status: "ERROR", fullUrl, length: 0 };
        proberData.push(resultItem);

        if (doesItemMatchFilters(resultItem)) {
          renderProberLine(path, "ERROR", fullUrl, 0);
        }
      }
    }
    if (!isProberStopped) {
      proberStatus.innerText = `Probing complete! ${total} paths checked.`;
    }
    proberFilterSection.style.display = "flex";
  } catch (e) {
    alert("Invalid URL");
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
      renderProberLine(item.path, item.status, item.fullUrl, item.length);
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

function renderProberLine(path, status, fullUrl, length) {
  const line = document.createElement("div");
  line.className = "prober-line";

  let statusClass = "status-error"; // Default Red
  if (status === 200) statusClass = "status-200"; // Green
  else if (status === 403) statusClass = "status-403"; // Orange
  else if (status === 401) statusClass = "status-401"; // Dark Orange
  else if (status === 404) statusClass = "status-404"; // Red (Specified)

  const lengthDisplay = length !== undefined ? `<span class="prober-length" style="color:var(--text-dim); font-size:0.85em; font-family: monospace;">[${length}]</span>` : '';

  let openBtnHtml = "";
  if (status === 200) {
    openBtnHtml = `<a href="${fullUrl}" target="_blank" class="prober-open-btn-200" style="margin-left: 0;">OPEN🔗</a>`;
  } else if (status === 403 || status === 401) {
    openBtnHtml = `<a href="${fullUrl}" target="_blank" class="prober-open-btn-403" style="margin-left: 0;">OPEN🔗</a>`;
  }

  line.innerHTML = `
    <span class="prober-path" style="flex: 1; word-break: break-all; padding-right: 15px;">${path}</span>
    <div style="display: flex; align-items: center; justify-content: flex-end; flex-shrink: 0;">
      <span class="prober-status ${statusClass}" style="width: 50px; text-align: center;">${status}</span>
      <div style="width: 75px; text-align: center; margin-left: 5px;">${openBtnHtml}</div>
      <div style="width: 75px; text-align: right; margin-left: 5px;">${lengthDisplay}</div>
    </div>
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
  const cookieHeader = getHeader(headers, "x-web-x-sider-set-cookie");
  const weak = [];

  if (csp && /unsafe-inline|unsafe-eval|\*/i.test(csp)) weak.push("CSP contains unsafe-inline, unsafe-eval, or wildcard");
  if (hsts && !/max-age=(?:31536000|[4-9]\d{7,})/i.test(hsts)) weak.push("HSTS max-age looks low");
  if (xcto && !/nosniff/i.test(xcto)) weak.push("X-Content-Type-Options is not nosniff");
  if (cookieHeader) {
    if (!/;\s*secure/i.test(cookieHeader)) weak.push("Set-Cookie missing Secure");
    if (!/;\s*httponly/i.test(cookieHeader)) weak.push("Set-Cookie missing HttpOnly");
    if (!/;\s*samesite=/i.test(cookieHeader)) weak.push("Set-Cookie missing SameSite");
  }

  renderReconCard("Security Headers", "fas fa-lock", [
    ["Missing", missing.length ? missing.map(item => badge(item, "bad")).join("") : badge("none", "good")],
    ...presentRows,
    ["Weak Signals", weak.length ? weak.map(item => badge(item, "warn")).join("") : badge("none spotted", "good")]
  ], missing.length || weak.length ? "warn" : "good");

  return { missing, weak };
}

async function analyzeCors(url) {
  const testOrigins = ["https://evil.example", "null"];
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

function findInterestingSignals(body) {
  const hits = interestingBodySignals
    .filter(signal => signal.pattern.test(body))
    .map(signal => signal.label);

  renderReconCard("Interesting Response Signals", "fas fa-triangle-exclamation", [
    ["Signals", hits.length ? hits.map(item => badge(item, "warn")).join("") : badge("none spotted", "good")]
  ], hits.length ? "warn" : "good");

  return hits;
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
        found.push({ url: candidate, length: text.length });
      }
    } catch { }
  }

  renderReconCard("Source Maps", "fas fa-map", [
    ["Checked", badge(`${limited.length} candidates`, "info")],
    ["Found", found.length ? found.map(item =>
      `<div class="recon-list-item">${urlLine(item.url)} ${badge(`${item.length} bytes`, "warn")}</div>`
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
      checked.push({ url, status: res.status, length: text.length });
    } catch {
      checked.push({ url, status: "ERROR", length: 0 });
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
  if (!url) return alert("Enter a URL to recon");
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

    const allEndpointUrls = [...new Set([...importedUrls, ...extractedEndpoints])];
    setReconProgress(18);
    setReconStatus("Analyzing headers...");
    const headers = analyzeSecurityHeaders(res);

    setReconProgress(32);
    setReconStatus("Checking CORS...");
    const cors = await analyzeCors(url);

    setReconProgress(48);
    setReconStatus("Fingerprinting tech...");
    const tech = detectTech(url, res, body);

    setReconProgress(60);
    setReconStatus("Finding risky parameters...");
    const riskyParams = findRiskyParameters(allEndpointUrls);

    setReconProgress(72);
    setReconStatus("Checking response signals...");
    const signals = findInterestingSignals(body);

    setReconProgress(84);
    setReconStatus("Looking for source maps...");
    const maps = await findSourceMaps(url, body);

    setReconProgress(92);
    setReconStatus("Live-checking endpoints...");
    const endpointChecks = await liveCheckEndpoints(allEndpointUrls, url);
    const liveInteresting = endpointChecks.filter(item => [200, 201, 202, 204, 301, 302, 307, 308, 401, 403].includes(item.status));

    renderReconSummary([
      { label: "Missing Headers", value: headers.missing.length, tone: headers.missing.length ? "bad" : "good", note: headers.missing.length ? "review" : "clean" },
      { label: "CORS Risks", value: cors.length, tone: cors.length ? "bad" : "good", note: cors.length ? "possible issue" : "none" },
      { label: "Source Maps", value: maps.length, tone: maps.length ? "warn" : "good", note: maps.length ? "exposed" : "none" },
      { label: "Risky Params", value: riskyParams.length, tone: riskyParams.length ? "warn" : "good", note: riskyParams.length ? "test manually" : "none" },
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

function renderResults(filter = "", category = "all") {
  results.innerHTML = "";
  const grouped = {};

  state.allData.forEach(item => {
    if (category !== "all" && item.type !== category.slice(0, -1)) return;
    if (filter && !item.value.toLowerCase().includes(filter.toLowerCase())) return;

    if (!grouped[item.source]) grouped[item.source] = [];
    grouped[item.source].push(item);
  });

  const sourceEntries = Object.entries(grouped);
  if (sourceEntries.length === 0) {
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
    items.forEach(item => {
      const li = document.createElement("li");

      const lineSpan = document.createElement("span");
      lineSpan.className = "line-number";
      lineSpan.innerText = `[L${item.line}]`;

      const span = document.createElement("span");
      span.className = `endpoint-text ${item.type === 'secret' ? 'secret-item' : ''}`;
      span.innerText = item.value;

      const copyBtn = document.createElement("button");
      copyBtn.className = "copy-btn";
      copyBtn.innerHTML = "📋";
      copyBtn.onclick = () => copyToClipboard(item.value, copyBtn);

      li.appendChild(lineSpan);
      li.appendChild(span);
      li.appendChild(copyBtn);
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

// Tabs & Filter Logic (Crawler Section)
document.querySelectorAll("#crawler-section .tab-btn").forEach(btn => {
  btn.onclick = () => {
    document.querySelector("#crawler-section .tab-btn.active").classList.remove("active");
    btn.classList.add("active");
    renderResults(document.getElementById("filterInput").value, btn.dataset.tab);
  };
});

document.getElementById("filterInput").oninput = (e) => {
  const activeTab = document.querySelector(".tab-btn.active").dataset.tab;
  renderResults(e.target.value, activeTab);
};

// Advanced Exports
const exportCsv = document.getElementById("exportCsv");
const exportMd = document.getElementById("exportMd");

exportCsv.onclick = () => {
  const csv = "Source,Line,Type,Value\n" + state.allData.map(d => `"${d.source}",${d.line},"${d.type}","${d.value.replace(/"/g, '""')}"`).join("\n");
  downloadFile("web-x-sider-results.csv", csv, "text/csv");
};

exportMd.onclick = () => {
  let md = "# Web X Sider Scan Results\n\n";
  md += `**Total Endpoints:** ${state.endpoints.size}\n`;
  md += `**Total Secrets:** ${state.secrets.size}\n\n`;

  const grouped = {};
  state.allData.forEach(d => {
    if (!grouped[d.source]) grouped[d.source] = [];
    grouped[d.source].push(d);
  });

  for (const [src, items] of Object.entries(grouped)) {
    md += `### ${src}\n`;
    items.forEach(it => md += `- [L${it.line}] [${it.type}] ${it.value}\n`);
    md += "\n";
  }
  downloadFile("web-x-sider-report.md", md, "text/markdown");
};

exportTxt.onclick = () => {
  const content = state.allData.map(d => `[L${d.line}] [${d.type}] ${d.value} (Source: ${d.source})`).join("\n");
  downloadFile("web-x-sider-endpoints.txt", content, "text/plain");
};

exportJson.onclick = () => {
  const json = JSON.stringify(state.allData, null, 2);
  downloadFile("web-x-sider-results.json", json, "application/json");
};

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

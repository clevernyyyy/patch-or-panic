// Copyright (c) 2026 Pixee, Inc. All rights reserved.
//
// This software and associated documentation files (the "Software") are the
// proprietary and confidential property of Pixee, Inc. Unauthorized copying,
// distribution, modification, or use of this Software, via any medium, is
// strictly prohibited without prior written permission from Pixee, Inc.
//
// Use of this Software is subject to the terms of a valid license agreement
// with Pixee, Inc.

const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 3847;
const CACHE_FILE = path.join(__dirname, 'cve_cache.json');
const CACHE_TTL = 8 * 60 * 60 * 1000; // 8 hours

let cvePool = [];
let poolReady = false;
let poolStatus = 'initializing';

// Known vendor → domain for logo fetching
const VENDOR_DOMAINS = {
  microsoft: 'microsoft.com',
  google: 'google.com',
  apple: 'apple.com',
  adobe: 'adobe.com',
  oracle: 'oracle.com',
  ibm: 'ibm.com',
  cisco: 'cisco.com',
  apache: 'apache.org',
  nginx: 'nginx.org',
  wordpress: 'wordpress.org',
  drupal: 'drupal.org',
  php: 'php.net',
  python: 'python.org',
  jenkins: 'jenkins.io',
  docker: 'docker.com',
  kubernetes: 'kubernetes.io',
  atlassian: 'atlassian.com',
  github: 'github.com',
  gitlab: 'gitlab.com',
  mozilla: 'mozilla.org',
  zoom: 'zoom.us',
  fortinet: 'fortinet.com',
  vmware: 'vmware.com',
  broadcom: 'broadcom.com',
  ivanti: 'ivanti.com',
  f5: 'f5.com',
  citrix: 'citrix.com',
  palo_alto_networks: 'paloaltonetworks.com',
  juniper: 'juniper.net',
  juniper_networks: 'juniper.net',
  solarwinds: 'solarwinds.com',
  progress: 'progress.com',
  openssl: 'openssl.org',
  redhat: 'redhat.com',
  canonical: 'ubuntu.com',
  debian: 'debian.org',
  splunk: 'splunk.com',
  elastic: 'elastic.co',
  grafana_labs: 'grafana.com',
  grafana: 'grafana.com',
  hashicorp: 'hashicorp.com',
  mongodb: 'mongodb.com',
  postgresql: 'postgresql.org',
  mysql: 'mysql.com',
  redis: 'redis.io',
  mattermost: 'mattermost.com',
  nextcloud: 'nextcloud.com',
  liferay: 'liferay.com',
  sonatype: 'sonatype.com',
  jetbrains: 'jetbrains.com',
  zoom_video_communications: 'zoom.us',
  checkmk: 'checkmk.com',
  veeam: 'veeam.com',
  openshift: 'redhat.com',
  atlassian_corporation: 'atlassian.com',
  amazon: 'aws.amazon.com',
  amazon_web_services: 'aws.amazon.com',
  salesforce: 'salesforce.com',
  servicenow: 'servicenow.com',
  sap: 'sap.com',
  openstack: 'openstack.org',
  netapp: 'netapp.com',
  dell: 'dell.com',
  hp: 'hp.com',
  lenovo: 'lenovo.com',
  huawei: 'huawei.com',
  samsung: 'samsung.com',
  pfsense: 'pfsense.org',
  opnsense: 'opnsense.org',
  roundcube: 'roundcube.net',
  zimbra: 'zimbra.com',
  exchange: 'microsoft.com',
  sharepoint: 'microsoft.com',
  confluence: 'atlassian.com',
  jira: 'atlassian.com',
  sonarqube: 'sonarsource.com',
  sonarsource: 'sonarsource.com',
  traefik: 'traefik.io',
  minio: 'min.io',
  keycloak: 'keycloak.org',
};

async function nvdGet(params) {
  const qs = new URLSearchParams(params).toString();
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?${qs}`;
  const resp = await fetch(url, {
    headers: {
      'User-Agent': 'PatchOrPanic-Game/1.0 (security-education-game)',
      'Accept': 'application/json',
    },
    signal: AbortSignal.timeout(60000),
  });
  if (!resp.ok) throw new Error(`NVD HTTP ${resp.status}`);
  return resp.json();
}

function isAppCVE(raw) {
  const configs = raw.cve?.configurations || [];
  for (const config of configs) {
    for (const node of config.nodes || []) {
      for (const m of node.cpeMatch || []) {
        // Must be an application CPE *and* actually vulnerable (not just a platform requirement)
        if (m.vulnerable && (m.criteria || '').startsWith('cpe:2.3:a:')) return true;
      }
    }
  }
  return false;
}

function mostCommon(arr) {
  if (!arr.length) return null;
  const freq = {};
  for (const v of arr) freq[v] = (freq[v] || 0) + 1;
  return Object.entries(freq).sort((a, b) => b[1] - a[1])[0][0];
}

function extractVendorProduct(configurations) {
  const vendors = [], products = [];
  for (const config of configurations || []) {
    for (const node of config.nodes || []) {
      for (const m of node.cpeMatch || []) {
        const cpe = m.criteria || '';
        // Only consider application CPEs that are actually vulnerable
        if (!m.vulnerable || !cpe.startsWith('cpe:2.3:a:')) continue;
        const parts = cpe.split(':');
        if (parts[3] && parts[3] !== '*') vendors.push(parts[3]);
        if (parts[4] && parts[4] !== '*') products.push(parts[4]);
      }
    }
  }
  const vendorSet = new Set(vendors);
  const productSet = new Set(products);
  // Use most-frequent vendor/product rather than whichever happens to be first
  const vendor = mostCommon(vendors);
  const domain = vendor ? (VENDOR_DOMAINS[vendor] || null) : null;
  const product = mostCommon(products);
  return {
    vendor,
    vendorDomain: domain,
    product: product ? product.replace(/_/g, ' ') : null,
    affectedProductCount: productSet.size,
    affectedVendorCount: vendorSet.size,
  };
}

function detectAttackType(desc) {
  const d = (desc || '').toLowerCase();
  if (/remote code exec|rce\b/.test(d)) return 'Remote Code Execution';
  if (/sql injection|sqli/.test(d)) return 'SQL Injection';
  if (/cross.site scripting|xss/.test(d)) return 'Cross-Site Scripting';
  if (/cross.site request forgery|csrf/.test(d)) return 'CSRF';
  if (/server.side request forgery|ssrf/.test(d)) return 'SSRF';
  if (/buffer overflow|heap overflow|stack overflow/.test(d)) return 'Buffer Overflow';
  if (/privilege escalation|local privilege|elevat/.test(d)) return 'Privilege Escalation';
  if (/directory traversal|path traversal/.test(d)) return 'Path Traversal';
  if (/command injection|os command/.test(d)) return 'Command Injection';
  if (/code injection/.test(d)) return 'Code Injection';
  if (/xml external entity|xxe/.test(d)) return 'XXE Injection';
  if (/deserialization|insecure deseri/.test(d)) return 'Deserialization';
  if (/use.after.free/.test(d)) return 'Use-After-Free';
  if (/null pointer|null dereference/.test(d)) return 'Null Pointer Deref';
  if (/type confusion/.test(d)) return 'Type Confusion';
  if (/prototype pollution/.test(d)) return 'Prototype Pollution';
  if (/open redirect/.test(d)) return 'Open Redirect';
  if (/authentication bypass|bypass.{0,30}auth|unauthenticated.{0,40}access/.test(d)) return 'Auth Bypass';
  if (/arbitrary file (read|write|upload|delete|access)/.test(d)) return 'Arbitrary File Access';
  if (/information disclosure|sensitive information|data leak/.test(d)) return 'Info Disclosure';
  if (/denial.of.service|resource exhaustion/.test(d)) return 'Denial of Service';
  if (/hardcoded (password|credential|secret|key)/.test(d)) return 'Hardcoded Credentials';
  if (/insecure direct object|idor/.test(d)) return 'IDOR';
  if (/race condition/.test(d)) return 'Race Condition';
  if (/out.of.bounds (read|write|access)/.test(d)) return 'Out-of-Bounds';
  if (/integer overflow|integer underflow/.test(d)) return 'Integer Overflow';
  if (/format string/.test(d)) return 'Format String';
  return null;
}

function parseCVE(raw) {
  const cve = raw.cve;
  if (!cve) return null;

  const desc = (cve.descriptions || []).find((d) => d.lang === 'en')?.value || '';
  if (!desc || desc.startsWith('** RESERVED **') || desc.startsWith('** REJECT **')) return null;

  const metrics = cve.metrics || {};
  const cvssEntry = (metrics.cvssMetricV31 || metrics.cvssMetricV30 || [])[0];
  if (!cvssEntry?.cvssData?.baseScore) return null;

  const c = cvssEntry.cvssData;
  const score = c.baseScore;
  const severity = c.baseSeverity;
  const attackVector = c.attackVector;
  const attackComplexity = c.attackComplexity;
  const privilegesRequired = c.privilegesRequired;
  const userInteraction = c.userInteraction;
  const scope = c.scope;
  const confImpact = c.confidentialityImpact;
  const integImpact = c.integrityImpact;
  const availImpact = c.availabilityImpact;

  const cweRaw = (cve.weaknesses || [])
    .flatMap((w) => (w.description || []).filter((d) => d.lang === 'en').map((d) => d.value))
    .find((v) => v.startsWith('CWE-')) || null;

  const { vendor, vendorDomain, product, affectedProductCount, affectedVendorCount } =
    extractVendorProduct(cve.configurations);

  const attackType = detectAttackType(desc);
  const published = cve.published || '';
  const year = published.substring(0, 4);

  // Calculate EPSS-style "danger hints" from CVSS vector
  const highImpact =
    confImpact === 'HIGH' || integImpact === 'HIGH' || availImpact === 'HIGH';
  const easyToExploit =
    attackVector === 'NETWORK' &&
    attackComplexity === 'LOW' &&
    privilegesRequired === 'NONE' &&
    userInteraction === 'NONE';

  return {
    id: cve.id,
    description: desc,
    score,
    severity,
    attackVector,
    attackComplexity,
    privilegesRequired,
    userInteraction,
    scope,
    confImpact,
    integImpact,
    availImpact,
    highImpact,
    easyToExploit,
    cwe: cweRaw,
    vendor,
    vendorDomain,
    product,
    affectedProductCount,
    affectedVendorCount,
    attackType,
    year,
    published,
  };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// NVD API date filters return 404 regardless of format — use startIndex pagination instead.
// Fetch the tail of the result set (highest CVE IDs = most recent) for a given severity.
async function fetchRecentSeverity(severity, wantCount = 400) {
  try {
    // Step 1: get total count (1 result is enough)
    const meta = await nvdGet({ resultsPerPage: '1', cvssV3Severity: severity });
    const total = meta.totalResults || 0;
    if (total === 0) return [];

    // Step 2: fetch from the tail — CVEs are ordered by ID (oldest first)
    const startIndex = Math.max(0, total - wantCount);
    const result = await nvdGet({
      resultsPerPage: String(wantCount),
      cvssV3Severity: severity,
      startIndex: String(startIndex),
    });
    const vulns = result.vulnerabilities || [];
    return vulns.filter(isAppCVE).map(parseCVE).filter(Boolean);
  } catch (err) {
    console.error(`[NVD] Fetch error (${severity}):`, err.message);
    return [];
  }
}

async function buildPool() {
  console.log('[CVE] Building pool from NVD API (tail-of-list for recency)…');
  poolStatus = 'fetching';
  const all = [];

  const severities = [
    { level: 'CRITICAL', count: 500 },
    { level: 'HIGH',     count: 600 },
    { level: 'MEDIUM',   count: 400 },
  ];

  for (const { level, count } of severities) {
    console.log(`[CVE] Fetching ${level} (tail ${count})…`);
    await sleep(7000); // rate limit: 5 req/30s → 2 req per severity = 1 per 3.5s, be safe
    const batch = await fetchRecentSeverity(level, count);
    console.log(`[CVE]   → ${batch.length} app CVEs`);
    all.push(...batch);
    await sleep(7000);
  }

  // Deduplicate
  const seen = new Set();
  const unique = all.filter((c) => {
    if (seen.has(c.id)) return false;
    seen.add(c.id);
    return true;
  });

  // Filter: require meaningful description and some vendor/product info
  const filtered = unique.filter(
    (c) => c.description.length > 80 && (c.vendor || c.product) && c.score > 0
  );

  // Sort newest first by published date so we favour recent CVEs
  filtered.sort((a, b) => (b.published || '').localeCompare(a.published || ''));

  console.log(`[CVE] Pool ready: ${filtered.length} unique application CVEs`);
  return filtered;
}

async function initPool() {
  // Try cache
  if (fs.existsSync(CACHE_FILE)) {
    try {
      const cached = JSON.parse(fs.readFileSync(CACHE_FILE, 'utf8'));
      const age = Date.now() - (cached.timestamp || 0);
      if (age < CACHE_TTL && Array.isArray(cached.cves) && cached.cves.length >= 80) {
        cvePool = cached.cves;
        poolReady = true;
        poolStatus = 'ready';
        console.log(`[CVE] Loaded ${cvePool.length} CVEs from cache (${Math.round(age / 60000)}min old)`);
        return;
      }
    } catch {
      console.log('[CVE] Cache unreadable, fetching fresh…');
    }
  }

  cvePool = await buildPool();
  poolReady = cvePool.length >= 10;
  poolStatus = poolReady ? 'ready' : 'error';

  if (poolReady) {
    try {
      fs.writeFileSync(CACHE_FILE, JSON.stringify({ timestamp: Date.now(), cves: cvePool }));
      console.log('[CVE] Cache written');
    } catch {}
  }
}

// --- Routes ---
app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/status', (req, res) => {
  res.json({ ready: poolReady, count: cvePool.length, status: poolStatus });
});

app.get('/api/cves', (req, res) => {
  if (!poolReady) return res.status(503).json({ error: 'Pool not ready', status: poolStatus });
  res.json(cvePool);
});

// One-shot LinkedIn share: token exchange + member ID via introspection + post creation.
// Requires LI_CLIENT_SECRET env var: LI_CLIENT_SECRET=<secret> node server.js
app.post('/api/li-share', express.json({ limit: '2mb' }), async (req, res) => {
  const LI_CLIENT_SECRET = process.env.LI_CLIENT_SECRET || '';
  if (!LI_CLIENT_SECRET) {
    return res.status(500).json({ error: 'LI_CLIENT_SECRET not set — restart server with: LI_CLIENT_SECRET=<secret> node server.js' });
  }
  const { code, redirect_uri, client_id, text, imageBase64 } = req.body;
  try {
    // Step 1: exchange auth code for tokens
    const tokenResp = await fetch('https://www.linkedin.com/oauth/v2/accessToken', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri, client_id, client_secret: LI_CLIENT_SECRET }).toString(),
    });
    const tokenData = await tokenResp.json();
    console.log('[LI] token keys:', Object.keys(tokenData));
    const { access_token, id_token } = tokenData;
    if (!access_token) throw new Error('No access_token — ' + (tokenData.error_description || JSON.stringify(tokenData).slice(0, 120)));

    // Step 2: get member ID — from id_token (openid scope) or /v2/userinfo fallback
    let sub;
    if (id_token) {
      const payload = JSON.parse(Buffer.from(id_token.split('.')[1], 'base64url').toString('utf8'));
      sub = String(payload.sub);
    } else {
      const uiResp = await fetch('https://api.linkedin.com/v2/userinfo', {
        headers: { Authorization: `Bearer ${access_token}`, 'LinkedIn-Version': '202608' },
      });
      const uiData = await uiResp.json();
      if (!uiData.sub) throw new Error(`Cannot get member ID: ${JSON.stringify(uiData)}`);
      sub = String(uiData.sub);
    }
    const authorUrn = `urn:li:person:${sub}`;
    console.log('[LI] posting as:', authorUrn);

    // Step 3: optionally upload score card image
    let imageUrn = null;
    if (imageBase64) {
      try {
        const liHeaders = {
          Authorization: `Bearer ${access_token}`,
          'Content-Type': 'application/json',
          'LinkedIn-Version': '202608',
          'X-Restli-Protocol-Version': '2.0.0',
        };
        const initResp = await fetch('https://api.linkedin.com/rest/images?action=initializeUpload', {
          method: 'POST',
          headers: liHeaders,
          body: JSON.stringify({ initializeUploadRequest: { owner: authorUrn } }),
        });
        const initData = await initResp.json();
        const uploadUrl = initData.value?.uploadUrl;
        imageUrn = initData.value?.image || null;
        if (uploadUrl && imageUrn) {
          const imgBuffer = Buffer.from(imageBase64, 'base64');
          await fetch(uploadUrl, {
            method: 'PUT',
            headers: { 'Content-Type': 'image/jpeg' },
            body: imgBuffer,
          });
          console.log('[LI] image uploaded:', imageUrn);
        } else {
          imageUrn = null;
        }
      } catch (imgErr) {
        console.warn('[LI] image upload failed, posting without image:', imgErr.message);
        imageUrn = null;
      }
    }

    // Step 4: create the LinkedIn post via /rest/posts (newer API, accepts urn:li:person:{oidc_sub})
    const postBody = {
      author: authorUrn,
      lifecycleState: 'PUBLISHED',
      visibility: 'PUBLIC',
      commentary: text,
      distribution: {
        feedDistribution: 'MAIN_FEED',
        targetEntities: [],
        thirdPartyDistributionChannels: [],
      },
    };
    if (imageUrn) postBody.content = { media: { id: imageUrn } };

    const postResp = await fetch('https://api.linkedin.com/rest/posts', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${access_token}`,
        'Content-Type': 'application/json',
        'LinkedIn-Version': '202608',
        'X-Restli-Protocol-Version': '2.0.0',
      },
      body: JSON.stringify(postBody),
    });
    if (!postResp.ok) {
      const err = await postResp.text();
      throw new Error(`Post failed (${postResp.status}): ${err.slice(0, 200)}`);
    }
    res.json({ ok: true });
  } catch (e) {
    console.error('[LI] share error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// Start — listen immediately so the frontend loading screen can poll /api/status
app.listen(PORT, () => {
  console.log(`\n🚨  PATCH OR PANIC?  →  http://localhost:${PORT}\n`);
});

// Build pool in background (frontend polls /api/status until ready)
(async () => {
  await initPool();

  // Background refresh
  setInterval(async () => {
    console.log('[CVE] Background refresh…');
    const fresh = await buildPool();
    if (fresh.length >= 50) {
      cvePool = fresh;
      poolReady = true;
      try {
        fs.writeFileSync(CACHE_FILE, JSON.stringify({ timestamp: Date.now(), cves: cvePool }));
      } catch {}
    }
  }, CACHE_TTL);
})();

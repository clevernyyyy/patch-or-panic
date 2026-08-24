// Copyright (c) 2026 Pixee, Inc. All rights reserved.
//
// This software and associated documentation files (the "Software") are the
// proprietary and confidential property of Pixee, Inc. Unauthorized copying,
// distribution, modification, or use of this Software, via any medium, is
// strictly prohibited without prior written permission from Pixee, Inc.
//
// Use of this Software is subject to the terms of a valid license agreement
// with Pixee, Inc.

// Standalone script: fetches CVEs from NVD API and writes public/cves.json.
// Used by GitHub Actions to build the static dataset for GitHub Pages.
// Requires Node.js 18+ (native fetch). No npm dependencies.

const fs   = require('fs');
const path = require('path');

const OUT_FILE  = path.join(__dirname, '..', 'public', 'cves.json');
const API_KEY   = process.env.NVD_API_KEY || '';   // optional — raises rate limit to 50 req/30s

const VENDOR_DOMAINS = {
  microsoft:'microsoft.com', google:'google.com', apple:'apple.com',
  adobe:'adobe.com', oracle:'oracle.com', ibm:'ibm.com', cisco:'cisco.com',
  apache:'apache.org', nginx:'nginx.org', wordpress:'wordpress.org',
  drupal:'drupal.org', php:'php.net', python:'python.org', jenkins:'jenkins.io',
  docker:'docker.com', kubernetes:'kubernetes.io', atlassian:'atlassian.com',
  github:'github.com', gitlab:'gitlab.com', mozilla:'mozilla.org', zoom:'zoom.us',
  fortinet:'fortinet.com', vmware:'vmware.com', broadcom:'broadcom.com',
  ivanti:'ivanti.com', f5:'f5.com', citrix:'citrix.com',
  palo_alto_networks:'paloaltonetworks.com', juniper:'juniper.net',
  juniper_networks:'juniper.net', solarwinds:'solarwinds.com',
  progress:'progress.com', openssl:'openssl.org', redhat:'redhat.com',
  canonical:'ubuntu.com', debian:'debian.org', splunk:'splunk.com',
  elastic:'elastic.co', grafana_labs:'grafana.com', grafana:'grafana.com',
  hashicorp:'hashicorp.com', mongodb:'mongodb.com', postgresql:'postgresql.org',
  mysql:'mysql.com', redis:'redis.io', mattermost:'mattermost.com',
  nextcloud:'nextcloud.com', liferay:'liferay.com', sonatype:'sonatype.com',
  jetbrains:'jetbrains.com', zoom_video_communications:'zoom.us',
  checkmk:'checkmk.com', veeam:'veeam.com', openshift:'redhat.com',
  atlassian_corporation:'atlassian.com', amazon:'aws.amazon.com',
  amazon_web_services:'aws.amazon.com', salesforce:'salesforce.com',
  servicenow:'servicenow.com', sap:'sap.com', openstack:'openstack.org',
  netapp:'netapp.com', dell:'dell.com', hp:'hp.com', lenovo:'lenovo.com',
  huawei:'huawei.com', samsung:'samsung.com', pfsense:'pfsense.org',
  opnsense:'opnsense.org', roundcube:'roundcube.net', zimbra:'zimbra.com',
  exchange:'microsoft.com', sharepoint:'microsoft.com',
  confluence:'atlassian.com', jira:'atlassian.com',
  sonarqube:'sonarsource.com', sonarsource:'sonarsource.com',
  traefik:'traefik.io', minio:'min.io', keycloak:'keycloak.org',
};

async function nvdGet(params) {
  const qs  = new URLSearchParams(params).toString();
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?${qs}`;
  const headers = { 'User-Agent': 'PatchOrPanic-Game/1.0 (security-education-game)', Accept: 'application/json' };
  if (API_KEY) headers['apiKey'] = API_KEY;
  const resp = await fetch(url, { headers, signal: AbortSignal.timeout(60000) });
  if (!resp.ok) throw new Error(`NVD HTTP ${resp.status}`);
  return resp.json();
}

function isAppCVE(raw) {
  for (const config of raw.cve?.configurations || [])
    for (const node of config.nodes || [])
      for (const m of node.cpeMatch || [])
        if (m.vulnerable && (m.criteria || '').startsWith('cpe:2.3:a:')) return true;
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
  for (const config of configurations || [])
    for (const node of config.nodes || [])
      for (const m of node.cpeMatch || []) {
        const cpe = m.criteria || '';
        if (!m.vulnerable || !cpe.startsWith('cpe:2.3:a:')) continue;
        const parts = cpe.split(':');
        if (parts[3] && parts[3] !== '*') vendors.push(parts[3]);
        if (parts[4] && parts[4] !== '*') products.push(parts[4]);
      }
  const vendor  = mostCommon(vendors);
  const product = mostCommon(products);
  return {
    vendor,
    vendorDomain: vendor ? (VENDOR_DOMAINS[vendor] || null) : null,
    product: product ? product.replace(/_/g, ' ') : null,
    affectedProductCount: new Set(products).size,
    affectedVendorCount:  new Set(vendors).size,
  };
}

function detectAttackType(desc) {
  const d = (desc || '').toLowerCase();
  if (/remote code exec|rce\b/.test(d))                              return 'Remote Code Execution';
  if (/sql injection|sqli/.test(d))                                  return 'SQL Injection';
  if (/cross.site scripting|xss/.test(d))                           return 'Cross-Site Scripting';
  if (/cross.site request forgery|csrf/.test(d))                    return 'CSRF';
  if (/server.side request forgery|ssrf/.test(d))                   return 'SSRF';
  if (/buffer overflow|heap overflow|stack overflow/.test(d))       return 'Buffer Overflow';
  if (/privilege escalation|local privilege|elevat/.test(d))        return 'Privilege Escalation';
  if (/directory traversal|path traversal/.test(d))                 return 'Path Traversal';
  if (/command injection|os command/.test(d))                       return 'Command Injection';
  if (/code injection/.test(d))                                     return 'Code Injection';
  if (/xml external entity|xxe/.test(d))                            return 'XXE Injection';
  if (/deserialization|insecure deseri/.test(d))                    return 'Deserialization';
  if (/use.after.free/.test(d))                                     return 'Use-After-Free';
  if (/null pointer|null dereference/.test(d))                      return 'Null Pointer Deref';
  if (/type confusion/.test(d))                                     return 'Type Confusion';
  if (/prototype pollution/.test(d))                                return 'Prototype Pollution';
  if (/open redirect/.test(d))                                      return 'Open Redirect';
  if (/authentication bypass|bypass.{0,30}auth|unauthenticated.{0,40}access/.test(d)) return 'Auth Bypass';
  if (/arbitrary file (read|write|upload|delete|access)/.test(d))  return 'Arbitrary File Access';
  if (/information disclosure|sensitive information|data leak/.test(d)) return 'Info Disclosure';
  if (/denial.of.service|resource exhaustion/.test(d))             return 'Denial of Service';
  if (/hardcoded (password|credential|secret|key)/.test(d))        return 'Hardcoded Credentials';
  if (/insecure direct object|idor/.test(d))                        return 'IDOR';
  if (/race condition/.test(d))                                     return 'Race Condition';
  if (/out.of.bounds (read|write|access)/.test(d))                 return 'Out-of-Bounds';
  if (/integer overflow|integer underflow/.test(d))                 return 'Integer Overflow';
  if (/format string/.test(d))                                      return 'Format String';
  return null;
}

function parseCVE(raw) {
  const cve = raw.cve;
  if (!cve) return null;
  const desc = (cve.descriptions || []).find(d => d.lang === 'en')?.value || '';
  if (!desc || desc.startsWith('** RESERVED **') || desc.startsWith('** REJECT **')) return null;
  const metrics   = cve.metrics || {};
  const cvssEntry = (metrics.cvssMetricV31 || metrics.cvssMetricV30 || [])[0];
  if (!cvssEntry?.cvssData?.baseScore) return null;
  const c = cvssEntry.cvssData;
  const cweRaw = (cve.weaknesses || [])
    .flatMap(w => (w.description || []).filter(d => d.lang === 'en').map(d => d.value))
    .find(v => v.startsWith('CWE-')) || null;
  const { vendor, vendorDomain, product, affectedProductCount, affectedVendorCount } =
    extractVendorProduct(cve.configurations);
  const published = cve.published || '';
  return {
    id: cve.id, description: desc,
    score: c.baseScore, severity: c.baseSeverity,
    attackVector: c.attackVector, attackComplexity: c.attackComplexity,
    privilegesRequired: c.privilegesRequired, userInteraction: c.userInteraction,
    scope: c.scope, confImpact: c.confidentialityImpact,
    integImpact: c.integrityImpact, availImpact: c.availabilityImpact,
    highImpact: c.confidentialityImpact === 'HIGH' || c.integrityImpact === 'HIGH' || c.availabilityImpact === 'HIGH',
    easyToExploit: c.attackVector === 'NETWORK' && c.attackComplexity === 'LOW' && c.privilegesRequired === 'NONE' && c.userInteraction === 'NONE',
    cwe: cweRaw, vendor, vendorDomain, product,
    affectedProductCount, affectedVendorCount,
    attackType: detectAttackType(desc),
    year: published.substring(0, 4), published,
  };
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

// Delay between requests (ms). NVD allows 5 req/30s without key, 50/30s with key.
const DELAY = API_KEY ? 700 : 7000;

async function fetchRecentSeverity(severity, wantCount = 400) {
  try {
    const meta  = await nvdGet({ resultsPerPage: '1', cvssV3Severity: severity });
    const total = meta.totalResults || 0;
    if (total === 0) return [];
    await sleep(DELAY);
    const result = await nvdGet({
      resultsPerPage: String(wantCount),
      cvssV3Severity: severity,
      startIndex: String(Math.max(0, total - wantCount)),
    });
    return (result.vulnerabilities || []).filter(isAppCVE).map(parseCVE).filter(Boolean);
  } catch (err) {
    console.error(`[NVD] Fetch error (${severity}):`, err.message);
    return [];
  }
}

async function buildPool() {
  const all = [];
  for (const { level, count } of [
    { level: 'CRITICAL', count: 500 },
    { level: 'HIGH',     count: 600 },
    { level: 'MEDIUM',   count: 400 },
  ]) {
    console.log(`[CVE] Fetching ${level} (tail ${count})…`);
    const batch = await fetchRecentSeverity(level, count);
    console.log(`[CVE]   → ${batch.length} app CVEs`);
    all.push(...batch);
    await sleep(DELAY);
  }
  const seen = new Set();
  const unique = all.filter(c => { if (seen.has(c.id)) return false; seen.add(c.id); return true; });
  const filtered = unique.filter(c => c.description.length > 80 && (c.vendor || c.product) && c.score > 0);
  filtered.sort((a, b) => (b.published || '').localeCompare(a.published || ''));
  return filtered;
}

async function main() {
  console.log('[CVE] Building static CVE dataset for GitHub Pages…');
  if (API_KEY) console.log('[CVE] Using NVD API key (higher rate limit)');
  else console.log('[CVE] No NVD_API_KEY set — using anonymous rate limit (slow)');

  const pool = await buildPool();
  console.log(`[CVE] Pool: ${pool.length} unique application CVEs`);

  fs.mkdirSync(path.dirname(OUT_FILE), { recursive: true });
  fs.writeFileSync(OUT_FILE, JSON.stringify(pool));
  console.log(`[CVE] Written to ${OUT_FILE}`);
}

main().catch(e => { console.error('[CVE] Fatal:', e.message); process.exit(1); });

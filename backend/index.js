const http = require('http');
const https = require('https');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');

// ═══════════════════════════════════════════════════════════════════
// REQUIRED ENVIRONMENT VARIABLES
// ═══════════════════════════════════════════════════════════════════
const SEARXNG_URL = process.env.SEARXNG_URL;
const GROQ_API_KEY = process.env.GROQ_API_KEY;
const GROQ_MODEL = process.env.GROQ_MODEL || 'llama-3.3-70b-versatile';
const NVD_API_KEY = process.env.NVD_API_KEY || null;
const ABUSEIPDB_API_KEY = process.env.ABUSEIPDB_API_KEY || null;
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || 'http://localhost:3000';
const SEARXNG_ENGINES = process.env.SEARXNG_ENGINES || 'google,bing,duckduckgo,startpage';
const SEARXNG_MAX_RESULTS = parseInt(process.env.SEARXNG_MAX_RESULTS || '5');

const missingVars = [];
if (!SEARXNG_URL) missingVars.push('SEARXNG_URL');
if (!GROQ_API_KEY) missingVars.push('GROQ_API_KEY');

if (missingVars.length > 0) {
  console.error('❌ FATAL: Missing required environment variables!');
  missingVars.forEach(v => console.error(`   - ${v}`));
  process.exit(1);
}

console.log('✅ Environment variables loaded:');
console.log(`   SEARXNG_URL       = ${SEARXNG_URL}`);
console.log(`   GROQ_API_KEY      = ${GROQ_API_KEY ? GROQ_API_KEY.slice(0, 10) + '...' : 'NOT SET'}`);
console.log(`   GROQ_MODEL        = ${GROQ_MODEL}`);
console.log(`   NVD_API_KEY       = ${NVD_API_KEY ? NVD_API_KEY.slice(0, 10) + '...' : 'NOT SET'}`);
console.log(`   ABUSEIPDB_API_KEY = ${ABUSEIPDB_API_KEY ? ABUSEIPDB_API_KEY.slice(0, 10) + '...' : 'NOT SET'}`);
console.log(`   ALLOWED_ORIGIN    = ${ALLOWED_ORIGIN}`);

// ── Backblaze B2 Client ────────────────────────────────────────────
const { S3Client, GetObjectCommand, PutObjectCommand, DeleteObjectCommand, HeadObjectCommand } = require('@aws-sdk/client-s3');

const b2 = new S3Client({
  region: process.env.B2_BUCKET_REGION || 'us-west-004',
  endpoint: process.env.B2_ENDPOINT,
  credentials: {
    accessKeyId: process.env.B2_KEY_ID,
    secretAccessKey: process.env.B2_APP_KEY,
  },
  requestChecksumCalculation: 'WHEN_REQUIRED',
  responseChecksumValidation: 'WHEN_REQUIRED',
});

async function downloadFromB2(b2Key, destPath) {
  console.log(`[B2] Downloading ${b2Key} → ${destPath}`);
  const res = await b2.send(new GetObjectCommand({
    Bucket: process.env.B2_BUCKET_NAME,
    Key: b2Key,
  }));
  await new Promise((resolve, reject) => {
    const ws = fs.createWriteStream(destPath);
    res.Body.pipe(ws);
    ws.on('finish', resolve);
    ws.on('error', reject);
  });
  console.log(`[B2] ✓ Download complete`);
}

async function deleteFromB2(b2Key) {
  try {
    await b2.send(new DeleteObjectCommand({
      Bucket: process.env.B2_BUCKET_NAME,
      Key: b2Key,
    }));
    console.log(`[B2] Deleted ${b2Key}`);
  } catch (e) {
    console.error(`[B2] Delete failed: ${e.message}`);
  }
}

/**
 * Check if a key exists in B2 without downloading it
 */
async function existsInB2(b2Key) {
  try {
    await b2.send(new HeadObjectCommand({
      Bucket: process.env.B2_BUCKET_NAME,
      Key: b2Key,
    }));
    return true;
  } catch (_) {
    return false;
  }
}

/**
 * Fetch JSON from B2, returns null if not found
 */
async function fetchB2JSON(b2Key) {
  try {
    const r = await b2.send(new GetObjectCommand({
      Bucket: process.env.B2_BUCKET_NAME,
      Key: b2Key,
    }));
    const text = await r.Body.transformToString();
    return JSON.parse(text);
  } catch (_) {
    return null;
  }
}

// ═══════════════════════════════════════════════════════════════════
// IANA PORT REGISTRY - Dynamic Fetch from Official IANA CSV
// ═══════════════════════════════════════════════════════════════════
const IANA_CSV_URL = 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv';
const IANA_CACHE_FILE = './iana_ports_cache.json';
const IANA_CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours

let ianaPortRegistry = new Map();
let ianaLastFetch = 0;
let ianaFetchPromise = null;

// Secure services (encrypted by default) — still makes sense to keep as a small set
const SECURE_SERVICES = new Set([
  'ssh', 'https', 'imaps', 'pop3s', 'ldaps', 'smtps', 'sips', 'ftps', 'dot', 'doq',
  'tls', 'ssl', 'quic'
]);

async function fetchIANARegistry() {
  if (ianaFetchPromise) return ianaFetchPromise;
  if (ianaPortRegistry.size > 0 && (Date.now() - ianaLastFetch) < IANA_CACHE_TTL) {
    return ianaPortRegistry;
  }

  if (fs.existsSync(IANA_CACHE_FILE)) {
    try {
      const cacheData = JSON.parse(fs.readFileSync(IANA_CACHE_FILE, 'utf8'));
      if (cacheData.timestamp && (Date.now() - cacheData.timestamp) < IANA_CACHE_TTL) {
        console.log('[IANA] ✓ Loaded from local cache');
        ianaPortRegistry = new Map(Object.entries(cacheData.ports).map(([k, v]) => [parseInt(k), v]));
        ianaLastFetch = cacheData.timestamp;
        return ianaPortRegistry;
      }
    } catch (e) {
      console.log('[IANA] Cache file corrupted, will refetch');
    }
  }

  ianaFetchPromise = new Promise((resolve) => {
    console.log('[IANA] Fetching official registry from iana.org...');
    https.get(IANA_CSV_URL, { timeout: 30000, headers: { 'Accept': 'text/csv' } }, (res) => {
      if (res.statusCode !== 200) {
        console.error(`[IANA] HTTP ${res.statusCode}`);
        ianaFetchPromise = null;
        return resolve(new Map());
      }
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const parsed = parseIANACSV(data);
          ianaPortRegistry = parsed;
          ianaLastFetch = Date.now();
          const cacheObj = {
            timestamp: ianaLastFetch,
            ports: Object.fromEntries([...ianaPortRegistry].map(([k, v]) => [k.toString(), v]))
          };
          fs.writeFileSync(IANA_CACHE_FILE, JSON.stringify(cacheObj));
          console.log(`[IANA] ✓ Loaded ${ianaPortRegistry.size} port entries`);
          ianaFetchPromise = null;
          resolve(ianaPortRegistry);
        } catch (e) {
          console.error(`[IANA] Parse error: ${e.message}`);
          ianaFetchPromise = null;
          resolve(new Map());
        }
      });
    }).on('error', (e) => {
      console.error(`[IANA] Fetch error: ${e.message}`);
      ianaFetchPromise = null;
      resolve(new Map());
    }).on('timeout', () => {
      console.error('[IANA] Timeout');
      ianaFetchPromise = null;
      resolve(new Map());
    });
  });

  return ianaFetchPromise;
}

function parseIANACSV(csvData) {
  const lines = csvData.split('\n');
  const portMap = new Map();
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    const parts = parseCSVLine(line);
    if (parts.length < 4) continue;
    const serviceName = parts[0]?.trim() || '';
    const portNumber = parts[1]?.trim() || '';
    const protocol = parts[2]?.trim() || '';
    const description = parts[3]?.trim() || '';
    if (!portNumber || !serviceName) continue;
    if (portNumber.includes('-')) {
      const [start, end] = portNumber.split('-').map(p => parseInt(p.trim()));
      if (!isNaN(start) && !isNaN(end)) {
        for (let port = start; port <= end; port++) {
          addPortToRegistry(portMap, port, serviceName, protocol, description);
        }
      }
    } else {
      const port = parseInt(portNumber);
      if (!isNaN(port)) addPortToRegistry(portMap, port, serviceName, protocol, description);
    }
  }
  return portMap;
}

function parseCSVLine(line) {
  const parts = [];
  let current = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    if (char === '"') { inQuotes = !inQuotes; }
    else if (char === ',' && !inQuotes) { parts.push(current); current = ''; }
    else { current += char; }
  }
  parts.push(current);
  return parts;
}

function addPortToRegistry(portMap, port, serviceName, protocol, description) {
  if (portMap.has(port)) return;
  const serviceLower = serviceName.toLowerCase();
  const isSecure = SECURE_SERVICES.has(serviceLower);
  portMap.set(port, {
    service: serviceName,
    description: description || `${serviceName} Protocol`,
    protocol: protocol || 'TCP/UDP',
    secure: isSecure
    // NOTE: risks are now fetched dynamically from SearXNG, not hardcoded
  });
}

async function getIANAPortInfo(port) {
  const portNum = parseInt(port);
  if (isNaN(portNum)) return null;
  const registry = await fetchIANARegistry();
  const info = registry.get(portNum);
  if (info) {
    return {
      port: portNum,
      service_name: info.service,
      description: info.description,
      protocol: info.protocol,
      secure: info.secure || false,
      source: 'IANA Registry'
    };
  }
  if (portNum >= 49152 && portNum <= 65535) {
    return { port: portNum, service_name: 'Ephemeral', description: 'Dynamic/private port', protocol: 'TCP/UDP', secure: true, source: 'IANA Registry' };
  }
  if (portNum >= 1024 && portNum < 49152) {
    return { port: portNum, service_name: 'Registered', description: 'Registered port - service depends on application', protocol: 'TCP/UDP', secure: false, source: 'IANA Registry' };
  }
  return { port: portNum, service_name: 'Unknown', description: 'Unassigned or unknown service', protocol: 'Unknown', secure: false, source: 'IANA Registry' };
}

fetchIANARegistry().then(() => console.log('[IANA] Registry initialized')).catch(e => console.error('[IANA] Init error:', e.message));

// ═══════════════════════════════════════════════════════════════════
// SearXNG - Dynamic Security Risk Lookup (replaces hardcoded map!)
// ═══════════════════════════════════════════════════════════════════
const searxngRiskCache = new Map();
const SEARXNG_RISK_TTL = 24 * 60 * 60 * 1000; // 24 hours

async function fetchServiceRisksFromSearXNG(serviceName) {
  if (!serviceName || serviceName === 'Unknown' || serviceName === 'Ephemeral' || serviceName === 'Registered') {
    return { risks: [], alternatives: [] };
  }

  const cacheKey = serviceName.toLowerCase();
  const cached = searxngRiskCache.get(cacheKey);
  if (cached && (Date.now() - cached.timestamp) < SEARXNG_RISK_TTL) {
    return cached.data;
  }

  try {
    const query = `${serviceName} protocol security risks vulnerabilities`;
    const results = await searchSearXNG(query, 8000);

    const risks = [];
    const alternatives = [];

    if (results.results && results.results.length > 0) {
      // Extract risk keywords from snippets
      const riskKeywords = [
        'unencrypted', 'cleartext', 'clear text', 'plain text', 'no authentication',
        'brute force', 'default credentials', 'buffer overflow', 'injection',
        'man-in-the-middle', 'mitm', 'spoofing', 'amplification', 'ddos',
        'information disclosure', 'data exposure', 'unauthenticated', 'anonymous',
        'privilege escalation', 'remote code execution', 'rce', 'exploit',
        'backdoor', 'malware', 'ransomware', 'exfiltration', 'tunneling',
        'weak encryption', 'deprecated', 'insecure', 'vulnerable', 'attack'
      ];

      const altKeywords = [
        'use instead', 'replace with', 'alternative', 'secure version',
        'recommended', 'upgrade to', 'switch to', 'migrate to', 'prefer'
      ];

      for (const result of results.results.slice(0, 5)) {
        const text = (result.title + ' ' + result.snippet).toLowerCase();

        // Extract risks
        for (const keyword of riskKeywords) {
          if (text.includes(keyword)) {
            const risk = capitalizeFirst(keyword.replace(/-/g, ' '));
            if (!risks.includes(risk)) risks.push(risk);
          }
        }

        // Extract alternatives
        for (const keyword of altKeywords) {
          const idx = text.indexOf(keyword);
          if (idx !== -1) {
            const snippet = text.slice(idx, idx + 60);
            // Look for protocol names after the keyword
            const protoMatch = snippet.match(/(?:ssh|sftp|https|ldaps|smtps|tls|ssl|snmpv3|imaps|pop3s|ftps|scp)\b/i);
            if (protoMatch && !alternatives.includes(protoMatch[0].toUpperCase())) {
              alternatives.push(protoMatch[0].toUpperCase());
            }
          }
        }
      }
    }

    const data = {
      risks: risks.slice(0, 6),
      alternatives: alternatives.slice(0, 3)
    };

    searxngRiskCache.set(cacheKey, { data, timestamp: Date.now() });
    console.log(`[SearXNG] ✓ Risks for ${serviceName}: ${data.risks.length} found`);
    return data;

  } catch (e) {
    console.error(`[SearXNG] Risk fetch error for ${serviceName}: ${e.message}`);
    return { risks: [], alternatives: [] };
  }
}

function capitalizeFirst(str) {
  return str.charAt(0).toUpperCase() + str.slice(1);
}

/**
 * Batch fetch risks for multiple unique services in parallel
 */
async function batchFetchServiceRisks(serviceNames) {
  const unique = [...new Set(serviceNames.filter(s =>
    s && s !== 'Unknown' && s !== 'Ephemeral' && s !== 'Registered'
  ))];

  console.log(`[SearXNG] Batch fetching risks for ${unique.length} unique services...`);

  const results = new Map();
  await Promise.all(unique.map(async (name) => {
    const risk = await fetchServiceRisksFromSearXNG(name);
    results.set(name.toLowerCase(), risk);
  }));

  return results;
}

// ═══════════════════════════════════════════════════════════════════
// NVD API - CVE Lookups
// ═══════════════════════════════════════════════════════════════════
const nvdCache = new Map();
const NVD_CACHE_TTL = 24 * 60 * 60 * 1000;
let nvdRequestQueue = [];
let nvdProcessing = false;

async function fetchCVEsFromNVD(serviceName, limit = 5) {
  if (!serviceName) return [];
  const cacheKey = serviceName.toLowerCase();
  const cached = nvdCache.get(cacheKey);
  if (cached && (Date.now() - cached.timestamp) < NVD_CACHE_TTL) return cached.data;

  return new Promise((resolve) => {
    nvdRequestQueue.push({ serviceName, limit, resolve });
    processNVDQueue();
  });
}

async function processNVDQueue() {
  if (nvdProcessing || nvdRequestQueue.length === 0) return;
  nvdProcessing = true;
  while (nvdRequestQueue.length > 0) {
    const request = nvdRequestQueue.shift();
    const cacheKey = request.serviceName.toLowerCase();
    const cached = nvdCache.get(cacheKey);
    if (cached && (Date.now() - cached.timestamp) < NVD_CACHE_TTL) {
      request.resolve(cached.data);
      continue;
    }
    const result = await fetchNVDDirect(request.serviceName, request.limit);
    request.resolve(result);
    await new Promise(r => setTimeout(r, NVD_API_KEY ? 600 : 6000));
  }
  nvdProcessing = false;
}

function fetchNVDDirect(serviceName, limit) {
  return new Promise((resolve) => {
    const queryParams = new URLSearchParams({ keywordSearch: serviceName, resultsPerPage: limit.toString() });
    const headers = {};
    if (NVD_API_KEY) headers['apiKey'] = NVD_API_KEY;
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?${queryParams.toString()}`;
    console.log(`[NVD] Fetching CVEs for: ${serviceName}`);
    const req = https.get(url, { headers, timeout: 15000 }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          if (res.statusCode !== 200) return resolve([]);
          const json = JSON.parse(data);
          const cves = (json.vulnerabilities || []).slice(0, limit).map(vuln => {
            const cve = vuln.cve;
            const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV2?.[0] || {};
            const cvssData = metrics.cvssData || {};
            return {
              cve_id: cve.id,
              cvss_score: cvssData.baseScore || null,
              severity: cvssData.baseSeverity || metrics.baseSeverity || 'UNKNOWN',
              description: cve.descriptions?.[0]?.value || 'No description available',
              published: cve.published,
              modified: cve.lastModified
            };
          });
          nvdCache.set(serviceName.toLowerCase(), { data: cves, timestamp: Date.now() });
          console.log(`[NVD] ✓ Found ${cves.length} CVEs for ${serviceName}`);
          resolve(cves);
        } catch (e) {
          console.error(`[NVD] Parse error: ${e.message}`);
          resolve([]);
        }
      });
    });
    req.on('error', () => resolve([]));
    req.on('timeout', () => { req.destroy(); resolve([]); });
    req.end();
  });
}

async function batchFetchCVEs(portServiceMap) {
  const uniqueServices = new Set();
  for (const [, serviceName] of portServiceMap) {
    if (serviceName && serviceName !== 'Unknown' && serviceName !== 'Ephemeral' && serviceName !== 'Registered') {
      uniqueServices.add(serviceName.toLowerCase().split(/[\s-]/)[0]);
    }
  }
  console.log(`[NVD] Batch: ${uniqueServices.size} unique services from ${portServiceMap.size} ports`);
  const results = new Map();
  await Promise.all([...uniqueServices].map(async service => {
    results.set(service, await fetchCVEsFromNVD(service, 3));
  }));
  const portCVEMap = new Map();
  for (const [port, serviceName] of portServiceMap) {
    const normalized = serviceName?.toLowerCase().split(/[\s-]/)[0];
    if (normalized && results.has(normalized)) portCVEMap.set(port, results.get(normalized));
  }
  return portCVEMap;
}

// ═══════════════════════════════════════════════════════════════════
// AbuseIPDB - IP Reputation
// ═══════════════════════════════════════════════════════════════════
const ipReputationCache = new Map();
const IP_CACHE_TTL = 60 * 60 * 1000;
const IP_BATCH_SIZE = 10;

function isPrivateIP(ip) {
  return !ip ||
    ip.startsWith('192.168.') || ip.startsWith('10.') ||
    ip.startsWith('172.16.') || ip === '127.0.0.1' ||
    ip.startsWith('169.254.') || ip.startsWith('::1') ||
    ip.startsWith('fe80:');
}

async function checkIPReputation(ip) {
  if (isPrivateIP(ip)) return { ip, abuse_score: 0, is_malicious: false, source: 'Local IP' };
  const cached = ipReputationCache.get(ip);
  if (cached && (Date.now() - cached.timestamp) < IP_CACHE_TTL) return cached.data;
  if (!ABUSEIPDB_API_KEY) return { ip, abuse_score: 0, is_malicious: false, source: 'No API Key' };

  return new Promise((resolve) => {
    const queryParams = new URLSearchParams({ ipAddress: ip, maxAgeInDays: '90', verbose: '' });
    const options = {
      hostname: 'api.abuseipdb.com',
      path: `/api/v2/check?${queryParams.toString()}`,
      method: 'GET',
      headers: { 'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json' },
      timeout: 10000
    };
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          if (res.statusCode !== 200) return resolve({ ip, abuse_score: 0, is_malicious: false, source: 'Error' });
          const json = JSON.parse(data);
          const result = json.data || {};
          const abuseScore = result.abuseConfidenceScore || 0;
          const reputation = {
            ip, abuse_score: abuseScore,
            is_malicious: abuseScore >= 50,
            is_suspicious: abuseScore >= 25,
            total_reports: result.totalReports || 0,
            last_reported: result.lastReportedAt || null,
            usage_type: result.usageType || 'Unknown',
            source: 'AbuseIPDB'
          };
          ipReputationCache.set(ip, { data: reputation, timestamp: Date.now() });
          console.log(`[AbuseIPDB] ✓ ${ip}: Score ${abuseScore}`);
          resolve(reputation);
        } catch (e) {
          resolve({ ip, abuse_score: 0, is_malicious: false, source: 'Error' });
        }
      });
    });
    req.on('error', () => resolve({ ip, abuse_score: 0, is_malicious: false, source: 'Error' }));
    req.on('timeout', () => { req.destroy(); resolve({ ip, abuse_score: 0, is_malicious: false, source: 'Timeout' }); });
    req.end();
  });
}

async function batchCheckIPReputation(ips) {
  const results = new Map();
  const publicIPs = [...new Set(ips)].filter(ip => !isPrivateIP(ip));
  console.log(`[AbuseIPDB] Batch: ${publicIPs.length} unique public IPs`);
  for (let i = 0; i < publicIPs.length; i += IP_BATCH_SIZE) {
    const batch = publicIPs.slice(i, i + IP_BATCH_SIZE);
    const batchResults = await Promise.all(batch.map(ip => checkIPReputation(ip)));
    batch.forEach((ip, j) => results.set(ip, batchResults[j]));
    if (i + IP_BATCH_SIZE < publicIPs.length) await new Promise(r => setTimeout(r, 500));
  }
  return results;
}

// ═══════════════════════════════════════════════════════════════════
// THREAT DETECTION
// ═══════════════════════════════════════════════════════════════════
function detectPortScans(packets) {
  const ipPortTimestamps = new Map();
  for (const pkt of packets) {
    if (!pkt.src_ip || !pkt.dst_port) continue;
    if (!ipPortTimestamps.has(pkt.src_ip)) ipPortTimestamps.set(pkt.src_ip, []);
    ipPortTimestamps.get(pkt.src_ip).push({ port: pkt.dst_port, timestamp: pkt.timestamp });
  }
  const portScans = [];
  for (const [ip, events] of ipPortTimestamps) {
    events.sort((a, b) => a.timestamp - b.timestamp);
    let startIdx = 0;
    const portSet = new Set();
    for (let endIdx = 0; endIdx < events.length; endIdx++) {
      while (startIdx < endIdx && events[endIdx].timestamp - events[startIdx].timestamp > 60) {
        portSet.delete(events[startIdx].port);
        startIdx++;
      }
      portSet.add(events[endIdx].port);
      if (portSet.size >= 10) {
        portScans.push({ type: 'PORT_SCAN', ip, ports_scanned: portSet.size, ports: [...portSet].sort((a, b) => a - b), severity: 'HIGH', timestamp: events[startIdx].timestamp });
        break;
      }
    }
  }
  return portScans;
}

function detectBruteForce(packets) {
  const authFailures = new Map();
  const authPatterns = [/login.*fail/i, /authentication.*fail/i, /access.*denied/i, /invalid.*password/i, /invalid.*user/i, /login.*incorrect/i, /401/, /403/, /530/, /550/, /permission denied/i];
  for (const pkt of packets) {
    if (!pkt.info) continue;
    if (authPatterns.some(p => p.test(pkt.info)) && pkt.src_ip && pkt.dst_port) {
      const key = `${pkt.src_ip}:${pkt.dst_port}`;
      authFailures.set(key, (authFailures.get(key) || 0) + 1);
    }
  }
  const results = [];
  for (const [key, count] of authFailures) {
    if (count >= 5) {
      const [ip, port] = key.split(':');
      results.push({ type: 'BRUTE_FORCE', ip, port: parseInt(port), attempts: count, severity: count >= 20 ? 'CRITICAL' : count >= 10 ? 'HIGH' : 'MEDIUM', timestamp: Date.now() });
    }
  }
  return results;
}

function detectDNSTunneling(dnsQueries) {
  const suspicious = [];
  for (const query of dnsQueries) {
    if (!query.domain) continue;
    const labels = query.domain.split('.');
    for (const label of labels.slice(0, -2)) {
      if (label.length > 50) {
        suspicious.push({ type: 'DNS_TUNNELING', domain: query.domain, reason: 'Long subdomain detected', subdomain_length: label.length, severity: 'HIGH' });
        break;
      }
      const entropy = calculateEntropy(label);
      if (entropy > 4.0 && label.length > 20) {
        suspicious.push({ type: 'DNS_TUNNELING', domain: query.domain, reason: 'High entropy subdomain', entropy: entropy.toFixed(2), severity: 'MEDIUM' });
        break;
      }
    }
    if (labels.length > 6) {
      suspicious.push({ type: 'DNS_TUNNELING', domain: query.domain, reason: 'Excessive subdomain depth', depth: labels.length, severity: 'MEDIUM' });
    }
  }
  return suspicious;
}

function calculateEntropy(str) {
  const freq = {};
  for (const char of str) freq[char] = (freq[char] || 0) + 1;
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function detectDataExfiltration(packets, ipReputations) {
  const outboundBytes = new Map();
  for (const pkt of packets) {
    if (!pkt.src_ip) continue;
    const isPrivateDest = pkt.dst_ip && isPrivateIP(pkt.dst_ip);
    if (!isPrivateDest) outboundBytes.set(pkt.src_ip, (outboundBytes.get(pkt.src_ip) || 0) + (pkt.length || 0));
  }
  const exfil = [];
  for (const [ip, bytes] of outboundBytes) {
    if (bytes > 10 * 1024 * 1024) {
      const reputation = ipReputations.get(ip);
      exfil.push({ type: 'DATA_EXFILTRATION', ip, bytes_transferred: bytes, bytes_mb: (bytes / 1024 / 1024).toFixed(2), severity: 'HIGH', is_known_malicious: reputation?.is_malicious || false });
    }
  }
  return exfil;
}

function detectDDoSPatterns(packets) {
  const ipPackets = new Map();
  for (const pkt of packets) {
    if (!pkt.src_ip || pkt.timestamp === undefined) continue;
    if (!ipPackets.has(pkt.src_ip)) ipPackets.set(pkt.src_ip, []);
    ipPackets.get(pkt.src_ip).push(pkt.timestamp);
  }
  const ddosIndicators = [];
  for (const [ip, timestamps] of ipPackets) {
    timestamps.sort((a, b) => a - b);
    for (let i = 0; i < timestamps.length; i++) {
      let count = 1;
      for (let j = i + 1; j < timestamps.length; j++) {
        if (timestamps[j] - timestamps[i] <= 1) count++;
        else break;
      }
      if (count >= 1000) {
        ddosIndicators.push({ type: 'DDOS_INDICATOR', ip, packets_per_second: count, severity: 'CRITICAL', timestamp: timestamps[i] });
        break;
      }
    }
  }
  return ddosIndicators;
}

function detectMaliciousIPs(uniqueIPs, ipReputations) {
  const malicious = [];
  for (const ip of uniqueIPs) {
    const reputation = ipReputations.get(ip);
    if (reputation?.is_malicious) {
      malicious.push({ type: 'MALICIOUS_IP', ip, abuse_score: reputation.abuse_score, total_reports: reputation.total_reports || 0, severity: reputation.abuse_score >= 75 ? 'CRITICAL' : 'HIGH', source: 'AbuseIPDB' });
    }
  }
  return malicious;
}

// ═══════════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════════
const SEARXNG_TIMEOUT_MS = 10000;
const TSHARK_BIN = process.env.TSHARK_PATH || (process.platform === 'win32' ? 'C:\\Program Files\\Wireshark\\tshark.exe' : 'tshark');
const PCAP_DIR = './tmp_pcaps';
const EXPORT_DIR = './tmp_exports';
if (!fs.existsSync(PCAP_DIR)) fs.mkdirSync(PCAP_DIR, { recursive: true });
if (!fs.existsSync(EXPORT_DIR)) fs.mkdirSync(EXPORT_DIR, { recursive: true });

console.log(`[Init] TShark path: ${TSHARK_BIN}`);
exec(`"${TSHARK_BIN}" -v 2>/dev/null`, (err, stdout) => {
  if (err) console.error(`[FATAL] tshark not found at: ${TSHARK_BIN}`);
  else console.log(`[Init] Found: ${stdout.split('\n')[0]}`);
});

// ── Session store ──────────────────────────────────────────────
const sessions = new Map();
const SESSION_TTL_MS = 30 * 60 * 1000;

async function ensureSession(sessionId) {
  if (sessions.has(sessionId)) return true;
  const pcapPath = path.join(PCAP_DIR, `${sessionId}.pcap`);
  if (fs.existsSync(pcapPath)) {
    sessions.set(sessionId, { session_id: sessionId, filename: 'restored.pcap', created_at: Date.now() });
    return true;
  }
  try {
    const r = await b2.send(new GetObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: `analysis/${sessionId}-summary.json` }));
    const text = await r.Body.transformToString();
    const summaryData = JSON.parse(text);
    sessions.set(sessionId, { session_id: sessionId, filename: 'restored.pcap', created_at: Date.now(), total_packets: summaryData.total_packets || 0 });
    return true;
  } catch (_) {
    return false;
  }
}

setInterval(async () => {
  const now = Date.now();
  for (const [id, session] of sessions) {
    if (now - session.created_at > SESSION_TTL_MS) {
      try { const p = path.join(PCAP_DIR, `${id}.pcap`); if (fs.existsSync(p)) fs.unlinkSync(p); } catch (_) { }
      try { const p = path.join(EXPORT_DIR, id); if (fs.existsSync(p)) fs.rmSync(p, { recursive: true }); } catch (_) { }
      const analysisTypes = ['summary', 'packets', 'dns', 'tls', 'http', 'ports', 'threats',
        'ftp', 'smtp', 'pop3imap', 'icmp', 'arp', 'dhcp', 'ssh', 'smb', 'rdp', 'snmp',
        'sip', 'nbns', 'quic', 'ldap', 'telnet', 'kerberos', 'radius', 'nfs', 'tftp',
        'syslog', 'bgp', 'ospf', 'gre', 'ipsec', 'vlan', 'modbus', 'dnp3', 'mqtt',
        'mdns', 'wsd', 'rpc', 'postgresql', 'mysql', 'redis', 'mongodb', 'netflow',
        'vxlan', 'l2tp', 'ppp', 'coap', 'bacnet', 'diameter'
      ];
      await Promise.all(analysisTypes.map(type => deleteFromB2(`analysis/${id}-${type}.json`).catch(() => {})));
      sessions.delete(id);
      console.log(`[Session] Expired + B2 cleaned: ${id}`);
    }
  }
}, 5 * 60 * 1000);

// ── Rate limiting ──────────────────────────────────────────────
const rateLimits = new Map();
const RATE_UPLOAD = { max: 10, windowMs: 60_000 };
const RATE_AGENT = { max: 30, windowMs: 60_000 };

function checkRateLimit(ip, limit) {
  const key = `${ip}:${limit.max}`;
  const now = Date.now();
  const e = rateLimits.get(key) || { count: 0, windowStart: now };
  if (now - e.windowStart > limit.windowMs) { e.count = 0; e.windowStart = now; }
  e.count++;
  rateLimits.set(key, e);
  return e.count <= limit.max;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of rateLimits)
    if (now - v.windowStart > 5 * 60_000) rateLimits.delete(k);
}, 2 * 60_000);

// ── CORS ──────────────────────────────────────────────────────
function getCorsHeaders(origin) {
  const allowedOrigins = (process.env.ALLOWED_ORIGIN || 'http://localhost:3000').split(',').map(o => o.trim());
  let allowedOrigin = allowedOrigins[0];
  if (origin && allowedOrigins.includes(origin)) allowedOrigin = origin;
  if (origin && (origin.includes('localhost') || origin.includes('127.0.0.1'))) allowedOrigin = origin;
  return {
    'Access-Control-Allow-Origin': allowedOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
  };
}

// ── HTTP helpers ───────────────────────────────────────────────
function parseBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', d => chunks.push(d));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function parseMultipart(buffer, boundary) {
  const clean = boundary.replace(/^["']|["']$/g, '').trim();
  const bBuf = Buffer.from('\r\n--' + clean);
  const fBuf = Buffer.from('--' + clean);
  const CRLF4 = Buffer.from('\r\n\r\n');
  const parts = [];
  let pos = buffer.indexOf(fBuf);
  if (pos === -1) return parts;
  pos += fBuf.length;
  let safety = 0;
  while (pos < buffer.length && safety++ < 1000) {
    const lEnd = buffer.indexOf(Buffer.from('\r\n'), pos);
    if (lEnd === -1) break;
    if (buffer.slice(pos, lEnd).toString().startsWith('--')) break;
    const hEnd = buffer.indexOf(CRLF4, lEnd + 2);
    if (hEnd === -1) break;
    const nBound = buffer.indexOf(bBuf, hEnd + 4);
    parts.push({ headers: buffer.slice(lEnd + 2, hEnd).toString(), data: buffer.slice(hEnd + 4, nBound === -1 ? buffer.length : nBound) });
    if (nBound === -1) break;
    pos = nBound + bBuf.length;
  }
  return parts;
}

function json(res, data, status, origin, acceptEncoding) {
  const payload = JSON.stringify(data);
  const headers = { 'Content-Type': 'application/json', ...getCorsHeaders(origin) };
  if (/\bgzip\b/.test(acceptEncoding) && payload.length > 1024) {
    zlib.gzip(Buffer.from(payload), (err, compressed) => {
      if (err) { res.writeHead(status || 200, headers); return res.end(payload); }
      res.writeHead(status || 200, { ...headers, 'Content-Encoding': 'gzip' });
      res.end(compressed);
    });
  } else {
    res.writeHead(status || 200, headers);
    res.end(payload);
  }
}

function getQuery(url) {
  const q = {};
  const i = url.indexOf('?');
  if (i === -1) return q;
  for (const part of url.slice(i + 1).split('&')) {
    const [k, v] = part.split('=');
    if (k) q[decodeURIComponent(k)] = decodeURIComponent(v || '');
  }
  return q;
}

const isValidSessionId = (id) => typeof id === 'string' && /^session-\d{13}-[a-z0-9]{6}$/.test(id);

// ═══════════════════════════════════════════════════════════════════
// SearXNG Search
// ═══════════════════════════════════════════════════════════════════
async function searchSearXNG(query, timeout = SEARXNG_TIMEOUT_MS) {
  return new Promise((resolve) => {
    const url = `${SEARXNG_URL}/search?q=${encodeURIComponent(query)}&format=json&engines=${SEARXNG_ENGINES}&max_results=${SEARXNG_MAX_RESULTS}`;
    const req = https.get(url, { timeout, headers: { 'Accept': 'application/json' } }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          if (res.statusCode !== 200) return resolve({ error: `HTTP ${res.statusCode}`, results: [] });
          const json = JSON.parse(data);
          resolve({ results: (json.results || []).map(r => ({ title: r.title || '', url: r.url || '', snippet: r.content || '', engine: r.engine || 'unknown' })) });
        } catch (e) {
          resolve({ error: e.message, results: [] });
        }
      });
    });
    req.on('error', e => resolve({ error: e.message, results: [] }));
    req.on('timeout', () => { req.destroy(); resolve({ error: 'Timeout', results: [] }); });
    req.end();
  });
}

// ═══════════════════════════════════════════════════════════════════
// Groq LLM
// ═══════════════════════════════════════════════════════════════════
async function callGroqLLM(messages, maxTokens = 1500) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({ model: GROQ_MODEL, messages, max_tokens: maxTokens, temperature: 0.7 });
    const options = {
      hostname: 'api.groq.com',
      path: '/openai/v1/chat/completions',
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${GROQ_API_KEY}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
      },
      timeout: 30000,
    };
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          if (res.statusCode !== 200) return reject(new Error(`Groq API ${res.statusCode}: ${data}`));
          const json = JSON.parse(data);
          resolve(json.choices?.[0]?.message?.content || '');
        } catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Groq timeout')); });
    req.write(payload);
    req.end();
  });
}

// ═══════════════════════════════════════════════════════════════════
// TSHARK - FULL PROTOCOL EXTRACTION (Single Pass, All Protocols)
// ═══════════════════════════════════════════════════════════════════
function runTShark(pcapPath) {
  return new Promise((resolve, reject) => {

    // ── ALL FIELDS IN ONE SINGLE TSHARK COMMAND ────────────────
    const fields = [
      // Base packet fields
      'frame.number', 'frame.time_epoch', 'frame.len',
      'ip.src', 'ip.dst', 'ip.proto',
      'tcp.srcport', 'tcp.dstport', 'tcp.flags',
      'udp.srcport', 'udp.dstport',
      '_ws.col.Protocol', '_ws.col.Info',

      // DNS (col 12-16)
      'dns.qry.name', 'dns.a', 'dns.aaaa', 'dns.flags.response', 'dns.qry.type',

      // TLS (col 17-18)
      'tls.handshake.type', 'tls.handshake.extensions_server_name',

      // HTTP (col 19-24)
      'http.request.method', 'http.request.uri', 'http.host',
      'http.response.code', 'http.user_agent', 'http.content_type',

      // FTP (col 25-27)
      'ftp.request.command', 'ftp.request.arg', 'ftp.response.code',

      // SMTP (col 28-30)
      'smtp.req.command', 'smtp.req.parameter', 'smtp.response.code',

      // POP3 / IMAP (col 31-33)
      'pop.request.command', 'imap.request', 'imap.response',

      // ICMP (col 34-36)
      'icmp.type', 'icmp.code', 'icmp.checksum',

      // ARP (col 37-40)
      'arp.opcode', 'arp.src.hw_mac', 'arp.src.proto_ipv4', 'arp.dst.proto_ipv4',

      // DHCP (col 41-44)
      'dhcp.option.hostname', 'dhcp.option.requested_ip_address',
      'dhcp.option.dhcp', 'dhcp.hw.mac_addr',

      // SSH (col 45-47)
      'ssh.protocol', 'ssh.kex.algorithms', 'ssh.message_code',

      // SMB (col 48-51)
      'smb.cmd', 'smb.path', 'smb2.cmd', 'smb2.filename',

      // RDP (col 52-53)
      'rdp.negReq.requestedProtocols', 'rdp.domain',

      // SNMP (col 54-56)
      'snmp.community', 'snmp.var_bind_str', 'snmp.version',

      // SIP / RTP (col 57-61)
      'sip.Method', 'sip.from.user', 'sip.to.user',
      'sip.Call-ID', 'rtp.ssrc',

      // NetBIOS / NBNS (col 62-64)
      'nbns.name', 'nbss.type', 'netbios.name',

      // QUIC (col 65-67)
      'quic.version', 'quic.connection_id', 'quic.packet_type',

      // LDAP (col 68-70)
      'ldap.baseObject', 'ldap.filter_string', 'ldap.resultCode',

      // Telnet (col 71-72)
      'telnet.data', 'telnet.cmd',

      // Kerberos (col 73-75)
      'kerberos.realm', 'kerberos.CNameString', 'kerberos.msg_type',

      // RADIUS (col 76-78)
      'radius.User_Name', 'radius.code', 'radius.NAS_IP_Address',

      // NFS (col 79-81)
      'nfs.path', 'nfs.ftype', 'nfs.status',

      // TFTP (col 82-84)
      'tftp.opcode', 'tftp.source_file', 'tftp.destination_file',

      // Syslog (col 85-87)
      'syslog.facility', 'syslog.severity', 'syslog.msg',

      // BGP (col 88-90)
      'bgp.type', 'bgp.prefix_length', 'bgp.next_hop',

      // OSPF (col 91-93)
      'ospf.msg', 'ospf.srcrouter', 'ospf.area_id',

      // GRE (col 94-95)
      'gre.proto', 'gre.key',

      // IPSec / IKE (col 96-98)
      'isakmp.exchtype', 'esp.sequence', 'isakmp.version',

      // VLAN (col 99-100)
      'vlan.id', 'vlan.priority',

      // Modbus (col 101-103)
      'mbtcp.func_code', 'mbtcp.reference_num', 'mbtcp.word_cnt',

      // DNP3 (col 104-106)
      'dnp3.ctl.dir', 'dnp3.src', 'dnp3.dst',

      // MQTT (col 107-109)
      'mqtt.msgtype', 'mqtt.topic', 'mqtt.msg',

      // mDNS (col 110-111)
      'mdns.qry.name', 'mdns.ans.name',

      // WSD (col 112)
      'wsd.action',

      // RPC / MSRPC (col 113-115)
      'dcerpc.opnum', 'dcerpc.cn_call_id', 'dcerpc.pkt_type',

      // PostgreSQL (col 116-118)
      'pgsql.query', 'pgsql.authtype', 'pgsql.statement',

      // MySQL (col 119-121)
      'mysql.query', 'mysql.command', 'mysql.affected_rows',

      // Redis (col 122-123)
      'redis.command', 'redis.bulk_string',

      // MongoDB (col 124-126)
      'mongo.opcode', 'mongo.query', 'mongo.documents',

      // NetFlow / IPFIX (col 127-129)
      'cflow.srcaddr', 'cflow.dstaddr', 'cflow.packets',

      // VXLAN (col 130-131)
      'vxlan.vni', 'vxlan.flags',

      // L2TP (col 132-134)
      'l2tp.tunnel_id', 'l2tp.session_id', 'l2tp.type',

      // PPP (col 135-136)
      'ppp.protocol', 'ppp.direction',

      // CoAP (col 137-139)
      'coap.code', 'coap.opt.uri_path_recon', 'coap.type',

      // BACnet (col 140-142)
      'bacapp.service', 'bacapp.objectidentifier', 'bacapp.instance_number',

      // DIAMETER (col 143-145)
      'diameter.cmd.code', 'diameter.applicationId', 'diameter.Session-Id',
    ].join(' -e ');

    const cmd = `"${TSHARK_BIN}" -r "${pcapPath}" -T fields -E header=y -E separator=/t -E quote=n -e ${fields} 2>/dev/null`;

    exec(cmd, { maxBuffer: 200 * 1024 * 1024 }, (err, stdout) => {
      if (err) return reject(new Error(`TShark failed: ${err.message}`));

      const lines = stdout.trim().split('\n');

      // Protocol data arrays
      const packets = [], dns = [], tls = [], http = [];
      const ftp = [], smtp = [], pop3imap = [], icmp = [], arp = [], dhcp = [];
      const ssh = [], smb = [], rdp = [], snmp = [], sip = [], nbns = [];
      const quic = [], ldap = [], telnet = [], kerberos = [], radius = [], nfs = [];
      const tftp = [], syslog = [], bgp = [], ospf = [], gre = [], ipsec = [];
      const vlan = [], modbus = [], dnp3 = [], mqtt = [], mdns = [], wsd = [];
      const rpc = [], postgresql = [], mysql = [], redis = [], mongodb = [];
      const netflow = [], vxlan = [], l2tp = [], ppp = [], coap = [], bacnet = [];
      const diameter = [];

      // Skip header line (i=0)
      for (let i = 1; i < lines.length; i++) {
        const line = lines[i];
        if (!line.trim()) continue;
        const c = line.split('\t');

        // Base packet
        const pkt = {
          frame_number: parseInt(c[0]) || 0,
          timestamp: parseFloat(c[1]) || 0,
          length: parseInt(c[2]) || 0,
          src_ip: c[3] || '',
          dst_ip: c[4] || '',
          ip_proto: c[5] || '',
          src_port: parseInt(c[6]) || parseInt(c[9]) || 0,
          dst_port: parseInt(c[7]) || parseInt(c[10]) || 0,
          tcp_flags: c[8] || '',
          protocol: c[11] || '',
          info: c[12] || ''
        };
        packets.push(pkt);

        const ts = pkt.timestamp;
        const sip_addr = pkt.src_ip;
        const dip_addr = pkt.dst_ip;

        // DNS (cols 13-17)
        if (c[13]) dns.push({ domain: c[13], answer_a: c[14] || '', answer_aaaa: c[15] || '', is_response: c[16] === '1', qry_type: c[17] || '', src_ip: sip_addr, timestamp: ts });

        // TLS (cols 18-19)
        if (c[18] || c[19]) tls.push({ handshake_type: c[18] || '', sni: c[19] || '', src_ip: sip_addr, dst_ip: dip_addr, dst_port: pkt.dst_port, timestamp: ts });

        // HTTP (cols 20-25)
        if (c[20] || c[21]) http.push({ method: c[20] || '', uri: c[21] || '', host: c[22] || '', status_code: c[23] || '', user_agent: c[24] || '', content_type: c[25] || '', src_ip: sip_addr, dst_ip: dip_addr, timestamp: ts });

        // FTP (cols 26-28)
        if (c[26] || c[28]) ftp.push({ command: c[26] || '', arg: c[27] || '', response_code: c[28] || '', src_ip: sip_addr, dst_ip: dip_addr, timestamp: ts });

        // SMTP (cols 29-31)
        if (c[29] || c[31]) smtp.push({ command: c[29] || '', parameter: c[30] || '', response_code: c[31] || '', src_ip: sip_addr, dst_ip: dip_addr, timestamp: ts });

        // POP3 / IMAP (cols 32-34)
        if (c[32] || c[33]) pop3imap.push({ pop3_command: c[32] || '', imap_request: c[33] || '', imap_response: c[34] || '', src_ip: sip_addr, dst_ip: dip_addr, timestamp: ts });

        // ICMP (cols 35-37)
        if (c[35]) icmp.push({ type: c[35] || '', code: c[36] || '', checksum: c[37] || '', src_ip: sip_addr, dst_ip: dip_addr, timestamp: ts });

        // ARP (cols 38-41)
        if (c[38]) arp.push({ opcode: c[38] || '', src_mac: c[39] || '', src_ip: c[40] || '', dst_ip: c[41] || '', timestamp: ts });

        // DHCP (cols 42-45)
        if (c[42] || c[45]) dhcp.push({ hostname: c[42] || '', requested_ip: c[43] || '', dhcp_type: c[44] || '', mac: c[45] || '', src_ip: sip_addr, timestamp: ts });

        // SSH (cols 46-48)
        if (c[46]) ssh.push({ protocol: c[46] || '', kex_algorithms: c[47] || '', message_code: c[48] || '', src_ip: sip_addr, dst_ip: dip_addr, timestamp: ts });

        // SMB (cols 49-52)
        if (c[49] || c[51]) smb.push({ cmd_v1: c[49] || '', path_v1: c[50] || '', cmd_v2: c[51] || '', filename_v2: c[52] || '', src_ip: sip_addr, dst_ip: dip_addr, timestamp: ts });

        // RDP (cols 53-54)
        if (c[53] || c[54]) rdp.push({ protocols: c[53] || '', domain: c[54] || '', src_ip: sip_addr, dst_ip: dip_addr, timestamp: ts });

        // SNMP (cols 55-57)
        if (c[55] || c[56]) snmp.push({ community: c[55] || '', var_bind: c[56] || '', version: c[57] || '', src_ip: sip_addr, dst_ip: dip_addr, timestamp: ts });

        // SIP / RTP (cols 58-62)
        if (c[58] || c[62]) sip.push({ method: c[58] || '', from_user: c[59] || '', to_user: c[60] || '', call_id: c[61] || '', rtp_ssrc: c[62] || '', src_ip: sip_addr, dst_ip: dip_addr, timestamp: ts });

        // NBNS (cols 63-65)
        if (c[63] || c[65]) nbns.push({ name: c[63] || '', nbss_type: c[64] || '', netbios_name: c[65] || '', src_ip: sip_addr, dst_ip: dip_addr, timestamp: ts });

        // QUIC (cols 66-68)
        if (c[66]) quic.push({ version: c[66] || '', connection_id: c[67] || '', packet_type: c[68] || '', src_ip: sip_addr, dst_ip: dip_addr, timestamp: ts });

        // LDAP (cols 69-71)
        if (c[69] || c[71]) ldap.push({ base_object: c[69] || '', filter: c[70] || '', result_code: c[71] || '', src_ip: sip_addr, dst_ip: dip_addr, timestamp: ts });

        // Telnet (cols 72-73)
        if (c[72]) telnet.push({ data: c[72] || '', cmd: c[73] || '', src_ip: sip_addr, dst_ip: dip_addr, timestamp: ts });

        // Kerberos (cols 74-76)
        if (c[74] || c[75]) kerberos.push({ realm: c[74] || '', cname: c[75] || '', msg_type: c[76] || '', src_ip: sip_addr, dst_ip: dip_addr, timestamp: ts });

        // RADIUS (cols 77-79)
        if (c[77] || c[78]) radius.push({ username: c[77] || '', code: c[78] || '', nas_ip: c[79] || '', src_ip: sip_addr, dst_ip: dip_addr, timestamp: ts });

        // NFS (cols 80-82)
        if (c[80]) nfs.push({ path: c[80] || '', ftype: c[81] || '', status: c[82] || '', src_ip: sip_addr, dst_ip: dip_addr, timestamp: ts });

        // TFTP (cols 83-85)
        if (c[83]) tftp.push({ opcode: c[83] || '', source_file: c[84] || '', dest_file: c[85] || '', src_ip: sip_addr, dst_ip: dip_addr, timestamp: ts });

        // Syslog (cols 86-88)
        if (c[88]) syslog.push({ facility: c[86] || '', severity: c[87] || '', message: c[88] || '', src_ip: sip_addr, timestamp: ts });

        // BGP (cols 89-91)
        if (c[89]) bgp.push({ type: c[89] || '', prefix_length: c[90] || '', next_hop: c[91] || '', src_ip: sip_addr, dst_ip: dip_addr, timestamp: ts });

        // OSPF (cols 92-94)
        if (c[92]) ospf.push({ msg: c[92] || '', src_router: c[93] || '', area_id: c[94] || '', src_ip: sip_addr, timestamp: ts });

        // GRE (cols 95-96)
        if (c[95]) gre.push({ proto: c[95] || '', key: c[96] || '', src_ip: sip_addr, dst_ip: dip_addr, timestamp: ts });

        // IPSec / IKE (cols 97-99)
        if (c[97] || c[98]) ipsec.push({ ike_exchtype: c[97] || '', esp_seq: c[98] || '', ike_version: c[99] || '', src_ip: sip_addr, dst_ip: dip_addr, timestamp: ts });

        // VLAN (cols 100-101)
        if (c[100]) vlan.push({ vlan_id: c[100] || '', priority: c[101] || '', src_ip: sip_addr, timestamp: ts });

        // Modbus (cols 102-104)
        if (c[102]) modbus.push({ func_code: c[102] || '', ref_num: c[103] || '', word_cnt: c[104] || '', src_ip: sip_addr, dst_ip: dip_addr, timestamp: ts });

        // DNP3 (cols 105-107)
        if (c[105] || c[106]) dnp3.push({ dir: c[105] || '', src: c[106] || '', dst: c[107] || '', src_ip: sip_addr, timestamp: ts });

        // MQTT (cols 108-110)
        if (c[108]) mqtt.push({ msg_type: c[108] || '', topic: c[109] || '', msg: c[110] || '', src_ip: sip_addr, dst_ip: dip_addr, timestamp: ts });

        // mDNS (cols 111-112)
        if (c[111] || c[112]) mdns.push({ query_name: c[111] || '', answer_name: c[112] || '', src_ip: sip_addr, timestamp: ts });

        // WSD (col 113)
        if (c[113]) wsd.push({ action: c[113] || '', src_ip: sip_addr, dst_ip: dip_addr, timestamp: ts });

        // RPC / MSRPC (cols 114-116)
        if (c[114]) rpc.push({ opnum: c[114] || '', call_id: c[115] || '', pkt_type: c[116] || '', src_ip: sip_addr, dst_ip: dip_addr, timestamp: ts });

        // PostgreSQL (cols 117-119)
        if (c[117]) postgresql.push({ query: c[117] || '', authtype: c[118] || '', statement: c[119] || '', src_ip: sip_addr, dst_ip: dip_addr, timestamp: ts });

        // MySQL (cols 120-122)
        if (c[120] || c[121]) mysql.push({ query: c[120] || '', command: c[121] || '', affected_rows: c[122] || '', src_ip: sip_addr, dst_ip: dip_addr, timestamp: ts });

        // Redis (cols 123-124)
        if (c[123]) redis.push({ command: c[123] || '', response: c[124] || '', src_ip: sip_addr, dst_ip: dip_addr, timestamp: ts });

        // MongoDB (cols 125-127)
        if (c[125]) mongodb.push({ opcode: c[125] || '', query: c[126] || '', documents: c[127] || '', src_ip: sip_addr, dst_ip: dip_addr, timestamp: ts });

        // NetFlow (cols 128-130)
        if (c[128]) netflow.push({ src_addr: c[128] || '', dst_addr: c[129] || '', packets: c[130] || '', src_ip: sip_addr, timestamp: ts });

        // VXLAN (cols 131-132)
        if (c[131]) vxlan.push({ vni: c[131] || '', flags: c[132] || '', src_ip: sip_addr, dst_ip: dip_addr, timestamp: ts });

        // L2TP (cols 133-135)
        if (c[133]) l2tp.push({ tunnel_id: c[133] || '', session_id: c[134] || '', type: c[135] || '', src_ip: sip_addr, dst_ip: dip_addr, timestamp: ts });

        // PPP (cols 136-137)
        if (c[136]) ppp.push({ protocol: c[136] || '', direction: c[137] || '', src_ip: sip_addr, timestamp: ts });

        // CoAP (cols 138-140)
        if (c[138]) coap.push({ code: c[138] || '', uri_path: c[139] || '', type: c[140] || '', src_ip: sip_addr, dst_ip: dip_addr, timestamp: ts });

        // BACnet (cols 141-143)
        if (c[141]) bacnet.push({ service: c[141] || '', object_id: c[142] || '', instance: c[143] || '', src_ip: sip_addr, dst_ip: dip_addr, timestamp: ts });

        // DIAMETER (cols 144-146)
        if (c[144]) diameter.push({ cmd_code: c[144] || '', app_id: c[145] || '', session_id: c[146] || '', src_ip: sip_addr, dst_ip: dip_addr, timestamp: ts });
      }

      resolve({
        packets, dns, tls, http,
        ftp, smtp, pop3imap, icmp, arp, dhcp,
        ssh, smb, rdp, snmp, sip, nbns,
        quic, ldap, telnet, kerberos, radius, nfs,
        tftp, syslog, bgp, ospf, gre, ipsec,
        vlan, modbus, dnp3, mqtt, mdns, wsd,
        rpc, postgresql, mysql, redis, mongodb,
        netflow, vxlan, l2tp, ppp, coap, bacnet, diameter
      });
    });
  });
}

// ═══════════════════════════════════════════════════════════════════
// MAIN ANALYSIS HANDLER
// ═══════════════════════════════════════════════════════════════════
async function analyzePCAP(sessionId, pcapPath) {
  console.log(`[Analysis] Starting for session: ${sessionId}`);
  const startTime = Date.now();

  try {
    // 1. Run TShark (single pass, all protocols)
    console.log('[Analysis] Running TShark (full protocol extraction)...');
    const tsharkData = await runTShark(pcapPath);
    const { packets, dns, tls, http } = tsharkData;
    console.log(`[Analysis] Parsed ${packets.length} packets`);

    // 2. Aggregate base stats
    const ports = new Set();
    const srcIPs = new Set();
    const dstIPs = new Set();
    const protocols = new Map();
    let totalBytes = 0, firstTimestamp = Infinity, lastTimestamp = 0;

    for (const pkt of packets) {
      if (pkt.dst_port) ports.add(pkt.dst_port);
      if (pkt.src_port && pkt.src_port < 49152) ports.add(pkt.src_port);
      if (pkt.src_ip) srcIPs.add(pkt.src_ip);
      if (pkt.dst_ip) dstIPs.add(pkt.dst_ip);
      if (pkt.protocol) protocols.set(pkt.protocol, (protocols.get(pkt.protocol) || 0) + 1);
      totalBytes += pkt.length || 0;
      if (pkt.timestamp) {
        if (pkt.timestamp < firstTimestamp) firstTimestamp = pkt.timestamp;
        if (pkt.timestamp > lastTimestamp) lastTimestamp = pkt.timestamp;
      }
    }

    // 3. IANA port info
    console.log(`[Analysis] Getting IANA info for ${ports.size} ports...`);
    const portInfoMap = new Map();
    const portServiceMap = new Map();
    for (const port of ports) {
      const info = await getIANAPortInfo(port);
      portInfoMap.set(port, info);
      portServiceMap.set(port, info?.service_name || 'Unknown');
    }

    // 4. Batch fetch CVEs + SearXNG risks IN PARALLEL
    console.log('[Analysis] Fetching CVEs + security risks in parallel...');
    const serviceNames = [...new Set([...portServiceMap.values()])];
    const [portCVEMap, serviceRisksMap] = await Promise.all([
      batchFetchCVEs(portServiceMap),
      batchFetchServiceRisks(serviceNames)
    ]);

    // 5. IP reputation check
    console.log('[Analysis] Checking IP reputations...');
    const ipReputations = await batchCheckIPReputation([...srcIPs, ...dstIPs]);

    // 6. Threat detection
    console.log('[Analysis] Running threat detection...');
    const threats = {
      port_scans: detectPortScans(packets),
      brute_force: detectBruteForce(packets),
      dns_tunneling: detectDNSTunneling(dns),
      data_exfiltration: detectDataExfiltration(packets, ipReputations),
      ddos_indicators: detectDDoSPatterns(packets),
      malicious_ips: detectMaliciousIPs([...srcIPs, ...dstIPs], ipReputations)
    };

    const criticalAlerts = [...threats.ddos_indicators, ...threats.malicious_ips.filter(t => t.severity === 'CRITICAL'), ...threats.data_exfiltration].length;
    const highAlerts = [...threats.port_scans, ...threats.brute_force.filter(t => t.severity === 'HIGH'), ...threats.dns_tunneling.filter(t => t.severity === 'HIGH'), ...threats.malicious_ips.filter(t => t.severity === 'HIGH')].length;

    // 7. Build summary
    const duration = lastTimestamp > firstTimestamp ? lastTimestamp - firstTimestamp : 0;
    const summary = {
      session_id: sessionId,
      total_packets: packets.length,
      total_bytes: totalBytes,
      duration_seconds: duration,
      unique_src_ips: srcIPs.size,
      unique_dst_ips: dstIPs.size,
      unique_ports: ports.size,
      protocols: Object.fromEntries(protocols),
      critical_alerts: criticalAlerts,
      high_alerts: highAlerts,
      analysis_time_ms: Date.now() - startTime,
      // Protocol presence map (for agent routing)
      protocols_detected: {
        dns: dns.length > 0,
        tls: tls.length > 0,
        http: http.length > 0,
        ftp: tsharkData.ftp.length > 0,
        smtp: tsharkData.smtp.length > 0,
        pop3imap: tsharkData.pop3imap.length > 0,
        icmp: tsharkData.icmp.length > 0,
        arp: tsharkData.arp.length > 0,
        dhcp: tsharkData.dhcp.length > 0,
        ssh: tsharkData.ssh.length > 0,
        smb: tsharkData.smb.length > 0,
        rdp: tsharkData.rdp.length > 0,
        snmp: tsharkData.snmp.length > 0,
        sip: tsharkData.sip.length > 0,
        nbns: tsharkData.nbns.length > 0,
        quic: tsharkData.quic.length > 0,
        ldap: tsharkData.ldap.length > 0,
        telnet: tsharkData.telnet.length > 0,
        kerberos: tsharkData.kerberos.length > 0,
        radius: tsharkData.radius.length > 0,
        nfs: tsharkData.nfs.length > 0,
        tftp: tsharkData.tftp.length > 0,
        syslog: tsharkData.syslog.length > 0,
        bgp: tsharkData.bgp.length > 0,
        ospf: tsharkData.ospf.length > 0,
        gre: tsharkData.gre.length > 0,
        ipsec: tsharkData.ipsec.length > 0,
        vlan: tsharkData.vlan.length > 0,
        modbus: tsharkData.modbus.length > 0,
        dnp3: tsharkData.dnp3.length > 0,
        mqtt: tsharkData.mqtt.length > 0,
        mdns: tsharkData.mdns.length > 0,
        wsd: tsharkData.wsd.length > 0,
        rpc: tsharkData.rpc.length > 0,
        postgresql: tsharkData.postgresql.length > 0,
        mysql: tsharkData.mysql.length > 0,
        redis: tsharkData.redis.length > 0,
        mongodb: tsharkData.mongodb.length > 0,
        netflow: tsharkData.netflow.length > 0,
        vxlan: tsharkData.vxlan.length > 0,
        l2tp: tsharkData.l2tp.length > 0,
        ppp: tsharkData.ppp.length > 0,
        coap: tsharkData.coap.length > 0,
        bacnet: tsharkData.bacnet.length > 0,
        diameter: tsharkData.diameter.length > 0,
      }
    };

    // 8. Build port intelligence (with dynamic SearXNG risks!)
    const portIntel = [];
    for (const port of [...ports].sort((a, b) => a - b)) {
      const info = portInfoMap.get(port);
      const cves = portCVEMap.get(port) || [];
      const serviceLower = (info?.service_name || '').toLowerCase();
      const riskData = serviceRisksMap.get(serviceLower) || { risks: [], alternatives: [] };

      portIntel.push({
        port,
        service_name: info?.service_name || 'Unknown',
        description: info?.description || '',
        protocol: info?.protocol || 'Unknown',
        risks: riskData.risks,           // ← Dynamic from SearXNG!
        alternatives: riskData.alternatives, // ← New: secure alternatives
        secure: info?.secure || false,
        cves,
        packet_count: packets.filter(p => p.dst_port === port || p.src_port === port).length
      });
    }

    // 9. Build upload map — ONLY non-empty protocol arrays go to B2
    const uploadMap = {
      [`analysis/${sessionId}-summary.json`]: summary,
      [`analysis/${sessionId}-packets.json`]: packets.slice(0, 10000),
      [`analysis/${sessionId}-ports.json`]: portIntel,
      [`analysis/${sessionId}-threats.json`]: threats,
    };

    // Conditionally add protocol files only if they have data
    const protocolFiles = {
      dns: tsharkData.dns,
      tls: tsharkData.tls,
      http: tsharkData.http,
      ftp: tsharkData.ftp,
      smtp: tsharkData.smtp,
      pop3imap: tsharkData.pop3imap,
      icmp: tsharkData.icmp,
      arp: tsharkData.arp,
      dhcp: tsharkData.dhcp,
      ssh: tsharkData.ssh,
      smb: tsharkData.smb,
      rdp: tsharkData.rdp,
      snmp: tsharkData.snmp,
      sip: tsharkData.sip,
      nbns: tsharkData.nbns,
      quic: tsharkData.quic,
      ldap: tsharkData.ldap,
      telnet: tsharkData.telnet,
      kerberos: tsharkData.kerberos,
      radius: tsharkData.radius,
      nfs: tsharkData.nfs,
      tftp: tsharkData.tftp,
      syslog: tsharkData.syslog,
      bgp: tsharkData.bgp,
      ospf: tsharkData.ospf,
      gre: tsharkData.gre,
      ipsec: tsharkData.ipsec,
      vlan: tsharkData.vlan,
      modbus: tsharkData.modbus,
      dnp3: tsharkData.dnp3,
      mqtt: tsharkData.mqtt,
      mdns: tsharkData.mdns,
      wsd: tsharkData.wsd,
      rpc: tsharkData.rpc,
      postgresql: tsharkData.postgresql,
      mysql: tsharkData.mysql,
      redis: tsharkData.redis,
      mongodb: tsharkData.mongodb,
      netflow: tsharkData.netflow,
      vxlan: tsharkData.vxlan,
      l2tp: tsharkData.l2tp,
      ppp: tsharkData.ppp,
      coap: tsharkData.coap,
      bacnet: tsharkData.bacnet,
      diameter: tsharkData.diameter,
    };

    let uploadedProtocols = 0;
    for (const [name, data] of Object.entries(protocolFiles)) {
      if (data && data.length > 0) {
        uploadMap[`analysis/${sessionId}-${name}.json`] = data;
        uploadedProtocols++;
      }
    }
    console.log(`[Analysis] ${uploadedProtocols} protocol files have data, uploading to B2...`);

    // 10. Upload all at once
    await Promise.all(
      Object.entries(uploadMap).map(([key, data]) =>
        b2.send(new PutObjectCommand({
          Bucket: process.env.B2_BUCKET_NAME,
          Key: key,
          Body: JSON.stringify(data),
          ContentType: 'application/json'
        }))
      )
    );

    console.log(`[Analysis] ✓ Complete in ${Date.now() - startTime}ms`);
    return { success: true, summary, port_intelligence: portIntel, threats };

  } catch (error) {
    console.error(`[Analysis] Error: ${error.message}`);
    return { success: false, error: error.message };
  }
}

// ═══════════════════════════════════════════════════════════════════
// SMART AGENT KEYWORD ROUTING
// Maps user message keywords → B2 file keys to fetch
// ═══════════════════════════════════════════════════════════════════

// Full keyword → protocol file map
const KEYWORD_PROTOCOL_MAP = [
  // DNS
  { keywords: ['dns', 'domain', 'resolve', 'hostname', 'nslookup', 'lookup', 'subdomain', 'zone'], file: 'dns' },
  // TLS / SSL / Certificates
  { keywords: ['tls', 'ssl', 'certificate', 'https', 'handshake', 'cipher', 'sni', 'x509', 'encrypt'], file: 'tls' },
  // HTTP
  { keywords: ['http', 'web', 'url', 'request', 'response', 'get', 'post', 'header', 'user-agent', 'cookie', 'html', 'api', 'rest', 'status code', 'content-type'], file: 'http' },
  // FTP
  { keywords: ['ftp', 'file transfer', 'filezilla', 'vsftpd', 'passive', 'active mode'], file: 'ftp' },
  // SMTP / Email sending
  { keywords: ['smtp', 'email', 'mail', 'send mail', 'sendgrid', 'postfix', 'relay', 'spam', 'phishing', 'from address', 'to address'], file: 'smtp' },
  // POP3 / IMAP
  { keywords: ['pop3', 'imap', 'retrieve email', 'inbox', 'mailbox', 'fetch mail', 'email client'], file: 'pop3imap' },
  // ICMP
  { keywords: ['icmp', 'ping', 'traceroute', 'unreachable', 'ttl exceeded', 'echo request', 'echo reply', 'network reachability'], file: 'icmp' },
  // ARP
  { keywords: ['arp', 'mac address', 'layer 2', 'arp spoofing', 'arp poisoning', 'gratuitous arp', 'ip to mac', 'mac to ip'], file: 'arp' },
  // DHCP
  { keywords: ['dhcp', 'ip assignment', 'ip lease', 'ip address assigned', 'dhcp discover', 'dhcp offer', 'dhcp request', 'dhcp ack', 'hostname assignment'], file: 'dhcp' },
  // SSH
  { keywords: ['ssh', 'secure shell', 'openssh', 'key exchange', 'ssh tunnel', 'sftp', 'scp', 'remote login'], file: 'ssh' },
  // SMB
  { keywords: ['smb', 'samba', 'file share', 'windows share', 'network share', 'cifs', 'ransomware', 'eternalblue', 'smb relay'], file: 'smb' },
  // RDP
  { keywords: ['rdp', 'remote desktop', 'mstsc', 'xrdp', 'bluekeep', 'remote access', 'screen sharing'], file: 'rdp' },
  // SNMP
  { keywords: ['snmp', 'community string', 'oid', 'mib', 'network management', 'trap', 'snmpwalk', 'device monitoring'], file: 'snmp' },
  // SIP / RTP / VoIP
  { keywords: ['sip', 'rtp', 'voip', 'call', 'phone', 'asterisk', 'invite', 'register', 'toll fraud', 'call hijack', 'audio stream'], file: 'sip' },
  // NBNS / NetBIOS
  { keywords: ['nbns', 'netbios', 'windows name', 'llmnr', 'broadcast name', 'nbt', 'workgroup', 'responder'], file: 'nbns' },
  // QUIC / HTTP3
  { keywords: ['quic', 'http/3', 'http3', 'udp web', 'google quic', 'chromium transport'], file: 'quic' },
  // LDAP
  { keywords: ['ldap', 'directory', 'active directory', 'ad', 'ldap bind', 'ldap search', 'openldap', 'credential stuffing ldap'], file: 'ldap' },
  // Telnet
  { keywords: ['telnet', 'clear text login', 'unencrypted shell', 'telnet session', 'terminal'], file: 'telnet' },
  // Kerberos
  { keywords: ['kerberos', 'ticket', 'tgt', 'kdc', 'krbtgt', 'pass the ticket', 'golden ticket', 'ad authentication', 'windows auth'], file: 'kerberos' },
  // RADIUS
  { keywords: ['radius', 'aaa', 'authentication server', 'access control', 'nas', 'wifi auth', '802.1x'], file: 'radius' },
  // NFS
  { keywords: ['nfs', 'network file system', 'mount', 'nfs share', 'rpc nfs', 'file system access'], file: 'nfs' },
  // TFTP
  { keywords: ['tftp', 'trivial ftp', 'tftp server', 'firmware update', 'cisco tftp', 'no auth transfer'], file: 'tftp' },
  // Syslog
  { keywords: ['syslog', 'log', 'logging', 'event log', 'log server', 'rsyslog', 'log message', 'facility', 'severity'], file: 'syslog' },
  // BGP
  { keywords: ['bgp', 'border gateway', 'routing', 'autonomous system', 'as path', 'route hijack', 'bgp hijack', 'internet routing'], file: 'bgp' },
  // OSPF
  { keywords: ['ospf', 'link state', 'internal routing', 'area', 'lsa', 'routing protocol internal'], file: 'ospf' },
  // GRE
  { keywords: ['gre', 'tunnel', 'encapsulation', 'gre tunnel', 'ip over ip', 'vpn tunnel protocol'], file: 'gre' },
  // IPSec / IKE / VPN
  { keywords: ['ipsec', 'ike', 'vpn', 'esp', 'ah', 'isakmp', 'internet key exchange', 'vpn tunnel', 'encrypted vpn'], file: 'ipsec' },
  // VLAN
  { keywords: ['vlan', '802.1q', 'vlan tag', 'trunk port', 'vlan hopping', 'network segmentation'], file: 'vlan' },
  // Modbus / SCADA
  { keywords: ['modbus', 'scada', 'industrial', 'ics', 'plc', 'modbus tcp', 'industrial control', 'ot security'], file: 'modbus' },
  // DNP3
  { keywords: ['dnp3', 'dnp', 'utility', 'substation', 'critical infrastructure', 'power grid'], file: 'dnp3' },
  // MQTT / IoT
  { keywords: ['mqtt', 'iot', 'publish', 'subscribe', 'broker', 'mosquitto', 'sensor', 'embedded device'], file: 'mqtt' },
  // mDNS / Bonjour
  { keywords: ['mdns', 'bonjour', 'avahi', 'local discovery', 'zero conf', 'zeroconf', 'local service'], file: 'mdns' },
  // WSD
  { keywords: ['wsd', 'web services discovery', 'ws-discovery', 'device discovery', 'windows wsd'], file: 'wsd' },
  // RPC / MSRPC
  { keywords: ['rpc', 'msrpc', 'dcom', 'dcerpc', 'microsoft rpc', 'remote procedure', 'com+'], file: 'rpc' },
  // PostgreSQL
  { keywords: ['postgresql', 'postgres', 'psql', 'pg', 'sql query postgres', 'database postgres'], file: 'postgresql' },
  // MySQL
  { keywords: ['mysql', 'mariadb', 'mysqld', 'sql query', 'database query', 'sql injection mysql'], file: 'mysql' },
  // Redis
  { keywords: ['redis', 'cache', 'in-memory', 'redis command', 'redis server', 'keyspace'], file: 'redis' },
  // MongoDB
  { keywords: ['mongodb', 'mongo', 'nosql', 'bson', 'mongo query', 'mongodb exploit'], file: 'mongodb' },
  // NetFlow / IPFIX
  { keywords: ['netflow', 'ipfix', 'flow data', 'traffic flow', 'flow export', 'flow collector'], file: 'netflow' },
  // VXLAN
  { keywords: ['vxlan', 'overlay network', 'vxlan vni', 'virtual extensible lan'], file: 'vxlan' },
  // L2TP
  { keywords: ['l2tp', 'layer 2 tunnel', 'l2tp vpn', 'pptp', 'l2f'], file: 'l2tp' },
  // PPP
  { keywords: ['ppp', 'point to point', 'pppoe', 'ppp auth', 'wan protocol'], file: 'ppp' },
  // CoAP
  { keywords: ['coap', 'constrained', 'iot coap', 'coap request', 'coap response'], file: 'coap' },
  // BACnet
  { keywords: ['bacnet', 'building automation', 'hvac', 'building control', 'smart building'], file: 'bacnet' },
  // DIAMETER
  { keywords: ['diameter', 'aaa diameter', '3gpp', 'lte auth', 'telecoms auth', 'diameter protocol'], file: 'diameter' },
  // General / always included
  { keywords: ['threat', 'attack', 'malicious', 'scan', 'exploit', 'intrusion', 'detect', 'alert', 'suspicious'], file: 'threats' },
  { keywords: ['port', 'service', 'cve', 'vulnerability', 'risk', 'exposure'], file: 'ports' },
  { keywords: ['packet', 'traffic', 'ip', 'flow', 'raw', 'frame', 'capture'], file: 'packets' },
  { keywords: ['summary', 'overview', 'total', 'stats', 'count', 'how many', 'statistics'], file: 'summary' },
];

/**
 * Smart keyword routing: figure out which B2 files to fetch for a given user message.
 * Returns array of file type names (e.g. ['dns', 'threats', 'summary'])
 */
function resolveFilesForMessage(message) {
  const lower = message.toLowerCase();
  const files = new Set();

  for (const entry of KEYWORD_PROTOCOL_MAP) {
    if (entry.keywords.some(kw => lower.includes(kw))) {
      files.add(entry.file);
    }
  }

  // Always include summary for context
  files.add('summary');

  // Fallback: vague/generic questions → default set
  if (files.size <= 1) {
    files.add('threats');
    files.add('ports');
  }

  return [...files];
}

// ═══════════════════════════════════════════════════════════════════
// HTTP Server
// ═══════════════════════════════════════════════════════════════════
const server = http.createServer(async (req, res) => {
  const origin = req.headers.origin || '';
  const acceptEncoding = req.headers['accept-encoding'] || '';

  if (req.method === 'OPTIONS') {
    res.writeHead(204, getCorsHeaders(origin));
    return res.end();
  }

  const url = req.url || '/';
  const clientIP = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.headers['x-real-ip'] || req.socket.remoteAddress || 'unknown';

  try {

    // ── Upload PCAP ─────────────────────────────────────────────
    if (req.method === 'POST' && url.startsWith('/upload')) {
      if (!checkRateLimit(clientIP, RATE_UPLOAD)) {
        return json(res, { error: 'Rate limit exceeded' }, 429, origin, acceptEncoding);
      }
      const contentType = req.headers['content-type'] || '';
      if (!contentType.includes('multipart/form-data')) {
        return json(res, { error: 'Expected multipart/form-data' }, 400, origin, acceptEncoding);
      }
      const boundary = contentType.split('boundary=')[1];
      if (!boundary) return json(res, { error: 'No boundary in content-type' }, 400, origin, acceptEncoding);

      const buffer = await parseBody(req);
      const parts = parseMultipart(buffer, boundary);
      const pcapPart = parts.find(p => p.headers.includes('name="pcap"') || p.headers.includes('name="file"') || p.headers.includes('.pcap') || p.headers.includes('.pcapng'));
      if (!pcapPart) return json(res, { error: 'No PCAP file found in upload' }, 400, origin, acceptEncoding);

      const filenameMatch = pcapPart.headers.match(/filename="([^"]+)"/);
      const filename = filenameMatch ? filenameMatch[1] : 'upload.pcap';
      const sessionId = `session-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
      const pcapPath = path.join(PCAP_DIR, `${sessionId}.pcap`);

      fs.writeFileSync(pcapPath, pcapPart.data);
      console.log(`[Upload] Saved: ${filename} (${pcapPart.data.length} bytes) → ${sessionId}`);

      sessions.set(sessionId, { session_id: sessionId, filename, created_at: Date.now(), size: pcapPart.data.length });

      await b2.send(new PutObjectCommand({
        Bucket: process.env.B2_BUCKET_NAME,
        Key: `pcaps/${sessionId}.pcap`,
        Body: pcapPart.data,
        ContentType: 'application/vnd.tcpdump.pcap'
      }));

      analyzePCAP(sessionId, pcapPath).catch(err => console.error(`[Analysis] Background error: ${err.message}`));

      return json(res, { success: true, session_id: sessionId, filename, size: pcapPart.data.length, message: 'Upload successful, analysis started' }, 200, origin, acceptEncoding);
    }

    // ── Get Summary ──────────────────────────────────────────────
    if (req.method === 'GET' && url.startsWith('/api/summary/')) {
      const sessionId = url.split('/api/summary/')[1]?.split('?')[0];
      if (!isValidSessionId(sessionId)) return json(res, { error: 'Invalid session ID' }, 400, origin, acceptEncoding);
      if (!await ensureSession(sessionId)) return json(res, { error: 'Session not found' }, 404, origin, acceptEncoding);
      const data = await fetchB2JSON(`analysis/${sessionId}-summary.json`);
      if (!data) return json(res, { error: 'Analysis not ready yet, please wait...' }, 202, origin, acceptEncoding);
      return json(res, data, 200, origin, acceptEncoding);
    }

    // ── Get Port Intelligence ────────────────────────────────────
    if (req.method === 'GET' && url.startsWith('/api/ports/')) {
      const sessionId = url.split('/api/ports/')[1]?.split('?')[0];
      if (!isValidSessionId(sessionId)) return json(res, { error: 'Invalid session ID' }, 400, origin, acceptEncoding);
      if (!await ensureSession(sessionId)) return json(res, { error: 'Session not found' }, 404, origin, acceptEncoding);
      const data = await fetchB2JSON(`analysis/${sessionId}-ports.json`);
      if (!data) return json(res, { error: 'Port analysis not ready yet' }, 202, origin, acceptEncoding);
      return json(res, data, 200, origin, acceptEncoding);
    }

    // ── Get Threats ───────────────────────────────────────────────
    if (req.method === 'GET' && url.startsWith('/api/threats/')) {
      const sessionId = url.split('/api/threats/')[1]?.split('?')[0];
      if (!isValidSessionId(sessionId)) return json(res, { error: 'Invalid session ID' }, 400, origin, acceptEncoding);
      if (!await ensureSession(sessionId)) return json(res, { error: 'Session not found' }, 404, origin, acceptEncoding);
      const data = await fetchB2JSON(`analysis/${sessionId}-threats.json`);
      if (!data) return json(res, { error: 'Threat analysis not ready yet' }, 202, origin, acceptEncoding);
      return json(res, data, 200, origin, acceptEncoding);
    }

    // ── Smart Agent Chat ─────────────────────────────────────────
    if (req.method === 'POST' && url.startsWith('/api/agent')) {
      if (!checkRateLimit(clientIP, RATE_AGENT)) {
        return json(res, { error: 'Rate limit exceeded' }, 429, origin, acceptEncoding);
      }

      const body = await parseBody(req);
      const { session_id, message, conversation_history } = JSON.parse(body.toString());
      if (!session_id || !message) return json(res, { error: 'Missing session_id or message' }, 400, origin, acceptEncoding);
      if (!await ensureSession(session_id)) return json(res, { error: 'Session not found' }, 404, origin, acceptEncoding);

      // 1. Keyword routing → decide which files to fetch
      const filesToFetch = resolveFilesForMessage(message);
      console.log(`[Agent] Keyword routing for "${message.slice(0, 60)}..." → files: [${filesToFetch.join(', ')}]`);

      // 2. Fetch only files that exist in B2
      let analysisContext = '';
      const fetchPromises = filesToFetch.map(async (fileType) => {
        const key = `analysis/${session_id}-${fileType}.json`;
        const data = await fetchB2JSON(key);
        if (data) {
          // Limit size for large arrays to avoid LLM token overflow
          const limited = Array.isArray(data) ? data.slice(0, 50) : data;
          return `\n## ${fileType.toUpperCase()} Data\n${JSON.stringify(limited, null, 2)}`;
        }
        return null; // File doesn't exist, skip silently
      });

      const contextParts = await Promise.all(fetchPromises);
      analysisContext = contextParts.filter(Boolean).join('\n');

      if (!analysisContext) {
        analysisContext = '\n## Note\nNo specific protocol data found for this query. Answer based on general network security knowledge.';
      }

      // 3. Build LLM messages
      const messages = [
        {
          role: 'system',
          content: `You are a network security analyst AI with access to PCAP analysis data. Help the user understand network traffic, identify security issues, and provide actionable recommendations.

Only the following data was fetched based on the user's question (other protocol data was skipped to save tokens):
${analysisContext}

Respond in a helpful, concise manner using markdown formatting. If data for a specific protocol isn't shown, mention that no traffic was detected for it in this capture.`
        },
        ...(conversation_history || []),
        { role: 'user', content: message }
      ];

      try {
        const response = await callGroqLLM(messages);
        return json(res, { response, files_used: filesToFetch }, 200, origin, acceptEncoding);
      } catch (e) {
        return json(res, { error: `LLM error: ${e.message}` }, 500, origin, acceptEncoding);
      }
    }

    // ── Health Check ──────────────────────────────────────────────
    if (req.method === 'GET' && url === '/health') {
      return json(res, {
        status: 'ok',
        uptime: process.uptime(),
        sessions: sessions.size,
        iana_registry_loaded: ianaPortRegistry.size,
        nvd_cache_size: nvdCache.size,
        ip_reputation_cache_size: ipReputationCache.size,
        searxng_risk_cache_size: searxngRiskCache.size,
      }, 200, origin, acceptEncoding);
    }

    return json(res, { error: 'Not found' }, 404, origin, acceptEncoding);

  } catch (error) {
    console.error(`[Server] Error: ${error.message}`);
    return json(res, { error: error.message }, 500, origin, acceptEncoding);
  }
});

// ── Start Server ───────────────────────────────────────────────────
const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('  PCAP Intelligence Server - FULL PROTOCOL EDITION');
  console.log('═══════════════════════════════════════════════════════════════');
  console.log(`  Server running on port ${PORT}`);
  console.log(`  CORS Origin: ${ALLOWED_ORIGIN}`);
  console.log('');
  console.log('  WHAT\'S NEW:');
  console.log('  ✓ TShark: Single pass extracts 45+ protocols');
  console.log('  ✓ B2: Only uploads non-empty protocol files (zero waste)');
  console.log('  ✓ Risks: Dynamic from SearXNG (no hardcoded map!)');
  console.log('  ✓ Agent: Smart keyword routing (fetches only relevant files)');
  console.log('  ✓ Agent: Checks B2 existence before fetching (zero wasted tokens)');
  console.log('  ✓ Protocols: DNS, TLS, HTTP, FTP, SMTP, POP3/IMAP, ICMP, ARP,');
  console.log('               DHCP, SSH, SMB, RDP, SNMP, SIP/RTP, NBNS, QUIC,');
  console.log('               LDAP, Telnet, Kerberos, RADIUS, NFS, TFTP, Syslog,');
  console.log('               BGP, OSPF, GRE, IPSec/IKE, VLAN, Modbus, DNP3,');
  console.log('               MQTT, mDNS, WSD, RPC, PostgreSQL, MySQL, Redis,');
  console.log('               MongoDB, NetFlow, VXLAN, L2TP, PPP, CoAP, BACnet,');
  console.log('               DIAMETER');
  console.log('═══════════════════════════════════════════════════════════════');
});

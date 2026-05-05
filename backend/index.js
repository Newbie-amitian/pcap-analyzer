const http = require('http');
const https = require('https');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');
const MiniSearch = require('minisearch');

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
const { S3Client, GetObjectCommand, PutObjectCommand, DeleteObjectCommand, HeadObjectCommand, ListObjectsV2Command } = require('@aws-sdk/client-s3');

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
const IANA_CACHE_TTL = 24 * 60 * 60 * 1000;

let ianaPortRegistry = new Map();
let ianaLastFetch = 0;
let ianaFetchPromise = null;

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
https.get(IANA_CSV_URL, { timeout: 30000, headers: { 
      'Accept': 'text/csv,text/plain,*/*',
      'User-Agent': 'Mozilla/5.0 (compatible; PCAP-Analyzer/1.0; +https://github.com/your-repo)',
      'Accept-Language': 'en-US,en;q=0.9',
    } }, (res) => {      if (res.statusCode !== 200) {
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
// KNOWN 45 PROTOCOLS - Hardcoded risks (reliable, zero-fail)
// ═══════════════════════════════════════════════════════════════════
const KNOWN_PROTOCOL_RISKS = {
  'dns': { risks: ['DNS Spoofing', 'Cache Poisoning', 'DNS Tunneling', 'Amplification DDoS', 'Zone Transfer Exposure'], alternatives: ['DNSSEC', 'DoH', 'DoT'] },
  'http': { risks: ['Cleartext Transmission', 'Man-in-the-Middle', 'Credential Exposure', 'Injection Attacks', 'Session Hijacking'], alternatives: ['HTTPS', 'TLS 1.3'] },
  'ftp': { risks: ['Cleartext Credentials', 'Cleartext Data', 'Anonymous Access', 'Bounce Attack', 'Brute Force'], alternatives: ['SFTP', 'FTPS', 'SCP'] },
  'smtp': { risks: ['Open Relay', 'Spam', 'Phishing', 'Cleartext Auth', 'Email Spoofing'], alternatives: ['SMTPS', 'STARTTLS', 'DMARC'] },
  'pop3': { risks: ['Cleartext Credentials', 'Cleartext Email', 'No Encryption', 'Brute Force'], alternatives: ['POP3S', 'IMAP over TLS'] },
  'imap': { risks: ['Cleartext Credentials', 'Cleartext Email', 'Brute Force', 'MITM'], alternatives: ['IMAPS', 'TLS'] },
  'telnet': { risks: ['Cleartext Everything', 'No Authentication Hardening', 'MITM', 'Credential Exposure', 'Command Injection'], alternatives: ['SSH', 'Mosh'] },
  'snmp': { risks: ['Weak Community Strings', 'Information Disclosure', 'Unauthenticated v1/v2', 'DDoS Amplification', 'Device Enumeration'], alternatives: ['SNMPv3', 'HTTPS-based NMS'] },
  'rdp': { risks: ['BlueKeep CVE', 'Brute Force', 'Pass-the-Hash', 'MITM', 'Credential Theft'], alternatives: ['VPN + RDP', 'SSH Tunnel', 'Zero Trust'] },
  'smb': { risks: ['EternalBlue', 'Ransomware Vector', 'Pass-the-Hash', 'NTLM Relay', 'Lateral Movement'], alternatives: ['SMBv3 with Encryption', 'SFTP', 'VPN'] },
  'ssh': { risks: ['Brute Force', 'Weak Keys', 'Default Credentials', 'SSH Tunneling Abuse'], alternatives: ['Certificate Auth', 'MFA', 'Bastion Host'] },
  'https': { risks: ['Weak TLS Version', 'Expired Certificate', 'Weak Cipher Suite', 'HSTS Missing'], alternatives: ['TLS 1.3', 'HSTS Preload'] },
  'tls': { risks: ['Weak Cipher Suite', 'Old TLS Version', 'Certificate Pinning Missing', 'Downgrade Attack'], alternatives: ['TLS 1.3', 'HSTS'] },
  'ldap': { risks: ['Cleartext Bind', 'Anonymous Bind', 'LDAP Injection', 'Credential Exposure', 'Enumeration'], alternatives: ['LDAPS', 'SASL', 'TLS'] },
  'kerberos': { risks: ['Pass-the-Ticket', 'Golden Ticket', 'Kerberoasting', 'AS-REP Roasting', 'Ticket Replay'], alternatives: ['MFA', 'PAC Validation', 'Tiered Admin'] },
  'radius': { risks: ['Weak Shared Secret', 'MD5-based Auth', 'Replay Attack', 'CoA Injection'], alternatives: ['RADIUS over TLS', 'RadSec', 'TACACS+'] },
  'dhcp': { risks: ['DHCP Starvation', 'Rogue DHCP Server', 'IP Conflict', 'MITM via Gateway Spoofing'], alternatives: ['DHCP Snooping', 'Static ARP', '802.1X'] },
  'arp': { risks: ['ARP Spoofing', 'ARP Poisoning', 'MITM', 'DoS via Gratuitous ARP', 'MAC Flooding'], alternatives: ['Dynamic ARP Inspection', 'Static ARP', 'IPv6 NDP Guard'] },
  'icmp': { risks: ['Ping Flood', 'ICMP Tunneling', 'Smurf Attack', 'Network Mapping', 'TTL Fingerprinting'], alternatives: ['ICMP Rate Limiting', 'Firewall Rules'] },
  'nfs': { risks: ['Unauthenticated Mount', 'Data Exposure', 'RPC Enumeration', 'Privilege Escalation via UID'], alternatives: ['NFSv4 with Kerberos', 'SFTP', 'SMB with Auth'] },
  'tftp': { risks: ['No Authentication', 'Cleartext Transfer', 'Directory Traversal', 'Firmware Tampering'], alternatives: ['SFTP', 'SCP', 'HTTPS-based delivery'] },
  'sip': { risks: ['Toll Fraud', 'Call Hijacking', 'Registration Hijacking', 'Cleartext SIP', 'DoS on PBX'], alternatives: ['SIPS', 'SRTP', 'TLS for SIP'] },
  'mqtt': { risks: ['No Auth by Default', 'Cleartext Topics', 'Topic Injection', 'Unauthorized Publish', 'IoT Botnets'], alternatives: ['MQTT over TLS', 'Auth + ACLs', 'AMQP'] },
  'modbus': { risks: ['No Authentication', 'No Encryption', 'Write to PLC', 'DoS on SCADA', 'Replay Attack'], alternatives: ['VPN over Modbus', 'OPC-UA', 'Encrypted Tunnel'] },
  'dnp3': { risks: ['No Native Auth', 'Replay Attack', 'Spoofed Commands to RTU', 'Critical Infrastructure Risk'], alternatives: ['DNP3 Secure Auth v5', 'IEC 62351'] },
  'bgp': { risks: ['Route Hijacking', 'BGP Hijack', 'Path Manipulation', 'Prefix Deaggregation Attack', 'Session Reset'], alternatives: ['RPKI', 'BGPsec', 'Route Filtering'] },
  'ospf': { risks: ['Rogue Router Injection', 'LSA Flooding', 'Topology Disclosure', 'Auth Bypass'], alternatives: ['OSPFv3 with IPSec', 'MD5 Auth', 'Routing Segmentation'] },
  'gre': { risks: ['No Encryption', 'Tunnel Hijacking', 'Inner Packet Injection', 'DoS via Flood'], alternatives: ['GRE over IPSec', 'WireGuard', 'OpenVPN'] },
  'ipsec': { risks: ['Weak IKE Config', 'Aggressive Mode', 'Pre-shared Key Brute Force', 'IKE Fragmentation'], alternatives: ['IKEv2', 'Certificate Auth', 'WireGuard'] },
  'vlan': { risks: ['VLAN Hopping', 'Double Tagging Attack', 'Trunk Misconfiguration', 'Lateral Movement'], alternatives: ['Private VLAN', 'VLAN ACLs', 'Network Segmentation'] },
  'quic': { risks: ['0-RTT Replay Attack', 'UDP Amplification', 'Connection Migration Abuse'], alternatives: ['Strict 0-RTT Policy', 'Rate Limiting'] },
  'rdp_2': { risks: ['BlueKeep', 'Brute Force', 'DejaBlue', 'MITM'], alternatives: ['NLA', 'VPN', 'MFA'] },
  'syslog': { risks: ['Cleartext UDP', 'Log Injection', 'Forged Log Messages', 'No Auth'], alternatives: ['Syslog over TLS', 'RELP', 'Splunk Forwarder'] },
  'nbns': { risks: ['NBNS Spoofing', 'Credential Capture via Responder', 'NTLM Relay', 'Name Poisoning'], alternatives: ['DNS', 'Disable NetBIOS', 'LLMNR Disabled'] },
  'netflow': { risks: ['Cleartext Flow Data', 'Flow Injection', 'Traffic Pattern Disclosure'], alternatives: ['Encrypted sFlow', 'IPFIX over TLS'] },
  'vxlan': { risks: ['No Native Auth', 'VXLAN Flooding', 'Inner Frame Injection', 'VM-to-VM Lateral Movement'], alternatives: ['VXLAN with IPSec', 'NSX Security Groups'] },
  'l2tp': { risks: ['No Encryption (L2TP alone)', 'PPP Auth Weakness', 'Tunnel Flooding'], alternatives: ['L2TP/IPSec', 'WireGuard', 'OpenVPN'] },
  'coap': { risks: ['Amplification Attack', 'No Auth by Default', 'Cleartext', 'Resource Discovery Abuse'], alternatives: ['CoAPS (DTLS)', 'OSCORE'] },
  'bacnet': { risks: ['No Authentication', 'Unauthenticated Write', 'Building Control Takeover', 'Enumeration'], alternatives: ['BACnet/SC', 'VPN Overlay', 'Firewall Isolation'] },
  'diameter': { risks: ['SS7-like Attacks', 'Subscriber Enumeration', 'Auth Bypass', 'Routing Manipulation'], alternatives: ['Diameter over TLS', 'IPX Filtering', 'SEPP for 5G'] },
  'ldap_plain': { risks: ['Cleartext Bind Credentials', 'Anonymous Access', 'User Enumeration'], alternatives: ['LDAPS', 'StartTLS'] },
  'mysql': { risks: ['SQL Injection', 'Cleartext Auth', 'Default Root No Password', 'Brute Force', 'Data Exfiltration'], alternatives: ['TLS for MySQL', 'Prepared Statements', 'Least Privilege'] },
  'postgresql': { risks: ['SQL Injection', 'Cleartext Auth', 'Trust Auth Misconfiguration', 'Privilege Escalation'], alternatives: ['TLS', 'scram-sha-256', 'pg_hba Hardening'] },
  'redis': { risks: ['No Auth by Default', 'Remote Code Execution', 'Data Exposure', 'SSRF Pivot'], alternatives: ['Redis ACLs', 'TLS', 'requirepass', 'Bind to localhost'] },
  'mongodb': { risks: ['No Auth by Default', 'Open Exposure', 'Data Exfiltration', 'Injection'], alternatives: ['MongoDB Auth', 'TLS', 'IP Whitelisting'] },
};

/**
 * Check if a port belongs to one of the 45 known protocols
 * Returns the key into KNOWN_PROTOCOL_RISKS or null
 */
function getKnownProtocolKey(serviceName) {
  if (!serviceName) return null;
  const lower = serviceName.toLowerCase();
  // Direct match
  if (KNOWN_PROTOCOL_RISKS[lower]) return lower;
  // Partial match for variants like "http-alt" → "http"
  for (const key of Object.keys(KNOWN_PROTOCOL_RISKS)) {
    if (lower.startsWith(key) || lower.includes(key)) return key;
  }
  return null;
}

// ═══════════════════════════════════════════════════════════════════
// SearXNG - Dynamic Security Risk Lookup (ONLY for unknown ports)
// ═══════════════════════════════════════════════════════════════════
const searxngRiskCache = new Map();
const SEARXNG_RISK_TTL = 24 * 60 * 60 * 1000;

async function fetchServiceRisksFromSearXNG(serviceName) {
  if (!serviceName || serviceName === 'Unknown' || serviceName === 'Ephemeral' || serviceName === 'Registered') {
    return { risks: [], alternatives: [], tags: [] };
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
    const tags = new Set();

    // Seed tags from service name words
    serviceName.toLowerCase().split(/[\s\-_\/]+/).filter(w => w.length > 2).forEach(w => tags.add(w));

    if (results.results && results.results.length > 0) {
      const riskKeywords = [
        'unencrypted', 'cleartext', 'clear text', 'plain text', 'no authentication',
        'brute force', 'default credentials', 'buffer overflow', 'injection',
        'man-in-the-middle', 'mitm', 'spoofing', 'amplification', 'ddos',
        'information disclosure', 'data exposure', 'unauthenticated', 'anonymous',
        'privilege escalation', 'remote code execution', 'rce', 'exploit',
        'backdoor', 'malware', 'ransomware', 'exfiltration', 'tunneling',
        'weak encryption', 'deprecated', 'insecure', 'vulnerable', 'attack',
        'replay attack', 'session hijack', 'credential theft', 'lateral movement'
      ];

      const altKeywords = [
        'use instead', 'replace with', 'alternative', 'secure version',
        'recommended', 'upgrade to', 'switch to', 'migrate to', 'prefer'
      ];

      for (const result of results.results.slice(0, 5)) {
        const text = (result.title + ' ' + result.snippet).toLowerCase();

        for (const keyword of riskKeywords) {
          if (text.includes(keyword)) {
            const risk = capitalizeFirst(keyword.replace(/-/g, ' '));
            if (!risks.includes(risk)) {
              risks.push(risk);
              // Each risk keyword also becomes a search tag
              keyword.split(/[\s\-]+/).filter(w => w.length > 3).forEach(w => tags.add(w));
            }
          }
        }

        for (const keyword of altKeywords) {
          const idx = text.indexOf(keyword);
          if (idx !== -1) {
            const snippet = text.slice(idx, idx + 60);
            const protoMatch = snippet.match(/(?:ssh|sftp|https|ldaps|smtps|tls|ssl|snmpv3|imaps|pop3s|ftps|scp|wireguard|ipsec)\b/i);
            if (protoMatch && !alternatives.includes(protoMatch[0].toUpperCase())) {
              alternatives.push(protoMatch[0].toUpperCase());
              tags.add(protoMatch[0].toLowerCase());
            }
          }
        }

        // Extract meaningful words from titles as tags
        result.title.toLowerCase().split(/[\s\-_,]+/).filter(w => w.length > 4).forEach(w => tags.add(w));
      }
    }

    const data = {
      risks: risks.slice(0, 6),
      alternatives: alternatives.slice(0, 3),
      tags: [...tags].slice(0, 20)
    };

    searxngRiskCache.set(cacheKey, { data, timestamp: Date.now() });
    console.log(`[SearXNG] ✓ Dynamic risks for ${serviceName}: ${data.risks.length} risks, ${data.tags.length} tags`);
    return data;

  } catch (e) {
    console.error(`[SearXNG] Risk fetch error for ${serviceName}: ${e.message}`);
    return { risks: [], alternatives: [], tags: [serviceName.toLowerCase()] };
  }
}

function capitalizeFirst(str) {
  return str.charAt(0).toUpperCase() + str.slice(1);
}

/**
 * For known protocols: return hardcoded risks + generate static tags
 * For unknown protocols: fetch dynamically from SearXNG
 */
async function resolvePortRisksAndTags(serviceName, portNum) {
  const knownKey = getKnownProtocolKey(serviceName);

  if (knownKey) {
    // ── KNOWN: use hardcoded risks, build tags from service name + risk words
    const riskData = KNOWN_PROTOCOL_RISKS[knownKey];
    const tags = new Set();
    tags.add(knownKey);
    serviceName.toLowerCase().split(/[\s\-_\/]+/).filter(w => w.length > 2).forEach(w => tags.add(w));
    riskData.risks.forEach(r => r.toLowerCase().split(/[\s\-]+/).filter(w => w.length > 3).forEach(w => tags.add(w)));
    return {
      risks: riskData.risks,
      alternatives: riskData.alternatives,
      tags: [...tags],
      source: 'hardcoded'
    };
  } else {
    // ── UNKNOWN: fully dynamic via SearXNG
    console.log(`[Hybrid] Unknown port ${portNum} (${serviceName}) → SearXNG dynamic lookup`);
    const data = await fetchServiceRisksFromSearXNG(serviceName);
    return {
      risks: data.risks,
      alternatives: data.alternatives,
      tags: data.tags,
      source: 'dynamic'
    };
  }
}

/**
 * Batch resolve risks for all ports, known ones skip SearXNG entirely
 */
async function batchResolvePortRisks(portServiceMap) {
  const results = new Map();

  const uniquePortServicePairs = new Map();
  for (const [port, serviceName] of portServiceMap) {
    if (!uniquePortServicePairs.has(serviceName)) {
      uniquePortServicePairs.set(serviceName, port);
    }
  }

  console.log(`[Risks] Resolving risks for ${uniquePortServicePairs.size} unique services (hybrid: hardcoded + SearXNG)...`);

  const resolvedCache = new Map();
  await Promise.all(
    [...uniquePortServicePairs.entries()].map(async ([serviceName, port]) => {
      const resolved = await resolvePortRisksAndTags(serviceName, port);
      resolvedCache.set(serviceName?.toLowerCase(), resolved);
    })
  );

  for (const [port, serviceName] of portServiceMap) {
    const cached = resolvedCache.get(serviceName?.toLowerCase());
    results.set(port, cached || { risks: [], alternatives: [], tags: [serviceName?.toLowerCase() || ''], source: 'unknown' });
  }

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

// ── Analysis Progress Tracker ─────────────────────────────────
const analysisProgress = new Map();   // sessionId → { step, label, done }
const progressListeners = new Map();  // sessionId → Set of SSE response objects

function setProgress(sessionId, step, label, done = false) {
  const data = { step, label, done };
  analysisProgress.set(sessionId, data);
  console.log(`[Progress] ${sessionId} → step ${step}: ${label}`);

  // Push to all listening SSE clients immediately — zero polling
  const listeners = progressListeners.get(sessionId);
  if (listeners && listeners.size > 0) {
    const msg = `data: ${JSON.stringify(data)}\n\n`;
    for (const res of listeners) {
      try {
        res.write(msg);
        if (done) res.end();
      } catch (_) {}
    }
    if (done) progressListeners.delete(sessionId);
  }
}

// MiniSearch indexes per session (cleaned up on expiry)
const sessionPortIndexes = new Map();     // portIndex per sessionId
const sessionContentIndexes = new Map();  // contentIndex per sessionId

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
      // Clean local files
      try { const p = path.join(PCAP_DIR, `${id}.pcap`); if (fs.existsSync(p)) fs.unlinkSync(p); } catch (_) { }
      try { const p = path.join(EXPORT_DIR, id); if (fs.existsSync(p)) fs.rmSync(p, { recursive: true }); } catch (_) { }

      // ── IMPORTANT: clear MiniSearch indexes to prevent RAM leak ──
      sessionPortIndexes.delete(id);
      sessionContentIndexes.delete(id);

// Fetch summary to know which protocol files actually exist
const summary = await fetchB2JSON(`analysis/${id}-summary.json`);
const dynamicTypes = ['summary', 'packets', 'ports', 'threats'];

if (summary?.protocols_detected) {
  Object.keys(summary.protocols_detected).forEach(proto => dynamicTypes.push(proto));
}

await Promise.all(dynamicTypes.map(type => deleteFromB2(`analysis/${id}-${type}.json`).catch(() => {})));

      // Delete all artifacts for this session from B2
      try {
        const listed = await b2.send(new ListObjectsV2Command({
          Bucket: process.env.B2_BUCKET_NAME,
          Prefix: `artifacts/${id}/`,
        }));
        if (listed.Contents?.length > 0) {
          await Promise.all(listed.Contents.map(obj =>
            deleteFromB2(obj.Key).catch(() => {})
          ));
          console.log(`[Session] Deleted ${listed.Contents.length} artifacts for ${id}`);
        }
      } catch (_) {}

     analysisProgress.delete(id);
      progressListeners.delete(id);
      sessions.delete(id);
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

// ── Groq LLM STREAMING ────────────────────────────────────────────
function callGroqLLMStream(messages, res) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({
      model: GROQ_MODEL,
      messages,
      max_tokens: 1500,
      temperature: 0.7,
      stream: true,
    });

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

    const req = https.request(options, (groqRes) => {
      let buffer = '';

      groqRes.on('data', (chunk) => {
        buffer += chunk.toString();
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed || !trimmed.startsWith('data: ')) continue;
          const data = trimmed.slice(6);
          if (data === '[DONE]') {
            res.write('data: [DONE]\n\n');
            resolve();
            return;
          }
          try {
            const json = JSON.parse(data);
            const token = json.choices?.[0]?.delta?.content;
            if (token) {
              res.write(`data: ${JSON.stringify({ token })}\n\n`);
            }
          } catch (_) { }
        }
      });

      groqRes.on('end', () => {
        res.write('data: [DONE]\n\n');
        resolve();
      });

      groqRes.on('error', reject);
    });

    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Groq stream timeout')); });
    req.write(payload);
    req.end();
  });
}

// Step 3: run extraction + bucket by protocol prefix dynamically
function runTShark(pcapPath) {
  return new Promise((resolve, reject) => {
    const { spawn } = require('child_process');
    const args = [
      '-r', pcapPath,
      '-T', 'json',
      '--no-duplicate-keys',
    ];

    let stdout = '';
    let stderr = '';
    const proc = spawn(TSHARK_BIN, args);
    console.log(`[TShark] Spawned PID: ${proc.pid} — JSON mode (fully dynamic, no field list)`);

    const killTimer = setTimeout(() => {
      console.error(`[TShark] TIMEOUT 120s — killing PID ${proc.pid}. stderr: ${stderr.slice(0, 500)}`);
      proc.kill('SIGKILL');
      reject(new Error('TShark timed out after 120s'));
    }, 120000);

    proc.stdout.on('data', chunk => {
      if (stdout.length === 0) console.log('[TShark] First stdout chunk received');
      stdout += chunk.toString();
    });
    proc.stderr.on('data', chunk => stderr += chunk.toString());
    proc.on('error', err => { clearTimeout(killTimer); reject(new Error(`TShark spawn failed: ${err.message}`)); });
    proc.on('close', (code) => {
      clearTimeout(killTimer);
      if (code !== 0 && code !== null) return reject(new Error(`TShark exited ${code}: ${stderr}`));

      let rawPackets;
      try {
        rawPackets = JSON.parse(stdout);
      } catch (e) {
        return reject(new Error(`TShark JSON parse failed: ${e.message}`));
      }
      if (!Array.isArray(rawPackets) || rawPackets.length === 0) return resolve({ packets: [] });

      const SKIP_PROTOS = new Set(['frame', 'ip', 'ipv6', 'tcp', 'udp', '_ws', 'eth']);

      const buckets = {};
      const packets = [];

      for (const rawPkt of rawPackets) {
        const layers = rawPkt._source?.layers || {};

const gv = (field) => {
          // Try flat key first (some tshark versions flatten)
          if (layers[field] !== undefined) {
            const val = layers[field];
            return Array.isArray(val) ? val[0] || '' : (val || '');
          }
          // Try nested: field = 'udp.srcport' → layers['udp']['udp.srcport']
          const proto = field.split('.')[0];
          if (layers[proto] && typeof layers[proto] === 'object') {
            const val = layers[proto][field];
            if (val !== undefined) return Array.isArray(val) ? val[0] || '' : (val || '');
          }
          return '';
        };

        // DEBUG: log first packet's layer keys to see actual field names
if (packets.length === 0) {
          console.log('[TShark DEBUG] First packet layer keys:', Object.keys(layers).slice(0, 30).join(', '));
          console.log('[TShark DEBUG] udp fields:', JSON.stringify(Object.fromEntries(Object.entries(layers).filter(([k]) => k.startsWith('udp')))));
          console.log('[TShark DEBUG] tcp fields:', JSON.stringify(Object.fromEntries(Object.entries(layers).filter(([k]) => k.startsWith('tcp')))));
        }

        const pkt = {
          frame_number: parseInt(gv('frame.number')) || 0,
          timestamp:    parseFloat(gv('frame.time_epoch')) || 0,
          length:       parseInt(gv('frame.len')) || 0,
          src_ip:       gv('ip.src') || gv('ipv6.src'),
          dst_ip:       gv('ip.dst') || gv('ipv6.dst'),
          ip_proto:     gv('ip.proto'),
          src_port:     parseInt(gv('tcp.srcport')) || parseInt(gv('tcp.src_port')) || parseInt(gv('udp.srcport')) || parseInt(gv('udp.src_port')) || 0,
          dst_port:     parseInt(gv('tcp.dstport')) || parseInt(gv('tcp.dst_port')) || parseInt(gv('udp.dstport')) || parseInt(gv('udp.dst_port')) || 0,
          tcp_flags:    gv('tcp.flags'),
          protocol:     gv('_ws.col.Protocol') || gv('_ws_col_Protocol'),
          info:         gv('_ws.col.Info') || gv('_ws_col_Info'),
        };
        packets.push(pkt);

        // Dynamically bucket by protocol — driven entirely by what fields exist in this packet
        const seenProtos = new Set();
        for (const fieldName of Object.keys(layers)) {
          const proto = fieldName.split('.')[0];
          if (SKIP_PROTOS.has(proto) || seenProtos.has(proto)) continue;
          seenProtos.add(proto);

          const entry = {
            src_ip: pkt.src_ip,
            dst_ip: pkt.dst_ip,
            src_port: pkt.src_port,
            dst_port: pkt.dst_port,
            timestamp: pkt.timestamp,
          };

// In nested JSON mode, protocol fields are inside layers[proto]
          const protoLayer = layers[proto];
          if (protoLayer && typeof protoLayer === 'object' && !Array.isArray(protoLayer)) {
            for (const [k, v] of Object.entries(protoLayer)) {
              if (!k.startsWith(proto + '.')) continue;
              const key = k.slice(proto.length + 1).replace(/\./g, '_');
              entry[key] = Array.isArray(v) ? v[0] : (typeof v === 'object' ? '' : (v || ''));
            }
          }

          if (!buckets[proto]) buckets[proto] = [];
          buckets[proto].push(entry);
        }
      }

      console.log(`[TShark] Extracted packets: ${packets.length}, protocol buckets: ${Object.keys(buckets).join(', ')}`);
      resolve({ packets, ...buckets });
    });
  });
}// ═══════════════════════════════════════════════════════════════════
// MINISEARCH - Port Index Builder
// Used ONLY for unknown ports (outside the 45 hardcoded protocols)
// ═══════════════════════════════════════════════════════════════════

/**
 * Build or return cached MiniSearch port index for a session.
 * portIntel is the array of port objects saved to B2.
 * Only unknown ports (source: 'dynamic') get indexed — known ones
 * are handled by KEYWORD_PROTOCOL_MAP at agent routing time.
 */
function buildPortIndex(sessionId, portIntel) {
  if (sessionPortIndexes.has(sessionId)) return sessionPortIndexes.get(sessionId);

  const index = new MiniSearch({
    fields: ['service_name', 'description', 'tags', 'risks_text'],
    storeFields: ['port', 'service_name', 'description', 'risks', 'alternatives', 'secure', 'source'],
    idField: 'id'
  });

  const docs = portIntel
    .filter(p => p.source === 'dynamic') // only index unknown ports
    .map(p => ({
      id: `port-${p.port}`,
      port: p.port,
      service_name: p.service_name || '',
      description: p.description || '',
      tags: (p.tags || []).join(' '),
      risks_text: (p.risks || []).join(' '),
      risks: p.risks || [],
      alternatives: p.alternatives || [],
      secure: p.secure || false,
      source: p.source || 'unknown'
    }));

  if (docs.length > 0) {
    index.addAll(docs);
    console.log(`[MiniSearch] Built port index for ${sessionId}: ${docs.length} unknown ports indexed`);
  }

  sessionPortIndexes.set(sessionId, index);
  return index;
}

/**
 * Build or return cached MiniSearch content index for a session.
 * Indexes actual traffic content: HTTP URIs, FTP args, SMB files, DNS domains, etc.
 * This is the content search layer — lets agent find specific filenames/URLs/domains.
 */
function buildContentIndex(sessionId, tsharkData) {
  if (sessionContentIndexes.has(sessionId)) return sessionContentIndexes.get(sessionId);

  const index = new MiniSearch({
    fields: ['content', 'protocol', 'src_ip', 'dst_ip'],
    storeFields: ['content', 'protocol', 'src_ip', 'dst_ip', 'port', 'extra'],
    idField: 'id'
  });

  const docs = [];
  let idCounter = 0;

  for (const [proto, data] of Object.entries(tsharkData)) {
    if (proto === 'packets') continue;
    if (!Array.isArray(data) || data.length === 0) continue;

    for (const r of data.slice(0, 2000)) {
      // Grab every field that has a non-blank string value
      const contentParts = Object.entries(r)
        .filter(([k, v]) =>
          v !== null &&
          v !== undefined &&
          typeof v === 'string' &&
          v.trim() !== '' &&
          !['src_ip', 'dst_ip', 'src_port', 'dst_port', 'timestamp'].includes(k)
        )
        .map(([, v]) => v.trim());

      if (contentParts.length === 0) continue;

      docs.push({
        id: `c-${idCounter++}`,
        content: contentParts.join(' '),
        protocol: proto,
        src_ip: r.src_ip || '',
        dst_ip: r.dst_ip || '',
        port: r.dst_port || r.src_port || 0,
        extra: ''
      });
    }
  }

  if (docs.length > 0) {
    index.addAll(docs);
    console.log(`[MiniSearch] Built content index for ${sessionId}: ${docs.length} entries across ${Object.keys(tsharkData).filter(k => k !== 'packets').length} protocols`);
  }

  sessionContentIndexes.set(sessionId, index);
  return index;
}
// ═══════════════════════════════════════════════════════════════════
// SMART AGENT KEYWORD ROUTING (Hardcoded for 45 known protocols)
// ═══════════════════════════════════════════════════════════════════
const KEYWORD_PROTOCOL_MAP = [
  { keywords: ['dns', 'domain', 'resolve', 'hostname', 'nslookup', 'lookup', 'subdomain', 'zone'], file: 'dns' },
  { keywords: ['tls', 'ssl', 'certificate', 'https', 'handshake', 'cipher', 'sni', 'x509', 'encrypt'], file: 'tls' },
  { keywords: ['http', 'web', 'url', 'request', 'response', 'get', 'post', 'header', 'user-agent', 'cookie', 'html', 'api', 'rest', 'status code', 'content-type'], file: 'http' },
  { keywords: ['ftp', 'file transfer', 'filezilla', 'vsftpd', 'passive', 'active mode'], file: 'ftp' },
  { keywords: ['smtp', 'email', 'mail', 'send mail', 'sendgrid', 'postfix', 'relay', 'spam', 'phishing', 'from address', 'to address'], file: 'smtp' },
  { keywords: ['pop3', 'imap', 'retrieve email', 'inbox', 'mailbox', 'fetch mail', 'email client'], file: 'pop3imap' },
  { keywords: ['icmp', 'ping', 'traceroute', 'unreachable', 'ttl exceeded', 'echo request', 'echo reply', 'network reachability'], file: 'icmp' },
  { keywords: ['arp', 'mac address', 'layer 2', 'arp spoofing', 'arp poisoning', 'gratuitous arp', 'ip to mac', 'mac to ip'], file: 'arp' },
  { keywords: ['dhcp', 'ip assignment', 'ip lease', 'ip address assigned', 'dhcp discover', 'dhcp offer', 'dhcp request', 'dhcp ack', 'hostname assignment'], file: 'dhcp' },
  { keywords: ['ssh', 'secure shell', 'openssh', 'key exchange', 'ssh tunnel', 'sftp', 'scp', 'remote login'], file: 'ssh' },
  { keywords: ['smb', 'samba', 'file share', 'windows share', 'network share', 'cifs', 'ransomware', 'eternalblue', 'smb relay'], file: 'smb' },
  { keywords: ['rdp', 'remote desktop', 'mstsc', 'xrdp', 'bluekeep', 'remote access', 'screen sharing'], file: 'rdp' },
  { keywords: ['snmp', 'community string', 'oid', 'mib', 'network management', 'trap', 'snmpwalk', 'device monitoring'], file: 'snmp' },
  { keywords: ['sip', 'rtp', 'voip', 'call', 'phone', 'asterisk', 'invite', 'register', 'toll fraud', 'call hijack', 'audio stream'], file: 'sip' },
  { keywords: ['nbns', 'netbios', 'windows name', 'llmnr', 'broadcast name', 'nbt', 'workgroup', 'responder'], file: 'nbns' },
  { keywords: ['quic', 'http/3', 'http3', 'udp web', 'google quic', 'chromium transport'], file: 'quic' },
  { keywords: ['ldap', 'directory', 'active directory', 'ad', 'ldap bind', 'ldap search', 'openldap', 'credential stuffing ldap'], file: 'ldap' },
  { keywords: ['telnet', 'clear text login', 'unencrypted shell', 'telnet session', 'terminal'], file: 'telnet' },
  { keywords: ['kerberos', 'ticket', 'tgt', 'kdc', 'krbtgt', 'pass the ticket', 'golden ticket', 'ad authentication', 'windows auth'], file: 'kerberos' },
  { keywords: ['radius', 'aaa', 'authentication server', 'access control', 'nas', 'wifi auth', '802.1x'], file: 'radius' },
  { keywords: ['nfs', 'network file system', 'mount', 'nfs share', 'rpc nfs', 'file system access'], file: 'nfs' },
  { keywords: ['tftp', 'trivial ftp', 'tftp server', 'firmware update', 'cisco tftp', 'no auth transfer'], file: 'tftp' },
  { keywords: ['syslog', 'log', 'logging', 'event log', 'log server', 'rsyslog', 'log message', 'facility', 'severity'], file: 'syslog' },
  { keywords: ['bgp', 'border gateway', 'routing', 'autonomous system', 'as path', 'route hijack', 'bgp hijack', 'internet routing'], file: 'bgp' },
  { keywords: ['ospf', 'link state', 'internal routing', 'area', 'lsa', 'routing protocol internal'], file: 'ospf' },
  { keywords: ['gre', 'tunnel', 'encapsulation', 'gre tunnel', 'ip over ip', 'vpn tunnel protocol'], file: 'gre' },
  { keywords: ['ipsec', 'ike', 'vpn', 'esp', 'ah', 'isakmp', 'internet key exchange', 'vpn tunnel', 'encrypted vpn'], file: 'ipsec' },
  { keywords: ['vlan', '802.1q', 'vlan tag', 'trunk port', 'vlan hopping', 'network segmentation'], file: 'vlan' },
  { keywords: ['modbus', 'scada', 'industrial', 'ics', 'plc', 'modbus tcp', 'industrial control', 'ot security'], file: 'modbus' },
  { keywords: ['dnp3', 'dnp', 'utility', 'substation', 'critical infrastructure', 'power grid'], file: 'dnp3' },
  { keywords: ['mqtt', 'iot', 'publish', 'subscribe', 'broker', 'mosquitto', 'sensor', 'embedded device'], file: 'mqtt' },
  { keywords: ['mdns', 'bonjour', 'avahi', 'local discovery', 'zero conf', 'zeroconf', 'local service'], file: 'mdns' },
  { keywords: ['wsd', 'web services discovery', 'ws-discovery', 'device discovery', 'windows wsd'], file: 'wsd' },
  { keywords: ['rpc', 'msrpc', 'dcom', 'dcerpc', 'microsoft rpc', 'remote procedure', 'com+'], file: 'rpc' },
  { keywords: ['postgresql', 'postgres', 'psql', 'pg', 'sql query postgres', 'database postgres'], file: 'postgresql' },
  { keywords: ['mysql', 'mariadb', 'mysqld', 'sql query', 'database query', 'sql injection mysql'], file: 'mysql' },
  { keywords: ['redis', 'cache', 'in-memory', 'redis command', 'redis server', 'keyspace'], file: 'redis' },
  { keywords: ['mongodb', 'mongo', 'nosql', 'bson', 'mongo query', 'mongodb exploit'], file: 'mongodb' },
  { keywords: ['netflow', 'ipfix', 'flow data', 'traffic flow', 'flow export', 'flow collector'], file: 'netflow' },
  { keywords: ['vxlan', 'overlay network', 'vxlan vni', 'virtual extensible lan'], file: 'vxlan' },
  { keywords: ['l2tp', 'layer 2 tunnel', 'l2tp vpn', 'pptp', 'l2f'], file: 'l2tp' },
  { keywords: ['ppp', 'point to point', 'pppoe', 'ppp auth', 'wan protocol'], file: 'ppp' },
  { keywords: ['coap', 'constrained', 'iot coap', 'coap request', 'coap response'], file: 'coap' },
  { keywords: ['bacnet', 'building automation', 'hvac', 'building control', 'smart building'], file: 'bacnet' },
  { keywords: ['diameter', 'aaa diameter', '3gpp', 'lte auth', 'telecoms auth', 'diameter protocol'], file: 'diameter' },
  { keywords: ['threat', 'attack', 'malicious', 'scan', 'exploit', 'intrusion', 'detect', 'alert', 'suspicious'], file: 'threats' },
  { keywords: ['port', 'service', 'cve', 'vulnerability', 'risk', 'exposure'], file: 'ports' },
  { keywords: ['packet', 'traffic', 'ip', 'flow', 'raw', 'frame', 'capture'], file: 'packets' },
  { keywords: ['summary', 'overview', 'total', 'stats', 'count', 'how many', 'statistics'], file: 'summary' },
];

/**
 * HYBRID routing:
 * 1. Run hardcoded KEYWORD_PROTOCOL_MAP → instant, reliable for 45 known protocols
 * 2. If MiniSearch port index exists for session → search it for unknown port matches
 * 3. If MiniSearch content index exists → search for specific filenames/IPs/domains
 * 4. Merge all results, dedupe
 */
async function resolveFilesForMessage(message, sessionId) {
  const lower = message.toLowerCase();
  const files = new Set();

  // ── Step 1: Hardcoded keyword routing (45 known protocols) ──
  for (const entry of KEYWORD_PROTOCOL_MAP) {
    if (entry.keywords.some(kw => lower.includes(kw))) {
      files.add(entry.file);
    }
  }

  // Always include summary
  files.add('summary');

  // ── Step 2: MiniSearch port index (unknown ports only) ──
  let unknownPortMatches = [];
  const portIndex = sessionPortIndexes.get(sessionId);
  if (portIndex && portIndex.documentCount > 0) {
    try {
      const portResults = portIndex.search(message, { fuzzy: 0.2, prefix: true, boost: { service_name: 3, tags: 2 } });
      if (portResults.length > 0) {
        unknownPortMatches = portResults.slice(0, 5).map(r => ({
          port: r.port,
          service_name: r.service_name,
          score: r.score
        }));
        console.log(`[MiniSearch] Port index matched ${portResults.length} unknown ports for query`);
      }
    } catch (_) { }
  }

  // ── Step 3: MiniSearch content index (specific content search) ──
  let contentMatches = [];
  const contentIndex = sessionContentIndexes.get(sessionId);
  if (contentIndex && contentIndex.documentCount > 0) {
    try {
      const contentResults = contentIndex.search(message, { fuzzy: 0.1, prefix: true });
      if (contentResults.length > 0) {
        // Group by protocol to know which protocol files to also pull
        const protocolsFound = new Set(contentResults.slice(0, 20).map(r => r.protocol));
        for (const proto of protocolsFound) {
          files.add(proto); // e.g. 'http', 'ftp', 'smb' etc
        }
        contentMatches = contentResults.slice(0, 10).map(r => ({
          content: r.content,
          protocol: r.protocol,
          src_ip: r.src_ip,
          dst_ip: r.dst_ip,
          port: r.port
        }));
        console.log(`[MiniSearch] Content index matched ${contentResults.length} entries`);
      }
    } catch (_) { }
  }

  // ── Fallback: vague/generic questions ──
  if (files.size <= 1) {
    files.add('threats');
    files.add('ports');
  }

  return {
    files: [...files],
    unknownPortMatches,
    contentMatches
  };
}
// ═══════════════════════════════════════════════════════════════════
// HTTP OBJECT EXPORT - tshark --export-objects
// ═══════════════════════════════════════════════════════════════════
async function exportHttpObjects(sessionId, pcapPath) {
  const exportDir = path.join(EXPORT_DIR, sessionId);
  if (!fs.existsSync(exportDir)) fs.mkdirSync(exportDir, { recursive: true });

  const exportTypes = ['http', 'imf', 'smb', 'tftp', 'dicom'];
  const mimeMap = {
    jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png',
    gif: 'image/gif', webp: 'image/webp', bmp: 'image/bmp',
    html: 'text/html', css: 'text/css', js: 'application/javascript',
    json: 'application/json', txt: 'text/plain', pdf: 'application/pdf',
  };

  console.log(`[Export] Running tshark --export-objects for session ${sessionId}...`);

  // ── Pass 1: tshark --export-objects for SMB/IMF/TFTP/DICOM/HTTP binary files ──
  await Promise.all(exportTypes.map(type => new Promise((resolve) => {
    const { spawn } = require('child_process');
    const typeDir = path.join(exportDir, type);
    if (!fs.existsSync(typeDir)) fs.mkdirSync(typeDir, { recursive: true });

    const proc = spawn(TSHARK_BIN, [
      '-r', pcapPath,
      '--export-objects', `${type},${typeDir}`,
    ], {
      env: { ...process.env, WIRESHARK_RUN_FROM_BUILD: '1' },
      stdio: ['ignore', 'ignore', 'pipe'], // suppress stdout/stderr cleanly
    });

    proc.stderr.resume(); // drain stderr so process doesn't hang
    proc.on('error', () => resolve());
    proc.on('close', (code) => {
      console.log(`[Export] ✓ ${type} export done (exit ${code})`);
      resolve();
    });
    setTimeout(() => { try { proc.kill('SIGKILL'); } catch(_){} resolve(); }, 60000);
  })));

// ── Upload all files to B2 + build manifest ──
// ── Get HTTP object metadata from tshark ──
  const httpMeta = await new Promise((resolve) => {
    const { spawn } = require('child_process');
    const proc = spawn(TSHARK_BIN, [
      '-r', pcapPath,
      '-Y', 'http.response or http.request',
      '-T', 'fields',
      '-e', 'frame.number',
      '-e', 'ip.src',
      '-e', 'ip.dst',
      '-e', 'http.host',
      '-e', 'http.request.uri',
      '-e', 'http.response_for.uri',
    ]);
    let out = '';
    proc.stdout.on('data', d => out += d.toString());
    proc.stderr.resume();
    proc.on('close', () => {
      const rows = [];
      for (const line of out.split('\n')) {
        const [frame, src, dst, host, uri, ruri] = line.split('\t');
        if (frame) rows.push({ frame: parseInt(frame), src, dst, host, uri: uri || ruri || '' });
      }
      resolve(rows);
    });
    proc.on('error', () => resolve([]));
    setTimeout(() => { try { proc.kill(); } catch(_){} resolve([]); }, 15000);
  });

  // ── Upload all files to B2 + build manifest ──
  let uploaded = 0;
  const manifest = [];
  let fileIndex = 0;

  const allDirs = exportTypes.map(t => ({ type: t, dir: path.join(exportDir, t) }));

  for (const { type, dir } of allDirs) {
    if (!fs.existsSync(dir)) continue;
    let files;
    try { files = fs.readdirSync(dir); } catch(_) { continue; }

    await Promise.all(files.map(async (filename) => {
      try {
        const filePath = path.join(dir, filename);
        const fileBuffer = fs.readFileSync(filePath);
        const ext = filename.split('.').pop()?.toLowerCase() || '';
        const contentType = mimeMap[ext] || 'application/octet-stream';
        const b2Key = `artifacts/${sessionId}/${filename}`;

        await b2.send(new PutObjectCommand({
          Bucket: process.env.B2_BUCKET_NAME,
          Key: b2Key,
          Body: fileBuffer,
          ContentType: contentType,
        }));

const meta = httpMeta[fileIndex] || {};
        manifest.push({
          filename,
          artifact_key: b2Key,
          size: fileBuffer.length,
          content_type: contentType,
          src_ip: meta.src || 'unknown',
          dst_ip: meta.dst || 'unknown',
          host: meta.host || '',
          uri: meta.uri || '',
          src_port: 0,
          dst_port: type === 'http' ? 80 : 0,
          packet_num: meta.frame || 0,
          is_image: contentType.startsWith('image/'),
          export_type: type,
        });
        fileIndex++;
        uploaded++;
      } catch (e) {
        console.error(`[Export] Failed to upload ${filename}: ${e.message}`);
      }
    }));
    console.log(`[Export] ✓ ${type}: uploaded ${files.length} files`);
  }
  // Save manifest so /pcap/images can read it instantly without listing B2
  await b2.send(new PutObjectCommand({
    Bucket: process.env.B2_BUCKET_NAME,
    Key: `artifacts/${sessionId}/_manifest.json`,
    Body: JSON.stringify(manifest),
    ContentType: 'application/json',
  }));

  console.log(`[Export] ✓ Total uploaded ${uploaded} objects to B2`);

  // Cleanup local tmp
  try { fs.rmSync(exportDir, { recursive: true }); } catch (_) {}

  return manifest;
}
// ═══════════════════════════════════════════════════════════════════
// MAIN ANALYSIS HANDLER
// ═══════════════════════════════════════════════════════════════════
async function analyzePCAP(sessionId, pcapPath) {
  console.log(`[Analysis] Starting for session: ${sessionId}`);
  const startTime = Date.now();

  try {
    setProgress(sessionId, 0, 'Running TShark extraction');
    console.log('[Analysis] Running TShark + export-objects in parallel...');
    const [tsharkData, exportedManifest] = await Promise.all([
      runTShark(pcapPath),
      exportHttpObjects(sessionId, pcapPath)
    ]);

    const session = sessions.get(sessionId);
    if (session) {
      session.export_done = true;
      session.object_count = exportedManifest.length;
    }

    const { packets } = tsharkData;
    console.log(`[Analysis] Parsed ${packets.length} packets, exported ${exportedManifest.length} objects`);

    setProgress(sessionId, 1, 'Resolving IANA port registry');
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

    // 3. IANA port info for ALL ports (no exceptions)
    console.log(`[Analysis] Getting IANA info for ${ports.size} ports...`);
    const portInfoMap = new Map();
    const portServiceMap = new Map();
    for (const port of ports) {
      const info = await getIANAPortInfo(port);
      portInfoMap.set(port, info);
      portServiceMap.set(port, info?.service_name || 'Unknown');
    }

    setProgress(sessionId, 2, 'Fetching CVEs from NVD');
    // 4. Batch resolve risks: hardcoded for known, SearXNG only for unknown
    console.log('[Analysis] Resolving port risks (hybrid: hardcoded + dynamic)...');
    const portRisksMap = await batchResolvePortRisks(portServiceMap);

    // 5. Batch CVEs for ALL ports
    console.log('[Analysis] Fetching CVEs...');
    const portCVEMap = await batchFetchCVEs(portServiceMap);

    setProgress(sessionId, 3, 'Checking IP reputations');
    // 6. IP reputation
    console.log('[Analysis] Checking IP reputations...');
    const ipReputations = await batchCheckIPReputation([...srcIPs, ...dstIPs]);

    setProgress(sessionId, 4, 'Building threat intelligence');
    // 7. Threat detection
    console.log('[Analysis] Running threat detection...');
    const threats = {
  port_scans: detectPortScans(packets),
  brute_force: detectBruteForce(packets),
  dns_tunneling: detectDNSTunneling(tsharkData.dns || []),
  data_exfiltration: detectDataExfiltration(packets, ipReputations),
  ddos_indicators: detectDDoSPatterns(packets),
  malicious_ips: detectMaliciousIPs([...srcIPs, ...dstIPs], ipReputations)
};

    const criticalAlerts = [...threats.ddos_indicators, ...threats.malicious_ips.filter(t => t.severity === 'CRITICAL'), ...threats.data_exfiltration].length;
    const highAlerts = [...threats.port_scans, ...threats.brute_force.filter(t => t.severity === 'HIGH'), ...threats.dns_tunneling.filter(t => t.severity === 'HIGH'), ...threats.malicious_ips.filter(t => t.severity === 'HIGH')].length;

    // 8. Summary
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
      protocols_detected: Object.fromEntries(
  Object.entries(tsharkData)
    .filter(([proto]) => proto !== 'packets')
    .map(([proto, data]) => [proto, Array.isArray(data) && data.length > 0])
),
    };
    // 9. Build port intelligence (hybrid risks + tags)
    const portIntel = [];
    for (const port of [...ports].sort((a, b) => a - b)) {
      const info = portInfoMap.get(port);
      const cves = portCVEMap.get(port) || [];
      const riskData = portRisksMap.get(port) || { risks: [], alternatives: [], tags: [], source: 'unknown' };

      portIntel.push({
        port,
        service_name: info?.service_name || 'Unknown',
        description: info?.description || '',
        protocol: info?.protocol || 'Unknown',
        risks: riskData.risks,
        alternatives: riskData.alternatives,
        tags: riskData.tags,              // ← used by MiniSearch for unknown ports
        source: riskData.source,          // 'hardcoded' or 'dynamic'
        secure: info?.secure || false,
        cves,
        packet_count: packets.filter(p => p.dst_port === port || p.src_port === port).length
      });
    }

    // 10. Build MiniSearch indexes in memory for this session
    buildPortIndex(sessionId, portIntel);
    buildContentIndex(sessionId, tsharkData);
    console.log(`[Analysis] ✓ MiniSearch indexes built for session ${sessionId}`);

    // 11. Upload to B2
    const uploadMap = {
      [`analysis/${sessionId}-summary.json`]: summary,
      [`analysis/${sessionId}-packets.json`]: packets.slice(0, 10000),
      [`analysis/${sessionId}-ports.json`]: portIntel,
      [`analysis/${sessionId}-threats.json`]: threats,
    };

    let uploadedProtocols = 0;
for (const [proto, data] of Object.entries(tsharkData)) {
  if (proto === 'packets') continue;
  if (Array.isArray(data) && data.length > 0) {
    uploadMap[`analysis/${sessionId}-${proto}.json`] = data;
    uploadedProtocols++;
  }
}
setProgress(sessionId, 5, 'Uploading results to B2');
    console.log(`[Analysis] ${uploadedProtocols} protocol files have data, uploading to B2...`);

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

setProgress(sessionId, 6, 'Analysis complete', true);
    console.log(`[Analysis] ✓ Complete in ${Date.now() - startTime}ms`);
    return { success: true, summary, port_intelligence: portIntel, threats };

  } catch (error) {
    console.error(`[Analysis] Error: ${error.message}`);
    return { success: false, error: error.message };
  }
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
// ── Analysis Progress ─────────────────────────────────────────
    if (req.method === 'GET' && url.startsWith('/api/progress/')) {
      const sessionId = url.split('/api/progress/')[1]?.split('?')[0];
      if (!isValidSessionId(sessionId)) return json(res, { error: 'Invalid session ID' }, 400, origin, acceptEncoding);

      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET',
        'Access-Control-Allow-Headers': 'Content-Type',
      });

      // Send current state immediately
      const current = analysisProgress.get(sessionId) || { step: 0, label: 'Waiting to start...', done: false };
      res.write(`data: ${JSON.stringify(current)}\n\n`);

      if (current.done) return res.end();

      // Register this response as a listener
      if (!progressListeners.has(sessionId)) progressListeners.set(sessionId, new Set());
      progressListeners.get(sessionId).add(res);

      // Clean up when client disconnects
      req.on('close', () => {
        const listeners = progressListeners.get(sessionId);
        if (listeners) {
          listeners.delete(res);
          if (listeners.size === 0) progressListeners.delete(sessionId);
        }
      });

      return; // don't end — keep SSE open
    }

    // ── Get Summary ──────────────────────────────────────────────
    if (req.method === 'GET' && url.startsWith('/api/summary/')) {      const sessionId = url.split('/api/summary/')[1]?.split('?')[0];
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

   // ── GET /pcap/images ─────────────────────────────────────────
    if (req.method === 'GET' && url.startsWith('/pcap/images')) {
      const q = getQuery(url);
      const sessionId = q.session_id;
      if (!isValidSessionId(sessionId)) return json(res, { error: 'Invalid session ID' }, 400, origin, acceptEncoding);
      if (!await ensureSession(sessionId)) return json(res, { error: 'Session not found' }, 404, origin, acceptEncoding);

      // Return 202 if export still running (frontend should poll)
      const sess = sessions.get(sessionId);
      if (sess && sess.export_done === false) {
        return json(res, { error: 'Export still in progress', retry: true }, 202, origin, acceptEncoding);
      }

      // Read manifest written by exportHttpObjects — fast, no B2 listing needed
      const manifest = await fetchB2JSON(`artifacts/${sessionId}/_manifest.json`);
      const images = manifest || [];

      console.log(`[Images] Session ${sessionId}: ${images.length} artifacts found`);
      return json(res, { images }, 200, origin, acceptEncoding);
    }

    // ── GET /pcap/image-data ──────────────────────────────────────
    if (req.method === 'GET' && url.startsWith('/pcap/image-data')) {
      const q = getQuery(url);
      const sessionId = q.session_id;
      const artifactKey = q.key;

      if (!isValidSessionId(sessionId)) return json(res, { error: 'Invalid session ID' }, 400, origin, acceptEncoding);
      if (!artifactKey) return json(res, { error: 'Missing key' }, 400, origin, acceptEncoding);
      if (!await ensureSession(sessionId)) return json(res, { error: 'Session not found' }, 404, origin, acceptEncoding);

      // Security: make sure key belongs to this session
      if (!artifactKey.startsWith(`artifacts/${sessionId}/`)) {
        return json(res, { error: 'Forbidden' }, 403, origin, acceptEncoding);
      }

      try {
        const r = await b2.send(new GetObjectCommand({
          Bucket: process.env.B2_BUCKET_NAME,
          Key: artifactKey,
        }));

        const ext = artifactKey.split('.').pop()?.toLowerCase() || '';
        const mimeMap = {
          jpg: 'image/jpeg', jpeg: 'image/jpeg', png: 'image/png',
          gif: 'image/gif', webp: 'image/webp', bmp: 'image/bmp',
          html: 'text/html', css: 'text/css', js: 'application/javascript',
          json: 'application/json', txt: 'text/plain', pdf: 'application/pdf',
        };
        const contentType = mimeMap[ext] || 'application/octet-stream';

        res.writeHead(200, {
          'Content-Type': contentType,
          'Cache-Control': 'public, max-age=3600',
          ...getCorsHeaders(origin),
        });
        r.Body.pipe(res);
      } catch (e) {
        return json(res, { error: 'Artifact not found' }, 404, origin, acceptEncoding);
      }
      return;
    }

    

    // ── Smart Agent Chat (Hybrid: Hardcoded + MiniSearch) ────────
    const isAgentStream = req.method === 'POST' && url.startsWith('/pcap/agent/stream');
    const isAgentQuery = req.method === 'POST' && (url.startsWith('/pcap/agent/query') || url.startsWith('/api/agent'));

    if (isAgentStream || isAgentQuery) {
      if (!checkRateLimit(clientIP, RATE_AGENT)) {
        if (isAgentStream) {
          res.writeHead(429, { 'Content-Type': 'text/event-stream', ...getCorsHeaders(origin) });
          res.write(`data: ${JSON.stringify({ error: 'Rate limit exceeded' })}\n\n`);
          res.write('data: [DONE]\n\n');
          return res.end();
        }
        return json(res, { error: 'Rate limit exceeded' }, 429, origin, acceptEncoding);
      }

      const body = await parseBody(req);
      // Support both field names: AgentChatBox sends 'prompt', legacy sends 'message'
      const parsed = JSON.parse(body.toString());
      const session_id = parsed.session_id;
      const message = parsed.message || parsed.prompt;
      const conversation_history = parsed.conversation_history || [];

      if (!session_id || !message) {
        if (isAgentStream) {
          res.writeHead(400, { 'Content-Type': 'text/event-stream', ...getCorsHeaders(origin) });
          res.write(`data: ${JSON.stringify({ error: 'Missing session_id or message/prompt' })}\n\n`);
          res.write('data: [DONE]\n\n');
          return res.end();
        }
        return json(res, { error: 'Missing session_id or message' }, 400, origin, acceptEncoding);
      }

      if (!await ensureSession(session_id)) {
        if (isAgentStream) {
          res.writeHead(404, { 'Content-Type': 'text/event-stream', ...getCorsHeaders(origin) });
          res.write(`data: ${JSON.stringify({ error: 'Session not found' })}\n\n`);
          res.write('data: [DONE]\n\n');
          return res.end();
        }
        return json(res, { error: 'Session not found' }, 404, origin, acceptEncoding);
      }

      // ── For streaming: write SSE headers immediately so browser doesn't time out ──
      if (isAgentStream) {
        res.writeHead(200, {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          'Connection': 'keep-alive',
          ...getCorsHeaders(origin),
        });
      }

      // ── If MiniSearch indexes aren't in memory (server restart), rebuild from B2 ──
      if (!sessionPortIndexes.has(session_id) || !sessionContentIndexes.has(session_id)) {
  console.log(`[Agent] MiniSearch indexes not in memory for ${session_id}, rebuilding from B2...`);

  const [portIntelData, summary] = await Promise.all([
    fetchB2JSON(`analysis/${session_id}-ports.json`),
    fetchB2JSON(`analysis/${session_id}-summary.json`),
  ]);

  if (portIntelData) buildPortIndex(session_id, portIntelData);

  if (summary?.protocols_detected) {
    const rebuiltTsharkData = {};

    await Promise.all(
      Object.entries(summary.protocols_detected)
        .filter(([, hasData]) => hasData)
        .map(async ([proto]) => {
          const data = await fetchB2JSON(`analysis/${session_id}-${proto}.json`);
          if (data) rebuiltTsharkData[proto] = data;
        })
    );

    buildContentIndex(session_id, rebuiltTsharkData);
    console.log(`[Agent] Rebuilt content index from protocols: ${Object.keys(rebuiltTsharkData).join(', ')}`);
  } else {
    console.warn(`[Agent] No protocols_detected in summary for ${session_id}, content index will be empty`);
    buildContentIndex(session_id, {});
  }
}
      // 1. Hybrid routing: hardcoded keywords + MiniSearch
      const routing = await resolveFilesForMessage(message, session_id);
      const { files: filesToFetch, unknownPortMatches, contentMatches } = routing;
      console.log(`[Agent] Hybrid routing → files: [${filesToFetch.join(', ')}], unknown ports: ${unknownPortMatches.length}, content hits: ${contentMatches.length}`);

      // 2. Fetch B2 files in parallel
      const fetchPromises = filesToFetch.map(async (fileType) => {
        const key = `analysis/${session_id}-${fileType}.json`;
        const data = await fetchB2JSON(key);
        if (data) {
          const limited = Array.isArray(data) ? data.slice(0, 50) : data;
          return `\n## ${fileType.toUpperCase()} Data\n${JSON.stringify(limited, null, 2)}`;
        }
        return null;
      });

      const contextParts = await Promise.all(fetchPromises);
      let analysisContext = contextParts.filter(Boolean).join('\n');

      // 3. Append unknown port summaries
      if (unknownPortMatches.length > 0) {
        analysisContext += `\n## Unknown/Custom Ports Matched\n`;
        for (const match of unknownPortMatches) {
          analysisContext += `- Port ${match.port} (${match.service_name}) — relevance score: ${match.score?.toFixed(2)}\n`;
          const portData = await fetchB2JSON(`analysis/${session_id}-port-${match.port}.json`);
          if (portData) analysisContext += `  Details: ${JSON.stringify(portData)}\n`;
        }
      }

      // 4. Append content search results
      if (contentMatches.length > 0) {
        analysisContext += `\n## Relevant Traffic Content Found\n`;
        for (const match of contentMatches) {
          analysisContext += `- [${match.protocol.toUpperCase()}] ${match.src_ip} → ${match.dst_ip}:${match.port} | ${match.content}\n`;
        }
      }

      if (!analysisContext.trim()) {
        analysisContext = '\n## Note\nNo specific data found for this query. Answering from general network security knowledge.';
      }

      // 5. Build LLM messages
      const llmMessages = [
        {
          role: 'system',
          content: `You are a network security analyst AI with access to PCAP analysis data. Help the user understand network traffic, identify security issues, and provide actionable recommendations.

Routing used:
- Known protocol files fetched: [${filesToFetch.join(', ')}]
- Unknown port matches (MiniSearch): ${unknownPortMatches.length}
- Content matches (MiniSearch): ${contentMatches.length}

Only the following data was fetched based on the user's question:
${analysisContext}

Respond in a helpful, concise manner using markdown formatting. If data for a specific protocol isn't shown, mention that no traffic was detected for it in this capture.`
        },
        ...conversation_history,
        { role: 'user', content: message }
      ];

      // 6. Stream or JSON respond
      if (isAgentStream) {
        try {
          await callGroqLLMStream(llmMessages, res);
        } catch (e) {
          console.error(`[Agent] Stream error: ${e.message}`);
          res.write(`data: ${JSON.stringify({ error: e.message })}\n\n`);
          res.write('data: [DONE]\n\n');
        } finally {
          res.end();
        }
        return;
      }

      // isAgentQuery — non-streaming JSON response
      try {
        const response = await callGroqLLM(llmMessages);
        return json(res, {
          response,
          files_used: filesToFetch,
          unknown_port_matches: unknownPortMatches.length,
          content_matches: contentMatches.length
        }, 200, origin, acceptEncoding);
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
        minisearch_port_indexes: sessionPortIndexes.size,
        minisearch_content_indexes: sessionContentIndexes.size,
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
  console.log('  PCAP Intelligence Server - HYBRID PROTOCOL EDITION');
  console.log('═══════════════════════════════════════════════════════════════');
  console.log(`  Server running on port ${PORT}`);
  console.log(`  CORS Origin: ${ALLOWED_ORIGIN}`);
  console.log('');
  console.log('  ARCHITECTURE:');
  console.log('  ✓ TShark: Single pass, 45+ protocol extraction');
  console.log('  ✓ Known protocols (45): Hardcoded risks — reliable, zero-fail');
  console.log('  ✓ Unknown ports: Dynamic IANA + SearXNG enrichment');
  console.log('  ✓ Agent routing: Hardcoded keywords for known protocols');
  console.log('  ✓ Agent routing: MiniSearch for unknown port discovery');
  console.log('  ✓ Content search: MiniSearch over HTTP/DNS/FTP/SMB/etc content');
  console.log('  ✓ MiniSearch indexes cleared on session expiry (no RAM leak)');
  console.log('  ✓ MiniSearch auto-rebuilt from B2 on server restart');
  console.log('  ✓ B2: Only non-empty protocol files uploaded');
  console.log('  ✓ Token cost: ~500-900/query (vs 10k-15k before)');
  console.log('═══════════════════════════════════════════════════════════════');
});

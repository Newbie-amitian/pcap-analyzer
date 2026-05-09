const http = require('http');
const { WebSocketServer } = require('ws');
const https = require('https');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');
const MiniSearch = require('minisearch');
const archiver = require('archiver');


// ── Persistent log file ───────────────────────────────────────
const logFile = fs.createWriteStream('./server.log', { flags: 'a' });
const originalLog = console.log.bind(console);
const originalError = console.error.bind(console);
const originalWarn = console.warn.bind(console);

console.log = (...args) => {
  const line = `[${new Date().toISOString()}] ${args.join(' ')}\n`;
  logFile.write(line);
  originalLog(...args);
};
console.error = (...args) => {
  const line = `[ERROR ${new Date().toISOString()}] ${args.join(' ')}\n`;
  logFile.write(line);
  originalError(...args);
};
console.warn = (...args) => {
  const line = `[WARN ${new Date().toISOString()}] ${args.join(' ')}\n`;
  logFile.write(line);
  originalWarn(...args);
};

console.log('=== Server started, logging to server.log ===');

// ── Global crash handler — catch TypeError before it kills the process ──
process.on('uncaughtException', (err, origin) => {
  const stack = err.stack || '';
  const lines = stack.split('\n');
  // Print each line separately so the terminal doesn't truncate
  console.error(`[CRASH] ${err.message}`);
  lines.forEach((line, i) => console.error(`[CRASH:${i}] ${line.trim()}`));
});

process.on('unhandledRejection', (reason, promise) => {
  console.error(`[CRASH] Unhandled Promise Rejection:`, reason);
});
// ═══════════════════════════════════════════════════════════════════
// REQUIRED ENVIRONMENT VARIABLES
// ═══════════════════════════════════════════════════════════════════
const SEARXNG_URL = process.env.SEARXNG_URL;
const GROQ_API_KEY = process.env.GROQ_API_KEY;
const GROQ_MODEL = process.env.GROQ_MODEL || 'llama-3.3-70b-versatile';
const NVIDIA_API_KEY = process.env.NVIDIA_API_KEY;
const NVIDIA_MODEL = process.env.NVIDIA_MODEL || 'meta/llama-4-maverick-17b-128e-instruct';
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
    https.get(IANA_CSV_URL, {
      timeout: 30000, headers: {
        'Accept': 'text/csv,text/plain,*/*',
        'User-Agent': 'Mozilla/5.0 (compatible; PCAP-Analyzer/1.0; +https://github.com/your-repo)',
        'Accept-Language': 'en-US,en;q=0.9',
      }
    }, (res) => {
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

async function fetchServiceRisksFromSearXNG(serviceName, portNum = null) {
  if (!serviceName || serviceName === 'Unknown' || serviceName === 'Ephemeral' || serviceName === 'Registered') {
    console.log(`[SearXNG] Skipping risk lookup for generic service: "${serviceName}"`);
    return { risks: [], alternatives: [], tags: [] };
  }

  const cacheKey = portNum ? `${serviceName.toLowerCase()}:${portNum}` : serviceName.toLowerCase();
  console.log(`[SearXNG] Risk lookup for "${serviceName}"${portNum ? ` port ${portNum}` : ''} (cache key: ${cacheKey})`);
  const cached = searxngRiskCache.get(cacheKey);
  if (cached && (Date.now() - cached.timestamp) < SEARXNG_RISK_TTL) {
    return cached.data;
  }

  try {
    const query = portNum
      ? `"${serviceName}" port ${portNum} protocol security risks vulnerabilities CVE`
      : `"${serviceName}" protocol security risks vulnerabilities CVE`;
    console.log(`[SearXNG] Search query: ${query}`);
    const results = await searchSearXNG(query, 8000);
    console.log(`[SearXNG] Got ${results.results?.length || 0} results for "${serviceName}"`);

    const risks = [];
    const alternatives = [];
    const tags = new Set();

    // Seed tags from service name words
    serviceName.toLowerCase().split(/[\s\-_\/]+/).filter(w => w.length > 2).forEach(w => tags.add(w));

    if (results.results && results.results.length > 0) {
      console.log(`[SearXNG] Processing ${results.results.length} results for "${serviceName}":`);
      results.results.slice(0, 3).forEach((r, i) => {
        console.log(`[SearXNG]   [${i + 1}] ${r.title} | ${r.url}`);
      });
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
    console.log(`[SearXNG] ✓ "${serviceName}" → risks: [${data.risks.join(', ')}]`);
    console.log(`[SearXNG] ✓ "${serviceName}" → alternatives: [${data.alternatives.join(', ')}]`);
    console.log(`[SearXNG] ✓ "${serviceName}" → tags: [${data.tags.slice(0, 8).join(', ')}]`);
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
  // ── IANA gave us the service name. Now ALWAYS ask SearXNG for risks.
  // KNOWN_PROTOCOL_RISKS is used ONLY as a fallback if SearXNG returns nothing.
  console.log(`[Risks] Port ${portNum} → service "${serviceName}" → querying SearXNG...`);

  const data = await fetchServiceRisksFromSearXNG(serviceName, portNum);

  const hasRisks = data.risks && data.risks.length > 0;

  if (hasRisks) {
    console.log(`[Risks] Port ${portNum} (${serviceName}) → SearXNG returned ${data.risks.length} risks`);
    return {
      risks: data.risks,
      alternatives: data.alternatives,
      tags: data.tags,
      source: 'searxng'
    };
  }

  // SearXNG returned nothing — fall back to hardcoded table
  const knownKey = getKnownProtocolKey(serviceName);
  if (knownKey) {
    console.warn(`[Risks] Port ${portNum} (${serviceName}) → SearXNG empty, using hardcoded fallback`);
    const riskData = KNOWN_PROTOCOL_RISKS[knownKey];
    const tags = new Set();
    tags.add(knownKey);
    serviceName.toLowerCase().split(/[\s\-_\/]+/).filter(w => w.length > 2).forEach(w => tags.add(w));
    riskData.risks.forEach(r =>
      r.toLowerCase().split(/[\s\-]+/).filter(w => w.length > 3).forEach(w => tags.add(w))
    );
    return {
      risks: riskData.risks,
      alternatives: riskData.alternatives,
      tags: [...tags],
      source: 'hardcoded-fallback'
    };
  }

  console.warn(`[Risks] Port ${portNum} (${serviceName}) → no risks found from SearXNG or hardcoded table`);
  return {
    risks: [],
    alternatives: [],
    tags: [serviceName.toLowerCase()],
    source: 'none'
  };
}

/**
 * Batch resolve risks for all ports, known ones skip SearXNG entirely
 */
async function batchResolvePortRisks(portServiceMap) {
  const results = new Map();

  // Dedupe by service name — but keep one port per service for the query
  const uniquePortServicePairs = new Map();
  for (const [port, serviceName] of portServiceMap) {
    if (!uniquePortServicePairs.has(serviceName)) {
      uniquePortServicePairs.set(serviceName, port);
    }
  }

  console.log(`[Risks] ═══════════════════════════════════════════`);
  console.log(`[Risks] Resolving risks for ${uniquePortServicePairs.size} unique services via IANA → SearXNG pipeline`);
  console.log(`[Risks] Services to resolve: ${[...uniquePortServicePairs.keys()].join(', ')}`);
  console.log(`[Risks] ═══════════════════════════════════════════`);

  const resolvedCache = new Map();

  // Run SearXNG lookups with concurrency limit (avoid hammering SearXNG)
  const entries = [...uniquePortServicePairs.entries()];
  const CONCURRENCY = 3;

  for (let i = 0; i < entries.length; i += CONCURRENCY) {
    const batch = entries.slice(i, i + CONCURRENCY);
    console.log(`[Risks] Batch ${Math.floor(i / CONCURRENCY) + 1}: resolving [${batch.map(([s]) => s).join(', ')}]`);

    await Promise.all(batch.map(async ([serviceName, port]) => {
      const resolved = await resolvePortRisksAndTags(serviceName, port);
      resolvedCache.set(serviceName?.toLowerCase(), resolved);
      console.log(`[Risks] ✓ Port ${port} (${serviceName}) → source=${resolved.source} risks=${resolved.risks.length} alts=${resolved.alternatives.length}`);
    }));

    // Small delay between batches so SearXNG doesn't rate-limit us
    if (i + CONCURRENCY < entries.length) {
      await new Promise(r => setTimeout(r, 300));
    }
  }

  for (const [port, serviceName] of portServiceMap) {
    const cached = resolvedCache.get(serviceName?.toLowerCase());
    if (!cached) {
      console.warn(`[Risks] Port ${port} (${serviceName}) → cache miss, using empty`);
    }
    results.set(port, cached || {
      risks: [],
      alternatives: [],
      tags: [serviceName?.toLowerCase() || ''],
      source: 'unknown'
    });
  }

  console.log(`[Risks] ✓ All ${results.size} ports resolved`);
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
  // Group by src_ip → dst_ip → list of { port, timestamp, isSynOnly }
  const srcToDst = new Map();

  for (const pkt of packets) {
    if (!pkt.src_ip || !pkt.dst_ip || !pkt.dst_port) continue;

    // Only count SYN packets (tcp.flags = 0x002) — real scanners send SYN only
    // If tcp_flags is missing (non-TCP), skip entirely
    if (!pkt.tcp_flags) continue;
    const flags = parseInt(pkt.tcp_flags, 16);
    const isSynOnly = (flags & 0x3f) === 0x02; // SYN set, ACK not set
    if (!isSynOnly) continue;

    const key = pkt.src_ip;
    if (!srcToDst.has(key)) srcToDst.set(key, new Map());
    const dstMap = srcToDst.get(key);

    if (!dstMap.has(pkt.dst_ip)) dstMap.set(pkt.dst_ip, []);
    dstMap.get(pkt.dst_ip).push({ port: pkt.dst_port, timestamp: pkt.timestamp });
  }

  const portScans = [];

  for (const [srcIp, dstMap] of srcToDst) {
    for (const [dstIp, events] of dstMap) {
      events.sort((a, b) => a.timestamp - b.timestamp);

      // Sliding 60s window
      let startIdx = 0;
      const portSet = new Set();

      for (let endIdx = 0; endIdx < events.length; endIdx++) {
        while (
          startIdx < endIdx &&
          events[endIdx].timestamp - events[startIdx].timestamp > 60
        ) {
          portSet.delete(events[startIdx].port);
          startIdx++;
        }
        portSet.add(events[endIdx].port);

        // Only flag if scanning MULTIPLE DIFFERENT ports on the SAME destination
        // 15+ different ports to same IP in 60s = actual scan
        if (portSet.size >= 15) {
          portScans.push({
            type: 'PORT_SCAN',
            src_ip: srcIp,
            dst_ip: dstIp,               // specific target
            ports_scanned: portSet.size,
            ports: [...portSet].sort((a, b) => a - b),
            severity: portSet.size >= 50 ? 'CRITICAL' : 'HIGH',
            timestamp: events[startIdx].timestamp,
            note: 'SYN-only packets to multiple different ports on same host'
          });
          break;
        }
      }
    }
  }

  return portScans;
}

function detectBruteForce(packets) {
  const attempts = new Map();

  for (const pkt of packets) {
    if (!pkt.src_ip || !pkt.dst_ip || !pkt.dst_port || !pkt.info) continue;

    const info = pkt.info.toLowerCase();
    const isFailure =
      info.includes('fail') ||
      info.includes('invalid') ||
      info.includes('incorrect') ||
      info.includes('denied') ||
      info.includes('unauthorized') ||
      info.includes('rejected');

    if (!isFailure) continue;

    const key = `${pkt.src_ip}→${pkt.dst_ip}:${pkt.dst_port}`;
    if (!attempts.has(key)) {
      attempts.set(key, { timestamps: [], protocol: pkt.protocol || 'UNKNOWN' });
    }
    attempts.get(key).timestamps.push(pkt.timestamp);
  }

  const results = [];

  for (const [key, { timestamps, protocol }] of attempts) {
    timestamps.sort((a, b) => a - b);

    // Sliding 60s window
    let maxInWindow = 0;
    let windowStart = 0;

    for (let i = 0; i < timestamps.length; i++) {
      while (timestamps[i] - timestamps[windowStart] > 60) windowStart++;
      maxInWindow = Math.max(maxInWindow, i - windowStart + 1);
    }

    if (maxInWindow >= 5) {
      const [src, dst] = key.split('→');
      const [dstIp, port] = dst.split(':');
      results.push({
        type: 'BRUTE_FORCE',
        src_ip: src,
        dst_ip: dstIp,
        port: parseInt(port),
        protocol,           // tshark already told you: SSH, FTP, RDP, etc
        attempts: maxInWindow,
        severity: maxInWindow >= 20 ? 'CRITICAL' : maxInWindow >= 10 ? 'HIGH' : 'MEDIUM',
        timestamp: timestamps[0],
        note: `${maxInWindow} failures in 60s window on port ${port} (${protocol})`
      });
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
// CREDENTIAL EXTRACTION — Strict tshark dissector fields ONLY
// Extracts credentials ONLY if explicitly visible in tshark output.
// NO entropy analysis. NO inference. NO decryption attempts.
// If encrypted or absent → "no credentials found"
// Sources (per system prompt):
//   - HTTP Basic Auth: http.authorization
//   - FTP USER/PASS: ftp.request.command + ftp.request.arg
//   - Telnet plaintext: telnet.data
//   - SMTP AUTH plaintext: smtp.auth.username / smtp.auth.password
// ═══════════════════════════════════════════════════════════════════
function analyzeValueForCredentials(fieldKey, value, proto, record) {
  // This function is now a strict allow-list of tshark dissector fields only.
  // Any field NOT in this list is silently ignored — no inference attempted.

  const lower = fieldKey.toLowerCase();

  // ── HTTP Basic Auth ──
  // tshark field: http.authorization → "Basic dXNlcjpwYXNz"
  if (lower === 'authorization' && proto === 'http') {
    const val = (value || '').trim();
    if (val.toLowerCase().startsWith('basic ')) {
      console.log(`[Credentials] HTTP Basic Auth header found (tshark http.authorization field)`);
      return [{
        type: 'HTTP Basic Auth',
        severity: 'CRITICAL',
        evidence: 'tshark http.authorization field contains Basic auth — cleartext credentials in HTTP header'
      }];
    }
    // Not Basic auth — could be Bearer/Digest/etc — do NOT infer
    console.log(`[Credentials] http.authorization present but not Basic auth — not extracting (no inference)`);
    return null;
  }

  // ── SMTP AUTH plaintext ──
  // tshark fields: smtp.auth.username, smtp.auth.password
  if (proto === 'smtp') {
    if (lower === 'auth_username' || lower === 'auth_password') {
      console.log(`[Credentials] SMTP AUTH plaintext field found: smtp.${fieldKey}`);
      return [{
        type: lower.includes('password') ? 'SMTP AUTH Password (Cleartext)' : 'SMTP AUTH Username (Cleartext)',
        severity: 'CRITICAL',
        evidence: `tshark smtp.${fieldKey} field explicitly present in dissection output`
      }];
    }
  }

  // All other fields: do NOT analyze, do NOT infer
  return null;
}


async function fetchEthResolvedFields(pcapPath) {
  // Dynamically verify these fields exist in THIS tshark version
  const validFields = await new Promise((resolve) => {
    const { spawn } = require('child_process');
    const proc = spawn(TSHARK_BIN, ['-G', 'fields']);
    let out = '';
    proc.stdout.on('data', d => out += d.toString());
    proc.stderr.resume();
    proc.on('close', () => {
      const fields = new Set(
        out.split('\n')
          .filter(l => l.startsWith('F\t'))
          .map(l => l.split('\t')[2]?.trim())
          .filter(Boolean)
      );
      resolve(fields);
    });
    proc.on('error', () => resolve(new Set()));
    setTimeout(() => { try { proc.kill(); } catch (_) { } resolve(new Set()); }, 20000);
  });

  const srcField = validFields.has('eth.src_resolved') ? 'eth.src_resolved' : validFields.has('eth.src') ? 'eth.src' : null;
  const dstField = validFields.has('eth.dst_resolved') ? 'eth.dst_resolved' : validFields.has('eth.dst') ? 'eth.dst' : null;

  if (!srcField || !dstField) {
    console.warn('[EthResolved] No resolved MAC fields available in this tshark version');
    return new Map();
  }

  console.log(`[EthResolved] Using fields: src=${srcField}, dst=${dstField}`);

  return new Promise((resolve) => {
    const { spawn } = require('child_process');
    const proc = spawn(TSHARK_BIN, [
      '-r', pcapPath,
      '-T', 'fields',
      '-E', 'separator=|',
      '-E', 'occurrence=f',
      '-E', 'header=n',
      '-e', 'frame.number',
      '-e', srcField,
      '-e', dstField,
    ]);

    let out = '';
    proc.stdout.on('data', d => out += d.toString());
    proc.stderr.resume();
    proc.on('error', () => resolve(new Map()));
    proc.on('close', () => {
      const map = new Map();
      for (const line of out.split('\n')) {
        if (!line.trim()) continue;
        const cols = line.split('|');
        const n = parseInt(cols[0]);
        if (isNaN(n)) continue;
        map.set(n, {
          src_resolved: cols[1] || '',
          dst_resolved: cols[2] || '',
        });
      }
      console.log(`[EthResolved] Fetched resolved MACs for ${map.size} packets`);
      resolve(map);
    });
    setTimeout(() => { try { proc.kill(); } catch (_) { } resolve(new Map()); }, 120000);
  });
}

// Layer 1 — tshark native -z credentials
function runTSharkCredentials(pcapPath) {
  return new Promise((resolve) => {
    const { spawn } = require('child_process');
    const proc = spawn(TSHARK_BIN, [
      '-r', pcapPath,
      '-z', 'credentials',
      '-q'
    ]);

    let stdout = '';
    proc.stdout.on('data', d => stdout += d.toString());
    proc.stderr.resume();

    proc.on('close', () => {
      const leaks = [];
      const lines = stdout.split('\n');
      for (const line of lines) {
        if (!line.includes('|')) continue;
        const parts = line.split('|').map(p => p.trim()).filter(Boolean);
        if (parts.length < 3) continue;
        if (parts[0] === 'Packet' || parts[0] === '------') continue;
        leaks.push({
          type: 'tshark_native',
          packet_num: parseInt(parts[0]) || 0,
          protocol: parts[1] || 'Unknown',
          username: parts[2] || '',
          info: parts[3] || '',
          severity: 'CRITICAL',
          source: 'tshark -z credentials'
        });
      }
      console.log(`[Credentials] tshark native found: ${leaks.length}`);
      resolve(leaks);
    });

    proc.on('error', () => resolve([]));
    setTimeout(() => { try { proc.kill(); } catch (_) { } resolve([]); }, 30000);
  });
}


// ── Helper: decode tshark colon-hex OR plain hex → utf8 string ──
// tshark stores binary data as "75:73:65:72..." (colon-separated bytes)
// Your old code only handled pure hex "757365..." — this handles both
function decodeTSharkHex(raw) {
  if (!raw || typeof raw !== 'string') return null;
  // colon-hex: "75:73:65:72:6e:61:6d:65"
  if (/^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2})+$/.test(raw.trim())) {
    try { return Buffer.from(raw.trim().split(':').join(''), 'hex').toString('utf8'); }
    catch (_) { return null; }
  }
  // plain hex: "757365726e616d65"
  if (/^[0-9a-fA-F]+$/.test(raw.trim()) && raw.length % 2 === 0) {
    try { return Buffer.from(raw.trim(), 'hex').toString('utf8'); }
    catch (_) { return null; }
  }
  // already text
  return raw;
}

// ── Helper: scan a decoded query-string body for secret params ──
// Purely key-name driven — zero hardcoded protocol assumptions
function scanDecodedBody(decoded, record, sourceLabel) {
  if (!decoded || typeof decoded !== 'string') return [];
  const leaks = [];
  const params = decoded.split('&');
  for (const param of params) {
    const eqIdx = param.indexOf('=');
    if (eqIdx === -1) continue;
    let key = '', val = '';
    try {
      key = decodeURIComponent(param.slice(0, eqIdx)).toLowerCase().trim();
      val = decodeURIComponent(param.slice(eqIdx + 1)).trim();
    } catch (_) {
      key = param.slice(0, eqIdx).toLowerCase().trim();
      val = param.slice(eqIdx + 1).trim();
    }
    if (!val || val.length < 1) continue;

    // Dynamic key-name check — no hardcoded protocol names
    const isSecretKey =
      key.includes('pass') || key.includes('pwd') ||
      key.includes('secret') || key.includes('token') ||
      key.includes('api_key') || key.includes('apikey') ||
      key.includes('auth') || key.includes('credential') ||
      key.includes('private') || key.includes('key');

    if (!isSecretKey) continue;

    leaks.push({
      type: 'dynamic_scan',
      protocol: record._proto ? record._proto.toUpperCase() : 'HTTP',
      field: `POST body param: ${key}`,
      severity: 'CRITICAL',
      credential_type: 'Cleartext Credential in POST Body',
      evidence: `param key "${key}" found in cleartext POST body`,
      src_ip: record.src_ip || null,
      dst_ip: record.dst_ip || null,
      src_port: record.src_port || null,
      dst_port: record.dst_port || null,
      value_length: val.length,
      value_preview: val.slice(0, 8) + '...[redacted]',
      source: sourceLabel,
    });
  }
  return leaks;
}

// ── Layer 2+3: scan ALL tshark protocol buckets dynamically ──
function scanTsharkDataForCredentials(tsharkData, packets) {
  const leaks = [];

  for (const [proto, records] of Object.entries(tsharkData)) {
    if (proto === 'packets' || !Array.isArray(records)) continue;

    for (const record of records) {
      for (const [fieldKey, value] of Object.entries(record)) {
        // Skip non-string and internal fields
        if (!value || typeof value !== 'string') continue;

        // ── Skip known-noisy field names entirely ──
        // These are structural tshark fields that never contain secrets
        const lowerKey = fieldKey.toLowerCase();
        if (
          lowerKey === 'src_ip' || lowerKey === 'dst_ip' ||
          lowerKey === 'src_port' || lowerKey === 'dst_port' ||
          lowerKey === 'timestamp' || lowerKey === 'proto' ||
          lowerKey.includes('timestamp') || lowerKey.includes('_raw') ||
          lowerKey === 'request_line' || lowerKey === 'response_line' ||
          lowerKey === 'user_agent' || lowerKey === 'accept' ||
          lowerKey === 'accept_encoding' || lowerKey === 'accept_language' ||
          lowerKey === 'content_type' || lowerKey === 'referer' ||
          lowerKey === 'connection' || lowerKey === 'host' ||
          lowerKey === 'cache_control' || lowerKey === 'request_full_uri' ||
          lowerKey === 'request_number' || lowerKey === 'prev_request_in' ||
          lowerKey === 'server' || lowerKey === 'date' || lowerKey === 'content_length' ||
          lowerKey === 'content_length_header' || lowerKey === 'request' ||
          lowerKey === 'file_data' || lowerKey === 'data' ||
          lowerKey === 'response_body' || lowerKey === 'chunk_data' ||
          lowerKey === 'request_body'
        ) continue;

        // Skip entire encrypted protocol buckets — tshark cannot give us plaintext
        if (['tls', 'ssl', 'quic', 'dtls'].includes(proto)) {
          // Encrypted — no credentials extractable without decryption key
          // Per system prompt: NEVER attempt decryption or inference
          continue;
        }

        const findings = analyzeValueForCredentials(fieldKey, value, proto, record); if (!findings) continue;

        for (const finding of findings) {
          leaks.push({
            type: 'dynamic_scan',
            protocol: proto.toUpperCase(),
            field: `${proto}: ${fieldKey}`,
            severity: finding.severity,
            credential_type: finding.type,
            evidence: finding.evidence,
            src_ip: record.src_ip || null,
            dst_ip: record.dst_ip || null,
            src_port: record.src_port || null,
            dst_port: record.dst_port || null,
            value_length: value.length,
            value_preview: value.slice(0, 8) + '...[redacted]',
            source: `dynamic-scan-${proto}`,
          });
        }
      }
    }
  }

  // ── Layer 4a: HTTP POST body via http bucket file_data ──
  // tshark stores POST body as colon-hex in http.file_data — decode it properly
  const httpRecords = tsharkData['http'] || [];
  for (const record of httpRecords) {
    const rawBody = record.file_data || record.request_body || record.data || '';
    if (!rawBody) continue;
    const decoded = decodeTSharkHex(rawBody);   // ← handles both colon-hex AND plain hex
    if (!decoded) continue;
    const bodyLeaks = scanDecodedBody(decoded, { ...record, _proto: 'http' }, 'http-file_data');
    bodyLeaks.forEach(l => {
      l.packet_num = record.frame_number || null;
      // Hard sanitize value_preview — strip any HTML/JS blobs, keep only short clean previews
      if (l.value_preview && (
        l.value_preview.length > 20 ||
        l.value_preview.includes('<') ||
        l.value_preview.includes('>') ||
        l.value_preview.includes('{') ||
        l.value_preview.includes('}') ||
        l.value_preview.includes('</') ||
        /[a-z]{20,}/i.test(l.value_preview)
      )) {
        l.value_preview = '...[redacted]';
      }
    });
    leaks.push(...bodyLeaks);
  }

  // ── Layer 4b: urlencoded-form bucket — tshark pre-parsed key/value pairs ──
  // This is the PRIMARY source for HTML form POST credentials.
  // tshark dissects "username=admin&password=password" into explicit key/value fields.
  // The bucket loop now stores them as arrays (key=[username,password,...], value=[admin,password,...])
  // because multiple form items all share the same field names urlencoded-form.key / .value
  const formRecords = tsharkData['urlencoded-form'] || [];
  for (const record of formRecords) {
    // keys and values are stored as arrays from the bucket loop fix
    const keys = Array.isArray(record.key) ? record.key : (record.key ? [record.key] : []);
    const vals = Array.isArray(record.value) ? record.value : (record.value ? [record.value] : []);

    for (let i = 0; i < keys.length; i++) {
      const k = (keys[i] || '').toLowerCase().trim();
      const v = (vals[i] || '').trim();
      if (!k || !v) continue;

      const isSecretKey =
        k.includes('pass') || k.includes('pwd') ||
        k.includes('secret') || k.includes('token') ||
        k.includes('api_key') || k.includes('apikey') ||
        k.includes('auth') || k.includes('credential') ||
        k.includes('private') || k.includes('key');

      if (!isSecretKey) continue;

      leaks.push({
        type: 'dynamic_scan',
        protocol: 'HTTP',
        field: `urlencoded-form: ${k}`,
        severity: 'CRITICAL',
        credential_type: 'Cleartext Credential in HTML Form POST',
        evidence: `form field "${k}" submitted in cleartext over HTTP`,
        src_ip: record.src_ip || null,
        dst_ip: record.dst_ip || null,
        src_port: record.src_port || null,
        dst_port: record.dst_port || null,
        value_length: v.length,
        value_preview: v.slice(0, 8) + '...[redacted]',
        source: 'urlencoded-form-bucket',
        packet_num: record.frame_number || null,
        value_preview: v.slice(0, 8).replace(/[<>{}&]/g, '') + '...[redacted]',
      });
    }
  }

  // ── FTP USER/PASS — tshark ftp.request.command + ftp.request.arg ──
  // ONLY extract if tshark explicitly dissected these fields.
  // Never reconstruct from raw TCP data.
  const ftpRecords = tsharkData['ftp'] || [];
  console.log(`[Credentials][FTP] Checking ${ftpRecords.length} tshark FTP records for USER/PASS`);

  let ftpFoundAny = false;
  for (const record of ftpRecords) {
    const cmd = (record.request_command || '').toUpperCase().trim();
    const arg = (record.request_arg || '').trim();

    if (!cmd || !arg) continue;

    if (cmd === 'USER' || cmd === 'PASS') {
      ftpFoundAny = true;
      console.log(`[Credentials][FTP] tshark ftp.request.command="${cmd}" explicitly found | ${record.src_ip} → ${record.dst_ip}`);
      leaks.push({
        type: 'tshark_dissector',
        protocol: 'FTP',
        field: 'ftp.request.command / ftp.request.arg',
        severity: 'CRITICAL',
        credential_type: cmd === 'USER' ? 'FTP Username (Cleartext)' : 'FTP Password (Cleartext)',
        evidence: `tshark ftp dissector explicitly decoded FTP ${cmd} command — cleartext credential in control channel`,
        src_ip: record.src_ip || null,
        dst_ip: record.dst_ip || null,
        src_port: record.src_port || null,
        dst_port: record.dst_port || null,
        value_length: arg.length,
        value_preview: cmd === 'USER' ? arg.slice(0, 12) : arg.slice(0, 2) + '...[redacted]',
        source: 'ftp-dissector-field',
      });
    }
  }
  if (!ftpFoundAny && ftpRecords.length > 0) {
    console.log(`[Credentials][FTP] FTP traffic present but no USER/PASS in tshark dissection — may be encrypted (FTPS) or data-only`);
  }
  if (ftpRecords.length === 0) {
    console.log(`[Credentials][FTP] Not present in this capture`);
  }

  // ── Telnet plaintext — tshark telnet.data field ──
  // tshark reassembles Telnet data — if login/password appear, they're explicitly in the field
  const telnetRecords = tsharkData['telnet'] || [];
  console.log(`[Credentials][Telnet] Checking ${telnetRecords.length} tshark Telnet records`);

  let telnetFoundAny = false;
  for (const record of telnetRecords) {
    // tshark field: telnet.data — contains the actual cleartext bytes tshark decoded
    const rawData = record.data || record.telnet_data || '';
    if (!rawData) continue;

    const decoded = decodeTSharkHex(rawData);
    if (!decoded) continue;

    // Only flag if tshark's own dissection shows login prompt keywords
    // This means tshark explicitly decoded these bytes — not inferred
    const lower = decoded.toLowerCase();
    if (lower.includes('login:') || lower.includes('password:') || lower.includes('username:')) {
      telnetFoundAny = true;
      console.log(`[Credentials][Telnet] tshark telnet.data contains login prompt — cleartext session | ${record.src_ip} → ${record.dst_ip}`);
      leaks.push({
        type: 'tshark_dissector',
        protocol: 'TELNET',
        field: 'telnet.data',
        severity: 'CRITICAL',
        credential_type: 'Telnet Cleartext Login Session',
        evidence: `tshark telnet dissector decoded cleartext login prompt in telnet.data field`,
        src_ip: record.src_ip || null,
        dst_ip: record.dst_ip || null,
        src_port: record.src_port || null,
        dst_port: record.dst_port || null,
        value_length: decoded.length,
        value_preview: decoded.slice(0, 20).replace(/[\r\n<>{}&]/g, '↵').replace(/\s+/g, ' ').trim() + '...',
        source: 'telnet-dissector-field',
      });
    }
  }
  if (telnetRecords.length === 0) {
    console.log(`[Credentials][Telnet] Not present in this capture`);
  }

  // ── SMTP AUTH plaintext — already handled by analyzeValueForCredentials above ──
  const smtpRecords = tsharkData['smtp'] || [];
  console.log(`[Credentials][SMTP] Checking ${smtpRecords.length} tshark SMTP records`);
  if (smtpRecords.length === 0) {
    console.log(`[Credentials][SMTP] Not present in this capture`);
  }

  // ── HTTP Basic Auth — from http.authorization via analyzeValueForCredentials above ──
  const httpRecords2 = tsharkData['http'] || [];
  const basicAuthCount = leaks.filter(l => l.credential_type === 'HTTP Basic Auth').length;
  if (httpRecords2.length > 0 && basicAuthCount === 0) {
    console.log(`[Credentials][HTTP] HTTP traffic present but no Basic Auth found in tshark http.authorization — may be using other auth or none`);
  }
  if (httpRecords2.length === 0) {
    console.log(`[Credentials][HTTP] Not present in this capture`);
  }

  console.log(`[Credentials] ═══════════════════════════════════════════`);
  console.log(`[Credentials] Scan complete. Total: ${leaks.length} credential leaks found`);
  console.log(`[Credentials] Breakdown: FTP=${leaks.filter(l => l.protocol === 'FTP').length} | Telnet=${leaks.filter(l => l.protocol === 'TELNET').length} | HTTP=${leaks.filter(l => l.protocol === 'HTTP').length} | SMTP=${leaks.filter(l => l.protocol === 'SMTP').length} | native=${leaks.filter(l => l.type === 'tshark_native').length}`);
  console.log(`[Credentials] ═══════════════════════════════════════════`);
  if (leaks.length === 0) {
    console.log(`[Credentials] No credentials found in this capture (encrypted or absent)`);
  }
  return leaks;
}


function runTSharkExpert(pcapPath) {
  return new Promise((resolve) => {
    const { spawn } = require('child_process');
    const proc = spawn(TSHARK_BIN, ['-r', pcapPath, '-z', 'expert', '-q']);

    let stdout = '';
    proc.stdout.on('data', d => stdout += d.toString());
    proc.stderr.resume();

    proc.on('close', () => {
      const threats = [];
      const lines = stdout.split('\n');
      let inTable = false;

      for (const line of lines) {
        if (line.includes('Expert Information')) { inTable = true; continue; }
        if (!inTable || !line.trim() || line.startsWith('=')) continue;

        const match = line.match(/^\s*(\d+)\s+(Error|Warn|Note|Chat)\s+(\S+)\s+(.+)$/i);
        if (!match) continue;

        const [, freq, severity, protocol, summary] = match;

        if (severity.toLowerCase() === 'chat') continue;

        const SKIP_SUMMARIES = [
          'TCP Retransmission', 'Duplicate ACK', 'TCP Out-Of-Order',
          'TCP Fast Retransmission', 'TCP Dup ACK', 'TCP Window',
        ];
        if (SKIP_SUMMARIES.some(s => summary.includes(s))) continue;

        threats.push({
          type: 'EXPERT_INFO',
          frequency: parseInt(freq),
          severity: severity.toLowerCase() === 'error' ? 'HIGH'
            : severity.toLowerCase() === 'warn' ? 'MEDIUM'
              : 'LOW',
          protocol: protocol.toUpperCase(),
          summary: summary.trim(),
          source: 'tshark -z expert'
        });
      }

      console.log(`[Expert] tshark found: ${threats.length} expert items`);
      resolve(threats);
    });

    proc.on('error', () => resolve([]));
    setTimeout(() => { try { proc.kill(); } catch (_) { } resolve([]); }, 30000);
  });
}

// Master function — combines all 3 layers
async function detectCredentialLeaks(pcapPath, tsharkData, packets) {
  console.log(`[Credentials] ═══ Starting credential extraction ═══`);
  console.log(`[Credentials] Method: tshark dissector fields ONLY — no inference, no decryption`);
  console.log(`[Credentials] Checking: HTTP Basic Auth | FTP USER/PASS | Telnet plaintext | SMTP AUTH`);

  const [nativeLeaks, dynamicLeaks] = await Promise.all([
    runTSharkCredentials(pcapPath),
    Promise.resolve(scanTsharkDataForCredentials(tsharkData, packets))
  ]);

  console.log('[Credentials] nativeLeaks:', nativeLeaks?.length, 'dynamicLeaks:', dynamicLeaks?.length);

  const all = [...(nativeLeaks || []), ...(dynamicLeaks || [])];

  console.log('[Credentials] Pre-dedupe count:', all.length);
  all.forEach((l, i) => {
    console.log(`[Credentials] leak[${i}]: source=${l.source} field=${l.field} credential_type=${l.credential_type}`);
  });
  all.forEach((l, i) => {
    console.log(`[Credentials] leak[${i}]: source=${l.source} field=${l.field} credential_type=${l.credential_type} src=${l.src_ip} dst=${l.dst_ip} marker=${l._unique_marker || 'none'}`);
  });

  const seen = new Set();
  const deduped = all.filter(leak => {
    // Normalize field name — strips source prefix so "urlencoded-form: password"
    // and "POST body param: password" from the same connection are treated as one
    const normalizedField = (leak.field || '')
      .replace(/^(urlencoded-form:|POST body param:|http:|ftp:|smtp:)\s*/i, '')
      .toLowerCase()
      .trim();

    const key = [
      leak.protocol || '',
      leak.src_ip || '',
      leak.dst_ip || '',
      leak.src_port || '',
      leak.dst_port || '',
      normalizedField,           // ← normalized instead of raw field
      leak.credential_type || '',
    ].join('|');
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  console.log(`[Credentials] Total after dedupe: ${deduped.length} (${nativeLeaks.length} native + ${dynamicLeaks.length} dynamic)`);
  return deduped;
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

// ── TShark version detection ───────────────────────────────────────
// Resolves once at startup. All field names and export logic branch on this.
const TSHARK_CAPS = {
  version: [0, 0, 0],       // [major, minor, patch]
  versionStr: 'unknown',
  // field name variants that changed across versions
  fields: {
    contentLength: 'http.content_length',        // default (old)
    srcPort_tcp: 'tcp.srcport',
    dstPort_tcp: 'tcp.dstport',
    srcPort_udp: 'udp.srcport',
    dstPort_udp: 'udp.dstport',
    frameNumber: 'frame.number',
    timeEpoch: 'frame.time_epoch',
    frameLen: 'frame.len',
    colProtocol: '_ws.col.Protocol',
    colInfo: '_ws.col.Info',
    fullUri: 'http.request.full_uri',
  },
  // export-objects filename format:
  // Windows (all versions) : bare filename, no prefix  e.g. "login.php"
  // Linux tshark < 3.3     : bare filename, no prefix  e.g. "login.php"
  // Linux tshark >= 3.3    : stream-index prefix        e.g. "28_login.php"
  // NOTE: tcp.stream dissector field works on ALL platforms — this only affects filenames.
  hasStreamPrefix: false,
  // http.content_length_64bit exists only in >= 3.4
  has64bitContentLength: false,
  // nested JSON mode (--no-duplicate-keys changes layout in 3.6+)
  nestedJson: false,
};

const TSHARK_CAPS_READY = new Promise((resolve) => {
  const { spawn } = require('child_process');

  // Use spawn instead of exec — avoids cmd.exe wrapper breaking the pipe on Windows
  const proc = spawn(TSHARK_BIN, ['-v']);
  let stdout = '';
  let stderr = '';

  proc.stdout.on('data', d => stdout += d.toString());
  proc.stderr.on('data', d => stderr += d.toString());

  proc.on('error', (err) => {
    console.error(`[FATAL] tshark not found at: ${TSHARK_BIN} — ${err.message}`);
    resolve(TSHARK_CAPS);
  });

  const killTimer = setTimeout(() => {
    try { proc.kill(); } catch (_) { }
    console.error(`[FATAL] tshark -v timed out`);
    resolve(TSHARK_CAPS);
  }, 8000);

  proc.on('close', () => {
    clearTimeout(killTimer);
    const raw = (stdout || stderr || '').split('\n')[0];
    console.log(`[Init] TShark found: ${raw}`);

    const m = raw.match(/(\d+)\.(\d+)\.(\d+)/);
    if (m) {
      const [, maj, min, pat] = m.map(Number);
      TSHARK_CAPS.version = [maj, min, pat];
      TSHARK_CAPS.versionStr = `${maj}.${min}.${pat}`;
      TSHARK_CAPS.hasStreamPrefix = process.platform !== 'win32' && ((maj > 3) || (maj === 3 && min >= 3));
      TSHARK_CAPS.has64bitContentLength = (maj > 3) || (maj === 3 && min >= 4);
      TSHARK_CAPS.nestedJson = (maj > 3) || (maj === 3 && min >= 6);
      TSHARK_CAPS.fields.contentLength = ((maj > 3) || (maj === 3 && min >= 4))
        ? 'http.content_length_64bit'
        : 'http.content_length';

      console.log(`[Init] TShark caps: v${TSHARK_CAPS.versionStr} | streamPrefix=${TSHARK_CAPS.hasStreamPrefix} | 64bitLen=${TSHARK_CAPS.has64bitContentLength}`);
    }
    resolve(TSHARK_CAPS);
  });
});

// AFTER — add a one-time cached promise for all link fields:
console.log(`[Init] TShark path: ${TSHARK_BIN}`);

// Cache tshark link fields once at startup — used by packet-dissection endpoint
// Avoids re-running tshark -G fields on every packet click
let _cachedLinkFields = null;
async function getCachedLinkFields() {
  if (_cachedLinkFields) return _cachedLinkFields;
  _cachedLinkFields = await new Promise((resolve) => {
    const { spawn } = require('child_process');
    const proc = spawn(TSHARK_BIN, ['-G', 'fields']);
    let out = '';
    proc.stdout.on('data', d => out += d.toString());
    proc.stderr.resume();
    proc.on('close', () => {
      const fields = out.split('\n')
        .filter(l => l.startsWith('F\t'))
        .map(l => l.split('\t')[2]?.trim())
        .filter(f => f && (
          f.endsWith('.response_in') ||
          f.endsWith('.request_in') ||
          f.endsWith('.response_to') ||
          f.endsWith('.request_for') ||
          f.endsWith('.resp_in') ||
          f.endsWith('.resp_to') ||
          f.endsWith('.request_out') ||
          f.endsWith('.response_out') ||
          f.endsWith('.response_for') ||
          f.endsWith('.next_request_in') ||
          f.endsWith('.prev_request_in')
        ));
      console.log(`[Init] Cached ${fields.length} cross-frame link fields from tshark`);
      resolve(fields);
    });
    proc.on('error', () => resolve([]));
    setTimeout(() => { try { proc.kill(); } catch (_) { } resolve([]); }, 20000);
  });
  return _cachedLinkFields;
}
// Warm the cache at startup
getCachedLinkFields().catch(() => { });

// ── Session store ──────────────────────────────────────────────
const sessions = new Map();
const SESSION_TTL_MS = 30 * 60 * 1000;

// ── Analysis Progress Tracker ─────────────────────────────────
const analysisProgress = new Map();
const progressHistory = new Map();
const progressClients = new Map(); // sessionId → Set of WebSocket clients

function setProgress(sessionId, step, label, done = false) {
  const data = { step, label, done };
  analysisProgress.set(sessionId, data);
  if (!progressHistory.has(sessionId)) progressHistory.set(sessionId, []);
  progressHistory.get(sessionId).push(data);
  console.log(`[Progress] ${sessionId} → step ${step}: ${label}`);
  const clients = progressClients.get(sessionId);
  if (clients && clients.size > 0) {
    const msg = JSON.stringify(data);
    for (const ws of clients) {
      try {
        if (ws.readyState === 1) ws.send(msg);
      } catch (_) { }
    }
    if (done) progressClients.delete(sessionId);
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

      await Promise.all(dynamicTypes.map(type => deleteFromB2(`analysis/${id}-${type}.json`).catch(() => { })));

      // Delete all artifacts for this session from B2
      try {
        const listed = await b2.send(new ListObjectsV2Command({
          Bucket: process.env.B2_BUCKET_NAME,
          Prefix: `artifacts/${id}/`,
        }));
        if (listed.Contents?.length > 0) {
          await Promise.all(listed.Contents.map(obj =>
            deleteFromB2(obj.Key).catch(() => { })
          ));
          console.log(`[Session] Deleted ${listed.Contents.length} artifacts for ${id}`);
        }
      } catch (_) { }

      analysisProgress.delete(id);
      progressHistory.delete(id);
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
function callLLMDirect(hostname, path, apiKey, model, messages, maxTokens) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({ model, messages, max_tokens: maxTokens, temperature: 0.7 });
    const options = {
      hostname,
      path,
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
      },
      timeout: 60000,
    };
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          if (res.statusCode !== 200) return reject(new Error(`LLM API ${res.statusCode}: ${data}`));
          const json = JSON.parse(data);
          resolve(json.choices?.[0]?.message?.content || '');
        } catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('LLM timeout')); });
    req.write(payload);
    req.end();
  });
}

async function callGroqLLM(messages, maxTokens = 1500) {
  // ── Try NVIDIA first ──
  if (NVIDIA_API_KEY) {
    try {
      console.log('[LLM] Trying NVIDIA NIM...');
      const result = await callLLMDirect(
        'integrate.api.nvidia.com',
        '/v1/chat/completions',
        NVIDIA_API_KEY,
        NVIDIA_MODEL,
        messages,
        4096
      );
      console.log('[LLM] ✓ NVIDIA NIM responded');
      return result;
    } catch (e) {
      console.warn(`[LLM] NVIDIA failed: ${e.message} — falling back to Groq`);
    }
  }
  // ── Fallback to Groq ──
  console.log('[LLM] Trying Groq fallback...');
  return callLLMDirect(
    'api.groq.com',
    '/openai/v1/chat/completions',
    GROQ_API_KEY,
    GROQ_MODEL,
    messages,
    maxTokens
  );
}

// ── Groq LLM STREAMING ────────────────────────────────────────────
function callGroqLLMStream(messages, res, useNvidia = true) {
  return new Promise((resolve, reject) => {

    const hostname = (useNvidia && NVIDIA_API_KEY)
      ? 'integrate.api.nvidia.com'
      : 'api.groq.com';
    const path = (useNvidia && NVIDIA_API_KEY)
      ? '/v1/chat/completions'
      : '/openai/v1/chat/completions';
    const apiKey = (useNvidia && NVIDIA_API_KEY)
      ? NVIDIA_API_KEY
      : GROQ_API_KEY;
    const model = (useNvidia && NVIDIA_API_KEY)
      ? NVIDIA_MODEL
      : GROQ_MODEL;

    console.log(`[LLM Stream] Using ${useNvidia && NVIDIA_API_KEY ? 'NVIDIA NIM' : 'Groq'}`);

    const payload = JSON.stringify({
      model,
      messages,
      max_tokens: (useNvidia && NVIDIA_API_KEY) ? 4096 : 1500,
      temperature: 0.7,
      stream: true,
    });

    const options = {
      hostname,
      path,
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
      },
      timeout: 60000,
    };

    const req = https.request(options, (groqRes) => {
      let buffer = '';

      groqRes.on('data', (chunk) => {
        const raw = chunk.toString();
        if (buffer.length === 0) console.log('[NVIDIA Debug] First chunk:', raw.slice(0, 300));
        buffer += raw;
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
            if (token !== undefined && token !== null && token !== '') {
              res.write(`data: ${JSON.stringify({ token })}\n\n`);
            }
            // NVIDIA sometimes sends usage stats at end — ignore non-content chunks
          } catch (_) { }
        }
      });

      groqRes.on('end', () => {
        res.write('data: [DONE]\n\n');
        resolve();
      });

      groqRes.on('error', reject);
    });

    req.on('error', (e) => {
      if (useNvidia && NVIDIA_API_KEY) {
        console.warn(`[LLM Stream] NVIDIA failed: ${e.message} — falling back to Groq`);
        callGroqLLMStream(messages, res, false).then(resolve).catch(reject);
      } else {
        reject(e);
      }
    });
    req.on('timeout', () => {
      req.destroy();
      if (useNvidia && NVIDIA_API_KEY) {
        console.warn('[LLM Stream] NVIDIA timeout — falling back to Groq');
        callGroqLLMStream(messages, res, false).then(resolve).catch(reject);
      } else {
        reject(new Error('LLM stream timeout'));
      }
    });
    req.write(payload);
    req.end();
  });
}
async function fetchWsColFields(pcapPath) {
  // Step 1: ask tshark which _ws.col.* fields it supports — fully dynamic
  const wsColFields = await new Promise((resolve) => {
    const { spawn } = require('child_process');
    const proc = spawn(TSHARK_BIN, ['-G', 'fields']);
    let out = '';
    proc.stdout.on('data', d => out += d.toString());
    proc.stderr.resume();
    proc.on('close', () => {
      const fields = out.split('\n')
        .filter(l => l.startsWith('F\t'))
        .map(l => l.split('\t')[2]?.trim())
        .filter(f => f && (f.startsWith('_ws.col.') || f.startsWith('frame.coloring_rule.')));
      console.log(`[WsCol] tshark supports ${fields.length} _ws.col.* fields: ${fields.join(', ')}`);
      resolve(fields);
    });
    proc.on('error', () => resolve([]));
    setTimeout(() => { try { proc.kill(); } catch (_) { } resolve([]); }, 20000);
  });

  if (!wsColFields.length) return new Map();

  // Step 2: fetch all of them for every packet
  const activeFields = ['frame.number', ...wsColFields];

  return new Promise((resolve) => {
    const { spawn } = require('child_process');
    const proc = spawn(TSHARK_BIN, [
      '-r', pcapPath,
      '-T', 'fields',
      '-E', 'separator=|',
      '-E', 'occurrence=f',
      '-E', 'header=n',
      ...activeFields.flatMap(f => ['-e', f]),
    ]);

    let out = '';
    proc.stdout.on('data', d => out += d.toString());
    proc.stderr.resume();
    proc.on('error', () => resolve(new Map()));
    proc.on('close', () => {
      const map = new Map();
      for (const line of out.split('\n')) {
        if (!line.trim()) continue;
        const cols = line.split('|');
        const n = parseInt(cols[0]);
        if (isNaN(n)) continue;
        // Build a plain object: { '_ws.col.Info': '...', '_ws.col.Protocol': '...', ... }
        const entry = {};
        wsColFields.forEach((field, idx) => {
          entry[field] = cols[idx + 1] || '';
        });
        map.set(n, entry);
      }
      console.log(`[WsCol] Fetched ${wsColFields.length} _ws.col fields for ${map.size} packets`);
      resolve(map);
    });
    setTimeout(() => { try { proc.kill(); } catch (_) { } resolve(new Map()); }, 120000);
  });
}

async function fetchRawTimestamps(pcapPath) {
  return new Promise((resolve) => {
    const { spawn } = require('child_process');
    const proc = spawn(TSHARK_BIN, [
      '-r', pcapPath,
      '-T', 'fields',
      '-e', 'frame.number',
      '-e', 'frame.time_epoch',
      '-E', 'separator=|',
      '-E', 'header=n',
    ]);
    let out = '';
    proc.stdout.on('data', d => out += d.toString());
    proc.stderr.resume();
    proc.on('close', () => {
      const map = new Map();
      for (const line of out.split('\n')) {
        const [num, ts] = line.trim().split('|');
        if (num && ts) map.set(parseInt(num), ts.trim());
      }
      console.log(`[RawTimestamps] Extracted ${map.size} timestamps`);
      resolve(map);
    });
    proc.on('error', () => resolve(new Map()));
    setTimeout(() => { try { proc.kill(); } catch (_) { } resolve(new Map()); }, 120000);
  });
}

// Step 3: run extraction + bucket by protocol prefix dynamically
async function runTShark(pcapPath) {
  await TSHARK_CAPS_READY;
  const caps = TSHARK_CAPS;

  // Run _ws.col fields pass in parallel with the JSON pass
  const wsColPromise = fetchWsColFields(pcapPath);
  const ethResolvedPromise = fetchEthResolvedFields(pcapPath);
  const rawTimestampsPromise = fetchRawTimestamps(pcapPath);


  return new Promise((resolve, reject) => {
    const { spawn } = require('child_process');
    const args = [
      '-r', pcapPath,
      '-2',                    // ← ADD THIS — enables two-pass analysis
      '-T', 'json',
      '--no-duplicate-keys',
      '-N', 'mndN',
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
      const nullCount = rawPackets.filter(p => p == null || p._source == null).length;
      if (nullCount > 0) console.warn(`[TShark] Filtered ${nullCount} null/malformed entries from JSON output`);

      // tshark on Windows sometimes emits null entries in the JSON array
      rawPackets = rawPackets.filter(p => p != null && p._source != null && p._source.layers != null);
      if (rawPackets.length === 0) return resolve({ packets: [] });

      const SKIP_PROTOS = new Set();

      const buckets = {};
      const packets = [];

      for (let __i = 0; __i < rawPackets.length; __i++) {
        const rawPkt = rawPackets[__i];
        if (!rawPkt || !rawPkt._source) {
          console.warn(`[TShark] Null packet at index ${__i}, skipping`);
          continue;
        }
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
          console.log('[TShark DEBUG] ALL layer keys:', Object.keys(layers).join(', '));
          console.log('[TShark DEBUG] Full first packet:', JSON.stringify(rawPackets[0]).slice(0, 1000)); console.log('[TShark DEBUG] frame.time_epoch raw:', gv('frame.time_epoch'));  // 👈 add this
          console.log('[TShark DEBUG] udp fields:', JSON.stringify(Object.fromEntries(Object.entries(layers).filter(([k]) => k.startsWith('udp')))));
          console.log('[TShark DEBUG] tcp fields:', JSON.stringify(Object.fromEntries(Object.entries(layers).filter(([k]) => k.startsWith('tcp')))));
          console.log('[TShark DEBUG] _ws raw value:', JSON.stringify(layers['_ws'] ?? null).slice(0, 300));
          console.log('[TShark DEBUG] _ws.col.Info flat:', layers['_ws.col.Info']);
          console.log('[TShark DEBUG] _ws.col.Protocol flat:', layers['_ws.col.Protocol']);
          console.log('[TShark DEBUG] _ws.col.color_filter_name flat:', layers['_ws.col.color_filter_name']);
        }


        const pkt = {
          frame_number: parseInt(gv('frame.number')) || 0,
          timestamp: (() => {
            const raw = gv('frame.time_epoch') || gv('frame.time_relative') || '';
            if (!raw) return null;
            if (/[a-zA-Z\-T:]/.test(raw)) {
              const asDate = new Date(raw);
              return isNaN(asDate.getTime()) ? null : asDate.getTime() / 1000;
            }
            // Store as STRING to preserve microsecond precision — never parseFloat a Unix timestamp
            return raw.trim() || null;
          })(),
          length: parseInt(gv('frame.len')) || 0,

          // Dynamically pick src/dst based on what layers actually exist in THIS packet
          src_ip: (() => {
            // Pass 1: IP-layer resolved hostname (most specific)
            const ipSrcHost = gv('ip.src_host') || gv('ipv6.src_host');
            if (ipSrcHost) return ipSrcHost;
            // Pass 2: eth resolved name (handles ARP Intel_f8:1c:c8, etc.)
            const ethSrcResolved = gv('eth.src_resolved');
            if (ethSrcResolved) return ethSrcResolved;
            // Pass 3: any other layer's src_host or src_resolved
            for (const key of Object.keys(layers)) {
              if (key === 'eth' || key === 'ip' || key === 'ipv6') continue;
              const val = gv(`${key}.src_host`) || gv(`${key}.src_resolved`);
              if (val) return val;
            }
            // Pass 4: raw IP from any non-eth layer
            for (const key of Object.keys(layers)) {
              if (key === 'eth') continue;
              const val = gv(`${key}.src`);
              if (val) return val;
            }
            // Pass 5: last resort — eth raw MAC
            return gv('eth.src') || null;
          })(),
          dst_ip: (() => {
            // Pass 1: IP-layer resolved hostname (most specific)
            const ipDstHost = gv('ip.dst_host') || gv('ipv6.dst_host');
            if (ipDstHost) return ipDstHost;
            // Pass 2: eth resolved name (handles ARP Broadcast, Intel_f8:1c:c8, etc.)
            const ethDstResolved = gv('eth.dst_resolved');
            if (ethDstResolved) return ethDstResolved;
            // Pass 3: any other layer's dst_host or dst_resolved
            for (const key of Object.keys(layers)) {
              if (key === 'eth' || key === 'ip' || key === 'ipv6') continue;
              const val = gv(`${key}.dst_host`) || gv(`${key}.dst_resolved`);
              if (val) return val;
            }
            // Pass 4: raw IP from any non-eth layer
            for (const key of Object.keys(layers)) {
              if (key === 'eth') continue;
              const val = gv(`${key}.dst`);
              if (val) return val;
            }
            // Pass 5: last resort — eth raw MAC
            return gv('eth.dst') || null;
          })(),

          ip_proto: gv('ip.proto'),
          src_port: parseInt(gv('tcp.srcport')) || parseInt(gv('tcp.src_port')) || parseInt(gv('udp.srcport')) || parseInt(gv('udp.src_port')) || 0,
          dst_port: parseInt(gv('tcp.dstport')) || parseInt(gv('tcp.dst_port')) || parseInt(gv('udp.dstport')) || parseInt(gv('udp.dst_port')) || 0,
          src_hostname: gv('ip.src_host') || gv('ipv6.src_host') || null,
          dst_hostname: gv('ip.dst_host') || gv('ipv6.dst_host') || null,
          tcp_flags: gv('tcp.flags'),
          tcp_stream: (() => {
            // tshark is authoritative — use its stream index directly
            const raw = gv('tcp.stream');
            if (raw === '' || raw === undefined) return null;
            const parsed = parseInt(raw);
            return isNaN(parsed) ? null : parsed;
          })(),
          udp_stream: (() => {
            const raw = gv('udp.stream');
            if (raw === '' || raw === undefined) return null;
            const parsed = parseInt(raw);
            return isNaN(parsed) ? null : parsed;
          })(),
          protocol: (() => {
            // --no-duplicate-keys always puts _ws fields FLAT on layers directly
            // e.g. layers['_ws.col.Protocol'], never nested inside layers['_ws']
            const flat = layers['_ws.col.Protocol'];
            if (flat) return typeof flat === 'string' ? flat.trim() : (Array.isArray(flat) ? flat[0] : '');
            // nestedJson (3.6+): tshark may nest under layers['_ws']['_ws.col.Protocol']
            const ws = layers['_ws'];
            if (ws && typeof ws === 'object') {
              const nested = ws['_ws.col.Protocol'] || ws['_ws_col_Protocol'] || ws['col.Protocol'];
              if (nested) return String(nested).trim();
              // last-resort scan
              const found = Object.entries(ws).find(([k]) => k.toLowerCase().includes('col.protocol'));
              if (found) return String(found[1]).trim();
            }
            // Protocol will be overwritten by fetchWsColFields merge — return empty string as placeholder
            return '';
          })(),
          info: (() => {
            const flat = layers['_ws.col.Info'];
            if (flat) return typeof flat === 'string' ? flat : (Array.isArray(flat) ? flat[0] : '');
            const ws = layers['_ws'];
            if (!ws || typeof ws !== 'object') return '';
            const nested = ws['_ws.col.Info'] || ws['_ws_col_Info'] || ws['col.Info'];
            if (nested) return String(nested);
            const found = Object.entries(ws).find(([k]) => k.toLowerCase().includes('col.info'));
            return found ? String(found[1]) : '';
          })(),
          color_filter_name: (() => {
            // Linux: _ws.col.color_filter_name (flat)
            if (layers['_ws.col.color_filter_name']) return String(layers['_ws.col.color_filter_name']);
            // Windows: frame.coloring_rule.name (nested under frame layer)
            const frame = layers['frame'];
            if (frame && typeof frame === 'object') {
              const win = frame['frame.coloring_rule.name'];
              if (win) return String(win);
            }
            // flat Windows fallback
            if (layers['frame.coloring_rule.name']) return String(layers['frame.coloring_rule.name']);
            // _ws nested fallback
            const ws = layers['_ws'];
            if (ws && typeof ws === 'object') {
              const found = Object.entries(ws).find(([k]) => k.toLowerCase().includes('color'));
              if (found) return String(found[1]);
            }
            return '';
          })(),
          color_filter_string: (() => {
            if (layers['_ws.col.color_filter_string']) return String(layers['_ws.col.color_filter_string']);
            const frame = layers['frame'];
            if (frame && typeof frame === 'object') {
              const win = frame['frame.coloring_rule.string'];
              if (win) return String(win);
            }
            if (layers['frame.coloring_rule.string']) return String(layers['frame.coloring_rule.string']);
            return '';
          })(),
        };
        if (!pkt.protocol && packets.length < 5) {
          console.log('[Protocol Debug] empty proto pkt:', JSON.stringify({
            keys: Object.keys(layers),
            ws: layers['_ws'],
          }));
        }
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
            tcp_stream: pkt.tcp_stream,
            frame_number: pkt.frame_number,
          };

          const protoLayer = layers[proto];
          if (protoLayer && typeof protoLayer === 'object' && !Array.isArray(protoLayer)) {
            for (const [k, v] of Object.entries(protoLayer)) {
              if (!k || typeof k !== 'string') continue;

              if (k.startsWith(proto + '.')) {
                // Normal flat field: urlencoded-form.key, http.user_agent, etc.
                const key = k.slice(proto.length + 1).replace(/\./g, '_');
                if (v === null || v === undefined) {
                  entry[key] = '';
                } else if (Array.isArray(v)) {
                  entry[key] = v[0] ?? '';
                } else if (typeof v === 'object') {
                  entry[key] = '';
                } else {
                  entry[key] = String(v);
                }
              } else if (typeof v === 'object' && v !== null && !Array.isArray(v)) {
                // Nested group like "Form item: \"username\" = \"admin\"": { "urlencoded-form.key": "username", "urlencoded-form.value": "admin" }
                // Flatten: pull out all proto-prefixed children into the entry
                for (const [ck, cv] of Object.entries(v)) {
                  if (!ck.startsWith(proto + '.')) continue;
                  const key = ck.slice(proto.length + 1).replace(/\./g, '_');
                  const existing = entry[key];
                  const val = (cv === null || cv === undefined) ? '' : Array.isArray(cv) ? (cv[0] ?? '') : typeof cv === 'object' ? '' : String(cv);
                  // Collect multiple values as array (e.g. multiple form params all become key/value)
                  if (existing === undefined) {
                    entry[key] = val;
                  } else if (Array.isArray(existing)) {
                    existing.push(val);
                  } else {
                    entry[key] = [existing, val];
                  }
                }
              }
            }
          }

          if (!buckets[proto]) buckets[proto] = [];
          buckets[proto].push(entry);
        }
      }

      console.log(`[TShark] Extracted packets: ${packets.length}, protocol buckets: ${Object.keys(buckets).join(', ')}`);

      // Merge _ws.col.* fields from the parallel fields pass
      Promise.all([wsColPromise, ethResolvedPromise, rawTimestampsPromise]).then(([wsColMap, ethResolvedMap, rawTimestampMap]) => {
        for (const pkt of packets) {
          const col = wsColMap.get(pkt.frame_number);
          if (col) {
            if (!pkt.info) pkt.info = col['_ws.col.Info'] || col['_ws.col.info'] || '';
            const wsProto = col['_ws.col.Protocol'] || col['_ws.col.protocol'] || '';
            if (wsProto) pkt.protocol = wsProto; const colorNameKey = Object.keys(col).find(k => k.includes('coloring_rule.name') || k.includes('color_filter_name'));
            const colorStringKey = Object.keys(col).find(k => k.includes('coloring_rule.string') || k.includes('color_filter_string'));
            pkt.color_filter_name = (colorNameKey ? col[colorNameKey] : '') || pkt.color_filter_name || '';
            pkt.color_filter_string = (colorStringKey ? col[colorStringKey] : '') || pkt.color_filter_string || '';
          }
          const eth = ethResolvedMap.get(pkt.frame_number);
          if (eth) {
            if (!pkt.src_ip && eth.src_resolved) pkt.src_ip = eth.src_resolved;
            if (!pkt.dst_ip && eth.dst_resolved) pkt.dst_ip = eth.dst_resolved;
            if (eth.src_resolved && /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(pkt.src_ip || '')) pkt.src_ip = eth.src_resolved;
            if (eth.dst_resolved && /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(pkt.dst_ip || '')) pkt.dst_ip = eth.dst_resolved;
          }
          // Overwrite timestamp with raw string from tshark -T fields — bypasses JSON float coercion entirely
          const rawTs = rawTimestampMap.get(pkt.frame_number);
          if (rawTs) pkt.timestamp = rawTs;
        }
        console.log(`[WsCol] Merged. Sample → info: "${packets[0]?.info}", proto: "${packets[0]?.protocol}"`);
        console.log(`[RawTimestamps] Sample → frame 1 timestamp: "${rawTimestampMap.get(1)}"`);
        console.log(`[EthResolved] Merged. Sample ARP → src: "${packets.find(p => p.protocol === 'ARP')?.src_ip}", dst: "${packets.find(p => p.protocol === 'ARP')?.dst_ip}"`);
        resolve({ packets, ...buckets });
      }).catch(() => {
        resolve({ packets, ...buckets });
      });
    });
  });
}

// ═══════════════════════════════════════════════════════════════════
// TCP STREAM REASSEMBLY — 100% tshark-authoritative
// Phase 1: metadata index from JSON (fast, used by analyzePCAP)
// Phase 2: payload reconstruction via tshark -z follow,tcp,raw,N
//          (on-demand per stream, Wireshark-grade)
// ═══════════════════════════════════════════════════════════════════
function reassembleTCPStreams(packets) {
  const streams = new Map();
  const result = new Map();

  for (const pkt of packets) {
    const rawStream = pkt.tcp_stream;
    if (rawStream === undefined || rawStream === null || rawStream === '') continue;

    const streamIdx = Number(rawStream);
    if (!Number.isFinite(streamIdx)) continue;

    let stream = streams.get(streamIdx);

    if (!stream) {
      stream = {
        tcp_stream: streamIdx,
        client_ip: null,
        server_ip: null,
        client_port: null,
        server_port: null,
        protocol: pkt.protocol || 'TCP',
        rawPackets: [],
        total_bytes: 0,
        first_seen: Infinity,
        last_seen: -Infinity,
        syn_seen: false,
        flags: { rst: false, fin: false, zero_window: false },
        anomalies: [],
        anomalyKeys: new Set()
      };

      streams.set(streamIdx, stream);
    }

    stream.rawPackets.push(pkt);
    stream.total_bytes += Number(pkt.length || 0);

    const ts = Number(pkt.timestamp);
    if (Number.isFinite(ts)) {
      stream.first_seen = Math.min(stream.first_seen, ts);
      stream.last_seen = Math.max(stream.last_seen, ts);
    }
  }

  for (const [streamIdx, stream] of streams) {

    // ═══════════════════════════════════════
    // 1. SORT (Wireshark frame order)
    // ═══════════════════════════════════════
    const sortedPackets = stream.rawPackets.sort(
      (a, b) => (a.frame_number || 0) - (b.frame_number || 0)
    );

    // ═══════════════════════════════════════
    // 2. SYN-BASED CLIENT/SERVER DETECTION
    // ═══════════════════════════════════════
    let synPkt = null;

    for (const p of sortedPackets) {
      if (!p.tcp_flags) continue;
      const flags = Number.parseInt(p.tcp_flags, 16);

      // SYN without ACK = connection initiator
      if ((flags & 0x02) && !(flags & 0x10)) {
        synPkt = p;
        break;
      }
    }

    let clientIp, clientPort, serverIp, serverPort;

    if (synPkt) {
      clientIp = synPkt.src_ip;
      clientPort = synPkt.src_port;
      serverIp = synPkt.dst_ip;
      serverPort = synPkt.dst_port;
      stream.syn_seen = true;
    } else {
      const first = sortedPackets[0];
      clientIp = first?.src_ip;
      clientPort = first?.src_port;
      serverIp = first?.dst_ip;
      serverPort = first?.dst_port;
    }

    // store resolved endpoints (important for later phases)
    stream.client_ip = clientIp;
    stream.client_port = clientPort;
    stream.server_ip = serverIp;
    stream.server_port = serverPort;

    // ═══════════════════════════════════════
    // 3. BUILD CONVERSATION (Wireshark-like view)
    // ═══════════════════════════════════════
    const conversation = [];

    for (const pkt of sortedPackets) {

      const isClient =
        pkt.src_ip === clientIp &&
        pkt.src_port === clientPort;

      const seq = pkt.tcp_seq != null ? Number(pkt.tcp_seq) : null;
      const ack = pkt.tcp_ack != null ? Number(pkt.tcp_ack) : null;

      const payload =
        pkt.tcp_payload ||
        pkt.payload ||
        '';

      const segLen =
        pkt.tcp_len != null
          ? Number(pkt.tcp_len)
          : pkt.tcp_segment_len != null
            ? Number(pkt.tcp_segment_len)
            : payload.length || 0;


      // ===============================
      // ACK sanity check (lightweight)
      // ===============================
      if (ack != null && seq != null) {
        if (ack < seq) {
          stream.anomalies = stream.anomalies || [];
          stream.anomalies.push({
            type: 'INVALID_ACK',
            ack,
            seq,
            frame: pkt.frame_number
          });
        }
      }


      conversation.push({
        direction: isClient ? 'client → server' : 'server → client',

        src_ip: pkt.src_ip,
        dst_ip: pkt.dst_ip,
        src_port: pkt.src_port,
        dst_port: pkt.dst_port,

        frame_number: pkt.frame_number,
        timestamp: pkt.timestamp,
        length: pkt.length,

        protocol: pkt.protocol || 'TCP',
        info: pkt.info || '',
        tcp_flags: pkt.tcp_flags || null,

        tcp_seq: seq,
        tcp_ack: ack,
        tcp_len: segLen,
        tcp_next_seq: seq != null ? seq + segLen : null,

        tcp_retransmission:
          !!pkt.tcp_analysis_retransmission || !!pkt.tcp_retransmission,

        tcp_out_of_order:
          !!pkt.tcp_analysis_out_of_order || !!pkt.tcp_out_of_order,

        tcp_lost_segment: !!pkt.tcp_analysis_lost_segment,
        tcp_duplicate_ack: !!pkt.tcp_analysis_duplicate_ack,
        tcp_fast_retransmission: !!pkt.tcp_analysis_fast_retransmission,
      });
    }

    // ═══════════════════════════════════════
    // 4. STREAM HEALTH ANALYSIS
    // ═══════════════════════════════════════
    const outOfOrderCount = conversation.filter(p => p.tcp_out_of_order).length;
    const reorderRatio = conversation.length
      ? outOfOrderCount / conversation.length
      : 0;

    const hasClient = conversation.some(p => p.direction === 'client → server');
    const hasServer = conversation.some(p => p.direction === 'server → client');

    const anomalies = [];

    if (!stream.syn_seen) {
      anomalies.push({ type: 'NO_SYN' });
    }

    if (conversation.some(p => p.tcp_retransmission)) {
      anomalies.push({ type: 'RETRANSMISSION' });
    }

    if (conversation.some(p => p.tcp_out_of_order)) {
      anomalies.push({ type: 'OUT_OF_ORDER' });
    }

    if (conversation.some(p => p.tcp_lost_segment)) {
      anomalies.push({ type: 'LOST_SEGMENT' });
    }

    if (reorderRatio > 0.1) {
      anomalies.push({
        type: 'PACKET_REORDER',
        reorder_ratio: reorderRatio.toFixed(3),
      });
    }

    if (!(hasClient && hasServer)) {
      anomalies.push({
        type: 'UNIDIRECTIONAL',
        direction: hasClient ? 'client→server only' : 'server→client only',
      });
    }

    const stream_health =
      anomalies.length === 0 ? 'complete' : 'analysis_flags_present';

    // ═══════════════════════════════════════
    // 5. FINAL STREAM OBJECT
    // ═══════════════════════════════════════
    result.set(streamIdx, {
      tcp_stream: streamIdx,

      client: {
        ip: clientIp,
        port: clientPort,
      },

      server: {
        ip: serverIp,
        port: serverPort,
      },

      protocol: stream.protocol,

      conversation,

      payload: null,
      total_bytes: stream.total_bytes,
      packet_count: conversation.length,

      first_seen:
        stream.first_seen === Infinity ? null : stream.first_seen,

      last_seen:
        stream.last_seen === -Infinity ? null : stream.last_seen,

      duration_seconds:
        stream.first_seen !== Infinity && stream.last_seen !== -Infinity
          ? (stream.last_seen - stream.first_seen).toFixed(3)
          : null,

      stream_health,
      anomalies,
      credentials: [],
    });

    console.log(
      `[TCPStream L2] Stream ${streamIdx}: ${conversation.length} packets | health=${stream_health}`
    );
  }

  console.log(`[TCPStream] ✓ Conversation reconstruction complete: ${result.size} streams`);
  return result;
}


function reassembleUDPStreams(packets) {
  const streams = new Map();
  const result = new Map();

  for (const pkt of packets) {
    const rawStream = pkt.udp_stream;
    if (rawStream === undefined || rawStream === null || rawStream === '') continue;

    const streamIdx = Number(rawStream);
    if (!Number.isFinite(streamIdx)) continue;

    let stream = streams.get(streamIdx);

    if (!stream) {
      stream = {
        udp_stream: streamIdx,
        client_ip: null,
        server_ip: null,
        client_port: null,
        server_port: null,
        protocol: pkt.protocol || 'UDP',
        rawPackets: [],
        total_bytes: 0,
        first_seen: Infinity,
        last_seen: -Infinity,
      };
      streams.set(streamIdx, stream);
    }

    stream.rawPackets.push(pkt);
    stream.total_bytes += Number(pkt.length || 0);

    const ts = Number(pkt.timestamp);
    if (Number.isFinite(ts)) {
      stream.first_seen = Math.min(stream.first_seen, ts);
      stream.last_seen = Math.max(stream.last_seen, ts);
    }
  }

  for (const [streamIdx, stream] of streams) {

    // Sort by frame number
    const sortedPackets = stream.rawPackets.sort(
      (a, b) => (a.frame_number || 0) - (b.frame_number || 0)
    );

    // Client = first sender
    const first = sortedPackets[0];
    const clientIp = first?.src_ip;
    const clientPort = first?.src_port;
    const serverIp = first?.dst_ip;
    const serverPort = first?.dst_port;

    stream.client_ip = clientIp;
    stream.client_port = clientPort;
    stream.server_ip = serverIp;
    stream.server_port = serverPort;

    // Build conversation
    const conversation = [];

    for (const pkt of sortedPackets) {
      const isClient =
        pkt.src_ip === clientIp &&
        pkt.src_port === clientPort;

      conversation.push({
        direction: isClient ? 'client → server' : 'server → client',
        src_ip: pkt.src_ip,
        dst_ip: pkt.dst_ip,
        src_port: pkt.src_port,
        dst_port: pkt.dst_port,
        frame_number: pkt.frame_number,
        timestamp: pkt.timestamp,
        length: pkt.length,
        protocol: pkt.protocol || 'UDP',
        info: pkt.info || '',
      });
    }

    const hasClient = conversation.some(p => p.direction === 'client → server');
    const hasServer = conversation.some(p => p.direction === 'server → client');

    const anomalies = [];
    if (!(hasClient && hasServer)) {
      anomalies.push({
        type: 'UNIDIRECTIONAL',
        direction: hasClient ? 'client→server only' : 'server→client only',
      });
    }

    result.set(streamIdx, {
      udp_stream: streamIdx,

      client: {
        ip: clientIp,
        port: clientPort,
      },

      server: {
        ip: serverIp,
        port: serverPort,
      },

      protocol: stream.protocol,
      conversation,
      payload: null,
      total_bytes: stream.total_bytes,
      packet_count: conversation.length,

      first_seen: stream.first_seen === Infinity ? null : stream.first_seen,
      last_seen: stream.last_seen === -Infinity ? null : stream.last_seen,

      duration_seconds:
        stream.first_seen !== Infinity && stream.last_seen !== -Infinity
          ? (stream.last_seen - stream.first_seen).toFixed(3)
          : null,

      stream_health: anomalies.length === 0 ? 'complete' : 'analysis_flags_present',
      anomalies,
      credentials: [],
    });

    console.log(
      `[UDPStream] Stream ${streamIdx}: ${conversation.length} packets | protocol=${stream.protocol}`
    );
  }

  console.log(`[UDPStream] ✓ Reconstruction complete: ${result.size} streams`);
  return result;
}


// ── NEW: Bind credential leaks to their tcp_stream conversation ──
// Replaces the old global credential list with stream-scoped binding.
// Call this AFTER detectCredentialLeaks() and reassembleTCPStreams().
function bindCredentialsToStreams(tcpStreams, credentialLeaks, packets) {
  const frameToStream = new Map();

  for (const pkt of packets) {
    if (pkt.tcp_stream != null && pkt.frame_number != null) {
      frameToStream.set(pkt.frame_number, Number(pkt.tcp_stream));
    }
  }

  const endpointToStream = new Map();

  for (const [streamIdx, stream] of tcpStreams) {
    const key = (a, b) => `${a.ip || ''}:${a.port || 0}→${b.ip || ''}:${b.port || 0}`;

    endpointToStream.set(key(stream.client, stream.server), streamIdx);
    endpointToStream.set(key(stream.server, stream.client), streamIdx);
  }

  let bound = 0;

  for (const leak of credentialLeaks) {
    let streamIdx =
      leak.packet_num ? frameToStream.get(leak.packet_num) : null;

    if (streamIdx == null && leak.src_ip && leak.dst_ip) {
      const key = `${leak.src_ip}:${leak.src_port}→${leak.dst_ip}:${leak.dst_port}`;
      streamIdx = endpointToStream.get(key);
    }

    if (streamIdx == null) continue;

    const stream = tcpStreams.get(streamIdx);
    if (!stream) continue;

    stream.credentials ??= [];
    stream.credentials.push(leak);

    bound++;
  }

  console.log(`[Credentials] Bound ${bound}/${credentialLeaks.length} leaks to TCP streams`);

  return tcpStreams;
}

// ── Phase 2: Wireshark-grade payload reconstruction (on-demand) ──
// Calls tshark -z follow,tcp,raw,N which handles:
//   - deduplication of retransmitted segments (tshark does this internally)
//   - out-of-order segment reordering (tshark does this internally)
//   - overlapping segment resolution (tshark does this internally)
//   - direction splitting: Node 0 = client→server, Node 1 = server→client
//     (tshark tab-prefixes server→client chunks in raw output)
// Returns hex strings which caller can decode to ASCII or keep as Buffer.
async function followTcpStream(pcapPath, streamId) {
  return new Promise((resolve) => {
    const { spawn } = require('child_process');

    const args = [
      '-r', pcapPath,
      '-q',
      '-z', `follow,tcp,raw,${streamId}`,
    ];

    let stdout = '';
    let stderr = '';

    const proc = spawn(TSHARK_BIN, args);

    proc.stdout.on('data', d => { stdout += d.toString(); });
    proc.stderr.on('data', d => { stderr += d.toString(); });

    proc.on('error', (err) => {
      console.error(`[TCPFollow] spawn error stream ${streamId}: ${err.message}`);
      resolve(null);
    });

    const killTimer = setTimeout(() => {
      try { proc.kill('SIGKILL'); } catch (_) { }
      console.error(`[TCPFollow] Timeout stream ${streamId}`);
      resolve(null);
    }, 30000);

    proc.on('close', (code) => {
      clearTimeout(killTimer);

      if (code !== 0 && !stdout) {
        console.error(`[TCPFollow] tshark exited ${code} for stream ${streamId}: ${stderr.slice(0, 200)}`);
        return resolve(null);
      }

      const lines = stdout.split('\n');

      let node0 = '';
      let node1 = '';
      let clientHex = '';
      let serverHex = '';

      let inBody = false;

      for (const line of lines) {
        const raw = line.replace(/\r$/, '');

        if (raw.startsWith('===')) {
          inBody = !inBody;
          continue;
        }

        if (!inBody) continue;

        if (raw.startsWith('Node 0:')) {
          node0 = raw.slice(7).trim();
          continue;
        }

        if (raw.startsWith('Node 1:')) {
          node1 = raw.slice(7).trim();
          continue;
        }

        if (!raw.trim()) continue;

        // Wireshark follow format: server lines are tab-indented
        if (raw.startsWith('\t')) {
          serverHex += raw.trim();
        } else {
          clientHex += raw.trim();
        }
      }

      const toBufferOrText = (hex) => {
        if (!hex) return { text: '', bytes: 0, is_binary: false };

        let buf;
        try {
          buf = Buffer.from(hex, 'hex');
        } catch (_) {
          return { text: hex, bytes: 0, is_binary: false };
        }

        let nonPrint = 0;
        for (let i = 0; i < buf.length; i++) {
          const b = buf[i];
          if (b < 0x09 || (b > 0x0d && b < 0x20) || b === 0x7f) nonPrint++;
        }

        const isBinary = buf.length > 0 && (nonPrint / buf.length) > 0.20;

        return {
          text: isBinary
            ? `[Binary data — ${buf.length} bytes]`
            : buf.toString('utf8').replace(/\r\n/g, '\n'),
          hex: isBinary ? hex : undefined,
          bytes: buf.length,
          is_binary: isBinary,
        };
      };

      const c2s = toBufferOrText(clientHex);
      const s2c = toBufferOrText(serverHex);

      const parseEndpoint = (nodeStr) => {
        const lastColon = nodeStr.lastIndexOf(':');
        if (lastColon === -1) return { ip: nodeStr, port: 0 };
        return {
          ip: nodeStr.slice(0, lastColon).replace(/^\[|\]$/g, ''),
          port: parseInt(nodeStr.slice(lastColon + 1)) || 0,
        };
      };

      const client = parseEndpoint(node0);
      const server = parseEndpoint(node1);

      const result = {
        stream_id: streamId,
        client,
        server,
        client_to_server: {
          text: c2s.text,
          bytes: c2s.bytes,
          is_binary: c2s.is_binary,
          hex: c2s.hex,
        },
        server_to_client: {
          text: s2c.text,
          bytes: s2c.bytes,
          is_binary: s2c.is_binary,
          hex: s2c.hex,
        },
        total_bytes: c2s.bytes + s2c.bytes,
      };

      console.log(
        `[TCPFollow] Stream ${streamId}: client ${node0} | c→s ${c2s.bytes}B | s→c ${s2c.bytes}B | binary=${c2s.is_binary || s2c.is_binary}`
      );

      resolve(result);
    });
  });
}
// ═══════════════════════════════════════════════════════════════════
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
      const contentParts = [];

      for (const [k, v] of Object.entries(r)) {
        if (
          ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'timestamp'].includes(k) ||
          v === null ||
          v === undefined
        ) {
          continue;
        }

        if (typeof v === 'string') {
          const s = v.trim();
          if (s) contentParts.push(s);
        } else if (Array.isArray(v)) {
          for (const item of v) {
            if (item === null || item === undefined) continue;
            const s = String(item).trim();
            if (s) contentParts.push(s);
          }
        } else if (typeof v === 'number' || typeof v === 'boolean') {
          contentParts.push(String(v));
        }
      }

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
  { keywords: ['threat', 'attack', 'malicious', 'scan', 'exploit', 'intrusion', 'detect', 'alert', 'suspicious', 'credential', 'password', 'leaked', 'leak', 'token', 'api key', 'jwt', 'bearer', 'auth', 'secret', 'plaintext', 'exposed'], file: 'threats' },
  { keywords: ['port', 'service', 'cve', 'vulnerability', 'risk', 'exposure', 'ports being used', 'port safe', 'which ports', 'port number'], file: 'ports' },
  { keywords: ['specific packet', 'raw packet', 'frame number', 'packet number', 'find packet'], file: 'packets' },
  { keywords: ['summary', 'overview', 'total', 'stats', 'count', 'how many', 'statistics'], file: 'summary' },
  { keywords: ['website', 'websites', 'visited', 'browsed', 'web traffic', 'domain visited', 'pages visited'], file: 'http' },
  { keywords: ['top talker', 'most traffic', 'bandwidth', 'heaviest', 'most data', 'biggest transfer', 'who sent'], file: 'packets' },
  { keywords: ['dns query', 'dns queries', 'resolved', 'domains resolved', 'lookups', 'name resolution'], file: 'dns' },
  { keywords: ['expert', 'malformed', 'retransmission', 'reset', 'network health', 'packet loss', 'tcp warning', 'tcp error'], file: 'threats' },
  { keywords: ['stream', 'conversation', 'tcp stream', 'udp stream', 'session count', 'how many connections'], file: 'tcp-streams' },
  { keywords: ['file transfer', 'transferred', 'downloaded', 'uploaded', 'smb file', 'ftp file', 'what files'], file: 'smb' },
  { keywords: ['geolocation', 'country', 'origin', 'where is', 'location of ip', 'which country'], file: 'threats' },
  { keywords: ['risk score', 'overall risk', 'how risky', 'security score', 'risk level'], file: 'ports' },
  { keywords: ['attack timeline', 'when did', 'chronological', 'sequence of events', 'order of attacks'], file: 'threats' },
  { keywords: ['unencrypted', 'insecure protocol', 'cleartext', 'plaintext protocol', 'no encryption'], file: 'ports' },
  { keywords: ['recommendation', 'what should i do', 'how to fix', 'remediation', 'action', 'suggest'], file: 'threats' },
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
  if (portIndex && typeof portIndex.search === 'function') {
    try {
      const portResults = portIndex.search(message, {
        fuzzy: 0.25,
        prefix: true,
        boost: {
          service_name: 3,
          tags: 2,
          description: 1
        }
      }); if (portResults.length > 0) {
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
  if (contentIndex && typeof contentIndex.search === 'function') {
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
// PROTOCOL STREAM PARSERS
// Each parser receives the raw reassembled Buffer from
// tshark -z follow,tcp,raw,N  (or udp for TFTP)
// and returns array of extracted objects.
// This is exactly what Wireshark does internally:
//   follow stream → parse protocol → extract object bytes
// ═══════════════════════════════════════════════════════════════════

// ── HTTP / HTTP2 ──────────────────────────────────────────────────
// Parse a raw reassembled TCP stream for HTTP responses.


// ── SMB / SMB2 ────────────────────────────────────────────────────
// SMB file transfers happen on named pipe or file share streams.
// tshark --export-objects smb already handles the dissection correctly,
// but we still need to correlate the stream for metadata.
// For SMB we use --export-objects output + stream metadata only
// (SMB binary parsing is extremely complex — Wireshark itself uses
// its full SMB dissector for this, not raw stream parsing).
// So: use exported file bytes + enrich with stream metadata.


// ── FTP-DATA ──────────────────────────────────────────────────────
// FTP data channel is a raw byte stream — no headers.
// The filename comes from the RETR/STOR command on the control stream.
// We just take the entire s2c (RETR) or c2s (STOR) buffer as the file.
function parseFtpDataFromStream(c2s, s2c, controlMeta) {
  // RETR = server→client (s2c), STOR = client→server (c2s)
  const isRetr = (controlMeta?.ftp_command || 'RETR') === 'RETR';
  const body = isRetr ? s2c : c2s;
  if (!body || body.length === 0) return null;

  const filename = path.basename(controlMeta?.ftp_filename || 'ftp_file');
  return {
    body,
    filename,
    content_type: getMimeFromFilename(filename),
    content_length: body.length,
    ftp_command: controlMeta?.ftp_command || 'RETR',
    ftp_filename: controlMeta?.ftp_filename || '',
  };
}

// ── TFTP ──────────────────────────────────────────────────────────
// TFTP uses UDP. Each DATA packet has a 4-byte header (opcode + block#).
// We strip headers and concatenate data blocks from the raw follow output.
function parseTftpFromStream(c2s, s2c, meta) {
  // TFTP DATA packets are in s2c (server→client for RRQ)
  // opcode 0x0003 = DATA, bytes 2-3 = block number, rest = data
  const buf = s2c && s2c.length > 0 ? s2c : c2s;
  if (!buf || buf.length === 0) return null;

  const chunks = [];
  let pos = 0;
  while (pos + 4 <= buf.length) {
    const opcode = buf.readUInt16BE(pos);
    if (opcode !== 3) { pos += 2; continue; } // not DATA
    // skip opcode (2) + block# (2) = 4 bytes header
    const dataStart = pos + 4;
    const dataEnd = Math.min(pos + 4 + 512, buf.length); // TFTP blocks ≤ 512 bytes
    chunks.push(buf.slice(dataStart, dataEnd));
    pos = dataEnd;
  }

  // If no valid TFTP DATA frames found, treat entire buffer as raw file
  const body = chunks.length > 0 ? Buffer.concat(chunks) : buf;
  const filename = path.basename(meta?.tftp_filename || 'tftp_file');

  return {
    body,
    filename,
    content_type: getMimeFromFilename(filename),
    content_length: body.length,
    tftp_filename: meta?.tftp_filename || '',
  };
}
// ── Follow UDP stream (for TFTP) ──────────────────────────────────
async function followUdpStream(pcapPath, streamId) {
  return new Promise((resolve) => {
    const { spawn } = require('child_process');
    const args = ['-r', pcapPath, '-q', '-z', `follow,udp,raw,${streamId}`];
    let stdout = '';
    const proc = spawn(TSHARK_BIN, args);
    proc.stdout.on('data', d => { stdout += d.toString(); });
    proc.stderr.resume();
    proc.on('error', () => resolve(null));
    const killTimer = setTimeout(() => { try { proc.kill(); } catch (_) { } resolve(null); }, 30000);
    proc.on('close', () => {
      clearTimeout(killTimer);
      // Same parsing as followTcpStream
      const lines = stdout.split('\n');
      let clientHex = '', serverHex = '';
      let inBody = false;
      for (const line of lines) {
        const raw = line.replace(/\r$/, '');
        if (raw.startsWith('===')) { inBody = !inBody; continue; }
        if (!inBody || !raw.trim()) continue;
        if (raw.startsWith('Node 0:') || raw.startsWith('Node 1:')) continue;
        if (raw.startsWith('\t')) serverHex += raw.trim();
        else clientHex += raw.trim();
      }
      const toBuffer = (hex) => {
        try { return hex ? Buffer.from(hex, 'hex') : Buffer.alloc(0); } catch (_) { return Buffer.alloc(0); }
      };
      resolve({ c2s: toBuffer(clientHex), s2c: toBuffer(serverHex) });
    });
  });
}

// ═══════════════════════════════════════════════════════════════════
// exportObjects — Wireshark-exact method:
//   1. Get all TCP/UDP stream indices from metadata index
//   2. For each stream: followTcpStream / followUdpStream
//      → get raw reassembled bytes (c2s + s2c)
//   3. Parse the protocol from the stream bytes
//      → extract object body + filename + metadata
//   4. For SMB/DICOM/IMF: use --export-objects (they need
//      full dissector context that raw bytes alone can't give)
//   5. Upload each object to B2, build manifest
//   packet_num = response_frame from stream meta
//   (the exact frame Wireshark shows in Export Objects dialog)
// ═══════════════════════════════════════════════════════════════════
async function exportObjects(sessionId, pcapPath, tsharkData) {
  await TSHARK_CAPS_READY;

  const exportDir = path.join(EXPORT_DIR, sessionId);
  if (!fs.existsSync(exportDir)) fs.mkdirSync(exportDir, { recursive: true });

  const manifest = [];

  // ── STEP 1: Run all --export-objects in parallel ──────────────
  // This is exactly what Wireshark does — full dissector context,
  // stream index prefix in filename, host/uri already known internally.
  const EXPORT_TYPES = ['http', 'smb', 'smb2', 'dicom', 'imf', 'ftp-data', 'tftp'];

  await Promise.all(EXPORT_TYPES.map(type => new Promise((resolve) => {
    const { spawn } = require('child_process');
    const typeDir = path.join(exportDir, type);
    if (!fs.existsSync(typeDir)) fs.mkdirSync(typeDir, { recursive: true });
    const proc = spawn(TSHARK_BIN, ['-r', pcapPath, '--export-objects', `${type},${typeDir}`], {
      stdio: ['ignore', 'ignore', 'pipe'],
    });
    proc.stderr.resume();
    proc.on('error', () => resolve());
    proc.on('close', () => resolve());
    setTimeout(() => { try { proc.kill('SIGKILL'); } catch (_) { } resolve(); }, 90000);
  })));

  // ── STEP 2: ONE metadata pass to get host/uri/IPs/packet_num ──
  // tshark filenames give us: stream index (prefix) + filename
  // We need: host, uri, src_ip, dst_ip, ports, response frame number
  // Build stream meta directly from already-parsed tsharkData http bucket
  // This is the same data tshark already gave us — no second pass needed
  const streamMeta = await (async () => {
    const byStream = new Map();
    const byUdpStream = new Map();

    // Pull from the http bucket which already has all fields from runTShark
    const httpRecords = tsharkData['http'] || [];
    console.log(`[Export] Building meta from ${httpRecords.length} HTTP records already in memory`);

    for (const r of httpRecords) {
      const tcpStream = r.tcp_stream !== undefined && r.tcp_stream !== null && r.tcp_stream !== ''
        ? parseInt(r.tcp_stream) : null;
      if (tcpStream === null || isNaN(tcpStream)) continue;
      console.log(`[HTTP Meta Debug] stream=${tcpStream} method="${r.request_method || ''}" resp_code="${r.response_code || ''}" frame=${r.frame_number}`); // 👈 ADD THIS

      const e = byStream.get(tcpStream) || {};
      if (!e.frame_number && r.timestamp) e.frame_number = 0;

      const method = r.request_method || '';
      const uri = r.request_uri || '';
      const fullUri = r.request_full_uri || '';
      const host = r.host || '';
      const respCode = r.response_code || '';
      const ctype = r.content_type || '';

      if (method) {
        if (!e.method) {
          e.method = method;
          e.src_ip = r.src_ip || '';
          e.dst_ip = r.dst_ip || '';
          e.src_port = r.src_port || 0;
          e.dst_port = r.dst_port || 0;
        }
        // Always track POST/PUT — stream reuse means GET comes before POST
        e._pending_request_method = method;
        if (method === 'POST' || method === 'PUT') {
          e.request_frame = r.frame_number || 0;
        }
        if (uri) { e.uri = uri; e.uris = e.uris || []; if (!e.uris.includes(uri)) e.uris.push(uri); }
        if (fullUri) { e.full_uri = fullUri; }
        if (host && !e.host) e.host = host;
      } else {
        if (!e.src_ip && r.src_ip) e.src_ip = r.src_ip;
        if (!e.dst_ip && r.dst_ip) e.dst_ip = r.dst_ip;
        if (!e.src_port && r.src_port) e.src_port = r.src_port;
        if (!e.dst_port && r.dst_port) e.dst_port = r.dst_port;
      }

      if (respCode) {
        // Store ALL responses per stream as an array — HTTP/1.1 reuses one stream for many files
        e.responses = e.responses || [];
        e.responses.push({
          response_frame: r.frame_number || 0,
          response_code: respCode,
          content_type: ctype ? ctype.split(';')[0].trim() : '',
          uri: uri,
          full_uri: fullUri,
          filename: uri ? path.basename(uri).split('?')[0] : '',
          // Use the pending request method for THIS response, then clear it
          method: e._pending_request_method || 'GET',
        });
        // Clear after consuming — next response won't inherit this method
        e._pending_request_method = null;
        // Keep last for backwards compat
        e.response_frame = r.frame_number || 0;
        e.response_code = respCode;
        if (ctype) e.content_type = ctype.split(';')[0].trim();
      }

      byStream.set(tcpStream, e);
    }

    // FTP from ftp bucket
    for (const r of (tsharkData['ftp'] || [])) {
      const tcpStream = r.tcp_stream !== undefined ? parseInt(r.tcp_stream) : null;
      if (tcpStream === null || isNaN(tcpStream)) continue;
      const e = byStream.get(tcpStream) || {};
      const cmd = (r.request_command || '').toUpperCase();
      if (cmd === 'RETR' || cmd === 'STOR') {
        e.ftp_command = cmd;
        e.ftp_filename = r.request_arg || '';
      }
      if (!e.src_ip && r.src_ip) e.src_ip = r.src_ip;
      if (!e.dst_ip && r.dst_ip) e.dst_ip = r.dst_ip;
      if (!e.src_port && r.src_port) e.src_port = r.src_port;
      if (!e.dst_port && r.dst_port) e.dst_port = r.dst_port;
      byStream.set(tcpStream, e);
    }

    // SMB
    for (const r of [...(tsharkData['smb'] || []), ...(tsharkData['smb2'] || [])]) {
      const tcpStream = r.tcp_stream !== undefined ? parseInt(r.tcp_stream) : null;
      if (tcpStream === null || isNaN(tcpStream)) continue;
      const e = byStream.get(tcpStream) || {};
      if (r.fname && !e.smb_filename) e.smb_filename = r.fname;
      if (r.path && !e.smb_path) e.smb_path = r.path;
      if (!e.src_ip && r.src_ip) e.src_ip = r.src_ip;
      if (!e.dst_ip && r.dst_ip) e.dst_ip = r.dst_ip;
      byStream.set(tcpStream, e);
    }

    // TFTP (UDP)
    for (const r of (tsharkData['tftp'] || [])) {
      const udpStream = r.udp_stream !== undefined ? parseInt(r.udp_stream) : null;
      if (udpStream === null || isNaN(udpStream)) continue;
      const e = byUdpStream.get(udpStream) || {};
      if (r.source_file && !e.tftp_filename) e.tftp_filename = r.source_file;
      if (r.destination_file && !e.tftp_filename) e.tftp_filename = r.destination_file;
      if (!e.src_ip && r.src_ip) e.src_ip = r.src_ip;
      if (!e.dst_ip && r.dst_ip) e.dst_ip = r.dst_ip;
      byUdpStream.set(udpStream, e);
    }

    console.log(`[Export] Meta from tsharkData: ${byStream.size} TCP streams, ${byUdpStream.size} UDP streams`);
    console.log(`[Export] byStream entries:`, JSON.stringify([...byStream.entries()].map(([k, v]) => ({ k, uri: v.uri, host: v.host, src_ip: v.src_ip, dst_ip: v.dst_ip })), null, 2));

    return { byStream, byUdpStream };
  })();

  const { byStream, byUdpStream } = streamMeta;

  // ── STEP 3: Process exported files ───────────────────────────
  // tshark 4.6.3 — hasStreamPrefix=true — stream index prefix ALWAYS present
  // Format: "28_login.php" → stream 28, "6_login.php" → stream 6
  // No fallback needed. Each stream = one unique HTTP conversation.

  console.log(`[Export] byStream keys: ${[...byStream.keys()].join(', ')}`);

  // Fix: also store request_content_type and request_frame in byStream
  // We need to do one more pass over HTTP records for POST requests
  for (const r of (tsharkData['http'] || [])) {
    const tcpStream = r.tcp_stream !== undefined && r.tcp_stream !== null && r.tcp_stream !== ''
      ? parseInt(r.tcp_stream) : null;
    if (tcpStream === null || isNaN(tcpStream)) continue;
    const e = byStream.get(tcpStream);
    if (!e) continue;
    const method = r.request_method || '';
    if ((method === 'POST' || method === 'PUT') && r.content_type) {
      e.request_content_type = r.content_type.split(';')[0].trim();
    }
  }

  for (const type of EXPORT_TYPES) {
    const typeDir = path.join(exportDir, type);
    if (!fs.existsSync(typeDir)) continue;

    let files;
    try { files = fs.readdirSync(typeDir); } catch (_) { continue; }

    for (const filename of files) {
      try {
        const filePath = path.join(typeDir, filename);
        const fileBuffer = fs.readFileSync(filePath);
        if (fileBuffer.length === 0) continue;

        // ── Stream-index extraction ──
        // Linux tshark >= 3.3 : filenames have "N_" prefix  e.g. "28_login.php"
        // Windows tshark      : NO prefix ever              e.g. "login.php"
        // tcp.stream itself works fine on Windows — only the filename prefix differs.
        const streamPrefixMatch = TSHARK_CAPS.hasStreamPrefix
          ? filename.match(/^(\d+)[_\-]/)
          : null;
        const streamIdx = streamPrefixMatch ? parseInt(streamPrefixMatch[1]) : null;

        // ── Attempt 1: direct stream index lookup (Linux with prefix) ──
        let meta = (streamIdx !== null) ? (byStream.get(streamIdx) || null) : null;
        console.log(`[Export Debug] stream=${streamIdx} responses=`, JSON.stringify(meta?.responses));

        if (!meta) {
          // ── Attempt 2: match by URI/filename across all streams (Windows or no-prefix) ──
          // Strip tshark dup index from filename first: "login(1).php" → "login.php"
          const baseClean = path.basename(filename)
            .replace(/\(\d+\)(\.[^.]+)$/, '$1')   // "login(1).php" → "login.php"
            .replace(/\(\d+\)$/, '')               // "login(1)"     → "login"
            .toLowerCase()
            .split('?')[0];

          // Handle duplicate filenames: login.php, login(1).php → dupIdx 0, 1, ...
          const dupMatch = path.basename(filename).match(/\((\d+)\)/);
          const dupIdx = dupMatch ? parseInt(dupMatch[1]) : 0;

          const occurrenceCount = new Map();

          for (const [streamKey, m] of byStream) {
            if (!m.responses) continue;
            for (const resp of m.responses) {
              const respFile = (resp.filename || '').toLowerCase();
              if (respFile !== baseClean) continue;

              const seen = occurrenceCount.get(baseClean) || 0;
              if (seen === dupIdx) {
                meta = {
                  ...m,
                  uri: resp.uri,
                  full_uri: resp.full_uri,
                  response_frame: resp.response_frame,
                  response_code: resp.response_code,
                  content_type: resp.content_type,
                  method: resp.method || m.method || 'GET', // ← use per-response method
                };
                console.log(`[Export] Windows URI-match: "${filename}" → stream ${streamKey} uri="${resp.uri}"`);
                break;
              }
              occurrenceCount.set(baseClean, seen + 1);
            }
            if (meta) break;
          }

          // ── Attempt 3: match by content-type when filename is generic (e.g. "%2f") ──
          // tshark sometimes URL-encodes the filename; try matching by position order
          if (!meta) {
            // Build ordered list of responses that haven't been matched yet
            const allResponses = [];
            for (const [streamKey, m] of byStream) {
              if (!m.responses) continue;
              for (const resp of m.responses) {
                allResponses.push({ streamKey, m, resp });
              }
            }
            // Sort by response_frame to get deterministic order matching tshark export order
            allResponses.sort((a, b) => (a.resp.response_frame || 0) - (b.resp.response_frame || 0));

            // Use dupIdx as position index into ordered responses
            const candidate = allResponses[dupIdx];
            if (candidate) {
              meta = {
                ...candidate.m,
                uri: candidate.resp.uri,
                full_uri: candidate.resp.full_uri,
                response_frame: candidate.resp.response_frame,
                response_code: candidate.resp.response_code,
                content_type: candidate.resp.content_type,
              };
              console.warn(`[Export] Windows position-fallback: "${filename}" → stream ${candidate.streamKey} uri="${candidate.resp.uri}"`);
            }
          }

          // ── Attempt 4: single-stream captures — safe universal fallback ──
          if (!meta && byStream.size === 1) {
            meta = [...byStream.values()][0];
            console.warn(`[Export] Single-stream fallback for "${filename}"`);
          }

          if (!meta) {
            console.warn(`[Export] No meta found for "${filename}" — skipping (${byStream.size} streams available)`);
            continue;
          }
        }

        // ── Clean filename ──
        // Strip stream prefix: "28_login.php" → "login.php"
        // Strip tshark dup index: "login(1).php" → "login.php" (with method suffix)
        const baseClean = TSHARK_CAPS.hasStreamPrefix
          ? path.basename(filename).replace(/^[\d]+[_\-]/, '')  // Linux: strip "28_"
          : path.basename(filename);                              // Windows: use as-is
        // Match tshark dup patterns: "login(1).php" or "login(1)"
        const dupMatchWithExt = baseClean.match(/^(.+)\((\d+)\)(\.[^.]+)$/);
        const dupMatchNoExt = baseClean.match(/^(.+)\((\d+)\)$/);

        let cleanFilename;
        if (dupMatchWithExt) {
          cleanFilename = dupMatchWithExt[1] + dupMatchWithExt[3]; // "login.php"
        } else if (dupMatchNoExt) {
          cleanFilename = dupMatchNoExt[1];                         // "login"
        } else {
          cleanFilename = baseClean;                                // "login.php"
        }

        const method = meta.method || '';

        // DICOM/IMF extension fix
        if (type === 'dicom' && !cleanFilename.endsWith('.dcm')) cleanFilename += '.dcm';
        if (type === 'imf' && !cleanFilename.endsWith('.eml')) cleanFilename += '.eml';
        if (!cleanFilename) cleanFilename = filename;

        // ── UDP meta for TFTP ──
        const udpMeta = (type === 'tftp') ? (byUdpStream.get(streamIdx) || null) : null;
        const activeMeta = udpMeta || meta;

        // ── Content type: POST request needs request_content_type ──
        // For GET responses: use matched response's content_type
        // For POST/PUT: derive from file extension (the request body has no meaningful content_type for storage)
        const matchedContentType = meta?.responses?.find(r =>
          (r.filename || '').toLowerCase() === path.basename(cleanFilename).toLowerCase()
        )?.content_type || activeMeta?.content_type || '';

        const contentType = matchedContentType || getMimeFromFilename(cleanFilename) || 'application/octet-stream';

        // ── Packet number ──
        // tshark --export-objects always tags objects with the RESPONSE frame number,
        // matching what Wireshark's Export Objects dialog shows — even for POST requests.
        // POST/PUT: tshark tags with request frame (where credentials/data are)
        // GET: tshark tags with response frame (where the file content is)
        console.log(`[PacketNum Debug2] "${cleanFilename}" method="${method}" request_frame=${activeMeta?.request_frame} response_frame=${activeMeta?.response_frame}`);

        // Backtrace: streamIdx (from filename prefix) → meta.responses[] (ordered by frame)
        // → match this specific file → use its own response_frame or request_frame
        let packetNum = 0;

        if (meta?.responses?.length > 0) {
          // Strip stream prefix and dup index to get clean base filename
          const strippedName = TSHARK_CAPS.hasStreamPrefix
            ? path.basename(filename).replace(/^[\d]+[_\-]/, '')
            : path.basename(filename);
          const dupMatch = strippedName.match(/^(.+)\((\d+)\)(\.[^.]+)$/) || strippedName.match(/^(.+)\((\d+)\)$/);
          const dupIdx = dupMatch ? parseInt(dupMatch[2]) : 0;
          const cleanBase = strippedName
            .replace(/\(\d+\)(\.[^.]+)$/, '$1')
            .replace(/\(\d+\)$/, '')
            .toLowerCase().split('?')[0];

          // Find matching response — try URI/filename match first, then fall back to position
          const uriMatches = meta.responses.filter(r =>
            (r.filename || '').toLowerCase() === cleanBase ||
            (r.uri || '').toLowerCase().split('?')[0].split('/').pop() === cleanBase
          );

          const matched = uriMatches[dupIdx] ?? uriMatches[0] ?? meta.responses[dupIdx] ?? meta.responses[0];

          if (matched) {
            packetNum = (matched.method === 'POST' || matched.method === 'PUT')
              ? (meta.request_frame || matched.response_frame || 0)
              : (matched.response_frame || 0);
            console.log(`[PacketNum] "${cleanBase}" dupIdx=${dupIdx} → method=${matched.method} frame=${packetNum}`);
          }
        } else {
          // Fallback for non-HTTP types (SMB, FTP, TFTP) — use activeMeta directly
          const m = activeMeta?.method || '';
          packetNum = (m === 'POST' || m === 'PUT')
            ? (activeMeta?.request_frame || activeMeta?.response_frame || 0)
            : (activeMeta?.response_frame || activeMeta?.frame_number || 0);
        }
        console.log(`[PacketNum Debug] "${cleanFilename}" → response_frame=${activeMeta?.response_frame} frame_number=${activeMeta?.frame_number} → final=${packetNum}`);
        const b2Key = `artifacts/${sessionId}/${type}_${filename}`;

        await b2.send(new PutObjectCommand({
          Bucket: process.env.B2_BUCKET_NAME,
          Key: b2Key,
          Body: fileBuffer,
          ContentType: contentType,
        }));

        manifest.push({
          filename: cleanFilename,
          original_filename: filename,
          artifact_key: b2Key,
          export_type: type,
          size: fileBuffer.length,
          content_type: contentType,
          is_image: contentType.startsWith('image/'),
          tcp_stream: type === 'tftp' ? null : streamIdx,
          udp_stream: type === 'tftp' ? streamIdx : null,
          packet_num: packetNum,
          frame_number: packetNum,
          src_ip: activeMeta?.src_ip || '',
          dst_ip: activeMeta?.dst_ip || '',
          src_port: activeMeta?.src_port || 0,
          dst_port: activeMeta?.dst_port || 0,
          hostname: activeMeta?.host || activeMeta?.dst_ip || '',
          host: activeMeta?.host || '',
          uri: activeMeta?.uri || '',
          full_uri: activeMeta?.full_uri || '',
          request_uri: activeMeta?.uri || '',
          method: method,
          status_code: activeMeta?.response_code || '',
          content_length: fileBuffer.length,
          ftp_command: activeMeta?.ftp_command || '',
          ftp_filename: activeMeta?.ftp_filename || '',
          smb_filename: activeMeta?.smb_filename || '',
          smb_path: activeMeta?.smb_path || '',
          tftp_filename: activeMeta?.tftp_filename || '',
          match_confidence: 'high',
        });

        console.log(`[Export] ✓ [${type}] stream=${streamIdx} frame=${packetNum} method=${method} host="${activeMeta?.host || ''}" uri="${activeMeta?.uri || ''}" "${cleanFilename}" (${fileBuffer.length}B)`);

      } catch (e) {
        console.error(`[Export] ${type} failed "${filename}": ${e.message}`);
      }
    }
  }


  // ── Upload manifest ───────────────────────────────────────────
  await b2.send(new PutObjectCommand({
    Bucket: process.env.B2_BUCKET_NAME,
    Key: `artifacts/${sessionId}/_manifest.json`,
    Body: JSON.stringify(manifest),
    ContentType: 'application/json',
  }));

  console.log(`[Export] ✓ Complete: ${manifest.length} objects | types: ${[...new Set(manifest.map(m => m.export_type))].join(', ')}`);
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

    // Send sub-progress updates while TShark runs (every 8s)
    let subStep = 0;
    const subLabels = [
      'Running TShark extraction',
      'Parsing packets & protocol layers...',
      'Extracting protocol buckets...',
      'Exporting HTTP objects...',
      'Finalizing packet data...',
    ];
    const subTimer = setInterval(() => {
      subStep = Math.min(subStep + 1, subLabels.length - 1);
      setProgress(sessionId, 0, subLabels[subStep]);
    }, 8000);

    const tsharkData = await runTShark(pcapPath);
    const exportedManifest = await exportObjects(sessionId, pcapPath, tsharkData);

    clearInterval(subTimer);

    const session = sessions.get(sessionId);
    if (session) {
      session.export_done = true;
      session.object_count = exportedManifest.length;
    }

    const { packets } = tsharkData;
    console.log(`[Analysis] Parsed ${packets.length} packets, exported ${exportedManifest.length} objects`);

    // Log what tshark explicitly found per export type — authoritative only
    const exportByType = {};
    for (const obj of exportedManifest) {
      exportByType[obj.export_type] = (exportByType[obj.export_type] || 0) + 1;
    }
    console.log(`[Export] tshark-extracted objects by type:`, JSON.stringify(exportByType));

    // FTP object extraction — RETR/STOR from tshark ftp dissector only
    const ftpRecords = tsharkData['ftp'] || [];
    const ftpDataRecords = tsharkData['ftp-data'] || [];
    console.log(`[FTP] tshark dissected ${ftpRecords.length} FTP control records, ${ftpDataRecords.length} FTP-DATA records`);
    for (const r of ftpRecords) {
      const cmd = (r.request_command || '').toUpperCase();
      const arg = r.request_arg || '';
      if (cmd === 'RETR' || cmd === 'STOR') {
        console.log(`[FTP] tshark found ${cmd} transfer: "${arg}" | stream=${r.tcp_stream || 'unknown'} | ${r.src_ip} → ${r.dst_ip}`);
      }
    }
    if (ftpRecords.length === 0 && ftpDataRecords.length === 0) {
      console.log(`[FTP] Not present in this capture`);
    }

    // SMB object extraction — tshark smb/smb2 dissector only
    const smbRecords = (tsharkData['smb'] || []).concat(tsharkData['smb2'] || []);
    console.log(`[SMB] tshark dissected ${smbRecords.length} SMB/SMB2 records`);
    if (smbRecords.length === 0) {
      console.log(`[SMB] Not present in this capture`);
    }
    // TCP Stream Reassembly — tshark stream indices are authoritative
    // Phase 2: Wireshark-grade payload reconstruction (on-demand)
    const tcpStreams = reassembleTCPStreams(packets);
    console.log(`[Debug] TCP Stream keys: ${[...tcpStreams.keys()].sort((a, b) => a - b).join(', ')}`);

    console.log(`[Analysis] TCP streams built from metadata (${tcpStreams.size} streams) — payloads fetched on demand`);
    // ── UDP Stream Reassembly ──────────────────────────────────────
    const udpStreams = reassembleUDPStreams(packets);
    console.log(`[Debug] UDP Stream keys: ${[...udpStreams.keys()].sort((a, b) => a - b).join(', ')}`);

    console.log(`[Analysis] UDP streams built from metadata (${udpStreams.size} streams) — payloads fetched on demand`);

    // (already inside the threats block below — add this line after credentialLeaks is ready)
    // 2. Aggregate base stats
    const ports = new Set();
    const srcIPs = new Set();
    const dstIPs = new Set();
    const protocols = new Map();
    let totalBytes = 0, firstTimestamp = Infinity, lastTimestamp = 0;

    for (const pkt of packets) {
      if (pkt.dst_port) ports.add(pkt.dst_port);
      if (pkt.src_port) ports.add(pkt.src_port);
      if (pkt.src_ip) srcIPs.add(pkt.src_ip);
      if (pkt.dst_ip) dstIPs.add(pkt.dst_ip);
      if (pkt.protocol) protocols.set(pkt.protocol, (protocols.get(pkt.protocol) || 0) + 1);
      totalBytes += pkt.length || 0;
      if (pkt.timestamp !== null && pkt.timestamp !== undefined) {
        if (pkt.timestamp < firstTimestamp) firstTimestamp = pkt.timestamp;
        if (pkt.timestamp > lastTimestamp) lastTimestamp = pkt.timestamp;
      }
    }
    console.log(`[Duration Debug] first=${firstTimestamp} last=${lastTimestamp} duration=${lastTimestamp - firstTimestamp}`); // 👈 add here


    // 3. IANA port info for ALL ports — IANA is the ONLY source of service names
    console.log(`[Analysis] ═══ STEP 1: IANA port resolution for ${ports.size} ports ═══`);
    const portInfoMap = new Map();
    const portServiceMap = new Map();
    for (const port of ports) {
      const info = await getIANAPortInfo(port);
      portInfoMap.set(port, info);
      const serviceName = info?.service_name || 'Unknown';
      portServiceMap.set(port, serviceName);
      console.log(`[IANA] Port ${port} → "${serviceName}" (${info?.description || 'no description'}) secure=${info?.secure}`);
    }
    console.log(`[Analysis] ═══ STEP 1 complete: ${portServiceMap.size} ports mapped ═══`);
    console.log(`[Analysis] Port→Service map: ${[...portServiceMap.entries()].map(([p, s]) => `${p}=${s}`).join(', ')}`);

    // Now hand service names to SearXNG for risk resolution
    console.log(`[Analysis] ═══ STEP 2: SearXNG risk resolution (IANA service names as input) ═══`);

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
    const [credentialLeaks, expertThreats] = await Promise.all([
      detectCredentialLeaks(pcapPath, tsharkData, packets),
      runTSharkExpert(pcapPath)
    ]);

    // Bind credentials to their streams NOW that we have both
    bindCredentialsToStreams(tcpStreams, credentialLeaks, packets);

    const threats = {
      port_scans: detectPortScans(packets),
      brute_force: detectBruteForce(packets),
      dns_tunneling: detectDNSTunneling(tsharkData.dns || []),
      data_exfiltration: detectDataExfiltration(packets, ipReputations),
      ddos_indicators: detectDDoSPatterns(packets),
      malicious_ips: detectMaliciousIPs([...srcIPs, ...dstIPs], ipReputations),
      credential_leaks: credentialLeaks,
      expert_info: expertThreats
    };

    // Group credential leaks by frame+src+dst (same as UI cards)
    const credLeakGroups = new Set(
      (threats.credential_leaks || []).map(t =>
        `${t.packet_num || t.frame_number || 'unknown'}-${t.src_ip}-${t.dst_ip}`
      )
    );

    const criticalAlerts = [
      ...threats.ddos_indicators,
      ...threats.malicious_ips.filter(t => t.severity === 'CRITICAL'),
      ...threats.data_exfiltration,
    ].length + credLeakGroups.size;

    const highAlerts = [
      ...threats.port_scans,
      ...threats.brute_force.filter(t => t.severity === 'HIGH'),
      ...threats.dns_tunneling.filter(t => t.severity === 'HIGH'),
      ...threats.malicious_ips.filter(t => t.severity === 'HIGH'),
    ].length;
    // 8. Summary
    const duration = lastTimestamp > firstTimestamp ? lastTimestamp - firstTimestamp : 0;
    console.log(`[Duration Debug] first=${firstTimestamp} last=${lastTimestamp} duration=${duration}`);

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
    // Lean version — port number + service name only (for ports.json)
    const portLean = portIntel.map(p => ({
      port: p.port,
      service_name: p.service_name,
    }));

    // Full intel kept separately for vulnerability/risk display
    const uploadMap = {
      [`analysis/${sessionId}-summary.json`]: summary,
      [`analysis/${sessionId}-packets.json`]: packets.slice(0, 10000).map(p => ({
        ...p,
        timestamp: p.timestamp !== null && p.timestamp !== undefined ? String(p.timestamp) : null
      })),
      [`analysis/${sessionId}-ports.json`]: portLean,       // ← lean: port + service only
      [`analysis/${sessionId}-ports-intel.json`]: portIntel, // ← full: risks, CVEs, tags, alternatives
      [`analysis/${sessionId}-threats.json`]: threats,
      [`analysis/${sessionId}-tcp-streams.json`]: [...tcpStreams.values()],
      [`analysis/${sessionId}-udp-streams.json`]: [...udpStreams.values()],  // ← added
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

    // ── Force Re-analyze ───────────────────────────────────────────────
    if (req.method === 'POST' && url.startsWith('/api/reanalyze/')) {
      const sessionId = url.split('/api/reanalyze/')[1]?.split('?')[0];
      if (!isValidSessionId(sessionId)) {
        return json(res, { error: 'Invalid session ID' }, 400, origin, acceptEncoding);
      }

      console.log(`[Reanalyze] Force re-analyzing session: ${sessionId}`);

      // Delete ALL cached data for this session from B2
      const deletePromises = [
        `analysis/${sessionId}-summary.json`,
        `analysis/${sessionId}-packets.json`,
        `analysis/${sessionId}-ports.json`,
        `analysis/${sessionId}-threats.json`,
        `analysis/${sessionId}-tcp-streams.json`,
        `artifacts/${sessionId}/_manifest.json`,
      ].map(key => deleteFromB2(key).catch(() => { }));

      // Get summary to find which protocol files exist
      const summary = await fetchB2JSON(`analysis/${sessionId}-summary.json`);
      if (summary?.protocols_detected) {
        Object.keys(summary.protocols_detected).forEach(proto => {
          deletePromises.push(deleteFromB2(`analysis/${sessionId}-${proto}.json`).catch(() => { }));
        });
      }

      // Delete artifacts folder
      try {
        const listed = await b2.send(new ListObjectsV2Command({
          Bucket: process.env.B2_BUCKET_NAME,
          Prefix: `artifacts/${sessionId}/`,
        }));
        if (listed.Contents?.length > 0) {
          listed.Contents.forEach(obj => {
            deletePromises.push(deleteFromB2(obj.Key).catch(() => { }));
          });
        }
      } catch (_) { }

      await Promise.all(deletePromises);
      console.log(`[Reanalyze] Deleted cached B2 files for ${sessionId}`);

      // Clear local caches
      sessionPortIndexes.delete(sessionId);
      sessionContentIndexes.delete(sessionId);
      sessions.delete(sessionId);

      // Delete local files
      try {
        const p = path.join(PCAP_DIR, `${sessionId}.pcap`);
        if (fs.existsSync(p)) fs.unlinkSync(p);
      } catch (_) { }
      try {
        const p = path.join(EXPORT_DIR, sessionId);
        if (fs.existsSync(p)) fs.rmSync(p, { recursive: true });
      } catch (_) { }

      // Get PCAP from B2 and re-run analysis
      const pcapPath = path.join(PCAP_DIR, `${sessionId}.pcap`);
      const b2PcapKey = `pcaps/${sessionId}.pcap`;

      try {
        await downloadFromB2(b2PcapKey, pcapPath);
        console.log(`[Reanalyze] Downloaded PCAP, starting fresh analysis...`);

        analyzePCAP(sessionId, pcapPath).catch(err =>
          console.error(`[Reanalyze] Error: ${err.message}`)
        );

        return json(res, { success: true, message: 'Re-analysis started with fresh cache' }, 200, origin, acceptEncoding);
      } catch (e) {
        return json(res, { error: 'PCAP not found in storage - please re-upload' }, 404, origin, acceptEncoding);
      }
    }
    // ── Get Summary ──────────────────────────────────────────────
    // ── Analysis Progress ─────────────────────────────────────────


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

    // ── Get Port Intelligence (full: risks, CVEs, tags) ──────────
    if (req.method === 'GET' && url.startsWith('/api/ports-intel/')) {
      const sessionId = url.split('/api/ports-intel/')[1]?.split('?')[0];
      if (!isValidSessionId(sessionId)) return json(res, { error: 'Invalid session ID' }, 400, origin, acceptEncoding);
      if (!await ensureSession(sessionId)) return json(res, { error: 'Session not found' }, 404, origin, acceptEncoding);
      const data = await fetchB2JSON(`analysis/${sessionId}-ports-intel.json`);
      if (!data) return json(res, { error: 'Port intel not ready yet' }, 202, origin, acceptEncoding);
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

    // ── GET /pcap/objects ────────────────────────────────────────
    if (req.method === 'GET' && url.startsWith('/pcap/objects/zip')) {
      const q = getQuery(url);
      const sessionId = q.session_id;
      const typeFilter = q.type || 'all';
      if (!isValidSessionId(sessionId)) return json(res, { error: 'Invalid session ID' }, 400, origin, acceptEncoding);
      // REMOVED ensureSession

      const manifest = await fetchB2JSON(`artifacts/${sessionId}/_manifest.json`);
      if (!manifest || manifest.length === 0) {
        return json(res, { error: 'No objects found' }, 404, origin, acceptEncoding);
      }

      const toZip = typeFilter === 'all'
        ? manifest
        : manifest.filter(o => o.export_type === typeFilter);

      if (toZip.length === 0) {
        return json(res, { error: `No objects found for type: ${typeFilter}` }, 404, origin, acceptEncoding);
      }

      const archiver = require('archiver');

      res.writeHead(200, {
        'Content-Type': 'application/zip',
        'Content-Disposition': `attachment; filename="objects-${sessionId}-${typeFilter}.zip"`,
        ...getCorsHeaders(origin),
      });

      const archive = archiver('zip', { zlib: { level: 6 } });
      archive.pipe(res);
      archive.on('error', (err) => {
        console.error(`[ZIP] Archive error: ${err.message}`);
        res.end();
      });

      for (const obj of toZip) {
        try {
          const r = await b2.send(new GetObjectCommand({
            Bucket: process.env.B2_BUCKET_NAME,
            Key: obj.artifact_key,
          }));
          archive.append(r.Body, { name: `${obj.export_type}/${obj.filename}` });
        } catch (e) {
          console.error(`[ZIP] Skipping ${obj.filename}: ${e.message}`);
        }
      }

      await archive.finalize();
      console.log(`[ZIP] Sent ${toZip.length} objects for session ${sessionId}`);
      return;
    }

    if (req.method === 'GET' && url.startsWith('/pcap/objects')) {
      const q = getQuery(url);
      const sessionId = q.session_id;
      if (!isValidSessionId(sessionId)) return json(res, { error: 'Invalid session ID' }, 400, origin, acceptEncoding);
      // REMOVED ensureSession

      const sess = sessions.get(sessionId);
      if (sess && sess.export_done === false) {
        return json(res, { error: 'Export still in progress', retry: true }, 202, origin, acceptEncoding);
      }

      const manifest = await fetchB2JSON(`artifacts/${sessionId}/_manifest.json`);
      const allObjects = manifest || [];
      const typeFilter = q.type || 'all';
      const filtered = typeFilter === 'all'
        ? allObjects
        : allObjects.filter(o => o.export_type === typeFilter);

      console.log(`[Objects] Session ${sessionId}: ${filtered.length}/${allObjects.length} objects (filter=${typeFilter})`);
      return json(res, { objects: filtered, total: allObjects.length }, 200, origin, acceptEncoding);
    }

    // ── GET /pcap/image-data ──────────────────────────────────────
    if (req.method === 'GET' && url.startsWith('/pcap/image-data')) {
      const q = getQuery(url);
      const sessionId = q.session_id;
      const artifactKey = q.key;

      if (!isValidSessionId(sessionId)) return json(res, { error: 'Invalid session ID' }, 400, origin, acceptEncoding);
      if (!artifactKey) return json(res, { error: 'Missing key' }, 400, origin, acceptEncoding);
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
        // Tell frontend which provider is being used
        const provider = (NVIDIA_API_KEY) ? 'nvidia' : 'groq';
        res.write(`data: ${JSON.stringify({ provider })}\n\n`);
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
      // Strip each file type to only essential fields before sending to LLM
      function compressForLLM(fileType, data) {
        if (!Array.isArray(data)) return data; // summary, threats — keep as-is

        switch (fileType) {
          case 'packets':
            return data.map(p => ({
              f: p.frame_number,
              t: p.timestamp,
              s: p.src_ip,
              d: p.dst_ip,
              sp: p.src_port,
              dp: p.dst_port,
              pr: p.protocol,
              l: p.length,
            }));

          case 'ports':
          case 'ports-intel':
            return data.map(p => ({
              port: p.port,
              service: p.service_name,
              desc: p.description,
              secure: p.secure,
              risks: p.risks || [],
              alts: p.alternatives || [],
              cves: (p.cves || []).slice(0, 2).map(c => ({
                id: c.cve_id, score: c.cvss_score, sev: c.severity
              })),
              pkts: p.packet_count,
            }));
          case 'http':
            return data.map(r => ({
              t: r.timestamp,
              s: r.src_ip,
              d: r.dst_ip,
              dp: r.dst_port,
              m: r.request_method,
              u: r.request_uri,
              h: r.host,
              rc: r.response_code,
              f: r.frame_number,
            }));

          case 'dns':
            return data.map(r => ({
              t: r.timestamp,
              s: r.src_ip,
              d: r.dst_ip,
              qn: r.qry_name,
              f: r.frame_number,
            }));

          case 'tcp-streams':
          case 'udp-streams':
            return data.map(r => ({
              id: r.tcp_stream ?? r.udp_stream,
              s: r.client?.ip,
              sp: r.client?.port,
              d: r.server?.ip,
              dp: r.server?.port,
              pr: r.protocol,
              bytes: r.total_bytes,
              pkts: r.packet_count,
              dur: r.duration_seconds,
              health: r.stream_health,
            }));

          case 'tls':
            return data.map(r => ({
              t: r.timestamp,
              s: r.src_ip,
              d: r.dst_ip,
              sni: r.handshake_extensions_server_name,
              f: r.frame_number,
            }));

          case 'smb':
          case 'smb2':
            return data.map(r => ({
              t: r.timestamp,
              s: r.src_ip,
              d: r.dst_ip,
              f: r.frame_number,
              file: r.fname,
              path: r.path,
            }));

          case 'ftp':
            return data.map(r => ({
              t: r.timestamp,
              s: r.src_ip,
              d: r.dst_ip,
              cmd: r.request_command,
              arg: r.request_arg,
              f: r.frame_number,
            }));

          default:
            // All other protocol buckets — just keep IPs, ports, timestamp
            return data.map(r => ({
              t: r.timestamp,
              s: r.src_ip,
              d: r.dst_ip,
              sp: r.src_port,
              dp: r.dst_port,
              f: r.frame_number,
            }));
        }
      }

      const fetchPromises = filesToFetch.map(async (fileType) => {
        const key = fileType === 'ports'
          ? `analysis/${session_id}-ports-intel.json`
          : `analysis/${session_id}-${fileType}.json`; const data = await fetchB2JSON(key);
        if (data) {
          const compressed = compressForLLM(fileType, data);
          return `\n## ${fileType.toUpperCase()} Data\n${JSON.stringify(compressed, null, 2)}`;
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
          content: `You are PacketSight AI — an expert network security analyst. You analyze real PCAP data extracted by TShark and answer questions precisely and concisely.

STRICT RULES:
- Start EVERY response with a one-liner verdict: 🔴 Critical / ⚠️ Warning / ✅ Clean
- If the question is about websites but credentials were leaked over HTTP, verdict must be 🔴 Critical — not ✅ Clean
- If the question is about encryption and HTTP is present with no TLS, verdict must be ⚠️ Warning — not ✅ Clean since unencrypted HTTP is a security risk
- Verdict is based on the OVERALL security of the capture, not just the specific question asked
- Be CONCISE — answer exactly what was asked, nothing more
- NEVER say "based on the data provided" or "without specific information" — you HAVE the data, use it
- NEVER guess or say "likely" or "probably" — only state what the data explicitly shows
- For ports: use the PORTS data to list exact port numbers, service names, packet counts — never guess
- For encryption: check if 'tls' protocol exists in protocols_detected — if yes = encrypted traffic present, if no = no encryption detected. Never say "unconfirmed"
- For protocols: only mention protocols that actually appear in the data — never mention TCP as "may contain TLS" unless TLS is explicitly in protocols list
- For credentials: always state exactly what was leaked (field names), which frame, which IPs
- For websites: list exact URIs and hosts from HTTP data
- Keep responses SHORT and TO THE POINT — no padding, no repetition
- Use these section headers when relevant: 📊 Summary, 🔴 Threats, 🌐 Traffic, 🔑 Credentials, 🛡️ Recommendations
- NEVER print the section list itself in your response
- End with max 3 bullet recommendations only if issues found

FIELD KEY (compressed data):
f=frame_number, t=timestamp, s=src_ip, d=dst_ip, sp=src_port, dp=dst_port, pr=protocol, l=length, m=http_method, u=uri, h=host, rc=response_code, sni=tls_server_name

Data fetched for this query (${filesToFetch.join(', ')}):
${analysisContext}

Routing context:
- Unknown port matches: ${unknownPortMatches.length}
- Content matches: ${contentMatches.length}`
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

    // ── GET /pcap/udp-stream — Wireshark Follow UDP Stream ───────
    if (req.method === 'GET' && url.startsWith('/pcap/udp-stream')) {
      const q = getQuery(url);
      const sessionId = q.session_id;
      const streamId = parseInt(q.stream || '0');

      if (!isValidSessionId(sessionId)) {
        return json(res, { error: 'Invalid session ID' }, 400, origin, acceptEncoding);
      }
      if (isNaN(streamId) || streamId < 0) {
        return json(res, { error: 'Missing or invalid stream index' }, 400, origin, acceptEncoding);
      }
      if (!await ensureSession(sessionId)) {
        return json(res, { error: 'Session not found' }, 404, origin, acceptEncoding);
      }

      let pcapPath = path.join(PCAP_DIR, `${sessionId}.pcap`);
      let downloadedTemp = false;

      if (!fs.existsSync(pcapPath)) {
        const b2PcapKey = `pcaps/${sessionId}.pcap`;
        const inB2 = await existsInB2(b2PcapKey);
        if (!inB2) {
          return json(res, { error: 'PCAP file not found — session may have expired' }, 404, origin, acceptEncoding);
        }
        pcapPath = path.join(PCAP_DIR, `${sessionId}-udpstream-${Date.now()}.pcap`);
        await downloadFromB2(b2PcapKey, pcapPath);
        downloadedTemp = true;
      }

      try {
        const packetsData = await fetchB2JSON(`analysis/${sessionId}-packets.json`);

        let streamMeta = null;
        if (packetsData) {
          const streamPackets = packetsData.filter(p =>
            p.udp_stream !== null && p.udp_stream !== undefined && parseInt(p.udp_stream) === streamId
          );
          if (streamPackets.length > 0) {
            const first = streamPackets[0];
            streamMeta = {
              stream_id: streamId,
              src_ip: first.src_ip,
              dst_ip: first.dst_ip,
              src_port: first.src_port,
              dst_port: first.dst_port,
              protocol: first.protocol,
              packet_count: streamPackets.length,
              total_bytes: streamPackets.reduce((s, p) => s + (p.length || 0), 0),
            };
          }
        }

        if (!streamMeta) {
          return json(res, { error: `UDP stream ${streamId} not found in this capture` }, 404, origin, acceptEncoding);
        }

        console.log(`[UDPStream] Following stream ${streamId} for session ${sessionId}`);
        const followResult = await followUdpStream(pcapPath, streamId);

        if (!followResult) {
          return json(res, { error: `Failed to reconstruct UDP stream ${streamId}` }, 500, origin, acceptEncoding);
        }

        const toText = (buf) => {
          if (!buf || buf.length === 0) return { text: '', bytes: 0, is_binary: false };
          let nonPrint = 0;
          for (let i = 0; i < buf.length; i++) {
            const b = buf[i];
            if (b < 0x09 || (b > 0x0d && b < 0x20) || b === 0x7f) nonPrint++;
          }
          const isBinary = buf.length > 0 && (nonPrint / buf.length) > 0.20;
          return {
            text: isBinary
              ? `[Binary data — ${buf.length} bytes]`
              : buf.toString('utf8').replace(/\r\n/g, '\n'),
            bytes: buf.length,
            is_binary: isBinary,
          };
        };

        const c2s = toText(followResult.c2s);
        const s2c = toText(followResult.s2c);

        return json(res, {
          stream_id: streamId,
          client: streamMeta.src_ip ? { ip: streamMeta.src_ip, port: streamMeta.src_port } : null,
          server: streamMeta.dst_ip ? { ip: streamMeta.dst_ip, port: streamMeta.dst_port } : null,
          client_to_server: c2s,
          server_to_client: s2c,
          total_bytes: c2s.bytes + s2c.bytes,
          meta: streamMeta,
        }, 200, origin, acceptEncoding);

      } finally {
        if (downloadedTemp && fs.existsSync(pcapPath)) {
          try { fs.unlinkSync(pcapPath); } catch (_) { }
        }
      }
    }

    // ── GET /pcap/tcp-stream — Wireshark Follow TCP Stream ───────
    if (req.method === 'GET' && url.startsWith('/pcap/tcp-stream')) {
      const q = getQuery(url);
      const sessionId = q.session_id;
      const streamId = parseInt(q.stream || '0');

      if (!isValidSessionId(sessionId)) {
        return json(res, { error: 'Invalid session ID' }, 400, origin, acceptEncoding);
      }
      if (isNaN(streamId) || streamId < 0) {
        return json(res, { error: 'Missing or invalid stream index' }, 400, origin, acceptEncoding);
      }
      if (!await ensureSession(sessionId)) {
        return json(res, { error: 'Session not found' }, 404, origin, acceptEncoding);
      }

      let pcapPath = path.join(PCAP_DIR, `${sessionId}.pcap`);
      let downloadedTemp = false;

      if (!fs.existsSync(pcapPath)) {
        const b2PcapKey = `pcaps/${sessionId}.pcap`;
        const inB2 = await existsInB2(b2PcapKey);
        if (!inB2) {
          return json(res, { error: 'PCAP file not found — session may have expired' }, 404, origin, acceptEncoding);
        }
        pcapPath = path.join(PCAP_DIR, `${sessionId}-tcpstream-${Date.now()}.pcap`);
        await downloadFromB2(b2PcapKey, pcapPath);
        downloadedTemp = true;
      }

      try {
        const summaryData = await fetchB2JSON(`analysis/${sessionId}-summary.json`);
        const packetsData = await fetchB2JSON(`analysis/${sessionId}-packets.json`);

        let streamMeta = null;
        if (packetsData) {
          const streamPackets = packetsData.filter(p =>
            p.tcp_stream !== null && p.tcp_stream !== undefined && parseInt(p.tcp_stream) === streamId
          );
          if (streamPackets.length > 0) {
            const first = streamPackets[0];
            streamMeta = {
              stream_id: streamId,
              src_ip: first.src_ip,
              dst_ip: first.dst_ip,
              src_port: first.src_port,
              dst_port: first.dst_port,
              protocol: first.protocol,
              packet_count: streamPackets.length,
              total_bytes: streamPackets.reduce((s, p) => s + (p.length || 0), 0),
            };
          }
        }

        if (!streamMeta) {
          return json(res, { error: `TCP stream ${streamId} not found in this capture` }, 404, origin, acceptEncoding);
        }

        console.log(`[TCPStream] Following stream ${streamId} for session ${sessionId}`);
        const followResult = await followTcpStream(pcapPath, streamId);

        if (!followResult) {
          return json(res, { error: `Failed to reconstruct stream ${streamId}` }, 500, origin, acceptEncoding);
        }

        return json(res, {
          ...followResult,
          meta: streamMeta,
        }, 200, origin, acceptEncoding);

      } finally {
        if (downloadedTemp && fs.existsSync(pcapPath)) {
          try { fs.unlinkSync(pcapPath); } catch (_) { }
        }
      }
    }

    // ── GET /pcap/packet-dissection ───────────────────────────────
    // ── GET /pcap/packets — paginated packet list ─────────────────
    if (req.method === 'GET' && url.startsWith('/pcap/packets')) {
      const q = getQuery(url);
      const sessionId = q.session_id;
      const page = Math.max(1, parseInt(q.page || '1'));
      const perPage = Math.min(500, Math.max(1, parseInt(q.per_page || '100')));

      if (!isValidSessionId(sessionId)) return json(res, { error: 'Invalid session ID' }, 400, origin, acceptEncoding);
      if (!await ensureSession(sessionId)) return json(res, { error: 'Session not found' }, 404, origin, acceptEncoding);

      const allPackets = await fetchB2JSON(`analysis/${sessionId}-packets.json`);
      if (!allPackets) return json(res, { error: 'Packets not ready yet' }, 202, origin, acceptEncoding);

      const total = allPackets.length;
      const start = (page - 1) * perPage;
      const slice = allPackets.slice(start, start + perPage);

      if (slice[0]) console.log(`[PacketDebug] raw timestamp from B2: ${JSON.stringify(slice[0].timestamp)} type=${typeof slice[0].timestamp}`);

      const packets = slice.map((p, i) => ({
        id: p.frame_number || (start + i + 1),
        timestamp: p.timestamp ?? null,
        src_ip: p.src_hostname || p.src_ip || null,
        dst_ip: p.dst_hostname || p.dst_ip || null,
        src_port: p.src_port || null,
        dst_port: p.dst_port || null,
        protocol: p.protocol || '',
        length: p.length || 0,
        ttl: p.ttl || null,
        flags: p.tcp_flags || null,
        payload_preview: '',
        info: p.info || '',
        datetime: p.timestamp ? new Date(p.timestamp * 1000).toISOString() : '',
        color_filter_name: p.color_filter_name || '',
        color_filter_string: p.color_filter_string || '',
        tcp_stream: p.tcp_stream ?? null,   // ← added
        udp_stream: p.udp_stream ?? null,   // ← added
      }));

      return json(res, { packets, total, page, per_page: perPage, total_pages: Math.ceil(total / perPage) }, 200, origin, acceptEncoding);
    }

    // ── GET /pcap/packet-dissection ───────────────────────────────
    if (req.method === 'GET' && url.startsWith('/pcap/packet-dissection')) {
      const q = getQuery(url);
      const sessionId = q.session_id;
      const packetNumber = parseInt(q.packet_number || '0');

      if (!isValidSessionId(sessionId)) return json(res, { error: 'Invalid session ID' }, 400, origin, acceptEncoding);
      if (!packetNumber) return json(res, { error: 'Missing packet_number' }, 400, origin, acceptEncoding);
      if (!await ensureSession(sessionId)) return json(res, { error: 'Session not found' }, 404, origin, acceptEncoding);

      // Step 1: get the PCAP file — disk first, B2 fallback
      let pcapPath = path.join(PCAP_DIR, `${sessionId}.pcap`);
      let downloadedTemp = false;

      if (!fs.existsSync(pcapPath)) {
        const b2PcapKey = `pcaps/${sessionId}.pcap`;
        const inB2 = await existsInB2(b2PcapKey);
        if (!inB2) return json(res, { error: 'PCAP file not found' }, 404, origin, acceptEncoding);
        pcapPath = path.join(PCAP_DIR, `${sessionId}-tmp-${Date.now()}.pcap`);
        await downloadFromB2(b2PcapKey, pcapPath);
        downloadedTemp = true;
      }

      // Step 2: run TShark on just this one packet with full verbose output
      await TSHARK_CAPS_READY;
      const caps = TSHARK_CAPS;

      try {
        const dissection = await new Promise((resolve, reject) => {
          const { spawn } = require('child_process');

          const args = [
            '-r', pcapPath,
            '-2',                    // ← ADD THIS HERE TOO
            '-T', 'json',
            '--no-duplicate-keys',
            '-N', 'mndN',
          ];

          let stdout = '';
          let stderr = '';
          const proc = spawn(TSHARK_BIN, args);

          const killTimer = setTimeout(() => {
            proc.kill('SIGKILL');
            reject(new Error('TShark dissection timed out'));
          }, 30000);

          proc.stdout.on('data', chunk => stdout += chunk.toString());
          proc.stderr.on('data', chunk => stderr += chunk.toString());
          proc.on('error', err => { clearTimeout(killTimer); reject(err); });
          proc.on('close', (code) => {
            clearTimeout(killTimer);
            if (code !== 0 && code !== null && !stdout) {
              return reject(new Error(`TShark exited ${code}: ${stderr}`));
            }

            let rawPackets;
            try {
              rawPackets = JSON.parse(stdout);
            } catch (e) {
              return reject(new Error(`JSON parse failed: ${e.message}`));
            }

            if (!Array.isArray(rawPackets) || rawPackets.length === 0) {
              return reject(new Error(`Packet ${packetNumber} not found`));
            }

            const targetPkt = rawPackets.find(p => {
              const fn = p?._source?.layers?.['frame.number'] ||
                p?._source?.layers?.['frame']?.['frame.number'];
              return parseInt(Array.isArray(fn) ? fn[0] : fn) === packetNumber;
            });

            if (!targetPkt) {
              return reject(new Error(`Packet ${packetNumber} not found`));
            }

            const layers = targetPkt._source?.layers || {};

            const httpLayer = layers['http'];
            console.log('[DEBUG] http layer type:', typeof httpLayer);
            // ── RESPONSE_IN DEBUG ──
            console.log('[ResponseIn Debug] flat layers keys with response/request_in:',
              Object.keys(layers).filter(k => k.includes('response') || k.includes('request_in'))
            );
            if (httpLayer && typeof httpLayer === 'object') {
              console.log('[ResponseIn Debug] http sub-keys with response/request_in:',
                Object.keys(httpLayer).filter(k => k.includes('response') || k.includes('request_in'))
              );
              // Deep scan ALL nested keys
              const deepScan = (obj, prefix) => {
                for (const [k, v] of Object.entries(obj)) {
                  if (k.includes('response') || k.includes('request_in')) {
                    console.log(`[ResponseIn Debug] FOUND: ${prefix}.${k} =`, JSON.stringify(v));
                  }
                  if (v && typeof v === 'object' && !Array.isArray(v)) deepScan(v, `${prefix}.${k}`);
                }
              };
              deepScan(httpLayer, 'http');
            } console.log('[DEBUG] http layer keys:', JSON.stringify(Object.keys(httpLayer || {})));
            console.log('[DEBUG] full http layer:', JSON.stringify(httpLayer, null, 2).slice(0, 3000));

            // Helper: get flat or nested field value
            const gv = (field) => {
              if (layers[field] !== undefined) {
                const val = layers[field];
                // Always return as string to preserve numeric precision (e.g. frame.time_epoch microseconds)
                const raw = Array.isArray(val) ? val[0] : val;
                return raw === null || raw === undefined ? '' : String(raw);
              }
              const proto = field.split('.')[0];
              if (layers[proto] && typeof layers[proto] === 'object') {
                const val = layers[proto][field];
                if (val !== undefined) {
                  const raw = Array.isArray(val) ? val[0] : val;
                  return raw === null || raw === undefined ? '' : String(raw);
                }
              }
              return '';
            };
            // Step 4: build PacketLayer[] — fully dynamic, no hardcoded protocol names
            const SKIP_LAYER_KEYS = new Set(['_ws']);
            const builtLayers = [];

            // Exact suffix → bracket label mapping
            // Keys here are the tshark field suffixes AFTER stripping proto prefix
            // e.g. http.response_in → suffix = "response_in"
            // ORDER MATTERS — more specific first (request.full_uri before full_uri)
            const COMPUTED_SUFFIX_MAP = [
              // Match by ENDS-WITH — handles both flat and double-nested tshark output
              // e.g. suffix "http.response_in" OR "response_in" both match rule ending "response_in"
              { suffix: 'response_in', label: '[Response in frame]', isFrameRef: true, timeMs: false },
              { suffix: 'response_for', label: '[Request in frame]', isFrameRef: true, timeMs: false },
              { suffix: 'request_in', label: '[Request in frame]', isFrameRef: true, timeMs: false },
              { suffix: 'prev_request_in', label: '[Prev request in frame]', isFrameRef: true, timeMs: false },
              { suffix: 'next_request_in', label: '[Next request in frame]', isFrameRef: true, timeMs: false },
              { suffix: 'request.full_uri', label: '[Full request URI]', isFrameRef: false, timeMs: false },
              { suffix: 'time', label: '[Time since request]', isFrameRef: false, timeMs: true },
              { suffix: 'request_number', label: '[HTTP request]', isFrameRef: false, timeMs: false },
            ];


            // Fields to SUPPRESS from normal display when they become computed bracket fields
            // This prevents showing both raw "response_in: 6" AND "[Response in frame]: 6"
            const SUPPRESS_IF_COMPUTED = new Set([
              'response_in', 'response_for', 'request_in',
              'prev_request_in', 'next_request_in',
              'request.full_uri', 'full_uri',
              'time', 'request_number',
            ]);

            function collectComputedFields(protoData, proto) {
              const computed = [];
              const seenLabels = new Set();

              const matchesRule = (key) => {
                for (const rule of COMPUTED_SUFFIX_MAP) {
                  if (
                    key === rule.suffix ||
                    key === `${proto}.${rule.suffix}` ||
                    key.endsWith(`.${rule.suffix}`) ||
                    key.endsWith(`_${rule.suffix.replace(/\./g, '_')}`)  // handles http_response_in variant
                  ) {
                    return rule;
                  }
                }
                return null;
              };

              const walk = (obj) => {
                if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return;
                for (const [k, v] of Object.entries(obj)) {
                  const rule = matchesRule(k);
                  if (rule && !seenLabels.has(rule.label)) {
                    seenLabels.add(rule.label);
                    const rawVal = Array.isArray(v) ? v[0] : String(v ?? '');
                    let displayVal = rawVal;
                    if (rule.timeMs) {
                      const secs = parseFloat(rawVal);
                      if (!isNaN(secs)) {
                        displayVal = `${(secs * 1000).toFixed(6)} milliseconds`;
                      }
                    }
                    computed.push({
                      key: rule.label,
                      value: displayVal,
                      isComputed: true,
                      isFrameRef: rule.isFrameRef,
                      children: [],
                      isExpandable: false,
                    });
                  }
                  // Always recurse into nested objects
                  if (v && typeof v === 'object' && !Array.isArray(v)) walk(v);
                }
              };

              // Check flat keys on protoData directly first (catches "http.response_in" flat)
              for (const [k, v] of Object.entries(protoData)) {
                // Strip proto prefix before matching — handles both "response_in" and "http.response_in"
                const strippedKey = k.startsWith(`${proto}.`) ? k.slice(proto.length + 1) : k;
                const rule = matchesRule(strippedKey) || matchesRule(k);
                if (rule && !seenLabels.has(rule.label)) {
                  seenLabels.add(rule.label);
                  const rawVal = Array.isArray(v) ? v[0] : String(v ?? '');
                  let displayVal = rawVal;
                  if (rule.timeMs) {
                    const secs = parseFloat(rawVal);
                    if (!isNaN(secs)) displayVal = `${(secs * 1000).toFixed(6)} milliseconds`;
                  }
                  computed.push({
                    key: rule.label,
                    value: displayVal,
                    isComputed: true,
                    isFrameRef: rule.isFrameRef,
                    children: [],
                    isExpandable: false,
                  });
                }
                // Recurse into nested
                if (v && typeof v === 'object' && !Array.isArray(v)) walk(v);
              }

              return computed;
            }

            // Modified parseFields that SUPPRESSES fields that will become computed bracket fields
            const parseFields = (obj, parentProto) => {
              if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return [];
              return Object.entries(obj)
                .filter(([k]) => {
                  const suffix = k.startsWith(`${parentProto}.`)
                    ? k.slice(parentProto.length + 1)
                    : k;
                  // Check endsWith to handle double-nested tshark keys like "http.request.full_uri"
                  return ![...SUPPRESS_IF_COMPUTED].some(s =>
                    suffix === s || suffix.endsWith(`.${s}`) || suffix.endsWith(`_${s}`)
                  );
                })
                .map(([k, v]) => {
                  const key = k.startsWith(`${parentProto}.`)
                    ? k.slice(parentProto.length + 1)
                    : k;
                  if (v && typeof v === 'object' && !Array.isArray(v)) {
                    return {
                      key,
                      value: null,
                      children: parseFields(v, k),
                      isExpandable: true,
                    };
                  }
                  const strVal = Array.isArray(v) ? v.join(', ') : String(v ?? '');
                  return { key, value: strVal, children: [], isExpandable: false };
                });
            };

            // AFTER:
            for (const [proto, protoData] of Object.entries(layers)) {
              if (SKIP_LAYER_KEYS.has(proto)) continue;
              if (proto.endsWith('_raw')) continue;

              let fields = [];

              if (protoData && typeof protoData === 'object' && !Array.isArray(protoData)) {
                fields = parseFields(protoData, proto);
                const computed = collectComputedFields(protoData, proto);
                if (computed.length > 0) fields = [...fields, ...computed];
              } else {
                fields = [{
                  key: proto,
                  value: Array.isArray(protoData) ? protoData.join(', ') : String(protoData ?? ''),
                  children: [],
                  isExpandable: false,
                }];
              }

              builtLayers.push({
                name: proto.toUpperCase(),
                protocol: proto.toLowerCase(),
                fields,
              });
            }

            const result = {
              frame: {
                number: String(packetNumber),
                time: gv('frame.time') || gv('frame.time_epoch'),
                time_relative: gv('frame.time_relative'),
                length: gv('frame.len'),
              },
              layers: builtLayers,
              info: (() => {
                if (layers['_ws.col.Info']) return layers['_ws.col.Info'];
                const wsLayer = layers['_ws'];
                if (wsLayer && typeof wsLayer === 'object') {
                  return wsLayer['_ws.col.Info'] || wsLayer['_ws_col_Info'] || wsLayer['col.Info'] || '';
                }
                return '';
              })(),
              protocol: gv('_ws.col.Protocol') || gv('_ws_col_Protocol'),
            };

            // AFTER — capture layerKeys inside the Promise before resolving, pass it out:
            // capture before resolve so httpLinkFields can use it
            const _layerKeys = Object.keys(layers);
            // Serialize flat layer values for post-Promise injection
            const _flatLayers = Object.fromEntries(
              Object.entries(layers).map(([k, v]) => [k, Array.isArray(v) ? v[0] : v])
            );
            resolve({ ...result, _layerKeys, _flatLayers });
          });
        });

        const allLinkFields = await getCachedLinkFields();
        // pull _layerKeys out and strip it from the dissection response
        const { _layerKeys: layerKeys, _flatLayers: flatLayers, ...dissectionClean } = dissection; const dissectionResult = dissectionClean;

        // AFTER — delete the duplicate, keep only one:
        const httpLinkFields = await (async () => {
          if (allLinkFields.length === 0) return {};

          const relevantFields = allLinkFields.filter(field => {
            const proto = field.split('.')[0];
            return layerKeys.some(k => k === proto || k.startsWith(proto + '.'));
          });

          if (relevantFields.length === 0) return {};

          const fieldArgs = relevantFields.flatMap(f => ['-e', f]);

          return new Promise((resolve) => {
            const { spawn } = require('child_process');
            const proc = spawn(TSHARK_BIN, [
              '-r', pcapPath,
              '-2',                    // ← AND HERE
              '-Y', `frame.number == ${packetNumber}`,
              '-T', 'fields',
              '-E', 'separator=|',
              '-E', 'header=y',
              '-E', 'occurrence=f',
              ...fieldArgs,
            ]);

            let out = '';
            proc.stdout.on('data', d => out += d.toString());
            proc.stderr.resume();
            proc.on('error', () => resolve({}));
            proc.on('close', () => {
              const lines = out.trim().split('\n').filter(Boolean);
              if (lines.length < 2) return resolve({});
              const headers = lines[0].split('|');
              const values = lines[1].split('|');
              const result = {};
              headers.forEach((h, i) => {
                const v = values[i]?.trim();
                if (v) result[h.trim()] = v;
              });
              resolve(result);
            });
            setTimeout(() => { try { proc.kill(); } catch (_) { } resolve({}); }, 20000);
          });
        })();

        // Dynamically inject [Response in frame] / [Request in frame] into ANY protocol layer
        // Wireshark does this per-dissector — we replicate by checking every field tshark returned
        const LABEL_MAP = {
          response_in: '[Response in frame]',
          request_in: '[Request in frame]',
          response_to: '[Response to request in frame]',
          request_for: '[Request for frame]',
          resp_in: '[Response in frame]',
          resp_to: '[Response to frame]',
          request_out: '[Request in frame]',
          response_out: '[Response in frame]',
          response_for: '[Request in frame]',
          next_request_in: '[Next request in frame]',
          prev_request_in: '[Prev request in frame]',
        };

        for (const [field, value] of Object.entries(httpLinkFields)) {
          if (!value) continue;
          const proto = field.split('.')[0];
          const suffix = field.slice(proto.length + 1);
          const label = LABEL_MAP[suffix] || `[${suffix.replace(/_/g, ' ')}]`;
          const targetLayer = dissectionResult.layers.find(l => l.protocol === proto);
          if (!targetLayer) continue;
          if (targetLayer.fields.some(f => f.key === label)) continue;
          // Push to TOP of fields so it appears right below the layer header — same as Wireshark
          targetLayer.fields.push({
            key: label,
            value: String(value),
            children: [],
            isExpandable: false,
            isComputed: true,
            isFrameRef: true,
          });
        }

        // ── ALSO inject from flat layers keys directly (tshark sometimes puts
        //    http.response_in flat on layers, not nested inside layers['http']) ──
        for (const [flatKey, flatVal] of Object.entries(flatLayers || {})) {
          const proto = flatKey.split('.')[0];
          const suffix = flatKey.slice(proto.length + 1);
          if (!suffix) continue;
          const label = LABEL_MAP[suffix];
          if (!label) continue;
          if (!flatVal || flatVal === '') continue;
          const targetLayer = dissectionResult.layers.find(l => l.protocol === proto);
          if (!targetLayer) continue;
          if (targetLayer.fields.some(f => f.key === label)) continue;
          targetLayer.fields.push({
            key: label,
            value: String(Array.isArray(flatVal) ? flatVal[0] : flatVal),
            children: [],
            isExpandable: false,
            isComputed: true,
            isFrameRef: true,
          });
        }

        return json(res, dissectionResult, 200, origin, acceptEncoding);

      } catch (err) {
        console.error(`[Dissection] Error for packet ${packetNumber}: ${err.message}`);
        return json(res, { error: err.message }, 500, origin, acceptEncoding);
      } finally {
        // Clean up temp downloaded file if we pulled from B2
        if (downloadedTemp && fs.existsSync(pcapPath)) {
          try { fs.unlinkSync(pcapPath); } catch (_) { }
        }
      }
    }

    // ── Filter Packets (Wireshark display filter via tshark -Y) ──────
    if (req.method === 'POST' && url.startsWith('/pcap/filter')) {
      const body = await parseBody(req);
      const { session_id, filter } = JSON.parse(body.toString());

      if (!isValidSessionId(session_id)) {
        return json(res, { error: 'Invalid session ID' }, 400, origin, acceptEncoding);
      }
      if (!filter || typeof filter !== 'string') {
        return json(res, { error: 'Missing filter expression' }, 400, origin, acceptEncoding);
      }
      if (!await ensureSession(session_id)) {
        return json(res, { error: 'Session not found' }, 404, origin, acceptEncoding);
      }

      let pcapPath = path.join(PCAP_DIR, `${session_id}.pcap`);
      let downloadedTemp = false;

      if (!fs.existsSync(pcapPath)) {
        const b2PcapKey = `pcaps/${session_id}.pcap`;
        const inB2 = await existsInB2(b2PcapKey);
        if (!inB2) return json(res, { error: 'PCAP not found' }, 404, origin, acceptEncoding);
        pcapPath = path.join(PCAP_DIR, `${session_id}-filter-${Date.now()}.pcap`);
        await downloadFromB2(b2PcapKey, pcapPath);
        downloadedTemp = true;
      }

      try {
        const { spawn } = require('child_process');

        // Step 1: validate filter syntax first via tshark -Y with zero packets
        const isValid = await new Promise((resolve) => {
          const proc = spawn(TSHARK_BIN, [
            '-r', pcapPath,
            '-Y', filter,
            '-c', '0',   // read 0 packets — just validate
            '-q',
          ]);
          let stderr = '';
          proc.stderr.on('data', d => stderr += d.toString());
          proc.on('close', (code) => {
            // tshark exits non-zero and prints to stderr on bad filter
            resolve(!stderr.toLowerCase().includes('invalid') && !stderr.toLowerCase().includes('unknown') && !stderr.toLowerCase().includes('error'));
          });
          proc.on('error', () => resolve(false));
          setTimeout(() => { try { proc.kill(); } catch (_) { } resolve(false); }, 5000);
        });

        if (!isValid) {
          return json(res, { error: 'Invalid filter expression', invalid: true }, 400, origin, acceptEncoding);
        }

        // Step 2: run actual filter + extract same fields as /pcap/packets
        const wsColPromise = fetchWsColFields(pcapPath);
        const rawTimestampsPromise = fetchRawTimestamps(pcapPath);

        const filtered = await new Promise((resolve, reject) => {
          const args = [
            '-r', pcapPath,
            '-2',
            '-Y', filter,
            '-T', 'json',
            '--no-duplicate-keys',
            '-N', 'mndN',
          ];
          const proc = spawn(TSHARK_BIN, args);
          let stdout = '';
          let stderr = '';
          proc.stdout.on('data', d => stdout += d.toString());
          proc.stderr.on('data', d => stderr += d.toString());
          proc.on('error', reject);
          const kill = setTimeout(() => { proc.kill('SIGKILL'); reject(new Error('Timeout')); }, 60000);
          proc.on('close', (code) => {
            clearTimeout(kill);
            try {
              const raw = JSON.parse(stdout || '[]');
              resolve(Array.isArray(raw) ? raw.filter(p => p && p._source) : []);
            } catch (e) {
              resolve([]);
            }
          });
        });

        const [wsColMap, rawTimestampMap] = await Promise.all([wsColPromise, rawTimestampsPromise]);

        const packets = filtered.map(rawPkt => {
          const layers = rawPkt._source?.layers || {};
          const gv = (field) => {
            if (layers[field] !== undefined) {
              const val = layers[field];
              return Array.isArray(val) ? val[0] || '' : (val || '');
            }
            const proto = field.split('.')[0];
            if (layers[proto] && typeof layers[proto] === 'object') {
              const val = layers[proto][field];
              if (val !== undefined) return Array.isArray(val) ? val[0] || '' : (val || '');
            }
            return '';
          };

          const frameNum = parseInt(gv('frame.number')) || 0;
          const col = wsColMap.get(frameNum);
          const rawTs = rawTimestampMap.get(frameNum);

          return {
            id: frameNum,
            timestamp: rawTs || gv('frame.time_epoch') || null,
            src_ip: gv('ip.src_host') || gv('ipv6.src_host') || gv('ip.src') || gv('eth.src_resolved') || null,
            dst_ip: gv('ip.dst_host') || gv('ipv6.dst_host') || gv('ip.dst') || gv('eth.dst_resolved') || null,
            src_port: parseInt(gv('tcp.srcport')) || parseInt(gv('udp.srcport')) || 0,
            dst_port: parseInt(gv('tcp.dstport')) || parseInt(gv('udp.dstport')) || 0,
            protocol: (
              col?.['_ws.col.Protocol'] ||
              col?.['_ws.col.protocol'] ||
              gv('_ws.col.Protocol') ||
              gv('_ws.col.protocol') ||
              Object.values(col || {}).find(v => typeof v === 'string' && v.trim()) ||
              ''
            ).trim(), length: parseInt(gv('frame.len')) || 0,
            info: col?.['_ws.col.Info'] || gv('_ws.col.Info') || '',
            tcp_stream: (() => { const v = gv('tcp.stream'); return v !== '' ? parseInt(v) : null; })(),
            udp_stream: (() => { const v = gv('udp.stream'); return v !== '' ? parseInt(v) : null; })(),
            color_filter_name: gv('_ws.col.color_filter_name') || '',
            color_filter_string: gv('_ws.col.color_filter_string') || '',
          };
        });

        console.log(`[Filter] "${filter}" → ${packets.length} packets`);
        return json(res, { packets, total: packets.length, filter }, 200, origin, acceptEncoding);

      } catch (e) {
        console.error(`[Filter] Error: ${e.message}`);
        return json(res, { error: e.message }, 500, origin, acceptEncoding);
      } finally {
        if (downloadedTemp && fs.existsSync(pcapPath)) {
          try { fs.unlinkSync(pcapPath); } catch (_) { }
        }
      }
    }

    // ── Get tshark field list (for filter autocomplete) ──────────────
    if (req.method === 'GET' && url.startsWith('/pcap/filter-fields')) {
      const q = getQuery(url);
      const prefix = (q.prefix || '').toLowerCase().trim();

      if (!prefix || prefix.length < 2) {
        return json(res, { fields: [] }, 200, origin, acceptEncoding);
      }

      const allFields = await getCachedLinkFields();

      // getCachedLinkFields only caches cross-frame link fields —
      // for autocomplete we need ALL fields, cache separately
      const allTsharkFields = await new Promise((resolve) => {
        if (global._tsharkAllFields) return resolve(global._tsharkAllFields);
        const { spawn } = require('child_process');
        const proc = spawn(TSHARK_BIN, ['-G', 'fields']);
        let out = '';
        proc.stdout.on('data', d => out += d.toString());
        proc.stderr.resume();
        proc.on('close', () => {
          const fields = out.split('\n')
            .filter(l => l.startsWith('F\t'))
            .map(l => {
              const parts = l.split('\t');
              return { name: parts[2]?.trim(), desc: parts[3]?.trim() };
            })
            .filter(f => f.name);
          global._tsharkAllFields = fields;
          console.log(`[FilterFields] Cached ${fields.length} tshark fields`);
          resolve(fields);
        });
        proc.on('error', () => resolve([]));
        setTimeout(() => { try { proc.kill(); } catch (_) { } resolve([]); }, 30000);
      });

      const matches = allTsharkFields
        .filter(f => f.name.toLowerCase().startsWith(prefix))
        .slice(0, 20)
        .map(f => ({ name: f.name, desc: f.desc }));

      return json(res, { fields: matches }, 200, origin, acceptEncoding);
    }

    // ── Health Check ──────────────────────────────────────────────
    if ((req.method === 'GET' || req.method === 'HEAD') && url === '/health') {
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
const wss = new WebSocketServer({ server });

wss.on('connection', (ws, req) => {
  const urlPath = req.url || '';
  const match = urlPath.match(/\/api\/progress\/([^?]+)/);
  if (!match) return ws.close();

  const sessionId = match[1];
  if (!isValidSessionId(sessionId)) return ws.close();

  // Replay all missed steps instantly
  const history = progressHistory.get(sessionId) || [];
  for (const event of history) {
    try { ws.send(JSON.stringify(event)); } catch (_) { }
  }

  // Already done — close immediately
  const last = history[history.length - 1];
  if (last?.done) return ws.close();

  // Register client
  if (!progressClients.has(sessionId)) progressClients.set(sessionId, new Set());
  progressClients.get(sessionId).add(ws);

  ws.on('close', () => {
    const clients = progressClients.get(sessionId);
    if (clients) {
      clients.delete(ws);
      if (clients.size === 0) progressClients.delete(sessionId);
    }
  });
});

server.listen(PORT, () => {
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('  PCAP Intelligence Server - HYBRID PROTOCOL EDITION');
  console.log('═══════════════════════════════════════════════════════════════');
  console.log(`  Server running on port ${PORT}`);
  console.log('═══════════════════════════════════════════════════════════════');
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
const http = require('http');
const https = require('https');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');

// ═══════════════════════════════════════════════════════════════════
// REQUIRED ENVIRONMENT VARIABLES (Set these in Render dashboard!)
// ═══════════════════════════════════════════════════════════════════
const SEARXNG_URL = process.env.SEARXNG_URL;

// Cloudflare Workers AI credentials
const CF_ACCOUNT_ID = process.env.CF_ACCOUNT_ID;
const CF_API_TOKEN = process.env.CF_API_TOKEN;

// ALLOWED_ORIGIN: Your frontend URL (default: localhost for local dev)
// Change this when deploying to Vercel: https://your-app.vercel.app
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || 'http://localhost:3000';

// Validate required env vars on startup
const missingVars = [];
if (!SEARXNG_URL) missingVars.push('SEARXNG_URL');
if (!CF_ACCOUNT_ID) missingVars.push('CF_ACCOUNT_ID');
if (!CF_API_TOKEN) missingVars.push('CF_API_TOKEN');

if (missingVars.length > 0) {
  console.error('═══════════════════════════════════════════════════════════════');
  console.error('❌ FATAL: Missing required environment variables!');
  console.error('═══════════════════════════════════════════════════════════════');
  missingVars.forEach(v => console.error(`   - ${v}`));
  console.error('');
  console.error('Set these in your Render dashboard → Environment tab:');
  console.error('   SEARXNG_URL     = https://searxng-krq1.onrender.com');
  console.error('   CF_ACCOUNT_ID   = your_cloudflare_account_id');
  console.error('   CF_API_TOKEN    = your_cloudflare_api_token');
  console.error('   ALLOWED_ORIGIN  = http://localhost:3000 (or your Vercel URL)');
  console.error('═══════════════════════════════════════════════════════════════');
  process.exit(1); // Crash early with clear error
}

console.log('✅ Environment variables loaded:');
console.log(`   SEARXNG_URL    = ${SEARXNG_URL}`);
console.log(`   CF_ACCOUNT_ID  = ${CF_ACCOUNT_ID}`);
console.log(`   CF_API_TOKEN   = ${CF_API_TOKEN ? CF_API_TOKEN.slice(0, 10) + '...' : 'NOT SET'}`);
console.log(`   ALLOWED_ORIGIN = ${ALLOWED_ORIGIN}`);

// ═══════════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════════
// Cloudflare Workers AI - Qwen 2.5 14B is SMARTER than Llama 3 8B!
// Options: @cf/qwen/qwen2.5-14b-instruct (smartest) or @cf/meta/llama-3-8b-instruct (faster)
const CF_LLM_MODEL = '@cf/qwen/qwen2.5-14b-instruct';
const CF_LLM_TIMEOUT_MS = 15000; // 15 seconds for smarter model
const HF_LLM_TIMEOUT_MS = 8000; // Kept for compatibility
const SEARXNG_TIMEOUT_MS = 10000;
const SEARXNG_MAX_RESULTS = 5;
const SEARXNG_ENGINES = 'google,bing,duckduckgo,startpage';

// ── TShark binary path ─────────────────────────────────────────
const TSHARK_BIN = process.env.TSHARK_PATH ||
  (process.platform === 'win32'
    ? 'C:\\Program Files\\Wireshark\\tshark.exe'
    : 'tshark');

console.log(`[Init] TShark path: ${TSHARK_BIN}`);

exec(`"${TSHARK_BIN}" -v`, (err, stdout) => {
  if (err) {
    console.error(`[FATAL] tshark not found at: ${TSHARK_BIN}`);
    console.error(`        Set TSHARK_PATH env var to override.`);
  } else {
    console.log(`[Init] Found: ${stdout.split('\n')[0]}`);
  }
});

// ── Directories ────────────────────────────────────────────────
const PCAP_DIR = './tmp_pcaps';
const EXPORT_DIR = './tmp_exports';
if (!fs.existsSync(PCAP_DIR)) fs.mkdirSync(PCAP_DIR, { recursive: true });
if (!fs.existsSync(EXPORT_DIR)) fs.mkdirSync(EXPORT_DIR, { recursive: true });

// ── Session store ──────────────────────────────────────────────
const sessions = new Map();
const imageStore = new Map();
const SESSION_TTL_MS = 30 * 60 * 1000;

// Pre-computed data store (cached analysis results)
const precomputedData = new Map();

setInterval(() => {
  const now = Date.now();
  for (const [id, session] of sessions) {
    if (now - session.created_at > SESSION_TTL_MS) {
      try { const p = path.join(PCAP_DIR, `${id}.pcap`); if (fs.existsSync(p)) fs.unlinkSync(p); } catch (_) { }
      try { const p = path.join(EXPORT_DIR, id); if (fs.existsSync(p)) fs.rmSync(p, { recursive: true }); } catch (_) { }
      sessions.delete(id);
      imageStore.delete(id);
      precomputedData.delete(id);
      console.log(`[Session] Expired: ${id}`);
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
  // Allow both localhost variants during dev
  const allowed = [ALLOWED_ORIGIN, 'http://localhost:3000', 'http://127.0.0.1:3000'];
  const allowedOrigin = allowed.includes(origin) ? origin : ALLOWED_ORIGIN;
  return {
    'Access-Control-Allow-Origin': allowedOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Credentials': 'true',
    'Vary': 'Origin',
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
    parts.push({
      headers: buffer.slice(lEnd + 2, hEnd).toString(),
      data: buffer.slice(hEnd + 4, nBound === -1 ? buffer.length : nBound),
    });
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

const isValidSessionId = (id) =>
  typeof id === 'string' && /^session-\d{13}-[a-z0-9]{6}$/.test(id);

// ── TShark core runner ─────────────────────────────────────────
// Include IPv4, IPv6, MAC addresses for ARP, TCP and UDP ports
const DEFAULT_FIELDS = [
  'frame.number',
  'ip.src', 'ip.dst',           // IPv4 addresses
  'ipv6.src', 'ipv6.dst',       // IPv6 addresses
  'eth.src', 'eth.dst',         // MAC addresses (for ARP and non-IP)
  'frame.len',
  '_ws.col.Protocol',
  'tcp.srcport', 'tcp.dstport', // TCP ports
  'udp.srcport', 'udp.dstport', // UDP ports
  'frame.time_relative',
  'frame.time',                 // Absolute date/time
  '_ws.col.Info',               // Info column (Wireshark-style)
];

function runTshark(sessionId, filter = '', fields = DEFAULT_FIELDS, limit = 0) {
  return new Promise((resolve) => {
    const pcapPath = path.join(PCAP_DIR, `${sessionId}.pcap`);
    if (!fs.existsSync(pcapPath)) {
      console.warn(`[TShark] PCAP not found: ${pcapPath}`);
      return resolve([]);
    }

    let cmd = `"${TSHARK_BIN}" -r "${pcapPath}" -T fields -E separator=/t`;
    for (const f of fields) cmd += ` -e ${f}`;
    if (filter) cmd += ` -Y "${filter.replace(/"/g, '\\"')}"`;
    if (limit > 0) cmd += ` -c ${limit}`;

    console.log(`[TShark] Running: ${cmd}`);

    exec(cmd, { timeout: 60000, maxBuffer: 50 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) {
        console.error(`[TShark] exec error: ${err.message}`);
        if (stderr) console.error(`[TShark] stderr: ${stderr.slice(0, 400)}`);
        return resolve([]);
      }
      const lines = stdout.trim().split('\n').filter(l => l.trim());
      const packets = lines.map(line => {
        const c = line.split('\t');
        // Field order: frame.number, ip.src, ip.dst, ipv6.src, ipv6.dst, eth.src, eth.dst,
        //               frame.len, protocol, tcp.srcport, tcp.dstport, udp.srcport, udp.dstport,
        //               time_relative, frame.time, info
        // Use IPv4 if available, else IPv6, else MAC (for ARP/non-IP)
        const src_ip = c[1] || c[3] || c[5] || null;  // IPv4 src or IPv6 src or MAC src
        const dst_ip = c[2] || c[4] || c[6] || null;  // IPv4 dst or IPv6 dst or MAC dst
        return {
          id: parseInt(c[0]) || 0,
          src_ip,
          dst_ip,
          length: parseInt(c[7]) || 0,
          protocol: c[8] || 'UNKNOWN',
          src_port: parseInt(c[9]) || parseInt(c[11]) || null,  // TCP src or UDP src
          dst_port: parseInt(c[10]) || parseInt(c[12]) || null, // TCP dst or UDP dst
          timestamp: parseFloat(c[13]) || 0,
          datetime: c[14] || '',  // Absolute date/time
          info: c[15] || null,    // Info column (Wireshark-style)
        };
      });
      console.log(`[TShark] Returned ${packets.length} packets`);
      resolve(packets);
    });
  });
}

// ── Paginated packet fetch ─────────────────────────────────────
function runTsharkPaged(sessionId, skip, limit) {
  return new Promise((resolve) => {
    const pcapPath = path.join(PCAP_DIR, `${sessionId}.pcap`);
    if (!fs.existsSync(pcapPath)) return resolve([]);

    let cmd = `"${TSHARK_BIN}" -r "${pcapPath}" -T fields -E separator=/t`;
    for (const f of DEFAULT_FIELDS) cmd += ` -e ${f}`;
    cmd += ` -c ${skip + limit}`;

    console.log(`[TSharkPaged] skip=${skip} limit=${limit} cmd: ${cmd}`);

    exec(cmd, { timeout: 60000, maxBuffer: 20 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) {
        console.error(`[TSharkPaged] exec error: ${err.message}`);
        if (stderr) console.error(`[TSharkPaged] stderr: ${stderr.slice(0, 400)}`);
        return resolve([]);
      }
      const lines = stdout.trim().split('\n').filter(l => l.trim());
      const pageLines = lines.slice(skip);
      const packets = pageLines.map(line => {
        const c = line.split('\t');
        // Field order: frame.number, ip.src, ip.dst, ipv6.src, ipv6.dst, eth.src, eth.dst,
        //               frame.len, protocol, tcp.srcport, tcp.dstport, udp.srcport, udp.dstport,
        //               time_relative, frame.time, info
        // Use IPv4 if available, else IPv6, else MAC (for ARP/non-IP)
        const src_ip = c[1] || c[3] || c[5] || null;  // IPv4 src or IPv6 src or MAC src
        const dst_ip = c[2] || c[4] || c[6] || null;  // IPv4 dst or IPv6 dst or MAC dst
        return {
          id: parseInt(c[0]) || 0,
          src_ip,
          dst_ip,
          length: parseInt(c[7]) || 0,
          protocol: c[8] || 'UNKNOWN',
          src_port: parseInt(c[9]) || parseInt(c[11]) || null,  // TCP src or UDP src
          dst_port: parseInt(c[10]) || parseInt(c[12]) || null, // TCP dst or UDP dst
          timestamp: parseFloat(c[13]) || 0,
          datetime: c[14] || '',  // Absolute date/time
          info: c[15] || null,    // Info column (Wireshark-style)
        };
      });
      console.log(`[TSharkPaged] → ${packets.length} packets returned`);
      resolve(packets);
    });
  });
}

// ── True packet count ──────────────────────────────────────────
function getTruePacketCount(sessionId) {
  return new Promise((resolve) => {
    const pcapPath = path.join(PCAP_DIR, `${sessionId}.pcap`);
    if (!fs.existsSync(pcapPath)) return resolve(0);
    const cmd = `"${TSHARK_BIN}" -r "${pcapPath}" -T fields -e frame.number`;
    exec(cmd, { timeout: 120000, maxBuffer: 50 * 1024 * 1024 }, (err, stdout) => {
      if (err) return resolve(0);
      const count = stdout.trim().split('\n').filter(l => l.trim()).length;
      console.log(`[TShark] True packet count: ${count}`);
      resolve(count);
    });
  });
}

// ── Get protocol counts efficiently (just protocols, no full packet data) ────────
function getProtocolCounts(sessionId, limit = 2000) {
  return new Promise((resolve) => {
    const pcapPath = path.join(PCAP_DIR, `${sessionId}.pcap`);
    if (!fs.existsSync(pcapPath)) return resolve({ protocols: {}, maxTime: 0 });
    
    // Only extract protocol and time - MUCH smaller output!
    const cmd = `"${TSHARK_BIN}" -r "${pcapPath}" -T fields -E separator=/t -e _ws.col.Protocol -e frame.time_relative -c ${limit}`;
    
    exec(cmd, { timeout: 30000, maxBuffer: 10 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) {
        console.error(`[TShark-Proto] Error: ${err.message}`);
        return resolve({ protocols: {}, maxTime: 0 });
      }
      
      const protocols = {};
      let maxTime = 0;
      const lines = stdout.trim().split('\n').filter(l => l.trim());
      
      for (const line of lines) {
        const [proto, time] = line.split('\t');
        if (proto) {
          const p = proto.toUpperCase();
          protocols[p] = (protocols[p] || 0) + 1;
        }
        if (time) {
          const t = parseFloat(time);
          if (t > maxTime) maxTime = t;
        }
      }
      
      console.log(`[TShark-Proto] Found ${Object.keys(protocols).length} protocols from ${lines.length} packets`);
      resolve({ protocols, maxTime, sampledCount: lines.length });
    });
  });
}

// ── Get ALL unique ports efficiently (just ports, no full packet data) ────────
function getAllPorts(sessionId) {
  return new Promise((resolve) => {
    const pcapPath = path.join(PCAP_DIR, `${sessionId}.pcap`);
    if (!fs.existsSync(pcapPath)) return resolve({});
    
    // Only extract ports - MUCH smaller output than full packet data!
    const cmd = `"${TSHARK_BIN}" -r "${pcapPath}" -T fields -E separator=/t -e tcp.dstport -e udp.dstport`;
    
    console.log(`[TShark-Ports] Extracting all ports from PCAP...`);
    
    exec(cmd, { timeout: 60000, maxBuffer: 100 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) {
        console.error(`[TShark-Ports] Error: ${err.message}`);
        return resolve({});
      }
      
      const portCounts = {};
      const lines = stdout.trim().split('\n').filter(l => l.trim());
      
      for (const line of lines) {
        const [tcpPort, udpPort] = line.split('\t');
        const port = parseInt(tcpPort || udpPort);
        if (port && port > 0) {
          portCounts[port] = (portCounts[port] || 0) + 1;
        }
      }
      
      console.log(`[TShark-Ports] Found ${Object.keys(portCounts).length} unique ports from ${lines.length} packets`);
      resolve(portCounts);
    });
  });
}

function runTsharkStat(sessionId, statCommand) {
  return new Promise((resolve) => {
    const pcapPath = path.join(PCAP_DIR, `${sessionId}.pcap`);
    if (!fs.existsSync(pcapPath)) return resolve('PCAP not found');
    const cmd = `"${TSHARK_BIN}" -r "${pcapPath}" -q -z ${statCommand}`;
    console.log(`[TShark-Stat] Running: ${cmd}`);
    exec(cmd, { timeout: 60000, maxBuffer: 10 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) {
        console.error(`[TShark-Stat] Error: ${err.message}`);
        if (stderr) console.error(`[TShark-Stat] stderr: ${stderr.slice(0, 400)}`);
        return resolve('Stat failed');
      }
      resolve(stdout || '');
    });
  });
}

// ── PRE-COMPUTE EVERYTHING ON UPLOAD ─────────────────────────────────────
// This runs ONCE during upload, so queries are INSTANT later!
async function precomputeAllData(sessionId) {
  console.log(`[PreCompute] Starting for session ${sessionId}...`);
  const startTime = Date.now();
  const pcapPath = path.join(PCAP_DIR, `${sessionId}.pcap`);
  
  if (!fs.existsSync(pcapPath)) {
    console.error(`[PreCompute] PCAP not found: ${pcapPath}`);
    return null;
  }

  const data = {
    // Basic stats
    total_packets: 0,
    total_bytes: 0,
    duration_seconds: 0,
    
    // Protocols
    protocols: {},
    
    // Ports
    ports: {},
    
    // IPs (top talkers)
    top_src_ips: {},
    top_dst_ips: {},
    unique_src_ips: [],
    unique_dst_ips: [],
    
    // DNS
    dns_queries: [],
    dns_responses: [],
    top_domains: {},
    
    // HTTP
    http_hosts: [],
    http_requests: [],
    http_responses: [],
    
    // TLS/HTTPS
    tls_sni: [],
    https_sites: [],
    
    // HTTP Objects (files)
    http_objects: [],
    
    // Conversation stats
    ip_conversations: [],
    
    // Packets (first 500 for dashboard)
    packets: [],
    
    // Raw stats text
    raw_stats: '',
    raw_hierarchy: '',
    
    // Computed at timestamp
    computed_at: new Date().toISOString(),
  };

  try {
    // Run all TShark commands in parallel for speed
    console.log(`[PreCompute] Running TShark commands in parallel...`);
    
    const [
      statsText,
      hierarchyText,
      portCounts,
      protoData,
      trueTotal,
      dnsData,
      httpHostsData,
      tlsSniData,
      ipConversationsData,
    ] = await Promise.all([
      runTsharkStat(sessionId, 'io,stat,0'),
      runTsharkStat(sessionId, 'io,phs'),
      getAllPorts(sessionId),
      getProtocolCounts(sessionId, 5000),
      getTruePacketCount(sessionId),
      // DNS queries
      new Promise((resolve) => {
        const cmd = `"${TSHARK_BIN}" -r "${pcapPath}" -T fields -E separator=/t -e dns.qry.name -e dns.flags.response -e dns.a -e dns.aaaa 2>/dev/null | head -500`;
        exec(cmd, { timeout: 30000 }, (err, stdout) => {
          if (err || !stdout.trim()) return resolve({ queries: [], responses: [], domains: {} });
          const lines = stdout.trim().split('\n').filter(l => l.trim());
          const queries = [];
          const responses = [];
          const domains = {};
          lines.forEach(line => {
            const [qry, isResp, a, aaaa] = line.split('\t');
            if (qry) {
              domains[qry] = (domains[qry] || 0) + 1;
              if (isResp === '1') {
                responses.push({ query: qry, a, aaaa });
              } else {
                queries.push(qry);
              }
            }
          });
          resolve({ queries: [...new Set(queries)], responses, domains });
        });
      }),
      // HTTP hosts
      new Promise((resolve) => {
        const cmd = `"${TSHARK_BIN}" -r "${pcapPath}" -T fields -E separator=/t -e http.host -e http.request.method -e http.request.uri 2>/dev/null | head -200`;
        exec(cmd, { timeout: 30000 }, (err, stdout) => {
          if (err || !stdout.trim()) return resolve({ hosts: [], requests: [] });
          const lines = stdout.trim().split('\n').filter(l => l.trim());
          const hosts = new Set();
          const requests = [];
          lines.forEach(line => {
            const [host, method, uri] = line.split('\t');
            if (host) hosts.add(host);
            if (method && uri) requests.push({ method, uri, host });
          });
          resolve({ hosts: [...hosts], requests });
        });
      }),
      // TLS SNI
      new Promise((resolve) => {
        const cmd = `"${TSHARK_BIN}" -r "${pcapPath}" -T fields -E separator=/t -e tls.handshake.extensions_server_name 2>/dev/null | head -200`;
        exec(cmd, { timeout: 30000 }, (err, stdout) => {
          if (err || !stdout.trim()) return resolve([]);
          const lines = stdout.trim().split('\n').filter(l => l.trim());
          resolve([...new Set(lines)]);
        });
      }),
      // IP conversations (top talkers)
      new Promise((resolve) => {
        const cmd = `"${TSHARK_BIN}" -r "${pcapPath}" -q -z conv,ip 2>/dev/null`;
        exec(cmd, { timeout: 60000 }, (err, stdout) => {
          if (err || !stdout.trim()) return resolve([]);
          const lines = stdout.trim().split('\n');
          const convs = [];
          let inData = false;
          for (const line of lines) {
            if (line.includes('<->')) {
              inData = true;
              const match = line.match(/(\d+\.\d+\.\d+\.\d+)\s*<->\s*(\d+\.\d+\.\d+\.\d+)/);
              if (match) {
                const parts = line.trim().split(/\s+/);
                const bytes = parseInt(parts[parts.length - 2]) || 0;
                convs.push({ src: match[1], dst: match[2], bytes });
              }
            }
          }
          // Sort by bytes and take top 20
          convs.sort((a, b) => b.bytes - a.bytes);
          resolve(convs.slice(0, 20));
        });
      }),
    ]);

    // Parse stats text
    data.raw_stats = statsText;
    data.raw_hierarchy = hierarchyText;
    data.total_packets = trueTotal;
    data.protocols = protoData.protocols;
    data.duration_seconds = Math.round(protoData.maxTime);
    
    // Parse bytes from stats
    const bytesMatch = statsText.match(/(\d+)\s+bytes/i);
    if (bytesMatch) data.total_bytes = parseInt(bytesMatch[1]);

    // Ports
    data.ports = portCounts;

    // DNS
    data.dns_queries = dnsData.queries;
    data.dns_responses = dnsData.responses;
    data.top_domains = dnsData.domains;

    // HTTP
    data.http_hosts = httpHostsData.hosts;
    data.http_requests = httpHostsData.requests;

    // TLS
    data.tls_sni = tlsSniData;
    data.https_sites = tlsSniData.filter(s => s && !s.includes('undefined'));

    // IP conversations
    data.ip_conversations = ipConversationsData;
    
    // Extract unique IPs
    const srcIPs = {};
    const dstIPs = {};
    ipConversationsData.forEach(c => {
      srcIPs[c.src] = (srcIPs[c.src] || 0) + c.bytes;
      dstIPs[c.dst] = (dstIPs[c.dst] || 0) + c.bytes;
    });
    data.top_src_ips = srcIPs;
    data.top_dst_ips = dstIPs;
    data.unique_src_ips = Object.keys(srcIPs);
    data.unique_dst_ips = Object.keys(dstIPs);

    // HTTP Objects from imageStore (already extracted during upload)
    const artifacts = imageStore.get(sessionId);
    if (artifacts && artifacts.size > 0) {
      data.http_objects = Array.from(artifacts.entries()).map(([k, v]) => ({
        filename: v.filename,
        content_type: v.contentType,
        size: v.buffer.length,
        is_image: v.contentType.startsWith('image/'),
      }));
    }

    // ═══════════════════════════════════════════════════════════════
    // FETCH PACKETS FOR DASHBOARD - First 500 packets for quick display
    // ═══════════════════════════════════════════════════════════════
    console.log(`[PreCompute] Fetching packets for dashboard...`);
    const packetsData = await new Promise((resolve) => {
      const cmd = `"${TSHARK_BIN}" -r "${pcapPath}" -T fields -E separator=/t -e frame.number -e ip.src -e ip.dst -e frame.len -e _ws.col.Protocol -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e frame.time_relative 2>/dev/null | head -500`;
      exec(cmd, { timeout: 30000 }, (err, stdout) => {
        if (err || !stdout.trim()) return resolve([]);
        const lines = stdout.trim().split('\n').filter(l => l.trim());
        const packets = lines.map(line => {
          const c = line.split('\t');
          const protocol = (c[4] || '').trim();
          const srcPort = parseInt(c[5]) || parseInt(c[7]) || null;
          const dstPort = parseInt(c[6]) || parseInt(c[8]) || null;
          return {
            id: parseInt(c[0]) || 0,
            src_ip: c[1] || null,
            dst_ip: c[2] || null,
            length: parseInt(c[3]) || 0,
            protocol: detectProtocolFromPort(srcPort, dstPort, protocol),
            src_port: srcPort,
            dst_port: dstPort,
            timestamp: parseFloat(c[9]) || 0,
          };
        });
        resolve(packets);
      });
    });
    data.packets = packetsData;
    console.log(`[PreCompute] Cached ${packetsData.length} packets for dashboard`);

    const elapsed = Date.now() - startTime;
    console.log(`[PreCompute] ✓ Complete in ${elapsed}ms`);
    console.log(`[PreCompute] Stats: ${data.total_packets} packets, ${Object.keys(data.protocols).length} protocols, ${Object.keys(data.ports).length} ports`);
    console.log(`[PreCompute] DNS: ${data.dns_queries.length} queries, HTTP: ${data.http_hosts.length} hosts, TLS: ${data.https_sites.length} SNI`);
    
    return data;
  } catch (e) {
    console.error(`[PreCompute] Error: ${e.message}`);
    return null;
  }
}

// ── Detailed packet dissection ──────────────────────────────────
const DETAIL_FIELDS = [
  'frame.number', 'frame.time', 'frame.time_relative', 'frame.len',
  'eth.src', 'eth.dst', 'eth.type',
  'ip.src', 'ip.dst', 'ip.ttl', 'ip.id', 'ip.proto',
  'ip.flags.df', 'ip.flags.mf',
  'ipv6.src', 'ipv6.dst',
  'tcp.srcport', 'tcp.dstport', 'tcp.seq', 'tcp.ack',
  'tcp.flags.syn', 'tcp.flags.ack', 'tcp.flags.fin', 'tcp.flags.reset',
  'tcp.window_size',
  'udp.srcport', 'udp.dstport', 'udp.length',
  'icmp.type', 'icmp.code',
  'arp.opcode', 'arp.src.hw_mac', 'arp.src.proto_ipv4', 'arp.dst.hw_mac', 'arp.dst.proto_ipv4',
  'dns.qry.name', 'dns.a', 'dns.aaaa', 'dns.flags.response',
  'http.request.method', 'http.request.uri', 'http.host',
  'http.response.code', 'http.response.phrase',
  'tls.handshake.type', 'tls.handshake.extensions_server_name',
  '_ws.col.Info', '_ws.col.Protocol',
];

function getPacketDetails(sessionId, packetNumber) {
  return new Promise((resolve) => {
    const pcapPath = path.join(PCAP_DIR, `${sessionId}.pcap`);
    if (!fs.existsSync(pcapPath)) {
      return resolve({ error: 'PCAP not found' });
    }

    let cmd = `"${TSHARK_BIN}" -r "${pcapPath}" -T fields -E separator=/t`;
    for (const f of DETAIL_FIELDS) cmd += ` -e ${f}`;
    cmd += ` -c ${packetNumber}`;

    console.log(`[TShark-Detail] Getting packet ${packetNumber} (sequential read)`);

    exec(cmd, { timeout: 30000, maxBuffer: 10 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) {
        console.error(`[TShark-Detail] Error: ${err.message}`);
        if (stderr) console.error(`[TShark-Detail] stderr: ${stderr.slice(0, 200)}`);
        return resolve({ error: 'Failed to parse packet - ' + err.message.slice(0, 100) });
      }

      const lines = stdout.trim().split('\n').filter(l => l.trim());
      const targetLine = lines[packetNumber - 1];
      if (!targetLine) {
        console.error(`[TShark-Detail] Packet ${packetNumber} not found. Total lines: ${lines.length}`);
        return resolve({ error: `Packet ${packetNumber} not found. File has ${lines.length} packets.` });
      }

      const values = targetLine.split('\t');
      const fields = {};
      DETAIL_FIELDS.forEach((field, i) => {
        fields[field] = values[i] || null;
      });

      const tree = buildPacketTree(fields);
      console.log(`[TShark-Detail] ✓ Packet ${packetNumber} parsed, ${tree.layers.length} layers`);
      resolve(tree);
    });
  });
}

function buildPacketTree(f) {
  const tree = {
    frame: {
      number: f['frame.number'],
      time: f['frame.time'],
      time_relative: f['frame.time_relative'],
      length: f['frame.len'],
    },
    layers: []
  };

  if (f['eth.src'] || f['eth.dst']) {
    tree.layers.push({
      name: 'Ethernet II',
      protocol: 'eth',
      fields: [
        { key: 'Source MAC', value: f['eth.src'] },
        { key: 'Destination MAC', value: f['eth.dst'] },
        { key: 'Type', value: f['eth.type'] },
      ].filter(v => v.value)
    });
  }

  if (f['ip.src'] || f['ip.dst']) {
    const ipFlags = [];
    if (f['ip.flags.df'] === '1') ipFlags.push('DF (Don\'t Fragment)');
    if (f['ip.flags.mf'] === '1') ipFlags.push('MF (More Fragments)');
    
    tree.layers.push({
      name: 'Internet Protocol Version 4',
      protocol: 'ipv4',
      fields: [
        { key: 'Source IP', value: f['ip.src'] },
        { key: 'Destination IP', value: f['ip.dst'] },
        { key: 'TTL', value: f['ip.ttl'] },
        { key: 'Protocol', value: getProtocolName(f['ip.proto']) },
        { key: 'ID', value: f['ip.id'] ? `0x${parseInt(f['ip.id']).toString(16).padStart(4, '0')}` : null },
        { key: 'Flags', value: ipFlags.length > 0 ? ipFlags.join(', ') : null },
      ].filter(v => v.value)
    });
  } else if (f['ipv6.src'] || f['ipv6.dst']) {
    tree.layers.push({
      name: 'Internet Protocol Version 6',
      protocol: 'ipv6',
      fields: [
        { key: 'Source IP', value: f['ipv6.src'] },
        { key: 'Destination IP', value: f['ipv6.dst'] },
      ].filter(v => v.value)
    });
  }

  if (f['tcp.srcport'] || f['tcp.dstport']) {
    const tcpFlags = [];
    if (f['tcp.flags.syn'] === '1') tcpFlags.push('SYN');
    if (f['tcp.flags.ack'] === '1') tcpFlags.push('ACK');
    if (f['tcp.flags.fin'] === '1') tcpFlags.push('FIN');
    if (f['tcp.flags.reset'] === '1') tcpFlags.push('RST');
    
    tree.layers.push({
      name: 'Transmission Control Protocol',
      protocol: 'tcp',
      fields: [
        { key: 'Source Port', value: f['tcp.srcport'] },
        { key: 'Destination Port', value: f['tcp.dstport'] },
        { key: 'Sequence Number', value: f['tcp.seq'] },
        { key: 'Acknowledgment Number', value: f['tcp.ack'] },
        { key: 'Flags', value: tcpFlags.length > 0 ? `[${tcpFlags.join(', ')}]` : null },
        { key: 'Window Size', value: f['tcp.window_size'] },
      ].filter(v => v.value)
    });
  }

  if (f['udp.srcport'] || f['udp.dstport']) {
    tree.layers.push({
      name: 'User Datagram Protocol',
      protocol: 'udp',
      fields: [
        { key: 'Source Port', value: f['udp.srcport'] },
        { key: 'Destination Port', value: f['udp.dstport'] },
        { key: 'Length', value: f['udp.length'] },
      ].filter(v => v.value)
    });
  }

  if (f['icmp.type']) {
    tree.layers.push({
      name: 'Internet Control Message Protocol',
      protocol: 'icmp',
      fields: [
        { key: 'Type', value: getIcmpType(f['icmp.type']) },
        { key: 'Code', value: f['icmp.code'] },
      ].filter(v => v.value)
    });
  }

  if (f['arp.opcode']) {
    tree.layers.push({
      name: 'Address Resolution Protocol',
      protocol: 'arp',
      fields: [
        { key: 'Operation', value: f['arp.opcode'] === '1' ? 'Request' : 'Reply' },
        { key: 'Sender MAC', value: f['arp.src.hw_mac'] },
        { key: 'Sender IP', value: f['arp.src.proto_ipv4'] },
        { key: 'Target MAC', value: f['arp.dst.hw_mac'] },
        { key: 'Target IP', value: f['arp.dst.proto_ipv4'] },
      ].filter(v => v.value)
    });
  }

  if (f['dns.qry.name']) {
    tree.layers.push({
      name: 'Domain Name System',
      protocol: 'dns',
      fields: [
        { key: 'Type', value: f['dns.flags.response'] === '1' ? 'Response' : 'Query' },
        { key: 'Query Name', value: f['dns.qry.name'] },
        { key: 'Answer (A)', value: f['dns.a'] },
        { key: 'Answer (AAAA)', value: f['dns.aaaa'] },
      ].filter(v => v.value)
    });
  }

  if (f['http.request.method'] || f['http.response.code']) {
    const httpFields = [
      { key: 'Method', value: f['http.request.method'] },
      { key: 'URI', value: f['http.request.uri'] },
      { key: 'Host', value: f['http.host'] },
      { key: 'Status Code', value: f['http.response.code'] },
      { key: 'Status Phrase', value: f['http.response.phrase'] },
    ].filter(v => v.value);
    
    if (httpFields.length > 0) {
      tree.layers.push({
        name: 'Hypertext Transfer Protocol',
        protocol: 'http',
        fields: httpFields
      });
    }
  }

  if (f['tls.handshake.type'] || f['tls.handshake.extensions_server_name']) {
    tree.layers.push({
      name: 'Transport Layer Security',
      protocol: 'tls',
      fields: [
        { key: 'Handshake Type', value: getTlsHandshakeType(f['tls.handshake.type']) },
        { key: 'SNI (Server Name)', value: f['tls.handshake.extensions_server_name'] },
      ].filter(v => v.value)
    });
  }

  if (tree.layers.length === 0 && f['_ws.col.Protocol']) {
    tree.layers.push({
      name: f['_ws.col.Protocol'],
      protocol: f['_ws.col.Protocol'].toLowerCase(),
      fields: [
        { key: 'Protocol', value: f['_ws.col.Protocol'] },
        { key: 'Info', value: f['_ws.col.Info'] || 'No detailed dissection available' },
      ].filter(v => v.value)
    });
  }

  tree.info = f['_ws.col.Info'];
  tree.protocol = f['_ws.col.Protocol'];

  return tree;
}

function getProtocolName(proto) {
  const protocols = {
    '1': 'ICMP', '2': 'IGMP', '6': 'TCP', '17': 'UDP',
    '41': 'IPv6', '47': 'GRE', '50': 'ESP', '51': 'AH',
    '58': 'ICMPv6', '89': 'OSPF', '132': 'SCTP'
  };
  return protocols[proto] || `Protocol ${proto}`;
}

function getIcmpType(type) {
  const types = {
    '0': 'Echo Reply', '3': 'Destination Unreachable', '4': 'Source Quench',
    '5': 'Redirect', '8': 'Echo Request', '11': 'Time Exceeded',
    '12': 'Parameter Problem', '13': 'Timestamp', '14': 'Timestamp Reply'
  };
  return types[type] || `Type ${type}`;
}

function getTlsHandshakeType(type) {
  const types = {
    '1': 'Client Hello', '2': 'Server Hello', '11': 'Certificate',
    '12': 'Server Key Exchange', '14': 'Server Hello Done',
    '16': 'Client Key Exchange', '20': 'Finished'
  };
  return types[type] || `Type ${type}`;
}

// ── Parse TShark PDML Output (XML - captures ALL protocols with hierarchy) ─────────────────────────────
function parsePdmlOutput(pdmlXml, targetPacket) {
  const packets = [];
  
  // Simple XML parsing without external libraries
  const packetMatches = pdmlXml.match(/<packet[^>]*>[\s\S]*?<\/packet>/g) || [];
  
  for (const packetXml of packetMatches) {
    const packet = {
      frame: {},
      layers: [],
      info: ''
    };
    
    // Extract all protocol elements - handle both self-closing and with content
    const protoMatches = packetXml.match(/<proto[^>]*>[\s\S]*?<\/proto>/g) || [];
    
    for (const protoXml of protoMatches) {
      // Get protocol name
      const nameMatch = protoXml.match(/name="([^"]+)"/);
      const protoName = nameMatch ? nameMatch[1] : 'unknown';
      const shownameMatch = protoXml.match(/showname="([^"]+)"/);
      const protoShowName = shownameMatch ? shownameMatch[1] : protoName;
      
      // Skip geninfo - frame protocol has the real data
      if (protoName === 'geninfo') {
        continue;
      }
      
      // Extract ALL fields RECURSIVELY with hierarchy from this protocol
      const fields = extractFieldsHierarchical(protoXml, 0);
      
      // Handle frame protocol specially
      if (protoName === 'frame') {
        // Extract frame-level data for the packet object
        extractFrameData(fields, packet);
        
        packet.layers.push({
          name: 'Frame',
          protocol: 'frame',
          fields: fields
        });
        continue;
      }
      
      // Only add layer if it has fields or is a known protocol
      const knownProtocols = ['eth', 'ip', 'ipv6', 'tcp', 'udp', 'dns', 'http', 'tls', 'dhcp', 
        'dhcpv6', 'mdns', 'ssdp', 'icmp', 'icmpv6', 'arp', 'snmp', 'smb', 'ftp', 'ssh', 'smtp', 
        'ntp', 'igmp', 'stp', 'lldp', 'cdp', 'quic', 'sctp', 'gre', 'vlan', 'ppp', 'wlan'];
      
      if (fields.length > 0 || knownProtocols.includes(protoName)) {
        packet.layers.push({
          name: protoShowName || protoName.toUpperCase(),
          protocol: protoName.toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 10),
          fields: fields.length > 0 ? fields : [{ key: 'Protocol', value: protoShowName || protoName, children: [] }]
        });
      }
    }
    
    // Extract Info column if present (multiple patterns)
    let infoMatch = packetXml.match(/<field[^>]*name="_ws\.col\.Info"[^>]*show="([^"]+)"/);
    if (!infoMatch) {
      infoMatch = packetXml.match(/showname="Info[^"]*"[^>]*show="([^"]+)"/);
    }
    if (infoMatch) {
      packet.info = infoMatch[1];
    }
    
    packets.push(packet);
  }
  
  // Find the target packet
  const target = packets[targetPacket - 1];
  if (!target && packets.length > 0) {
    return packets[packets.length - 1];
  }
  
  return target || { frame: {}, layers: [], info: '' };
}

// Extract frame-level data from parsed fields
function extractFrameData(fields, packet) {
  for (const field of fields) {
    if (field.key === 'Frame Number') packet.frame.number = field.value;
    if (field.key === 'Arrival Time') packet.frame.time = field.value;
    if (field.key === 'Time Since Reference' || field.key === 'Time since reference') packet.frame.time_relative = field.value;
    if (field.key === 'Frame Length') packet.frame.length = field.value;
    // Recursively check children
    if (field.children && field.children.length > 0) {
      extractFrameData(field.children, packet);
    }
  }
}

// Recursively extract fields with hierarchy from a protocol XML block
function extractFieldsHierarchical(xmlBlock, depth) {
  const fields = [];
  const seen = new Set();
  
  // Find all direct child field elements (not nested ones - those are handled recursively)
  // A field can be self-closing <field .../> or have content <field ...>...</field>
  const fieldPattern = /<field\s+([^>]*)(?:\/>|>([\s\S]*?)<\/field>)/g;
  
  let match;
  while ((match = fieldPattern.exec(xmlBlock)) !== null) {
    const attrs = match[1];
    const content = match[2] || '';
    
    // Extract attributes
    const shownameMatch = attrs.match(/showname="([^"]+)"/);
    const showMatch = attrs.match(/show="([^"]+)"/);
    const nameMatch = attrs.match(/name="([^"]+)"/);
    const sizeMatch = attrs.match(/size="([^"]+)"/);
    const posMatch = attrs.match(/pos="([^"]+)"/);
    
    // Skip certain internal fields
    const fieldName = nameMatch ? nameMatch[1] : '';
    if (fieldName.startsWith('_ws.') && !fieldName.includes('Info')) {
      continue;
    }
    
    let key = '';
    let value = '';
    let isExpandable = false;
    
    if (shownameMatch) {
      // Parse "Key: Value" format from showname
      const showname = shownameMatch[1];
      const colonIdx = showname.indexOf(': ');
      if (colonIdx > 0) {
        key = showname.substring(0, colonIdx).trim();
        value = showMatch ? showMatch[1] : showname.substring(colonIdx + 2).trim();
      } else {
        key = showname.trim();
        value = showMatch ? showMatch[1] : '';
      }
    } else if (nameMatch && showMatch) {
      // Fallback to name attribute
      key = fieldName.split('.').pop().replace(/_/g, ' ');
      value = showMatch[1];
    }
    
    // Clean up the key - capitalize first letter
    if (key && key.length > 0) {
      key = key.charAt(0).toUpperCase() + key.slice(1);
    }
    
    // Check if this field has nested child fields
    let children = [];
    if (content && content.includes('<field')) {
      // Recursively extract nested fields
      children = extractFieldsHierarchical(content, depth + 1);
      isExpandable = children.length > 0;
    }
    
    // Filter out empty, duplicate, or very long values
    // Also filter out fields that only contain hex data with no readable value
    const isOnlyHex = value && /^[0-9a-fA-F:\s]+$/.test(value) && value.length > 50;
    
    if (key && value && value.length < 500 && !isOnlyHex) {
      const fieldKey = key + ':' + value.substring(0, 50);
      if (!seen.has(fieldKey)) {
        seen.add(fieldKey);
        fields.push({
          key,
          value,
          children,
          isExpandable,
          depth
        });
      }
    } else if (key && isExpandable && children.length > 0) {
      // Include expandable parent even if it has no value
      const fieldKey = key + ':expandable';
      if (!seen.has(fieldKey)) {
        seen.add(fieldKey);
        fields.push({
          key,
          value: value || '',
          children,
          isExpandable: true,
          depth
        });
      }
    }
  }
  
  return fields;
}

// ── SEARXNG WEB SEARCH FOR PORT INFO ─────────────────────────────────
const portInfoCache = new Map();
const PORT_INFO_CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours

// SearXNG search function (NO AI - pure HTTP requests to your SearXNG instance)
function searxngSearch(query) {
  return new Promise((resolve) => {
    // Ensure JSON format is requested
    const url = `${SEARXNG_URL}/search?q=${encodeURIComponent(query)}&format=json&engines=${SEARXNG_ENGINES}`;
    
    console.log(`[SearXNG] Searching: "${query}" via ${SEARXNG_URL}`);
    
    const req = https.get(url, {
      headers: { 
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'application/json',
        'Accept-Encoding': 'identity'
      },
      timeout: SEARXNG_TIMEOUT_MS
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          // Check if response is HTML (error page)
          if (data.trim().toLowerCase().startsWith('<!doctype') || 
              data.trim().toLowerCase().startsWith('<html')) {
            console.error(`[SearXNG] Received HTML instead of JSON. Response may need format=json enabled on server.`);
            console.error(`[SearXNG] HTML preview: ${data.slice(0, 200)}...`);
            return resolve(null);
          }
          
          const json = JSON.parse(data);
          if (json.results && json.results.length > 0) {
            const results = json.results.slice(0, SEARXNG_MAX_RESULTS).map(r => ({
              title: r.title || '',
              url: r.url || '',
              snippet: r.content || r.snippet || '',
              engine: r.engine || 'unknown'
            }));
            console.log(`[SearXNG] ✓ Found ${results.length} results`);
            resolve(results);
          } else {
            console.log(`[SearXNG] No results found`);
            resolve(null);
          }
        } catch (e) {
          console.error(`[SearXNG] Parse error: ${e.message}`);
          console.error(`[SearXNG] Response preview: ${data.slice(0, 300)}...`);
          resolve(null);
        }
      });
    });
    
    req.on('error', (e) => {
      console.error(`[SearXNG] Request error: ${e.message}`);
      resolve(null);
    });
    
    req.on('timeout', () => {
      req.destroy();
      console.error(`[SearXNG] Timeout`);
      resolve(null);
    });
  });
}

async function searchPortInfo(port) {
  // Check cache first
  const cached = portInfoCache.get(port);
  if (cached && (Date.now() - cached.timestamp) < PORT_INFO_CACHE_TTL) {
    console.log(`[SearXNG] Using cached info for port ${port}`);
    return cached.data;
  }

  try {
    // Search for port information using SearXNG (NO AI!)
    const query = `TCP UDP port ${port} service protocol what is it used for IANA`;
    console.log(`[SearXNG] Searching for port ${port} info...`);
    
    const results = await searxngSearch(query);

    if (results && results.length > 0) {
      // Extract relevant info from search results - PURE LOGIC, NO AI
      const info = parsePortSearchResults(port, results);
      
      // Cache the result
      portInfoCache.set(port, { data: info, timestamp: Date.now() });
      console.log(`[SearXNG] ✓ Found info for port ${port}: ${info.service_name}`);
      return info;
    }
  } catch (e) {
    console.error(`[SearXNG] Error for port ${port}:`, e.message);
  }

  // Return default if search fails
  return {
    service_name: 'unknown',
    description: `Port ${port} - no information found via web search`,
    secure_alternative: 'Investigate manually',
    common_uses: ['Unknown'],
    source: 'none'
  };
}

function parsePortSearchResults(port, results) {
  // Combine all snippets for pattern matching - PURE LOGIC, NO AI
  const combinedText = results.map(r => `${r.title} ${r.snippet}`).join(' ').toLowerCase();
  const firstResult = results[0];
  
  // Common patterns to look for - DATABASE OF KNOWN SERVICES (not AI, just data)
  const servicePatterns = [
    { pattern: /\bhttp\b/i, name: 'http', desc: 'Hypertext Transfer Protocol - web traffic', secure: 'HTTPS (443)', uses: ['Web browsing', 'APIs', 'Web services'] },
    { pattern: /\bhttps\b/i, name: 'https', desc: 'Secure HTTP - encrypted web traffic', secure: 'Already secure', uses: ['Secure web browsing', 'Secure APIs'] },
    { pattern: /\bftp\b/i, name: 'ftp', desc: 'File Transfer Protocol - file transfers', secure: 'SFTP (22) or FTPS (990)', uses: ['File transfers', 'Legacy systems'] },
    { pattern: /\bssh\b/i, name: 'ssh', desc: 'Secure Shell - encrypted remote access', secure: 'Already secure', uses: ['Remote administration', 'Secure file transfer'] },
    { pattern: /\btelnet\b/i, name: 'telnet', desc: 'Telnet - unencrypted remote terminal', secure: 'SSH (22)', uses: ['Legacy systems', 'Network devices'] },
    { pattern: /\bsmtp\b/i, name: 'smtp', desc: 'Simple Mail Transfer Protocol - email', secure: 'SMTPS (465) or STARTTLS', uses: ['Email servers', 'Mail delivery'] },
    { pattern: /\bdns\b/i, name: 'dns', desc: 'Domain Name System - name resolution', secure: 'DNSSEC / DoH', uses: ['Name resolution', 'Service discovery'] },
    { pattern: /\bpop3\b/i, name: 'pop3', desc: 'Post Office Protocol - email retrieval', secure: 'POP3S (995)', uses: ['Email clients'] },
    { pattern: /\bimap\b/i, name: 'imap', desc: 'Internet Message Access Protocol - email', secure: 'IMAPS (993)', uses: ['Email clients', 'Sync email'] },
    { pattern: /\bmysql\b/i, name: 'mysql', desc: 'MySQL Database - relational database', secure: 'Bind localhost + SSL', uses: ['Web applications', 'Databases'] },
    { pattern: /\bpostgresql\b/i, name: 'postgresql', desc: 'PostgreSQL Database', secure: 'Bind localhost + SSL', uses: ['Web applications', 'Databases'] },
    { pattern: /\bmongodb\b/i, name: 'mongodb', desc: 'MongoDB - NoSQL database', secure: 'Bind localhost + Auth', uses: ['Web applications', 'NoSQL storage'] },
    { pattern: /\bredis\b/i, name: 'redis', desc: 'Redis - in-memory data store', secure: 'Bind localhost + AUTH', uses: ['Caching', 'Sessions', 'Queues'] },
    { pattern: /\belasticsearch\b/i, name: 'elasticsearch', desc: 'Elasticsearch - search engine', secure: 'Bind localhost + Auth', uses: ['Search', 'Analytics', 'Logging'] },
    { pattern: /\brdp\b|remote desktop\b/i, name: 'rdp', desc: 'Remote Desktop Protocol', secure: 'VPN + NLA', uses: ['Remote access', 'Remote desktop'] },
    { pattern: /\bvnc\b/i, name: 'vnc', desc: 'Virtual Network Computing - remote desktop', secure: 'VPN + SSH tunnel', uses: ['Remote access', 'Screen sharing'] },
    { pattern: /\bsmb\b|samba\b/i, name: 'smb', desc: 'Server Message Block - file sharing', secure: 'VPN only / Disable if unused', uses: ['File sharing', 'Printers', 'Windows networking'] },
    { pattern: /\bldap\b/i, name: 'ldap', desc: 'Lightweight Directory Access Protocol', secure: 'LDAPS (636)', uses: ['Authentication', 'Active Directory'] },
    { pattern: /\bsnmp\b/i, name: 'snmp', desc: 'Simple Network Management Protocol', secure: 'SNMPv3', uses: ['Network monitoring', 'Device management'] },
    { pattern: /\bdocker\b/i, name: 'docker', desc: 'Docker API - container management', secure: 'Bind localhost + TLS', uses: ['Container management', 'DevOps'] },
    { pattern: /\bkubernetes\b|k8s\b/i, name: 'kubernetes', desc: 'Kubernetes - container orchestration', secure: 'Restrict access + mTLS', uses: ['Container orchestration', 'Cloud native'] },
    { pattern: /\bproxy\b|\bnginx\b|\bapache\b/i, name: 'web-proxy', desc: 'Web server / Reverse proxy', secure: 'Enable HTTPS', uses: ['Web serving', 'Load balancing', 'Reverse proxy'] },
    { pattern: /\bgaming\b|game\b/i, name: 'gaming', desc: 'Gaming service port', secure: 'Verify application', uses: ['Online gaming', 'Game servers'] },
    { pattern: /\btorrent\b|p2p\b|peer\b/i, name: 'p2p', desc: 'Peer-to-peer / Torrent traffic', secure: 'Monitor traffic', uses: ['File sharing', 'P2P applications'] },
    { pattern: /\bntp\b/i, name: 'ntp', desc: 'Network Time Protocol - time synchronization', secure: 'Use authenticated NTP', uses: ['Time sync', 'Clock synchronization'] },
    { pattern: /\bkerberos\b/i, name: 'kerberos', desc: 'Kerberos - network authentication', secure: 'Already secure', uses: ['Authentication', 'SSO'] },
    { pattern: /\bnfs\b/i, name: 'nfs', desc: 'Network File System', secure: 'NFSv4 with Kerberos', uses: ['File sharing', 'Network storage'] },
    { pattern: /\bopenvpn\b/i, name: 'openvpn', desc: 'OpenVPN - VPN protocol', secure: 'Already secure', uses: ['VPN', 'Secure tunneling'] },
    { pattern: /\bwireguard\b/i, name: 'wireguard', desc: 'WireGuard - modern VPN', secure: 'Already secure', uses: ['VPN', 'Secure tunneling'] },
  ];

  // Pattern matching - PURE CODE LOGIC
  for (const { pattern, name, desc, secure, uses } of servicePatterns) {
    if (pattern.test(combinedText)) {
      return {
        service_name: name,
        description: desc,
        secure_alternative: secure,
        common_uses: uses,
        source: 'searxng_web_search',
        search_result: {
          title: firstResult.title,
          url: firstResult.url,
          engine: firstResult.engine
        }
      };
    }
  }

  // If no pattern matched, generate dynamic info based on port range
  let genericName = 'custom-service';
  let genericDesc = `Port ${port} - custom or application-specific service`;
  let genericSecure = 'Investigate application';
  let genericUses = ['Application specific'];
  
  if (port >= 0 && port < 1024) {
    genericName = 'well-known-port';
    genericDesc = `Well-known port ${port} - check IANA registry (iana.org/assignments/service-names-port-numbers)`;
    genericUses = ['System services', 'Standard protocols'];
  } else if (port >= 1024 && port < 49152) {
    genericName = 'registered-port';
    genericDesc = `Registered port ${port} - may be used by specific applications`;
    genericUses = ['Application specific', 'Custom services'];
  } else if (port >= 49152) {
    genericName = 'ephemeral-port';
    genericDesc = `Ephemeral port ${port} - typically used for outbound/client connections`;
    genericSecure = 'Usually client-side, low risk';
    genericUses = ['Client connections', 'Temporary connections'];
  }

  return {
    service_name: genericName,
    description: genericDesc,
    secure_alternative: genericSecure,
    common_uses: genericUses,
    source: 'searxng_web_search',
    search_result: {
      title: firstResult.title,
      url: firstResult.url,
      engine: firstResult.engine
    }
  };
}

// ── IANA Port Database (Built-in, no web search needed) ─────────────
const IANA_PORTS = {
  // Well-known ports (0-1023)
  20: { name: 'ftp-data', desc: 'FTP Data Transfer', risk: 'MEDIUM', secure: 'SFTP (22)' },
  21: { name: 'ftp', desc: 'File Transfer Protocol (Control)', risk: 'HIGH', secure: 'SFTP (22)' },
  22: { name: 'ssh', desc: 'Secure Shell', risk: 'LOW', secure: 'Already secure' },
  23: { name: 'telnet', desc: 'Telnet (Unencrypted)', risk: 'CRITICAL', secure: 'SSH (22)' },
  25: { name: 'smtp', desc: 'Simple Mail Transfer Protocol', risk: 'MEDIUM', secure: 'SMTPS (465)' },
  53: { name: 'dns', desc: 'Domain Name System', risk: 'MEDIUM', secure: 'DNSSEC/DoH' },
  67: { name: 'dhcp', desc: 'DHCP Server', risk: 'LOW', secure: 'N/A' },
  68: { name: 'dhcp', desc: 'DHCP Client', risk: 'LOW', secure: 'N/A' },
  69: { name: 'tftp', desc: 'Trivial FTP (Unencrypted)', risk: 'HIGH', secure: 'SFTP (22)' },
  80: { name: 'http', desc: 'Hypertext Transfer Protocol', risk: 'MEDIUM', secure: 'HTTPS (443)' },
  110: { name: 'pop3', desc: 'Post Office Protocol v3', risk: 'MEDIUM', secure: 'POP3S (995)' },
  119: { name: 'nntp', desc: 'Network News Transfer', risk: 'MEDIUM', secure: 'NNTPS (563)' },
  123: { name: 'ntp', desc: 'Network Time Protocol', risk: 'LOW', secure: 'Authenticated NTP' },
  135: { name: 'rpc', desc: 'Remote Procedure Call', risk: 'HIGH', secure: 'Firewall restrict' },
  137: { name: 'netbios-ns', desc: 'NetBIOS Name Service', risk: 'MEDIUM', secure: 'Disable if unused' },
  138: { name: 'netbios-dgm', desc: 'NetBIOS Datagram', risk: 'MEDIUM', secure: 'Disable if unused' },
  139: { name: 'netbios-ssn', desc: 'NetBIOS Session', risk: 'HIGH', secure: 'SMB over SSH' },
  143: { name: 'imap', desc: 'Internet Message Access Protocol', risk: 'MEDIUM', secure: 'IMAPS (993)' },
  161: { name: 'snmp', desc: 'Simple Network Management Protocol', risk: 'HIGH', secure: 'SNMPv3' },
  162: { name: 'snmp-trap', desc: 'SNMP Trap', risk: 'MEDIUM', secure: 'SNMPv3' },
  389: { name: 'ldap', desc: 'Lightweight Directory Access Protocol', risk: 'MEDIUM', secure: 'LDAPS (636)' },
  443: { name: 'https', desc: 'HTTP Secure', risk: 'LOW', secure: 'Already secure' },
  445: { name: 'smb', desc: 'Server Message Block', risk: 'HIGH', secure: 'VPN only' },
  465: { name: 'smtps', desc: 'SMTP Secure', risk: 'LOW', secure: 'Already secure' },
  514: { name: 'syslog', desc: 'Syslog', risk: 'MEDIUM', secure: 'TLS syslog' },
  587: { name: 'smtp-msa', desc: 'SMTP Message Submission', risk: 'MEDIUM', secure: 'STARTTLS' },
  636: { name: 'ldaps', desc: 'LDAP Secure', risk: 'LOW', secure: 'Already secure' },
  993: { name: 'imaps', desc: 'IMAP Secure', risk: 'LOW', secure: 'Already secure' },
  995: { name: 'pop3s', desc: 'POP3 Secure', risk: 'LOW', secure: 'Already secure' },
  1080: { name: 'socks', desc: 'SOCKS Proxy', risk: 'MEDIUM', secure: 'SOCKS5 + Auth' },
  1433: { name: 'mssql', desc: 'Microsoft SQL Server', risk: 'HIGH', secure: 'Encrypt connections' },
  1434: { name: 'mssql-monitor', desc: 'MS SQL Monitor', risk: 'HIGH', secure: 'Firewall restrict' },
  1521: { name: 'oracle', desc: 'Oracle Database', risk: 'HIGH', secure: 'Encrypt connections' },
  1723: { name: 'pptp', desc: 'Point-to-Point Tunneling', risk: 'MEDIUM', secure: 'OpenVPN/WireGuard' },
  2049: { name: 'nfs', desc: 'Network File System', risk: 'HIGH', secure: 'NFSv4 + Kerberos' },
  3306: { name: 'mysql', desc: 'MySQL Database', risk: 'HIGH', secure: 'Bind localhost + TLS' },
  3389: { name: 'rdp', desc: 'Remote Desktop Protocol', risk: 'HIGH', secure: 'VPN + NLA' },
  5432: { name: 'postgresql', desc: 'PostgreSQL Database', risk: 'HIGH', secure: 'Bind localhost + TLS' },
  5900: { name: 'vnc', desc: 'Virtual Network Computing', risk: 'HIGH', secure: 'VPN + SSH tunnel' },
  5901: { name: 'vnc-1', desc: 'VNC Display 1', risk: 'HIGH', secure: 'VPN + SSH tunnel' },
  6379: { name: 'redis', desc: 'Redis Database', risk: 'HIGH', secure: 'Bind localhost + AUTH' },
  8080: { name: 'http-proxy', desc: 'HTTP Proxy/Alt Port', risk: 'MEDIUM', secure: 'HTTPS (443)' },
  8443: { name: 'https-alt', desc: 'HTTPS Alt Port', risk: 'LOW', secure: 'Already secure' },
  9200: { name: 'elasticsearch', desc: 'Elasticsearch HTTP', risk: 'HIGH', secure: 'Bind localhost + Auth' },
  27017: { name: 'mongodb', desc: 'MongoDB Database', risk: 'HIGH', secure: 'Bind localhost + Auth' },
};

// Services that should trigger CVE lookup (specific products, not generic protocols)
const CVE_SERVICES = ['ssh', 'ftp', 'telnet', 'smb', 'rdp', 'vnc', 'mysql', 'postgresql', 'mongodb', 'redis', 'elasticsearch', 'mssql', 'oracle'];

// ── CVECache ─────────────────────────────────────────────────
const cveCache = new Map();
const CVE_CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours

// ── Fetch CVE data from NVD API ─────────────────────────────────────
function fetchCveData(serviceName, port) {
  return new Promise((resolve) => {
    if (!serviceName || serviceName === 'unknown') return resolve(null);
    
    // Only search CVE for specific services, not generic protocols
    if (!CVE_SERVICES.includes(serviceName)) {
      console.log(`[CVE] Skipping CVE for generic service: ${serviceName}`);
      return resolve(null);
    }
    
    // Check cache first
    const cached = cveCache.get(serviceName);
    if (cached && (Date.now() - cached.timestamp) < CVE_CACHE_TTL) {
      console.log(`[CVE] Using cached data for port ${port} (${serviceName})`);
      return resolve(cached.data);
    }
    
    // More specific CVE search
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(serviceName)}&resultsPerPage=2`;
    console.log(`[CVE] Fetching for port ${port} (${serviceName})...`);
    
    const req = https.get(url, {
      headers: { 'User-Agent': 'PCAP-Analyzer/1.0' },
      timeout: 3000
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (json.vulnerabilities && json.vulnerabilities.length > 0) {
            const result = json.vulnerabilities.map(v => {
              const cve = v.cve;
              const cveId = cve.id;
              const desc = cve.descriptions?.[0]?.value || 'No description';
              const metrics = cve.metrics;
              let cvssScore = null;
              let severity = 'MEDIUM';
              
              if (metrics?.cvssMetricV31) {
                cvssScore = metrics.cvssMetricV31[0].cvssData.baseScore;
                severity = metrics.cvssMetricV31[0].cvssData.baseSeverity;
              } else if (metrics?.cvssMetricV2) {
                cvssScore = metrics.cvssMetricV2[0].cvssData.baseScore;
                severity = metrics.cvssMetricV2[0].baseSeverity || 'MEDIUM';
              }
              
              return {
                cve_id: cveId,
                description: desc.slice(0, 200) + (desc.length > 200 ? '...' : ''),
                cvss_score: cvssScore,
                severity: severity,
                source: 'NVD CVE API'
              };
            });
            
            cveCache.set(serviceName, { data: result, timestamp: Date.now() });
            console.log(`[CVE] Found ${result.length} CVEs for ${serviceName}`);
            resolve(result);
          } else {
            console.log(`[CVE] No CVEs found for ${serviceName}`);
            resolve(null);
          }
        } catch (e) {
          console.error(`[CVE] Parse error: ${e.message}`);
          resolve(null);
        }
      });
    });
    
    req.on('error', (e) => {
      console.error(`[CVE] Request error: ${e.message}`);
      resolve(null);
    });
    
    req.on('timeout', () => {
      req.destroy();
      console.error(`[CVE] Request timeout`);
      resolve(null);
    });
  });
}

// ── Get comprehensive port info (IANA DB first, Web Search fallback, CVE only for specific services) ─
async function getPortIntelligence(port) {
  // Check built-in IANA database first (instant, no network)
  const ianaInfo = IANA_PORTS[port];
  
  if (ianaInfo) {
    console.log(`[PortIntel] Port ${port} found in IANA database: ${ianaInfo.name}`);
    
    // Fetch CVE only for specific services
    let cveData = null;
    if (CVE_SERVICES.includes(ianaInfo.name)) {
      cveData = await fetchCveData(ianaInfo.name, port);
    }
    
    let risk = ianaInfo.risk;
    let reason = ianaInfo.desc;
    
    // If CVE found and it's relevant, update risk
    if (cveData && cveData.length > 0 && cveData[0].cvss_score >= 7) {
      risk = cveData[0].severity.toUpperCase();
      reason = cveData[0].description;
    }
    
    return {
      port: port,
      service_name: ianaInfo.name,
      description: ianaInfo.desc,
      secure_alternative: ianaInfo.secure,
      common_uses: [],
      risk: risk,
      reason: reason,
      cve_id: cveData?.[0]?.cve_id || null,
      cvss_score: cveData?.[0]?.cvss_score || null,
      cve_count: cveData?.length || 0,
      all_cves: cveData || [],
      source: 'IANA Port Registry',
      search_source: 'iana_db',
      search_result: null
    };
  }
  
  // Ephemeral ports (49152-65535) - client-side, LOW risk
  if (port >= 49152 && port <= 65535) {
    console.log(`[PortIntel] Port ${port} is ephemeral (client-side)`);
    return {
      port: port,
      service_name: 'ephemeral',
      description: `Ephemeral port ${port} - client-side temporary connection`,
      secure_alternative: 'Usually client-side, low risk',
      common_uses: ['Client connections', 'Temporary connections'],
      risk: 'LOW',
      reason: 'Ephemeral port - typically used for outbound client connections',
      cve_id: null,
      cvss_score: null,
      cve_count: 0,
      all_cves: [],
      source: 'IANA Port Registry',
      search_source: 'iana_ephemeral',
      search_result: null
    };
  }
  
  // Registered ports (1024-49151) - could be app-specific
  if (port >= 1024 && port < 49152) {
    // Check cache first
    const cached = portInfoCache.get(port);
    if (cached && (Date.now() - cached.timestamp) < PORT_INFO_CACHE_TTL) {
      console.log(`[PortIntel] Using cached info for registered port ${port}`);
      return cached.data;
    }
    
    // Search web for registered port info
    console.log(`[PortIntel] Searching web for registered port ${port}`);
    const webInfo = await searchPortInfo(port);
    
    // Registered ports are generally MEDIUM risk unless known otherwise
    let risk = 'MEDIUM';
    let reason = webInfo.description;
    
    // Only flag as HIGH if it's a known risky service
    const riskyServices = ['telnet', 'ftp', 'vnc', 'smb', 'rdp', 'snmp'];
    if (riskyServices.includes(webInfo.service_name)) {
      risk = 'HIGH';
      reason = `${webInfo.service_name.toUpperCase()} detected on non-standard port`;
    } else if (webInfo.service_name === 'ssh' || webInfo.service_name === 'https') {
      risk = 'LOW';
      reason = `${webInfo.service_name.toUpperCase()} - Secure protocol`;
    }
    
    const result = {
      port: port,
      service_name: webInfo.service_name,
      description: webInfo.description,
      secure_alternative: webInfo.secure_alternative,
      common_uses: webInfo.common_uses,
      risk: risk,
      reason: reason,
      cve_id: null,
      cvss_score: null,
      cve_count: 0,
      all_cves: [],
      source: 'SearXNG Web Search',
      search_source: webInfo.source,
      search_result: webInfo.search_result || null
    };
    
    // Cache the result
    portInfoCache.set(port, { data: result, timestamp: Date.now() });
    return result;
  }
  
  // Default for any other ports
  return {
    port: port,
    service_name: 'unknown',
    description: `Port ${port} - unknown service`,
    secure_alternative: 'Investigate manually',
    common_uses: ['Unknown'],
    risk: 'MEDIUM',
    reason: 'Unknown service - manual investigation recommended',
    cve_id: null,
    cvss_score: null,
    cve_count: 0,
    all_cves: [],
    source: 'none',
    search_source: 'none',
    search_result: null
  };
}

// ── Time-based greeting helper ────────────────────────────────────────
function getTimeBasedGreeting() {
  const hour = new Date().getHours();
  if (hour >= 5 && hour < 12) return 'Good morning';
  if (hour >= 12 && hour < 17) return 'Good afternoon';
  if (hour >= 17 && hour < 21) return 'Good evening';
  return 'Hello';
}

// ── Check if message is a greeting ─────────────────────────────────────
function isGreeting(text) {
  const greetings = ['hello', 'hi', 'hey', 'hola', 'good morning', 'good afternoon', 
    'good evening', 'good night', "what's up", 'whats up', 'howdy', 'greetings',
    'bonjour', 'namaste', 'yo', 'sup'];
  const lower = text.toLowerCase().trim();
  return greetings.some(g => lower === g || lower.startsWith(g + ' ') || lower === g + '!' || lower === g + '.');
}

// ── Check if message is a compliment/thanks ─────────────────────────────
function isCompliment(text) {
  const compliments = ['good job', 'great job', 'well done', 'thanks', 'thank you', 
    'awesome', 'amazing', 'fantastic', 'brilliant', 'excellent', 'you rock',
    'you are amazing', 'you\'re amazing', 'love this', 'love it', 'helpful',
    'you did great', 'nice work', 'great work', 'good work', 'appreciate'];
  const lower = text.toLowerCase();
  return compliments.some(c => lower.includes(c));
}

// ── Check if message is about the agent ────────────────────────────────
function isAboutAgent(text) {
  const aboutAgent = ['who are you', 'what are you', 'what can you do', 'your name',
    'help me', 'how do you work', 'introduce yourself', 'tell me about yourself',
    'what do you do', 'capabilities', 'features', 'how can you help'];
  const lower = text.toLowerCase();
  return aboutAgent.some(a => lower.includes(a));
}

// ── Check if asking for time ───────────────────────────────────────────
function isAskingTime(text) {
  const timePhrases = ['what time', 'current time', 'time is it', 'what\'s the time'];
  const lower = text.toLowerCase();
  return timePhrases.some(t => lower.includes(t));
}

// ── Check if asking how are you ────────────────────────────────────────
function isHowAreYou(text) {
  const phrases = ['how are you', 'how do you feel', 'how\'s it going', 'hows it going',
    'how are things', 'how have you been', 'you doing', 'how is your day'];
  const lower = text.toLowerCase();
  return phrases.some(p => lower.includes(p));
}

// ── Generate natural response using LLM for dynamic conversation ────────
async function generateNaturalResponse(prompt) {
  const lower = prompt.toLowerCase().trim();
  
  // For simple greetings, use quick local response (no LLM needed)
  if (isGreeting(prompt) && lower.split(' ').length <= 3) {
    const greeting = getTimeBasedGreeting();
    return {
      tool: 'chat',
      response: `👋 ${greeting}!\n\n• I'm your PCAP Security Agent\n• I can analyze network traffic and find anomalies\n• Try asking me about: DNS queries, HTTP requests, TLS connections, or suspicious activity\n\nHow can I help you today?`
    };
  }
  
  // For more complex natural conversation, use LLM for dynamic response
  if (isCompliment(prompt) || isHowAreYou(prompt) || isAboutAgent(prompt) || isAskingTime(prompt) || isGreeting(prompt)) {
    // SHORT prompt for fast LLM response
    const llmPrompt = `User: "${prompt}"\nReply with 3 bullets + emojis. Be brief.`;

    const llmResponse = await callLLM(llmPrompt);
    if (llmResponse) {
      return { tool: 'chat', response: llmResponse };
    }
    
    // Fallback to local responses if LLM fails
    if (isCompliment(prompt)) {
      return { tool: 'chat', response: `😊 Thank you so much!\n\n• I'm glad I could help\n• Let me know if you need anything else\n• I'm always here to analyze your PCAP files!` };
    }
    if (isHowAreYou(prompt)) {
      return { tool: 'chat', response: `🤖 I'm doing great, thank you for asking!\n\n• Ready to dig into your PCAP whenever you are\n• What would you like to discover?` };
    }
    if (isAboutAgent(prompt)) {
      return { tool: 'chat', response: `🕵️‍♂️ I'm your PCAP Security Agent!\n\n• 📊 Summarize network captures\n• 🔍 Find specific packets by protocol/IP/port\n• 🛡️ Detect vulnerabilities and risks\n• 🌐 Analyze DNS, HTTP, TLS traffic\n• ⚠️ Detect suspicious activity\n\nI use TShark (Wireshark's CLI) under the hood! 🦈` };
    }
    if (isAskingTime(prompt)) {
      const now = new Date();
      return { tool: 'chat', response: `🕐 Current time: ${now.toLocaleTimeString()}\n\n• Date: ${now.toLocaleDateString()}\n• Timezone: ${Intl.DateTimeFormat().resolvedOptions().timeZone}` };
    }
  }
  
  return null; // Not a natural conversation, fall through to PCAP analysis
}

// ── Local agent ────────────────────────────────────────────────────
function localDynamicAgent(prompt) {
  const l = prompt.toLowerCase();
  
  // ═══════════════════════════════════════════════════════════════
  // Note: Natural conversation is handled separately in generateNaturalResponse
  // This function handles PCAP analysis queries
  // ═══════════════════════════════════════════════════════════════
  
  // ═══════════════════════════════════════════════════════════════
  // PCAP ANALYSIS TOOLS
  // ═══════════════════════════════════════════════════════════════
  const portM = l.match(/port\s*(\d{1,5})/);
  const ipM = l.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
  const macM = l.match(/([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})/i);

  // Summary and overview
  if (l.includes('summary') || l.includes('overview') || l.includes('summarize this') || l.includes('give me a summary')) 
    return { tool: 'stat', stat: 'io,stat,0', response: '📊 **PCAP Summary**\n\nHere\'s an overview of your network capture:' };
  
  // Protocol counts
  if (l.includes('protocol') && (l.includes('used') || l.includes('count') || l.includes('list') || l.includes('what protocol')))
    return { tool: 'stat', stat: 'io,phs', response: '📋 **Protocol Breakdown**\n\nShowing all protocols detected in this capture:' };
  
  if (l.includes('hierarchy')) return { tool: 'stat', stat: 'io,phs', response: '📊 **Protocol Hierarchy**' };
  if (l.includes('timeline')) return { tool: 'stat', stat: 'io,stat,1', response: '📈 **Traffic Timeline**' };
  if (l.includes('top talker') || l.includes('bandwidth') || l.includes('endpoint'))
    return { tool: 'stat', stat: 'conv,ip', response: '🌐 **Top Talkers**\n\nShowing IPs with most traffic:' };
  if (l.includes('expert') || l.includes('warning')) return { tool: 'stat', stat: 'expert', response: '⚠️ **Expert Info & Warnings**' };
  
  // Vulnerability and risk
  if (l.includes('vulnerab') || l.includes('risk') || l.includes('security') || l.includes('threat'))
    return { tool: 'vuln', response: '🛡️ **Security & Vulnerability Analysis**\n\nAnalyzing ports for potential risks:' };
  
  // Suspicious traffic
  if (l.includes('suspicious') || l.includes('anomaly') || l.includes('attack') || l.includes('malicious'))
    return { tool: 'packets', filter: 'tcp.flags.syn == 1 && tcp.flags.ack == 0 || tcp.flags.reset == 1 || icmp', fields: DEFAULT_FIELDS, response: '🚨 **Suspicious Activity Detected**\n\nChecking for:\n• Port scans (SYN floods)\n• Connection resets\n• ICMP anomalies' };
  
  // TCP issues
  if (l.includes('retransmission')) return { tool: 'packets', filter: 'tcp.analysis.retransmission', fields: DEFAULT_FIELDS, response: '🔄 **TCP Retransmissions**' };
  if (l.includes('out of order')) return { tool: 'packets', filter: 'tcp.analysis.out_of_order', fields: DEFAULT_FIELDS, response: '📦 **Out of Order Packets**' };
  if (l.includes('zero window')) return { tool: 'packets', filter: 'tcp.analysis.zero_window', fields: DEFAULT_FIELDS, response: '🪟 **Zero Window Packets**' };
  if (l.includes('duplicate ack')) return { tool: 'packets', filter: 'tcp.analysis.duplicate_ack', fields: DEFAULT_FIELDS, response: '🔃 **Duplicate ACKs**' };
  if (l.includes('rst') || l.includes('reset'))
    return { tool: 'packets', filter: 'tcp.flags.reset == 1', fields: DEFAULT_FIELDS, response: '🔴 **TCP Reset Packets**' };
  if (l.includes('syn flood') || l.includes('port scan'))
    return { tool: 'packets', filter: 'tcp.flags.syn == 1 && tcp.flags.ack == 0', fields: DEFAULT_FIELDS, response: '🔍 **Port Scan Detection**\n\nShowing SYN packets (potential port scan):' };
  
  // HTTP
  if (l.includes('http request') || l.includes('http method'))
    return { tool: 'packets', filter: 'http.request', fields: [...DEFAULT_FIELDS, 'http.request.method', 'http.request.uri', 'http.host'], response: '🌐 **HTTP Requests**' };
  if (l.includes('http status') || l.includes('404') || l.includes('500'))
    return { tool: 'packets', filter: 'http.response', fields: [...DEFAULT_FIELDS, 'http.response.code', 'http.response.phrase'], response: '📊 **HTTP Responses**' };
  if (l.includes('user agent'))
    return { tool: 'packets', filter: 'http.user_agent', fields: [...DEFAULT_FIELDS, 'http.user_agent'], response: '🖥️ **User Agents**' };
  if (l.includes('http') || l.includes('web'))
    return { tool: 'packets', filter: 'http', fields: [...DEFAULT_FIELDS, 'http.request.method', 'http.request.uri'], response: '🌐 **HTTP Traffic**' };
  
  // TLS/HTTPS
  if (l.includes('tls') || l.includes('sni') || l.includes('https site') || l.includes('https'))
    return { tool: 'packets', filter: 'tls.handshake.type == 1', fields: [...DEFAULT_FIELDS, 'tls.handshake.extensions_server_name'], response: '🔒 **TLS/HTTPS Traffic**\n\nShowing TLS Client Hello packets (SNI visible):' };
  if (l.includes('certificate'))
    return { tool: 'packets', filter: 'tls.handshake.type == 11', fields: ['frame.number', 'ip.src', 'ip.dst', 'x509ce.dNSName'], response: '📜 **TLS Certificates**' };
  
  // DNS
  if (l.includes('dns') || l.includes('domain'))
    return { tool: 'packets', filter: 'dns', fields: [...DEFAULT_FIELDS, 'dns.qry.name'], response: '🔍 **DNS Traffic**\n\nShowing DNS queries and responses:' };
  
  // Credentials
  if (l.includes('credential') || l.includes('password') || l.includes('auth'))
    return { tool: 'packets', filter: 'ftp.request.command == "USER" || ftp.request.command == "PASS" || http.authorization', fields: DEFAULT_FIELDS, response: '🔐 **Credential Detection**\n\n⚠️ Checking for plaintext credentials...' };
  
  // HTTP Objects and Files
  if (l.includes('http object') || l.includes('file') || l.includes('image') || l.includes('jpg') || l.includes('png') || l.includes('gif') || l.includes('downloaded') || l.includes('received file') || l.includes('extracted'))
    return { tool: 'http_objects', response: '📁 **HTTP Objects / Extracted Files**\n\nChecking for files extracted from HTTP traffic...' };
  
  // Websites visited
  if (l.includes('website') || l.includes('visited') || l.includes('domain') || l.includes('host'))
    return { tool: 'packets', filter: 'http.host || tls.handshake.extensions_server_name', fields: [...DEFAULT_FIELDS, 'http.host', 'tls.handshake.extensions_server_name'], response: '🌐 **Websites & Domains Visited**\n\nShowing HTTP hosts and TLS SNI:' };
  
  // ARP
  if (l.includes('arp') || l.includes('spoof'))
    return { tool: 'packets', filter: 'arp', fields: ['frame.number', 'arp.opcode', 'arp.src.hw_mac', 'arp.src.proto_ipv4', 'arp.dst.proto_ipv4'], response: '🔗 **ARP Traffic**\n\nChecking for ARP spoofing or anomalies:' };
  
  // DHCP
  if (l.includes('dhcp'))
    return { tool: 'packets', filter: 'dhcp', fields: [...DEFAULT_FIELDS, 'dhcp.option.hostname'], response: '📡 **DHCP Traffic**' };
  
  // ICMP/Ping
  if (l.includes('icmp') || l.includes('ping'))
    return { tool: 'packets', filter: 'icmp', fields: [...DEFAULT_FIELDS, 'icmp.type'], response: '🏓 **ICMP/Ping Traffic**' };
  
  // Broadcast
  if (l.includes('broadcast'))
    return { tool: 'packets', filter: 'eth.dst == ff:ff:ff:ff:ff:ff', fields: DEFAULT_FIELDS, response: '📢 **Broadcast Traffic**' };
  
  // SMB
  if (l.includes('smb'))
    return { tool: 'packets', filter: 'smb || smb2', fields: [...DEFAULT_FIELDS, 'smb2.cmd'], response: '📁 **SMB Traffic**' };
  
  // RDP
  if (l.includes('rdp') || l.includes('remote desktop'))
    return { tool: 'packets', filter: 'tcp.dstport == 3389', fields: DEFAULT_FIELDS, response: '🖥️ **RDP Traffic**' };
  
  // SSH
  if (l.includes('ssh'))
    return { tool: 'packets', filter: 'tcp.dstport == 22', fields: DEFAULT_FIELDS, response: '🔑 **SSH Traffic**' };
  
  // SMTP/Email
  if (l.includes('smtp') || l.includes('email'))
    return { tool: 'packets', filter: 'smtp', fields: [...DEFAULT_FIELDS, 'smtp.req.from'], response: '📧 **SMTP/Email Traffic**' };
  
  // QUIC
  if (l.includes('quic'))
    return { tool: 'packets', filter: 'quic', fields: DEFAULT_FIELDS, response: '⚡ **QUIC Traffic**' };
  
  // TCP
  if (l.includes('tcp'))
    return { tool: 'packets', filter: 'tcp', fields: DEFAULT_FIELDS, response: '🔀 **TCP Traffic**' };
  
  // UDP  
  if (l.includes('udp'))
    return { tool: 'packets', filter: 'udp', fields: DEFAULT_FIELDS, response: '📤 **UDP Traffic**' };
  
  // MAC address lookup
  if (macM)
    return { tool: 'packets', filter: `eth.src == ${macM[0]} || eth.dst == ${macM[0]}`, fields: ['frame.number', 'eth.src', 'eth.dst', 'ip.src', 'ip.dst', '_ws.col.Protocol'], response: `🔍 **Packets with MAC: ${macM[0]}**` };
  
  // Port lookup
  if (portM)
    return { tool: 'packets', filter: `tcp.port == ${portM[1]} || udp.port == ${portM[1]}`, fields: DEFAULT_FIELDS, response: `🔌 **Packets on Port ${portM[1]}**` };
  
  // IP lookup
  if (ipM)
    return { tool: 'packets', filter: `ip.addr == ${ipM[1]}`, fields: DEFAULT_FIELDS, response: `🌐 **Packets involving IP: ${ipM[1]}**` };
  
  // Custom filter
  if (l.includes('filter:'))
    return { tool: 'packets', filter: prompt.split(/filter:/i)[1]?.trim() || '', fields: DEFAULT_FIELDS, response: '🔍 **Custom Filter Results**' };

  // ═══════════════════════════════════════════════════════════════
  // DEFAULT: Unknown query - mark for LLM processing
  // ═══════════════════════════════════════════════════════════════
  return { tool: 'llm', response: '🤔 Let me think about that...' };
}

async function executeTool(agentResult, sessionId) {
  const { tool, stat, filter, fields, response: customResponse } = agentResult;

  // ═══════════════════════════════════════════════════════════════
  // CHAT TOOL - Natural conversation (no TShark needed)
  // ═══════════════════════════════════════════════════════════════
  if (tool === 'chat') {
    return { result: null, response: customResponse || 'Hello! How can I help you?' };
  }

  // ═══════════════════════════════════════════════════════════════
  // LLM TOOL - Unknown query, use LLM to understand and respond
  // ═══════════════════════════════════════════════════════════════
  if (tool === 'llm') {
    return { result: null, response: customResponse || 'Thinking...', needsLLM: true };
  }

  // ═══════════════════════════════════════════════════════════════
  // HTTP OBJECTS TOOL - List extracted files from HTTP traffic
  // ═══════════════════════════════════════════════════════════════
  if (tool === 'http_objects') {
    const artifacts = imageStore.get(sessionId);
    if (!artifacts || artifacts.size === 0) {
      return { 
        result: [], 
        response: '📁 No HTTP objects found in this capture.\n\n• No files were extracted from HTTP traffic\n• This could mean:\n  - No HTTP file downloads in the capture\n  - Files were transmitted over HTTPS (encrypted)\n  - The capture only contains headers, not full file content\n\nTry checking the "Images" tab to see if extraction is still running.' 
      };
    }
    
    const files = Array.from(artifacts.entries()).map(([k, v]) => ({
      filename: v.filename,
      content_type: v.contentType,
      size: v.buffer.length,
      is_image: v.contentType.startsWith('image/'),
    }));
    
    const images = files.filter(f => f.is_image);
    const otherFiles = files.filter(f => !f.is_image);
    
    let response = customResponse || '📁 **HTTP Objects Found**\n\n';
    response += `• **Total files extracted:** ${files.length}\n`;
    response += `• **Images:** ${images.length}\n`;
    response += `• **Other files:** ${otherFiles.length}\n\n`;
    
    if (images.length > 0) {
      response += `**Images found:**\n`;
      images.slice(0, 10).forEach(f => {
        response += `• ${f.filename} (${(f.size / 1024).toFixed(1)} KB, ${f.content_type})\n`;
      });
    }
    
    if (otherFiles.length > 0) {
      response += `\n**Other files:**\n`;
      otherFiles.slice(0, 5).forEach(f => {
        response += `• ${f.filename} (${(f.size / 1024).toFixed(1)} KB, ${f.content_type})\n`;
      });
    }
    
    return { result: files, response };
  }

  // ═══════════════════════════════════════════════════════════════
  // STAT TOOL - TShark statistics
  // ═══════════════════════════════════════════════════════════════
  if (tool === 'stat') {
    const raw_text = await runTsharkStat(sessionId, stat);
    // Build a nice formatted response
    let formattedResponse = customResponse || '📊 **Statistics**\n\n';
    return { result: { raw_text }, response: formattedResponse };
  }

  // ═══════════════════════════════════════════════════════════════
  // VULN TOOL - Vulnerability analysis (uses efficient port extraction)
  // ═══════════════════════════════════════════════════════════════
  if (tool === 'vuln') {
    // Efficiently get ALL ports without loading full packet data
    const portCounts = await getAllPorts(sessionId);
    
    const portEntries = Object.entries(portCounts);
    console.log(`[Vuln] Analyzing ${portEntries.length} ports with web search + CVE API...`);
    
    const vulnResults = await Promise.all(
      portEntries.map(async ([port, count]) => {
        const intel = await getPortIntelligence(parseInt(port));
        return { port: parseInt(port), count, ...intel };
      })
    );
    
    // Build formatted response
    let formattedResponse = customResponse || '🛡️ **Security Analysis**\n\n';
    formattedResponse += `\n• Analyzed ${vulnResults.length} unique ports\n• Used SearXNG Web Search + NVD CVE Database\n\n`;
    
    return { result: vulnResults, response: formattedResponse };
  }

  // ═══════════════════════════════════════════════════════════════
  // PACKETS TOOL - Filter packets
  // ═══════════════════════════════════════════════════════════════
  const packets = await runTshark(sessionId, filter || '', fields || DEFAULT_FIELDS, 200);
  
  // Build formatted response
  let formattedResponse = customResponse || `🔍 **Packet Results**\n\n`;
  formattedResponse += `• Found **${packets.length}** matching packets\n`;
  if (filter) {
    formattedResponse += `• Filter: \`${filter}\`\n`;
  }
  
  return { result: packets, response: formattedResponse };
}

// ── Call Cloudflare Workers AI with STREAMING support ────────────────────────────────
async function callLLMStream(prompt, res, origin) {
  return new Promise((resolve, reject) => {
    const systemPrompt = `You are an expert PCAP Security Agent. You analyze network traffic professionally.

RULES:
• Give DETAILED, INTELLIGENT responses (5-8 bullet points when analyzing data)
• Use emojis sparingly (1-2 per response, not every bullet)
• If user asks multiple questions, answer ALL of them separately
• When analyzing packets, provide specific details: IPs, ports, protocols, packet counts
• Be technical but clear - you're talking to security professionals
• If you see suspicious patterns, explain WHY they're suspicious
• For files/HTTP objects, list them with sizes and types
• Format numbers with commas (e.g., "5,110 packets" not "5110")`;
    
    const postData = JSON.stringify({
      messages: [
        { role: 'system', content: systemPrompt },
        { role: 'user', content: prompt }
      ],
      max_tokens: 800,
      stream: true  // ENABLE STREAMING!
    });
    
    const options = {
      hostname: 'api.cloudflare.com',
      port: 443,
      path: `/client/v4/accounts/${CF_ACCOUNT_ID}/ai/run/${CF_LLM_MODEL}`,
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${CF_API_TOKEN}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData),
      },
      timeout: CF_LLM_TIMEOUT_MS,
    };
    
    console.log(`[LLM-Stream] Starting streaming request to Cloudflare...`);
    
    // Set up SSE headers
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'Access-Control-Allow-Origin': ALLOWED_ORIGIN === '*' ? '*' : ALLOWED_ORIGIN,
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    });
    
    const req = https.request(options, (cfRes) => {
      if (cfRes.statusCode !== 200) {
        console.error(`[LLM-Stream] Error ${cfRes.statusCode}`);
        res.write(`data: ${JSON.stringify({ error: 'LLM request failed' })}\n\n`);
        res.end();
        return resolve(null);
      }
      
      let buffer = '';
      let fullResponse = '';
      
      cfRes.on('data', (chunk) => {
        const text = chunk.toString();
        buffer += text;
        
        // Process SSE lines
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';  // Keep incomplete line in buffer
        
        for (const line of lines) {
          if (line.startsWith('data: ')) {
            const data = line.slice(6).trim();
            if (data === '[DONE]') {
              res.write('data: [DONE]\n\n');
              continue;
            }
            try {
              const json = JSON.parse(data);
              // Cloudflare streaming format: { response: "token" }
              if (json.response) {
                fullResponse += json.response;
                // Forward to client
                res.write(`data: ${JSON.stringify({ token: json.response })}\n\n`);
              }
            } catch (e) {
              // Non-JSON line, skip
            }
          }
        }
      });
      
      cfRes.on('end', () => {
        console.log(`[LLM-Stream] ✓ Complete (${fullResponse.length} chars)`);
        res.write('data: [DONE]\n\n');
        res.end();
        resolve(fullResponse);
      });
      
      cfRes.on('error', (e) => {
        console.error(`[LLM-Stream] Response error: ${e.message}`);
        res.write(`data: ${JSON.stringify({ error: e.message })}\n\n`);
        res.end();
        resolve(null);
      });
    });
    
    req.on('error', (e) => {
      console.error(`[LLM-Stream] Request error: ${e.message}`);
      res.write(`data: ${JSON.stringify({ error: e.message })}\n\n`);
      res.end();
      resolve(null);
    });
    
    req.on('timeout', () => {
      req.destroy();
      console.error(`[LLM-Stream] Timeout`);
      res.write(`data: ${JSON.stringify({ error: 'Timeout' })}\n\n`);
      res.end();
      resolve(null);
    });
    
    req.write(postData);
    req.end();
  });
}

// ── Call Cloudflare Workers AI for intelligent responses (non-streaming) ────────────────────────────────
async function callLLM(prompt, systemOverride = null) {
  return new Promise((resolve, reject) => {
    // Use Cloudflare Workers AI - FAST edge inference!
    const defaultSystem = `You are an expert PCAP Security Agent. You analyze network traffic professionally.

RULES:
• Give DETAILED, INTELLIGENT responses (5-8 bullet points when analyzing data)
• Use emojis sparingly (1-2 per response, not every bullet)
• If user asks multiple questions, answer ALL of them separately
• When analyzing packets, provide specific details: IPs, ports, protocols, packet counts
• Be technical but clear - you're talking to security professionals
• If you see suspicious patterns, explain WHY they're suspicious
• For files/HTTP objects, list them with sizes and types
• Format numbers with commas (e.g., "5,110 packets" not "5110")`;
    
    const postData = JSON.stringify({
      messages: [
        { role: 'system', content: systemOverride || defaultSystem },
        { role: 'user', content: prompt }
      ],
      max_tokens: 600  // Longer, more detailed responses
    });
    
    const options = {
      hostname: 'api.cloudflare.com',
      port: 443,
      path: `/client/v4/accounts/${CF_ACCOUNT_ID}/ai/run/${CF_LLM_MODEL}`,
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${CF_API_TOKEN}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData),
      },
      timeout: CF_LLM_TIMEOUT_MS,
    };
    
    console.log(`[LLM] Calling Cloudflare Workers AI: ${CF_LLM_MODEL}`);
    
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          if (res.statusCode !== 200) {
            console.error(`[LLM] Error ${res.statusCode}: ${data.slice(0, 300)}`);
            return resolve(null);
          }
          const json = JSON.parse(data);
          
          // Cloudflare returns: { result: { response: "..." }, success: true }
          if (json.success && json.result?.response) {
            console.log(`[LLM] ✓ Got response (${json.result.response.length} chars)`);
            resolve(json.result.response);
          } else {
            console.error(`[LLM] Unexpected response format: ${JSON.stringify(json).slice(0, 200)}`);
            resolve(null);
          }
        } catch (e) {
          console.error(`[LLM] Parse error: ${e.message}`);
          console.error(`[LLM] Response preview: ${data.slice(0, 300)}`);
          resolve(null);
        }
      });
    });
    
    req.on('error', (e) => {
      console.error(`[LLM] Request error: ${e.message}`);
      resolve(null);
    });
    
    req.on('timeout', () => {
      req.destroy();
      console.error(`[LLM] Timeout after ${CF_LLM_TIMEOUT_MS}ms`);
      resolve(null);
    });
    
    req.write(postData);
    req.end();
  });
}

// ── Format response with LLM for better readability ────────────────────────────────
async function formatResponseWithLLM(userPrompt, agentResult, toolResult, sessionId) {
  // Build context for LLM based on the tool type - MORE CONTEXT FOR BETTER RESPONSES
  let llmPrompt = '';
  
  // Handle unknown queries (llm tool) - GIVE MORE CONTEXT
  if (agentResult.tool === 'llm') {
    // Get session context for smarter responses
    const sessionData = sessions.get(sessionId);
    const httpObjects = imageStore.get(sessionId);
    const httpFiles = httpObjects ? [...httpObjects.keys()] : [];
    
    llmPrompt = `You have access to a PCAP file with network traffic data.
${sessionData ? `PCAP File: ${sessionData.filename}` : ''}
${httpFiles.length > 0 ? `HTTP Objects Found: ${httpFiles.slice(0, 10).join(', ')}${httpFiles.length > 10 ? ` (${httpFiles.length} total)` : ''}` : 'No HTTP objects extracted yet.'}

User Question: "${userPrompt}"

Answer in detail. If they ask about files/images, check the HTTP Objects list above. If they ask multiple questions, answer ALL of them.`;
  }
  // Handle statistics - MORE DETAIL
  else if (agentResult.tool === 'stat' && toolResult.result?.raw_text) {
    const raw = toolResult.result.raw_text;
    const durationMatch = raw.match(/Duration:\s*([\d.]+)/);
    const framesMatch = raw.match(/(\d+)\s+frames?\s+\|\s+(\d+)\s+bytes/i) || raw.match(/\|\s*(\d+)\s*\|\s*(\d+)/);
    const duration = durationMatch ? durationMatch[1] : '?';
    const frames = framesMatch ? framesMatch[1] : '?';
    const bytes = framesMatch ? framesMatch[2] : '?';
    
    llmPrompt = `PCAP Summary Analysis:
• Total Packets: ${parseInt(frames).toLocaleString()}
• Total Bytes: ${parseInt(bytes).toLocaleString()}
• Duration: ${duration} seconds

Provide a detailed analysis of this network capture. Mention packet rate (packets/sec), data rate, and what kind of traffic this might be.`;
  }
  // Handle protocol hierarchy - MORE DETAIL
  else if (agentResult.tool === 'stat' && agentResult.stat === 'io,phs') {
    const raw = toolResult.result?.raw_text || '';
    const protoMatches = raw.match(/(\w+)\s+frames:(\d+)/g) || [];
    const allProtos = protoMatches.slice(0, 10).map(m => {
      const parts = m.match(/(\w+)\s+frames:(\d+)/);
      return parts ? { proto: parts[1], count: parseInt(parts[2]) } : null;
    }).filter(Boolean);
    
    const totalFrames = allProtos.reduce((sum, p) => sum + p.count, 0);
    const protoList = allProtos.map(p => `${p.proto}: ${p.count.toLocaleString()} packets`).join('\n');
    
    llmPrompt = `Protocol Hierarchy Analysis:
${protoList}

Total analyzed: ${totalFrames.toLocaleString()} packets

Explain what each protocol means and what kind of network activity this represents. Are there any unusual protocols?`;
  }
  // Handle top talkers - MORE DETAIL
  else if (agentResult.tool === 'stat' && agentResult.stat === 'conv,ip') {
    const raw = toolResult.result?.raw_text || '';
    const ipMatches = raw.match(/(\d+\.\d+\.\d+\.\d+)\s*<->\s*(\d+\.\d+\.\d+\.\d+)/g) || [];
    const topIPs = ipMatches.slice(0, 5);
    
    llmPrompt = `Top Talkers (IPs with most traffic):
${topIPs.join('\n')}

Analyze these IP conversations. Which IPs are most active? Could any be suspicious?`;
  }
  // Handle packet results - MORE DETAIL
  else if (agentResult.tool === 'packets' && Array.isArray(toolResult.result)) {
    const count = toolResult.result.length;
    const protocols = [...new Set(toolResult.result.map(p => p.protocol))];
    const protoCounts = {};
    toolResult.result.forEach(p => { protoCounts[p.protocol] = (protoCounts[p.protocol] || 0) + 1; });
    const protoSummary = Object.entries(protoCounts).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([p, c]) => `${p}: ${c}`).join(', ');
    
    // Get unique IPs
    const srcIPs = [...new Set(toolResult.result.map(p => p.src_ip).filter(Boolean))].slice(0, 5);
    const dstIPs = [...new Set(toolResult.result.map(p => p.dst_ip).filter(Boolean))].slice(0, 5);
    
    // Get unique ports
    const ports = [...new Set([...toolResult.result.map(p => p.dst_port), ...toolResult.result.map(p => p.src_port)].filter(Boolean))].slice(0, 10);
    
    llmPrompt = `Packet Analysis Results:
• Total matching packets: ${count.toLocaleString()}
• Protocols: ${protoSummary}
• Source IPs: ${srcIPs.join(', ') || 'N/A'}
• Destination IPs: ${dstIPs.join(', ') || 'N/A'}
• Ports seen: ${ports.join(', ') || 'N/A'}

Summarize this traffic. What's happening? Any patterns or anomalies?`;
  }
  // Handle vulnerability analysis - MORE DETAIL
  else if (agentResult.tool === 'vuln' && Array.isArray(toolResult.result)) {
    const highRisk = toolResult.result.filter(v => v.risk === 'HIGH' || v.risk === 'CRITICAL');
    const mediumRisk = toolResult.result.filter(v => v.risk === 'MEDIUM');
    const lowRisk = toolResult.result.filter(v => v.risk === 'LOW');
    
    const riskyPorts = highRisk.map(v => `Port ${v.port} (${v.service_name}): ${v.reason}`).join('\n');
    
    llmPrompt = `Security Analysis Results:
• Total ports analyzed: ${toolResult.result.length}
• HIGH/CRITICAL risk: ${highRisk.length}
• MEDIUM risk: ${mediumRisk.length}
• LOW risk: ${lowRisk.length}

${highRisk.length > 0 ? `High-risk ports:\n${riskyPorts}` : 'No high-risk ports found.'}

Provide a security assessment. What are the main risks? What should be investigated?`;
  }
  // Default case - MORE CONTEXT
  else {
    llmPrompt = `User asked: "${userPrompt}"

Provide a helpful, detailed response. If this is about the PCAP file, explain what you found.`;
  }

  const llmResponse = await callLLM(llmPrompt);
  return llmResponse || toolResult.response;
}

// ── INSTANT QUERY - ALWAYS use LLM with full pre-computed data (NO TShark!) ────────
function getInstantQueryResult(prompt, data, sessionId) {
  // Just return llm tool - the LLM will handle ALL queries with full context
  // This ensures CONSISTENT, accurate answers without hallucination
  return {
    tool: 'llm',
    response: 'Analyzing with pre-computed data...',
    data: null
  };
}

// ── Build LLM prompt from pre-computed data ────────────────────────────────
function buildLLMPromptFromPrecomputed(prompt, data) {
  // Build COMPLETE context for LLM with ALL data - no truncation!
  const allProtocols = Object.entries(data.protocols).sort((a, b) => b[1] - a[1]);
  const allPorts = Object.entries(data.ports).sort((a, b) => b[1] - a[1]);
  const allDomains = Object.entries(data.top_domains || {}).sort((a, b) => b[1] - a[1]);
  
  let context = `You are analyzing a PCAP network capture. Here is the COMPLETE data:

═══════════════════════════════════════════════════════════════
📊 BASIC STATISTICS
═══════════════════════════════════════════════════════════════
• Total Packets: ${data.total_packets.toLocaleString()}
• Total Bytes: ${(data.total_bytes / 1024 / 1024).toFixed(2)} MB
• Duration: ${data.duration_seconds} seconds
• Packet Rate: ${data.duration_seconds > 0 ? (data.total_packets / data.duration_seconds).toFixed(1) : 'N/A'} packets/sec

═══════════════════════════════════════════════════════════════
📋 ALL PROTOCOLS (${allProtocols.length} total)
═══════════════════════════════════════════════════════════════
${allProtocols.map(([p, c]) => `• ${p}: ${c.toLocaleString()} packets`).join('\n')}

═══════════════════════════════════════════════════════════════
🔌 ALL PORTS (${allPorts.length} total)
═══════════════════════════════════════════════════════════════
${allPorts.slice(0, 30).map(([p, c]) => `• Port ${p}: ${c} packets`).join('\n')}
${allPorts.length > 30 ? `... and ${allPorts.length - 30} more ports` : ''}

═══════════════════════════════════════════════════════════════
🌐 IP CONVERSATIONS (Top 20 by bytes)
═══════════════════════════════════════════════════════════════
${data.ip_conversations.slice(0, 20).map(c => `• ${c.src} → ${c.dst} (${(c.bytes / 1024).toFixed(1)} KB)`).join('\n')}

═══════════════════════════════════════════════════════════════
🔍 ALL DNS QUERIES (${data.dns_queries.length} total)
═══════════════════════════════════════════════════════════════
${data.dns_queries.length > 0 ? data.dns_queries.join('\n') : 'No DNS queries found'}

═══════════════════════════════════════════════════════════════
🌐 TOP DOMAINS BY QUERY COUNT
═══════════════════════════════════════════════════════════════
${allDomains.slice(0, 20).map(([d, c]) => `• ${d}: ${c} queries`).join('\n')}

═══════════════════════════════════════════════════════════════
🌐 ALL HTTP HOSTS (${data.http_hosts.length} total)
═══════════════════════════════════════════════════════════════
${data.http_hosts.length > 0 ? data.http_hosts.join('\n') : 'No HTTP hosts found'}

═══════════════════════════════════════════════════════════════
🔒 ALL HTTPS/TLS SITES (${data.https_sites.length} total)
═══════════════════════════════════════════════════════════════
${data.https_sites.filter(s => s).length > 0 ? data.https_sites.filter(s => s).join('\n') : 'No HTTPS sites found'}

═══════════════════════════════════════════════════════════════
📁 ALL HTTP OBJECTS/FILES (${data.http_objects.length} total)
═══════════════════════════════════════════════════════════════
${data.http_objects.length > 0 ? data.http_objects.map(f => `• ${f.filename} (${(f.size / 1024).toFixed(1)} KB, ${f.content_type})`).join('\n') : 'No HTTP objects found'}

═══════════════════════════════════════════════════════════════
USER QUESTION: "${prompt}"
═══════════════════════════════════════════════════════════════

INSTRUCTIONS:
1. Answer the user's question using ONLY the data above - DO NOT MAKE UP DATA
2. Be specific: use actual numbers, domain names, IP addresses from the data
3. If asked about domains/websites, list the ACTUAL domains from the DNS/HTTP/HTTPS sections
4. If asked about files/images, list the ACTUAL filenames from the HTTP OBJECTS section
5. Format your response clearly with bullet points
6. If something is not in the data, say "No [X] found in this PCAP" instead of making it up`;

  return context;
}

// ── Main server ────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const url = req.url || '/';
  const method = req.method || 'GET';
  const origin = req.headers['origin'] || '';
  const enc = req.headers['accept-encoding'] || '';
  const clientIp = req.headers['x-forwarded-for']?.split(',')[0].trim()
    || req.socket.remoteAddress || 'unknown';

  const respond = (data, status = 200) => json(res, data, status, origin, enc);

  if (method === 'OPTIONS') { res.writeHead(204, getCorsHeaders(origin)); return res.end(); }

  if (url === '/ping' || url === '/pcap/ping') {
    res.writeHead(200, { 'Content-Type': 'text/plain', ...getCorsHeaders(origin) });
    return res.end('pong');
  }

  if (url === '/pcap/health') {
    return respond({ status: 'ok', engine: 'TShark + IANA Port DB + SearXNG + NVD CVE + Llama-3-8B', sessions: sessions.size, note: 'AI-powered by Llama-3-8B via Cloudflare Workers AI!' });
  }

  // ── Upload ─────────────────────────────────────────────────
  if (url === '/pcap/upload' && method === 'POST') {
    if (!checkRateLimit(clientIp, RATE_UPLOAD))
      return respond({ error: 'Too many uploads. Limit: 10/min.' }, 429);

    try {
      const ct = req.headers['content-type'] || '';
      const bm = ct.match(/boundary=(?:"([^"]+)"|([^;,\s]+))/);
      const boundary = bm?.[1] ?? bm?.[2];
      if (!boundary) return respond({ error: 'Missing multipart boundary' }, 400);

      const body = await parseBody(req);

      const MAX_BYTES = 200 * 1024 * 1024;
      if (body.length > MAX_BYTES)
        return respond({ error: `File too large (${(body.length / 1024 / 1024).toFixed(0)} MB). Max 200 MB.` }, 413);

      const parts = parseMultipart(body, boundary);
      let fileData = null, filename = 'upload.pcap';
      for (const p of parts) {
        const m = p.headers.match(/filename\*?=(?:UTF-8''|")?([^";\r\n]+)/i);
        if (m) { filename = decodeURIComponent(m[1].replace(/"/g, '').trim()); fileData = p.data; }
      }
      if (!fileData) return respond({ error: 'No file found in upload' }, 400);

      const session_id = `session-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
      const pcapPath = path.join(PCAP_DIR, `${session_id}.pcap`);
      const exportDir = path.join(EXPORT_DIR, session_id);

      fs.writeFileSync(pcapPath, fileData);
      console.log(`[Upload] ${filename} → ${pcapPath} (${(fileData.length / 1024 / 1024).toFixed(1)} MB)`);

      fs.mkdirSync(exportDir, { recursive: true });
      exec(`"${TSHARK_BIN}" -r "${pcapPath}" --export-objects http,"${exportDir}"`, { timeout: 120000 }, (err, _out, stderr) => {
        if (err) { console.error(`[Export] Failed: ${err.message}`); if (stderr) console.error(stderr.slice(0, 300)); return; }
        try {
          const EXT_CT = {
            '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png',
            '.gif': 'image/gif', '.webp': 'image/webp', '.svg': 'image/svg+xml',
            '.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript',
            '.json': 'application/json', '.pdf': 'application/pdf',
          };
          const artifacts = new Map();
          for (const file of fs.readdirSync(exportDir)) {
            const fp = path.join(exportDir, file);
            const ext = path.extname(file).toLowerCase();
            artifacts.set(encodeURIComponent(file), {
              buffer: fs.readFileSync(fp),
              contentType: EXT_CT[ext] || 'application/octet-stream',
              filename: file,
            });
          }
          imageStore.set(session_id, artifacts);
          console.log(`[Export] ${artifacts.size} HTTP objects extracted`);
        } catch (e) { console.error(`[Export] Read error: ${e.message}`); }
      });

      sessions.set(session_id, { session_id, filename, created_at: Date.now() });

      if (sessions.size > 10) {
        let evictKey = null, oldestAge = -1;
        for (const [k, s] of sessions) {
          if (k === session_id) continue;
          const age = Date.now() - s.created_at;
          if (age > oldestAge) { oldestAge = age; evictKey = k; }
        }
        if (evictKey) sessions.delete(evictKey);
      }

      // ═══════════════════════════════════════════════════════════════
      // QUICK STATS FIRST - Return response FAST, pre-compute in background!
      // ═══════════════════════════════════════════════════════════════
      console.log(`[Upload] Getting quick stats for ${session_id}...`);
      
      // Get basic stats QUICKLY (just packet count and protocols)
      const [quickTotal, quickProtos, quickDuration] = await Promise.all([
        getTruePacketCount(session_id),
        getProtocolCounts(session_id, 2000),  // Sample 2000 packets for protocols
        new Promise((resolve) => {
          const cmd = `"${TSHARK_BIN}" -r "${pcapPath}" -T fields -e frame.time_relative 2>/dev/null | tail -1`;
          exec(cmd, { timeout: 10000 }, (err, stdout) => {
            resolve(parseFloat(stdout.trim()) || 0);
          });
        }),
      ]);
      
      console.log(`[Upload] Quick stats: ${quickTotal} packets, ${Object.keys(quickProtos || {}).length} protocols`);
      
      // Update session with quick stats
      const sessionData = sessions.get(session_id);
      if (sessionData) {
        sessionData.total_packets = quickTotal || 0;
        sessionData.precomputed = false;  // Mark as not yet pre-computed
        sessions.set(session_id, sessionData);
      }

      // ═══════════════════════════════════════════════════════════════
      // RETURN RESPONSE IMMEDIATELY - Don't wait for full pre-computation!
      // ═══════════════════════════════════════════════════════════════
      respond({
        session_id,
        summary: {
          total_packets: quickTotal || 0,
          protocols: quickProtos || {},
          duration_seconds: Math.round(quickDuration) || 0,
          time_range: { start: 0, end: Math.round(quickDuration) || 0 },
          raw_text: '',
        },
        precomputed: {
          status: 'computing',  // Tell frontend we're still computing
          dns_queries: 0,
          http_hosts: 0,
          https_sites: 0,
          http_objects: 0,
          unique_ips: 0,
          ports: 0,
        },
      });
      
      // ═══════════════════════════════════════════════════════════════
      // PRE-COMPUTE IN BACKGROUND - Runs ONCE, queries are INSTANT later!
      // ═══════════════════════════════════════════════════════════════
      console.log(`[Upload] Starting BACKGROUND pre-computation for ${session_id}...`);
      
      // Run pre-computation in background (don't await!)
      precomputeAllData(session_id).then((precomputed) => {
        if (precomputed) {
          // Store pre-computed data for instant queries
          precomputedData.set(session_id, precomputed);
          console.log(`[Upload] ✓ Background pre-computation complete!`);
          console.log(`[Upload] ✓ Data: ${precomputed.total_packets} packets, ${precomputed.dns_queries?.length || 0} DNS, ${precomputed.http_hosts?.length || 0} HTTP hosts`);
          
          // Update session to mark pre-computation complete
          const sd = sessions.get(session_id);
          if (sd) {
            sd.precomputed = true;
            sd.total_packets = precomputed.total_packets;
            sessions.set(session_id, sd);
          }
        } else {
          console.warn(`[Upload] ⚠ Background pre-computation had issues.`);
        }
      }).catch(err => {
        console.error(`[Upload] Background pre-computation error: ${err.message}`);
      });
      
      return;  // Response already sent!
    } catch (e) {
      console.error(`[Upload] Error: ${e.message}`);
      return respond({ error: e.message }, 500);
    }
  }

  // ── Packets ────────────────────────────────────────────────
  if (url.startsWith('/pcap/packets') && method === 'GET') {
    try {
      const q = getQuery(url);
      if (!isValidSessionId(q.session_id)) return respond({ error: 'Invalid session_id' }, 400);

      const page = Math.max(1, parseInt(q.page || '1'));
      const per_page = Math.min(100, parseInt(q.per_page || '50'));  // Reduced from 200 to 100
      const skip = (page - 1) * per_page;

      // Check if we have pre-computed packets
      const precomputed = precomputedData.get(q.session_id);
      if (precomputed?.packets?.length) {
        console.log(`[Packets] Using pre-computed packets for ${q.session_id}`);
        const start = skip;
        const end = skip + per_page;
        const packets = precomputed.packets.slice(start, end);
        return respond({ packets, total: precomputed.total_packets, page, per_page });
      }

      // Fall back to TShark with timeout protection
      const packets = await Promise.race([
        runTsharkPaged(q.session_id, skip, per_page),
        new Promise((_, reject) => setTimeout(() => reject(new Error('TShark timeout')), 15000))
      ]);

      const sessionData = sessions.get(q.session_id);
      const realTotal = sessionData?.total_packets ?? packets.length;

      return respond({ packets, total: realTotal, page, per_page });
    } catch (err) {
      console.error(`[Packets] Error: ${err.message}`);
      // Return empty result instead of erroring
      return respond({ packets: [], total: 0, page: 1, per_page: 50, error: 'Still processing. Refresh in a few seconds.' });
    }
  }

  // ── Detailed Packet Dissection ────────────────────────────────
  if (url.startsWith('/pcap/packet-detail') && method === 'GET') {
    const q = getQuery(url);
    if (!isValidSessionId(q.session_id)) return respond({ error: 'Invalid session_id' }, 400);
    
    const packetNum = parseInt(q.packet_number);
    if (!packetNum || packetNum < 1) return respond({ error: 'Invalid packet_number' }, 400);
    
    if (!fs.existsSync(path.join(PCAP_DIR, `${q.session_id}.pcap`)))
      return respond({ error: 'Session expired or not found' }, 404);

    const details = await getPacketDetails(q.session_id, packetNum);
    return respond(details);
  }

  // ── Full Wireshark-style Packet Dissection (TShark PDML) ────────────────────────
  if (url.startsWith('/pcap/packet-dissection') && method === 'GET') {
    const q = getQuery(url);
    if (!isValidSessionId(q.session_id)) return respond({ error: 'Invalid session_id' }, 400);
    
    const packetNum = parseInt(q.packet_number);
    if (!packetNum || packetNum < 1) return respond({ error: 'Invalid packet_number' }, 400);
    
    const pcapPath = path.join(PCAP_DIR, `${q.session_id}.pcap`);
    if (!fs.existsSync(pcapPath)) return respond({ error: 'Session expired or not found' }, 404);

    // Use TShark's PDML output for COMPLETE protocol dissection (XML format - captures ALL protocols)
    const cmd = `"${TSHARK_BIN}" -r "${pcapPath}" -T pdml -c ${packetNum}`;
    console.log(`[TShark-Dissect] Getting PDML dissection for packet ${packetNum}`);
    
    exec(cmd, { timeout: 30000, maxBuffer: 10 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) {
        console.error(`[TShark-Dissect] Error: ${err.message}`);
        return respond({ error: 'Failed to dissect packet' }, 500);
      }
      
      // Parse the PDML XML output into structured layers
      const dissection = parsePdmlOutput(stdout, packetNum);
      console.log(`[TShark-Dissect] ✓ Parsed ${dissection.layers?.length || 0} layers`);
      return respond(dissection);
    });
    return;
  }

  // ── Packets with Info column ────────────────────────────────
  if (url.startsWith('/pcap/packets-detailed') && method === 'GET') {
    const q = getQuery(url);
    if (!isValidSessionId(q.session_id)) return respond({ error: 'Invalid session_id' }, 400);

    const page = Math.max(1, parseInt(q.page || '1'));
    const per_page = Math.min(200, parseInt(q.per_page || '50'));
    const skip = (page - 1) * per_page;

    const pcapPath = path.join(PCAP_DIR, `${q.session_id}.pcap`);
    if (!fs.existsSync(pcapPath)) return respond({ packets: [], total: 0, page, per_page });

    // Use TShark's tabular output format which includes Info column properly
    // -P prints packet summary with columns, -T json gives us structured data
    let cmd = `"${TSHARK_BIN}" -r "${pcapPath}" -T json -c ${skip + per_page}`;
    
    console.log(`[TSharkDetailed] Running JSON output for packets`);

    exec(cmd, { timeout: 60000, maxBuffer: 100 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) {
        console.error(`[TSharkDetailed] Error: ${err.message}`);
        if (stderr) console.error(`[TSharkDetailed] stderr: ${stderr.slice(0, 300)}`);
        return respond({ packets: [], total: 0, page, per_page });
      }

      try {
        const jsonData = JSON.parse(stdout);
        const pageData = jsonData.slice(skip);
        
        const packets = pageData.map((pkt, idx) => {
          const layers = pkt._source?.layers || {};
          const frame = layers.frame || {};
          
          // Extract source IP (IPv4 or IPv6)
          let src_ip = null;
          let dst_ip = null;
          if (layers.ip) {
            src_ip = layers.ip['ip.src'] || null;
            dst_ip = layers.ip['ip.dst'] || null;
          } else if (layers.ipv6) {
            src_ip = layers.ipv6['ipv6.src'] || null;
            dst_ip = layers.ipv6['ipv6.dst'] || null;
          }
          
          // Extract ports
          let src_port = null;
          let dst_port = null;
          if (layers.tcp) {
            src_port = parseInt(layers.tcp['tcp.srcport']) || null;
            dst_port = parseInt(layers.tcp['tcp.dstport']) || null;
          } else if (layers.udp) {
            src_port = parseInt(layers.udp['udp.srcport']) || null;
            dst_port = parseInt(layers.udp['udp.dstport']) || null;
          }
          
          // Extract protocol
          let protocol = 'UNKNOWN';
          if (layers.tcp) protocol = 'TCP';
          else if (layers.udp) protocol = 'UDP';
          else if (layers.icmp || layers.icmpv6) protocol = 'ICMP';
          else if (layers.arp) protocol = 'ARP';
          else if (layers.dns || layers.mdns) protocol = layers.mdns ? 'MDNS' : 'DNS';
          else if (layers.http) protocol = 'HTTP';
          else if (layers.tls || layers.ssl) protocol = 'TLS';
          else if (layers.dhcp || layers.dhcpv6) protocol = layers.dhcpv6 ? 'DHCPv6' : 'DHCP';
          else if (layers.ssh) protocol = 'SSH';
          else if (layers.ftp) protocol = 'FTP';
          else if (layers.ssdp) protocol = 'SSDP';
          else if (layers.ntp) protocol = 'NTP';
          else if (layers.igmp) protocol = 'IGMP';
          if (frame['frame.protocols']) {
            const protocols = frame['frame.protocols'].split(':');
            if (protocols.length > 0 && protocol === 'UNKNOWN') {
              protocol = protocols[protocols.length - 1].toUpperCase();
            }
          }
          
          // Extract Info - this is the key part!
          let info = '';
          // Try multiple sources for Info
          if (layers.dns || layers.mdns) {
            const dnsLayer = layers.dns || layers.mdns;
            if (dnsLayer['dns.qry.name']) {
              info = dnsLayer['dns.flags.response'] === '1' ? 
                `Response: ${dnsLayer['dns.qry.name']}` : 
                `Query: ${dnsLayer['dns.qry.name']}`;
            }
            if (dnsLayer['dns.a']) info += ` A: ${dnsLayer['dns.a']}`;
            if (dnsLayer['dns.aaaa']) info += ` AAAA: ${dnsLayer['dns.aaaa']}`;
          } else if (layers.dhcpv6) {
            info = layers.dhcpv6['dhcpv6.msg_type'] || 'DHCPv6';
            if (layers.dhcpv6['dhcpv6.transaction_id']) {
              info += ` XID: ${layers.dhcpv6['dhcpv6.transaction_id']}`;
            }
          } else if (layers.http) {
            if (layers.http['http.request.method']) {
              info = `${layers.http['http.request.method']} ${layers.http['http.request.uri'] || '/'}`;
            } else if (layers.http['http.response.code']) {
              info = `HTTP ${layers.http['http.response.code']} ${layers.http['http.response.phrase'] || ''}`;
            }
          } else if (layers.tcp) {
            const flags = [];
            if (layers.tcp['tcp.flags.syn'] === '1') flags.push('SYN');
            if (layers.tcp['tcp.flags.ack'] === '1') flags.push('ACK');
            if (layers.tcp['tcp.flags.fin'] === '1') flags.push('FIN');
            if (layers.tcp['tcp.flags.reset'] === '1') flags.push('RST');
            if (flags.length > 0) info = `[${flags.join(', ')}]`;
            if (layers.tcp['tcp.seq']) info += ` Seq=${layers.tcp['tcp.seq']}`;
            if (layers.tcp['tcp.ack']) info += ` Ack=${layers.tcp['tcp.ack']}`;
          } else if (layers.udp) {
            info = `Len=${layers.udp['udp.length'] || ''}`;
          } else if (layers.icmp || layers.icmpv6) {
            const icmp = layers.icmp || layers.icmpv6;
            info = `Type=${icmp['icmp.type'] || icmp['icmpv6.type'] || ''}`;
          } else if (layers.arp) {
            const opcode = layers.arp['arp.opcode'];
            const senderIP = layers.arp['arp.src.proto_ipv4'] || '';
            const targetIP = layers.arp['arp.dst.proto_ipv4'] || '';
            const senderMAC = layers.arp['arp.src.hw_mac'] || '';
            
            if (opcode === '1') {
              // ARP Request - "Who has X? Tell Y"
              if (targetIP) {
                info = `Who has ${targetIP}?`;
                if (senderIP) info += ` Tell ${senderIP}`;
              } else {
                info = 'ARP Request';
              }
            } else if (opcode === '2') {
              // ARP Reply - "X is at Y"
              if (senderIP && senderMAC) {
                info = `${senderIP} is at ${senderMAC}`;
              } else {
                info = 'ARP Reply';
              }
            } else {
              info = `ARP (opcode ${opcode || '?'})`;
            }
          }
          
          // Build packet object
          return {
            id: parseInt(frame['frame.number']) || (skip + idx + 1),
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            length: parseInt(frame['frame.len']) || 0,
            timestamp: parseFloat(frame['frame.time_relative']) || 0,
            datetime: frame['frame.time'] || '',
            info: info.trim(),
          };
        });

        const sessionData = sessions.get(q.session_id);
        const realTotal = sessionData?.total_packets ?? jsonData.length;

        return respond({ packets, total: realTotal, page, per_page });
      } catch (parseErr) {
        console.error(`[TSharkDetailed] JSON parse error: ${parseErr.message}`);
        return respond({ packets: [], total: 0, page, per_page });
      }
    });
    return;
  }

  // ── Port Intelligence with Web Search + CVE ────────────────────────
  if (url.startsWith('/pcap/vulnerabilities') && method === 'GET') {
    const q = getQuery(url);
    if (!isValidSessionId(q.session_id)) return respond({ error: 'Invalid session_id' }, 400);
    if (!fs.existsSync(path.join(PCAP_DIR, `${q.session_id}.pcap`)))
      return respond({ error: 'Session expired or not found' }, 404);

    // Efficiently get ALL ports without loading full packet data
    const portCounts = await getAllPorts(q.session_id);
    
    const portEntries = Object.entries(portCounts);
    console.log(`[PortIntel] Analyzing ${portEntries.length} unique ports with Web Search + NVD API...`);
    
    // Process ports in parallel (but limit concurrency to avoid rate limits)
    const BATCH_SIZE = 5;
    const alerts = [];
    
    for (let i = 0; i < portEntries.length; i += BATCH_SIZE) {
      const batch = portEntries.slice(i, i + BATCH_SIZE);
      const batchResults = await Promise.all(
        batch.map(async ([port, count]) => {
          const intel = await getPortIntelligence(parseInt(port));
          return {
            port: parseInt(port),
            count,
            risk: intel.risk,
            reason: intel.reason,
            cve_id: intel.cve_id,
            cvss_score: intel.cvss_score,
            source: intel.source,
            cve_count: intel.cve_count,
            all_cves: intel.all_cves,
            service_name: intel.service_name,
            description: intel.description,
            secure_alternative: intel.secure_alternative,
            common_uses: intel.common_uses,
          };
        })
      );
      alerts.push(...batchResults);
      console.log(`[PortIntel] Processed ${Math.min(i + BATCH_SIZE, portEntries.length)}/${portEntries.length} ports`);
    }
    
    const summary = { critical: 0, high: 0, medium: 0, low: 0, web_search: true, cve_api: true };
    for (const a of alerts) {
      const r = a.risk.toLowerCase();
      if (summary[r] !== undefined) summary[r]++;
    }
    
    return respond({ 
      alerts, 
      summary,
      data_sources: {
        port_info: 'Web Search API (real-time)',
        vulnerabilities: 'NVD (National Vulnerability Database) API'
      },
      total_ports: portEntries.length,
      timestamp: new Date().toISOString()
    });
  }

  // ── Single Port Intelligence ────────────────────────────────
  if (url.startsWith('/pcap/port-intel') && method === 'GET') {
    const q = getQuery(url);
    const port = parseInt(q.port);
    
    if (!port || port < 1 || port > 65535) {
      return respond({ error: 'Invalid port number (1-65535)' }, 400);
    }
    
    console.log(`[PortIntel] Looking up port ${port}...`);
    const intel = await getPortIntelligence(port);
    
    return respond({
      port,
      ...intel,
      timestamp: new Date().toISOString()
    });
  }

  // ── Agent STREAMING endpoint (ChatGPT-style) ───────────────────────────────
  if (url === '/pcap/agent/stream' && method === 'POST') {
    if (!checkRateLimit(clientIp, RATE_AGENT)) {
      res.writeHead(429, { 'Content-Type': 'application/json', ...getCorsHeaders(origin) });
      return res.end(JSON.stringify({ error: 'Too many queries. Limit: 30/min.' }));
    }

    try {
      const body = await parseBody(req);
      const parsed = JSON.parse(body.toString());
      const { prompt, session_id } = parsed || {};

      if (!isValidSessionId(session_id)) {
        res.writeHead(400, { 'Content-Type': 'application/json', ...getCorsHeaders(origin) });
        return res.end(JSON.stringify({ error: 'Invalid session_id' }));
      }
      if (!fs.existsSync(path.join(PCAP_DIR, `${session_id}.pcap`))) {
        res.writeHead(404, { 'Content-Type': 'application/json', ...getCorsHeaders(origin) });
        return res.end(JSON.stringify({ error: 'Session expired or PCAP not found' }));
      }
      if (!prompt || typeof prompt !== 'string') {
        res.writeHead(400, { 'Content-Type': 'application/json', ...getCorsHeaders(origin) });
        return res.end(JSON.stringify({ error: 'Missing prompt' }));
      }

      console.log(`[Agent-Stream] Query received for session: ${session_id}`);
      
      // Check for pre-computed data
      let precomputed = precomputedData.get(session_id);
      
      // If no pre-computed data yet, check if it's still computing
      if (!precomputed) {
        const sessionInfo = sessions.get(session_id);
        if (sessionInfo && sessionInfo.precomputed === false) {
          console.log(`[Agent-Stream] Pre-computation still running, waiting...`);
          // Wait up to 30 seconds for pre-computation to complete
          for (let i = 0; i < 30; i++) {
            await new Promise(r => setTimeout(r, 1000));
            precomputed = precomputedData.get(session_id);
            if (precomputed) {
              console.log(`[Agent-Stream] ✓ Pre-computation completed while waiting!`);
              break;
            }
          }
        }
      }
      
      if (!precomputed) {
        console.error(`[Agent-Stream] ❌ NO PRE-COMPUTED DATA for ${session_id}!`);
        res.writeHead(200, {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          'Connection': 'keep-alive',
          ...getCorsHeaders(origin),
        });
        res.write(`data: ${JSON.stringify({ token: '⏳ Still analyzing your PCAP file. Please wait a few seconds and try again. Large files may take up to a minute to fully analyze.' })}\n\n`);
        res.write('data: [DONE]\n\n');
        return res.end();
      }
      
      console.log(`[Agent-Stream] ✓ Using pre-computed data: ${precomputed.total_packets} packets`);
      
      // Build FULL context from pre-computed data
      const llmPrompt = buildLLMPromptFromPrecomputed(prompt, precomputed);
      
      // Stream the response!
      await callLLMStream(llmPrompt, res, origin);
      return;  // Response already sent via stream
      
    } catch (e) {
      console.error(`[Agent-Stream] Error: ${e.message}`);
      res.writeHead(500, { 'Content-Type': 'application/json', ...getCorsHeaders(origin) });
      return res.end(JSON.stringify({ error: e.message }));
    }
  }

  // ── Agent ──────────────────────────────────────────────────
  if (url === '/pcap/agent/query' && method === 'POST') {
    if (!checkRateLimit(clientIp, RATE_AGENT))
      return respond({ error: 'Too many queries. Limit: 30/min.' }, 429);

    try {
      const body = await parseBody(req);
      const parsed = JSON.parse(body.toString());
      const { prompt, session_id } = parsed || {};

      if (!isValidSessionId(session_id)) return respond({ error: 'Invalid session_id' }, 400);
      if (!fs.existsSync(path.join(PCAP_DIR, `${session_id}.pcap`)))
        return respond({ error: 'Session expired or PCAP not found' }, 404);
      if (!prompt || typeof prompt !== 'string')
        return respond({ error: 'Missing prompt' }, 400);

      // Check if we have pre-computed data (INSTANT queries!)
      const precomputed = precomputedData.get(session_id);
      console.log(`[Agent] Query received for session: ${session_id}`);
      console.log(`[Agent] Pre-computed data found: ${!!precomputed}`);
      console.log(`[Agent] Available sessions in cache:`, [...precomputedData.keys()]);
      
      // First try LLM-powered natural conversation (greetings, compliments, etc.)
      const naturalResponse = await generateNaturalResponse(prompt);
      if (naturalResponse) {
        return respond({
          tool_called: 'chat',
          parameters: {},
          result: null,
          response: naturalResponse.response,
        });
      }
      
      // ═══════════════════════════════════════════════════════════════
      // INSTANT QUERY - Read from pre-computed memory (NO TShark!)
      // ═══════════════════════════════════════════════════════════════
      if (precomputed) {
        console.log(`[Agent] ✓ Using pre-computed data (INSTANT query)`);
        console.log(`[Agent] Data: ${precomputed.total_packets} packets, ${precomputed.dns_queries?.length || 0} DNS, ${precomputed.http_hosts?.length || 0} HTTP hosts`);
        
        // Build FULL context from pre-computed data - NO TRUNCATION
        const llmPrompt = buildLLMPromptFromPrecomputed(prompt, precomputed);
        const llmResponse = await callLLM(llmPrompt);
        
        console.log(`[Agent] ✓ LLM response: ${(llmResponse || '').slice(0, 100)}...`);
        
        return respond({
          tool_called: 'llm',
          parameters: {},
          result: null,
          response: llmResponse || 'Unable to analyze. Please try again.',
        });
      }
      
      // NO PRE-COMPUTED DATA YET - Maybe still computing?
      console.log(`[Agent] ⚠ No pre-computed data yet for ${session_id}`);
      console.log(`[Agent] Available sessions:`, [...precomputedData.keys()]);
      
      // Check if session exists but pre-computation is still running
      const sessionInfo = sessions.get(session_id);
      if (sessionInfo && sessionInfo.precomputed === false) {
        console.log(`[Agent] Pre-computation still running, waiting...`);
        // Wait up to 30 seconds for pre-computation to complete
        for (let i = 0; i < 30; i++) {
          await new Promise(r => setTimeout(r, 1000));
          const checkPrecomputed = precomputedData.get(session_id);
          if (checkPrecomputed) {
            console.log(`[Agent] ✓ Pre-computation completed while waiting!`);
            const llmPrompt = buildLLMPromptFromPrecomputed(prompt, checkPrecomputed);
            const llmResponse = await callLLM(llmPrompt);
            return respond({
              tool_called: 'llm',
              parameters: {},
              result: null,
              response: llmResponse || 'Unable to analyze. Please try again.',
            });
          }
        }
        // Still not ready after 30 seconds
        return respond({
          tool_called: 'chat',
          parameters: {},
          result: null,
          response: '⏳ Still analyzing your PCAP file. Please wait a few seconds and try again. Large files may take up to a minute to fully analyze.',
        });
      }
      
      // ═══════════════════════════════════════════════════════════════
      // FALLBACK - No pre-computed data, run TShark (slower)
      // ═══════════════════════════════════════════════════════════════
      console.log(`[Agent] ⚠ No pre-computed data, running TShark (slower)...`);
      
      const agentResult = localDynamicAgent(prompt);
      
      if (agentResult.tool === 'chat') {
        return respond({
          tool_called: 'chat',
          parameters: {},
          result: null,
          response: agentResult.response,
        });
      }
      
      if (agentResult.tool === 'llm') {
        const llmResponse = await formatResponseWithLLM(prompt, agentResult, { result: null, response: '' }, session_id);
        return respond({
          tool_called: 'llm',
          parameters: {},
          result: null,
          response: llmResponse || agentResult.response,
        });
      }
      
      const toolResult = await executeTool(agentResult, session_id);
      const llmResponse = await formatResponseWithLLM(prompt, agentResult, toolResult, session_id);

      if (llmResponse) {
        return respond({
          tool_called: agentResult.tool,
          parameters: { filter: agentResult.filter || '', stat: agentResult.stat || '' },
          result: null,
          response: llmResponse,
        });
      }

      return respond({
        tool_called: agentResult.tool,
        parameters: { filter: agentResult.filter || '', stat: agentResult.stat || '' },
        result: toolResult.result,
        response: toolResult.response,
      });
    } catch (e) {
      console.error(`[Agent] Error: ${e.message}`);
      return respond({ error: e.message }, 500);
    }
  }

  // ── HTTP Objects list ──────────────────────────────────────
  if (url.startsWith('/pcap/images') && method === 'GET') {
    const q = getQuery(url);
    if (!isValidSessionId(q.session_id)) return respond({ error: 'Invalid session_id' }, 400);

    const artifacts = imageStore.get(q.session_id);
    if (!artifacts || artifacts.size === 0)
      return respond({
        images: [], total: 0,
        message: 'No HTTP objects found yet. Extraction runs in the background after upload — wait a few seconds then retry.',
      });

    return respond({
      images: Array.from(artifacts.entries()).map(([k, v]) => ({
        filename: v.filename,
        content_type: v.contentType,
        artifact_key: k,
        size: v.buffer.length,
        is_image: v.contentType.startsWith('image/'),
      })),
      total: artifacts.size,
    });
  }

  // ── HTTP Object data ───────────────────────────────────────
  if (url.startsWith('/pcap/image-data') && method === 'GET') {
    const q = getQuery(url);
    if (!isValidSessionId(q.session_id)) return respond({ error: 'Invalid session_id' }, 400);
    const art = imageStore.get(q.session_id)?.get(q.key || '');
    if (!art) return respond({ error: 'Object not found' }, 404);

    res.writeHead(200, {
      'Content-Type': art.contentType,
      'Content-Length': art.buffer.length,
      'Content-Disposition': `inline; filename="${art.filename}"`,
      ...getCorsHeaders(origin),
    });
    return res.end(art.buffer);
  }

  return respond({ error: 'Not found' }, 404);
});

const PORT = process.env.PORT || 4000;
server.listen(PORT, () => {
  console.log(`✅ TShark PCAP Analyzer running on port ${PORT}`);
  console.log(`🔧 TShark binary: ${TSHARK_BIN}`);
  console.log(`🌐 SearXNG URL:   ${SEARXNG_URL}`);
  console.log(`📚 Port DB:       IANA Registry (40+ well-known ports)`);
  console.log(`🛡️ CVE API:       NVD (only for risky services)`);
  console.log(`🧠 AI Agent:      Qwen 2.5 14B via Cloudflare Workers AI!`);
  console.log(`📁 PCAP dir:      ${path.resolve(PCAP_DIR)}`);
  console.log(`📁 Export dir:    ${path.resolve(EXPORT_DIR)}`);
});

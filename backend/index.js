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
  process.exit(1);
}

console.log('✅ Environment variables loaded:');
console.log(`   SEARXNG_URL    = ${SEARXNG_URL}`);
console.log(`   CF_ACCOUNT_ID  = ${CF_ACCOUNT_ID}`);
console.log(`   CF_API_TOKEN   = ${CF_API_TOKEN ? CF_API_TOKEN.slice(0, 10) + '...' : 'NOT SET'}`);
console.log(`   ALLOWED_ORIGIN = ${ALLOWED_ORIGIN}`);

// ═══════════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════════
const CF_LLM_MODEL = '@cf/meta/llama-3-8b-instruct';
const CF_LLM_TIMEOUT_MS = 30000; // Increased for 2-step process
const SEARXNG_TIMEOUT_MS = 10000;
const SEARXNG_MAX_RESULTS = 5;
const SEARXNG_ENGINES = 'google,bing,duckduckgo,startpage';

// ── TShark binary path ─────────────────────────────────────────
const TSHARK_BIN = process.env.TSHARK_PATH ||
  (process.platform === 'win32'
    ? 'C:\\Program Files\\Wireshark\\tshark.exe'
    : 'tshark');

console.log(`[Init] TShark path: ${TSHARK_BIN}`);

exec(`"${TSHARK_BIN}" -v 2>/dev/null`, (err, stdout) => {
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
const portIntelCache = new Map();
const SESSION_TTL_MS = 30 * 60 * 1000;

// ── Session Recovery ───────────────────────────────────────────
async function ensureSession(sessionId) {
  if (sessions.has(sessionId)) {
    return true;
  }
  
  const pcapPath = path.join(PCAP_DIR, `${sessionId}.pcap`);
  
  if (fs.existsSync(pcapPath)) {
    console.log(`[SessionRecovery] Recreating lost session: ${sessionId}`);
    
    sessions.set(sessionId, {
      session_id: sessionId,
      filename: 'restored.pcap',
      created_at: Date.now(),
    });
    
    return true;
  }
  
  return false;
}

setInterval(() => {
  const now = Date.now();
  for (const [id, session] of sessions) {
    if (now - session.created_at > SESSION_TTL_MS) {
      try { const p = path.join(PCAP_DIR, `${id}.pcap`); if (fs.existsSync(p)) fs.unlinkSync(p); } catch (_) { }
      try { const p = path.join(EXPORT_DIR, id); if (fs.existsSync(p)) fs.rmSync(p, { recursive: true }); } catch (_) { }
      sessions.delete(id);
      imageStore.delete(id);
      portIntelCache.delete(id);
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
  let allowedOrigin = ALLOWED_ORIGIN;
  
  if (origin && (origin.includes('localhost') || origin.includes('127.0.0.1'))) {
    allowedOrigin = origin;
  }
  
  if (ALLOWED_ORIGIN === '*') {
    allowedOrigin = '*';
  }
  
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

// ═══════════════════════════════════════════════════════════════════
// TShark core runner
// ═══════════════════════════════════════════════════════════════════
const DEFAULT_FIELDS = [
  'frame.number',
  'ip.src', 'ip.dst',
  'ipv6.src', 'ipv6.dst',
  'eth.src', 'eth.dst',
  'frame.len',
  '_ws.col.Protocol',
  'tcp.srcport', 'tcp.dstport',
  'udp.srcport', 'udp.dstport',
  'frame.time_relative',
  'frame.time',
  '_ws.col.Info',
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
    cmd += ' 2>/dev/null';

    console.log(`[TShark] Running: ${cmd.slice(0, 150)}...`);

    exec(cmd, { timeout: 60000, maxBuffer: 50 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) {
        console.error(`[TShark] exec error: ${err.message}`);
        return resolve([]);
      }
      const lines = stdout.trim().split('\n').filter(l => l.trim());
      const packets = lines.map(line => {
        const c = line.split('\t');
        const src_ip = c[1] || c[3] || c[5] || null;
        const dst_ip = c[2] || c[4] || c[6] || null;
        return {
          id: parseInt(c[0]) || 0,
          src_ip,
          dst_ip,
          length: parseInt(c[7]) || 0,
          protocol: c[8] || 'UNKNOWN',
          src_port: parseInt(c[9]) || parseInt(c[11]) || null,
          dst_port: parseInt(c[10]) || parseInt(c[12]) || null,
          timestamp: parseFloat(c[13]) || 0,
          datetime: c[14] || '',
          info: c[15] || null,
        };
      });
      console.log(`[TShark] Returned ${packets.length} packets`);
      resolve(packets);
    });
  });
}

function runTsharkPaged(sessionId, skip, limit) {
  return new Promise((resolve) => {
    const pcapPath = path.join(PCAP_DIR, `${sessionId}.pcap`);
    if (!fs.existsSync(pcapPath)) return resolve([]);

    let cmd = `"${TSHARK_BIN}" -r "${pcapPath}" -T fields -E separator=/t`;
    for (const f of DEFAULT_FIELDS) cmd += ` -e ${f}`;
    cmd += ` -c ${skip + limit}`;
    cmd += ' 2>/dev/null';

    exec(cmd, { timeout: 60000, maxBuffer: 20 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) {
        console.error(`[TSharkPaged] exec error: ${err.message}`);
        return resolve([]);
      }
      const lines = stdout.trim().split('\n').filter(l => l.trim());
      const pageLines = lines.slice(skip);
      const packets = pageLines.map(line => {
        const c = line.split('\t');
        const src_ip = c[1] || c[3] || c[5] || null;
        const dst_ip = c[2] || c[4] || c[6] || null;
        return {
          id: parseInt(c[0]) || 0,
          src_ip,
          dst_ip,
          length: parseInt(c[7]) || 0,
          protocol: c[8] || 'UNKNOWN',
          src_port: parseInt(c[9]) || parseInt(c[11]) || null,
          dst_port: parseInt(c[10]) || parseInt(c[12]) || null,
          timestamp: parseFloat(c[13]) || 0,
          datetime: c[14] || '',
          info: c[15] || null,
        };
      });
      console.log(`[TSharkPaged] → ${packets.length} packets returned`);
      resolve(packets);
    });
  });
}

function getTruePacketCount(sessionId) {
  return new Promise((resolve) => {
    const pcapPath = path.join(PCAP_DIR, `${sessionId}.pcap`);
    if (!fs.existsSync(pcapPath)) return resolve(0);
    const cmd = `"${TSHARK_BIN}" -r "${pcapPath}" -T fields -e frame.number 2>/dev/null`;
    exec(cmd, { timeout: 120000, maxBuffer: 50 * 1024 * 1024 }, (err, stdout) => {
      if (err) return resolve(0);
      const count = stdout.trim().split('\n').filter(l => l.trim()).length;
      console.log(`[TShark] True packet count: ${count}`);
      resolve(count);
    });
  });
}

function getProtocolCounts(sessionId, limit = 0) {
  return new Promise((resolve) => {
    const pcapPath = path.join(PCAP_DIR, `${sessionId}.pcap`);
    if (!fs.existsSync(pcapPath)) return resolve({ protocols: {}, maxTime: 0 });
    
    let cmd = `"${TSHARK_BIN}" -r "${pcapPath}" -T fields -E separator=/t -e _ws.col.Protocol -e frame.time_relative`;
    if (limit > 0) cmd += ` -c ${limit}`;
    cmd += ' 2>/dev/null';
    
    exec(cmd, { timeout: 60000, maxBuffer: 50 * 1024 * 1024 }, (err, stdout, stderr) => {
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

function getAllPorts(sessionId) {
  return new Promise((resolve) => {
    const pcapPath = path.join(PCAP_DIR, `${sessionId}.pcap`);
    if (!fs.existsSync(pcapPath)) return resolve({});
    
    const cmd = `"${TSHARK_BIN}" -r "${pcapPath}" -T fields -E separator=/t -e tcp.dstport -e udp.dstport 2>/dev/null`;
    
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

// ═══════════════════════════════════════════════════════════════════
// NEW: Get HTTP Objects, DNS Queries, TLS SNI
// ═══════════════════════════════════════════════════════════════════

function getHttpObjects(sessionId) {
  return new Promise((resolve) => {
    const exportDir = path.join(EXPORT_DIR, sessionId);
    if (!fs.existsSync(exportDir)) {
      return resolve([]);
    }
    
    try {
      const files = fs.readdirSync(exportDir);
      const objects = files.map(filename => {
        const fp = path.join(exportDir, filename);
        const stats = fs.statSync(fp);
        const ext = path.extname(filename).toLowerCase();
        const contentTypes = {
          '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png',
          '.gif': 'image/gif', '.webp': 'image/webp', '.svg': 'image/svg+xml',
          '.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript',
          '.json': 'application/json', '.pdf': 'application/pdf',
          '.ico': 'image/x-icon', '.woff': 'font/woff', '.woff2': 'font/woff2',
        };
        return {
          filename,
          content_type: contentTypes[ext] || 'application/octet-stream',
          size: stats.size,
          extension: ext,
        };
      });
      console.log(`[HTTP-Objects] Found ${objects.length} objects`);
      resolve(objects);
    } catch (e) {
      console.error(`[HTTP-Objects] Error: ${e.message}`);
      resolve([]);
    }
  });
}

function getDnsQueries(sessionId, limit = 200) {
  return new Promise((resolve) => {
    const pcapPath = path.join(PCAP_DIR, `${sessionId}.pcap`);
    if (!fs.existsSync(pcapPath)) return resolve([]);
    
    const cmd = `"${TSHARK_BIN}" -r "${pcapPath}" -Y "dns.qry.name" -T fields -E separator=/t -e dns.qry.name -e dns.a -e dns.aaaa -e dns.flags.response -c ${limit} 2>/dev/null`;
    
    exec(cmd, { timeout: 30000 }, (err, stdout) => {
      if (err) {
        console.error(`[DNS] Error: ${err.message}`);
        return resolve([]);
      }
      
      const queries = [];
      const seen = new Set();
      const lines = stdout.trim().split('\n').filter(l => l.trim());
      
      for (const line of lines) {
        const [name, a, aaaa, isResponse] = line.split('\t');
        if (name && !seen.has(name)) {
          seen.add(name);
          queries.push({
            domain: name,
            type: isResponse === '1' ? 'response' : 'query',
            answers: [a, aaaa].filter(Boolean).join(', ') || null,
          });
        }
      }
      
      console.log(`[DNS] Found ${queries.length} unique queries`);
      resolve(queries);
    });
  });
}

function getTlsSni(sessionId, limit = 100) {
  return new Promise((resolve) => {
    const pcapPath = path.join(PCAP_DIR, `${sessionId}.pcap`);
    if (!fs.existsSync(pcapPath)) return resolve([]);
    
    const cmd = `"${TSHARK_BIN}" -r "${pcapPath}" -Y "tls.handshake.extensions_server_name" -T fields -e tls.handshake.extensions_server_name -e ip.dst -c ${limit} 2>/dev/null`;
    
    exec(cmd, { timeout: 30000 }, (err, stdout) => {
      if (err) {
        console.error(`[TLS-SNI] Error: ${err.message}`);
        return resolve([]);
      }
      
      const sniList = [];
      const seen = new Set();
      const lines = stdout.trim().split('\n').filter(l => l.trim());
      
      for (const line of lines) {
        const [sni, dstIp] = line.split('\t');
        if (sni && !seen.has(sni)) {
          seen.add(sni);
          sniList.push({ server_name: sni, destination_ip: dstIp || null });
        }
      }
      
      console.log(`[TLS-SNI] Found ${sniList.length} unique SNI domains`);
      resolve(sniList);
    });
  });
}

function getHttpRequests(sessionId, limit = 100) {
  return new Promise((resolve) => {
    const pcapPath = path.join(PCAP_DIR, `${sessionId}.pcap`);
    if (!fs.existsSync(pcapPath)) return resolve([]);
    
    const cmd = `"${TShARK_BIN}" -r "${pcapPath}" -Y "http.request" -T fields -E separator=/t -e http.host -e http.request.method -e http.request.uri -e http.user-agent -c ${limit} 2>/dev/null`;
    
    exec(cmd, { timeout: 30000 }, (err, stdout) => {
      if (err) {
        console.error(`[HTTP-Req] Error: ${err.message}`);
        return resolve([]);
      }
      
      const requests = [];
      const lines = stdout.trim().split('\n').filter(l => l.trim());
      
      for (const line of lines) {
        const [host, method, uri, userAgent] = line.split('\t');
        if (host || uri) {
          requests.push({
            host: host || null,
            method: method || 'GET',
            uri: uri || '/',
            user_agent: userAgent || null,
          });
        }
      }
      
      console.log(`[HTTP-Req] Found ${requests.length} HTTP requests`);
      resolve(requests);
    });
  });
}

function runTsharkStat(sessionId, statCommand) {
  return new Promise((resolve) => {
    const pcapPath = path.join(PCAP_DIR, `${sessionId}.pcap`);
    if (!fs.existsSync(pcapPath)) return resolve('PCAP not found');
    const cmd = `"${TSHARK_BIN}" -r "${pcapPath}" -q -z ${statCommand} 2>/dev/null`;
    console.log(`[TShark-Stat] Running: ${cmd}`);
    exec(cmd, { timeout: 60000, maxBuffer: 10 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) {
        console.error(`[TShark-Stat] Error: ${err.message}`);
        return resolve('Stat failed');
      }
      resolve(stdout || '');
    });
  });
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
    cmd += ' 2>/dev/null';

    exec(cmd, { timeout: 30000, maxBuffer: 10 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) {
        console.error(`[TShark-Detail] Error: ${err.message}`);
        return resolve({ error: 'Failed to parse packet - ' + err.message.slice(0, 100) });
      }

      const lines = stdout.trim().split('\n').filter(l => l.trim());
      const targetLine = lines[packetNumber - 1];
      if (!targetLine) {
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

// ── Parse TShark PDML Output ───────────────────────────────────
function parsePdmlOutput(pdmlXml, targetPacket) {
  const packets = [];
  const packetMatches = pdmlXml.match(/<packet[^>]*>[\s\S]*?<\/packet>/g) || [];
  
  for (const packetXml of packetMatches) {
    const packet = {
      frame: {},
      layers: [],
      info: ''
    };
    
    const protoMatches = packetXml.match(/<proto[^>]*>[\s\S]*?<\/proto>/g) || [];
    
    for (const protoXml of protoMatches) {
      const nameMatch = protoXml.match(/name="([^"]+)"/);
      const protoName = nameMatch ? nameMatch[1] : 'unknown';
      const shownameMatch = protoXml.match(/showname="([^"]+)"/);
      const protoShowName = shownameMatch ? shownameMatch[1] : protoName;
      
      if (protoName === 'geninfo') continue;
      
      const fields = extractFieldsHierarchical(protoXml, 0);
      
      if (protoName === 'frame') {
        extractFrameData(fields, packet);
        packet.layers.push({
          name: 'Frame',
          protocol: 'frame',
          fields: fields
        });
        continue;
      }
      
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
    
    let infoMatch = packetXml.match(/<field[^>]*name="_ws\.col\.Info"[^>]*show="([^"]+)"/);
    if (!infoMatch) {
      infoMatch = packetXml.match(/showname="Info[^"]*"[^>]*show="([^"]+)"/);
    }
    if (infoMatch) {
      packet.info = infoMatch[1];
    }
    
    packets.push(packet);
  }
  
  const target = packets[targetPacket - 1];
  if (!target && packets.length > 0) {
    return packets[packets.length - 1];
  }
  
  return target || { frame: {}, layers: [], info: '' };
}

function extractFrameData(fields, packet) {
  for (const field of fields) {
    if (field.key === 'Frame Number') packet.frame.number = field.value;
    if (field.key === 'Arrival Time') packet.frame.time = field.value;
    if (field.key === 'Time Since Reference' || field.key === 'Time since reference') packet.frame.time_relative = field.value;
    if (field.key === 'Frame Length') packet.frame.length = field.value;
    if (field.children && field.children.length > 0) {
      extractFrameData(field.children, packet);
    }
  }
}

function extractFieldsHierarchical(xmlBlock, depth) {
  const fields = [];
  const seen = new Set();
  
  const fieldPattern = /<field\s+([^>]*)(?:\/>|>([\s\S]*?)<\/field>)/g;
  
  let match;
  while ((match = fieldPattern.exec(xmlBlock)) !== null) {
    const attrs = match[1];
    const content = match[2] || '';
    
    const shownameMatch = attrs.match(/showname="([^"]+)"/);
    const showMatch = attrs.match(/show="([^"]+)"/);
    const nameMatch = attrs.match(/name="([^"]+)"/);
    
    const fieldName = nameMatch ? nameMatch[1] : '';
    if (fieldName.startsWith('_ws.') && !fieldName.includes('Info')) {
      continue;
    }
    
    let key = '';
    let value = '';
    let isExpandable = false;
    
    if (shownameMatch) {
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
      key = fieldName.split('.').pop().replace(/_/g, ' ');
      value = showMatch[1];
    }
    
    if (key && key.length > 0) {
      key = key.charAt(0).toUpperCase() + key.slice(1);
    }
    
    let children = [];
    if (content && content.includes('<field')) {
      children = extractFieldsHierarchical(content, depth + 1);
      isExpandable = children.length > 0;
    }
    
    const isOnlyHex = value && /^[0-9a-fA-F:\s]+$/.test(value) && value.length > 50;
    
    if (key && value && value.length < 500 && !isOnlyHex) {
      const fieldKey = key + ':' + value.substring(0, 50);
      if (!seen.has(fieldKey)) {
        seen.add(fieldKey);
        fields.push({ key, value, children, isExpandable, depth });
      }
    } else if (key && isExpandable && children.length > 0) {
      const fieldKey = key + ':expandable';
      if (!seen.has(fieldKey)) {
        seen.add(fieldKey);
        fields.push({ key, value: value || '', children, isExpandable: true, depth });
      }
    }
  }
  
  return fields;
}

// ═══════════════════════════════════════════════════════════════════
// SearXNG Search for Port Intelligence - NO HARDCODING
// ═══════════════════════════════════════════════════════════════════
async function searchPortWithSearXNG(port, searchType = 'general') {
  return new Promise((resolve, reject) => {
    const queries = {
      general: `IANA network TCP UDP port ${port} service name protocol what is`,
      risks: `network port ${port} TCP UDP security vulnerability exploit CVE NVD`,
      uses: `network port ${port} TCP UDP purpose application usage`
    };

    const searchUrl = `${SEARXNG_URL}/search?q=${encodeURIComponent(queries[searchType] || queries.general)}&format=json&engines=${SEARXNG_ENGINES}`;

    console.log(`[SearXNG] Searching ${searchType} for port ${port}...`);

    const urlObj = new URL(searchUrl);
    const options = {
      hostname: urlObj.hostname,
      port: urlObj.port || 443,
      path: urlObj.pathname + urlObj.search,
      method: 'GET',
      timeout: SEARXNG_TIMEOUT_MS,
    };

    const protocol = urlObj.protocol === 'https:' ? https : http;

    const req = protocol.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          if (res.statusCode !== 200) {
            console.error(`[SearXNG] Error ${res.statusCode} for port ${port}`);
            return resolve(null);
          }

          const json = JSON.parse(data);
          const results = json.results || [];

          if (results.length === 0) {
            return resolve(null);
          }

          let serviceName = 'Unknown';
          let description = '';
          let commonUses = [];
          let risks = [];

          for (const result of results.slice(0, 5)) {
            const content = (result.content || '').toLowerCase();
            const title = (result.title || '').toLowerCase();

            if (!description && result.content) {
              description = result.content.slice(0, 300);
            }

            // Service identification patterns
            if (content.includes('dns') || title.includes('dns')) {
              serviceName = 'DNS';
              if (!commonUses.includes('DNS queries')) commonUses.push('DNS queries', 'Name resolution');
            }
            if (content.includes('dhcp') || title.includes('dhcp')) {
              serviceName = 'DHCP';
              if (!commonUses.includes('IP address assignment')) commonUses.push('IP address assignment', 'Network configuration');
            }
            if (content.includes('http') || title.includes('http') || content.includes('web')) {
              if (serviceName === 'Unknown') serviceName = 'HTTP';
              if (!commonUses.includes('Web services')) commonUses.push('Web services', 'HTTP traffic');
            }
            if (content.includes('https') || title.includes('https') || content.includes('ssl') || content.includes('tls')) {
              serviceName = 'HTTPS';
              if (!commonUses.includes('Secure web')) commonUses.push('Secure web browsing', 'Encrypted HTTP');
            }
            if (content.includes('ssh') || title.includes('ssh')) {
              serviceName = 'SSH';
              if (!commonUses.includes('Remote access')) commonUses.push('Secure remote access', 'Terminal access');
            }
            if (content.includes('ftp') || title.includes('ftp')) {
              serviceName = 'FTP';
              if (!commonUses.includes('File transfer')) commonUses.push('File transfer', 'Data exchange');
            }
            if (content.includes('smtp') || title.includes('smtp') || content.includes('email') || content.includes('mail')) {
              serviceName = 'SMTP';
              if (!commonUses.includes('Email')) commonUses.push('Email sending', 'Mail relay');
            }
            if (content.includes('ephemeral') || content.includes('dynamic port') || content.includes('client port')) {
              serviceName = 'Ephemeral';
              if (!commonUses.includes('Client connections')) commonUses.push('Client connections', 'Temporary connections', 'Outbound traffic');
            }

            // Security risks
            if (content.includes('vulnerability') || content.includes('vulnerable')) {
              if (!risks.includes('Known vulnerabilities')) risks.push('Known vulnerabilities exist');
            }
            if (content.includes('exploit') || content.includes('exploited')) {
              if (!risks.includes('Active exploits')) risks.push('Active exploits reported');
            }
            if (content.includes('cve') || content.includes('cve-')) {
              const cveMatch = content.match(/cve-\d{4}-\d+/gi);
              if (cveMatch && !risks.some(r => r.includes('CVE'))) {
                risks.push(`Related CVEs: ${cveMatch.slice(0, 3).join(', ').toUpperCase()}`);
              }
            }
            if (content.includes('brute force')) {
              if (!risks.includes('Brute force')) risks.push('Brute force attack risk');
            }
            if (content.includes('port scanning') || content.includes('reconnaissance')) {
              if (!risks.includes('Port scanning')) risks.push('Port scanning risk');
            }
          }

          if (commonUses.length === 0) {
            commonUses.push('Network service', 'Application communication');
          }

          console.log(`[SearXNG] ✓ Found ${searchType} info for port ${port}: ${serviceName}`);
          resolve({
            service_name: serviceName,
            description: description || `Port ${port} - network service`,
            common_uses: commonUses,
            risks: risks,
            source: 'SearXNG Web Search'
          });
        } catch (e) {
          console.error(`[SearXNG] Parse error for port ${port}: ${e.message}`);
          resolve(null);
        }
      });
    });

    req.on('error', (e) => {
      console.error(`[SearXNG] Request error for port ${port}: ${e.message}`);
      resolve(null);
    });

    req.on('timeout', () => {
      req.destroy();
      console.error(`[SearXNG] Timeout for port ${port}`);
      resolve(null);
    });

    req.end();
  });
}

// ── Port Intelligence using SearXNG only (NO HARDCODING) ──────────────────────────────────────────
async function getPortIntelligence(port) {
  // NO HARDCODING - Use SearXNG for ALL ports including ephemeral
  console.log(`[PortIntel] Port ${port} - searching SearXNG...`);

  const [generalResult, risksResult] = await Promise.all([
    searchPortWithSearXNG(port, 'general'),
    searchPortWithSearXNG(port, 'risks')
  ]);

  const serviceName = generalResult?.service_name || 'Unknown';
  const description = generalResult?.description || `Port ${port} - network service`;
  const commonUses = generalResult?.common_uses || ['Network service', 'Application communication'];
  const risks = risksResult?.risks || [];

  // Determine risk level
  let riskLevel = 'LOW';
  if (risks.length > 0) {
    if (risks.some(r => r.toLowerCase().includes('critical') || r.toLowerCase().includes('rce'))) {
      riskLevel = 'CRITICAL';
    } else if (risks.some(r => r.toLowerCase().includes('exploit') || r.toLowerCase().includes('vulnerability') || r.toLowerCase().includes('cve'))) {
      riskLevel = 'HIGH';
    } else if (risks.length > 0) {
      riskLevel = 'MEDIUM';
    }
  }

  if (risks.length === 0) {
    risks.push('Standard network service - review traffic patterns');
  }

  console.log(`[PortIntel] ✓ Port ${port}: ${serviceName}, ${risks.length} risks, ${commonUses.length} uses`);

  return {
    port: port,
    service_name: serviceName,
    description: description,
    secure_alternative: 'Review firewall rules and traffic patterns',
    common_uses: commonUses,
    risks: risks,
    risk: riskLevel,
    reason: risks[0] || description,
    cve_id: null,
    cvss_score: null,
    cve_count: 0,
    all_cves: [],
    source: 'SearXNG Web Search',
  };
}

// ═══════════════════════════════════════════════════════════════════
// LLM Functions - 2-STEP DYNAMIC PROCESS
// ═══════════════════════════════════════════════════════════════════

// Step 1: Analyze prompt to decide what TShark command to run
async function analyzePromptForTshark(prompt, contextSummary) {
  return new Promise((resolve) => {
    const analysisPrompt = `You are a PCAP analysis assistant. Analyze the user's question and decide what TShark data would help answer it.

AVAILABLE DATA TYPES:
- packets: Basic packet list (src_ip, dst_ip, protocol, ports, info)
- protocols: Protocol distribution (counts per protocol)
- dns: DNS queries and responses
- http: HTTP requests (hosts, URIs, methods)
- tls_sni: TLS Server Name Indication (domains accessed via HTTPS)
- http_objects: Extracted HTTP files (images, HTML, JS, etc)
- ports: Unique destination ports with counts
- conversations: IP conversation statistics
- endpoints: Top talkers (IPs with most traffic)

PCAP SUMMARY:
${contextSummary}

USER QUESTION: "${prompt}"

Respond with ONLY a JSON object (no markdown, no explanation):
{
  "data_types": ["list", "of", "needed", "data", "types"],
  "reasoning": "brief explanation"
}`;

    const postData = JSON.stringify({
      model: CF_LLM_MODEL,
      messages: [
        { role: 'user', content: analysisPrompt }
      ],
      max_tokens: 200,
      response_format: { type: "json_object" }
    });

    const options = {
      hostname: 'api.cloudflare.com',
      port: 443,
      path: `/client/v4/accounts/${CF_ACCOUNT_ID}/ai/v1/chat/completions`,
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${CF_API_TOKEN}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData),
      },
      timeout: 15000,
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          if (res.statusCode !== 200) {
            console.error(`[LLM-Analyze] Error ${res.statusCode}`);
            return resolve({ data_types: ['packets', 'protocols'], reasoning: 'Default fallback' });
          }
          const json = JSON.parse(data);
          const content = json.choices?.[0]?.message?.content || '{}';
          const parsed = JSON.parse(content);
          console.log(`[LLM-Analyze] Need: ${parsed.data_types?.join(', ')}`);
          resolve(parsed);
        } catch (e) {
          console.error(`[LLM-Analyze] Parse error: ${e.message}`);
          resolve({ data_types: ['packets', 'protocols'], reasoning: 'Parse error fallback' });
        }
      });
    });

    req.on('error', (e) => {
      console.error(`[LLM-Analyze] Request error: ${e.message}`);
      resolve({ data_types: ['packets', 'protocols'], reasoning: 'Request error fallback' });
    });

    req.on('timeout', () => {
      req.destroy();
      resolve({ data_types: ['packets', 'protocols'], reasoning: 'Timeout fallback' });
    });

    req.write(postData);
    req.end();
  });
}

// Step 2: Generate final response with all context
async function callLLMStream(prompt, res, origin, fullContext) {
  return new Promise((resolve, reject) => {
    const systemPrompt = `You are an expert PCAP Security Agent. You analyze network traffic professionally.

RULES:
• Give DETAILED, INTELLIGENT responses (5-8 bullet points when analyzing data)
• Use **bold** for emphasis on important items
• If user asks multiple questions, answer ALL of them separately
• When analyzing packets, provide specific details: IPs, ports, protocols, packet counts
• Be technical but clear - you're talking to security professionals
• If you see suspicious patterns, explain WHY they're suspicious
• For files/HTTP objects, list them with sizes and types
• Format numbers with commas (e.g., "5,110 packets" not "5110")
• If the user asks about a specific website, domain, or file - SEARCH the provided data for it`;

    const llmPrompt = `${systemPrompt}

${fullContext}

USER QUESTION: "${prompt}"

Answer the user's question using ONLY the data provided above. Be specific with actual IPs, ports, domains, and packet counts. Use **bold** for important findings.`;

    const postData = JSON.stringify({
      model: CF_LLM_MODEL,
      messages: [
        { role: 'user', content: llmPrompt }
      ],
      max_tokens: 1000,
      stream: true
    });

    const options = {
      hostname: 'api.cloudflare.com',
      port: 443,
      path: `/client/v4/accounts/${CF_ACCOUNT_ID}/ai/v1/chat/completions`,
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${CF_API_TOKEN}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData),
      },
      timeout: CF_LLM_TIMEOUT_MS,
    };

    console.log(`[LLM-Stream] Starting streaming request...`);

    const corsHeaders = getCorsHeaders(origin);
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      ...corsHeaders,
    });
    
    const req = https.request(options, (cfRes) => {
      if (cfRes.statusCode !== 200) {
        let errorBody = '';
        cfRes.on('data', chunk => errorBody += chunk);
        cfRes.on('end', () => {
          console.error(`[LLM-Stream] Error ${cfRes.statusCode}: ${errorBody.slice(0, 500)}`);
          res.write(`data: ${JSON.stringify({ error: `LLM error: ${cfRes.statusCode}` })}\n\n`);
          res.end();
        });
        return resolve(null);
      }
      
      let buffer = '';
      let fullResponse = '';

      cfRes.on('data', (chunk) => {
        const text = chunk.toString();
        buffer += text;

        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            const data = line.slice(6).trim();
            if (data === '[DONE]') {
              res.write('data: [DONE]\n\n');
              continue;
            }
            try {
              const json = JSON.parse(data);
              const content = json.choices?.[0]?.delta?.content || json.response;
              if (content) {
                fullResponse += content;
                res.write(`data: ${JSON.stringify({ token: content })}\n\n`);
              }
            } catch (e) { }
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

async function callLLM(prompt, systemOverride = null) {
  return new Promise((resolve, reject) => {
    const defaultSystem = `You are an expert PCAP Security Agent. You analyze network traffic professionally.

RULES:
• Give DETAILED, INTELLIGENT responses
• Use **bold** for emphasis
• Be specific with IPs, ports, protocols, and packet counts`;

    const postData = JSON.stringify({
      model: CF_LLM_MODEL,
      messages: [
        { role: 'system', content: systemOverride || defaultSystem },
        { role: 'user', content: prompt }
      ],
      max_tokens: 800
    });

    const options = {
      hostname: 'api.cloudflare.com',
      port: 443,
      path: `/client/v4/accounts/${CF_ACCOUNT_ID}/ai/v1/chat/completions`,
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
          const content = json.choices?.[0]?.message?.content;
          if (content) {
            console.log(`[LLM] ✓ Got response (${content.length} chars)`);
            resolve(content);
          } else {
            console.error(`[LLM] Unexpected response format`);
            resolve(null);
          }
        } catch (e) {
          console.error(`[LLM] Parse error: ${e.message}`);
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
      console.error(`[LLM] Timeout`);
      resolve(null);
    });

    req.write(postData);
    req.end();
  });
}

// ═══════════════════════════════════════════════════════════════════
// Main Server
// ═══════════════════════════════════════════════════════════════════
const server = http.createServer(async (req, res) => {
  const url = req.url || '/';
  const method = req.method || 'GET';
  const origin = req.headers['origin'] || '';
  const enc = req.headers['accept-encoding'] || '';
  const clientIp = req.headers['x-forwarded-for']?.split(',')[0].trim()
    || req.socket.remoteAddress || 'unknown';

  console.log(`[Request] ${method} ${url} Origin: ${origin || 'none'}`);

  const respond = (data, status = 200) => json(res, data, status, origin, enc);

  // Handle CORS preflight FIRST
  if (method === 'OPTIONS') {
    const corsHeaders = getCorsHeaders(origin);
    res.writeHead(204, corsHeaders);
    return res.end();
  }

  if (url === '/ping' || url === '/pcap/ping') {
    res.writeHead(200, { 'Content-Type': 'text/plain', ...getCorsHeaders(origin) });
    return res.end('pong');
  }

  if (url === '/pcap/health') {
    return respond({ status: 'ok', engine: 'TShark + SearXNG', sessions: sessions.size });
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

      // Extract HTTP objects in background
      fs.mkdirSync(exportDir, { recursive: true });
      exec(`"${TSHARK_BIN}" -r "${pcapPath}" --export-objects http,"${exportDir}" 2>/dev/null`, { timeout: 120000 }, (err, _out, stderr) => {
        if (err) { console.error(`[Export] Failed: ${err.message}`); return; }
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

      // Get quick stats for immediate response
      const [quickTotal, quickProtos, quickDuration] = await Promise.all([
        getTruePacketCount(session_id),
        getProtocolCounts(session_id, 0), // Get ALL protocols
        new Promise((resolve) => {
          const cmd = `"${TSHARK_BIN}" -r "${pcapPath}" -T fields -e frame.time_relative 2>/dev/null | tail -1`;
          exec(cmd, { timeout: 10000 }, (err, stdout) => {
            resolve(parseFloat(stdout.trim()) || 0);
          });
        }),
      ]);

      sessions.set(session_id, { 
        session_id, 
        filename, 
        created_at: Date.now(),
        total_packets: quickTotal || 0
      });

      if (sessions.size > 10) {
        let evictKey = null, oldestAge = -1;
        for (const [k, s] of sessions) {
          if (k === session_id) continue;
          const age = Date.now() - s.created_at;
          if (age > oldestAge) { oldestAge = age; evictKey = k; }
        }
        if (evictKey) sessions.delete(evictKey);
      }

      respond({
        session_id,
        summary: {
          total_packets: quickTotal || 0,
          protocols: quickProtos.protocols || {},
          duration_seconds: Math.round(quickDuration) || 0,
          time_range: { start: 0, end: Math.round(quickDuration) || 0 },
          raw_text: '',
        },
      });
      
      return;
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

      const sessionExists = await ensureSession(q.session_id);
      if (!sessionExists) {
        return respond({ error: 'Session expired or not found. Please re-upload your PCAP file.' }, 404);
      }

      const page = Math.max(1, parseInt(q.page || '1'));
      const per_page = Math.min(100, parseInt(q.per_page || '50'));
      const skip = (page - 1) * per_page;

      const packets = await runTsharkPaged(q.session_id, skip, per_page);
      const sessionData = sessions.get(q.session_id);
      const realTotal = sessionData?.total_packets ?? packets.length;

      return respond({ packets, total: realTotal, page, per_page });
    } catch (err) {
      console.error(`[Packets] Error: ${err.message}`);
      return respond({ packets: [], total: 0, page: 1, per_page: 50, error: 'Still processing. Refresh in a few seconds.' });
    }
  }

  // ── Packet Detail ───────────────────────────────────────────
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

  // ── Packet Dissection (PDML) ────────────────────────────────
  if (url.startsWith('/pcap/packet-dissection') && method === 'GET') {
    const q = getQuery(url);
    if (!isValidSessionId(q.session_id)) return respond({ error: 'Invalid session_id' }, 400);
    
    const packetNum = parseInt(q.packet_number);
    if (!packetNum || packetNum < 1) return respond({ error: 'Invalid packet_number' }, 400);
    
    const pcapPath = path.join(PCAP_DIR, `${q.session_id}.pcap`);
    if (!fs.existsSync(pcapPath)) return respond({ error: 'Session expired or not found' }, 404);

    const cmd = `"${TSHARK_BIN}" -r "${pcapPath}" -T pdml -c ${packetNum} 2>/dev/null`;
    console.log(`[TShark-Dissect] Getting PDML dissection for packet ${packetNum}`);
    
    exec(cmd, { timeout: 30000, maxBuffer: 10 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) {
        console.error(`[TShark-Dissect] Error: ${err.message}`);
        return respond({ error: 'Failed to dissect packet' }, 500);
      }
      
      const dissection = parsePdmlOutput(stdout, packetNum);
      console.log(`[TShark-Dissect] ✓ Parsed ${dissection.layers?.length || 0} layers`);
      return respond(dissection);
    });
    return;
  }

  // ── Vulnerabilities / Port Intel ────────────────────────────
  if (url.startsWith('/pcap/vulnerabilities') && method === 'GET') {
    const q = getQuery(url);
    if (!isValidSessionId(q.session_id)) return respond({ error: 'Invalid session_id' }, 400);
    
    const sessionExists = await ensureSession(q.session_id);
    if (!sessionExists) {
      return respond({ error: 'Session expired or not found. Please re-upload your PCAP file.' }, 404);
    }

    // Check cache first
    const cached = portIntelCache.get(q.session_id);
    if (cached) {
      console.log(`[PortIntel] Returning cached results for ${q.session_id}`);
      return respond(cached);
    }

    // Get ports directly
    const portCounts = await getAllPorts(q.session_id);
    const portEntries = Object.entries(portCounts);
    console.log(`[PortIntel] Analyzing ${portEntries.length} unique ports via SearXNG...`);
    
    // Get intelligence for ALL ports via SearXNG (NO HARDCODING)
    const alerts = await Promise.all(
      portEntries.map(async ([port, count]) => {
        const portNum = parseInt(port);
        const intel = await getPortIntelligence(portNum);
        return {
          port: portNum,
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
          risks: intel.risks,
        };
      })
    );
    
    const summary = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const a of alerts) {
      const r = a.risk.toLowerCase();
      if (summary[r] !== undefined) summary[r]++;
    }
    
    const result = { 
      alerts, 
      summary,
      total_ports: portEntries.length,
      timestamp: new Date().toISOString(),
      cached: false,
      data_sources: {
        port_info: 'SearXNG Web Search',
        vulnerabilities: 'SearXNG Web Search'
      }
    };
    
    // Cache the results
    portIntelCache.set(q.session_id, { ...result, cached: true });
    console.log(`[PortIntel] Cached results for ${q.session_id}`);
    
    return respond(result);
  }

  // ── Agent STREAMING endpoint - DYNAMIC TSHARK ────────────────────────────────
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
      
      const sessionExists = await ensureSession(session_id);
      if (!sessionExists) {
        res.writeHead(404, { 'Content-Type': 'application/json', ...getCorsHeaders(origin) });
        return res.end(JSON.stringify({ error: 'Session expired or not found. Please re-upload your PCAP file.' }));
      }
      
      if (!prompt || typeof prompt !== 'string') {
        res.writeHead(400, { 'Content-Type': 'application/json', ...getCorsHeaders(origin) });
        return res.end(JSON.stringify({ error: 'Missing prompt' }));
      }

      console.log(`[Agent-Stream] Query received for session: ${session_id}`);
      
      // Get session data
      const sessionData = sessions.get(session_id);
      
      // Get ALL data types for comprehensive context
      const [packets, protocols, ports, dnsQueries, tlsSni, httpObjects, httpRequests] = await Promise.all([
        runTshark(session_id, '', DEFAULT_FIELDS, 500), // More packets
        getProtocolCounts(session_id, 0), // ALL protocols
        getAllPorts(session_id),
        getDnsQueries(session_id, 100),
        getTlsSni(session_id, 100),
        getHttpObjects(session_id),
        getHttpRequests(session_id, 100),
      ]);

      // Build comprehensive context
      const contextSummary = `Total Packets: ${sessionData?.total_packets || packets.length}
Protocols: ${Object.entries(protocols.protocols || {}).map(([p, c]) => `${p}(${c})`).join(', ')}
Unique Ports: ${Object.keys(ports).length}
DNS Queries: ${dnsQueries.length}
TLS Domains: ${tlsSni.length}
HTTP Objects: ${httpObjects.length}`;

      // Step 1: Analyze prompt to decide what data is needed
      const analysis = await analyzePromptForTshark(prompt, contextSummary);
      console.log(`[Agent-Stream] Analysis: ${analysis.reasoning}`);
      console.log(`[Agent-Stream] Need: ${analysis.data_types?.join(', ')}`);

      // Build full context based on analysis
      let fullContext = `**PCAP ANALYSIS DATA**\n\n`;
      
      // Basic stats always included
      fullContext += `**BASIC STATISTICS:**\n`;
      fullContext += `• Total Packets: ${(sessionData?.total_packets || packets.length).toLocaleString()}\n`;
      fullContext += `• Duration: ${protocols.maxTime?.toFixed(2) || 0} seconds\n\n`;
      
      // Protocols
      if (!analysis.data_types || analysis.data_types.includes('protocols')) {
        fullContext += `**PROTOCOL DISTRIBUTION:**\n`;
        const sortedProtos = Object.entries(protocols.protocols || {}).sort((a, b) => b[1] - a[1]);
        for (const [proto, count] of sortedProtos) {
          fullContext += `• ${proto}: ${count.toLocaleString()} packets\n`;
        }
        fullContext += `\n`;
      }
      
      // DNS Queries
      if (!analysis.data_types || analysis.data_types.includes('dns')) {
        if (dnsQueries.length > 0) {
          fullContext += `**DNS QUERIES (${dnsQueries.length} unique):**\n`;
          for (const q of dnsQueries.slice(0, 50)) {
            fullContext += `• ${q.domain}${q.answers ? ` → ${q.answers}` : ''}\n`;
          }
          fullContext += `\n`;
        }
      }
      
      // TLS SNI
      if (!analysis.data_types || analysis.data_types.includes('tls_sni')) {
        if (tlsSni.length > 0) {
          fullContext += `**TLS/HTTPS DOMAINS (${tlsSni.length} unique):**\n`;
          for (const s of tlsSni) {
            fullContext += `• ${s.server_name}${s.destination_ip ? ` (→ ${s.destination_ip})` : ''}\n`;
          }
          fullContext += `\n`;
        }
      }
      
      // HTTP Requests
      if (!analysis.data_types || analysis.data_types.includes('http')) {
        if (httpRequests.length > 0) {
          fullContext += `**HTTP REQUESTS (${httpRequests.length}):**\n`;
          for (const r of httpRequests) {
            fullContext += `• ${r.method || 'GET'} ${r.host || ''}${r.uri || '/'}\n`;
          }
          fullContext += `\n`;
        }
      }
      
      // HTTP Objects
      if (!analysis.data_types || analysis.data_types.includes('http_objects')) {
        if (httpObjects.length > 0) {
          fullContext += `**EXTRACTED HTTP OBJECTS (${httpObjects.length}):**\n`;
          for (const obj of httpObjects) {
            fullContext += `• ${obj.filename} (${(obj.size / 1024).toFixed(1)} KB, ${obj.content_type})\n`;
          }
          fullContext += `\n`;
        }
      }
      
      // Ports
      if (!analysis.data_types || analysis.data_types.includes('ports')) {
        const sortedPorts = Object.entries(ports).sort((a, b) => b[1] - a[1]).slice(0, 30);
        fullContext += `**TOP PORTS:**\n`;
        for (const [port, count] of sortedPorts) {
          fullContext += `• Port ${port}: ${count} packets\n`;
        }
        fullContext += `\n`;
      }
      
      // Top Talkers
      if (!analysis.data_types || analysis.data_types.includes('endpoints')) {
        const ipCounts = {};
        for (const p of packets) {
          if (p.src_ip) ipCounts[p.src_ip] = (ipCounts[p.src_ip] || 0) + 1;
          if (p.dst_ip) ipCounts[p.dst_ip] = (ipCounts[p.dst_ip] || 0) + 1;
        }
        const topIps = Object.entries(ipCounts).sort((a, b) => b[1] - a[1]).slice(0, 10);
        fullContext += `**TOP TALKERS (IPs with most traffic):**\n`;
        for (const [ip, count] of topIps) {
          fullContext += `• ${ip}: ${count.toLocaleString()} packets\n`;
        }
        fullContext += `\n`;
      }
      
      // Sample Packets
      if (!analysis.data_types || analysis.data_types.includes('packets')) {
        fullContext += `**SAMPLE PACKETS (first 50):**\n`;
        for (const p of packets.slice(0, 50)) {
          fullContext += `• #${p.id}: ${p.src_ip || 'N/A'} → ${p.dst_ip || 'N/A'} [${p.protocol}] ${p.info || ''}\n`;
        }
        fullContext += `\n`;
      }

      // Step 2: Stream response with full context
      await callLLMStream(prompt, res, origin, fullContext);
      return;
      
    } catch (e) {
      console.error(`[Agent-Stream] Error: ${e.message}`);
      res.writeHead(500, { 'Content-Type': 'application/json', ...getCorsHeaders(origin) });
      return res.end(JSON.stringify({ error: e.message }));
    }
  }

  // ── Agent Query (non-streaming) ─────────────────────────────
  if (url === '/pcap/agent/query' && method === 'POST') {
    if (!checkRateLimit(clientIp, RATE_AGENT))
      return respond({ error: 'Too many queries. Limit: 30/min.' }, 429);

    try {
      const body = await parseBody(req);
      const parsed = JSON.parse(body.toString());
      const { prompt, session_id } = parsed || {};

      if (!isValidSessionId(session_id)) return respond({ error: 'Invalid session_id' }, 400);
      
      const sessionExists = await ensureSession(session_id);
      if (!sessionExists) {
        return respond({ error: 'Session expired or not found. Please re-upload your PCAP file.' }, 404);
      }
      
      if (!prompt || typeof prompt !== 'string')
        return respond({ error: 'Missing prompt' }, 400);

      const sessionData = sessions.get(session_id);
      
      // Get data for context
      const [packets, ports, protocols] = await Promise.all([
        runTshark(session_id, '', DEFAULT_FIELDS, 100),
        getAllPorts(session_id),
        getProtocolCounts(session_id, 0),
      ]);
      
      const llmPrompt = `You are analyzing a PCAP network capture. Here is the data:

**Basic Stats:**
• Total Packets: ${sessionData?.total_packets || packets.length}
• Protocols: ${Object.entries(protocols.protocols || {}).map(([p, c]) => `${p}: ${c}`).join(', ')}

**Sample Packets (first 20):**
${packets.slice(0, 20).map(p => `• #${p.id}: ${p.src_ip || 'N/A'} → ${p.dst_ip || 'N/A'} [${p.protocol}] ${p.info || ''}`).join('\n')}

**Unique Ports:** ${Object.keys(ports).slice(0, 20).join(', ')}

**User Question:** "${prompt}"

Answer the user's question using ONLY the data above. Be specific with actual IPs, ports, and packet counts.`;

      const llmResponse = await callLLM(llmPrompt);
      
      return respond({
        tool_called: 'llm',
        parameters: {},
        result: null,
        response: llmResponse || 'Unable to analyze. Please try again.',
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

    const sessionExists = await ensureSession(q.session_id);
    if (!sessionExists) {
      return respond({ error: 'Session expired or not found. Please re-upload your PCAP file.' }, 404);
    }

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
    
    const sessionExists = await ensureSession(q.session_id);
    if (!sessionExists) {
      return respond({ error: 'Session expired or not found. Please re-upload your PCAP file.' }, 404);
    }

    const artifactKey = q.artifact_key;
    if (!artifactKey) return respond({ error: 'Missing artifact_key' }, 400);

    const artifacts = imageStore.get(q.session_id);
    if (!artifacts) return respond({ error: 'No objects found for this session' }, 404);

    const artifact = artifacts.get(artifactKey);
    if (!artifact) return respond({ error: 'Object not found' }, 404);

    res.writeHead(200, {
      'Content-Type': artifact.contentType,
      'Content-Length': artifact.buffer.length,
      'Cache-Control': 'public, max-age=3600',
      ...getCorsHeaders(origin),
    });
    return res.end(artifact.buffer);
  }

  // ── 404 ─────────────────────────────────────────────────────
  res.writeHead(404, { 'Content-Type': 'application/json', ...getCorsHeaders(origin) });
  return res.end(JSON.stringify({ error: 'Not found' }));
});

// ═══════════════════════════════════════════════════════════════════
// Start Server
// ═══════════════════════════════════════════════════════════════════
const PORT = process.env.PORT || 10000;
server.listen(PORT, () => {
  console.log('═══════════════════════════════════════════════════════════════');
  console.log(`🚀 PCAP Analyzer Backend running on port ${PORT}`);
  console.log(`📊 Engine: TShark + SearXNG (NO AI for port intel)`);
  console.log(`🤖 LLM: Cloudflare Workers AI (${CF_LLM_MODEL})`);
  console.log('═══════════════════════════════════════════════════════════════');
});

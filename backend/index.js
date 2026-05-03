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
const CF_LLM_MODEL = '@cf/qwen/qwen2.5-14b-instruct';
const CF_LLM_TIMEOUT_MS = 15000;
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
const portIntelCache = new Map(); // Cache for port intelligence
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
// TShark core runner - FIXED to handle root warning
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
    // Suppress root warning with 2>/dev/null
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

function getProtocolCounts(sessionId, limit = 2000) {
  return new Promise((resolve) => {
    const pcapPath = path.join(PCAP_DIR, `${sessionId}.pcap`);
    if (!fs.existsSync(pcapPath)) return resolve({ protocols: {}, maxTime: 0 });
    
    const cmd = `"${TSHARK_BIN}" -r "${pcapPath}" -T fields -E separator=/t -e _ws.col.Protocol -e frame.time_relative -c ${limit} 2>/dev/null`;
    
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
// IANA Port Database
// ═══════════════════════════════════════════════════════════════════
const IANA_PORTS = {
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
  123: { name: 'ntp', desc: 'Network Time Protocol', risk: 'LOW', secure: 'Authenticated NTP' },
  135: { name: 'rpc', desc: 'Remote Procedure Call', risk: 'HIGH', secure: 'Firewall restrict' },
  137: { name: 'netbios-ns', desc: 'NetBIOS Name Service', risk: 'MEDIUM', secure: 'Disable if unused' },
  138: { name: 'netbios-dgm', desc: 'NetBIOS Datagram', risk: 'MEDIUM', secure: 'Disable if unused' },
  139: { name: 'netbios-ssn', desc: 'NetBIOS Session', risk: 'HIGH', secure: 'SMB over SSH' },
  143: { name: 'imap', desc: 'Internet Message Access Protocol', risk: 'MEDIUM', secure: 'IMAPS (993)' },
  161: { name: 'snmp', desc: 'Simple Network Management Protocol', risk: 'HIGH', secure: 'SNMPv3' },
  389: { name: 'ldap', desc: 'Lightweight Directory Access Protocol', risk: 'MEDIUM', secure: 'LDAPS (636)' },
  443: { name: 'https', desc: 'HTTP Secure', risk: 'LOW', secure: 'Already secure' },
  445: { name: 'smb', desc: 'Server Message Block', risk: 'HIGH', secure: 'VPN only' },
  465: { name: 'smtps', desc: 'SMTP Secure', risk: 'LOW', secure: 'Already secure' },
  547: { name: 'dhcpv6', desc: 'DHCPv6 Server', risk: 'LOW', secure: 'N/A' },
  587: { name: 'smtp-msa', desc: 'SMTP Message Submission', risk: 'MEDIUM', secure: 'STARTTLS' },
  636: { name: 'ldaps', desc: 'LDAP Secure', risk: 'LOW', secure: 'Already secure' },
  993: { name: 'imaps', desc: 'IMAP Secure', risk: 'LOW', secure: 'Already secure' },
  995: { name: 'pop3s', desc: 'POP3 Secure', risk: 'LOW', secure: 'Already secure' },
  1433: { name: 'mssql', desc: 'Microsoft SQL Server', risk: 'HIGH', secure: 'Encrypt connections' },
  1521: { name: 'oracle', desc: 'Oracle Database', risk: 'HIGH', secure: 'Encrypt connections' },
  1900: { name: 'ssdp', desc: 'Simple Service Discovery Protocol (UPnP)', risk: 'MEDIUM', secure: 'Disable UPnP if unused' },
  3306: { name: 'mysql', desc: 'MySQL Database', risk: 'HIGH', secure: 'Bind localhost + TLS' },
  3389: { name: 'rdp', desc: 'Remote Desktop Protocol', risk: 'HIGH', secure: 'VPN + NLA' },
  5353: { name: 'mdns', desc: 'Multicast DNS (Bonjour/mDNS)', risk: 'LOW', secure: 'Disable if unused' },
  5355: { name: 'llmnr', desc: 'Link-Local Multicast Name Resolution', risk: 'MEDIUM', secure: 'Disable if unused' },
  5432: { name: 'postgresql', desc: 'PostgreSQL Database', risk: 'HIGH', secure: 'Bind localhost + TLS' },
  5900: { name: 'vnc', desc: 'Virtual Network Computing', risk: 'HIGH', secure: 'VPN + SSH tunnel' },
  6379: { name: 'redis', desc: 'Redis Database', risk: 'HIGH', secure: 'Bind localhost + AUTH' },
  8080: { name: 'http-proxy', desc: 'HTTP Proxy/Alt Port', risk: 'MEDIUM', secure: 'HTTPS (443)' },
  8443: { name: 'https-alt', desc: 'HTTPS Alt Port', risk: 'LOW', secure: 'Already secure' },
  9200: { name: 'elasticsearch', desc: 'Elasticsearch HTTP', risk: 'HIGH', secure: 'Bind localhost + Auth' },
  27017: { name: 'mongodb', desc: 'MongoDB Database', risk: 'HIGH', secure: 'Bind localhost + Auth' },
};

// ── SearXNG Search for Port Intelligence ──────────────────────────────────
async function searchPortWithSearXNG(port) {
  return new Promise((resolve, reject) => {
    const searchUrl = `${SEARXNG_URL}/search?q=TCP+UDP+port+${port}+service+protocol&format=json&engines=${SEARXNG_ENGINES}`;

    console.log(`[SearXNG] Searching for port ${port}...`);

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

          // Extract useful info from search results
          let serviceName = 'unknown';
          let description = '';
          let commonUses = [];
          let risks = [];

          for (const result of results.slice(0, 5)) {
            const content = (result.content || '').toLowerCase();
            const title = (result.title || '').toLowerCase();

            // Try to identify service name from title or content
            if (!description && result.content) {
              description = result.content.slice(0, 200);
            }

            // Look for common patterns
            if (content.includes('dns') || title.includes('dns')) {
              serviceName = 'dns';
              commonUses.push('DNS queries', 'Name resolution');
            }
            if (content.includes('dhcp') || title.includes('dhcp')) {
              serviceName = 'dhcp';
              commonUses.push('IP address assignment', 'Network configuration');
            }
            if (content.includes('http') || title.includes('http') || content.includes('web')) {
              commonUses.push('Web services', 'HTTP traffic');
            }
            if (content.includes('streaming') || content.includes('media')) {
              commonUses.push('Media streaming', 'Video/Audio');
            }
            if (content.includes('gaming') || content.includes('game')) {
              commonUses.push('Gaming', 'Online multiplayer');
            }
            if (content.includes('voip') || content.includes('sip')) {
              commonUses.push('VoIP', 'Voice over IP');
            }
            if (content.includes('vpn') || content.includes('tunnel')) {
              commonUses.push('VPN', 'Secure tunneling');
            }
            if (content.includes('vulnerability') || content.includes('exploit') || content.includes('security')) {
              risks.push('Potential security concerns found');
            }
          }

          // Default common uses if none found
          if (commonUses.length === 0) {
            commonUses.push('Network service', 'Application communication');
          }

          console.log(`[SearXNG] ✓ Found info for port ${port}: ${serviceName}`);
          resolve({
            service_name: serviceName,
            description: description || `Port ${port} - identified via web search`,
            common_uses: commonUses,
            risks: risks.length > 0 ? risks : ['Standard network service - review traffic patterns'],
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

// ── Port Intelligence ──────────────────────────────────────────
async function getPortIntelligence(port) {
  const ianaInfo = IANA_PORTS[port];

  if (ianaInfo) {
    // Add common uses based on service
    const commonUsesMap = {
      'ftp-data': ['File transfer', 'FTP data channel'],
      'ftp': ['File transfer', 'FTP control'],
      'ssh': ['Remote administration', 'Secure file transfer (SFTP)', 'Tunneling'],
      'telnet': ['Legacy remote access', 'Device configuration'],
      'smtp': ['Email sending', 'Mail relay'],
      'dns': ['Domain name resolution', 'DNS queries'],
      'dhcp': ['Automatic IP assignment', 'Network boot'],
      'tftp': ['Simple file transfer', 'Network boot'],
      'http': ['Web browsing', 'API services', 'Web applications'],
      'pop3': ['Email retrieval', 'Mail client access'],
      'ntp': ['Time synchronization', 'Clock sync'],
      'rpc': ['Remote procedure calls', 'Windows services'],
      'netbios-ns': ['Windows name resolution', 'NetBIOS'],
      'netbios-dgm': ['Windows datagram service', 'NetBIOS'],
      'netbios-ssn': ['Windows session service', 'NetBIOS'],
      'imap': ['Email retrieval', 'Mail client access'],
      'snmp': ['Network monitoring', 'Device management'],
      'ldap': ['Directory services', 'Authentication'],
      'https': ['Secure web browsing', 'API services', 'Web applications'],
      'smb': ['File sharing', 'Printer sharing', 'Windows networking'],
      'smtps': ['Secure email sending', 'Mail relay'],
      'dhcpv6': ['IPv6 address assignment', 'IPv6 network config'],
      'ldaps': ['Secure directory services', 'Secure authentication'],
      'imaps': ['Secure email retrieval', 'Mail client access'],
      'pop3s': ['Secure email retrieval', 'Mail client access'],
      'mssql': ['Microsoft SQL Server', 'Database access'],
      'oracle': ['Oracle Database', 'Database access'],
      'ssdp': ['UPnP discovery', 'Device discovery'],
      'mysql': ['MySQL Database', 'Database access'],
      'rdp': ['Remote desktop', 'Windows remote access'],
      'mdns': ['Bonjour/mDNS', 'Local name resolution', 'Apple services'],
      'llmnr': ['Windows name resolution', 'Local network'],
      'postgresql': ['PostgreSQL Database', 'Database access'],
      'vnc': ['Remote desktop access', 'Screen sharing'],
      'redis': ['In-memory database', 'Caching', 'Message broker'],
      'http-proxy': ['Web proxy', 'Alternative HTTP port'],
      'https-alt': ['Alternative HTTPS port', 'Web services'],
      'elasticsearch': ['Search engine', 'Log analytics', 'Full-text search'],
      'mongodb': ['MongoDB Database', 'NoSQL database'],
    };

    return {
      port: port,
      service_name: ianaInfo.name,
      description: ianaInfo.desc,
      secure_alternative: ianaInfo.secure,
      common_uses: commonUsesMap[ianaInfo.name] || ['Network service'],
      risk: ianaInfo.risk,
      reason: ianaInfo.desc,
      cve_id: null,
      cvss_score: null,
      cve_count: 0,
      all_cves: [],
      source: 'IANA Port Registry',
    };
  }

  if (port >= 49152 && port <= 65535) {
    return {
      port: port,
      service_name: 'ephemeral',
      description: `Ephemeral port ${port} - client-side temporary connection`,
      secure_alternative: 'Usually client-side, low risk',
      common_uses: ['Client connections', 'Temporary connections', 'Outbound traffic'],
      risk: 'LOW',
      reason: 'Ephemeral port - typically used for outbound client connections',
      cve_id: null,
      cvss_score: null,
      cve_count: 0,
      all_cves: [],
      source: 'IANA Port Registry',
    };
  }

  // Unknown port - search SearXNG
  console.log(`[PortIntel] Unknown port ${port} - searching SearXNG...`);
  const searxngResult = await searchPortWithSearXNG(port);

  if (searxngResult) {
    return {
      port: port,
      service_name: searxngResult.service_name,
      description: searxngResult.description,
      secure_alternative: 'Review traffic patterns and firewall rules',
      common_uses: searxngResult.common_uses,
      risk: 'MEDIUM',
      reason: searxngResult.risks[0] || 'Unknown service - identified via web search',
      cve_id: null,
      cvss_score: null,
      cve_count: 0,
      all_cves: [],
      source: searxngResult.source,
    };
  }

  return {
    port: port,
    service_name: 'unknown',
    description: `Port ${port} - unknown service`,
    secure_alternative: 'Investigate manually',
    common_uses: ['Unknown - requires manual investigation'],
    risk: 'MEDIUM',
    reason: 'Unknown service - manual investigation recommended',
    cve_id: null,
    cvss_score: null,
    cve_count: 0,
    all_cves: [],
    source: 'none',
  };
}

// ═══════════════════════════════════════════════════════════════════
// LLM Functions
// ═══════════════════════════════════════════════════════════════════
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
      stream: true
    });
    
    // URL-encode the model name (@ symbol and special chars)
    const encodedModel = encodeURIComponent(CF_LLM_MODEL);

    const options = {
      hostname: 'api.cloudflare.com',
      port: 443,
      path: `/client/v4/accounts/${CF_ACCOUNT_ID}/ai/run/${encodedModel}`,
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${CF_API_TOKEN}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData),
      },
      timeout: CF_LLM_TIMEOUT_MS,
    };

    console.log(`[LLM-Stream] Starting streaming request to Cloudflare...`);
    console.log(`[LLM-Stream] Model: ${CF_LLM_MODEL}, Encoded: ${encodedModel}`);
    
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
              if (json.response) {
                fullResponse += json.response;
                res.write(`data: ${JSON.stringify({ token: json.response })}\n\n`);
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
      max_tokens: 600
    });

    // URL-encode the model name (@ symbol and special chars)
    const encodedModel = encodeURIComponent(CF_LLM_MODEL);

    const options = {
      hostname: 'api.cloudflare.com',
      port: 443,
      path: `/client/v4/accounts/${CF_ACCOUNT_ID}/ai/run/${encodedModel}`,
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
          
          if (json.success && json.result?.response) {
            console.log(`[LLM] ✓ Got response (${json.result.response.length} chars)`);
            resolve(json.result.response);
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
      console.error(`[LLM] Timeout after ${CF_LLM_TIMEOUT_MS}ms`);
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
    return respond({ status: 'ok', engine: 'TShark + IANA Port DB', sessions: sessions.size });
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
        getProtocolCounts(session_id, 2000),
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

      // Return response immediately
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

  // ── Packets Detailed ────────────────────────────────────────
  if (url.startsWith('/pcap/packets-detailed') && method === 'GET') {
    const q = getQuery(url);
    if (!isValidSessionId(q.session_id)) return respond({ error: 'Invalid session_id' }, 400);

    const page = Math.max(1, parseInt(q.page || '1'));
    const per_page = Math.min(200, parseInt(q.per_page || '50'));
    const skip = (page - 1) * per_page;

    const pcapPath = path.join(PCAP_DIR, `${q.session_id}.pcap`);
    if (!fs.existsSync(pcapPath)) return respond({ packets: [], total: 0, page, per_page });

    let cmd = `"${TSHARK_BIN}" -r "${pcapPath}" -T json -c ${skip + per_page} 2>/dev/null`;
    
    console.log(`[TSharkDetailed] Running JSON output for packets`);

    exec(cmd, { timeout: 60000, maxBuffer: 100 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) {
        console.error(`[TSharkDetailed] Error: ${err.message}`);
        return respond({ packets: [], total: 0, page, per_page });
      }

      try {
        const jsonData = JSON.parse(stdout);
        const pageData = jsonData.slice(skip);
        
        const packets = pageData.map((pkt, idx) => {
          const layers = pkt._source?.layers || {};
          const frame = layers.frame || {};
          
          let src_ip = null;
          let dst_ip = null;
          if (layers.ip) {
            src_ip = layers.ip['ip.src'] || null;
            dst_ip = layers.ip['ip.dst'] || null;
          } else if (layers.ipv6) {
            src_ip = layers.ipv6['ipv6.src'] || null;
            dst_ip = layers.ipv6['ipv6.dst'] || null;
          }
          
          let src_port = null;
          let dst_port = null;
          if (layers.tcp) {
            src_port = parseInt(layers.tcp['tcp.srcport']) || null;
            dst_port = parseInt(layers.tcp['tcp.dstport']) || null;
          } else if (layers.udp) {
            src_port = parseInt(layers.udp['udp.srcport']) || null;
            dst_port = parseInt(layers.udp['udp.dstport']) || null;
          }
          
          let protocol = 'UNKNOWN';
          if (layers.tcp) protocol = 'TCP';
          else if (layers.udp) protocol = 'UDP';
          else if (layers.icmp || layers.icmpv6) protocol = 'ICMP';
          else if (layers.arp) protocol = 'ARP';
          else if (layers.dns || layers.mdns) protocol = layers.mdns ? 'MDNS' : 'DNS';
          else if (layers.http) protocol = 'HTTP';
          else if (layers.tls || layers.ssl) protocol = 'TLS';
          else if (layers.dhcp || layers.dhcpv6) protocol = layers.dhcpv6 ? 'DHCPv6' : 'DHCP';
          else if (layers.ssdp) protocol = 'SSDP';
          else if (layers.ntp) protocol = 'NTP';
          else if (layers.igmp) protocol = 'IGMP';
          
          let info = '';
          if (layers.dns || layers.mdns) {
            const dnsLayer = layers.dns || layers.mdns;
            if (dnsLayer['dns.qry.name']) {
              info = dnsLayer['dns.flags.response'] === '1' ? 
                `Response: ${dnsLayer['dns.qry.name']}` : 
                `Query: ${dnsLayer['dns.qry.name']}`;
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
          } else if (layers.arp) {
            const opcode = layers.arp['arp.opcode'];
            const senderIP = layers.arp['arp.src.proto_ipv4'] || '';
            const targetIP = layers.arp['arp.dst.proto_ipv4'] || '';
            const senderMAC = layers.arp['arp.src.hw_mac'] || '';
            
            if (opcode === '1') {
              info = targetIP ? `Who has ${targetIP}? Tell ${senderIP}` : 'ARP Request';
            } else if (opcode === '2') {
              info = senderIP && senderMAC ? `${senderIP} is at ${senderMAC}` : 'ARP Reply';
            }
          }
          
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
    console.log(`[PortIntel] Analyzing ${portEntries.length} unique ports`);
    
    // Separate ephemeral ports from service ports
    const ephemeralPorts = [];
    const servicePorts = [];
    
    for (const [port, count] of portEntries) {
      const portNum = parseInt(port);
      if (portNum >= 49152 && portNum <= 65535) {
        ephemeralPorts.push({ port: portNum, count });
      } else {
        servicePorts.push({ port: portNum, count });
      }
    }
    
    // Get intelligence for service ports
    const serviceAlerts = await Promise.all(
      servicePorts.map(async ({ port, count }) => {
        const intel = await getPortIntelligence(port);
        return {
          port,
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
    
    // Group ephemeral ports into a single entry
    const alerts = [...serviceAlerts];

    if (ephemeralPorts.length > 0) {
      const totalEphemeralPackets = ephemeralPorts.reduce((sum, p) => sum + p.count, 0);
      const portList = ephemeralPorts.map(p => p.port).sort((a, b) => a - b);
      // Store ALL port numbers, not just sample
      const portDetails = ephemeralPorts.map(p => ({ port: p.port, count: p.count })).sort((a, b) => a.port - b.port);

      alerts.push({
        port: 'ephemeral',
        port_range: { min: portList[0], max: portList[portList.length - 1] },
        port_count: ephemeralPorts.length,
        count: totalEphemeralPackets,
        risk: 'LOW',
        reason: 'Ephemeral ports (49152-65535) are used for outbound client connections',
        service_name: 'ephemeral',
        description: `${ephemeralPorts.length} ephemeral ports used for outbound connections`,
        secure_alternative: 'Client-side ports, typically low risk',
        common_uses: ['Client connections', 'Temporary connections', 'Outbound traffic'],
        source: 'IANA Port Registry',
        all_ports: portDetails, // ALL port numbers with their counts
        sample_ports: portList.slice(0, 10), // Keep sample for backward compatibility
      });
    }
    
    const summary = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const a of alerts) {
      const r = a.risk.toLowerCase();
      if (summary[r] !== undefined) summary[r]++;
    }
    
    const result = { 
      alerts, 
      summary,
      total_ports: portEntries.length,
      service_ports: servicePorts.length,
      ephemeral_ports: ephemeralPorts.length,
      timestamp: new Date().toISOString(),
      cached: false
    };
    
    // Cache the results
    portIntelCache.set(q.session_id, { ...result, cached: true });
    console.log(`[PortIntel] Cached results for ${q.session_id}`);
    
    return respond(result);
  }

  // ── Agent STREAMING endpoint ────────────────────────────────
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
      
      // Get session data for context
      const sessionData = sessions.get(session_id);
      const pcapPath = path.join(PCAP_DIR, `${session_id}.pcap`);
      
      // Build context from current session
      const [packets, ports, protocols] = await Promise.all([
        runTshark(session_id, '', DEFAULT_FIELDS, 100),
        getAllPorts(session_id),
        getProtocolCounts(session_id, 1000),
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

      await callLLMStream(llmPrompt, res, origin);
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
        getProtocolCounts(session_id, 1000),
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

// Global error handler
process.on('uncaughtException', (err) => {
  console.error('[FATAL] Uncaught exception:', err.message);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('[FATAL] Unhandled rejection:', reason);
});

const PORT = process.env.PORT || 4000;
server.listen(PORT, () => {
  console.log(`✅ TShark PCAP Analyzer running on port ${PORT}`);
  console.log(`🔧 TShark binary: ${TSHARK_BIN}`);
  console.log(`📁 PCAP dir:      ${path.resolve(PCAP_DIR)}`);
  console.log(`📁 Export dir:    ${path.resolve(EXPORT_DIR)}`);
});

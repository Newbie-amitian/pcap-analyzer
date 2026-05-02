const http = require('http');
const https = require('https');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');

// SearXNG Configuration - YOUR INSTANCE ONLY
// ============================
const SEARXNG_URL = process.env.SEARXNG_URL || 'https://searxng-krq1.onrender.com';

// Search settings
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

setInterval(() => {
  const now = Date.now();
  for (const [id, session] of sessions) {
    if (now - session.created_at > SESSION_TTL_MS) {
      try { const p = path.join(PCAP_DIR, `${id}.pcap`); if (fs.existsSync(p)) fs.unlinkSync(p); } catch (_) { }
      try { const p = path.join(EXPORT_DIR, id); if (fs.existsSync(p)) fs.rmSync(p, { recursive: true }); } catch (_) { }
      sessions.delete(id);
      imageStore.delete(id);
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
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';
function getCorsHeaders(origin) {
  return {
    'Access-Control-Allow-Origin': ALLOWED_ORIGIN === '*' ? '*' : (origin || ALLOWED_ORIGIN),
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
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
// Include both IPv4 and IPv6 fields, TCP and UDP ports
const DEFAULT_FIELDS = [
  'frame.number', 
  'ip.src', 'ip.dst',           // IPv4 addresses
  'ipv6.src', 'ipv6.dst',       // IPv6 addresses
  'frame.len',
  '_ws.col.Protocol', 
  'tcp.srcport', 'tcp.dstport', // TCP ports
  'udp.srcport', 'udp.dstport', // UDP ports
  'frame.time_relative',
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

    exec(cmd, { timeout: 60000 }, (err, stdout, stderr) => {
      if (err) {
        console.error(`[TShark] exec error: ${err.message}`);
        if (stderr) console.error(`[TShark] stderr: ${stderr.slice(0, 400)}`);
        return resolve([]);
      }
      const lines = stdout.trim().split('\n').filter(l => l.trim());
      const packets = lines.map(line => {
        const c = line.split('\t');
        // Field order: frame.number, ip.src, ip.dst, ipv6.src, ipv6.dst, frame.len, protocol, tcp.srcport, tcp.dstport, udp.srcport, udp.dstport, time_relative
        // Use IPv4 if available, else IPv6; Use TCP ports if available, else UDP ports
        return {
          id: parseInt(c[0]) || 0,
          src_ip: c[1] || c[3] || null,  // IPv4 src or IPv6 src
          dst_ip: c[2] || c[4] || null,  // IPv4 dst or IPv6 dst
          length: parseInt(c[5]) || 0,
          protocol: c[6] || 'UNKNOWN',
          src_port: parseInt(c[7]) || parseInt(c[9]) || null,  // TCP src or UDP src
          dst_port: parseInt(c[8]) || parseInt(c[10]) || null, // TCP dst or UDP dst
          timestamp: parseFloat(c[11]) || 0,
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

    exec(cmd, { timeout: 60000 }, (err, stdout, stderr) => {
      if (err) {
        console.error(`[TSharkPaged] exec error: ${err.message}`);
        if (stderr) console.error(`[TSharkPaged] stderr: ${stderr.slice(0, 400)}`);
        return resolve([]);
      }
      const lines = stdout.trim().split('\n').filter(l => l.trim());
      const pageLines = lines.slice(skip);
      const packets = pageLines.map(line => {
        const c = line.split('\t');
        // Field order: frame.number, ip.src, ip.dst, ipv6.src, ipv6.dst, frame.len, protocol, tcp.srcport, tcp.dstport, udp.srcport, udp.dstport, time_relative
        return {
          id: parseInt(c[0]) || 0,
          src_ip: c[1] || c[3] || null,  // IPv4 src or IPv6 src
          dst_ip: c[2] || c[4] || null,  // IPv4 dst or IPv6 dst
          length: parseInt(c[5]) || 0,
          protocol: c[6] || 'UNKNOWN',
          src_port: parseInt(c[7]) || parseInt(c[9]) || null,  // TCP src or UDP src
          dst_port: parseInt(c[8]) || parseInt(c[10]) || null, // TCP dst or UDP dst
          timestamp: parseFloat(c[11]) || 0,
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
    exec(cmd, { timeout: 120000 }, (err, stdout) => {
      if (err) return resolve(0);
      const count = stdout.trim().split('\n').filter(l => l.trim()).length;
      console.log(`[TShark] True packet count: ${count}`);
      resolve(count);
    });
  });
}

function runTsharkStat(sessionId, statCommand) {
  return new Promise((resolve) => {
    const pcapPath = path.join(PCAP_DIR, `${sessionId}.pcap`);
    if (!fs.existsSync(pcapPath)) return resolve('PCAP not found');
    const cmd = `"${TSHARK_BIN}" -r "${pcapPath}" -q -z ${statCommand}`;
    console.log(`[TShark-Stat] Running: ${cmd}`);
    exec(cmd, { timeout: 60000 }, (err, stdout, stderr) => {
      if (err) {
        console.error(`[TShark-Stat] Error: ${err.message}`);
        if (stderr) console.error(`[TShark-Stat] stderr: ${stderr.slice(0, 400)}`);
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

// ── Parse TShark Verbose Output (Wireshark-style) ─────────────────────────────
function parseVerboseOutput(output, targetPacket) {
  const lines = output.split('\n');
  const packets = [];
  let currentPacket = null;
  let currentLayer = null;
  let currentSubLayer = null;
  let lastIndent = 0;
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim()) continue;
    
    // Calculate indentation level
    const trimmedLine = line.trimStart();
    const indent = line.length - trimmedLine.length;
    
    // Detect new packet (starts with "Frame X:")
    if (trimmedLine.match(/^Frame \d+:/)) {
      if (currentPacket) packets.push(currentPacket);
      currentPacket = {
        frame: {},
        layers: [],
        raw_text: ''
      };
      currentLayer = null;
      currentSubLayer = null;
      lastIndent = indent;
      continue;
    }
    
    if (!currentPacket) continue;
    
    // Detect new protocol layer (lines ending with no colon, followed by indented content)
    // Protocol layers typically start at indent 0-4 and have specific patterns
    const layerPatterns = [
      /^Ethernet II/,
      /^Internet Protocol Version \d/,
      /^IPv[46]/,
      /^User Datagram Protocol/,
      /^Transmission Control Protocol/,
      /^Internet Control Message Protocol/,
      /^Address Resolution Protocol/,
      /^Domain Name System/,
      /^Hypertext Transfer Protocol/,
      /^HTTP\/\d/,
      /^Transport Layer Security/,
      /^Secure Sockets Layer/,
      /^DHCPv?6?/,
      /^Simple Network Management Protocol/,
      /^Server Message Block/,
      /^NetBIOS/,
      /^OpenVPN/,
      /^Generic Routing Encapsulation/,
      /^Spanning Tree Protocol/,
      /^Link Layer Discovery Protocol/,
      /^Cisco Discovery Protocol/,
      /^Dynamic Host Configuration Protocol/,
      /^Internet Group Management Protocol/,
      /^Pragmatic General Multicast/,
      /^Real-time Transport Protocol/,
      /^Session Description Protocol/,
      /^Session Announcement Protocol/,
      /^File Transfer Protocol/,
      /^Simple Mail Transfer Protocol/,
      /^Post Office Protocol/,
      /^Internet Message Access Protocol/,
      /^Border Gateway Protocol/,
      /^Open Shortest Path First/,
      /^Layer [0-9]/,
      /^\w+[\s\w]*:$/,  // Generic protocol name ending with colon
    ];
    
    // Check if this is a new layer header (typically at indent 0-4)
    if (indent <= 8 && !trimmedLine.includes(': ') && !trimmedLine.startsWith('[')) {
      const possibleLayer = trimmedLine.replace(/:$/, '').trim();
      if (possibleLayer.length > 3 && possibleLayer.length < 60) {
        // Check if it matches a known protocol pattern
        const isLayer = layerPatterns.some(p => p.test(possibleLayer));
        if (isLayer || (indent === 0 && possibleLayer.includes('Protocol'))) {
          currentLayer = {
            name: possibleLayer,
            fields: [],
            sublayers: []
          };
          currentPacket.layers.push(currentLayer);
          currentSubLayer = null;
          lastIndent = indent;
          continue;
        }
      }
    }
    
    // Parse field lines (contains ": " separator)
    if (trimmedLine.includes(': ')) {
      const colonIndex = trimmedLine.indexOf(': ');
      const key = trimmedLine.substring(0, colonIndex).trim();
      const value = trimmedLine.substring(colonIndex + 2).trim();
      
      if (key && value !== undefined) {
        const field = { key, value, indent };
        
        // Determine which layer/sublayer to add to
        if (indent > 12 && currentSubLayer) {
          currentSubLayer.fields.push(field);
        } else if (currentLayer) {
          // Check if this starts a new sublayer (indented section)
          if (indent > lastIndent + 4) {
            currentSubLayer = {
              name: key,
              fields: [field]
            };
            currentLayer.sublayers.push(currentSubLayer);
          } else {
            currentLayer.fields.push(field);
            currentSubLayer = null;
          }
        } else {
          // Frame-level fields
          currentPacket.frame[key] = value;
        }
        lastIndent = indent;
      }
    } else if (trimmedLine.startsWith('[') && trimmedLine.endsWith(']')) {
      // Bracketed metadata like [Coloring Rule Name: UDP]
      const content = trimmedLine.slice(1, -1);
      if (content.includes(': ')) {
        const [key, value] = content.split(': ');
        if (currentLayer) {
          currentLayer.fields.push({ key: `[${key}]`, value, indent });
        }
      }
    } else if (currentLayer && trimmedLine.length > 0 && !trimmedLine.includes(':')) {
      // Continuation line or standalone value
      if (currentLayer.fields.length > 0) {
        const lastField = currentLayer.fields[currentLayer.fields.length - 1];
        if (lastField.value.length < 200) {
          lastField.value += ' ' + trimmedLine;
        }
      }
    }
  }
  
  // Don't forget the last packet
  if (currentPacket) packets.push(currentPacket);
  
  // Find the target packet (TShark -V outputs all packets up to -c limit)
  const target = packets.find((p, i) => i === targetPacket - 1);
  
  if (!target && packets.length > 0) {
    return packets[packets.length - 1]; // Return last packet if target not found
  }
  
  return target || { frame: {}, layers: [], raw_text: output };
}

// ── SEARXNG WEB SEARCH FOR PORT INFO ─────────────────────────────────
const portInfoCache = new Map();
const PORT_INFO_CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours

// SearXNG search function (NO AI - pure HTTP requests to your SearXNG instance)
function searxngSearch(query) {
  return new Promise((resolve) => {
    const url = `${SEARXNG_URL}/search?q=${encodeURIComponent(query)}&format=json&engines=${SEARXNG_ENGINES}`;
    
    console.log(`[SearXNG] Searching: "${query}" via ${SEARXNG_URL}`);
    
    const req = https.get(url, {
      headers: { 
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'application/json'
      },
      timeout: SEARXNG_TIMEOUT_MS
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
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

// ── Local agent ────────────────────────────────────────────────────
function localDynamicAgent(prompt) {
  const l = prompt.toLowerCase();
  const portM = l.match(/port\s*(\d{1,5})/);
  const ipM = l.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
  const macM = l.match(/([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})/i);

  if (l.includes('hierarchy')) return { tool: 'stat', stat: 'io,phs' };
  if (l.includes('timeline')) return { tool: 'stat', stat: 'io,stat,1' };
  if (l.includes('top talker') || l.includes('bandwidth') || l.includes('endpoint'))
    return { tool: 'stat', stat: 'conv,ip' };
  if (l.includes('expert') || l.includes('warning')) return { tool: 'stat', stat: 'expert' };
  if (l.includes('summary') || l.includes('overview')) return { tool: 'stat', stat: 'io,stat,0' };
  if (l.includes('vulnerab') || l.includes('risk')) return { tool: 'vuln' };
  if (l.includes('retransmission')) return { tool: 'packets', filter: 'tcp.analysis.retransmission', fields: DEFAULT_FIELDS };
  if (l.includes('out of order')) return { tool: 'packets', filter: 'tcp.analysis.out_of_order', fields: DEFAULT_FIELDS };
  if (l.includes('zero window')) return { tool: 'packets', filter: 'tcp.analysis.zero_window', fields: DEFAULT_FIELDS };
  if (l.includes('duplicate ack')) return { tool: 'packets', filter: 'tcp.analysis.duplicate_ack', fields: DEFAULT_FIELDS };
  if (l.includes('rst') || l.includes('reset'))
    return { tool: 'packets', filter: 'tcp.flags.reset == 1', fields: DEFAULT_FIELDS };
  if (l.includes('syn flood') || l.includes('port scan'))
    return { tool: 'packets', filter: 'tcp.flags.syn == 1 && tcp.flags.ack == 0', fields: DEFAULT_FIELDS };
  if (l.includes('http method') || l.includes('http request'))
    return { tool: 'packets', filter: 'http.request', fields: [...DEFAULT_FIELDS, 'http.request.method', 'http.request.uri', 'http.host'] };
  if (l.includes('http status') || l.includes('404') || l.includes('500'))
    return { tool: 'packets', filter: 'http.response', fields: [...DEFAULT_FIELDS, 'http.response.code', 'http.response.phrase'] };
  if (l.includes('user agent'))
    return { tool: 'packets', filter: 'http.user_agent', fields: [...DEFAULT_FIELDS, 'http.user_agent'] };
  if (l.includes('tls') || l.includes('sni'))
    return { tool: 'packets', filter: 'tls.handshake.type == 1', fields: [...DEFAULT_FIELDS, 'tls.handshake.extensions_server_name'] };
  if (l.includes('certificate'))
    return { tool: 'packets', filter: 'tls.handshake.type == 11', fields: ['frame.number', 'ip.src', 'ip.dst', 'x509ce.dNSName'] };
  if (l.includes('dns') || l.includes('domain'))
    return { tool: 'packets', filter: 'dns', fields: [...DEFAULT_FIELDS, 'dns.qry.name'] };
  if (l.includes('credential') || l.includes('password'))
    return { tool: 'packets', filter: 'ftp.request.command == "USER" || ftp.request.command == "PASS" || http.authorization', fields: DEFAULT_FIELDS };
  if (l.includes('arp') || l.includes('spoof'))
    return { tool: 'packets', filter: 'arp', fields: ['frame.number', 'arp.opcode', 'arp.src.hw_mac', 'arp.src.proto_ipv4', 'arp.dst.proto_ipv4'] };
  if (l.includes('dhcp'))
    return { tool: 'packets', filter: 'dhcp', fields: [...DEFAULT_FIELDS, 'dhcp.option.hostname'] };
  if (l.includes('icmp') || l.includes('ping'))
    return { tool: 'packets', filter: 'icmp', fields: [...DEFAULT_FIELDS, 'icmp.type'] };
  if (l.includes('broadcast'))
    return { tool: 'packets', filter: 'eth.dst == ff:ff:ff:ff:ff:ff', fields: DEFAULT_FIELDS };
  if (l.includes('smb'))
    return { tool: 'packets', filter: 'smb || smb2', fields: [...DEFAULT_FIELDS, 'smb2.cmd'] };
  if (l.includes('rdp'))
    return { tool: 'packets', filter: 'tcp.dstport == 3389', fields: DEFAULT_FIELDS };
  if (l.includes('ssh'))
    return { tool: 'packets', filter: 'tcp.dstport == 22', fields: DEFAULT_FIELDS };
  if (l.includes('smtp') || l.includes('email'))
    return { tool: 'packets', filter: 'smtp', fields: [...DEFAULT_FIELDS, 'smtp.req.from'] };
  if (l.includes('quic'))
    return { tool: 'packets', filter: 'quic', fields: DEFAULT_FIELDS };
  if (macM)
    return { tool: 'packets', filter: `eth.src == ${macM[0]} || eth.dst == ${macM[0]}`, fields: ['frame.number', 'eth.src', 'eth.dst', 'ip.src', 'ip.dst', '_ws.col.Protocol'] };
  if (portM)
    return { tool: 'packets', filter: `tcp.port == ${portM[1]} || udp.port == ${portM[1]}`, fields: DEFAULT_FIELDS };
  if (ipM)
    return { tool: 'packets', filter: `ip.addr == ${ipM[1]}`, fields: DEFAULT_FIELDS };
  if (l.includes('filter:'))
    return { tool: 'packets', filter: prompt.split(/filter:/i)[1]?.trim() || '', fields: DEFAULT_FIELDS };

  return { tool: 'stat', stat: 'io,stat,0' };
}

async function executeTool(agentResult, sessionId) {
  const { tool, stat, filter, fields } = agentResult;

  if (tool === 'stat') {
    const raw_text = await runTsharkStat(sessionId, stat);
    return { result: { raw_text }, response: raw_text || 'No data.' };
  }

  if (tool === 'vuln') {
    const packets = await runTshark(sessionId, '', DEFAULT_FIELDS, 10000);
    const portCounts = {};
    for (const p of packets) {
      const port = p.dst_port;
      if (port) {
        portCounts[port] = (portCounts[port] || 0) + 1;
      }
    }
    
    const portEntries = Object.entries(portCounts);
    console.log(`[Vuln] Analyzing ${portEntries.length} ports with web search + CVE API...`);
    
    const vulnResults = await Promise.all(
      portEntries.map(async ([port, count]) => {
        const intel = await getPortIntelligence(parseInt(port));
        return { port: parseInt(port), count, ...intel };
      })
    );
    
    return { result: vulnResults, response: `Analyzed ${vulnResults.length} ports using SearXNG Web Search + NVD CVE API (NO AI!).` };
  }

  const packets = await runTshark(sessionId, filter || '', fields || DEFAULT_FIELDS, 200);
  return { result: packets, response: `Found ${packets.length} matching packets.` };
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
    return respond({ status: 'ok', engine: 'TShark + IANA Port DB + SearXNG + NVD CVE', sessions: sessions.size, note: 'NO AI - Pure dynamic code and logic!' });
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

      const [summaryText, protoPkts, trueTotal] = await Promise.all([
        runTsharkStat(session_id, 'io,stat,0'),
        runTshark(session_id, '', DEFAULT_FIELDS, 5000),
        getTruePacketCount(session_id),
      ]);

      const protocols = {};
      let maxTime = 0;
      for (const p of protoPkts) {
        const proto = (p.protocol || 'UNKNOWN').toUpperCase();
        protocols[proto] = (protocols[proto] || 0) + 1;
        if (p.timestamp > maxTime) maxTime = p.timestamp;
      }

      const sampledCount = protoPkts.length;
      const scaledProtocols = {};
      if (sampledCount > 0 && trueTotal > sampledCount) {
        const ratio = trueTotal / sampledCount;
        for (const [proto, count] of Object.entries(protocols)) {
          scaledProtocols[proto] = Math.round(count * ratio);
        }
      } else {
        Object.assign(scaledProtocols, protocols);
      }

      const sessionData = sessions.get(session_id);
      if (sessionData) {
        sessionData.total_packets = trueTotal;
        sessions.set(session_id, sessionData);
      }

      return respond({
        session_id,
        summary: {
          total_packets: trueTotal,
          protocols: scaledProtocols,
          duration_seconds: Math.round(maxTime),
          time_range: { start: 0, end: maxTime },
          raw_text: summaryText,
        },
      });
    } catch (e) {
      console.error(`[Upload] Error: ${e.message}`);
      return respond({ error: e.message }, 500);
    }
  }

  // ── Packets ────────────────────────────────────────────────
  if (url.startsWith('/pcap/packets') && method === 'GET') {
    const q = getQuery(url);
    if (!isValidSessionId(q.session_id)) return respond({ error: 'Invalid session_id' }, 400);

    const page = Math.max(1, parseInt(q.page || '1'));
    const per_page = Math.min(200, parseInt(q.per_page || '50'));
    const skip = (page - 1) * per_page;

    const packets = await runTsharkPaged(q.session_id, skip, per_page);

    const sessionData = sessions.get(q.session_id);
    const realTotal = sessionData?.total_packets ?? 0;

    return respond({ packets, total: realTotal, page, per_page });
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

  // ── Full Wireshark-style Packet Dissection (TShark -V) ────────────────────────
  if (url.startsWith('/pcap/packet-dissection') && method === 'GET') {
    const q = getQuery(url);
    if (!isValidSessionId(q.session_id)) return respond({ error: 'Invalid session_id' }, 400);
    
    const packetNum = parseInt(q.packet_number);
    if (!packetNum || packetNum < 1) return respond({ error: 'Invalid packet_number' }, 400);
    
    const pcapPath = path.join(PCAP_DIR, `${q.session_id}.pcap`);
    if (!fs.existsSync(pcapPath)) return respond({ error: 'Session expired or not found' }, 404);

    // Use TShark's verbose mode for full dissection like Wireshark
    const cmd = `"${TSHARK_BIN}" -r "${pcapPath}" -V -c ${packetNum}`;
    console.log(`[TShark-Dissect] Getting full dissection for packet ${packetNum}`);
    
    exec(cmd, { timeout: 30000, maxBuffer: 10 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) {
        console.error(`[TShark-Dissect] Error: ${err.message}`);
        return respond({ error: 'Failed to dissect packet' }, 500);
      }
      
      // Parse the verbose output into structured layers
      const dissection = parseVerboseOutput(stdout, packetNum);
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

    const extendedFields = [...DEFAULT_FIELDS, '_ws.col.Info'];
    
    const pcapPath = path.join(PCAP_DIR, `${q.session_id}.pcap`);
    if (!fs.existsSync(pcapPath)) return respond({ packets: [], total: 0, page, per_page });

    let cmd = `"${TSHARK_BIN}" -r "${pcapPath}" -T fields -E separator=/t`;
    for (const f of extendedFields) cmd += ` -e ${f}`;
    cmd += ` -c ${skip + per_page}`;

    exec(cmd, { timeout: 60000, maxBuffer: 100 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) {
        console.error(`[TSharkDetailed] Error: ${err.message}`);
        return respond({ packets: [], total: 0, page, per_page });
      }

      const lines = stdout.trim().split('\n').filter(l => l.trim());
      const pageLines = lines.slice(skip);
      
      const packets = pageLines.map(line => {
        const c = line.split('\t');
        // Field order: frame.number, ip.src, ip.dst, ipv6.src, ipv6.dst, frame.len, protocol, tcp.srcport, tcp.dstport, udp.srcport, udp.dstport, time_relative, info
        return {
          id: parseInt(c[0]) || 0,
          src_ip: c[1] || c[3] || null,  // IPv4 src or IPv6 src
          dst_ip: c[2] || c[4] || null,  // IPv4 dst or IPv6 dst
          length: parseInt(c[5]) || 0,
          protocol: c[6] || 'UNKNOWN',
          src_port: parseInt(c[7]) || parseInt(c[9]) || null,  // TCP src or UDP src
          dst_port: parseInt(c[8]) || parseInt(c[10]) || null, // TCP dst or UDP dst
          timestamp: parseFloat(c[11]) || 0,
          info: c[12] || '',
        };
      });

      const sessionData = sessions.get(q.session_id);
      const realTotal = sessionData?.total_packets ?? lines.length;

      return respond({ packets, total: realTotal, page, per_page });
    });
    return;
  }

  // ── Port Intelligence with Web Search + CVE ────────────────────────
  if (url.startsWith('/pcap/vulnerabilities') && method === 'GET') {
    const q = getQuery(url);
    if (!isValidSessionId(q.session_id)) return respond({ error: 'Invalid session_id' }, 400);
    if (!fs.existsSync(path.join(PCAP_DIR, `${q.session_id}.pcap`)))
      return respond({ error: 'Session expired or not found' }, 404);

    const packets = await runTshark(q.session_id, '', DEFAULT_FIELDS, 10000);
    const portCounts = {};
    for (const p of packets) {
      const port = p.dst_port;
      if (port) {
        portCounts[port] = (portCounts[port] || 0) + 1;
      }
    }
    
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

      const agentResult = localDynamicAgent(prompt);
      const toolResult = await executeTool(agentResult, session_id);

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
  console.log(`🚫 NO AI:         Pure dynamic code and logic!`);
  console.log(`📁 PCAP dir:      ${path.resolve(PCAP_DIR)}`);
  console.log(`📁 Export dir:    ${path.resolve(EXPORT_DIR)}`);
});

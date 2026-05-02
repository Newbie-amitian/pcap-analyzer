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
// Include both IPv4 and IPv6 fields, TCP and UDP ports, and INFO COLUMN
const DEFAULT_FIELDS = [
  'frame.number',
  'ip.src', 'ip.dst',           // IPv4 addresses
  'ipv6.src', 'ipv6.dst',       // IPv6 addresses
  'frame.len',
  '_ws.col.Protocol',
  'tcp.srcport', 'tcp.dstport', // TCP ports
  'udp.srcport', 'udp.dstport', // UDP ports
  'frame.time_relative',
  'frame.time',                 // Absolute date/time
  '_ws.col.Info',               // Info column (WIRESHARK EXACT!)
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
        // Field order: frame.number, ip.src, ip.dst, ipv6.src, ipv6.dst, frame.len, protocol, 
        //               tcp.srcport, tcp.dstport, udp.srcport, udp.dstport, time_relative, frame.time, info
        return {
          id: parseInt(c[0]) || 0,
          src_ip: c[1] || c[3] || null,  // IPv4 src or IPv6 src
          dst_ip: c[2] || c[4] || null,  // IPv4 dst or IPv6 dst
          length: parseInt(c[5]) || 0,
          protocol: c[6] || 'UNKNOWN',
          src_port: parseInt(c[7]) || parseInt(c[9]) || null,  // TCP src or UDP src
          dst_port: parseInt(c[8]) || parseInt(c[10]) || null, // TCP dst or UDP dst
          timestamp: parseFloat(c[11]) || 0,
          datetime: c[12] || '',  // Absolute date/time
          info: c[13] || null,    // Info column (WIRESHARK EXACT!)
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
        // Field order: frame.number, ip.src, ip.dst, ipv6.src, ipv6.dst, frame.len, protocol,
        //               tcp.srcport, tcp.dstport, udp.srcport, udp.dstport, time_relative, frame.time, info
        return {
          id: parseInt(c[0]) || 0,
          src_ip: c[1] || c[3] || null,  // IPv4 src or IPv6 src
          dst_ip: c[2] || c[4] || null,  // IPv4 dst or IPv6 dst
          length: parseInt(c[5]) || 0,
          protocol: c[6] || 'UNKNOWN',
          src_port: parseInt(c[7]) || parseInt(c[9]) || null,  // TCP src or UDP src
          dst_port: parseInt(c[8]) || parseInt(c[10]) || null, // TCP dst or UDP dst
          timestamp: parseFloat(c[11]) || 0,
          datetime: c[12] || '',  // Absolute date/time
          info: c[13] || null,    // Info column (WIRESHARK EXACT!)
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
        { key: 'Operation', value: f['arp.opcode'] === '1' ? 'Request (1)' : 'Reply (2)' },
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
  1723: { name: 'pptp', desc: 'Point-to-Point Tunneling Protocol', risk: 'HIGH', secure: 'OpenVPN/WireGuard' },
  2049: { name: 'nfs', desc: 'Network File System', risk: 'HIGH', secure: 'NFSv4 + Kerberos' },
  3306: { name: 'mysql', desc: 'MySQL Database', risk: 'HIGH', secure: 'Bind localhost + SSL' },
  3389: { name: 'rdp', desc: 'Remote Desktop Protocol', risk: 'HIGH', secure: 'VPN + NLA' },
  5432: { name: 'postgresql', desc: 'PostgreSQL Database', risk: 'HIGH', secure: 'Bind localhost + SSL' },
  5900: { name: 'vnc', desc: 'Virtual Network Computing', risk: 'HIGH', secure: 'VPN + SSH tunnel' },
  6379: { name: 'redis', desc: 'Redis Database', risk: 'HIGH', secure: 'Bind localhost + Auth' },
  8080: { name: 'http-proxy', desc: 'HTTP Proxy / Alternate HTTP', risk: 'MEDIUM', secure: 'HTTPS' },
  8443: { name: 'https-alt', desc: 'HTTPS Alternate', risk: 'LOW', secure: 'Already secure' },
  9200: { name: 'elasticsearch', desc: 'Elasticsearch', risk: 'HIGH', secure: 'Bind localhost + Auth' },
  27017: { name: 'mongodb', desc: 'MongoDB Database', risk: 'HIGH', secure: 'Bind localhost + Auth' },
};

// ── NVD CVE API Integration ─────────────────────────────────────────
const NVD_API_KEY = process.env.NVD_API_KEY || ''; // Optional but recommended
const NVD_RATE_LIMIT_DELAY = NVD_API_KEY ? 300 : 6000; // 0.3s with key, 6s without

async function fetchCvesForService(serviceName, port) {
  const cacheKey = `${serviceName}:${port}`;
  const cached = portInfoCache.get(cacheKey);
  if (cached && (Date.now() - cached.timestamp) < PORT_INFO_CACHE_TTL) {
    return cached.cves;
  }

  const cves = [];
  const queries = [serviceName, `port ${port}`];
  
  for (const query of queries.slice(0, 1)) { // Only query once to save time
    try {
      const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(query)}&resultsPerPage=5`;
      
      const headers = { 'User-Agent': 'PCAP-Analyzer/1.0' };
      if (NVD_API_KEY) headers['apiKey'] = NVD_API_KEY;
      
      const response = await new Promise((resolve, reject) => {
        https.get(url, { headers, timeout: 10000 }, (res) => {
          let data = '';
          res.on('data', chunk => data += chunk);
          res.on('end', () => {
            try { resolve(JSON.parse(data)); } catch (e) { reject(e); }
          });
        }).on('error', reject).on('timeout', () => reject(new Error('Timeout')));
      });
      
      if (response.vulnerabilities) {
        for (const vuln of response.vulnerabilities) {
          const cve = vuln.cve;
          const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV2?.[0];
          const score = metrics?.cvssData?.baseScore || 0;
          
          cves.push({
            id: cve.id,
            score: score,
            severity: metrics?.cvssData?.baseSeverity || (score >= 9 ? 'CRITICAL' : score >= 7 ? 'HIGH' : score >= 4 ? 'MEDIUM' : 'LOW'),
            description: cve.descriptions?.[0]?.value?.slice(0, 200) || 'No description',
            url: `https://nvd.nist.gov/vuln/detail/${cve.id}`
          });
        }
      }
      
      await new Promise(r => setTimeout(r, NVD_RATE_LIMIT_DELAY));
      break; // Only do one query
    } catch (e) {
      console.error(`[NVD] Error: ${e.message}`);
    }
  }
  
  portInfoCache.set(cacheKey, { cves, timestamp: Date.now() });
  return cves;
}

// ── Combined Port Intelligence ───────────────────────────────────────
async function getPortIntelligence(port) {
  // Check IANA first
  const iana = IANA_PORTS[port];
  
  // Get SearXNG web search results
  const webInfo = await searchPortInfo(port);
  
  // Get CVE data
  const cves = await fetchCvesForService(webInfo.service_name, port);
  
  // Determine risk level
  let risk = 'LOW';
  let reason = '';
  
  if (iana) {
    risk = iana.risk;
    reason = iana.desc;
  } else if (webInfo.service_name !== 'unknown') {
    risk = webInfo.secure_alternative === 'Already secure' ? 'LOW' : 'MEDIUM';
    reason = webInfo.description;
  } else if (port >= 49152) {
    risk = 'LOW';
    reason = 'Ephemeral port - typically client-side';
  } else {
    risk = 'MEDIUM';
    reason = 'Unknown service - investigate manually';
  }
  
  // Check CVEs for higher risk
  const highCve = cves.find(c => c.score >= 7);
  if (highCve) {
    risk = highCve.score >= 9 ? 'CRITICAL' : 'HIGH';
  }
  
  return {
    port,
    service_name: iana?.name || webInfo.service_name,
    description: iana?.desc || webInfo.description,
    risk,
    reason,
    secure_alternative: iana?.secure || webInfo.secure_alternative,
    common_uses: webInfo.common_uses,
    cve_id: cves[0]?.id || null,
    cvss_score: cves[0]?.score || null,
    cve_count: cves.length,
    all_cves: cves.slice(0, 3),
    source: iana ? 'iana' : 'searxng_web_search',
    sources: {
      iana: !!iana,
      searxng: webInfo.service_name !== 'unknown',
      nvd: cves.length > 0
    }
  };
}

// ── MAIN HTTP SERVER ───────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const origin = req.headers.origin;
  const acceptEncoding = req.headers['accept-encoding'] || '';
  const respond = (data, status = 200) => json(res, data, status, origin, acceptEncoding);
  
  // CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, getCorsHeaders(origin));
    return res.end();
  }
  
  const url = req.url || '/';
  const method = req.method || 'GET';

  // ── Health check ────────────────────────────────────────────────
  if (url === '/health' || url === '/') {
    return respond({ status: 'ok', timestamp: new Date().toISOString() });
  }

  // ── File Upload ──────────────────────────────────────────────────
  if (url === '/pcap/upload' && method === 'POST') {
    const ip = req.socket.remoteAddress || 'unknown';
    if (!checkRateLimit(ip, RATE_UPLOAD)) {
      return respond({ error: 'Rate limit exceeded' }, 429);
    }

    const contentType = req.headers['content-type'] || '';
    if (!contentType.includes('multipart/form-data')) {
      return respond({ error: 'Expected multipart/form-data' }, 400);
    }

    const boundary = contentType.split('boundary=')[1];
    if (!boundary) {
      return respond({ error: 'No boundary in content-type' }, 400);
    }

    const body = await parseBody(req);
    const parts = parseMultipart(body, boundary);

    const pcapPart = parts.find(p => 
      p.headers.includes('name="pcap"') || 
      p.headers.includes('name="file"') ||
      p.headers.includes('.pcap') ||
      p.headers.includes('.cap')
    );

    if (!pcapPart) {
      return respond({ error: 'No PCAP file found in upload' }, 400);
    }

    const sessionId = `session-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
    const pcapPath = path.join(PCAP_DIR, `${sessionId}.pcap`);

    fs.writeFileSync(pcapPath, pcapPart.data);
    console.log(`[Upload] Saved ${pcapPart.data.length} bytes to ${pcapPath}`);

    // Get packet count and basic stats
    const totalPackets = await getTruePacketCount(sessionId);
    
    sessions.set(sessionId, {
      created_at: Date.now(),
      total_packets: totalPackets,
      filename: pcapPart.headers.match(/filename="([^"]+)"/)?.[1] || 'unknown.pcap'
    });

    // Get initial packets for preview
    const initialPackets = await runTshark(sessionId, '', DEFAULT_FIELDS, 500);
    
    // Get protocol stats
    const protocolCounts = {};
    for (const p of initialPackets) {
      protocolCounts[p.protocol] = (protocolCounts[p.protocol] || 0) + 1;
    }

    return respond({
      session_id: sessionId,
      summary: {
        total_packets: totalPackets,
        protocols: protocolCounts,
        duration_seconds: initialPackets.length > 0 ? 
          (initialPackets[initialPackets.length - 1].timestamp - initialPackets[0].timestamp) : 0
      },
      packets: initialPackets
    });
  }

  // ── Get Packets (paginated) ───────────────────────────────────────
  if (url.startsWith('/pcap/packets') && method === 'GET') {
    const q = getQuery(url);
    if (!isValidSessionId(q.session_id)) return respond({ error: 'Invalid session_id' }, 400);

    const page = Math.max(1, parseInt(q.page || '1'));
    const perPage = Math.min(200, parseInt(q.per_page || '50'));
    const skip = (page - 1) * perPage;

    const packets = await runTsharkPaged(q.session_id, skip, perPage);
    const sessionData = sessions.get(q.session_id);
    const total = sessionData?.total_packets || packets.length;

    return respond({ packets, total, page, per_page: perPage });
  }

  // ── Packet Detail ────────────────────────────────────────────────
  if (url.startsWith('/pcap/packet-detail') && method === 'GET') {
    const q = getQuery(url);
    if (!isValidSessionId(q.session_id)) return respond({ error: 'Invalid session_id' }, 400);
    
    const packetNum = parseInt(q.packet_number);
    if (!packetNum || packetNum < 1) return respond({ error: 'Invalid packet_number' }, 400);
    
    const details = await getPacketDetails(q.session_id, packetNum);
    return respond(details);
  }

  // ── Packet Dissection (PDML - full hierarchical) ─────────────────
  if (url.startsWith('/pcap/packet-dissection') && method === 'GET') {
    const q = getQuery(url);
    if (!isValidSessionId(q.session_id)) return respond({ error: 'Invalid session_id' }, 400);
    
    const packetNum = parseInt(q.packet_number);
    if (!packetNum || packetNum < 1) return respond({ error: 'Invalid packet_number' }, 400);
    
    const pcapPath = path.join(PCAP_DIR, `${q.session_id}.pcap`);
    if (!fs.existsSync(pcapPath)) return respond({ error: 'Session expired or not found' }, 404);

    const cmd = `"${TSHARK_BIN}" -r "${pcapPath}" -T pdml -c ${packetNum}`;
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

  // ── Packets with Info column (detailed) ────────────────────────────────
  if (url.startsWith('/pcap/packets-detailed') && method === 'GET') {
    const q = getQuery(url);
    if (!isValidSessionId(q.session_id)) return respond({ error: 'Invalid session_id' }, 400);

    const page = Math.max(1, parseInt(q.page || '1'));
    const per_page = Math.min(200, parseInt(q.per_page || '50'));
    const skip = (page - 1) * per_page;

    const pcapPath = path.join(PCAP_DIR, `${q.session_id}.pcap`);
    if (!fs.existsSync(pcapPath)) return respond({ packets: [], total: 0, page, per_page });

    // Use TShark JSON output for complete protocol info
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
          
          // Extract source/destination (IPv4, IPv6, or MAC for layer2 protocols)
          let src_ip = null;
          let dst_ip = null;
          
          if (layers.ip) {
            src_ip = layers.ip['ip.src'] || null;
            dst_ip = layers.ip['ip.dst'] || null;
          } else if (layers.ipv6) {
            src_ip = layers.ipv6['ipv6.src'] || null;
            dst_ip = layers.ipv6['ipv6.dst'] || null;
          } else if (layers.eth) {
            // For non-IP protocols like ARP, show MAC addresses
            src_ip = layers.eth['eth.src'] || null;
            dst_ip = layers.eth['eth.dst'] || null;
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
          else if (layers.icmp) protocol = 'ICMP';
          else if (layers.icmpv6) protocol = 'ICMPv6';
          else if (layers.arp) protocol = 'ARP';
          else if (layers.dns) protocol = 'DNS';
          else if (layers.mdns) protocol = 'MDNS';
          else if (layers.http) protocol = 'HTTP';
          else if (layers.tls || layers.ssl) protocol = 'TLS';
          else if (layers.dhcp) protocol = 'DHCP';
          else if (layers.dhcpv6) protocol = 'DHCPv6';
          else if (layers.ssh) protocol = 'SSH';
          else if (layers.ftp) protocol = 'FTP';
          else if (layers.ssdp) protocol = 'SSDP';
          else if (layers.ntp) protocol = 'NTP';
          else if (layers.igmp) protocol = 'IGMP';
          else if (layers.stp) protocol = 'STP';
          else if (layers.lldp) protocol = 'LLDP';
          else if (frame['frame.protocols']) {
            const protocols = frame['frame.protocols'].split(':');
            protocol = protocols[protocols.length - 1].toUpperCase();
          }
          
          // ═══════════════════════════════════════════════════════════════
          // WIRESHARK-EXACT INFO COLUMN EXTRACTION
          // ═══════════════════════════════════════════════════════════════
          let info = '';
          
          // Use TShark's built-in Info column if available (MOST RELIABLE)
          if (frame['_ws.col.Info']) {
            info = frame['_ws.col.Info'];
          }
          // Fallback: Build info manually per protocol
          else if (layers.arp) {
            // ARP - Wireshark exact format
            const opcode = layers.arp['arp.opcode'];
            const senderMAC = layers.arp['arp.src.hw_mac'] || '';
            const senderIP = layers.arp['arp.src.proto_ipv4'] || '';
            const targetMAC = layers.arp['arp.dst.hw_mac'] || '';
            const targetIP = layers.arp['arp.dst.proto_ipv4'] || '';
            
            if (opcode === '1') {
              // ARP Request: "Who has 192.168.1.1? Tell 192.168.1.100"
              if (targetIP) {
                info = `Who has ${targetIP}?`;
                if (senderIP) info += ` Tell ${senderIP}`;
              } else {
                info = 'Who has ? Tell ' + (senderIP || '?');
              }
              // Check for ARP Probe (sender IP is 0.0.0.0)
              if (senderIP === '0.0.0.0' || !senderIP) {
                info = `Who has ${targetIP}? (ARP Probe)`;
              }
            } else if (opcode === '2') {
              // ARP Reply: "192.168.1.1 is at aa:bb:cc:dd:ee:ff"
              if (senderIP && senderMAC) {
                info = `${senderIP} is at ${senderMAC}`;
              } else {
                info = 'ARP Reply';
              }
            } else {
              info = `ARP (opcode ${opcode})`;
            }
          } else if (layers.dns || layers.mdns) {
            // DNS - Wireshark exact format
            const dns = layers.dns || layers.mdns;
            const isResponse = dns['dns.flags.response'] === '1';
            const qryName = dns['dns.qry.name'] || '';
            const qryType = dns['dns.qry.type'] || '';
            const answers = [];
            
            // Collect all answers
            if (dns['dns.a']) answers.push(`A ${dns['dns.a']}`);
            if (dns['dns.aaaa']) answers.push(`AAAA ${dns['dns.aaaa']}`);
            if (dns['dns.cname']) answers.push(`CNAME ${dns['dns.cname']}`);
            if (dns['dns.ns']) answers.push(`NS ${dns['dns.ns']}`);
            if (dns['dns.mx']) answers.push(`MX ${dns['dns.mx']}`);
            if (dns['dns.txt']) answers.push(`TXT ${dns['dns.txt']}`);
            
            if (qryName) {
              if (isResponse) {
                info = `Response: ${qryName}`;
                if (answers.length > 0) info += ` → ${answers.join(', ')}`;
              } else {
                info = `Query: ${qryName}`;
                if (qryType) info += ` type ${qryType}`;
              }
            }
          } else if (layers.http) {
            // HTTP - Wireshark exact format
            const method = layers.http['http.request.method'];
            const uri = layers.http['http.request.uri'];
            const host = layers.http['http.host'];
            const code = layers.http['http.response.code'];
            const phrase = layers.http['http.response.phrase'];
            
            if (method) {
              info = `${method} ${uri || '/'}`;
              if (host) info += ` HTTP/1.1`;
            } else if (code) {
              info = `HTTP/1.1 ${code} ${phrase || ''}`;
            }
          } else if (layers.tcp) {
            // TCP - Wireshark exact format
            const flags = [];
            if (layers.tcp['tcp.flags.syn'] === '1') flags.push('SYN');
            if (layers.tcp['tcp.flags.ack'] === '1') flags.push('ACK');
            if (layers.tcp['tcp.flags.fin'] === '1') flags.push('FIN');
            if (layers.tcp['tcp.flags.reset'] === '1') flags.push('RST');
            if (layers.tcp['tcp.flags.push'] === '1') flags.push('PSH');
            
            const seq = layers.tcp['tcp.seq'];
            const ack = layers.tcp['tcp.ack'];
            const len = layers.tcp['tcp.len'] || frame['frame.len'];
            
            if (flags.length > 0) {
              info = `[${flags.join(', ')}]`;
              if (seq) info += ` Seq=${seq}`;
              if (ack && flags.includes('ACK')) info += ` Ack=${ack}`;
              if (len) info += ` Len=${len}`;
            } else {
              info = `${layers.tcp['tcp.srcport']} → ${layers.tcp['tcp.dstport']} Len=${len || 0}`;
            }
          } else if (layers.udp) {
            // UDP - Wireshark exact format
            const len = layers.udp['udp.length'] || frame['frame.len'];
            info = `Len=${len}`;
          } else if (layers.icmp) {
            // ICMP - Wireshark exact format
            const type = layers.icmp['icmp.type'];
            const code = layers.icmp['icmp.code'];
            const types = {
              '0': 'Echo (ping) reply', '3': 'Destination unreachable', '5': 'Redirect',
              '8': 'Echo (ping) request', '9': 'Router advertisement', '10': 'Router selection',
              '11': 'Time exceeded', '12': 'Parameter problem', '13': 'Timestamp request',
              '14': 'Timestamp reply'
            };
            info = types[type] || `Type ${type}`;
            if (type === '8' || type === '0') {
              const id = layers.icmp['icmp.id'];
              const seq = layers.icmp['icmp.seq'];
              if (id) info += ` id=${id}`;
              if (seq) info += ` seq=${seq}`;
            }
            if (code) info += ` (Code ${code})`;
          } else if (layers.icmpv6) {
            // ICMPv6
            const type = layers.icmpv6['icmpv6.type'];
            info = `ICMPv6 Type=${type}`;
          } else if (layers.dhcpv6) {
            // DHCPv6
            const msgType = layers.dhcpv6['dhcpv6.msg_type'];
            info = msgType || 'DHCPv6';
          } else if (layers.dhcp) {
            // DHCP
            const msgType = layers.dhcp['dhcp.option.message_type'];
            const xid = layers.dhcp['dhcp.xid'];
            info = `DHCP ${msgType || 'message'}`;
            if (xid) info += ` - Transaction ID ${xid}`;
          } else if (layers.tls || layers.ssl) {
            // TLS/SSL
            const tls = layers.tls || layers.ssl;
            const handshake = tls['tls.handshake.type'];
            const sni = tls['tls.handshake.extensions_server_name'];
            const types = {
              '1': 'Client Hello', '2': 'Server Hello', '4': 'New Session Ticket',
              '11': 'Certificate', '12': 'Server Key Exchange', '14': 'Server Hello Done',
              '16': 'Client Key Exchange', '20': 'Finished'
            };
            if (handshake) info = types[handshake] || `Handshake ${handshake}`;
            if (sni) info += ` - SNI: ${sni}`;
          } else if (layers.ntp) {
            // NTP
            info = 'NTP';
          } else if (layers.ssdp) {
            // SSDP
            const method = layers.ssdp['http.request.method'] || layers.ssdp['ssdp.method'];
            const uri = layers.ssdp['http.request.uri'] || layers.ssdp['ssdp.uri'];
            if (method && uri) info = `${method} ${uri}`;
            else info = 'SSDP';
          } else if (layers.igmp) {
            // IGMP
            const type = layers.igmp['igmp.type'];
            info = type ? `IGMP v${type}` : 'IGMP';
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
      sources: ['IANA', 'SearXNG Web Search', 'NVD CVE Database']
    });
  }

  // ── Protocol Statistics ───────────────────────────────────────────
  if (url.startsWith('/pcap/stats') && method === 'GET') {
    const q = getQuery(url);
    if (!isValidSessionId(q.session_id)) return respond({ error: 'Invalid session_id' }, 400);

    const packets = await runTshark(q.session_id, '', DEFAULT_FIELDS, 10000);
    
    const protocols = {};
    const srcIPs = {};
    const dstIPs = {};
    
    for (const p of packets) {
      protocols[p.protocol] = (protocols[p.protocol] || 0) + 1;
      if (p.src_ip) srcIPs[p.src_ip] = (srcIPs[p.src_ip] || 0) + 1;
      if (p.dst_ip) dstIPs[p.dst_ip] = (dstIPs[p.dst_ip] || 0) + 1;
    }

    return respond({
      total_packets: packets.length,
      protocols,
      top_sources: Object.entries(srcIPs).sort((a, b) => b[1] - a[1]).slice(0, 10),
      top_destinations: Object.entries(dstIPs).sort((a, b) => b[1] - a[1]).slice(0, 10),
    });
  }

  // ── Conversation Endpoints (for Agent) ─────────────────────────────
  if (url.startsWith('/pcap/conversations') && method === 'GET') {
    const q = getQuery(url);
    if (!isValidSessionId(q.session_id)) return respond({ error: 'Invalid session_id' }, 400);

    const statOutput = await runTsharkStat(q.session_id, 'conv,tcp');
    return respond({ type: 'tcp', raw: statOutput });
  }

  if (url.startsWith('/pcap/endpoints') && method === 'GET') {
    const q = getQuery(url);
    if (!isValidSessionId(q.session_id)) return respond({ error: 'Invalid session_id' }, 400);

    const statOutput = await runTsharkStat(q.session_id, 'endpoints,tcp');
    return respond({ type: 'tcp', raw: statOutput });
  }

  // ── Export PCAP ───────────────────────────────────────────────────
  if (url.startsWith('/pcap/export') && method === 'GET') {
    const q = getQuery(url);
    if (!isValidSessionId(q.session_id)) return respond({ error: 'Invalid session_id' }, 400);

    const filter = q.filter || '';
    const pcapPath = path.join(PCAP_DIR, `${q.session_id}.pcap`);
    if (!fs.existsSync(pcapPath)) return respond({ error: 'Session expired' }, 404);

    const exportPath = path.join(EXPORT_DIR, q.session_id);
    if (!fs.existsSync(exportPath)) fs.mkdirSync(exportPath, { recursive: true });
    
    const outFile = path.join(exportPath, `filtered_${Date.now()}.pcap`);
    const cmd = `"${TSHARK_BIN}" -r "${pcapPath}" -Y "${filter.replace(/"/g, '\\"')}" -w "${outFile}"`;
    
    exec(cmd, { timeout: 60000 }, (err) => {
      if (err) return respond({ error: 'Export failed' }, 500);
      return respond({ download_url: `/pcap/download?session_id=${q.session_id}&file=${path.basename(outFile)}` });
    });
    return;
  }

  // ── Download Exported File ────────────────────────────────────────
  if (url.startsWith('/pcap/download') && method === 'GET') {
    const q = getQuery(url);
    if (!isValidSessionId(q.session_id)) return respond({ error: 'Invalid session_id' }, 400);

    const filePath = path.join(EXPORT_DIR, q.session_id, q.file);
    if (!fs.existsSync(filePath)) return respond({ error: 'File not found' }, 404);

    const stat = fs.statSync(filePath);
    res.writeHead(200, {
      'Content-Type': 'application/vnd.tcpdump.pcap',
      'Content-Length': stat.size,
      'Content-Disposition': `attachment; filename="${q.file}"`,
      ...getCorsHeaders(origin)
    });
    
    const stream = fs.createReadStream(filePath);
    stream.pipe(res);
    return;
  }

  // ── Session Ping ──────────────────────────────────────────────────
  if (url.startsWith('/pcap/ping-session') && method === 'GET') {
    const q = getQuery(url);
    if (!isValidSessionId(q.session_id)) return respond({ error: 'Invalid session_id' }, 400);
    
    const exists = fs.existsSync(path.join(PCAP_DIR, `${q.session_id}.pcap`));
    const sessionData = sessions.get(q.session_id);
    
    return respond({ 
      valid: exists, 
      total_packets: sessionData?.total_packets || 0,
      created_at: sessionData?.created_at || null
    });
  }

  // ── Image Extraction (for Agent) ──────────────────────────────────
  if (url.startsWith('/pcap/images') && method === 'GET') {
    const q = getQuery(url);
    if (!isValidSessionId(q.session_id)) return respond({ error: 'Invalid session_id' }, 400);

    const pcapPath = path.join(PCAP_DIR, `${q.session_id}.pcap`);
    if (!fs.existsSync(pcapPath)) return respond({ error: 'Session expired' }, 404);

    const exportPath = path.join(EXPORT_DIR, q.session_id, 'images');
    if (!fs.existsSync(exportPath)) fs.mkdirSync(exportPath, { recursive: true });

    const cmd = `"${TSHARK_BIN}" -r "${pcapPath}" -Y "http" -T fields -e http.file_data -e frame.number 2>/dev/null | head -100`;
    
    exec(cmd, { timeout: 30000 }, (err, stdout) => {
      if (err) return respond({ images: [] });
      
      const images = [];
      const lines = stdout.trim().split('\n').filter(l => l.trim());
      
      for (const line of lines) {
        const hexData = line.split('\t')[0];
        if (hexData && hexData.length > 100) {
          // Try to identify image magic bytes
          const magicBytes = hexData.slice(0, 8).toLowerCase();
          let ext = 'bin';
          if (magicBytes.startsWith('ffd8ff')) ext = 'jpg';
          else if (magicBytes.startsWith('89504e47')) ext = 'png';
          else if (magicBytes.startsWith('474946')) ext = 'gif';
          
          const key = `img_${images.length}_${Date.now()}.${ext}`;
          images.push({ key, size: hexData.length / 2, type: ext });
          imageStore.set(`${q.session_id}:${key}`, hexData);
        }
      }
      
      return respond({ images, count: images.length });
    });
    return;
  }

  // ── Image Data ────────────────────────────────────────────────────
  if (url.startsWith('/pcap/image-data') && method === 'GET') {
    const q = getQuery(url);
    if (!isValidSessionId(q.session_id)) return respond({ error: 'Invalid session_id' }, 400);

    const hexData = imageStore.get(`${q.session_id}:${q.key}`);
    if (!hexData) return respond({ error: 'Image not found' }, 404);

    // Convert hex to binary
    const binaryData = Buffer.from(hexData, 'hex');
    
    // Detect content type
    let contentType = 'application/octet-stream';
    if (hexData.startsWith('ffd8ff')) contentType = 'image/jpeg';
    else if (hexData.startsWith('89504e47')) contentType = 'image/png';
    else if (hexData.startsWith('474946')) contentType = 'image/gif';
    else if (hexData.startsWith('424d')) contentType = 'image/bmp';
    
    res.writeHead(200, {
      'Content-Type': contentType,
      'Content-Length': binaryData.length,
      'Cache-Control': 'public, max-age=3600',
      ...getCorsHeaders(origin)
    });
    res.end(binaryData);
    return;
  }

  // ── Agent Query (placeholder - uses external AI service) ───────────
  if (url.startsWith('/pcap/agent/query') && method === 'POST') {
    const ip = req.socket.remoteAddress || 'unknown';
    if (!checkRateLimit(ip, RATE_AGENT)) {
      return respond({ error: 'Rate limit exceeded' }, 429);
    }

    let body;
    try {
      body = JSON.parse((await parseBody(req)).toString());
    } catch (e) {
      return respond({ error: 'Invalid JSON body' }, 400);
    }

    const { session_id, query } = body;
    if (!isValidSessionId(session_id)) return respond({ error: 'Invalid session_id' }, 400);
    if (!query) return respond({ error: 'Query is required' }, 400);

    // Get session data for context
    const sessionData = sessions.get(session_id);
    const pcapPath = path.join(PCAP_DIR, `${session_id}.pcap`);
    
    if (!fs.existsSync(pcapPath)) {
      return respond({ error: 'Session expired or not found' }, 404);
    }

    // Build context from PCAP
    const packets = await runTshark(session_id, '', DEFAULT_FIELDS, 100);
    const protocolCounts = {};
    for (const p of packets) {
      protocolCounts[p.protocol] = (protocolCounts[p.protocol] || 0) + 1;
    }

    // For now, return a helpful response based on the query
    const queryLower = query.toLowerCase();
    let response = '';
    
    if (queryLower.includes('summary') || queryLower.includes('overview')) {
      response = `This PCAP contains ${sessionData?.total_packets || packets.length} total packets. ` +
        `Protocols: ${Object.entries(protocolCounts).map(([k, v]) => `${k}: ${v}`).join(', ')}.`;
    } else if (queryLower.includes('suspicious') || queryLower.includes('anomaly')) {
      const suspicious = packets.filter(p => 
        p.protocol === 'ICMP' || 
        (p.protocol === 'TCP' && p.info?.includes('RST')) ||
        (p.protocol === 'TCP' && p.info?.includes('SYN') && !p.info?.includes('ACK'))
      );
      response = `Found ${suspicious.length} potentially suspicious packets. ` +
        `Check the Port Intelligence tab for detailed risk analysis.`;
    } else if (queryLower.includes('port') || queryLower.includes('service')) {
      const ports = new Set(packets.map(p => p.dst_port).filter(Boolean));
      response = `Found ${ports.size} unique destination ports. ` +
        `Visit the Port Intelligence tab for detailed service information.`;
    } else {
      response = `I can help you analyze this PCAP file. ` +
        `It contains ${sessionData?.total_packets || packets.length} packets. ` +
        `Ask me about: summary, suspicious traffic, ports, protocols, or specific IPs.`;
    }

    return respond({ 
      response,
      context: {
        total_packets: sessionData?.total_packets || packets.length,
        protocols: protocolCounts,
        sample_packets: packets.slice(0, 5)
      }
    });
  }

  // ── 404 for unknown routes ────────────────────────────────────────
  return respond({ error: 'Not found' }, 404);
});

// ── Start Server ────────────────────────────────────────────────────
const PORT = process.env.PORT || 4000;
server.listen(PORT, () => {
  console.log(`[Server] PCAP Analyzer Backend running on port ${PORT}`);
  console.log(`[Server] CORS Origin: ${ALLOWED_ORIGIN}`);
  console.log(`[Server] SearXNG URL: ${SEARXNG_URL}`);
});

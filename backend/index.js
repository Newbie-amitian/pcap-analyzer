const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const { Buffer } = require('buffer');

// ── In-memory session store ────────────────────────────────────
const sessions = new Map();

// ── CORS Configuration ─────────────────────────────────────────
// For local dev:  set ALLOWED_ORIGIN=http://localhost:3000 in .env
// For production: set ALLOWED_ORIGIN=https://your-app.vercel.app in Render dashboard
//
// Switching from local to production = change ONE environment variable.
// No code changes required.
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || 'http://localhost:3000';

// Returns correct CORS headers for a given request origin.
// Only the configured origin is allowed through; everything else gets no header.
function getCorsHeaders(requestOrigin) {
  const origin = requestOrigin || '';

  // Exact match only — never a wildcard
  if (origin === ALLOWED_ORIGIN) {
    return {
      'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Vary': 'Origin',            // required when origin varies per-request
    };
  }

  // Origin not allowed — return no CORS headers (browser will block the request)
  return {};
}

// ── PCAP Protocol/Port Knowledge ──────────────────────────────
const PROTOCOL_MAP = {
  20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'TELNET', 25: 'SMTP',
  53: 'DNS', 67: 'DHCP', 68: 'DHCP', 69: 'TFTP', 80: 'HTTP',
  110: 'POP3', 119: 'NNTP', 123: 'NTP', 135: 'RPC', 137: 'NetBIOS',
  138: 'NetBIOS', 139: 'NetBIOS', 143: 'IMAP', 161: 'SNMP', 162: 'SNMP',
  179: 'BGP', 194: 'IRC', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB',
  465: 'SMTPS', 514: 'Syslog', 515: 'LPD', 587: 'SMTP', 636: 'LDAPS',
  993: 'IMAPS', 995: 'POP3S', 1080: 'SOCKS', 1194: 'OpenVPN',
  1433: 'MSSQL', 1521: 'Oracle', 1723: 'PPTP', 3306: 'MySQL',
  3389: 'RDP', 4444: 'Metasploit', 5432: 'PostgreSQL', 5900: 'VNC',
  6379: 'Redis', 6667: 'IRC', 8080: 'HTTP-ALT', 8443: 'HTTPS-ALT',
  8888: 'HTTP-ALT', 9200: 'Elasticsearch', 27017: 'MongoDB',
};

const VULNERABLE_PORTS = {
  21: { risk: 'HIGH', reason: 'FTP transmits credentials in plaintext' },
  23: { risk: 'CRITICAL', reason: 'Telnet transmits everything in plaintext including passwords' },
  25: { risk: 'MEDIUM', reason: 'SMTP can be exploited for spam/relay if misconfigured' },
  53: { risk: 'LOW', reason: 'DNS can be used for tunneling or amplification attacks' },
  69: { risk: 'HIGH', reason: 'TFTP has no authentication' },
  80: { risk: 'MEDIUM', reason: 'HTTP transmits data in plaintext' },
  110: { risk: 'HIGH', reason: 'POP3 transmits credentials in plaintext' },
  135: { risk: 'HIGH', reason: 'RPC endpoint mapper — common attack vector' },
  137: { risk: 'HIGH', reason: 'NetBIOS — information leakage risk' },
  139: { risk: 'HIGH', reason: 'NetBIOS Session — lateral movement risk' },
  143: { risk: 'MEDIUM', reason: 'IMAP may transmit credentials in plaintext' },
  161: { risk: 'HIGH', reason: 'SNMP v1/v2 use plaintext community strings' },
  389: { risk: 'MEDIUM', reason: 'LDAP without TLS exposes directory data' },
  445: { risk: 'CRITICAL', reason: 'SMB — EternalBlue / ransomware vector' },
  1080: { risk: 'HIGH', reason: 'SOCKS proxy — potential data exfiltration' },
  1433: { risk: 'HIGH', reason: 'MSSQL exposed to network — brute force risk' },
  1521: { risk: 'HIGH', reason: 'Oracle DB exposed — brute force risk' },
  1723: { risk: 'MEDIUM', reason: 'PPTP VPN — weak encryption (MS-CHAPv2)' },
  3306: { risk: 'HIGH', reason: 'MySQL exposed — brute force / data exfil risk' },
  3389: { risk: 'HIGH', reason: 'RDP — BlueKeep / brute force attack vector' },
  4444: { risk: 'CRITICAL', reason: 'Metasploit default port — likely backdoor!' },
  5432: { risk: 'HIGH', reason: 'PostgreSQL exposed — brute force risk' },
  5900: { risk: 'HIGH', reason: 'VNC often uses weak/no authentication' },
  6379: { risk: 'CRITICAL', reason: 'Redis with no auth — full server compromise risk' },
  6667: { risk: 'MEDIUM', reason: 'IRC — often used by botnets for C2' },
  8080: { risk: 'LOW', reason: 'Alternate HTTP — may expose dev/admin panels' },
  9200: { risk: 'CRITICAL', reason: 'Elasticsearch with no auth — data breach risk' },
  27017: { risk: 'CRITICAL', reason: 'MongoDB with no auth — full DB exposure risk' },
};

const PORT_KNOWLEDGE = {
  21: { name: 'FTP', description: 'File Transfer Protocol', risk: 'HIGH', secure_alternative: 'Use SFTP (port 22) or FTPS (port 990)', common_uses: ['File transfers', 'Web hosting uploads'], vulnerabilities: ['Plaintext credentials', 'Anonymous login', 'Bounce attacks'], recommendations: ['Disable FTP, use SFTP instead', 'If required, use FTPS with TLS', 'Disable anonymous login'] },
  22: { name: 'SSH', description: 'Secure Shell', risk: 'SECURE', secure_alternative: 'Already secure', common_uses: ['Remote admin', 'Tunneling', 'SFTP'], vulnerabilities: ['Brute force', 'Weak keys'], recommendations: ['Use key-based auth', 'Disable root login', 'Use fail2ban'] },
  23: { name: 'TELNET', description: 'Telnet Protocol', risk: 'CRITICAL', secure_alternative: 'Use SSH (port 22)', common_uses: ['Legacy remote admin', 'Network device management'], vulnerabilities: ['Plaintext everything', 'No encryption', 'MITM attacks'], recommendations: ['Immediately disable Telnet', 'Replace with SSH', 'Block at firewall'] },
  80: { name: 'HTTP', description: 'HyperText Transfer Protocol', risk: 'MEDIUM', secure_alternative: 'Use HTTPS (port 443)', common_uses: ['Web browsing', 'APIs', 'Web apps'], vulnerabilities: ['Plaintext data', 'Session hijacking', 'MITM'], recommendations: ['Redirect all HTTP to HTTPS', 'Use HSTS headers'] },
  443: { name: 'HTTPS', description: 'HTTP Secure', risk: 'SECURE', secure_alternative: 'Already secure', common_uses: ['Secure web browsing', 'APIs', 'Web apps'], vulnerabilities: ['Weak TLS configs', 'Expired certs'], recommendations: ['Use TLS 1.2+', 'Enable HSTS', 'Renew certificates'] },
  445: { name: 'SMB', description: 'Server Message Block', risk: 'CRITICAL', secure_alternative: 'Use VPN + SMB, or SFTP', common_uses: ['File sharing', 'Windows networking'], vulnerabilities: ['EternalBlue (MS17-010)', 'WannaCry', 'NotPetya'], recommendations: ['Block at perimeter', 'Patch immediately', 'Disable SMBv1'] },
  3389: { name: 'RDP', description: 'Remote Desktop Protocol', risk: 'HIGH', secure_alternative: 'RDP over VPN only', common_uses: ['Windows remote desktop', 'IT support'], vulnerabilities: ['BlueKeep (CVE-2019-0708)', 'Brute force', 'DejaBlue'], recommendations: ['Never expose to internet', 'Use VPN', 'Enable NLA'] },
  3306: { name: 'MySQL', description: 'MySQL Database', risk: 'HIGH', secure_alternative: 'Bind to localhost only', common_uses: ['Database access', 'Web apps'], vulnerabilities: ['Brute force', 'SQL injection', 'Unauthorized access'], recommendations: ['Bind to 127.0.0.1', 'Use strong passwords', 'Restrict remote access'] },
  6379: { name: 'Redis', description: 'Redis Cache/DB', risk: 'CRITICAL', secure_alternative: 'Bind to localhost, enable AUTH', common_uses: ['Caching', 'Session storage', 'Pub/Sub'], vulnerabilities: ['No auth by default', 'Remote code execution', 'Data theft'], recommendations: ['Bind to localhost only', 'Enable AUTH', 'Use firewall rules'] },
  27017: { name: 'MongoDB', description: 'MongoDB Database', risk: 'CRITICAL', secure_alternative: 'Bind to localhost, enable auth', common_uses: ['NoSQL database', 'Web apps'], vulnerabilities: ['No auth by default', 'Mass data breaches'], recommendations: ['Enable authentication', 'Bind to localhost', 'Use TLS'] },
};

// ── PCAP Parser ────────────────────────────────────────────────
function parsePcap(buffer) {
  const packets = [];
  let offset = 0;

  if (buffer.length < 24) return packets;

  const magicNumber = buffer.readUInt32LE(0);
  const isLE = magicNumber === 0xa1b2c3d4 || magicNumber === 0xa1b23c4d;
  const isNano = magicNumber === 0xa1b23c4d;

  if (!isLE && magicNumber !== 0xd4c3b2a1 && magicNumber !== 0x4d3cb2a1) {
    return packets;
  }

  const read32 = (off) => isLE ? buffer.readUInt32LE(off) : buffer.readUInt32BE(off);
  const read16 = (off) => isLE ? buffer.readUInt16LE(off) : buffer.readUInt16BE(off);

  const linkType = read32(20);
  offset = 24;

  let packetId = 0;

  while (offset + 16 <= buffer.length && packetId < 10000) {
    const tsSec = read32(offset);
    const tsUsec = read32(offset + 4);
    const inclLen = read32(offset + 8);
    const origLen = read32(offset + 12);
    offset += 16;

    if (offset + inclLen > buffer.length || inclLen > 65536) break;

    const packetData = buffer.slice(offset, offset + inclLen);
    offset += inclLen;

    const timestamp = tsSec + tsUsec / (isNano ? 1e9 : 1e6);
    let packet = {
      id: packetId++,
      timestamp,
      src_ip: null, dst_ip: null,
      src_port: null, dst_port: null,
      protocol: 'UNKNOWN',
      length: origLen,
      ttl: null, flags: null,
      payload_preview: '',
    };

    if (linkType === 1 && packetData.length >= 14) {
      const etherType = packetData.readUInt16BE(12);

      if (etherType === 0x0800 && packetData.length >= 34) {
        const ipStart = 14;
        const ihl = (packetData[ipStart] & 0x0f) * 4;
        const ipProto = packetData[ipStart + 9];
        packet.ttl = packetData[ipStart + 8];
        packet.src_ip = `${packetData[ipStart + 12]}.${packetData[ipStart + 13]}.${packetData[ipStart + 14]}.${packetData[ipStart + 15]}`;
        packet.dst_ip = `${packetData[ipStart + 16]}.${packetData[ipStart + 17]}.${packetData[ipStart + 18]}.${packetData[ipStart + 19]}`;

        const transportStart = ipStart + ihl;

        if (ipProto === 6 && packetData.length >= transportStart + 20) {
          packet.src_port = packetData.readUInt16BE(transportStart);
          packet.dst_port = packetData.readUInt16BE(transportStart + 2);
          const tcpFlags = packetData[transportStart + 13];
          const flagStr = [];
          if (tcpFlags & 0x02) flagStr.push('S');
          if (tcpFlags & 0x10) flagStr.push('A');
          if (tcpFlags & 0x08) flagStr.push('P');
          if (tcpFlags & 0x01) flagStr.push('F');
          if (tcpFlags & 0x04) flagStr.push('R');
          packet.flags = flagStr.join('') || null;

          const dataOffset = (packetData[transportStart + 12] >> 4) * 4;
          const payloadStart = transportStart + dataOffset;
          if (packetData.length > payloadStart) {
            packet.payload_preview = packetData.slice(payloadStart, payloadStart + 64).toString('utf8', 0, 64).replace(/[^\x20-\x7E]/g, '.');
          }

          packet.protocol = PROTOCOL_MAP[packet.dst_port] || PROTOCOL_MAP[packet.src_port] || 'TCP';

        } else if (ipProto === 17 && packetData.length >= transportStart + 8) {
          packet.src_port = packetData.readUInt16BE(transportStart);
          packet.dst_port = packetData.readUInt16BE(transportStart + 2);
          packet.protocol = PROTOCOL_MAP[packet.dst_port] || PROTOCOL_MAP[packet.src_port] || 'UDP';

        } else if (ipProto === 1) {
          packet.protocol = 'ICMP';
        }
      } else if (etherType === 0x86DD) {
        packet.protocol = 'IPv6';
      } else if (etherType === 0x0806) {
        packet.protocol = 'ARP';
      }
    }

    packets.push(packet);
  }

  return packets;
}

// ── Vulnerability Engine ───────────────────────────────────────
function detectVulnerabilities(packets) {
  const alerts = [];
  const seenPortPairs = new Set();
  const publicIps = new Set();

  for (const pkt of packets) {
    const port = pkt.dst_port || pkt.src_port;
    if (port && VULNERABLE_PORTS[port]) {
      const key = `${pkt.src_ip}-${pkt.dst_ip}-${port}`;
      if (!seenPortPairs.has(key)) {
        seenPortPairs.add(key);
        alerts.push({
          layer: 1,
          risk: VULNERABLE_PORTS[port].risk,
          protocol: pkt.protocol,
          port,
          src_ip: pkt.src_ip,
          dst_ip: pkt.dst_ip,
          reason: VULNERABLE_PORTS[port].reason,
        });
      }
    }

    if (pkt.payload_preview) {
      const payload = pkt.payload_preview.toUpperCase();
      if (payload.includes('USER ') || payload.includes('PASS ') || payload.includes('PASSWORD=') || payload.includes('LOGIN:') || payload.includes('AUTHORIZATION: BASIC')) {
        alerts.push({
          layer: 2,
          risk: 'CRITICAL',
          protocol: pkt.protocol,
          port: pkt.dst_port || pkt.src_port,
          src_ip: pkt.src_ip,
          dst_ip: pkt.dst_ip,
          reason: 'Plaintext credentials detected in packet payload!',
          payload_snippet: pkt.payload_preview.slice(0, 100),
        });
      }
    }

    for (const ip of [pkt.src_ip, pkt.dst_ip]) {
      if (ip && !isPrivateIP(ip)) publicIps.add(ip);
    }
  }

  return { alerts, publicIps: [...publicIps].slice(0, 10) };
}

function isPrivateIP(ip) {
  if (!ip) return true;
  return ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.') || ip.startsWith('127.') || ip.startsWith('169.254.');
}

// ── Agent keyword parser ───────────────────────────────────────
function agentQuery(prompt, packets) {
  const p = prompt.toLowerCase();

  if (p.includes('port') && (p.includes('21') || p.includes('ftp'))) {
    const result = packets.filter(pk => pk.dst_port === 21 || pk.src_port === 21);
    return { tool_called: 'filter_by_port', parameters: { port: 21 }, result, response: `Found ${result.length} FTP packets on port 21.` };
  }
  if (p.includes('telnet') || p.includes('port 23')) {
    const result = packets.filter(pk => pk.dst_port === 23 || pk.src_port === 23);
    return { tool_called: 'filter_by_port', parameters: { port: 23 }, result, response: `Found ${result.length} Telnet packets. Telnet is unencrypted — critical risk!` };
  }
  if (p.includes('credential') || p.includes('password') || p.includes('login')) {
    const result = packets.filter(pk => pk.payload_preview && /USER |PASS |PASSWORD=/i.test(pk.payload_preview));
    return { tool_called: 'find_credentials', parameters: {}, result, response: `Found ${result.length} packets with potential plaintext credentials!` };
  }
  if (p.includes('dns')) {
    const result = packets.filter(pk => pk.protocol === 'DNS');
    return { tool_called: 'get_dns_queries', parameters: {}, result, response: `Found ${result.length} DNS packets.` };
  }
  if (p.includes('http') && !p.includes('https')) {
    const result = packets.filter(pk => pk.protocol === 'HTTP');
    return { tool_called: 'filter_by_port', parameters: { port: 80 }, result, response: `Found ${result.length} unencrypted HTTP packets.` };
  }
  if (p.includes('large') || p.includes('biggest')) {
    const sorted = [...packets].sort((a, b) => b.length - a.length).slice(0, 20);
    return { tool_called: 'filter_large_packets', parameters: { threshold: 1000 }, result: sorted, response: `Top ${sorted.length} largest packets shown.` };
  }
  if (p.includes('top talker') || p.includes('most traffic') || p.includes('busiest')) {
    const ipCount = {};
    for (const pk of packets) {
      if (pk.src_ip) ipCount[pk.src_ip] = (ipCount[pk.src_ip] || 0) + pk.length;
    }
    const sorted = Object.entries(ipCount).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([ip, bytes]) => ({ ip, bytes }));
    return { tool_called: 'get_top_talkers', parameters: {}, result: sorted, response: `Top ${sorted.length} IPs by traffic volume shown.` };
  }
  if (p.includes('scan') || p.includes('port scan')) {
    const ipPorts = {};
    for (const pk of packets) {
      if (pk.src_ip && pk.dst_port) {
        if (!ipPorts[pk.src_ip]) ipPorts[pk.src_ip] = new Set();
        ipPorts[pk.src_ip].add(pk.dst_port);
      }
    }
    const scanners = Object.entries(ipPorts).filter(([, ports]) => ports.size > 15).map(([ip, ports]) => ({ ip, ports_scanned: ports.size }));
    return { tool_called: 'detect_port_scan', parameters: {}, result: scanners, response: scanners.length ? `Detected ${scanners.length} potential port scanners!` : 'No port scans detected.' };
  }

  const ipMatch = prompt.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
  if (ipMatch) {
    const ip = ipMatch[1];
    const result = packets.filter(pk => pk.src_ip === ip || pk.dst_ip === ip);
    return { tool_called: 'filter_by_ip', parameters: { ip }, result, response: `Found ${result.length} packets involving IP ${ip}.` };
  }

  const portMatch = prompt.match(/port\s+(\d+)/i);
  if (portMatch) {
    const port = parseInt(portMatch[1]);
    const result = packets.filter(pk => pk.src_port === port || pk.dst_port === port);
    return { tool_called: 'filter_by_port', parameters: { port }, result, response: `Found ${result.length} packets on port ${port}.` };
  }

  const totalPackets = packets.length;
  const protocols = {};
  for (const pk of packets) protocols[pk.protocol] = (protocols[pk.protocol] || 0) + 1;
  const topProtocol = Object.entries(protocols).sort((a, b) => b[1] - a[1])[0];

  return {
    tool_called: 'summary',
    parameters: {},
    result: { total_packets: totalPackets, protocols },
    response: `This capture has ${totalPackets} packets. Most common protocol: ${topProtocol ? topProtocol[0] : 'unknown'} (${topProtocol ? topProtocol[1] : 0} packets). Try asking about specific ports, IPs, credentials, DNS, or port scans!`,
  };
}

// ── HTTP helpers ───────────────────────────────────────────────
function parseBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function parseMultipart(buffer, boundary) {
  const boundaryBuf = Buffer.from('--' + boundary);
  const parts = [];
  let start = 0;

  while (start < buffer.length) {
    const bStart = buffer.indexOf(boundaryBuf, start);
    if (bStart === -1) break;
    const headerStart = bStart + boundaryBuf.length + 2;
    const headerEnd = buffer.indexOf(Buffer.from('\r\n\r\n'), headerStart);
    if (headerEnd === -1) break;

    const headers = buffer.slice(headerStart, headerEnd).toString();
    const dataStart = headerEnd + 4;
    const nextBound = buffer.indexOf(boundaryBuf, dataStart);
    const dataEnd = nextBound === -1 ? buffer.length : nextBound - 2;

    parts.push({ headers, data: buffer.slice(dataStart, dataEnd) });
    start = nextBound === -1 ? buffer.length : nextBound;
  }
  return parts;
}

// json() now reads the request origin and sets CORS headers accordingly
function json(res, data, status = 200, requestOrigin = '') {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    ...getCorsHeaders(requestOrigin),
  });
  res.end(body);
}

function getQuery(url) {
  const q = {};
  const idx = url.indexOf('?');
  if (idx === -1) return q;
  for (const part of url.slice(idx + 1).split('&')) {
    const [k, v] = part.split('=');
    if (k) q[decodeURIComponent(k)] = decodeURIComponent(v || '');
  }
  return q;
}

// ── Keep-alive (fallback — GitHub Actions is primary) ──────────
const RENDER_URL = process.env.RENDER_EXTERNAL_URL || '';
if (RENDER_URL) {
  setInterval(() => {
    https.get(`${RENDER_URL}/pcap/health`, () => { }).on('error', () => { });
    console.log('[Keep-alive] ping sent to', RENDER_URL);
  }, 9 * 60 * 1000);
}

// ── Main HTTP Server ───────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const url = req.url || '/';
  const method = req.method || 'GET';
  const requestOrigin = req.headers['origin'] || '';

  // CORS preflight — must respond before any other logic
  if (method === 'OPTIONS') {
    res.writeHead(204, getCorsHeaders(requestOrigin));
    return res.end();
  }

  console.log(`[${method}] ${url}`);

  // ── Lightweight ping (used by GitHub Actions to prevent sleep) ──────────
  if (url === '/ping' || url === '/pcap/ping') {
    res.writeHead(200, {
      'Content-Type': 'text/plain',
      ...getCorsHeaders(requestOrigin),
    });
    return res.end('pong');
  }

  // ── Health check ──────────────────────────────────────────────
  if (url === '/pcap/health' || url === '/health') {
    return json(res, { status: 'ok', service: 'pcap-analyzer', sessions: sessions.size }, 200, requestOrigin);
  }

  // ── Upload PCAP ───────────────────────────────────────────────
  if (url === '/pcap/upload' && method === 'POST') {
    try {
      const contentType = req.headers['content-type'] || '';
      const boundaryMatch = contentType.match(/boundary=(.+)/);
      if (!boundaryMatch) return json(res, { error: 'Missing multipart boundary' }, 400, requestOrigin);

      const body = await parseBody(req);
      const parts = parseMultipart(body, boundaryMatch[1]);

      let fileData = null;
      let filename = 'upload.pcap';

      for (const part of parts) {
        if (part.headers.includes('filename=')) {
          const fnMatch = part.headers.match(/filename="([^"]+)"/);
          if (fnMatch) filename = fnMatch[1];
          fileData = part.data;
        }
      }

      if (!fileData) return json(res, { error: 'No file found in upload' }, 400, requestOrigin);

      const packets = parsePcap(fileData);
      if (packets.length === 0) return json(res, { error: 'Could not parse PCAP file. Make sure it is a valid .pcap or .pcapng file.' }, 400, requestOrigin);

      const protocols = {};
      let totalBytes = 0;
      for (const pk of packets) {
        protocols[pk.protocol] = (protocols[pk.protocol] || 0) + 1;
        totalBytes += pk.length;
      }
      const timestamps = packets.map(p => p.timestamp);
      const minT = Math.min(...timestamps);
      const maxT = Math.max(...timestamps);

      const session_id = `session-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
      sessions.set(session_id, { session_id, filename, packets, created_at: Date.now() });

      if (sessions.size > 10) {
        const oldest = [...sessions.keys()][0];
        sessions.delete(oldest);
      }

      return json(res, {
        session_id,
        summary: {
          total_packets: packets.length,
          protocols,
          duration_seconds: Math.round(maxT - minT),
          total_bytes: totalBytes,
          time_range: { start: minT, end: maxT },
        },
      }, 200, requestOrigin);
    } catch (e) {
      console.error('[Upload Error]', e);
      return json(res, { error: 'Upload failed: ' + e.message }, 500, requestOrigin);
    }
  }

  // ── Get Packets ───────────────────────────────────────────────
  if (url.startsWith('/pcap/packets') && method === 'GET') {
    const q = getQuery(url);
    const session = sessions.get(q.session_id);
    if (!session) return json(res, { error: 'Session not found' }, 404, requestOrigin);

    const page = parseInt(q.page || '1');
    const per_page = parseInt(q.per_page || '50');
    const start = (page - 1) * per_page;
    const paginated = session.packets.slice(start, start + per_page);

    return json(res, {
      packets: paginated,
      total: session.packets.length,
      page,
      per_page,
    }, 200, requestOrigin);
  }

  // ── Vulnerabilities ───────────────────────────────────────────
  if (url.startsWith('/pcap/vulnerabilities') && method === 'GET') {
    const q = getQuery(url);
    const session = sessions.get(q.session_id);
    if (!session) return json(res, { error: 'Session not found' }, 404, requestOrigin);

    const { alerts, publicIps } = detectVulnerabilities(session.packets);

    const enrichedAlerts = [...alerts];
    for (const ip of publicIps.slice(0, 5)) {
      try {
        await new Promise((resolve) => {
          https.get(`https://internetdb.shodan.io/${ip}`, (r) => {
            let data = '';
            r.on('data', d => data += d);
            r.on('end', () => {
              try {
                const parsed = JSON.parse(data);
                if (parsed.cves && parsed.cves.length > 0) {
                  enrichedAlerts.push({
                    layer: 3,
                    risk: 'HIGH',
                    ip,
                    reason: `Shodan reports ${parsed.cves.length} known CVEs for this IP`,
                    open_ports: parsed.ports || [],
                    cves: parsed.cves.slice(0, 5),
                    hostnames: parsed.hostnames || [],
                  });
                }
              } catch (_) { }
              resolve();
            });
          }).on('error', () => resolve());
          setTimeout(resolve, 3000);
        });
      } catch (_) { }
    }

    const summary = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const a of enrichedAlerts) {
      const r = a.risk?.toLowerCase();
      if (summary[r] !== undefined) summary[r]++;
    }

    return json(res, { alerts: enrichedAlerts, summary }, 200, requestOrigin);
  }

  // ── Agent Query ───────────────────────────────────────────────
  if (url === '/pcap/agent/query' && method === 'POST') {
    try {
      const body = await parseBody(req);
      const { prompt, session_id } = JSON.parse(body.toString());
      const session = sessions.get(session_id);
      if (!session) return json(res, { error: 'Session not found' }, 404, requestOrigin);
      const result = agentQuery(prompt, session.packets);
      return json(res, result, 200, requestOrigin);
    } catch (e) {
      return json(res, { error: 'Agent error: ' + e.message }, 500, requestOrigin);
    }
  }
  // ── Images ────────────────────────────────────────────────────
  // Add this block RIGHT BEFORE the Port Intelligence block
  if (url.startsWith('/pcap/images') && method === 'GET') {
    const q = getQuery(url);
    const session = sessions.get(q.session_id);
    if (!session) return json(res, { error: 'Session not found' }, 404, requestOrigin);

    // ── Magic byte signatures for image formats ──────────────
    const MAGIC = [
      { sig: [0xFF, 0xD8, 0xFF], ext: 'jpg', mime: 'image/jpeg' },
      { sig: [0x89, 0x50, 0x4E, 0x47], ext: 'png', mime: 'image/png' },
      { sig: [0x47, 0x49, 0x46, 0x38, 0x37], ext: 'gif', mime: 'image/gif' },
      { sig: [0x47, 0x49, 0x46, 0x38, 0x39], ext: 'gif', mime: 'image/gif' },
      { sig: [0x42, 0x4D], ext: 'bmp', mime: 'image/bmp' },
    ];

    // ── Build a raw buffer from all TCP payloads on port 80 ──
    // We reconstruct what Wireshark's "Export Objects → HTTP" does:
    // collect raw payload bytes from HTTP traffic and carve images out
    const httpPayloads = [];

    for (const pkt of session.packets) {
      // Only look at HTTP traffic (port 80 src or dst)
      const isHttp = pkt.dst_port === 80 || pkt.src_port === 80;
      if (!isHttp) continue;

      // payload_preview is a string — convert back to bytes
      // Note: payload_preview is already stored as utf8 string in our parser
      // For carving we need the raw bytes, so we re-parse from the stored preview
      if (pkt.payload_preview && pkt.payload_preview.length > 0) {
        httpPayloads.push({
          data: Buffer.from(pkt.payload_preview, 'utf8'),
          src_ip: pkt.src_ip,
          dst_ip: pkt.dst_ip,
          timestamp: pkt.timestamp,
        });
      }
    }

    // ── Carve images using magic byte signatures ──────────────
    const images = [];
    const seen = new Set();

    for (const payload of httpPayloads) {
      const buf = payload.data;

      for (const magic of MAGIC) {
        let searchFrom = 0;

        while (searchFrom < buf.length) {
          // Find magic byte signature in buffer
          let found = -1;
          outer: for (let i = searchFrom; i <= buf.length - magic.sig.length; i++) {
            for (let j = 0; j < magic.sig.length; j++) {
              if (buf[i + j] !== magic.sig[j]) continue outer;
            }
            found = i;
            break;
          }

          if (found === -1) break;

          // Extract chunk from found offset (max 2MB)
          const chunk = buf.slice(found, Math.min(found + 2 * 1024 * 1024, buf.length));

          // Skip tiny chunks — not real images
          if (chunk.length < 100) {
            searchFrom = found + 1;
            continue;
          }

          // Deduplicate by first 32 bytes
          const fingerprint = chunk.slice(0, 32).toString('hex');
          if (!seen.has(fingerprint)) {
            seen.add(fingerprint);

            // Convert to base64 data URL so frontend can display directly
            // No file system needed — works on Render without disk access
            const base64 = chunk.toString('base64');
            const dataUrl = `data:${magic.mime};base64,${base64}`;

            images.push({
              filename: `extracted_${images.length}.${magic.ext}`,
              url: dataUrl,           // ← data URL, works directly in <img src>
              size: chunk.length,
              content_type: magic.mime,
              method: 'magic-carve',
              src_ip: payload.src_ip || 'unknown',
              dst_ip: payload.dst_ip || 'unknown',
              timestamp: payload.timestamp,
            });
          }

          searchFrom = found + 1;
        }
      }
    }

    return json(res, {
      images,
      total: images.length,
      message: images.length === 0
        ? 'No images found. Images can only be extracted from unencrypted HTTP (port 80) traffic.'
        : `Extracted ${images.length} image(s) from HTTP traffic.`,
    }, 200, requestOrigin);
  }

  // ── Port Intelligence ─────────────────────────────────────────
  if (url.startsWith('/pcap/port-intel') && method === 'GET') {
    const q = getQuery(url);
    const query = q.query || '';
    const portNum = parseInt(query);

    if (!isNaN(portNum) && PORT_KNOWLEDGE[portNum]) {
      return json(res, { ...PORT_KNOWLEDGE[portNum], port: portNum }, 200, requestOrigin);
    }

    const match = Object.entries(PORT_KNOWLEDGE).find(([, v]) =>
      v.name.toLowerCase().includes(query.toLowerCase()) ||
      v.description.toLowerCase().includes(query.toLowerCase())
    );
    if (match) return json(res, { ...match[1], port: parseInt(match[0]) }, 200, requestOrigin);

    if (!query) {
      return json(res, Object.entries(PORT_KNOWLEDGE).map(([port, info]) => ({ port: parseInt(port), ...info })), 200, requestOrigin);
    }

    return json(res, { error: 'Port not found in knowledge base' }, 404, requestOrigin);
  }

  // ── 404 ───────────────────────────────────────────────────────
  json(res, {
    error: 'Not found', available_endpoints: [
      'GET  /pcap/health',
      'GET  /ping',
      'POST /pcap/upload',
      'GET  /pcap/packets?session_id=X',
      'GET  /pcap/vulnerabilities?session_id=X',
      'POST /pcap/agent/query',
      'GET  /pcap/port-intel?query=X',
    ]
  }, 404, requestOrigin);
});

const PORT = process.env.PORT || 4000;
server.listen(PORT, () => {
  console.log(`✅ PCAP Analyzer Backend running on port ${PORT}`);
  console.log(`🌐 CORS allowed origin: ${ALLOWED_ORIGIN}`);
  console.log(`📡 Endpoints available at /pcap/*`);
});

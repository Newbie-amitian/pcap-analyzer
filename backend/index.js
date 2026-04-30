const http = require('http');
const https = require('https');
const { Buffer } = require('buffer');

// ── In-memory session store ────────────────────────────────────
const sessions = new Map();

// ── CORS ──────────────────────────────────────────────────────
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || 'http://localhost:3000';

function getCorsHeaders(requestOrigin) {
  const origin = requestOrigin || '';
  if (origin === ALLOWED_ORIGIN) {
    return {
      'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Vary': 'Origin',
    };
  }
  return {};
}

// ── Groq ──────────────────────────────────────────────────────
const GROQ_API_KEY = process.env.GROQ_API_KEY || '';
const GROQ_MODEL = 'llama-3.3-70b-versatile';

function groqRequest(messages, maxTokens = 1024) {
  return new Promise((resolve) => {
    if (!GROQ_API_KEY) return resolve(null);

    const body = JSON.stringify({ model: GROQ_MODEL, max_tokens: maxTokens, messages });
    const options = {
      hostname: 'api.groq.com',
      path: '/openai/v1/chat/completions',
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${GROQ_API_KEY}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          resolve(json.choices?.[0]?.message?.content?.trim() || null);
        } catch (_) { resolve(null); }
      });
    });
    req.on('error', () => resolve(null));
    setTimeout(() => resolve(null), 25000);
    req.write(body);
    req.end();
  });
}

// ── CVE enrichment from live APIs ─────────────────────────────
async function fetchCveDetails(cveId) {
  return new Promise((resolve) => {
    https.get(`https://cve.circl.lu/api/cve/${cveId}`, (res) => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch (_) { resolve(null); }
      });
    }).on('error', () => resolve(null));
    setTimeout(() => resolve(null), 4000);
  });
}

async function fetchShodanIp(ip) {
  return new Promise((resolve) => {
    https.get(`https://internetdb.shodan.io/${ip}`, (res) => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch (_) { resolve(null); }
      });
    }).on('error', () => resolve(null));
    setTimeout(() => resolve(null), 4000);
  });
}

// ── Protocol/Port maps ─────────────────────────────────────────
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

// ── Tool executor (all deterministic tools) ───────────────────
function runTool(toolName, params, packets) {
  switch (toolName) {
    case 'filter_by_port': {
      const port = params.port;
      const result = packets.filter(pk => pk.dst_port === port || pk.src_port === port);
      return { result, response: `Found ${result.length} packets on port ${port}.` };
    }
    case 'filter_by_ip': {
      const result = packets.filter(pk => pk.src_ip === params.ip || pk.dst_ip === params.ip);
      return { result, response: `Found ${result.length} packets involving IP ${params.ip}.` };
    }
    case 'find_credentials': {
      const result = packets.filter(pk => pk.payload_preview && /USER |PASS |PASSWORD=|AUTHORIZATION: BASIC|LOGIN:/i.test(pk.payload_preview));
      return { result, response: `Found ${result.length} packets with potential plaintext credentials.` };
    }
    case 'detect_port_scan': {
      const ipPorts = {};
      for (const pk of packets) {
        if (pk.src_ip && pk.dst_port) {
          if (!ipPorts[pk.src_ip]) ipPorts[pk.src_ip] = new Set();
          ipPorts[pk.src_ip].add(pk.dst_port);
        }
      }
      const result = Object.entries(ipPorts)
        .filter(([, ports]) => ports.size > 15)
        .map(([ip, ports]) => ({ ip, ports_scanned: ports.size, ports: [...ports].slice(0, 20) }));
      return { result, response: result.length ? `Detected ${result.length} potential port scanners.` : 'No port scanning detected.' };
    }
    case 'get_dns_queries': {
      const result = packets.filter(pk => pk.protocol === 'DNS');
      const domains = {};
      for (const pk of result) {
        if (pk.payload_preview) {
          const match = pk.payload_preview.match(/[a-zA-Z0-9-]+\.[a-zA-Z]{2,}/g);
          if (match) match.forEach(d => { domains[d] = (domains[d] || 0) + 1; });
        }
      }
      return { result: { packets: result.slice(0, 50), top_domains: Object.entries(domains).sort((a, b) => b[1] - a[1]).slice(0, 10) }, response: `Found ${result.length} DNS packets.` };
    }
    case 'get_top_talkers': {
      const ipCount = {};
      for (const pk of packets) {
        if (pk.src_ip) ipCount[pk.src_ip] = (ipCount[pk.src_ip] || 0) + pk.length;
      }
      const result = Object.entries(ipCount).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([ip, bytes]) => ({ ip, bytes }));
      return { result, response: `Top ${result.length} IPs by traffic volume.` };
    }
    case 'filter_large_packets': {
      const result = [...packets].sort((a, b) => b.length - a.length).slice(0, 20);
      return { result, response: `Top ${result.length} largest packets.` };
    }
    case 'get_vulnerability_report': {
      const vulnPorts = Object.keys(VULNERABLE_PORTS).map(Number);
      const result = packets.filter(pk => vulnPorts.includes(pk.dst_port) || vulnPorts.includes(pk.src_port));
      const byPort = {};
      for (const pk of result) {
        const p = pk.dst_port || pk.src_port;
        if (!byPort[p]) byPort[p] = { port: p, count: 0, risk: VULNERABLE_PORTS[p]?.risk, reason: VULNERABLE_PORTS[p]?.reason };
        byPort[p].count++;
      }
      return { result: Object.values(byPort), response: `Found traffic on ${Object.keys(byPort).length} vulnerable ports affecting ${result.length} packets.` };
    }
    case 'domain_lookup': {
      const domain = (params.domain || '').toLowerCase();
      const result = packets.filter(pk => pk.payload_preview?.toLowerCase().includes(domain));
      const dns = packets.filter(pk => pk.protocol === 'DNS' && pk.payload_preview?.toLowerCase().includes(domain));
      return {
        result: { domain_packets: result.slice(0, 30), dns_hits: dns.slice(0, 10), total_hits: result.length },
        response: `Found ${result.length} packets referencing "${domain}", including ${dns.length} DNS queries.`,
      };
    }
    case 'filter_by_protocol': {
      const proto = (params.protocol || '').toUpperCase();
      const result = packets.filter(pk => pk.protocol === proto);
      return { result: result.slice(0, 100), response: `Found ${result.length} ${proto} packets.` };
    }
    case 'get_summary':
    default: {
      const protocols = {};
      const ipCount = {};
      let totalBytes = 0;
      for (const pk of packets) {
        protocols[pk.protocol] = (protocols[pk.protocol] || 0) + 1;
        if (pk.src_ip) ipCount[pk.src_ip] = (ipCount[pk.src_ip] || 0) + pk.length;
        totalBytes += pk.length;
      }
      const topIps = Object.entries(ipCount).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([ip, bytes]) => ({ ip, bytes }));
      const timestamps = packets.map(p => p.timestamp);
      const duration = Math.round(Math.max(...timestamps) - Math.min(...timestamps));
      return {
        result: { total_packets: packets.length, protocols, top_ips: topIps, total_bytes: totalBytes, duration_seconds: duration },
        response: `${packets.length} packets, ${duration}s capture duration.`,
      };
    }
  }
}

// ── Dynamic agent: Groq picks the tool ────────────────────────
async function dynamicAgent(userPrompt, packets) {
  const protocols = {};
  for (const pk of packets) protocols[pk.protocol] = (protocols[pk.protocol] || 0) + 1;

  const toolSchema = `
Available tools (respond ONLY with valid JSON, no markdown, no explanation):
- get_summary → {}
- filter_by_port → {"port": number}
- filter_by_ip → {"ip": "x.x.x.x"}
- filter_by_protocol → {"protocol": "HTTP"|"DNS"|"TCP"|"UDP"|"ICMP"|"ARP"|"IPv6"|"HTTPS"|"FTP"|"SSH"|...}
- find_credentials → {}
- detect_port_scan → {}
- get_dns_queries → {}
- get_top_talkers → {}
- filter_large_packets → {}
- get_vulnerability_report → {}
- domain_lookup → {"domain": "example.com"}

Capture has ${packets.length} packets. Protocol breakdown: ${JSON.stringify(protocols)}.

Pick the best tool for the user's question. Respond ONLY with: {"tool": "tool_name", "params": {...}}`;

  let toolName = 'get_summary';
  let toolParams = {};

  if (GROQ_API_KEY) {
    const decision = await groqRequest([
      { role: 'system', content: toolSchema },
      { role: 'user', content: userPrompt },
    ], 100);

    if (decision) {
      try {
        const clean = decision.replace(/```json|```/g, '').trim();
        const parsed = JSON.parse(clean);
        if (parsed.tool) {
          toolName = parsed.tool;
          toolParams = parsed.params || {};
        }
      } catch (_) { }
    }
  }

  // Run the tool
  const toolResult = runTool(toolName, toolParams, packets);

  // Summarize result for Groq (avoid token overflow)
  const resultSummary = Array.isArray(toolResult.result) && toolResult.result.length > 30
    ? { sample: toolResult.result.slice(0, 30), total_count: toolResult.result.length }
    : toolResult.result;

  // Fetch live CVE/Shodan data if vulnerability report
  let liveEnrichment = '';
  if (toolName === 'get_vulnerability_report' && Array.isArray(toolResult.result)) {
    const ports = toolResult.result.map(r => r.port).filter(Boolean).slice(0, 3);
    const publicIps = [...new Set(packets.filter(pk => !isPrivateIP(pk.src_ip)).map(pk => pk.src_ip))].slice(0, 2);

    for (const ip of publicIps) {
      const shodan = await fetchShodanIp(ip);
      if (shodan?.cves?.length) {
        liveEnrichment += `\nShodan data for ${ip}: ${shodan.cves.length} known CVEs including ${shodan.cves.slice(0, 3).join(', ')}.`;
        for (const cveId of shodan.cves.slice(0, 2)) {
          const cveDetail = await fetchCveDetails(cveId);
          if (cveDetail?.summary) {
            liveEnrichment += `\n${cveId}: ${cveDetail.summary.slice(0, 150)}`;
          }
        }
      }
    }
  }

  // Ask Groq to explain like a human — no markdown, no bullet points
  const explanation = await groqRequest([
    {
      role: 'system',
      content: `You are a network security expert talking casually to a developer. 
You just ran a tool on their PCAP file and got results. 
Explain what you found in plain conversational English — like a colleague explaining over chat.
No markdown. No bullet points. No asterisks. No headers. Just natural sentences.
Be direct, specific, and mention actual numbers and IPs from the data.
If there are security risks, explain them plainly. Keep it under 200 words.
${liveEnrichment ? `Live threat intelligence gathered: ${liveEnrichment}` : ''}`,
    },
    {
      role: 'user',
      content: `User asked: "${userPrompt}"
Tool used: ${toolName}
Tool result: ${JSON.stringify(resultSummary)}
Raw response: ${toolResult.response}

Explain this to the user conversationally.`,
    },
  ], 512);

  return {
    tool_called: toolName,
    parameters: toolParams,
    result: toolResult.result,
    response: explanation || toolResult.response,
  };
}

function isPrivateIP(ip) {
  if (!ip) return true;
  return ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.') || ip.startsWith('127.') || ip.startsWith('169.254.');
}

// ── PCAP Parser ────────────────────────────────────────────────
function parsePcap(buffer) {
  const packets = [];
  let offset = 0;

  if (buffer.length < 24) return packets;

  const magicNumber = buffer.readUInt32LE(0);
  const isLE = magicNumber === 0xa1b2c3d4 || magicNumber === 0xa1b23c4d;
  const isNano = magicNumber === 0xa1b23c4d;

  if (!isLE && magicNumber !== 0xd4c3b2a1 && magicNumber !== 0x4d3cb2a1) return packets;

  const read32 = (off) => isLE ? buffer.readUInt32LE(off) : buffer.readUInt32BE(off);

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
      raw_payload: null,
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
            packet.payload_preview = packetData
              .slice(payloadStart, payloadStart + 128)
              .toString('utf8', 0, 128)
              .replace(/[^\x20-\x7E]/g, '.');
            packet.raw_payload = packetData.slice(payloadStart);
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

// ── Keep-alive ────────────────────────────────────────────────
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

  if (method === 'OPTIONS') {
    res.writeHead(204, getCorsHeaders(requestOrigin));
    return res.end();
  }

  console.log(`[${method}] ${url}`);

  if (url === '/ping' || url === '/pcap/ping') {
    res.writeHead(200, { 'Content-Type': 'text/plain', ...getCorsHeaders(requestOrigin) });
    return res.end('pong');
  }

  if (url === '/pcap/health' || url === '/health') {
    return json(res, { status: 'ok', service: 'pcap-analyzer', sessions: sessions.size }, 200, requestOrigin);
  }

  // ── Upload ────────────────────────────────────────────────────
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
      if (packets.length === 0) return json(res, { error: 'Could not parse PCAP file.' }, 400, requestOrigin);

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
      if (sessions.size > 10) sessions.delete([...sessions.keys()][0]);

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

  // ── Packets ───────────────────────────────────────────────────
  if (url.startsWith('/pcap/packets') && method === 'GET') {
    const q = getQuery(url);
    const session = sessions.get(q.session_id);
    if (!session) return json(res, { error: 'Session not found' }, 404, requestOrigin);

    const page = parseInt(q.page || '1');
    const per_page = parseInt(q.per_page || '50');
    const start = (page - 1) * per_page;
    const paginated = session.packets.slice(start, start + per_page);

    return json(res, { packets: paginated, total: session.packets.length, page, per_page }, 200, requestOrigin);
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
        const shodan = await fetchShodanIp(ip);
        if (shodan?.cves?.length) {
          enrichedAlerts.push({
            layer: 3, risk: 'HIGH', ip,
            reason: `Shodan reports ${shodan.cves.length} known CVEs for this IP`,
            open_ports: shodan.ports || [],
            cves: shodan.cves.slice(0, 5),
            hostnames: shodan.hostnames || [],
          });
        }
      } catch (_) { }
    }

    const summary = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const a of enrichedAlerts) {
      const r = a.risk?.toLowerCase();
      if (summary[r] !== undefined) summary[r]++;
    }

    return json(res, { alerts: enrichedAlerts, summary }, 200, requestOrigin);
  }

  // ── Agent Query — fully dynamic ────────────────────────────────
  if (url === '/pcap/agent/query' && method === 'POST') {
    try {
      const body = await parseBody(req);
      const { prompt, session_id } = JSON.parse(body.toString());
      const session = sessions.get(session_id);
      if (!session) return json(res, { error: 'Session not found' }, 404, requestOrigin);

      const result = await dynamicAgent(prompt, session.packets);
      return json(res, result, 200, requestOrigin);

    } catch (e) {
      console.error('[Agent Error]', e);
      return json(res, { error: 'Agent error: ' + e.message }, 500, requestOrigin);
    }
  }

  // ── Images ────────────────────────────────────────────────────
  if (url.startsWith('/pcap/images') && method === 'GET') {
    const q = getQuery(url);
    const session = sessions.get(q.session_id);
    if (!session) return json(res, { error: 'Session not found' }, 404, requestOrigin);

    const MAGIC = [
      { sig: [0xFF, 0xD8, 0xFF], ext: 'jpg', mime: 'image/jpeg' },
      { sig: [0x89, 0x50, 0x4E, 0x47], ext: 'png', mime: 'image/png' },
      { sig: [0x47, 0x49, 0x46, 0x38, 0x37], ext: 'gif', mime: 'image/gif' },
      { sig: [0x47, 0x49, 0x46, 0x38, 0x39], ext: 'gif', mime: 'image/gif' },
      { sig: [0x42, 0x4D], ext: 'bmp', mime: 'image/bmp' },
      { sig: [0x52, 0x49, 0x46, 0x46], ext: 'webp', mime: 'image/webp' },
    ];

    // Collect ALL TCP streams (any port, not just 80)
    const streams = {};
    for (const pkt of session.packets) {
      if (!pkt.raw_payload || pkt.raw_payload.length === 0) continue;
      if (!pkt.src_ip || !pkt.dst_ip || !pkt.src_port || !pkt.dst_port) continue;

      // Server→client only: server has lower port OR src_port is 80/8080/8443
      const isServerResponse = pkt.src_port === 80 || pkt.src_port === 8080 || pkt.src_port === 8443 || pkt.src_port < pkt.dst_port;
      if (!isServerResponse) continue;

      const streamKey = `${pkt.src_ip}:${pkt.src_port}-${pkt.dst_ip}:${pkt.dst_port}`;
      if (!streams[streamKey]) streams[streamKey] = { chunks: [], src_ip: pkt.src_ip, dst_ip: pkt.dst_ip };
      streams[streamKey].chunks.push(pkt.raw_payload);
    }

    // Reassemble streams and strip HTTP headers
    const httpBodies = [];
    for (const stream of Object.values(streams)) {
      if (!stream.chunks.length) continue;
      const combined = Buffer.concat(stream.chunks);

      // Strip HTTP response headers
      const headerEnd = combined.indexOf(Buffer.from('\r\n\r\n'));
      let body = headerEnd !== -1 ? combined.slice(headerEnd + 4) : combined;

      // Handle chunked transfer encoding — strip chunk size lines
      const headerStr = headerEnd !== -1 ? combined.slice(0, headerEnd).toString() : '';
      if (headerStr.toLowerCase().includes('transfer-encoding: chunked')) {
        try {
          const dechunked = [];
          let pos = 0;
          while (pos < body.length) {
            const lineEnd = body.indexOf(Buffer.from('\r\n'), pos);
            if (lineEnd === -1) break;
            const chunkSizeHex = body.slice(pos, lineEnd).toString().trim();
            const chunkSize = parseInt(chunkSizeHex, 16);
            if (isNaN(chunkSize) || chunkSize === 0) break;
            const chunkStart = lineEnd + 2;
            dechunked.push(body.slice(chunkStart, chunkStart + chunkSize));
            pos = chunkStart + chunkSize + 2;
          }
          if (dechunked.length > 0) body = Buffer.concat(dechunked);
        } catch (_) { }
      }

      if (body.length > 50) httpBodies.push({ data: body, src_ip: stream.src_ip, dst_ip: stream.dst_ip });
    }

    // Carve images by magic bytes
    const images = [];
    const seen = new Set();

    for (const payload of httpBodies) {
      const buf = payload.data;

      for (const magic of MAGIC) {
        let searchFrom = 0;
        while (searchFrom < buf.length) {
          let found = -1;
          outer: for (let i = searchFrom; i <= buf.length - magic.sig.length; i++) {
            for (let j = 0; j < magic.sig.length; j++) {
              if (buf[i + j] !== magic.sig[j]) continue outer;
            }
            found = i;
            break;
          }
          if (found === -1) break;

          const chunk = buf.slice(found, Math.min(found + 3 * 1024 * 1024, buf.length));
          if (chunk.length < 50) { searchFrom = found + 1; continue; }

          const fingerprint = chunk.slice(0, 32).toString('hex');
          if (!seen.has(fingerprint)) {
            seen.add(fingerprint);
            const base64 = chunk.toString('base64');
            images.push({
              filename: `extracted_${images.length}.${magic.ext}`,
              url: `data:${magic.mime};base64,${base64}`,
              size: chunk.length,
              content_type: magic.mime,
              method: 'magic-carve',
              src_ip: payload.src_ip || 'unknown',
              dst_ip: payload.dst_ip || 'unknown',
            });
          }
          searchFrom = found + magic.sig.length;
        }
      }
    }

    return json(res, {
      images,
      total: images.length,
      message: images.length === 0
        ? 'No images found. Images can only be extracted from unencrypted HTTP traffic.'
        : `Extracted ${images.length} image(s) from HTTP traffic.`,
    }, 200, requestOrigin);
  }

  // ── Port Intelligence — live CVE enrichment ───────────────────
  if (url.startsWith('/pcap/port-intel') && method === 'GET') {
    const q = getQuery(url);
    const query = q.query || '';

    // Ask Groq for dynamic port info instead of hardcoded knowledge base
    if (GROQ_API_KEY) {
      const portInfo = await groqRequest([
        {
          role: 'system',
          content: `You are a network security expert. When given a port number or protocol name, provide accurate security information about it. Respond in plain JSON only with these fields: name, description, risk (CRITICAL/HIGH/MEDIUM/LOW/SECURE), secure_alternative, common_uses (array), vulnerabilities (array), recommendations (array). No markdown.`,
        },
        { role: 'user', content: `Tell me about port/protocol: ${query}` },
      ], 400);

      if (portInfo) {
        try {
          const clean = portInfo.replace(/```json|```/g, '').trim();
          const parsed = JSON.parse(clean);
          return json(res, { ...parsed, port: parseInt(query) || query, source: 'groq' }, 200, requestOrigin);
        } catch (_) { }
      }
    }

    return json(res, { error: 'Port not found' }, 404, requestOrigin);
  }

  // ── 404 ───────────────────────────────────────────────────────
  json(res, {
    error: 'Not found',
    available_endpoints: [
      'GET  /pcap/health',
      'POST /pcap/upload',
      'GET  /pcap/packets?session_id=X',
      'GET  /pcap/vulnerabilities?session_id=X',
      'POST /pcap/agent/query',
      'GET  /pcap/images?session_id=X',
      'GET  /pcap/port-intel?query=X',
    ],
  }, 404, requestOrigin);
});

const PORT = process.env.PORT || 4000;
server.listen(PORT, () => {
  console.log(`✅ PCAP Analyzer Backend running on port ${PORT}`);
  console.log(`🌐 CORS allowed origin: ${ALLOWED_ORIGIN}`);
  console.log(`🤖 Groq AI: ${GROQ_API_KEY ? 'enabled ✅' : 'MISSING ❌ — set GROQ_API_KEY'}`);
});

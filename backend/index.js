const http = require('http');
const https = require('https');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');

// ── Directory Setup ──────────────────────────────────────────
const PCAP_DIR = '/tmp/pcaps';
const EXPORT_DIR = '/tmp/exports';
if (!fs.existsSync(PCAP_DIR)) fs.mkdirSync(PCAP_DIR, { recursive: true });
if (!fs.existsSync(EXPORT_DIR)) fs.mkdirSync(EXPORT_DIR, { recursive: true });

// ── In-memory stores ─────────────────────────────────────────
const sessions = new Map();
const imageStore = new Map();
const SESSION_TTL_MS = 30 * 60 * 1000;

setInterval(() => {
  const now = Date.now();
  for (const [id] of sessions) {
    if (now - sessions.get(id).created_at > SESSION_TTL_MS) {
      const pcapPath = path.join(PCAP_DIR, `${id}.pcap`);
      const exportPath = path.join(EXPORT_DIR, id);
      if (fs.existsSync(pcapPath)) fs.unlinkSync(pcapPath);
      if (fs.existsSync(exportPath)) fs.rmSync(exportPath, { recursive: true });
      sessions.delete(id); imageStore.delete(id);
    }
  }
}, 5 * 60 * 1000);

// ── CORS & HTTP Helpers ─────────────────────────────────────
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';
function getCorsHeaders(origin) { return { 'Access-Control-Allow-Origin': ALLOWED_ORIGIN === '*' ? '*' : origin, 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type' }; }
function parseBody(req) { return new Promise((res, rej) => { const c = []; req.on('data', d => c.push(d)); req.on('end', () => res(Buffer.concat(c))); req.on('error', rej); }); }
function parseMultipart(buffer, boundary) {
  const bBuf = Buffer.from('\r\n--' + boundary.replace(/^["']|["']$/g, '').trim()); const fBuf = Buffer.from('--' + boundary.replace(/^["']|["']$/g, '').trim()); const CRLF = Buffer.from('\r\n\r\n'); const parts = [];
  let pos = buffer.indexOf(fBuf); if (pos === -1) return parts; pos += fBuf.length; let s = 0;
  while (pos < buffer.length && s++ < 1000) { const lEnd = buffer.indexOf(Buffer.from('\r\n'), pos); if (lEnd === -1) break; if (buffer.slice(pos, lEnd).toString().startsWith('--')) break; const hEnd = buffer.indexOf(CRLF, lEnd + 2); if (hEnd === -1) break; const nBound = buffer.indexOf(bBuf, hEnd + 4); parts.push({ headers: buffer.slice(lEnd + 2, hEnd).toString(), data: buffer.slice(hEnd + 4, nBound === -1 ? buffer.length : nBound) }); if (nBound === -1) break; pos = nBound + bBuf.length; }
  return parts;
}
function json(res, data, status, origin, enc) {
  const p = JSON.stringify(data); const h = getCorsHeaders(origin);
  if (/\bgzip\b/.test(enc) && p.length > 1024) { zlib.gzip(Buffer.from(p), (e, c) => { if (e) { res.writeHead(status, { 'Content-Type': 'application/json', ...h }); res.end(p); return; } res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Encoding': 'gzip', ...h }); res.end(c); }); }
  else { res.writeHead(status || 200, { 'Content-Type': 'application/json', ...h }); res.end(p); }
}
function getQuery(url) { const q = {}; const i = url.indexOf('?'); if (i === -1) return q; for (const p of url.slice(i + 1).split('&')) { const [k, v] = p.split('='); if (k) q[decodeURIComponent(k)] = decodeURIComponent(v || ''); } return q; }
const isValidSessionId = (id) => typeof id === 'string' && /^session-\d{13}-[a-z0-9]{6}$/.test(id);

// ── TShark Core Engine ──────────────────────────────────────
const DEFAULT_FIELDS = ['frame.number', 'ip.src', 'ip.dst', 'frame.len', '_ws.col.Protocol', 'tcp.srcport', 'tcp.dstport', 'frame.time_relative'];

function runTshark(sessionId, filter = '', fields = DEFAULT_FIELDS, limit = 0) {
  return new Promise((resolve) => {
    const pPath = path.join(PCAP_DIR, `${sessionId}.pcap`);
    if (!fs.existsSync(pPath)) return resolve([]);
    let cmd = `tshark -r "${pPath}" -T fields -E separator='\\t' -e ${fields.join(' -e ')}`;
    if (filter) cmd += ` -Y "${filter}"`;
    if (limit > 0) cmd += ` | head -n ${limit}`;
    exec(cmd, { timeout: 15000 }, (err, stdout) => {
      if (err) return resolve([]);
      resolve(stdout.trim().split('\n').filter(l => l.trim()).map(line => {
        const c = line.split('\t');
        return { id: parseInt(c[0]) || 0, src_ip: c[1] || null, dst_ip: c[2] || null, length: parseInt(c[3]) || 0, protocol: c[4] || 'UNKNOWN', src_port: parseInt(c[5]) || null, dst_port: parseInt(c[6]) || null, timestamp: parseFloat(c[7]) || 0 };
      }));
    });
  });
}

function runTsharkStat(sessionId, statCommand) {
  return new Promise((resolve) => {
    const pPath = path.join(PCAP_DIR, `${sessionId}.pcap`);
    if (!fs.existsSync(pPath)) return resolve("PCAP not found");
    exec(`tshark -r "${pPath}" -q -z ${statCommand}`, { timeout: 15000 }, (err, stdout) => resolve(stdout || "Stat failed"));
  });
}

// ── Vulnerable Ports Map ────────────────────────────────────
const VULN_PORTS = { 21: 'HIGH', 22: 'LOW', 23: 'CRITICAL', 25: 'MEDIUM', 53: 'LOW', 69: 'HIGH', 80: 'MEDIUM', 110: 'HIGH', 135: 'HIGH', 137: 'HIGH', 138: 'HIGH', 139: 'HIGH', 161: 'HIGH', 389: 'MEDIUM', 445: 'CRITICAL', 1433: 'HIGH', 1521: 'HIGH', 1723: 'MEDIUM', 3306: 'HIGH', 3389: 'HIGH', 4444: 'CRITICAL', 5432: 'HIGH', 5900: 'HIGH', 6379: 'CRITICAL', 8080: 'LOW', 9200: 'CRITICAL', 27017: 'CRITICAL' };

// ── ULTIMATE INTENT ROUTER (50+ Rules) ─────────────────────
function localDynamicAgent(prompt) {
  const l = prompt.toLowerCase();
  let tool = 'get_summary', params = {}, filter = '', fields = DEFAULT_FIELDS;

  const portM = l.match(/port\s*(\d{1,5})/);
  const ipM = l.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
  const macM = l.match(/([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})/i);

  // --- CORE STATS ---
  if (l.includes('hierarchy') || l.includes('protocol distribution')) { tool = 'get_hierarchy'; }
  else if (l.includes('expert') || l.includes('warnings') || l.includes('errors')) { tool = 'get_expert_info'; }
  else if (l.includes('endpoint') || l.includes('top talker') || l.includes('bandwidth')) { tool = 'get_endpoints'; }
  
  // --- TCP ANALYSIS ---
  else if (l.includes('retransmission') || l.includes('retransmit')) { tool = 'get_tcp_anomalies'; filter = 'tcp.analysis.retransmission'; fields = [...DEFAULT_FIELDS, 'tcp.analysis.retransmission']; }
  else if (l.includes('out of order')) { tool = 'get_tcp_anomalies'; filter = 'tcp.analysis.out_of_order'; }
  else if (l.includes('zero window') || l.includes('flow control')) { tool = 'get_tcp_anomalies'; filter = 'tcp.analysis.zero_window'; }
  else if (l.includes('duplicate ack')) { tool = 'get_tcp_anomalies'; filter = 'tcp.analysis.duplicate_ack'; }
  else if (l.includes('rst') || l.includes('reset')) { tool = 'get_tcp_anomalies'; filter = 'tcp.flags.reset == 1'; }
  else if (l.includes('syn flood') || l.includes('port scan') || l.includes('scanning')) { tool = 'get_tcp_anomalies'; filter = 'tcp.flags.syn == 1 && tcp.flags.ack == 0'; }
  else if (l.includes('fin')) { tool = 'get_tcp_anomalies'; filter = 'tcp.flags.fin == 1'; }
  
  // --- HTTP ---
  else if (l.includes('http method') || l.includes('get post put')) { tool = 'get_http_methods'; filter = 'http.request'; fields = [...DEFAULT_FIELDS, 'http.request.method', 'http.request.uri', 'http.host']; }
  else if (l.includes('http status') || l.includes('status code') || l.includes('404') || l.includes('500')) { tool = 'get_http_status'; filter = 'http.response.code'; fields = [...DEFAULT_FIELDS, 'http.response.code', 'http.response.phrase']; }
  else if (l.includes('user agent') || l.includes('browser')) { tool = 'get_http_details'; filter = 'http.user_agent'; fields = [...DEFAULT_FIELDS, 'http.user_agent']; }
  else if (l.includes('http header') || l.includes('content type')) { tool = 'get_http_details'; filter = 'http.request || http.response'; fields = [...DEFAULT_FIELDS, 'http.content_type']; }
  
  // --- TLS / HTTPS ---
  else if (l.includes('tls') || l.includes('ssl') || l.includes('sni')) { tool = 'get_tls_sni'; filter = 'tls.handshake.type == 1'; fields = [...DEFAULT_FIELDS, 'tls.handshake.extensions_server_name']; }
  else if (l.includes('ja3') || l.includes('fingerprint')) { tool = 'get_tls_sni'; filter = 'tls.handshake.type == 1'; fields = [...DEFAULT_FIELDS, 'tcp.handshake.ja3']; }
  else if (l.includes('certificate') || l.includes('cert')) { tool = 'get_tls_certs'; filter = 'tls.handshake.type == 11'; fields = ['frame.number', 'ip.src', 'ip.dst', 'x509ce.dNSName']; }
  
  // --- DNS ---
  else if (l.includes('dns') || l.includes('domain')) { tool = 'get_dns'; filter = 'dns'; fields = [...DEFAULT_FIELDS, 'dns.qry.name', 'dns.qry.type']; }
  else if (l.includes('dga') || l.includes('suspicious domain')) { tool = 'get_dns'; filter = 'dns.qry.name.len > 25'; fields = [...DEFAULT_FIELDS, 'dns.qry.name']; }
  
  // --- AUTH & PLAINTEXT ---
  else if (l.includes('credential') || l.includes('password') || l.includes('login')) { tool = 'get_creds'; filter = 'ftp.request.command == USER || ftp.request.command == PASS || http.authorization || smb2.auth'; }
  else if (l.includes('telnet')) { tool = 'get_creds'; filter = 'telnet'; }
  
  // --- NETWORK / LAYER 2 ---
  else if (l.includes('arp') || l.includes('spoof')) { tool = 'get_arp'; filter = 'arp'; fields = ['frame.number', 'arp.opcode', 'arp.src.hw_mac', 'arp.src.proto_ipv4', 'arp.dst.proto_ipv4']; }
  else if (l.includes('dhcp')) { tool = 'get_dhcp'; filter = 'dhcp'; fields = [...DEFAULT_FIELDS, 'dhcp.option.hostname', 'dhcp.option.requested_ip_address']; }
  else if (l.includes('icmp') || l.includes('ping')) { tool = 'get_icmp'; filter = 'icmp'; fields = [...DEFAULT_FIELDS, 'icmp.type']; }
  else if (l.includes('broadcast') || l.includes('multicast')) { tool = 'get_arp'; filter = 'eth.dst == ff:ff:ff:ff:ff:ff || eth.dst[0:1] == "01:00:5e"'; }
  else if (macM) { tool = 'get_arp'; filter = `eth.src == ${macM[0]} || eth.dst == ${macM[0]}`; fields = ['frame.number', 'eth.src', 'eth.dst', 'ip.src', 'ip.dst', '_ws.col.Protocol']; }
  
  // --- PROTOCOLS ---
  else if (l.includes('smb') || l.includes('cifs')) { tool = 'get_generic_proto'; filter = 'smb || smb2'; fields = [...DEFAULT_FIELDS, 'smb2.cmd']; }
  else if (l.includes('rdp')) { tool = 'get_generic_proto'; filter = 'tcp.dstport == 3389 || rdp'; }
  else if (l.includes('ssh')) { tool = 'get_generic_proto'; filter = 'tcp.dstport == 22 || ssh'; }
  else if (l.includes('ftp')) { tool = 'get_generic_proto'; filter = 'ftp'; fields = [...DEFAULT_FIELDS, 'ftp.request.command', 'ftp.request.arg']; }
  else if (l.includes('smtp') || l.includes('email') || l.includes('mail')) { tool = 'get_generic_proto'; filter = 'smtp'; fields = [...DEFAULT_FIELDS, 'smtp.req.from', 'smtp.rcpt.to']; }
  else if (l.includes('quic') || l.includes('http/3') || l.includes('http 3')) { tool = 'get_generic_proto'; filter = 'quic'; }
  
  // --- VULNERABILITIES ---
  else if (l.includes('vulnerab') || l.includes('risk')) { tool = 'get_vuln_report'; }
  
  // --- TIMELINE ---
  else if (l.includes('timeline') || l.includes('over time')) { tool = 'get_timeline'; }
  
  // --- EXPLICIT FILTERS ---
  else if (portM) { tool = 'get_generic_proto'; filter = `tcp.port == ${portM[1]} || udp.port == ${portM[1]}`; }
  else if (ipM) { tool = 'get_generic_proto'; filter = `ip.addr == ${ipM[1]}`; }
  else if (l.includes('filter:') || l.includes('display:')) { tool = 'get_generic_proto'; filter = prompt.split(/(?:filter|:)/i)[1]?.trim() || ''; }
  
  // --- FALLBACK ---
  else if (l.includes('summary') || l.includes('overview')) { tool = 'get_summary'; }
  else { return { tool_called: 'none', parameters: {}, result: null, response: "I'm a TShark engine. Ask me about protocols, ports, DNS, ARP, TCP anomalies, HTTP methods, or use raw filters like 'filter: tcp.port == 80'.", followup: "Try: 'Show me protocol hierarchy'" }; }

  return { toolName: tool, tsharkFilter: filter, tsharkFields: fields };
}

// ── Tool Executor ────────────────────────────────────────────
async function executeTool(toolName, filter, fields, sessionId) {
  switch (toolName) {
    case 'get_summary': return { result: { raw_text: await runTSharkStat(sessionId, 'io,stat,0') }, response: 'Capture summary generated by Wireshark engine.' };
    case 'get_hierarchy': return { result: { raw_text: await runTSharkStat(sessionId, 'io,phs') }, response: 'Protocol hierarchy generated.' };
    case 'get_expert_info': return { result: { raw_text: await runTSharkStat(sessionId, 'expert') }, response: 'Expert info (Errors/Warnings) generated.' };
    case 'get_endpoints': return { result: { raw_text: await runTSharkStat(sessionId, 'conv,ip') }, response: 'IP Endpoints generated.' };
    case 'get_timeline': return { result: { raw_text: await runTSharkStat(sessionId, 'io,stat,1') }, response: 'Timeline statistics generated.' };
    case 'get_vuln_report': {
      const portFields = ['tcp.dstport', 'udp.dstport'];
      const packets = await runTshark(sessionId, "", portFields, 5000);
      const portCounts = {}; packets.forEach(p => { const port = p.tcp_dstport || p.udp_dstport; if (port) portCounts[port] = (portCounts[port] || 0) + 1; });
      const result = Object.entries(portCounts).filter(([port]) => VULN_PORTS[port]).map(([port, count]) => ({ port: parseInt(port), count, risk: VULN_PORTS[port] }));
      return { result, response: `Found traffic on ${result.length} vulnerable ports.` };
    }
    case 'get_tls_certs': return { result: await runTshark(sessionId, filter, fields, 50), response: 'TLS Certificate details extracted.' };
    // ALL OTHER PROTOCOL/ANALYSIS QUERIES FALL HERE
    default: {
      const packets = await runTShark(sessionId, filter, fields, 100);
      return { result: packets, response: `Found ${packets.length} packets.` };
    }
  }
}

// ── Main Server ──────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const url = req.url || '/'; const method = req.method || 'GET';
  const origin = req.headers['origin'] || ''; const enc = req.headers['accept-encoding'] || '';
  const respond = (data, status) => json(res, data, status, origin, enc);

  if (method === 'OPTIONS') { res.writeHead(204, getCorsHeaders(origin)); return res.end(); }
  if (url === '/ping' || url === '/pcap/ping') { res.writeHead(200, { 'Content-Type': 'text/plain' }); return res.end('pong'); }
  if (url === '/pcap/health') return respond({ status: 'ok', engine: 'TShark (Wireshark CLI)' });

  if (url === '/pcap/upload' && method === 'POST') {
    try {
      const ct = req.headers['content-type'] || ''; const bm = ct.match(/boundary=(?:"([^"]+)"|([^;,\s]+))/); const boundary = bm?.[1] ?? bm?.[2];
      if (!boundary) return respond({ error: 'Missing boundary' }, 400);
      const body = await parseBody(req); const parts = parseMultipart(body, boundary);
      let fileData = null, filename = 'upload.pcap';
      for (const p of parts) { const m = p.headers.match(/filename\*?=(?:UTF-8''|")?([^";\r\n]+)/i); if (m) { filename = decodeURIComponent(m[1].replace(/"/g, '').trim()); fileData = p.data; } }
      if (!fileData) return respond({ error: 'No file' }, 400);

      const session_id = `session-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
      const pcapPath = path.join(PCAP_DIR, `${session_id}.pcap`);
      fs.writeFileSync(pcapPath, fileData);

      const exportDir = path.join(EXPORT_DIR, session_id);
      if (!fs.existsSync(exportDir)) fs.mkdirSync(exportDir, { recursive: true });
      
      // Extract HTTP objects in background (non-blocking)
      exec(`tshark -r "${pcapPath}" --export-objects http,"${exportDir}"`, { timeout: 15000 }, (err) => {
        if (err) return;
        if (fs.existsSync(exportDir)) {
          const artifacts = new Map();
          fs.readdirSync(exportDir).forEach(file => {
            const fp = path.join(exportDir, file); const ext = path.extname(file).toLowerCase();
            artifacts.set(encodeURIComponent(file), { buffer: fs.readFileSync(fp), contentType: ext === '.jpg' ? 'image/jpeg' : ext === '.png' ? 'image/png' : 'application/octet-stream', filename: file });
          });
          imageStore.set(session_id, artifacts);
        }
      });

      sessions.set(session_id, { session_id, filename, created_at: Date.now() });
      const summaryText = await runTSharkStat(session_id, 'io,stat,0');
      const totalMatch = summaryText.match(/(\d+)\s+packets/);
      return respond({ session_id, summary: { total_packets: totalMatch ? parseInt(totalMatch[1]) : 0, raw_text: summaryText } });
    } catch (e) { return respond({ error: e.message }, 500); }
  }

  if (url === '/pcap/agent/query' && method === 'POST') {
    try {
      const body = await parseBody(req); const parsed = JSON.parse(body.toString());
      const { prompt, session_id } = parsed || {};
      if (!isValidSessionId(session_id)) return respond({ error: 'Invalid session_id' }, 400);
      if (!fs.existsSync(path.join(PCAP_DIR, `${session_id}.pcap`))) return respond({ error: 'PCAP expired' }, 404);

      const { toolName, tsharkFilter, tsharkFields } = localDynamicAgent(prompt);
      const toolResult = await executeTool(toolName, tsharkFilter, tsharkFields, session_id);

      let finalResponse = toolResult.response;
      let followup = "Check for vulnerabilities.";

      if (toolName === 'get_hierarchy') followup = "Show me TCP retransmissions.";
      else if (toolName === 'get_expert_info') followup = "Extract HTTP objects.";
      else if (toolName === 'get_creds' && toolResult.result?.length > 0) finalResponse = `🚨 WARNING: Found ${toolResult.result.length} plaintext credentials!`;
      else if (toolName === 'get_tcp_anomalies' && toolResult.result?.length > 0) finalResponse = `Found ${toolResult.result.length} TCP anomalies.`;

      return respond({ tool_called: toolName, parameters: {}, result: toolResult.result, response: finalResponse, followup });
    } catch (e) { return respond({ error: e.message }, 500); }
  }

  if (url.startsWith('/pcap/packets') && method === 'GET') {
    const q = getQuery(url); if (!isValidSessionId(q.session_id)) return respond({ error: 'Invalid' }, 400);
    const page = parseInt(q.page || '1'); const per_page = parseInt(q.per_page || '50'); const skip = (page - 1) * per_page;
    const filter = `frame.number > ${skip} && frame.number <= ${skip + per_page}`;
    return respond({ packets: await runTShark(q.session_id, filter, DEFAULT_FIELDS, per_page), total: 99999, page, per_page });
  }

  if (url.startsWith('/pcap/images') && method === 'GET') {
    const q = getQuery(url); if (!isValidSessionId(q.session_id)) return respond({ error: 'Invalid' }, 400);
    const artifacts = imageStore.get(q.session_id);
    if (!artifacts) return respond({ error: 'No objects' }, 404);
    return respond({ images: Array.from(artifacts.entries()).map(([k, v]) => ({ filename: v.filename, content_type: v.contentType, artifact_key: k })), total: artifacts.size });
  }

  if (url.startsWith('/pcap/image-data') && method === 'GET') {
    const q = getQuery(url); if (!isValidSessionId(q.session_id)) return respond({ error: 'Invalid' }, 400);
    const art = imageStore.get(q.session_id)?.get(q.key || ''); if (!art) return respond({ error: 'Not found' }, 404);
    res.writeHead(200, { 'Content-Type': art.contentType, 'Content-Length': art.buffer.length, 'Content-Disposition': `inline; filename="${art.filename}"`, ...getCorsHeaders(origin) });
    return res.end(art.buffer);
  }

  respond({ error: 'Not found' }, 404);
});

const PORT = process.env.PORT || 4000;
server.listen(PORT, () => console.log(`🔥 Ultimate TShark Engine running on ${PORT}`));

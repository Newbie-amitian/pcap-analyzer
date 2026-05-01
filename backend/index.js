const http = require('http');
const https = require('https');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');

// ── Directory Setup for TShark ────────────────────────────────
const PCAP_DIR = '/tmp/pcaps';
const EXPORT_DIR = '/tmp/exports';
if (!fs.existsSync(PCAP_DIR)) fs.mkdirSync(PCAP_DIR, { recursive: true });
if (!fs.existsSync(EXPORT_DIR)) fs.mkdirSync(EXPORT_DIR, { recursive: true });

// ── In-memory stores ──────────────────────────────────────────
const sessions = new Map();
const imageStore = new Map();

const SESSION_TTL_MS = 30 * 60 * 1000;
setInterval(() => {
  const now = Date.now();
  for (const [id, session] of sessions) {
    if (now - session.created_at > SESSION_TTL_MS) {
      // CRITICAL: Delete physical files to save Render disk space!
      const pcapPath = path.join(PCAP_DIR, `${id}.pcap`);
      const exportPath = path.join(EXPORT_DIR, id);
      if (fs.existsSync(pcapPath)) fs.unlinkSync(pcapPath);
      if (fs.existsSync(exportPath)) fs.rmSync(exportPath, { recursive: true });
      
      sessions.delete(id);
      imageStore.delete(id);
      console.log(`[Session] Expired, evicted, and cleaned disk: ${id}`);
    }
  }
}, 5 * 60 * 1000);

// ── CORS ──────────────────────────────────────────────────────
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';
function getCorsHeaders(requestOrigin) {
  let origin = ALLOWED_ORIGIN === '*' ? '*' : (requestOrigin === ALLOWED_ORIGIN ? requestOrigin : ALLOWED_ORIGIN);
  return { 'Access-Control-Allow-Origin': origin, 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type', 'Vary': 'Origin' };
}

// ── TShark Engine (The Brain) ────────────────────────────────
// Uses -T fields (Tab-Separated Values) because it is 100x faster 
// and uses 0 RAM compared to TShark's JSON output.
const DEFAULT_FIELDS = [
  'frame.number', 'ip.src', 'ip.dst', 'frame.len', 
  '_ws.col.Protocol', 'tcp.srcport', 'tcp.dstport', 'frame.time_relative'
];

function runTshark(sessionId, displayFilter = '', fields = DEFAULT_FIELDS, limit = 0) {
  return new Promise((resolve) => {
    const pcapPath = path.join(PCAP_DIR, `${sessionId}.pcap`);
    if (!fs.existsSync(pcapPath)) return resolve([]);

    let command = `tshark -r "${pcapPath}" -T fields -E separator='\\t' -e ${fields.join(' -e ')}`;
    if (displayFilter) command += ` -Y "${displayFilter}"`;
    if (limit > 0) command += ` | head -n ${limit}`;

    exec(command, { timeout: 10000 }, (error, stdout) => {
      if (error) {
        console.error(`[TShark] Error: ${error.message}`);
        return resolve([]);
      }

      const lines = stdout.trim().split('\n').filter(l => l.trim() !== '');
      const packets = lines.map(line => {
        const cols = line.split('\t');
        return {
          id: parseInt(cols[0]) || 0,
          src_ip: cols[1] || null,
          dst_ip: cols[2] || null,
          length: parseInt(cols[3]) || 0,
          protocol: cols[4] || 'UNKNOWN',
          src_port: parseInt(cols[5]) || null,
          dst_port: parseInt(cols[6]) || null,
          timestamp: parseFloat(cols[7]) || 0,
        };
      });

      resolve(packets);
    });
  });
}

// ── Shodan / CVE helpers ─────────────────────────────────────
async function fetchShodanIp(ip) {
  return new Promise((resolve) => {
    let settled = false; const cleanup = () => { if (!settled) settled = true; };
    const req = https.get(`https://internetdb.shodan.io/${ip}`, (res) => {
      let data = ''; res.on('data', d => data += d);
      res.on('end', () => { if (settled) return; cleanup(); try { resolve(JSON.parse(data)); } catch (_) { resolve(null); } });
    });
    req.on('error', () => { if (settled) return; cleanup(); resolve(null); });
    setTimeout(() => { if (settled) return; cleanup(); req.destroy(); resolve(null); }, 4000);
  });
}

// ── Vulnerable Ports Map ─────────────────────────────────────
const VULNERABLE_PORTS = {
  21: { risk: 'HIGH', reason: 'FTP transmits credentials in plaintext' },
  23: { risk: 'CRITICAL', reason: 'Telnet transmits everything in plaintext' },
  80: { risk: 'MEDIUM', reason: 'HTTP transmits data in plaintext' },
  135: { risk: 'HIGH', reason: 'RPC endpoint mapper' },
  445: { risk: 'CRITICAL', reason: 'SMB — EternalBlue / ransomware vector' },
  3389: { risk: 'HIGH', reason: 'RDP — BlueKeep / brute force vector' },
  4444: { risk: 'CRITICAL', reason: 'Metasploit default port' },
  6379: { risk: 'CRITICAL', reason: 'Redis with no auth' },
  9200: { risk: 'CRITICAL', reason: 'Elasticsearch with no auth' },
  27017: { risk: 'CRITICAL', reason: 'MongoDB with no auth' },
};

// ── Local Intent Router (No AI) ──────────────────────────────
function localDynamicAgent(userPrompt, sessionId) {
  const lower = userPrompt.toLowerCase();
  let toolName = 'get_summary';
  let toolParams = {};
  let tsharkFilter = '';

  const portMatch = lower.match(/port\s*(\d{1,5})/);
  const ipMatch = lower.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);

  // 1. Detect Intent
  if (lower.includes('credential') || lower.includes('password') || lower.includes('login')) {
    toolName = 'find_credentials';
    tsharkFilter = "ftp.request.command == USER || ftp.request.command == PASS || http.authorization";
  } else if (lower.includes('port scan') || lower.includes('scanning') || lower.includes('nmap')) {
    toolName = 'detect_port_scan';
    tsharkFilter = "tcp.flags.syn==1 && tcp.flags.ack==0";
  } else if (lower.includes('dns') || lower.includes('domain')) {
    toolName = 'get_dns_queries';
    tsharkFilter = "dns";
  } else if (lower.includes('https') || lower.includes('tls') || lower.includes('sni')) {
    toolName = 'get_tls_sni';
  } else if (lower.includes('vulnerab') || lower.includes('risk')) {
    toolName = 'get_vulnerability_report';
  } else if (lower.includes('top talker') || lower.includes('bandwidth') || lower.includes('most traffic')) {
    toolName = 'get_top_talkers';
  } else if (portMatch) {
    toolName = 'filter_by_port';
    tsharkFilter = `tcp.port == ${portMatch[1]} || udp.port == ${portMatch[1]}`;
    toolParams = { port: parseInt(portMatch[1]) };
  } else if (ipMatch) {
    toolName = 'filter_by_ip';
    tsharkFilter = `ip.addr == ${ipMatch[1]}`;
    toolParams = { ip: ipMatch[1] };
  } else if (lower.includes('filter:') || lower.includes('display filter')) {
    // POWER MODE: User typed a raw Wireshark filter!
    toolName = 'custom_filter';
    tsharkFilter = userPrompt.split(/(?:filter|:)/i)[1]?.trim() || '';
  } else if (lower.includes('summary') || lower.includes('overview')) {
    toolName = 'get_summary';
  } else {
    return { tool_called: 'none', parameters: {}, result: null, response: "I'm a local TShark engine. Ask me to summarize traffic, find DNS queries, or filter by port/IP.", followup: "Try: 'Summarize this capture'" };
  }

  return { toolName, toolParams, tsharkFilter };
}

// ── Tool Executor via TShark ──────────────────────────────────
async function executeTool(toolName, toolParams, tsharkFilter, sessionId) {
  switch (toolName) {
    case 'get_summary': {
      return new Promise((resolve) => {
        const pcapPath = path.join(PCAP_DIR, `${sessionId}.pcap`);
        exec(`tshark -r "${pcapPath}" -q -z io,stat,0`, { timeout: 10000 }, (err, stdout) => {
          const text = stdout || "Could not read summary.";
          resolve({ result: { raw_text: text }, response: "Capture summary generated." });
        });
      });
    }

    case 'get_top_talkers': {
      return new Promise((resolve) => {
        const pcapPath = path.join(PCAP_DIR, `${sessionId}.pcap`);
        exec(`tshark -r "${pcapPath}" -q -z conv,ip,tcp | head -n 15`, { timeout: 10000 }, (err, stdout) => {
          const lines = stdout.split('\n').filter(l => l.includes('|')).slice(1);
          const result = lines.map(line => {
            const p = line.split('|').map(s => s.trim());
            if(p.length < 5) return null;
            return { ip_a: p[0], ip_b: p[1], packets: parseInt(p[2]) || 0, bytes: p[3] };
          }).filter(Boolean);
          resolve({ result, response: `Top ${result.length} talkers.` });
        });
      });
    }

    case 'get_dns_queries': {
      const dnsFields = ['frame.number', 'dns.qry.name', 'ip.src', 'ip.dst', '_ws.col.Protocol', 'frame.len'];
      const packets = await runTshark(sessionId, tsharkFilter, dnsFields, 100);
      const domains = {};
      packets.forEach(p => {
        if (p.dns_qry_name) {
          const d = p.dns_qry_name.toLowerCase();
          domains[d] = (domains[d] || 0) + 1;
        }
      });
      return { result: { packets, top_domains: Object.entries(domains).sort((a,b)=>b[1]-a[1]).slice(0, 15) }, response: `Found ${packets.length} DNS packets.` };
    }

    case 'get_tls_sni': {
      const sniFields = ['frame.number', 'tls.handshake.extensions_server_name', 'ip.dst', '_ws.col.Protocol'];
      const packets = await runTshark(sessionId, "tls.handshake.type == 1", sniFields, 100);
      // Map TShark fields to frontend expected fields
      const formatted = packets.map(p => ({
        ...p, 
        dst_ip: p.tls_handshake_extensions_server_name || p.ip_dst,
        payload_preview: p.tls_handshake_extensions_server_name
      }));
      return { result: formatted, response: `Found ${formatted.length} HTTPS SNI packets.` };
    }

    case 'custom_filter':
    case 'filter_by_port':
    case 'filter_by_ip':
    case 'find_credentials':
    case 'detect_port_scan': {
      const packets = await runTshark(sessionId, tsharkFilter, DEFAULT_FIELDS, 100);
      return { result: packets, response: `Found ${packets.length} packets matching filter.` };
    }

    case 'get_vulnerability_report': {
      // Get all unique ports
      const portFields = ['tcp.dstport', 'udp.dstport'];
      const packets = await runTshark(sessionId, "", portFields, 5000);
      const portCounts = {};
      packets.forEach(p => {
        const port = p.tcp_dstport || p.udp_dstport;
        if (port) portCounts[port] = (portCounts[port] || 0) + 1;
      });
      
      const result = Object.entries(portCounts)
        .filter(([port]) => VULNERABLE_PORTS[port])
        .map(([port, count]) => ({
          port: parseInt(port),
          count,
          risk: VULNERABLE_PORTS[port].risk,
          reason: VULNERABLE_PORTS[port].reason
        }));
        
      return { result, response: `Found traffic on ${result.length} vulnerable ports.` };
    }

    default:
      return { result: null, response: "Tool not implemented." };
  }
}

// ── HTTP Helpers ─────────────────────────────────────────────
function parseBody(req) { return new Promise((resolve, reject) => { const chunks = []; req.on('data', chunk => chunks.push(chunk)); req.on('end', () => resolve(Buffer.concat(chunks))); req.on('error', reject); }); }
function parseMultipart(buffer, boundary) {
  const cleanBoundary = boundary.replace(/^["']|["']$/g, '').trim();
  const boundaryBuf = Buffer.from('\r\n--' + cleanBoundary); const firstBound = Buffer.from('--' + cleanBoundary); const CRLF4 = Buffer.from('\r\n\r\n'); const parts = [];
  let pos = buffer.indexOf(firstBound); if (pos === -1) return parts; pos += firstBound.length; let safety = 0;
  while (pos < buffer.length && safety++ < 1000) {
    const lineEnd = buffer.indexOf(Buffer.from('\r\n'), pos); if (lineEnd === -1) break;
    const boundaryLine = buffer.slice(pos, lineEnd).toString(); if (boundaryLine.startsWith('--')) break;
    const headerStart = lineEnd + 2; const headerEnd = buffer.indexOf(CRLF4, headerStart); if (headerEnd === -1) break;
    const headers = buffer.slice(headerStart, headerEnd).toString(); const dataStart = headerEnd + 4;
    const nextBound = buffer.indexOf(boundaryBuf, dataStart); const dataEnd = nextBound === -1 ? buffer.length : nextBound;
    parts.push({ headers, data: buffer.slice(dataStart, dataEnd) }); if (nextBound === -1) break; pos = nextBound + boundaryBuf.length;
  }
  return parts;
}
function json(res, data, status = 200, requestOrigin = '', acceptEncoding = '') {
  const payload = JSON.stringify(data); const corsHeaders = getCorsHeaders(requestOrigin);
  const wantsGzip = /\bgzip\b/.test(acceptEncoding);
  if (wantsGzip && payload.length > 1024) {
    zlib.gzip(Buffer.from(payload, 'utf8'), (err, compressed) => { if (err) { res.writeHead(status, { 'Content-Type': 'application/json', ...corsHeaders }); res.end(payload); return; } res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Encoding': 'gzip', 'Vary': 'Accept-Encoding', ...corsHeaders }); res.end(compressed); });
  } else { res.writeHead(status, { 'Content-Type': 'application/json', ...corsHeaders }); res.end(payload); }
}
function getQuery(url) {
  const q = {}; const idx = url.indexOf('?'); if (idx === -1) return q;
  for (const part of url.slice(idx + 1).split('&')) { const [k, v] = part.split('='); if (k) q[decodeURIComponent(k)] = decodeURIComponent(v || ''); }
  return q;
}

// ── Session ID validation ─────────────────────────────────────
const SESSION_ID_RE = /^session-\d{13}-[a-z0-9]{6}$/;
function isValidSessionId(id) { return typeof id === 'string' && SESSION_ID_RE.test(id); }

// ── Rate limiter ──────────────────────────────────────────────
const rateLimits = new Map();
function checkRateLimit(ip, limit) {
  const now = Date.now(); const key = `${ip}:${limit.max}`; const entry = rateLimits.get(key) || { count: 0, windowStart: now };
  if (now - entry.windowStart > limit.windowMs) { entry.count = 0; entry.windowStart = now; }
  entry.count++; rateLimits.set(key, entry); return entry.count <= limit.max;
}

// ── Main HTTP Server ───────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const url = req.url || '/'; const method = req.method || 'GET';
  const requestOrigin = req.headers['origin'] || ''; const acceptEncoding = req.headers['accept-encoding'] || '';
  const respond = (data, status = 200) => json(res, data, status, requestOrigin, acceptEncoding);

  if (method === 'OPTIONS') { res.writeHead(204, getCorsHeaders(requestOrigin)); return res.end(); }

  if (url === '/ping' || url === '/pcap/ping') { res.writeHead(200, { 'Content-Type': 'text/plain' }); return res.end('pong'); }

  if (url === '/pcap/health' || url === '/health') {
    return respond({ status: 'ok', service: 'pcap-tshark-analyzer', sessions: sessions.size, engine: 'TShark (Wireshark CLI)' }, 200);
  }

  // ── Upload (Saves to Disk + Extracts HTTP Objects) ────────
  if (url === '/pcap/upload' && method === 'POST') {
    try {
      const contentType = req.headers['content-type'] || '';
      const boundaryMatch = contentType.match(/boundary=(?:"([^"]+)"|([^;,\s]+))/);
      const boundary = boundaryMatch?.[1] ?? boundaryMatch?.[2];
      if (!boundary) return respond({ error: 'Missing multipart boundary' }, 400);

      const body = await parseBody(req); const parts = parseMultipart(body, boundary);
      let fileData = null; let filename = 'upload.pcap';
      for (const part of parts) { const fnMatch = part.headers.match(/filename\*?=(?:UTF-8''|")?([^";\r\n]+)/i); if (fnMatch) { filename = decodeURIComponent(fnMatch[1].replace(/"/g, '').trim()); fileData = part.data; } }
      if (!fileData) return respond({ error: 'No file found' }, 400);

      const session_id = `session-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
      const pcapPath = path.join(PCAP_DIR, `${session_id}.pcap`);
      
      // 1. Save file to disk
      fs.writeFileSync(pcapPath, fileData);
      console.log(`[Upload] Saved ${filename} to disk for ${session_id}`);

      // 2. Extract HTTP Objects using REAL Wireshark logic!
      const exportDir = path.join(EXPORT_DIR, session_id);
      if (!fs.existsSync(exportDir)) fs.mkdirSync(exportDir, { recursive: true });
      
      // This command is identical to Wireshark GUI -> File -> Export Objects -> HTTP
      exec(`tshark -r "${pcapPath}" --export-objects http,"${exportDir}"`, { timeout: 15000 }, (err) => {
        if (err) console.warn(`[Export] HTTP Export warning/failed: ${err.message}`);
        
        // Read exported files and store in imageStore
        if (fs.existsSync(exportDir)) {
          const files = fs.readdirSync(exportDir);
          const artifacts = new Map();
          
          files.forEach(file => {
            const filePath = path.join(exportDir, file);
            const buffer = fs.readFileSync(filePath);
            const ext = path.extname(file).toLowerCase();
            const contentType = ext === '.jpg' || ext === '.jpeg' ? 'image/jpeg' : ext === '.png' ? 'image/png' : 'application/octet-stream';
            
            const artifactKey = encodeURIComponent(file);
            artifacts.set(artifactKey, { buffer, contentType, filename: file });
          });

          imageStore.set(session_id, artifacts);
        }
      });

      // 3. Get basic summary for immediate frontend response
      exec(`tshark -r "${pcapPath}" -q -z io,stat,0`, { timeout: 10000 }, (err, stdout) => {
        const summaryText = stdout || "Parsed";
        const totalPacketsMatch = summaryText.match(/(\d+)\s+packets/);
        const totalPackets = totalPacketsMatch ? parseInt(totalPacketsMatch[1]) : 0;

        sessions.set(session_id, { session_id, filename, created_at: Date.now() });
        return respond({ session_id, summary: { total_packets: totalPackets, raw_text: summaryText } }, 200);
      });

    } catch (e) { console.error('[Upload Error]', e); return respond({ error: 'Upload failed: ' + e.message }, 500); }
  }

  // ── Agent (Local Router + TShark Execution) ──────────────
  if (url === '/pcap/agent/query' && method === 'POST') {
    try {
      const body = await parseBody(req); let parsed;
      try { parsed = JSON.parse(body.toString()); } catch { return respond({ error: 'Invalid JSON' }, 400); }
      const { prompt, session_id } = parsed || {};
      if (!isValidSessionId(session_id)) return respond({ error: 'Invalid session_id' }, 400);
      
      const pcapPath = path.join(PCAP_DIR, `${session_id}.pcap`);
      if (!fs.existsSync(pcapPath)) return respond({ error: 'Session PCAP expired or missing' }, 404);

      console.log(`[Agent] Query: "${prompt.substring(0, 50)}..."`);
      
      // 1. Route intent
      const { toolName, toolParams, tsharkFilter } = localDynamicAgent(prompt, session_id);
      
      // 2. Execute via TShark
      const toolResult = await executeTool(toolName, toolParams, tsharkFilter, session_id);

      // 3. Format final response
      let finalResponse = toolResult.response;
      let followup = "Want to check for vulnerabilities?";

      if (toolName === 'get_summary') {
        finalResponse = "Here is the capture summary generated by the Wireshark engine.";
        followup = "Show me the DNS queries.";
      } else if (toolName === 'find_credentials' && toolResult.result?.length > 0) {
        finalResponse = `Warning: Found ${toolResult.result.length} plaintext credentials in this traffic!`;
        followup = "Check for port scanning.";
      } else if (toolName === 'detect_port_scan' && toolResult.result?.length > 0) {
        finalResponse = `Detected SYN scan activity from ${toolResult.result.length} packets.`;
      } else if (toolName === 'custom_filter') {
        finalResponse = `Applied custom Wireshark filter. Found ${toolResult.result?.length || 0} packets.`;
      }

      return respond({
        tool_called: toolName,
        parameters: toolParams,
        result: toolResult.result,
        response: finalResponse,
        followup: followup,
      }, 200);

    } catch (e) { console.error('[Agent Error]', e); return respond({ error: 'Agent error: ' + e.message }, 500); }
  }

  // ── Packets (Fetches via TShark on demand) ────────────────
  if (url.startsWith('/pcap/packets') && method === 'GET') {
    const q = getQuery(url); if (!isValidSessionId(q.session_id)) return respond({ error: 'Invalid session_id' }, 400);
    const pcapPath = path.join(PCAP_DIR, `${q.session_id}.pcap`);
    if (!fs.existsSync(pcapPath)) return respond({ error: 'Session not found' }, 404);
    
    const page = parseInt(q.page || '1'); const per_page = parseInt(q.per_page || '50');
    const skip = (page - 1) * per_page;
    
    // TShark native pagination using -Y "frame.number > X && frame.number <= Y"
    const filter = `frame.number > ${skip} && frame.number <= ${skip + per_page}`;
    const packets = await runTshark(q.session_id, filter, DEFAULT_FIELDS, per_page);
    
    return respond({ packets, total: 99999, page, per_page }, 200); 
  }

  // ── HTTP Objects (Served from Disk) ───────────────────────
  if (url.startsWith('/pcap/images') && method === 'GET') {
    const q = getQuery(url); if (!isValidSessionId(q.session_id)) return respond({ error: 'Invalid session_id' }, 400);
    const artifacts = imageStore.get(q.session_id);
    if (!artifacts) return respond({ error: 'No objects found' }, 404);
    
    const images = Array.from(artifacts.entries()).map(([key, val]) => ({
      filename: val.filename, content_type: val.contentType, artifact_key: key, is_image: val.contentType.startsWith('image/')
    }));
    
    return respond({ images, total: images.length }, 200);
  }

  // ── Image-data route (Streams from Disk) ──────────────────
  if (url.startsWith('/pcap/image-data') && method === 'GET') {
    const q = getQuery(url); if (!isValidSessionId(q.session_id)) return respond({ error: 'Invalid session_id' }, 400);
    const artifactKey = q.key || ''; if (!artifactKey) return respond({ error: 'Missing key' }, 400);
    
    const sessionArtifacts = imageStore.get(q.session_id);
    if (!sessionArtifacts) return respond({ error: 'Not found' }, 404);
    
    const artifact = sessionArtifacts.get(artifactKey);
    if (!artifact) return respond({ error: 'Artifact not found' }, 404);

    res.writeHead(200, { 'Content-Type': artifact.contentType, 'Content-Length': artifact.buffer.length, 'Content-Disposition': `inline; filename="${artifact.filename}"`, ...getCorsHeaders(requestOrigin) });
    return res.end(artifact.buffer);
  }

  respond({ error: 'Not found' }, 404);
});

const PORT = process.env.PORT || 4000;
server.listen(PORT, () => {
  console.log(`✅ PCAP TShark Engine running on port ${PORT}`);
  console.log(`🔥 Powered by 100% Official Wireshark Logic`);
});

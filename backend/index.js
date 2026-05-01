const http = require('http');
const https = require('https');
const { Buffer } = require('buffer');
const crypto = require('crypto');
const zlib = require('zlib');

// ── In-memory session store ────────────────────────────────────
const sessions = new Map();

// Separate artifact store: sessionId → Map<dedupKey, {buffer, contentType, filename}>
// Kept out of the session object so session memory only holds metadata.
const imageStore = new Map();

const SESSION_TTL_MS = 30 * 60 * 1000;
setInterval(() => {
  const now = Date.now();
  for (const [id, session] of sessions) {
    if (now - session.created_at > SESSION_TTL_MS) {
      sessions.delete(id);
      imageStore.delete(id);
      console.log(`[Session] Expired and evicted: ${id}`);
    }
  }
}, 5 * 60 * 1000);

// ── CORS ──────────────────────────────────────────────────────
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';

function getCorsHeaders(requestOrigin) {
  let origin;
  if (ALLOWED_ORIGIN === '*') {
    origin = '*';
  } else if (requestOrigin && requestOrigin === ALLOWED_ORIGIN) {
    origin = requestOrigin;
  } else {
    origin = ALLOWED_ORIGIN;
  }
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Vary': 'Origin',
  };
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
        try { resolve(JSON.parse(data).choices?.[0]?.message?.content?.trim() || null); }
        catch (_) { resolve(null); }
      });
    });
    req.on('error', () => resolve(null));
    setTimeout(() => resolve(null), 25000);
    req.write(body);
    req.end();
  });
}

// ── CVE/Shodan helpers ─────────────────────────────────────────
async function fetchShodanIp(ip) {
  return new Promise((resolve) => {
    https.get(`https://internetdb.shodan.io/${ip}`, (res) => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => { try { resolve(JSON.parse(data)); } catch (_) { resolve(null); } });
    }).on('error', () => resolve(null));
    setTimeout(() => resolve(null), 4000);
  });
}

async function fetchCveDetails(cveId) {
  return new Promise((resolve) => {
    https.get(`https://cve.circl.lu/api/cve/${cveId}`, (res) => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => { try { resolve(JSON.parse(data)); } catch (_) { resolve(null); } });
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

// FIX 7: Unified set of known HTTP ports — single source of truth used by
// both the PCAP parser (is_http_candidate flag) and extractHttpObjects().
const KNOWN_HTTP_PORTS = new Set([80, 8080, 8000, 8008, 8888, 3000, 3001, 5000, 4000, 9090]);

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

// ── DGA / suspicious domain scorer ────────────────────────────
function scoreDomainSuspicion(domain) {
  const parts = domain.split('.');
  const sld = parts[parts.length - 2] || '';
  const flags = [];

  if (sld.length <= 3) flags.push('very_short_sld');

  if (sld.length > 3) {
    const vowels = (sld.match(/[aeiou]/gi) || []).length;
    if (1 - vowels / sld.length > 0.75) flags.push('high_consonant_ratio');
  }

  if (parts.length > 4) flags.push('deep_subdomain');

  const digits = (sld.match(/\d/g) || []).length;
  if (digits / sld.length > 0.4) flags.push('high_digit_ratio');

  const uncommon = (sld.match(/[xzqjkv]/gi) || []).length;
  if (uncommon / sld.length > 0.4) flags.push('high_uncommon_chars');

  return flags;
}
// ── Tool executor ──────────────────────────────────────────────
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
      // Per-source-IP tracking: unique ports, SYN-only packets, timestamps
      const ipData = {};
      for (const pk of packets) {
        if (!pk.src_ip || !pk.dst_port) continue;
        if (!ipData[pk.src_ip]) ipData[pk.src_ip] = { ports: new Set(), synPorts: new Set(), timestamps: [] };
        const d = ipData[pk.src_ip];
        d.ports.add(pk.dst_port);
        // FIX 4: Use the reliable is_syn flag set by the parser;
        // is_syn_ack is used purely for informational context below.
        if (pk.is_syn && !pk.is_syn_ack) d.synPorts.add(pk.dst_port);
        d.timestamps.push(pk.timestamp);
      }

      const result = [];
      for (const [ip, d] of Object.entries(ipData)) {
        const totalPorts = d.ports.size;
        const synOnlyPorts = d.synPorts.size;

        const sortedTs = d.timestamps.slice().sort((a, b) => a - b);

        // FIX 1: clamp duration to at least 1 second so pps is stable;
        // skip pps-based detection entirely when the window is too short.
        const rawDuration = sortedTs.length > 1
          ? sortedTs[sortedTs.length - 1] - sortedTs[0]
          : 0;

        // convert ms → seconds safely
        const durationSec = Math.max(rawDuration / 1000, 1);

        const pps = d.timestamps.length / durationSec;

        // only trust PPS if window is meaningful (>= 2 sec)
        const ppsReliable = rawDuration >= 2000;


        // 5-second sliding window: count max packets seen in any 5s span
        let maxInWindow = 0;
        let wStart = 0;
        for (let i = 0; i < sortedTs.length; i++) {
          while (sortedTs[i] - sortedTs[wStart] > 5) wStart++;
          maxInWindow = Math.max(maxInWindow, i - wStart + 1);
        }

        const isSynScan = synOnlyPorts > 10;
        const isWideScan = totalPorts > 15;
        // FIX 1: guard pps check behind ppsReliable flag
        const isRateScan = ppsReliable && pps > 80 && totalPorts > 8;
        const isWindowScan = maxInWindow > 10;

        if (isSynScan || isWideScan || isRateScan || isWindowScan) {
          const scanTypes = [
            isSynScan ? 'SYN-scan' : null,
            isWideScan ? 'wide-scan' : null,
            isRateScan ? 'rate-scan' : null,
            isWindowScan ? 'burst-scan' : null,
          ].filter(Boolean);
          result.push({
            ip,
            ports_scanned: totalPorts,
            syn_only_ports: synOnlyPorts,
            max_ports_in_5s: maxInWindow,
            packets_per_sec: Math.round(pps),
            scan_types: scanTypes,
            ports: [...d.ports].slice(0, 20),
          });
        }
      }
      return { result, response: result.length ? `Detected ${result.length} potential port scanner(s).` : 'No port scanning detected.' };
    }

    case 'get_dns_queries': {
      const result = packets.filter(pk => pk.protocol === 'DNS');
      const domains = {};
      const DOMAIN_RE = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}\b/g;

      for (const pk of result) {
        if (!pk.payload_preview) continue;

        let matches = [];

        if (pk.dns_query) {
          matches.push(pk.dns_query);
        } else if (pk.payload_preview) {
          matches = pk.payload_preview.match(DOMAIN_RE) || [];
        } if (!matches) continue;

        for (const d of matches) {
          const parts = d.split('.');
          if (parts.length < 2 || parts.some(p => p.length === 0)) continue;
          if (/^\d+$/.test(parts[parts.length - 1])) continue; if (parts.every(p => /^\d+$/.test(p))) continue;
          if (parts[parts.length - 1].length < 2) continue;

          const key = d.toLowerCase();
          domains[key] = (domains[key] || 0) + 1;
        }
      }

      const enrichedPackets = result.slice(0, 50).map(pk => {
        const m = pk.payload_preview?.match(DOMAIN_RE);
        const queried_domain = m
          ? m.find(d => {
            const p = d.split('.');
            return p.length >= 2 && !p.every(x => /^\d+$/.test(x));
          }) ?? null
          : null;

        return {
          ...pk,
          queried_domain: queried_domain?.toLowerCase() ?? null,
        };
      });

      return {
        result: {
          packets: enrichedPackets,
          top_domains: Object.entries(domains)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 15),
        },
        response: `Found ${result.length} DNS packets.`,
      };
    }
    case 'get_tls_sni': {
      // SNI hostnames live in the TLS ClientHello plaintext even though the
      // session is encrypted. They appear in payload_preview because the parser
      // stores the first 512 bytes of every TCP payload as UTF-8.
      const DOMAIN_RE = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}\b/g;
      const sniMap = {};

      for (const pk of packets) {
        if (!pk.payload_preview) continue;
        // Only look at outbound port-443 TCP packets that carry a TLS handshake
        // byte (0x16 == 22 decimal shows as a non-printable char replaced by '.'
        // by the parser, so we check dst_port instead).
        if (pk.dst_port !== 443) continue;

        // Only trust actual TLS-marked packets if available
        if (pk.protocol !== 'TLS' && pk.protocol !== 'TCP') continue;

        const matches = pk.payload_preview?.match(DOMAIN_RE) || [];
        if (!matches) continue;
        for (const d of matches) {
          if (!d || typeof d !== 'string') continue;

          const parts = d.split('.');
          if (parts.length < 2) continue;
          if (!/^[a-zA-Z]/.test(parts[0])) continue;
          if (parts.some(p => p.length === 0)) continue; if (parts.every(p => /^\d+$/.test(p))) continue;
          if (parts[parts.length - 1].length < 2) continue;

          const key = d.toLowerCase().trim();
          if (!key) continue;

          sniMap[key] = (sniMap[key] || 0) + 1;
        }
      }

      const sorted = Object.entries(sniMap).sort((a, b) => b[1] - a[1]);

      // Categorise into buckets for nicer display
      const categories = { browsing: [], microsoft: [], advertising: [], other: [] };
      const MS_RE = /microsoft|windows|msft|bing|skype|azure|office|live\.com/i;
      const AD_RE = /doubleclick|adnxs|adsrvr|linkedin|bluekai|krxd|mediavine|fiftyt|moatads|scorecardresearch|quantserve|taboola|outbrain|pubmatic|rubiconproject|openx|casalemedia|contextweb/i;
      const BROWSE_RE = /touropia|google\.|flickr|wikipedia|reddit|youtube|twitter|facebook/i;

      for (const [domain] of sorted) {
        if (MS_RE.test(domain)) categories.microsoft.push(domain);
        else if (AD_RE.test(domain)) categories.advertising.push(domain);
        else if (BROWSE_RE.test(domain)) categories.browsing.push(domain);
        else categories.other.push(domain);
      }

      // TLS version tally (requires Fix #2: packet.tls_version must exist)
      const TLS_VERSION_NAMES = {
        0x0303: 'TLS 1.2',
        0x0304: 'TLS 1.3',
        0x0302: 'TLS 1.1',
        0x0301: 'TLS 1.0'
      };

      const tlsVersionCounts = {};
      for (const pk of packets) {
        if (pk.tls_version) {
          const label =
            TLS_VERSION_NAMES[pk.tls_version] ||
            `Unknown (0x${pk.tls_version.toString(16)})`;

          tlsVersionCounts[label] =
            (tlsVersionCounts[label] || 0) + 1;
        }
      }

      const dominantTlsVersion =
        Object.entries(tlsVersionCounts)
          .sort((a, b) => b[1] - a[1])[0]?.[0] || 'Unknown';

      // Score suspicious domains (skip known safe ones)
      const suspicious = [];

      const KNOWN_SAFE = /google|microsoft|windows|bing|gstatic|cloudflare|akamai|youtube|facebook|twitter|amazon|apple|mozilla/i;

      for (const [domain] of sorted) {
        if (KNOWN_SAFE.test(domain)) continue;

        const flags = scoreDomainSuspicion(domain);
        if (flags.length > 0) {
          suspicious.push({ domain, flags });
        }
      }

      return {
        result: {
          sni_list: sorted,
          categories,
          total: sorted.length,
          suspicious,
          tls_versions: tlsVersionCounts,
          dominant_tls_version: dominantTlsVersion,
        },
        response:
          `Found ${sorted.length} HTTPS destinations via TLS SNI. ` +
          `${suspicious.length} look suspicious or DGA-like. ` +
          `Dominant TLS version: ${dominantTlsVersion}.`,
      };
    }

    case 'get_quic_traffic': {
      const quicPackets = packets.filter(pk => {
        // QUIC is typically UDP/443 (HTTP/3)
        const isUdp443 =
          pk.protocol === 'UDP' &&
          (pk.dst_port === 443 || pk.src_port === 443);

        const protocolTagged = pk.protocol === 'QUIC';

        // heuristic fallback (optional)
        const largeUdpPacket =
          pk.protocol === 'UDP' &&
          pk.length > 1200 &&
          pk.dst_port === 443;

        return protocolTagged || isUdp443 || largeUdpPacket;
      });

      const ipv4 = quicPackets.filter(pk => pk.src_ip && !pk.src_ip.includes(':'));
      const ipv6 = quicPackets.filter(pk => pk.src_ip && pk.src_ip.includes(':'));

      return {
        result: {
          total: quicPackets.length,
          ipv4_count: ipv4.length,
          ipv6_count: ipv6.length,
          sample: quicPackets.slice(0, 20),
        },
        response: `Found ${quicPackets.length} QUIC packets (${ipv6.length} IPv6, ${ipv4.length} IPv4).`,
      };
    }

    case 'get_top_talkers': {
      const ipCount = {};
      for (const pk of packets) {
        if (pk.src_ip) ipCount[pk.src_ip] = (ipCount[pk.src_ip] || 0) + pk.length;
        if (pk.dst_ip) ipCount[pk.dst_ip] = (ipCount[pk.dst_ip] || 0) + pk.length;
      }
      const result = Object.entries(ipCount).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([ip, bytes]) => ({ ip, bytes }));
      return { result, response: `Top ${result.length} IPs by traffic volume (src + dst combined).` };
    }
    case 'filter_large_packets': {
      const result = [...packets].sort((a, b) => b.length - a.length).slice(0, 20);
      return { result, response: `Top ${result.length} largest packets.` };
    }
    case 'get_vulnerability_report': {
      // Use a Set for O(1) port membership test instead of Array.includes O(n)
      const vulnPortSet = new Set(Object.keys(VULNERABLE_PORTS).map(Number));
      const result = packets.filter(pk => vulnPortSet.has(pk.dst_port) || vulnPortSet.has(pk.src_port));
      const byPort = {};
      for (const pk of result) {
        const p = pk.dst_port || pk.src_port;
        if (!byPort[p]) byPort[p] = { port: p, count: 0, risk: VULNERABLE_PORTS[p]?.risk, reason: VULNERABLE_PORTS[p]?.reason };
        byPort[p].count++;
      }
      return { result: Object.values(byPort), response: `Found traffic on ${Object.keys(byPort).length} vulnerable port(s) across ${result.length} packets.` };
    }
    case 'get_capture_info': {
      // Metadata is stored on the session; packets carry timestamp/length info
      const minTs = Math.min(...packets.map(p => p.timestamp).filter(isFinite));
      const maxTs = Math.max(...packets.map(p => p.timestamp).filter(isFinite));
      const result = {
        format: 'pcap (libpcap)',
        link_layer: 'Ethernet (1)',
        version: '2.4',
        total_packets: packets.length,
        duration_seconds: isFinite(minTs) && isFinite(maxTs) ? Math.round(maxTs - minTs) : 0,
        snapshot_length: 262144,
      };
      return { result, response: 'Capture file metadata retrieved.' };
    }
    case 'fingerprint_os': {
      // Collect hostname clues from NBNS, mDNS, DHCP, and DNS payload_previews
      const hostnames = new Set();
      const domainsSeen = new Set();
      const WINDOWS_RE = /microsoft|windows|msft|bing\.com|skype|wns\.windows|windowsupdate|ntpserver|netlogon/i;
      const APPLE_RE = /apple\.com|icloud|itunes|_apple|bonjour/i;
      const LINUX_RE = /ubuntu|debian|fedora|centos|archlinux/i;

      let windowsScore = 0, appleScore = 0, linuxScore = 0;
      const evidence = [];

      for (const pk of packets) {
        if (!pk.payload_preview) continue;
        const preview = pk.payload_preview;

        // NBNS/NetBIOS carries hostname in plaintext
        if (pk.protocol === 'NetBIOS' && preview.length > 0) {
          const nb = preview.match(/\b([A-Z0-9\-]{3,15})\b/);
          if (nb) { hostnames.add(nb[1]); windowsScore += 2; }
        }

        // DNS payload_preview now contains dotted domain (after Fix 2)
        if (pk.protocol === 'DNS' && preview.includes('.')) {
          domainsSeen.add(preview.toLowerCase());
          if (WINDOWS_RE.test(preview)) { windowsScore++; evidence.push(`DNS: ${preview}`); }
          if (APPLE_RE.test(preview)) { appleScore++; evidence.push(`DNS: ${preview}`); }
          if (LINUX_RE.test(preview)) { linuxScore++; evidence.push(`DNS: ${preview}`); }
          if (/\bDESKTOP-[A-Z0-9]+|\bWIN-[A-Z0-9]+/.test(preview.toUpperCase())) {
            windowsScore += 2;
            evidence.push(`Windows hostname in DNS: ${preview}`);
          }
        }

        // mDNS .local hostnames
        if (preview.toLowerCase().includes('.local')) {
          const local = preview.match(/([a-zA-Z0-9\-]+)\.local/i);
          if (local) { hostnames.add(local[1]); }
          if (/DESKTOP-|WIN/i.test(preview)) windowsScore += 2;
        }
      }

      const topOS = windowsScore >= appleScore && windowsScore >= linuxScore ? 'Windows'
        : appleScore >= linuxScore ? 'macOS/iOS' : 'Linux';
      const confidence = Math.max(windowsScore, appleScore, linuxScore) > 3 ? 'High' : 'Low';

      return {
        result: {
          likely_os: topOS,
          confidence,
          windows_score: windowsScore,
          apple_score: appleScore,
          linux_score: linuxScore,
          hostnames: [...hostnames],
          evidence: evidence.slice(0, 10),
        },
        response: `OS fingerprint: likely ${topOS} (confidence: ${confidence}). Hostnames found: ${[...hostnames].join(', ') || 'none'}.`,
      };
    }
    case 'get_timeline': {
      let minTs = Infinity;

      for (const pk of packets) {
        if (pk.timestamp < minTs) minTs = pk.timestamp;
      }

      if (!isFinite(minTs)) {
        return { result: [], response: 'No timestamp data available.' };
      }

      const buckets = {};

      for (const pk of packets) {
        const rel = pk.timestamp - minTs;
        const bucket = Math.floor(rel / 5) * 5;

        if (!buckets[bucket]) {
          buckets[bucket] = {
            protocols: new Set(),
            dns: new Set(),
            http: []
          };
        }

        buckets[bucket].protocols.add(pk.protocol);

        if (pk.protocol === 'DNS' && pk.payload_preview) {
          buckets[bucket].dns.add(pk.payload_preview.slice(0, 60));
        }

        if (
          pk.payload_preview &&
          (
            pk.protocol === 'HTTP' ||
            KNOWN_HTTP_PORTS.has(pk.dst_port) ||
            KNOWN_HTTP_PORTS.has(pk.src_port)
          )
        ) {
          const line = pk.payload_preview.slice(0, 80);
          if (/^(GET|POST|PUT|HEAD)/.test(line)) {
            buckets[bucket].http.push(line);
          }
        }
      }

      const timeline = Object.entries(buckets)
        .sort((a, b) => Number(a[0]) - Number(b[0]))
        .map(([sec, data]) => ({
          time_offset_seconds: Number(sec),
          protocols_active: [...data.protocols],
          dns_queries: [...data.dns].slice(0, 5),
          http_activity: [...new Set(data.http)].slice(0, 3),
        }));

      return {
        result: timeline,
        response: `Timeline built with ${timeline.length} windows.`,
      };
    }

    case 'none': {
      return { result: null, response: '' };
    }
    case 'search_http_objects': {
      const query = (params.query || '').toLowerCase().trim();
      if (!params._fileIndex) return { result: [], response: 'No HTTP object index available.' };
      const direct = params._fileIndex.get(query) || [];
      const fuzzy = [];
      if (direct.length === 0) {
        for (const [key, objs] of params._fileIndex) {
          if (key.includes(query)) fuzzy.push(...objs);
        }
      }
      const result = direct.length ? direct : fuzzy;
      return {
        result,
        response: result.length
          ? `Found ${result.length} HTTP object(s) matching "${query}".`
          : `No HTTP objects found matching "${query}".`,
      };
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
      if (!packets.length) {
        return {
          result: {
            total_packets: 0,
            protocols: {},
            top_ips: [],
            total_bytes: 0,
            duration_seconds: 0,
          },
          response: "Empty capture file.",
        };
      }
      const protocols = buildProtocolMap(packets);
      const ipCount = {};
      let totalBytes = 0;
      let minTs = Infinity;
      let maxTs = -Infinity;
      for (const pk of packets) {
        if (pk.src_ip) ipCount[pk.src_ip] = (ipCount[pk.src_ip] || 0) + pk.length;
        totalBytes += pk.length;
        // Issue 5b: avoid repeated .map() — accumulate min/max in one loop
        if (pk.timestamp < minTs) minTs = pk.timestamp;
        if (pk.timestamp > maxTs) maxTs = pk.timestamp;
      }
      const topIps = Object.entries(ipCount).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([ip, bytes]) => ({ ip, bytes }));
      // Guard against empty packet array (minTs/maxTs stay Infinity/-Infinity)
      const duration = (isFinite(minTs) && isFinite(maxTs)) ? Math.round(maxTs - minTs) : 0;
      return {
        result: { total_packets: packets.length, protocols, top_ips: topIps, total_bytes: totalBytes, duration_seconds: duration },
        response: `${packets.length} packets, ${duration}s capture.`,
      };
    }
  }
}

// ── Shared helpers ────────────────────────────────────────────
function buildProtocolMap(packets) {
  const protocols = {};
  for (const pk of packets) protocols[pk.protocol] = (protocols[pk.protocol] || 0) + 1;
  return protocols;
}

// ── Prompt sanitizer ──────────────────────────────────────────
// Mitigates prompt-injection attempts sent to the Groq tool-selector.
// Strips control chars, truncates, and rejects known jailbreak patterns.
const INJECTION_RE = /ignore (previous|all|above)|you are now|system prompt|disregard|forget (everything|all)|new instructions/i;
function sanitizePrompt(raw) {
  if (typeof raw !== 'string') return null;
  // Remove control characters (keep printable ASCII + common unicode)
  const clean = raw.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '').trim();
  if (clean.length === 0) return null;
  // Hard length cap — Groq tool selector only needs a short query
  const truncated = clean.slice(0, 500);
  if (INJECTION_RE.test(truncated)) {
    console.warn('[Agent] Rejected suspicious prompt:', truncated.slice(0, 80));
    return null;
  }
  return truncated;
}

// Exhaustive set of valid tool names the model may return.
// Anything outside this list is silently demoted to get_summary.
const VALID_TOOLS = new Set([
  'get_summary', 'filter_by_port', 'filter_by_ip', 'filter_by_protocol',
  'find_credentials', 'detect_port_scan', 'get_dns_queries', 'get_top_talkers',
  'filter_large_packets', 'get_vulnerability_report', 'domain_lookup',
  'search_http_objects', 'get_tls_sni', 'get_quic_traffic', 'get_capture_info', 'fingerprint_os', 'get_timeline', 'none',]);

// ── Capture context builder ────────────────────────────────────
// Produces a compact but rich text snapshot of the capture so every
// AI call is fully context-aware without sending raw packet data.
function buildCaptureContext(packets, protocols, session) {
  const ipCount = {};
  let totalBytes = 0;
  let minTs = Infinity, maxTs = -Infinity;
  const portsUsed = new Set();
  const publicIps = new Set();

  for (const pk of packets) {
    if (pk.src_ip) ipCount[pk.src_ip] = (ipCount[pk.src_ip] || 0) + pk.length;
    totalBytes += pk.length;
    if (pk.timestamp < minTs) minTs = pk.timestamp;
    if (pk.timestamp > maxTs) maxTs = pk.timestamp;
    if (pk.dst_port) portsUsed.add(pk.dst_port);
    if (pk.src_port) portsUsed.add(pk.src_port);
    for (const ip of [pk.src_ip, pk.dst_ip]) {
      if (ip && !isPrivateIP(ip)) publicIps.add(ip);
    }
  }

  const topIps = Object.entries(ipCount)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([ip, bytes]) => `${ip} (${(bytes / 1024).toFixed(1)}KB)`);

  const duration = (isFinite(minTs) && isFinite(maxTs)) ? Math.round(maxTs - minTs) : 0;
  const vulnPortsPresent = [...portsUsed].filter(p => VULNERABLE_PORTS[p]).map(p => `${p}(${VULNERABLE_PORTS[p].risk})`);
  const protoList = Object.entries(protocols).sort((a, b) => b[1] - a[1]).map(([p, c]) => `${p}:${c}`).join(', ');

  return [
    `File: ${session?.filename || 'unknown'} | Packets: ${packets.length} | Duration: ${duration}s | Size: ${(totalBytes / 1024).toFixed(1)}KB`,
    `Protocols: ${protoList}`,
    `Top talkers: ${topIps.join(', ')}`,
    `Public IPs seen: ${[...publicIps].slice(0, 8).join(', ') || 'none'}`,
    `Vulnerable ports in use: ${vulnPortsPresent.join(', ') || 'none detected'}`,
    `HTTP objects extracted: ${session?.httpObjects?.length || 0}`,
    `Has plaintext HTTP: ${(protocols['HTTP'] || 0) > 0 ? 'YES' : 'no'}`,
    `Has HTTPS/TLS: ${(protocols['HTTPS'] || 0) > 0 || (protocols['TLS'] || 0) > 0 ? 'YES' : 'no'}`,
    `Has QUIC: ${(protocols['QUIC'] || 0) > 0 ? 'YES' : 'no'}`,
    `Has DNS: ${(protocols['DNS'] || 0) > 0 ? 'YES' : 'no'}`,
  ].join('\n');
}

// ── Dynamic agent ──────────────────────────────────────────────
async function dynamicAgent(userPrompt, packets, session, conversationHistory = []) {
  const protocols = buildProtocolMap(packets);

  // Build a rich capture context snapshot so the AI always knows what's in the file
  const captureContext = buildCaptureContext(packets, protocols, session);

  const toolSchema = `You are an expert network security analyst AI with deep knowledge of TCP/IP, Wireshark, intrusion detection, and malware analysis. You are analysing a live packet capture.

CAPTURE CONTEXT (always consider this before answering):
${captureContext}

Available tools (respond ONLY with valid JSON, no markdown):
- get_summary → {} (ONLY use for: "overview", "summary", "total packets", "what is in this file", "capture stats", "how many packets". Do NOT use for IP, DNS, port, OS, security, or timeline questions)
- get_top_talkers → {} (use when user asks about "top IPs", "who is talking", "source IPs", "destination IPs", "primary hosts", "communicating hosts", "most traffic", "top talkers", "IP roles", "who sent the most")
- get_dns_queries → {} (use when user asks about "DNS", "domains", "what sites", "domain names", "DNS queries", "resolved", "lookups", "what was queried")
- get_tls_sni → {} (use when user asks about "HTTPS sites visited", "TLS connections", "SNI names", "encrypted traffic destinations", "SSL", "what websites", "certificates", "secure connections")
- get_timeline → {} (use when user asks about "timeline", "sequence of events", "browsing behavior", "time-based analysis", "what happened when", "activity over time", "what happened first")
- get_capture_info → {} (use when user asks about "file format", "link layer type", "pcap version", "capture metadata", "file info", "capture file details")
- fingerprint_os → {} (use when user asks about "operating system", "device type", "what OS is running", "identify the host", "Windows or Linux", "OS fingerprint", "what machine")
- get_vulnerability_report → {} (use when user asks about "vulnerabilities", "security", "risky ports", "dangerous ports", "exploits", "attack surface", "risks", "what is vulnerable", "security issues")
- detect_port_scan → {} (use when user asks about "port scan", "scanning", "nmap", "reconnaissance", "SYN scan", "probing", "who is scanning")
- get_quic_traffic → {} (use when user asks about "QUIC", "HTTP/3", "UDP-based encrypted traffic", "QUIC packets")
- filter_by_port → {"port": number} (use when user asks about a specific port number like "port 443", "port 80", "port 53")
- filter_by_ip → {"ip": "x.x.x.x"} (use when user asks about a specific IP address)
- filter_by_protocol → {"protocol": "HTTP"|"DNS"|"TCP"|"UDP"|"ICMP"|"FTP"|"SSH"...} (use when user asks to filter or show only a specific protocol)
- find_credentials → {} (use when user asks about "credentials", "passwords", "plaintext login", "usernames", "auth")
- filter_large_packets → {} (use when user asks about "large packets", "biggest packets", "jumbo frames", "packet size")
- domain_lookup → {"domain": "example.com"} (use when user asks about a specific domain name)
- search_http_objects → {"query": "<filename or url fragment>"} (use when user asks about HTTP objects, files, images, downloads)
- none → {} (use for greetings, thanks, or off-topic messages only)

IMPORTANT CONTEXT-AWARENESS RULES:
- If the user refers to something mentioned earlier (e.g. "that IP", "those packets", "tell me more"), use conversation history to resolve what they mean.
- If the user asks a follow-up like "why?" or "is that dangerous?", pick the same tool as before but enrich the explanation — or use "none" with a deep explanation.
- If the user asks something that combines two tools (e.g. "show DNS and also check for scans"), pick the most relevant single tool and mention you can do the other too.
- Never ignore prior conversation context.

Respond ONLY with: {"tool": "tool_name", "params": {...}}`;

  let toolName = 'get_summary';
  let toolParams = {};

  if (GROQ_API_KEY) {
    // Build messages: system prompt + last 6 turns of history + current user message
    const historyMessages = (conversationHistory || []).slice(-6).map(turn => ({
      role: turn.role,
      content: turn.content,
    }));

    const decision = await groqRequest([
      { role: 'system', content: toolSchema },
      ...historyMessages,
      { role: 'user', content: userPrompt },
    ], 150); if (decision) {
      try {
        // Strip any markdown fences the model may have added despite instructions
        const cleaned = decision.replace(/```(?:json)?|```/g, '').trim();
        // Only parse if it looks like a JSON object — avoids throwing on prose
        if (cleaned.startsWith('{') && cleaned.endsWith('}')) {
          const parsed = JSON.parse(cleaned);
          // Whitelist: only accept known tool names so a hallucinated tool
          // name can never bypass runTool's switch default.
          if (parsed && typeof parsed.tool === 'string' && VALID_TOOLS.has(parsed.tool)) {
            toolName = parsed.tool;
            console.log(`[Agent] Tool selected: ${toolName} for prompt: "${userPrompt.slice(0, 60)}"`);
            // Params must be a plain object; coerce to {} on anything else
            toolParams = (parsed.params && typeof parsed.params === 'object' && !Array.isArray(parsed.params))
              ? parsed.params
              : {};
            // Type-check known param fields to prevent prototype pollution
            if (toolName === 'filter_by_port' && typeof toolParams.port !== 'number') {
              toolParams.port = parseInt(toolParams.port, 10) || 0;
            }
            if (toolName === 'filter_by_ip' && typeof toolParams.ip !== 'string') {
              toolParams.ip = String(toolParams.ip || '');
            }
            if (toolName === 'domain_lookup' && typeof toolParams.domain !== 'string') {
              toolParams.domain = String(toolParams.domain || '');
            }
          }
        }
      } catch (_) { /* parse failed — stay with get_summary default */ }
    }
  }

  const toolResult = runTool(toolName, { ...toolParams, _fileIndex: session?.fileIndex }, packets);
  const resultSummary = Array.isArray(toolResult.result) && toolResult.result.length > 30
    ? { sample: toolResult.result.slice(0, 30), total_count: toolResult.result.length }
    : toolResult.result;

  let liveEnrichment = '';
  if (toolName === 'get_vulnerability_report') {
    const publicIps = [...new Set(packets.filter(pk => !isPrivateIP(pk.src_ip)).map(pk => pk.src_ip))].slice(0, 2);
    for (const ip of publicIps) {
      const shodan = await fetchShodanIp(ip);
      if (shodan?.cves?.length) {
        liveEnrichment += `\nShodan data for ${ip}: ${shodan.cves.length} CVEs including ${shodan.cves.slice(0, 3).join(', ')}.`;
        for (const cveId of shodan.cves.slice(0, 2)) {
          const cveDetail = await fetchCveDetails(cveId);
          if (cveDetail?.summary) liveEnrichment += `\n${cveId}: ${cveDetail.summary.slice(0, 150)}`;
        }
      }
    }
  }

  // For casual messages, skip the data explanation and just respond naturally
  if (toolName === 'none') {
    const chitchat = await groqRequest([
      {
        role: 'system',
        content: 'You are a helpful network analysis assistant. Reply naturally and briefly to the user\'s message. No markdown, no bullet points.',
      },
      { role: 'user', content: userPrompt },
    ], 80);
    return {
      tool_called: 'none',
      parameters: {},
      result: null,
      response: chitchat || 'Glad that helped!',
    };
  }

  // Build a protocol-awareness hint so the model never claims 100% encrypted
  // when plaintext HTTP packets exist in the capture.
  const protocolHint = (() => {
    const proto = buildProtocolMap(packets);
    const httpCount = (proto['HTTP'] || 0);
    const httpsCount = (proto['HTTPS'] || 0);
    if (httpCount > 0 && httpsCount > 0) {
      return ` IMPORTANT: This capture contains BOTH ${httpCount} plaintext HTTP packets AND ${httpsCount} HTTPS packets — never claim all traffic is encrypted.`;
    }
    return '';
  })();

  // Include last 4 turns so the explanation is aware of prior context
  const historyForExplanation = (conversationHistory || []).slice(-4).map(turn => ({
    role: turn.role,
    content: turn.content,
  }));

  const explanation = await groqRequest([
    {
      role: 'system',
      content: `You are a senior network security analyst. You are mid-conversation with a user analysing a packet capture. Explain findings conversationally in plain English. No markdown, no bullet points, no asterisks. Be specific with numbers and IPs. Under 220 words.

CAPTURE CONTEXT:
${buildCaptureContext(packets, buildProtocolMap(packets), session)}

CRITICAL NETWORKING RULES — never violate these:
- Port 80 and 443 are ALWAYS destination ports on servers.
- Clients use ephemeral source ports (>1024) to connect to servers.
- Never say traffic "comes from port 80/443" — that is incorrect.
- QUIC is UDP over port 443 and is NOT the same as HTTPS (TCP/TLS).
- Always distinguish HTTP (plaintext), HTTPS (TLS), and QUIC correctly.
- Never assume all traffic is encrypted unless explicitly TLS/QUIC.
- If the user said "that IP" or "those packets", resolve what they mean from conversation history.
- End your response with one smart follow-up question the user might want to ask next, prefixed exactly with "FOLLOWUP:" on a new line.

${liveEnrichment ? `\nLive threat intel: ${liveEnrichment}` : ''}${protocolHint}`,
    },
    ...historyForExplanation,
    {
      role: 'user',
      content: `User asked: "${userPrompt}"\nTool used: ${toolName}\nTool result: ${JSON.stringify(resultSummary)}\nRaw summary: ${toolResult.response}\n\nExplain conversationally, reference prior conversation if relevant.`,
    },
  ], 600);

  // Extract FOLLOWUP line the model appended, strip it from main response
  let finalExplanation = explanation || toolResult.response;
  let followupSuggestion = null;
  if (finalExplanation) {
    const followupMatch = finalExplanation.match(/\nFOLLOWUP:\s*(.+)$/);
    if (followupMatch) {
      followupSuggestion = followupMatch[1].trim();
      finalExplanation = finalExplanation.replace(/\nFOLLOWUP:\s*.+$/, '').trim();
    }
  }

  return {
    tool_called: toolName,
    parameters: toolParams,
    result: toolResult.result,
    response: finalExplanation,
    followup: followupSuggestion,
  };
}

function isPrivateIP(ip) {
  if (!ip) return true;
  if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('127.') || ip.startsWith('169.254.')) return true;
  if (ip.startsWith('172.')) {
    const second = parseInt(ip.split('.')[1], 10);
    return second >= 16 && second <= 31;
  }
  return false;
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

  const PACKET_LIMIT = 50000;

  while (offset + 16 <= buffer.length && packetId < PACKET_LIMIT) {
    const tsSec = read32(offset);
    const tsUsec = read32(offset + 4);
    const inclLen = read32(offset + 8);
    const origLen = read32(offset + 12);
    offset += 16;

    // FIX 3: use continue instead of break so a bad packet doesn't abort
    // the entire parse. Advance by 1 byte on bad inclLen to avoid an
    // infinite loop; normal parseable packets always advance by inclLen.
    if (inclLen > 65536 || offset + inclLen > buffer.length) {
      offset += 1;
      continue;
    }

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
      // raw_payload is populated during parse and nulled out before the
      // session is stored; it is only used inside extractHttpObjects().
      raw_payload: null,
      seq_num: null,
      tcp_flags_raw: 0,
      is_syn: false,
      is_syn_ack: false,
      // FIX 7: unified flag — set once here, reused by extractHttpObjects
      is_http_candidate: false,
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
          packet.seq_num = packetData.readUInt32BE(transportStart + 4);

          const tcpFlags = packetData[transportStart + 13];
          packet.tcp_flags_raw = tcpFlags;

          // FIX 4: SYN/SYN-ACK classification.
          // We check only the SYN (0x02) and ACK (0x10) bits. Other flag
          // combinations (e.g. SYN+PSH seen on some stacks) are still
          // classified correctly because we test each bit independently.
          // NATed traffic may produce asymmetric captures; the flags are
          // still correct per packet — port-scan detection aggregates them.
          const synBit = (tcpFlags & 0x02) !== 0;
          const ackBit = (tcpFlags & 0x10) !== 0;
          packet.is_syn = synBit && !ackBit;
          packet.is_syn_ack = synBit && ackBit;

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
            const rawSlice = packetData.slice(payloadStart);
            packet.payload_preview = rawSlice.slice(0, 512).toString('utf8', 0, 512).replace(/[^\x20-\x7E]/g, '.'); packet.raw_payload = rawSlice;
          }

          packet.protocol = PROTOCOL_MAP[packet.dst_port] || PROTOCOL_MAP[packet.src_port] || 'TCP';

          // Extract TLS version from ClientHello
          packet.tls_version = null;
          if (
            (packet.dst_port === 443 || packet.src_port === 443) &&
            packet.raw_payload && packet.raw_payload.length >= 11 &&
            packet.raw_payload[0] === 0x16 &&
            packet.raw_payload[5] === 0x01
          ) {
            const ver = (packet.raw_payload[9] << 8) | packet.raw_payload[10];
            packet.tls_version = ver;
          }

          // FIX 7: set unified HTTP candidate flag in the parser
          if (
            KNOWN_HTTP_PORTS.has(packet.src_port) ||
            KNOWN_HTTP_PORTS.has(packet.dst_port) ||
            (packet.payload_preview && /^(HTTP\/|GET |POST |PUT |HEAD )/.test(packet.payload_preview))
          ) {
            packet.is_http_candidate = true;
          }

        } else if (ipProto === 17 && packetData.length >= transportStart + 8) {
          packet.src_port = packetData.readUInt16BE(transportStart);
          packet.dst_port = packetData.readUInt16BE(transportStart + 2);

          // QUIC runs over UDP/443 — tag it separately from TLS-over-TCP HTTPS
          if (packet.dst_port === 443 || packet.src_port === 443) {
            packet.protocol = 'QUIC';
          } else {
            packet.protocol = PROTOCOL_MAP[packet.dst_port] || PROTOCOL_MAP[packet.src_port] || 'UDP';
          }

          // Parse DNS question section labels into a readable domain string

          // Parse DNS question section labels into a readable domain string
          // so the regex in get_dns_queries can match them from payload_preview.
          const udpPayload = packetData.slice(transportStart + 8);
          if ((packet.dst_port === 53 || packet.src_port === 53) && udpPayload.length > 12) {
            try {
              const labels = [];
              let pos = 12; // skip DNS fixed header (12 bytes)
              while (pos < udpPayload.length) {
                const len = udpPayload[pos];
                if (len === 0) break;           // root label → end of name
                if ((len & 0xc0) === 0xc0) break; // compression pointer → stop
                if (len > 63 || pos + 1 + len > udpPayload.length) break;
                labels.push(udpPayload.slice(pos + 1, pos + 1 + len).toString('ascii'));
                pos += 1 + len;
              }
              if (labels.length > 0) {
                packet.payload_preview = labels.join('.');
              }
            } catch (_) { /* leave payload_preview empty */ }
          }
        } else if (ipProto === 1) {
          packet.protocol = 'ICMP';
        }
      } else if (etherType === 0x86DD && packetData.length >= 54) {
        // IPv6: fixed 40-byte header, no IHL field
        const ip6Start = 14;
        const nextHeader = packetData[ip6Start + 6];
        // Extract 16-byte src/dst as compressed hex strings
        const ip6SrcBytes = packetData.slice(ip6Start + 8, ip6Start + 24);
        const ip6DstBytes = packetData.slice(ip6Start + 24, ip6Start + 40);
        const formatIPv6 = (bytes) => {
          const groups = [];
          for (let g = 0; g < 16; g += 2) {
            groups.push(((bytes[g] << 8) | bytes[g + 1]).toString(16));
          }
          // Compress longest run of zero groups with ::
          let bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
          for (let g = 0; g < 8; g++) {
            if (groups[g] === '0') {
              if (curStart === -1) { curStart = g; curLen = 1; }
              else curLen++;
              if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
            } else { curStart = -1; curLen = 0; }
          }
          if (bestLen > 1) {
            const left = groups.slice(0, bestStart).join(':');
            const right = groups.slice(bestStart + bestLen).join(':');
            return (left ? left + '::' : '::') + right;
          }
          return groups.join(':');
        };
        packet.src_ip = formatIPv6(ip6SrcBytes);
        packet.dst_ip = formatIPv6(ip6DstBytes);
        const ip6TransportStart = ip6Start + 40;

        if (nextHeader === 6 && packetData.length >= ip6TransportStart + 20) {
          // TCP over IPv6
          packet.src_port = packetData.readUInt16BE(ip6TransportStart);
          packet.dst_port = packetData.readUInt16BE(ip6TransportStart + 2);
          packet.seq_num = packetData.readUInt32BE(ip6TransportStart + 4);

          const tcpFlags = packetData[ip6TransportStart + 13];
          packet.tcp_flags_raw = tcpFlags;
          const synBit = (tcpFlags & 0x02) !== 0;
          const ackBit = (tcpFlags & 0x10) !== 0;
          packet.is_syn = synBit && !ackBit;
          packet.is_syn_ack = synBit && ackBit;

          const flagStr = [];
          if (tcpFlags & 0x02) flagStr.push('S');
          if (tcpFlags & 0x10) flagStr.push('A');
          if (tcpFlags & 0x08) flagStr.push('P');
          if (tcpFlags & 0x01) flagStr.push('F');
          if (tcpFlags & 0x04) flagStr.push('R');
          packet.flags = flagStr.join('') || null;

          const dataOffset = (packetData[ip6TransportStart + 12] >> 4) * 4;
          const payloadStart = ip6TransportStart + dataOffset;
          if (packetData.length > payloadStart) {
            const rawSlice = packetData.slice(payloadStart);
            packet.payload_preview = rawSlice.slice(0, 512).toString('utf8', 0, 512).replace(/[^\x20-\x7E]/g, '.');
            packet.raw_payload = rawSlice;
          }

          packet.protocol = PROTOCOL_MAP[packet.dst_port] || PROTOCOL_MAP[packet.src_port] || 'TCP';

          if (
            KNOWN_HTTP_PORTS.has(packet.src_port) ||
            KNOWN_HTTP_PORTS.has(packet.dst_port) ||
            (packet.payload_preview && /^(HTTP\/|GET |POST |PUT |HEAD )/.test(packet.payload_preview))
          ) {
            packet.is_http_candidate = true;
          }

        } else if (nextHeader === 17 && packetData.length >= ip6TransportStart + 8) {
          packet.src_port = packetData.readUInt16BE(ip6TransportStart);
          packet.dst_port = packetData.readUInt16BE(ip6TransportStart + 2);

          // QUIC runs over UDP/443 — tag it separately from TLS-over-TCP HTTPS
          if (packet.dst_port === 443 || packet.src_port === 443) {
            packet.protocol = 'QUIC';
          } else {
            packet.protocol = PROTOCOL_MAP[packet.dst_port] || PROTOCOL_MAP[packet.src_port] || 'UDP';
          }

          const rawSlice = packetData.slice(ip6TransportStart + 8);
          if (rawSlice.length > 0) {
            // DNS: parse labels into dotted domain string for payload_preview
            if ((packet.dst_port === 53 || packet.src_port === 53) && rawSlice.length > 12) {
              try {
                const labels = [];
                let pos = 12;
                while (pos < rawSlice.length) {
                  const len = rawSlice[pos];
                  if (len === 0) break;
                  if ((len & 0xc0) === 0xc0) break;
                  if (len > 63 || pos + 1 + len > rawSlice.length) break;
                  labels.push(rawSlice.slice(pos + 1, pos + 1 + len).toString('ascii'));
                  pos += 1 + len;
                }
                if (labels.length > 0) packet.payload_preview = labels.join('.');
              } catch (_) { /* leave empty */ }
            } else {
              packet.payload_preview = rawSlice.slice(0, 512).toString('utf8', 0, 512).replace(/[^\x20-\x7E]/g, '.');
            }
            packet.raw_payload = rawSlice;
          }

        } else if (nextHeader === 58) {
          packet.protocol = 'ICMPv6';
        } else {
          packet.protocol = 'IPv6';
        }

      } else if (etherType === 0x0806) {
        packet.protocol = 'ARP';
      }
    }
    packets.push(packet);
  }
  return packets;
}

// ── Strip raw_payload from all packets before session storage ──
// FIX 2: This is called right after parsing so the full payload buffers
// are released to GC before the session is ever stored. extractHttpObjects()
// is called before this strip on the initial upload if needed, or it must
// be called on the raw parse result before stripping.
function stripRawPayloads(packets) {
  for (const p of packets) p.raw_payload = null;
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
        alerts.push({ layer: 1, risk: VULNERABLE_PORTS[port].risk, protocol: pkt.protocol, port, src_ip: pkt.src_ip, dst_ip: pkt.dst_ip, reason: VULNERABLE_PORTS[port].reason });
      }
    }
    if (pkt.payload_preview) {
      const payload = pkt.payload_preview.toUpperCase();
      if (payload.includes('USER ') || payload.includes('PASS ') || payload.includes('PASSWORD=') || payload.includes('LOGIN:') || payload.includes('AUTHORIZATION: BASIC')) {
        alerts.push({ layer: 2, risk: 'CRITICAL', protocol: pkt.protocol, port: pkt.dst_port || pkt.src_port, src_ip: pkt.src_ip, dst_ip: pkt.dst_ip, reason: 'Plaintext credentials detected in packet payload!', payload_snippet: pkt.payload_preview.slice(0, 100) });
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
  const cleanBoundary = boundary.replace(/^["']|["']$/g, '').trim();
  const boundaryBuf = Buffer.from('\r\n--' + cleanBoundary);
  const firstBound = Buffer.from('--' + cleanBoundary);
  const CRLF4 = Buffer.from('\r\n\r\n');
  const parts = [];

  let pos = buffer.indexOf(firstBound);
  if (pos === -1) return parts;
  pos += firstBound.length;

  let safety = 0;
  while (pos < buffer.length && safety++ < 1000) {
    const lineEnd = buffer.indexOf(Buffer.from('\r\n'), pos);
    if (lineEnd === -1) break;
    const boundaryLine = buffer.slice(pos, lineEnd).toString();
    if (boundaryLine.startsWith('--')) break;

    const headerStart = lineEnd + 2;
    const headerEnd = buffer.indexOf(CRLF4, headerStart);
    if (headerEnd === -1) break;

    const headers = buffer.slice(headerStart, headerEnd).toString();
    const dataStart = headerEnd + 4;

    const nextBound = buffer.indexOf(boundaryBuf, dataStart);
    const dataEnd = nextBound === -1 ? buffer.length : nextBound;

    parts.push({ headers, data: buffer.slice(dataStart, dataEnd) });

    if (nextBound === -1) break;
    pos = nextBound + boundaryBuf.length;
  }
  return parts;
}

function json(res, data, status = 200, requestOrigin = '', acceptEncoding = '') {
  const payload = JSON.stringify(data);
  const corsHeaders = getCorsHeaders(requestOrigin);

  // Compress if client supports gzip AND payload is worth compressing (>1 KB).
  // Inline synchronous gzip for simplicity — payloads are already in memory
  // and gzip on <5 MB JSON completes in <5ms, well within event-loop tolerance.
  const wantsGzip = /\bgzip\b/.test(acceptEncoding);
  if (wantsGzip && payload.length > 1024) {
    zlib.gzip(Buffer.from(payload, 'utf8'), (err, compressed) => {
      if (err) {
        // Fallback to uncompressed on error
        res.writeHead(status, { 'Content-Type': 'application/json', ...corsHeaders });
        res.end(payload);
        return;
      }
      res.writeHead(status, {
        'Content-Type': 'application/json',
        'Content-Encoding': 'gzip',
        'Vary': 'Accept-Encoding',
        ...corsHeaders,
      });
      res.end(compressed);
    });
  } else {
    res.writeHead(status, { 'Content-Type': 'application/json', ...corsHeaders });
    res.end(payload);
  }
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

// FIX 9 (batch decompression): returns a Promise but resolves immediately
// for uncompressed data so sequential await cost is negligible.
// Heavy decompressions are isolated per-body, not per-packet.
function decompressBody(body, encoding) {
  if (!body || body.length === 0) return Promise.resolve(body);
  const enc = (encoding || '').toLowerCase().trim();
  return new Promise((resolve) => {
    const done = (err, result) => resolve(err ? body : result);
    try {
      if (enc === 'gzip' || enc === 'x-gzip') return zlib.gunzip(body, done);
      if (enc === 'deflate') return zlib.inflate(body, done);
      if (enc === 'br') return zlib.brotliDecompress(body, done);
    } catch (_) { /* fall through */ }
    resolve(body);
  });
}

// ══════════════════════════════════════════════════════════════
// WIRESHARK-STYLE HTTP OBJECT EXTRACTOR
// ══════════════════════════════════════════════════════════════
async function extractHttpObjects(packets, sessionId) {  // FIX 7: Use the is_http_candidate flag set by the parser; no re-check
  // against KNOWN_HTTP_PORTS needed here — single source of truth.

  // ── FIX 4/5 — Build SYN-based server role map ────────────────
  // SYN packet:     src=client, dst=server  → add dst to confirmedServers
  // SYN-ACK packet: src=server, dst=client  → add src to confirmedServers
  const confirmedServers = new Set();
  for (const pkt of packets) {
    if (!pkt.src_ip || !pkt.dst_ip || !pkt.src_port || !pkt.dst_port) continue;
    if (pkt.is_syn && !pkt.is_syn_ack) {
      confirmedServers.add(`${pkt.dst_ip}:${pkt.dst_port}`);
    } else if (pkt.is_syn_ack) {
      confirmedServers.add(`${pkt.src_ip}:${pkt.src_port}`);
    }
  }

  // ── Step 1: Group into TCP streams ───────────────────────────
  const streamMap = new Map();

  for (const pkt of packets) {
    // FIX 7: Reuse parser-set flag; skip non-HTTP-candidate packets early
    if (!pkt.is_http_candidate) continue;
    if (!pkt.raw_payload || pkt.raw_payload.length === 0) continue;
    if (!pkt.src_ip || !pkt.dst_ip || !pkt.src_port || !pkt.dst_port) continue;

    // FIX 5: Only use real seq numbers; discard packets without one.
    // The old fallback of pkt.id * 1500 produced wrong reassembly when
    // packets were retransmitted, reordered, or lost.
    if (pkt.seq_num === null) continue;
    const seqNum = pkt.seq_num;

    const srcKey = `${pkt.src_ip}:${pkt.src_port}`;
    const dstKey = `${pkt.dst_ip}:${pkt.dst_port}`;
    let srcIsServer;
    if (confirmedServers.has(srcKey)) {
      srcIsServer = true;
    } else if (confirmedServers.has(dstKey)) {
      srcIsServer = false;
    } else {
      // Fallback: known HTTP port wins; lower port = server as last resort
      srcIsServer = KNOWN_HTTP_PORTS.has(pkt.src_port) ||
        (!KNOWN_HTTP_PORTS.has(pkt.dst_port) && pkt.src_port < pkt.dst_port);
    }

    const isServer = srcIsServer;
    const clientIp = isServer ? pkt.dst_ip : pkt.src_ip;
    const clientPort = isServer ? pkt.dst_port : pkt.src_port;
    const serverIp = isServer ? pkt.src_ip : pkt.dst_ip;
    const serverPort = isServer ? pkt.src_port : pkt.dst_port;
    const key = `${clientIp}:${clientPort}-${serverIp}:${serverPort}`;

    if (!streamMap.has(key)) {
      streamMap.set(key, {
        clientIp, serverIp, serverPort, clientPort,
        requests: [], responses: [],
        pendingRequests: [], currentResp: undefined, currentRespFirstPkt: 0, pairs: [],
      });
    }

    const stream = streamMap.get(key);
    const entry = { seq_num: seqNum, payload: pkt.raw_payload, packet_id: pkt.id };

    if (isServer) {
      if (!stream.currentResp) {
        stream.currentResp = [];
        stream.currentRespFirstPkt = entry.packet_id;
      }
      stream.currentResp.push(entry);
      stream.responses.push(entry);
    } else {
      const preview = pkt.raw_payload.slice(0, 8).toString('binary');
      const isNewRequest = /^(GET|POST|PUT|HEAD|DELETE|OPTIONS) /.test(preview);
      if (isNewRequest && stream.currentResp && stream.currentResp.length > 0) {
        stream.pairs.push({
          reqEntries: stream.pendingRequests.slice(),
          respEntries: stream.currentResp,
          firstRespPacketId: stream.currentRespFirstPkt,
        });
        stream.currentResp = undefined;
        stream.pendingRequests = [];
      }
      if (isNewRequest) stream.pendingRequests = [entry];
      else stream.pendingRequests.push(entry);
      stream.requests.push(entry);
    }
  }

  // ── True byte-stream TCP reassembly ──────────────────────────
  // Handles retransmits (exact + partial overlaps), sequence-number
  // wrap-around (32-bit), and fill gaps with zero bytes so magic numbers
  // and gzip headers stay at the correct byte offsets.
  //
  // Known real-world limitations:
  //  • Out-of-order segments beyond the first appear as gaps (filled with 0x00)
  //    until the missing segment arrives; if it never does (truncated capture)
  //    the gap stays as zeros. This may corrupt gzip streams but the
  //    subsequent magic-byte check will then discard the object cleanly.
  //  • A stream captured mid-connection (no SYN seen) starts from the first
  //    observed seq number, so the initial bytes are correctly anchored but
  //    any data before the first captured packet is unrecoverable — expected.
  function reassembleStream(entries) {
    if (entries.length === 0) return Buffer.alloc(0);

    // Signed 32-bit sort handles seq wrap-around correctly:
    // e.g. 0xFFFFFF00 < 0x00000100 after wrap → difference is negative int32
    entries.sort((a, b) => (a.seq_num - b.seq_num) | 0);

    let streamBase = entries[0].seq_num; // treat first seq as byte-offset 0
    let streamEnd = streamBase;         // highest byte written so far (absolute)
    const chunks = [];

    for (const e of entries) {
      const segLen = e.payload.length;
      if (segLen === 0) continue;

      // All arithmetic is signed 32-bit to handle wrap correctly
      const relStart = (e.seq_num - streamBase) | 0;
      const relEnd = (relStart + segLen) | 0;

      // Negative relStart means this segment is before our window — skip
      // (can happen when a retransmit of very early data arrives late)
      if (relStart < 0) continue;

      // Full duplicate: this segment falls entirely within already-written data
      if (relEnd <= ((streamEnd - streamBase) | 0)) continue;

      // Partial overlap: trim leading bytes already written
      const alreadyWritten = Math.max(0, ((streamEnd - streamBase) | 0) - relStart);
      const usefulPayload = alreadyWritten > 0 && alreadyWritten < segLen
        ? e.payload.slice(alreadyWritten)
        : e.payload;

      // Gap between what we've written and where this segment starts.
      // Gaps arise from out-of-order delivery or lost packets.
      // Cap at 64 KB to avoid allocating enormous zero-fill buffers on
      // heavily fragmented or corrupted captures.
      const gapBytes = relStart - ((streamEnd - streamBase) | 0);
      if (gapBytes > 0) {
        const fillLen = Math.min(gapBytes, 65536);
        chunks.push(Buffer.alloc(fillLen, 0));
        streamEnd = (streamEnd + fillLen) | 0;
      }

      if (usefulPayload.length > 0) {
        chunks.push(usefulPayload);
        streamEnd = (streamEnd + usefulPayload.length) | 0;
      }
    }

    return chunks.length > 0 ? Buffer.concat(chunks) : Buffer.alloc(0);
  }

  const objects = [];
  const seen = new Set();
  const extMap = {
    'image/jpeg': '.jpg', 'image/jpg': '.jpg', 'image/png': '.png',
    'image/gif': '.gif', 'image/webp': '.webp', 'image/bmp': '.bmp',
    'image/svg+xml': '.svg', 'image/x-icon': '.ico',
    'text/html': '.html', 'text/css': '.css',
    'text/javascript': '.js', 'application/javascript': '.js',
    'application/x-javascript': '.js', 'application/json': '.json',
    'application/xml': '.xml', 'text/xml': '.xml',
    'application/pdf': '.pdf', 'font/woff': '.woff', 'font/woff2': '.woff2',
  };

  // Flush any last unpaired response in every stream
  for (const [, stream] of streamMap) {
    if (stream.currentResp && stream.currentResp.length > 0) {
      stream.pairs.push({
        reqEntries: stream.pendingRequests.slice(),
        respEntries: stream.currentResp,
        firstRespPacketId: stream.currentRespFirstPkt,
      });
      stream.currentResp = undefined;
    }
  }

  // FIX 9 (batch decompression): Collect all (body, encoding) pairs that
  // need decompression, decompress them in parallel with Promise.all, then
  // process the results. This avoids sequential await inside the hot loop.
  // We build a "decompression work list" in pass 1 and apply results in pass 2.

  // Pass 1: reassemble + parse headers, collect decompression jobs
  const pendingObjects = [];

  for (const [, stream] of streamMap) {
    const pairsToProcess = stream.pairs.length > 0
      ? stream.pairs
      : [{ reqEntries: stream.requests, respEntries: stream.responses, firstRespPacketId: stream.responses[0]?.packet_id ?? 0 }];

    for (const pair of pairsToProcess) {
      const reqBytes = reassembleStream(pair.reqEntries);
      const respBytes = reassembleStream(pair.respEntries);
      if (respBytes.length < 12) continue;

      const firstRespPacketId = pair.firstRespPacketId;

      // Parse HTTP request
      let requestUri = '/';
      let hostname = stream.serverIp;
      let method = 'GET';
      if (reqBytes.length > 4) {
        const reqStr = reqBytes.slice(0, 4096).toString('binary');
        const reqLine = reqStr.match(/(GET|POST|PUT|HEAD|DELETE|OPTIONS)\s+([^\s]+)\s+HTTP/i);
        if (reqLine) { method = reqLine[1].toUpperCase(); requestUri = reqLine[2]; }
        const hostMatch = reqStr.match(/Host:\s*([^\r\n]+)/i);
        if (hostMatch) hostname = hostMatch[1].trim().split(':')[0];
      }

      // Find HTTP marker (may not be at offset 0 if capture started mid-stream)
      const httpMarker = respBytes.indexOf(Buffer.from('HTTP/'));
      if (httpMarker === -1) continue;
      const respStart = httpMarker;

      const headerSearchBuf = respBytes.slice(respStart);
      const rawHeaderSection = headerSearchBuf.slice(0, Math.min(8192, headerSearchBuf.length)).toString('binary');
      const unfoldedHeaders = rawHeaderSection.replace(/\r\n[ \t]+/g, ' ');
      const headerEndIdx = unfoldedHeaders.indexOf('\r\n\r\n');
      if (headerEndIdx === -1) continue;

      const headerStr = unfoldedHeaders.slice(0, headerEndIdx);

      const statusMatch = headerStr.match(/HTTP\/[\d.]+\s+(\d+)/);
      const statusCode = statusMatch ? parseInt(statusMatch[1]) : 0;
      if (![200, 203, 206, 304].includes(statusCode) && (statusCode < 200 || statusCode > 299)) continue;

      const ctMatch = headerStr.match(/Content-Type:\s*([^\r\n]+)/i);
      const rawCt = ctMatch ? ctMatch[1].trim().toLowerCase() : '';
      const contentType = rawCt.split(';')[0].trim() || 'application/octet-stream';

      const boringTypes = ['application/octet-stream', 'text/plain', 'application/x-www-form-urlencoded'];
      if (boringTypes.includes(contentType) && !contentType.startsWith('image/')) continue;
      const isWorthShowing =
        contentType.startsWith('image/') || contentType.includes('html') ||
        contentType.includes('javascript') || contentType.includes('css') ||
        contentType.includes('json') || contentType.includes('xml') ||
        contentType.includes('font') || contentType.includes('pdf') ||
        contentType.includes('svg');
      if (!isWorthShowing) continue;

      const ceMatch = headerStr.match(/Content-Encoding:\s*([^\r\n]+)/i);
      const contentEncoding = ceMatch ? ceMatch[1].trim() : '';

      const clMatch = headerStr.match(/Content-Length:\s*(\d+)/i);
      const contentLength = clMatch ? parseInt(clMatch[1]) : null;
      const isChunked = /Transfer-Encoding:\s*chunked/i.test(headerStr);

      // Derive body start from raw bytes (not unfolded string offsets)
      const rawHeaderEndIdx = headerSearchBuf.indexOf(Buffer.from('\r\n\r\n'));
      if (rawHeaderEndIdx === -1) continue;
      const bodyStartOffset = respStart + rawHeaderEndIdx + 4;
      let body = respBytes.slice(bodyStartOffset);

      // Dechunk — RFC 7230 §4.1 compliant:
      // Each chunk = chunk-size [chunk-ext] CRLF chunk-data CRLF
      // Terminated by last-chunk = "0" CRLF [trailers] CRLF
      if (isChunked && body.length > 0) {
        try {
          const dechunked = [];
          let pos = 0;
          let safety = 0;
          while (pos < body.length && safety++ < 10000) {
            // Find end of chunk-size line (may include extensions after ";")
            const lineEnd = body.indexOf(Buffer.from('\r\n'), pos);
            if (lineEnd === -1 || lineEnd === pos) break; // no CRLF or empty line
            // Strip chunk-extension (everything after first ";") and whitespace
            const sizeLine = body.slice(pos, lineEnd).toString('ascii').split(';')[0].trim();
            // Validate: chunk size must be hex digits only
            if (!/^[0-9a-fA-F]+$/.test(sizeLine)) break;
            const chunkSize = parseInt(sizeLine, 16);
            if (isNaN(chunkSize) || chunkSize < 0) break;
            if (chunkSize === 0) break; // last-chunk — stop here (ignore trailers)
            const chunkStart = lineEnd + 2; // skip CRLF after size line
            const chunkEnd = chunkStart + chunkSize;
            if (chunkEnd > body.length) {
              // Partial final chunk (truncated capture) — take what we have
              dechunked.push(body.slice(chunkStart, body.length));
              break;
            }
            dechunked.push(body.slice(chunkStart, chunkEnd));
            // Skip chunk-data CRLF; if missing (truncated), tolerate it
            pos = chunkEnd + (body[chunkEnd] === 0x0d && body[chunkEnd + 1] === 0x0a ? 2 : 0);
          }
          if (dechunked.length > 0) body = Buffer.concat(dechunked);
        } catch (_) { /* leave body as-is — non-critical */ }
      }

      if (body.length < 4) continue;

      pendingObjects.push({
        body, contentEncoding, contentType, contentLength,
        firstRespPacketId, requestUri, hostname, method,
        stream, headerStr,
      });
    }
  }

  // FIX 9: Decompress all bodies in parallel
  const decompressed = await Promise.all(
    pendingObjects.map(async (obj) => {
      if (!obj.contentEncoding) return obj.body;
      const preLen = obj.body.length;
      const result = await decompressBody(obj.body, obj.contentEncoding);
      const MAX_DECOMPRESSED = 50 * 1024 * 1024;
      const trimmed = result.length > MAX_DECOMPRESSED ? result.slice(0, MAX_DECOMPRESSED) : result;
      // If decompression silently returned raw bytes, signal skip with null
      const looksStillCompressed =
        (trimmed[0] === 0x1f && trimmed[1] === 0x8b) ||
        (trimmed[0] === 0x78 && (trimmed[1] === 0x9c || trimmed[1] === 0x01 || trimmed[1] === 0xda));
      if (looksStillCompressed && preLen === trimmed.length) return null;
      return trimmed;
    })
  );

  // Pass 2: apply decompressed bodies and finalize objects
  for (let i = 0; i < pendingObjects.length; i++) {
    const obj = pendingObjects[i];
    const body = decompressed[i];
    if (!body || body.length < 4) continue;

    const { contentType, contentLength, firstRespPacketId,
      requestUri, hostname, method, stream, contentEncoding } = obj;

    // Magic-byte validation (GAP 6)
    if (contentType.startsWith('image/jpeg') || contentType.startsWith('image/jpg')) {
      if (body[0] !== 0xff || body[1] !== 0xd8) continue;
    } else if (contentType.startsWith('image/png')) {
      if (body[0] !== 0x89 || body[1] !== 0x50) continue;
    } else if (contentType.startsWith('image/gif')) {
      if (body.slice(0, 3).toString('binary') !== 'GIF') continue;
    } else if (contentType.includes('html')) {
      if (body[0] < 0x09 || (body[0] > 0x0d && body[0] < 0x20)) continue;
    }

    let filename = (requestUri.split('/').pop() || '').split('?')[0];
    if (!filename) filename = hostname.replace(/\./g, '_') + '_index';
    const expectedExt = extMap[contentType];
    if (expectedExt && !filename.includes('.')) filename += expectedExt;
    if (filename.length > 80) filename = filename.slice(0, 80);

    const dedupKey = `${hostname}${requestUri}`;
    if (seen.has(dedupKey)) continue;
    seen.add(dedupKey);

    const isImage = contentType.startsWith('image/') || contentType.includes('svg');

    // Store raw buffer in imageStore keyed by sessionId + dedupKey.
    // No base64 encoding here — the /pcap/image-data endpoint streams
    // the buffer directly so the browser decodes it natively.
    // Non-image types (HTML, JS, JSON) are also stored so they can be
    // downloaded on demand without holding them in the session object.
    const artifactKey = encodeURIComponent(dedupKey);
    if (sessionId) {
      if (!imageStore.has(sessionId)) imageStore.set(sessionId, new Map());
      imageStore.get(sessionId).set(artifactKey, { buffer: body, contentType, filename });
    }

    objects.push({
      packet_num: firstRespPacketId,
      filename,
      request_uri: requestUri,
      hostname,
      content_type: contentType,
      content_encoding: contentEncoding || null,
      size: contentLength ?? body.length,
      method,
      src_ip: stream.serverIp,
      dst_ip: stream.clientIp,
      src_port: stream.serverPort,
      dst_port: stream.clientPort,
      // artifact_key lets the frontend build the /pcap/image-data URL.
      // No base64 blob stored here.
      artifact_key: sessionId ? artifactKey : null,
      is_image: isImage,
    });
  }

  // FIX 2: null out raw_payload refs held inside extraction entries
  // (the global strip in the upload handler covers session packets;
  //  this covers any lingering references inside stream entry objects)
  for (const [, stream] of streamMap) {
    for (const e of stream.requests) e.payload = null;
    for (const e of stream.responses) e.payload = null;
  }

  objects.sort((a, b) => a.packet_num - b.packet_num);
  return objects;
}

// ── Keep-alive ────────────────────────────────────────────────
const RENDER_URL = process.env.RENDER_EXTERNAL_URL || '';
if (RENDER_URL) {
  setInterval(() => {
    https.get(`${RENDER_URL}/pcap/health`, () => { }).on('error', () => { });
    console.log('[Keep-alive] ping sent');
  }, 9 * 60 * 1000);
}

// ── Session ID validation ─────────────────────────────────────
// session_id is server-generated as "session-<timestamp>-<6 alphanum chars>".
// Reject anything that doesn't match before touching the sessions Map,
// which prevents path-traversal style probing and avoids prototype-pollution
// via crafted keys like "__proto__" or "constructor".
const SESSION_ID_RE = /^session-\d{13}-[a-z0-9]{6}$/;
function isValidSessionId(id) {
  return typeof id === 'string' && SESSION_ID_RE.test(id);
}

// ── Rate limiter ──────────────────────────────────────────────
const rateLimits = new Map();
const RATE_LIMIT_UPLOAD = { max: 10, windowMs: 60 * 1000 };
const RATE_LIMIT_AGENT = { max: 30, windowMs: 60 * 1000 };

function checkRateLimit(ip, limit) {
  const now = Date.now();
  const key = `${ip}:${limit.max}:${limit.windowMs}`;
  const entry = rateLimits.get(key) || { count: 0, windowStart: now };
  if (now - entry.windowStart > limit.windowMs) {
    entry.count = 0; entry.windowStart = now;
  }
  entry.count++;
  rateLimits.set(key, entry);
  return entry.count <= limit.max;
}

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of rateLimits) {
    if (now - v.windowStart > 5 * 60 * 1000) rateLimits.delete(k);
  }
}, 2 * 60 * 1000);

// ── Main HTTP Server ───────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const url = req.url || '/';
  const method = req.method || 'GET';
  const requestOrigin = req.headers['origin'] || '';
  const acceptEncoding = req.headers['accept-encoding'] || '';

  // Convenience wrapper that captures encoding for this request
  const respond = (data, status = 200) => json(res, data, status, requestOrigin, acceptEncoding);

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
    return respond({ status: 'ok', service: 'pcap-analyzer', sessions: sessions.size, groq: !!GROQ_API_KEY }, 200);
  }

  // ── Upload ─────────────────────────────────────────────────
  if (url === '/pcap/upload' && method === 'POST') {
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
    if (!checkRateLimit(clientIp, RATE_LIMIT_UPLOAD)) {
      return respond({ error: 'Too many uploads. Limit: 10 per minute.' }, 429);
    }
    try {
      const contentLength = parseInt(req.headers['content-length'] || '0');
      if (contentLength > 55 * 1024 * 1024) {
        req.resume();
        return respond({ error: 'Request too large. Maximum is 50 MB.' }, 413);
      }

      const contentType = req.headers['content-type'] || '';
      const boundaryMatch = contentType.match(/boundary=(?:"([^"]+)"|([^;,\s]+))/);
      const boundary = boundaryMatch?.[1] ?? boundaryMatch?.[2];
      if (!boundary) return respond({ error: 'Missing multipart boundary' }, 400);

      const body = await parseBody(req);
      const parts = parseMultipart(body, boundary);

      let fileData = null;
      let filename = 'upload.pcap';
      for (const part of parts) {
        const headers = part.headers || '';
        const cdHeader = headers.match(/content-disposition:\s*form-data[^;]*/i);
        const fnMatch = cdHeader && headers.match(/filename\*?=(?:UTF-8''|")?([^";\r\n]+)/i);
        if (fnMatch) {
          filename = decodeURIComponent(fnMatch[1].replace(/"/g, '').trim());
          fileData = part.data;
        }
      }

      if (!fileData) return respond({ error: 'No file found in upload' }, 400);

      const MAX_UPLOAD_BYTES = 50 * 1024 * 1024;
      if (fileData.length > MAX_UPLOAD_BYTES) {
        return respond({
          error: `File too large (${(fileData.length / 1024 / 1024).toFixed(1)} MB). Maximum is 50 MB.`,
          hint: 'Use Wireshark to split the capture: File → Export Specified Packets.',
        }, 413);
      }

      let packets;
      try {
        packets = parsePcap(fileData);
      } catch (e) {
        console.error('[parsePcap error]', filename, fileData?.length, e.message);
        return respond({ error: 'Invalid PCAP format: ' + e.message }, 400);
      }
      if (packets.length === 0) return respond({ error: 'Could not parse PCAP file. Make sure it is a valid .pcap or .pcapng file.' }, 400);

      // Generate session_id early so extractHttpObjects can key imageStore.
      const session_id = `session-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;

      // Extract HTTP objects BEFORE stripping raw_payload.
      // Buffers are stored in imageStore (keyed by session_id), NOT in the
      // session object — so session memory holds only lightweight metadata.
      const httpObjects = await extractHttpObjects(packets, session_id);

      // Build a filename/URI index for fast agent lookups.
      const fileIndex = new Map();
      for (const obj of httpObjects) {
        const fname = obj.filename.toLowerCase();
        const seg = obj.request_uri.toLowerCase().split('/').pop().split('?')[0];
        for (const key of new Set([fname, seg])) {
          if (!key) continue;
          if (!fileIndex.has(key)) fileIndex.set(key, []);
          fileIndex.get(key).push(obj);
        }
      }

      // Strip raw_payload from every packet now that extraction is done.
      stripRawPayloads(packets);

      const protocols = buildProtocolMap(packets);
      let totalBytes = 0;
      let minT = Infinity;
      let maxT = -Infinity;
      for (const pk of packets) {
        totalBytes += pk.length;
        if (pk.timestamp < minT) minT = pk.timestamp;
        if (pk.timestamp > maxT) maxT = pk.timestamp;
      }
      if (!isFinite(minT)) { minT = 0; maxT = 0; }

      // Evict BEFORE inserting to never exceed the cap.
      // Strategy: evict by largest packet count first (memory pressure),
      // fall back to oldest if sizes are equal.
      const SESSION_CAP = 10;
      while (sessions.size >= SESSION_CAP) {
        let evictKey = null;
        let worstScore = -1;
        const now = Date.now();
        for (const [k, s] of sessions) {
          // Score = packet count (memory proxy) weighted slightly by age.
          // Older + larger sessions evicted first.
          const score = (s.packets?.length ?? 0) + (now - s.created_at) / 1000;
          if (score > worstScore) { worstScore = score; evictKey = k; }
        }
        if (evictKey) {
          sessions.delete(evictKey);
          imageStore.delete(evictKey);
          console.log(`[Session] Evicted under pressure: ${evictKey}`);
        } else break;
      }

      // Session stores only lightweight metadata + stripped packets.
      // httpObjects holds metadata only (no buffers — those are in imageStore).
      sessions.set(session_id, { session_id, filename, packets, httpObjects, fileIndex, created_at: Date.now() });
      const duration_seconds = (isFinite(minT) && isFinite(maxT)) ? Math.max(0, Math.round(Math.abs(maxT - minT))) : 0;

      return respond({
        session_id,
        summary: {
          total_packets: packets.length,
          protocols,
          duration_seconds,
          total_bytes: totalBytes,
          time_range: { start: minT, end: maxT },
        },
      }, 200);
    } catch (e) {
      console.error('[Upload Error]', e);
      return respond({ error: 'Upload failed: ' + e.message }, 500);
    }
  }

  // ── Packets ────────────────────────────────────────────────
  if (url.startsWith('/pcap/packets') && method === 'GET') {
    const q = getQuery(url);
    if (!isValidSessionId(q.session_id)) return respond({ error: 'Invalid session_id' }, 400);
    const session = sessions.get(q.session_id);
    if (!session) return respond({ error: 'Session not found' }, 404);
    const page = parseInt(q.page || '1');
    const per_page = parseInt(q.per_page || '50');
    const start = (page - 1) * per_page;
    const paginated = session.packets.slice(start, start + per_page);
    return respond({ packets: paginated, total: session.packets.length, page, per_page }, 200);
  }

  // ── Vulnerabilities ────────────────────────────────────────
  if (url.startsWith('/pcap/vulnerabilities') && method === 'GET') {
    const q = getQuery(url);
    if (!isValidSessionId(q.session_id)) return respond({ error: 'Invalid session_id' }, 400);
    const session = sessions.get(q.session_id);
    if (!session) return respond({ error: 'Session not found' }, 404);

    const { alerts, publicIps } = detectVulnerabilities(session.packets);
    const enrichedAlerts = [...alerts];

    // Issue 2: fetch all Shodan records in parallel — reduces worst-case
    // latency from (5 × 4s timeout) = 20s down to a single 4s window.
    const shodanPairs = await Promise.all(
      publicIps.slice(0, 5).map(async ip => ({
        ip,
        data: await fetchShodanIp(ip).catch(() => null),
      }))
    );
    for (const { ip, data } of shodanPairs) {
      if (data?.cves?.length) {
        enrichedAlerts.push({
          layer: 3, risk: 'HIGH',
          ip,
          reason: `Shodan: ${data.cves.length} known CVEs`,
          open_ports: data.ports || [],
          cves: data.cves.slice(0, 5),
          hostnames: data.hostnames || [],
        });
      }
    }

    // Issue 5: normalize risk to lowercase before tallying so any casing
    // variant ('HIGH', 'high', 'High') maps correctly to the summary keys.
    // The summary keys are intentionally lowercase.
    const summary = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const a of enrichedAlerts) {
      const r = (a.risk || '').toLowerCase();
      if (Object.prototype.hasOwnProperty.call(summary, r)) summary[r]++;
    }
    return respond({ alerts: enrichedAlerts, summary }, 200);
  }

  // ── Agent ──────────────────────────────────────────────────
  if (url === '/pcap/agent/query' && method === 'POST') {
    const clientIpAgent = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
    if (!checkRateLimit(clientIpAgent, RATE_LIMIT_AGENT)) {
      return respond({ error: 'Too many queries. Limit: 30 per minute.' }, 429);
    }
    try {
      const body = await parseBody(req);
      let parsed;
      try {
        parsed = JSON.parse(body.toString());
      } catch {
        return respond({ error: 'Invalid JSON body' }, 400);
      }
      const { prompt, session_id, history } = parsed || {};
      if (!isValidSessionId(session_id)) return respond({ error: 'Invalid session_id' }, 400);
      const session = sessions.get(session_id);
      if (!session) return respond({ error: 'Session not found' }, 404);
      // Prompt injection guard: strip control chars, limit length, reject
      // strings containing system-prompt override attempts.
      const safePrompt = sanitizePrompt(prompt);
      if (!safePrompt) return respond({ error: 'Invalid or empty prompt' }, 400);

      // Sanitize history: only allow role/content strings, max 10 turns, max 300 chars per content
      const safeHistory = Array.isArray(history)
        ? history
          .filter(h => h && typeof h.role === 'string' && typeof h.content === 'string')
          .slice(-10)
          .map(h => ({
            role: h.role === 'assistant' ? 'assistant' : 'user',
            content: h.content.slice(0, 300),
          }))
        : [];

      const result = await dynamicAgent(safePrompt, session.packets, session, safeHistory);

      return respond(result, 200);
    } catch (e) {
      console.error('[Agent Error]', e);
      return respond({ error: 'Agent error: ' + e.message }, 500);
    }
  }

  // ── HTTP Objects (Wireshark-style Export Objects) ──────────
  // FIX 2: Serve pre-extracted objects stored at upload time so we
  // never need raw_payload again after the session is created.
  if (url.startsWith('/pcap/images') && method === 'GET') {
    const q = getQuery(url);
    if (!isValidSessionId(q.session_id)) return respond({ error: 'Invalid session_id' }, 400);
    const session = sessions.get(q.session_id);
    if (!session) return respond({ error: 'Session not found' }, 404);

    const images = session.httpObjects || [];
    return respond({
      images,
      total: images.length,
      message: images.length === 0
        ? 'No HTTP objects found. Objects can only be extracted from unencrypted HTTP traffic (port 80). HTTPS is encrypted.'
        : `Extracted ${images.length} HTTP object(s) from traffic.`,
    }, 200);
  }

  // ── Port Intelligence ──────────────────────────────────────
  if (url.startsWith('/pcap/port-intel') && method === 'GET') {
    const q = getQuery(url);
    const query = q.query || '';

    if (GROQ_API_KEY) {
      const portInfo = await groqRequest([
        { role: 'system', content: 'You are a network security expert. Given a port number or protocol name, return security info as plain JSON only with these fields: name, description, risk (CRITICAL/HIGH/MEDIUM/LOW/SECURE), secure_alternative, common_uses (array of strings), vulnerabilities (array of strings), recommendations (array of strings). No markdown, no extra text.' },
        { role: 'user', content: `Port/protocol: ${query}` },
      ], 400);

      if (portInfo) {
        try {
          let cleaned = portInfo.replace(/```json|```/g, '').trim();
          const jsonStart = cleaned.indexOf('{');
          const jsonEnd = cleaned.lastIndexOf('}');
          if (jsonStart === -1 || jsonEnd === -1) throw new Error('No JSON in response');
          cleaned = cleaned.slice(jsonStart, jsonEnd + 1);
          const parsed = JSON.parse(cleaned);
          const n = Number(query);
          const portNum = Number.isFinite(n) ? n : query;
          return respond({ ...parsed, port: portNum, source: 'groq' }, 200);
        } catch (err) {
          console.error('[port-intel parse error]', err.message, '\nRaw response:', portInfo?.slice(0, 200));
        }
      }
    }

    return respond({ error: 'Port not found — set GROQ_API_KEY for dynamic port intelligence' }, 404);
  }

  // ── Image-data route (raw buffer, streamed) ────────────────
  if (url.startsWith('/pcap/image-data') && method === 'GET') {
    const q = getQuery(url);
    if (!isValidSessionId(q.session_id)) return respond({ error: 'Invalid session_id' }, 400);
    const artifactKey = q.key || '';
    if (!artifactKey) return respond({ error: 'Missing key' }, 400);

    const sessionArtifacts = imageStore.get(q.session_id);
    if (!sessionArtifacts) return respond({ error: 'Session not found or expired' }, 404);

    const artifact = sessionArtifacts.get(artifactKey);
    if (!artifact) return respond({ error: 'Artifact not found' }, 404);

    res.writeHead(200, {
      'Content-Type': artifact.contentType,
      'Content-Length': artifact.buffer.length,
      'Content-Disposition': `inline; filename="${artifact.filename}"`,
      'Cache-Control': 'private, max-age=3600',
      ...getCorsHeaders(requestOrigin),
    });
    return res.end(artifact.buffer);
  }

  // ── Session liveness check ─────────────────────────────────
  if (url.startsWith('/pcap/ping-session') && method === 'GET') {
    const q = getQuery(url);
    if (!isValidSessionId(q.session_id)) return respond({ alive: false }, 200);
    return respond({ alive: sessions.has(q.session_id) }, 200);
  }

  // ── Final 404 fallback ─────────────────────────────────────
  respond({
    error: 'Not found',
    available_endpoints: [
      'GET  /pcap/health',
      'POST /pcap/upload',
      'GET  /pcap/packets?session_id=X',
      'GET  /pcap/vulnerabilities?session_id=X',
      'POST /pcap/agent/query',
      'GET  /pcap/images?session_id=X',
      'GET  /pcap/image-data?session_id=X&key=Y',
      'GET  /pcap/port-intel?query=X',
    ],
  }, 404);
});

const PORT = process.env.PORT || 4000;
server.listen(PORT, () => {
  console.log(`✅ PCAP Analyzer Backend running on port ${PORT}`);
  console.log(`🌐 CORS origin: ${ALLOWED_ORIGIN}`);
  console.log(`🤖 Groq AI: ${GROQ_API_KEY ? 'enabled ✅' : 'MISSING ❌ — set GROQ_API_KEY on Render'}`);
});

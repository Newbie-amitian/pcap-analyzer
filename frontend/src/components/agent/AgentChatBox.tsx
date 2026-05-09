"use client";

import { useState, useRef, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Send, Bot, User, Wrench, Loader2, Sparkles,
  Search, Shield, Network, FileSearch, AlertTriangle,
  Globe, Activity, Key, ChevronDown, ChevronUp,
  Download, X,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import type { ChatMessage, Packet } from "@/lib/types";
import { useAppStore } from "@/lib/store";
import { cn } from "@/lib/utils";
import ReactMarkdown from 'react-markdown';


const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "https://pcap-analyzer-backend.onrender.com";

// ── Simple Markdown Renderer ─────────────────────────────────────────
// ── Domain Grid renderer ─────────────────────────────────────────
// ── Domain Grid renderer ─────────────────────────────────────────
// ── Hash-based color for any string ─────────────────────────
function stringToColor(str: string): string {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = str.charCodeAt(i) + ((hash << 5) - hash);
  }
  const colors = [
    'text-cyan-400',
    'text-green-400',
    'text-orange-400',
    'text-violet-400',
    'text-blue-400',
    'text-pink-400',
    'text-amber-400',
    'text-red-400',
    'text-teal-400',
    'text-indigo-400',
  ];
  return colors[Math.abs(hash) % colors.length];
}

// ── Markdown renderer using react-markdown ───────────────────
function MarkdownMessage({ content }: { content: string }) {
  const API_BASE = process.env.NEXT_PUBLIC_API_URL;
  return (
    <ReactMarkdown
      components={{
        h3: ({ children }) => {
          const text = String(children);
          const color = stringToColor(text);
          return (
            <div className={`text-xs font-bold uppercase tracking-wider mt-3 mb-0.5 ${color}`}>
              {text}
            </div>
          );
        },
        h2: ({ children }) => (
          <div className="text-sm font-bold text-white mt-3 mb-1">
            {String(children)}
          </div>
        ),
        h1: ({ children }) => (
          <div className="text-base font-bold text-cyan-400 mt-3 mb-1">
            {String(children)}
          </div>
        ),
        p: ({ children }) => (
          <div className="text-xs font-mono text-gray-300 leading-relaxed mb-1">
            {children}
          </div>
        ),
        img: ({ src, alt }) => {
          const sessionId = useAppStore.getState().session?.session_id;
          const srcStr = typeof src === 'string' ? src : '';
          if (!srcStr) return null;
          const realSrc = srcStr.startsWith('IMAGE_URL_PLACEHOLDER:')
            ? `${API_BASE}/pcap/image-data?session_id=${sessionId}&artifact_key=${encodeURIComponent(srcStr.replace('IMAGE_URL_PLACEHOLDER:', ''))}`
            : srcStr;
          //console.log('[IMG]', { srcStr, realSrc, sessionId }); // remove after fixing
          return (
            <img
              src={realSrc}
              alt={alt || 'extracted image'}
              className="rounded-lg border border-white/10 max-w-full mt-2 mb-2"
              style={{ maxHeight: '300px', objectFit: 'contain' }}
            />
          );
        },
        strong: ({ children }) => (
          <strong className="font-bold text-white">{children}</strong>
        ),
        em: ({ children }) => (
          <em className="italic text-gray-300">{children}</em>
        ),
        code: ({ children }) => (
          <code className="bg-white/10 text-cyan-400 px-1.5 py-0.5 rounded text-xs font-mono">
            {children}
          </code>
        ),
        ul: ({ children }) => (
          <ul className="space-y-0.5 my-1">{children}</ul>
        ),
        li: ({ children }) => (
          <div className="flex gap-2 text-xs text-gray-300">
            <span className="text-cyan-400 flex-shrink-0 mt-0.5">•</span>
            <span>{children}</span>
          </div>
        ),
        ol: ({ children }) => (
          <ol className="space-y-0.5 my-1 list-decimal list-inside text-xs text-gray-300">
            {children}
          </ol>
        ),
        a: ({ children }) => (
          <span className="text-gray-300 font-mono">{children}</span>
        ),
        table: ({ children }) => (
          <div className="overflow-x-auto my-3">
            <table className="w-full text-xs border-collapse">{children}</table>
          </div>
        ),
        thead: ({ children }) => (
          <thead className="border-b border-white/20">{children}</thead>
        ),
        th: ({ children }) => (
          <th className="px-3 py-2 text-left text-cyan-400 font-semibold whitespace-nowrap bg-white/5">
            {children}
          </th>
        ),
        tbody: ({ children }) => <tbody>{children}</tbody>,
        tr: ({ children }) => (
          <tr className="border-b border-white/5 hover:bg-white/5 transition-colors">
            {children}
          </tr>
        ),
        td: ({ children }) => (
          <td className="px-3 py-1.5 text-gray-300 font-mono whitespace-nowrap">
            {children}
          </td>
        ),
      }}
    >
      {content}
    </ReactMarkdown>
  );
}

// ── Suggested prompts ─────────────────────────────────────────
const suggestedPrompts = [
  { icon: Search, text: "Summarize this capture", color: "text-cyan-400" },
  { icon: Shield, text: "Find credentials in traffic", color: "text-red-400" },
  { icon: Network, text: "Detect port scanning", color: "text-amber-400" },
  { icon: FileSearch, text: "Get vulnerability report", color: "text-violet-400" },
  { icon: Globe, text: "Show DNS queries", color: "text-green-400" },
  { icon: Activity, text: "Show top talkers", color: "text-pink-400" },
  { icon: Key, text: "Show packets on port 21", color: "text-orange-400" },
  { icon: AlertTriangle, text: "Show largest packets", color: "text-yellow-400" },
  { icon: Shield, text: "What HTTPS sites were visited", color: "text-blue-400" },
  { icon: Activity, text: "How much QUIC traffic is there", color: "text-purple-400" },
];

// ── Risk colour helper ────────────────────────────────────────
function riskColor(risk: string) {
  switch (risk?.toUpperCase()) {
    case "CRITICAL": return "text-red-400 bg-red-400/10 border-red-400/30";
    case "HIGH": return "text-orange-400 bg-orange-400/10 border-orange-400/30";
    case "MEDIUM": return "text-yellow-400 bg-yellow-400/10 border-yellow-400/30";
    default: return "text-green-400 bg-green-400/10 border-green-400/30";
  }
}

// ── Mini packet table (used for filter_by_port / filter_by_ip etc.) ──
function PacketResultTable({ packets }: { packets: Packet[] }) {
  const [expanded, setExpanded] = useState(false);
  const shown = expanded ? packets : packets.slice(0, 8);

  if (!packets.length) return (
    <p className="text-xs text-gray-500 mt-2">No packets matched.</p>
  );

  return (
    <div className="mt-3 rounded-lg overflow-hidden border border-white/10">
      {/* Header row */}
      <div className="grid grid-cols-[50px_1fr_1fr_80px_70px_60px] bg-[#0A0E1A] border-b border-white/10">
        {["#", "Src IP", "Dst IP", "Proto", "Port", "Len"].map(h => (
          <div key={h} className="px-2 py-1.5 text-xs font-medium text-gray-500 uppercase tracking-wider">{h}</div>
        ))}
      </div>
      {/* Data rows */}
      <div className="divide-y divide-white/5 max-h-56 overflow-y-auto">
        {shown.map((pkt, i) => (
          <div key={i} className="grid grid-cols-[50px_1fr_1fr_80px_70px_60px] hover:bg-white/5 transition-colors">
            <div className="px-2 py-1.5 text-xs font-mono text-gray-500">{pkt.id}</div>
            <div className="px-2 py-1.5 text-xs font-mono text-cyan-400 truncate">{pkt.src_ip ?? "—"}</div>
            <div className="px-2 py-1.5 text-xs font-mono text-amber-400 truncate">{pkt.dst_ip ?? "—"}</div>
            <div className="px-2 py-1.5">
              <Badge className="text-xs bg-violet-500/10 text-violet-400 border-violet-500/20">{pkt.protocol}</Badge>
            </div>
            <div className="px-2 py-1.5 text-xs font-mono text-gray-400">{pkt.dst_port ?? pkt.src_port ?? "—"}</div>
            <div className="px-2 py-1.5 text-xs font-mono text-gray-500">{pkt.length}</div>
          </div>
        ))}
      </div>
      {packets.length > 8 && (
        <button
          onClick={() => setExpanded(e => !e)}
          className="w-full flex items-center justify-center gap-1 py-1.5 text-xs text-gray-500 hover:text-cyan-400 bg-[#0A0E1A] border-t border-white/10 transition-colors"
        >
          {expanded ? <><ChevronUp className="w-3 h-3" /> Show less</> : <><ChevronDown className="w-3 h-3" /> Show all {packets.length} packets</>}
        </button>
      )}
    </div>
  );
}

// ── Top talkers table ─────────────────────────────────────────
function TopTalkersTable({ data }: { data: { ip: string; bytes: number }[] }) {
  if (!data.length) return null;
  const max = data[0].bytes;
  return (
    <div className="mt-3 space-y-2">
      {data.map((row, i) => (
        <div key={i} className="space-y-1">
          <div className="flex items-center justify-between text-xs">
            <span className="font-mono text-cyan-400">{row.ip}</span>
            <span className="text-gray-400">{(row.bytes / 1024).toFixed(1)} KB</span>
          </div>
          <div className="w-full bg-white/5 rounded-full h-1.5">
            <div
              className="h-1.5 rounded-full bg-gradient-to-r from-cyan-500 to-violet-500"
              style={{ width: `${(row.bytes / max) * 100}%` }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}

// ── DNS result ────────────────────────────────────────────────
function DnsResult({ data }: { data: { packets: Packet[]; top_domains: [string, number][] } }) {
  return (
    <div className="mt-3 space-y-3">
      {data.top_domains.length > 0 && (
        <div>
          <p className="text-xs text-gray-500 mb-2 uppercase tracking-wider">Top Domains</p>
          <div className="space-y-1">
            {data.top_domains.map(([domain, count], i) => (
              <div key={i} className="flex items-center justify-between bg-[#0A0E1A] rounded px-3 py-1.5 border border-white/5">
                <span className="text-xs font-mono text-green-400">{domain}</span>
                <Badge className="text-xs bg-green-500/10 text-green-400 border-green-500/20">{count}x</Badge>
              </div>
            ))}
          </div>
        </div>
      )}
      {data.packets?.length > 0 && (
        <PacketResultTable packets={data.packets} />
      )}
    </div>
  );
}

// ── Vulnerability result ──────────────────────────────────────
function VulnResult({ data }: { data: { port: number; count: number; risk: string; reason: string }[] }) {
  if (!data.length) return <p className="text-xs text-gray-500 mt-2">No vulnerable ports detected.</p>;
  return (
    <div className="mt-3 space-y-2">
      {data.map((v, i) => (
        <div key={i} className={cn("rounded-lg px-3 py-2 border text-xs", riskColor(v.risk))}>
          <div className="flex items-center justify-between mb-1">
            <span className="font-mono font-bold">Port {v.port}</span>
            <Badge className={cn("text-xs border", riskColor(v.risk))}>{v.risk}</Badge>
          </div>
          <p className="text-gray-400">{v.reason}</p>
          <p className="text-gray-500 mt-0.5">{v.count} packet{v.count !== 1 ? "s" : ""}</p>
        </div>
      ))}
    </div>
  );
}

// ── Port scan result ──────────────────────────────────────────
function PortScanResult({ data }: { data: { ip: string; ports_scanned: number; ports: number[] }[] }) {
  if (!data.length) return <p className="text-xs text-green-400 mt-2">✓ No port scanning detected.</p>;
  return (
    <div className="mt-3 space-y-2">
      {data.map((s, i) => (
        <div key={i} className="rounded-lg border border-red-500/30 bg-red-500/5 px-3 py-2">
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs font-mono text-red-400">{s.ip}</span>
            <Badge className="text-xs bg-red-500/10 text-red-400 border-red-500/20">{s.ports_scanned} ports</Badge>
          </div>
          <p className="text-xs text-gray-500 font-mono truncate">
            Ports: {s.ports.slice(0, 15).join(", ")}{s.ports.length > 15 ? "…" : ""}
          </p>
        </div>
      ))}
    </div>
  );
}

// ── Credential result ─────────────────────────────────────────
function CredentialResult({ packets }: { packets: Packet[] }) {
  if (!packets.length) return <p className="text-xs text-green-400 mt-2">✓ No plaintext credentials found.</p>;
  return (
    <div className="mt-3 space-y-2">
      {packets.slice(0, 10).map((pkt, i) => (
        <div key={i} className="rounded-lg border border-red-500/40 bg-red-500/5 px-3 py-2">
          <div className="flex items-center gap-2 mb-1">
            <Badge className="text-xs bg-red-500/10 text-red-400 border-red-500/20">CRITICAL</Badge>
            <span className="text-xs font-mono text-gray-400">{pkt.src_ip} → {pkt.dst_ip}</span>
          </div>
          {pkt.payload_preview && (
            <code className="text-xs text-red-300 bg-black/30 rounded px-2 py-1 block truncate font-mono">
              {pkt.payload_preview.slice(0, 120)}
            </code>
          )}
        </div>
      ))}
    </div>
  );
}

// ── Summary result ────────────────────────────────────────────
function SummaryResult({ data }: { data: { total_packets: number; protocols: Record<string, number>; top_ips: { ip: string; bytes: number }[]; total_bytes: number; duration_seconds: number } }) {
  const sortedProtos = Object.entries(data.protocols).sort((a, b) => b[1] - a[1]);
  return (
    <div className="mt-3 space-y-3">
      {/* Stats row */}
      <div className="grid grid-cols-3 gap-2">
        {[
          { label: "Packets", value: data.total_packets.toLocaleString() },
          { label: "Duration", value: `${data.duration_seconds}s` },
          { label: "Total Size", value: `${(data.total_bytes / 1024).toFixed(1)} KB` },
        ].map(({ label, value }) => (
          <div key={label} className="bg-[#0A0E1A] rounded-lg border border-white/5 p-2 text-center">
            <p className="text-xs text-gray-500">{label}</p>
            <p className="text-sm font-bold text-white font-mono">{value}</p>
          </div>
        ))}
      </div>
      {/* Protocol breakdown */}
      <div>
        <p className="text-xs text-gray-500 mb-1.5 uppercase tracking-wider">Protocols</p>
        <div className="flex flex-wrap gap-1.5">
          {sortedProtos.map(([proto, count]) => (
            <Badge key={proto} className="text-xs bg-cyan-500/10 text-cyan-400 border-cyan-500/20">
              {proto} <span className="ml-1 text-gray-500">{count}</span>
            </Badge>
          ))}
        </div>
      </div>
      {/* Top IPs */}
      {data.top_ips?.length > 0 && (
        <div>
          <p className="text-xs text-gray-500 mb-2 uppercase tracking-wider">Top IPs</p>
          <TopTalkersTable data={data.top_ips} />
        </div>
      )}
    </div>
  );
}

// ── Smart result renderer — picks the right component ────────
// ── TLS SNI result ────────────────────────────────────────────
function TlsSniResult({ data }: { data: { sni_list: [string, number][]; categories: { browsing: string[]; microsoft: string[]; advertising: string[]; other: string[] }; total: number } }) {
  if (!data.sni_list.length) return <p className="text-xs text-gray-500 mt-2">No TLS SNI names found.</p>;

  const buckets: { key: keyof typeof data.categories; label: string; color: string; bg: string }[] = [
    { key: 'browsing', label: '🌍 Browsing', color: 'text-green-400', bg: 'border-green-500/20' },
    { key: 'microsoft', label: '🔵 Microsoft Services', color: 'text-blue-400', bg: 'border-blue-500/20' },
    { key: 'advertising', label: '📢 Advertising / Tracking', color: 'text-orange-400', bg: 'border-orange-500/20' },
    { key: 'other', label: '🔒 Other', color: 'text-gray-400', bg: 'border-gray-500/20' },
  ];

  const nonEmpty = buckets.filter(b => data.categories[b.key].length > 0);

  return (
    <div className="mt-3 space-y-2">
      <p className="text-xs text-gray-500">{data.total} unique HTTPS destinations</p>

      {/* Grid: 2 columns on wider, 1 on narrow */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {nonEmpty.map(({ key, label, color, bg }) => (
          <div key={key} className={`rounded-lg border ${bg} bg-white/[0.02] p-3`}>
            <p className={`text-xs font-semibold mb-2 ${color}`}>{label}</p>
            <div className="space-y-1">
              {data.categories[key].map((domain, i) => (
                <div key={i} className="text-xs font-mono text-gray-300 truncate py-0.5 border-b border-white/5 last:border-0">
                  {domain}
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── QUIC result ───────────────────────────────────────────────
function QuicResult({ data }: { data: { total: number; ipv4_count: number; ipv6_count: number; sample: Packet[] } }) {
  if (!data.total) return <p className="text-xs text-gray-500 mt-2">No QUIC traffic detected.</p>;
  return (
    <div className="mt-3 space-y-3">
      <div className="grid grid-cols-3 gap-2">
        {[
          { label: 'Total QUIC', value: data.total.toLocaleString() },
          { label: 'Over IPv6', value: data.ipv6_count.toLocaleString() },
          { label: 'Over IPv4', value: data.ipv4_count.toLocaleString() },
        ].map(({ label, value }) => (
          <div key={label} className="bg-[#0A0E1A] rounded-lg border border-white/5 p-2 text-center">
            <p className="text-xs text-gray-500">{label}</p>
            <p className="text-sm font-bold text-white font-mono">{value}</p>
          </div>
        ))}
      </div>
      {data.sample?.length > 0 && <PacketResultTable packets={data.sample} />}
    </div>
  );
}

// ── Raw tshark stat output renderer ──────────────────────────
function StatResult({ data }: { data: { raw_text: string } }) {
  if (!data?.raw_text?.trim()) return <p className="text-xs text-gray-500 mt-2">No stat data returned.</p>;
  return (
    <div className="mt-3 rounded-lg bg-[#0A0E1A] border border-white/10 p-3 overflow-x-auto">
      <pre className="text-xs font-mono text-gray-300 whitespace-pre">{data.raw_text}</pre>
    </div>
  );
}

// ── Smart result renderer — picks the right component ────────
function ResultRenderer({ toolCalled, result }: { toolCalled: string; result: unknown }) {
  if (!result) return null;

  // ── CHAT TOOL - Natural conversation (no data to render) ─────
  if (toolCalled === "chat") {
    return null; // Just show the text response
  }

  // ── NEW tshark backend tool names ──────────────────────────
  // tool: 'stat' → raw tshark stat text
  if (toolCalled === "stat" && typeof result === "object" && result !== null) {
    return <StatResult data={result as { raw_text: string }} />;
  }

  // tool: 'vuln' → array of {port, count, risk, reason}
  if (toolCalled === "vuln" && Array.isArray(result)) {
    return <VulnResult data={result as { port: number; count: number; risk: string; reason: string }[]} />;
  }

  // tool: 'packets' → array of Packet objects
  if (toolCalled === "packets" && Array.isArray(result)) {
    return <PacketResultTable packets={result as Packet[]} />;
  }

  // ── Legacy AI-era tool names (kept for backwards compat) ───
  const packetArrayTools = ["filter_by_port", "filter_by_ip", "filter_by_protocol", "filter_large_packets", "domain_lookup"];
  if (packetArrayTools.includes(toolCalled) && Array.isArray(result)) {
    return <PacketResultTable packets={result as Packet[]} />;
  }

  if (toolCalled === "domain_lookup" && typeof result === "object" && result !== null) {
    const r = result as { domain_packets: Packet[]; dns_hits: Packet[]; total_hits: number };
    return <PacketResultTable packets={r.domain_packets ?? []} />;
  }

  if (toolCalled === "find_credentials" && Array.isArray(result)) {
    return <CredentialResult packets={result as Packet[]} />;
  }

  if (toolCalled === "get_top_talkers" && Array.isArray(result)) {
    return <TopTalkersTable data={result as { ip: string; bytes: number }[]} />;
  }

  if (toolCalled === "get_dns_queries" && typeof result === "object" && result !== null) {
    return <DnsResult data={result as { packets: Packet[]; top_domains: [string, number][] }} />;
  }

  if (toolCalled === "get_vulnerability_report" && Array.isArray(result)) {
    return <VulnResult data={result as { port: number; count: number; risk: string; reason: string }[]} />;
  }

  if (toolCalled === "detect_port_scan" && Array.isArray(result)) {
    return <PortScanResult data={result as { ip: string; ports_scanned: number; ports: number[] }[]} />;
  }

  if (toolCalled === "get_summary" && typeof result === "object" && result !== null) {
    return <SummaryResult data={result as { total_packets: number; protocols: Record<string, number>; top_ips: { ip: string; bytes: number }[]; total_bytes: number; duration_seconds: number }} />;
  }

  if (toolCalled === "get_tls_sni" && typeof result === "object" && result !== null) {
    return <TlsSniResult data={result as { sni_list: [string, number][]; categories: { browsing: string[]; microsoft: string[]; advertising: string[]; other: string[] }; total: number }} />;
  }

  if (toolCalled === "get_quic_traffic" && typeof result === "object" && result !== null) {
    return <QuicResult data={result as { total: number; ipv4_count: number; ipv6_count: number; sample: Packet[] }} />;
  }

  return null;
}

// ── API call with STREAMING support ──────────────────────────────────────────────────
async function callAgent(prompt: string, sessionId: string, history: ChatMessage[]) {
  // Serialize only the last 10 messages as {role, content} for backend
  const serializedHistory = history.slice(-10).map(m => ({
    role: m.role,
    content: m.content,
  }));

  const res = await fetch(`${API_BASE}/pcap/agent/query`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ prompt, session_id: sessionId, history: serializedHistory }),
  });
  if (res.status === 404) {
    useAppStore.setState({ session: null, activeView: 'upload' });
    throw new Error('SESSION_EXPIRED');
  }
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Backend error ${res.status}: ${text}`);
  }
  const data = await res.json();
  if (!data?.response) throw new Error("Invalid backend response");
  return data;
}

// ── Streaming API call (ChatGPT-style) ──────────────────────────────────────────────────
async function callAgentStream(
  prompt: string,
  sessionId: string,
  onToken: (token: string) => void,
  onComplete: () => void,
  onError: (error: string) => void,
  onProvider?: (provider: string) => void
) {
  try {
    const recentHistory = useAppStore.getState().chatMessages
      .slice(-6)
      .map(m => `${m.role === 'user' ? 'User' : 'Assistant'}: ${m.content}`)
      .join('\n');

    const res = await fetch(`${API_BASE}/pcap/agent/stream`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ prompt, session_id: sessionId, history: recentHistory }),
    });

    if (res.status === 404) {
      useAppStore.setState({ session: null, activeView: 'upload' });
      onError('SESSION_EXPIRED');
      return;
    }
    if (!res.ok) {
      const text = await res.text();
      onError(`Backend error ${res.status}: ${text}`);
      return;
    }

    const reader = res.body?.getReader();
    if (!reader) {
      onError('No response stream');
      return;
    }

    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });

      // Process SSE lines
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';

      for (const line of lines) {
        if (line.startsWith('data: ')) {
          const data = line.slice(6).trim();
          if (data === '[DONE]') {
            onComplete();
            return;
          }
          try {
            const json = JSON.parse(data);
            if (json.provider) {
              onProvider?.(json.provider);
            } else if (json.token) {
              onToken(json.token);
            } else if (json.error) {
              onError(json.error);
              return;
            }
          } catch (e) {
            // Non-JSON line, skip
          }
        }
      }
    }

    onComplete();
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'Unknown error';
    onError(msg);
  }
}

// ── Main component ────────────────────────────────────────────
// ── Auto Image Preview ─────────────────────────────────────────
function AutoImagePreview({ content, sessionId }: { content: string; sessionId: string }) {
  const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "https://pcap-analyzer-backend.onrender.com";

  const match = content.match(/(?:preview of|here'?s?|pulled from traffic[:\s]+)\*?\*?([^\s*]+\.(jpg|jpeg|png|gif|webp|svg))\*?\*?/i)
    || content.match(/([^\s*]+\.(jpg|jpeg|png|gif|webp|svg))/i);

  if (!match) return null;

  const filename = match[1];
  const src = `${API_BASE}/pcap/image-data?session_id=${sessionId}&artifact_key=${encodeURIComponent(filename)}`;

  return (
    <div className="mt-3">
      <img
        src={src}
        alt={filename}
        className="rounded-lg border border-white/10 max-w-full"
        style={{ maxHeight: '300px', objectFit: 'contain' }}
        onError={(e) => { (e.target as HTMLImageElement).style.display = 'none'; }}
      />
      <p className="text-xs text-gray-500 mt-1 font-mono">{filename}</p>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────

export function AgentChatBox() {
  const { session, chatMessages: messages, setChatMessages: setMessages, clearChatMessages, isAgentStreaming, streamingMessageId } = useAppStore();
  const [input, setInput] = useState("");
  const [activeProvider, setActiveProvider] = useState<'nvidia' | 'groq' | null>(null);
  const isLoading = isAgentStreaming;
  const streamingContent = streamingMessageId
    ? (messages.find(m => m.id === streamingMessageId)?.content ?? "")
    : "";
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, streamingContent]);

  const isDemo = session?.session_id?.startsWith("demo-");

  const handleSend = async (overridePrompt?: string) => {
    const query = (overridePrompt ?? input).trim();
    if (!query || isLoading) return;

    const userMsg: ChatMessage = {
      id: Date.now().toString(),
      role: "user",
      content: query,
      timestamp: new Date().toISOString(),
    };
    setMessages([...useAppStore.getState().chatMessages, userMsg]);
    setInput("");

    if (!session?.session_id || isDemo) {
      setMessages([...useAppStore.getState().chatMessages, {
        id: (Date.now() + 1).toString(),
        role: "assistant",
        content: "Upload a real .pcap file first — demo mode has no traffic data to analyse.",
        toolCalled: "demo_mode",
        toolParams: {},
        timestamp: new Date().toISOString(),
      }]);
      return;
    }

    const assistantMsgId = (Date.now() + 1).toString();
    let fullContent = "";

    const placeholderMsgs = [...useAppStore.getState().chatMessages, {
      id: assistantMsgId,
      role: "assistant" as const,
      content: "",
      toolCalled: "llm",
      toolParams: {},
      timestamp: new Date().toISOString(),
    }];
    setMessages(placeholderMsgs);
    useAppStore.setState({ isAgentStreaming: true, streamingMessageId: assistantMsgId });

    // Fire and forget — survives page switches
    callAgentStream(
      query,
      session.session_id,
      (token) => {
        fullContent += token;
        const currentMsgs = useAppStore.getState().chatMessages;
        const updatedMsgs = currentMsgs.map(m =>
          m.id === assistantMsgId ? { ...m, content: fullContent } : m
        );
        useAppStore.getState().setChatMessages(updatedMsgs);
      },
      () => {
        useAppStore.setState({ isAgentStreaming: false, streamingMessageId: null });
      },
      (error) => {
        if (error === 'SESSION_EXPIRED') return;
        const currentMsgs = useAppStore.getState().chatMessages;
        const updatedMsgs = currentMsgs.map(m =>
          m.id === assistantMsgId ? { ...m, content: `Error: ${error}` } : m
        );
        useAppStore.getState().setChatMessages(updatedMsgs);
        useAppStore.setState({ isAgentStreaming: false, streamingMessageId: null });
      },
      (provider) => {
        setActiveProvider(provider as 'nvidia' | 'groq');
      }
    );
  };
  return (
    <Card className="bg-[#0D1117]/60 backdrop-blur-sm border border-white/5 flex flex-col h-[calc(100vh-120px)]">
      {/* Header */}
      <CardHeader className="pb-3 flex-shrink-0 border-b border-white/5">
        <div className="flex items-center justify-between">
          <CardTitle className="text-white text-lg flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-violet-400 animate-pulse" />
            AI Security Agent
          </CardTitle>
          <div className="flex items-center gap-2">
            {isDemo && (
              <Badge className="bg-amber-500/10 text-amber-400 border-amber-500/20 text-xs">
                Demo Mode
              </Badge>
            )}
            <Badge variant="outline" className="border-cyan-500/30 text-cyan-400 text-xs">
              <Sparkles className="w-3 h-3 mr-1" />
              TShark Engine
            </Badge>
            {activeProvider === 'nvidia' && (
              <Badge className="bg-green-500/10 text-green-400 border-green-500/20 text-xs">
                <span className="w-1.5 h-1.5 rounded-full bg-green-400 mr-1.5 animate-pulse inline-block" />
                NVIDIA NIM
              </Badge>
            )}
            {activeProvider === 'groq' && (
              <Badge className="bg-orange-500/10 text-orange-400 border-orange-500/20 text-xs">
                <span className="w-1.5 h-1.5 rounded-full bg-orange-400 mr-1.5 animate-pulse inline-block" />
                Groq
              </Badge>
            )}
            {messages.length > 0 && (
              <>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-7 text-xs text-gray-400 hover:text-white border border-white/10 hover:bg-white/5"
                  onClick={() => {
                    const text = messages.map(m =>
                      `[${new Date(m.timestamp).toLocaleTimeString()}] ${m.role === 'user' ? 'You' : 'Agent'}: ${m.content}`
                    ).join('\n\n');
                    const blob = new Blob([text], { type: 'text/plain' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `packetsight-chat-${Date.now()}.txt`;
                    a.click();
                    URL.revokeObjectURL(url);
                  }}
                >
                  <Download className="w-3 h-3 mr-1" />
                  Export
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-7 text-xs text-red-400 hover:text-red-300 border border-red-500/20 hover:bg-red-500/10"
                  onClick={() => clearChatMessages()}
                >
                  <X className="w-3 h-3 mr-1" />
                  Clear
                </Button>
              </>
            )}
          </div>
        </div>
      </CardHeader>

      <CardContent className="flex-1 flex flex-col overflow-hidden p-0 min-h-0">

        {/* Messages scroll area */}
        <ScrollArea className="flex-1 px-4 min-h-0">
          <div className="space-y-4 py-4">

            {messages.length === 0 && (
              <div className="text-center py-8">
                <Bot className="w-12 h-12 text-violet-400/30 mx-auto mb-3" />
                <p className="text-gray-500 text-sm">Upload a PCAP then ask me anything about the traffic.</p>
                <p className="text-gray-600 text-xs mt-1">I'll run tools and show you real data — not just text.</p>
              </div>
            )}

            <AnimatePresence>
              {messages.map((msg) => (
                <motion.div
                  key={msg.id}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.2 }}
                  className={cn("flex gap-3", msg.role === "user" && "justify-end")}
                >
                  {msg.role === "assistant" && (
                    <div className="w-8 h-8 rounded-lg bg-violet-500/20 flex items-center justify-center flex-shrink-0 mt-0.5">
                      <Bot className="w-4 h-4 text-violet-400" />
                    </div>
                  )}

                  <div className={cn(
                    "rounded-xl px-4 py-3 max-w-[85%]",
                    msg.role === "user"
                      ? "bg-cyan-500/15 border border-cyan-500/25"
                      : "bg-[#0A0E1A] border border-white/5 w-full"
                  )}>
                    {/* Tool badge */}
                    {msg.role === "assistant" && msg.toolCalled && msg.toolCalled !== "demo_mode" && (
                      <div className="flex items-center gap-2 mb-2 pb-2 border-b border-white/10">
                        <Wrench className="w-3 h-3 text-violet-400" />
                        <span className="text-xs text-violet-400 font-mono">{msg.toolCalled}</span>
                        {msg.toolParams && Object.keys(msg.toolParams).length > 0 && (
                          <code className="text-xs text-gray-500 bg-white/5 px-1.5 py-0.5 rounded font-mono">
                            {JSON.stringify(msg.toolParams)}
                          </code>
                        )}
                      </div>
                    )}

                    {/* Text response with Markdown rendering */}
                    <div className="text-sm text-gray-200 leading-relaxed">
                      <MarkdownMessage
                        content={
                          isLoading && streamingContent && msg.content === streamingContent
                            ? msg.content + '▋'
                            : msg.content
                        }
                      />
                    </div>

                    {/* Auto image preview */}
                    {msg.role === "assistant" && !isLoading && session?.session_id && (
                      <AutoImagePreview content={msg.content} sessionId={session.session_id} />
                    )}

                    {/* ── Wireshark-style data result ── */}
                    {msg.role === "assistant" && msg.toolCalled && msg.result !== undefined && (
                      <ResultRenderer toolCalled={msg.toolCalled} result={msg.result} />
                    )}

                    {/* ── AI-suggested follow-up ── */}
                    {msg.role === "assistant" && msg.followup && (
                      <button
                        onClick={() => handleSend(msg.followup!)}
                        disabled={isLoading}
                        className="mt-3 w-full text-left text-xs text-violet-400 border border-violet-500/25 bg-violet-500/8 hover:bg-violet-500/15 rounded-lg px-3 py-2 transition-colors flex items-center gap-2"
                      >
                        <Sparkles className="w-3 h-3 flex-shrink-0" />
                        <span>{msg.followup}</span>
                      </button>
                    )}

                    <p className="text-xs text-gray-600 mt-2">
                      {new Date(msg.timestamp).toLocaleTimeString()}
                    </p>
                  </div>

                  {msg.role === "user" && (
                    <div className="w-8 h-8 rounded-lg bg-cyan-500/20 flex items-center justify-center flex-shrink-0 mt-0.5">
                      <User className="w-4 h-4 text-cyan-400" />
                    </div>
                  )}
                </motion.div>
              ))}
            </AnimatePresence>

            {/* Loading bubble - only show when waiting for first token */}
            {isLoading && !streamingContent && (
              <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex gap-3">
                <div className="w-8 h-8 rounded-lg bg-violet-500/20 flex items-center justify-center flex-shrink-0">
                  <Bot className="w-4 h-4 text-violet-400" />
                </div>
                <div className="bg-[#0A0E1A] border border-white/5 rounded-xl px-4 py-3">
                  <div className="flex items-center gap-2">
                    <Loader2 className="w-4 h-4 text-violet-400 animate-spin" />
                    <span className="text-sm text-gray-400">Thinking…</span>
                  </div>
                </div>
              </motion.div>
            )}

            <div ref={bottomRef} />
          </div>
        </ScrollArea>

        {/* Quick prompts */}
        {messages.length <= 2 && (
          <div className="px-4 py-3 border-t border-white/5 flex-shrink-0">
            <p className="text-xs text-gray-600 mb-2">Quick prompts:</p>
            <div className="flex flex-wrap gap-1.5">
              {suggestedPrompts.map((p, i) => (
                <Button
                  key={i}
                  variant="outline"
                  size="sm"
                  className={cn("h-7 text-xs border-white/10 hover:bg-white/5", p.color)}
                  onClick={() => handleSend(p.text)}
                  disabled={isLoading}
                >
                  <p.icon className="w-3 h-3 mr-1" />
                  {p.text}
                </Button>
              ))}
            </div>
          </div>
        )}

        {/* Input bar */}
        <div className="px-4 py-3 border-t border-white/5 flex-shrink-0">
          <div className="flex gap-2">
            <Input
              placeholder="Ask anything — ports, IPs, credentials, DNS, scans…"
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => e.key === "Enter" && handleSend()}
              className="bg-[#0A0E1A] border-white/10 text-white focus:border-violet-500/50 text-sm"
              disabled={isLoading}
            />
            <Button
              onClick={() => handleSend()}
              disabled={!input.trim() || isLoading}
              className="bg-gradient-to-r from-cyan-600 to-violet-600 hover:from-cyan-500 hover:to-violet-500 flex-shrink-0"
            >
              {isLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
            </Button>
          </div>
        </div>

      </CardContent>
    </Card>
  );
}
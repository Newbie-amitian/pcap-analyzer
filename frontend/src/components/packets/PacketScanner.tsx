"use client";

import { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Download, ZoomIn, X, Loader2, AlertTriangle,
  RefreshCw, FileText, FileCode, FileImage, File,
  Search, Globe, Archive,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import type { HttpObject } from "@/lib/types";
import { useAppStore } from "@/lib/store";
import { cn } from "@/lib/utils";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "https://pcap-analyzer-backend.onrender.com";

// ── Protocol tab definitions — mirrors Wireshark Export Objects ──
const PROTOCOL_TABS = [
  { id: "all", label: "All", exportType: "all" },
  { id: "http", label: "HTTP", exportType: "http" },
  { id: "http2", label: "HTTP2", exportType: "http2" },
  { id: "smb", label: "SMB", exportType: "smb" },
  { id: "smb2", label: "SMB2", exportType: "smb2" },
  { id: "ftp-data", label: "FTP-DATA", exportType: "ftp-data" },
  { id: "tftp", label: "TFTP", exportType: "tftp" },
  { id: "dicom", label: "DICOM", exportType: "dicom" },
  { id: "imf", label: "IMF", exportType: "imf" },
] as const;

type ProtocolTabId = typeof PROTOCOL_TABS[number]["id"];

// ── Helpers ───────────────────────────────────────────────────────
function formatBytes(bytes: number) {
  if (bytes >= 1048576) return `${(bytes / 1048576).toFixed(2)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
}

function getFileIcon(contentType: string) {
  if (contentType.startsWith("image/")) return FileImage;
  if (contentType.includes("html")) return FileCode;
  if (contentType.includes("javascript") || contentType.includes("css")) return FileCode;
  if (contentType.includes("json") || contentType.includes("xml")) return FileText;
  return File;
}

function getTypeTextColor(contentType: string) {
  if (contentType.startsWith("image/")) return "text-green-400";
  if (contentType.includes("html")) return "text-orange-400";
  if (contentType.includes("javascript")) return "text-yellow-400";
  if (contentType.includes("css")) return "text-blue-400";
  if (contentType.includes("json")) return "text-violet-400";
  if (contentType.includes("x-www-form-urlencoded")) return "text-pink-400";
  return "text-gray-400";
}

function getProtoColor(exportType: string) {
  const map: Record<string, string> = {
    "http": "text-cyan-400 bg-cyan-400/10 border-cyan-400/20",
    "http2": "text-cyan-300 bg-cyan-300/10 border-cyan-300/20",
    "smb": "text-amber-400 bg-amber-400/10 border-amber-400/20",
    "smb2": "text-amber-300 bg-amber-300/10 border-amber-300/20",
    "ftp-data": "text-pink-400 bg-pink-400/10 border-pink-400/20",
    "tftp": "text-purple-400 bg-purple-400/10 border-purple-400/20",
    "dicom": "text-green-400 bg-green-400/10 border-green-400/20",
    "imf": "text-blue-400 bg-blue-400/10 border-blue-400/20",
  };
  return map[exportType] ?? "text-gray-400 bg-gray-400/10 border-gray-400/20";
}

function artifactUrl(sessionId: string | undefined, key: string | null | undefined) {
  if (!sessionId || !key) return null;
  return `${API_BASE}/pcap/image-data?session_id=${encodeURIComponent(sessionId)}&key=${encodeURIComponent(key)}`;
}

// ── Main component ────────────────────────────────────────────────
export function PacketScanner() {
  const {
    session, setSession,
    scannedObjects: objects,
    setScannedObjects: setObjects,
    scanHasLoaded: hasLoaded,
    setScanHasLoaded: setHasLoaded,
  } = useAppStore();

  const [activeProto, setActiveProto] = useState<ProtocolTabId>("all");
  const [typeFilter, setTypeFilter] = useState<string>("all");
  const [search, setSearch] = useState("");
  const [sortCol, setSortCol] = useState<string | null>(null);
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");

  const handleSort = (col: string) => {
    if (sortCol === col) setSortDir(d => d === "asc" ? "desc" : "asc");
    else { setSortCol(col); setSortDir("asc"); }
  };
  const [selected, setSelected] = useState<HttpObject | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isZipping, setIsZipping] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tcpStream, setTcpStream] = useState<any>(null);
  const [tcpStreamLoading, setTcpStreamLoading] = useState(false);

  const fetchTcpStream = async (obj: HttpObject) => {
    if (obj.tcp_stream === null || obj.tcp_stream === undefined) return;
    setTcpStreamLoading(true);
    setTcpStream(null);
    try {
      const res = await fetch(`${API_BASE}/pcap/tcp-stream?session_id=${session?.session_id}&stream=${obj.tcp_stream}`);
      const data = await res.json();
      setTcpStream(data);
    } catch (e) {
      console.error(e);
    } finally {
      setTcpStreamLoading(false);
    }
  };

  const isDemo = session?.session_id?.startsWith("demo-");

  // ── Filtered view ─────────────────────────────────────────────
  const filtered = objects.filter(o => {
    const protoMatch = activeProto === "all" || o.export_type === activeProto;
    if (!protoMatch) return false;
    const typeMatch = typeFilter === "all" || o.content_type === typeFilter;
    if (!typeMatch) return false;
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    return o.filename.toLowerCase().includes(q);
  });

  const sorted = [...filtered].sort((a, b) => {
    if (!sortCol) return 0;
    const dir = sortDir === "asc" ? 1 : -1;
    switch (sortCol) {
      case "Packet": return (a.packet_num - b.packet_num) * dir;
      case "Protocol": return a.export_type.localeCompare(b.export_type) * dir;
      case "Hostname": return (a.hostname ?? "").localeCompare(b.hostname ?? "") * dir;
      case "Filename": return a.filename.localeCompare(b.filename) * dir;
      case "Content-Type": return a.content_type.localeCompare(b.content_type) * dir;
      case "Size": return (a.size - b.size) * dir;
      default: return 0;
    }
  });

  // ── Count per protocol tab ────────────────────────────────────
  const countFor = (tabId: ProtocolTabId) =>
    tabId === "all"
      ? objects.length
      : objects.filter(o => o.export_type === tabId).length;

  // ── Fetch objects from backend ────────────────────────────────
  const handleExtract = useCallback(async () => {
    if (!session?.session_id) return;
    if (isDemo) {
      setError("Demo mode — upload a real PCAP to extract objects.");
      setHasLoaded(true);
      return;
    }
    if (!session?.summary) {
      setError("Analysis still in progress. Please wait for it to complete before extracting objects.");
      return;
    }

    setIsLoading(true);
    setError(null);

    for (let attempt = 0; attempt < 20; attempt++) {
      try {
        const res = await fetch(`${API_BASE}/pcap/objects?session_id=${session.session_id}`);

        if (res.status === 202) {
          await new Promise(r => setTimeout(r, 5000));
          continue;
        }
        if (res.status === 404) {
          setError("Session expired — please re-upload your PCAP file.");
          setHasLoaded(true);
          setIsLoading(false);
          return;
        }
        if (!res.ok) {
          const err = await res.json().catch(() => ({ error: "Extraction failed" }));
          throw new Error(err.error ?? `HTTP ${res.status}`);
        }

        const data = await res.json();

        if (data.objects?.length > 0) {
          console.log("[PacketScanner] First object raw from backend:", JSON.stringify(data.objects[0], null, 2));
        }

        const extracted: HttpObject[] = (data.objects ?? []).map((obj: any) => {
          const pick = (...vals: any[]) => {
            for (const v of vals) {
              const s = String(v ?? "").trim();
              if (s && s !== "Not present" && s !== "unknown" && s !== "0") return s;
            }
            return "";
          };
          const pickNum = (...vals: any[]) => {
            for (const v of vals) {
              if (v === null || v === undefined || v === "") continue;
              const n = Number(v);
              if (!isNaN(n) && n > 0) return n;
            }
            return 0;
          };

          const contentType = (obj.content_type || "application/octet-stream").split(";")[0].trim();

          return {
            filename: obj.filename || "unknown",
            export_type: obj.export_type || "http",
            request_uri: pick(obj.request_uri, obj.uri, obj.full_uri),
            hostname: pick(obj.hostname, obj.host, obj.dst_ip),
            url: obj.artifact_key ? artifactUrl(session?.session_id, obj.artifact_key) : null,
            size: pickNum(obj.size, obj.content_length),
            content_type: contentType,
            method: pick(obj.method),
            src_ip: pick(obj.src_ip),
            dst_ip: pick(obj.dst_ip),
            src_port: obj.src_port ? Number(obj.src_port) : 0,
            dst_port: obj.dst_port ? Number(obj.dst_port) : 0,
            packet_num: obj.packet_num ? Number(obj.packet_num) : (obj.frame_number ? Number(obj.frame_number) : 0),
            tcp_stream: obj.tcp_stream !== undefined && obj.tcp_stream !== null ? obj.tcp_stream : null,
            is_image: contentType.startsWith("image/"),
            ftp_filename: obj.ftp_filename || "",
            smb_filename: obj.smb_filename || "",
            smb_path: obj.smb_path || "",
            tftp_filename: obj.tftp_filename || "",
          } as HttpObject;
        });

        console.log("[PacketScanner] All extracted objects:", JSON.stringify(extracted, null, 2));
        setObjects(extracted);
        setHasLoaded(true);
        if (session) setSession({ ...session, images: extracted });
        setIsLoading(false);
        return;

      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : "Unknown error");
        setHasLoaded(true);
        setIsLoading(false);
        return;
      }
    }
    setError("Export timed out. Try re-scanning.");
    setHasLoaded(true);
    setIsLoading(false);
  }, [session, isDemo]);

  // ── Save All as ZIP ───────────────────────────────────────────
  const handleSaveAll = async () => {
    if (!session?.session_id) return;
    setIsZipping(true);
    try {
      const typeParam = activeProto === "all" ? "all" : activeProto;
      const zipUrl = `${API_BASE}/pcap/objects/zip?session_id=${encodeURIComponent(session.session_id)}&type=${typeParam}`;
      const res = await fetch(zipUrl);
      if (!res.ok) throw new Error(`ZIP failed: ${res.status}`);
      const blob = await res.blob();
      const blobUrl = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = blobUrl;
      link.download = `objects-${activeProto}.zip`;
      link.click();
      URL.revokeObjectURL(blobUrl);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setIsZipping(false);
    }
  };

  // ── Loading ───────────────────────────────────────────────────
  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center h-64 gap-4">
        <Loader2 className="w-10 h-10 text-cyan-400 animate-spin" />
        <p className="text-gray-400 font-medium">Reassembling TCP streams...</p>
        <p className="text-gray-600 text-sm">Extracting objects from HTTP, SMB, FTP, TFTP, DICOM, IMF</p>
      </div>
    );
  }

  // ── Render ────────────────────────────────────────────────────
  return (
    <div className="space-y-0 border border-white/10 rounded-lg overflow-hidden bg-[#0D1117]">

      {/* ── Wireshark-style title bar ─────────────────────────── */}
      <div className="flex items-center justify-between px-4 py-2 bg-[#0A0E1A] border-b border-white/10">
        <CardTitle className="text-white flex items-center gap-2 text-sm">
          <Globe className="w-4 h-4 text-cyan-400" />
          Export Objects
          {hasLoaded && (
            <Badge className="bg-cyan-500/20 text-cyan-400 border-cyan-500/30 text-xs ml-1">
              {objects.length}
            </Badge>
          )}
        </CardTitle>
        <div className="flex items-center gap-2">
          {hasLoaded && !isDemo && (
            <>
              <Button
                variant="outline" size="sm"
                onClick={handleSaveAll}
                disabled={isZipping || filtered.length === 0}
                className="border-green-500/30 text-green-400 hover:bg-green-500/10 text-xs h-7"
              >
                {isZipping
                  ? <Loader2 className="w-3 h-3 mr-1 animate-spin" />
                  : <Archive className="w-3 h-3 mr-1" />}
                Save All ({filtered.length})
              </Button>
              <Button
                variant="outline" size="sm"
                onClick={handleExtract}
                className="border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/10 text-xs h-7"
              >
                <RefreshCw className="w-3 h-3 mr-1" /> Re-scan
              </Button>
            </>
          )}
        </div>
      </div>

      {/* ── Protocol tabs — exactly like Wireshark ────────────── */}
      <div className="flex items-center gap-0 border-b border-white/10 bg-[#0A0E1A] overflow-x-auto">
        {PROTOCOL_TABS.map(tab => {
          const count = countFor(tab.id);
          const isActive = activeProto === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => { setActiveProto(tab.id); setTypeFilter("all"); setSearch(""); }}
              className={cn(
                "px-4 py-2 text-xs font-medium whitespace-nowrap border-b-2 transition-all",
                isActive
                  ? "border-cyan-400 text-cyan-400 bg-cyan-400/5"
                  : "border-transparent text-gray-500 hover:text-gray-300 hover:bg-white/5",
                count === 0 && !isActive && "opacity-40"
              )}
            >
              {tab.label}
              {count > 0 && (
                <span className={cn(
                  "ml-1.5 px-1.5 py-0.5 rounded text-xs",
                  isActive ? "bg-cyan-500/20 text-cyan-400" : "bg-white/10 text-gray-500"
                )}>
                  {count}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* ── Error ─────────────────────────────────────────────── */}
      {error && (
        <div className="flex items-center gap-3 px-4 py-3 bg-red-500/10 border-b border-red-500/20">
          <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0" />
          <p className="text-red-400 text-xs">{error}</p>
        </div>
      )}

      {/* ── Scan Now prompt ───────────────────────────────────── */}
      {!hasLoaded && !isLoading && (
        <div className="flex flex-col items-center gap-6 py-16 px-4">
          <Globe className="w-16 h-16 text-cyan-400/20" />
          <div className="text-center">
            <p className="text-white font-medium text-lg mb-1">Export Objects</p>
            <p className="text-gray-500 text-sm max-w-sm">
              Extracts transferred files from HTTP, SMB, FTP-DATA, TFTP, DICOM and IMF streams — exactly like Wireshark.
            </p>
          </div>
          <Button
            onClick={handleExtract}
            disabled={isDemo || !session?.summary}
            className="bg-blue-600 hover:bg-blue-500 text-white px-10 py-6 text-base rounded-xl flex items-center gap-3"
          >
            <Search className="w-5 h-5" /> Export Objects
          </Button>

          {!session?.summary && !isDemo && (
            <p className="text-amber-400 text-xs mt-2">Waiting for analysis to complete...</p>
          )}
        </div>
      )}

      {/* ── Empty state ───────────────────────────────────────── */}
      {hasLoaded && !error && objects.length === 0 && (
        <div className="flex flex-col items-center gap-4 py-12 px-4">
          <Globe className="w-12 h-12 text-gray-600" />
          <p className="text-gray-400 font-medium">No objects found</p>
          <p className="text-gray-600 text-sm text-center max-w-sm">
            No transferable objects were found in this capture. Encrypted traffic (TLS/HTTPS) cannot be inspected.
          </p>
          <Button onClick={handleExtract} variant="outline" className="border-cyan-500/30 text-cyan-400 mt-1">
            <RefreshCw className="w-4 h-4 mr-2" /> Try Again
          </Button>
        </div>
      )}

      {/* ── Wireshark-style table ─────────────────────────────── */}
      {hasLoaded && objects.length > 0 && (
        <>
          {/* Wireshark-style filter bar: Text Filter + Content Type */}
          {(() => {
            const uniqueTypes = ["All Content-Types", ...Array.from(new Set(
              objects
                .filter(o => activeProto === "all" || o.export_type === activeProto)
                .map(o => o.content_type)
            )).sort()];
            return (
              <div className="flex items-center gap-3 px-3 py-2 border-b border-white/10 bg-[#0A0E1A]">
                <span className="text-xs text-gray-500 whitespace-nowrap">Text Filter:</span>
                <input
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                  placeholder=""
                  className="flex-1 h-6 bg-transparent border border-[#FF4444] rounded-sm px-2 text-xs text-white font-mono focus:outline-none focus:border-cyan-400"
                />
                <span className="text-xs text-gray-500 whitespace-nowrap">Content Type:</span>
                <select
                  value={typeFilter}
                  onChange={e => setTypeFilter(e.target.value)}
                  className="h-6 bg-[#0D1117] border border-white/10 rounded-sm px-2 text-xs text-gray-300 focus:outline-none focus:border-cyan-400"
                >
                  {uniqueTypes.map(t => (
                    <option key={t} value={t === "All Content-Types" ? "all" : t}>{t}</option>
                  ))}
                </select>
              </div>
            );
          })()}

          {/* Table */}
          <div className="overflow-x-auto max-h-[55vh] custom-scrollbar">
            <table className="w-full table-auto border-collapse">
              <thead className="sticky top-0 z-10">
                <tr className="border-b border-white/10 bg-[#0A0E1A]">
                  {["Packet", "Protocol", "Hostname", "Filename", "Content-Type", "Size"].map(h => (
                    <th
                      key={h}
                      onClick={() => handleSort(h)}
                      className="px-3 py-2 text-xs font-medium text-gray-500 uppercase tracking-wider text-left whitespace-nowrap cursor-pointer select-none hover:text-cyan-400 transition-colors"
                    >
                      {h}
                      <span className="ml-1 inline-block w-3 text-center">
                        {sortCol === h ? (sortDir === "asc" ? "↑" : "↓") : <span className="opacity-20">↕</span>}
                      </span>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                <AnimatePresence>
                  {sorted.map((obj, idx) => {
                    const Icon = getFileIcon(obj.content_type);
                    return (
                      <motion.tr
                        key={`${obj.packet_num}-${obj.filename}-${idx}`}
                        initial={{ opacity: 0, x: -8 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ duration: 0.12, delay: idx * 0.015 }}
                        className={cn(
                          "cursor-pointer transition-colors",
                          idx % 2 === 0 ? "bg-transparent" : "bg-white/[0.02]",
                          "hover:bg-cyan-400/5"
                        )} onClick={() => setSelected(obj)}
                      >
                        <td className="px-3 py-2.5 whitespace-nowrap">
                          <span className="text-xs font-mono text-gray-500">{obj.packet_num || "—"}</span>
                        </td>
                        <td className="px-3 py-2.5 whitespace-nowrap">
                          <Badge className={cn("text-xs border uppercase", getProtoColor(obj.export_type))}>
                            {obj.export_type}
                          </Badge>
                        </td>
                        <td className="px-3 py-2.5 whitespace-nowrap">
                          <p className="text-xs text-cyan-400 font-mono">{obj.hostname || obj.src_ip || "—"}</p>
                        </td>
                        <td className="px-3 py-2.5 whitespace-nowrap">
                          <div className="flex items-center gap-2">
                            <Icon className="w-3.5 h-3.5 text-gray-500 flex-shrink-0" />
                            <p className="text-xs text-white font-medium">{obj.filename}</p>
                          </div>
                        </td>
                        <td className="px-3 py-2.5 whitespace-nowrap">
                          <p className={cn("text-xs font-mono", getTypeTextColor(obj.content_type))}>
                            {obj.content_type}
                          </p>
                        </td>
                        <td className="px-3 py-2.5 whitespace-nowrap text-right">
                          <span className="text-xs font-mono text-gray-400">{formatBytes(obj.size)}</span>
                        </td>
                      </motion.tr>
                    );
                  })}
                </AnimatePresence>

                {filtered.length === 0 && objects.length > 0 && (
                  <tr>
                    <td colSpan={6} className="py-8 text-center text-gray-600 text-sm">
                      No objects match your search.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {/* Footer */}
          <div className="border-t border-white/10 bg-[#0A0E1A] px-3 py-2 flex items-center justify-end">
            <span className="text-xs text-gray-600 whitespace-nowrap font-mono">
              {filtered.length} of {objects.length} · {formatBytes(filtered.reduce((a, o) => a + o.size, 0))}
            </span>
          </div>
        </>
      )}
      {/* ── Detail Dialog ─────────────────────────────────────── */}
      <Dialog open={!!selected} onOpenChange={() => { setSelected(null); setTcpStream(null); }}>
        <DialogContent className="bg-[#0D1117] border-white/10 text-white max-w-2xl">
          <DialogHeader>
            <DialogTitle className="text-cyan-400 flex items-center gap-2 text-sm font-mono">
              {selected && (() => { const I = getFileIcon(selected.content_type); return <I className="w-4 h-4" />; })()}
              {selected?.filename}
              {selected && (
                <Badge className={cn("text-xs border ml-2", getProtoColor(selected.export_type))}>
                  {selected.export_type?.toUpperCase()}
                </Badge>
              )}
            </DialogTitle>
          </DialogHeader>

          {selected && (
            <div className="space-y-4">
              {/* Image preview */}
              {selected.is_image && selected.url && (
                <div className="rounded-lg overflow-hidden bg-[#0A0E1A] border border-white/5 flex items-center justify-center min-h-[120px]">
                  <img
                    src={selected.url}
                    alt={selected.filename}
                    className="max-w-full max-h-72 object-contain"
                    onError={e => { (e.target as HTMLImageElement).style.display = "none"; }}
                  />
                </div>
              )}

              {/* Metadata grid — protocol-aware */}
              <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                {[
                  { label: "Packet #", value: selected.packet_num || "—" },
                  { label: "Protocol", value: selected.export_type?.toUpperCase() },
                  { label: "Content-Type", value: selected.content_type, mono: true },
                  { label: "Size", value: formatBytes(selected.size), mono: true },
                  { label: "Client IP", value: selected.src_ip || "—", mono: true, color: "text-amber-400" },
                  { label: "Server IP", value: selected.dst_ip || "—", mono: true },
                  { label: "Src Port", value: selected.src_port || "—", mono: true },
                  { label: "Dst Port", value: selected.dst_port || "—", mono: true },
                  ...(selected.hostname ? [{ label: "Hostname", value: selected.hostname, mono: true, color: "text-cyan-400" }] : []),
                  ...(selected.request_uri ? [{ label: "URI", value: selected.request_uri, mono: true }] : []),
                  ...(selected.method ? [{ label: "Method", value: selected.method, mono: true }] : []),
                  ...(selected.ftp_filename ? [{ label: "FTP File", value: selected.ftp_filename, mono: true }] : []),
                  ...(selected.smb_path ? [{ label: "SMB Path", value: selected.smb_path, mono: true }] : []),
                  ...(selected.tftp_filename ? [{ label: "TFTP File", value: selected.tftp_filename, mono: true }] : []),
                ].map(({ label, value, mono, color }) => (
                  <div key={label} className="bg-[#0A0E1A] rounded-lg p-3 border border-white/5">
                    <p className="text-xs text-gray-500 mb-1">{label}</p>
                    <p className={cn("text-xs truncate", mono && "font-mono", color ?? "text-white")}>
                      {String(value)}
                    </p>
                  </div>
                ))}
              </div>

              {/* Actions */}
              <div className="flex justify-end gap-2">
                <Button variant="outline" onClick={() => { setSelected(null); setTcpStream(null); }} className="border-white/10 text-xs h-8">
                  <X className="w-3.5 h-3.5 mr-1.5" /> Close
                </Button>
                {selected.url && (
                  <Button
                    className="bg-cyan-600 hover:bg-cyan-500 text-xs h-8"
                    onClick={async () => {
                      const blob = await fetch(selected.url!).then(r => r.blob());
                      const blobUrl = URL.createObjectURL(blob);
                      const a = document.createElement("a");
                      a.href = blobUrl;
                      a.download = selected.filename;
                      a.click();
                      URL.revokeObjectURL(blobUrl);
                    }}
                  >
                    <Download className="w-3.5 h-3.5 mr-1.5" /> Save Object
                  </Button>
                )}
              </div>

              {/* ── Follow TCP Stream ── */}
              {selected.tcp_stream !== null && selected.tcp_stream !== undefined && (
                <div className="border-t border-white/10 pt-3">
                  <div className="flex items-center justify-between mb-2">
                    <p className="text-xs text-gray-400 font-medium">Follow TCP Stream #{selected.tcp_stream}</p>
                    {!tcpStream && (
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => fetchTcpStream(selected)}
                        disabled={tcpStreamLoading}
                        className="border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/10 text-xs h-7"
                      >
                        {tcpStreamLoading
                          ? <Loader2 className="w-3 h-3 mr-1 animate-spin" />
                          : <FileText className="w-3 h-3 mr-1" />}
                        Follow Stream
                      </Button>
                    )}
                  </div>

                  {tcpStream && (
                    <div className="rounded-lg overflow-hidden border border-white/10 font-mono text-xs">
                      {/* Client → Server */}
                      {tcpStream.client_to_server?.bytes > 0 && (
                        <div>
                          <div className="px-3 py-1 bg-red-500/10 border-b border-white/10 text-red-400 text-xs">
                            ▶ {tcpStream.client?.ip}:{tcpStream.client?.port} → {tcpStream.server?.ip}:{tcpStream.server?.port}
                          </div>
                          <pre className="px-3 py-2 bg-red-500/5 text-red-300 whitespace-pre-wrap break-all max-h-48 overflow-y-auto text-[11px]">
                            {tcpStream.client_to_server.is_binary
                              ? `[Binary data — ${tcpStream.client_to_server.bytes} bytes]`
                              : tcpStream.client_to_server.text}
                          </pre>
                        </div>
                      )}

                      {/* Server → Client */}
                      {tcpStream.server_to_client?.bytes > 0 && (
                        <div>
                          <div className="px-3 py-1 bg-blue-500/10 border-b border-white/10 text-blue-400 text-xs">
                            ◀ {tcpStream.server?.ip}:{tcpStream.server?.port} → {tcpStream.client?.ip}:{tcpStream.client?.port}
                          </div>
                          <pre className="px-3 py-2 bg-blue-500/5 text-blue-300 whitespace-pre-wrap break-all max-h-48 overflow-y-auto text-[11px]">
                            {tcpStream.server_to_client.is_binary
                              ? `[Binary data — ${tcpStream.server_to_client.bytes} bytes]`
                              : tcpStream.server_to_client.text}
                          </pre>
                        </div>
                      )}

                      {/* Footer */}
                      <div className="px-3 py-1.5 bg-[#0A0E1A] border-t border-white/10 flex items-center justify-between">
                        <span className="text-gray-600 text-xs">
                          {tcpStream.total_bytes} bytes · {tcpStream.meta?.packet_count} packets
                        </span>
                        <span className="text-gray-600 text-xs">
                          Stream {tcpStream.stream_id}
                        </span>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
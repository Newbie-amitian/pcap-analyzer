"use client";

import { useState, useEffect, useCallback, useMemo, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
    ChevronDown,
    ChevronRight,
    Layers,
    ArrowLeft,
    Search,
    ArrowRightLeft,
    X,
    Copy,
    Check,
} from "lucide-react";
import type { StreamData } from "@/lib/types";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";

import type {
    Packet,
    DetailedPacket,
    PacketLayer,
    PacketLayerField,
} from "@/lib/types";

import { cn } from "@/lib/utils";

const API_BASE = process.env.NEXT_PUBLIC_API_URL;

// Layer colors
const layerStyles: Record<
    string,
    { color: string; bgColor: string; borderColor: string }
> = {
    frame: {
        color: "text-gray-200",
        bgColor: "bg-slate-700/50",
        borderColor: "border-slate-600",
    },
    eth: {
        color: "text-purple-300",
        bgColor: "bg-purple-900/40",
        borderColor: "border-purple-700/50",
    },
    ethernet: {
        color: "text-purple-300",
        bgColor: "bg-purple-900/40",
        borderColor: "border-purple-700/50",
    },
    ipv4: {
        color: "text-blue-300",
        bgColor: "bg-blue-900/40",
        borderColor: "border-blue-700/50",
    },
    ip: {
        color: "text-blue-300",
        bgColor: "bg-blue-900/40",
        borderColor: "border-blue-700/50",
    },
    ipv6: {
        color: "text-cyan-300",
        bgColor: "bg-cyan-900/40",
        borderColor: "border-cyan-700/50",
    },
    tcp: {
        color: "text-green-300",
        bgColor: "bg-green-900/40",
        borderColor: "border-green-700/50",
    },
    udp: {
        color: "text-yellow-300",
        bgColor: "bg-yellow-900/40",
        borderColor: "border-yellow-700/50",
    },
};

// ── Hex Dump Panel ──────────────────────────────────────────────────────────
function HexDumpPanel({ hexData }: { hexData?: string }) {
    if (!hexData) {
        return (
            <div className="flex items-center justify-center h-full text-gray-600 text-xs font-mono">
                No hex data available
            </div>
        );
    }

    // Parse hex string into bytes (handles "c4:b3:01:bc..." or "c4 b3 01 bc..." or raw hex)
    const parseHexBytes = (raw: string): number[] => {
        const cleaned = raw.replace(/[:\s]/g, "");
        const bytes: number[] = [];
        for (let i = 0; i < cleaned.length; i += 2) {
            const byte = parseInt(cleaned.slice(i, i + 2), 16);
            if (!isNaN(byte)) bytes.push(byte);
        }
        return bytes;
    };

    const bytes = parseHexBytes(hexData);
    const COLS = 16;
    const rows: number[][] = [];
    for (let i = 0; i < bytes.length; i += COLS) {
        rows.push(bytes.slice(i, i + COLS));
    }

    const toAscii = (b: number) =>
        b >= 32 && b <= 126 ? String.fromCharCode(b) : ".";

    return (
        <div className="font-mono text-xs overflow-auto custom-scrollbar h-full p-3 select-text">
            <table className="w-full border-collapse">
                <tbody>
                    {rows.map((row, rowIdx) => {
                        const offset = rowIdx * COLS;
                        return (
                            <tr key={rowIdx} className="hover:bg-white/5 transition-colors">
                                {/* Offset */}
                                <td className="pr-4 text-gray-600 whitespace-nowrap align-top py-0.5 select-none">
                                    {offset.toString(16).padStart(4, "0")}
                                </td>

                                {/* Hex bytes — two groups of 8 */}
                                <td className="pr-4 align-top py-0.5 whitespace-nowrap">
                                    {row.map((byte, i) => (
                                        <span key={i}>
                                            <span className="text-cyan-300/80 hover:text-cyan-200 cursor-default transition-colors">
                                                {byte.toString(16).padStart(2, "0")}
                                            </span>
                                            {/* Space between bytes, wider gap at midpoint */}
                                            <span className={cn(
                                                "text-transparent select-none",
                                                i === 7 ? "mr-2" : "mr-1"
                                            )}>
                                                {" "}
                                            </span>
                                        </span>
                                    ))}
                                    {/* Pad short last row */}
                                    {row.length < COLS &&
                                        Array.from({ length: COLS - row.length }).map((_, i) => (
                                            <span key={`pad-${i}`} className="mr-1 text-transparent select-none">
                                                {"   "}
                                            </span>
                                        ))}
                                </td>

                                {/* ASCII */}
                                <td className="align-top py-0.5 whitespace-nowrap">
                                    {row.map((byte, i) => (
                                        <span
                                            key={i}
                                            className={cn(
                                                "cursor-default transition-colors",
                                                byte >= 32 && byte <= 126
                                                    ? "text-green-300/80 hover:text-green-200"
                                                    : "text-gray-600"
                                            )}
                                        >
                                            {toAscii(byte)}
                                        </span>
                                    ))}
                                </td>
                            </tr>
                        );
                    })}
                </tbody>
            </table>
        </div>
    );
}

// ── Hierarchical field tree (unchanged) ─────────────────────────────────────
function HierarchicalField({
    field,
    depth = 0,
    onFrameJump,
}: {
    field: PacketLayerField & { isComputed?: boolean; isFrameRef?: boolean };
    depth?: number;
    onFrameJump: (frameNum: number) => void;
}) {
    const [isExpanded, setIsExpanded] = useState(depth < 2);
    const hasChildren = field.children && field.children.length > 0;
    const indentStyle = depth > 0 ? `ml-${Math.min(depth * 4, 16)}` : "";

    const renderValue = () => {
        if (!field.value) return null;

        // ── Priority 1: backend already flagged this as a frame ref (computed bracket field) ──
        if (field.isFrameRef && /^\d+$/.test(field.value.trim())) {
            const frameNum = parseInt(field.value.trim());
            return (
                <span
                    className="text-cyan-300 font-mono text-xs break-all hover:text-cyan-100 underline underline-offset-2 cursor-pointer"
                    title={`Jump to frame ${frameNum}`}
                    onClick={(e) => {
                        e.stopPropagation();
                        onFrameJump(frameNum);
                    }}
                >
                    {field.value}
                </span>
            );
        }

        // ── Priority 2: full URL ──
        if (/^https?:\/\//i.test(field.value)) {
            return (
                <a

                    href={field.value}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-cyan-300 font-mono text-xs break-all hover:text-cyan-100 underline underline-offset-2 cursor-pointer"
                    onClick={(e) => e.stopPropagation()
                    }
                >
                    {field.value}
                </a>
            );
        }

        // ── Priority 3: relative URI (copy on click) ──
        if (
            /^\//.test(field.value) &&
            (field.key.toLowerCase().includes("uri") || field.key.toLowerCase().includes("url"))
        ) {
            return (
                <span
                    className="text-cyan-300 font-mono text-xs break-all hover:text-cyan-100 underline underline-offset-2 cursor-pointer"
                    title="Click to copy URI"
                    onClick={(e) => {
                        e.stopPropagation();
                        navigator.clipboard.writeText(field.value!);
                    }}
                >
                    {field.value}
                </span>
            );
        }

        // ── Priority 4: dynamic frame ref detection for non-computed fields ──
        // Catches any field tshark gives that has "in" / "for" in the key and a numeric value
        const keyLower = field.key.toLowerCase();
        const isDynamicFrameRef =
            /^\d+$/.test(field.value.trim()) &&
            (keyLower.includes("response in") ||
                keyLower.includes("request in") ||
                keyLower.includes("request for") ||
                keyLower.includes("response for") ||
                keyLower.includes("prev request") ||
                keyLower.includes("next request") ||
                keyLower.endsWith("_in") ||
                keyLower.endsWith("_for"));

        if (isDynamicFrameRef) {
            const frameNum = parseInt(field.value.trim());
            return (
                <span
                    className="text-cyan-300 font-mono text-xs break-all hover:text-cyan-100 underline underline-offset-2 cursor-pointer"
                    title={`Jump to frame ${frameNum}`}
                    onClick={(e) => {
                        e.stopPropagation();
                        onFrameJump(frameNum);
                    }}
                >
                    {field.value}
                </span>
            );
        }

        // ── Computed display field (URI, time etc) — cyan but no click ──
        if (field.isComputed) {
            return (
                <span className="text-cyan-400 font-mono text-xs break-all">
                    {field.value}
                </span>
            );
        }

        return (
            <span className="text-cyan-300 font-mono text-xs break-all">
                {field.value}
            </span>
        );
    };

    return (
        <div className="w-full">
            <div
                className={cn(
                    "flex items-start gap-1 py-0.5 hover:bg-white/5 px-1 rounded cursor-pointer transition-colors",
                    indentStyle,
                    field.isComputed && "opacity-90"
                )}
                onClick={() => hasChildren && setIsExpanded(!isExpanded)}
            >
                <span className="w-4 h-4 flex-shrink-0 flex items-center justify-center">
                    {hasChildren ? (
                        isExpanded ? (
                            <ChevronDown className="w-3 h-3 text-gray-400" />
                        ) : (
                            <ChevronRight className="w-3 h-3 text-gray-400" />
                        )
                    ) : null}
                </span>
                {/* Computed bracket fields shown in orange like Wireshark */}
                <span className={cn(
                    "text-xs min-w-[160px] flex-shrink-0",
                    field.isComputed ? "text-orange-400 font-mono" : "text-gray-400"
                )}>
                    {field.key}:
                </span>
                {renderValue()}
            </div>

            <AnimatePresence>
                {hasChildren && isExpanded && (
                    <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: "auto", opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        transition={{ duration: 0.15 }}
                        className="overflow-hidden custom-scrollbar border-l border-white/10 ml-4"
                    >
                        {field.children!.map((child, i) => (
                            <HierarchicalField
                                key={`${child.key}-${i}-${depth}`}
                                field={child}
                                depth={depth + 1}
                                onFrameJump={onFrameJump}
                            />
                        ))}
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
}

function LayerTreeNode({
    layer,
    isExpanded,
    onToggle,
    onFrameJump,
}: {
    layer: PacketLayer;
    isExpanded: boolean;
    onToggle: () => void;
    onFrameJump: (frameNum: number) => void;
}) {
    const style = layerStyles[layer.protocol.toLowerCase()] || {
        color: "text-gray-300",
        bgColor: "bg-gray-800/40",
        borderColor: "border-gray-700/50",
    };

    const countFields = (fields: PacketLayerField[]): number =>
        fields.reduce(
            (acc, f) => acc + 1 + (f.children ? countFields(f.children) : 0),
            0
        );
    const totalFields = countFields(layer.fields);

    return (
        <div className="w-full">
            <button
                onClick={onToggle}
                className={cn(
                    "w-full flex items-center gap-2 px-3 py-2 transition-colors text-left",
                    "bg-black/40 hover:bg-black/60",
                    isExpanded && "border-b border-white/10"
                )}
            >
                {isExpanded ? (
                    <ChevronDown className="w-4 h-4 text-gray-400 flex-shrink-0" />
                ) : (
                    <ChevronRight className="w-4 h-4 text-gray-400 flex-shrink-0" />
                )}
                <span className="font-medium text-sm text-white">
                    {layer.name}
                </span>
                {totalFields > 0 && (
                    <span className="text-gray-500 text-xs">({totalFields} fields)</span>
                )}
            </button>

            <AnimatePresence>
                {isExpanded && (
                    <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: "auto", opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        transition={{ duration: 0.15 }}
                        className="overflow-hidden bg-black/20"
                    >
                        <div className="px-3 py-2 font-mono text-xs">
                            {layer.fields.map((field, i) => (
                                <HierarchicalField
                                    key={`${field.key}-${i}`}
                                    field={field}
                                    depth={0}
                                    onFrameJump={onFrameJump}
                                />
                            ))}
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
}

function LayerTreeNodeWrapper({
    layer,
    index,
    onFrameJump,
}: {
    layer: PacketLayer;
    index: number;
    onFrameJump: (frameNum: number) => void;
}) {
    const [expanded, setExpanded] = useState(false);
    return (
        <LayerTreeNode
            layer={layer}
            isExpanded={expanded}
            onToggle={() => setExpanded((p) => !p)}
            onFrameJump={onFrameJump}
        />
    );
}

function FollowStreamModal({
    stream,
    streamType,
    onClose,
}: {
    stream: StreamData;
    streamType: 'tcp' | 'udp';
    onClose: () => void;
}) {
    const [copied, setCopied] = useState(false);
    const [activeDir, setActiveDir] = useState<'both' | 'c2s' | 's2c'>('both');

    const c2s = stream.client_to_server;
    const s2c = stream.server_to_client;

    const copyAll = () => {
        const text = `=== Client → Server ===\n${c2s.text}\n\n=== Server → Client ===\n${s2c.text}`;
        navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };

    const renderContent = (data: StreamData['client_to_server'], dir: string, color: string) => {
        if (!data.bytes) return (
            <div className="text-gray-600 text-xs font-mono p-2">No data in this direction</div>
        );
        if (data.is_binary) return (
            <div className="text-yellow-500/70 text-xs font-mono p-2">
                [Binary data — {data.bytes} bytes]
            </div>
        );
        return (
            <pre className={`text-xs font-mono whitespace-pre-wrap break-all p-2 ${color}`}>
                {data.text}
            </pre>
        );
    };

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
            {/* Backdrop */}
            <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />

            {/* Modal */}
            <div className="relative z-10 w-full max-w-4xl max-h-[85vh] flex flex-col bg-[#0D1117] border border-white/10 rounded-xl shadow-2xl">

                {/* Header */}
                <div className="flex items-center justify-between px-4 py-3 border-b border-white/10 flex-shrink-0">
                    <div className="flex items-center gap-3">
                        <ArrowRightLeft className="w-4 h-4 text-cyan-400" />
                        <span className="text-white font-medium text-sm">
                            Follow {streamType.toUpperCase()} Stream #{stream.stream_id}
                        </span>
                        <Badge className="bg-cyan-500/10 text-cyan-400 border-cyan-500/20 text-xs">
                            {stream.client?.ip}:{stream.client?.port} ↔ {stream.server?.ip}:{stream.server?.port}
                        </Badge>
                        <Badge className="bg-white/5 text-gray-400 text-xs">
                            {stream.total_bytes} bytes total
                        </Badge>
                    </div>
                    <div className="flex items-center gap-2">
                        <button
                            onClick={copyAll}
                            className="flex items-center gap-1 text-xs text-gray-400 hover:text-white px-2 py-1 rounded bg-white/5 hover:bg-white/10 transition-colors"
                        >
                            {copied ? <Check className="w-3 h-3 text-green-400" /> : <Copy className="w-3 h-3" />}
                            {copied ? 'Copied!' : 'Copy all'}
                        </button>
                        <button onClick={onClose} className="text-gray-400 hover:text-white transition-colors">
                            <X className="w-4 h-4" />
                        </button>
                    </div>
                </div>

                {/* Direction filter pills */}
                <div className="flex gap-2 px-4 py-2 border-b border-white/10 flex-shrink-0">
                    {[
                        { key: 'both', label: 'Both directions' },
                        { key: 'c2s', label: `Client → Server (${c2s.bytes}B)` },
                        { key: 's2c', label: `Server → Client (${s2c.bytes}B)` },
                    ].map(opt => (
                        <button
                            key={opt.key}
                            onClick={() => setActiveDir(opt.key as any)}
                            className={cn(
                                "px-3 py-1 rounded-full text-xs border transition-all",
                                activeDir === opt.key
                                    ? "bg-cyan-500/20 border-cyan-500/40 text-cyan-300"
                                    : "bg-white/5 border-white/10 text-gray-400 hover:bg-white/10"
                            )}
                        >
                            {opt.label}
                        </button>
                    ))}
                </div>

                {/* Stream content */}
                <div className="flex-1 overflow-auto custom-scrollbar p-4 space-y-4 font-mono text-xs">

                    {(activeDir === 'both' || activeDir === 'c2s') && (
                        <div>
                            <div className="flex items-center gap-2 mb-1">
                                <div className="w-2 h-2 rounded-full bg-cyan-400" />
                                <span className="text-cyan-400 text-xs">
                                    Client → Server ({stream.client?.ip}:{stream.client?.port}) — {c2s.bytes} bytes
                                </span>
                            </div>
                            <div className="bg-cyan-500/5 border border-cyan-500/20 rounded-lg overflow-auto max-h-60">
                                {renderContent(c2s, 'c2s', 'text-cyan-200/80')}
                            </div>
                        </div>
                    )}

                    {(activeDir === 'both' || activeDir === 's2c') && (
                        <div>
                            <div className="flex items-center gap-2 mb-1">
                                <div className="w-2 h-2 rounded-full bg-pink-400" />
                                <span className="text-pink-400 text-xs">
                                    Server → Client ({stream.server?.ip}:{stream.server?.port}) — {s2c.bytes} bytes
                                </span>
                            </div>
                            <div className="bg-pink-500/5 border border-pink-500/20 rounded-lg overflow-auto max-h-60">
                                {renderContent(s2c, 's2c', 'text-pink-200/80')}
                            </div>
                        </div>
                    )}

                </div>
            </div>
        </div>
    );
}

// ── Main component ───────────────────────────────────────────────────────────
export function DetailedAnalysisView({
    sessionId,
    onBack,
}: {
    sessionId: string;
    onBack: () => void;
}) {
    const [packets, setPackets] = useState<Packet[]>([]);
    const [selectedId, setSelectedId] = useState<number | null>(null);
    const [selectedPacket, setSelectedPacket] = useState<DetailedPacket | null>(null);

    const [isLoadingPackets, setIsLoadingPackets] = useState(true);
    const [isLoadingDetail, setIsLoadingDetail] = useState(false);

    const [page] = useState(1);
    const [total, setTotal] = useState(0);

    const [searchInput, setSearchInput] = useState("");

    const [searchFilter, setSearchFilter] = useState("");


    const protocolColorMap = useMemo(() => {
        const protocols = [...new Set(packets.map(p => p.protocol).filter(Boolean))];
        const map: Record<string, string> = {};
        protocols.forEach((proto, i) => {
            const hue = (i * 137.508) % 360;
            map[proto] = `hsl(${Math.round(hue)}, 75%, 60%)`;
        });
        return map;
    }, [packets]); const [sortField, setSortField] = useState("id");
    const [sortDirection, setSortDirection] = useState<"asc" | "desc">("asc");
    const [contextMenu, setContextMenu] = useState<{ x: number; y: number; packet: Packet } | null>(null);
    const [followStream, setFollowStream] = useState<{ stream: StreamData; type: 'tcp' | 'udp' } | null>(null);
    const [isLoadingStream, setIsLoadingStream] = useState(false);
    const [filterExpression, setFilterExpression] = useState("");
    const [filterInput, setFilterInput] = useState("");
    const [filterError, setFilterError] = useState(false);
    const [isFiltering, setIsFiltering] = useState(false);
    const [isFilterActive, setIsFilterActive] = useState(false);
    const [autocomplete, setAutocomplete] = useState<{ name: string; desc: string }[]>([]);
    const [autocompleteOpen, setAutocompleteOpen] = useState(false);
    const [autocompleteIndex, setAutocompleteIndex] = useState(0);
    const autocompleteRef = useRef<HTMLDivElement>(null);

    // Bottom panel height (shared between detail + hex)
    const [bottomHeight, setBottomHeight] = useState(320);
    const isResizing = useRef(false);

    const perPage = 100;

    const onResizeMouseDown = (e: React.MouseEvent) => {
        e.preventDefault();
        isResizing.current = true;
        const startY = e.clientY;
        const startH = bottomHeight;

        const onMove = (ev: MouseEvent) => {
            if (!isResizing.current) return;
            const delta = startY - ev.clientY;
            setBottomHeight(Math.max(160, Math.min(640, startH + delta)));
        };
        const onUp = () => {
            isResizing.current = false;
            window.removeEventListener("mousemove", onMove);
            window.removeEventListener("mouseup", onUp);
        };
        window.addEventListener("mousemove", onMove);
        window.addEventListener("mouseup", onUp);
    };

    const fetchPackets = useCallback(async () => {
        setIsLoadingPackets(true);
        try {
            const res = await fetch(
                `${API_BASE}/pcap/packets?session_id=${sessionId}&page=${page}&per_page=${perPage}`
            );
            if (!res.ok) throw new Error("Failed to fetch packets");
            const data = await res.json();
            setPackets(data.packets || []);
            setTotal(data.total || 0);
        } catch (err) {
            console.error(err);
        } finally {
            setIsLoadingPackets(false);
        }
    }, [sessionId, page]);

    useEffect(() => { fetchPackets(); }, [fetchPackets]);

    useEffect(() => {
        if (selectedId === null) return;
        const fetchDetail = async () => {
            setIsLoadingDetail(true);
            setSelectedPacket(null);
            try {
                const res = await fetch(
                    `${API_BASE}/pcap/packet-dissection?session_id=${sessionId}&packet_number=${selectedId}`
                );
                if (!res.ok) throw new Error(`Failed: ${res.status}`);
                const data = await res.json();
                setSelectedPacket(data);
            } catch (err) {
                console.error(err);
            } finally {
                setIsLoadingDetail(false);
            }
        };
        fetchDetail();
    }, [selectedId, sessionId]);

    const handleSort = (field: string) => {
        if (sortField === field) {
            setSortDirection((prev) => (prev === "asc" ? "desc" : "asc"));
        } else {
            setSortField(field);
            setSortDirection("asc");
        }
    };

    const handleContextMenu = (e: React.MouseEvent, packet: Packet) => {
        e.preventDefault();
        setContextMenu({ x: e.clientX, y: e.clientY, packet });
    };

    const handleFollowStream = async (packet: Packet) => {
        closeContextMenu();

        // Determine stream type dynamically
        const isTcp = packet.tcp_stream !== null && packet.tcp_stream !== undefined;
        const isUdp = packet.udp_stream !== null && packet.udp_stream !== undefined;

        if (!isTcp && !isUdp) {
            console.warn('[Follow] No stream index found on packet — not a TCP/UDP stream');
            return;
        }

        const streamType = isTcp ? 'tcp' : 'udp';
        const streamId = isTcp ? packet.tcp_stream : packet.udp_stream;

        setIsLoadingStream(true);
        try {
            const res = await fetch(
                `${API_BASE}/pcap/tcp-stream?session_id=${sessionId}&stream=${streamId}`
            );
            if (!res.ok) throw new Error(`Failed: ${res.status}`);
            const data = await res.json();

            setFollowStream({
                stream: {
                    stream_id: streamId!,
                    client: data.client,
                    server: data.server,
                    client_to_server: data.client_to_server,
                    server_to_client: data.server_to_client,
                    total_bytes: data.total_bytes,
                    meta: data.meta,
                },
                type: streamType,
            });
        } catch (err) {
            console.error('[Follow] Error:', err);
        } finally {
            setIsLoadingStream(false);
        }
    };

    const closeContextMenu = () => setContextMenu(null);

    const applyFilter = async (expr: string) => {
        const trimmed = expr.trim();
        if (!trimmed) {
            // clear filter — reload original packets
            setIsFilterActive(false);
            setFilterError(false);
            setFilterExpression("");
            fetchPackets();
            return;
        }

        setIsFiltering(true);
        setFilterError(false);
        try {
            const res = await fetch(`${API_BASE}/pcap/filter`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ session_id: sessionId, filter: trimmed }),
            });
            const data = await res.json();
            if (!res.ok || data.invalid) {
                setFilterError(true);
                return;
            }
            setPackets(data.packets || []);
            setTotal(data.total || 0);
            setFilterExpression(trimmed);
            setIsFilterActive(true);
        } catch (e) {
            setFilterError(true);
        } finally {
            setIsFiltering(false);
            setAutocompleteOpen(false);
        }
    };

    const fetchAutocomplete = async (val: string) => {
        // grab the last token being typed (after last space or operator)
        const token = val.split(/[\s&&||()!]+/).pop() || '';
        if (token.length < 2) { setAutocomplete([]); setAutocompleteOpen(false); return; }
        try {
            const res = await fetch(`${API_BASE}/pcap/filter-fields?prefix=${encodeURIComponent(token)}`);
            const data = await res.json();
            if (data.fields?.length) {
                setAutocomplete(data.fields);
                setAutocompleteOpen(true);
                setAutocompleteIndex(0);
            } else {
                setAutocompleteOpen(false);
            }
        } catch (_) { setAutocompleteOpen(false); }
    };

    const copyPacketAsCSV = (packet: Packet) => {
        const headers = "id,timestamp,src_ip,dst_ip,src_port,dst_port,protocol,length,info";
        const row = [
            packet.id,
            packet.timestamp,
            packet.src_ip ?? "",
            packet.dst_ip ?? "",
            packet.src_port ?? "",
            packet.dst_port ?? "",
            packet.protocol ?? "",
            packet.length ?? "",
            `"${(packet.info ?? "").replace(/"/g, '""')}"`,
        ].join(",");
        navigator.clipboard.writeText(`${headers}\n${row}`);
        closeContextMenu();
    };

    const filteredPackets = useMemo(() => {
        if (!searchFilter.trim()) return packets;
        const f = searchFilter.toLowerCase();
        return packets.filter(
            (p) =>
                p.protocol?.toLowerCase().includes(f) ||
                p.src_ip?.toLowerCase().includes(f) ||
                p.dst_ip?.toLowerCase().includes(f) ||
                p.info?.toLowerCase().includes(f)
        );
    }, [packets, searchFilter]);

    const sortedPackets = [...filteredPackets].sort((a, b) => {
        let aVal: any = a[sortField as keyof Packet];
        let bVal: any = b[sortField as keyof Packet];
        if (typeof aVal === "string") aVal = aVal.toLowerCase();
        if (typeof bVal === "string") bVal = bVal.toLowerCase();
        return sortDirection === "asc" ? (aVal > bVal ? 1 : -1) : aVal < bVal ? 1 : -1;
    });

    const showBottom = selectedPacket || isLoadingDetail;

    // Extract hex from packet (adjust field name to match your API response)
    const hexData: string | undefined = useMemo(() => {
        if (!selectedPacket) return undefined;
        if (selectedPacket.hex_dump) return selectedPacket.hex_dump;
        if (selectedPacket.raw_hex) return selectedPacket.raw_hex;

        // Recursively search all layer fields for raw frame bytes
        const searchFields = (fields: PacketLayerField[]): string | undefined => {
            for (const f of fields) {
                if (
                    (f.key === 'frame_raw' ||
                        f.key === 'raw' ||
                        f.key === 'file_data' ||
                        f.key === 'data' ||
                        f.key === 'eth_raw' ||
                        f.key === 'ip_raw') &&
                    f.value &&
                    /^[0-9a-fA-F:]+$/.test(f.value.trim())
                ) {
                    return f.value;
                }
                if (f.children?.length) {
                    const found = searchFields(f.children);
                    if (found) return found;
                }
            }
            return undefined;
        };

        // Check frame layer first (most likely to have raw bytes)
        const frameLayer = selectedPacket.layers?.find(l => l.protocol === 'frame');
        if (frameLayer) {
            const found = searchFields(frameLayer.fields);
            if (found) return found;
        }

        // Fall back to all layers
        for (const layer of selectedPacket.layers ?? []) {
            const found = searchFields(layer.fields);
            if (found) return found;
        }

        return undefined;
    }, [selectedPacket]);

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            transition={{ duration: 0.2 }}
            className="h-full flex flex-col gap-2"
        >
            {/* ── Header ── */}
            <div className="flex items-center justify-between mb-1">
                <div className="flex items-center gap-3">
                    <Button
                        variant="ghost"
                        size="sm"
                        onClick={onBack}
                        className="text-gray-400 hover:text-white"
                    >
                        <ArrowLeft className="w-4 h-4 mr-1" />
                        Back
                    </Button>
                    <h2 className="text-lg font-bold text-white flex items-center gap-2">
                        <Layers className="w-5 h-5 text-cyan-400" />
                        Manual Inspection
                    </h2>
                </div>

                {/* Wireshark-style filter bar */}
                <div className="flex items-center gap-2 flex-1 ml-4 relative">
                    <div className="relative flex-1">
                        <div className={cn(
                            "flex items-center rounded-md border transition-colors overflow-hidden",
                            filterError
                                ? "border-red-500/60 bg-red-500/5"
                                : isFilterActive
                                    ? "border-green-500/60 bg-green-500/5"
                                    : "border-white/10 bg-black/30"
                        )}>
                            {/* green/red dot like Wireshark */}
                            <div className={cn(
                                "w-2 h-2 rounded-full mx-2 flex-shrink-0 transition-colors",
                                filterError ? "bg-red-500" : isFilterActive ? "bg-green-500" : "bg-gray-600"
                            )} />
                            <input
                                className="flex-1 h-8 bg-transparent text-xs text-white outline-none font-mono placeholder:text-gray-600"
                                placeholder='Apply a display filter … e.g. http || tcp.port == 443'
                                value={filterInput}
                                onChange={async (e) => {
                                    setFilterInput(e.target.value);
                                    setFilterError(false);
                                    await fetchAutocomplete(e.target.value);
                                }}
                                onKeyDown={(e) => {
                                    if (autocompleteOpen) {
                                        if (e.key === 'ArrowDown') {
                                            e.preventDefault();
                                            setAutocompleteIndex(i => Math.min(i + 1, autocomplete.length - 1));
                                            return;
                                        }
                                        if (e.key === 'ArrowUp') {
                                            e.preventDefault();
                                            setAutocompleteIndex(i => Math.max(i - 1, 0));
                                            return;
                                        }
                                        if (e.key === 'Tab' || e.key === 'Enter' && autocompleteOpen) {
                                            e.preventDefault();
                                            const chosen = autocomplete[autocompleteIndex];
                                            if (chosen) {
                                                // replace last token with chosen field
                                                const tokens = filterInput.split(/(?<=[\s&&||()!])/);
                                                tokens[tokens.length - 1] = chosen.name + ' ';
                                                setFilterInput(tokens.join(''));
                                                setAutocompleteOpen(false);
                                            }
                                            return;
                                        }
                                        if (e.key === 'Escape') { setAutocompleteOpen(false); return; }
                                    }
                                    if (e.key === 'Enter') applyFilter(filterInput);
                                }}
                                onBlur={() => setTimeout(() => setAutocompleteOpen(false), 150)}
                            />
                            {/* clear button */}
                            {(filterInput || isFilterActive) && (
                                <button
                                    className="px-2 text-gray-500 hover:text-white transition-colors"
                                    onClick={() => {
                                        setFilterInput('');
                                        setIsFilterActive(false);
                                        setFilterError(false);
                                        setFilterExpression('');
                                        fetchPackets();
                                        setAutocompleteOpen(false);
                                    }}
                                >
                                    <X className="w-3 h-3" />
                                </button>
                            )}
                            <button
                                disabled={isFiltering}
                                onClick={() => applyFilter(filterInput)}
                                className={cn(
                                    "px-3 h-8 text-xs font-medium border-l border-white/10 transition-colors flex-shrink-0",
                                    isFiltering
                                        ? "text-gray-600 cursor-wait"
                                        : filterError
                                            ? "text-red-400 hover:bg-red-500/10"
                                            : "text-cyan-400 hover:bg-cyan-500/10"
                                )}
                            >
                                {isFiltering ? '...' : 'Apply'}
                            </button>
                        </div>

                        {/* Autocomplete dropdown */}
                        {autocompleteOpen && autocomplete.length > 0 && (
                            <div
                                ref={autocompleteRef}
                                className="absolute top-full left-0 right-0 mt-1 z-50 bg-[#0D1117] border border-white/10 rounded-md shadow-xl overflow-hidden"
                            >
                                {autocomplete.map((f, i) => (
                                    <div
                                        key={f.name}
                                        className={cn(
                                            "flex items-center gap-3 px-3 py-1.5 cursor-pointer text-xs transition-colors",
                                            i === autocompleteIndex ? "bg-cyan-500/10" : "hover:bg-white/5"
                                        )}
                                        onMouseDown={() => {
                                            const tokens = filterInput.split(/(?<=[\s&&||()!])/);
                                            tokens[tokens.length - 1] = f.name + ' ';
                                            setFilterInput(tokens.join(''));
                                            setAutocompleteOpen(false);
                                        }}
                                    >
                                        <span className="font-mono text-cyan-300">{f.name}</span>
                                        <span className="text-gray-500 truncate">{f.desc}</span>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>

                    {isFilterActive && (
                        <Badge className="bg-green-500/10 border-green-500/30 text-green-400 text-xs flex-shrink-0">
                            {total} matched
                        </Badge>
                    )}

                    {/* Export CSV button */}
                    <button
                        onClick={() => {
                            const headers = [
                                'No.', 'Relative Time', 'Date & Time (UTC)',
                                'Source IP', 'Destination IP', 'Dest. Port', 'Src. Port',
                                'Protocol', 'Length', 'Info'
                            ];

                            const rows = sortedPackets.map(p => {
                                const ts = String(p.timestamp ?? '');
                                const base = String(packets[0]?.timestamp ?? '');
                                let relTime = '0.000000';
                                if (ts && base) {
                                    const [tsSec, tsFrac = '000000'] = ts.split('.');
                                    const [baseSec, baseFrac = '000000'] = base.split('.');
                                    const tsMicros = parseInt(tsSec) * 1_000_000 + parseInt(tsFrac.padEnd(6, '0').slice(0, 6));
                                    const baseMicros = parseInt(baseSec) * 1_000_000 + parseInt(baseFrac.padEnd(6, '0').slice(0, 6));
                                    const diff = tsMicros - baseMicros;
                                    const secs = Math.floor(diff / 1_000_000);
                                    const frac = String(diff % 1_000_000).padStart(6, '0');
                                    relTime = `${secs}.${frac}`;
                                }

                                let datetime = '';
                                if (p.timestamp) {
                                    const raw = String(p.timestamp);
                                    const [sec, frac = '000000'] = raw.split('.');
                                    const micros = frac.padEnd(6, '0').slice(0, 6);
                                    const d = new Date(parseInt(sec) * 1000);
                                    const pad = (n: number) => String(n).padStart(2, '0');
                                    datetime = `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}.${micros}Z`;
                                }

                                return [
                                    p.id,
                                    relTime,
                                    datetime,
                                    p.src_ip ?? '',
                                    p.dst_ip ?? '',
                                    p.dst_port ?? '',
                                    p.src_port ?? '',
                                    p.protocol ?? '',
                                    p.length ?? '',
                                    `"${(p.info ?? '').replace(/"/g, '""')}"`,
                                ].join(',');
                            });

                            // Title row: filter expression or default
                            const titleRow = isFilterActive && filterExpression
                                ? `# Filter: ${filterExpression}`
                                : '# All packets (no filter applied)';

                            const csv = [titleRow, headers.join(','), ...rows].join('\n');
                            const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
                            const url = URL.createObjectURL(blob);
                            const a = document.createElement('a');
                            a.href = url;
                            a.download = isFilterActive && filterExpression
                                ? `packets_${filterExpression.replace(/[^a-z0-9]/gi, '_').slice(0, 40)}.csv`
                                : 'packets_all.csv';
                            a.click();
                            URL.revokeObjectURL(url);
                        }}
                        className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/20 transition-colors flex-shrink-0"
                    >
                        <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                        </svg>
                        Export CSV
                    </button>
                </div>
            </div>

            {/* ── Packet list ── */}
            <Card className="bg-[#0D1117]/60 border border-white/5 flex-1 overflow-hidden">
                <CardHeader className="py-2 px-3 border-b border-white/10">
                    <CardTitle className="text-white text-sm flex items-center gap-2">
                        <ArrowRightLeft className="w-4 h-4 text-cyan-400" />
                        <Badge variant="outline" className="border-cyan-500/30 text-cyan-400 text-xs">
                            {total} packets
                        </Badge>
                    </CardTitle>
                </CardHeader>

                <CardContent className="p-0 overflow-auto custom-scrollbar h-full relative">
                    <table className="w-full text-xs">
                        <thead className="bg-[#0D1117] sticky top-0 z-10 border-b border-white/10"><tr>
                            {[
                                { key: "id", label: "No.", width: "min-w-[48px]" },
                                { key: "rel_time", label: "Time", width: "min-w-[90px]" },
                                { key: "timestamp", label: "Date & Time (UTC)", width: "min-w-[180px]" },
                                { key: "src_ip", label: "Source", width: "min-w-[130px]" },
                                { key: "dst_ip", label: "Destination", width: "min-w-[130px]" },
                                { key: "dst_port", label: "Dest. Port", width: "min-w-[80px] whitespace-nowrap" },
                                { key: "src_port", label: "Src. Port", width: "min-w-[80px] whitespace-nowrap" },
                                { key: "protocol", label: "Protocol", width: "min-w-[90px]" },
                                { key: "length", label: "Length", width: "min-w-[70px]" },
                                { key: "info", label: "Info", width: "min-w-[200px]" },
                            ].map((col) => (
                                <th
                                    key={col.key}
                                    className={`px-2 py-2 text-left cursor-pointer hover:text-cyan-400 text-gray-400 font-medium select-none whitespace-nowrap ${col.width}`}
                                    onClick={() => handleSort(col.key)}
                                >
                                    {col.label}
                                </th>
                            ))}
                        </tr>
                        </thead>
                        <tbody>
                            {isLoadingPackets ? (
                                <tr>
                                    <td colSpan={5} className="py-10 text-center text-gray-500 text-xs">
                                        Loading packets...
                                    </td>
                                </tr>
                            ) : (
                                sortedPackets.map((packet) => (
                                    <tr
                                        key={packet.id}
                                        data-frame={packet.id}
                                        onClick={() => { setSelectedId(packet.id); closeContextMenu(); }}
                                        onContextMenu={(e) => handleContextMenu(e, packet)}
                                        className={cn(
                                            "border-b border-white/5 cursor-pointer hover:bg-white/5 transition-colors",
                                            selectedId === packet.id && "bg-cyan-500/10 border-cyan-500/20"
                                        )}
                                    >
                                        <td className="px-2 py-1 font-mono text-gray-400 min-w-[48px]">{packet.id}</td>
                                        <td className="px-2 py-1 font-mono text-cyan-300/70 min-w-[90px] whitespace-nowrap">
                                            {packet.timestamp && packets[0]?.timestamp
                                                ? (() => {
                                                    const ts = String(packet.timestamp);
                                                    const base = String(packets[0].timestamp);
                                                    const [tsSec, tsFrac = "000000"] = ts.split(".");
                                                    const [baseSec, baseFrac = "000000"] = base.split(".");
                                                    const tsMicros = parseInt(tsSec) * 1_000_000 + parseInt(tsFrac.padEnd(6, "0").slice(0, 6));
                                                    const baseMicros = parseInt(baseSec) * 1_000_000 + parseInt(baseFrac.padEnd(6, "0").slice(0, 6));
                                                    const diff = tsMicros - baseMicros;
                                                    const secs = Math.floor(diff / 1_000_000);
                                                    const frac = String(diff % 1_000_000).padStart(6, "0");
                                                    return `${secs}.${frac}`;
                                                })()
                                                : "0.000000"}
                                        </td>
                                        <td className="px-2 py-1 font-mono text-gray-400 min-w-[210px] whitespace-nowrap">
                                            {packet.timestamp
                                                ? (() => {
                                                    const raw = String(packet.timestamp);
                                                    const [sec, frac = "000000"] = raw.split(".");
                                                    const micros = frac.padEnd(6, "0").slice(0, 6);
                                                    const d = new Date(parseInt(sec) * 1000);
                                                    const pad = (n: number) => String(n).padStart(2, "0");
                                                    return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}.${micros}Z`;
                                                })()
                                                : "—"}
                                        </td>
                                        <td className="px-2 py-1 font-mono text-gray-300 min-w-[130px] whitespace-nowrap">{packet.src_ip}</td>
                                        <td className="px-2 py-1 font-mono text-gray-300 min-w-[130px] whitespace-nowrap">{packet.dst_ip}</td>
                                        <td className="px-2 py-1 font-mono text-gray-400 min-w-[80px] whitespace-nowrap">{packet.dst_port ?? "—"}</td>
                                        <td className="px-2 py-1 font-mono text-gray-400 min-w-[80px] whitespace-nowrap">{packet.src_port ?? "—"}</td>
                                        <td className="px-2 py-1 min-w-[90px] whitespace-nowrap">
                                            <Badge style={{
                                                backgroundColor: (protocolColorMap[packet.protocol] ?? '#6b7280') + '33',
                                                color: protocolColorMap[packet.protocol] ?? '#9ca3af',
                                                borderWidth: '1px',
                                                borderStyle: 'solid',
                                                borderColor: (protocolColorMap[packet.protocol] ?? '#6b7280') + '66',
                                            }}>
                                                {packet.protocol}
                                            </Badge>
                                        </td>
                                        <td className="px-2 py-1 font-mono text-gray-400 min-w-[70px] whitespace-nowrap">{packet.length ?? "—"}</td>
                                        <td className="px-2 py-1 text-gray-400 min-w-[200px]">
                                            <div className="overflow-x-auto whitespace-nowrap max-w-[400px] [&::-webkit-scrollbar]:hidden [-ms-overflow-style:none] [scrollbar-width:none]">
                                                {packet.info}
                                            </div>
                                        </td>
                                    </tr>
                                ))
                            )}
                        </tbody>
                    </table>
                </CardContent>
            </Card>

            {/* ── Resize handle ── */}
            {
                showBottom && (
                    <div
                        className="h-1.5 rounded-full bg-white/5 hover:bg-cyan-500/30 cursor-row-resize transition-colors"
                        onMouseDown={onResizeMouseDown}
                    />
                )
            }

            {/* ── Bottom: Frame Detail (left) + Hex Dump (right) ── */}
            {
                showBottom && (
                    <div
                        className="flex gap-2 flex-shrink-0"
                        style={{ height: bottomHeight }}
                    >
                        {/* Frame Detail — left half */}
                        <Card className="bg-[#0D1117]/60 border border-white/5 overflow-hidden flex-1 min-w-0">
                            <CardHeader className="py-2 px-3 border-b border-white/10 flex-shrink-0">
                                <CardTitle className="text-white text-sm flex items-center gap-2">
                                    <Layers className="w-4 h-4 text-cyan-400" />
                                    Frame Detail — Packet #{selectedId}
                                </CardTitle>
                            </CardHeader>
                            <CardContent className="p-0 overflow-auto custom-scrollbar h-[calc(100%-33px)]">                                {isLoadingDetail ? (
                                <div className="flex items-center justify-center h-16 text-gray-500 text-xs">
                                    Loading frame detail...
                                </div>
                            ) : (
                                selectedPacket?.layers?.map((layer, i) => (
                                    <LayerTreeNodeWrapper
                                        key={`${layer.protocol}-${i}`}
                                        layer={layer}
                                        index={i}
                                        onFrameJump={(frameNum) => {
                                            // Scroll the packet row into view then select it — works for both request→response and response→request
                                            setSelectedId(frameNum);
                                            setTimeout(() => {
                                                const row = document.querySelector(`tr[data-frame="${frameNum}"]`);
                                                if (row) {
                                                    row.scrollIntoView({ behavior: "smooth", block: "center" });
                                                }
                                            }, 50);
                                        }}
                                    />
                                ))
                            )}
                            </CardContent>
                        </Card>

                        {/* Vertical divider — draggable could be added later */}
                        <div className="w-px bg-white/10 flex-shrink-0" />

                        {/* Hex Dump — right half */}
                        <Card className="bg-[#0D1117]/60 border border-white/5 overflow-hidden flex-1 min-w-0">
                            <CardHeader className="py-2 px-3 border-b border-white/10 flex-shrink-0">
                                <CardTitle className="text-white text-sm flex items-center gap-2">
                                    {/* simple hex icon via text */}
                                    <span className="text-cyan-400 font-mono text-xs font-bold tracking-widest">0x</span>
                                    Hex Dump
                                </CardTitle>
                            </CardHeader>
                            <CardContent className="p-0 overflow-auto custom-scrollbar h-[calc(100%-33px)] !p-0">                                {isLoadingDetail ? (
                                <div className="flex items-center justify-center h-16 text-gray-500 text-xs">
                                    Loading hex dump...
                                </div>
                            ) : (
                                <HexDumpPanel hexData={hexData} />
                            )}
                            </CardContent>
                        </Card>
                    </div>
                )
            }

            {/* Follow Stream Modal */}
            {followStream && (
                <FollowStreamModal
                    stream={followStream.stream}
                    streamType={followStream.type}
                    onClose={() => setFollowStream(null)}
                />
            )}

            {contextMenu && (
                <>
                    <div
                        className="fixed inset-0 z-40"
                        onClick={closeContextMenu}
                    />
                    <div
                        className="fixed z-50 bg-[#0D1117] border border-white/10 rounded-md shadow-lg py-1 min-w-[160px]"
                        style={{ top: contextMenu.y, left: contextMenu.x }}
                    >
                        <button
                            className="w-full text-left px-3 py-1.5 text-xs text-gray-300 hover:bg-white/5 transition-colors flex items-center gap-2"
                            onClick={() => handleFollowStream(contextMenu.packet)}
                            disabled={isLoadingStream}
                        >
                            <ArrowRightLeft className="w-3 h-3 text-cyan-400" />
                            {isLoadingStream ? 'Loading...' : 'Follow'}
                        </button>
                        <div className="border-t border-white/10 my-1" />
                        <button
                            className="w-full text-left px-3 py-1.5 text-xs text-gray-300 hover:bg-white/5 transition-colors flex items-center gap-2"
                            onClick={() => copyPacketAsCSV(contextMenu.packet)}
                        >
                            <Search className="w-3 h-3 text-cyan-400" />
                            Copy as CSV
                        </button>
                    </div>
                </>
            )}
        </motion.div>
    );
}
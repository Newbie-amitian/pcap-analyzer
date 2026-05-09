// PCAP Network Analyzer - TypeScript Type Definitions

import { StringToBoolean } from "class-variance-authority/types";

// ============ PACKET TYPES ============

export interface Packet {
  id: number;
  timestamp: number;
  src_ip: string | null;
  dst_ip: string | null;
  src_port: number | null;
  dst_port: number | null;
  protocol: string;
  length: number;
  ttl: number | null;
  flags: string | null;
  payload_preview: string;
  info?: string;  // Wireshark-style Info column
  datetime?: string;  // Absolute date/time from TShark
  color_filter_name?: string;
  color_filter_string?: string;
  tcp_stream?: number | null;   // ← added
  udp_stream?: number | null;   // ← added

}

// Detailed packet layer for tree view
export interface PacketLayerField {
  key: string;
  value: string | null;
  children?: PacketLayerField[];  // Nested child fields
  isExpandable?: boolean;         // Whether this field has expandable children
  depth?: number;                 // Nesting depth
}

export interface PacketLayer {
  name: string;
  protocol: string;
  fields: PacketLayerField[];
}

export interface DetailedPacket {
  frame: {
    number: string;
    time: string;
    time_relative: string;
    length: string;
  };
  layers: PacketLayer[];
  info?: string;
  protocol?: string;
  error?: string;
  hex_dump?: string | null;
  raw_hex?: string | null;
}

export interface TimeRange {
  start: number;
  end: number;
}

export interface PacketSummary {
  total_packets: number;
  protocols: Record<string, number>;
  duration_seconds: number;
  total_bytes?: number;
  time_range: TimeRange;
  raw_text?: string;
  unique_src_ips?: number;
  unique_dst_ips?: number;
  unique_ports?: number;
  critical_alerts?: number;
  high_alerts?: number;
}

// ============ UPLOAD TYPES ============

export interface UploadResponse {
  session_id: string;
  summary: PacketSummary;
}

// ============ VULNERABILITY TYPES ============

export type RiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface VulnerabilityAlert {
  layer: 1 | 2 | 3 | 4;
  risk: RiskLevel;
  protocol?: string;
  port?: number;
  src_ip?: string;
  dst_ip?: string;
  reason: string;
  payload_snippet?: string;
  ip?: string;
  open_ports?: number[];
  cves?: string[];
  hostnames?: string[];
  cve_details?: CVEDetail[];
  // CVE API fields
  cve_id?: string | null;
  cvss_score?: number | null;
  source?: string;
  cve_count?: number | null;
  all_cves?: CVEDetail[];
  count?: number; // packet count
  service_name?: string | null; // Dynamic service name from backend
}

export interface CVEDetail {
  id?: string;
  cve_id?: string;
  summary?: string;
  description?: string;
  cvss?: number | string;
  cvss_score?: number | null;
  severity?: string;
  published?: string;
  source?: string;
}

export interface VulnerabilitySummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface VulnerabilityResponse {
  alerts: VulnerabilityAlert[];
  summary: VulnerabilitySummary;
}

// ============ AGENT TYPES ============

export interface AgentTool {
  name: string;
  description: string;
  params: string[];
}

export interface AgentQueryRequest {
  prompt: string;
  session_id: string;
}

export interface AgentQueryResponse {
  tool_called: string;
  parameters: Record<string, unknown>;
  result: unknown;
  response: string;
}

export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  toolCalled?: string;
  toolParams?: Record<string, unknown>;
  result?: unknown;
  followup?: string | null;
  timestamp: Date | string;
}

// ============ PORT INTELLIGENCE TYPES ============

export interface PortInfo {
  port: number;
  name: string;
  description: string;
  risk: RiskLevel | 'SECURE';
  secure_alternative: string;
  common_uses: string[];
  vulnerabilities: string[];
  recommendations: string[];
}

// ============ EXPORTED OBJECT TYPES (Wireshark Export Objects — all protocols) ============

export interface HttpObject {
  // ── Identity ──────────────────────────────────────────────
  // packet_num = the response frame number — exactly what Wireshark
  // shows in the Export Objects dialog (the frame where data arrives,
  // not the request frame)
  packet_num: number;
  filename: string;   // derived from URI / Content-Disposition / protocol metadata
  export_type: string;   // 'http' | 'http2' | 'smb' | 'smb2' | 'ftp-data' | 'tftp' | 'dicom' | 'imf'

  // ── Stream correlation ────────────────────────────────────
  tcp_stream: number | null;  // tshark tcp.stream index (null for TFTP/UDP)
  udp_stream: number | null;  // tshark udp.stream index (null for TCP protocols)
  frame_number: number;         // same as packet_num — included for clarity

  // ── File info ─────────────────────────────────────────────
  content_type: string;   // MIME type from protocol headers or sniffed from filename
  size: number;   // actual body bytes after decompression
  content_length: number;   // Content-Length header value (may differ from size if compressed)
  is_image: boolean;  // true if content_type starts with 'image/'

  // ── Network endpoints ─────────────────────────────────────
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;

  // ── HTTP-specific ─────────────────────────────────────────
  request_uri: string;   // e.g. /images/logo.png
  hostname: string;   // from Host: header e.g. example.com
  full_uri: string;   // full URL if available
  method: string;   // GET | POST | etc
  status_code: string;   // HTTP response code e.g. '200'

  // ── FTP-specific ──────────────────────────────────────────
  ftp_command: string;  // RETR | STOR
  ftp_filename: string;  // filename from RETR/STOR arg

  // ── SMB-specific ──────────────────────────────────────────
  smb_filename: string;  // filename from SMB dissector
  smb_path: string;  // UNC path e.g. \\server\share\file.docx

  // ── TFTP-specific ─────────────────────────────────────────
  tftp_filename: string; // from WRQ/RRQ opcode

  // ── Preview / download ────────────────────────────────────
  url?: string | null;  // backend artifact URL for download/preview
  artifact_key?: string;         // B2 object key

  // ── Match metadata ────────────────────────────────────────
  match_confidence?: string;  // 'high' (stream-derived) | 'low' (filename-only)
}

// Keep ExtractedImage as alias for backwards compatibility
export type ExtractedImage = HttpObject;

// ============ SESSION TYPES ============

export interface AnalysisSession {
  session_id: string;
  filename: string;
  uploaded_at: Date;
  summary: PacketSummary | null;
  packets: Packet[];
  vulnerabilities: VulnerabilityAlert[];
  images: HttpObject[];
}

// ============ CHART DATA TYPES ============

export interface ProtocolChartData {
  name: string;
  value: number;
  color: string;
}

export interface TimelineDataPoint {
  time: string;
  packets: number;
  bytes: number;
}

export interface TopTalkerData {
  ip: string;
  packets: number;
  bytes: number;
  direction: 'inbound' | 'outbound';
}

// ============ UI STATE TYPES ============

export interface AppState {
  currentSession: AnalysisSession | null;
  isLoading: boolean;
  activeTab: string;
  sidebarOpen: boolean;
}

// ============ STREAM TYPES ============
export interface StreamData {
  stream_id: number;
  client: { ip: string; port: number };
  server: { ip: string; port: number };
  client_to_server: {
    text: string;
    bytes: number;
    is_binary: boolean;
    hex?: string;
  };
  server_to_client: {
    text: string;
    bytes: number;
    is_binary: boolean;
    hex?: string;
  };
  total_bytes: number;
  meta?: {
    stream_id: number;
    src_ip: string;
    dst_ip: string;
    src_port: number;
    dst_port: number;
    protocol: string;
    packet_count: number;
    total_bytes: number;
  };
}
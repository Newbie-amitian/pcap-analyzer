// PCAP Network Analyzer - TypeScript Type Definitions

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
}

export interface TimeRange {
  start: number;
  end: number;
}

export interface PacketSummary {
  total_packets: number;
  protocols: Record<string, number>;
  duration_seconds: number;
  total_bytes: number;
  time_range: TimeRange;
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
}

export interface CVEDetail {
  id: string;
  summary: string;
  cvss: number | string;
  published: string;
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
  timestamp: Date;
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

// ============ IMAGE TYPES ============

export interface ExtractedImage {
  filename: string;
  method: string;
  size: number;
  content_type: string;
  url?: string;
}

// ============ SESSION TYPES ============

export interface AnalysisSession {
  session_id: string;
  filename: string;
  uploaded_at: Date;
  summary: PacketSummary;
  packets: Packet[];
  vulnerabilities: VulnerabilityAlert[];
  images: ExtractedImage[];
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

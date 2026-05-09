"use client";
import { useEffect } from "react";
import { Loader2 } from "lucide-react";
import { useCallback, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Shield,
  Upload,
  FileDigit,
  AlertTriangle,
  Brain,
  Network,
  Image,
  ChevronRight,
  Sparkles,
  Zap,
  Layers
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { useAppStore } from "@/lib/store";
import { cn } from "@/lib/utils";

// Import dashboard components
import { Sidebar, Navbar } from "@/components/layout/Sidebar";
import { StatsBar } from "@/components/dashboard/StatsBar";
import { ProtocolPieChart } from "@/components/dashboard/ProtocolPieChart";
import { TrafficTimeline } from "@/components/dashboard/TrafficTimeline";
import { VulnerabilityAlerts } from "@/components/dashboard/VulnerabilityAlerts";
import { AgentChatBox } from "@/components/agent/AgentChatBox";
import { PortIntelPage } from "@/components/port-intel/PortIntelPage";
import { PacketScanner } from "@/components/packets/PacketScanner";
import { DetailedAnalysisView } from "@/components/manual-inspection/ManualInspection";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "https://pcap-analyzer-backend.onrender.com";

// Upload page component
function UploadPage() {
  const [isDragOver, setIsDragOver] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const { isLoading, uploadError } = useAppStore();

  const handleFileUpload = useCallback(async (file: File) => {
    setUploadProgress(0);

    try {
      setUploadProgress(5);
      const form = new FormData();
      form.append('pcap', file);

      const data = await new Promise<any>((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.open('POST', `${API_BASE}/upload`);
        xhr.upload.onprogress = (e) => {
          if (e.lengthComputable) {
            const pct = 5 + Math.round((e.loaded / e.total) * 70);
            setUploadProgress(pct);
          }
        };
        xhr.onload = () => {
          if (xhr.status < 300) {
            resolve(JSON.parse(xhr.responseText));
          } else {
            reject(new Error(`Upload failed: ${xhr.status}`));
          }
        };
        xhr.onerror = () => reject(new Error('Upload network error'));
        xhr.send(form);
      });

      if (!data.session_id) throw new Error(data.error || 'Processing failed');

      setUploadProgress(100);

      useAppStore.getState().setSession({
        session_id: data.session_id,
        filename: file.name,
        uploaded_at: new Date(),
        summary: null,
        packets: [],
        vulnerabilities: [],
        images: [],
      });

      // ✅ Clear ALL caches for the new file
      useAppStore.getState().clearDashboardCache();
      useAppStore.getState().clearChatMessages();
      useAppStore.getState().setScannedObjects([]);
      useAppStore.getState().setScanHasLoaded(false);

      useAppStore.getState().setActiveView('analyzing');

    } catch (err: any) {
      console.error('[Upload] Failed:', err);
      useAppStore.setState({ uploadError: err.message, isLoading: false });
      setUploadProgress(0);
    }
  }, []);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);

    const files = e.dataTransfer.files;
    if (files.length > 0) {
      const file = files[0];
      if (file.name.endsWith('.pcap') || file.name.endsWith('.pcapng')) {
        handleFileUpload(file);
      }
    }
  }, [handleFileUpload]);

  const handleFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      handleFileUpload(files[0]);
    }
  }, [handleFileUpload]);

  const features = [
    { icon: FileDigit, title: "PCAP Parsing", description: "Deep packet inspection with protocol classification", color: "text-cyan-400" },
    { icon: AlertTriangle, title: "Vulnerability Detection", description: "IANA + NVD + AbuseIPDB integration", color: "text-red-400" },
    { icon: Brain, title: "AI Agent", description: "Natural language network queries", color: "text-violet-400" },
    { icon: Network, title: "Port Intelligence", description: "Grouped by service with CVE lookup", color: "text-amber-400" },
    { icon: Image, title: "Image Extraction", description: "Wireshark-style HTTP image carving", color: "text-green-400" },
  ];

  return (
    <div className="min-h-screen bg-[#0A0E1A] flex flex-col">
      {/* Animated background */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl animate-pulse" />
        <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-violet-500/10 rounded-full blur-3xl animate-pulse delay-1000" />
        <div className="absolute top-1/2 left-1/2 w-64 h-64 bg-green-500/5 rounded-full blur-3xl animate-pulse delay-500" />
      </div>

      {/* Main content */}
      <div className="relative z-10 flex-1 flex flex-col items-center justify-center px-4 py-12">
        {/* Logo and title */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          className="text-center mb-8"
        >
          <div className="flex items-center justify-center gap-3 mb-4">
            <Shield className="w-16 h-16 text-cyan-400" />
          </div>
          <h1 className="text-5xl md:text-6xl font-bold text-white mb-2">
            PacketSight <span className="text-cyan-400">AI</span>
          </h1>
          <p className="text-lg text-cyan-400/80 flex items-center justify-center gap-2">
            <Sparkles className="w-4 h-4" />
            AI-Powered PCAP Network Analyzer
            <Sparkles className="w-4 h-4" />
          </p>
        </motion.div>

        {/* Upload zone */}
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.6, delay: 0.2 }}
          className="w-full max-w-xl mb-12"
        >
          <Card
            className={cn(
              "relative border-2 border-dashed transition-all duration-300 cursor-pointer",
              "bg-[#0D1117]/80 backdrop-blur-xl",
              isDragOver
                ? "border-cyan-400 shadow-lg shadow-cyan-500/20"
                : "border-violet-500/30 hover:border-violet-500/60"
            )}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
          >
            <CardContent className="p-8">
              <input
                type="file"
                accept=".pcap,.pcapng"
                onChange={handleFileSelect}
                className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                disabled={isLoading}
              />

              <AnimatePresence mode="wait">
                {isLoading ? (
                  <motion.div
                    key="loading"
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }}
                    className="flex flex-col items-center"
                  >
                    <div className="relative w-16 h-16 mb-4">
                      <div className="absolute inset-0 rounded-full border-4 border-violet-500/20" />
                      <div
                        className="absolute inset-0 rounded-full border-4 border-cyan-400 border-t-transparent animate-spin"
                        style={{ animationDuration: '1s' }}
                      />
                      <Upload className="absolute inset-0 m-auto w-6 h-6 text-cyan-400" />
                    </div>
                    <p className="text-white font-medium mb-2">Analyzing PCAP file...</p>
                    <div className="w-full max-w-xs bg-gray-800 rounded-full h-2 overflow-hidden">
                      <motion.div
                        className="h-full bg-gradient-to-r from-cyan-500 to-violet-500"
                        initial={{ width: 0 }}
                        animate={{ width: `${uploadProgress}%` }}
                        transition={{ duration: 0.3 }}
                      />
                    </div>
                    <p className="text-gray-500 text-sm mt-2">
                      {uploadProgress < 15 ? "Uploading file..." :
                        uploadProgress < 30 ? "Running TShark analysis..." :
                          uploadProgress < 50 ? "Extracting protocols..." :
                            uploadProgress < 70 ? "Analyzing traffic..." :
                              uploadProgress < 85 ? "Fetching CVE data..." :
                                uploadProgress < 95 ? "Checking IP reputations..." :
                                  uploadProgress < 100 ? "Preparing dashboard..." : "Complete!"}
                    </p>
                  </motion.div>
                ) : (
                  <motion.div
                    key="upload"
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }}
                    className="flex flex-col items-center"
                  >
                    <motion.div
                      animate={isDragOver ? { scale: 1.1 } : { scale: 1 }}
                      transition={{ type: "spring", stiffness: 300 }}
                    >
                      <Upload className="w-12 h-12 text-violet-400 mb-4" />
                    </motion.div>
                    <p className="text-white font-medium text-lg mb-2">
                      Drop your .pcap file here
                    </p>
                    <p className="text-gray-400 text-sm">
                      or click to browse
                    </p>
                    <div className="flex items-center gap-2 mt-4 text-xs text-gray-500">
                      <Zap className="w-3 h-3 text-cyan-400" />
                      Supports .pcap and .pcapng formats
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </CardContent>
          </Card>
        </motion.div>

        {/* Feature cards */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.4 }}
          className="w-full max-w-4xl"
        >
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
            {features.map((feature, index) => (
              <motion.div
                key={feature.title}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.4, delay: 0.5 + index * 0.1 }}
              >
                <Card className="bg-[#0D1117]/60 backdrop-blur-sm border border-white/5 hover:border-cyan-500/30 transition-colors h-full">
                  <CardContent className="p-4 text-center">
                    <feature.icon className={cn("w-8 h-8 mx-auto mb-2", feature.color)} />
                    <h3 className="text-white font-medium text-sm mb-1">{feature.title}</h3>
                    <p className="text-gray-500 text-xs">{feature.description}</p>
                  </CardContent>
                </Card>
              </motion.div>
            ))}
          </div>
        </motion.div>

        {/* Footer */}
        <footer className="relative z-10 py-6 text-center text-gray-500 text-sm mt-8">
          <p>Built with Next.js • TShark • IANA • NVD • AbuseIPDB</p>
        </footer>
      </div>
    </div>
  );
}

const ANALYSIS_STEPS = [
  { label: 'Running TShark extraction', sublabel: 'Parsing packets & protocol layers', icon: '🔬' },
  { label: 'Resolving IANA port registry', sublabel: 'Mapping ports to known services', icon: '📡' },
  { label: 'Fetching CVEs from NVD', sublabel: 'Looking up known vulnerabilities', icon: '🛡️' },
  { label: 'Checking IP reputations', sublabel: 'Querying AbuseIPDB for malicious IPs', icon: '🔍' },
  { label: 'Building threat intelligence', sublabel: 'Running port scan & brute force detection', icon: '⚡' },
  { label: 'Uploading results to B2', sublabel: 'Storing analysis data', icon: '☁️' },
  { label: 'Analysis complete', sublabel: 'Loading your dashboard...', icon: '✅' },
];

function AnalyzingView() {
  const { session } = useAppStore();
  const [step, setStep] = useState(0);
  const [label, setLabel] = useState(ANALYSIS_STEPS[0].label);
  const [done, setDone] = useState(false);
  const [elapsed, setElapsed] = useState(0);

  // Tick elapsed seconds
  useEffect(() => {
    const t = setInterval(() => setElapsed(s => s + 1), 1000);
    return () => clearInterval(t);
  }, []);

  // WebSocket progress sync
  useEffect(() => {
    if (!session?.session_id) return;
    let ws: WebSocket;
    let cancelled = false;

    const connect = () => {
      if (cancelled) return;
      const wsUrl = API_BASE.replace('https://', 'wss://').replace('http://', 'ws://');
      ws = new WebSocket(`${wsUrl}/api/progress/${session.session_id}`);

      ws.onmessage = async (event) => {
        const data = JSON.parse(event.data);
        setStep(prev => Math.max(prev, data.step ?? 0));
        setLabel(data.label ?? '');
        if (data.done) {
          setDone(true);
          ws.close();
          const summaryRes = await fetch(`${API_BASE}/api/summary/${session.session_id}`);
          if (summaryRes.ok) {
            const summaryData = await summaryRes.json();
            setTimeout(() => {
              useAppStore.getState().setSession({ ...session, summary: summaryData });
              useAppStore.getState().setActiveView('dashboard');
            }, 800);
          }
        }
      };

      ws.onerror = () => {
        if (!cancelled) setTimeout(connect, 2000);
      };
    };

    connect();

    return () => {
      cancelled = true;
      ws?.close();
    };
  }, [session?.session_id]);

  const progressPct = Math.round((step / (ANALYSIS_STEPS.length - 1)) * 100);

  return (
    <div className="min-h-screen bg-[#0A0E1A] flex flex-col items-center justify-center px-4">
      {/* Background blobs */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl animate-pulse" />
        <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-violet-500/10 rounded-full blur-3xl animate-pulse delay-1000" />
      </div>

      <div className="relative z-10 w-full max-w-lg">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: -16 }}
          animate={{ opacity: 1, y: 0 }}
          className="text-center mb-10"
        >
          <div className="flex items-center justify-center gap-3 mb-3">
            <Shield className="w-10 h-10 text-cyan-400" />
            <h1 className="text-3xl font-bold text-white">Analyzing <span className="text-cyan-400">PCAP</span></h1>
          </div>
          <p className="text-gray-400 text-sm font-mono truncate max-w-xs mx-auto">
            {session?.filename}
          </p>
          <p className="text-gray-600 text-xs mt-1">{elapsed}s elapsed</p>
        </motion.div>

        {/* Progress bar */}
        <div className="mb-8">
          <div className="flex justify-between text-xs text-gray-500 mb-2">
            <span>Progress</span>
            <span>{progressPct}%</span>
          </div>
          <div className="w-full bg-white/5 rounded-full h-2 overflow-hidden">
            <motion.div
              className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-violet-500"
              animate={{ width: `${progressPct}%` }}
              transition={{ duration: 0.6, ease: 'easeOut' }}
            />
          </div>
        </div>

        {/* Steps list */}
        <div className="space-y-3">
          {ANALYSIS_STEPS.map((s, i) => {
            const isActive = i === step && !done;
            const isComplete = i < step || done;
            const isPending = i > step && !done;

            return (
              <motion.div
                key={i}
                initial={{ opacity: 0, x: -12 }}
                animate={{ opacity: isPending ? 0.35 : 1, x: 0 }}
                transition={{ duration: 0.3, delay: i * 0.04 }}
                className={cn(
                  'flex items-center gap-4 px-4 py-3 rounded-xl border transition-all duration-300',
                  isActive && 'bg-cyan-500/10 border-cyan-500/40',
                  isComplete && 'bg-white/3 border-white/5',
                  isPending && 'bg-transparent border-white/5',
                )}
              >
                {/* Icon / spinner */}
                <div className="w-8 h-8 flex-shrink-0 flex items-center justify-center">
                  {isActive ? (
                    <Loader2 className="w-5 h-5 text-cyan-400 animate-spin" />
                  ) : isComplete ? (
                    <span className="text-lg">{s.icon}</span>
                  ) : (
                    <span className="text-lg opacity-30">{s.icon}</span>
                  )}
                </div>

                {/* Text */}
                <div className="flex-1 min-w-0">
                  <p className={cn(
                    'text-sm font-medium',
                    isActive && 'text-cyan-300',
                    isComplete && 'text-white',
                    isPending && 'text-gray-600',
                  )}>
                    {s.label}
                  </p>
                  {(isActive || isComplete) && (
                    <p className="text-xs text-gray-500 mt-0.5">{s.sublabel}</p>
                  )}
                </div>

                {/* Badge */}
                {isComplete && (
                  <Badge className="bg-green-500/15 text-green-400 border-0 text-xs shrink-0">
                    done
                  </Badge>
                )}
                {isActive && (
                  <Badge className="bg-cyan-500/15 text-cyan-400 border-0 text-xs shrink-0 animate-pulse">
                    running
                  </Badge>
                )}
              </motion.div>
            );
          })}
        </div>

        {/* Footer note */}
        <p className="text-center text-gray-600 text-xs mt-8">
          Large captures may take 30–90 seconds · Dashboard loads automatically
        </p>
      </div>
    </div>
  );
}


function DashboardView() {
  const { session, setActiveView, dashboardCache, setDashboardCache } = useAppStore();
  const [portData, setPortData] = useState<any[]>(dashboardCache?.portData ?? []);
  const [threats, setThreats] = useState<any>(dashboardCache?.threats ?? null);
  const [packets, setPackets] = useState<any[]>([]);
  const [summary, setSummary] = useState<any>(dashboardCache?.summary ?? null);
  const [loading, setLoading] = useState({
    summary: !dashboardCache,
    ports: !dashboardCache,
    threats: !dashboardCache,
    packets: false,
  });

  useEffect(() => {
    if (!session?.session_id) return;

    // ✅ Skip fetching if we already have cached data
    if (dashboardCache) return;

    const sid = session.session_id;
    let summaryData: any = null;
    let portDataResult: any[] = [];
    let threatsData: any = null;

    // Fetch summary
    fetch(`${API_BASE}/api/summary/${sid}`)
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (data) {
          console.log('[DEBUG] summary.protocols:', data.protocols);
          summaryData = data;
          setSummary(data);
        }
        setLoading(prev => ({ ...prev, summary: false }));
        // Save to cache if all done
        if (portDataResult !== null && threatsData !== null) {
          setDashboardCache({ summary: summaryData, portData: portDataResult, threats: threatsData });
        }
      })
      .catch(() => setLoading(prev => ({ ...prev, summary: false })));

    // Fetch ports
    fetch(`${API_BASE}/api/ports-intel/${sid}`)
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        const result = data ?? [];
        portDataResult = result;
        if (data) setPortData(data);
        setLoading(prev => ({ ...prev, ports: false }));
      })
      .catch(() => setLoading(prev => ({ ...prev, ports: false })));

    // Fetch threats
    fetch(`${API_BASE}/api/threats/${sid}`)
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        threatsData = data;
        if (data) setThreats(data);
        setLoading(prev => ({ ...prev, threats: false }));
      })
      .catch(() => setLoading(prev => ({ ...prev, threats: false })));

  }, [session?.session_id, dashboardCache]);

  // Only count alerts from actual traffic patterns in YOUR pcap
  // Port CVEs are general info — shown in Port Intel page, not counted here
  // Group credential leaks same way as the UI cards do
  const credLeakGroups = new Set(
    (threats?.credential_leaks || []).map((t: any) =>
      `${t.packet_num || t.frame_number || 'unknown'}-${t.src_ip}-${t.dst_ip}`
    )
  );
  const credLeakCritical = [...credLeakGroups].filter(key => {
    const leak = (threats?.credential_leaks || []).find((t: any) =>
      `${t.packet_num || t.frame_number || 'unknown'}-${t.src_ip}-${t.dst_ip}` === key
    );
    return leak?.severity === 'CRITICAL';
  }).length;

  const vulnSummary = {
    critical: (threats?.ddos_indicators?.length || 0)
      + (threats?.malicious_ips?.filter((t: any) => t.severity === 'CRITICAL')?.length || 0)
      + credLeakCritical,
    high: (threats?.port_scans?.length || 0)
      + (threats?.malicious_ips?.filter((t: any) => t.severity === 'HIGH')?.length || 0)
      + (threats?.brute_force?.filter((t: any) => t.severity === 'HIGH')?.length || 0)
      + (threats?.dns_tunneling?.filter((t: any) => t.severity === 'HIGH')?.length || 0),
    medium: (threats?.brute_force?.filter((t: any) => t.severity === 'MEDIUM')?.length || 0)
      + (threats?.dns_tunneling?.filter((t: any) => t.severity === 'MEDIUM')?.length || 0),
    low: (threats?.credential_leaks?.filter((t: any) => t.severity === 'LOW')?.length || 0),
  };

  // Format summary for StatsBar
  const formattedSummary = summary ? {
    total_packets: summary.total_packets || 0,
    total_bytes: summary.total_bytes || 0,
    duration_seconds: summary.duration_seconds || 0,
    protocols: summary.protocols || {},
    unique_src_ips: summary.unique_src_ips || 0,
    unique_dst_ips: summary.unique_dst_ips || 0,
    unique_ports: summary.unique_ports || 0,
    time_range: summary.time_range || { start: 0, end: 0 },
  } : session?.summary;

  if (!session) return null;

  return (
    <div className="space-y-6">
      {loading.summary ? (
        <div className="flex items-center gap-2 text-gray-500 text-sm p-4">
          <Loader2 className="w-4 h-4 animate-spin" />
          Loading analysis summary...
        </div>
      ) : (
        <StatsBar summary={formattedSummary!} vulnSummary={vulnSummary} />
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <ProtocolPieChart summary={formattedSummary!} />
        <TrafficTimeline summary={formattedSummary!} />
      </div>

      {/* Show detected threats if any */}
      {threats && !loading.threats && (
        threats.port_scans?.length > 0 ||
        threats.malicious_ips?.length > 0 ||
        threats.brute_force?.length > 0 ||
        threats.dns_tunneling?.length > 0 ||
        threats.ddos_indicators?.length > 0 ||
        threats.credential_leaks?.length > 0
      ) && (
          <Card className="bg-[#0D1117]/60 backdrop-blur-sm border border-white/5">
            <CardHeader>
              <CardTitle className="text-white text-lg flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-red-400" />
                Detected Threats
                <Badge variant="secondary" className="ml-2 bg-white/5 text-gray-400">
                  Pattern-Based Detection
                </Badge>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {threats.port_scans?.slice(0, 3).map((t: any, i: number) => (
                  <div key={i} className="p-3 rounded-lg bg-red-500/10 border border-red-500/30">
                    <Badge className="bg-red-500/20 text-red-400 mb-2">PORT SCAN</Badge>
                    <p className="text-sm text-cyan-400 font-mono">{t.ip}</p>
                    <p className="text-xs text-gray-500">{t.ports_scanned} ports scanned</p>
                  </div>
                ))}
                {threats.malicious_ips?.slice(0, 3).map((t: any, i: number) => (
                  <div key={i} className="p-3 rounded-lg bg-orange-500/10 border border-orange-500/30">
                    <Badge className="bg-orange-500/20 text-orange-400 mb-2">MALICIOUS IP</Badge>
                    <p className="text-sm text-cyan-400 font-mono">{t.ip}</p>
                    <p className="text-xs text-gray-500">Abuse Score: {t.abuse_score}</p>
                  </div>
                ))}
                {threats.brute_force?.slice(0, 3).map((t: any, i: number) => (
                  <div key={i} className="p-3 rounded-lg bg-yellow-500/10 border border-yellow-500/30">
                    <Badge className="bg-yellow-500/20 text-yellow-400 mb-2">BRUTE FORCE</Badge>
                    <p className="text-sm text-cyan-400 font-mono">{t.ip}:{t.port}</p>
                    <p className="text-xs text-gray-500">{t.attempts} attempts</p>
                  </div>
                ))}
                {threats.dns_tunneling?.slice(0, 3).map((t: any, i: number) => (
                  <div key={i} className="p-3 rounded-lg bg-purple-500/10 border border-purple-500/30">
                    <Badge className="bg-purple-500/20 text-purple-400 mb-2">DNS TUNNELING</Badge>
                    <p className="text-sm text-cyan-400 font-mono truncate">{t.domain}</p>
                    <p className="text-xs text-gray-500">{t.reason}</p>
                  </div>
                ))}
                {threats.ddos_indicators?.slice(0, 3).map((t: any, i: number) => (
                  <div key={i} className="p-3 rounded-lg bg-red-500/10 border border-red-500/30">
                    <Badge className="bg-red-500/20 text-red-400 mb-2">DDoS INDICATOR</Badge>
                    <p className="text-sm text-cyan-400 font-mono">{t.ip}</p>
                    <p className="text-xs text-gray-500">{t.packets_per_second} pkts/sec</p>
                  </div>
                ))}
                {(() => {
                  // Group credential leaks by frame number + src/dst
                  const leaks = threats.credential_leaks || [];
                  const groups = new Map<string, any[]>();

                  for (const t of leaks) {
                    const groupKey = `${t.packet_num || t.frame_number || 'unknown'}-${t.src_ip}-${t.dst_ip}`;
                    if (!groups.has(groupKey)) groups.set(groupKey, []);
                    groups.get(groupKey)!.push(t);
                  }

                  return [...groups.entries()].slice(0, 3).map(([groupKey, groupLeaks]) => {
                    const first = groupLeaks[0];
                    const frameNum = first.packet_num || first.frame_number;

                    // Dedupe fields within the group
                    const uniqueFields = [...new Set(groupLeaks.map((l: any) => {
                      // Normalize: strip source prefix to get just the param name
                      return (l.field || '')
                        .replace(/^(urlencoded-form:|POST body param:|http:|ftp:|smtp:)\s*/i, '')
                        .trim();
                    }))];

                    // Dedupe credential types
                    const uniqueTypes = [...new Set(groupLeaks.map((l: any) =>
                      l.credential_type || l.info || 'Plaintext credential detected'
                    ))];

                    // Dedupe value previews
                    const uniquePreviews = [...new Set(groupLeaks
                      .map((l: any) => l.value_preview)
                      .filter(Boolean)
                    )];

                    return (
                      <div key={groupKey} className="p-3 rounded-lg bg-pink-500/10 border border-pink-500/30 overflow-hidden">
                        <div className="flex items-center justify-between mb-2">
                          <Badge className="bg-pink-500/20 text-pink-400">
                            {first.type === 'tshark_native' ? '🔑 CREDENTIAL LEAK' : '🔐 SENSITIVE DATA'}
                          </Badge>
                          {frameNum && (
                            <span className="text-[10px] text-gray-600 font-mono">
                              frame #{frameNum}
                            </span>
                          )}
                        </div>

                        <p className="text-sm text-cyan-400 font-mono truncate">
                          {first.protocol} — {first.src_ip || 'unknown'} → {first.dst_ip || 'unknown'}
                        </p>

                        {/* All unique credential types */}
                        <div className="flex flex-wrap gap-1 mt-1">
                          {uniqueTypes.map((type: string, i: number) => (
                            <p key={i} className="text-xs text-gray-500">{type}</p>
                          ))}
                        </div>

                        {/* All unique fields found in this frame */}
                        <div className="flex flex-wrap gap-1 mt-2">
                          {uniqueFields.map((field: string, i: number) => (
                            <span key={i} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-pink-500/10 text-pink-300/70 break-all max-w-full">
                              {field}
                            </span>
                          ))}
                        </div>

                        {/* Value previews — only show short redacted previews, skip long HTML blobs */}
                        {uniquePreviews.filter((p: string) => p.length < 60 && !p.includes('<') && !p.includes('}')).length > 0 && (
                          <div className="flex flex-wrap gap-1 mt-1">
                            {uniquePreviews
                              .filter((p: string) => p.length < 60 && !p.includes('<') && !p.includes('}'))
                              .map((preview: string, i: number) => (
                                <p key={i} className="text-xs text-pink-300/60 font-mono break-all">{preview}</p>
                              ))}
                          </div>
                        )}
                      </div>
                    );
                  });
                })()}
              </div>
            </CardContent>
          </Card>
        )}

      {loading.ports ? (
        <div className="flex items-center gap-2 text-gray-500 text-sm p-4">
          <Loader2 className="w-4 h-4 animate-spin" />
          Loading port intelligence...
        </div>
      ) : (
        <VulnerabilityAlerts alerts={portData.map(p => ({
          port: p.port,
          count: p.packet_count,
          risk: p.cves?.[0]?.severity?.toUpperCase() || (p.risks?.length > 0 ? 'MEDIUM' : 'LOW'),
          reason: p.description || p.service_name,
          cve_id: p.cves?.[0]?.cve_id,
          cvss_score: p.cves?.[0]?.cvss_score,
          source: 'IANA + NVD',
          service_name: p.service_name,
          all_cves: p.cves,
          layer: 4 as 1 | 2 | 3 | 4,
        }))} />
      )}
    </div>
  );
}

// Main application with routing
export default function HomePage() {
  const { session, activeView, sidebarCollapsed } = useAppStore();
  const [mounted] = useState(true);

  if (!mounted) return null;

  // Show upload page if no session
  if (!session) {
    return <UploadPage />;
  }

  // Show analyzing screen while backend is still processing
  if (activeView === 'analyzing') {
    return <AnalyzingView />;
  }

  // Show main application with sidebar
  return (
    <div className="min-h-screen bg-[#0A0E1A]">
      {/* Background effects */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-cyan-500/5 rounded-full blur-3xl" />
        <div className="absolute bottom-0 left-0 w-[500px] h-[500px] bg-violet-500/5 rounded-full blur-3xl" />
      </div>

      {/* Sidebar */}
      <Sidebar />

      {/* Navbar */}
      <Navbar />

      {/* Main content */}
      <main
        className={cn(
          "relative z-10 pt-20 pb-8 px-6 transition-all duration-300",
          sidebarCollapsed ? "md:ml-16" : "md:ml-64"
        )}
      >
        <AnimatePresence mode="wait">
          {activeView === 'dashboard' && (
            <motion.div
              key="dashboard"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              transition={{ duration: 0.2 }}
            >
              <DashboardView />
            </motion.div>
          )}

          {activeView === 'agent' && (
            <motion.div
              key="agent"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              transition={{ duration: 0.2 }}
            >
              <AgentChatBox />
            </motion.div>
          )}

          {activeView === 'port-intel' && (
            <motion.div
              key="port-intel"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              transition={{ duration: 0.2 }}
            >
              <PortIntelPage />
            </motion.div>
          )}

          {activeView === 'images' && (
            <motion.div
              key="images"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              transition={{ duration: 0.2 }}
            >
              <PacketScanner />
            </motion.div>
          )}

          <motion.div
            key="manual-inspection"
            style={{ display: activeView === 'manual-inspection' ? 'block' : 'none' }}
            className="h-[calc(100vh-120px)]"
          >
            <DetailedAnalysisView
              sessionId={session?.session_id || ''}
              onBack={() => useAppStore.getState().setActiveView('dashboard')}
            />
          </motion.div>
        </AnimatePresence>
      </main>
    </div>
  );
}

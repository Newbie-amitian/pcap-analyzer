"use client";

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
  Zap
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { useAppStore } from "@/lib/store";
import { cn } from "@/lib/utils";

// Import dashboard components
import { Sidebar, Navbar } from "@/components/layout/Sidebar";
import { StatsBar } from "@/components/dashboard/StatsBar";
import { ProtocolPieChart } from "@/components/dashboard/ProtocolPieChart";
import { TrafficTimeline } from "@/components/dashboard/TrafficTimeline";
import { VulnerabilityAlerts } from "@/components/dashboard/VulnerabilityAlerts";
import { PacketTable } from "@/components/dashboard/PacketTable";
import { AgentChatBox } from "@/components/agent/AgentChatBox";
import { PortIntelPage } from "@/components/port-intel/PortIntelPage";
import { ImageGallery } from "@/components/images/ImageGallery";

// Upload page component
function UploadPage() {
  const [isDragOver, setIsDragOver] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const { simulateUpload, isLoading } = useAppStore();

  const handleFileUpload = useCallback((file: File) => {
    setUploadProgress(0);
    const interval = setInterval(() => {
      setUploadProgress(prev => {
        if (prev >= 100) {
          clearInterval(interval);
          return 100;
        }
        return prev + 10;
      });
    }, 150);

    simulateUpload(file.name);
  }, [simulateUpload]);

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
    { icon: AlertTriangle, title: "Vulnerability Detection", description: "4-layer security analysis engine", color: "text-red-400" },
    { icon: Brain, title: "AI Agent", description: "Natural language network queries", color: "text-violet-400" },
    { icon: Network, title: "Port Intelligence", description: "Comprehensive port security database", color: "text-amber-400" },
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
                    <p className="text-gray-500 text-sm mt-2">{uploadProgress}% complete</p>
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

        {/* Quick start button */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.6, delay: 0.8 }}
          className="mt-8"
        >
          <Button
            onClick={() => simulateUpload('demo_capture.pcap')}
            disabled={isLoading}
            className="bg-gradient-to-r from-cyan-600 to-violet-600 hover:from-cyan-500 hover:to-violet-500 text-white px-8 py-6 rounded-xl font-medium flex items-center gap-2 shadow-lg shadow-violet-500/20"
          >
            <Zap className="w-5 h-5" />
            Try Demo Analysis
            <ChevronRight className="w-4 h-4" />
          </Button>
        </motion.div>
      </div>

      {/* Footer */}
      <footer className="relative z-10 py-6 text-center text-gray-500 text-sm">
        <p>Built with Next.js • FastAPI • Scapy • Ollama</p>
      </footer>
    </div>
  );
}

// Dashboard view
function DashboardView() {
  const { session } = useAppStore();
  if (!session) return null;

  const vulnSummary = {
    critical: session.vulnerabilities.filter(v => v.risk === 'CRITICAL').length,
    high: session.vulnerabilities.filter(v => v.risk === 'HIGH').length,
    medium: session.vulnerabilities.filter(v => v.risk === 'MEDIUM').length,
    low: session.vulnerabilities.filter(v => v.risk === 'LOW').length,
  };

  return (
    <div className="space-y-6">
      <StatsBar summary={session.summary} vulnSummary={vulnSummary} />
      
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <ProtocolPieChart summary={session.summary} />
        <TrafficTimeline summary={session.summary} />
      </div>

      <VulnerabilityAlerts alerts={session.vulnerabilities} />
      
      <PacketTable packets={session.packets} />
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
              <ImageGallery />
            </motion.div>
          )}
        </AnimatePresence>
      </main>
    </div>
  );
}

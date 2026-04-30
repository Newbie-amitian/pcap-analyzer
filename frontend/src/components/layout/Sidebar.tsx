"use client";

import { motion } from "framer-motion";
import { 
  Shield, 
  LayoutDashboard, 
  Brain, 
  Network, 
  Image, 
  Menu,
  ChevronLeft,
  ChevronRight,
  Activity
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { useAppStore } from "@/lib/store";
import { cn } from "@/lib/utils";

const navItems = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'agent', label: 'AI Agent', icon: Brain },
  { id: 'port-intel', label: 'Port Intel', icon: Network },
  { id: 'images', label: 'Images', icon: Image },
] as const;

export function Sidebar() {
  const { activeView, setActiveView, sidebarCollapsed, toggleSidebar, session } = useAppStore();

  if (!session) return null;

  return (
    <motion.aside
      initial={{ x: -100, opacity: 0 }}
      animate={{ x: 0, opacity: 1 }}
      transition={{ duration: 0.3 }}
      className={cn(
        "fixed left-0 top-0 h-full bg-[#0D1117]/95 backdrop-blur-xl border-r border-white/5 z-40",
        "transition-all duration-300 ease-in-out",
        sidebarCollapsed ? "w-16" : "w-64"
      )}
    >
      {/* Logo */}
      <div className="flex items-center gap-3 p-4 border-b border-white/5">
        <Shield className="w-8 h-8 text-cyan-400 flex-shrink-0" />
        {!sidebarCollapsed && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
          >
            <h1 className="text-lg font-bold text-white">PacketSight</h1>
            <p className="text-xs text-cyan-400">AI Network Analyzer</p>
          </motion.div>
        )}
      </div>

      {/* Navigation */}
      <nav className="p-2 mt-4">
        {navItems.map((item) => (
          <button
            key={item.id}
            onClick={() => setActiveView(item.id)}
            className={cn(
              "w-full flex items-center gap-3 px-3 py-3 rounded-lg transition-all duration-200 mb-1",
              "hover:bg-white/5",
              activeView === item.id
                ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/20"
                : "text-gray-400 hover:text-white"
            )}
          >
            <item.icon className="w-5 h-5 flex-shrink-0" />
            {!sidebarCollapsed && (
              <motion.span
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="font-medium"
              >
                {item.label}
              </motion.span>
            )}
          </button>
        ))}
      </nav>

      {/* Status indicator */}
      {!sidebarCollapsed && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="absolute bottom-20 left-4 right-4"
        >
          <div className="bg-[#0A0E1A] rounded-lg p-3 border border-white/5">
            <div className="flex items-center gap-2 mb-2">
              <Activity className="w-4 h-4 text-green-400" />
              <span className="text-xs text-gray-400">Session Active</span>
            </div>
            <p className="text-xs text-gray-500 truncate">
              {session.filename}
            </p>
            <p className="text-xs text-cyan-400 mt-1">
              {session.summary.total_packets.toLocaleString()} packets
            </p>
          </div>
        </motion.div>
      )}

      {/* Collapse toggle */}
      <button
        onClick={toggleSidebar}
        className="absolute bottom-4 right-0 transform translate-x-1/2 w-6 h-6 rounded-full bg-[#0A0E1A] border border-white/10 flex items-center justify-center text-gray-400 hover:text-white hover:border-cyan-500/50 transition-colors"
      >
        {sidebarCollapsed ? (
          <ChevronRight className="w-3 h-3" />
        ) : (
          <ChevronLeft className="w-3 h-3" />
        )}
      </button>
    </motion.aside>
  );
}

export function Navbar() {
  const { session, setActiveView } = useAppStore();

  if (!session) return null;

  return (
    <header className="fixed top-0 right-0 left-0 md:left-64 h-16 bg-[#0D1117]/95 backdrop-blur-xl border-b border-white/5 z-30 transition-all duration-300">
      <div className="flex items-center justify-between h-full px-6">
        {/* Left section */}
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
            <span className="text-sm text-gray-400">Connected</span>
          </div>
          <div className="h-4 w-px bg-white/10" />
          <span className="text-sm text-white">
            {session.filename}
          </span>
        </div>

        {/* Center section - Stats */}
        <div className="hidden md:flex items-center gap-6">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-400" />
            <span className="text-sm text-gray-400">
              <span className="text-white font-medium">{session.summary.total_packets.toLocaleString()}</span> packets
            </span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-sm text-gray-400">
              <span className="text-white font-medium">{(session.summary.total_bytes / 1024 / 1024).toFixed(2)}</span> MB
            </span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-sm text-gray-400">
              <span className="text-white font-medium">{session.summary.duration_seconds}s</span> duration
            </span>
          </div>
        </div>

        {/* Right section */}
        <div className="flex items-center gap-3">
          {/* Vulnerability count */}
          <div className="flex items-center gap-2 px-3 py-1.5 bg-red-500/10 rounded-lg border border-red-500/20">
            <span className="text-xs text-red-400 font-medium">
              {session.vulnerabilities.length} alerts
            </span>
          </div>

          {/* New Analysis button */}
          <Button
            onClick={() => {
              useAppStore.setState({ session: null, activeView: 'upload' });
            }}
            variant="outline"
            size="sm"
            className="border-violet-500/30 text-violet-400 hover:bg-violet-500/10"
          >
            New Analysis
          </Button>
        </div>
      </div>
    </header>
  );
}

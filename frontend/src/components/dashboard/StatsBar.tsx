"use client";

import { motion } from "framer-motion";
import {
  Package,
  Clock,
  Database,
  AlertTriangle,
  TrendingUp,
  Activity,
} from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import type { PacketSummary, VulnerabilitySummary } from "@/lib/types";
import { cn } from "@/lib/utils";

interface StatsBarProps {
  summary: PacketSummary;
  vulnSummary: VulnerabilitySummary;
}

export function StatsBar({ summary, vulnSummary }: StatsBarProps) {
  const formatBytes = (bytes: number) => {
    if (bytes >= 1073741824) return `${(bytes / 1073741824).toFixed(2)} GB`;
    if (bytes >= 1048576) return `${(bytes / 1048576).toFixed(2)} MB`;
    if (bytes >= 1024) return `${(bytes / 1024).toFixed(2)} KB`;
    return `${bytes} B`;
  };

  const formatDuration = (seconds: number) => {
    if (seconds >= 3600) return `${(seconds / 3600).toFixed(1)}h`;
    if (seconds >= 60) return `${(seconds / 60).toFixed(1)}m`;
    return `${seconds}s`;
  };

  const stats = [
    {
      label: "Total Packets",
      value: summary.total_packets.toLocaleString(),
      icon: Package,
      color: "text-cyan-400",
      bgColor: "bg-cyan-500/10",
    },
    {
      label: "Total Bytes",
      value: formatBytes(summary.total_bytes),
      icon: Database,
      color: "text-violet-400",
      bgColor: "bg-violet-500/10",
    },
    {
      label: "Duration",
      value: formatDuration(summary.duration_seconds),
      icon: Clock,
      color: "text-green-400",
      bgColor: "bg-green-500/10",
    },
    {
      label: "Protocols",
      value: Object.keys(summary.protocols).length.toString(),
      icon: Activity,
      color: "text-amber-400",
      bgColor: "bg-amber-500/10",
    },
    {
      label: "Critical Alerts",
      value: vulnSummary.critical.toString(),
      icon: AlertTriangle,
      color: "text-red-400",
      bgColor: "bg-red-500/10",
    },
    {
      label: "High Alerts",
      value: vulnSummary.high.toString(),
      icon: TrendingUp,
      color: "text-orange-400",
      bgColor: "bg-orange-500/10",
    },
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
      {stats.map((stat, index) => (
        <motion.div
          key={stat.label}
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: index * 0.05 }}
        >
          <Card className="bg-[#0D1117]/60 backdrop-blur-sm border border-white/5 hover:border-white/10 transition-colors">
            <CardContent className="p-4">
              <div className="flex items-center gap-3">
                <div className={cn("p-2 rounded-lg", stat.bgColor)}>
                  <stat.icon className={cn("w-4 h-4", stat.color)} />
                </div>
                <div>
                  <p className="text-xs text-gray-500">{stat.label}</p>
                  <p className={cn("text-lg font-bold", stat.color)}>{stat.value}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      ))}
    </div>
  );
}

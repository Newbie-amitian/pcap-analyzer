"use client";

import { motion } from "framer-motion";
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { PacketSummary } from "@/lib/types";

interface TrafficTimelineProps {
  summary: PacketSummary;
}

export function TrafficTimeline({ summary }: TrafficTimelineProps) {
  // Generate timeline data from summary
  const generateTimelineData = () => {
    const data = [];
    const { time_range, total_packets, duration_seconds } = summary;
    const interval = Math.max(1, Math.floor(duration_seconds / 20));
    
    for (let i = 0; i <= 20; i++) {
      const timestamp = time_range.start + (i * interval);
      const date = new Date(timestamp * 1000);
      const packets = Math.floor(total_packets / 20) + Math.floor(Math.random() * (total_packets / 40));
      const bytes = Math.floor((summary.total_bytes / 20) * (0.8 + Math.random() * 0.4));
      
      data.push({
        time: date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
        packets,
        bytes: Math.floor(bytes / 1024),
      });
    }
    
    return data;
  };

  const data = generateTimelineData();

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.3, delay: 0.2 }}
    >
      <Card className="bg-[#0D1117]/60 backdrop-blur-sm border border-white/5 h-full">
        <CardHeader className="pb-2">
          <CardTitle className="text-white text-lg flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-violet-400" />
            Traffic Timeline
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="h-[280px]">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={data}>
                <defs>
                  <linearGradient id="colorPackets" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#00D4FF" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#00D4FF" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="colorBytes" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#7B2FFF" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#7B2FFF" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis
                  dataKey="time"
                  stroke="#6B7280"
                  fontSize={10}
                  tickLine={false}
                  axisLine={false}
                />
                <YAxis
                  stroke="#6B7280"
                  fontSize={10}
                  tickLine={false}
                  axisLine={false}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0D1117',
                    border: '1px solid rgba(255,255,255,0.1)',
                    borderRadius: '8px',
                    color: '#fff',
                  }}
                  labelStyle={{ color: '#9CA3AF' }}
                />
                <Area
                  type="monotone"
                  dataKey="packets"
                  stroke="#00D4FF"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#colorPackets)"
                />
                <Area
                  type="monotone"
                  dataKey="bytes"
                  stroke="#7B2FFF"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#colorBytes)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          <div className="flex justify-center gap-6 mt-2">
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-cyan-400" />
              <span className="text-xs text-gray-400">Packets</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-violet-500" />
              <span className="text-xs text-gray-400">Bytes (KB)</span>
            </div>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}

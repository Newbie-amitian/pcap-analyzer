"use client";

import { motion } from "framer-motion";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from "recharts";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { PacketSummary } from "@/lib/types";
import { protocolColors } from "@/lib/mock-data";

interface ProtocolPieChartProps {
  summary: PacketSummary;
}

export function ProtocolPieChart({ summary }: ProtocolPieChartProps) {
  const data = Object.entries(summary.protocols)
    .map(([name, value]) => ({
      name,
      value,
      color: protocolColors[name] || '#636E72',
    }))
    .sort((a, b) => b.value - a.value)
    .slice(0, 8);

  const total = data.reduce((acc, item) => acc + item.value, 0);

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.3, delay: 0.1 }}
    >
      <Card className="bg-[#0D1117]/60 backdrop-blur-sm border border-white/5 h-full">
        <CardHeader className="pb-2">
          <CardTitle className="text-white text-lg flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-cyan-400" />
            Protocol Distribution
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="h-[280px]">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={data}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={100}
                  paddingAngle={2}
                  dataKey="value"
                  stroke="none"
                >
                  {data.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0D1117',
                    border: '1px solid rgba(255,255,255,0.1)',
                    borderRadius: '8px',
                    color: '#fff',
                  }}
                  formatter={(value: number) => [
                    `${value.toLocaleString()} (${((value / total) * 100).toFixed(1)}%)`,
                    'Packets'
                  ]}
                />
                <Legend
                  layout="horizontal"
                  verticalAlign="bottom"
                  align="center"
                  formatter={(value) => (
                    <span className="text-gray-400 text-xs">{value}</span>
                  )}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}

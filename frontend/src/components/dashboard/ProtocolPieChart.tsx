"use client";

import { useState } from "react";
import { motion } from "framer-motion";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ChevronDown, ChevronUp } from "lucide-react";
import type { PacketSummary } from "@/lib/types";

interface ProtocolPieChartProps {
  summary: PacketSummary;
}

export function ProtocolPieChart({ summary }: ProtocolPieChartProps) {
  const [expanded, setExpanded] = useState(false);

  const generateUniqueColors = (count: number) => {
    const used = new Set<string>();
    const colors: string[] = [];
    let attempt = 0;
    while (colors.length < count && attempt < 1000) {
      attempt++;
      const hue = (colors.length * 137.508) % 360;
      const saturation = 65 + (attempt % 3) * 10;
      const lightness = 55 + (attempt % 2) * 10;
      const color = `hsl(${Math.round(hue)}, ${saturation}%, ${lightness}%)`;
      if (!used.has(color)) { used.add(color); colors.push(color); }
    }
    return colors;
  };

  const protocolList = Object.entries(summary.protocols || {})
    .sort((a, b) => b[1] - a[1]);

  const uniqueColors = generateUniqueColors(protocolList.length);

  const data = protocolList.map(([name, value], index) => ({
    name,
    value,
    color: uniqueColors[index],
  }));

  const total = data.reduce((acc, item) => acc + item.value, 0);
  const visibleProtocols = expanded ? data : data.slice(0, 5);

  if (data.length === 0) {
    return (
      <Card className="bg-[#0D1117]/60 backdrop-blur-sm border border-white/5 h-full">
        <CardHeader className="pb-2">
          <CardTitle className="text-white text-lg flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-cyan-400" />
            Protocol Distribution
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="h-[280px] flex items-center justify-center text-gray-500">
            <p className="text-sm">Loading protocol data...</p>
          </div>
        </CardContent>
      </Card>
    );
  }

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
            <span className="ml-auto text-xs text-gray-500 font-normal">
              {data.length} protocols
            </span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex gap-4 items-start">
            {/* Pie chart — left */}
            <div className="w-[180px] h-[180px] flex-shrink-0">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={data}
                    cx="50%"
                    cy="50%"
                    innerRadius={45}
                    outerRadius={80}
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
                      fontSize: '12px',
                    }}
                    formatter={(value) => {
                      const num = typeof value === "number" ? value : Number(value || 0);
                      return [
                        `${num.toLocaleString()} (${total ? ((num / total) * 100).toFixed(1) : "0.0"}%)`,
                        "Packets",
                      ];
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>

            {/* Protocol list — right */}
            <div className="flex-1 min-w-0">
              <style>{`
                .proto-scroll::-webkit-scrollbar { width: 4px; }
                .proto-scroll::-webkit-scrollbar-track { background: transparent; }
                .proto-scroll::-webkit-scrollbar-thumb { background: rgba(6,182,212,0.3); border-radius: 999px; }
                .proto-scroll::-webkit-scrollbar-thumb:hover { background: rgba(6,182,212,0.6); }
              `}</style>
              <div
                className="proto-scroll space-y-1 overflow-y-auto overflow-x-hidden transition-all duration-300"
                style={{ maxHeight: expanded ? '200px' : 'auto' }}
              >
                {visibleProtocols.map((item, index) => (
                  <motion.div
                    key={item.name}
                    initial={{ opacity: 0, x: 10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ duration: 0.2, delay: index * 0.04 }}
                    className="flex items-center gap-2 px-2 py-1.5 rounded-lg hover:bg-white/5 transition-colors"
                  >
                    <div
                      className="w-2.5 h-2.5 rounded-full flex-shrink-0"
                      style={{ backgroundColor: item.color }}
                    />
                    <span className="text-xs text-gray-300 font-mono w-20 truncate">
                      {item.name}
                    </span>
                    <div className="flex-1 h-1 bg-white/5 rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full"
                        style={{
                          width: `${total ? (item.value / total) * 100 : 0}%`,
                          backgroundColor: item.color,
                          opacity: 0.6,
                        }}
                      />
                    </div>
                    <span className="text-xs text-gray-400 flex-shrink-0 w-10 text-right">
                      {total ? ((item.value / total) * 100).toFixed(1) : "0.0"}%
                    </span>
                    <span className="text-xs text-gray-600 flex-shrink-0 font-mono w-12 text-right">
                      {item.value.toLocaleString()}
                    </span>
                  </motion.div>
                ))}
              </div>

              {/* Expand/collapse button */}
              {data.length > 5 && (
                <button
                  onClick={() => setExpanded(!expanded)}
                  className="mt-2 w-full flex items-center justify-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 transition-colors py-1 rounded-lg hover:bg-cyan-500/10"
                >
                  {expanded ? (
                    <><ChevronUp className="w-3 h-3" /> Show less</>
                  ) : (
                    <><ChevronDown className="w-3 h-3" /> Show {data.length - 5} more</>
                  )}
                </button>
              )}
            </div>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
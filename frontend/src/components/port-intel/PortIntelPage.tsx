"use client";

import { useState } from "react";
import { motion } from "framer-motion";
import {
  Search,
  Shield,
  AlertTriangle,
  CheckCircle,
  ExternalLink,
  Lock,
  Server,
  Info,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import type { PortInfo, RiskLevel } from "@/lib/types";
import { mockPortIntel } from "@/lib/mock-data";
import { cn } from "@/lib/utils";

const riskColors: Record<RiskLevel | 'SECURE', { bg: string; text: string; border: string }> = {
  CRITICAL: { bg: "bg-red-500/20", text: "text-red-400", border: "border-red-500/30" },
  HIGH: { bg: "bg-orange-500/20", text: "text-orange-400", border: "border-orange-500/30" },
  MEDIUM: { bg: "bg-yellow-500/20", text: "text-yellow-400", border: "border-yellow-500/30" },
  LOW: { bg: "bg-blue-500/20", text: "text-blue-400", border: "border-blue-500/30" },
  SECURE: { bg: "bg-green-500/20", text: "text-green-400", border: "border-green-500/30" },
};

export function PortIntelCard({ port }: { port: PortInfo }) {
  const colors = riskColors[port.risk];
  
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
    >
      <Card className="bg-[#0D1117]/60 backdrop-blur-sm border border-white/5 hover:border-white/10 transition-colors">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className={cn("p-2 rounded-lg", colors.bg)}>
                <Server className={cn("w-5 h-5", colors.text)} />
              </div>
              <div>
                <CardTitle className="text-white text-lg">
                  Port {port.port} - {port.name}
                </CardTitle>
                <p className="text-xs text-gray-500 mt-0.5">{port.description}</p>
              </div>
            </div>
            <Badge
              variant="outline"
              className={cn("font-medium", colors.bg, colors.text, colors.border)}
            >
              {port.risk === "SECURE" ? (
                <CheckCircle className="w-3 h-3 mr-1" />
              ) : (
                <AlertTriangle className="w-3 h-3 mr-1" />
              )}
              {port.risk}
            </Badge>
          </div>
        </CardHeader>
        
        <CardContent className="space-y-4">
          {/* Secure Alternative */}
          <div className="flex items-center gap-2 p-3 bg-[#0A0E1A] rounded-lg">
            <Lock className="w-4 h-4 text-green-400" />
            <span className="text-sm text-gray-400">Secure Alternative:</span>
            <span className="text-sm text-green-400 font-medium">{port.secure_alternative}</span>
          </div>

          {/* Common Uses */}
          <div>
            <p className="text-xs text-gray-500 mb-2 flex items-center gap-1">
              <Info className="w-3 h-3" />
              Common Uses
            </p>
            <div className="flex flex-wrap gap-2">
              {port.common_uses.map((use, i) => (
                <Badge key={i} variant="secondary" className="bg-white/5 text-gray-300 text-xs">
                  {use}
                </Badge>
              ))}
            </div>
          </div>

          {/* Vulnerabilities */}
          <div>
            <p className="text-xs text-gray-500 mb-2 flex items-center gap-1">
              <AlertTriangle className="w-3 h-3 text-red-400" />
              Known Vulnerabilities
            </p>
            <ul className="space-y-1">
              {port.vulnerabilities.map((vuln, i) => (
                <li key={i} className="text-xs text-gray-400 flex items-start gap-2">
                  <span className="text-red-400 mt-0.5">•</span>
                  {vuln}
                </li>
              ))}
            </ul>
          </div>

          {/* Recommendations */}
          <div>
            <p className="text-xs text-gray-500 mb-2 flex items-center gap-1">
              <Shield className="w-3 h-3 text-cyan-400" />
              Security Recommendations
            </p>
            <ul className="space-y-1">
              {port.recommendations.map((rec, i) => (
                <li key={i} className="text-xs text-gray-400 flex items-start gap-2">
                  <span className="text-cyan-400 mt-0.5">•</span>
                  {rec}
                </li>
              ))}
            </ul>
          </div>

          {/* CVE Link */}
          <div className="pt-3 border-t border-white/5">
            <Button
              variant="link"
              size="sm"
              className="text-cyan-400 p-0 h-auto"
              onClick={() => window.open(`https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query=${port.name}&search_type=all&isCpeNameSearch=false`, '_blank')}
            >
              <ExternalLink className="w-3 h-3 mr-1" />
              Search NVD for {port.name} vulnerabilities
            </Button>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}

export function PortIntelPage() {
  const [searchQuery, setSearchQuery] = useState("");
  const [riskFilter, setRiskFilter] = useState<string>("all");

  const filteredPorts = mockPortIntel.filter((port) => {
    const matchesSearch =
      port.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      port.port.toString().includes(searchQuery) ||
      port.description.toLowerCase().includes(searchQuery.toLowerCase());
    
    const matchesRisk = riskFilter === "all" || port.risk === riskFilter.toUpperCase();
    
    return matchesSearch && matchesRisk;
  });

  return (
    <div className="space-y-6">
      {/* Search and Filter */}
      <Card className="bg-[#0D1117]/60 backdrop-blur-sm border border-white/5">
        <CardContent className="p-4">
          <div className="flex gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-500" />
              <Input
                placeholder="Search by port number or protocol name..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-10 bg-[#0A0E1A] border-white/10 text-white"
              />
            </div>
            <Select value={riskFilter} onValueChange={setRiskFilter}>
              <SelectTrigger className="w-40 bg-[#0A0E1A] border-white/10 text-white">
                <SelectValue placeholder="Risk Level" />
              </SelectTrigger>
              <SelectContent className="bg-[#0D1117] border-white/10">
                <SelectItem value="all">All Risks</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="secure">Secure</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Results count */}
      <div className="flex items-center justify-between">
        <p className="text-sm text-gray-400">
          Showing {filteredPorts.length} of {mockPortIntel.length} ports
        </p>
        <div className="flex gap-2">
          {(["CRITICAL", "HIGH", "MEDIUM", "SECURE"] as const).map((risk) => {
            const count = mockPortIntel.filter((p) => p.risk === risk).length;
            if (count === 0) return null;
            const colors = riskColors[risk];
            return (
              <Badge key={risk} variant="outline" className={cn(colors.bg, colors.text, colors.border)}>
                {count} {risk}
              </Badge>
            );
          })}
        </div>
      </div>

      {/* Port Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {filteredPorts.map((port) => (
          <PortIntelCard key={port.port} port={port} />
        ))}
      </div>

      {filteredPorts.length === 0 && (
        <div className="text-center py-12">
          <Search className="w-12 h-12 text-gray-600 mx-auto mb-4" />
          <p className="text-gray-400">No ports found matching your search.</p>
        </div>
      )}
    </div>
  );
}

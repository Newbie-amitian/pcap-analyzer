"use client";

import { useState, useEffect, useMemo } from "react";
import { motion } from "framer-motion";
import {
  Search,
  Shield,
  AlertTriangle,
  CheckCircle,
  ExternalLink,
  Server,
  Info,
  RefreshCw,
  Database,
  AlertCircle,
  Globe,
  Lock,
  ChevronDown,
  ChevronUp,
  Network,
  Bug,
  Activity,
  Zap,
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
import type { RiskLevel } from "@/lib/types";
import { useAppStore } from "@/lib/store";
import { cn } from "@/lib/utils";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? 'https://pcap-analyzer-backend.onrender.com';

const riskColors: Record<RiskLevel | 'SECURE', { bg: string; text: string; border: string }> = {
  CRITICAL: { bg: "bg-red-500/20", text: "text-red-400", border: "border-red-500/30" },
  HIGH: { bg: "bg-orange-500/20", text: "text-orange-400", border: "border-orange-500/30" },
  MEDIUM: { bg: "bg-yellow-500/20", text: "text-yellow-400", border: "border-yellow-500/30" },
  LOW: { bg: "bg-green-500/20", text: "text-green-400", border: "border-green-500/30" },
  SECURE: { bg: "bg-emerald-500/20", text: "text-emerald-400", border: "border-emerald-500/30" },
};

interface CVEDetail {
  cve_id: string;
  cvss_score: number | null;
  severity: string;
  description?: string;
  published?: string;
  modified?: string;
}

interface PortIntelData {
  port: number;
  service_name: string;
  description: string;
  protocol: string;
  risks: string[];
  secure: boolean;
  cves: CVEDetail[];
  packet_count: number;
}

interface ThreatData {
  port_scans: any[];
  brute_force: any[];
  dns_tunneling: any[];
  data_exfiltration: any[];
  ddos_indicators: any[];
  malicious_ips: any[];
  credential_leaks: any[];
}

interface GroupedService {
  serviceName: string;
  ports: PortIntelData[];
  totalPackets: number;
  portRange: string;
  hasVulnerabilities: boolean;
  highestRisk: string;
  description: string;
}

// Group ports by service name
function groupPortsByService(portData: PortIntelData[]): GroupedService[] {
  const groups = new Map<string, PortIntelData[]>();

  for (const data of portData) {
    const serviceName = data.service_name || 'Unknown';
    if (!groups.has(serviceName)) {
      groups.set(serviceName, []);
    }
    groups.get(serviceName)!.push(data);
  }

  const result: GroupedService[] = [];

  for (const [serviceName, ports] of groups) {
    // Sort ports by port number
    ports.sort((a, b) => a.port - b.port);

    const totalPackets = ports.reduce((sum, p) => sum + (p.packet_count || 0), 0);

    // Create port range string
    const numericPorts = ports.map(p => p.port);

    let portRange = '';
    if (numericPorts.length === 0) {
      portRange = 'Ephemeral';
    } else if (numericPorts.length === 1) {
      portRange = numericPorts[0].toString();
    } else {
      const sorted = [...numericPorts].sort((a, b) => a - b);
      const ranges: string[] = [];
      let start = sorted[0];
      let end = sorted[0];

      for (let i = 1; i < sorted.length; i++) {
        if (sorted[i] === end + 1) {
          end = sorted[i];
        } else {
          ranges.push(start === end ? `${start}` : `${start}-${end}`);
          start = sorted[i];
          end = sorted[i];
        }
      }
      ranges.push(start === end ? `${start}` : `${start}-${end}`);
      portRange = ranges.join(', ');
    }

    // Check for vulnerabilities
    const hasVulnerabilities = ports.some(p =>
      (p.cves && p.cves.length > 0) ||
      (p.risks && p.risks.length > 0)
    );

    // Determine highest risk
    const riskOrder: Record<string, number> = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'SECURE': 0 };
    let highestRisk = 'LOW';

    for (const port of ports) {
      // Check CVE severities
      if (port.cves) {
        for (const cve of port.cves) {
          const cveRisk = cve.severity?.toUpperCase() || 'LOW';
          if ((riskOrder[cveRisk] || 0) > (riskOrder[highestRisk] || 0)) {
            highestRisk = cveRisk;
          }
        }
      }
      // Check risks array
      if (port.risks && port.risks.length > 0) {
        if ((riskOrder['MEDIUM'] || 0) > (riskOrder[highestRisk] || 0)) {
          highestRisk = 'MEDIUM';
        }
      }
    }

    const description = ports[0]?.description || '';

    result.push({
      serviceName,
      ports,
      totalPackets,
      portRange,
      hasVulnerabilities,
      highestRisk,
      description
    });
  }

  // Sort by highest risk first, then alphabetically
  const riskOrder: Record<string, number> = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'SECURE': 0 };
  result.sort((a, b) => {
    const riskA = riskOrder[a.highestRisk?.toUpperCase()] || 0;
    const riskB = riskOrder[b.highestRisk?.toUpperCase()] || 0;
    if (riskA !== riskB) return riskB - riskA;
    return a.serviceName.localeCompare(b.serviceName);
  });

  return result;
}

// Service Group Card Component
function ServiceGroupCard({ group }: { group: GroupedService }) {
  const [expanded, setExpanded] = useState(false);
  const [cveExpanded, setCveExpanded] = useState<number | null>(null);

  const colors = riskColors[group.highestRisk as RiskLevel] || riskColors.MEDIUM;
  const hasVulns = group.hasVulnerabilities;

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
              <div className={cn("p-2 rounded-lg", hasVulns ? colors.bg : "bg-emerald-500/20")}>
                <Network className={cn("w-5 h-5", hasVulns ? colors.text : "text-emerald-400")} />
              </div>
              <div>
                <CardTitle className="text-white text-lg">{group.serviceName}</CardTitle>
                <div className="flex items-center gap-2 mt-1">
                  <span className="text-xs text-gray-500">Ports:</span>
                  <code className="text-xs text-cyan-400 font-mono">{group.portRange}</code>
                  <span className="text-xs text-gray-600">•</span>
                  <span className="text-xs text-gray-500">{group.ports.length} port{group.ports.length !== 1 ? 's' : ''}</span>
                </div>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Badge variant="outline" className={cn("font-medium", hasVulns ? colors : riskColors.SECURE)}>
                {hasVulns ? (
                  <AlertTriangle className="w-3 h-3 mr-1" />
                ) : (
                  <CheckCircle className="w-3 h-3 mr-1" />
                )}
                {hasVulns ? group.highestRisk : 'SECURE'}
              </Badge>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setExpanded(!expanded)}
                className="h-8 w-8 p-0"
              >
                {expanded ? (
                  <ChevronUp className="w-4 h-4 text-gray-400" />
                ) : (
                  <ChevronDown className="w-4 h-4 text-gray-400" />
                )}
              </Button>
            </div>
          </div>
        </CardHeader>

        {expanded && (
          <CardContent className="pt-0">
            <div className="border-t border-white/5 pt-4">
              {/* Description */}
              {group.description && (
                <p className="text-sm text-gray-400 mb-3">{group.description}</p>
              )}

              <p className="text-xs text-gray-500 mb-3 flex items-center gap-1">
                <Server className="w-3 h-3" />
                Port Details ({group.totalPackets.toLocaleString()} total packets)
              </p>

              {/* Scrollable port list - shows 5 ports at a time */}
              <div className="max-h-64 overflow-y-auto custom-scrollbar space-y-2 pr-2">
                {group.ports.map((portData) => {
                  const hasCVE = portData.cves && portData.cves.length > 0;
                  const hasRisks = portData.risks && portData.risks.length > 0;
                  const isClickable = hasCVE || hasRisks;

                  return (
                    <div
                      key={portData.port}
                      className={cn(
                        "p-3 rounded-lg border transition-colors",
                        isClickable
                          ? "bg-[#0A0E1A] border-white/10 hover:border-cyan-500/30 cursor-pointer"
                          : "bg-[#0A0E1A]/50 border-white/5"
                      )}
                      onClick={() => isClickable && setCveExpanded(cveExpanded === portData.port ? null : portData.port)}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <code className="text-sm font-mono text-cyan-400">
                            {portData.port}
                          </code>
                          <span className="text-xs text-gray-500">:</span>
                          <span className="text-sm text-white">{portData.service_name}</span>
                          {portData.secure && (
                            <Lock className="w-3 h-3 text-emerald-400" />
                          )}
                        </div>
                        <div className="flex items-center gap-2">
                          <Badge variant="secondary" className="text-xs bg-white/5 text-gray-400">
                            {portData.packet_count} pkts
                          </Badge>
                          {hasCVE && (
                            <Badge className="text-xs bg-red-500/10 text-red-400 border-red-500/20">
                              <Bug className="w-3 h-3 mr-1" />
                              {portData.cves?.length} CVE{portData.cves?.length !== 1 ? 's' : ''}
                            </Badge>
                          )}
                          {isClickable && (
                            cveExpanded === portData.port
                              ? <ChevronUp className="w-4 h-4 text-gray-400" />
                              : <ChevronDown className="w-4 h-4 text-gray-400" />
                          )}
                        </div>
                      </div>

                      {/* CVE Dropdown */}
                      {cveExpanded === portData.port && hasCVE && (
                        <motion.div
                          initial={{ opacity: 0, height: 0 }}
                          animate={{ opacity: 1, height: 'auto' }}
                          className="mt-3 pt-3 border-t border-white/5"
                        >
                          <p className="text-xs text-gray-500 mb-2 flex items-center gap-1">
                            <AlertTriangle className="w-3 h-3 text-red-400" />
                            Vulnerabilities (from NVD API)
                          </p>
                          <div className="space-y-2">
                            {portData.cves?.slice(0, 5).map((cve, cveIndex) => (
                              <div key={cveIndex} className="p-2 bg-black/30 rounded border border-white/5">
                                <div className="flex items-center gap-2 mb-1">
                                  <a
                                    href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="text-xs font-mono text-red-400 hover:text-red-300 underline"
                                    onClick={(e) => e.stopPropagation()}
                                  >
                                    {cve.cve_id}
                                  </a>
                                  {cve.cvss_score && (
                                    <Badge className={cn(
                                      "text-[10px]",
                                      cve.cvss_score >= 9 ? "bg-red-500/20 text-red-400" :
                                        cve.cvss_score >= 7 ? "bg-orange-500/20 text-orange-400" :
                                          "bg-yellow-500/20 text-yellow-400"
                                    )}>
                                      CVSS: {cve.cvss_score}
                                    </Badge>
                                  )}
                                  {cve.severity && (
                                    <Badge className={cn(
                                      "text-[10px]",
                                      cve.severity.toUpperCase() === 'CRITICAL' ? "bg-red-500/20 text-red-400" :
                                        cve.severity.toUpperCase() === 'HIGH' ? "bg-orange-500/20 text-orange-400" :
                                          "bg-yellow-500/20 text-yellow-400"
                                    )}>
                                      {cve.severity}
                                    </Badge>
                                  )}
                                </div>
                                {cve.description && (
                                  <p className="text-xs text-gray-400 line-clamp-2">{cve.description}</p>
                                )}
                              </div>
                            ))}
                          </div>
                        </motion.div>
                      )}

                      {/* Security Risks (if no CVEs) */}
                      {!hasCVE && hasRisks && cveExpanded === portData.port && (
                        <motion.div
                          initial={{ opacity: 0, height: 0 }}
                          animate={{ opacity: 1, height: 'auto' }}
                          className="mt-3 pt-3 border-t border-white/5"
                        >
                          <p className="text-xs text-gray-500 mb-2 flex items-center gap-1">
                            <AlertTriangle className="w-3 h-3 text-orange-400" />
                            Security Risks (from IANA Registry)
                          </p>
                          <div className="flex flex-wrap gap-2">
                            {portData.risks.map((risk, i) => (
                              <Badge key={i} variant="secondary" className="bg-orange-500/10 text-orange-400 text-xs border border-orange-500/20">
                                {risk}
                              </Badge>
                            ))}
                          </div>
                        </motion.div>
                      )}
                    </div>
                  );
                })}
              </div>

              {/* Data Source Badges */}
              <div className="flex flex-wrap gap-2 mt-4 pt-4 border-t border-white/5">
                <div className="flex items-center gap-2 px-2 py-1 bg-purple-500/10 rounded-lg border border-purple-500/20">
                  <Database className="w-3.5 h-3.5 text-purple-400" />
                  <span className="text-xs text-purple-400 font-medium">IANA Registry (Dynamic)</span>
                </div>
                {group.ports.some(p => p.cves && p.cves.length > 0) && (
                  <div className="flex items-center gap-2 px-2 py-1 bg-emerald-500/10 rounded-lg border border-emerald-500/20">
                    <Database className="w-3.5 h-3.5 text-emerald-400" />
                    <span className="text-xs text-emerald-400 font-medium">NVD CVE API</span>
                  </div>
                )}
              </div>
            </div>
          </CardContent>
        )}
      </Card>
    </motion.div>
  );
}

export function PortIntelPage() {
  const { session } = useAppStore();
  const [searchQuery, setSearchQuery] = useState("");
  const [riskFilter, setRiskFilter] = useState<string>("all");
  const [portData, setPortData] = useState<PortIntelData[]>([]);
  const [threats, setThreats] = useState<ThreatData | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Fetch port intelligence data
  const fetchPortIntel = async () => {
    if (!session?.session_id) return;

    setIsLoading(true);
    setError(null);

    try {
      // Fetch ports
      const portsRes = await fetch(`${API_BASE}/api/ports-intel/${session.session_id}`);
      if (!portsRes.ok) {
        throw new Error('Failed to fetch port intelligence');
      }
      const portsData = await portsRes.json();
      setPortData(Array.isArray(portsData) ? portsData : []);

      // Fetch threats
      try {
        const threatsRes = await fetch(`${API_BASE}/api/threats/${session.session_id}`);
        if (threatsRes.ok) {
          const threatsData = await threatsRes.json();
          setThreats(threatsData);
        }
      } catch (e) {
        console.log('Threats not ready yet');
      }

    } catch (err) {
      console.error('Error fetching port intel:', err);
      setError(err instanceof Error ? err.message : 'Failed to load data');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchPortIntel();
  }, [session?.session_id]);

  // Group ports by service
  const groupedServices = useMemo(() => {
    const filtered = portData.filter((data) => {
      const serviceName = data.service_name || 'Unknown';
      const portStr = data.port.toString();
      const matchesSearch =
        serviceName.toLowerCase().includes(searchQuery.toLowerCase()) ||
        portStr.includes(searchQuery) ||
        data.description?.toLowerCase().includes(searchQuery.toLowerCase());

      const matchesRisk = riskFilter === "all" ||
        (riskFilter === "secure" && data.secure) ||
        data.cves?.some(c => c.severity?.toLowerCase() === riskFilter.toLowerCase());

      return matchesSearch && (riskFilter === "all" || matchesRisk);
    });

    return groupPortsByService(filtered);
  }, [portData, searchQuery, riskFilter]);

  // Calculate summary from REAL data
  const summary = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, secure: 0 };

    for (const data of portData) {
      if (data.secure && (!data.cves || data.cves.length === 0)) {
        counts.secure++;
        continue;
      }

      if (data.cves) {
        for (const cve of data.cves) {
          const sev = cve.severity?.toUpperCase();
          if (sev === 'CRITICAL') counts.critical++;
          else if (sev === 'HIGH') counts.high++;
          else if (sev === 'MEDIUM') counts.medium++;
          else counts.low++;
        }
      }

      if (data.risks && data.risks.length > 0 && (!data.cves || data.cves.length === 0)) {
        counts.medium++;
      }
    }

    return counts;
  }, [portData]);

  // Count threats
  const threatCounts = useMemo(() => {
    if (!threats) return { portScans: 0, bruteForce: 0, maliciousIPs: 0, dnsTunneling: 0, credentialLeaks: 0 };
    return {
      portScans: threats.port_scans?.length || 0,
      bruteForce: threats.brute_force?.length || 0,
      maliciousIPs: threats.malicious_ips?.length || 0,
      dnsTunneling: threats.dns_tunneling?.length || 0,
      credentialLeaks: threats.credential_leaks?.length || 0,
    };
  }, [threats]);

  if (!session?.session_id) {
    return (
      <div className="flex flex-col items-center justify-center h-64 text-center">
        <AlertCircle className="w-12 h-12 text-gray-600 mb-4" />
        <p className="text-gray-400">Upload a PCAP file to see port intelligence</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white">Port Intelligence</h2>
          <p className="text-sm text-gray-500 flex items-center gap-2 flex-wrap">
            <Database className="w-3.5 h-3.5 text-purple-400" />
            <span className="text-purple-400">IANA Registry (Dynamic Fetch)</span>
            <span className="text-gray-600">|</span>
            <Database className="w-3.5 h-3.5 text-emerald-400" />
            <span className="text-emerald-400">NVD CVE API</span>
            <span className="text-gray-600">|</span>
            <Zap className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-cyan-400">Pattern-Based Threats</span>
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={fetchPortIntel}
          disabled={isLoading}
          className="border-white/10 text-gray-400"
        >
          {isLoading ? (
            <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
          ) : (
            <RefreshCw className="w-4 h-4 mr-2" />
          )}
          Refresh
        </Button>
      </div>

      {/* Threat Summary Cards */}
      {threats && (threatCounts.portScans > 0 || threatCounts.maliciousIPs > 0 || threatCounts.bruteForce > 0) && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {threatCounts.portScans > 0 && (
            <Card className="bg-[#0D1117]/60 border border-red-500/20">
              <CardContent className="p-4">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-red-500/20 rounded-lg">
                    <Network className="w-5 h-5 text-red-400" />
                  </div>
                  <div>
                    <p className="text-sm text-gray-400">Port Scans</p>
                    <p className="text-2xl font-bold text-red-400">{threatCounts.portScans}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {threatCounts.maliciousIPs > 0 && (
            <Card className="bg-[#0D1117]/60 border border-orange-500/20">
              <CardContent className="p-4">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-orange-500/20 rounded-lg">
                    <AlertTriangle className="w-5 h-5 text-orange-400" />
                  </div>
                  <div>
                    <p className="text-sm text-gray-400">Malicious IPs</p>
                    <p className="text-2xl font-bold text-orange-400">{threatCounts.maliciousIPs}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {threatCounts.bruteForce > 0 && (
            <Card className="bg-[#0D1117]/60 border border-yellow-500/20">
              <CardContent className="p-4">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-yellow-500/20 rounded-lg">
                    <Activity className="w-5 h-5 text-yellow-400" />
                  </div>
                  <div>
                    <p className="text-sm text-gray-400">Brute Force</p>
                    <p className="text-2xl font-bold text-yellow-400">{threatCounts.bruteForce}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {threatCounts.dnsTunneling > 0 && (
            <Card className="bg-[#0D1117]/60 border border-purple-500/20">
              <CardContent className="p-4">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-purple-500/20 rounded-lg">
                    <Globe className="w-5 h-5 text-purple-400" />
                  </div>
                  <div>
                    <p className="text-sm text-gray-400">DNS Tunneling</p>
                    <p className="text-2xl font-bold text-purple-400">{threatCounts.dnsTunneling}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
          {threatCounts.credentialLeaks > 0 && (
            <Card className="bg-[#0D1117]/60 border border-pink-500/20">
              <CardContent className="p-4">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-pink-500/20 rounded-lg">
                    <Shield className="w-5 h-5 text-pink-400" />
                  </div>
                  <div>
                    <p className="text-sm text-gray-400">Credential Leaks</p>
                    <p className="text-2xl font-bold text-pink-400">{threatCounts.credentialLeaks}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {/* Search and Filter */}
      <Card className="bg-[#0D1117]/60 backdrop-blur-sm border border-white/5">
        <CardContent className="p-4">
          <div className="flex gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-500" />
              <Input
                placeholder="Search by port, service, or description..."
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
                <SelectItem value="low">Low</SelectItem>
                <SelectItem value="secure">Secure Only</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Error state */}
      {error && (
        <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-lg">
          <p className="text-red-400 text-sm">{error}</p>
        </div>
      )}

      {/* Loading state */}
      {isLoading && (
        <div className="flex items-center justify-center py-12">
          <RefreshCw className="w-6 h-6 text-cyan-400 animate-spin mr-2" />
          <div className="text-gray-400">
            <span className="block">Analyzing ports from PCAP...</span>
            <span className="text-xs text-gray-500">Fetching IANA Registry, NVD CVEs, and checking IP reputations...</span>
          </div>
        </div>
      )}

      {/* Results count and summary */}
      {!isLoading && portData.length > 0 && (
        <div className="flex items-center justify-between flex-wrap gap-2">
          <p className="text-sm text-gray-400">
            Showing {groupedServices.length} services ({portData.length} ports)
          </p>
          <div className="flex gap-2 flex-wrap">
            {summary.critical > 0 && (
              <Badge variant="outline" className={cn(riskColors.CRITICAL)}>
                {summary.critical} CRITICAL
              </Badge>
            )}
            {summary.high > 0 && (
              <Badge variant="outline" className={cn(riskColors.HIGH)}>
                {summary.high} HIGH
              </Badge>
            )}
            {summary.medium > 0 && (
              <Badge variant="outline" className={cn(riskColors.MEDIUM)}>
                {summary.medium} MEDIUM
              </Badge>
            )}
            {summary.low > 0 && (
              <Badge variant="outline" className={cn(riskColors.LOW)}>
                {summary.low} LOW
              </Badge>
            )}
            {summary.secure > 0 && (
              <Badge variant="outline" className={cn(riskColors.SECURE)}>
                {summary.secure} SECURE
              </Badge>
            )}
          </div>
        </div>
      )}

      {/* Service Groups Grid */}
      {!isLoading && groupedServices.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {groupedServices.map((group) => (
            <ServiceGroupCard
              key={group.serviceName}
              group={group}
            />
          ))}
        </div>
      )}

      {/* Empty state */}
      {!isLoading && portData.length === 0 && !error && (
        <div className="text-center py-12">
          <Search className="w-12 h-12 text-gray-600 mx-auto mb-4" />
          <p className="text-gray-400">Waiting for analysis to complete...</p>
          <p className="text-gray-500 text-sm mt-2">
            This may take a few seconds for large PCAP files.
          </p>
        </div>
      )}

      {!isLoading && groupedServices.length === 0 && portData.length > 0 && (
        <div className="text-center py-12">
          <Search className="w-12 h-12 text-gray-600 mx-auto mb-4" />
          <p className="text-gray-400">No services match your search.</p>
        </div>
      )}
    </div>
  );
}

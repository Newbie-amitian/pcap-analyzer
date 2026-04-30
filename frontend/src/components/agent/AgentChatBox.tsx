"use client";

import { useState, useRef, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Send,
  Bot,
  User,
  Wrench,
  ChevronRight,
  Loader2,
  Sparkles,
  Search,
  Shield,
  Network,
  FileSearch,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import type { ChatMessage } from "@/lib/types";
import { mockChatMessages } from "@/lib/mock-data";
import { cn } from "@/lib/utils";

const suggestedPrompts = [
  { icon: Search, text: "Show all FTP traffic", color: "text-amber-400" },
  { icon: Shield, text: "Find credentials in traffic", color: "text-red-400" },
  { icon: Network, text: "Detect port scanning", color: "text-cyan-400" },
  { icon: FileSearch, text: "Get vulnerability report", color: "text-violet-400" },
];

// Simulated AI responses
const getAIResponse = (prompt: string): { response: string; toolCalled: string; toolParams: Record<string, unknown> } => {
  const lowerPrompt = prompt.toLowerCase();
  
  if (lowerPrompt.includes('ftp') || lowerPrompt.includes('port 21')) {
    return {
      toolCalled: 'filter_by_port',
      toolParams: { ports: [21] },
      response: "Found **4 FTP packets** in the capture. I detected:\n\n• 2 connection attempts to port 21\n• **⚠️ Critical**: Plaintext credentials visible in packet #4\n• FTP server response: `220 ProFTPD 1.3.5 Server ready`\n\n**Recommendation**: This FTP server transmits credentials unencrypted. Migrate to SFTP immediately.",
    };
  }
  
  if (lowerPrompt.includes('credential') || lowerPrompt.includes('password') || lowerPrompt.includes('auth')) {
    return {
      toolCalled: 'find_credentials',
      toolParams: {},
      response: "🚨 **Security Alert**: Found **4 instances** of plaintext credentials:\n\n| Protocol | Location | Severity |\n|----------|----------|----------|\n| FTP | Packet #4 | CRITICAL |\n| Telnet | Packet #5 | CRITICAL |\n| HTTP Basic | Packet #6 | HIGH |\n| SNMP | Packet #12 | MEDIUM |\n\n**Immediate Actions Required:**\n1. Rotate all exposed credentials\n2. Disable FTP/Telnet services\n3. Implement encrypted protocols (SSH/SFTP)",
    };
  }
  
  if (lowerPrompt.includes('port scan') || lowerPrompt.includes('scan')) {
    return {
      toolCalled: 'detect_port_scan',
      toolParams: {},
      response: "✅ **Port Scan Analysis Complete**\n\nNo active port scanning detected in this capture. Traffic patterns appear normal.\n\n**Traffic Profile:**\n- Most traffic on standard ports (80, 443, 53)\n- No rapid sequential port access\n- Connection distribution is typical for normal operations",
    };
  }
  
  if (lowerPrompt.includes('vulnerability') || lowerPrompt.includes('vuln') || lowerPrompt.includes('security')) {
    return {
      toolCalled: 'get_vulnerability_report',
      toolParams: {},
      response: "📊 **Vulnerability Scan Results**\n\n**Summary:**\n- 🔴 **3 Critical** issues\n- 🟠 **5 High** issues\n- 🟡 **1 Medium** issue\n\n**Top Critical Findings:**\n1. **Telnet Active** - Unencrypted remote access\n2. **FTP Credentials Exposed** - Plaintext auth\n3. **HTTP Basic Auth** - Base64 encoded credentials\n\n**Recommendations:**\n- Immediately disable Telnet\n- Replace FTP with SFTP\n- Enforce HTTPS with proper authentication",
    };
  }
  
  if (lowerPrompt.includes('dns')) {
    return {
      toolCalled: 'get_dns_queries',
      toolParams: {},
      response: "🔍 **DNS Query Analysis**\n\nFound **389 DNS queries** in this capture:\n\n**Top Domains Queried:**\n- `google.com` (45 queries)\n- `api.github.com` (32 queries)\n- `cdn.jsdelivr.net` (28 queries)\n\n**Observations:**\n- No suspicious DNS tunneling detected\n- All queries to legitimate domains\n- DNSSEC validation recommended",
    };
  }
  
  if (lowerPrompt.includes('top') || lowerPrompt.includes('talker')) {
    return {
      toolCalled: 'get_top_talkers',
      toolParams: {},
      response: "📈 **Top Traffic Sources**\n\n**By Packet Count:**\n1. `192.168.1.100` - 1,245 packets (outbound)\n2. `8.8.8.8` - 389 packets (DNS responses)\n3. `142.250.185.78` - 256 packets (Google)\n\n**By Bytes Transferred:**\n1. `192.168.1.100` - 8.2 MB\n2. `142.250.185.78` - 4.1 MB\n3. `185.199.108.153` - 2.3 MB",
    };
  }
  
  return {
    toolCalled: 'general_query',
    toolParams: { prompt },
    response: "I can help you analyze the PCAP data. Here are some things I can do:\n\n• **Filter packets** by port, IP, or protocol\n• **Find credentials** in plaintext traffic\n• **Detect anomalies** like port scans\n• **Generate reports** on vulnerabilities\n\nTry asking me something like:\n- \"Show me all FTP traffic\"\n- \"Find any credentials in the traffic\"\n- \"Detect if there's port scanning\"",
  };
};

export function AgentChatBox() {
  const [messages, setMessages] = useState<ChatMessage[]>(mockChatMessages);
  const [input, setInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages]);

  const handleSend = async () => {
    if (!input.trim() || isLoading) return;

    const userMessage: ChatMessage = {
      id: Date.now().toString(),
      role: "user",
      content: input,
      timestamp: new Date(),
    };

    setMessages((prev) => [...prev, userMessage]);
    setInput("");
    setIsLoading(true);

    // Simulate AI processing delay
    await new Promise((resolve) => setTimeout(resolve, 1500));

    const aiResult = getAIResponse(input);
    
    const assistantMessage: ChatMessage = {
      id: (Date.now() + 1).toString(),
      role: "assistant",
      content: aiResult.response,
      toolCalled: aiResult.toolCalled,
      toolParams: aiResult.toolParams,
      timestamp: new Date(),
    };

    setMessages((prev) => [...prev, assistantMessage]);
    setIsLoading(false);
  };

  const handlePromptClick = (prompt: string) => {
    setInput(prompt);
  };

  return (
    <Card className="bg-[#0D1117]/60 backdrop-blur-sm border border-white/5 h-[calc(100vh-10rem)] flex flex-col">
      <CardHeader className="pb-3 flex-shrink-0">
        <div className="flex items-center justify-between">
          <CardTitle className="text-white text-lg flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-violet-400 animate-pulse" />
            AI Security Agent
          </CardTitle>
          <Badge variant="outline" className="border-violet-500/30 text-violet-400">
            <Sparkles className="w-3 h-3 mr-1" />
            Mistral Powered
          </Badge>
        </div>
      </CardHeader>
      
      <CardContent className="flex-1 flex flex-col overflow-hidden p-0">
        {/* Messages */}
        <ScrollArea className="flex-1 px-6" ref={scrollRef}>
          <div className="space-y-4 pb-4">
            <AnimatePresence>
              {messages.map((message) => (
                <motion.div
                  key={message.id}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.2 }}
                  className={cn(
                    "flex gap-3",
                    message.role === "user" && "justify-end"
                  )}
                >
                  {message.role === "assistant" && (
                    <div className="w-8 h-8 rounded-lg bg-violet-500/20 flex items-center justify-center flex-shrink-0">
                      <Bot className="w-4 h-4 text-violet-400" />
                    </div>
                  )}
                  
                  <div
                    className={cn(
                      "max-w-[80%] rounded-xl px-4 py-3",
                      message.role === "user"
                        ? "bg-cyan-500/20 border border-cyan-500/30"
                        : "bg-[#0A0E1A] border border-white/5"
                    )}
                  >
                    {message.role === "assistant" && message.toolCalled && (
                      <div className="flex items-center gap-2 mb-2 pb-2 border-b border-white/10">
                        <Wrench className="w-3 h-3 text-violet-400" />
                        <span className="text-xs text-violet-400 font-mono">
                          {message.toolCalled}
                        </span>
                        {message.toolParams && Object.keys(message.toolParams).length > 0 && (
                          <code className="text-xs text-gray-500 bg-white/5 px-1.5 py-0.5 rounded">
                            {JSON.stringify(message.toolParams)}
                          </code>
                        )}
                      </div>
                    )}
                    
                    <p className="text-sm text-gray-200 whitespace-pre-wrap">
                      {message.content}
                    </p>
                    
                    <p className="text-xs text-gray-600 mt-2">
                      {message.timestamp.toLocaleTimeString()}
                    </p>
                  </div>
                  
                  {message.role === "user" && (
                    <div className="w-8 h-8 rounded-lg bg-cyan-500/20 flex items-center justify-center flex-shrink-0">
                      <User className="w-4 h-4 text-cyan-400" />
                    </div>
                  )}
                </motion.div>
              ))}
            </AnimatePresence>
            
            {isLoading && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="flex gap-3"
              >
                <div className="w-8 h-8 rounded-lg bg-violet-500/20 flex items-center justify-center flex-shrink-0">
                  <Bot className="w-4 h-4 text-violet-400" />
                </div>
                <div className="bg-[#0A0E1A] border border-white/5 rounded-xl px-4 py-3">
                  <div className="flex items-center gap-2">
                    <Loader2 className="w-4 h-4 text-violet-400 animate-spin" />
                    <span className="text-sm text-gray-400">Analyzing...</span>
                  </div>
                </div>
              </motion.div>
            )}
          </div>
        </ScrollArea>

        {/* Suggested prompts */}
        {messages.length <= 4 && (
          <div className="px-6 py-3 border-t border-white/5">
            <p className="text-xs text-gray-500 mb-2">Quick prompts:</p>
            <div className="flex flex-wrap gap-2">
              {suggestedPrompts.map((prompt, i) => (
                <Button
                  key={i}
                  variant="outline"
                  size="sm"
                  className={cn(
                    "h-7 text-xs border-white/10 hover:bg-white/5",
                    prompt.color
                  )}
                  onClick={() => handlePromptClick(prompt.text)}
                >
                  <prompt.icon className="w-3 h-3 mr-1" />
                  {prompt.text}
                </Button>
              ))}
            </div>
          </div>
        )}

        {/* Input */}
        <div className="px-6 py-4 border-t border-white/5">
          <div className="flex gap-2">
            <Input
              placeholder="Ask about the network traffic..."
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleSend()}
              className="bg-[#0A0E1A] border-white/10 text-white focus:border-violet-500/50"
              disabled={isLoading}
            />
            <Button
              onClick={handleSend}
              disabled={!input.trim() || isLoading}
              className="bg-gradient-to-r from-cyan-600 to-violet-600 hover:from-cyan-500 hover:to-violet-500"
            >
              <Send className="w-4 h-4" />
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "PacketSight AI - PCAP Network Analyzer",
  description: "AI-Powered PCAP Network Traffic Analyzer",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body>{children}</body>
    </html>
  );
}
// Global State Store for PCAP Analyzer
import { create } from 'zustand';
import type {
  AnalysisSession,
  Packet,
  VulnerabilityAlert,
  ExtractedImage,
} from './types';
import { mockPackets, mockSummary, mockVulnerabilities, mockImages } from './mock-data';

// ─── Base URL from env (set in Vercel dashboard) ──────────────────────────────
const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:4000';

// ─── State shape ──────────────────────────────────────────────────────────────
interface AppState {
  // Session data
  session: AnalysisSession | null;

  // Loading / error
  isLoading: boolean;
  isAnalyzing: boolean;
  uploadError: string | null;

  // UI
  activeView: 'upload' | 'dashboard' | 'agent' | 'port-intel' | 'images';
  sidebarCollapsed: boolean;

  // Setters
  setSession: (session: AnalysisSession | null) => void;
  setLoading: (loading: boolean) => void;
  setAnalyzing: (analyzing: boolean) => void;
  setActiveView: (view: AppState['activeView']) => void;
  toggleSidebar: () => void;
  clearError: () => void;

  // ── FLOW A: Demo mode (mock data only — never calls backend) ──────────────
  simulateUpload: (filename: string) => void;

  // ── FLOW B: Real upload (backend only — never uses mock data) ─────────────
  uploadPcap: (file: File) => Promise<void>;
}

// ─── Store ────────────────────────────────────────────────────────────────────
export const useAppStore = create<AppState>((set) => ({
  // Initial state
  session: null,
  isLoading: false,
  isAnalyzing: false,
  uploadError: null,
  activeView: 'upload',
  sidebarCollapsed: false,

  // Basic setters
  setSession: (session) => set({ session }),
  setLoading: (isLoading) => set({ isLoading }),
  setAnalyzing: (isAnalyzing) => set({ isAnalyzing }),
  setActiveView: (activeView) => set({ activeView }),
  toggleSidebar: () => set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),
  clearError: () => set({ uploadError: null }),

  // ────────────────────────────────────────────────────────────────────────────
  // FLOW A — Demo / Try It Out
  // Uses hardcoded mock data. Zero network requests. Always fast.
  // ────────────────────────────────────────────────────────────────────────────
  simulateUpload: (filename) => {
    set({ isLoading: true, isAnalyzing: true, uploadError: null });

    setTimeout(() => {
      const session: AnalysisSession = {
        session_id: `demo-${Date.now()}`,
        filename,
        uploaded_at: new Date(),
        summary: mockSummary,
        packets: mockPackets,
        vulnerabilities: mockVulnerabilities.alerts,
        images: mockImages,
      };

      set({
        session,
        isLoading: false,
        isAnalyzing: false,
        activeView: 'dashboard',
      });
    }, 2000);
  },

  // ────────────────────────────────────────────────────────────────────────────
  // FLOW B — Real Upload
  // Sends the .pcap file to the backend and fetches live analysis results.
  // Never touches mock data.
  // ────────────────────────────────────────────────────────────────────────────
  uploadPcap: async (file) => {
    set({ isLoading: true, isAnalyzing: true, uploadError: null });

    try {
      // ── Step 1: Upload file ────────────────────────────────────────────────
      const form = new FormData();
      form.append('file', file);

      const uploadRes = await fetch(`${API_BASE}/pcap/upload`, {
        method: 'POST',
        body: form,
      });

      if (!uploadRes.ok) {
        const err = await uploadRes.json().catch(() => ({ error: 'Upload failed' }));
        throw new Error(err.error ?? `HTTP ${uploadRes.status}`);
      }

      const { session_id, summary } = await uploadRes.json();

      // ── Step 2: Fetch packets (page 1, up to 200) ─────────────────────────
      const packetsRes = await fetch(
        `${API_BASE}/pcap/packets?session_id=${session_id}&page=1&per_page=200`
      );
      if (!packetsRes.ok) throw new Error('Failed to fetch packets');
      const { packets }: { packets: Packet[] } = await packetsRes.json();

      // ── Step 3: Fetch vulnerabilities ─────────────────────────────────────
      const vulnRes = await fetch(
        `${API_BASE}/pcap/vulnerabilities?session_id=${session_id}`
      );
      if (!vulnRes.ok) throw new Error('Failed to fetch vulnerabilities');
      const vulnData: { alerts: VulnerabilityAlert[] } = await vulnRes.json();

      // ── Step 4: Build session (images fetched lazily on the Images tab) ───
      const session: AnalysisSession = {
        session_id,
        filename: file.name,
        uploaded_at: new Date(),
        summary,
        packets,
        vulnerabilities: vulnData.alerts,
        images: [], // populated later when user visits Images tab
      };

      set({
        session,
        isLoading: false,
        isAnalyzing: false,
        activeView: 'dashboard',
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      set({
        isLoading: false,
        isAnalyzing: false,
        uploadError: message,
      });
    }
  },
}));
// Global State Store for PCAP Analyzer
import { create } from 'zustand';
import type {
  AnalysisSession,
  Packet,
  VulnerabilityAlert,
  ChatMessage,
  HttpObject,
} from './types';
import { mockPackets, mockSummary, mockVulnerabilities, mockImages } from './mock-data';

// ─── Base URL from env ─────────────────────────────────────────
const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? 'https://pcap-analyzer-backend.onrender.com';

// ─── State shape ──────────────────────────────────────────────────────────────
interface AppState {
  // Session data
  session: AnalysisSession | null;
  checkSession: () => Promise<void>;
  chatMessages: ChatMessage[];
  setChatMessages: (messages: ChatMessage[]) => void;
  clearChatMessages: () => void;
  scannedObjects: HttpObject[];
  setScannedObjects: (objects: HttpObject[]) => void;
  scanHasLoaded: boolean;
  // Dashboard cache
  dashboardCache: { summary: any; portData: any[]; threats: any } | null;
  setDashboardCache: (cache: { summary: any; portData: any[]; threats: any }) => void;
  clearDashboardCache: () => void;
  setScanHasLoaded: (val: boolean) => void;
  isAgentStreaming: boolean;
  streamingMessageId: string | null;

  // Loading / error
  isLoading: boolean;
  isAnalyzing: boolean;
  uploadError: string | null;

  // UI
  activeView: 'upload' | 'dashboard' | 'agent' | 'port-intel' | 'images' | 'manual-inspection' | 'analyzing';
  sidebarCollapsed: boolean;

  // Setters
  setSession: (session: AnalysisSession | null) => void;
  setLoading: (loading: boolean) => void;
  setAnalyzing: (analyzing: boolean) => void;
  setActiveView: (view: AppState['activeView']) => void;
  toggleSidebar: () => void;
  clearError: () => void;

  // ── FLOW A: Demo mode (mock data only)
  simulateUpload: (filename: string) => void;

  // ── FLOW B: Real upload (backend)
  uploadPcap: (file: File) => Promise<void>;

  // ── Fetch functions for on-demand data
  fetchPackets: (sessionId: string, page?: number, perPage?: number) => Promise<Packet[]>;
  fetchVulnerabilities: (sessionId: string) => Promise<VulnerabilityAlert[]>;
  fetchImages: (sessionId: string) => Promise<HttpObject[]>;
}

// ─── Store ────────────────────────────────────────────────────────────────────
export const useAppStore = create<AppState>((set, get) => ({
  // Initial state
  session: null,
  isLoading: false,
  isAnalyzing: false,
  uploadError: null,
  activeView: 'upload',
  sidebarCollapsed: false,
  chatMessages: [],
  scannedObjects: [],
  scanHasLoaded: false,
  isAgentStreaming: false,
  streamingMessageId: null as string | null,
  dashboardCache: null,


  // Basic setters
  setSession: (session) => set({ session }),
  setChatMessages: (chatMessages) => set({ chatMessages }),
  clearChatMessages: () => set({ chatMessages: [] }),
  setScannedObjects: (scannedObjects) => set({ scannedObjects }),
  setScanHasLoaded: (scanHasLoaded) => set({ scanHasLoaded }),
  setDashboardCache: (dashboardCache) => set({ dashboardCache }),
  clearDashboardCache: () => set({ dashboardCache: null }),

  checkSession: async () => {
    const session = get().session;
    if (!session?.session_id || session.session_id.startsWith('demo-')) return;
    try {
      const res = await fetch(`${API_BASE}/pcap/ping?session_id=${session.session_id}`);
      if (!res.ok) {
        set({ session: null, activeView: 'upload' });
      }
    } catch (_) { }
  },

  setLoading: (isLoading) => set({ isLoading }),
  setAnalyzing: (isAnalyzing) => set({ isAnalyzing }),
  setActiveView: (activeView) => set({ activeView }),
  toggleSidebar: () => set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),
  clearError: () => set({ uploadError: null }),

  // ────────────────────────────────────────────────────────────────────────────
  // FLOW A — Demo / Try It Out
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
        dashboardCache: null,
        chatMessages: [],
        scannedObjects: [],
        scanHasLoaded: false,
      });

    }, 2000);
  },

  // ────────────────────────────────────────────────────────────────────────────
  // FLOW B — Real Upload - Direct API calls, no pre-computation
  // ────────────────────────────────────────────────────────────────────────────
  uploadPcap: async (file) => {
    set({ isLoading: true, isAnalyzing: true, uploadError: null });

    try {
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

      const session: AnalysisSession = {
        session_id,
        filename: file.name,
        uploaded_at: new Date(),
        summary,
        packets: [],
        vulnerabilities: [],
        images: [],
      };

      set({
        session,
        isLoading: false,
        isAnalyzing: false,
        activeView: 'dashboard',
        dashboardCache: null,
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

  // ────────────────────────────────────────────────────────────────────────────
  // On-demand data fetching - Direct TShark calls
  // ────────────────────────────────────────────────────────────────────────────
  fetchPackets: async (sessionId, page = 1, perPage = 100) => {
    try {
      const res = await fetch(`${API_BASE}/pcap/packets?session_id=${sessionId}&page=${page}&per_page=${perPage}`);
      if (!res.ok) throw new Error('Failed to fetch packets');
      const data = await res.json();

      // Update session with fetched packets
      const currentSession = get().session;
      if (currentSession && currentSession.session_id === sessionId) {
        set({
          session: {
            ...currentSession,
            packets: data.packets || [],
          }
        });
      }

      return data.packets || [];
    } catch (err) {
      console.error('Error fetching packets:', err);
      return [];
    }
  },

  fetchVulnerabilities: async (sessionId) => {
    try {
      const res = await fetch(`${API_BASE}/pcap/vulnerabilities?session_id=${sessionId}`);
      if (!res.ok) throw new Error('Failed to fetch vulnerabilities');
      const data = await res.json();

      // Update session with fetched vulnerabilities
      const currentSession = get().session;
      if (currentSession && currentSession.session_id === sessionId) {
        set({
          session: {
            ...currentSession,
            vulnerabilities: data.alerts || [],
          }
        });
      }

      return data.alerts || [];
    } catch (err) {
      console.error('Error fetching vulnerabilities:', err);
      return [];
    }
  },

  fetchImages: async (sessionId) => {
    try {
      const res = await fetch(`${API_BASE}/pcap/images?session_id=${sessionId}`);
      if (!res.ok) throw new Error('Failed to fetch images');
      const data = await res.json();

      // Update session with fetched images
      const currentSession = get().session;
      if (currentSession && currentSession.session_id === sessionId) {
        set({
          session: {
            ...currentSession,
            images: data.images || [],
          }
        });
      }

      return data.images || [];
    } catch (err) {
      console.error('Error fetching images:', err);
      return [];
    }
  },
}));

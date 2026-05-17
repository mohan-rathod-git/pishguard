import { create } from 'zustand';
import { ScanHistoryItem, ThreatLevel, QRStatus } from '@/types';

interface AppStore {
  // Scan history
  history: ScanHistoryItem[];
  addHistory: (item: Omit<ScanHistoryItem, 'id' | 'timestamp'>) => void;
  clearHistory: () => void;

  // Live threat feed (mock real-time)
  liveThreats: ScanHistoryItem[];
  addLiveThreat: (item: Omit<ScanHistoryItem, 'id' | 'timestamp'>) => void;

  // Global state
  isConnected: boolean;
  setConnected: (v: boolean) => void;

  // Stats
  totalScans: number;
  totalBlocked: number;
  incrementScans: () => void;
  incrementBlocked: () => void;
}

let idCounter = 0;

export const useAppStore = create<AppStore>((set) => ({
  history: [],
  addHistory: (item) =>
    set((s) => ({
      history: [
        {
          ...item,
          id: `scan-${++idCounter}-${Date.now()}`,
          timestamp: new Date(),
        },
        ...s.history.slice(0, 49), // keep last 50
      ],
    })),
  clearHistory: () => set({ history: [] }),

  liveThreats: [],
  addLiveThreat: (item) =>
    set((s) => ({
      liveThreats: [
        {
          ...item,
          id: `live-${++idCounter}-${Date.now()}`,
          timestamp: new Date(),
        },
        ...s.liveThreats.slice(0, 19),
      ],
    })),

  isConnected: true,
  setConnected: (v) => set({ isConnected: v }),

  totalScans: 0,
  totalBlocked: 0,
  incrementScans: () => set((s) => ({ totalScans: s.totalScans + 1 })),
  incrementBlocked: () => set((s) => ({ totalBlocked: s.totalBlocked + 1 })),
}));

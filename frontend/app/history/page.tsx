'use client';

import { motion } from 'framer-motion';
import Navbar from '@/components/Navbar';
import HistoryTable from '@/components/HistoryTable';
import { useAppStore } from '@/store/useAppStore';
import { History, Trash2, Download } from 'lucide-react';
import toast from 'react-hot-toast';

export default function HistoryPage() {
  const { history, clearHistory } = useAppStore();

  const handleClear = () => {
    clearHistory();
    toast.success('Scan history cleared');
  };

  const handleExport = () => {
    const csv = [
      ['Type', 'Input', 'Verdict', 'Risk Score', 'Timestamp'],
      ...history.map((h) => [h.type, h.input, h.prediction || '', h.risk_score, h.timestamp.toISOString()]),
    ]
      .map((r) => r.join(','))
      .join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishguard-history-${Date.now()}.csv`;
    a.click();
    toast.success('History exported as CSV');
  };

  return (
    <main className="min-h-screen relative">
      <div className="fixed inset-0 cyber-grid opacity-20 pointer-events-none" />
      <Navbar />
      <div className="relative z-10 container max-w-5xl py-8">
        <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }}
          className="flex items-center justify-between mb-8">
          <div>
            <div className="text-xs font-mono text-cyber-blue uppercase tracking-widest mb-1">Scan Records</div>
            <h1 className="text-display text-3xl font-black text-white">Threat History</h1>
            <p className="text-sm text-cyber-muted mt-1">{history.length} scan{history.length !== 1 ? 's' : ''} recorded this session</p>
          </div>
          {history.length > 0 && (
            <div className="flex items-center gap-2">
              <motion.button whileHover={{ scale: 1.05 }} onClick={handleExport}
                className="cyber-btn cyber-btn-secondary text-xs px-4 py-2.5">
                <Download className="w-3.5 h-3.5" /> Export CSV
              </motion.button>
              <motion.button whileHover={{ scale: 1.05 }} onClick={handleClear}
                className="cyber-btn text-xs px-4 py-2.5"
                style={{ background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', color: '#ef4444' }}>
                <Trash2 className="w-3.5 h-3.5" /> Clear
              </motion.button>
            </div>
          )}
        </motion.div>

        {/* Summary stats */}
        {history.length > 0 && (
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
            className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            {[
              { label: 'Total Scans', value: history.length, color: '#4facfe' },
              { label: 'URL Scans', value: history.filter((h) => h.type === 'url').length, color: '#00f2fe' },
              { label: 'QR Scans', value: history.filter((h) => h.type === 'qr').length, color: '#a855f7' },
              { label: 'Threats Found', value: history.filter((h) => h.prediction !== 'SAFE').length, color: '#ef4444' },
            ].map((s) => (
              <div key={s.label} className="glass-card p-4 text-center">
                <div className="text-2xl font-black" style={{ color: s.color }}>{s.value}</div>
                <div className="text-xs text-cyber-muted mt-1">{s.label}</div>
              </div>
            ))}
          </motion.div>
        )}

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="glass-card p-5">
          <div className="flex items-center gap-2 mb-5">
            <History className="w-4 h-4 text-cyber-blue" />
            <span className="text-sm font-bold text-white">All Scans</span>
          </div>
          <HistoryTable items={history} />
        </motion.div>
      </div>
    </main>
  );
}

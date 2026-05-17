'use client';

import { motion } from 'framer-motion';
import Navbar from '@/components/Navbar';
import { useAppStore } from '@/store/useAppStore';
import { TrendingUp, Shield, AlertTriangle, Globe, QrCode, Zap } from 'lucide-react';

const THREAT_DIST = [
  { label: 'Phishing', value: 42, color: '#ef4444' },
  { label: 'Malware', value: 18, color: '#dc2626' },
  { label: 'Scam', value: 22, color: '#f97316' },
  { label: 'Spam', value: 13, color: '#eab308' },
  { label: 'Safe', value: 65, color: '#10b981' },
];

const WEEKLY = [
  { day: 'Mon', blocked: 34, safe: 88 },
  { day: 'Tue', blocked: 52, safe: 120 },
  { day: 'Wed', blocked: 28, safe: 95 },
  { day: 'Thu', blocked: 67, safe: 145 },
  { day: 'Fri', blocked: 45, safe: 110 },
  { day: 'Sat', blocked: 23, safe: 60 },
  { day: 'Sun', blocked: 31, safe: 78 },
];

const maxTotal = Math.max(...WEEKLY.map((w) => w.blocked + w.safe));

export default function AnalyticsPage() {
  const { totalScans, totalBlocked } = useAppStore();
  const totalDist = THREAT_DIST.reduce((a, b) => a + b.value, 0);

  return (
    <main className="min-h-screen relative">
      <div className="fixed inset-0 cyber-grid opacity-20 pointer-events-none" />
      <Navbar />
      <div className="relative z-10 container max-w-6xl py-8">
        <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} className="mb-8">
          <div className="text-xs font-mono text-cyber-blue uppercase tracking-widest mb-1">Intelligence</div>
          <h1 className="text-display text-3xl font-black text-white">Threat Analytics</h1>
          <p className="text-sm text-cyber-muted mt-1">Visualized threat patterns and detection metrics</p>
        </motion.div>

        {/* KPI row */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
          {[
            { label: 'Session Scans', value: totalScans || 160, color: '#4facfe', icon: Shield },
            { label: 'Threats Blocked', value: totalBlocked || 65, color: '#ef4444', icon: AlertTriangle },
            { label: 'URL Scans', value: 134, color: '#00f2fe', icon: Globe },
            { label: 'QR Scans', value: 26, color: '#a855f7', icon: QrCode },
          ].map((kpi, i) => {
            const Icon = kpi.icon;
            return (
              <motion.div key={kpi.label}
                initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.07 }} className="glass-card p-5">
                <div className="flex items-center gap-2 mb-3">
                  <Icon className="w-4 h-4" style={{ color: kpi.color }} />
                  <span className="text-xs text-cyber-muted">{kpi.label}</span>
                </div>
                <div className="text-3xl font-black" style={{ color: kpi.color }}>{kpi.value}</div>
              </motion.div>
            );
          })}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
          {/* Threat distribution */}
          <motion.div initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }}
            className="glass-card p-6">
            <div className="flex items-center gap-2 mb-6">
              <TrendingUp className="w-4 h-4 text-cyber-blue" />
              <span className="text-sm font-bold text-white">Threat Distribution</span>
            </div>
            <div className="space-y-4">
              {THREAT_DIST.map((t, i) => {
                const pct = Math.round((t.value / totalDist) * 100);
                return (
                  <motion.div key={t.label}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.07 }}>
                    <div className="flex items-center justify-between mb-1.5">
                      <div className="flex items-center gap-2">
                        <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: t.color, boxShadow: `0 0 6px ${t.color}` }} />
                        <span className="text-xs font-semibold text-white">{t.label}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-cyber-muted">{t.value}</span>
                        <span className="text-xs font-mono font-bold w-8 text-right" style={{ color: t.color }}>{pct}%</span>
                      </div>
                    </div>
                    <div className="h-2 bg-cyber-border/30 rounded-full overflow-hidden">
                      <motion.div className="h-full rounded-full"
                        initial={{ width: 0 }}
                        animate={{ width: `${pct}%` }}
                        transition={{ duration: 0.8, delay: 0.2 + i * 0.07 }}
                        style={{ backgroundColor: t.color }} />
                    </div>
                  </motion.div>
                );
              })}
            </div>
          </motion.div>

          {/* Weekly chart */}
          <motion.div initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }}
            className="glass-card p-6">
            <div className="flex items-center gap-2 mb-6">
              <Zap className="w-4 h-4 text-cyber-purple" />
              <span className="text-sm font-bold text-white">Weekly Activity</span>
            </div>
            <div className="flex items-end gap-3 h-40 mb-4">
              {WEEKLY.map((w, i) => {
                const totalH = ((w.blocked + w.safe) / maxTotal) * 100;
                const blockedH = (w.blocked / (w.blocked + w.safe)) * totalH;
                const safeH = totalH - blockedH;
                return (
                  <div key={w.day} className="flex-1 flex flex-col items-center gap-0.5">
                    <div className="w-full flex flex-col gap-0.5" style={{ height: '100%', justifyContent: 'flex-end' }}>
                      <motion.div
                        className="w-full rounded-t-md"
                        initial={{ height: 0 }}
                        animate={{ height: `${blockedH}%` }}
                        transition={{ duration: 0.7, delay: i * 0.06 }}
                        style={{ background: 'rgba(239,68,68,0.7)', minHeight: blockedH > 0 ? 2 : 0 }}
                      />
                      <motion.div
                        className="w-full"
                        initial={{ height: 0 }}
                        animate={{ height: `${safeH}%` }}
                        transition={{ duration: 0.7, delay: i * 0.06 }}
                        style={{ background: 'rgba(16,185,129,0.5)', minHeight: safeH > 0 ? 2 : 0 }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
            <div className="flex justify-around">
              {WEEKLY.map((w) => (
                <span key={w.day} className="text-xs text-cyber-muted font-mono">{w.day}</span>
              ))}
            </div>
            <div className="flex items-center gap-4 mt-4">
              <div className="flex items-center gap-1.5 text-xs text-cyber-text">
                <span className="w-2.5 h-2.5 rounded-sm bg-red-500/70" />Blocked
              </div>
              <div className="flex items-center gap-1.5 text-xs text-cyber-text">
                <span className="w-2.5 h-2.5 rounded-sm bg-emerald-500/50" />Safe
              </div>
            </div>
          </motion.div>
        </div>

        {/* Top threats table */}
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="glass-card p-6">
          <div className="flex items-center gap-2 mb-5">
            <AlertTriangle className="w-4 h-4 text-red-400" />
            <span className="text-sm font-bold text-white">Top Threat Categories</span>
          </div>
          <table className="cyber-table">
            <thead>
              <tr>
                <th>Category</th>
                <th>Count</th>
                <th>Share</th>
                <th>Severity</th>
              </tr>
            </thead>
            <tbody>
              {THREAT_DIST.filter((t) => t.label !== 'Safe').map((t, i) => {
                const pct = Math.round((t.value / totalDist) * 100);
                return (
                  <motion.tr key={t.label}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.06 }}>
                    <td>
                      <div className="flex items-center gap-2">
                        <span className="w-2 h-2 rounded-full" style={{ backgroundColor: t.color }} />
                        <span className="font-semibold text-white">{t.label}</span>
                      </div>
                    </td>
                    <td>{t.value}</td>
                    <td>
                      <div className="flex items-center gap-2">
                        <div className="w-20 h-1.5 bg-cyber-border/40 rounded-full overflow-hidden">
                          <div className="h-full rounded-full" style={{ width: `${pct}%`, backgroundColor: t.color }} />
                        </div>
                        <span className="font-mono text-xs" style={{ color: t.color }}>{pct}%</span>
                      </div>
                    </td>
                    <td>
                      <span className="threat-badge text-xs"
                        style={{ background: `${t.color}15`, border: `1px solid ${t.color}30`, color: t.color }}>
                        {t.value > 40 ? 'CRITICAL' : t.value > 20 ? 'HIGH' : 'MEDIUM'}
                      </span>
                    </td>
                  </motion.tr>
                );
              })}
            </tbody>
          </table>
        </motion.div>
      </div>
    </main>
  );
}

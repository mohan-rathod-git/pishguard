'use client';

import { motion } from 'framer-motion';
import { useEffect, useState } from 'react';
import Link from 'next/link';
import Navbar from '@/components/Navbar';
import RiskMeter from '@/components/RiskMeter';
import HistoryTable from '@/components/HistoryTable';
import { useAppStore } from '@/store/useAppStore';
import { getHealth, getQRHealth, getModelInfo } from '@/lib/api';
import {
  Shield, Globe, QrCode, Activity, Zap,
  TrendingUp, TrendingDown, AlertTriangle, CheckCircle,
  ArrowRight, RefreshCw, Cpu, Server, Lock
} from 'lucide-react';

const MOCK_THREATS = [
  { url: 'http://paypal-verify.ru/login', type: 'PHISHING', risk: 96, time: '2s ago' },
  { url: 'https://bit.ly/3xFreeGift', type: 'SCAM', risk: 82, time: '18s ago' },
  { url: 'http://malware-cdn.xyz/payload.exe', type: 'MALWARE', risk: 99, time: '45s ago' },
  { url: 'http://fake-upi-payment.in/qr', type: 'PHISHING', risk: 91, time: '1m ago' },
  { url: 'https://spam-casino-bet.net', type: 'SPAM', risk: 74, time: '2m ago' },
];

const THREAT_COLORS: Record<string, string> = {
  PHISHING: '#ef4444',
  MALWARE: '#dc2626',
  SCAM: '#f97316',
  SPAM: '#eab308',
  SAFE: '#10b981',
};

function MetricCard({
  label, value, subtext, icon: Icon, color, trend
}: {
  label: string; value: string; subtext?: string;
  icon: React.ElementType; color: string; trend?: 'up' | 'down';
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      whileHover={{ y: -3 }}
      className="glass-card p-5"
    >
      <div className="flex items-start justify-between mb-4">
        <div
          className="w-10 h-10 rounded-xl flex items-center justify-center"
          style={{ background: `${color}15`, border: `1px solid ${color}30` }}
        >
          <Icon className="w-5 h-5" style={{ color }} />
        </div>
        {trend && (
          <div className={`flex items-center gap-1 text-xs font-semibold ${trend === 'up' ? 'text-emerald-400' : 'text-red-400'}`}>
            {trend === 'up' ? <TrendingUp className="w-3.5 h-3.5" /> : <TrendingDown className="w-3.5 h-3.5" />}
          </div>
        )}
      </div>
      <div className="text-2xl font-black text-white mb-0.5">{value}</div>
      <div className="text-xs font-semibold text-cyber-muted uppercase tracking-wider">{label}</div>
      {subtext && <div className="text-xs text-cyber-muted/70 mt-1">{subtext}</div>}
    </motion.div>
  );
}

export default function DashboardPage() {
  const { history, totalScans, totalBlocked } = useAppStore();
  const [apiStatus, setApiStatus] = useState<{ url: boolean; qr: boolean; model: string }>({
    url: false, qr: false, model: '—',
  });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const [health, qrHealth, modelInfo] = await Promise.allSettled([
          getHealth(), getQRHealth(), getModelInfo(),
        ]);
        setApiStatus({
          url: health.status === 'fulfilled' && health.value.model_loaded,
          qr: qrHealth.status === 'fulfilled' && qrHealth.value.qr_engine_active,
          model: modelInfo.status === 'fulfilled' ? modelInfo.value.model_type : 'Unknown',
        });
      } catch {
        // silently fail
      } finally {
        setLoading(false);
      }
    };
    fetchStatus();
  }, []);

  const blockRate = totalScans > 0 ? Math.round((totalBlocked / totalScans) * 100) : 0;

  return (
    <main className="min-h-screen relative">
      <div className="fixed inset-0 cyber-grid opacity-20 pointer-events-none" />
      <Navbar />

      <div className="relative z-10 container max-w-7xl py-8">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex items-center justify-between mb-8"
        >
          <div>
            <div className="text-xs font-mono text-cyber-blue uppercase tracking-widest mb-2">Security Command Center</div>
            <h1 className="text-display text-3xl font-black text-white">Dashboard</h1>
            <p className="text-sm text-cyber-muted mt-1">Real-time threat intelligence and scan analytics</p>
          </div>
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 px-3 py-2 rounded-xl text-xs font-semibold"
              style={{ background: 'rgba(16,185,129,0.1)', border: '1px solid rgba(16,185,129,0.2)', color: '#10b981' }}>
              <span className="w-1.5 h-1.5 rounded-full bg-cyber-green animate-pulse" />
              Systems Operational
            </div>
            <Link href="/scan">
              <motion.button whileHover={{ scale: 1.05 }} className="cyber-btn cyber-btn-primary text-xs px-4 py-2.5">
                <Zap className="w-3.5 h-3.5" />
                New Scan
              </motion.button>
            </Link>
          </div>
        </motion.div>

        {/* Metric cards */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          <MetricCard label="Total Scans" value={totalScans.toString()} icon={Shield} color="#4facfe" trend="up" subtext="This session" />
          <MetricCard label="Threats Blocked" value={totalBlocked.toString()} icon={AlertTriangle} color="#ef4444" trend="down" subtext="Active protection" />
          <MetricCard label="Block Rate" value={`${blockRate}%`} icon={Lock} color="#a855f7" subtext="Session average" />
          <MetricCard label="Avg Response" value="<240ms" icon={Zap} color="#10b981" trend="up" subtext="Sub-300ms target" />
        </div>

        {/* System status + quick actions */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
          {/* System status */}
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            className="glass-card p-5"
          >
            <div className="flex items-center gap-2 mb-5">
              <Server className="w-4 h-4 text-cyber-blue" />
              <span className="text-sm font-bold text-white">System Status</span>
            </div>
            <div className="space-y-3">
              {[
                { label: 'URL Detection API', active: apiStatus.url, loading },
                { label: 'QR Security Engine', active: apiStatus.qr, loading },
                { label: 'ML Model', active: true, loading, detail: apiStatus.model },
                { label: 'Batch Predictor', active: true, loading },
              ].map((s) => (
                <div key={s.label} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span
                      className="w-2 h-2 rounded-full"
                      style={{
                        backgroundColor: s.loading ? '#64748b' : s.active ? '#10b981' : '#ef4444',
                        boxShadow: s.active && !s.loading ? '0 0 8px #10b981' : undefined,
                      }}
                    />
                    <span className="text-xs text-cyber-text">{s.label}</span>
                  </div>
                  <span className="text-xs font-mono font-bold"
                    style={{ color: s.loading ? '#64748b' : s.active ? '#10b981' : '#ef4444' }}>
                    {s.loading ? '...' : s.detail || (s.active ? 'ONLINE' : 'OFFLINE')}
                  </span>
                </div>
              ))}
            </div>
          </motion.div>

          {/* Quick scan */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="glass-card p-5"
          >
            <div className="flex items-center gap-2 mb-5">
              <Zap className="w-4 h-4 text-cyber-blue" />
              <span className="text-sm font-bold text-white">Quick Actions</span>
            </div>
            <div className="space-y-3">
              {[
                { label: 'Scan URL', href: '/scan', icon: Globe, color: '#4facfe' },
                { label: 'Scan QR Code', href: '/qr', icon: QrCode, color: '#a855f7' },
                { label: 'Live Monitor', href: '/monitor', icon: Activity, color: '#10b981' },
                { label: 'View Analytics', href: '/analytics', icon: TrendingUp, color: '#f97316' },
              ].map((a) => {
                const Icon = a.icon;
                return (
                  <Link key={a.href} href={a.href}>
                    <motion.div
                      whileHover={{ x: 4 }}
                      className="flex items-center justify-between p-3 rounded-xl cursor-pointer transition-all hover:bg-white/3"
                      style={{ border: '1px solid rgba(30,45,69,0.4)' }}
                    >
                      <div className="flex items-center gap-2.5">
                        <div className="w-8 h-8 rounded-lg flex items-center justify-center"
                          style={{ background: `${a.color}15` }}>
                          <Icon className="w-4 h-4" style={{ color: a.color }} />
                        </div>
                        <span className="text-sm font-semibold text-white">{a.label}</span>
                      </div>
                      <ArrowRight className="w-3.5 h-3.5 text-cyber-muted" />
                    </motion.div>
                  </Link>
                );
              })}
            </div>
          </motion.div>

          {/* Risk meter overview */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            className="glass-card p-5 flex flex-col items-center justify-center"
          >
            <div className="text-xs font-mono text-cyber-muted uppercase tracking-widest mb-4">Session Block Rate</div>
            <RiskMeter score={blockRate} size="lg" />
            <div className="mt-4 text-center">
              <div className="text-xs text-cyber-muted">
                {totalBlocked} of {totalScans} scans blocked
              </div>
            </div>
          </motion.div>
        </div>

        {/* Live threat feed + history */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Live threats */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="glass-card p-5"
          >
            <div className="flex items-center justify-between mb-5">
              <div className="flex items-center gap-2">
                <Activity className="w-4 h-4 text-red-400" />
                <span className="text-sm font-bold text-white">Live Threat Feed</span>
              </div>
              <span className="flex items-center gap-1.5 text-xs text-red-400 font-semibold">
                <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-pulse" />
                LIVE
              </span>
            </div>
            <div className="space-y-2">
              {MOCK_THREATS.map((t, i) => (
                <motion.div
                  key={i}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.08 }}
                  className="flex items-center gap-3 p-3 rounded-xl"
                  style={{ background: `${THREAT_COLORS[t.type]}08`, border: `1px solid ${THREAT_COLORS[t.type]}20` }}
                >
                  <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" style={{ color: THREAT_COLORS[t.type] }} />
                  <div className="flex-1 min-w-0">
                    <div className="text-xs font-mono text-cyber-text truncate">{t.url}</div>
                    <div className="text-xs text-cyber-muted mt-0.5">{t.time}</div>
                  </div>
                  <span className="text-xs font-black font-mono flex-shrink-0" style={{ color: THREAT_COLORS[t.type] }}>
                    {t.risk}
                  </span>
                </motion.div>
              ))}
            </div>
            <Link href="/monitor">
              <motion.div whileHover={{ x: 2 }} className="flex items-center justify-center gap-2 mt-4 text-xs text-cyber-blue font-semibold cursor-pointer">
                View Live Monitor <ArrowRight className="w-3.5 h-3.5" />
              </motion.div>
            </Link>
          </motion.div>

          {/* Recent scan history */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="glass-card p-5"
          >
            <div className="flex items-center justify-between mb-5">
              <div className="flex items-center gap-2">
                <Shield className="w-4 h-4 text-cyber-blue" />
                <span className="text-sm font-bold text-white">Recent Scans</span>
              </div>
              <Link href="/history">
                <span className="text-xs text-cyber-blue hover:text-cyber-cyan transition-colors cursor-pointer">View All</span>
              </Link>
            </div>
            <HistoryTable items={history.slice(0, 5)} compact />
          </motion.div>
        </div>
      </div>
    </main>
  );
}

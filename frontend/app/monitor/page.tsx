'use client';

import { motion, AnimatePresence } from 'framer-motion';
import { useEffect, useState, useRef } from 'react';
import Navbar from '@/components/Navbar';
import { Activity, Shield, AlertTriangle, Globe, QrCode, Zap } from 'lucide-react';
import { getThreatColor, formatTimeAgo } from '@/lib/utils';
import { ThreatLevel } from '@/types';

interface LiveEvent {
  id: string;
  url: string;
  type: 'url' | 'qr';
  threat: ThreatLevel;
  risk: number;
  country: string;
  timestamp: Date;
}

const COUNTRIES = ['India', 'Russia', 'China', 'USA', 'Ukraine', 'Brazil', 'Nigeria', 'Germany'];
const THREATS: ThreatLevel[] = ['PHISHING', 'MALWARE', 'SCAM', 'SPAM', 'SAFE', 'SAFE', 'SAFE'];
const SAMPLE_URLS = [
  'http://paypal-verify.ru/signin',
  'https://free-crypto-win.xyz/claim',
  'http://bank-login-secure.in/auth',
  'https://amazon-gift.suspicious.com',
  'http://malware-host.cn/payload',
  'https://legit-news.com/article',
  'https://github.com/repo',
  'http://upi-fake-payment.ru',
  'https://google.com',
];

let liveIdCounter = 0;
function generateEvent(): LiveEvent {
  const threat = THREATS[Math.floor(Math.random() * THREATS.length)];
  return {
    id: `live-${++liveIdCounter}`,
    url: SAMPLE_URLS[Math.floor(Math.random() * SAMPLE_URLS.length)],
    type: Math.random() > 0.8 ? 'qr' : 'url',
    threat,
    risk: threat === 'SAFE' ? Math.floor(Math.random() * 20) : Math.floor(Math.random() * 40) + 60,
    country: COUNTRIES[Math.floor(Math.random() * COUNTRIES.length)],
    timestamp: new Date(),
  };
}

export default function MonitorPage() {
  const [events, setEvents] = useState<LiveEvent[]>(() => Array.from({ length: 8 }, generateEvent));
  const [stats, setStats] = useState({ total: 1247, blocked: 342, safe: 905 });
  const [paused, setPaused] = useState(false);
  const intervalRef = useRef<NodeJS.Timeout | null>(null);

  useEffect(() => {
    if (!paused) {
      intervalRef.current = setInterval(() => {
        const e = generateEvent();
        setEvents((prev) => [e, ...prev.slice(0, 24)]);
        setStats((s) => ({
          total: s.total + 1,
          blocked: e.threat !== 'SAFE' ? s.blocked + 1 : s.blocked,
          safe: e.threat === 'SAFE' ? s.safe + 1 : s.safe,
        }));
      }, 2200);
    }
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [paused]);

  const blockedPct = Math.round((stats.blocked / stats.total) * 100);

  return (
    <main className="min-h-screen relative">
      <div className="fixed inset-0 cyber-grid opacity-20 pointer-events-none" />
      <Navbar />
      <div className="relative z-10 container max-w-6xl py-8">
        <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }}
          className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-8">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="w-2 h-2 rounded-full bg-red-400 animate-pulse" />
              <span className="text-xs font-mono text-red-400 uppercase tracking-widest">Live</span>
            </div>
            <h1 className="text-display text-3xl font-black text-white">Threat Monitor</h1>
            <p className="text-sm text-cyber-muted mt-1">Real-time global threat detection feed</p>
          </div>
          <motion.button whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}
            onClick={() => setPaused(!paused)}
            className={`cyber-btn text-sm px-5 py-2.5 ${paused ? 'cyber-btn-primary' : 'cyber-btn-secondary'}`}>
            {paused ? <><Activity className="w-4 h-4" /> Resume</> : <><Shield className="w-4 h-4" /> Pause</>}
          </motion.button>
        </motion.div>

        <div className="grid grid-cols-3 gap-4 mb-6">
          {[
            { label: 'Total Events', value: stats.total.toLocaleString(), color: '#4facfe', icon: Activity },
            { label: 'Threats Blocked', value: stats.blocked.toLocaleString(), color: '#ef4444', icon: AlertTriangle },
            { label: 'Safe Requests', value: stats.safe.toLocaleString(), color: '#10b981', icon: Shield },
          ].map((s, i) => {
            const Icon = s.icon;
            return (
              <motion.div key={s.label} initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.08 }} className="glass-card p-4 text-center">
                <Icon className="w-5 h-5 mx-auto mb-2" style={{ color: s.color }} />
                <div className="text-xl font-black text-white">{s.value}</div>
                <div className="text-xs text-cyber-muted mt-0.5">{s.label}</div>
              </motion.div>
            );
          })}
        </div>

        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="glass-card p-4 mb-6">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-semibold text-cyber-muted uppercase tracking-wider">Threat Rate</span>
            <span className="text-xs font-mono font-black text-red-400">{blockedPct}% blocked</span>
          </div>
          <div className="h-2.5 bg-cyber-border/30 rounded-full overflow-hidden">
            <motion.div initial={{ width: 0 }} animate={{ width: `${blockedPct}%` }}
              transition={{ duration: 1 }} className="h-full rounded-full"
              style={{ background: 'linear-gradient(90deg, #ef4444, #f97316)' }} />
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="glass-card overflow-hidden">
          <div className="flex items-center justify-between px-6 py-4 border-b border-cyber-border/30">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-red-400" />
              <span className="text-sm font-bold text-white">Live Event Stream</span>
            </div>
            <div className="flex items-center gap-1.5 text-xs font-semibold" style={{ color: paused ? '#64748b' : '#ef4444' }}>
              <span className="w-1.5 h-1.5 rounded-full animate-pulse" style={{ backgroundColor: paused ? '#64748b' : '#ef4444' }} />
              {paused ? 'PAUSED' : 'LIVE'}
            </div>
          </div>
          <div className="divide-y divide-cyber-border/20 max-h-[560px] overflow-y-auto">
            <AnimatePresence initial={false}>
              {events.map((event) => {
                const color = getThreatColor(event.threat);
                return (
                  <motion.div key={event.id}
                    initial={{ opacity: 0, x: -20, height: 0 }}
                    animate={{ opacity: 1, x: 0, height: 'auto' }}
                    exit={{ opacity: 0, height: 0 }}
                    transition={{ duration: 0.3 }}
                    className="flex items-center gap-4 px-6 py-3.5 hover:bg-white/2 transition-colors">
                    <div className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
                      style={{ background: `${color}15`, border: `1px solid ${color}30` }}>
                      {event.type === 'qr' ? <QrCode className="w-4 h-4" style={{ color }} /> : <Globe className="w-4 h-4" style={{ color }} />}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="font-mono text-xs text-cyber-text truncate">{event.url}</div>
                      <div className="text-xs text-cyber-muted mt-0.5">{event.country} · {formatTimeAgo(event.timestamp)}</div>
                    </div>
                    <span className="threat-badge text-xs flex-shrink-0"
                      style={{ background: `${color}15`, border: `1px solid ${color}30`, color }}>
                      {event.threat}
                    </span>
                    <div className="flex items-center gap-2 flex-shrink-0 w-16">
                      <div className="flex-1 h-1.5 bg-cyber-border/40 rounded-full overflow-hidden">
                        <div className="h-full rounded-full" style={{ width: `${event.risk}%`, backgroundColor: color }} />
                      </div>
                      <span className="text-xs font-mono font-bold w-6 text-right" style={{ color }}>{event.risk}</span>
                    </div>
                    {event.threat === 'SAFE'
                      ? <span className="w-2 h-2 rounded-full bg-emerald-400 flex-shrink-0" />
                      : <motion.div animate={{ scale: [1, 1.3, 1] }} transition={{ duration: 0.4 }}>
                          <Zap className="w-3.5 h-3.5 flex-shrink-0" style={{ color }} />
                        </motion.div>}
                  </motion.div>
                );
              })}
            </AnimatePresence>
          </div>
        </motion.div>
      </div>
    </main>
  );
}

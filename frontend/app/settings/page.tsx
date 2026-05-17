'use client';

import { motion } from 'framer-motion';
import { useState } from 'react';
import Navbar from '@/components/Navbar';
import {
  Settings, Globe, Bell, Shield, Key,
  Moon, Sun, Monitor, Check, Copy, RefreshCw
} from 'lucide-react';
import toast from 'react-hot-toast';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1';

export default function SettingsPage() {
  const [apiUrl, setApiUrl] = useState(API_URL);
  const [notifications, setNotifications] = useState(true);
  const [autoScan, setAutoScan] = useState(false);
  const [theme, setTheme] = useState<'dark' | 'light' | 'system'>('dark');
  const [rateLimit, setRateLimit] = useState('100');
  const [copied, setCopied] = useState(false);

  const handleSave = () => toast.success('Settings saved successfully');

  const handleCopyKey = () => {
    navigator.clipboard.writeText('pg_sk_demo_1234567890abcdef');
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
    toast.success('API key copied!');
  };

  const Toggle = ({ value, onChange }: { value: boolean; onChange: (v: boolean) => void }) => (
    <button onClick={() => onChange(!value)}
      className="relative w-11 h-6 rounded-full transition-all duration-300 flex-shrink-0"
      style={{ background: value ? '#4facfe' : 'rgba(30,45,69,0.8)' }}>
      <motion.span animate={{ x: value ? 20 : 2 }}
        className="absolute top-1 w-4 h-4 rounded-full bg-white shadow-sm" />
    </button>
  );

  const Section = ({ title, icon: Icon, children }: { title: string; icon: React.ElementType; children: React.ReactNode }) => (
    <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="glass-card p-6 mb-5">
      <div className="flex items-center gap-2 mb-5 pb-4 border-b border-cyber-border/30">
        <Icon className="w-4 h-4 text-cyber-blue" />
        <span className="text-sm font-bold text-white">{title}</span>
      </div>
      <div className="space-y-5">{children}</div>
    </motion.div>
  );

  const Row = ({ label, desc, children }: { label: string; desc?: string; children: React.ReactNode }) => (
    <div className="flex items-center justify-between gap-4">
      <div>
        <div className="text-sm font-semibold text-white">{label}</div>
        {desc && <div className="text-xs text-cyber-muted mt-0.5">{desc}</div>}
      </div>
      {children}
    </div>
  );

  return (
    <main className="min-h-screen relative">
      <div className="fixed inset-0 cyber-grid opacity-20 pointer-events-none" />
      <Navbar />
      <div className="relative z-10 container max-w-2xl py-8">
        <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} className="mb-8">
          <div className="text-xs font-mono text-cyber-blue uppercase tracking-widest mb-1">Configuration</div>
          <h1 className="text-display text-3xl font-black text-white">Settings</h1>
          <p className="text-sm text-cyber-muted mt-1">Customize your PhishGuard experience</p>
        </motion.div>

        {/* API Config */}
        <Section title="API Configuration" icon={Globe}>
          <Row label="Backend API URL" desc="PhishGuard FastAPI endpoint">
            <div className="flex-1 max-w-xs">
              <input className="cyber-input text-xs py-2 px-3" value={apiUrl}
                onChange={(e) => setApiUrl(e.target.value)} />
            </div>
          </Row>
          <Row label="Max Batch Size" desc="URLs per batch request">
            <div className="w-24">
              <input className="cyber-input text-xs py-2 px-3 text-center" type="number"
                value={rateLimit} onChange={(e) => setRateLimit(e.target.value)} />
            </div>
          </Row>
        </Section>

        {/* API Key */}
        <Section title="API Key" icon={Key}>
          <Row label="Your API Key" desc="Use this key to authenticate API requests">
            <div className="flex items-center gap-2">
              <div className="font-mono text-xs text-cyber-muted bg-cyber-surface/50 border border-cyber-border/40 px-3 py-2 rounded-lg truncate max-w-[160px]">
                pg_sk_demo_••••••••••••
              </div>
              <motion.button whileHover={{ scale: 1.05 }} onClick={handleCopyKey}
                className="w-8 h-8 rounded-lg flex items-center justify-center transition-all"
                style={{ background: copied ? 'rgba(16,185,129,0.2)' : 'rgba(79,172,254,0.1)', border: '1px solid rgba(79,172,254,0.2)' }}>
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-cyber-blue" />}
              </motion.button>
              <motion.button whileHover={{ scale: 1.05 }}
                className="w-8 h-8 rounded-lg flex items-center justify-center"
                style={{ background: 'rgba(79,172,254,0.1)', border: '1px solid rgba(79,172,254,0.2)' }}>
                <RefreshCw className="w-3.5 h-3.5 text-cyber-blue" />
              </motion.button>
            </div>
          </Row>
        </Section>

        {/* Appearance */}
        <Section title="Appearance" icon={Monitor}>
          <Row label="Theme" desc="Choose your preferred color scheme">
            <div className="flex gap-2">
              {[
                { id: 'dark', icon: Moon, label: 'Dark' },
                { id: 'light', icon: Sun, label: 'Light' },
                { id: 'system', icon: Monitor, label: 'System' },
              ].map((t) => {
                const Icon = t.icon;
                return (
                  <button key={t.id} onClick={() => setTheme(t.id as 'dark' | 'light' | 'system')}
                    className="flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-semibold transition-all"
                    style={{
                      background: theme === t.id ? 'rgba(79,172,254,0.15)' : 'rgba(13,18,32,0.6)',
                      border: `1px solid ${theme === t.id ? 'rgba(79,172,254,0.4)' : 'rgba(30,45,69,0.6)'}`,
                      color: theme === t.id ? '#4facfe' : '#64748b',
                    }}>
                    <Icon className="w-3.5 h-3.5" />{t.label}
                  </button>
                );
              })}
            </div>
          </Row>
        </Section>

        {/* Notifications */}
        <Section title="Notifications & Scanning" icon={Bell}>
          <Row label="Toast Notifications" desc="Show alerts when threats are detected">
            <Toggle value={notifications} onChange={setNotifications} />
          </Row>
          <Row label="Auto-Scan Clipboard" desc="Automatically scan URLs copied to clipboard">
            <Toggle value={autoScan} onChange={setAutoScan} />
          </Row>
        </Section>

        {/* Security */}
        <Section title="Security" icon={Shield}>
          <Row label="Block Threshold" desc="Risk score above which URLs are auto-blocked">
            <div className="flex items-center gap-3">
              <input type="range" min="30" max="90" defaultValue="60"
                className="w-28 accent-cyber-blue" />
              <span className="text-xs font-mono text-cyber-blue w-8">60</span>
            </div>
          </Row>
          <Row label="Follow Redirects" desc="Trace redirect chains in QR scans">
            <Toggle value={true} onChange={() => {}} />
          </Row>
          <Row label="Use ML Model" desc="Apply XGBoost classifier for predictions">
            <Toggle value={true} onChange={() => {}} />
          </Row>
        </Section>

        {/* Save button */}
        <motion.button whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.98 }} onClick={handleSave}
          className="w-full cyber-btn cyber-btn-primary py-4 rounded-2xl font-black text-cyber-black">
          Save Settings
        </motion.button>
      </div>
    </main>
  );
}

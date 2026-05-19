'use client';

import { motion, useInView } from 'framer-motion';
import Link from 'next/link';
import { useRef, useState, useEffect } from 'react';
import {
  Shield, Globe, QrCode, Zap, Lock, Activity,
  ArrowRight, Check, Terminal
} from 'lucide-react';
import Navbar from '@/components/Navbar';
import ParticleBackground from '@/components/ParticleBackground';

const features = [
  {
    icon: Globe,
    title: 'URL Threat Detection',
    desc: 'AI-powered analysis of malicious URLs, phishing sites, malware domains, and scam links with 98%+ accuracy.',
    color: '#4facfe',
    bg: 'rgba(79,172,254,0.1)',
  },
  {
    icon: QrCode,
    title: 'QR Code Security',
    desc: 'Decode and analyze QR codes for hidden threats, fake payment redirects, and malicious payloads in real-time.',
    color: '#a855f7',
    bg: 'rgba(168,85,247,0.1)',
  },
  {
    icon: Zap,
    title: 'Real-time Analysis',
    desc: 'Sub-300ms threat detection with deep redirect chain analysis and explainable AI risk scoring.',
    color: '#00f2fe',
    bg: 'rgba(0,242,254,0.1)',
  },
  {
    icon: Lock,
    title: 'Multi-Layer Defense',
    desc: 'XGBoost ML model with 25+ extracted URL features, reputation scoring, and cascade routing.',
    color: '#10b981',
    bg: 'rgba(16,185,129,0.1)',
  },
  {
    icon: Activity,
    title: 'Live Threat Monitor',
    desc: 'Real-time threat feed with animated cyber attack visualization and live block/allow decisions.',
    color: '#f97316',
    bg: 'rgba(249,115,22,0.1)',
  },
  {
    icon: Shield,
    title: 'Batch Processing',
    desc: 'Scan up to 50 URLs simultaneously with batch prediction API for enterprise security workflows.',
    color: '#eab308',
    bg: 'rgba(234,179,8,0.1)',
  },
];

const stats = [
  { value: '98.4%', label: 'Detection Accuracy' },
  { value: '<240ms', label: 'Avg Response Time' },
  { value: '12M+', label: 'Threats Blocked' },
  { value: '24/7', label: 'Active Monitoring' },
];



function AnimatedStat({ value, label }: { value: string; label: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { once: true });

  return (
    <motion.div
      ref={ref}
      initial={{ opacity: 0, y: 30 }}
      animate={inView ? { opacity: 1, y: 0 } : {}}
      transition={{ duration: 0.6 }}
      className="text-center"
    >
      <div className="text-4xl lg:text-5xl font-black gradient-text mb-2">{value}</div>
      <div className="text-xs font-semibold text-cyber-muted uppercase tracking-widest">{label}</div>
    </motion.div>
  );
}

export default function LandingPage() {
  const [terminalLines, setTerminalLines] = useState<string[]>([]);
  const allLines = [
    '> phishguard --scan https://suspicious-bank.ru/login',
    '  → Extracting 25 URL features...',
    '  → Running XGBoost classifier...',
    '  → Checking reputation database...',
    '  ✗ THREAT DETECTED: PHISHING',
    '  → Risk Score: 94/100 | Confidence: 97.3%',
    '  → Reasons: fake-domain, credential-harvest-form, IP-redirect',
    '  → STATUS: BLOCKED ⛔',
    '',
    '> phishguard --qr-scan payment.png',
    '  → Decoding QR image...',
    '  → Payload: https://bit.ly/3xFake99',
    '  → Following redirect chain (3 hops)...',
    '  → Final URL: http://evil-payment.xyz/steal',
    '  ✗ FAKE PAYMENT QR DETECTED',
    '  → STATUS: BLOCKED ⛔',
  ];

  useEffect(() => {
    let i = 0;
    const interval = setInterval(() => {
      if (i < allLines.length) {
        setTerminalLines((prev) => [...prev, allLines[i]]);
        i++;
      } else {
        clearInterval(interval);
      }
    }, 220);
    return () => clearInterval(interval);
  }, []);

  return (
    <main className="relative min-h-screen overflow-x-hidden">
      <ParticleBackground />
      <Navbar />

      {/* Hero */}
      <section className="relative pt-8 pb-24 px-4 text-center overflow-hidden">
        {/* Animated grid */}
        <div className="absolute inset-0 cyber-grid opacity-40" />

        {/* Blobs */}
        <div className="absolute top-0 left-1/4 w-[600px] h-[600px] rounded-full bg-cyber-blue/5 blur-[120px] pointer-events-none" />
        <div className="absolute top-20 right-1/4 w-[400px] h-[400px] rounded-full bg-cyber-purple/5 blur-[100px] pointer-events-none" />

        <div className="relative z-10 container max-w-5xl">
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-full mb-8 text-xs font-bold uppercase tracking-widest"
            style={{
              background: 'rgba(79,172,254,0.1)',
              border: '1px solid rgba(79,172,254,0.3)',
              color: '#4facfe',
            }}
          >
            <span className="w-1.5 h-1.5 rounded-full bg-cyber-blue animate-pulse" />
            AI-Powered Cybersecurity Platform · v2.0
          </motion.div>

          <motion.h1
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.1 }}
            className="text-display text-5xl md:text-7xl lg:text-8xl font-black leading-[1.0] tracking-tight mb-6"
          >
            AI Cyber Defense
            <br />
            <span className="gradient-text">for the Modern</span>
            <br />
            Internet.
          </motion.h1>

          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.2 }}
            className="text-cyber-text text-lg md:text-xl max-w-2xl mx-auto mb-10 leading-relaxed"
          >
            Detect phishing URLs, malicious QR codes, malware domains, and scam links
            in real-time using production-grade AI with explainable threat intelligence.
          </motion.p>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.3 }}
            className="flex flex-col sm:flex-row items-center justify-center gap-4"
          >
            <Link href="/scan">
              <motion.button
                whileHover={{ scale: 1.05, boxShadow: '0 0 40px rgba(79,172,254,0.5)' }}
                whileTap={{ scale: 0.95 }}
                className="cyber-btn cyber-btn-primary text-sm px-8 py-4 text-cyber-black font-black rounded-2xl"
              >
                <Zap className="w-5 h-5" />
                Start Scanning Free
                <ArrowRight className="w-4 h-4" />
              </motion.button>
            </Link>
            <Link href="/dashboard">
              <motion.button
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                className="cyber-btn cyber-btn-secondary text-sm px-8 py-4 rounded-2xl"
              >
                <Activity className="w-5 h-5" />
                View Dashboard
              </motion.button>
            </Link>
          </motion.div>

          {/* Trust badges */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.5 }}
            className="flex items-center justify-center gap-6 mt-10 flex-wrap"
          >
            {['No signup required', '98.4% accuracy', 'Open API', 'QR + URL detection'].map((badge) => (
              <div key={badge} className="flex items-center gap-1.5 text-xs text-cyber-muted">
                <Check className="w-3.5 h-3.5 text-cyber-green" />
                {badge}
              </div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* Stats */}
      <section className="py-16 px-4 border-y border-cyber-border/30">
        <div className="container max-w-4xl">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
            {stats.map((s) => <AnimatedStat key={s.label} {...s} />)}
          </div>
        </div>
      </section>

      {/* Features */}
      <section className="py-24 px-4">
        <div className="container max-w-6xl">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="text-center mb-16"
          >
            <div className="text-xs font-mono text-cyber-blue uppercase tracking-widest mb-4">Capabilities</div>
            <h2 className="text-display text-4xl lg:text-5xl font-black text-white mb-4">
              Full-spectrum <span className="gradient-text">threat detection</span>
            </h2>
            <p className="text-cyber-text max-w-xl mx-auto">
              Every layer of your digital attack surface, covered by AI.
            </p>
          </motion.div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
            {features.map((f, i) => {
              const Icon = f.icon;
              return (
                <motion.div
                  key={f.title}
                  initial={{ opacity: 0, y: 30 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true }}
                  transition={{ delay: i * 0.08 }}
                  whileHover={{ y: -4, transition: { duration: 0.2 } }}
                  className="glass-card p-6 group"
                >
                  <div
                    className="w-12 h-12 rounded-2xl flex items-center justify-center mb-5 transition-transform group-hover:scale-110"
                    style={{ background: f.bg, border: `1px solid ${f.color}30` }}
                  >
                    <Icon className="w-6 h-6" style={{ color: f.color }} />
                  </div>
                  <h3 className="text-base font-bold text-white mb-2">{f.title}</h3>
                  <p className="text-sm text-cyber-text leading-relaxed">{f.desc}</p>
                </motion.div>
              );
            })}
          </div>
        </div>
      </section>

      {/* Terminal showcase */}
      <section className="py-24 px-4">
        <div className="container max-w-5xl">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
            <motion.div
              initial={{ opacity: 0, x: -30 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true }}
            >
              <div className="text-xs font-mono text-cyber-blue uppercase tracking-widest mb-4">Live Demo</div>
              <h2 className="text-display text-4xl font-black text-white mb-4">
                See it in <span className="gradient-text">action</span>
              </h2>
              <p className="text-cyber-text leading-relaxed mb-6">
                PhishGuard's AI engine runs a multi-stage analysis pipeline — from feature extraction
                to ML classification to reputation checks — all in under 300ms.
              </p>
              <Link href="/scan">
                <motion.button
                  whileHover={{ scale: 1.05 }}
                  className="cyber-btn cyber-btn-primary text-sm"
                >
                  Try URL Scanner
                  <ArrowRight className="w-4 h-4" />
                </motion.button>
              </Link>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, x: 30 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true }}
              className="rounded-2xl overflow-hidden"
              style={{
                background: '#0a0f1a',
                border: '1px solid rgba(79,172,254,0.15)',
                boxShadow: '0 0 60px rgba(79,172,254,0.1)',
              }}
            >
              {/* Terminal header */}
              <div className="flex items-center gap-2 px-5 py-3 border-b border-cyber-border/40">
                <div className="w-3 h-3 rounded-full bg-red-500/60" />
                <div className="w-3 h-3 rounded-full bg-yellow-500/60" />
                <div className="w-3 h-3 rounded-full bg-green-500/60" />
                <div className="flex items-center gap-2 ml-2">
                  <Terminal className="w-3.5 h-3.5 text-cyber-muted" />
                  <span className="text-xs font-mono text-cyber-muted">phishguard-cli</span>
                </div>
              </div>
              {/* Terminal body */}
              <div className="p-5 font-mono text-xs leading-relaxed min-h-[300px] space-y-1">
                {terminalLines.map((line, i) => (
                  <motion.div
                    key={i}
                    initial={{ opacity: 0, x: -5 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ duration: 0.2 }}
                    className={
                      line?.includes('✗') || line?.includes('BLOCKED') || line?.includes('DETECTED')
                        ? 'text-red-400'
                        : line?.includes('→')
                        ? 'text-cyber-text'
                        : line?.startsWith('>')
                        ? 'text-cyber-blue'
                        : 'text-cyber-muted'
                    }
                  >
                    {line || '\u00A0'}
                  </motion.div>
                ))}
                <span className="inline-block w-1.5 h-3.5 bg-cyber-blue animate-pulse ml-0.5" />
              </div>
            </motion.div>
          </div>
        </div>
      </section>



      {/* CTA */}
      <section className="py-24 px-4">
        <div className="container max-w-3xl text-center">
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            whileInView={{ opacity: 1, scale: 1 }}
            viewport={{ once: true }}
            className="glass-card p-12 relative overflow-hidden"
            style={{ borderColor: 'rgba(79,172,254,0.2)' }}
          >
            <div className="absolute inset-0 bg-gradient-to-br from-cyber-blue/5 to-cyber-purple/5" />
            <div className="relative">
              <Shield className="w-16 h-16 gradient-text mx-auto mb-6" style={{ color: '#4facfe' }} />
              <h2 className="text-display text-4xl font-black text-white mb-4">
                Start protecting your users <span className="gradient-text">today</span>
              </h2>
              <p className="text-cyber-text mb-8">
                Free to start. No credit card required. Scan your first URL in under 60 seconds.
              </p>
              <div className="flex flex-col sm:flex-row gap-4 justify-center">
                <Link href="/scan">
                  <motion.button
                    whileHover={{ scale: 1.05 }}
                    className="cyber-btn cyber-btn-primary text-sm px-8 py-4 text-cyber-black font-black rounded-2xl"
                  >
                    <Zap className="w-5 h-5" />
                    Scan a URL Now
                  </motion.button>
                </Link>
                <Link href="/qr">
                  <motion.button
                    whileHover={{ scale: 1.05 }}
                    className="cyber-btn cyber-btn-secondary text-sm px-8 py-4 rounded-2xl"
                  >
                    <QrCode className="w-5 h-5" />
                    Scan a QR Code
                  </motion.button>
                </Link>
              </div>
            </div>
          </motion.div>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-10 px-4 border-t border-cyber-border/20">
        <div className="container max-w-6xl flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-xl gradient-bg flex items-center justify-center">
              <Shield className="w-4 h-4 text-cyber-black" />
            </div>
            <span className="font-bold text-sm">PhishGuard AI</span>
          </div>
          <div className="text-xs text-cyber-muted">© 2026 PhishGuard AI. All rights reserved. Powered by XGBoost ML.</div>
          <div className="flex items-center gap-4 text-xs text-cyber-muted">
            <Link href="/docs" className="hover:text-white transition-colors">API Docs</Link>
            <Link href="/settings" className="hover:text-white transition-colors">Settings</Link>
          </div>
        </div>
      </footer>
    </main>
  );
}

'use client';

import { motion } from 'framer-motion';
import { useState, useCallback, useRef } from 'react';
import Navbar from '@/components/Navbar';
import RiskMeter from '@/components/RiskMeter';
import ThreatResultCard from '@/components/ThreatResultCard';
import { predictUrl } from '@/lib/api';
import { PredictionResponse, AIExplanationState } from '@/types';
import { useAppStore } from '@/store/useAppStore';
import { explainThreat, AIExplainPayload } from '@/services/aiExplainer';
import AIExplanationCard from '@/components/AIExplanationCard';
import toast from 'react-hot-toast';
import {
  Globe, Zap, Shield, Search, X,
  ChevronRight, AlertTriangle, CheckCircle
} from 'lucide-react';

const EXAMPLE_URLS = [
  'https://google.com',
  'http://paypal-secure-login.ru/account/verify',
  'https://github.com',
  'http://free-iphone15.giveaway.xyz/claim',
];

export default function ScanPage() {
  const [url, setUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<PredictionResponse | null>(null);
  const [error, setError] = useState('');
  const [aiState, setAiState] = useState<AIExplanationState>({ status: 'idle', explanation: null, error: null });
  const [chatContext, setChatContext] = useState<AIExplainPayload | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const { addHistory, incrementScans, incrementBlocked } = useAppStore();

  const handleScan = useCallback(async (targetUrl?: string) => {
    const scanUrl = targetUrl || url.trim();
    if (!scanUrl) return;

    setScanning(true);
    setError('');
    setResult(null);
    setAiState({ status: 'idle', explanation: null, error: null });
    setChatContext(null);

    try {
      const data = await predictUrl(scanUrl);
      setResult(data);
      setUrl(scanUrl);

      // Update store
      addHistory({
        type: 'url',
        input: scanUrl,
        prediction: data.prediction,
        risk_score: data.risk_score,
        status: 'SCANNED',
      });
      incrementScans();
      if (data.prediction !== 'SAFE') incrementBlocked();

      if (data.prediction === 'SAFE') {
        toast.success('URL appears safe!');
      } else {
        toast.error(`Threat detected: ${data.prediction}`);
        const ctx: AIExplainPayload = {
          url: scanUrl,
          risk_score: data.risk_score,
          prediction: data.prediction,
          reasons: data.reasons || [],
        };
        setChatContext(ctx);
        setAiState({ status: 'loading', explanation: null, error: null });
        explainThreat(ctx)
          .then((res) => setAiState({ status: 'done', explanation: res.explanation, error: null }))
          .catch((err) => setAiState({ status: 'error', explanation: null, error: err.message || 'Failed to generate explanation' }));
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Scan failed';
      setError(msg);
      toast.error(msg);
    } finally {
      setScanning(false);
    }
  }, [url, addHistory, incrementScans, incrementBlocked]);

  const reset = () => {
    setResult(null);
    setError('');
    setUrl('');
    setAiState({ status: 'idle', explanation: null, error: null });
    setChatContext(null);
    inputRef.current?.focus();
  };

  return (
    <main className="min-h-screen relative">
      <div className="fixed inset-0 cyber-grid opacity-30 pointer-events-none" />
      <div className="fixed top-0 left-0 w-[600px] h-[600px] bg-cyber-blue/5 rounded-full blur-[150px] pointer-events-none" />
      <div className="fixed bottom-0 right-0 w-[400px] h-[400px] bg-cyber-purple/5 rounded-full blur-[120px] pointer-events-none" />

      <Navbar />

      <div className="relative z-10 container max-w-4xl py-8">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="text-center mb-10"
        >
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-bold uppercase tracking-widest mb-5"
            style={{ background: 'rgba(79,172,254,0.1)', border: '1px solid rgba(79,172,254,0.2)', color: '#4facfe' }}>
            <Globe className="w-3.5 h-3.5" />
            URL Threat Scanner
          </div>
          <h1 className="text-display text-4xl md:text-5xl font-black mb-4">
            Scan a <span className="gradient-text">Suspicious URL</span>
          </h1>
          <p className="text-cyber-text max-w-xl mx-auto">
            Deep AI-powered analysis: phishing detection, malware classification, and explainable threat scoring.
          </p>
        </motion.div>

        {/* Input */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="glass-card p-2 mb-4"
          style={{ borderColor: scanning ? 'rgba(79,172,254,0.5)' : undefined }}
        >
          <div className="flex items-center gap-3 p-3">
            <div className="flex-shrink-0 w-10 h-10 rounded-xl gradient-bg flex items-center justify-center">
              <Globe className="w-5 h-5 text-cyber-black" />
            </div>
            <input
              ref={inputRef}
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleScan()}
              placeholder="Enter URL to analyze... e.g. https://suspicious-site.com"
              disabled={scanning}
              className="flex-1 bg-transparent outline-none text-white placeholder:text-cyber-muted/60 text-sm font-mono"
            />
            {url && (
              <button onClick={reset} className="text-cyber-muted hover:text-white transition-colors">
                <X className="w-4 h-4" />
              </button>
            )}
            <motion.button
              whileHover={{ scale: 1.03 }}
              whileTap={{ scale: 0.97 }}
              onClick={() => handleScan()}
              disabled={scanning || !url.trim()}
              className="cyber-btn cyber-btn-primary text-sm px-6 py-3 rounded-xl disabled:opacity-50 flex-shrink-0"
            >
              {scanning ? (
                <>
                  <span className="w-4 h-4 border-2 border-cyber-black/30 border-t-cyber-black rounded-full animate-spin" />
                  Analyzing...
                </>
              ) : (
                <>
                  <Zap className="w-4 h-4" />
                  Analyze
                </>
              )}
            </motion.button>
          </div>
        </motion.div>

        {/* Example URLs */}
        {!result && !scanning && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.2 }}
            className="flex flex-wrap gap-2 justify-center mb-8"
          >
            <span className="text-xs text-cyber-muted mr-2 self-center">Try:</span>
            {EXAMPLE_URLS.map((exUrl) => (
              <button
                key={exUrl}
                onClick={() => handleScan(exUrl)}
                className="text-xs font-mono px-3 py-1.5 rounded-lg bg-cyber-surface/50 border border-cyber-border/40 text-cyber-text hover:text-white hover:border-cyber-blue/40 transition-all"
              >
                {exUrl.length > 35 ? exUrl.slice(0, 35) + '…' : exUrl}
              </button>
            ))}
          </motion.div>
        )}

        {/* Status indicators */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.3 }}
          className="flex items-center justify-center gap-6 mb-8"
        >
          {[
            { label: 'ML Model Active', color: '#10b981' },
            { label: 'QR Engine Ready', color: '#4facfe' },
            { label: 'Batch API Online', color: '#a855f7' },
          ].map((s) => (
            <div key={s.label} className="flex items-center gap-1.5 text-xs text-cyber-muted">
              <span className="w-1.5 h-1.5 rounded-full animate-pulse-slow" style={{ backgroundColor: s.color, boxShadow: `0 0 6px ${s.color}` }} />
              {s.label}
            </div>
          ))}
        </motion.div>

        {/* Scanning animation */}
        {scanning && (
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="glass-card p-10 text-center mb-8"
          >
            <div className="relative w-24 h-24 mx-auto mb-6">
              <motion.div
                animate={{ rotate: 360 }}
                transition={{ duration: 3, repeat: Infinity, ease: 'linear' }}
                className="absolute inset-0 border-2 border-transparent border-t-cyber-blue rounded-full"
              />
              <motion.div
                animate={{ rotate: -360 }}
                transition={{ duration: 2, repeat: Infinity, ease: 'linear' }}
                className="absolute inset-3 border-2 border-transparent border-t-cyber-purple rounded-full"
              />
              <div className="absolute inset-0 flex items-center justify-center">
                <Shield className="w-8 h-8 text-cyber-blue" />
              </div>
            </div>
            <h3 className="text-lg font-bold text-white mb-2">Analyzing URL...</h3>
            <p className="text-sm text-cyber-muted">Running XGBoost classifier · Checking reputation · Extracting features</p>
            <div className="mt-4 h-1 bg-cyber-border/30 rounded-full overflow-hidden max-w-xs mx-auto">
              <motion.div
                className="h-full gradient-bg rounded-full"
                animate={{ x: ['-100%', '100%'] }}
                transition={{ duration: 1.5, repeat: Infinity, ease: 'easeInOut' }}
              />
            </div>
          </motion.div>
        )}

        {/* Error */}
        {error && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="glass-card p-5 mb-8 flex items-center gap-3"
            style={{ borderColor: 'rgba(239,68,68,0.3)' }}
          >
            <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0" />
            <div>
              <div className="font-semibold text-red-400 text-sm">Scan Failed</div>
              <div className="text-xs text-cyber-text mt-0.5">{error}</div>
            </div>
            <button onClick={reset} className="ml-auto text-xs cyber-btn cyber-btn-secondary px-3 py-1.5">Retry</button>
          </motion.div>
        )}

        {/* Results */}
        {result && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="space-y-6"
          >
            {/* URL display */}
            <div className="glass-card p-4">
              <div className="text-xs font-mono text-cyber-muted uppercase tracking-widest mb-1">Scanned URL</div>
              <div className="font-mono text-sm text-cyber-text break-all">{result.url}</div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {/* Risk Meter */}
              <div className="glass-card p-6 flex flex-col items-center justify-center">
                <div className="text-xs font-mono text-cyber-muted uppercase tracking-widest mb-4">Risk Score</div>
                <RiskMeter score={result.risk_score} size="lg" />
              </div>

              {/* Threat Result */}
              <div className="md:col-span-2 space-y-6">
                <ThreatResultCard result={result} type="url" />
                
                {/* AI Explanation Card */}
                {result.prediction !== 'SAFE' && (
                  <AIExplanationCard
                    explanation={aiState.explanation}
                    isLoading={aiState.status === 'loading'}
                    error={aiState.error}
                    prediction={result.prediction}
                    chatContext={chatContext ?? undefined}
                    onRetry={() => {
                      if (!chatContext) return;
                      setAiState({ status: 'loading', explanation: null, error: null });
                      explainThreat(chatContext)
                        .then((res) => setAiState({ status: 'done', explanation: res.explanation, error: null }))
                        .catch((err) => setAiState({ status: 'error', explanation: null, error: err.message || 'Failed' }));
                    }}
                  />
                )}
              </div>
            </div>

            {/* Scan again */}
            <motion.button
              whileHover={{ scale: 1.02 }}
              onClick={reset}
              className="w-full cyber-btn cyber-btn-secondary py-3 rounded-xl text-sm"
            >
              <Search className="w-4 h-4" />
              Scan Another URL
            </motion.button>
          </motion.div>
        )}
      </div>
    </main>
  );
}

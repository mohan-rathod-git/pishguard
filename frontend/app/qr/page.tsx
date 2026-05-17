'use client';

import { motion, AnimatePresence } from 'framer-motion';
import { useState, useCallback, useRef } from 'react';
import Navbar from '@/components/Navbar';
import RiskMeter from '@/components/RiskMeter';
import ThreatResultCard from '@/components/ThreatResultCard';
import { scanQRFile, scanQRBase64 } from '@/lib/api';
import { QRScanResponse } from '@/types';
import { useAppStore } from '@/store/useAppStore';
import toast from 'react-hot-toast';
import {
  QrCode, Upload, Shield, AlertTriangle,
  CheckCircle, Search, X, Image as ImageIcon,
  Link as LinkIcon, Scan, Info
} from 'lucide-react';
import { fileToBase64 } from '@/lib/utils';

const ACCEPTED_TYPES = ['image/png', 'image/jpeg', 'image/jpg', 'image/bmp', 'image/webp'];

type ScanState = 'idle' | 'scanning' | 'done' | 'error';

export default function QRScanPage() {
  const [scanState, setScanState] = useState<ScanState>('idle');
  const [result, setResult] = useState<QRScanResponse | null>(null);
  const [error, setError] = useState('');
  const [preview, setPreview] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [activeTab, setActiveTab] = useState<'upload' | 'url'>('upload');
  const [manualUrl, setManualUrl] = useState('');
  const fileInputRef = useRef<HTMLInputElement>(null);
  const { addHistory, incrementScans, incrementBlocked } = useAppStore();

  const processFile = useCallback(async (file: File) => {
    if (!ACCEPTED_TYPES.includes(file.type)) {
      toast.error('Unsupported file type. Use PNG, JPEG, BMP, or WEBP.');
      return;
    }
    if (file.size > 10 * 1024 * 1024) {
      toast.error('File too large. Maximum 10MB.');
      return;
    }

    // Show preview
    const reader = new FileReader();
    reader.onload = (e) => setPreview(e.target?.result as string);
    reader.readAsDataURL(file);

    setScanState('scanning');
    setError('');
    setResult(null);

    try {
      const data = await scanQRFile(file);
      setResult(data);
      setScanState('done');

      addHistory({
        type: 'qr',
        input: data.decoded_payload || 'QR Image',
        prediction: data.prediction,
        risk_score: data.risk_score,
        status: data.status,
      });
      incrementScans();
      if (data.status === 'BLOCKED') incrementBlocked();

      if (data.status === 'BLOCKED') {
        toast.error(`QR BLOCKED: ${data.prediction}`);
      } else if (data.status === 'ALLOWED') {
        toast.success('QR code appears safe!');
      } else if (data.status === 'NO_QR_FOUND') {
        toast('No QR code found in image', { icon: '🔍' });
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'QR scan failed';
      setError(msg);
      setScanState('error');
      toast.error(msg);
    }
  }, [addHistory, incrementScans, incrementBlocked]);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) processFile(file);
  }, [processFile]);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) processFile(file);
  };

  const handleManualScan = async () => {
    if (!manualUrl.trim()) return;

    setScanState('scanning');
    setError('');
    setResult(null);
    setPreview(null);

    try {
      // Use the predict endpoint for direct URLs from QR
      const { predictUrl } = await import('@/lib/api');
      const urlResult = await predictUrl(manualUrl.trim());

      // Convert to QR response format
      const qrResult: QRScanResponse = {
        status: urlResult.prediction !== 'SAFE' ? 'BLOCKED' : 'ALLOWED',
        prediction: urlResult.prediction,
        confidence: urlResult.confidence,
        risk_score: urlResult.risk_score,
        decoded_payload: manualUrl.trim(),
        payload_type: 'URL',
        redirect_chain: [],
        final_url: manualUrl.trim(),
        reasons: urlResult.reasons,
        fake_payment_detected: false,
        processing_time_ms: urlResult.processing_time_ms || 0,
        is_shortened_url: manualUrl.includes('bit.ly') || manualUrl.includes('tinyurl') || manualUrl.includes('t.co'),
      };

      setResult(qrResult);
      setScanState('done');
      addHistory({
        type: 'qr',
        input: manualUrl.trim(),
        prediction: urlResult.prediction,
        risk_score: urlResult.risk_score,
        status: qrResult.status,
      });
      incrementScans();
      if (qrResult.status === 'BLOCKED') incrementBlocked();

      if (qrResult.status === 'BLOCKED') {
        toast.error(`URL BLOCKED: ${urlResult.prediction}`);
      } else {
        toast.success('URL appears safe!');
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Scan failed';
      setError(msg);
      setScanState('error');
      toast.error(msg);
    }
  };

  const reset = () => {
    setScanState('idle');
    setResult(null);
    setError('');
    setPreview(null);
    setManualUrl('');
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  return (
    <main className="min-h-screen relative">
      <div className="fixed inset-0 cyber-grid opacity-30 pointer-events-none" />
      <div className="fixed top-0 right-0 w-[600px] h-[600px] bg-cyber-purple/5 rounded-full blur-[150px] pointer-events-none" />
      <div className="fixed bottom-0 left-0 w-[400px] h-[400px] bg-cyber-cyan/5 rounded-full blur-[120px] pointer-events-none" />

      <Navbar />

      <div className="relative z-10 container max-w-4xl py-8">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="text-center mb-10"
        >
          <div
            className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-bold uppercase tracking-widest mb-5"
            style={{ background: 'rgba(168,85,247,0.1)', border: '1px solid rgba(168,85,247,0.2)', color: '#a855f7' }}
          >
            <QrCode className="w-3.5 h-3.5" />
            QR Code Security Scanner
          </div>
          <h1 className="text-display text-4xl md:text-5xl font-black mb-4">
            Scan a <span className="gradient-text-purple">QR Code</span>
          </h1>
          <p className="text-cyber-text max-w-xl mx-auto">
            Upload a QR code image to detect hidden malicious URLs, fake payment redirects,
            phishing payloads, and dangerous domains.
          </p>
        </motion.div>

        {/* Fake payment warning banner */}
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="flex items-center gap-3 p-4 rounded-2xl mb-6"
          style={{ background: 'rgba(249,115,22,0.08)', border: '1px solid rgba(249,115,22,0.2)' }}
        >
          <AlertTriangle className="w-4 h-4 text-orange-400 flex-shrink-0" />
          <p className="text-xs text-orange-300/80 leading-relaxed">
            <strong className="text-orange-300">Fake Payment QR Detection Active.</strong> AI detects fraudulent UPI, PhonePe, GPay, and Paytm QR codes designed to steal funds.
          </p>
        </motion.div>

        {/* Tabs */}
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.15 }}
          className="flex items-center gap-2 p-1.5 rounded-2xl mb-6 w-fit mx-auto"
          style={{ background: 'rgba(13,18,32,0.8)', border: '1px solid rgba(30,45,69,0.6)' }}
        >
          {[
            { id: 'upload', label: 'Upload Image', icon: Upload },
            { id: 'url', label: 'Enter URL', icon: LinkIcon },
          ].map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as 'upload' | 'url')}
                className={`flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold transition-all ${
                  activeTab === tab.id
                    ? 'gradient-bg-purple text-white'
                    : 'text-cyber-muted hover:text-white'
                }`}
              >
                <Icon className="w-4 h-4" />
                {tab.label}
              </button>
            );
          })}
        </motion.div>

        {/* Upload area or URL input */}
        <AnimatePresence mode="wait">
          {activeTab === 'upload' ? (
            <motion.div
              key="upload"
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 20 }}
              className="mb-6"
            >
              <div
                className={`dropzone p-10 text-center cursor-pointer transition-all ${isDragging ? 'active' : ''}`}
                onDrop={handleDrop}
                onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
                onDragLeave={() => setIsDragging(false)}
                onClick={() => fileInputRef.current?.click()}
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  accept="image/png,image/jpeg,image/jpg,image/bmp,image/webp"
                  className="hidden"
                  onChange={handleFileChange}
                />

                {preview ? (
                  <div className="flex flex-col items-center gap-4">
                    <div className="relative">
                      {/* eslint-disable-next-line @next/next/no-img-element */}
                      <img
                        src={preview}
                        alt="QR preview"
                        className="w-40 h-40 object-contain rounded-2xl border border-cyber-purple/30"
                      />
                      <div className="absolute inset-0 rounded-2xl bg-cyber-purple/5" />
                    </div>
                    <p className="text-xs text-cyber-muted">Click to change image</p>
                  </div>
                ) : (
                  <>
                    <motion.div
                      animate={isDragging ? { scale: 1.1 } : { scale: 1 }}
                      className="w-20 h-20 rounded-3xl mx-auto mb-5 flex items-center justify-center"
                      style={{ background: 'rgba(168,85,247,0.1)', border: '1px solid rgba(168,85,247,0.2)' }}
                    >
                      <QrCode className="w-10 h-10 text-cyber-purple" />
                    </motion.div>
                    <h3 className="text-lg font-bold text-white mb-2">
                      {isDragging ? 'Drop QR code here' : 'Upload QR Code Image'}
                    </h3>
                    <p className="text-sm text-cyber-muted mb-4">
                      Drag & drop or click to select · PNG, JPEG, BMP, WEBP · Max 10MB
                    </p>
                    <div className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold gradient-bg-purple text-white">
                      <Upload className="w-4 h-4" />
                      Choose File
                    </div>
                  </>
                )}
              </div>
            </motion.div>
          ) : (
            <motion.div
              key="url"
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
              className="mb-6"
            >
              <div className="glass-card p-2">
                <div className="flex items-center gap-3 p-3">
                  <div className="w-10 h-10 rounded-xl gradient-bg-purple flex items-center justify-center flex-shrink-0">
                    <LinkIcon className="w-5 h-5 text-white" />
                  </div>
                  <input
                    type="text"
                    value={manualUrl}
                    onChange={(e) => setManualUrl(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && handleManualScan()}
                    placeholder="Enter URL from a QR code to analyze..."
                    className="flex-1 bg-transparent outline-none text-white placeholder:text-cyber-muted/60 text-sm font-mono"
                  />
                  {manualUrl && (
                    <button onClick={() => setManualUrl('')}>
                      <X className="w-4 h-4 text-cyber-muted hover:text-white" />
                    </button>
                  )}
                  <motion.button
                    whileHover={{ scale: 1.03 }}
                    whileTap={{ scale: 0.97 }}
                    onClick={handleManualScan}
                    disabled={!manualUrl.trim() || scanState === 'scanning'}
                    className="flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-bold gradient-bg-purple text-white disabled:opacity-50"
                  >
                    <Scan className="w-4 h-4" />
                    Analyze
                  </motion.button>
                </div>
              </div>
              <div className="flex items-center gap-2 mt-3 text-xs text-cyber-muted px-2">
                <Info className="w-3.5 h-3.5" />
                Scans the URL payload from a QR code directly using AI threat detection
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Scanning animation */}
        <AnimatePresence>
          {scanState === 'scanning' && (
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="glass-card p-10 text-center mb-8"
              style={{ borderColor: 'rgba(168,85,247,0.3)' }}
            >
              <div className="relative w-28 h-28 mx-auto mb-6">
                {/* Outer ring */}
                <motion.div
                  animate={{ rotate: 360 }}
                  transition={{ duration: 3, repeat: Infinity, ease: 'linear' }}
                  className="absolute inset-0 border-2 border-transparent border-t-cyber-purple rounded-full"
                />
                {/* Middle ring */}
                <motion.div
                  animate={{ rotate: -360 }}
                  transition={{ duration: 2, repeat: Infinity, ease: 'linear' }}
                  className="absolute inset-4 border-2 border-transparent border-t-cyber-cyan rounded-full"
                />
                {/* QR icon */}
                <div className="absolute inset-0 flex items-center justify-center">
                  <QrCode className="w-9 h-9 text-cyber-purple" />
                </div>
                {/* Scan line overlay on preview */}
                {preview && (
                  <div className="absolute inset-0 rounded-full overflow-hidden">
                    <motion.div
                      className="absolute left-0 right-0 h-0.5 bg-cyber-purple/60"
                      animate={{ top: ['0%', '100%'] }}
                      transition={{ duration: 1.5, repeat: Infinity, ease: 'linear' }}
                    />
                  </div>
                )}
              </div>
              <h3 className="text-lg font-bold text-white mb-2">Scanning QR Code...</h3>
              <div className="space-y-1 text-sm text-cyber-muted">
                <p>Decoding QR payload · Extracting URLs · Analyzing redirects</p>
                <p>Running ML classifier · Checking fake payment patterns</p>
              </div>
              <div className="mt-5 h-1 bg-cyber-border/30 rounded-full overflow-hidden max-w-xs mx-auto">
                <motion.div
                  className="h-full rounded-full"
                  style={{ background: 'linear-gradient(90deg, #a855f7, #00f2fe)' }}
                  animate={{ x: ['-100%', '100%'] }}
                  transition={{ duration: 1.5, repeat: Infinity, ease: 'easeInOut' }}
                />
              </div>
            </motion.div>
          )}
        </AnimatePresence>

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
            <button onClick={reset} className="ml-auto text-xs cyber-btn cyber-btn-secondary px-3 py-1.5">
              Try Again
            </button>
          </motion.div>
        )}

        {/* Results */}
        <AnimatePresence>
          {scanState === 'done' && result && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="space-y-6"
            >
              {/* Status banner */}
              <motion.div
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                className={`flex items-center gap-4 p-5 rounded-2xl ${
                  result.status === 'BLOCKED'
                    ? 'border-glow-danger'
                    : result.status === 'ALLOWED'
                    ? 'border-glow-safe'
                    : 'glass-card'
                }`}
                style={{
                  background: result.status === 'BLOCKED'
                    ? 'rgba(239,68,68,0.08)'
                    : result.status === 'ALLOWED'
                    ? 'rgba(16,185,129,0.08)'
                    : 'rgba(13,18,32,0.7)',
                }}
              >
                {result.status === 'BLOCKED' ? (
                  <AlertTriangle className="w-8 h-8 text-red-400 flex-shrink-0" />
                ) : result.status === 'ALLOWED' ? (
                  <CheckCircle className="w-8 h-8 text-emerald-400 flex-shrink-0" />
                ) : (
                  <Shield className="w-8 h-8 text-cyber-muted flex-shrink-0" />
                )}
                <div>
                  <div className="text-lg font-black" style={{
                    color: result.status === 'BLOCKED' ? '#ef4444' : result.status === 'ALLOWED' ? '#10b981' : '#64748b'
                  }}>
                    {result.status === 'BLOCKED' ? '⛔ QR CODE BLOCKED'
                      : result.status === 'ALLOWED' ? '✅ QR CODE SAFE'
                      : result.status === 'NO_QR_FOUND' ? '🔍 No QR Code Found'
                      : result.status}
                  </div>
                  <div className="text-xs text-cyber-muted mt-0.5">
                    {result.payload_type && `Payload type: ${result.payload_type} · `}
                    {result.is_shortened_url && 'Shortened URL detected · '}
                    Risk score: {result.risk_score}/100
                  </div>
                </div>
              </motion.div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                {/* Risk meter + preview */}
                <div className="space-y-4">
                  <div className="glass-card p-6 flex flex-col items-center justify-center">
                    <div className="text-xs font-mono text-cyber-muted uppercase tracking-widest mb-4">Risk Score</div>
                    <RiskMeter score={result.risk_score} size="lg" />
                  </div>
                  {preview && (
                    <div className="glass-card p-4">
                      <div className="text-xs font-mono text-cyber-muted uppercase tracking-widest mb-3">QR Image</div>
                      {/* eslint-disable-next-line @next/next/no-img-element */}
                      <img src={preview} alt="QR" className="w-full rounded-xl object-contain max-h-32" />
                    </div>
                  )}
                </div>

                {/* Threat details */}
                <div className="md:col-span-2">
                  <ThreatResultCard result={result} type="qr" />
                </div>
              </div>

              {/* Scan again */}
              <motion.button
                whileHover={{ scale: 1.02 }}
                onClick={reset}
                className="w-full cyber-btn cyber-btn-secondary py-3 rounded-xl text-sm"
              >
                <QrCode className="w-4 h-4" />
                Scan Another QR Code
              </motion.button>
            </motion.div>
          )}
        </AnimatePresence>

        {/* How it works */}
        {scanState === 'idle' && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
            className="mt-10 glass-card p-6"
          >
            <h3 className="text-sm font-bold text-white mb-4">How QR Scanning Works</h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
              {[
                { step: '01', label: 'Decode QR', desc: 'Extract payload from image' },
                { step: '02', label: 'Follow Redirects', desc: 'Unshorten URLs, trace hops' },
                { step: '03', label: 'AI Analysis', desc: 'XGBoost threat classification' },
                { step: '04', label: 'Block/Allow', desc: 'Risk-scored verdict returned' },
              ].map((s) => (
                <div key={s.step} className="text-center">
                  <div className="text-2xl font-black gradient-text-purple mb-1">{s.step}</div>
                  <div className="text-xs font-bold text-white mb-0.5">{s.label}</div>
                  <div className="text-xs text-cyber-muted">{s.desc}</div>
                </div>
              ))}
            </div>
          </motion.div>
        )}
      </div>
    </main>
  );
}

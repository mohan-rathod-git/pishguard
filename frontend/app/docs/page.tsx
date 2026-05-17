'use client';

import { motion } from 'framer-motion';
import { useState } from 'react';
import Navbar from '@/components/Navbar';
import { BookOpen, Copy, Check, ChevronDown, ChevronRight, Terminal } from 'lucide-react';
import toast from 'react-hot-toast';

const BASE = 'http://localhost:8000/api/v1';

const endpoints = [
  {
    method: 'POST',
    path: '/predict',
    tag: 'URL Detection',
    color: '#4facfe',
    desc: 'Analyze a single URL for phishing, malware, spam, or scam threats.',
    requestBody: JSON.stringify({ url: 'https://suspicious-site.com/login' }, null, 2),
    response: JSON.stringify({
      url: 'https://suspicious-site.com/login',
      prediction: 'PHISHING',
      confidence: 0.97,
      risk_score: 94,
      reasons: ['suspicious-domain', 'credential-form-detected', 'ip-redirect'],
      processing_time_ms: 180,
    }, null, 2),
  },
  {
    method: 'POST',
    path: '/batch_predict',
    tag: 'URL Detection',
    color: '#4facfe',
    desc: 'Analyze up to 50 URLs in a single request.',
    requestBody: JSON.stringify({ urls: ['https://google.com', 'http://phish.ru/login'] }, null, 2),
    response: JSON.stringify({ count: 2, results: [{ url: 'https://google.com', prediction: 'SAFE', risk_score: 3 }] }, null, 2),
  },
  {
    method: 'POST',
    path: '/qr/scan',
    tag: 'QR Security',
    color: '#a855f7',
    desc: 'Upload a QR code image (PNG/JPEG/BMP/WEBP) and get a full threat analysis with redirect chain.',
    requestBody: 'multipart/form-data:\n  file: <image_file>\n  follow_redirects: true\n  use_ml_model: true',
    response: JSON.stringify({
      status: 'BLOCKED',
      prediction: 'PHISHING',
      confidence: 0.94,
      risk_score: 91,
      decoded_payload: 'https://bit.ly/3fakeQR',
      payload_type: 'URL',
      redirect_chain: ['https://bit.ly/3fakeQR', 'http://evil-payment.xyz/steal'],
      final_url: 'http://evil-payment.xyz/steal',
      reasons: ['shortened-url', 'malicious-redirect', 'credential-harvest'],
      fake_payment_detected: true,
      processing_time_ms: 340,
      is_shortened_url: true,
    }, null, 2),
  },
  {
    method: 'POST',
    path: '/qr/scan/base64',
    tag: 'QR Security',
    color: '#a855f7',
    desc: 'Scan a QR code via JSON body with base64-encoded image.',
    requestBody: JSON.stringify({ image_base64: '<base64_string>', follow_redirects: true, use_ml_model: true }, null, 2),
    response: '{ /* same as /qr/scan response */ }',
  },
  {
    method: 'GET',
    path: '/health',
    tag: 'System',
    color: '#10b981',
    desc: 'Check API health, model status, and uptime.',
    requestBody: '— No body required —',
    response: JSON.stringify({ status: 'healthy', app: 'PhishGuard AI', version: '2.0.0', model_loaded: true, uptime_seconds: 3600 }, null, 2),
  },
  {
    method: 'GET',
    path: '/qr/health',
    tag: 'System',
    color: '#10b981',
    desc: 'Check QR security engine health and component status.',
    requestBody: '— No body required —',
    response: JSON.stringify({ status: 'healthy', qr_engine_active: true, ml_model_loaded: true, total_scans: 1247, total_blocked: 342, block_rate: 0.274 }, null, 2),
  },
  {
    method: 'GET',
    path: '/model-info',
    tag: 'System',
    color: '#10b981',
    desc: 'Retrieve metadata about the loaded ML model.',
    requestBody: '— No body required —',
    response: JSON.stringify({ model_type: 'XGBClassifier', feature_count: 27, training_accuracy: 0.984, training_date: '2026-05-16' }, null, 2),
  },
];

const METHOD_COLORS: Record<string, string> = {
  GET: '#10b981',
  POST: '#4facfe',
  DELETE: '#ef4444',
};

function EndpointCard({ ep }: { ep: typeof endpoints[0] }) {
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState('');

  const copy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopied(key);
    toast.success('Copied!');
    setTimeout(() => setCopied(''), 2000);
  };

  const curlCmd = ep.method === 'GET'
    ? `curl -X GET "${BASE}${ep.path}"`
    : `curl -X POST "${BASE}${ep.path}" \\\n  -H "Content-Type: application/json" \\\n  -d '${ep.requestBody}'`;

  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
      className="glass-card overflow-hidden mb-4">
      <button onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-4 p-5 text-left hover:bg-white/2 transition-colors">
        <span className="text-xs font-black font-mono px-2.5 py-1 rounded-lg flex-shrink-0"
          style={{ background: `${METHOD_COLORS[ep.method]}20`, color: METHOD_COLORS[ep.method], border: `1px solid ${METHOD_COLORS[ep.method]}30` }}>
          {ep.method}
        </span>
        <span className="font-mono text-sm text-white flex-1">{ep.path}</span>
        <span className="text-xs px-2 py-1 rounded-lg flex-shrink-0"
          style={{ background: `${ep.color}15`, border: `1px solid ${ep.color}30`, color: ep.color }}>
          {ep.tag}
        </span>
        {open ? <ChevronDown className="w-4 h-4 text-cyber-muted flex-shrink-0" /> : <ChevronRight className="w-4 h-4 text-cyber-muted flex-shrink-0" />}
      </button>

      {open && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }}
          className="border-t border-cyber-border/30 p-5 space-y-4">
          <p className="text-sm text-cyber-text">{ep.desc}</p>

          {/* cURL */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-1.5 text-xs text-cyber-muted"><Terminal className="w-3.5 h-3.5" />cURL Example</div>
              <button onClick={() => copy(curlCmd, 'curl')}
                className="flex items-center gap-1 text-xs text-cyber-blue hover:text-cyber-cyan">
                {copied === 'curl' ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                {copied === 'curl' ? 'Copied' : 'Copy'}
              </button>
            </div>
            <pre className="text-xs font-mono text-emerald-300 bg-black/40 border border-cyber-border/30 rounded-xl p-4 overflow-x-auto whitespace-pre-wrap">
              {curlCmd}
            </pre>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Request */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-cyber-muted">Request Body</span>
                <button onClick={() => copy(ep.requestBody, 'req')}
                  className="flex items-center gap-1 text-xs text-cyber-blue">
                  {copied === 'req' ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                </button>
              </div>
              <pre className="text-xs font-mono text-cyber-text bg-black/40 border border-cyber-border/30 rounded-xl p-4 overflow-x-auto whitespace-pre-wrap max-h-48">
                {ep.requestBody}
              </pre>
            </div>
            {/* Response */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-cyber-muted">Response</span>
                <button onClick={() => copy(ep.response, 'res')}
                  className="flex items-center gap-1 text-xs text-cyber-blue">
                  {copied === 'res' ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                </button>
              </div>
              <pre className="text-xs font-mono text-cyber-blue/80 bg-black/40 border border-cyber-border/30 rounded-xl p-4 overflow-x-auto whitespace-pre-wrap max-h-48">
                {ep.response}
              </pre>
            </div>
          </div>
        </motion.div>
      )}
    </motion.div>
  );
}

export default function DocsPage() {
  return (
    <main className="min-h-screen relative">
      <div className="fixed inset-0 cyber-grid opacity-20 pointer-events-none" />
      <Navbar />
      <div className="relative z-10 container max-w-4xl py-8">
        <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} className="mb-8">
          <div className="text-xs font-mono text-cyber-blue uppercase tracking-widest mb-1">REST API</div>
          <h1 className="text-display text-3xl font-black text-white">API Documentation</h1>
          <p className="text-sm text-cyber-muted mt-1">
            Base URL: <span className="font-mono text-cyber-blue">{BASE}</span>
          </p>
        </motion.div>

        {/* Quick info */}
        <div className="grid grid-cols-3 gap-4 mb-8">
          {[
            { label: 'Base URL', value: 'localhost:8000/api/v1', color: '#4facfe' },
            { label: 'Auth', value: 'Rate limit (IP)', color: '#a855f7' },
            { label: 'Format', value: 'JSON / multipart', color: '#10b981' },
          ].map((info) => (
            <div key={info.label} className="glass-card p-4">
              <div className="text-xs text-cyber-muted mb-1">{info.label}</div>
              <div className="font-mono text-xs font-bold" style={{ color: info.color }}>{info.value}</div>
            </div>
          ))}
        </div>

        {/* Endpoints */}
        <div>
          {endpoints.map((ep, i) => <EndpointCard key={i} ep={ep} />)}
        </div>
      </div>
    </main>
  );
}

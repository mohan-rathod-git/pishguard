'use client';

import { motion } from 'framer-motion';
import { AlertTriangle, CheckCircle, ShieldAlert, Zap, Clock, ChevronRight } from 'lucide-react';
import { PredictionResponse, QRScanResponse } from '@/types';
import { getThreatColor, getThreatBg } from '@/lib/utils';

interface ThreatResultCardProps {
  result: PredictionResponse | QRScanResponse;
  type: 'url' | 'qr';
}

function isFull(r: PredictionResponse | QRScanResponse): r is QRScanResponse {
  return 'status' in r;
}

export default function ThreatResultCard({ result, type }: ThreatResultCardProps) {
  const prediction = result.prediction;
  const isSafe = prediction === 'SAFE';
  const isBlocked = isFull(result) ? result.status === 'BLOCKED' : !isSafe;
  const color = getThreatColor(prediction);
  const bg = getThreatBg(prediction);

  const containerVariants = {
    hidden: { opacity: 0, y: 20 },
    visible: { opacity: 1, y: 0, transition: { staggerChildren: 0.08 } },
  };

  const itemVariants = {
    hidden: { opacity: 0, x: -10 },
    visible: { opacity: 1, x: 0 },
  };

  return (
    <motion.div
      variants={containerVariants}
      initial="hidden"
      animate="visible"
      className="space-y-4"
    >
      {/* Main verdict card */}
      <motion.div
        variants={itemVariants}
        className="glass-card p-6 relative overflow-hidden"
        style={{ borderColor: `${color}30` }}
      >
        {/* Background glow */}
        <div
          className="absolute inset-0 opacity-5 rounded-xl"
          style={{ background: bg }}
        />

        <div className="relative flex items-start justify-between gap-4">
          <div className="flex items-center gap-4">
            <motion.div
              initial={{ scale: 0, rotate: -180 }}
              animate={{ scale: 1, rotate: 0 }}
              transition={{ type: 'spring', stiffness: 200, delay: 0.2 }}
              className="w-14 h-14 rounded-2xl flex items-center justify-center flex-shrink-0"
              style={{ background: bg, border: `1px solid ${color}40` }}
            >
              {isSafe ? (
                <CheckCircle className="w-7 h-7" style={{ color }} />
              ) : (
                <ShieldAlert className="w-7 h-7" style={{ color }} />
              )}
            </motion.div>

            <div>
              <div className="text-xs font-mono text-cyber-muted uppercase tracking-widest mb-1">
                {type === 'qr' ? 'QR Threat Analysis' : 'URL Threat Analysis'}
              </div>
              <div className="text-2xl font-black" style={{ color }}>
                {prediction || 'UNKNOWN'}
              </div>
              {isFull(result) && (
                <div className="text-xs font-semibold text-cyber-muted mt-0.5">
                  Status: <span style={{ color }}>{result.status}</span>
                </div>
              )}
            </div>
          </div>

          <div className="text-right flex-shrink-0">
            <div className="text-xs text-cyber-muted mb-1">Confidence</div>
            <div className="text-xl font-black text-white">
              {(result.confidence * 100).toFixed(1)}%
            </div>
          </div>
        </div>

        {/* QR-specific: payload */}
        {isFull(result) && result.decoded_payload && (
          <motion.div
            variants={itemVariants}
            className="mt-4 p-3 rounded-xl bg-white/3 border border-white/5"
          >
            <div className="text-xs font-mono text-cyber-muted uppercase tracking-wider mb-1">Decoded Payload</div>
            <div className="font-mono text-xs text-cyber-text break-all">{result.decoded_payload}</div>
          </motion.div>
        )}

        {/* QR: fake payment warning */}
        {isFull(result) && result.fake_payment_detected && (
          <motion.div
            variants={itemVariants}
            className="mt-4 flex items-center gap-2 p-3 rounded-xl"
            style={{ background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)' }}
          >
            <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0" />
            <span className="text-xs font-semibold text-red-400">⚠ Fake Payment QR Detected — Do NOT scan with banking apps</span>
          </motion.div>
        )}
      </motion.div>

      {/* Confidence bar */}
      <motion.div variants={itemVariants} className="glass-card p-4">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-semibold text-cyber-muted uppercase tracking-wider">AI Confidence</span>
          <span className="text-xs font-mono font-bold" style={{ color }}>
            {(result.confidence * 100).toFixed(1)}%
          </span>
        </div>
        <div className="h-2 bg-cyber-border/50 rounded-full overflow-hidden">
          <motion.div
            initial={{ width: 0 }}
            animate={{ width: `${result.confidence * 100}%` }}
            transition={{ duration: 1, ease: 'easeOut', delay: 0.3 }}
            className="h-full rounded-full"
            style={{ background: `linear-gradient(90deg, ${color}80, ${color})` }}
          />
        </div>
      </motion.div>

      {/* Risk reasons */}
      {result.reasons && result.reasons.length > 0 && (
        <motion.div variants={itemVariants} className="glass-card p-5">
          <div className="flex items-center gap-2 mb-4">
            <Zap className="w-4 h-4 text-cyber-blue" />
            <span className="text-sm font-bold text-white">Threat Indicators</span>
          </div>
          <ul className="space-y-2">
            {result.reasons.map((reason, i) => (
              <motion.li
                key={i}
                variants={itemVariants}
                className="flex items-start gap-2 text-xs text-cyber-text"
              >
                <ChevronRight className="w-3.5 h-3.5 text-cyber-blue flex-shrink-0 mt-0.5" />
                <span>{reason}</span>
              </motion.li>
            ))}
          </ul>
        </motion.div>
      )}

      {/* QR redirect chain */}
      {isFull(result) && result.redirect_chain && result.redirect_chain.length > 0 && (
        <motion.div variants={itemVariants} className="glass-card p-5">
          <div className="flex items-center gap-2 mb-4">
            <ChevronRight className="w-4 h-4 text-cyber-purple" />
            <span className="text-sm font-bold text-white">Redirect Chain</span>
            <span className="text-xs text-cyber-muted">({result.redirect_chain.length} hop{result.redirect_chain.length > 1 ? 's' : ''})</span>
          </div>
          <div className="space-y-2">
            {result.redirect_chain.map((url, i) => (
              <div key={i} className="flex items-center gap-2">
                <span className="text-xs font-mono text-cyber-purple w-5 text-right flex-shrink-0">{i + 1}</span>
                <div className="h-px w-4 bg-cyber-border" />
                <span className="font-mono text-xs text-cyber-text break-all">{url}</span>
              </div>
            ))}
          </div>
        </motion.div>
      )}

      {/* Processing time */}
      {result.processing_time_ms !== undefined && (
        <motion.div variants={itemVariants} className="flex items-center gap-2 text-xs text-cyber-muted">
          <Clock className="w-3.5 h-3.5" />
          <span>Processed in <strong className="text-cyber-blue">{result.processing_time_ms}ms</strong></span>
        </motion.div>
      )}
    </motion.div>
  );
}

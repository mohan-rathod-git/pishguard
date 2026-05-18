'use client';

import { motion, AnimatePresence } from 'framer-motion';
import { useEffect, useState, useRef } from 'react';
import { Bot, Copy, CheckCheck, AlertTriangle, Sparkles, RotateCcw } from 'lucide-react';
import toast from 'react-hot-toast';

interface AIExplanationCardProps {
  explanation?: string | null;
  isLoading?: boolean;
  error?: string | null;
  onRetry?: () => void;
  /** Threat level for color theming */
  prediction?: string;
}

// Typing effect hook
function useTypingEffect(text: string, speed = 18): { displayed: string; done: boolean } {
  const [displayed, setDisplayed] = useState('');
  const [done, setDone] = useState(false);
  const indexRef = useRef(0);

  useEffect(() => {
    if (!text) {
      setDisplayed('');
      setDone(false);
      indexRef.current = 0;
      return;
    }
    setDisplayed('');
    setDone(false);
    indexRef.current = 0;

    const interval = setInterval(() => {
      if (indexRef.current < text.length) {
        setDisplayed(text.slice(0, indexRef.current + 1));
        indexRef.current += 1;
      } else {
        setDone(true);
        clearInterval(interval);
      }
    }, speed);

    return () => clearInterval(interval);
  }, [text, speed]);

  return { displayed, done };
}

// Skeleton loader
function SkeletonLines() {
  return (
    <div className="space-y-2.5 py-1">
      {[100, 85, 92, 60].map((w, i) => (
        <motion.div
          key={i}
          className="h-3 rounded-full bg-white/6"
          style={{ width: `${w}%` }}
          animate={{ opacity: [0.4, 0.8, 0.4] }}
          transition={{ duration: 1.6, repeat: Infinity, delay: i * 0.15 }}
        />
      ))}
    </div>
  );
}

function getThreatAccent(prediction?: string) {
  if (!prediction || prediction === 'SAFE') return '#10b981';
  if (prediction === 'PHISHING') return '#ef4444';
  if (prediction === 'MALWARE') return '#f97316';
  if (prediction === 'SCAM') return '#eab308';
  if (prediction === 'SPAM') return '#a855f7';
  return '#ef4444';
}

export default function AIExplanationCard({
  explanation,
  isLoading,
  error,
  onRetry,
  prediction,
}: AIExplanationCardProps) {
  const accent = getThreatAccent(prediction);
  const { displayed, done } = useTypingEffect(explanation || '', 14);
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    if (!explanation) return;
    try {
      await navigator.clipboard.writeText(explanation);
      setCopied(true);
      toast.success('Explanation copied!');
      setTimeout(() => setCopied(false), 2000);
    } catch {
      toast.error('Copy failed');
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
      className="relative overflow-hidden rounded-2xl"
      style={{
        background: 'rgba(7, 11, 22, 0.85)',
        border: `1px solid ${accent}28`,
        boxShadow: `0 0 40px ${accent}0d`,
        backdropFilter: 'blur(16px)',
      }}
    >
      {/* Top gradient bar */}
      <div
        className="absolute top-0 left-0 right-0 h-[2px]"
        style={{
          background: `linear-gradient(90deg, transparent, ${accent}90, transparent)`,
        }}
      />

      {/* Ambient glow */}
      <div
        className="absolute top-0 left-0 w-48 h-48 rounded-full pointer-events-none"
        style={{
          background: `radial-gradient(circle, ${accent}08 0%, transparent 70%)`,
        }}
      />

      {/* Header */}
      <div className="flex items-center justify-between px-5 py-4 border-b border-white/5">
        <div className="flex items-center gap-2.5">
          <motion.div
            className="w-8 h-8 rounded-xl flex items-center justify-center flex-shrink-0"
            style={{ background: `${accent}18`, border: `1px solid ${accent}30` }}
            animate={isLoading ? { scale: [1, 1.08, 1] } : {}}
            transition={{ duration: 1.4, repeat: Infinity }}
          >
            {isLoading ? (
              <Sparkles className="w-4 h-4" style={{ color: accent }} />
            ) : (
              <Bot className="w-4 h-4" style={{ color: accent }} />
            )}
          </motion.div>
          <div>
            <div className="text-xs font-bold text-white tracking-wide">AI Threat Analyst</div>
            <div className="text-[10px] font-mono" style={{ color: accent }}>
              Powered by OpenRouter via n8n
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {/* Status badge */}
          <div
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-bold uppercase tracking-widest"
            style={{
              background: isLoading ? 'rgba(79,172,254,0.1)' : error ? 'rgba(239,68,68,0.1)' : `${accent}15`,
              border: `1px solid ${isLoading ? 'rgba(79,172,254,0.25)' : error ? 'rgba(239,68,68,0.3)' : `${accent}30`}`,
              color: isLoading ? '#4facfe' : error ? '#ef4444' : accent,
            }}
          >
            <span
              className="w-1.5 h-1.5 rounded-full"
              style={{
                backgroundColor: isLoading ? '#4facfe' : error ? '#ef4444' : accent,
                boxShadow: `0 0 4px ${isLoading ? '#4facfe' : error ? '#ef4444' : accent}`,
                animation: isLoading ? 'pulse 1s infinite' : 'none',
              }}
            />
            {isLoading ? 'Analyzing...' : error ? 'Error' : explanation ? 'Complete' : 'Ready'}
          </div>

          {/* Copy button */}
          <AnimatePresence>
            {explanation && !isLoading && (
              <motion.button
                initial={{ opacity: 0, scale: 0.8 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.8 }}
                onClick={handleCopy}
                className="w-7 h-7 rounded-lg flex items-center justify-center transition-all hover:bg-white/8"
                title="Copy explanation"
              >
                {copied ? (
                  <CheckCheck className="w-3.5 h-3.5 text-emerald-400" />
                ) : (
                  <Copy className="w-3.5 h-3.5 text-cyber-muted hover:text-white" />
                )}
              </motion.button>
            )}
          </AnimatePresence>
        </div>
      </div>

      {/* Body */}
      <div className="px-5 py-5 min-h-[100px]">
        <AnimatePresence mode="wait">
          {isLoading && (
            <motion.div
              key="loading"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
            >
              <div className="flex items-center gap-2 mb-4">
                <div className="flex gap-1">
                  {[0, 1, 2].map((i) => (
                    <motion.div
                      key={i}
                      className="w-1.5 h-1.5 rounded-full"
                      style={{ backgroundColor: accent }}
                      animate={{ scale: [1, 1.5, 1], opacity: [0.4, 1, 0.4] }}
                      transition={{ duration: 0.8, repeat: Infinity, delay: i * 0.2 }}
                    />
                  ))}
                </div>
                <span className="text-xs text-cyber-muted font-mono">
                  Generating threat explanation...
                </span>
              </div>
              <SkeletonLines />
            </motion.div>
          )}

          {error && !isLoading && (
            <motion.div
              key="error"
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              className="flex flex-col items-center gap-3 py-3 text-center"
            >
              <div className="w-10 h-10 rounded-2xl bg-red-500/10 border border-red-500/25 flex items-center justify-center">
                <AlertTriangle className="w-5 h-5 text-red-400" />
              </div>
              <div>
                <div className="text-sm font-semibold text-red-400 mb-1">AI Explanation Failed</div>
                <div className="text-xs text-cyber-muted max-w-xs">{error}</div>
              </div>
              {onRetry && (
                <motion.button
                  whileHover={{ scale: 1.04 }}
                  whileTap={{ scale: 0.96 }}
                  onClick={onRetry}
                  className="flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold text-white"
                  style={{
                    background: 'rgba(239,68,68,0.12)',
                    border: '1px solid rgba(239,68,68,0.3)',
                  }}
                >
                  <RotateCcw className="w-3.5 h-3.5" />
                  Retry
                </motion.button>
              )}
            </motion.div>
          )}

          {explanation && !isLoading && (
            <motion.div
              key="explanation"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="relative"
            >
              {/* Quotation mark */}
              <div
                className="absolute -top-1 -left-1 text-4xl leading-none font-black select-none"
                style={{ color: `${accent}25` }}
              >
                "
              </div>
              <p className="text-sm leading-relaxed text-slate-200 pl-3 font-light tracking-wide">
                {displayed}
                {!done && (
                  <motion.span
                    className="inline-block w-0.5 h-4 ml-0.5 align-middle rounded-full"
                    style={{ backgroundColor: accent }}
                    animate={{ opacity: [1, 0] }}
                    transition={{ duration: 0.5, repeat: Infinity }}
                  />
                )}
              </p>
            </motion.div>
          )}

          {!explanation && !isLoading && !error && (
            <motion.div
              key="idle"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="flex items-center gap-3 py-2"
            >
              <Bot className="w-5 h-5 text-cyber-muted flex-shrink-0" />
              <p className="text-xs text-cyber-muted">
                AI explanation will appear here after a threat is detected and analyzed.
              </p>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Footer - model attribution */}
      <AnimatePresence>
        {explanation && !isLoading && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="px-5 pb-4 flex items-center gap-2"
          >
            <div className="h-px flex-1 bg-white/4" />
            <span className="text-[10px] font-mono text-cyber-muted/60">
              Analysis by OpenRouter LLM · n8n Workflow
            </span>
            <div className="h-px flex-1 bg-white/4" />
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

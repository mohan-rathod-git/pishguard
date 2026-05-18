'use client';

import { motion, AnimatePresence } from 'framer-motion';
import { useEffect, useState, useRef } from 'react';
import {
  Bot, Copy, CheckCheck, AlertTriangle, Sparkles,
  RotateCcw, MessageSquare, Send, User, X, ChevronDown,
} from 'lucide-react';
import toast from 'react-hot-toast';
import { chatWithAI, ChatMessage, AIExplainPayload } from '@/services/aiExplainer';

// ── Props ─────────────────────────────────────────────────────────────────────

interface AIExplanationCardProps {
  explanation?: string | null;
  isLoading?: boolean;
  error?: string | null;
  onRetry?: () => void;
  /** Threat level for color theming */
  prediction?: string;
  /** Context for interactive chat */
  chatContext?: AIExplainPayload;
}

// ── Typing Effect Hook ────────────────────────────────────────────────────────

function useTypingEffect(text: string, speed = 14): { displayed: string; done: boolean } {
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

// ── Skeleton Loader ───────────────────────────────────────────────────────────

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

// ── Helpers ───────────────────────────────────────────────────────────────────

function getThreatAccent(prediction?: string) {
  if (!prediction || prediction === 'SAFE') return '#10b981';
  if (prediction === 'PHISHING') return '#ef4444';
  if (prediction === 'MALWARE') return '#f97316';
  if (prediction === 'SCAM') return '#eab308';
  if (prediction === 'SPAM') return '#a855f7';
  if (prediction === 'FAKE_PAYMENT') return '#f97316';
  if (prediction === 'CRITICAL') return '#dc2626';
  return '#ef4444';
}

// ── Chat Message Bubble ───────────────────────────────────────────────────────

function ChatBubble({
  message,
  accent,
  isLatest,
}: {
  message: ChatMessage;
  accent: string;
  isLatest: boolean;
}) {
  const isUser = message.role === 'user';
  const { displayed, done } = useTypingEffect(
    !isUser && isLatest ? message.content : '',
    10
  );
  const text = !isUser && isLatest ? displayed : message.content;
  const showCursor = !isUser && isLatest && !done;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      className={`flex gap-2.5 ${isUser ? 'flex-row-reverse' : 'flex-row'}`}
    >
      {/* Avatar */}
      <div
        className="w-7 h-7 rounded-xl flex items-center justify-center flex-shrink-0 mt-0.5"
        style={{
          background: isUser ? 'rgba(79,172,254,0.15)' : `${accent}18`,
          border: `1px solid ${isUser ? 'rgba(79,172,254,0.3)' : `${accent}30`}`,
        }}
      >
        {isUser ? (
          <User className="w-3.5 h-3.5 text-cyber-blue" />
        ) : (
          <Bot className="w-3.5 h-3.5" style={{ color: accent }} />
        )}
      </div>

      {/* Bubble */}
      <div
        className={`max-w-[82%] px-3.5 py-2.5 rounded-2xl text-sm leading-relaxed ${
          isUser ? 'rounded-tr-sm' : 'rounded-tl-sm'
        }`}
        style={
          isUser
            ? { background: 'rgba(79,172,254,0.12)', border: '1px solid rgba(79,172,254,0.2)', color: '#e2e8f0' }
            : { background: `${accent}0d`, border: `1px solid ${accent}20`, color: '#cbd5e1' }
        }
      >
        {text}
        {showCursor && (
          <motion.span
            className="inline-block w-0.5 h-3.5 ml-0.5 align-middle rounded-full"
            style={{ backgroundColor: accent }}
            animate={{ opacity: [1, 0] }}
            transition={{ duration: 0.5, repeat: Infinity }}
          />
        )}
      </div>
    </motion.div>
  );
}

// ── Main Component ────────────────────────────────────────────────────────────

export default function AIExplanationCard({
  explanation,
  isLoading,
  error,
  onRetry,
  prediction,
  chatContext,
}: AIExplanationCardProps) {
  const accent = getThreatAccent(prediction);
  const { displayed, done } = useTypingEffect(explanation || '', 14);
  const [copied, setCopied] = useState(false);

  // ── Chat State ──
  const [isChatOpen, setIsChatOpen] = useState(false);
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [chatInput, setChatInput] = useState('');
  const [chatLoading, setChatLoading] = useState(false);
  const chatEndRef = useRef<HTMLDivElement>(null);
  const chatInputRef = useRef<HTMLInputElement>(null);

  // Auto-scroll chat to bottom
  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [chatMessages, chatLoading]);

  // Focus input when chat opens
  useEffect(() => {
    if (isChatOpen) {
      setTimeout(() => chatInputRef.current?.focus(), 200);
    }
  }, [isChatOpen]);

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

  const handleChatSend = async () => {
    const q = chatInput.trim();
    if (!q || chatLoading || !chatContext) return;

    const userMsg: ChatMessage = { role: 'user', content: q, timestamp: new Date() };
    setChatMessages((prev) => [...prev, userMsg]);
    setChatInput('');
    setChatLoading(true);

    try {
      const reply = await chatWithAI(chatContext, q, [...chatMessages, userMsg]);
      const assistantMsg: ChatMessage = {
        role: 'assistant',
        content: reply,
        timestamp: new Date(),
      };
      setChatMessages((prev) => [...prev, assistantMsg]);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to get AI response';
      toast.error(msg);
      const errMsg: ChatMessage = {
        role: 'assistant',
        content: `⚠️ ${msg}`,
        timestamp: new Date(),
      };
      setChatMessages((prev) => [...prev, errMsg]);
    } finally {
      setChatLoading(false);
    }
  };

  const suggestedQuestions = [
    'What should I do to stay safe?',
    'How can I verify if this is malicious?',
    'What data could be stolen from this?',
  ];

  const canChat = !!chatContext && !!explanation && !isLoading;

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
        style={{ background: `linear-gradient(90deg, transparent, ${accent}90, transparent)` }}
      />

      {/* Ambient glow */}
      <div
        className="absolute top-0 left-0 w-48 h-48 rounded-full pointer-events-none"
        style={{ background: `radial-gradient(circle, ${accent}08 0%, transparent 70%)` }}
      />

      {/* ── Header ── */}
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
              background: isLoading
                ? 'rgba(79,172,254,0.1)'
                : error
                ? 'rgba(239,68,68,0.1)'
                : `${accent}15`,
              border: `1px solid ${
                isLoading
                  ? 'rgba(79,172,254,0.25)'
                  : error
                  ? 'rgba(239,68,68,0.3)'
                  : `${accent}30`
              }`,
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

      {/* ── Explanation Body ── */}
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

      {/* ── Ask AI Toggle Button ── */}
      {canChat && (
        <div className="px-5 pb-2">
          <motion.button
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
            onClick={() => setIsChatOpen((v) => !v)}
            className="w-full flex items-center justify-between px-4 py-2.5 rounded-xl text-xs font-semibold transition-all"
            style={{
              background: isChatOpen ? `${accent}18` : 'rgba(255,255,255,0.04)',
              border: `1px solid ${isChatOpen ? `${accent}35` : 'rgba(255,255,255,0.08)'}`,
              color: isChatOpen ? accent : '#94a3b8',
            }}
          >
            <span className="flex items-center gap-2">
              <MessageSquare className="w-3.5 h-3.5" />
              Ask AI about this threat
              {chatMessages.length > 0 && (
                <span
                  className="px-1.5 py-0.5 rounded-full text-[9px] font-bold"
                  style={{ background: `${accent}25`, color: accent }}
                >
                  {chatMessages.filter((m) => m.role === 'assistant').length}
                </span>
              )}
            </span>
            <motion.div
              animate={{ rotate: isChatOpen ? 180 : 0 }}
              transition={{ duration: 0.2 }}
            >
              <ChevronDown className="w-3.5 h-3.5" />
            </motion.div>
          </motion.button>
        </div>
      )}

      {/* ── Chat Panel ── */}
      <AnimatePresence>
        {isChatOpen && canChat && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.3, ease: 'easeInOut' }}
            className="overflow-hidden"
          >
            <div className="px-5 pt-1 pb-4 border-t border-white/5 mt-2">
              {/* Chat header */}
              <div className="flex items-center justify-between mb-3">
                <div className="text-[10px] font-bold uppercase tracking-widest text-cyber-muted">
                  Interactive AI Chat
                </div>
                <button
                  onClick={() => {
                    setChatMessages([]);
                    setChatInput('');
                  }}
                  className="text-[10px] text-cyber-muted hover:text-white transition-colors flex items-center gap-1"
                >
                  <X className="w-3 h-3" />
                  Clear
                </button>
              </div>

              {/* Suggested questions (when no messages yet) */}
              {chatMessages.length === 0 && (
                <div className="flex flex-wrap gap-2 mb-4">
                  {suggestedQuestions.map((q) => (
                    <button
                      key={q}
                      onClick={() => setChatInput(q)}
                      className="text-[11px] px-3 py-1.5 rounded-lg transition-all"
                      style={{
                        background: `${accent}0d`,
                        border: `1px solid ${accent}20`,
                        color: '#94a3b8',
                      }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.color = accent;
                        e.currentTarget.style.borderColor = `${accent}50`;
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.color = '#94a3b8';
                        e.currentTarget.style.borderColor = `${accent}20`;
                      }}
                    >
                      {q}
                    </button>
                  ))}
                </div>
              )}

              {/* Messages */}
              {chatMessages.length > 0 && (
                <div className="space-y-3 mb-4 max-h-64 overflow-y-auto pr-1 scrollbar-thin">
                  {chatMessages.map((msg, idx) => (
                    <ChatBubble
                      key={idx}
                      message={msg}
                      accent={accent}
                      isLatest={idx === chatMessages.length - 1}
                    />
                  ))}

                  {/* Loading indicator */}
                  {chatLoading && (
                    <motion.div
                      initial={{ opacity: 0, y: 4 }}
                      animate={{ opacity: 1, y: 0 }}
                      className="flex gap-2.5"
                    >
                      <div
                        className="w-7 h-7 rounded-xl flex items-center justify-center flex-shrink-0"
                        style={{ background: `${accent}18`, border: `1px solid ${accent}30` }}
                      >
                        <Bot className="w-3.5 h-3.5" style={{ color: accent }} />
                      </div>
                      <div
                        className="px-3.5 py-2.5 rounded-2xl rounded-tl-sm flex items-center gap-1.5"
                        style={{ background: `${accent}0d`, border: `1px solid ${accent}20` }}
                      >
                        {[0, 1, 2].map((i) => (
                          <motion.div
                            key={i}
                            className="w-1.5 h-1.5 rounded-full"
                            style={{ backgroundColor: accent }}
                            animate={{ scale: [1, 1.4, 1], opacity: [0.4, 1, 0.4] }}
                            transition={{ duration: 0.7, repeat: Infinity, delay: i * 0.15 }}
                          />
                        ))}
                      </div>
                    </motion.div>
                  )}
                  <div ref={chatEndRef} />
                </div>
              )}

              {/* Chat input */}
              <div
                className="flex items-center gap-2 p-1.5 rounded-xl"
                style={{
                  background: 'rgba(255,255,255,0.04)',
                  border: `1px solid ${accent}25`,
                }}
              >
                <input
                  ref={chatInputRef}
                  type="text"
                  value={chatInput}
                  onChange={(e) => setChatInput(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && !e.shiftKey && handleChatSend()}
                  placeholder="Ask anything about this threat..."
                  disabled={chatLoading}
                  className="flex-1 bg-transparent outline-none text-xs text-white placeholder:text-cyber-muted/50 px-2 py-1.5"
                />
                <motion.button
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                  onClick={handleChatSend}
                  disabled={!chatInput.trim() || chatLoading}
                  className="w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0 disabled:opacity-40 transition-all"
                  style={{ background: `${accent}25`, border: `1px solid ${accent}40` }}
                >
                  {chatLoading ? (
                    <div
                      className="w-3.5 h-3.5 border border-white/20 border-t-white rounded-full animate-spin"
                    />
                  ) : (
                    <Send className="w-3.5 h-3.5" style={{ color: accent }} />
                  )}
                </motion.button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Footer attribution */}
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

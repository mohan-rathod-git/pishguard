// ── AI Explainer Service ──────────────────────────────────────────────────────
// Sends phishing detection results through the internal Next.js proxy → n8n → OpenRouter.
// The proxy at /api/ai-explain eliminates browser CORS issues with n8n.

/** Internal proxy endpoint — server-side, no CORS restrictions */
const AI_PROXY_URL = '/api/ai-explain';

// ── Types ─────────────────────────────────────────────────────────────────────

export interface AIExplainPayload {
  url: string;
  risk_score: number;
  prediction: string;
  reasons: string[];
}

export interface AIExplainResponse {
  explanation: string;
  model?: string;
  tokens_used?: number;
}

export interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
  timestamp: Date;
}

// ── explainThreat ─────────────────────────────────────────────────────────────

/**
 * Sends threat data to n8n (via proxy) for an AI-generated explanation.
 * Returns a human-readable threat explanation or throws on failure.
 */
export async function explainThreat(
  payload: AIExplainPayload,
  timeoutMs = 30_000
): Promise<AIExplainResponse> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(AI_PROXY_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        type: 'explain',
        ...payload,
      }),
      signal: controller.signal,
    });

    const data = await res.json();

    if (!res.ok) {
      throw new Error(
        data.error ?? data.detail ?? `AI service error: ${res.status}`
      );
    }

    return {
      explanation: data.explanation ?? 'AI analysis complete.',
      model: data.model,
      tokens_used: data.tokens_used,
    };
  } catch (err: unknown) {
    if (err instanceof Error && err.name === 'AbortError') {
      throw new Error(
        'AI Explainer timed out. The n8n workflow took too long to respond.'
      );
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

// ── chatWithAI ────────────────────────────────────────────────────────────────

/**
 * Send a follow-up question to the AI about a detected threat.
 * Passes the full threat context + question to n8n so the LLM
 * can answer accurately.
 */
export async function chatWithAI(
  context: AIExplainPayload,
  question: string,
  history: ChatMessage[],
  timeoutMs = 25_000
): Promise<string> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(AI_PROXY_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        type: 'chat',
        question,
        url: context.url,
        risk_score: context.risk_score,
        prediction: context.prediction,
        reasons: context.reasons,
        // Compact history for context (last 6 messages max)
        history: history.slice(-6).map((m) => ({
          role: m.role,
          content: m.content,
        })),
      }),
      signal: controller.signal,
    });

    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.error ?? `Chat error: ${res.status}`);
    }

    return (
      data.explanation ??
      data.output ??
      data.message ??
      data.text ??
      data.reply ??
      'The AI did not return a response. Please try again.'
    );
  } catch (err: unknown) {
    if (err instanceof Error && err.name === 'AbortError') {
      throw new Error('Chat request timed out. Please try again.');
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

// ── AI Explainer Service ──────────────────────────────────────────────────────
// Sends phishing detection results to n8n webhook → OpenRouter → AI explanation

const N8N_WEBHOOK_URL =
  process.env.NEXT_PUBLIC_N8N_WEBHOOK_URL ||
  'https://mohanrathod123.app.n8n.cloud/webhook/explain-link';

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

/**
 * Sends threat data to the n8n webhook which routes to OpenRouter for AI explanation.
 * Returns a human-readable threat explanation or throws on failure.
 */
export async function explainThreat(
  payload: AIExplainPayload,
  timeoutMs = 20000
): Promise<AIExplainResponse> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(N8N_WEBHOOK_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });

    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(
        `AI Explainer returned ${res.status}${text ? ': ' + text.slice(0, 120) : ''}`
      );
    }

    const data = await res.json();

    // n8n can return {explanation: "..."} or [{explanation: "..."}] or raw string
    if (Array.isArray(data)) {
      const first = data[0];
      return {
        explanation:
          first?.explanation ||
          first?.output ||
          first?.message ||
          first?.text ||
          JSON.stringify(first),
        model: first?.model,
      };
    }

    if (typeof data === 'string') {
      return { explanation: data };
    }

    return {
      explanation:
        data.explanation ||
        data.output ||
        data.message ||
        data.text ||
        data.result ||
        'AI analysis complete.',
      model: data.model,
      tokens_used: data.tokens_used,
    };
  } catch (err: unknown) {
    if (err instanceof Error && err.name === 'AbortError') {
      throw new Error('AI Explainer timed out. The n8n workflow took too long to respond.');
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

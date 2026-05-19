/**
 * PhishGuard AI — AI Explain Proxy Route
 *
 * Calls OpenRouter directly (server-side, no CORS).
 * Falls back to n8n if FORCE_N8N=true env var is set.
 *
 * OpenRouter API key is kept server-side only — never exposed to the browser.
 */

import { NextRequest, NextResponse } from 'next/server';

export const runtime = 'nodejs';

// ── Config ────────────────────────────────────────────────────────────────────

const OPENROUTER_URL = 'https://openrouter.ai/api/v1/chat/completions';

const OPENROUTER_KEY = process.env.OPENROUTER_API_KEY || '';

const N8N_URL =
  process.env.N8N_WEBHOOK_URL ||
  process.env.NEXT_PUBLIC_N8N_WEBHOOK_URL ||
  'https://mohanrathod123.app.n8n.cloud/webhook/explain-link';

const USE_N8N =
  process.env.FORCE_N8N === 'true' ||
  process.env.NEXT_PUBLIC_FORCE_N8N === 'true' ||
  !OPENROUTER_KEY; // Default to n8n if no OpenRouter key is set


// ── Prompt builder ────────────────────────────────────────────────────────────

function buildPrompt(body: Record<string, unknown>): string {
  const url = (body.url as string) || 'Unknown URL';
  const prediction = (body.prediction as string) || 'UNKNOWN';
  const risk = (body.risk_score as number) ?? 0;
  const reasons = (body.reasons as string[]) || [];
  const type = (body.type as string) || 'explain';
  const question = (body.question as string) || '';
  const history = (body.history as Array<{ role: string; content: string }>) || [];

  if (type === 'chat' && question) {
    const historyText = history
      .map((m) => `${m.role === 'user' ? 'User' : 'AI'}: ${m.content}`)
      .join('\n');

    return [
      `You are PhishGuard AI, a cybersecurity expert.`,
      ``,
      `Threat context:`,
      `- URL: ${url}`,
      `- Threat type: ${prediction}`,
      `- Risk score: ${risk}/100`,
      `- Reasons: ${reasons.join(', ') || 'None'}`,
      ``,
      historyText ? `Previous conversation:\n${historyText}\n` : '',
      `User question: ${question}`,
      ``,
      `Answer clearly and helpfully in 2-3 sentences. Plain text only.`,
    ]
      .filter(Boolean)
      .join('\n');
  }

  // Default: explain the threat
  return [
    `Analyze this cybersecurity threat and explain it in 2-3 clear sentences.`,
    `Tell the user: what kind of attack this is, why it is dangerous, and what they should do.`,
    `Plain text only — no markdown, no bullet points.`,
    ``,
    `URL: ${url}`,
    `Threat type: ${prediction}`,
    `Risk score: ${risk}/100`,
    `Detection reasons: ${reasons.join(', ') || 'None'}`,
  ].join('\n');
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async function callOpenRouter(
  prompt: string,
  signal: AbortSignal
): Promise<string> {
  const res = await fetch(OPENROUTER_URL, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${OPENROUTER_KEY}`,
      'Content-Type': 'application/json',
      'HTTP-Referer': 'https://phishguard.ai',
      'X-Title': 'PhishGuard AI',
    },
    body: JSON.stringify({
      model: 'openai/gpt-4o-mini',
      messages: [
        {
          role: 'system',
          content:
            'You are PhishGuard AI, a cybersecurity expert. ' +
            'Provide clear, concise, and helpful threat analysis. ' +
            'Always respond in plain text without markdown.',
        },
        { role: 'user', content: prompt },
      ],
      max_tokens: 350,
      temperature: 0.7,
    }),
    signal,
  });

  const data = await res.json();

  if (!res.ok) {
    throw new Error(
      `OpenRouter error ${res.status}: ${data?.error?.message || JSON.stringify(data)}`
    );
  }

  const text: string = data?.choices?.[0]?.message?.content;
  if (!text) throw new Error('OpenRouter returned no content');
  return text;
}

async function callN8N(
  body: Record<string, unknown>,
  signal: AbortSignal
): Promise<string> {
  const res = await fetch(N8N_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify(body),
    signal,
  });

  const raw = await res.text();
  if (!res.ok) throw new Error(`n8n error ${res.status}: ${raw.slice(0, 200)}`);
  if (!raw.trim()) throw new Error('n8n returned empty response');

  try {
    const data = JSON.parse(raw);
    const arr = Array.isArray(data) ? data[0] : data;
    return (
      arr?.explanation ?? arr?.output ?? arr?.message ?? arr?.text ?? arr?.reply ?? raw
    );
  } catch {
    return raw;
  }
}

// ── Route handler ─────────────────────────────────────────────────────────────

export async function POST(req: NextRequest) {
  let body: Record<string, unknown>;
  try {
    body = (await req.json()) as Record<string, unknown>;
  } catch {
    return NextResponse.json({ error: 'Invalid JSON body' }, { status: 400 });
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 30_000);

  try {
    let explanation: string;

    if (USE_N8N) {
      // Route through n8n
      explanation = await callN8N(body, controller.signal);
    } else {
      // Call OpenRouter directly (reliable, no CORS, no n8n dependency)
      const prompt = buildPrompt(body);
      explanation = await callOpenRouter(prompt, controller.signal);
    }

    return NextResponse.json({ explanation });
  } catch (err: unknown) {
    if (err instanceof Error && err.name === 'AbortError') {
      return NextResponse.json(
        { error: 'AI request timed out after 30 seconds.' },
        { status: 504 }
      );
    }

    // If OpenRouter failed, try n8n as fallback (only if not already using n8n)
    if (!USE_N8N) {
      try {
        const explanation = await callN8N(body, new AbortController().signal);
        return NextResponse.json({ explanation });
      } catch {
        // Both failed — return the original error
      }
    }

    const msg = err instanceof Error ? err.message : 'Unknown error';
    console.error('[AI Proxy] Error:', msg);
    return NextResponse.json({ error: msg }, { status: 500 });
  } finally {
    clearTimeout(timer);
  }
}

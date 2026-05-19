/**
 * PhishGuard AI — AI Explain Proxy Route
 *
 * Priority order:
 *  1. OpenRouter (fastest — set OPENROUTER_API_KEY in Netlify env vars)
 *  2. n8n webhook (set N8N_WEBHOOK_URL in Netlify env vars)
 *  3. Built-in rule-based explanation (always works, no external deps)
 */

import { NextRequest, NextResponse } from 'next/server';

export const runtime = 'nodejs';

// ── Config ─────────────────────────────────────────────────────────────────

const OPENROUTER_URL = 'https://openrouter.ai/api/v1/chat/completions';
const OPENROUTER_KEY = process.env.OPENROUTER_API_KEY || '';

const N8N_URL =
  process.env.N8N_WEBHOOK_URL ||
  process.env.NEXT_PUBLIC_N8N_WEBHOOK_URL ||
  'https://mohanrathod123.app.n8n.cloud/webhook/explain-link';

const USE_OPENROUTER = !!OPENROUTER_KEY;
const FORCE_N8N =
  process.env.FORCE_N8N === 'true' ||
  process.env.NEXT_PUBLIC_FORCE_N8N === 'true';

// ── Built-in fallback explanation ──────────────────────────────────────────

function generateFallbackExplanation(body: Record<string, unknown>): string {
  const url = (body.url as string) || 'this URL';
  const prediction = ((body.prediction as string) || 'THREAT').toUpperCase();
  const risk = (body.risk_score as number) ?? 50;
  const reasons = (body.reasons as string[]) || [];
  const type = (body.type as string) || 'explain';
  const question = (body.question as string) || '';

  const threatDescriptions: Record<string, string> = {
    PHISHING:
      'This is a phishing attack designed to steal your login credentials or personal data by impersonating a legitimate website.',
    MALWARE:
      'This URL may distribute malware or ransomware that can infect and compromise your device.',
    SCAM:
      'This URL is associated with a scam operation designed to defraud users of money or personal information.',
    FAKE_PAYMENT:
      'This QR code contains a fake payment redirect — it is designed to hijack payment flows and steal funds through fraudulent UPI or payment gateway links.',
    SPAM:
      'This URL is classified as spam and leads to unwanted advertising or potentially harmful content.',
    SUSPICIOUS:
      'This URL exhibits suspicious characteristics commonly associated with malicious intent, such as unusual redirects or deceptive domain names.',
    CRITICAL:
      'This URL poses a critical and immediate security threat. It has been flagged with the highest severity indicators.',
    UNKNOWN:
      'This URL has been flagged as potentially dangerous based on its structural characteristics and domain analysis.',
  };

  const description =
    threatDescriptions[prediction] ||
    `This URL has been classified as a ${prediction} threat by the PhishGuard AI engine.`;

  const riskLabel =
    risk >= 75 ? 'critical' : risk >= 50 ? 'high' : risk >= 25 ? 'moderate' : 'low';

  const reasonText =
    reasons.length > 0
      ? ` Key detection signals: ${reasons.slice(0, 3).join('; ')}.`
      : '';

  if (type === 'chat' && question) {
    // Simple keyword-based chat response
    const q = question.toLowerCase();
    if (q.includes('safe') || q.includes('open') || q.includes('click')) {
      return `No — do not open or click this URL. It has a ${riskLabel} risk score of ${risk}/100 and has been classified as ${prediction}. ${description}`;
    }
    if (q.includes('what') || q.includes('why') || q.includes('how')) {
      return `${description} Risk score: ${risk}/100 (${riskLabel}).${reasonText} Avoid interacting with this link.`;
    }
    if (q.includes('report') || q.includes('who')) {
      return `You can report this ${prediction} threat to your national cybercrime authority or directly to the website being impersonated. Do not share this link with others.`;
    }
    return `This URL is classified as ${prediction} with a ${riskLabel} risk score (${risk}/100). ${description} Avoid any interaction with it.`;
  }

  return `${description} The AI risk assessment is ${risk}/100 (${riskLabel} risk).${reasonText} Immediately avoid this link — do not enter any credentials, make payments, or share personal information.`;
}

// ── Prompt builder ─────────────────────────────────────────────────────────

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

// ── External AI Handlers ───────────────────────────────────────────────────

async function callOpenRouter(prompt: string, signal: AbortSignal): Promise<string> {
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
    const text =
      arr?.explanation ?? arr?.output ?? arr?.message ?? arr?.text ?? arr?.reply;
    if (text && typeof text === 'string' && text.trim()) return text;
    return raw;
  } catch {
    return raw;
  }
}

// ── Route Handler ──────────────────────────────────────────────────────────

export async function POST(req: NextRequest) {
  let body: Record<string, unknown>;
  try {
    body = (await req.json()) as Record<string, unknown>;
  } catch {
    return NextResponse.json({ error: 'Invalid JSON body' }, { status: 400 });
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 28_000);

  try {
    let explanation: string | null = null;

    // 1. Try OpenRouter (if API key is configured)
    if (USE_OPENROUTER && !FORCE_N8N) {
      try {
        const prompt = buildPrompt(body);
        explanation = await callOpenRouter(prompt, controller.signal);
      } catch (e) {
        console.warn('[AI Proxy] OpenRouter failed, trying n8n:', (e as Error).message);
      }
    }

    // 2. Try n8n webhook (if OpenRouter unavailable or FORCE_N8N)
    if (!explanation) {
      try {
        explanation = await callN8N(body, controller.signal);
      } catch (e) {
        console.warn('[AI Proxy] n8n failed, using built-in fallback:', (e as Error).message);
      }
    }

    // 3. Built-in rule-based fallback (always works, no external dependency)
    if (!explanation) {
      explanation = generateFallbackExplanation(body);
    }

    return NextResponse.json({ explanation });
  } catch (err: unknown) {
    if (err instanceof Error && err.name === 'AbortError') {
      // On timeout, still return a fallback rather than an error
      const explanation = generateFallbackExplanation(body);
      return NextResponse.json({ explanation });
    }

    const msg = err instanceof Error ? err.message : 'Unknown error';
    console.error('[AI Proxy] Unhandled error:', msg);

    // Last resort: return built-in explanation
    const explanation = generateFallbackExplanation(body);
    return NextResponse.json({ explanation });
  } finally {
    clearTimeout(timer);
  }
}

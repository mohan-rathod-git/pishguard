/**
 * PhishGuard AI — Backend Proxy Route
 *
 * All browser requests to /api/backend/* are forwarded here (server-side)
 * to the FastAPI backend. This eliminates CORS issues and keeps the
 * backend URL private (not exposed to the browser).
 *
 * Set BACKEND_URL in Netlify → Site settings → Environment variables.
 * Example: https://phishguard-api.onrender.com/api/v1
 */

import { NextRequest, NextResponse } from 'next/server';

export const runtime = 'nodejs';

// Server-side only — never sent to the browser
const BACKEND_URL = (
  process.env.BACKEND_URL ||
  process.env.NEXT_PUBLIC_API_URL ||
  'http://localhost:8000/api/v1'
).replace(/\/$/, '');

async function proxy(req: NextRequest, pathSegments: string[]): Promise<NextResponse> {
  const path = pathSegments.join('/');
  const targetUrl = `${BACKEND_URL}/${path}`;
  const contentType = req.headers.get('content-type') ?? '';

  const fetchOptions: RequestInit = { method: req.method };

  if (req.method !== 'GET' && req.method !== 'HEAD') {
    if (contentType.includes('multipart/form-data')) {
      // Forward FormData — fetch sets the correct boundary automatically
      fetchOptions.body = await req.formData();
    } else {
      fetchOptions.headers = { 'Content-Type': contentType || 'application/json' };
      fetchOptions.body = await req.text();
    }
  }

  try {
    const upstream = await fetch(targetUrl, fetchOptions);
    const text = await upstream.text();
    const resCt = upstream.headers.get('content-type') ?? 'application/json';

    return new NextResponse(text, {
      status: upstream.status,
      headers: { 'Content-Type': resCt },
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'Network error';
    console.error(`[Backend Proxy] ${req.method} /${path} → ${targetUrl} :`, msg);
    return NextResponse.json(
      {
        detail:
          `PhishGuard backend is unreachable (${msg}). ` +
          'Deploy the FastAPI backend and set the BACKEND_URL environment variable in Netlify.',
      },
      { status: 503 }
    );
  }
}

export async function GET(req: NextRequest, { params }: { params: { path: string[] } }) {
  return proxy(req, params.path);
}

export async function POST(req: NextRequest, { params }: { params: { path: string[] } }) {
  return proxy(req, params.path);
}

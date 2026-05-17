import {
  PredictionResponse,
  BatchPredictionResponse,
  QRScanResponse,
  QRHealthResponse,
  HealthResponse,
  ModelInfoResponse,
} from '@/types';

const BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1';

async function fetcher<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Unknown error' }));
    throw new Error(err.detail || `Request failed: ${res.status}`);
  }

  return res.json();
}

// ── URL Prediction ────────────────────────────────────────

export async function predictUrl(url: string): Promise<PredictionResponse> {
  return fetcher<PredictionResponse>('/predict', {
    method: 'POST',
    body: JSON.stringify({ url }),
  });
}

export async function batchPredictUrls(urls: string[]): Promise<BatchPredictionResponse> {
  return fetcher<BatchPredictionResponse>('/batch_predict', {
    method: 'POST',
    body: JSON.stringify({ urls }),
  });
}

// ── QR Scanning ───────────────────────────────────────────

export async function scanQRFile(file: File): Promise<QRScanResponse> {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('follow_redirects', 'true');
  formData.append('use_ml_model', 'true');

  const res = await fetch(`${BASE_URL}/qr/scan`, {
    method: 'POST',
    body: formData,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Unknown error' }));
    throw new Error(err.detail || `QR scan failed: ${res.status}`);
  }

  return res.json();
}

export async function scanQRBase64(base64: string): Promise<QRScanResponse> {
  return fetcher<QRScanResponse>('/qr/scan/base64', {
    method: 'POST',
    body: JSON.stringify({
      image_base64: base64,
      follow_redirects: true,
      use_ml_model: true,
    }),
  });
}

// ── Health / System ───────────────────────────────────────

export async function getHealth(): Promise<HealthResponse> {
  return fetcher<HealthResponse>('/health');
}

export async function getQRHealth(): Promise<QRHealthResponse> {
  return fetcher<QRHealthResponse>('/qr/health');
}

export async function getModelInfo(): Promise<ModelInfoResponse> {
  return fetcher<ModelInfoResponse>('/model-info');
}

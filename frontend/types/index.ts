// ── URL Prediction Types ──────────────────────────────────

// URL model labels
export type ThreatLevel = 'SAFE' | 'PHISHING' | 'MALWARE' | 'SPAM' | 'SCAM' | 'ERROR';

// QR engine can return additional classifications
export type QRThreatLevel =
  | ThreatLevel
  | 'FAKE_PAYMENT'
  | 'SUSPICIOUS'
  | 'CRITICAL'
  | 'UNKNOWN';

export interface PredictionResponse {
  url: string;
  prediction: ThreatLevel;
  confidence: number;
  risk_score: number;
  reasons: string[];
  processing_time_ms?: number;
}

export interface BatchPredictionResponse {
  count: number;
  results: PredictionResponse[];
}

// ── QR Scan Types ─────────────────────────────────────────

export type QRStatus =
  | 'BLOCKED'
  | 'ALLOWED'
  | 'NO_QR_FOUND'
  | 'ERROR'
  | 'DECODE_FAILED'
  | 'SCAN_FAILED';

export type QRPayloadType =
  | 'URL'
  | 'TEXT'
  | 'EMAIL'
  | 'PHONE'
  | 'WIFI'
  | 'VCARD'
  | 'PAYMENT'
  | 'UPI_PAYMENT'
  | 'GEO'
  | 'GEO_LOCATION'
  | 'UNKNOWN';

export interface QRScanResponse {
  scan_id?: string;
  status: QRStatus;
  prediction: QRThreatLevel | null;
  confidence: number;
  risk_score: number;
  severity?: string;
  decoded_payload: string | null;
  payload_type: QRPayloadType | null;
  redirect_chain: string[];
  final_url: string | null;
  reasons: string[];
  fake_payment_detected: boolean;
  is_shortened_url: boolean;
  processing_time_ms: number;
  qr_count?: number;
  all_results?: Record<string, unknown>[];
}

export interface QRHealthResponse {
  status: 'healthy' | 'degraded';
  qr_engine_active: boolean;
  ml_model_loaded: boolean;
  total_scans: number;
  total_blocked: number;
  block_rate: number;
  blocking_threshold: number;
  sandbox_available: boolean;
  uptime_seconds: number;
}

// ── Health / Metrics Types ────────────────────────────────

export interface HealthResponse {
  status: string;
  app: string;
  version: string;
  model_loaded: boolean;
  uptime_seconds: number;
}

export interface ModelInfoResponse {
  model_type: string;
  feature_count: number;
  training_accuracy?: number;
  training_date?: string;
}

// ── UI / Store Types ──────────────────────────────────────

export interface ScanHistoryItem {
  id: string;
  type: 'url' | 'qr';
  input: string;
  prediction: ThreatLevel | null;
  risk_score: number;
  timestamp: Date;
  status: QRStatus | 'SCANNED';
}

export interface NavItem {
  label: string;
  href: string;
  icon?: string;
}

export interface MetricCard {
  label: string;
  value: string | number;
  change?: string;
  trend?: 'up' | 'down' | 'neutral';
  color?: 'blue' | 'green' | 'red' | 'purple' | 'orange';
}

// ── Analytics ────────────────────────────────────────────

export interface ThreatStat {
  label: string;
  count: number;
  percentage: number;
  color: string;
}

export interface ChartDataPoint {
  name: string;
  value: number;
  blocked?: number;
  safe?: number;
}

// ── AI Explanation ────────────────────────────────────────

export type AIExplainStatus = 'idle' | 'loading' | 'done' | 'error';

export interface AIExplanationState {
  status: AIExplainStatus;
  explanation: string | null;
  error: string | null;
}

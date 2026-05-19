/**
 * PhishGuard AI — Pure-JS QR Code Scanner
 * Works 100% on Netlify — uses jsqr (pure JS) + sharp for image processing.
 * No Python backend required.
 */
import { NextRequest, NextResponse } from 'next/server';

export const runtime = 'nodejs';

// ── URL heuristics (same logic as /api/scan/url) ──────────────────────────
function analyzeUrl(rawUrl: string) {
  const reasons: string[] = [];
  let risk = 0;

  const SAFE = new Set(['google.com','youtube.com','github.com','microsoft.com','apple.com','amazon.com','facebook.com','twitter.com','x.com','linkedin.com','netlify.app','vercel.app','wikipedia.org','stackoverflow.com']);
  const SHORTENERS = new Set(['bit.ly','tinyurl.com','t.co','goo.gl','rb.gy','t.ly','cutt.ly','ow.ly','is.gd']);
  const RISKY_TLDS = new Set(['.ru','.cn','.tk','.ml','.ga','.cf','.gq','.xyz','.top','.click','.online','.site','.website','.pw']);

  const urlStr = rawUrl.trim();
  let parsed: URL;
  try { parsed = new URL(/^https?:\/\//i.test(urlStr) ? urlStr : `http://${urlStr}`); }
  catch { return { risk: 80, reasons: ['Invalid URL format'], prediction: 'PHISHING' }; }

  const hostname = parsed.hostname.toLowerCase();
  const parts = hostname.split('.');
  const root = parts.slice(-2).join('.');
  const tld = '.' + parts[parts.length - 1];
  const path = parsed.pathname.toLowerCase();
  const full = urlStr.toLowerCase();

  if (SAFE.has(root)) return { risk: 5, reasons: ['Known trusted domain'], prediction: 'SAFE' };

  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) { risk += 45; reasons.push('IP address used as domain'); }
  if (rawUrl.includes('@')) { risk += 40; reasons.push('@ symbol in URL (phishing trick)'); }
  if (hostname.includes('xn--')) { risk += 35; reasons.push('Punycode domain (homograph attack)'); }
  if (SHORTENERS.has(hostname)) { risk += 30; reasons.push('URL shortener hides destination'); }
  if (RISKY_TLDS.has(tld)) { risk += 18; reasons.push(`High-risk TLD: ${tld}`); }

  const subCount = parts.length - 2;
  if (subCount > 3) { risk += 22; reasons.push(`Excessive subdomains (${subCount})`); }

  const BRANDS = ['paypal','amazon','apple','google','microsoft','facebook','instagram','netflix','ebay','hdfc','sbi','icici','phonepe','paytm','gpay'];
  const brandHits = BRANDS.filter(b => hostname.includes(b) && root !== `${b}.com` && root !== `${b}.in`);
  if (brandHits.length > 0) { risk += Math.min(brandHits.length * 18, 40); reasons.push(`Brand impersonation: ${brandHits.join(', ')}`); }

  const CRED = ['login','signin','auth','verify','validate','confirm','account','secure','password'];
  if (CRED.some(p => path.includes(p)) && brandHits.length > 0) { risk += 25; reasons.push('Credential harvesting page'); }

  const PAY = ['upi','gpay','phonepe','paytm','cashback','refund','kyc'];
  const payHits = PAY.filter(t => full.includes(t));
  if (payHits.length >= 2) { risk += 35; reasons.push(`Fake payment: ${payHits.join(', ')}`); }

  const MAL = ['.exe','.apk','.bat','.cmd','.ps1','.vbs','malware','exploit'];
  if (MAL.some(p => path.includes(p))) { risk += 30; reasons.push('Malicious download detected'); }

  if (rawUrl.length > 200) { risk += 12; reasons.push('Extremely long URL'); }
  if (parsed.protocol === 'http:' && subCount > 0) { risk += 8; reasons.push('Unencrypted HTTP'); }

  risk = Math.max(0, Math.min(100, risk));
  let prediction = 'SAFE';
  if (risk >= 70) prediction = 'PHISHING';
  else if (risk >= 52) prediction = 'SCAM';
  else if (risk >= 30) prediction = 'SUSPICIOUS';
  else if (risk >= 15) prediction = 'SPAM';

  if (reasons.length === 0) reasons.push('No significant threat indicators found');
  return { risk, reasons, prediction };
}

// ── Payload type classifier ───────────────────────────────────────────────
function classifyPayload(text: string): string {
  const t = text.trim();
  if (/^https?:\/\//i.test(t)) return 'URL';
  if (/^upi:\/\/pay\?/i.test(t)) return 'UPI_PAYMENT';
  if (/^BEGIN:VCARD/i.test(t)) return 'VCARD';
  if (/^WIFI:/i.test(t)) return 'WIFI';
  if (/^mailto:/i.test(t)) return 'EMAIL';
  if (/^tel:/i.test(t)) return 'PHONE';
  if (/^sms(to)?:/i.test(t)) return 'SMS';
  if (/^geo:/i.test(t)) return 'GEO_LOCATION';
  if (/^bitcoin:|^ethereum:/i.test(t)) return 'CRYPTO';
  if (/^[a-zA-Z0-9].*\.[a-zA-Z]{2,}/.test(t)) return 'URL';
  return 'PLAIN_TEXT';
}

function extractUrl(payload: string): string | null {
  const match = payload.match(/https?:\/\/[^\s<>"']+/i);
  if (match) return match[0];
  if (/^upi:\/\/pay\?/i.test(payload)) return payload;
  if (/^[a-zA-Z0-9].*\.[a-zA-Z]{2,}/.test(payload.trim())) return `http://${payload.trim()}`;
  return null;
}

const SHORTENER_DOMAINS = ['bit.ly','tinyurl.com','t.co','goo.gl','rb.gy','t.ly','cutt.ly'];

export async function POST(req: NextRequest) {
  const start = Date.now();
  const scanId = 'JS-' + Math.random().toString(36).slice(2, 10).toUpperCase();

  try {
    const formData = await req.formData();
    const file = formData.get('file') as File | null;

    if (!file) return NextResponse.json({ detail: 'No file uploaded' }, { status: 400 });
    if (!file.type.startsWith('image/')) return NextResponse.json({ detail: 'File must be an image' }, { status: 400 });

    const buffer = Buffer.from(await file.arrayBuffer());

    // Dynamic imports — avoids bundling issues
    const sharp = (await import('sharp')).default;
    const jsQR = (await import('jsqr')).default;

    // Try 1: original image
    let code = null;
    const { data, info } = await sharp(buffer).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
    code = jsQR(new Uint8ClampedArray(data), info.width, info.height);

    // Try 2: grayscale + normalize (improves low-contrast/damaged QRs)
    if (!code) {
      const { data: d2, info: i2 } = await sharp(buffer).grayscale().normalize().ensureAlpha().raw().toBuffer({ resolveWithObject: true });
      code = jsQR(new Uint8ClampedArray(d2), i2.width, i2.height);
    }

    // Try 3: resize to 600px (helps very large or very small images)
    if (!code) {
      const { data: d3, info: i3 } = await sharp(buffer).resize(600, 600, { fit: 'inside' }).grayscale().ensureAlpha().raw().toBuffer({ resolveWithObject: true });
      code = jsQR(new Uint8ClampedArray(d3), i3.width, i3.height);
    }

    if (!code) {
      return NextResponse.json({
        scan_id: scanId, status: 'NO_QR_FOUND', prediction: 'UNKNOWN',
        risk_score: 0, confidence: 0, severity: 'NONE',
        decoded_payload: null, payload_type: null, final_url: null,
        redirect_chain: [], reasons: ['No QR code detected in the uploaded image'],
        fake_payment_detected: false, is_shortened_url: false,
        processing_time_ms: Date.now() - start, qr_count: 0, all_results: [],
      });
    }

    const payload = code.data;
    const payloadType = classifyPayload(payload);
    const extractedUrl = extractUrl(payload);
    const urlToAnalyze = extractedUrl || payload;

    const { risk, reasons, prediction } = analyzeUrl(urlToAnalyze);

    const isFakePayment = payloadType === 'UPI_PAYMENT' && risk >= 50;
    if (isFakePayment && !reasons.some(r => r.includes('payment'))) {
      reasons.push('Suspicious UPI payment QR detected');
    }

    const isShortened = SHORTENER_DOMAINS.some(s => (extractedUrl || '').includes(s));
    const isBlocked = risk >= 55 || isFakePayment;
    const status = isBlocked ? 'BLOCKED' : 'ALLOWED';

    let severity = 'NONE';
    if (risk >= 80) severity = 'CRITICAL';
    else if (risk >= 60) severity = 'HIGH';
    else if (risk >= 40) severity = 'MEDIUM';
    else if (risk >= 15) severity = 'LOW';

    return NextResponse.json({
      scan_id: scanId,
      status,
      prediction,
      risk_score: risk,
      confidence: parseFloat(Math.min(0.99, 0.5 + risk / 180).toFixed(4)),
      severity,
      decoded_payload: payload,
      payload_type: payloadType,
      final_url: extractedUrl,
      redirect_chain: extractedUrl ? [extractedUrl] : [],
      reasons,
      fake_payment_detected: isFakePayment,
      is_shortened_url: isShortened,
      processing_time_ms: Date.now() - start,
      qr_count: 1,
      all_results: [],
    });

  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : 'QR scan failed';
    console.error('[QR Scan JS]', msg);
    return NextResponse.json({ detail: `QR scan error: ${msg}` }, { status: 500 });
  }
}

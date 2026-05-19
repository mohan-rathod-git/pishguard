/**
 * PhishGuard AI — Pure-JS URL Threat Scanner
 * Works 100% on Netlify — no Python backend required.
 * Uses structural URL heuristics to detect phishing, scams, and malware.
 */
import { NextRequest, NextResponse } from 'next/server';

export const runtime = 'nodejs';

// Known-safe root domains — immediate SAFE verdict
const SAFE_DOMAINS = new Set([
  'google.com','youtube.com','github.com','microsoft.com','apple.com',
  'amazon.com','facebook.com','twitter.com','x.com','instagram.com',
  'linkedin.com','netflix.com','cloudflare.com','netlify.app','vercel.app',
  'wikipedia.org','stackoverflow.com','reddit.com','yahoo.com','bing.com',
  'openai.com','stripe.com','shopify.com','wordpress.com','medium.com',
]);

// URL shorteners that hide the real destination
const SHORTENERS = new Set([
  'bit.ly','tinyurl.com','t.co','goo.gl','rb.gy','t.ly',
  'cutt.ly','ow.ly','is.gd','shorturl.at','v.gd','buff.ly',
]);

// High-risk TLDs
const RISKY_TLDS = new Set([
  '.ru','.cn','.tk','.ml','.ga','.cf','.gq','.xyz','.top',
  '.click','.online','.site','.website','.info','.biz','.pw',
]);

function analyzeUrl(rawUrl: string) {
  const start = Date.now();
  const reasons: string[] = [];
  let risk = 0;

  const urlStr = rawUrl.trim();
  const parseStr = /^https?:\/\//i.test(urlStr) ? urlStr : `http://${urlStr}`;

  let parsed: URL;
  try { parsed = new URL(parseStr); }
  catch {
    return { url: rawUrl, prediction: 'PHISHING', confidence: 0.85, risk_score: 85, reasons: ['Invalid or malformed URL'], processing_time_ms: Date.now() - start };
  }

  const hostname = parsed.hostname.toLowerCase();
  const domainParts = hostname.split('.');
  const rootDomain = domainParts.slice(-2).join('.');
  const tld = '.' + domainParts[domainParts.length - 1];
  const path = parsed.pathname.toLowerCase();
  const fullLower = urlStr.toLowerCase();

  // Instant SAFE for well-known trusted domains
  if (SAFE_DOMAINS.has(rootDomain)) {
    return { url: rawUrl, prediction: 'SAFE', confidence: 0.97, risk_score: 5, reasons: ['Domain is a well-known trusted service'], processing_time_ms: Date.now() - start };
  }

  // ── High-risk signals ───────────────────────────────────────────────────
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    risk += 45; reasons.push('IP address used as domain (phishing pattern)');
  }
  if (rawUrl.includes('@')) {
    risk += 40; reasons.push('@ symbol in URL (credential theft trick)');
  }
  if (hostname.includes('xn--')) {
    risk += 35; reasons.push('Punycode/IDN domain — possible homograph attack');
  }
  if (SHORTENERS.has(hostname)) {
    risk += 30; reasons.push('URL shortener hides true destination');
  }
  if (RISKY_TLDS.has(tld)) {
    risk += 18; reasons.push(`High-risk top-level domain: ${tld}`);
  }

  // ── Subdomain abuse ─────────────────────────────────────────────────────
  const subCount = domainParts.length - 2;
  if (subCount > 3) { risk += 22; reasons.push(`Excessive subdomains (${subCount}) — phishing tactic`); }
  else if (subCount > 1) { risk += 8; }

  // ── Brand impersonation ─────────────────────────────────────────────────
  const BRANDS = ['paypal','amazon','apple','google','microsoft','facebook',
    'instagram','netflix','ebay','adobe','dropbox','outlook','office365',
    'hdfc','sbi','icici','phonepe','paytm','gpay','upi'];
  const brandHits = BRANDS.filter(b => hostname.includes(b) && rootDomain !== `${b}.com` && rootDomain !== `${b}.in`);
  if (brandHits.length > 0) {
    risk += Math.min(brandHits.length * 18, 40);
    reasons.push(`Brand impersonation in domain: ${brandHits.join(', ')}`);
  }

  // ── Credential harvesting ────────────────────────────────────────────────
  const CRED_PATHS = ['login','signin','sign-in','auth','verify','validate','confirm','account','secure','update','password'];
  const credHits = CRED_PATHS.filter(p => path.includes(p));
  if (credHits.length > 0 && brandHits.length > 0) {
    risk += 25; reasons.push(`Credential harvesting page: /${credHits[0]}`);
  }

  // ── Fake payment / UPI fraud ─────────────────────────────────────────────
  const PAY_TERMS = ['upi','gpay','phonepe','paytm','cashback','refund','kyc','aadhar'];
  const payHits = PAY_TERMS.filter(t => fullLower.includes(t));
  if (payHits.length >= 2) {
    risk += 30; reasons.push(`Fake payment redirect pattern: ${payHits.join(', ')}`);
  }

  // ── Malicious downloads ──────────────────────────────────────────────────
  const MAL = ['.exe','.apk','.bat','.cmd','.ps1','.vbs','malware','ransom','exploit'];
  const malHits = MAL.filter(p => path.includes(p));
  if (malHits.length > 0) {
    risk += 30; reasons.push(`Malicious download indicator: ${malHits.join(', ')}`);
  }

  // ── Structural signals ───────────────────────────────────────────────────
  if (rawUrl.length > 200) { risk += 12; reasons.push('Extremely long URL (obfuscation)'); }
  else if (rawUrl.length > 120) { risk += 5; }

  if (parsed.protocol === 'http:' && subCount > 0) {
    risk += 8; reasons.push('Unencrypted HTTP with suspicious structure');
  }

  const hexCount = (rawUrl.match(/%[0-9a-fA-F]{2}/g) || []).length;
  if (hexCount > 8) { risk += 12; reasons.push(`Heavy URL encoding (${hexCount} chars)`); }

  if (parsed.port && !['80','443','8080','8443',''].includes(parsed.port)) {
    risk += 10; reasons.push(`Non-standard port: ${parsed.port}`);
  }
  if (path.includes('//')) { risk += 8; reasons.push('Double-slash redirect pattern'); }

  risk = Math.max(0, Math.min(100, risk));

  let prediction = 'SAFE';
  if (risk >= 70) prediction = 'PHISHING';
  else if (risk >= 52) prediction = 'SCAM';
  else if (risk >= 30) prediction = 'SUSPICIOUS';
  else if (risk >= 15) prediction = 'SPAM';

  if (reasons.length === 0) reasons.push('No significant threat indicators detected');

  return {
    url: rawUrl,
    prediction,
    confidence: parseFloat(Math.min(0.99, 0.5 + risk / 180).toFixed(4)),
    risk_score: risk,
    reasons,
    processing_time_ms: Date.now() - start,
  };
}

export async function POST(req: NextRequest) {
  try {
    const { url } = await req.json();
    if (!url || typeof url !== 'string') {
      return NextResponse.json({ detail: 'url is required' }, { status: 400 });
    }
    return NextResponse.json(analyzeUrl(url.trim()));
  } catch {
    return NextResponse.json({ detail: 'Invalid JSON body' }, { status: 400 });
  }
}

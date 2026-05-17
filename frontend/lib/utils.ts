import { ThreatLevel } from '@/types';

export function getRiskColor(score: number): string {
  if (score >= 75) return '#ef4444';
  if (score >= 50) return '#f97316';
  if (score >= 25) return '#eab308';
  return '#10b981';
}

export function getRiskLabel(score: number): string {
  if (score >= 75) return 'CRITICAL';
  if (score >= 50) return 'HIGH';
  if (score >= 25) return 'MEDIUM';
  return 'SAFE';
}

export function getThreatColor(level: ThreatLevel | null | string): string {
  switch (level) {
    case 'PHISHING': return '#ef4444';
    case 'MALWARE': return '#dc2626';
    case 'SCAM': return '#f97316';
    case 'SPAM': return '#eab308';
    case 'SAFE': return '#10b981';
    default: return '#64748b';
  }
}

export function getThreatBg(level: ThreatLevel | null | string): string {
  switch (level) {
    case 'PHISHING': return 'rgba(239,68,68,0.15)';
    case 'MALWARE': return 'rgba(220,38,38,0.15)';
    case 'SCAM': return 'rgba(249,115,22,0.15)';
    case 'SPAM': return 'rgba(234,179,8,0.15)';
    case 'SAFE': return 'rgba(16,185,129,0.15)';
    default: return 'rgba(100,116,139,0.15)';
  }
}

export function formatTimeAgo(date: Date): string {
  const seconds = Math.floor((Date.now() - date.getTime()) / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

export function truncateUrl(url: string, max = 50): string {
  if (url.length <= max) return url;
  return url.slice(0, max) + '…';
}

export function fileToBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.readAsDataURL(file);
    reader.onload = () => {
      const result = reader.result as string;
      // Strip the data:image/...;base64, prefix
      const base64 = result.split(',')[1];
      resolve(base64);
    };
    reader.onerror = reject;
  });
}

export function cn(...classes: (string | undefined | null | boolean)[]): string {
  return classes.filter(Boolean).join(' ');
}

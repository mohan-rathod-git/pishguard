'use client';

import { motion } from 'framer-motion';
import Link from 'next/link';
import { formatTimeAgo, getThreatColor, truncateUrl } from '@/lib/utils';
import { ScanHistoryItem } from '@/types';
import { Globe, QrCode, Shield, ExternalLink } from 'lucide-react';

interface HistoryTableProps {
  items: ScanHistoryItem[];
  compact?: boolean;
}

export default function HistoryTable({ items, compact = false }: HistoryTableProps) {
  if (items.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-center">
        <div className="w-16 h-16 rounded-2xl bg-cyber-surface/50 border border-cyber-border/50 flex items-center justify-center mb-4">
          <Shield className="w-8 h-8 text-cyber-muted" />
        </div>
        <p className="text-cyber-muted text-sm">No scans yet. Start scanning URLs or QR codes.</p>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="cyber-table">
        <thead>
          <tr>
            <th>Type</th>
            <th>Input</th>
            <th>Verdict</th>
            <th>Risk</th>
            {!compact && <th>Time</th>}
          </tr>
        </thead>
        <tbody>
          {items.map((item, i) => {
            const color = getThreatColor(item.prediction);
            return (
              <motion.tr
                key={item.id}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.04 }}
                className="group"
              >
                <td>
                  <div className="flex items-center gap-2">
                    <div
                      className="w-7 h-7 rounded-lg flex items-center justify-center"
                      style={{ background: `${color}15`, border: `1px solid ${color}30` }}
                    >
                      {item.type === 'url'
                        ? <Globe className="w-3.5 h-3.5" style={{ color }} />
                        : <QrCode className="w-3.5 h-3.5" style={{ color }} />}
                    </div>
                    {!compact && (
                      <span className="text-xs font-mono text-cyber-muted uppercase">
                        {item.type}
                      </span>
                    )}
                  </div>
                </td>
                <td>
                  <span className="font-mono text-xs" title={item.input}>
                    {truncateUrl(item.input, compact ? 30 : 50)}
                  </span>
                </td>
                <td>
                  <span
                    className="threat-badge"
                    style={{ background: `${color}15`, border: `1px solid ${color}30`, color }}
                  >
                    {item.prediction || 'UNKNOWN'}
                  </span>
                </td>
                <td>
                  <div className="flex items-center gap-2">
                    <div className="flex-1 h-1.5 bg-cyber-border/50 rounded-full overflow-hidden max-w-16">
                      <div
                        className="h-full rounded-full"
                        style={{
                          width: `${item.risk_score}%`,
                          background: color,
                        }}
                      />
                    </div>
                    <span className="text-xs font-mono font-bold" style={{ color }}>
                      {item.risk_score}
                    </span>
                  </div>
                </td>
                {!compact && (
                  <td className="text-xs text-cyber-muted">
                    {formatTimeAgo(item.timestamp)}
                  </td>
                )}
              </motion.tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

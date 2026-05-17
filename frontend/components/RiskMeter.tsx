'use client';

import { motion } from 'framer-motion';
import { getRiskColor, getRiskLabel } from '@/lib/utils';

interface RiskMeterProps {
  score: number;
  size?: 'sm' | 'md' | 'lg';
  showLabel?: boolean;
}

export default function RiskMeter({ score, size = 'md', showLabel = true }: RiskMeterProps) {
  const clampedScore = Math.max(0, Math.min(100, score));
  const color = getRiskColor(clampedScore);
  const label = getRiskLabel(clampedScore);

  const sizes = {
    sm: { r: 40, stroke: 6, fontSize: 'text-lg', labelSize: 'text-[10px]', wrapper: 'w-24 h-24' },
    md: { r: 56, stroke: 8, fontSize: 'text-2xl', labelSize: 'text-xs', wrapper: 'w-32 h-32' },
    lg: { r: 72, stroke: 10, fontSize: 'text-3xl', labelSize: 'text-sm', wrapper: 'w-44 h-44' },
  };

  const { r, stroke, fontSize, labelSize, wrapper } = sizes[size];
  const cx = r + stroke;
  const cy = r + stroke;
  const circumference = 2 * Math.PI * r;
  const dashOffset = circumference - (clampedScore / 100) * circumference;
  const svgSize = (r + stroke) * 2;

  return (
    <div className="flex flex-col items-center gap-3">
      <div className={`relative ${wrapper} flex items-center justify-center`}>
        <svg
          width={svgSize}
          height={svgSize}
          viewBox={`0 0 ${svgSize} ${svgSize}`}
          className="absolute inset-0 -rotate-90"
          style={{ width: '100%', height: '100%' }}
        >
          {/* Background track */}
          <circle
            cx={cx}
            cy={cy}
            r={r}
            fill="none"
            stroke="rgba(30,45,69,0.5)"
            strokeWidth={stroke}
          />
          {/* Progress arc */}
          <motion.circle
            cx={cx}
            cy={cy}
            r={r}
            fill="none"
            stroke={color}
            strokeWidth={stroke}
            strokeLinecap="round"
            strokeDasharray={circumference}
            initial={{ strokeDashoffset: circumference }}
            animate={{ strokeDashoffset: dashOffset }}
            transition={{ duration: 1.2, ease: 'easeOut' }}
            style={{ filter: `drop-shadow(0 0 8px ${color})` }}
          />
        </svg>

        {/* Center text */}
        <div className="relative z-10 text-center">
          <motion.div
            initial={{ opacity: 0, scale: 0.5 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.4, duration: 0.5 }}
            className={`font-black ${fontSize} leading-none`}
            style={{ color }}
          >
            {clampedScore}
          </motion.div>
          <div className={`font-mono ${labelSize} text-cyber-muted mt-0.5`}>/100</div>
        </div>
      </div>

      {showLabel && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.6 }}
          className="flex items-center gap-2"
        >
          <span
            className="w-2 h-2 rounded-full"
            style={{ backgroundColor: color, boxShadow: `0 0 8px ${color}` }}
          />
          <span
            className="font-mono font-bold tracking-widest text-xs"
            style={{ color }}
          >
            {label}
          </span>
        </motion.div>
      )}
    </div>
  );
}

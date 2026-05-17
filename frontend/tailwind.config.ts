import type { Config } from 'tailwindcss'

const config: Config = {
  content: [
    './pages/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
    './app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          black: '#030508',
          dark: '#080c14',
          surface: '#0d1220',
          card: '#111827',
          border: '#1e2d45',
          blue: '#4facfe',
          cyan: '#00f2fe',
          purple: '#a855f7',
          violet: '#7c3aed',
          green: '#10b981',
          red: '#ef4444',
          orange: '#f97316',
          muted: '#64748b',
          text: '#94a3b8',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
        display: ['Space Grotesk', 'Inter', 'system-ui', 'sans-serif'],
      },
      backgroundImage: {
        'gradient-cyber': 'linear-gradient(135deg, #4facfe 0%, #00f2fe 100%)',
        'gradient-purple': 'linear-gradient(135deg, #a855f7 0%, #7c3aed 100%)',
        'gradient-danger': 'linear-gradient(135deg, #ef4444 0%, #f97316 100%)',
        'gradient-safe': 'linear-gradient(135deg, #10b981 0%, #059669 100%)',
        'gradient-dark': 'linear-gradient(135deg, #080c14 0%, #0d1220 100%)',
        'grid-cyber': 'linear-gradient(rgba(79,172,254,0.05) 1px, transparent 1px), linear-gradient(90deg, rgba(79,172,254,0.05) 1px, transparent 1px)',
      },
      backgroundSize: {
        'grid': '60px 60px',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'spin-slow': 'spin 8s linear infinite',
        'ping-slow': 'ping 2s cubic-bezier(0, 0, 0.2, 1) infinite',
        'float': 'float 6s ease-in-out infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
        'scanline': 'scanline 2s linear infinite',
        'gradient-shift': 'gradient-shift 8s ease infinite',
        'fadeInUp': 'fadeInUp 0.6s ease-out both',
        'fadeInDown': 'fadeInDown 0.6s ease-out both',
      },
      keyframes: {
        float: {
          '0%, 100%': { transform: 'translateY(0px)' },
          '50%': { transform: 'translateY(-20px)' },
        },
        glow: {
          '0%': { boxShadow: '0 0 20px rgba(79,172,254,0.3)' },
          '100%': { boxShadow: '0 0 40px rgba(79,172,254,0.7)' },
        },
        scanline: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100%)' },
        },
        'gradient-shift': {
          '0%, 100%': { backgroundPosition: '0% 50%' },
          '50%': { backgroundPosition: '100% 50%' },
        },
        fadeInUp: {
          from: { opacity: '0', transform: 'translateY(20px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
        fadeInDown: {
          from: { opacity: '0', transform: 'translateY(-20px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
      },
      boxShadow: {
        'cyber': '0 0 30px rgba(79,172,254,0.3)',
        'cyber-lg': '0 0 60px rgba(79,172,254,0.4)',
        'danger': '0 0 30px rgba(239,68,68,0.3)',
        'safe': '0 0 30px rgba(16,185,129,0.3)',
        'purple': '0 0 30px rgba(168,85,247,0.3)',
        'glow-blue': '0 0 20px rgba(79,172,254,0.5), 0 0 60px rgba(79,172,254,0.2)',
        'glow-cyan': '0 0 20px rgba(0,242,254,0.5), 0 0 60px rgba(0,242,254,0.2)',
        'glow-red': '0 0 20px rgba(239,68,68,0.5), 0 0 60px rgba(239,68,68,0.2)',
        'glow-green': '0 0 20px rgba(16,185,129,0.5), 0 0 60px rgba(16,185,129,0.2)',
        'card': '0 4px 24px rgba(0,0,0,0.4)',
        'card-hover': '0 8px 48px rgba(0,0,0,0.6)',
      },
      borderRadius: {
        'xl2': '20px',
        'xl3': '24px',
      },
      backdropBlur: {
        'xs': '2px',
      },
    },
  },
  plugins: [],
}

export default config

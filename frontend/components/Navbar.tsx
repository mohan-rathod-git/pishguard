'use client';

import { motion } from 'framer-motion';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useState } from 'react';
import {
  Shield, Globe, QrCode, LayoutDashboard,
  Activity, History, Settings, BookOpen, Menu, X, Zap
} from 'lucide-react';

const navItems = [
  { label: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },
  { label: 'URL Scanner', href: '/scan', icon: Globe },
  { label: 'QR Scanner', href: '/qr', icon: QrCode },
  { label: 'Live Monitor', href: '/monitor', icon: Activity },
  { label: 'History', href: '/history', icon: History },
  { label: 'Analytics', href: '/analytics', icon: Zap },
  { label: 'API Docs', href: '/docs', icon: BookOpen },
  { label: 'Settings', href: '/settings', icon: Settings },
];

export default function Navbar() {
  const pathname = usePathname();
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <>
      <motion.nav
        initial={{ y: -80, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ duration: 0.5, ease: 'easeOut' }}
        className="fixed top-0 left-0 right-0 z-50"
      >
        <div
          className="mx-4 mt-4 rounded-2xl"
          style={{
            background: 'rgba(8, 12, 20, 0.85)',
            backdropFilter: 'blur(24px)',
            WebkitBackdropFilter: 'blur(24px)',
            border: '1px solid rgba(79,172,254,0.1)',
            boxShadow: '0 4px 40px rgba(0,0,0,0.5)',
          }}
        >
          <div className="flex items-center justify-between px-6 py-3">
            {/* Logo */}
            <Link href="/" className="flex items-center gap-2.5 group">
              <motion.div
                whileHover={{ scale: 1.05, rotate: 5 }}
                className="w-9 h-9 rounded-xl gradient-bg flex items-center justify-center shadow-glow-blue"
              >
                <Shield className="w-5 h-5 text-cyber-black" strokeWidth={2.5} />
              </motion.div>
              <div>
                <span className="font-bold text-sm text-white tracking-tight">PhishGuard</span>
                <span className="block text-[10px] text-cyber-muted font-mono tracking-wider">AI SECURITY</span>
              </div>
            </Link>

            {/* Desktop nav */}
            <div className="hidden lg:flex items-center gap-1">
              {navItems.map((item) => {
                const active = pathname === item.href;
                const Icon = item.icon;
                return (
                  <Link key={item.href} href={item.href}>
                    <motion.div
                      whileHover={{ scale: 1.02 }}
                      whileTap={{ scale: 0.98 }}
                      className={`flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-semibold transition-all duration-200 ${
                        active
                          ? 'gradient-bg text-cyber-black shadow-glow-blue'
                          : 'text-cyber-muted hover:text-white hover:bg-white/5'
                      }`}
                    >
                      <Icon className="w-3.5 h-3.5" />
                      {item.label}
                    </motion.div>
                  </Link>
                );
              })}
            </div>

            {/* Right side */}
            <div className="flex items-center gap-3">
              <div className="hidden sm:flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyber-green/10 border border-cyber-green/20">
                <span className="w-1.5 h-1.5 rounded-full bg-cyber-green animate-pulse-slow" />
                <span className="text-xs font-semibold text-cyber-green">LIVE</span>
              </div>

              <Link href="/scan">
                <motion.button
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                  className="hidden sm:flex cyber-btn cyber-btn-primary text-xs px-4 py-2"
                >
                  <Zap className="w-3.5 h-3.5" />
                  Scan Now
                </motion.button>
              </Link>

              {/* Mobile menu toggle */}
              <motion.button
                whileTap={{ scale: 0.9 }}
                onClick={() => setMobileOpen(!mobileOpen)}
                className="lg:hidden w-9 h-9 flex items-center justify-center rounded-xl bg-white/5 text-cyber-text"
              >
                {mobileOpen ? <X className="w-4 h-4" /> : <Menu className="w-4 h-4" />}
              </motion.button>
            </div>
          </div>
        </div>

        {/* Mobile menu */}
        {mobileOpen && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="lg:hidden mx-4 mt-2 rounded-2xl p-4 space-y-1"
            style={{
              background: 'rgba(8,12,20,0.95)',
              backdropFilter: 'blur(24px)',
              border: '1px solid rgba(79,172,254,0.1)',
            }}
          >
            {navItems.map((item) => {
              const active = pathname === item.href;
              const Icon = item.icon;
              return (
                <Link key={item.href} href={item.href} onClick={() => setMobileOpen(false)}>
                  <div className={`flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-semibold transition-all ${
                    active ? 'gradient-bg text-cyber-black' : 'text-cyber-text hover:text-white hover:bg-white/5'
                  }`}>
                    <Icon className="w-4 h-4" />
                    {item.label}
                  </div>
                </Link>
              );
            })}
          </motion.div>
        )}
      </motion.nav>

      {/* Spacer */}
      <div className="h-24" />
    </>
  );
}

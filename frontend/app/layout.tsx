import type { Metadata } from 'next';
import '../styles/globals.css';
import { Toaster } from 'react-hot-toast';

export const metadata: Metadata = {
  title: 'PhishGuard AI — AI-Powered Cybersecurity Platform',
  description: 'Detect malicious URLs, phishing websites, scam links, malware domains, and dangerous QR codes with PhishGuard AI — the next-generation cybersecurity platform.',
  keywords: 'phishing detection, malware detection, URL scanner, QR code security, cybersecurity AI',
  openGraph: {
    title: 'PhishGuard AI',
    description: 'AI-Powered Cyber Defense for the Modern Internet',
    type: 'website',
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=Space+Grotesk:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className="bg-cyber-black text-white antialiased overflow-x-hidden">
        {children}
        <Toaster
          position="top-right"
          toastOptions={{
            style: {
              background: '#0d1220',
              color: '#e2e8f0',
              border: '1px solid rgba(79,172,254,0.2)',
              borderRadius: '12px',
              fontSize: '0.875rem',
            },
            success: {
              iconTheme: { primary: '#10b981', secondary: '#030508' },
            },
            error: {
              iconTheme: { primary: '#ef4444', secondary: '#030508' },
            },
          }}
        />
      </body>
    </html>
  );
}

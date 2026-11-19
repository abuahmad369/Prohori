import type { Metadata } from 'next';
import Link from 'next/link';
import type { ReactNode } from 'react';
import { SiteHeader } from '@/components/site-header';
import './globals.css';

export const metadata: Metadata = {
  title: { default: 'Prohori: the trust layer for AI-built software', template: '%s · Prohori' },
  description: 'Scan, certify and sell apps built with AI. Prohori checks for the mistakes behind 2026’s breaches of AI-built apps.',
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <SiteHeader />
        <main className="container">{children}</main>
        <footer className="footer">
          <div className="container row spread">
            <span>Prohori (working name) · built in Bangladesh · Phase 0 preview</span>
            <span>
              Automated checks, not a guarantee. <Link href="/scan">Scan an app</Link>
            </span>
          </div>
        </footer>
      </body>
    </html>
  );
}

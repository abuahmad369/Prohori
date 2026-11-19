import Link from 'next/link';

export function Logo({ size = 26 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
      <path d="M16 2 4 6.5v8.2C4 22.3 9.1 28.2 16 30c6.9-1.8 12-7.7 12-15.3V6.5L16 2Z" fill="var(--brand)" />
      <path d="m10.5 16.2 3.8 3.8 7.4-7.6" fill="none" stroke="var(--brand-ink)" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function SiteHeader() {
  return (
    <header className="site-header">
      <div className="container">
        <Link href="/" className="logo">
          <Logo />
          Prohori
        </Link>
        <nav className="nav" aria-label="Main">
          <Link href="/scan">Scan an app</Link>
          <Link href="/marketplace">Marketplace</Link>
          <Link href="/sell">Sell</Link>
          <Link href="/dashboard">Dashboard</Link>
        </nav>
      </div>
    </header>
  );
}

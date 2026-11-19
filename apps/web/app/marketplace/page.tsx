import type { Metadata } from 'next';
import Link from 'next/link';
import { CATEGORIES } from '@/lib/constants';
import { publishedListings } from '@/lib/listings';
import { formatMoney } from '@/lib/money';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Marketplace' };

export default async function MarketplacePage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const params = await searchParams;
  const requested = typeof params.category === 'string' ? params.category : undefined;
  const category = requested && (CATEGORIES as readonly string[]).includes(requested) ? requested : undefined;
  const listings = await publishedListings(category);

  return (
    <>
      <p className="eyebrow">Verified apps only</p>
      <h1>Marketplace</h1>
      <p className="lead">
        Every app here passed Prohori’s checks: a score of at least 75 and no critical finding. Each listing links to its full report, so you
        can see exactly what was checked.
      </p>

      <nav className="row" aria-label="Categories" style={{ marginTop: 20 }}>
        <Link className={category ? 'pill sev-info' : 'pill ok'} href="/marketplace">
          All
        </Link>
        {CATEGORIES.map((c) => (
          <Link key={c} className={c === category ? 'pill ok' : 'pill sev-info'} href={`/marketplace?category=${encodeURIComponent(c)}`}>
            {c}
          </Link>
        ))}
      </nav>

      {listings.length === 0 ? (
        <div className="card" style={{ marginTop: 24 }}>
          No verified apps in this category yet. <Link href="/sell">List yours</Link>.
        </div>
      ) : (
        <div className="grid grid-3" style={{ marginTop: 24 }}>
          {listings.map((l) => (
            <Link key={l.id} href={`/marketplace/${l.slug}`} className="card listing-card">
              <div className="row spread">
                <span className="tag">{l.category}</span>
                {l.demo ? <span className="tag">Demo listing</span> : null}
              </div>
              <h3 style={{ margin: 0 }}>{l.title}</h3>
              <p className="muted small" style={{ margin: 0 }}>
                {l.tagline}
              </p>
              <div className="row spread" style={{ marginTop: 'auto' }}>
                <span className="price">{formatMoney(l.priceBdtMinor, 'BDT')}</span>
                <span className="pill ok">
                  Score {l.score} · {l.grade}
                </span>
              </div>
              <span className="small muted">
                {formatMoney(l.priceUsdMinor, 'USD')} international · by {l.builderName}
              </span>
            </Link>
          ))}
        </div>
      )}
    </>
  );
}

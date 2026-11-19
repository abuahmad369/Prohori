import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ScoreBadge, VerifiedPill } from '@/components/score-badge';
import { isSlug } from '@/lib/ids';
import { findListing } from '@/lib/listings';
import { formatMoney } from '@/lib/money';
import { getReport } from '@/lib/store';
import { BuyForm } from './buy-form';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'App details' };

export default async function ListingPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const listing = isSlug(slug) ? await findListing(slug) : null;
  if (!listing) notFound();
  const report = (await getReport(listing.scanId))?.report;
  const verifiedOn = new Date(listing.verifiedAt).toLocaleDateString('en-GB', { dateStyle: 'medium' });

  return (
    <div className="grid grid-2" style={{ alignItems: 'start' }}>
      <div className="stack">
        <Link href="/marketplace" className="small">
          Back to all apps
        </Link>
        <div className="row">
          <span className="tag">{listing.category}</span>
          {listing.demo ? <span className="tag">Demo listing</span> : null}
        </div>
        <h1 style={{ marginBottom: 0 }}>{listing.title}</h1>
        <p className="lead">{listing.tagline}</p>
        <p>{listing.description}</p>
        <p className="small muted">
          Stack: {listing.stacks.join(', ') || 'not detected'} · Builder: {listing.builderName}
        </p>

        <div className="card row">
          <ScoreBadge score={listing.score} grade={listing.grade} verified size={96} />
          <div style={{ flex: '1 1 220px' }}>
            <VerifiedPill verified />
            <p className="small muted" style={{ margin: '8px 0' }}>
              Passed Prohori’s automated checks on {verifiedOn}
              {report ? `, with ${report.counts.high} high, ${report.counts.medium} medium and ${report.counts.low} low findings` : ''}.
            </p>
            <Link href={`/reports/${listing.scanId}`}>Read the full report</Link>
          </div>
        </div>

        <div className="card small">
          <h3>What you get</h3>
          <ul>
            <li>Full source code and a setup guide</li>
            <li>A licence for one business brand, with a licence key</li>
            <li>12 months of updates from the builder</li>
            <li>30 days of support through Prohori</li>
          </ul>
          <p className="muted" style={{ margin: 0 }}>
            Preview: payments are simulated and no source code is delivered yet.
          </p>
        </div>
      </div>

      <div className="card">
        <h2>Buy</h2>
        <p className="price" style={{ marginBottom: 16 }}>
          {formatMoney(listing.priceBdtMinor, 'BDT')} <span className="muted small">or {formatMoney(listing.priceUsdMinor, 'USD')} international</span>
        </p>
        <BuyForm slug={listing.slug} priceBdt={formatMoney(listing.priceBdtMinor, 'BDT')} priceUsd={formatMoney(listing.priceUsdMinor, 'USD')} />
      </div>
    </div>
  );
}

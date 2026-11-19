import type { Metadata } from 'next';
import { isId } from '@/lib/ids';
import { getReport } from '@/lib/store';
import { SellForm, type ScanSummary } from './sell-form';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Sell your app' };

export default async function SellPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const params = await searchParams;
  const scanId = typeof params.scan === 'string' && isId(params.scan) ? params.scan : '';
  const stored = scanId ? await getReport(scanId) : null;
  const summary: ScanSummary | null = stored
    ? { id: scanId, name: stored.report.project.name, score: stored.report.score, grade: stored.report.grade, verified: stored.report.verified }
    : null;

  return (
    <div className="grid grid-2" style={{ alignItems: 'start' }}>
      <div>
        <p className="eyebrow">For builders</p>
        <h1>Sell your app</h1>
        <p className="lead">List an AI-built app. It goes live only if it passes the scan: a score of at least 75 and no critical finding.</p>
        <ul className="muted small">
          <li>Commission starts at 30% and drops to 25%, 20% and 15% as your lifetime sales pass $5,000, $25,000 and $100,000.</li>
          <li>Prices in taka for Bangladeshi buyers and in dollars for everyone else.</li>
          <li>Planned: weekly payouts by bKash, Nagad or bank, with no minimum.</li>
          <li>Your listing links to the public report, so buyers see exactly what was checked.</li>
        </ul>
      </div>
      <div className="card">
        <SellForm scan={summary} />
      </div>
    </div>
  );
}

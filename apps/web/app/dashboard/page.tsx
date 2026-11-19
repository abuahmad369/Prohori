import type { Metadata } from 'next';
import Link from 'next/link';
import type { Currency } from '@/lib/constants';
import { ensureSeeded } from '@/lib/listings';
import { formatMoney } from '@/lib/money';
import { balances } from '@/lib/orders';
import { readDb } from '@/lib/store';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Dashboard' };

const CURRENCIES: Currency[] = ['BDT', 'USD'];

function sumBy<T>(items: T[], currency: Currency, pick: (item: T) => { currency: Currency; amount: number }): number {
  return items.reduce((sum, item) => {
    const { currency: c, amount } = pick(item);
    return c === currency ? sum + amount : sum;
  }, 0);
}

const money = (byCurrency: Record<Currency, number>): string =>
  CURRENCIES.filter((c) => byCurrency[c] !== 0)
    .map((c) => formatMoney(byCurrency[c], c))
    .join(' + ') || formatMoney(0, 'BDT');

export default async function DashboardPage() {
  await ensureSeeded();
  const db = await readDb();
  const paid = db.orders.filter((o) => o.status === 'paid');
  const ledger = balances(db.ledger);
  const gmv = { BDT: sumBy(paid, 'BDT', (o) => ({ currency: o.currency, amount: o.amountMinor })), USD: sumBy(paid, 'USD', (o) => ({ currency: o.currency, amount: o.amountMinor })) };
  const revenue = {
    BDT: ledger.find((b) => b.account === 'platform_revenue' && b.currency === 'BDT')?.balanceMinor ?? 0,
    USD: ledger.find((b) => b.account === 'platform_revenue' && b.currency === 'USD')?.balanceMinor ?? 0,
  };
  const builderNames = new Map(db.listings.map((l) => [l.builderId, l.builderName]));
  const payables = ledger.filter((b) => b.account.startsWith('builder_payable:'));
  const verified = db.scans.filter((s) => s.verified).length;

  return (
    <div className="stack">
      <p className="notice small" style={{ margin: 0 }}>
        Local operator view with no sign-in. Add accounts and roles before deploying anywhere (see progress.md).
      </p>
      <h1>Dashboard</h1>

      <div className="stats">
        <div className="card stat">
          <strong>{db.scans.length}</strong>
          <span className="muted small">scans, {db.scans.length ? Math.round((verified / db.scans.length) * 100) : 0}% verified</span>
        </div>
        <div className="card stat">
          <strong>{db.listings.length}</strong>
          <span className="muted small">verified listings</span>
        </div>
        <div className="card stat">
          <strong>{paid.length}</strong>
          <span className="muted small">paid orders, {money(gmv)} in sales</span>
        </div>
        <div className="card stat">
          <strong>{money(revenue)}</strong>
          <span className="muted small">platform commission earned</span>
        </div>
      </div>

      <div className="card">
        <h2>Owed to builders</h2>
        {payables.length === 0 ? (
          <p className="muted small">No sales yet. Buy a demo app in the marketplace to see the ledger at work.</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Builder</th>
                  <th className="num">Balance</th>
                </tr>
              </thead>
              <tbody>
                {payables.map((b) => {
                  const builderId = b.account.slice('builder_payable:'.length);
                  return (
                    <tr key={b.account + b.currency}>
                      <td>{builderNames.get(builderId) ?? builderId}</td>
                      <td className="num">{formatMoney(b.balanceMinor, b.currency)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="card">
        <h2>Recent orders</h2>
        {db.orders.length === 0 ? (
          <p className="muted small">No orders yet.</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Order</th>
                  <th>App</th>
                  <th>Status</th>
                  <th className="num">Amount</th>
                </tr>
              </thead>
              <tbody>
                {db.orders.slice(0, 10).map((o) => (
                  <tr key={o.id}>
                    <td>
                      <Link href={`/orders/${o.id}`} className="mono">
                        {o.id}
                      </Link>
                    </td>
                    <td>{o.title}</td>
                    <td>{o.status}</td>
                    <td className="num">{formatMoney(o.amountMinor, o.currency)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="card">
        <h2>Recent scans</h2>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Project</th>
                <th>Source</th>
                <th className="num">Score</th>
                <th>Result</th>
              </tr>
            </thead>
            <tbody>
              {db.scans.slice(0, 15).map((s) => (
                <tr key={s.id}>
                  <td>
                    <Link href={`/reports/${s.id}`}>{s.projectName}</Link>
                  </td>
                  <td className="small muted">{s.label}</td>
                  <td className="num">
                    {s.score} ({s.grade})
                  </td>
                  <td>{s.verified ? <span className="pill ok">Verified</span> : <span className="pill bad">Not verified</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

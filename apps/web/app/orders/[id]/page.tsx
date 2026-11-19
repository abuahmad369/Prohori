import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { PAYMENT_METHODS } from '@/lib/constants';
import { isId } from '@/lib/ids';
import { formatMoney } from '@/lib/money';
import { getOrder } from '@/lib/orders';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Order' };

const HEADINGS = { paid: 'Payment received', pending: 'Waiting for payment', cancelled: 'Payment cancelled', failed: 'Payment failed' } as const;

export default async function OrderPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const order = isId(id) ? await getOrder(id) : null;
  if (!order) notFound();

  return (
    <div className="card stack" style={{ maxWidth: 640 }}>
      <p className="eyebrow" style={{ margin: 0 }}>
        Order {order.id}
      </p>
      <h1 style={{ margin: 0 }}>{HEADINGS[order.status]}</h1>
      <div className="table-wrap">
        <table>
          <tbody>
            <tr>
              <th scope="row">App</th>
              <td>
                <Link href={`/marketplace/${order.listingSlug}`}>{order.title}</Link>
              </td>
            </tr>
            <tr>
              <th scope="row">Amount</th>
              <td>{formatMoney(order.amountMinor, order.currency)}</td>
            </tr>
            <tr>
              <th scope="row">Method</th>
              <td>
                {PAYMENT_METHODS[order.method].label} ({order.provider === 'mock' ? 'simulated' : 'SSLCommerz'})
              </td>
            </tr>
            <tr>
              <th scope="row">Status</th>
              <td>
                <span className={order.status === 'paid' ? 'pill ok' : order.status === 'pending' ? 'pill sev-medium' : 'pill bad'}>{order.status}</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      {order.status === 'paid' && order.licenseKey ? (
        <>
          <div>
            <p className="small" style={{ fontWeight: 700, marginBottom: 6 }}>
              Your licence key
            </p>
            <div className="licence">{order.licenseKey}</div>
          </div>
          <p className="small muted" style={{ margin: 0 }}>
            In the live product, the source code download, licence certificate and setup guide appear here, and a copy goes to {order.buyerEmail}.
          </p>
        </>
      ) : null}
      {order.failureReason ? <p className="error small">{order.failureReason}</p> : null}

      <div className="row">
        <Link className="btn" href="/marketplace">
          Back to the marketplace
        </Link>
        {order.status !== 'paid' ? (
          <Link className="btn btn-primary" href={`/marketplace/${order.listingSlug}`}>
            Try again
          </Link>
        ) : null}
      </div>
    </div>
  );
}

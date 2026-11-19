import type { Metadata } from 'next';
import { notFound, redirect } from 'next/navigation';
import { PAYMENT_METHODS } from '@/lib/constants';
import { isId } from '@/lib/ids';
import { formatMoney } from '@/lib/money';
import { getOrder } from '@/lib/orders';
import { mockPaymentsEnabled } from '@/lib/payments/mock';
import { MockPay } from './mock-pay';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Payment' };

export default async function MockCheckoutPage({ params }: { params: Promise<{ orderId: string }> }) {
  const { orderId } = await params;
  const order = isId(orderId) ? await getOrder(orderId) : null;
  if (!order || order.provider !== 'mock' || !mockPaymentsEnabled()) notFound();
  if (order.status !== 'pending') redirect(`/orders/${order.id}`);
  const amount = formatMoney(order.amountMinor, order.currency);

  return (
    <div className="card stack" style={{ maxWidth: 540, marginInline: 'auto' }}>
      <p className="notice small" style={{ margin: 0 }}>
        Simulated payment gateway. No real money moves. Once SSLCommerz is configured, buyers see the real bKash, Nagad or card page here.
      </p>
      <h1 style={{ fontSize: '1.6rem', margin: 0 }}>Pay with {PAYMENT_METHODS[order.method].label}</h1>
      <div className="table-wrap">
        <table>
          <tbody>
            <tr>
              <th scope="row">App</th>
              <td>{order.title}</td>
            </tr>
            <tr>
              <th scope="row">Amount</th>
              <td className="price">{amount}</td>
            </tr>
            <tr>
              <th scope="row">Order</th>
              <td className="mono">{order.id}</td>
            </tr>
            <tr>
              <th scope="row">Receipt to</th>
              <td>{order.buyerEmail}</td>
            </tr>
          </tbody>
        </table>
      </div>
      <MockPay orderId={order.id} amount={amount} />
    </div>
  );
}

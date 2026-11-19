import { errorResponse, readJson, text, UserError } from '@/lib/errors';
import { isId } from '@/lib/ids';
import { getOrder, handleGatewayCallback } from '@/lib/orders';
import { mockPaymentsEnabled, signMockCallback, verifyMockSignature } from '@/lib/payments/mock';
import type { GatewayCallback } from '@/lib/payments/types';

export const runtime = 'nodejs';

// prohori-ignore access/route-without-auth: simulated gateway for local development; returns 404 in production unless ALLOW_MOCK_PAYMENTS=true
export async function POST(request: Request) {
  if (!mockPaymentsEnabled()) return Response.json({ error: 'Not found.' }, { status: 404 });
  try {
    const body = await readJson(request);
    const orderId = text(body, 'orderId', { max: 40 });
    const outcome = body.outcome === 'paid' ? 'paid' : 'cancelled';
    const order = isId(orderId) ? await getOrder(orderId) : null;
    if (!order || order.provider !== 'mock') throw new UserError('Order not found.', 404);
    // Like a real checkout session, a closed one cannot be paid or cancelled again.
    if (order.status !== 'pending') return Response.json({ status: order.status, redirect: `/orders/${order.id}` });

    // Play the gateway's part: sign the result with the shared secret, then send it through the
    // same verification path a real gateway notification takes.
    const callback: GatewayCallback = {
      orderId: order.id,
      providerRef: order.providerRef ?? `MOCK-${order.id}`,
      status: outcome,
      amountMinor: order.amountMinor,
      currency: order.currency,
    };
    const signature = signMockCallback(callback);
    const result = await handleGatewayCallback('mock', callback, verifyMockSignature(callback, signature));
    return Response.json({ status: result.order?.status ?? 'unknown', redirect: `/orders/${order.id}` });
  } catch (err) {
    return errorResponse(err);
  }
}

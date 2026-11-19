import { isId } from '@/lib/ids';
import { confirmSslcommerzPayment, sslcommerzConfigured } from '@/lib/payments/sslcommerz';

export const runtime = 'nodejs';

// prohori-ignore access/route-without-auth: SSLCommerz sends the buyer back here; the payment is confirmed with the validation API, never taken from the form
export async function POST(request: Request) {
  if (!sslcommerzConfigured()) return Response.json({ error: 'Not found.' }, { status: 404 });
  const form = await request.formData();
  const valId = String(form.get('val_id') ?? '');
  const tranId = String(form.get('tran_id') ?? '');
  let orderId = isId(tranId) ? tranId : undefined;
  if (/^[\w-]{4,100}$/.test(valId)) {
    const result = await confirmSslcommerzPayment(valId).catch(() => null);
    if (result?.orderId && isId(result.orderId)) orderId = result.orderId;
  }
  const origin = process.env.APP_URL ?? new URL(request.url).origin;
  return Response.redirect(`${origin}${orderId ? `/orders/${orderId}` : '/marketplace'}`, 303);
}

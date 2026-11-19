import { errorResponse } from '@/lib/errors';
import { confirmSslcommerzPayment, sslcommerzConfigured } from '@/lib/payments/sslcommerz';

export const runtime = 'nodejs';

// prohori-ignore access/route-without-auth: SSLCommerz payment notification; each one is confirmed with SSLCommerz's validation API before any order changes
export async function POST(request: Request) {
  if (!sslcommerzConfigured()) return Response.json({ error: 'Not found.' }, { status: 404 });
  try {
    const form = await request.formData();
    const valId = String(form.get('val_id') ?? '');
    if (!/^[\w-]{4,100}$/.test(valId)) return Response.json({ error: 'Missing val_id.' }, { status: 400 });
    const result = await confirmSslcommerzPayment(valId);
    return Response.json({ ok: result.ok });
  } catch (err) {
    return errorResponse(err);
  }
}

import { PAYMENT_METHODS, type PaymentMethod } from '@/lib/constants';
import { errorResponse, readJson, text, UserError } from '@/lib/errors';
import { isSlug } from '@/lib/ids';
import { findListing } from '@/lib/listings';
import { createOrder, setProviderRef } from '@/lib/orders';
import { providerFor } from '@/lib/payments';
import { mockPaymentsEnabled } from '@/lib/payments/mock';
import { clientIp, rateLimit, tooManyRequests } from '@/lib/rate-limit';

export const runtime = 'nodejs';

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// prohori-ignore access/route-without-auth: guest checkout; the price is read from the stored listing, never from the request, and requests are rate limited
export async function POST(request: Request) {
  const limit = rateLimit(`checkout:${clientIp(request)}`, 20);
  if (!limit.ok) return tooManyRequests(limit.retryAfter);
  try {
    const body = await readJson(request);
    const slug = text(body, 'listingSlug', { max: 80 });
    const email = text(body, 'email', { min: 5, max: 200 });
    if (!EMAIL_RE.test(email)) throw new UserError('Enter a valid email address.');
    if (typeof body.method !== 'string' || !Object.hasOwn(PAYMENT_METHODS, body.method)) throw new UserError('Choose a payment method.');
    const method = body.method as PaymentMethod;

    const listing = isSlug(slug) ? await findListing(slug) : null;
    if (!listing) throw new UserError('That app is not available.', 404);

    const provider = providerFor(method);
    if (provider.id === 'mock' && !mockPaymentsEnabled()) throw new UserError('Payments are not set up yet.', 503);

    const order = await createOrder(listing, method, email, provider.id);
    const origin = process.env.APP_URL ?? new URL(request.url).origin;
    const session = await provider.createCheckout(order, { origin });
    await setProviderRef(order.id, session.providerRef);
    return Response.json({ orderId: order.id, redirectUrl: session.redirectUrl }, { status: 201 });
  } catch (err) {
    return errorResponse(err, 'Checkout failed. Please try again.');
  }
}

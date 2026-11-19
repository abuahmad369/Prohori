import { PAYMENT_METHODS, type Currency, type PaymentMethod } from './constants';
import { licenseKey, newId } from './ids';
import { commissionRate, toUsdMinor } from './money';
import type { GatewayCallback, ProviderId } from './payments/types';
import { readDb, updateDb, type Db, type LedgerEntry, type Listing, type Order } from './store';

export async function createOrder(listing: Listing, method: PaymentMethod, buyerEmail: string, provider: ProviderId): Promise<Order> {
  const currency = PAYMENT_METHODS[method].currency;
  const order: Order = {
    id: newId(),
    listingId: listing.id,
    listingSlug: listing.slug,
    title: listing.title,
    builderId: listing.builderId,
    buyerEmail,
    method,
    provider,
    currency,
    amountMinor: currency === 'BDT' ? listing.priceBdtMinor : listing.priceUsdMinor,
    status: 'pending',
    createdAt: new Date().toISOString(),
  };
  await updateDb((db) => {
    db.orders.unshift(order);
  });
  return order;
}

export async function setProviderRef(orderId: string, providerRef: string): Promise<void> {
  await updateDb((db) => {
    const order = db.orders.find((o) => o.id === orderId);
    if (order && order.status === 'pending') order.providerRef = providerRef;
  });
}

export async function getOrder(id: string): Promise<Order | null> {
  return (await readDb()).orders.find((o) => o.id === id) ?? null;
}

function lifetimeUsdMinor(db: Db, builderId: string): number {
  return db.orders
    .filter((o) => o.builderId === builderId && o.status === 'paid')
    .reduce((sum, o) => sum + toUsdMinor(o.amountMinor, o.currency), 0);
}

/**
 * The only place an order becomes paid. Callers pass whether the gateway-specific check passed
 * (HMAC signature for the simulated gateway, validation API for SSLCommerz). Repeats are ignored.
 * A verified payment that arrives after a cancel or failure is still recorded: the buyer's money
 * has moved, so the order must deliver (or be refunded by an operator), never silently drop it.
 */
export async function handleGatewayCallback(
  provider: ProviderId,
  callback: GatewayCallback,
  verified: boolean,
): Promise<{ ok: boolean; order?: Order; reason?: string }> {
  if (!verified) return { ok: false, reason: 'The payment could not be verified with the gateway.' };
  return updateDb((db) => {
    const order = db.orders.find((o) => o.id === callback.orderId);
    if (!order) return { ok: false, reason: 'Unknown order.' };
    if (order.provider !== provider) return { ok: false, order, reason: 'The order belongs to a different gateway.' };
    if (order.status === 'paid') return { ok: true, order };
    if (callback.status !== 'paid') {
      if (order.status === 'pending') order.status = callback.status;
      return { ok: true, order };
    }
    if (callback.amountMinor !== order.amountMinor || callback.currency !== order.currency) {
      order.status = 'failed';
      order.failureReason = 'The paid amount or currency did not match the order.';
      return { ok: false, order, reason: order.failureReason };
    }

    const rate = commissionRate(lifetimeUsdMinor(db, order.builderId));
    const commission = Math.round(order.amountMinor * rate);
    const now = new Date().toISOString();
    order.status = 'paid';
    order.paidAt = now;
    order.providerRef = callback.providerRef;
    order.licenseKey = licenseKey();

    const entry = (account: string, debitMinor: number, creditMinor: number, memo: string): LedgerEntry => ({
      id: newId(),
      orderId: order.id,
      account,
      debitMinor,
      creditMinor,
      currency: order.currency,
      memo,
      createdAt: now,
    });
    db.ledger.push(
      entry('gateway_clearing', order.amountMinor, 0, `Payment for ${order.title} by ${PAYMENT_METHODS[order.method].label}`),
      entry(`builder_payable:${order.builderId}`, 0, order.amountMinor - commission, `Builder share (${Math.round((1 - rate) * 100)}%)`),
      entry('platform_revenue', 0, commission, `Commission (${Math.round(rate * 100)}%)`),
    );
    return { ok: true, order };
  });
}

export interface Balance {
  account: string;
  currency: Currency;
  balanceMinor: number;
}

/** Credit minus debit per account and currency. Gateway clearing is negative until the gateway pays out. */
export function balances(ledger: LedgerEntry[]): Balance[] {
  const map = new Map<string, Balance>();
  for (const e of ledger) {
    const key = `${e.account}|${e.currency}`;
    const b = map.get(key) ?? { account: e.account, currency: e.currency, balanceMinor: 0 };
    b.balanceMinor += e.creditMinor - e.debitMinor;
    map.set(key, b);
  }
  return [...map.values()].sort((a, b) => a.account.localeCompare(b.account));
}

// SSLCommerz: one integration for bKash, Nagad, Rocket and local cards.
// Written from SSLCommerz's documented session and validation APIs. Untested until sandbox credentials are added.
import { UserError } from '../errors';
import { handleGatewayCallback } from '../orders';
import type { Order } from '../store';
import type { GatewayCallback, PaymentProvider } from './types';

const sandbox = (): boolean => process.env.SSLCOMMERZ_SANDBOX !== 'false';
const baseUrl = (): string => (sandbox() ? 'https://sandbox.sslcommerz.com' : 'https://securepay.sslcommerz.com');

export function sslcommerzConfigured(): boolean {
  return Boolean(process.env.SSLCOMMERZ_STORE_ID && process.env.SSLCOMMERZ_STORE_PASSWORD);
}

function credentials(): { storeId: string; storePassword: string } {
  const storeId = process.env.SSLCOMMERZ_STORE_ID;
  const storePassword = process.env.SSLCOMMERZ_STORE_PASSWORD;
  if (!storeId || !storePassword) throw new Error('SSLCommerz is not configured');
  return { storeId, storePassword };
}

export const sslcommerzProvider: PaymentProvider = {
  id: 'sslcommerz',
  label: 'SSLCommerz (bKash, Nagad, cards)',
  async createCheckout(order: Order, { origin }) {
    const { storeId, storePassword } = credentials();
    const body = new URLSearchParams({
      store_id: storeId,
      store_passwd: storePassword,
      total_amount: (order.amountMinor / 100).toFixed(2),
      currency: order.currency,
      tran_id: order.id,
      success_url: `${origin}/api/payments/sslcommerz/return`,
      fail_url: `${origin}/api/payments/sslcommerz/return`,
      cancel_url: `${origin}/api/payments/sslcommerz/return`,
      ipn_url: `${origin}/api/payments/sslcommerz/ipn`,
      product_name: order.title,
      product_category: 'Software',
      product_profile: 'non-physical-goods',
      shipping_method: 'NO',
      cus_name: 'Prohori customer',
      cus_email: order.buyerEmail,
      cus_add1: 'Dhaka',
      cus_city: 'Dhaka',
      cus_country: 'Bangladesh',
      // TODO: collect the buyer's phone number at checkout; SSLCommerz requires one.
      cus_phone: '01700000000',
    });
    const response = await fetch(`${baseUrl()}/gwprocess/v4/api.php`, { method: 'POST', body, signal: AbortSignal.timeout(20_000) });
    const data = (await response.json().catch(() => ({}))) as { status?: string; GatewayPageURL?: string; sessionkey?: string; failedreason?: string };
    if (data.status !== 'SUCCESS' || !data.GatewayPageURL) {
      console.error('SSLCommerz session failed', data.failedreason);
      throw new UserError('The payment gateway is not available right now. Please try again.', 502);
    }
    return { redirectUrl: data.GatewayPageURL, providerRef: data.sessionkey ?? order.id };
  },
};

interface ValidationResponse {
  status?: string;
  tran_id?: string;
  val_id?: string;
  amount?: string;
  currency?: string;
  currency_type?: string;
  currency_amount?: string;
  bank_tran_id?: string;
}

/**
 * Never trust what the browser or the notification says. Ask SSLCommerz directly, then let
 * handleGatewayCallback check the amount and currency against the stored order.
 */
export async function confirmSslcommerzPayment(valId: string): Promise<{ ok: boolean; orderId?: string }> {
  const { storeId, storePassword } = credentials();
  const params = new URLSearchParams({ val_id: valId, store_id: storeId, store_passwd: storePassword, format: 'json' });
  const response = await fetch(`${baseUrl()}/validator/api/validationserverAPI.php?${params}`, { signal: AbortSignal.timeout(20_000) });
  const data = (await response.json().catch(() => ({}))) as ValidationResponse;
  const valid = data.status === 'VALID' || data.status === 'VALIDATED';
  if (!data.tran_id) return { ok: false };
  const currency = (data.currency_type ?? data.currency) === 'USD' ? 'USD' : 'BDT';
  const callback: GatewayCallback = {
    orderId: data.tran_id,
    providerRef: data.bank_tran_id ?? data.val_id ?? valId,
    status: valid ? 'paid' : 'failed',
    amountMinor: Math.round(Number.parseFloat(data.currency_amount ?? data.amount ?? '0') * 100),
    currency,
  };
  const result = await handleGatewayCallback('sslcommerz', callback, valid);
  return { ok: result.ok, orderId: data.tran_id };
}

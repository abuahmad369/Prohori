import type { Currency } from '../constants';
import type { Order } from '../store';

export type ProviderId = Order['provider'];

export interface CheckoutSession {
  redirectUrl: string;
  providerRef: string;
}

export interface PaymentProvider {
  id: ProviderId;
  label: string;
  createCheckout(order: Order, context: { origin: string }): Promise<CheckoutSession>;
}

/** What a gateway tells us about a payment. Only trusted after the provider-specific check passes. */
export interface GatewayCallback {
  orderId: string;
  providerRef: string;
  status: 'paid' | 'failed' | 'cancelled';
  amountMinor: number;
  currency: Currency;
}

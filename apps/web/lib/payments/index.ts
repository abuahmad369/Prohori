import type { PaymentMethod } from '../constants';
import { mockProvider } from './mock';
import { sslcommerzConfigured, sslcommerzProvider } from './sslcommerz';
import type { PaymentProvider } from './types';

/** Local methods go through SSLCommerz once it is configured. International cards wait for Paddle. */
export function providerFor(method: PaymentMethod): PaymentProvider {
  if (method !== 'international' && sslcommerzConfigured()) return sslcommerzProvider;
  return mockProvider;
}

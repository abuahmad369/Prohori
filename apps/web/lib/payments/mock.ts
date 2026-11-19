import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import type { GatewayCallback, PaymentProvider } from './types';

const globalMock = globalThis as typeof globalThis & { __prohoriMockSecret?: string };

function signingSecret(): string {
  globalMock.__prohoriMockSecret ??= process.env.MOCK_GATEWAY_SECRET || randomBytes(32).toString('hex');
  return globalMock.__prohoriMockSecret;
}

/** The simulated gateway only runs in development, unless explicitly allowed. */
export function mockPaymentsEnabled(): boolean {
  return process.env.NODE_ENV !== 'production' || process.env.ALLOW_MOCK_PAYMENTS === 'true';
}

const canonical = (c: GatewayCallback): string => [c.orderId, c.providerRef, c.status, c.amountMinor, c.currency].join('|');

export function signMockCallback(callback: GatewayCallback): string {
  return createHmac('sha256', signingSecret()).update(canonical(callback)).digest('hex');
}

export function verifyMockSignature(callback: GatewayCallback, signature: string): boolean {
  const expected = Buffer.from(signMockCallback(callback), 'hex');
  const given = Buffer.from(signature, 'hex');
  return given.length === expected.length && timingSafeEqual(expected, given);
}

export const mockProvider: PaymentProvider = {
  id: 'mock',
  label: 'Simulated gateway (no real money)',
  async createCheckout(order) {
    return { redirectUrl: `/checkout/mock/${order.id}`, providerRef: `MOCK-${order.id}` };
  },
};

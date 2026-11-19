import type { Currency } from './constants';

/** Planning exchange rate for commission tiers only. Check the real rate before going live. */
export const BDT_PER_USD = 122;

/** Amounts are stored as integers in minor units: paisa for BDT, cents for USD. */
export function formatMoney(minor: number, currency: Currency): string {
  const major = minor / 100;
  if (currency === 'BDT') return `৳${major.toLocaleString('en-IN', { maximumFractionDigits: 2 })}`;
  return `$${major.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
}

export function toUsdMinor(minor: number, currency: Currency): number {
  return currency === 'USD' ? minor : Math.round(minor / BDT_PER_USD);
}

/** Platform commission by the builder's lifetime sales: 30% to $5k, 25% to $25k, 20% to $100k, 15% above. */
export function commissionRate(lifetimeUsdMinor: number): number {
  if (lifetimeUsdMinor < 500_000) return 0.3;
  if (lifetimeUsdMinor < 2_500_000) return 0.25;
  if (lifetimeUsdMinor < 10_000_000) return 0.2;
  return 0.15;
}

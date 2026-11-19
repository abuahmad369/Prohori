// Shared by server and browser code. Keep Node-only imports out of this file.

export const CATEGORIES = ['Retail & POS', 'Healthcare', 'Education', 'Business tools', 'Hospitality', 'Finance'] as const;
export type Category = (typeof CATEGORIES)[number];

export type PaymentMethod = 'bkash' | 'nagad' | 'card' | 'international';
export type Currency = 'BDT' | 'USD';

export const PAYMENT_METHODS: Record<PaymentMethod, { label: string; currency: Currency; note: string }> = {
  bkash: { label: 'bKash', currency: 'BDT', note: 'Pay in taka from your bKash account.' },
  nagad: { label: 'Nagad', currency: 'BDT', note: 'Pay in taka from your Nagad account.' },
  card: { label: 'Bangladeshi card', currency: 'BDT', note: 'Visa, Mastercard or Amex issued in Bangladesh, charged in taka.' },
  international: { label: 'International card', currency: 'USD', note: 'Charged in US dollars. Paddle integration is planned; payments are simulated for now.' },
};

export const DEMO_SAMPLES = {
  vulnerable: 'QuickShop: a weekend AI-built store with typical mistakes',
  clean: 'Dokan POS: a well-built point-of-sale app',
} as const;
export type DemoSample = keyof typeof DEMO_SAMPLES;

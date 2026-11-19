'use client';

import { useState, type FormEvent } from 'react';
import { PAYMENT_METHODS, type PaymentMethod } from '@/lib/constants';

export function BuyForm({ slug, priceBdt, priceUsd }: { slug: string; priceBdt: string; priceUsd: string }) {
  const [method, setMethod] = useState<PaymentMethod>('bkash');
  const [email, setEmail] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const response = await fetch('/api/checkout', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ listingSlug: slug, method, email }),
      });
      const data = (await response.json().catch(() => ({}))) as { redirectUrl?: string; error?: string };
      if (!response.ok || !data.redirectUrl) {
        setError(data.error ?? 'Checkout failed. Please try again.');
        setBusy(false);
        return;
      }
      window.location.assign(data.redirectUrl);
    } catch {
      setError('Could not reach the server. Check your connection and try again.');
      setBusy(false);
    }
  }

  const price = PAYMENT_METHODS[method].currency === 'BDT' ? priceBdt : priceUsd;

  return (
    <form onSubmit={onSubmit}>
      <fieldset style={{ border: 0, padding: 0, margin: 0 }}>
        <legend className="small" style={{ fontWeight: 700, marginBottom: 8 }}>
          Payment method
        </legend>
        <div className="stack" style={{ marginTop: 0 }}>
          {(Object.keys(PAYMENT_METHODS) as PaymentMethod[]).map((m) => (
            <label key={m} className="method-option" htmlFor={`method-${m}`}>
              <input id={`method-${m}`} type="radio" name="method" value={m} checked={method === m} onChange={() => setMethod(m)} />
              <span>
                <strong>{PAYMENT_METHODS[m].label}</strong>
                <span className="small muted" style={{ display: 'block' }}>
                  {PAYMENT_METHODS[m].note}
                </span>
              </span>
            </label>
          ))}
        </div>
      </fieldset>

      <div className="field" style={{ marginTop: 16 }}>
        <label htmlFor="buyer-email">Email for the licence and receipt</label>
        <input id="buyer-email" type="email" autoComplete="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
      </div>

      <button type="submit" className="btn btn-primary" disabled={busy} style={{ marginTop: 18, width: '100%' }}>
        {busy ? 'Starting checkout…' : `Pay ${price}`}
      </button>
      {error ? (
        <p className="error small" role="alert" style={{ marginTop: 16 }}>
          {error}
        </p>
      ) : null}
    </form>
  );
}

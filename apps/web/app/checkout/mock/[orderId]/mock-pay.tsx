'use client';

import { useRouter } from 'next/navigation';
import { useState } from 'react';

export function MockPay({ orderId, amount }: { orderId: string; amount: string }) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function finish(outcome: 'paid' | 'cancelled') {
    setBusy(true);
    setError(null);
    try {
      const response = await fetch('/api/payments/mock/complete', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ orderId, outcome }),
      });
      const data = (await response.json().catch(() => ({}))) as { redirect?: string; error?: string };
      if (!response.ok || !data.redirect) {
        setError(data.error ?? 'The payment could not be completed.');
        setBusy(false);
        return;
      }
      router.push(data.redirect);
    } catch {
      setError('Could not reach the server. Check your connection and try again.');
      setBusy(false);
    }
  }

  return (
    <div className="stack">
      <div className="row">
        <button type="button" className="btn btn-primary" disabled={busy} onClick={() => void finish('paid')}>
          {busy ? 'Processing…' : `Pay ${amount} (simulated)`}
        </button>
        <button type="button" className="btn" disabled={busy} onClick={() => void finish('cancelled')}>
          Cancel
        </button>
      </div>
      {error ? (
        <p className="error small" role="alert">
          {error}
        </p>
      ) : null}
    </div>
  );
}

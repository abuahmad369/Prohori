'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useState, type FormEvent } from 'react';
import { CATEGORIES } from '@/lib/constants';

export interface ScanSummary {
  id: string;
  name: string;
  score: number;
  grade: string;
  verified: boolean;
}

type Source = 'scan' | 'github' | 'demo';

export function SellForm({ scan }: { scan: ScanSummary | null }) {
  const router = useRouter();
  const [source, setSource] = useState<Source>(scan?.verified ? 'scan' : 'github');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [rejected, setRejected] = useState<{ scanId: string; score: number; reasons: string[] } | null>(null);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const body = {
      title: form.get('title'),
      tagline: form.get('tagline'),
      description: form.get('description'),
      category: form.get('category'),
      priceBdt: Number(form.get('priceBdt')),
      priceUsd: Number(form.get('priceUsd')),
      builderName: form.get('builderName'),
      source,
      scanId: scan?.id,
      githubUrl: form.get('githubUrl'),
      demoSample: form.get('demoSample'),
    };
    setBusy(true);
    setError(null);
    setRejected(null);
    try {
      const response = await fetch('/api/listings', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
      const data = (await response.json().catch(() => ({}))) as { slug?: string; scanId?: string; score?: number; reasons?: string[]; error?: string };
      if (response.status === 201 && data.slug) {
        router.push(`/marketplace/${data.slug}`);
        return;
      }
      if (response.status === 422 && data.scanId) {
        setRejected({ scanId: data.scanId, score: data.score ?? 0, reasons: data.reasons ?? [] });
      } else {
        setError(data.error ?? 'Submitting the app failed. Please try again.');
      }
    } catch {
      setError('Could not reach the server. Check your connection and try again.');
    }
    setBusy(false);
  }

  return (
    <form onSubmit={onSubmit}>
      <fieldset style={{ border: 0, padding: 0, margin: 0 }}>
        <legend className="small" style={{ fontWeight: 700, marginBottom: 8 }}>
          What are you listing?
        </legend>
        <div className="stack" style={{ marginTop: 0 }}>
          {scan ? (
            <label className="method-option" htmlFor="source-scan">
              <input id="source-scan" type="radio" name="source" value="scan" checked={source === 'scan'} disabled={!scan.verified} onChange={() => setSource('scan')} />
              <span>
                <strong>The app you just scanned</strong>
                <span className="small muted" style={{ display: 'block' }}>
                  {scan.name}: score {scan.score} ({scan.grade}), {scan.verified ? 'verified' : 'not verified yet'}
                </span>
              </span>
            </label>
          ) : null}
          <label className="method-option" htmlFor="source-github">
            <input id="source-github" type="radio" name="source" value="github" checked={source === 'github'} onChange={() => setSource('github')} />
            <span>
              <strong>A public GitHub repository</strong>
              <span className="small muted" style={{ display: 'block' }}>
                We scan it now and publish only if it passes.
              </span>
            </span>
          </label>
          <label className="method-option" htmlFor="source-demo">
            <input id="source-demo" type="radio" name="source" value="demo" checked={source === 'demo'} onChange={() => setSource('demo')} />
            <span>
              <strong>A demo project</strong>
              <span className="small muted" style={{ display: 'block' }}>
                Try the flow with a sample app.
              </span>
            </span>
          </label>
        </div>
      </fieldset>

      {source === 'github' ? (
        <div className="field" style={{ marginTop: 16 }}>
          <label htmlFor="githubUrl">Repository</label>
          <input id="githubUrl" name="githubUrl" type="text" placeholder="github.com/owner/repo" required />
        </div>
      ) : null}
      {source === 'demo' ? (
        <div className="field" style={{ marginTop: 16 }}>
          <label htmlFor="demoSample">Demo project</label>
          <select id="demoSample" name="demoSample" defaultValue="clean">
            <option value="clean">Dokan POS (passes)</option>
            <option value="vulnerable">QuickShop (fails, to see a rejection)</option>
          </select>
        </div>
      ) : null}

      <div className="field" style={{ marginTop: 16 }}>
        <label htmlFor="title">App name</label>
        <input id="title" name="title" type="text" minLength={3} maxLength={80} required />
      </div>
      <div className="field">
        <label htmlFor="tagline">One-line description</label>
        <input id="tagline" name="tagline" type="text" minLength={10} maxLength={140} required />
      </div>
      <div className="field">
        <label htmlFor="description">What it does and who it is for</label>
        <textarea id="description" name="description" minLength={40} maxLength={4000} required />
      </div>
      <div className="field">
        <label htmlFor="category">Category</label>
        <select id="category" name="category" defaultValue={CATEGORIES[0]}>
          {CATEGORIES.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
      </div>
      <div className="grid grid-2" style={{ marginTop: 16 }}>
        <div>
          <label htmlFor="priceBdt">Price in taka</label>
          <input id="priceBdt" name="priceBdt" type="number" min={500} max={500000} step={1} defaultValue={3000} required />
        </div>
        <div>
          <label htmlFor="priceUsd">Price in US dollars</label>
          <input id="priceUsd" name="priceUsd" type="number" min={5} max={5000} step={1} defaultValue={29} required />
        </div>
      </div>
      <div className="field" style={{ marginTop: 16 }}>
        <label htmlFor="builderName">Your name or studio</label>
        <input id="builderName" name="builderName" type="text" minLength={2} maxLength={60} required />
      </div>

      <button type="submit" className="btn btn-primary" disabled={busy} style={{ marginTop: 18, width: '100%' }}>
        {busy ? 'Scanning and submitting…' : 'Scan and publish'}
      </button>

      {error ? (
        <p className="error small" role="alert" style={{ marginTop: 16 }}>
          {error}
        </p>
      ) : null}
      {rejected ? (
        <div className="error small" role="alert" style={{ marginTop: 16 }}>
          <strong>Not published: the app scored {rejected.score} and did not pass.</strong>
          <ul style={{ margin: '8px 0' }}>
            {rejected.reasons.map((r) => (
              <li key={r}>{r}</li>
            ))}
          </ul>
          <Link href={`/reports/${rejected.scanId}`}>See what to fix</Link>
        </div>
      ) : null}
    </form>
  );
}

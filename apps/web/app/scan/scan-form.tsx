'use client';

import { useRouter } from 'next/navigation';
import { useState, type FormEvent } from 'react';

type Mode = 'github' | 'upload' | 'demo';

const TABS: Array<{ id: Mode; label: string }> = [
  { id: 'github', label: 'GitHub link' },
  { id: 'upload', label: 'Upload a zip' },
  { id: 'demo', label: 'Try a demo' },
];

export function ScanForm() {
  const router = useRouter();
  const [mode, setMode] = useState<Mode>('github');
  const [url, setUrl] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function send(body: BodyInit, headers?: HeadersInit) {
    setBusy(true);
    setError(null);
    try {
      const response = await fetch('/api/scans', { method: 'POST', body, headers });
      const data = (await response.json().catch(() => ({}))) as { id?: string; error?: string };
      if (!response.ok || !data.id) {
        setError(data.error ?? 'The scan failed. Please try again.');
        setBusy(false);
        return;
      }
      router.push(`/reports/${data.id}`);
    } catch {
      setError('Could not reach the server. Check your connection and try again.');
      setBusy(false);
    }
  }

  function onSubmit(event: FormEvent) {
    event.preventDefault();
    if (mode === 'github') {
      if (!url.trim()) return setError('Paste a GitHub repository link first.');
      void send(JSON.stringify({ source: 'github', url }), { 'content-type': 'application/json' });
    } else if (mode === 'upload') {
      if (!file) return setError('Choose a .zip file first.');
      const form = new FormData();
      form.append('file', file);
      void send(form);
    }
  }

  const demo = (sample: 'vulnerable' | 'clean') => void send(JSON.stringify({ source: 'demo', sample }), { 'content-type': 'application/json' });

  return (
    <form onSubmit={onSubmit} aria-busy={busy}>
      <div className="tabs" role="tablist" aria-label="What to scan">
        {TABS.map((t) => (
          <button
            key={t.id}
            type="button"
            role="tab"
            className="tab"
            aria-selected={mode === t.id}
            onClick={() => {
              setMode(t.id);
              setError(null);
            }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {mode === 'github' ? (
        <div className="field">
          <label htmlFor="repo-url">Public GitHub repository</label>
          <input id="repo-url" name="url" type="text" inputMode="url" placeholder="github.com/owner/repo" value={url} onChange={(e) => setUrl(e.target.value)} />
          <p className="hint">The default branch is scanned. Lovable, Bolt and Replit projects can all sync to GitHub.</p>
        </div>
      ) : null}

      {mode === 'upload' ? (
        <div className="field">
          <label htmlFor="zip-file">Project as a .zip file</label>
          <input id="zip-file" name="file" type="file" accept=".zip,application/zip" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
          <p className="hint">Leave out node_modules and build folders; they are skipped anyway. Maximum 25 MB.</p>
        </div>
      ) : null}

      {mode === 'demo' ? (
        <div className="stack">
          <p className="small muted">No code of your own? Scan one of these sample projects to see what a report looks like.</p>
          <button type="button" className="btn" disabled={busy} onClick={() => demo('vulnerable')}>
            Scan QuickShop (unsafe on purpose)
          </button>
          <button type="button" className="btn" disabled={busy} onClick={() => demo('clean')}>
            Scan Dokan POS (well built)
          </button>
        </div>
      ) : (
        <button type="submit" className="btn btn-primary" disabled={busy} style={{ marginTop: 18, width: '100%' }}>
          {busy ? 'Scanning…' : 'Scan now'}
        </button>
      )}

      {busy && mode === 'demo' ? <p className="small muted">Scanning…</p> : null}
      {error ? (
        <p className="error small" role="alert" style={{ marginTop: 16 }}>
          {error}
        </p>
      ) : null}
    </form>
  );
}

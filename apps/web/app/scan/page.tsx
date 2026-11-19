import type { Metadata } from 'next';
import { ScanForm } from './scan-form';

export const metadata: Metadata = { title: 'Scan an app' };

export default function ScanPage() {
  return (
    <div className="grid grid-2" style={{ alignItems: 'start' }}>
      <div>
        <p className="eyebrow">Free scan</p>
        <h1>Scan an AI-built app</h1>
        <p className="lead">Get a score out of 100, every finding with a fix, and an SBOM, in a few seconds.</p>
        <ul className="muted small">
          <li>Your code is read in memory and never run.</li>
          <li>Only the findings are kept, with secrets masked. The source code is not stored.</li>
          <li>Public GitHub repositories and zip uploads up to 25 MB. Private repositories come with the GitHub App.</li>
          <li>Verified means a score of at least 75 and no critical finding.</li>
        </ul>
        <p className="small muted">
          Prefer the terminal? From this repository, run <code>pnpm scan path/to/project</code>.
        </p>
      </div>
      <div className="card">
        <ScanForm />
      </div>
    </div>
  );
}

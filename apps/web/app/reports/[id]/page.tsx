import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ReportView } from '@/components/report-view';
import { ScoreBadge, VerifiedPill } from '@/components/score-badge';
import { isId } from '@/lib/ids';
import { getReport, readDb } from '@/lib/store';

export const dynamic = 'force-dynamic';
export const metadata: Metadata = { title: 'Audit report' };

const SOURCE_LABEL = { github: 'GitHub', upload: 'Uploaded zip', demo: 'Demo project' } as const;

export default async function ReportPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const stored = isId(id) ? await getReport(id) : null;
  if (!stored) notFound();
  const { report } = stored;
  const record = (await readDb()).scans.find((s) => s.id === id);
  const scanned = new Date(report.scannedAt).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' });

  return (
    <div className="stack">
      <div className="row spread top">
        <div style={{ minWidth: 0, flex: '1 1 380px' }}>
          <p className="eyebrow">Audit report</p>
          <h1 style={{ overflowWrap: 'anywhere' }}>{report.project.name}</h1>
          <p className="muted small">
            {record ? `${SOURCE_LABEL[record.source]}: ${record.label} · ` : ''}scanned {scanned} · {report.project.files} {report.project.files === 1 ? 'file' : 'files'} ·{' '}
            {report.project.stacks.length ? report.project.stacks.join(', ') : 'no stack detected'}
            {report.project.truncated ? ' · large project, partly scanned' : ''}
          </p>
        </div>
        <ScoreBadge score={report.score} grade={report.grade} verified={report.verified} />
      </div>

      <div className={`card ${report.verified ? 'panel-ok' : 'panel-bad'}`}>
        <div className="row spread">
          <VerifiedPill verified={report.verified} />
          <span className="small muted">
            {report.counts.critical} critical · {report.counts.high} high · {report.counts.medium} medium · {report.counts.low} low
          </span>
        </div>
        <ul className="small" style={{ margin: '12px 0' }}>
          {report.gate.reasons.map((r) => (
            <li key={r}>{r}</li>
          ))}
        </ul>
        {report.verified ? (
          <Link className="btn btn-primary" href={`/sell?scan=${id}`}>
            List this app on the marketplace
          </Link>
        ) : (
          <p className="small" style={{ margin: 0 }}>
            {report.counts.critical > 0
              ? 'Fix the critical findings first, then scan again. '
              : report.score < report.gate.minScore
                ? 'Fix the high findings first, then scan again. '
                : 'Scan the full project, including its source code. '}
            Download the Markdown report and give it to your AI coding tool as a to-do list.
          </p>
        )}
      </div>

      <div className="row small">
        <span className="muted">Download:</span>
        <a href={`/api/scans/${id}?format=md`}>Markdown</a>
        <a href={`/api/scans/${id}?format=json`}>JSON</a>
        <a href={`/api/scans/${id}?format=sarif`}>SARIF (GitHub)</a>
        <a href={`/api/scans/${id}?format=sbom`}>SBOM (CycloneDX)</a>
      </div>

      <ReportView report={report} />

      <p className="small muted">
        Prohori runs automated checks. A pass means these checks found no critical problem on the date above; it is not a guarantee that
        the software is secure.
      </p>
    </div>
  );
}

import type { AuditReport, Finding, Severity } from '@prohori/audit-engine';

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const SEVERITY_LABEL: Record<Severity, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Suggestions' };

function barColor(score: number): string {
  if (score >= 80) return 'var(--ok)';
  if (score >= 60) return 'var(--medium)';
  return 'var(--high)';
}

function FindingItem({ finding }: { finding: Finding }) {
  return (
    <article className={`finding sev-${finding.severity}`}>
      <div className="row spread top">
        <strong className="text">{finding.title}</strong>
        <span className={`pill sev-${finding.severity}`}>{finding.severity}</span>
      </div>
      <p className="text small" style={{ marginTop: 6 }}>
        {finding.message}
      </p>
      {finding.file ? (
        <p className="small muted mono">
          {finding.file}
          {finding.line ? `:${finding.line}` : ''}
        </p>
      ) : null}
      {finding.snippet ? <div className="snippet">{finding.snippet}</div> : null}
      <details style={{ marginTop: 10 }}>
        <summary className="small text">How to fix</summary>
        <p className="small text" style={{ marginTop: 8 }}>
          {finding.remediation}
        </p>
        <p className="small muted">
          Rule <code>{finding.ruleId}</code>
          {finding.cwe ? ` · ${finding.cwe}` : ''} · confidence {finding.confidence}
        </p>
      </details>
    </article>
  );
}

export function ReportView({ report }: { report: AuditReport }) {
  return (
    <div className="stack">
      <div className="card">
        <h2>Six areas</h2>
        <div className="grid grid-2">
          {report.categories.map((c) => (
            <div key={c.id}>
              <div className="row spread small">
                <strong>{c.title}</strong>
                <span className="muted">
                  {c.score}/100 · {c.findings} finding{c.findings === 1 ? '' : 's'}
                </span>
              </div>
              <div className="bar" style={{ marginTop: 6 }}>
                <span style={{ width: `${c.score}%`, background: barColor(c.score) }} />
              </div>
            </div>
          ))}
        </div>
      </div>

      {report.findings.length === 0 ? (
        <div className="card">
          <h2>No findings</h2>
          <p className="muted">None of the checks found a problem in this project.</p>
        </div>
      ) : (
        SEVERITIES.map((severity) => {
          const list = report.findings.filter((f) => f.severity === severity);
          if (list.length === 0) return null;
          return (
            <section key={severity} style={{ marginBlock: 28 }} aria-labelledby={`sev-${severity}`}>
              <h2 id={`sev-${severity}`} className="row">
                {SEVERITY_LABEL[severity]} <span className={`pill sev-${severity}`}>{list.length}</span>
              </h2>
              <div className="stack">
                {list.map((f) => (
                  <FindingItem key={f.id} finding={f} />
                ))}
              </div>
            </section>
          );
        })
      )}

      {report.suppressed.length > 0 ? (
        <details className="card">
          <summary>
            {report.suppressed.length} suppressed finding{report.suppressed.length === 1 ? '' : 's'} (with reasons)
          </summary>
          <ul className="small" style={{ marginTop: 12 }}>
            {report.suppressed.map((f) => (
              <li key={f.id}>
                <code>{f.ruleId}</code> in {f.file ?? 'the project'}: {f.suppression?.reason}
              </li>
            ))}
          </ul>
        </details>
      ) : null}

      <div className="card small">
        <h3>Dependencies</h3>
        <p className="muted" style={{ marginBottom: 0 }}>
          {report.dependencies.total} packages ({report.dependencies.direct} direct)
          {report.dependencies.ecosystems.length ? ` from ${report.dependencies.ecosystems.join(', ')}` : ''}. Lockfiles:{' '}
          {report.dependencies.lockfiles.length ? report.dependencies.lockfiles.join(', ') : 'none'}. Known-vulnerability check:{' '}
          {report.dependencies.vulnerabilityCheck === 'online'
            ? `done, ${report.dependencies.vulnerable} vulnerable`
            : report.dependencies.vulnerabilityCheck === 'failed'
              ? 'could not reach OSV.dev'
              : 'not run'}
          .
        </p>
      </div>
    </div>
  );
}

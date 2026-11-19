import { SEVERITY_ORDER } from '../rules/helpers.ts';
import type { AuditReport, Severity } from '../types.ts';

const ANSI = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
} as const;

type Style = keyof typeof ANSI;

const SEVERITY_STYLE: Record<Severity, Style> = {
  critical: 'magenta',
  high: 'red',
  medium: 'yellow',
  low: 'blue',
  info: 'dim',
};

/** Human-readable terminal report. */
export function toText(report: AuditReport, options: { color?: boolean } = {}): string {
  const paint = (style: Style, text: string): string => (options.color ? `${ANSI[style]}${text}${ANSI.reset}` : text);
  const lines: string[] = [];

  lines.push(paint('bold', `Prohori audit: ${report.project.name}`));
  const verdict = report.verified ? paint('green', 'VERIFIED') : paint('red', 'NOT VERIFIED');
  lines.push(`Score ${paint('bold', `${report.score}/100`)} (grade ${report.grade})  ${verdict}`);
  const stacks = report.project.stacks.join(', ') || 'no stack detected';
  const truncated = report.project.truncated ? ' · truncated by size limits' : '';
  lines.push(paint('dim', `${report.project.files} files · ${stacks} · ${report.durationMs} ms${truncated}`));
  lines.push('');

  lines.push(paint('bold', 'Areas'));
  for (const c of report.categories) {
    const note = c.findings ? paint('dim', `${c.findings} finding(s)`) : '';
    lines.push(`  ${c.title.padEnd(22)} ${String(c.score).padStart(3)}  ${note}`.trimEnd());
  }
  lines.push('');

  const summary = SEVERITY_ORDER.filter((s) => report.counts[s] > 0)
    .map((s) => `${report.counts[s]} ${s}`)
    .join(', ');
  lines.push(paint('bold', report.findings.length ? `Findings (${summary})` : 'No findings'));
  for (const f of report.findings) {
    const where = f.file ? `${f.file}${f.line ? `:${f.line}` : ''}` : 'whole project';
    lines.push(`  ${paint(SEVERITY_STYLE[f.severity], f.severity.toUpperCase().padEnd(8))} ${f.title}  ${paint('dim', where)}`);
    lines.push(`           ${f.message}`);
    if (f.snippet) lines.push(paint('dim', `           > ${f.snippet}`));
    lines.push(paint('dim', `           Fix: ${f.remediation}`));
  }
  if (report.suppressed.length) {
    lines.push('');
    lines.push(paint('dim', `${report.suppressed.length} finding(s) suppressed with a reason (listed in the JSON and Markdown reports).`));
  }
  lines.push('');
  lines.push(paint('bold', 'Gate'));
  for (const r of report.gate.reasons) lines.push(`  ${r}`);
  if (report.errors.length) {
    lines.push('');
    lines.push(paint('yellow', `Rule errors (scan continued): ${report.errors.join('; ')}`));
  }
  return lines.join('\n');
}

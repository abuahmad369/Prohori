import { SEVERITY_ORDER } from '../rules/helpers.ts';
import type { AuditReport } from '../types.ts';

const capitalise = (s: string): string => s.charAt(0).toUpperCase() + s.slice(1);
const inlineCode = (s: string): string => `\`${s.replace(/`/g, "'")}\``;

/** Markdown report, for downloads, pull request comments and client hand-overs. */
export function toMarkdown(report: AuditReport): string {
  const lines: string[] = [];
  lines.push(`# Prohori audit report: ${report.project.name}`, '');
  lines.push(`**Score:** ${report.score}/100 (grade ${report.grade})  `);
  lines.push(`**Verified:** ${report.verified ? 'Yes' : 'No'}  `);
  lines.push(`**Scanned:** ${report.scannedAt} · ${report.project.files} files · engine ${report.engine.version}  `);
  lines.push(`**Stack:** ${report.project.stacks.join(', ') || 'not detected'}`, '');

  lines.push('## Gate', '', ...report.gate.reasons.map((r) => `- ${r}`), '');

  lines.push('## Areas', '', '| Area | Score | Findings |', '|---|---:|---:|');
  for (const c of report.categories) lines.push(`| ${c.title} | ${c.score} | ${c.findings} |`);
  lines.push('');

  lines.push('## Findings', '');
  if (report.findings.length === 0) lines.push('No findings.', '');
  for (const severity of SEVERITY_ORDER) {
    const list = report.findings.filter((f) => f.severity === severity);
    if (list.length === 0) continue;
    lines.push(`### ${capitalise(severity)} (${list.length})`, '');
    for (const f of list) {
      lines.push(`#### ${f.title}`, '');
      lines.push(`- **Where:** ${f.file ? inlineCode(`${f.file}${f.line ? `:${f.line}` : ''}`) : 'whole project'}`);
      lines.push(`- **What:** ${f.message}`);
      if (f.snippet) lines.push(`- **Code:** ${inlineCode(f.snippet)}`);
      lines.push(`- **Fix:** ${f.remediation}`);
      lines.push(`- **Rule:** ${inlineCode(f.ruleId)}${f.cwe ? ` (${f.cwe})` : ''} · confidence ${f.confidence}`, '');
    }
  }

  if (report.suppressed.length) {
    lines.push('## Suppressed', '');
    for (const f of report.suppressed) {
      lines.push(`- ${inlineCode(f.ruleId)} in ${f.file ? inlineCode(f.file) : 'the project'}: ${f.suppression?.reason ?? ''}`);
    }
    lines.push('');
  }

  const d = report.dependencies;
  lines.push('## Dependencies', '');
  lines.push(`- ${d.total} dependencies (${d.direct} direct) across ${d.ecosystems.join(', ') || 'no package manager'}`);
  lines.push(`- Lockfiles: ${d.lockfiles.length ? d.lockfiles.map(inlineCode).join(', ') : 'none'}`);
  lines.push(`- Vulnerability check: ${d.vulnerabilityCheck}${d.vulnerabilityCheck === 'online' ? ` (${d.vulnerable} vulnerable)` : ''}`, '');

  lines.push('---', '');
  lines.push('_Automated checks, not a guarantee. A pass means these checks found no critical problem on the date above._', '');
  return lines.join('\n');
}

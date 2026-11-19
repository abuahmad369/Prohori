import { lineText } from './rules/helpers.ts';
import type { Finding, ProjectFile, ScanContext } from './types.ts';

/** `prohori-ignore <rule-id>: <reason>` on the finding's line or the line above. A reason is required. */
const INLINE_RE = /prohori-ignore\s+([\w*-]+\/[\w*-]+|\*)\s*:\s*(.*?)\s*(?:\*\/|-->|#\}|$)/i;

export interface ProjectSuppression {
  ruleId: string;
  pathPrefix?: string;
  reason: string;
}

/**
 * Reads `.prohoriignore` at the project root. One entry per line:
 *   <rule-id or *> [<path prefix>]: <reason>
 */
export function parseProjectSuppressions(file: ProjectFile | undefined): ProjectSuppression[] {
  if (!file) return [];
  const out: ProjectSuppression[] = [];
  for (const raw of file.content.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const m = /^([\w*-]+\/[\w*-]+|\*)(?:\s+([^\s:]+))?\s*:\s*(.+)$/.exec(line);
    if (!m || (m[3] as string).trim().length < 3) continue;
    const entry: ProjectSuppression = { ruleId: m[1] as string, reason: (m[3] as string).trim() };
    if (m[2]) entry.pathPrefix = m[2];
    out.push(entry);
  }
  return out;
}

export function suppressionFor(finding: Finding, ctx: ScanContext, project: ProjectSuppression[]): string | null {
  if (finding.file && finding.line) {
    const file = ctx.byPath.get(finding.file);
    if (file) {
      for (const n of [finding.line, finding.line - 1]) {
        if (n < 1) continue;
        const m = INLINE_RE.exec(lineText(file, n));
        if (!m) continue;
        const reason = (m[2] as string).trim();
        if ((m[1] === '*' || m[1] === finding.ruleId) && reason.length >= 3) return reason;
      }
    }
  }
  for (const s of project) {
    if (s.ruleId !== '*' && s.ruleId !== finding.ruleId) continue;
    if (s.pathPrefix && !(finding.file ?? '').startsWith(s.pathPrefix)) continue;
    return s.reason;
  }
  return null;
}

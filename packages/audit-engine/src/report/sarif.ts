import { RULES_BY_ID } from '../rules/index.ts';
import type { AuditReport, Rule, Severity } from '../types.ts';
import { ENGINE_VERSION } from '../version.ts';

const LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

/** GitHub ranks code-scanning alerts by this 0-10 score. */
const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: '9.5',
  high: '7.5',
  medium: '5.0',
  low: '2.0',
  info: '0.0',
};

const ruleName = (id: string): string => id.replace(/[/-](\w)/g, (_m, c: string) => c.toUpperCase());

/** SARIF 2.1.0, ready for GitHub code scanning upload. */
export function toSarif(report: AuditReport): Record<string, unknown> {
  const used: Rule[] = [];
  const index = new Map<string, number>();
  for (const f of report.findings) {
    if (index.has(f.ruleId)) continue;
    const rule = RULES_BY_ID.get(f.ruleId);
    if (!rule) continue;
    index.set(f.ruleId, used.length);
    used.push(rule);
  }

  const rules = used.map((r) => ({
    id: r.id,
    name: ruleName(r.id),
    shortDescription: { text: r.title },
    fullDescription: { text: r.description },
    help: { text: r.remediation, markdown: `**Fix:** ${r.remediation}` },
    defaultConfiguration: { level: LEVEL[r.severity] },
    properties: {
      tags: ['security', r.category, ...(r.cwe ? [r.cwe] : [])],
      'security-severity': SECURITY_SEVERITY[r.severity],
      precision: r.confidence === 'high' || !r.confidence ? 'high' : 'medium',
    },
  }));

  const results = report.findings.map((f) => {
    const result: Record<string, unknown> = {
      ruleId: f.ruleId,
      level: LEVEL[f.severity],
      message: { text: f.message },
      partialFingerprints: { 'prohoriFindingId/v1': f.id },
      properties: { severity: f.severity, confidence: f.confidence },
    };
    const ruleIndex = index.get(f.ruleId);
    if (ruleIndex !== undefined) result.ruleIndex = ruleIndex;
    if (f.file) {
      const region: Record<string, unknown> = { startLine: f.line ?? 1 };
      if (f.snippet) region.snippet = { text: f.snippet };
      result.locations = [{ physicalLocation: { artifactLocation: { uri: f.file, uriBaseId: '%SRCROOT%' }, region } }];
    }
    return result;
  });

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: { driver: { name: 'Prohori', version: ENGINE_VERSION, rules } },
        results,
        properties: { score: report.score, grade: report.grade, verified: report.verified },
      },
    ],
  };
}

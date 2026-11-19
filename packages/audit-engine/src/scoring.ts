import type { CategoryId, CategoryResult, Finding, Gate, Grade, Severity } from './types.ts';

export const CATEGORY_META: Record<CategoryId, { title: string; weight: number }> = {
  secrets: { title: 'Secrets', weight: 0.2 },
  access: { title: 'Access control', weight: 0.25 },
  code: { title: 'Code safety', weight: 0.2 },
  dependencies: { title: 'Dependencies', weight: 0.15 },
  production: { title: 'Production readiness', weight: 0.1 },
  maintainability: { title: 'Maintainability', weight: 0.1 },
};

export const CATEGORY_ORDER = Object.keys(CATEGORY_META) as CategoryId[];
export const SEVERITY_POINTS: Record<Severity, number> = { critical: 40, high: 18, medium: 7, low: 2, info: 0 };
export const GATE_MIN_SCORE = 75;
export const CRITICAL_SCORE_CAP = 59;
const REPEAT_FACTOR = 0.25;
const MAX_REPEATS = 4;

export function gradeFor(score: number): Grade {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

export interface ScoreResult {
  score: number;
  grade: Grade;
  verified: boolean;
  gate: Gate;
  categories: CategoryResult[];
  counts: Record<Severity, number>;
}

/** What the scan actually covered. A pass needs code to check and every check to have run. */
export interface ScanCoverage {
  codeFiles: number;
  failedChecks: number;
}

/**
 * Scores active (not suppressed) findings.
 * Per category: first finding of each rule counts fully, repeats count 25% (max 4 repeats).
 * Overall: weighted average of categories. Any critical finding caps the score at 59.
 */
export function scoreFindings(findings: Finding[], coverage?: ScanCoverage): ScoreResult {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;

  const categories = CATEGORY_ORDER.map((id): CategoryResult => {
    const inCategory = findings.filter((f) => f.category === id);
    const byRule = new Map<string, Finding[]>();
    for (const f of inCategory) {
      const list = byRule.get(f.ruleId) ?? [];
      list.push(f);
      byRule.set(f.ruleId, list);
    }
    let deduction = 0;
    for (const list of byRule.values()) {
      const sorted = [...list].sort((a, b) => SEVERITY_POINTS[b.severity] - SEVERITY_POINTS[a.severity]);
      sorted.forEach((f, i) => {
        if (i === 0) deduction += SEVERITY_POINTS[f.severity];
        else if (i <= MAX_REPEATS) deduction += SEVERITY_POINTS[f.severity] * REPEAT_FACTOR;
      });
    }
    const { title, weight } = CATEGORY_META[id];
    return { id, title, weight, score: Math.max(0, Math.round(100 - deduction)), findings: inCategory.length };
  });

  let score = Math.round(categories.reduce((sum, c) => sum + c.score * c.weight, 0));
  if (counts.critical > 0) score = Math.min(score, CRITICAL_SCORE_CAP);

  const reasons: string[] = [];
  if (counts.critical > 0) reasons.push(`${counts.critical} critical finding(s) must be fixed.`);
  if (score < GATE_MIN_SCORE) reasons.push(`Score ${score} is below the minimum of ${GATE_MIN_SCORE}.`);
  if (coverage && coverage.codeFiles === 0) reasons.push('No application code was found, so there is nothing to verify.');
  if (coverage && coverage.failedChecks > 0) reasons.push(`${coverage.failedChecks} check(s) failed to run, so the result is incomplete.`);
  const passed = reasons.length === 0;
  if (passed) reasons.push(`Score ${score} meets the minimum of ${GATE_MIN_SCORE} and there are no critical findings.`);

  return { score, grade: gradeFor(score), verified: passed, gate: { minScore: GATE_MIN_SCORE, passed, reasons }, categories, counts };
}

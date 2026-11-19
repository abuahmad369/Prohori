import { createHash } from 'node:crypto';
import path from 'node:path';
import { buildContext } from './context.ts';
import { lookupVulnerabilities } from './deps/osv.ts';
import { loadDirectory, loadEntries } from './files.ts';
import { CODE_EXTS, severityRank } from './rules/helpers.ts';
import { ALL_RULES } from './rules/index.ts';
import { scoreFindings } from './scoring.ts';
import { parseProjectSuppressions, suppressionFor } from './suppress.ts';
import type { AuditReport, Ecosystem, Finding, LoadResult, RawFinding, Rule, ScanOptions, ScanResult } from './types.ts';
import { ENGINE_NAME, ENGINE_VERSION } from './version.ts';

function toFinding(rule: Rule, raw: RawFinding): Finding {
  const message = raw.message ?? rule.description;
  const basis = `${rule.id}|${raw.file ?? ''}|${raw.snippet ?? message}`;
  const finding: Finding = {
    id: createHash('sha1').update(basis).digest('hex').slice(0, 12),
    ruleId: rule.id,
    title: rule.title,
    category: rule.category,
    severity: raw.severity ?? rule.severity,
    confidence: raw.confidence ?? rule.confidence ?? 'high',
    message,
    remediation: rule.remediation,
  };
  if (raw.file) finding.file = raw.file;
  if (raw.line) finding.line = raw.line;
  if (raw.snippet) finding.snippet = raw.snippet;
  if (rule.cwe) finding.cwe = rule.cwe;
  return finding;
}

function compareFindings(a: Finding, b: Finding): number {
  return (
    severityRank(a.severity) - severityRank(b.severity) ||
    (a.file ?? '').localeCompare(b.file ?? '') ||
    (a.line ?? 0) - (b.line ?? 0) ||
    a.ruleId.localeCompare(b.ruleId)
  );
}

async function runScan(load: LoadResult, projectName: string, options: ScanOptions): Promise<ScanResult> {
  const now = options.now ?? (() => new Date());
  const startedAt = now();
  const t0 = performance.now();
  const ctx = buildContext(projectName, load.files, load.paths);

  let vulnerabilityCheck: AuditReport['dependencies']['vulnerabilityCheck'] = 'skipped';
  if (options.online) {
    try {
      ctx.vulnerabilities = await lookupVulnerabilities(ctx.dependencies, options.fetch ?? fetch);
      vulnerabilityCheck = 'online';
    } catch {
      vulnerabilityCheck = 'failed';
    }
  }

  const projectSuppressions = parseProjectSuppressions(ctx.byPath.get('.prohoriignore'));
  const seen = new Set<string>();
  const active: Finding[] = [];
  const suppressed: Finding[] = [];
  const errors: string[] = [];

  for (const rule of ALL_RULES) {
    let raws: RawFinding[];
    try {
      raws = await rule.check(ctx);
    } catch (err) {
      errors.push(`${rule.id}: ${err instanceof Error ? err.message : String(err)}`);
      continue;
    }
    for (const raw of raws) {
      const finding = toFinding(rule, raw);
      if (seen.has(finding.id)) continue;
      seen.add(finding.id);
      const reason = suppressionFor(finding, ctx, projectSuppressions);
      if (reason) suppressed.push({ ...finding, suppression: { reason } });
      else active.push(finding);
    }
  }
  active.sort(compareFindings);
  suppressed.sort(compareFindings);

  const codeFiles = load.files.filter((f) => CODE_EXTS.has(path.posix.extname(f.path).toLowerCase())).length;
  const scoring = scoreFindings(active, { codeFiles, failedChecks: errors.length });
  const ecosystems = [...new Set(ctx.dependencies.map((d) => d.ecosystem))].sort() as Ecosystem[];
  const report: AuditReport = {
    schemaVersion: '1.0',
    engine: { name: ENGINE_NAME, version: ENGINE_VERSION },
    project: {
      name: projectName,
      stacks: [...ctx.stacks].sort(),
      files: load.files.length,
      bytes: load.totalBytes,
      skipped: load.skipped,
      truncated: load.truncated,
    },
    scannedAt: startedAt.toISOString(),
    durationMs: Math.round(performance.now() - t0),
    score: scoring.score,
    grade: scoring.grade,
    verified: scoring.verified,
    gate: scoring.gate,
    categories: scoring.categories,
    counts: scoring.counts,
    findings: active,
    suppressed,
    dependencies: {
      total: ctx.dependencies.length,
      direct: ctx.dependencies.filter((d) => d.direct).length,
      ecosystems,
      lockfiles: ctx.lockfiles,
      vulnerabilityCheck,
      vulnerable: new Set(ctx.vulnerabilities.map((v) => `${v.dependency.ecosystem}|${v.dependency.name}|${v.dependency.version}`)).size,
    },
    errors,
  };
  return { report, dependencies: ctx.dependencies, vulnerabilities: ctx.vulnerabilities };
}

/** Scans a folder on disk. Respects the root .gitignore unless told not to. */
export async function scanDirectory(dir: string, options: ScanOptions & { respectGitignore?: boolean } = {}): Promise<ScanResult> {
  const root = path.resolve(dir);
  const loadOptions: { limits?: ScanOptions['limits']; respectGitignore?: boolean } = {};
  if (options.limits) loadOptions.limits = options.limits;
  if (options.respectGitignore !== undefined) loadOptions.respectGitignore = options.respectGitignore;
  const load = await loadDirectory(root, loadOptions);
  return runScan(load, options.projectName ?? path.basename(root), options);
}

/** Scans in-memory files, for example an unzipped upload. Nothing touches the disk. */
export async function scanFiles(entries: Iterable<readonly [string, string | Uint8Array]>, options: ScanOptions = {}): Promise<ScanResult> {
  const load = loadEntries(entries, options.limits ? { limits: options.limits } : {});
  return runScan(load, options.projectName ?? 'project', options);
}

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { gradeFor, purlFor, scanFiles, scoreFindings, toCycloneDx, toMarkdown, toSarif, toText } from '../src/index.ts';
import type { CategoryId, Dependency, Finding, Severity } from '../src/index.ts';
import { json } from './helpers.ts';

let counter = 0;
function finding(severity: Severity, category: CategoryId, ruleId = `${category}/sample-${severity}`): Finding {
  counter++;
  return { id: `f${counter}`, ruleId, title: 'Sample', category, severity, confidence: 'high', message: 'm', remediation: 'r' };
}

describe('scoring', () => {
  it('gives 100 and passes when there are no findings', () => {
    const r = scoreFindings([]);
    assert.equal(r.score, 100);
    assert.equal(r.grade, 'A');
    assert.equal(r.verified, true);
  });

  it('caps the score at 59 when there is a critical finding', () => {
    const r = scoreFindings([finding('critical', 'secrets')]);
    assert.equal(r.categories.find((c) => c.id === 'secrets')?.score, 60);
    assert.equal(r.score, 59);
    assert.equal(r.grade, 'F');
    assert.equal(r.verified, false);
    assert.match(r.gate.reasons[0]!, /critical/);
  });

  it('counts repeats of the same rule at 25%', () => {
    const r = scoreFindings([finding('high', 'access', 'access/x'), finding('high', 'access', 'access/x'), finding('high', 'access', 'access/x')]);
    assert.equal(r.categories.find((c) => c.id === 'access')?.score, 73);
    assert.equal(r.score, 93);
    assert.equal(r.verified, true);
  });

  it('fails the gate when the score drops below 75', () => {
    const list: Finding[] = [];
    for (const category of ['access', 'code', 'secrets'] as CategoryId[]) {
      for (const n of [1, 2, 3]) list.push(finding('high', category, `${category}/rule-${n}`));
    }
    const r = scoreFindings(list);
    assert.equal(r.score, 65);
    assert.equal(r.grade, 'D');
    assert.equal(r.verified, false);
    assert.match(r.gate.reasons.join(' '), /below the minimum of 75/);
  });

  it('does not verify a project with no application code', async () => {
    const { report } = await scanFiles(Object.entries({ 'README.md': '# Hello\n\nJust a readme.\n' }), { projectName: 'empty' });
    assert.ok(report.score >= 75);
    assert.equal(report.verified, false);
    assert.match(report.gate.reasons.join(' '), /No application code/);
  });

  it('does not verify a scan where a check failed to run', () => {
    const r = scoreFindings([], { codeFiles: 3, failedChecks: 1 });
    assert.equal(r.score, 100);
    assert.equal(r.verified, false);
    assert.match(r.gate.reasons.join(' '), /failed to run/);
  });

  it('maps scores to grades', () => {
    assert.deepEqual([90, 89, 80, 79, 70, 69, 60, 59].map(gradeFor), ['A', 'B', 'B', 'C', 'C', 'D', 'D', 'F']);
  });
});

describe('report formats', () => {
  const files = {
    'package.json': json({ dependencies: { '@scope/pkg': '1.2.3' }, devDependencies: { vitest: '3.0.0' } }),
    'package-lock.json': json({
      lockfileVersion: 3,
      packages: { 'node_modules/@scope/pkg': { version: '1.2.3' }, 'node_modules/vitest': { version: '3.0.0', dev: true } },
    }),
    'src/db.ts': 'export const q = (id: string) => pool.query(`SELECT * FROM t WHERE id = ${id}`);\n',
  };

  it('renders text and Markdown with score, findings and fixes', async () => {
    const { report } = await scanFiles(Object.entries(files), { projectName: 'demo' });
    const md = toMarkdown(report);
    assert.match(md, /^# Prohori audit report: demo/);
    assert.match(md, /Possible SQL injection/);
    assert.match(md, /\*\*Fix:\*\*/);
    const text = toText(report);
    assert.match(text, /Prohori audit: demo/);
    assert.match(text, /Possible SQL injection/);
  });

  it('renders SARIF 2.1.0 for GitHub code scanning', async () => {
    const { report } = await scanFiles(Object.entries(files));
    // SARIF is plain JSON; the test reads it loosely.
    const sarif = toSarif(report) as any;
    assert.equal(sarif.version, '2.1.0');
    const run = sarif.runs[0];
    assert.equal(run.results.length, report.findings.length);
    const rule = run.tool.driver.rules.find((r: { id: string }) => r.id === 'code/sql-injection');
    assert.equal(rule.properties['security-severity'], '7.5');
    const result = run.results.find((r: { ruleId: string }) => r.ruleId === 'code/sql-injection');
    assert.equal(result.level, 'error');
    assert.equal(result.locations[0].physicalLocation.artifactLocation.uri, 'src/db.ts');
  });

  it('renders a CycloneDX 1.5 SBOM with purls', async () => {
    const { report, dependencies } = await scanFiles(Object.entries(files), { projectName: 'demo' });
    const bom = toCycloneDx(report, dependencies) as any;
    assert.equal(bom.bomFormat, 'CycloneDX');
    assert.equal(bom.specVersion, '1.5');
    assert.match(bom.serialNumber, /^urn:uuid:[0-9a-f-]{36}$/);
    const scoped = bom.components.find((c: { name: string }) => c.name === 'pkg');
    assert.equal(scoped.group, '@scope');
    assert.equal(scoped.purl, 'pkg:npm/%40scope/pkg@1.2.3');
    assert.equal(scoped.scope, 'required');
    assert.equal(bom.components.find((c: { name: string }) => c.name === 'vitest').scope, 'excluded');
    assert.deepEqual(bom.dependencies[0].dependsOn.sort(), ['npm:@scope/pkg@1.2.3', 'npm:vitest@3.0.0']);
  });

  it('builds purls for every ecosystem', () => {
    const dep = (ecosystem: Dependency['ecosystem'], name: string, version: string, resolved = true): Dependency => ({
      ecosystem,
      name,
      version,
      resolved,
      direct: true,
      dev: false,
      source: 'x',
    });
    assert.equal(purlFor(dep('Packagist', 'laravel/framework', '12.1.0')), 'pkg:composer/laravel/framework@12.1.0');
    assert.equal(purlFor(dep('PyPI', 'Django', '5.1.2')), 'pkg:pypi/django@5.1.2');
    assert.equal(purlFor(dep('NuGet', 'Newtonsoft.Json', '13.0.3')), 'pkg:nuget/Newtonsoft.Json@13.0.3');
    assert.equal(purlFor(dep('npm', 'left', '*', false)), 'pkg:npm/left');
  });
});

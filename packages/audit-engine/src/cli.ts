#!/usr/bin/env node
import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { toMarkdown } from './report/markdown.ts';
import { toSarif } from './report/sarif.ts';
import { toCycloneDx } from './report/sbom.ts';
import { toText } from './report/text.ts';
import { severityRank } from './rules/helpers.ts';
import { ALL_RULES } from './rules/index.ts';
import { scanDirectory } from './scan.ts';
import type { AuditReport, Severity } from './types.ts';
import { ENGINE_VERSION } from './version.ts';

const HELP = `Prohori ${ENGINE_VERSION}: audit AI-built apps for security and production readiness.

Usage
  prohori scan [dir] [options]   Scan a project folder (default: current folder)
  prohori rules                  List all rules
  prohori --version

Scan options
  -f, --format <text|json|md|sarif>   Output format (default: text)
  -o, --out <file>                    Write the report to a file
      --sbom <file>                   Also write a CycloneDX SBOM (JSON)
      --online                        Check dependencies against OSV.dev (needs internet)
      --fail-on <gate|critical|high|medium|low|none>
                                      When to exit with code 1 (default: gate, meaning not verified)
      --no-gitignore                  Also scan files listed in .gitignore
      --name <name>                   Project name shown in the report

Exit codes: 0 passed, 1 failed the --fail-on check, 2 usage or runtime error.
`;

const FORMATS = ['text', 'json', 'md', 'sarif'];
const FAIL_ON = ['gate', 'critical', 'high', 'medium', 'low', 'none'];

function shouldFail(report: AuditReport, failOn: string): boolean {
  if (failOn === 'none') return false;
  if (failOn === 'gate') return !report.verified;
  const threshold = severityRank(failOn as Severity);
  return report.findings.some((f) => severityRank(f.severity) <= threshold);
}

async function main(argv: string[]): Promise<number> {
  const [command, ...rest] = argv;
  if (!command || command === 'help' || command === '--help' || command === '-h') {
    process.stdout.write(HELP);
    return 0;
  }
  if (command === '--version' || command === '-v') {
    process.stdout.write(`${ENGINE_VERSION}\n`);
    return 0;
  }
  if (command === 'rules') {
    for (const r of ALL_RULES) process.stdout.write(`${r.id.padEnd(42)} ${r.severity.padEnd(9)} ${r.title}\n`);
    return 0;
  }
  if (command !== 'scan') {
    process.stderr.write(`Unknown command "${command}".\n\n${HELP}`);
    return 2;
  }

  const { values, positionals } = parseArgs({
    args: rest,
    allowPositionals: true,
    options: {
      format: { type: 'string', short: 'f', default: 'text' },
      out: { type: 'string', short: 'o' },
      sbom: { type: 'string' },
      online: { type: 'boolean', default: false },
      'fail-on': { type: 'string', default: 'gate' },
      'no-gitignore': { type: 'boolean', default: false },
      name: { type: 'string' },
    },
  });

  const format = values.format ?? 'text';
  const failOn = values['fail-on'] ?? 'gate';
  if (!FORMATS.includes(format)) {
    process.stderr.write(`--format must be one of: ${FORMATS.join(', ')}\n`);
    return 2;
  }
  if (!FAIL_ON.includes(failOn)) {
    process.stderr.write(`--fail-on must be one of: ${FAIL_ON.join(', ')}\n`);
    return 2;
  }

  const dir = path.resolve(positionals[0] ?? '.');
  const { report, dependencies, vulnerabilities } = await scanDirectory(dir, {
    online: values.online ?? false,
    respectGitignore: !values['no-gitignore'],
    ...(values.name ? { projectName: values.name } : {}),
  });

  let output: string;
  if (format === 'json') output = JSON.stringify(report, null, 2);
  else if (format === 'md') output = toMarkdown(report);
  else if (format === 'sarif') output = JSON.stringify(toSarif(report), null, 2);
  else output = toText(report, { color: !values.out && process.stdout.isTTY === true && !process.env.NO_COLOR });

  if (values.out) {
    await writeFile(values.out, `${output}\n`, 'utf8');
    process.stderr.write(`Report written to ${values.out}\n`);
  } else {
    process.stdout.write(`${output}\n`);
  }
  if (values.sbom) {
    await writeFile(values.sbom, `${JSON.stringify(toCycloneDx(report, dependencies, vulnerabilities), null, 2)}\n`, 'utf8');
    process.stderr.write(`SBOM written to ${values.sbom}\n`);
  }
  return shouldFail(report, failOn) ? 1 : 0;
}

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (err: unknown) => {
    process.stderr.write(`prohori: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 2;
  },
);

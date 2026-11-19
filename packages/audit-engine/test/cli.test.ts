import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { after, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { CLEAN_APP, fake } from './helpers.ts';

const CLI = fileURLToPath(new URL('../src/cli.ts', import.meta.url));
const tempDirs: string[] = [];

async function project(files: Record<string, string>): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'prohori-cli-'));
  tempDirs.push(dir);
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(dir, rel);
    await mkdir(path.dirname(abs), { recursive: true });
    await writeFile(abs, content);
  }
  return dir;
}

function run(...args: string[]) {
  return spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', CLI, ...args], { encoding: 'utf8' });
}

after(async () => {
  await Promise.all(tempDirs.map((d) => rm(d, { recursive: true, force: true })));
});

const VULNERABLE = {
  'app/api/chat/route.ts':
    "import OpenAI from 'openai';\nconst client = new OpenAI();\nexport async function POST(req: Request) {\n  const { prompt } = await req.json();\n  return Response.json(await client.responses.create({ model: 'gpt-5', input: prompt }));\n}\n",
  'lib/stripe.ts': `export const key = "${fake('sk', '_live_', 'FAKE1234567890abcdefghijKL')}";\n`,
};

describe('cli', () => {
  it('prints the version and the rule list', () => {
    const version = run('--version');
    assert.equal(version.status, 0);
    assert.match(version.stdout, /^\d+\.\d+\.\d+/);
    const rules = run('rules');
    assert.equal(rules.status, 0);
    assert.match(rules.stdout, /secrets\/hardcoded-credential/);
  });

  it('exits 1 when the gate fails, and 0 with --fail-on none', async () => {
    const dir = await project(VULNERABLE);
    const failed = run('scan', dir, '--format', 'json');
    assert.equal(failed.status, 1, failed.stderr);
    const report = JSON.parse(failed.stdout);
    assert.equal(report.verified, false);
    assert.ok(report.findings.some((f: { ruleId: string }) => f.ruleId === 'access/ai-endpoint-unprotected'));
    assert.equal(run('scan', dir, '--fail-on', 'none').status, 0);
  });

  it('exits 0 for a clean project and writes an SBOM', async () => {
    const dir = await project(CLEAN_APP);
    const sbomPath = path.join(dir, 'sbom.json');
    const result = run('scan', dir, '--sbom', sbomPath);
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.match(result.stdout, /VERIFIED/);
    const bom = JSON.parse(await readFile(sbomPath, 'utf8'));
    assert.equal(bom.bomFormat, 'CycloneDX');
    assert.ok(bom.components.length >= 7);
  });

  it('respects .gitignore unless --no-gitignore is given', async () => {
    const dir = await project({
      '.gitignore': '.env\n',
      '.env': `STRIPE_KEY=${fake('sk', '_live_', 'FAKE1234567890abcdefghijKL')}\n`,
      'index.js': 'console.log(process.env.STRIPE_KEY);\n',
    });
    const count = (stdout: string): number =>
      (JSON.parse(stdout) as { findings: Array<{ ruleId: string }> }).findings.filter((f) => f.ruleId === 'secrets/env-file-committed').length;
    assert.equal(count(run('scan', dir, '--format', 'json', '--fail-on', 'none').stdout), 0);
    assert.equal(count(run('scan', dir, '--format', 'json', '--fail-on', 'none', '--no-gitignore').stdout), 1);
  });

  it('rejects unknown options with exit code 2', () => {
    assert.equal(run('scan', '.', '--format', 'pdf').status, 2);
    assert.equal(run('launch').status, 2);
  });
});

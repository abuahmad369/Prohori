import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { scanFiles } from '../src/index.ts';
import { findings, json, scan } from './helpers.ts';

const names = (deps: Array<{ name: string; version: string }>): string[] => deps.map((d) => `${d.name}@${d.version}`);

describe('dependency extraction', () => {
  it('reads package-lock v3 with scoped, dev and nested packages', async () => {
    const { dependencies } = await scanFiles(
      Object.entries({
        'package.json': json({ dependencies: { '@scope/pkg': '1.2.3', lodash: '4.17.21' }, devDependencies: { vitest: '3.0.0' } }),
        'package-lock.json': json({
          lockfileVersion: 3,
          packages: {
            '': { name: 'app' },
            'node_modules/@scope/pkg': { version: '1.2.3' },
            'node_modules/lodash': { version: '4.17.21' },
            'node_modules/vitest': { version: '3.0.0', dev: true },
            'node_modules/vitest/node_modules/tinyspy': { version: '3.0.2', dev: true },
          },
        }),
      }),
    );
    const byName = new Map(dependencies.map((d) => [d.name, d]));
    assert.equal(dependencies.length, 4);
    assert.equal(byName.get('@scope/pkg')?.direct, true);
    assert.equal(byName.get('lodash')?.resolved, true);
    assert.equal(byName.get('tinyspy')?.direct, false);
    assert.equal(byName.get('tinyspy')?.dev, true);
  });

  it('reads pnpm-lock v9', async () => {
    const lock = [
      "lockfileVersion: '9.0'",
      '',
      'importers:',
      '',
      '  .:',
      '    dependencies:',
      '      lodash:',
      '        specifier: 4.17.21',
      '        version: 4.17.21',
      '',
      'packages:',
      '',
      "  '@babel/core@7.26.0':",
      '    resolution: {integrity: sha512-x}',
      '',
      '  lodash@4.17.21:',
      '    resolution: {integrity: sha512-y}',
      '',
      'snapshots:',
      '',
      '  lodash@4.17.21: {}',
      '',
    ].join('\n');
    const { dependencies } = await scanFiles([['pnpm-lock.yaml', lock]]);
    assert.deepEqual(names(dependencies), ['@babel/core@7.26.0', 'lodash@4.17.21']);
  });

  it('reads yarn v1 and berry lockfiles', async () => {
    const v1 = ['# yarn lockfile v1', '', '"@babel/core@^7.0.0", "@babel/core@^7.1.0":', '  version "7.26.0"', '  resolved "https://registry.yarnpkg.com/x"', '', 'lodash@^4.17.21:', '  version "4.17.21"', ''].join('\n');
    const berry = ['__metadata:', '  version: 8', '', '"left-pad@npm:^1.3.0":', '  version: 1.3.0', ''].join('\n');
    assert.deepEqual(names((await scanFiles([['yarn.lock', v1]])).dependencies), ['@babel/core@7.26.0', 'lodash@4.17.21']);
    assert.deepEqual(names((await scanFiles([['yarn.lock', berry]])).dependencies), ['left-pad@1.3.0']);
  });

  it('reads composer.lock and marks direct and dev packages', async () => {
    const { dependencies } = await scanFiles(
      Object.entries({
        'composer.json': json({ require: { php: '^8.3', 'laravel/framework': '^12.0' }, 'require-dev': { 'phpunit/phpunit': '^11.0' } }),
        'composer.lock': json({ packages: [{ name: 'laravel/framework', version: 'v12.1.0' }], 'packages-dev': [{ name: 'phpunit/phpunit', version: '11.0.0' }] }),
      }),
    );
    const framework = dependencies.find((d) => d.name === 'laravel/framework');
    assert.equal(framework?.version, '12.1.0');
    assert.equal(framework?.direct, true);
    assert.equal(dependencies.find((d) => d.name === 'phpunit/phpunit')?.dev, true);
  });

  it('reads requirements.txt and .csproj, and flags loose versions', async () => {
    const { report, dependencies } = await scanFiles(
      Object.entries({
        'requirements.txt': 'Django==5.1.2\nrequests>=2.31\n# a comment\nflask\n',
        'App.csproj':
          '<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /><PackageReference Version="8.*" Include="Serilog" /></ItemGroup></Project>',
      }),
    );
    const byName = new Map(dependencies.map((d) => [d.name, d]));
    assert.equal(byName.get('django')?.version, '5.1.2');
    assert.equal(byName.get('django')?.resolved, true);
    assert.equal(byName.get('requests')?.resolved, false);
    assert.equal(byName.get('flask')?.version, '*');
    assert.equal(byName.get('Newtonsoft.Json')?.resolved, true);
    assert.equal(byName.get('Serilog')?.resolved, false);
    const loose = findings(report, 'dependencies/unpinned-version').map((f) => `${f.file} ${f.severity}`).sort();
    assert.deepEqual(loose, ['App.csproj medium', 'requirements.txt low']);
    assert.ok(report.project.stacks.includes('python'));
    assert.ok(report.project.stacks.includes('dotnet'));
  });

  it('flags a missing lockfile, star versions and git dependencies', async () => {
    const report = await scan({ 'package.json': json({ dependencies: { left: '*', right: 'github:user/right', ok: '^1.2.3' } }) });
    assert.equal(findings(report, 'dependencies/no-lockfile').length, 1);
    assert.equal(findings(report, 'dependencies/unpinned-version').length, 1);
    assert.equal(findings(report, 'dependencies/git-dependency').length, 1);
  });

  it('finds a lockfile at the monorepo root', async () => {
    const report = await scan({
      'pnpm-lock.yaml': "lockfileVersion: '9.0'\n",
      'apps/web/package.json': json({ dependencies: { next: '16.4.6' } }),
    });
    assert.equal(findings(report, 'dependencies/no-lockfile').length, 0);
  });
});

describe('online vulnerability check', () => {
  const project = {
    'package.json': json({ dependencies: { lodash: '4.17.21', ok: '1.0.0' } }),
    'package-lock.json': json({ lockfileVersion: 3, packages: { 'node_modules/lodash': { version: '4.17.21' }, 'node_modules/ok': { version: '1.0.0' } } }),
  };

  it('reports known vulnerabilities returned by OSV', async () => {
    const fakeFetch = (async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith('/querybatch')) {
        const body = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string } }> };
        return Response.json({ results: body.queries.map((q) => (q.package.name === 'lodash' ? { vulns: [{ id: 'GHSA-test-0001' }] } : {})) });
      }
      return Response.json({
        id: 'GHSA-test-0001',
        summary: 'Prototype pollution',
        aliases: ['CVE-2026-0001'],
        database_specific: { severity: 'HIGH' },
        affected: [{ package: { name: 'lodash', ecosystem: 'npm' }, ranges: [{ events: [{ introduced: '0' }, { fixed: '4.17.22' }] }] }],
      });
    }) as typeof fetch;

    const { report, vulnerabilities } = await scanFiles(Object.entries(project), { online: true, fetch: fakeFetch });
    assert.equal(report.dependencies.vulnerabilityCheck, 'online');
    assert.equal(report.dependencies.vulnerable, 1);
    assert.equal(vulnerabilities[0]?.fixedIn, '4.17.22');
    const found = findings(report, 'dependencies/known-vulnerability');
    assert.equal(found.length, 1);
    assert.equal(found[0]?.severity, 'high');
    assert.match(found[0]!.message, /GHSA-test-0001.*CVE-2026-0001.*4\.17\.22/);
  });

  it('marks the check as failed when OSV cannot be reached', async () => {
    const offline = (async () => {
      throw new Error('offline');
    }) as typeof fetch;
    const { report } = await scanFiles(Object.entries(project), { online: true, fetch: offline });
    assert.equal(report.dependencies.vulnerabilityCheck, 'failed');
  });
});

import type { Manifest, RawFinding, Rule, ScanContext } from '../types.ts';
import { at } from './helpers.ts';

const NPM_LOCKFILES = ['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lock', 'bun.lockb'];
const MAX_PER_MANIFEST = 15;

function ancestors(dir: string): string[] {
  const out: string[] = [];
  let d = dir;
  for (;;) {
    out.push(d);
    if (d === '.' || d === '') break;
    const i = d.lastIndexOf('/');
    d = i === -1 ? '.' : d.slice(0, i);
  }
  return out;
}

const joinPath = (dir: string, name: string): string => (dir === '.' || dir === '' ? name : `${dir}/${name}`);

function hasLockfileNear(ctx: ScanContext, m: Manifest, names: string[]): boolean {
  return ancestors(m.dir).some((d) => names.some((n) => ctx.paths.has(joinPath(d, n))));
}

function locate(ctx: ScanContext, file: string, needle: string): RawFinding {
  const f = ctx.byPath.get(file);
  if (!f) return { file };
  const idx = f.content.indexOf(needle);
  return idx >= 0 ? at(f, idx) : { file, line: 1 };
}

const noLockfile: Rule = {
  id: 'dependencies/no-lockfile',
  title: 'No lockfile',
  category: 'dependencies',
  severity: 'medium',
  cwe: 'CWE-1104',
  description: 'Without a lockfile, each install can pull different versions of your dependencies, including a newly compromised one, and builds cannot be reproduced.',
  remediation: 'Commit the lockfile your package manager creates (package-lock.json, pnpm-lock.yaml, yarn.lock or composer.lock), and install with npm ci or pnpm install --frozen-lockfile in CI.',
  check(ctx) {
    const out: RawFinding[] = [];
    for (const m of ctx.manifests) {
      if (m.direct.size === 0) continue;
      if (m.ecosystem === 'npm' && !hasLockfileNear(ctx, m, NPM_LOCKFILES)) {
        out.push({ file: m.file, line: 1, message: `${m.file} lists ${m.direct.size} dependencies but has no lockfile.` });
      } else if (m.ecosystem === 'Packagist' && !hasLockfileNear(ctx, m, ['composer.lock'])) {
        out.push({ file: m.file, line: 1, message: `${m.file} lists ${m.direct.size} dependencies but composer.lock is missing.` });
      }
    }
    return out;
  },
};

const looseNpmRange = (range: string): boolean => {
  const r = range.trim();
  return /^(?:\*|latest|x|next|)$/i.test(r) || (/^>=?\s*\d/.test(r) && !r.includes('<'));
};

const unpinnedVersion: Rule = {
  id: 'dependencies/unpinned-version',
  title: 'Dependency version not pinned',
  category: 'dependencies',
  severity: 'medium',
  cwe: 'CWE-1104',
  description: 'A dependency accepts any future version ("*", "latest", ">=", "dev-main"), so a single bad release can break or compromise the app on the next install.',
  remediation: 'Pin a specific version or a caret range (for example "^4.17.21"), and let a lockfile and an update bot such as Dependabot or Renovate handle upgrades.',
  check(ctx) {
    const out: RawFinding[] = [];
    for (const m of ctx.manifests) {
      let count = 0;
      if (m.ecosystem === 'PyPI') {
        const loose = [...m.direct.values()].filter((d) => !d.range.startsWith('==') || d.range.includes('*')).length;
        if (loose > 0) out.push({ file: m.file, line: 1, severity: 'low', message: `${loose} package(s) in ${m.file} are not pinned with ==.` });
        continue;
      }
      for (const [name, info] of m.direct) {
        if (count >= MAX_PER_MANIFEST) break;
        const loose =
          m.ecosystem === 'npm'
            ? looseNpmRange(info.range)
            : m.ecosystem === 'Packagist'
              ? info.range.trim() === '*' || /^dev-/.test(info.range.trim())
              : info.range.includes('*') || /^[[(]/.test(info.range.trim());
        if (!loose) continue;
        count++;
        out.push({ ...locate(ctx, m.file, `"${name}"`), message: `${name} is "${info.range}" in ${m.file}, so any future version can be installed.` });
      }
    }
    return out;
  },
};

const gitDependency: Rule = {
  id: 'dependencies/git-dependency',
  title: 'Dependency installed from git or a URL',
  category: 'dependencies',
  severity: 'low',
  cwe: 'CWE-829',
  description: 'A dependency is pulled straight from a git repository or URL, which skips registry checks and can change without a version bump.',
  remediation: 'Use a published version from the registry, or pin the git dependency to a specific commit hash.',
  check(ctx) {
    const out: RawFinding[] = [];
    for (const m of ctx.manifests) {
      if (m.ecosystem !== 'npm') continue;
      for (const [name, info] of m.direct) {
        if (/^(?:git\+|git:|github:|gitlab:|bitbucket:|https?:)/.test(info.range.trim())) {
          out.push({ ...locate(ctx, m.file, `"${name}"`), message: `${name} is installed from "${info.range}".` });
        }
      }
    }
    return out;
  },
};

const knownVulnerability: Rule = {
  id: 'dependencies/known-vulnerability',
  title: 'Dependency with a known vulnerability',
  category: 'dependencies',
  severity: 'high',
  cwe: 'CWE-1395',
  description: 'A dependency version in the lockfile has a published security advisory (from the OSV.dev database).',
  remediation: 'Upgrade to a fixed version (npm update, composer update or pip install -U for that package), commit the new lockfile and scan again.',
  check(ctx) {
    return ctx.vulnerabilities.map((v) => {
      const alias = v.aliases[0] ? `, ${v.aliases[0]}` : '';
      const fixed = v.fixedIn ? ` Fixed in ${v.fixedIn}.` : '';
      return {
        ...locate(ctx, v.dependency.source, `"${v.dependency.name}"`),
        severity: v.severity,
        message: `${v.dependency.name}@${v.dependency.version} has a known vulnerability (${v.id}${alias}): ${v.summary}${fixed}`,
      };
    });
  },
};

export const dependencyRules: Rule[] = [noLockfile, unpinnedVersion, gitDependency, knownVulnerability];

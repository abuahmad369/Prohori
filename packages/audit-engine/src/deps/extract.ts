import path from 'node:path';
import type { Dependency, Ecosystem, Manifest, ProjectFile } from '../types.ts';

// Lockfiles and manifests are untrusted JSON of unknown shape.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Json = any;

function parseJson(text: string): Json | null {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

export function normalizeName(ecosystem: Ecosystem, name: string): string {
  if (ecosystem === 'PyPI') return name.toLowerCase().replace(/[-_.]+/g, '-');
  if (ecosystem === 'Packagist' || ecosystem === 'NuGet') return name.toLowerCase();
  return name;
}

function manifest(file: ProjectFile, ecosystem: Ecosystem): Manifest {
  return { file: file.path, dir: path.posix.dirname(file.path), ecosystem, direct: new Map() };
}

function parsePackageJson(file: ProjectFile): Manifest | null {
  const json = parseJson(file.content);
  if (!json || typeof json !== 'object') return null;
  const m = manifest(file, 'npm');
  const sections: Array<[string, boolean]> = [
    ['dependencies', false],
    ['optionalDependencies', false],
    ['devDependencies', true],
  ];
  for (const [section, dev] of sections) {
    const deps = json[section];
    if (!deps || typeof deps !== 'object') continue;
    for (const [name, range] of Object.entries(deps)) {
      if (typeof range === 'string' && !m.direct.has(name)) m.direct.set(name, { range, dev });
    }
  }
  return m;
}

function parseComposerJson(file: ProjectFile): Manifest | null {
  const json = parseJson(file.content);
  if (!json || typeof json !== 'object') return null;
  const m = manifest(file, 'Packagist');
  const sections: Array<[string, boolean]> = [
    ['require', false],
    ['require-dev', true],
  ];
  for (const [section, dev] of sections) {
    const deps = json[section];
    if (!deps || typeof deps !== 'object') continue;
    for (const [name, range] of Object.entries(deps)) {
      if (typeof range !== 'string') continue;
      if (name === 'php' || /^(ext|lib)-/.test(name) || name === 'composer-plugin-api') continue;
      m.direct.set(name, { range, dev });
    }
  }
  return m;
}

function parsePackageLock(file: ProjectFile): Dependency[] {
  const json = parseJson(file.content);
  if (!json) return [];
  const out: Dependency[] = [];
  if (json.packages && typeof json.packages === 'object') {
    for (const [key, value] of Object.entries<Json>(json.packages)) {
      if (!key || !value || value.link) continue;
      const idx = key.lastIndexOf('node_modules/');
      if (idx === -1 || typeof value.version !== 'string') continue;
      const name = typeof value.name === 'string' ? value.name : key.slice(idx + 'node_modules/'.length);
      out.push({ ecosystem: 'npm', name, version: value.version, resolved: true, direct: false, dev: Boolean(value.dev), source: file.path });
    }
  } else if (json.dependencies && typeof json.dependencies === 'object') {
    const walk = (deps: Json): void => {
      for (const [name, value] of Object.entries<Json>(deps)) {
        if (value && typeof value.version === 'string') {
          out.push({ ecosystem: 'npm', name, version: value.version, resolved: true, direct: false, dev: Boolean(value.dev), source: file.path });
        }
        if (value?.dependencies) walk(value.dependencies);
      }
    };
    walk(json.dependencies);
  }
  return out;
}

const PNPM_KEY_RE = /^ {2}['"]?\/?((?:@[^@/\s'"]+\/)?[^@/\s'"()]+)@([^:()\s'"]+)/;

function parsePnpmLock(file: ProjectFile): Dependency[] {
  const out: Dependency[] = [];
  let section = '';
  for (const line of file.content.split(/\r?\n/)) {
    if (/^\S/.test(line)) {
      section = line.replace(/:.*$/, '').trim();
      continue;
    }
    if (section !== 'packages' && section !== 'snapshots') continue;
    const m = PNPM_KEY_RE.exec(line);
    if (m) out.push({ ecosystem: 'npm', name: m[1] as string, version: m[2] as string, resolved: true, direct: false, dev: false, source: file.path });
  }
  return out;
}

function parseYarnLock(file: ProjectFile): Dependency[] {
  const out: Dependency[] = [];
  let current: string | null = null;
  for (const line of file.content.split(/\r?\n/)) {
    if (!line || line.startsWith('#')) continue;
    if (/^\S.*:\s*$/.test(line)) {
      const first = (line.replace(/:\s*$/, '').split(',')[0] ?? '').trim().replace(/^"|"$/g, '');
      const at = first.indexOf('@', 1);
      current = at > 0 && !first.includes('@workspace:') ? first.slice(0, at) : null;
      continue;
    }
    const v = /^\s+version:?\s+"?([^"\s]+)"?/.exec(line);
    if (v && current) {
      out.push({ ecosystem: 'npm', name: current, version: v[1] as string, resolved: true, direct: false, dev: false, source: file.path });
      current = null;
    }
  }
  return out;
}

function parseComposerLock(file: ProjectFile): Dependency[] {
  const json = parseJson(file.content);
  if (!json) return [];
  const out: Dependency[] = [];
  const sections: Array<[string, boolean]> = [
    ['packages', false],
    ['packages-dev', true],
  ];
  for (const [key, dev] of sections) {
    const list = Array.isArray(json[key]) ? json[key] : [];
    for (const p of list) {
      if (typeof p?.name !== 'string' || p.version === undefined) continue;
      out.push({ ecosystem: 'Packagist', name: p.name, version: String(p.version).replace(/^v(?=\d)/, ''), resolved: true, direct: false, dev, source: file.path });
    }
  }
  return out;
}

function parseRequirements(file: ProjectFile): { manifest: Manifest; deps: Dependency[] } {
  const m = manifest(file, 'PyPI');
  const deps: Dependency[] = [];
  const dev = /dev|test/i.test(path.posix.basename(file.path));
  for (const raw of file.content.split(/\r?\n/)) {
    const line = raw.replace(/\s+#.*$/, '').trim();
    if (!line || line.startsWith('#') || line.startsWith('-') || /^[a-z][a-z+]*:\/\//i.test(line)) continue;
    const match = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(===|==|~=|>=|<=|!=|>|<)?\s*([^;\s,#]+)?/.exec(line);
    if (!match) continue;
    const name = (match[1] as string).toLowerCase();
    const op = match[2];
    const ver = match[3];
    const exact = (op === '==' || op === '===') && Boolean(ver) && !ver?.includes('*');
    const range = op ? `${op}${ver ?? ''}` : '*';
    m.direct.set(name, { range, dev });
    deps.push({ ecosystem: 'PyPI', name, version: exact ? (ver as string) : range, resolved: exact, direct: true, dev, source: file.path });
  }
  return { manifest: m, deps };
}

const PACKAGE_REFERENCE_PATTERNS: Array<{ re: RegExp; nameGroup: number; versionGroup: number }> = [
  { re: /<PackageReference\b[^>]*?\bInclude="([^"]+)"[^>]*?\bVersion="([^"]+)"/g, nameGroup: 1, versionGroup: 2 },
  { re: /<PackageReference\b[^>]*?\bVersion="([^"]+)"[^>]*?\bInclude="([^"]+)"/g, nameGroup: 2, versionGroup: 1 },
  { re: /<PackageReference\b[^>]*?\bInclude="([^"]+)"[^>]*>\s*<Version>([^<]+)<\/Version>/g, nameGroup: 1, versionGroup: 2 },
];

function parseCsproj(file: ProjectFile): { manifest: Manifest; deps: Dependency[] } {
  const m = manifest(file, 'NuGet');
  const deps: Dependency[] = [];
  for (const { re, nameGroup, versionGroup } of PACKAGE_REFERENCE_PATTERNS) {
    for (const match of file.content.matchAll(re)) {
      const name = match[nameGroup] as string;
      const version = (match[versionGroup] as string).trim();
      if (m.direct.has(name)) continue;
      const exact = /^\d+(?:\.\d+){1,3}(?:-[\w.]+)?$/.test(version);
      m.direct.set(name, { range: version, dev: false });
      deps.push({ ecosystem: 'NuGet', name, version, resolved: exact, direct: true, dev: false, source: file.path });
    }
  }
  return { manifest: m, deps };
}

function dedupe(deps: Dependency[]): Dependency[] {
  const byKey = new Map<string, Dependency>();
  for (const d of deps) {
    const key = `${d.ecosystem}|${normalizeName(d.ecosystem, d.name)}|${d.version}`;
    const existing = byKey.get(key);
    if (!existing) {
      byKey.set(key, { ...d });
    } else {
      existing.direct = existing.direct || d.direct;
      existing.dev = existing.dev && d.dev;
      existing.resolved = existing.resolved || d.resolved;
    }
  }
  return [...byKey.values()].sort((a, b) =>
    a.ecosystem === b.ecosystem ? (a.name < b.name ? -1 : a.name > b.name ? 1 : 0) : a.ecosystem < b.ecosystem ? -1 : 1,
  );
}

export interface Extraction {
  dependencies: Dependency[];
  lockfiles: string[];
  manifests: Manifest[];
}

/** Reads dependencies from manifests and lockfiles: npm, Composer, pip requirements and NuGet. */
export function extractDependencies(files: ProjectFile[]): Extraction {
  const manifests: Manifest[] = [];
  const found: Dependency[] = [];
  const lockfiles: string[] = [];

  for (const file of files) {
    const base = path.posix.basename(file.path).toLowerCase();
    if (base === 'package.json') {
      const m = parsePackageJson(file);
      if (m) manifests.push(m);
    } else if (base === 'composer.json') {
      const m = parseComposerJson(file);
      if (m) manifests.push(m);
    } else if (base === 'package-lock.json' || base === 'npm-shrinkwrap.json') {
      lockfiles.push(file.path);
      found.push(...parsePackageLock(file));
    } else if (base === 'pnpm-lock.yaml') {
      lockfiles.push(file.path);
      found.push(...parsePnpmLock(file));
    } else if (base === 'yarn.lock') {
      lockfiles.push(file.path);
      found.push(...parseYarnLock(file));
    } else if (base === 'bun.lock') {
      lockfiles.push(file.path);
    } else if (base === 'composer.lock') {
      lockfiles.push(file.path);
      found.push(...parseComposerLock(file));
    } else if (/^requirements[\w.-]*\.txt$/.test(base)) {
      const { manifest: m, deps } = parseRequirements(file);
      manifests.push(m);
      found.push(...deps);
    } else if (base.endsWith('.csproj')) {
      const { manifest: m, deps } = parseCsproj(file);
      manifests.push(m);
      found.push(...deps);
    }
  }

  const directNames = new Map<Ecosystem, Set<string>>();
  for (const m of manifests) {
    let set = directNames.get(m.ecosystem);
    if (!set) {
      set = new Set();
      directNames.set(m.ecosystem, set);
    }
    for (const name of m.direct.keys()) set.add(normalizeName(m.ecosystem, name));
  }
  for (const d of found) {
    if (directNames.get(d.ecosystem)?.has(normalizeName(d.ecosystem, d.name))) d.direct = true;
  }

  // Without a lockfile, fall back to the ranges declared in the manifest.
  const lockedEcosystems = new Set(found.filter((d) => d.resolved).map((d) => d.ecosystem));
  for (const m of manifests) {
    if (m.ecosystem === 'PyPI' || m.ecosystem === 'NuGet') continue;
    if (lockedEcosystems.has(m.ecosystem)) continue;
    for (const [name, info] of m.direct) {
      found.push({ ecosystem: m.ecosystem, name, version: info.range, resolved: false, direct: true, dev: info.dev, source: m.file });
    }
  }

  return { dependencies: dedupe(found), lockfiles: lockfiles.sort(), manifests };
}

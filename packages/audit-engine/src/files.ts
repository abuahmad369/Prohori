import { lstat, readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { parseGitignore, type IgnoreMatcher } from './gitignore.ts';
import type { LoadResult, ProjectFile, ScanLimits } from './types.ts';

export const DEFAULT_LIMITS: ScanLimits = {
  maxFiles: 5000,
  maxFileBytes: 1_000_000,
  maxLockfileBytes: 10_000_000,
  maxTotalBytes: 60_000_000,
};

const IGNORED_DIRS = new Set([
  'node_modules', '.git', '.hg', '.svn', '.next', '.nuxt', '.svelte-kit', '.turbo', '.vercel',
  '.output', '.cache', '.parcel-cache', 'dist', 'build', 'out', 'coverage', 'vendor', '.venv',
  'venv', '__pycache__', '.mypy_cache', '.pytest_cache', '.tox', 'obj', 'target', 'Pods',
  '.gradle', '.idea', '.pnpm-store', '.yarn',
]);

const TEXT_EXTENSIONS = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.mts', '.cts', '.vue', '.svelte', '.astro',
  '.php', '.py', '.rb', '.go', '.rs', '.java', '.kt', '.kts', '.cs', '.csproj', '.fsproj', '.sln',
  '.swift', '.dart', '.sql', '.prisma', '.graphql', '.gql', '.json', '.jsonc', '.yml', '.yaml',
  '.toml', '.ini', '.cfg', '.conf', '.properties', '.xml', '.html', '.htm', '.css', '.scss',
  '.md', '.mdx', '.txt', '.rst', '.rules', '.sh', '.bash', '.ps1', '.bat', '.env', '.gradle',
  '.lock', '.tf', '.hcl', '.config', '.jinja', '.j2', '.twig', '.ejs', '.hbs',
  '.pem', '.key', '.p8', '.asc', '.crt', '.cer',
]);

const TEXT_FILENAMES = new Set([
  'dockerfile', 'makefile', 'procfile', 'gemfile', 'license', 'licence', 'copying', 'notice',
  'readme', 'codeowners', '.gitignore', '.dockerignore', '.npmrc', '.nvmrc', '.htaccess',
  '.editorconfig', '.prohoriignore', '.cursorrules', '.windsurfrules',
]);

export const LOCKFILE_NAMES = new Set([
  'package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lock',
  'composer.lock', 'poetry.lock', 'pipfile.lock', 'packages.lock.json', 'cargo.lock',
  'gemfile.lock', 'go.sum',
]);

/** Normalises to a relative, forward-slash path. Returns null for paths that escape the root. */
export function normalizePath(p: string): string | null {
  const parts = p.replace(/\\/g, '/').split('/').filter((s) => s !== '' && s !== '.');
  if (parts.some((s) => s === '..')) return null;
  return parts.join('/');
}

export function isTextPath(relPath: string): boolean {
  const base = path.posix.basename(relPath).toLowerCase();
  if (base.startsWith('.env')) return true;
  if (TEXT_FILENAMES.has(base)) return true;
  if (base.endsWith('.min.js') || base.endsWith('.min.css') || base.endsWith('.map')) return false;
  return TEXT_EXTENSIONS.has(path.posix.extname(base));
}

/** True when a path (relative, any slash style) would be read by a scan: inside the root, not in an ignored folder, text. */
export function shouldLoadPath(rawPath: string): boolean {
  const rel = normalizePath(rawPath);
  if (!rel) return false;
  if (rel.split('/').slice(0, -1).some((d) => IGNORED_DIRS.has(d))) return false;
  return isTextPath(rel);
}

function looksBinary(bytes: Uint8Array): boolean {
  const n = Math.min(bytes.length, 8000);
  for (let i = 0; i < n; i++) if (bytes[i] === 0) return true;
  return false;
}

interface LoadState {
  files: ProjectFile[];
  paths: Set<string>;
  skipped: number;
  truncated: boolean;
  totalBytes: number;
}

const decoder = new TextDecoder('utf-8');
const encoder = new TextEncoder();

function maxBytesFor(relPath: string, limits: ScanLimits): number {
  return LOCKFILE_NAMES.has(path.posix.basename(relPath).toLowerCase())
    ? limits.maxLockfileBytes
    : limits.maxFileBytes;
}

function accept(state: LoadState, limits: ScanLimits, relPath: string, bytes: Uint8Array): void {
  if (state.files.length >= limits.maxFiles) {
    state.truncated = true;
    state.skipped++;
    return;
  }
  if (bytes.length > maxBytesFor(relPath, limits)) {
    state.skipped++;
    return;
  }
  if (state.totalBytes + bytes.length > limits.maxTotalBytes) {
    state.truncated = true;
    state.skipped++;
    return;
  }
  if (looksBinary(bytes)) {
    state.skipped++;
    return;
  }
  state.totalBytes += bytes.length;
  state.files.push({ path: relPath, content: decoder.decode(bytes), size: bytes.length });
}

function newState(): LoadState {
  return { files: [], paths: new Set(), skipped: 0, truncated: false, totalBytes: 0 };
}

function finish(state: LoadState): LoadResult {
  state.files.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return { ...state };
}

/** Reads a project folder into memory. Never follows symbolic links. */
export async function loadDirectory(
  root: string,
  options: { limits?: Partial<ScanLimits>; respectGitignore?: boolean } = {},
): Promise<LoadResult> {
  const limits = { ...DEFAULT_LIMITS, ...options.limits };
  const state = newState();
  let matcher: IgnoreMatcher | null = null;
  if (options.respectGitignore !== false) {
    try {
      matcher = parseGitignore(await readFile(path.join(root, '.gitignore'), 'utf8'));
    } catch {
      matcher = null;
    }
  }

  async function walk(dirAbs: string, dirRel: string): Promise<void> {
    let entries;
    try {
      entries = await readdir(dirAbs, { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const entry of entries) {
      if (state.files.length >= limits.maxFiles) {
        state.truncated = true;
        return;
      }
      const rel = dirRel ? `${dirRel}/${entry.name}` : entry.name;
      if (entry.isSymbolicLink()) {
        state.skipped++;
        continue;
      }
      if (entry.isDirectory()) {
        if (IGNORED_DIRS.has(entry.name)) continue;
        if (matcher?.ignores(rel, true)) continue;
        await walk(path.join(dirAbs, entry.name), rel);
        continue;
      }
      if (!entry.isFile()) continue;
      if (matcher?.ignores(rel, false)) continue;
      state.paths.add(rel);
      if (!isTextPath(rel)) {
        state.skipped++;
        continue;
      }
      const abs = path.join(dirAbs, entry.name);
      const info = await lstat(abs);
      if (info.size > maxBytesFor(rel, limits)) {
        state.skipped++;
        continue;
      }
      accept(state, limits, rel, await readFile(abs));
    }
  }

  await walk(root, '');
  return finish(state);
}

/** Loads in-memory entries, for example from an unzipped upload. Nothing is written to disk. */
export function loadEntries(
  entries: Iterable<readonly [string, string | Uint8Array]>,
  options: { limits?: Partial<ScanLimits> } = {},
): LoadResult {
  const limits = { ...DEFAULT_LIMITS, ...options.limits };
  const state = newState();
  for (const [rawPath, data] of entries) {
    if (rawPath.endsWith('/')) continue;
    const rel = normalizePath(rawPath);
    if (!rel || state.paths.has(rel)) {
      state.skipped++;
      continue;
    }
    const dirs = rel.split('/').slice(0, -1);
    if (dirs.some((d) => IGNORED_DIRS.has(d))) continue;
    state.paths.add(rel);
    if (!isTextPath(rel)) {
      state.skipped++;
      continue;
    }
    accept(state, limits, rel, typeof data === 'string' ? encoder.encode(data) : data);
  }
  return finish(state);
}

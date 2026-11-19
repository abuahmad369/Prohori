import { shouldLoadPath } from '@prohori/audit-engine';
import { unzipSync } from 'fflate';
import { UserError } from './errors';

const MAX_ENTRIES = 20_000;
const MAX_FILE_BYTES = 1_000_000;
const MAX_LOCKFILE_BYTES = 10_000_000;
const MAX_TOTAL_BYTES = 60_000_000;
const LOCKFILE_RE = /(^|[/\\])(package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock|composer\.lock|poetry\.lock|pipfile\.lock)$/i;

/**
 * Unzips a project in memory. Nothing is written to disk, so entry names can't escape a folder.
 * Only files a scan would read are decompressed, within count and size limits.
 */
export function unzipProject(data: Uint8Array): Array<[string, Uint8Array]> {
  let seen = 0;
  let total = 0;
  let files: Record<string, Uint8Array>;
  try {
    files = unzipSync(data, {
      filter(file) {
        if (file.name.endsWith('/')) return false;
        seen++;
        if (seen > MAX_ENTRIES || !shouldLoadPath(file.name)) return false;
        const max = LOCKFILE_RE.test(file.name) ? MAX_LOCKFILE_BYTES : MAX_FILE_BYTES;
        if (file.originalSize > max || total + file.originalSize > MAX_TOTAL_BYTES) return false;
        total += file.originalSize;
        return true;
      },
    });
  } catch {
    throw new UserError('That file is not a valid zip archive.');
  }

  let entries = Object.entries(files)
    .map(([name, bytes]): [string, Uint8Array] => [name.replace(/\\/g, '/'), bytes])
    .filter(([, bytes]) => bytes.byteLength <= MAX_LOCKFILE_BYTES);

  // Archives often wrap everything in one folder (GitHub always does). Drop it so paths start at the project root.
  const tops = new Set(entries.map(([name]) => (name.includes('/') ? name.slice(0, name.indexOf('/')) : '')));
  const only = [...tops][0];
  if (tops.size === 1 && only) entries = entries.map(([name, bytes]) => [name.slice(only.length + 1), bytes]);

  if (entries.length === 0) throw new UserError('No source files were found in the archive.');
  return entries;
}

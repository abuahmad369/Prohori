import { UserError } from './errors';

const MAX_ZIP_BYTES = 40 * 1024 * 1024;
const OWNER = '[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})';
const REPO = '[A-Za-z0-9._-]{1,100}?';
const URL_RE = new RegExp(`^(?:https?://)?(?:www\\.)?github\\.com/(${OWNER})/(${REPO})(?:\\.git)?/?(?:[?#].*)?$`, 'i');
const SHORT_RE = new RegExp(`^(${OWNER})/(${REPO})$`);

/**
 * Accepts "https://github.com/owner/repo" or "owner/repo". Only github.com is allowed, and the
 * download URL is built here from the validated parts, so user input never chooses the host (no SSRF).
 */
export function parseGithubRepo(input: string): { owner: string; repo: string } | null {
  const value = input.trim();
  const m = URL_RE.exec(value) ?? SHORT_RE.exec(value);
  if (!m) return null;
  const owner = m[1] as string;
  const repo = (m[2] as string).replace(/\.git$/i, '');
  if (!repo || repo === '.' || repo === '..') return null;
  return { owner, repo };
}

/** Downloads the default branch of a public repository as a zip, with a size limit. */
export async function downloadGithubZip(owner: string, repo: string): Promise<Uint8Array> {
  const headers: Record<string, string> = {
    'User-Agent': 'prohori-scanner',
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;

  let response: Response;
  try {
    response = await fetch(`https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/zipball`, {
      headers,
      redirect: 'follow',
      signal: AbortSignal.timeout(45_000),
    });
  } catch {
    throw new UserError('Could not reach GitHub. Check the connection and try again.', 502);
  }
  if (response.status === 404) throw new UserError('Repository not found. Prohori can scan public repositories only, for now.', 404);
  if (response.status === 403 || response.status === 429) {
    throw new UserError('GitHub is limiting requests right now. Try again later, or upload the project as a zip.', 429);
  }
  if (!response.ok || !response.body) throw new UserError(`GitHub returned an error (${response.status}).`, 502);
  if (Number(response.headers.get('content-length') ?? 0) > MAX_ZIP_BYTES) {
    throw new UserError('This repository is over 40 MB. Use the command-line tool for large projects.', 413);
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_ZIP_BYTES) {
      await reader.cancel();
      throw new UserError('This repository is over 40 MB. Use the command-line tool for large projects.', 413);
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}

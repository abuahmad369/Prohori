import path from 'node:path';
import type { Confidence, ProjectFile, RawFinding, ScanContext, Severity } from '../types.ts';
import { maskSecrets } from './secret-patterns.ts';

export const JS_EXTS = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.mts', '.cts', '.vue', '.svelte', '.astro'];
export const PY_EXTS = ['.py'];
export const PHP_EXTS = ['.php'];
export const CS_EXTS = ['.cs'];
export const GO_EXTS = ['.go'];
export const CODE_EXTS = new Set([...JS_EXTS, ...PY_EXTS, ...PHP_EXTS, ...CS_EXTS, ...GO_EXTS, '.rb', '.rs', '.java', '.kt', '.dart', '.swift']);

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
export const severityRank = (s: Severity): number => SEVERITY_ORDER.indexOf(s);

export const extOf = (p: string): string => path.posix.extname(p).toLowerCase();
export const baseOf = (p: string): string => path.posix.basename(p);

export function isTestPath(p: string): boolean {
  return /(^|\/)(__tests__|__mocks__|tests?|spec|specs|fixtures?|mocks?|e2e|cypress|playwright|testdata)(\/|$)|\.(test|spec|e2e)\.[a-z0-9]+$/i.test(p);
}

export function isDocPath(p: string): boolean {
  return /\.(md|mdx|txt|rst)$/i.test(p) || /(^|\/)(license|licence|copying|notice)$/i.test(p);
}

export function isEnvFile(p: string): boolean {
  return /(^|\/)\.env(?:\.[\w.-]+)?$/i.test(p);
}

export function isExampleEnv(p: string): boolean {
  return /(^|\/)\.env(?:\.[\w-]+)*\.(example|sample|template|dist|defaults|test)$/i.test(p) || /(^|\/)(example|sample)\.env$/i.test(p);
}

export function shannon(s: string): number {
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Replaces string literals with empty ones, so keyword checks only see code. */
export function stripStrings(code: string): string {
  return code.replace(/(['"`])(?:\\.|(?!\1)[^\\\n])*\1/g, '""');
}

const LINE_STARTS = new WeakMap<ProjectFile, number[]>();

function lineStarts(file: ProjectFile): number[] {
  let starts = LINE_STARTS.get(file);
  if (!starts) {
    starts = [0];
    const c = file.content;
    for (let i = 0; i < c.length; i++) if (c.charCodeAt(i) === 10) starts.push(i + 1);
    LINE_STARTS.set(file, starts);
  }
  return starts;
}

export function lineOf(file: ProjectFile, index: number): number {
  const starts = lineStarts(file);
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if ((starts[mid] as number) <= index) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1;
}

export function lineText(file: ProjectFile, line: number): string {
  const starts = lineStarts(file);
  const start = starts[line - 1];
  if (start === undefined) return '';
  const next = starts[line];
  const end = next === undefined ? file.content.length : next - 1;
  return file.content.slice(start, end).replace(/\r$/, '');
}

/**
 * True when a position is in code: not inside a string literal or after a line comment on the same line.
 * Line-local by design; multi-line strings and comments are not tracked.
 */
export function isInCode(file: ProjectFile, index: number): boolean {
  const line = lineOf(file, index);
  const text = lineText(file, line);
  const col = index - (lineStarts(file)[line - 1] ?? 0);
  const hashComments = /\.(py|rb|php|sh)$/i.test(file.path);
  let quote: string | null = null;
  for (let i = 0; i < col && i < text.length; i++) {
    const ch = text[i];
    if (quote) {
      if (ch === '\\') i++;
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') quote = ch;
    else if (ch === '/' && text[i + 1] === '/') return false;
    else if (hashComments && ch === '#') return false;
  }
  return quote === null;
}

export function snippetAt(file: ProjectFile, index: number): string {
  const line = lineOf(file, index);
  const text = lineText(file, line);
  const col = index - (lineStarts(file)[line - 1] ?? 0);
  let out = text;
  if (text.length > 180) {
    const start = Math.max(0, col - 60);
    out = (start > 0 ? '…' : '') + text.slice(start, start + 160) + (start + 160 < text.length ? '…' : '');
  }
  return maskSecrets(out.trim());
}

export interface FindingExtra {
  message?: string;
  severity?: Severity;
  confidence?: Confidence;
}

/** A finding pointing at a character position in a file, with a masked snippet. */
export function at(file: ProjectFile, index: number, extra: FindingExtra = {}): RawFinding {
  const finding: RawFinding = { file: file.path, line: lineOf(file, index), snippet: snippetAt(file, index) };
  if (extra.message) finding.message = extra.message;
  if (extra.severity) finding.severity = extra.severity;
  if (extra.confidence) finding.confidence = extra.confidence;
  return finding;
}

/** Iterates all matches with a private copy of the regex, so callers never share lastIndex. */
export function* matches(content: string, re: RegExp): Generator<RegExpExecArray> {
  const g = new RegExp(re.source, re.flags.includes('g') ? re.flags : `${re.flags}g`);
  let m: RegExpExecArray | null;
  while ((m = g.exec(content)) !== null) {
    yield m;
    if (m[0].length === 0) g.lastIndex++;
  }
}

export function hasDirective(file: ProjectFile, directive: 'use client' | 'use server'): boolean {
  return new RegExp(`^(?:\\s|//[^\\n]*|/\\*[\\s\\S]*?\\*/)*['"]${directive}['"]`).test(file.content.slice(0, 800));
}

export const NEXT_ROUTE_RE = /(^|\/)app\/(?:.*\/)?route\.(?:ts|js|mjs|tsx|jsx)$/;
export const PAGES_API_RE = /(^|\/)pages\/api\/.+\.(?:ts|js|mjs|tsx|jsx)$/;

export function hasExpressRoutes(content: string): boolean {
  return /\b(?:app|router|api|server|routes?|r)\.(?:get|post|put|patch|delete|all)\s*\(\s*['"`]\//.test(content);
}

export function hasPythonRoutes(content: string): boolean {
  return /@(?:app|router|bp|blueprint|api|\w+_bp)\.(?:route|get|post|put|patch|delete|api_route)\s*\(/.test(content);
}

/** A file that receives HTTP requests: route handlers, API routes, server actions, Express or Python routes. */
export function isEndpointFile(file: ProjectFile): boolean {
  const p = file.path;
  if (NEXT_ROUTE_RE.test(p) || PAGES_API_RE.test(p)) return true;
  if (/^api\/[^/]+\.(?:ts|js|mjs|cjs)$/.test(p)) return true;
  if (/(^|\/)(supabase\/functions|netlify\/functions|functions\/api)\//.test(p)) return true;
  if (/\.(?:[cm]?[jt]sx?)$/.test(p) && hasDirective(file, 'use server')) return true;
  if (/\.(?:[cm]?[jt]s)$/.test(p) && hasExpressRoutes(file.content)) return true;
  if (p.endsWith('.py') && hasPythonRoutes(file.content)) return true;
  return false;
}

export const AUTH_SIGNALS =
  /(?:\bauth\s*\(|getServerSession|getSession|currentUser|getUser|getAuth\b|requireAuth|requireUser|requireSession|verifySession|withAuth|isAuthenticated|ensureAuthenticated|verifyToken|verifyIdToken|jwtVerify|jwt\.verify|clerkClient|@clerk\/|session\.user|\breq\.user\b|\brequest\.user\b|\breq\.auth\b|\brequest\.auth\b|getToken|validateRequest|\blucia\b|\bauthenticate|\bauthorize|isAdmin|passport\.|unauthori[sz]ed|unauthenticated|status:\s*401|\b401\b|login_required|IsAuthenticated|get_current_user|\[Authorize|@Authorize|->middleware\(\s*['"]auth|Auth::check|Auth::user|auth\(\)->)/i;

export const RATE_LIMIT_SIGNALS =
  /rate[-_ ]?limit|ratelimit|limiter|throttl|slowDown|tokenBucket|leakyBucket|slowapi|flask[-_]limiter|EnableRateLimiting/i;

export const ROLE_SIGNALS =
  /\brole|isAdmin|is_admin|hasRole|hasPermission|\bcan\(|\bauthorize\b|permission|Gate::|abilit|is_superuser|isSuperuser|is_staff|requireAdmin|adminOnly|ensureAdmin|checkRole|@PreAuthorize|Authorize\(Roles/i;

export const VALIDATION_SIGNALS =
  /\bzod\b|\bz\.object|\byup\b|\bjoi\b|valibot|superstruct|class-validator|\.safeParse\(|\.parse\(|\bvalidate\(|\bajv\b|typebox|pydantic|FormRequest|\$request->validate|Validator::make/i;

/** Login, sign-up, callbacks and webhooks are meant to be reachable without a session. */
export const PUBLIC_FLOW_RE =
  /(^|[/_.-])(auth|login|logout|signin|sign-in|signup|sign-up|register|callback|oauth|webhooks?|forgot|reset|verify|otp|magic-link|health|healthz|ping|status|csp-report|cron)([/._-]|$)/i;

export function usesEnvVars(ctx: ScanContext): boolean {
  return ctx.codeFiles.some((f) =>
    /process\.env\b|import\.meta\.env\b|os\.environ|os\.getenv|\bgetenv\(|\benv\(\s*['"]|Environment\.GetEnvironmentVariable|Deno\.env/.test(f.content),
  );
}

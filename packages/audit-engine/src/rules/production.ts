import type { RawFinding, Rule } from '../types.ts';
import {
  at,
  baseOf,
  CODE_EXTS,
  extOf,
  hasExpressRoutes,
  isEndpointFile,
  isEnvFile,
  isExampleEnv,
  isInCode,
  isTestPath,
  matches,
  RATE_LIMIT_SIGNALS,
  stripStrings,
} from './helpers.ts';
import { patternRule } from './pattern-rule.ts';

const debugEnabled: Rule = {
  id: 'production/debug-enabled',
  title: 'Debug mode turned on',
  category: 'production',
  severity: 'medium',
  cwe: 'CWE-489',
  description: 'Debug mode shows stack traces, configuration and sometimes secrets to anyone who triggers an error.',
  remediation: 'Turn debug off in production (DEBUG = False, APP_DEBUG=false, no debug=True in app.run) and read the setting from an environment variable.',
  check(ctx) {
    const out: RawFinding[] = [];
    for (const f of ctx.files) {
      if (isTestPath(f.path)) continue;
      const ext = extOf(f.path);
      if (baseOf(f.path) === 'settings.py' || /(^|\/)settings\/[\w-]+\.py$/.test(f.path)) {
        for (const m of matches(f.content, /^\s*DEBUG\s*=\s*True\b/gm)) out.push(at(f, m.index, { message: `DEBUG = True in ${f.path}.` }));
      }
      if (ext === '.py') {
        for (const m of matches(f.content, /\.run\([^)\n]*debug\s*=\s*True/g)) out.push(at(f, m.index, { message: 'The Flask app runs with debug=True.' }));
      }
      if (isEnvFile(f.path) && !isExampleEnv(f.path)) {
        for (const m of matches(f.content, /^\s*APP_DEBUG\s*=\s*true\b/gim)) out.push(at(f, m.index, { message: `APP_DEBUG=true in ${f.path}.` }));
      }
      if (ext === '.cs' && !/IsDevelopment\(\)/.test(f.content)) {
        const m = /UseDeveloperExceptionPage\(\)/.exec(f.content);
        if (m) out.push(at(f, m.index, { message: 'The developer exception page is enabled outside a development check.' }));
      }
    }
    return out;
  },
};

const ERROR_RESPONSE_RE =
  /\b(?:res\.(?:status\(\s*\d+\s*\)\.)?(?:json|send)|NextResponse\.json|Response\.json|c\.json|reply\.send)\s*\([^)\n]*\b(?:err|error|e|ex|exception)\.(stack|message)\b/g;

const errorDetailsLeaked: Rule = {
  id: 'production/error-details-leaked',
  title: 'Error details sent to users',
  category: 'production',
  severity: 'low',
  cwe: 'CWE-209',
  description: 'Raw error messages or stack traces are returned to the client, which reveals file paths, queries and library versions to attackers.',
  remediation: 'Log the full error on the server and return a short generic message with a request id the user can quote to support.',
  check(ctx) {
    const out: RawFinding[] = [];
    for (const f of ctx.codeFiles) {
      if (isTestPath(f.path)) continue;
      for (const m of matches(f.content, ERROR_RESPONSE_RE)) {
        const stack = m[1] === 'stack';
        out.push(at(f, m.index, { severity: stack ? 'medium' : 'low', message: stack ? 'A stack trace is sent in the response.' : 'A raw error message is sent in the response.' }));
      }
      for (const m of matches(f.content, /->getTraceAsString\(\)|traceback\.format_exc\(\)/g)) {
        out.push(at(f, m.index, { severity: 'medium', message: 'A stack trace may be sent in the response.' }));
      }
    }
    return out;
  },
};

const LOG_CALL_RE =
  /\b(?:console\.(?:log|info|debug|warn|error)|print|logger\.(?:info|debug|warn|warning|error)|logging\.(?:info|debug|warning|error)|Log::(?:info|debug|error|warning))\s*\(([^\n]*)\)/g;
const SENSITIVE_NAME_RE =
  /\b(?:password|passwd|secret|api_?key|apikey|access_?token|refresh_?token|auth_?token|authorization|credit_?card|card_?number|cvv)\b/i;

const sensitiveLogging: Rule = {
  id: 'production/sensitive-logging',
  title: 'Secrets or passwords written to logs',
  category: 'production',
  severity: 'medium',
  cwe: 'CWE-532',
  description: 'A log statement prints a password, token or key. Logs are kept for a long time and read by many tools and people.',
  remediation: 'Remove the value from the log, or log only a masked version (for example the last four characters).',
  check(ctx) {
    const out: RawFinding[] = [];
    for (const f of ctx.codeFiles) {
      if (isTestPath(f.path)) continue;
      for (const m of matches(f.content, LOG_CALL_RE)) {
        if (!isInCode(f, m.index)) continue;
        if (SENSITIVE_NAME_RE.test(stripStrings(m[1] as string))) out.push(at(f, m.index, { message: 'A sensitive value is passed to a log call.' }));
      }
    }
    return out;
  },
};

const LOGIN_PATH_RE = /(^|[/_.-])(login|signin|sign-in|signup|sign-up|register|otp|forgot|reset-password|verify-code|magic-link)([/_.-]|$)/i;
const LOGIN_ROUTE_RE = /['"`]\/(?:api\/)?(?:auth\/)?(?:login|signin|signup|register|otp|forgot-password|reset-password)\b/i;

const noRateLimitOnLogin: Rule = {
  id: 'production/no-login-rate-limit',
  title: 'Login endpoint without a rate limit',
  category: 'production',
  severity: 'low',
  cwe: 'CWE-307',
  description: 'Login, sign-up or one-time-code endpoints accept unlimited attempts, which allows password guessing and SMS or email bombing.',
  remediation: 'Limit attempts per IP and per account (for example 5 per minute) with a rate limiter or Laravel throttle middleware.',
  check(ctx) {
    const out: RawFinding[] = [];
    for (const f of ctx.codeFiles) {
      if (isTestPath(f.path) || !isEndpointFile(f)) continue;
      if (!LOGIN_PATH_RE.test(f.path) && !LOGIN_ROUTE_RE.test(f.content)) continue;
      if (RATE_LIMIT_SIGNALS.test(f.content)) continue;
      out.push({ file: f.path, line: 1, message: `Login-related endpoint ${f.path} has no rate limit.` });
    }
    for (const f of ctx.files) {
      if (!/(^|\/)routes\/(web|api|auth)\.php$/.test(f.path)) continue;
      if (/['"](?:\/)?(?:login|register|forgot-password)['"]/.test(f.content) && !/throttle/.test(f.content)) {
        out.push({ file: f.path, line: 1, message: `Login routes in ${f.path} have no throttle middleware.` });
      }
    }
    return out;
  },
};

const missingSecurityHeaders: Rule = {
  id: 'production/missing-security-headers',
  title: 'No security headers configured',
  category: 'production',
  severity: 'low',
  cwe: 'CWE-693',
  description: 'The app does not set browser security headers such as Content-Security-Policy and X-Frame-Options, which limit the damage of injection and clickjacking.',
  remediation: 'Next.js: return the headers from headers() in next.config. Express: add helmet(). Start with X-Frame-Options, X-Content-Type-Options, Referrer-Policy and a Content-Security-Policy.',
  check(ctx) {
    const out: RawFinding[] = [];
    if (ctx.stacks.has('nextjs')) {
      const configs = ctx.files.filter((f) => /(^|\/)next\.config\.(?:js|mjs|cjs|ts)$/.test(f.path));
      const middleware = ctx.files.filter((f) => /(^|\/)(?:src\/)?(?:middleware|proxy)\.(?:ts|js)$/.test(f.path));
      const vercel = ctx.byPath.get('vercel.json');
      const configured =
        configs.some((f) => /headers\s*\(|Content-Security-Policy|X-Frame-Options/.test(f.content)) ||
        middleware.some((f) => /Content-Security-Policy|X-Frame-Options|Strict-Transport-Security/.test(f.content)) ||
        Boolean(vercel && /"headers"/.test(vercel.content));
      if (!configured) {
        const first = configs[0];
        out.push(first ? { file: first.path, line: 1, message: 'next.config sets no security headers.' } : { message: 'The Next.js app sets no security headers.' });
      }
    }
    if (ctx.stacks.has('express') && ctx.codeFiles.some((f) => hasExpressRoutes(f.content)) && !ctx.codeFiles.some((f) => /\bhelmet\b/.test(f.content))) {
      out.push({ message: 'The Express server does not use helmet or set security headers.' });
    }
    return out;
  },
};

const imageProxyWildcard = patternRule({
  id: 'production/image-proxy-wildcard',
  title: 'Image optimiser accepts any host',
  category: 'production',
  severity: 'low',
  cwe: 'CWE-918',
  description: "next/image is allowed to fetch and resize images from any host, so others can use your server's bandwidth and image quota.",
  remediation: 'List the exact hosts your images come from in images.remotePatterns.',
  patterns: [
    {
      re: /hostname\s*:\s*['"]\*\*['"]|domains\s*:\s*\[\s*['"]\*['"]/g,
      files: (p) => /(^|\/)next\.config\.(?:js|mjs|cjs|ts)$/.test(p),
      message: 'images.remotePatterns allows every host.',
    },
  ],
});

const WEAK_PASSWORDS = '(?:admin|admin123|password|password1|password123|123456|12345678|changeme|secret|root|qwerty|letmein|welcome1?)';

const defaultCredentials = patternRule({
  id: 'production/default-credentials',
  title: 'Default or weak password in the code',
  category: 'production',
  severity: 'medium',
  cwe: 'CWE-1393',
  description: 'An account is created or configured with a well-known password such as "admin123". Attackers try these first.',
  remediation: 'Generate a random password at setup time or require one through an environment variable, and force a change on first login.',
  skipTests: true,
  patterns: [
    {
      re: new RegExp(`\\b(?:password|passwd|pwd|admin_?pass(?:word)?)['"]?\\s*[:=]\\s*['"]${WEAK_PASSWORDS}['"]`, 'gi'),
      files: (p) => CODE_EXTS.has(extOf(p)) || ['.json', '.yml', '.yaml'].includes(extOf(p)),
      message: 'A well-known default password is set.',
      inStrings: true,
    },
    {
      re: new RegExp(`^\\s*[A-Z_]*PASS(?:WORD)?\\s*=\\s*${WEAK_PASSWORDS}\\s*$`, 'gim'),
      files: (p) => isEnvFile(p) && !isExampleEnv(p),
      message: 'A well-known default password is set in an environment file.',
      inStrings: true,
    },
  ],
});

export const productionRules: Rule[] = [
  debugEnabled,
  errorDetailsLeaked,
  sensitiveLogging,
  noRateLimitOnLogin,
  missingSecurityHeaders,
  imageProxyWildcard,
  defaultCredentials,
];

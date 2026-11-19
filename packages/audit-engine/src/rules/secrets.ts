import { LOCKFILE_NAMES } from '../files.ts';
import { parseGitignore } from '../gitignore.ts';
import type { RawFinding, Rule } from '../types.ts';
import {
  at,
  baseOf,
  CODE_EXTS,
  extOf,
  isDocPath,
  isEnvFile,
  isExampleEnv,
  isTestPath,
  matches,
  shannon,
  usesEnvVars,
} from './helpers.ts';
import { JWT_RE, PRIVATE_KEY_RE, SECRET_PATTERNS } from './secret-patterns.ts';

const isLockfile = (p: string): boolean => LOCKFILE_NAMES.has(baseOf(p).toLowerCase());

const hardcodedCredential: Rule = {
  id: 'secrets/hardcoded-credential',
  title: 'API key or token in the code',
  category: 'secrets',
  severity: 'critical',
  cwe: 'CWE-798',
  description: 'A credential from a known provider is written into the project. Anyone who can read the code or the built app can use it.',
  remediation:
    'Revoke the key in the provider dashboard, create a new one, keep it in a server-side environment variable, and remove the old value from git history.',
  check(ctx) {
    const out: RawFinding[] = [];
    for (const file of ctx.files) {
      if (isLockfile(file.path)) continue;
      for (const p of SECRET_PATTERNS) {
        for (const m of matches(file.content, p.re)) {
          out.push(
            at(file, m.index, {
              severity: p.severity,
              confidence: isTestPath(file.path) ? 'medium' : 'high',
              message: `${p.name} found in ${file.path}.${p.note ? ` ${p.note}` : ''}`,
            }),
          );
        }
      }
    }
    return out;
  },
};

const privateKey: Rule = {
  id: 'secrets/private-key',
  title: 'Private key in the code',
  category: 'secrets',
  severity: 'critical',
  cwe: 'CWE-321',
  description: 'A private key (RSA, EC, SSH or PGP) is stored in the project.',
  remediation: 'Treat the key as compromised: replace it, store the new one in a secrets manager or environment variable, and purge the old one from git history.',
  check(ctx) {
    const out: RawFinding[] = [];
    for (const file of ctx.files) {
      if (isLockfile(file.path)) continue;
      for (const m of matches(file.content, PRIVATE_KEY_RE)) out.push(at(file, m.index, { message: `Private key found in ${file.path}.` }));
    }
    return out;
  },
};

function jwtRole(token: string): string | null {
  const payload = token.split('.')[1];
  if (!payload) return null;
  try {
    const json = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as { role?: unknown };
    return typeof json.role === 'string' ? json.role : null;
  } catch {
    return null;
  }
}

const serviceRoleKey: Rule = {
  id: 'secrets/service-role-key',
  title: 'Supabase service-role key in the code',
  category: 'secrets',
  severity: 'critical',
  cwe: 'CWE-798',
  description: 'A Supabase service-role key bypasses every row-level security rule. Whoever has it can read and change all data.',
  remediation: 'Rotate the service-role key in Supabase now, keep the new one only in server-side environment variables, and never ship it to the browser.',
  check(ctx) {
    const out: RawFinding[] = [];
    for (const file of ctx.files) {
      if (isLockfile(file.path)) continue;
      for (const m of matches(file.content, JWT_RE)) {
        if (jwtRole(m[0]) === 'service_role') out.push(at(file, m.index, { message: `Supabase service-role key found in ${file.path}.` }));
      }
    }
    return out;
  },
};

const DB_URL_RE =
  /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver):\/\/([^:\s/@'"`]+):([^@\s'"`]+)@([^\s'"`/:?]+)/g;
const PLACEHOLDER_PASSWORD = /^(?:password|pass|passwd|pwd|secret|changeme|example|your[_-]?password|<.*>|\*+|x+|\.\.\.|\[.*\])$/i;
const LOCAL_HOST = /^(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1|host\.docker\.internal|db|database|postgres|postgresql|mysql|mariadb|mongo|mongodb|redis|rabbitmq)$/i;

const dbUrlWithPassword: Rule = {
  id: 'secrets/db-url-with-password',
  title: 'Database password in a connection string',
  category: 'secrets',
  severity: 'high',
  cwe: 'CWE-798',
  description: 'A database connection string with a username and password is written into the project.',
  remediation: 'Move the connection string to an environment variable, change the database password, and restrict database access by network.',
  check(ctx) {
    const out: RawFinding[] = [];
    for (const file of ctx.files) {
      if (isLockfile(file.path) || isDocPath(file.path) || isExampleEnv(file.path)) continue;
      for (const m of matches(file.content, DB_URL_RE)) {
        const password = m[2] as string;
        const host = m[3] as string;
        if (PLACEHOLDER_PASSWORD.test(password) || password.startsWith('$') || password.startsWith('%')) continue;
        const local = LOCAL_HOST.test(host);
        out.push(
          at(file, m.index, {
            severity: local ? 'low' : 'high',
            message: local
              ? `Connection string with a password for a local or Docker database (${host}). Fine for development; keep production credentials out of the code.`
              : `Connection string with a password for ${host}.`,
          }),
        );
      }
    }
    return out;
  },
};

const GENERIC_RE =
  /\b([A-Za-z0-9_]*?(?:secret|password|passwd|pwd|api_?key|apikey|access_?key|auth_?token|private_?key|client_?secret)[A-Za-z0-9_]*)['"]?\s*[:=]\s*(['"`])([^'"`\s]{8,200})\2/gi;
const NAME_EXCLUDE =
  /(label|placeholder|field|name|header|type|url|uri|path|route|regex|pattern|message|msg|text|title|hint|selector|class|style|length|min|max|policy|reset|confirm|input|column|param|hash|hashed|digest|salt|rounds|env|var|ref|id)$/i;
const PLACEHOLDER_VALUE =
  /^(?:your|<|\$\{|\{\{|%|process\.env|import\.meta|env\(|getenv|os\.environ|xxx|\*{3}|changeme|change_me|example|sample|dummy|placeholder|redacted|todo|replace|insert|enter|fake|test|none|null|undefined|secret|password|sk_test_|pk_)/i;
export const DEFAULT_PASSWORDS = new Set([
  'admin', 'admin123', 'password', 'password1', 'password123', '123456', '12345678', '123456789',
  'changeme', 'secret', 'root', 'qwerty', 'letmein', 'welcome', 'welcome1',
]);

function looksLikeSecret(value: string): boolean {
  // URLs, env var names and regex patterns are not secrets.
  if (value.includes('://') || /^[A-Z][A-Z0-9_]+$/.test(value) || /[|\\]|\(\?/.test(value)) return false;
  if (new Set(value).size < 4) return false;
  const letters = /[A-Za-z]/.test(value);
  const digits = /\d/.test(value);
  return (letters && digits && value.length >= 10) || (value.length >= 12 && shannon(value) >= 3.5);
}

const genericSecret: Rule = {
  id: 'secrets/generic-secret',
  title: 'Password or secret written in the code',
  category: 'secrets',
  severity: 'high',
  confidence: 'medium',
  cwe: 'CWE-798',
  description: 'A value assigned to a secret-looking name (password, apiKey, clientSecret and similar) is written directly in the code.',
  remediation: 'Read the value from an environment variable or a secrets manager instead, and rotate it if it was ever pushed to a shared repository.',
  check(ctx) {
    const out: RawFinding[] = [];
    for (const file of ctx.files) {
      const p = file.path;
      if (isLockfile(p) || isDocPath(p) || isExampleEnv(p) || isTestPath(p)) continue;
      for (const m of matches(file.content, GENERIC_RE)) {
        const name = m[1] as string;
        const value = m[3] as string;
        if (NAME_EXCLUDE.test(name) || PLACEHOLDER_VALUE.test(value) || DEFAULT_PASSWORDS.has(value.toLowerCase())) continue;
        if (!looksLikeSecret(value)) continue;
        out.push(at(file, m.index, { message: `"${name}" is set to a hard-coded value in ${p}.` }));
      }
    }
    return out;
  },
};

const ASSIGNMENT_RE = /^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*(.*)$/gm;

const envFileCommitted: Rule = {
  id: 'secrets/env-file-committed',
  title: 'Environment file included in the project',
  category: 'secrets',
  severity: 'high',
  cwe: 'CWE-538',
  description: 'A .env file with real values is part of the project, so everyone with access to the code also gets its secrets.',
  remediation: 'Delete the file from the repository and its history, add .env* to .gitignore (keep a .env.example with empty values), and rotate every secret it contained.',
  check(ctx) {
    const out: RawFinding[] = [];
    for (const file of ctx.files) {
      if (!isEnvFile(file.path) || isExampleEnv(file.path)) continue;
      let values = 0;
      for (const m of matches(file.content, ASSIGNMENT_RE)) {
        const value = (m[1] as string).trim().replace(/^['"]|['"]$/g, '');
        if (value && !PLACEHOLDER_VALUE.test(value)) values++;
      }
      out.push({
        file: file.path,
        line: 1,
        severity: values > 0 ? 'high' : 'low',
        message: values > 0 ? `${file.path} is included with ${values} filled-in value(s).` : `${file.path} is included, though its values are empty.`,
      });
    }
    return out;
  },
};

const PUBLIC_VAR_RE = /\b(NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_|NUXT_PUBLIC_|PUBLIC_|GATSBY_)([A-Z0-9_]+)\b/g;

function isSecretName(rest: string): boolean {
  const strong = /SECRET|SERVICE_ROLE|SERVICE_KEY|PRIVATE_KEY|PASSWORD|DATABASE_URL|DB_URL|ADMIN_(?:KEY|TOKEN)/;
  if (strong.test(rest)) return true;
  if (/PUBLISHABLE|ANON|PUBLIC_KEY|SITE_KEY|_URL$|ENDPOINT|PROJECT_ID|APP_ID|DSN|MEASUREMENT|CLIENT_ID|REGION|MODEL|VERSION/.test(rest)) return false;
  return /(OPENAI|ANTHROPIC|CLAUDE|GROQ|GEMINI|DEEPSEEK|MISTRAL|REPLICATE|COHERE|TOGETHER|XAI|PERPLEXITY|ELEVENLABS|HUGGINGFACE|SENDGRID|RESEND|MAILGUN|POSTMARK|TWILIO|AWS)[A-Z0-9_]*(KEY|TOKEN)/.test(rest);
}

const publicEnvSecret: Rule = {
  id: 'secrets/public-env-secret',
  title: 'Secret exposed through a browser-visible variable',
  category: 'secrets',
  severity: 'critical',
  cwe: 'CWE-200',
  description:
    'Variables starting with NEXT_PUBLIC_, VITE_, EXPO_PUBLIC_, REACT_APP_ or PUBLIC_ are copied into the JavaScript sent to every visitor. A secret placed there is public.',
  remediation:
    'Rename the variable without the public prefix, use it only in server code (API routes, server actions, edge functions), and rotate the value because it has already been shipped.',
  check(ctx) {
    const out: RawFinding[] = [];
    for (const file of ctx.files) {
      const p = file.path;
      if (isLockfile(p) || isDocPath(p)) continue;
      if (!CODE_EXTS.has(extOf(p)) && !isEnvFile(p) && !['.json', '.yml', '.yaml', '.toml'].includes(extOf(p)) && baseOf(p).toLowerCase() !== 'dockerfile') continue;
      const seen = new Set<string>();
      for (const m of matches(file.content, PUBLIC_VAR_RE)) {
        const full = m[0];
        if (seen.has(full) || !isSecretName(m[2] as string)) continue;
        seen.add(full);
        out.push(at(file, m.index, { message: `${full} looks like a secret but is exposed to the browser.` }));
      }
    }
    return out;
  },
};

const AI_CLIENT_RE =
  /new\s+(?:OpenAI|Anthropic|Groq|Mistral|GoogleGenerativeAI|GoogleGenAI)\s*\(|\bcreate(?:OpenAI|Anthropic|Groq|Mistral)\s*\(/g;

const clientSideAiKey: Rule = {
  id: 'secrets/client-side-ai-key',
  title: 'AI provider called straight from browser code',
  category: 'secrets',
  severity: 'high',
  cwe: 'CWE-522',
  description: 'Calling an AI provider from the browser means the API key travels to every visitor, who can then use your account and your budget.',
  remediation: 'Move the AI call into a server route that checks the user and applies a rate limit, and keep the API key in a server-side environment variable.',
  check(ctx) {
    const out: RawFinding[] = [];
    for (const file of ctx.codeFiles) {
      for (const m of matches(file.content, /dangerouslyAllowBrowser\s*:\s*true/g)) {
        out.push(at(file, m.index, { message: `dangerouslyAllowBrowser is enabled in ${file.path}, so the AI API key is sent to the browser.` }));
      }
      if (!ctx.isClientFile(file)) continue;
      for (const m of matches(file.content, AI_CLIENT_RE)) {
        out.push(at(file, m.index, { message: `An AI client is created in browser code (${file.path}).` }));
      }
    }
    return out;
  },
};

const envNotIgnored: Rule = {
  id: 'secrets/env-not-ignored',
  title: '.env files are not excluded from git',
  category: 'secrets',
  severity: 'low',
  cwe: 'CWE-538',
  description: 'The project reads environment variables, but .gitignore does not exclude .env files, so secrets can be committed by accident.',
  remediation: 'Add .env and .env.* to .gitignore, and keep a .env.example with empty values for other developers.',
  check(ctx) {
    if (!usesEnvVars(ctx) && !ctx.files.some((f) => isEnvFile(f.path))) return [];
    const gitignore = ctx.byPath.get('.gitignore');
    if (!gitignore) return [{ message: 'The project reads environment variables but has no .gitignore.' }];
    if (!parseGitignore(gitignore.content).ignores('.env', false)) {
      return [{ file: '.gitignore', line: 1, message: '.gitignore does not exclude .env files.' }];
    }
    return [];
  },
};

export const secretRules: Rule[] = [
  hardcodedCredential,
  privateKey,
  serviceRoleKey,
  dbUrlWithPassword,
  genericSecret,
  envFileCommitted,
  publicEnvSecret,
  clientSideAiKey,
  envNotIgnored,
];

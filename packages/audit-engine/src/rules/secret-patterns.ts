import type { Severity } from '../types.ts';

export interface SecretPattern {
  id: string;
  name: string;
  re: RegExp;
  severity: Severity;
  note?: string;
}

/** Provider credentials with a recognisable shape. Order matters only for readability. */
export const SECRET_PATTERNS: SecretPattern[] = [
  { id: 'aws-access-key', name: 'AWS access key ID', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, severity: 'critical' },
  { id: 'stripe-live', name: 'Stripe live secret key', re: /\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}/g, severity: 'critical' },
  { id: 'stripe-test', name: 'Stripe test secret key', re: /\bsk_test_[0-9a-zA-Z]{20,}/g, severity: 'medium' },
  { id: 'anthropic', name: 'Anthropic API key', re: /\bsk-ant-[A-Za-z0-9_-]{20,}/g, severity: 'critical' },
  { id: 'openai', name: 'OpenAI API key', re: /\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}/g, severity: 'critical' },
  { id: 'github', name: 'GitHub token', re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})/g, severity: 'critical' },
  { id: 'npm', name: 'npm access token', re: /\bnpm_[A-Za-z0-9]{36}\b/g, severity: 'critical' },
  { id: 'slack', name: 'Slack token', re: /\bxox[abprs]-[A-Za-z0-9-]{10,}/g, severity: 'high' },
  { id: 'sendgrid', name: 'SendGrid API key', re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g, severity: 'high' },
  { id: 'twilio', name: 'Twilio API key', re: /\bSK[0-9a-fA-F]{32}\b/g, severity: 'high' },
  { id: 'huggingface', name: 'Hugging Face token', re: /\bhf_[A-Za-z0-9]{30,}\b/g, severity: 'high' },
  { id: 'groq', name: 'Groq API key', re: /\bgsk_[A-Za-z0-9]{40,}\b/g, severity: 'high' },
  {
    id: 'google',
    name: 'Google API key',
    re: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    severity: 'low',
    note: 'Google keys in Firebase web config are public by design. Restrict this key to your domains and APIs in Google Cloud Console.',
  },
];

export const PRIVATE_KEY_RE = /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g;
export const JWT_RE = /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;

const URL_PASSWORD_RE = /(:\/\/[^:\s/@'"]+:)([^@\s'"]+)(@)/g;
const GENERIC_VALUE_RE =
  /((?:secret|password|passwd|pwd|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret)[A-Za-z0-9_]*['"]?\s*[:=]\s*['"`]?)([^'"`\s,;)]{6,})/gi;

export function mask(value: string): string {
  return value.length <= 8 ? '••••' : `${value.slice(0, 4)}…`;
}

/** Hides anything that looks like a credential so reports never carry a usable secret. */
export function maskSecrets(text: string): string {
  let out = text;
  for (const p of SECRET_PATTERNS) out = out.replace(p.re, (m) => mask(m));
  out = out.replace(JWT_RE, (m) => mask(m));
  out = out.replace(URL_PASSWORD_RE, (_m, prefix: string, password: string, at: string) => `${prefix}${mask(password)}${at}`);
  out = out.replace(GENERIC_VALUE_RE, (_m, key: string, value: string) => `${key}${mask(value)}`);
  return out;
}

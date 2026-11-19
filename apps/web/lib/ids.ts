import { randomBytes } from 'node:crypto';

// 32 characters, so each random byte maps without bias. No l, o, 0 or 1 to avoid confusion.
const ALPHABET = 'abcdefghijkmnpqrstuvwxyz23456789';

export function newId(length = 12): string {
  let out = '';
  for (const byte of randomBytes(length)) out += ALPHABET[byte % ALPHABET.length];
  return out;
}

export const isId = (value: string): boolean => /^[a-z0-9]{6,40}$/.test(value);

export function slugify(title: string): string {
  return (
    title
      .toLowerCase()
      .normalize('NFKD')
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 60) || 'app'
  );
}

export const isSlug = (value: string): boolean => /^[a-z0-9-]{1,80}$/.test(value);

/** A licence key buyers can quote to support: PRH-XXXX-XXXX-XXXX-XXXX. */
export function licenseKey(): string {
  const raw = newId(16).toUpperCase();
  return `PRH-${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}-${raw.slice(12, 16)}`;
}

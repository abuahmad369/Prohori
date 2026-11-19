// In-memory sliding window per key. Good for one server process; Phase 1 moves this to a shared store.
const globalLimits = globalThis as typeof globalThis & { __prohoriRateLimits?: Map<string, number[]> };
const buckets = (globalLimits.__prohoriRateLimits ??= new Map<string, number[]>());

export function rateLimit(key: string, limit: number, windowMs = 60_000): { ok: boolean; retryAfter: number } {
  const now = Date.now();
  const recent = (buckets.get(key) ?? []).filter((t) => now - t < windowMs);
  if (recent.length >= limit) {
    buckets.set(key, recent);
    return { ok: false, retryAfter: Math.ceil((windowMs - (now - (recent[0] ?? now))) / 1000) };
  }
  recent.push(now);
  buckets.set(key, recent);
  return { ok: true, retryAfter: 0 };
}

export function clientIp(request: Request): string {
  return request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || request.headers.get('x-real-ip') || 'local';
}

export function tooManyRequests(retryAfter: number): Response {
  return Response.json({ error: 'Too many requests. Please wait a minute and try again.' }, { status: 429, headers: { 'Retry-After': String(retryAfter) } });
}

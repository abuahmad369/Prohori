import type { Dependency, Severity, VulnMatch } from '../types.ts';

const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch';
const OSV_VULN_URL = 'https://api.osv.dev/v1/vulns/';
const BATCH_SIZE = 1000;

interface OsvVuln {
  id?: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  database_specific?: { severity?: string };
  affected?: Array<{
    package?: { name?: string; ecosystem?: string };
    ranges?: Array<{ events?: Array<{ introduced?: string; fixed?: string }> }>;
  }>;
}

function severityOf(vuln: OsvVuln | undefined): Severity {
  const label = vuln?.database_specific?.severity?.toUpperCase();
  if (label === 'CRITICAL') return 'critical';
  if (label === 'HIGH') return 'high';
  if (label === 'LOW') return 'low';
  return 'medium';
}

function fixedVersion(vuln: OsvVuln | undefined, dep: Dependency): string | undefined {
  const affected = vuln?.affected?.find((a) => a.package?.name?.toLowerCase() === dep.name.toLowerCase());
  for (const range of affected?.ranges ?? []) {
    for (const event of range.events ?? []) if (event.fixed) return event.fixed;
  }
  return undefined;
}

async function mapLimit<T>(items: T[], limit: number, fn: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const item = items[next++] as T;
      await fn(item);
    }
  });
  await Promise.all(workers);
}

/**
 * Looks up known vulnerabilities for resolved dependency versions with the OSV.dev API.
 * Throws if the batch query fails, so the caller can mark the check as failed.
 */
export async function lookupVulnerabilities(
  deps: Dependency[],
  fetchImpl: typeof fetch,
  options: { timeoutMs?: number; maxDetails?: number } = {},
): Promise<VulnMatch[]> {
  const timeoutMs = options.timeoutMs ?? 15_000;
  const maxDetails = options.maxDetails ?? 80;
  const targets = deps.filter((d) => d.resolved);
  if (targets.length === 0) return [];

  const hits: Array<{ dep: Dependency; id: string }> = [];
  for (let i = 0; i < targets.length; i += BATCH_SIZE) {
    const chunk = targets.slice(i, i + BATCH_SIZE);
    const response = await fetchImpl(OSV_BATCH_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        queries: chunk.map((d) => ({ package: { name: d.name, ecosystem: d.ecosystem }, version: d.version })),
      }),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!response.ok) throw new Error(`OSV query failed with HTTP ${response.status}`);
    const data = (await response.json()) as { results?: Array<{ vulns?: Array<{ id: string }> }> };
    (data.results ?? []).forEach((result, j) => {
      const dep = chunk[j];
      if (!dep) return;
      for (const v of result.vulns ?? []) hits.push({ dep, id: v.id });
    });
  }

  const ids = [...new Set(hits.map((h) => h.id))].slice(0, maxDetails);
  const details = new Map<string, OsvVuln>();
  await mapLimit(ids, 8, async (id) => {
    try {
      const response = await fetchImpl(OSV_VULN_URL + encodeURIComponent(id), { signal: AbortSignal.timeout(timeoutMs) });
      if (response.ok) details.set(id, (await response.json()) as OsvVuln);
    } catch {
      // Keep the id; the finding just has less detail.
    }
  });

  return hits.map(({ dep, id }) => {
    const vuln = details.get(id);
    const fixedIn = fixedVersion(vuln, dep);
    const match: VulnMatch = {
      dependency: dep,
      id,
      aliases: vuln?.aliases ?? [],
      summary: vuln?.summary ?? vuln?.details?.slice(0, 200) ?? 'Known vulnerability',
      severity: severityOf(vuln),
    };
    if (fixedIn) match.fixedIn = fixedIn;
    return match;
  });
}

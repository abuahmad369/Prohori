import { CATEGORIES, type Category, type DemoSample } from './constants';
import { cleanNextApp, DEMO_LISTINGS, demoProject } from './demo-projects';
import { UserError } from './errors';
import { downloadGithubZip, parseGithubRepo } from './github';
import { newId, slugify } from './ids';
import { osvEnabled, runAndStoreScan, scanToRecord } from './scan-service';
import { getReport, readDb, updateDb, type Db, type Listing, type ScanRecord } from './store';
import { unzipProject } from './unzip';

function uniqueSlug(db: Db, title: string): string {
  const base = slugify(title);
  let slug = base;
  for (let n = 2; db.listings.some((l) => l.slug === slug); n++) slug = `${base}-${n}`;
  return slug;
}

/** Creates the demo listings once, by scanning their sample projects with the real engine. */
export async function ensureSeeded(): Promise<void> {
  if ((await readDb()).meta.seeded) return;
  const scanned = await Promise.all(
    DEMO_LISTINGS.map(async (spec) => ({
      spec,
      record: await scanToRecord({ source: 'demo', label: `Demo listing: ${spec.title}`, projectName: spec.title, entries: Object.entries(cleanNextApp(spec.project)) }),
    })),
  );
  const stacksById = new Map<string, string[]>();
  for (const { record } of scanned) stacksById.set(record.id, (await getReport(record.id))?.report.project.stacks ?? []);

  await updateDb((db) => {
    if (db.meta.seeded) return;
    const now = new Date().toISOString();
    for (const { spec, record } of scanned) {
      db.scans.unshift(record);
      if (!record.verified) continue;
      db.listings.push({
        id: newId(),
        slug: db.listings.some((l) => l.slug === spec.slug) ? uniqueSlug(db, spec.title) : spec.slug,
        title: spec.title,
        tagline: spec.tagline,
        description: spec.description,
        category: spec.category,
        stacks: stacksById.get(record.id) ?? [],
        priceBdtMinor: spec.priceBdt * 100,
        priceUsdMinor: spec.priceUsd * 100,
        builderId: spec.builderId,
        builderName: spec.builderName,
        scanId: record.id,
        score: record.score,
        grade: record.grade,
        verifiedAt: record.createdAt,
        demo: true,
        createdAt: now,
      });
    }
    db.meta.seeded = true;
  });
}

export async function publishedListings(category?: string): Promise<Listing[]> {
  await ensureSeeded();
  const db = await readDb();
  return db.listings.filter((l) => !category || l.category === category).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

export async function findListing(slug: string): Promise<Listing | null> {
  await ensureSeeded();
  return (await readDb()).listings.find((l) => l.slug === slug) ?? null;
}

export interface SubmitInput {
  title: string;
  tagline: string;
  description: string;
  category: string;
  priceBdt: number;
  priceUsd: number;
  builderName: string;
  scanId?: string;
  githubUrl?: string;
  demoSample?: DemoSample;
}

export interface SubmitResult {
  published: boolean;
  listing?: Listing;
  scan: ScanRecord;
  reasons: string[];
}

async function scanForSubmission(input: SubmitInput): Promise<ScanRecord> {
  if (input.scanId) {
    const record = (await readDb()).scans.find((s) => s.id === input.scanId);
    if (!record) throw new UserError('That scan was not found. Scan the app again, then submit.', 404);
    return record;
  }
  if (input.githubUrl) {
    const repo = parseGithubRepo(input.githubUrl);
    if (!repo) throw new UserError('Enter a public GitHub repository, like github.com/owner/repo.');
    const entries = unzipProject(await downloadGithubZip(repo.owner, repo.repo));
    return runAndStoreScan({ source: 'github', label: `${repo.owner}/${repo.repo}`, projectName: repo.repo, entries, online: osvEnabled() });
  }
  if (input.demoSample) {
    const demo = demoProject(input.demoSample);
    return runAndStoreScan({ source: 'demo', label: `Demo: ${demo.name}`, projectName: demo.name, entries: Object.entries(demo.files) });
  }
  throw new UserError('Choose what to list: a verified scan, a GitHub repository or a demo project.');
}

/** Scans the app (or reuses a scan) and publishes it only if it passes the gate. */
export async function submitListing(input: SubmitInput): Promise<SubmitResult> {
  if (!(CATEGORIES as readonly string[]).includes(input.category)) throw new UserError('Choose a category from the list.');
  const scan = await scanForSubmission(input);
  const stored = await getReport(scan.id);
  if (!stored) throw new UserError('The report for that scan is missing. Scan the app again.', 404);
  if (!stored.report.verified) return { published: false, scan, reasons: stored.report.gate.reasons };

  const listing = await updateDb((db): Listing => {
    const now = new Date().toISOString();
    const builderSlug = slugify(input.builderName);
    const created: Listing = {
      id: newId(),
      slug: uniqueSlug(db, input.title),
      title: input.title,
      tagline: input.tagline,
      description: input.description,
      category: input.category as Category,
      stacks: stored.report.project.stacks,
      priceBdtMinor: input.priceBdt * 100,
      priceUsdMinor: input.priceUsd * 100,
      builderId: `builder-${builderSlug}`,
      builderName: input.builderName,
      scanId: scan.id,
      score: scan.score,
      grade: scan.grade,
      verifiedAt: scan.createdAt,
      // A listing built from a sample project is labelled as a demo, so buyers never mistake it for a real app.
      demo: scan.source === 'demo',
      createdAt: now,
    };
    db.listings.push(created);
    return created;
  });
  return { published: true, listing, scan, reasons: stored.report.gate.reasons };
}

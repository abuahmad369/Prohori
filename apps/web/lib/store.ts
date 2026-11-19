import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';
import type { AuditReport } from '@prohori/audit-engine';
import type { Category, Currency, PaymentMethod } from './constants';
import { isId } from './ids';

export interface ScanRecord {
  id: string;
  createdAt: string;
  source: 'github' | 'upload' | 'demo';
  label: string;
  projectName: string;
  score: number;
  grade: string;
  verified: boolean;
  counts: AuditReport['counts'];
}

export interface Listing {
  id: string;
  slug: string;
  title: string;
  tagline: string;
  description: string;
  category: Category;
  stacks: string[];
  priceBdtMinor: number;
  priceUsdMinor: number;
  builderId: string;
  builderName: string;
  scanId: string;
  score: number;
  grade: string;
  verifiedAt: string;
  demo: boolean;
  createdAt: string;
}

export type OrderStatus = 'pending' | 'paid' | 'failed' | 'cancelled';

export interface Order {
  id: string;
  listingId: string;
  listingSlug: string;
  title: string;
  builderId: string;
  buyerEmail: string;
  method: PaymentMethod;
  provider: 'mock' | 'sslcommerz';
  currency: Currency;
  amountMinor: number;
  status: OrderStatus;
  providerRef?: string;
  licenseKey?: string;
  failureReason?: string;
  createdAt: string;
  paidAt?: string;
}

export interface LedgerEntry {
  id: string;
  orderId: string;
  account: string;
  debitMinor: number;
  creditMinor: number;
  currency: Currency;
  memo: string;
  createdAt: string;
}

export interface Db {
  meta: { seeded: boolean };
  scans: ScanRecord[];
  listings: Listing[];
  orders: Order[];
  ledger: LedgerEntry[];
}

export interface StoredReport {
  report: AuditReport;
  sbom: Record<string, unknown>;
}

const DATA_DIR = path.join(process.cwd(), '.data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const REPORT_DIR = path.join(DATA_DIR, 'reports');

const emptyDb = (): Db => ({ meta: { seeded: false }, scans: [], listings: [], orders: [], ledger: [] });

// Next.js can load this module more than once (server components, route handlers), so the write queue lives on globalThis.
const globalStore = globalThis as typeof globalThis & { __prohoriWriteQueue?: Promise<unknown> };

async function writeAtomic(file: string, data: string): Promise<void> {
  await mkdir(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
  await writeFile(tmp, data, 'utf8');
  await rename(tmp, file);
}

async function load(): Promise<Db> {
  let raw: string;
  try {
    raw = await readFile(DB_FILE, 'utf8');
  } catch {
    return emptyDb();
  }
  try {
    return { ...emptyDb(), ...(JSON.parse(raw) as Partial<Db>) };
  } catch {
    const backup = `${DB_FILE}.corrupt-${Date.now()}`;
    await rename(DB_FILE, backup).catch(() => undefined);
    console.error(`Store file was unreadable and was moved to ${backup}. Starting with an empty store.`);
    return emptyDb();
  }
}

/** Reads the current data. Writes are atomic, so a read never sees a half-written file. */
export function readDb(): Promise<Db> {
  return load();
}

/** Runs one change at a time: load, change, save. */
export function updateDb<T>(change: (db: Db) => T | Promise<T>): Promise<T> {
  const previous = globalStore.__prohoriWriteQueue ?? Promise.resolve();
  const run = previous.then(async () => {
    const db = await load();
    const result = await change(db);
    await writeAtomic(DB_FILE, JSON.stringify(db, null, 2));
    return result;
  });
  globalStore.__prohoriWriteQueue = run.catch(() => undefined);
  return run;
}

export async function saveReport(id: string, stored: StoredReport): Promise<void> {
  if (!isId(id)) throw new Error('Invalid report id');
  await writeAtomic(path.join(REPORT_DIR, `${id}.json`), JSON.stringify(stored));
}

export async function getReport(id: string): Promise<StoredReport | null> {
  if (!isId(id)) return null;
  try {
    return JSON.parse(await readFile(path.join(REPORT_DIR, `${id}.json`), 'utf8')) as StoredReport;
  } catch {
    return null;
  }
}

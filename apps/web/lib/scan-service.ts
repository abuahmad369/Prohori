import { scanFiles, toCycloneDx } from '@prohori/audit-engine';
import { newId } from './ids';
import { saveReport, updateDb, type ScanRecord } from './store';

export interface ScanInput {
  source: ScanRecord['source'];
  label: string;
  projectName: string;
  entries: Iterable<readonly [string, string | Uint8Array]>;
  online?: boolean;
}

export const osvEnabled = (): boolean => process.env.PROHORI_OSV !== 'off';

/** Scans in memory and saves the report and SBOM. Does not touch the database, so it is safe inside updateDb. */
export async function scanToRecord(input: ScanInput): Promise<ScanRecord> {
  const { report, dependencies, vulnerabilities } = await scanFiles(input.entries, { projectName: input.projectName, online: input.online ?? false });
  const id = newId();
  await saveReport(id, { report, sbom: toCycloneDx(report, dependencies, vulnerabilities) });
  return {
    id,
    createdAt: report.scannedAt,
    source: input.source,
    label: input.label,
    projectName: report.project.name,
    score: report.score,
    grade: report.grade,
    verified: report.verified,
    counts: report.counts,
  };
}

export async function runAndStoreScan(input: ScanInput): Promise<ScanRecord> {
  const record = await scanToRecord(input);
  await updateDb((db) => {
    db.scans.unshift(record);
    db.scans.splice(500);
  });
  return record;
}

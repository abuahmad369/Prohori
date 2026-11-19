export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type CategoryId = 'secrets' | 'access' | 'code' | 'dependencies' | 'production' | 'maintainability';
export type Confidence = 'high' | 'medium' | 'low';
export type Grade = 'A' | 'B' | 'C' | 'D' | 'F';
export type Ecosystem = 'npm' | 'Packagist' | 'PyPI' | 'NuGet';

export type StackId =
  | 'node'
  | 'nextjs'
  | 'react'
  | 'vite'
  | 'vue'
  | 'svelte'
  | 'express'
  | 'supabase'
  | 'firebase'
  | 'prisma'
  | 'stripe'
  | 'ai-sdk'
  | 'php'
  | 'laravel'
  | 'python'
  | 'django'
  | 'flask'
  | 'fastapi'
  | 'dotnet';

export interface ProjectFile {
  /** Path relative to the project root, always with forward slashes. */
  path: string;
  content: string;
  size: number;
}

export interface Dependency {
  ecosystem: Ecosystem;
  name: string;
  /** Exact version when it came from a lockfile, otherwise the declared range. */
  version: string;
  resolved: boolean;
  direct: boolean;
  dev: boolean;
  /** File the dependency was read from. */
  source: string;
}

export interface VulnMatch {
  dependency: Dependency;
  id: string;
  aliases: string[];
  summary: string;
  severity: Severity;
  fixedIn?: string;
}

/** What a rule returns. The scan fills in the rest from the rule's metadata. */
export interface RawFinding {
  file?: string;
  line?: number;
  snippet?: string;
  message?: string;
  severity?: Severity;
  confidence?: Confidence;
}

export interface RuleMeta {
  id: string;
  title: string;
  category: CategoryId;
  severity: Severity;
  confidence?: Confidence;
  cwe?: string;
  description: string;
  remediation: string;
}

export interface Rule extends RuleMeta {
  check(ctx: ScanContext): RawFinding[] | Promise<RawFinding[]>;
}

export interface Finding {
  /** Stable fingerprint: same rule, file and line text give the same id across scans. */
  id: string;
  ruleId: string;
  title: string;
  category: CategoryId;
  severity: Severity;
  confidence: Confidence;
  file?: string;
  line?: number;
  snippet?: string;
  message: string;
  remediation: string;
  cwe?: string;
  suppression?: { reason: string };
}

export interface ScanContext {
  projectName: string;
  files: ProjectFile[];
  byPath: Map<string, ProjectFile>;
  /** Every path seen, including files that were skipped (binary, too large). */
  paths: Set<string>;
  codeFiles: ProjectFile[];
  stacks: Set<StackId>;
  dependencies: Dependency[];
  manifests: Manifest[];
  lockfiles: string[];
  vulnerabilities: VulnMatch[];
  isClientFile(file: ProjectFile): boolean;
}

export interface Manifest {
  file: string;
  dir: string;
  ecosystem: Ecosystem;
  /** Direct dependencies with their declared version range. */
  direct: Map<string, { range: string; dev: boolean }>;
}

export interface ScanLimits {
  maxFiles: number;
  maxFileBytes: number;
  maxLockfileBytes: number;
  maxTotalBytes: number;
}

export interface LoadResult {
  files: ProjectFile[];
  paths: Set<string>;
  skipped: number;
  truncated: boolean;
  totalBytes: number;
}

export interface ScanOptions {
  projectName?: string;
  /** Query OSV.dev for known vulnerabilities in resolved dependencies. */
  online?: boolean;
  /** Injected for tests; defaults to the global fetch. */
  fetch?: typeof fetch;
  limits?: Partial<ScanLimits>;
  now?: () => Date;
}

export interface CategoryResult {
  id: CategoryId;
  title: string;
  weight: number;
  score: number;
  findings: number;
}

export interface Gate {
  minScore: number;
  passed: boolean;
  reasons: string[];
}

export interface AuditReport {
  schemaVersion: '1.0';
  engine: { name: string; version: string };
  project: {
    name: string;
    stacks: StackId[];
    files: number;
    bytes: number;
    skipped: number;
    truncated: boolean;
  };
  scannedAt: string;
  durationMs: number;
  score: number;
  grade: Grade;
  verified: boolean;
  gate: Gate;
  categories: CategoryResult[];
  counts: Record<Severity, number>;
  findings: Finding[];
  suppressed: Finding[];
  dependencies: {
    total: number;
    direct: number;
    ecosystems: Ecosystem[];
    lockfiles: string[];
    vulnerabilityCheck: 'online' | 'skipped' | 'failed';
    vulnerable: number;
  };
  /** Rules that crashed. A crash never stops the scan. */
  errors: string[];
}

export interface ScanResult {
  report: AuditReport;
  dependencies: Dependency[];
  vulnerabilities: VulnMatch[];
}

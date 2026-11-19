import { LOCKFILE_NAMES } from '../files.ts';
import type { Confidence, RawFinding, Rule, RuleMeta, ScanContext, Severity } from '../types.ts';
import { at, baseOf, CODE_EXTS, extOf, isDocPath, isInCode, isTestPath, matches } from './helpers.ts';

export interface PatternSpec {
  re: RegExp;
  message: string;
  /** File extensions this pattern applies to. Defaults to all code files. */
  exts?: readonly string[];
  /** Custom file filter; overrides `exts`. */
  files?: (path: string) => boolean;
  severity?: Severity;
  confidence?: Confidence;
  /** When this matches anywhere in the file, skip the finding, or downgrade it to `downgradeTo`. Must not use the g flag. */
  unless?: RegExp;
  downgradeTo?: Severity;
  /** Also count matches inside string literals and comments (for markup, config keys and templates). */
  inStrings?: boolean;
}

/** Builds a rule from a list of regex patterns, which covers most single-line checks. */
export function patternRule(meta: RuleMeta & { patterns: PatternSpec[]; skipTests?: boolean }): Rule {
  const { patterns, skipTests = false, ...ruleMeta } = meta;
  return {
    ...ruleMeta,
    check(ctx: ScanContext): RawFinding[] {
      const out: RawFinding[] = [];
      for (const file of ctx.files) {
        if (isDocPath(file.path) || LOCKFILE_NAMES.has(baseOf(file.path).toLowerCase())) continue;
        if (skipTests && isTestPath(file.path)) continue;
        const ext = extOf(file.path);
        for (const p of patterns) {
          if (p.files ? !p.files(file.path) : p.exts ? !p.exts.includes(ext) : !CODE_EXTS.has(ext)) continue;
          let severity = p.severity;
          if (p.unless?.test(file.content)) {
            if (!p.downgradeTo) continue;
            severity = p.downgradeTo;
          }
          for (const m of matches(file.content, p.re)) {
            if (!p.inStrings && CODE_EXTS.has(ext) && !isInCode(file, m.index)) continue;
            const extra: { message: string; severity?: Severity; confidence?: Confidence } = { message: p.message };
            if (severity) extra.severity = severity;
            if (p.confidence) extra.confidence = p.confidence;
            out.push(at(file, m.index, extra));
          }
        }
      }
      return out;
    },
  };
}

import type { ProjectFile, RawFinding, Rule, ScanContext } from '../types.ts';
import { at, baseOf, extOf, matches } from './helpers.ts';

const CREATE_TABLE_RE = /create\s+table\s+(?:if\s+not\s+exists\s+)?((?:"?[A-Za-z_]\w*"?\s*\.\s*)?"?([A-Za-z_]\w*)"?)/gi;
const ENABLE_RLS_RE =
  /alter\s+table\s+(?:only\s+)?(?:if\s+exists\s+)?((?:"?[A-Za-z_]\w*"?\s*\.\s*)?"?([A-Za-z_]\w*)"?)\s+enable\s+row\s+level\s+security/gi;
const POLICY_RE = /create\s+policy\s+(?:"[^"]*"|\w+)\s+on\s+([\w."]+)([\s\S]*?);/gi;

function schemaOf(qualified: string): string {
  const m = /^"?([A-Za-z_]\w*)"?\s*\./.exec(qualified);
  return m ? (m[1] as string).toLowerCase() : 'public';
}

function sqlFiles(ctx: ScanContext): ProjectFile[] {
  return ctx.files.filter((f) => extOf(f.path) === '.sql');
}

function isSupabaseSql(ctx: ScanContext, files: ProjectFile[]): boolean {
  if (ctx.stacks.has('supabase')) return true;
  if (files.some((f) => /(^|\/)supabase\//.test(f.path))) return true;
  return files.some((f) => /auth\.uid\(\)|auth\.jwt\(\)|\bto\s+authenticated\b|\bto\s+anon\b/i.test(f.content));
}

const tableWithoutRls: Rule = {
  id: 'access/supabase-table-without-rls',
  title: 'Supabase table without row-level security',
  category: 'access',
  severity: 'critical',
  cwe: 'CWE-284',
  description:
    "Supabase exposes every table in the public schema through its API. Without row-level security, anyone holding the app's public key can read and change every row.",
  remediation:
    'Add "alter table <name> enable row level security;" in a migration, then write policies that allow each user to reach only their own rows (for example using auth.uid()).',
  check(ctx) {
    const files = sqlFiles(ctx);
    if (files.length === 0 || !isSupabaseSql(ctx, files)) return [];
    const protectedTables = new Set<string>();
    for (const f of files) {
      for (const m of matches(f.content, ENABLE_RLS_RE)) {
        if (schemaOf(m[1] as string) === 'public') protectedTables.add((m[2] as string).toLowerCase());
      }
    }
    const out: RawFinding[] = [];
    for (const f of files) {
      for (const m of matches(f.content, CREATE_TABLE_RE)) {
        if (schemaOf(m[1] as string) !== 'public') continue;
        const table = m[2] as string;
        if (protectedTables.has(table.toLowerCase())) continue;
        out.push(at(f, m.index, { message: `Table "${table}" is created without row-level security. Anyone with your public Supabase key can read and change every row.` }));
      }
    }
    return out;
  },
};

const permissivePolicy: Rule = {
  id: 'access/permissive-policy',
  title: 'Row-level security policy that allows everyone',
  category: 'access',
  severity: 'high',
  cwe: 'CWE-284',
  description: 'A policy uses "true" as its condition, so it lets every user, including anonymous visitors, do that action on every row.',
  remediation: 'Replace "true" with a real condition, such as "auth.uid() = user_id". Keep "using (true)" only for data that is meant to be fully public and read-only.',
  check(ctx) {
    const out: RawFinding[] = [];
    for (const f of sqlFiles(ctx)) {
      for (const m of matches(f.content, POLICY_RE)) {
        const body = m[2] as string;
        if (!/using\s*\(\s*true\s*\)|with\s+check\s*\(\s*true\s*\)/i.test(body)) continue;
        const command = (/\bfor\s+(select|insert|update|delete|all)\b/i.exec(body)?.[1] ?? 'all').toLowerCase();
        const readOnly = command === 'select';
        out.push(
          at(f, m.index, {
            severity: readOnly ? 'low' : 'high',
            message: readOnly
              ? `Policy on ${m[1]} lets anyone read every row. Confirm this data is meant to be public.`
              : `Policy on ${m[1]} lets anyone ${command === 'all' ? 'read and change' : command} every row.`,
          }),
        );
      }
    }
    return out;
  },
};

const FIRESTORE_ALLOW_RE = /allow\s+([a-z,\s]+?)\s*(?::\s*if\s+([^;]+))?;/g;

const openFirebaseRules: Rule = {
  id: 'access/firebase-open-rules',
  title: 'Firebase rules open to everyone',
  category: 'access',
  severity: 'critical',
  cwe: 'CWE-284',
  description: 'Firebase security rules allow access without any condition (or only a time limit, as in test mode), so anyone can use the database directly.',
  remediation: 'Require a signed-in user and check ownership, for example "allow read, write: if request.auth != null && request.auth.uid == resource.data.ownerId;".',
  check(ctx) {
    const out: RawFinding[] = [];
    for (const f of ctx.files) {
      const base = baseOf(f.path).toLowerCase();
      if (base === 'database.rules.json') {
        for (const m of matches(f.content, /"\.(read|write)"\s*:\s*(?:true|"true")/g)) {
          const write = m[1] === 'write';
          out.push(at(f, m.index, { severity: write ? 'critical' : 'high', message: `Realtime Database allows anyone to ${write ? 'write' : 'read'} (${f.path}).` }));
        }
        continue;
      }
      if (extOf(f.path) !== '.rules') continue;
      for (const m of matches(f.content, FIRESTORE_ALLOW_RE)) {
        const ops = m[1] as string;
        const condition = (m[2] ?? 'true').trim();
        const timeOnly = /^request\.time\s*<\s*timestamp\.date\(/.test(condition);
        if (condition !== 'true' && !timeOnly) continue;
        const write = /write|create|update|delete/.test(ops);
        out.push(
          at(f, m.index, {
            severity: write ? 'critical' : 'high',
            message: timeOnly
              ? `Test-mode rule: anyone can ${ops.trim()} until the date in ${f.path}.`
              : `Anyone can ${ops.trim()} without signing in (${f.path}).`,
          }),
        );
      }
    }
    return out;
  },
};

const ADMIN_CLIENT_RE = /service_role|SERVICE_ROLE|serviceRole|supabase\.auth\.admin|\bauth\.admin\.|from\s+['"]firebase-admin['"]|require\(\s*['"]firebase-admin['"]\s*\)/g;

const adminClientInBrowser: Rule = {
  id: 'access/admin-client-in-browser',
  title: 'Admin database access from browser code',
  category: 'access',
  severity: 'critical',
  cwe: 'CWE-284',
  description: 'Browser code uses an admin client (Supabase service role or firebase-admin), which skips all access rules and needs a secret that would be shipped to visitors.',
  remediation: 'Do admin operations only in server code (API routes, server actions, edge functions) after checking the user, and use the normal client with the public key in the browser.',
  check(ctx) {
    const out: RawFinding[] = [];
    for (const f of ctx.codeFiles) {
      if (!ctx.isClientFile(f)) continue;
      const m = ADMIN_CLIENT_RE.exec(f.content);
      ADMIN_CLIENT_RE.lastIndex = 0;
      if (m) out.push(at(f, m.index, { message: `Browser code in ${f.path} uses admin database access.` }));
    }
    return out;
  },
};

export const dataAccessRules: Rule[] = [tableWithoutRls, permissivePolicy, openFirebaseRules, adminClientInBrowser];

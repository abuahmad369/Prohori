import { scanFiles } from '../src/index.ts';
import type { AuditReport, Finding, ScanOptions } from '../src/index.ts';

/** Joins pieces so no complete fake secret appears in this repository. */
export const fake = (...parts: string[]): string => parts.join('');

export const json = (value: unknown): string => JSON.stringify(value, null, 2);

export async function scan(files: Record<string, string>, options: ScanOptions = {}): Promise<AuditReport> {
  const { report } = await scanFiles(Object.entries(files), { projectName: 'fixture', ...options });
  return report;
}

export const findings = (report: AuditReport, ruleId: string): Finding[] => report.findings.filter((f) => f.ruleId === ruleId);

const README = [
  '# Shop Admin',
  '',
  'Shop Admin is a small inventory and orders dashboard for independent retailers, built with Next.js, Supabase and Prisma.',
  '',
  '## Getting started',
  '',
  '1. Copy `.env.example` to `.env.local` and fill in the values from your Supabase project.',
  '2. Install dependencies with `npm ci`.',
  '3. Apply the database migrations with `npx supabase db push`.',
  '4. Start the app with `npm run dev` and open http://localhost:3000.',
  '',
  '## Tests',
  '',
  'Run `npm test` before every commit.',
  '',
].join('\n');

const DEPENDENCIES = {
  next: '16.4.6',
  react: '19.3.1',
  'react-dom': '19.3.1',
  '@supabase/supabase-js': '2.49.4',
  zod: '3.25.0',
  '@upstash/ratelimit': '2.0.5',
  openai: '5.0.0',
};

/** A well-built Next.js + Supabase app that should produce no findings at all. */
export const CLEAN_APP: Record<string, string> = {
  'README.md': README,
  '.gitignore': 'node_modules\n.next\n.env*\n!.env.example\n',
  '.env.example': 'NEXT_PUBLIC_SUPABASE_URL=\nNEXT_PUBLIC_SUPABASE_ANON_KEY=\nSUPABASE_SERVICE_ROLE_KEY=\nOPENAI_API_KEY=\n',
  LICENSE: 'MIT License\n\nCopyright (c) 2026 Example\n',
  'AGENTS.md': '# Agent guide\n\nRun npm test before every commit. Keep secrets out of browser-visible variables.\n',
  '.github/workflows/ci.yml': 'name: ci\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: npm ci\n      - run: npm test\n',
  'package.json': json({ name: 'shop-admin', version: '1.0.0', private: true, scripts: { dev: 'next dev', test: 'node --test' }, dependencies: DEPENDENCIES }),
  'package-lock.json': json({
    name: 'shop-admin',
    lockfileVersion: 3,
    requires: true,
    packages: {
      '': { name: 'shop-admin', version: '1.0.0', dependencies: DEPENDENCIES },
      ...Object.fromEntries(Object.entries(DEPENDENCIES).map(([name, version]) => [`node_modules/${name}`, { version }])),
    },
  }),
  'next.config.ts': [
    "import type { NextConfig } from 'next';",
    '',
    'const nextConfig: NextConfig = {',
    '  async headers() {',
    "    return [{ source: '/(.*)', headers: [{ key: 'X-Frame-Options', value: 'DENY' }] }];",
    '  },',
    '};',
    '',
    'export default nextConfig;',
    '',
  ].join('\n'),
  'app/api/orders/route.ts': [
    "import { NextResponse } from 'next/server';",
    "import { z } from 'zod';",
    "import { auth } from '@/lib/auth';",
    "import { db } from '@/lib/db';",
    '',
    'const Order = z.object({ productId: z.string(), quantity: z.number().int().positive() });',
    '',
    'export async function POST(request: Request) {',
    '  const session = await auth();',
    "  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });",
    '  const input = Order.parse(await request.json());',
    '  const order = await db.order.create({ data: { ...input, userId: session.user.id } });',
    '  return NextResponse.json(order);',
    '}',
    '',
  ].join('\n'),
  'app/api/assistant/route.ts': [
    "import { NextResponse } from 'next/server';",
    "import OpenAI from 'openai';",
    "import { auth } from '@/lib/auth';",
    "import { limiter } from '@/lib/rate-limit';",
    '',
    'const client = new OpenAI();',
    '',
    'export async function POST(request: Request) {',
    '  const session = await auth();',
    "  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });",
    '  const { success } = await limiter.limit(session.user.id);',
    "  if (!success) return NextResponse.json({ error: 'Too many requests' }, { status: 429 });",
    '  const { question } = await request.json();',
    "  const answer = await client.responses.create({ model: 'gpt-5', input: String(question).slice(0, 2000) });",
    '  return NextResponse.json({ answer: answer.output_text });',
    '}',
    '',
  ].join('\n'),
  'app/actions.ts': [
    "'use server';",
    '',
    "import { auth } from '@/lib/auth';",
    "import { db } from '@/lib/db';",
    '',
    'export async function archiveProduct(id: string) {',
    '  const session = await auth();',
    "  if (!session) throw new Error('Unauthorized');",
    '  await db.product.update({ where: { id, ownerId: session.user.id }, data: { archived: true } });',
    '}',
    '',
  ].join('\n'),
  'supabase/migrations/0001_init.sql': [
    'create table public.products (',
    '  id uuid primary key default gen_random_uuid(),',
    '  owner_id uuid not null references auth.users(id),',
    '  name text not null',
    ');',
    '',
    'alter table public.products enable row level security;',
    '',
    'create policy "Owners manage their products" on public.products',
    '  for all using (auth.uid() = owner_id) with check (auth.uid() = owner_id);',
    '',
  ].join('\n'),
  'lib/db.test.ts': "import test from 'node:test';\nimport assert from 'node:assert/strict';\n\ntest('adds numbers', () => {\n  assert.equal(1 + 1, 2);\n});\n",
  'components/order-list.tsx': [
    "'use client';",
    '',
    'export function OrderList({ orders }: { orders: { id: string; total: number }[] }) {',
    '  return <ul>{orders.map((o) => <li key={o.id}>{o.total}</li>)}</ul>;',
    '}',
    '',
  ].join('\n'),
};

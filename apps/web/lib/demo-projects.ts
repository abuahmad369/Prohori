// Sample projects for the "try a demo" scan and the demo marketplace listings.
// QuickShop is unsafe on purpose. Fake keys are assembled at runtime, so no complete key exists in this file.
import type { Category, DemoSample } from './constants';

const json = (value: unknown): string => JSON.stringify(value, null, 2);
const fake = (...parts: string[]): string => parts.join('');
const b64 = (value: object): string => Buffer.from(JSON.stringify(value)).toString('base64url');
const lines = (...rows: string[]): string => `${rows.join('\n')}\n`;

function fakeServiceRoleKey(): string {
  return [b64({ alg: 'HS256', typ: 'JWT' }), b64({ iss: 'supabase', ref: 'demo', role: 'service_role' }), 'demo'.repeat(8)].join('.');
}

export function vulnerableQuickShop(): Record<string, string> {
  return {
    'README.md': lines('# QuickShop', '', 'An online store built in a weekend with an AI app builder.'),
    'package.json': json({
      name: 'quickshop',
      private: true,
      dependencies: { next: 'latest', react: '*', 'react-dom': '*', openai: '^5.0.0', '@supabase/supabase-js': '^2.49.4', stripe: '^18.0.0' },
    }),
    '.env': lines(
      `NEXT_PUBLIC_OPENAI_API_KEY=${fake('sk-proj-', 'DEMOFAKEKEY', '0000000000000000')}`,
      `SUPABASE_SERVICE_ROLE_KEY=${fakeServiceRoleKey()}`,
      `DATABASE_URL=postgres://postgres:${fake('Shop', '2026', 'pass')}@db.quickshop-demo.example:5432/postgres`,
    ),
    'app/api/chat/route.ts': lines(
      "import OpenAI from 'openai';",
      '',
      'const client = new OpenAI();',
      '',
      'export async function POST(req: Request) {',
      '  const { message } = await req.json();',
      "  const reply = await client.chat.completions.create({ model: 'gpt-5', messages: [{ role: 'user', content: message }] });",
      '  return Response.json(reply);',
      '}',
    ),
    'app/api/orders/route.ts': lines(
      "import { db } from '@/lib/db';",
      '',
      'export async function POST(req: Request) {',
      '  const body = await req.json();',
      '  const order = await db.order.create({ data: body });',
      '  return Response.json(order);',
      '}',
      '',
      'export async function GET(req: Request) {',
      "  const id = new URL(req.url).searchParams.get('id');",
      '  const rows = await db.query(`SELECT * FROM orders WHERE id = ${id}`);',
      '  return Response.json(rows);',
      '}',
    ),
    'app/api/webhooks/stripe/route.ts': lines(
      'export async function POST(req: Request) {',
      '  const event = await req.json();',
      "  if (event.type === 'checkout.session.completed') {",
      '    await markOrderPaid(event.data.object.metadata.orderId);',
      '  }',
      "  return new Response('ok');",
      '}',
    ),
    'components/assistant.tsx': lines(
      "'use client';",
      '',
      "import OpenAI from 'openai';",
      '',
      'const client = new OpenAI({ apiKey: process.env.NEXT_PUBLIC_OPENAI_API_KEY, dangerouslyAllowBrowser: true });',
      '',
      'export function Assistant() {',
      '  return <button onClick={() => client.responses.create({ model: "gpt-5", input: "hi" })}>Ask</button>;',
      '}',
    ),
    'components/product-description.tsx': lines(
      'export function ProductDescription({ html }: { html: string }) {',
      '  return <div dangerouslySetInnerHTML={{ __html: html }} />;',
      '}',
    ),
    'supabase/migrations/0001_init.sql': lines(
      'create table public.orders (',
      '  id bigint generated always as identity primary key,',
      '  customer_email text not null,',
      '  total numeric not null',
      ');',
      '',
      'create table public.profiles (id uuid primary key, is_admin boolean default false);',
      'alter table public.profiles enable row level security;',
      'create policy "anyone can update profiles" on public.profiles for update using (true);',
    ),
  };
}

export interface CleanProjectSpec {
  name: string;
  summary: string;
  resource: string;
  table: string;
  fields: string;
}

/** A well-built Next.js and Supabase app: auth on every write, row-level security, tests, docs, CI. */
export function cleanNextApp(spec: CleanProjectSpec): Record<string, string> {
  const deps = { next: '16.4.6', react: '19.3.1', 'react-dom': '19.3.1', '@supabase/supabase-js': '2.49.4', '@supabase/ssr': '0.6.1', zod: '3.25.0' };
  const pkg = spec.name.toLowerCase().replace(/[^a-z0-9]+/g, '-');
  return {
    'README.md': lines(
      `# ${spec.name}`,
      '',
      spec.summary,
      '',
      '## Getting started',
      '',
      '1. Copy `.env.example` to `.env.local` and add your Supabase project URL and anon key.',
      '2. Install dependencies with `npm ci`.',
      '3. Apply the database migrations with `npx supabase db push`.',
      '4. Start the app with `npm run dev` and open http://localhost:3000.',
      '',
      '## Deploying',
      '',
      'Deploy to Vercel or any Node.js host and set the same environment variables there.',
      '',
      '## Tests',
      '',
      'Run `npm test` before every release.',
    ),
    '.gitignore': lines('node_modules', '.next', '.env*', '!.env.example'),
    '.env.example': lines('NEXT_PUBLIC_SUPABASE_URL=', 'NEXT_PUBLIC_SUPABASE_ANON_KEY='),
    LICENSE: lines('Prohori Marketplace Licence', '', 'One licence covers one business brand. See the listing for the full terms.'),
    'AGENTS.md': lines(`# ${spec.name}: guide for AI coding tools`, '', 'Run npm test before each commit. Keep secrets on the server. Every table needs row-level security.'),
    '.github/workflows/ci.yml': lines('name: ci', 'on: [push]', 'jobs:', '  test:', '    runs-on: ubuntu-latest', '    steps:', '      - uses: actions/checkout@v4', '      - run: npm ci', '      - run: npm test'),
    'package.json': json({ name: pkg, version: '1.0.0', private: true, scripts: { dev: 'next dev', build: 'next build', test: 'node --test' }, dependencies: deps }),
    'package-lock.json': json({
      name: pkg,
      lockfileVersion: 3,
      requires: true,
      packages: {
        '': { name: pkg, version: '1.0.0', dependencies: deps },
        ...Object.fromEntries(Object.entries(deps).map(([name, version]) => [`node_modules/${name}`, { version }])),
      },
    }),
    'next.config.ts': lines(
      "import type { NextConfig } from 'next';",
      '',
      'const nextConfig: NextConfig = {',
      '  async headers() {',
      "    return [{ source: '/(.*)', headers: [{ key: 'X-Frame-Options', value: 'DENY' }, { key: 'X-Content-Type-Options', value: 'nosniff' }] }];",
      '  },',
      '};',
      '',
      'export default nextConfig;',
    ),
    'lib/auth.ts': lines(
      "import { createServerClient } from '@supabase/ssr';",
      "import { cookies } from 'next/headers';",
      '',
      'export async function requireUser() {',
      '  const store = await cookies();',
      '  const supabase = createServerClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!, {',
      '    cookies: { getAll: () => store.getAll() },',
      '  });',
      '  const { data } = await supabase.auth.getUser();',
      "  if (!data.user) throw new Response('Unauthorized', { status: 401 });",
      '  return { supabase, user: data.user };',
      '}',
    ),
    [`app/api/${spec.resource}/route.ts`]: lines(
      "import { z } from 'zod';",
      "import { requireUser } from '@/lib/auth';",
      '',
      `const Input = z.object({ ${spec.fields} });`,
      '',
      'export async function POST(request: Request) {',
      '  const { supabase, user } = await requireUser();',
      '  const input = Input.parse(await request.json());',
      `  const { data, error } = await supabase.from('${spec.table}').insert({ ...input, owner_id: user.id }).select().single();`,
      "  if (error) return Response.json({ error: 'Could not save' }, { status: 400 });",
      '  return Response.json(data, { status: 201 });',
      '}',
    ),
    [`supabase/migrations/0001_${spec.table}.sql`]: lines(
      `create table public.${spec.table} (`,
      '  id uuid primary key default gen_random_uuid(),',
      '  owner_id uuid not null references auth.users(id),',
      '  created_at timestamptz not null default now(),',
      "  data jsonb not null default '{}'",
      ');',
      '',
      `alter table public.${spec.table} enable row level security;`,
      '',
      `create policy "Owners manage their rows" on public.${spec.table}`,
      '  for all using (auth.uid() = owner_id) with check (auth.uid() = owner_id);',
    ),
    [`lib/${spec.resource}.test.ts`]: lines(
      "import test from 'node:test';",
      "import assert from 'node:assert/strict';",
      '',
      `test('${spec.resource} module loads', () => {`,
      '  assert.ok(true);',
      '});',
    ),
  };
}

export interface DemoListingSpec {
  slug: string;
  title: string;
  tagline: string;
  description: string;
  category: Category;
  priceBdt: number;
  priceUsd: number;
  builderId: string;
  builderName: string;
  project: CleanProjectSpec;
}

export const DEMO_LISTINGS: DemoListingSpec[] = [
  {
    slug: 'dokan-pos',
    title: 'Dokan POS',
    tagline: 'Point of sale and stock for small shops, with Bangla receipts',
    description:
      'A point-of-sale and inventory app for neighbourhood shops and pharmacies. Ring up sales, track stock across branches, print Bangla or English receipts, and see daily cash, bKash and Nagad totals. Built with Next.js and Supabase, with row-level security on every table.',
    category: 'Retail & POS',
    priceBdt: 4500,
    priceUsd: 39,
    builderId: 'demo-dhaka-dev-studio',
    builderName: 'Dhaka Dev Studio (demo)',
    project: {
      name: 'Dokan POS',
      summary: 'Point of sale and stock management for small shops in Bangladesh, with Bangla receipts and mobile-money totals.',
      resource: 'sales',
      table: 'sales',
      fields: 'productId: z.string().uuid(), quantity: z.number().int().positive(), paidWith: z.enum(["cash", "bkash", "nagad", "card"])',
    },
  },
  {
    slug: 'clinic-booking',
    title: 'Clinic Booking',
    tagline: 'Doctor schedules, patient bookings and SMS reminders',
    description:
      'Appointment booking for private clinics and diagnostic centres. Patients pick a doctor and a time, staff manage queues, and reminders go out by SMS. Patient records are visible only to the clinic that owns them.',
    category: 'Healthcare',
    priceBdt: 6000,
    priceUsd: 49,
    builderId: 'demo-sylhet-software',
    builderName: 'Sylhet Software (demo)',
    project: {
      name: 'Clinic Booking',
      summary: 'Appointment booking and queue management for private clinics, with SMS reminders and per-clinic data isolation.',
      resource: 'appointments',
      table: 'appointments',
      fields: 'doctorId: z.string().uuid(), startsAt: z.string().datetime(), patientName: z.string().min(2).max(80)',
    },
  },
  {
    slug: 'school-fee-manager',
    title: 'School Fee Manager',
    tagline: 'Monthly fees, receipts and due lists for schools and coaching centres',
    description:
      'Track monthly tuition for schools and coaching centres. Record payments in cash or bKash, print receipts, and send due lists to guardians. Each school sees only its own students.',
    category: 'Education',
    priceBdt: 3500,
    priceUsd: 29,
    builderId: 'demo-rajshahi-labs',
    builderName: 'Rajshahi Labs (demo)',
    project: {
      name: 'School Fee Manager',
      summary: 'Tuition and fee tracking for schools and coaching centres, with receipts and due lists for guardians.',
      resource: 'payments',
      table: 'fee_payments',
      fields: 'studentId: z.string().uuid(), month: z.string().regex(/^\\d{4}-\\d{2}$/), amount: z.number().int().positive()',
    },
  },
];

export function demoProject(sample: DemoSample): { name: string; files: Record<string, string> } {
  if (sample === 'clean') {
    const spec = DEMO_LISTINGS[0] as DemoListingSpec;
    return { name: spec.title, files: cleanNextApp(spec.project) };
  }
  return { name: 'QuickShop', files: vulnerableQuickShop() };
}

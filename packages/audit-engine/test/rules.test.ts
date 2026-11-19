import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { CLEAN_APP, fake, findings, json, scan } from './helpers.ts';

const b64 = (value: object): string => Buffer.from(JSON.stringify(value)).toString('base64url');
const jwt = (payload: object): string => `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64(payload)}.${'s'.repeat(24)}`;

describe('clean app', () => {
  it('has no findings and passes the gate', async () => {
    const report = await scan(CLEAN_APP);
    assert.deepEqual(
      report.findings.map((f) => `${f.ruleId} ${f.file ?? ''}:${f.line ?? ''}`),
      [],
    );
    assert.equal(report.score, 100);
    assert.equal(report.grade, 'A');
    assert.equal(report.verified, true);
    assert.ok(report.project.stacks.includes('nextjs'));
    assert.ok(report.project.stacks.includes('supabase'));
  });
});

describe('secrets', () => {
  it('finds provider keys and never copies them into the report', async () => {
    const keys = {
      stripe: fake('sk', '_live_', 'FAKE1234567890abcdefghijKL'),
      aws: fake('AKIA', 'FAKEKEY000000000'),
      github: fake('ghp', '_', 'a'.repeat(36)),
      anthropic: fake('sk-ant-', 'api03-', 'x'.repeat(30)),
    };
    const report = await scan({
      'src/config.ts': Object.entries(keys)
        .map(([name, value]) => `export const ${name} = "${value}";`)
        .join('\n'),
    });
    const found = findings(report, 'secrets/hardcoded-credential');
    assert.equal(found.length, 4);
    assert.ok(found.every((f) => f.severity === 'critical'));
    const serialized = JSON.stringify(report);
    for (const value of Object.values(keys)) assert.ok(!serialized.includes(value), `report leaked a key starting ${value.slice(0, 6)}`);
    assert.equal(report.verified, false);
    assert.ok(report.score <= 59);
  });

  it('finds private keys', async () => {
    const pem = [fake('-----BEGIN ', 'RSA PRIVATE KEY-----'), 'MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu', fake('-----END ', 'RSA PRIVATE KEY-----')].join('\n');
    const report = await scan({ 'certs/server.pem': pem });
    assert.equal(findings(report, 'secrets/private-key').length, 1);
  });

  it('flags a Supabase service-role key but not the public anon key', async () => {
    const report = await scan({
      'lib/supabase.ts': `export const admin = "${jwt({ iss: 'supabase', role: 'service_role' })}";\nexport const anon = "${jwt({ iss: 'supabase', role: 'anon' })}";\n`,
    });
    assert.equal(findings(report, 'secrets/service-role-key').length, 1);
  });

  it('flags secrets in browser-visible env vars only', async () => {
    const report = await scan({
      'app/page.tsx': 'const key = process.env.NEXT_PUBLIC_OPENAI_API_KEY;\nconst anon = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;\nconst url = process.env.NEXT_PUBLIC_SUPABASE_URL;\n',
    });
    const found = findings(report, 'secrets/public-env-secret');
    assert.equal(found.length, 1);
    assert.match(found[0]!.message, /NEXT_PUBLIC_OPENAI_API_KEY/);
  });

  it('flags a committed .env file and a remote database password', async () => {
    const report = await scan({
      '.env': 'DATABASE_URL=postgres://app:Sup3rS3cretPass@db.example.com:5432/app\nAPP_DEBUG=true\n',
      '.env.example': 'DATABASE_URL=\n',
    });
    const envFiles = findings(report, 'secrets/env-file-committed');
    assert.equal(envFiles.length, 1);
    assert.equal(envFiles[0]?.severity, 'high');
    assert.equal(findings(report, 'secrets/db-url-with-password')[0]?.severity, 'high');
    assert.equal(findings(report, 'production/debug-enabled').length, 1);
    assert.ok(!JSON.stringify(report).includes('Sup3rS3cretPass'));
  });

  it('treats a local database password as low risk', async () => {
    const report = await scan({
      'docker-compose.yml': 'services:\n  app:\n    environment:\n      DATABASE_URL: postgres://postgres:devpass123@localhost:5432/dev\n',
    });
    assert.equal(findings(report, 'secrets/db-url-with-password')[0]?.severity, 'low');
  });

  it('flags hard-coded secrets by name but ignores labels and headers', async () => {
    const report = await scan({
      'config/settings.js': 'module.exports = {\n  jwtSecret: "n8Kq2Lw9Zx4Rt7Vb",\n  passwordLabel: "Enter your password",\n  apiKeyHeader: "x-api-key",\n};\n',
    });
    const found = findings(report, 'secrets/generic-secret');
    assert.equal(found.length, 1);
    assert.equal(found[0]?.line, 2);
    assert.ok(!JSON.stringify(report).includes('n8Kq2Lw9Zx4Rt7Vb'));
  });

  it('flags AI clients created in browser code', async () => {
    const report = await scan({
      'components/chat.tsx': "'use client';\nimport OpenAI from 'openai';\nconst client = new OpenAI({ apiKey: key, dangerouslyAllowBrowser: true });\n",
    });
    assert.ok(findings(report, 'secrets/client-side-ai-key').length >= 1);
  });

  it('warns when .gitignore does not exclude .env', async () => {
    const report = await scan({ 'index.js': 'console.log(process.env.PORT);\n', '.gitignore': 'node_modules\n' });
    assert.equal(findings(report, 'secrets/env-not-ignored').length, 1);
  });
});

describe('database access', () => {
  it('flags Supabase tables without row-level security', async () => {
    const report = await scan({
      'supabase/migrations/001_init.sql':
        'create table public.orders (id uuid primary key);\ncreate table profiles (id uuid primary key);\nalter table profiles enable row level security;\n',
    });
    const found = findings(report, 'access/supabase-table-without-rls');
    assert.equal(found.length, 1);
    assert.match(found[0]!.message, /orders/);
    assert.equal(report.verified, false);
  });

  it('ignores plain SQL in projects that do not use Supabase', async () => {
    const report = await scan({ 'db/schema.sql': 'create table orders (id int);\n' });
    assert.equal(findings(report, 'access/supabase-table-without-rls').length, 0);
  });

  it('flags policies that allow everyone', async () => {
    const report = await scan({
      'supabase/migrations/002.sql':
        'create table posts (id int);\nalter table posts enable row level security;\ncreate policy "anyone can edit" on posts for update using (true);\ncreate policy "public read" on posts for select using (true);\n',
    });
    const severities = findings(report, 'access/permissive-policy').map((f) => f.severity).sort();
    assert.deepEqual(severities, ['high', 'low']);
  });

  it('flags open Firebase rules', async () => {
    const report = await scan({
      'firestore.rules':
        "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    match /{document=**} {\n      allow read, write: if true;\n    }\n  }\n}\n",
    });
    assert.equal(findings(report, 'access/firebase-open-rules')[0]?.severity, 'critical');
  });

  it('flags admin database access from browser code', async () => {
    const report = await scan({
      'components/admin.tsx': "'use client';\nconst admin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!);\n",
    });
    assert.equal(findings(report, 'access/admin-client-in-browser').length, 1);
  });
});

describe('access control', () => {
  const unprotectedRoute =
    'export async function POST(req: Request) {\n  const body = await req.json();\n  return Response.json(await db.post.create({ data: body }));\n}\n';

  it('flags a route handler that writes without auth', async () => {
    const report = await scan({ 'app/api/posts/route.ts': unprotectedRoute });
    assert.equal(findings(report, 'access/route-without-auth').length, 1);
    assert.equal(findings(report, 'access/mass-assignment').length, 1);
  });

  it('accepts a route handler that checks the session', async () => {
    const protectedRoute = unprotectedRoute.replace(
      '{\n',
      "{\n  const session = await auth();\n  if (!session) return new Response('Unauthorized', { status: 401 });\n",
    );
    const report = await scan({ 'app/api/posts/route.ts': protectedRoute });
    assert.equal(findings(report, 'access/route-without-auth').length, 0);
  });

  it('skips login routes but asks for a rate limit there', async () => {
    const report = await scan({ 'app/api/auth/login/route.ts': unprotectedRoute });
    assert.equal(findings(report, 'access/route-without-auth').length, 0);
    assert.equal(findings(report, 'production/no-login-rate-limit').length, 1);
  });

  it('flags server actions that write without auth', async () => {
    const report = await scan({
      'app/actions.ts': "'use server';\nexport async function deletePost(id: string) {\n  await db.post.delete({ where: { id } });\n}\n",
    });
    assert.equal(findings(report, 'access/route-without-auth').length, 1);
  });

  it('flags Express write routes without auth middleware', async () => {
    const report = await scan({
      'server/routes.js':
        "const router = require('express').Router();\nrouter.post('/orders', async (req, res) => { res.json(await Order.create(req.body)); });\nrouter.delete('/orders/:id', requireAuth, handler);\nmodule.exports = router;\n",
    });
    const found = findings(report, 'access/route-without-auth');
    assert.equal(found.length, 1);
    assert.equal(found[0]?.severity, 'medium');
    assert.equal(findings(report, 'access/mass-assignment').length, 1);
  });

  it('flags AI endpoints without login or rate limit', async () => {
    const aiRoute =
      "import OpenAI from 'openai';\nconst client = new OpenAI();\nexport async function POST(req: Request) {\n  const { prompt } = await req.json();\n  const r = await client.chat.completions.create({ model: 'gpt-5', messages: [{ role: 'user', content: prompt }] });\n  return Response.json(r);\n}\n";
    const open = await scan({ 'app/api/chat/route.ts': aiRoute });
    assert.equal(findings(open, 'access/ai-endpoint-unprotected')[0]?.severity, 'high');

    const withAuth = aiRoute.replace('{\n  const { prompt }', "{\n  const session = await auth();\n  if (!session) return new Response('no', { status: 401 });\n  const { prompt }");
    const authOnly = await scan({ 'app/api/chat/route.ts': withAuth });
    assert.equal(findings(authOnly, 'access/ai-endpoint-unprotected')[0]?.severity, 'low');

    const limited = withAuth.replace('const { prompt }', 'await limiter.limit(session.user.id);\n  const { prompt }');
    const safe = await scan({ 'app/api/chat/route.ts': limited });
    assert.equal(findings(safe, 'access/ai-endpoint-unprotected').length, 0);
  });

  it('flags webhooks that do not verify the signature', async () => {
    const handler =
      "export async function POST(req: Request) {\n  const event = await req.json();\n  if (event.type === 'checkout.session.completed') await markPaid(event.data.object.id);\n  return new Response('ok');\n}\n";
    const report = await scan({ 'app/api/webhooks/stripe/route.ts': handler });
    assert.equal(findings(report, 'access/webhook-without-signature').length, 1);
    assert.equal(findings(report, 'access/route-without-auth').length, 0);

    const verified = handler.replace('const event = await req.json();', 'const event = stripe.webhooks.constructEvent(await req.text(), sig, secret);');
    const ok = await scan({ 'app/api/webhooks/stripe/route.ts': verified });
    assert.equal(findings(ok, 'access/webhook-without-signature').length, 0);
  });

  it('flags admin endpoints without a role check', async () => {
    const report = await scan({
      'app/api/admin/users/route.ts':
        "export async function DELETE(req: Request) {\n  const session = await auth();\n  if (!session) return new Response('Unauthorized', { status: 401 });\n  await db.user.deleteMany();\n  return new Response('done');\n}\n",
    });
    assert.equal(findings(report, 'access/admin-without-role-check').length, 1);
  });

  it('flags Laravel routes, mass assignment and raw Blade output', async () => {
    const report = await scan({
      'composer.json': json({ require: { php: '^8.3', 'laravel/framework': '^12.0' } }),
      'routes/web.php': "<?php\nRoute::post('/orders', [OrderController::class, 'store']);\n",
      'app/Http/Controllers/OrderController.php':
        '<?php\nclass OrderController {\n  public function store(Request $request) {\n    return Order::create($request->all());\n  }\n}\n',
      'resources/views/order.blade.php': '<div>{!! $order->notes !!}</div>\n',
    });
    assert.equal(findings(report, 'access/laravel-route-without-auth').length, 1);
    assert.equal(findings(report, 'access/mass-assignment').length, 1);
    assert.equal(findings(report, 'code/raw-html').length, 1);
    assert.equal(findings(report, 'dependencies/no-lockfile').length, 1);
    assert.ok(report.project.stacks.includes('laravel'));
  });
});

describe('code safety', () => {
  const ts = [
    'export const a = (id: string) => pool.query(`SELECT * FROM users WHERE id = ${id}`);',
    'export const b = (id: string) => sql`SELECT * FROM users WHERE id = ${id}`;',
    'export const c = (dir: string) => exec(`ls ${dir}`);',
    'export const d = (code: string) => eval(code);',
    'export const e = (page: any) => page.$eval(".x", (el: any) => el.textContent);',
    'export const f = { rejectUnauthorized: false };',
    "export const g = (payload: object) => jwt.sign(payload, 'super-secret-value');",
    "export const h = (token: string, key: string) => jwt.verify(token, key, { algorithms: ['none'] });",
    'export const i = (req: any) => fetch(req.query.url);',
    'export const j = (req: any) => fs.readFileSync(req.params.file);',
    'export const k = Math.random().toString(36); // reset token',
    'export const l = (req: any, res: any) => res.redirect(req.query.next);',
    '',
  ].join('\n');

  it('flags unsafe JavaScript and TypeScript patterns', async () => {
    const report = await scan({ 'src/db.ts': ts });
    const lines = (ruleId: string) => findings(report, ruleId).map((f) => f.line);
    assert.deepEqual(lines('code/sql-injection'), [1]);
    assert.deepEqual(lines('code/command-injection'), [3]);
    assert.deepEqual(lines('code/eval'), [4]);
    assert.deepEqual(lines('code/tls-verification-disabled'), [6]);
    assert.deepEqual(lines('code/jwt-hardcoded-secret'), [7]);
    assert.deepEqual(lines('code/jwt-none-algorithm'), [8]);
    assert.deepEqual(lines('code/ssrf'), [9]);
    assert.deepEqual(lines('code/path-traversal'), [10]);
    assert.deepEqual(lines('code/insecure-random'), [11]);
    assert.deepEqual(lines('code/open-redirect'), [12]);
  });

  it('flags unsafe Python and PHP patterns', async () => {
    const report = await scan({
      'app.py':
        'import requests\ndef find(cursor, name):\n    cursor.execute(f"SELECT * FROM users WHERE name = \'{name}\'")\nrequests.get("https://example.com", verify=False)\napp.run(debug=True)\n',
      'settings.py': 'DEBUG = True\n',
      'index.php': '<?php\n$rows = mysqli_query($conn, "SELECT * FROM users WHERE id = $id");\nshell_exec("convert " . $file);\n',
    });
    assert.deepEqual(findings(report, 'code/sql-injection').map((f) => f.file).sort(), ['app.py', 'index.php']);
    assert.equal(findings(report, 'code/tls-verification-disabled').length, 1);
    assert.equal(findings(report, 'production/debug-enabled').length, 2);
    assert.equal(findings(report, 'code/command-injection').length, 1);
  });

  it('downgrades raw HTML when a sanitizer is used', async () => {
    const report = await scan({
      'components/bio.tsx': 'export function Bio({ html }: { html: string }) {\n  return <div dangerouslySetInnerHTML={{ __html: html }} />;\n}\n',
      'components/safe-bio.tsx':
        "import DOMPurify from 'dompurify';\nexport function SafeBio({ html }: { html: string }) {\n  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;\n}\n",
    });
    const bySeverity = Object.fromEntries(findings(report, 'code/raw-html').map((f) => [f.file, f.severity]));
    assert.deepEqual(bySeverity, { 'components/bio.tsx': 'medium', 'components/safe-bio.tsx': 'low' });
  });

  it('flags open CORS with credentials and weak password hashing', async () => {
    const report = await scan({
      'server/app.js': "const cors = require('cors');\napp.use(cors({ origin: true, credentials: true }));\n",
      'lib/auth.js': "const crypto = require('crypto');\nfunction hashPassword(password) {\n  return crypto.createHash('md5').update(password).digest('hex');\n}\n",
    });
    assert.equal(findings(report, 'code/cors-misconfigured')[0]?.severity, 'high');
    assert.equal(findings(report, 'code/weak-password-hash').length, 1);
  });
});

describe('production readiness', () => {
  it('flags leaked errors, sensitive logs, missing headers and default passwords', async () => {
    const report = await scan({
      'package.json': json({ dependencies: { next: '16.4.6' } }),
      'package-lock.json': json({ lockfileVersion: 3, packages: { 'node_modules/next': { version: '16.4.6' } } }),
      'next.config.js': "module.exports = { images: { remotePatterns: [{ hostname: '**' }] } };\n",
      'app/api/upload/route.ts':
        "export async function POST(req: Request) {\n  const session = await auth();\n  if (!session) return new Response('no', { status: 401 });\n  try { await save(); } catch (err: any) { return Response.json({ error: err.stack }, { status: 500 }); }\n  console.log('user password', password);\n  return Response.json({ ok: true });\n}\n",
      'seed.js': "const admin = { email: 'admin@example.com', password: 'admin123' };\n",
    });
    assert.equal(findings(report, 'production/error-details-leaked')[0]?.severity, 'medium');
    assert.equal(findings(report, 'production/sensitive-logging').length, 1);
    assert.equal(findings(report, 'production/missing-security-headers').length, 1);
    assert.equal(findings(report, 'production/image-proxy-wildcard').length, 1);
    assert.equal(findings(report, 'production/default-credentials').length, 1);
    assert.equal(findings(report, 'secrets/generic-secret').length, 0);
  });
});

describe('maintainability', () => {
  it('reports missing README, tests, licence, CI and agent guide', async () => {
    const report = await scan({ 'index.js': "console.log('hi');\n" });
    const ids = report.findings.map((f) => f.ruleId).filter((id) => id.startsWith('maintainability/')).sort();
    assert.deepEqual(ids, [
      'maintainability/agent-guide',
      'maintainability/ci',
      'maintainability/license',
      'maintainability/readme',
      'maintainability/tests',
    ]);
  });
});

describe('precision', () => {
  it('ignores dangerous calls that only appear in strings or comments', async () => {
    const report = await scan({
      'src/messages.ts': [
        "export const a = 'eval() runs a string as code.';",
        '// never call eval(input) here',
        "export const b = { rejectUnauthorized: true, note: 'rejectUnauthorized: false is unsafe' };",
        "export const c = 'Math.random() is not a secure token source';",
        "export const WEAK_PASSWORDS = '(?:admin|password123|secret)';",
        '',
      ].join('\n'),
    });
    const noisy = report.findings.filter((f) => f.category === 'code' || f.ruleId === 'secrets/generic-secret');
    assert.deepEqual(noisy.map((f) => `${f.ruleId}:${f.line}`), []);
  });
});

describe('suppressions', () => {
  const route = 'export async function POST(req: Request) {\n  return Response.json(await db.item.create({ data: { name: "x" } }));\n}\n';

  it('honours an inline suppression with a reason', async () => {
    const report = await scan({
      'app/api/items/route.ts': `// prohori-ignore access/route-without-auth: public demo endpoint, rate limited upstream\n${route}`,
    });
    assert.equal(findings(report, 'access/route-without-auth').length, 0);
    const suppressed = report.suppressed.filter((f) => f.ruleId === 'access/route-without-auth');
    assert.equal(suppressed.length, 1);
    assert.match(suppressed[0]!.suppression!.reason, /public demo endpoint/);
  });

  it('ignores a suppression without a reason', async () => {
    const report = await scan({ 'app/api/items/route.ts': `// prohori-ignore access/route-without-auth\n${route}` });
    assert.equal(findings(report, 'access/route-without-auth').length, 1);
  });

  it('applies project-wide suppressions from .prohoriignore', async () => {
    const report = await scan({
      'index.js': "console.log('hi');\n",
      '.prohoriignore': '# reasons are required\nmaintainability/license: internal tool, no licence needed\n* fixtures/: intentionally vulnerable samples\n',
      'fixtures/bad.js': 'eval(input);\n',
    });
    assert.equal(findings(report, 'maintainability/license').length, 0);
    assert.equal(findings(report, 'code/eval').length, 0);
    assert.ok(report.suppressed.some((f) => f.ruleId === 'code/eval'));
  });
});

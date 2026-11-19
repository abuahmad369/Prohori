import type { ProjectFile, RawFinding, Rule } from '../types.ts';
import {
  at,
  AUTH_SIGNALS,
  extOf,
  hasDirective,
  hasExpressRoutes,
  hasPythonRoutes,
  isEndpointFile,
  isTestPath,
  JS_EXTS,
  matches,
  NEXT_ROUTE_RE,
  PAGES_API_RE,
  PHP_EXTS,
  PUBLIC_FLOW_RE,
  RATE_LIMIT_SIGNALS,
  ROLE_SIGNALS,
  VALIDATION_SIGNALS,
} from './helpers.ts';

const MUTATING_EXPORT_RE = /export\s+(?:async\s+)?function\s+(POST|PUT|PATCH|DELETE)\b|export\s+const\s+(POST|PUT|PATCH|DELETE)\s*=/g;
const PAGES_WRITE_RE = /req\.method\s*(?:===?|!==?)\s*['"](POST|PUT|PATCH|DELETE)['"]|case\s+['"](POST|PUT|PATCH|DELETE)['"]/;
const DB_WRITE_RE =
  /\.(?:insert|update|upsert|delete|create|createMany|updateMany|deleteMany|destroy|save|remove)\s*\(|\b(?:INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b/i;
const EXPRESS_WRITE_RE = /\b(?:app|router|api|server|routes?|r)\.(post|put|patch|delete)\s*\(\s*(['"`])([^'"`]*)\2\s*,([^\n]*)/g;
const EXPRESS_GLOBAL_AUTH_RE =
  /\.use\(\s*(?:['"`][^'"`]*['"`]\s*,\s*)?[\w.]*(?:auth|protect|requireUser|isAuthenticated|verifyToken|jwt|passport|session|clerk)/i;

const routeWithoutAuth: Rule = {
  id: 'access/route-without-auth',
  title: 'Endpoint changes data without checking the user',
  category: 'access',
  severity: 'high',
  confidence: 'medium',
  cwe: 'CWE-306',
  description:
    'An API route or server action writes data but has no visible authentication check, so anyone who finds the URL can call it. Server actions are public HTTP endpoints too.',
  remediation:
    'Check the session first ("const session = await auth(); if (!session) return 401"), then check the user owns the record. If the endpoint is public on purpose, add rate limiting and input validation and mark it with "prohori-ignore access/route-without-auth: <reason>".',
  check(ctx) {
    const out: RawFinding[] = [];
    for (const f of ctx.codeFiles) {
      const p = f.path;
      if (isTestPath(p) || PUBLIC_FLOW_RE.test(p)) continue;
      const hasAuth = AUTH_SIGNALS.test(f.content);
      if (NEXT_ROUTE_RE.test(p)) {
        if (hasAuth) continue;
        for (const m of matches(f.content, MUTATING_EXPORT_RE)) {
          out.push(at(f, m.index, { message: `${m[1] ?? m[2]} handler in ${p} changes data but checks no session.` }));
        }
      } else if (PAGES_API_RE.test(p)) {
        if (hasAuth) continue;
        const m = PAGES_WRITE_RE.exec(f.content);
        if (m || DB_WRITE_RE.test(f.content)) {
          out.push(at(f, m?.index ?? 0, { message: `API route ${p} accepts writes but checks no session.` }));
        }
      } else if (JS_EXTS.includes(extOf(p)) && hasDirective(f, 'use server')) {
        if (hasAuth || !DB_WRITE_RE.test(f.content)) continue;
        const m = /export\s+(?:async\s+)?function\s+\w+/.exec(f.content);
        out.push(at(f, m?.index ?? 0, { message: `Server actions in ${p} write data without checking who is calling.` }));
      } else if (hasExpressRoutes(f.content) && !EXPRESS_GLOBAL_AUTH_RE.test(f.content)) {
        for (const m of matches(f.content, EXPRESS_WRITE_RE)) {
          const route = m[3] as string;
          if (PUBLIC_FLOW_RE.test(route) || AUTH_SIGNALS.test(m[4] as string)) continue;
          out.push(at(f, m.index, { severity: 'medium', message: `${(m[1] as string).toUpperCase()} ${route} has no authentication middleware.` }));
        }
      }
    }
    return out;
  },
};

const LARAVEL_AUTH_RE = /middleware\(\s*\[?\s*['"](?:auth|auth:sanctum|auth:api|verified)/;

const laravelRouteWithoutAuth: Rule = {
  id: 'access/laravel-route-without-auth',
  title: 'Laravel write route without auth middleware',
  category: 'access',
  severity: 'medium',
  confidence: 'medium',
  cwe: 'CWE-306',
  description: 'A Laravel route that changes data is not inside an auth middleware group, and its controller does not add one.',
  remediation: "Wrap the routes in Route::middleware(['auth'])->group(...) (or auth:sanctum for APIs), and authorise each action with policies.",
  check(ctx) {
    const routeFiles = ctx.files.filter((f) => /(^|\/)routes\/(web|api)\.php$/.test(f.path));
    if (routeFiles.length === 0) return [];
    const controllersUseAuth = ctx.files.some((f) => /(^|\/)app\/Http\/Controllers\//.test(f.path) && LARAVEL_AUTH_RE.test(f.content));
    if (controllersUseAuth) return [];
    const out: RawFinding[] = [];
    for (const f of routeFiles) {
      if (LARAVEL_AUTH_RE.test(f.content)) continue;
      for (const m of matches(f.content, /Route::(post|put|patch|delete)\s*\(\s*['"]([^'"]+)['"]/g)) {
        if (PUBLIC_FLOW_RE.test(m[2] as string)) continue;
        out.push(at(f, m.index, { message: `Route::${m[1]}('${m[2]}') has no auth middleware.` }));
      }
    }
    return out;
  },
};

const AI_CALL_RE =
  /\b(?:openai|anthropic|chat\.completions\.create|responses\.create|messages\.create|generateText|streamText|generateObject|streamObject|ChatOpenAI|ChatAnthropic|GoogleGenerativeAI|GoogleGenAI|groq|replicate\.run|ollama)\b/i;

const aiEndpointUnprotected: Rule = {
  id: 'access/ai-endpoint-unprotected',
  title: 'AI endpoint anyone can call',
  category: 'access',
  severity: 'high',
  cwe: 'CWE-770',
  description:
    'An endpoint calls a paid AI model without checking who is asking or how often. Anyone can script it and run up your AI bill ("denial of wallet") or use your quota.',
  remediation: 'Require a signed-in user, add a per-user rate limit, cap input length, and set a monthly spending limit with your AI provider.',
  check(ctx) {
    const out: RawFinding[] = [];
    for (const f of ctx.codeFiles) {
      if (isTestPath(f.path) || !isEndpointFile(f)) continue;
      const call = AI_CALL_RE.exec(f.content);
      if (!call) continue;
      const hasAuth = AUTH_SIGNALS.test(f.content);
      const limited = RATE_LIMIT_SIGNALS.test(f.content);
      if (!hasAuth && !limited) {
        out.push(at(f, call.index, { message: `${f.path} calls an AI model with no login check and no rate limit.` }));
      } else if (!limited) {
        out.push(at(f, call.index, { severity: 'low', message: `${f.path} calls an AI model without a rate limit, so one user can still run up the bill.` }));
      }
    }
    return out;
  },
};

const WEBHOOK_VERIFIED_RE =
  /constructEvent|webhooks?\.(?:verify|unmarshal)|verifyWebhook|verifySignature|validateWebhook|createHmac|timingSafeEqual|compare_digest|hmac\.|stripe-signature|paddle-signature|x-hub-signature|x-signature|svix|new\s+Webhook\(|validationserverAPI|verify_sign|webhookSecret|WEBHOOK_SECRET|signing_secret/i;

function isWebhookHandler(f: ProjectFile): boolean {
  if (!isEndpointFile(f)) return false;
  if (/webhook/i.test(f.path)) return true;
  return (hasExpressRoutes(f.content) || hasPythonRoutes(f.content)) && /['"`][^'"`\n]*webhook[^'"`\n]*['"`]/i.test(f.content);
}

const webhookWithoutSignature: Rule = {
  id: 'access/webhook-without-signature',
  title: 'Webhook does not verify the sender',
  category: 'access',
  severity: 'high',
  confidence: 'medium',
  cwe: 'CWE-345',
  description: 'A webhook handler acts on the request without checking its signature, so anyone can send a fake "payment succeeded" or similar event.',
  remediation:
    "Verify the provider's signature before doing anything: stripe.webhooks.constructEvent for Stripe, the Paddle or GitHub signature header with an HMAC and timing-safe compare, or SSLCommerz's validation API.",
  check(ctx) {
    const out: RawFinding[] = [];
    for (const f of ctx.codeFiles) {
      if (isTestPath(f.path) || !isWebhookHandler(f)) continue;
      if (WEBHOOK_VERIFIED_RE.test(f.content)) continue;
      out.push({ file: f.path, line: 1, message: `Webhook handler ${f.path} never verifies a signature.` });
    }
    return out;
  },
};

const adminWithoutRoleCheck: Rule = {
  id: 'access/admin-without-role-check',
  title: 'Admin endpoint without a role check',
  category: 'access',
  severity: 'medium',
  confidence: 'medium',
  cwe: 'CWE-285',
  description: 'An admin endpoint checks that someone is signed in, or nothing at all, but not that they are an admin.',
  remediation: 'Check the role on the server for every admin action (for example "if (session.user.role !== \'admin\') return 403"), not only in the user interface.',
  check(ctx) {
    const out: RawFinding[] = [];
    for (const f of ctx.codeFiles) {
      if (isTestPath(f.path) || !isEndpointFile(f)) continue;
      const adminPath = /(^|\/)admin(\/|\.|-|_)/i.test(f.path);
      const adminRoute = /['"`]\/(?:api\/)?admin\b/i.exec(f.content);
      if (!adminPath && !adminRoute) continue;
      if (ROLE_SIGNALS.test(f.content)) continue;
      out.push(adminRoute ? at(f, adminRoute.index, { message: `Admin routes in ${f.path} never check the user's role.` }) : { file: f.path, line: 1, message: `Admin endpoint ${f.path} never checks the user's role.` });
    }
    return out;
  },
};

const MASS_ASSIGN_RE =
  /\.(?:create|update|upsert|insert|updateOne|updateMany|findOneAndUpdate|findByIdAndUpdate)\s*\(\s*(?:\{[^)]*?\b(?:data|values)\s*:\s*)?(req\.body|request\.body|await\s+req\.json\(\)|await\s+request\.json\(\)|body|payload)\s*[,)}]/g;
const LARAVEL_MASS_ASSIGN_RE = /(?:::create|->update|->fill|::updateOrCreate|::firstOrCreate)\s*\(\s*\$request->all\(\)\s*\)/g;

const massAssignment: Rule = {
  id: 'access/mass-assignment',
  title: 'Whole request body written to the database',
  category: 'access',
  severity: 'medium',
  confidence: 'medium',
  cwe: 'CWE-915',
  description: 'The full request body is saved as-is, so a user can set fields they should not control, such as role, price or owner.',
  remediation: 'Validate the input with a schema (zod, Laravel FormRequest, pydantic) and copy only the allowed fields into the database call.',
  check(ctx) {
    const out: RawFinding[] = [];
    for (const f of ctx.codeFiles) {
      if (isTestPath(f.path)) continue;
      if (PHP_EXTS.includes(extOf(f.path))) {
        for (const m of matches(f.content, LARAVEL_MASS_ASSIGN_RE)) {
          out.push(at(f, m.index, { message: `$request->all() is written straight to a model in ${f.path}.` }));
        }
        continue;
      }
      if (!JS_EXTS.includes(extOf(f.path)) || VALIDATION_SIGNALS.test(f.content)) continue;
      for (const m of matches(f.content, MASS_ASSIGN_RE)) {
        out.push(at(f, m.index, { message: `The request body is saved without validation in ${f.path}.` }));
      }
    }
    return out;
  },
};

export const accessRules: Rule[] = [
  routeWithoutAuth,
  laravelRouteWithoutAuth,
  aiEndpointUnprotected,
  webhookWithoutSignature,
  adminWithoutRoleCheck,
  massAssignment,
];

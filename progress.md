# Prohori progress log

> **To continue this work (you or a new Claude session):** read this file first, then `docs/scenario.md` and `docs/architecture.md`. Pick up from **Next steps**. At the end of every session, update **Status**, **Done**, **Next steps** and the **Session log**.
>
> Prompt to paste into a new Claude Code session: *"Read progress.md in this folder and continue the work from Next steps. Update progress.md when you finish."*

## সংক্ষেপে (Bangla summary)

আমরা **Prohori** (প্রহরী) নামে একটা কোম্পানির পরিকল্পনা আর সফটওয়্যার বানাচ্ছি। নামটা এখনো অস্থায়ী। এআই দিয়ে বানানো অ্যাপ নিরাপদ কিনা সেটা যাচাই করবে, সার্টিফিকেট দেবে, শুধু যাচাই করা অ্যাপ মার্কেটপ্লেসে বিক্রি করবে (বিকাশ, নগদ, কার্ড), আর পরে এআই দিয়ে সমস্যা ঠিকও করে দেবে।

**এখন পর্যন্ত যা হয়েছে:** গবেষণা, পুরো ব্যবসার পরিকল্পনা (`docs/scenario.md`), প্রযুক্তির নকশা (`docs/architecture.md`), স্ক্যান ইঞ্জিন (৩৯টা নিয়ম, ৫৯টা টেস্ট পাস), আর ওয়েবসাইট (স্ক্যান, রিপোর্ট, মার্কেটপ্লেস, বিক্রি করা, কেনা, ড্যাশবোর্ড) তৈরি এবং ব্রাউজারে পুরোটা পরীক্ষা করা হয়েছে। পেমেন্ট এখন সিমুলেটেড (আসল টাকা যায় না)। এটা শুধু নিজের কম্পিউটারে চলে, এখনো ইন্টারনেটে দেওয়ার মতো নয়।

সব কোড এখন GitHub-এর প্রাইভেট রিপোজিটরিতে আছে: github.com/abuahmad369/Prohori

**পরের কাজ:** ইউজার অ্যাকাউন্ট, ডাটাবেস (Postgres), SSLCommerz স্যান্ডবক্সে বিকাশ/নগদ পরীক্ষা, তারপর ইন্টারনেটে ডিপ্লয়। নিচের "Next steps" অংশে ক্রমানুসারে লেখা আছে।

**সতর্কতা:** D: ড্রাইভে জায়গা প্রায় শেষ (১৯ নভেম্বর ২০২৬ তারিখে ০.২৮ GB খালি)। আরো কাজের আগে কিছু জায়গা খালি করুন।

## Goal

Build **Prohori**, the trust layer for AI-built software:
1. **Scan:** audit any AI-built app (GitHub link, zip or local folder) for the mistakes that actually broke apps in 2026.
2. **Verified:** certify apps that pass (score ≥ 75, no critical finding, real code present, every check run).
3. **Market:** sell only verified apps, with bKash, Nagad and card payments (Bangladesh first) and international cards later.
4. Later: **Fix** (AI pull requests priced per fixed issue), **Guard** (inside AI coding agents and CI), **Comply** (SBOM and EU Cyber Resilience Act).

## Status

**Phase 0 (foundation) complete: a working local MVP.** Last updated: 2026-11-19.

Not deployable yet: there are no accounts, data is stored in a local JSON file, and payments are simulated. Phase 1 (below) fixes this before anything goes online.

Code: private GitHub repository **github.com/abuahmad369/Prohori**, branch `main`. Commit and push at the end of every session.

## Done

- [x] Research on the next software era, with sources → `docs/research.md`
- [x] Full business scenario: problem, products, customers, pricing, go-to-market, Bangladesh setup, revenue scenarios, milestones, risks, roadmap → `docs/scenario.md`
- [x] Architecture: engine pipeline, scoring model, web routes, store, payments, ledger, security model, decisions → `docs/architecture.md`
- [x] Monorepo scaffold (pnpm workspace), README, AGENTS.md, CI workflow (`.github/workflows/ci.yml`)
- [x] Audit engine (`packages/audit-engine`): 39 rules, scoring and gate, inline and project suppressions, JSON / text / Markdown / SARIF reports, CycloneDX SBOM, optional OSV vulnerability lookup, `prohori` CLI
- [x] Self-scan precision fix: pattern matches inside string literals and comments are ignored
- [x] Gate hardening: a project with no application code, or a scan where a check crashed, is never verified (found when a README-only GitHub repo scored 100 and passed)
- [x] Web app (`apps/web`, Next.js 16.4.6, React 19.3.1):
  - Landing page; free scanner (GitHub link, zip upload up to 25 MB, two demo projects)
  - Report page with score ring, gate result, six areas, findings with fixes, downloads (JSON, Markdown, SARIF, SBOM)
  - Verified-only marketplace with categories, listing pages, buy form (bKash, Nagad, Bangladeshi card, international card)
  - Sell flow: scan, then publish only if verified; rejected apps get the reasons and a link to the report
  - Simulated payment gateway using the same signed-callback path a real gateway will use; SSLCommerz adapter (IPN and return routes) behind env vars, **not yet tested against the sandbox**
  - Order page with licence key; double-entry ledger with tiered commission; operator dashboard (scans, listings, sales, commission, builder balances)
  - Rate limits on every write endpoint, input validation, security headers, secrets masked in every report
- [x] End-to-end check in the browser (2026-11-19), all passing:
  - Demo scan of the unsafe sample: 46 (F), 5 critical, not verified; all four downloads work; no unmasked secret in any download or page
  - Bought a demo app with simulated bKash: order paid, licence key issued, ledger split ৳4,500 into ৳1,350 commission (30%) and ৳3,150 builder share
  - Replayed and late-cancel callbacks change nothing; cancelled orders cannot be paid; a client-sent price is ignored
  - Sell: unsafe sample rejected with reasons; clean sample published and labelled "Demo listing"
  - Zip upload and public GitHub scans work; missing repo, wrong file type, bad ids, bad categories, bad emails and unknown pages give clear errors or 404
  - No server errors, no React or hydration errors; production build passes (17 routes)
- [x] Checks: **59 engine tests pass**, type check clean in both packages, `pnpm scan:self` gives **96/100 (A), verified**
- [x] Version control: git set up and pushed to the private repository github.com/abuahmad369/Prohori (2026-11-19)

## Next steps (in order)

**Before any of these:** free space on D: (see Environment notes). Installs and builds need about 1 GB.

1. **Check CI on GitHub.** The workflow in `.github/workflows/ci.yml` runs on every push (tests, type check, self-scan). Open the repository's Actions tab and confirm the first run passed. The SARIF upload step may be skipped on a private repository without GitHub code scanning; it is set to continue on error.
2. **Accounts and roles.** Sign-up and login for builders and buyers, and an operator role. Then:
   - Require a builder account on `POST /api/listings` (the one open finding in the self-scan) and take `builderId` from the account, not from the typed name.
   - Lock `/dashboard` to operators.
   - Show buyers their orders.
3. **Database.** Move `apps/web/lib/store.ts` from the JSON file to Postgres (Neon), with transactions for orders and ledger lines. Store reports in Postgres (JSONB) or object storage.
4. **Real payments in the sandbox.**
   - Get SSLCommerz sandbox credentials and put them in `apps/web/.env.local`.
   - Test bKash, Nagad and card end to end. The IPN needs a public URL, for example a tunnel.
   - Add a refund path for operators.
5. **Deploy** (Vercel or a small VPS):
   - Set a request body-size limit at the proxy.
   - Move rate limits to Redis (Upstash).
   - Set `APP_URL`, check that HSTS and CSP headers are live, and add error monitoring.
6. **Delivery to buyers.** Source code download through signed links, email receipts, and a licence certificate.
7. **Verified badge** (SVG endpoint) and **re-scan on every push** (GitHub App).
8. **Guard:** an MCP server so Claude Code, Cursor and other agents can run Prohori while they code.
9. **Fix:** an AI agent (Claude) that opens a pull request per finding, priced per fixed issue.
10. **International payments** with Paddle.
11. **Business groundwork** (can run in parallel):
    - Trademark and domain check for the name.
    - Company registration and bank account in Bangladesh.
    - Terms, refund policy and the builder agreement.

## How to run

```bash
pnpm install          # once
pnpm dev              # web app at http://localhost:3000
pnpm test             # engine tests
pnpm typecheck        # both packages
pnpm scan <folder>    # scan any folder from the command line
pnpm scan:self        # scan this repository
pnpm build            # production build (writes about 220 MB to apps/web/.next)
```

- **Settings:** copy `apps/web/.env.example` to `apps/web/.env.local`. Every value is optional for local use; with no SSLCommerz settings, the simulated gateway is used.
- **Try it:** Scan → Try a demo → QuickShop (fails) or Dokan POS (passes). Then Marketplace → an app → Pay (simulated) → order page → Dashboard. Sell → A demo project → publish.
- **Local data** lives in `apps/web/.data/` (git-ignored). Delete that folder to start fresh; the three demo listings are re-created on the next visit.
- In Claude Code, `.claude/launch.json` starts the dev server as `prohori-web`.

## Where things are

| Path | What |
|---|---|
| `progress.md` | This file |
| `docs/research.md` | Evidence and sources |
| `docs/scenario.md` | Business plan |
| `docs/architecture.md` | Technical design |
| `AGENTS.md` | Rules for AI coding tools working on this repository |
| `packages/audit-engine/src/rules/` | The 39 rules, one file per area |
| `packages/audit-engine/src/scoring.ts` | Score, grade and the Verified gate |
| `packages/audit-engine/test/` | Engine tests (`helpers.ts` has `fake()` and `CLEAN_APP`) |
| `apps/web/app/` | Pages and API routes |
| `apps/web/lib/orders.ts` | `handleGatewayCallback()`: the only place an order becomes paid; ledger |
| `apps/web/lib/payments/` | Simulated gateway and SSLCommerz adapter |
| `apps/web/lib/store.ts` | JSON-file store (replace with Postgres in Phase 1) |
| `apps/web/lib/demo-projects.ts` | Sample projects (one unsafe on purpose) and demo listings |
| `.prohoriignore` | Project-wide suppressions, each with a reason |
| `Vibe96 Successor Blueprint.html`, `Vibe96 Successor Blueprint (Bangla).html` | Earlier audit of vibe96.com and rebuild plan |
| `vibe96 like idea.pdf` | The founder's original idea document |

## Known issues and limits (Phase 0)

- No accounts. Anyone using the local app can submit listings and see the dashboard. The builder is identified by the typed name, so two people typing the same name share a balance.
- The JSON store suits one process on one machine; it is not for production.
- In-memory rate limits reset when the server restarts and are per process.
- Uploads are refused early when their declared size is over 25 MB; uploads without a declared size are read in full before the check. Production needs a proxy body limit.
- SSLCommerz code is written to their v4 API but has never been run against the sandbox.
- After a purchase, no source code is delivered yet; the order page explains this.
- The Bangla blueprint's "English version" link points to a deleted Artifact.
- No `LICENSE` file (business decision pending; shows as an info finding in the self-scan).

## Decisions so far

- Working name **Prohori**; check trademark and domains before public use.
- Lead with the free scanner (single-player value), then certification, then marketplace. Plain scanners are a commodity ($5 to $29 a month), so the business is certification + marketplace + fixes + monitoring.
- Engine: TypeScript, zero runtime dependencies, run directly by Node 24 (type stripping), tests with `node --test`.
- Web: Next.js 16 App Router; JSON-file store for Phase 0, Postgres (Neon) before deploy.
- Payments: provider interface; simulated gateway with the real verification path; SSLCommerz adapter (bKash, Nagad, cards) behind env vars; Paddle later. Stripe doesn't serve Bangladesh-registered companies.
- A verified payment that arrives after a cancel is still recorded (the buyer's money moved); the simulated gateway acts only on pending orders.
- No accounts in Phase 0 (local only). Accounts come first in Phase 1, before any deploy.
- `POST /api/listings` is left without a suppression on purpose, so the self-scan keeps showing the missing auth until accounts exist.
- Work is saved in repository files, not in Claude Artifacts (the founder's choice).

## Environment notes

- Windows 11, PowerShell; Node 24.11.1, npm 11.6.2, pnpm 11.1.3, git 2.47.1.
- **Disk space is critical.** On 2026-11-19, D: had 0.28 GB free (after deleting the 223 MB production build output). This project uses about 1.2 GB on D: (`node_modules` 348 MB, mostly hard links into the pnpm store at `D:\.pnpm-store`, which is 861 MB). The rest of the drop from about 5.5 GB two days earlier is outside this project. Free space before installing or building; `pnpm store prune` removes store packages no project uses.
- Git: remote `origin` is github.com/abuahmad369/Prohori (private); sign-in comes from Git Credential Manager. Large pushes timed out with HTTP 408, so this repository has `http.version HTTP/1.1` and `http.postBuffer 157286400` set locally; a push with the 6.7 MB PDF took about a minute. The `gh` CLI is installed but not signed in (`gh auth login` to use it).
- Separate earlier task: MiroFish's backend install failed for lack of disk space; still waiting on a decision (C: environment or free space on D:).

## Session log

- **2026-11-17 to 2026-11-19 (session 1):**
  - Research (8 web searches); scenario, architecture and this file written.
  - Engine built: 39 rules, 57 tests.
- **2026-11-19 (session 2):**
  - Web app finished: sell flow, simulated checkout, payment routes, order page, dashboard.
  - Clicked through every page in the browser.
  - Fixes from testing:
    - Demo-sourced listings are now labelled as demos.
    - The simulated gateway refuses closed orders.
    - Oversized uploads are refused before the body is read.
    - Report wording and plurals corrected.
  - Engine gate hardened: no code, or a crashed check, means not verified (2 new tests, 59 total).
  - Production build passes; self-scan 96 (A), verified.
  - Freed disk space by deleting `apps/web/.next` and the test data.
  - Git set up; first commit pushed to github.com/abuahmad369/Prohori on top of the repository's initial README commit. Added `.gitattributes` (LF line endings).

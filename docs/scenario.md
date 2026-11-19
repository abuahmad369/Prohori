# Prohori: the full scenario

**Prohori** (প্রহরী, "guard" or "sentinel" in Bangla) is a working name. Check trademarks and domains before using it publicly. Renaming means a find-and-replace across this repository.

> **One line:** Prohori is the trust layer for AI-built software. It checks, certifies, sells and keeps safe the apps that AI writes.

Evidence for every claim below is in [research.md](research.md). Numbers marked *assumption* are planning guesses to be tested, not forecasts.

---

## 1. The problem

AI made building software nearly free, but it didn't make software trustworthy.

- AI now writes somewhere between 27% (measured) and 47% (self-reported) of professional developers' code. Lovable alone reports about 100,000 new projects a day, and most vibe-coding users aren't developers.
- In Veracode's 2026 tests, about 44% of AI coding tasks introduced a risky security flaw.
- The real breaches of 2026 (Moltbook, the Lovable incidents, thousands of exposed apps) came from the same three mistakes: database tables without access rules, secrets left in code or in browser-visible settings, and no review before launch.
- 38% of developers say AI code is harder to review than human code. Verification is now the bottleneck.
- From 11 December 2027, anyone selling software into the EU must produce an SBOM (software bill of materials) under the Cyber Resilience Act.

**Who feels it:**
- **AI builders** (indie makers, students, founders) ship apps they can't judge, and find out about problems from their users or from attackers.
- **Agencies and freelancers** deliver AI-built apps to clients with no proof of quality.
- **Small businesses** want ready-made software but can't tell good from dangerous. Vibe96 tries to solve this with a one-time audit, and its own figures (68 apps, 2 customer deployments) show how slowly trust builds that way.

## 2. The insight

> When making software is cheap, **trust** is the scarce good. Whoever owns trust owns the distribution of AI-built software.

A plain scanner isn't enough. Seventeen "vibe scanners" already sell for $5 to $29 a month. Trust needs four things a one-off scan lacks:

1. **Continuity.** The check runs again on every change, not once.
2. **Proof others accept.** A certificate and public report that buyers, clients and platforms recognise.
3. **Consequences.** Only checked apps get sold, and problems get fixed, not just listed.
4. **Presence where code is written.** The check runs inside AI coding tools and CI pipelines, before deploy, not on a website someone has to remember.

## 3. What we build

| Product | What it does | Who pays | Status |
|---|---|---|---|
| **Prohori Scan** | Paste a GitHub link or upload a zip. Get a 0 to 100 score across six areas, plain-language findings, how to fix each one, an SBOM and a SARIF file for GitHub. Tuned for AI-era mistakes. | Free entry point; paid for private repos and history | **Built (MVP)** |
| **Prohori Verified** | A certificate for one app version: score ≥ 75 and no critical finding. Public report page and badge, re-checked on every push. | Included in paid plans; required for the marketplace | **Gate and report built**; badge and re-checks next |
| **Prohori Market** | Buy and sell verified business apps. Only apps that pass are listed. Local payments (bKash, Nagad, cards via SSLCommerz) and global (Paddle). | Builders pay a commission on sales | **Listings, checkout flow and ledger built** with a simulated gateway |
| **Prohori Fix** | An AI agent opens a pull request that fixes the findings, priced per fixed issue. Human experts handle the rest. | Builders, agencies | Phase 2 |
| **Prohori Guard** | Runs inside Claude Code, Cursor and other agents (via an MCP server) and in CI as a pre-deploy gate. Continuous monitoring with alerts. | Paid plans | Phase 2 to 3 |
| **Prohori Comply** | SBOM history, vulnerability tracking and the reporting workflow for the EU Cyber Resilience Act. | Companies selling into the EU | Phase 4 |
| **Prohori Run** | Managed hosting for verified apps, through hosting partners rather than our own servers. | Marketplace buyers | Phase 5 (optional) |

### What makes the scanner different

Generic scanners look for generic bugs. Prohori starts from what actually broke in 2026:

- Supabase tables created without row-level security; Firebase rules open to everyone.
- Secrets placed in browser-visible settings (`NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_`, `REACT_APP_`).
- AI provider keys used straight from browser code (`dangerouslyAllowBrowser: true`).
- **AI endpoints with no login or rate limit**, which let anyone drain the owner's AI budget.
- Payment webhooks that never check the provider's signature.
- API routes and server actions that change data without checking who is asking.
- Classic injection, cross-site scripting, open CORS and disabled TLS checks.
- **AI maintainability:** does the project tell AI coding tools how to work on it safely (an `AGENTS.md` or `CLAUDE.md`)?

## 4. Who pays

| Segment | Need | Willingness to pay (*assumption*) | Why they matter |
|---|---|---|---|
| A. AI builders | "Is my app safe to launch?" | $0 to $12 a month | Volume, word of mouth, badge spread |
| B. Agencies and freelancers | Proof of quality for clients | $49 to $149 a month | Best early revenue; Bangladesh and South Asia have large freelance developer communities |
| C. Small-business buyers (Bangladesh first) | Affordable software that is safe | ৳2,000 to ৳20,000 per app | Marketplace demand; global players ignore this market |
| D. Companies selling into the EU | SBOM and vulnerability reporting | $299+ a month | High value, arrives with the 2027 deadline |
| E. Platforms (vibe-coding tools, hosts) | A trusted check inside their product | Per-scan API pricing | Fastest route to millions of scans |

## 5. Pricing (first version, to test)

| Plan | Price | Includes |
|---|---|---|
| Free | $0 | 3 scans a month, public repos, full findings, badge with Prohori branding |
| Builder | $12/month (৳1,200 locally) | Private repos, re-scan on every push, SBOM and SARIF exports, private reports |
| Agency | $59/month | 15 projects, white-label client reports, CI gate |
| Fix | $5 per fixed critical or high finding, or $49 "make it pass" | AI pull requests and human review (Phase 2) |
| Marketplace | 30% → 15% commission, tiered by builder lifetime sales | Listing, payments, licence keys, payouts |
| Comply | from $299/month | SBOM history, vulnerability tracking, reporting workflow |
| Platform API | per scan, volume pricing | Embed Prohori checks in another product |

Competitors anchor the low end ($5 to $29 a month, $19 to $299 audits). Prohori sits mid-market and earns the difference through certification, fixes and the marketplace.

### Unit economics (*assumption*)

- The rules engine needs no AI calls, so a scan costs a few seconds of server time, effectively free at small scale.
- AI explanations and fixes cost model tokens. Expect roughly $0.01 to $0.20 per scan depending on model and app size, so AI features belong in paid plans or are rate-limited.
- Target gross margin: 80% or more on subscriptions; 60 to 70% on Fix.

## 6. Why we win

1. **Trust compounds.** Every badge on a README or app footer links back to a live Prohori report. Builders advertise us because it helps them sell.
2. **Data no one else has.** Every scan (anonymised, aggregated, never storing source code) teaches us which AI-era mistakes are spreading, which sharpens the rules and the fix agent.
3. **Two-sided network.** The marketplace gives builders a reason to get verified and buyers a reason to trust the badge. Every passing scan is a potential listing.
4. **Workflow lock-in.** CI gates, monitoring history and SBOM archives are painful to move.
5. **Home-market advantage.** bKash and Nagad payments, Bangla support, local VAT and pricing are hard for a US scanner to copy and not worth their time.
6. **Neutral across platforms.** Lovable's built-in scan only covers Lovable. Agencies and marketplaces need one standard across Lovable, Bolt, Cursor, Claude Code and hand-written code.

## 7. Competition (honest view)

| Competitor type | Examples | Their strength | Our angle |
|---|---|---|---|
| Enterprise code security | Snyk, Semgrep, Sonar, GitHub Advanced Security | Depth, brand, big customers | Built for non-experts and AI-era stacks; priced for builders; plain language |
| Platform-native checks | Lovable 2.0 security scan | Built into the editor | Cross-platform; certificate others accept; marketplace |
| Small vibe scanners | Vibe App Scanner, VibeSafe and about 15 others | Cheap, fast to launch | They stop at the scan. We certify, fix, sell and monitor |
| Marketplaces with audits | Vibe96, CodeCanyon | Catalogue, buyers | Continuous checks, open rule catalogue, lower commission, local payments, faster payouts |

**Biggest threat:** an AI coding platform makes security good by default, which shrinks the pain. Mitigation: certification and the marketplace keep value even when apps get safer, because buyers still need proof.

## 8. Go-to-market, in order

1. **Free scanner launch (month 1).** "Is your AI-built app safe? Paste a GitHub link." Post in Bangladeshi and global developer communities (Facebook groups, YouTube creators like the ones covering vibe coding, Reddit, Indie Hackers, Product Hunt).
2. **Publish the data (month 2).** A "State of AI-built app security" report from anonymised scan results. Press and backlinks follow.
3. **Inside the agents (months 2 to 4).** An MCP server and a one-line instruction for Claude Code and Cursor: "run Prohori before you deploy". A GitHub Action for CI.
4. **The badge loop (month 3 onward).** "Verified by Prohori" badges on READMEs and app footers.
5. **Agency programme (months 3 to 6).** White-label reports, referral commission, first in Bangladesh.
6. **Marketplace (months 4 to 8).** Invite builders whose apps pass; seed 50 verified apps; reach small businesses through Facebook ads and local partners; take bKash and Nagad.
7. **Platform deals (month 6 onward).** Use our scan data to pitch a "Verified by Prohori" integration to vibe-coding tools and hosts.

## 9. Bangladesh setup

- **Company:** a Bangladesh private limited company for the local market. Add a foreign entity (US LLC or UK Ltd) later if global card payments through Stripe and paying foreign builders become necessary. Confirm both with a lawyer and an accountant.
- **Payments:** SSLCommerz for bKash, Nagad, Rocket and local cards; Paddle for international buyers. Pay Bangladeshi builders by bKash, Nagad or bank (BEFTN/NPSB). Start with Bangladeshi builders only, because outward payments to foreign builders face Bangladesh Bank rules.
- **Team and cost:** one founder with Claude Code costs about ৳36,000 to ৳60,000 a month in tools and servers. A team of three costs about ৳2.5 to 4 lakh a month.
- **Rules to check:** the Digital Commerce Guidelines (advance payment, delivery, refunds), VAT, trade licence, TIN and Digital Business Identity registration.

## 10. Revenue scenarios at month 18 (*illustrative, assumption-driven*)

| Scenario | Assumptions | Monthly revenue |
|---|---|---|
| Conservative | 30,000 total scans, 1.5% become paying at about $15; small marketplace | About $9,000 (about ৳11 lakh) |
| Base | 150,000 scans, 2.5% paying at about $18; Fix $15,000; marketplace $10,000 | About $90,000 (about $1.1M a year) |
| Upside | Default pre-deploy check inside AI coding tools; 1M+ scans; one platform API deal | $300,000+ |

What "getting rich" realistically takes: growing recurring revenue fast enough to raise money or attract a buyer. Security and developer-tool companies are commonly acquired by larger security, cloud or developer-platform companies. The two things that decide the outcome are distribution (being inside the tools where code is written) and a trust brand people recognise. Most startups fail, so the milestones below exist to show early whether this one is working.

## 11. Milestones and stop signals

| When | Milestone | Stop or pivot signal |
|---|---|---|
| Week 4 | Free scanner live; 1,000 scans; at least 20% of scanned apps have a critical finding | Under 5% critical: the pain is smaller than the research says |
| Week 10 | 100 users re-scan after fixing; 30 paying customers | Nobody re-scans: people don't act on findings |
| Month 6 | $5,000 a month in revenue; 50 verified listings; 100 marketplace orders | Free-to-paid under 0.5% after three pricing tries |
| Month 12 | $30,000 a month or one platform partnership | Fewer than 10 marketplace orders a month: drop the marketplace, focus on Scan, Fix and Comply |

## 12. Risks

| Risk | Mitigation |
|---|---|
| A missed vulnerability causes harm (false negative) | Say plainly what is checked; the certificate reads "passed automated checks on date X", never "secure"; publish the rule catalogue; add insurance later |
| Too many false alarms | Confidence levels, inline suppressions with a required reason, fast rule fixes from user feedback |
| AI platforms build their own checks | Stay cross-platform; the certificate and marketplace keep value |
| AI costs grow faster than revenue | Rules engine runs without AI; AI only in paid plans, with budgets per user |
| We get breached while holding customer code | Scan in memory, never store source code, keep only findings with secrets masked, delete uploads after the scan |
| Payment and legal limits in Bangladesh | SSLCommerz plus Paddle; local builders first; lawyer review before launch |
| A new brand lacks credibility | Open rule catalogue, published methodology, Prohori scans its own code in public |

## 13. Roadmap

| Phase | Goal | Done when |
|---|---|---|
| **0. Foundation** (this session) | Audit engine, web app with scan, report, marketplace and simulated checkout; full documentation | Tests pass, app runs locally, `progress.md` written |
| 1. Public launch | Deploy the free scanner; accounts; badge; storage in Postgres | 1,000 real scans |
| 2. Fix and Guard | AI explanations and fix pull requests; MCP server; GitHub App and Action | First paid fixes; scans running inside agents |
| 3. Paid plans | Paddle and SSLCommerz live; continuous monitoring; private repos | First $1,000 a month |
| 4. Marketplace live | Real listings, licence delivery, builder payouts, reviews, refunds | 100 orders |
| 5. Comply | SBOM history, vulnerability tracking, CRA reporting workflow | First compliance customer |
| 6. Run | Managed deploys through partners | Optional, demand-driven |

Current status and next steps: see [../progress.md](../progress.md).

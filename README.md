# Prohori

**The trust layer for AI-built software:** scan, certify and sell the apps that AI writes.

*Prohori* (প্রহরী) means "guard" in Bangla. It is a working name; check trademarks and domains before public use.

- Business plan: [docs/scenario.md](docs/scenario.md)
- Evidence and sources: [docs/research.md](docs/research.md)
- Technical design: [docs/architecture.md](docs/architecture.md)
- **Status and next steps: [progress.md](progress.md)**, read this first when resuming work

## What is in this repository

| Path | What |
|---|---|
| `packages/audit-engine` | The audit engine and the `prohori` command-line tool. Zero runtime dependencies. |
| `apps/web` | Next.js web app: free scanner, reports, verified-only marketplace, checkout with a simulated gateway |
| `docs/` | Research, scenario, architecture |
| `progress.md` | Current status, next steps, how to resume |
| `AGENTS.md` | Rules for AI coding tools working in this repository |

## Requirements

- Node.js 22.18 or newer (24 recommended); Node runs the engine's TypeScript directly
- pnpm 10 or newer

## Quick start

```bash
pnpm install
```

```bash
pnpm test
```

```bash
pnpm dev
```

The web app runs at http://localhost:3000. Use **Scan** to check a public GitHub repository, upload a zip, or try the built-in vulnerable demo.

## Scan a project from the command line

```bash
pnpm scan path/to/project
```

Options:

| Option | Meaning |
|---|---|
| `--format text\|json\|md\|sarif` | Output format (default `text`) |
| `--out <file>` | Write the report to a file |
| `--sbom <file>` | Also write a CycloneDX 1.5 SBOM |
| `--online` | Check dependencies against OSV.dev for known vulnerabilities |
| `--fail-on gate\|critical\|high\|medium\|low\|none` | When to exit with code 1 (default `gate`: not verified) |
| `--no-gitignore` | Also scan files listed in `.gitignore` |

`pnpm scan:self` scans this repository with its own engine.

## What the engine checks

39 rules in six areas, tuned to the mistakes behind 2026's breaches of AI-built apps: Supabase tables without row-level security, open Firebase rules, secrets in `NEXT_PUBLIC_`/`VITE_` variables, AI endpoints anyone can call, unsigned payment webhooks, routes and server actions without auth, injection, and more. Run `pnpm scan -- --help` or see `packages/audit-engine/src/rules/`.

**Verified** means: score of at least 75 out of 100, no critical finding, application code present and every check run. It is a result of automated checks on a given date, not a guarantee.

## Suppressing a finding

On the line (or the line above): `// prohori-ignore <rule-id>: <reason>`. For whole folders, add a line to `.prohoriignore`: `<rule-id or *> <path prefix>: <reason>`. A reason is required, and suppressed findings stay listed in reports.

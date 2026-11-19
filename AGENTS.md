# Guide for AI coding tools

Read `progress.md` first: it has the current status and the next steps. The business plan is in `docs/scenario.md`, the technical design in `docs/architecture.md`.

## Commands

| Task | Command |
|---|---|
| Install | `pnpm install` |
| Engine tests | `pnpm test` |
| Type check everything | `pnpm typecheck` |
| Web app (dev) | `pnpm dev` (http://localhost:3000) |
| Scan a folder | `pnpm scan <path>` |
| Scan this repository | `pnpm scan:self` |

## Rules

- **The engine has zero runtime dependencies.** Don't add packages to `packages/audit-engine`.
- **Node runs the engine's TypeScript directly** (type stripping). Use `import type` for types, include the `.ts` extension in relative imports, and don't use enums, namespaces or constructor parameter properties. `tsc` enforces this through `verbatimModuleSyntax` and `erasableSyntaxOnly`.
- **Never write a complete fake secret in the repository.** In tests, assemble it with `fake('sk', '_live_', '...')` from `test/helpers.ts`.
- **Every new rule needs a test** in `packages/audit-engine/test/`, and `CLEAN_APP` in `test/helpers.ts` must stay free of findings.
- **Suppressions need a reason.** Use `prohori-ignore <rule-id>: <reason>` or a `.prohoriignore` line, never a silent skip.
- **Secrets:** never in `NEXT_PUBLIC_` variables, never in committed `.env` files. Use `.env.example` with empty values.
- **Money:** amounts are integers in minor units (paisa, cents). Payment status changes only through `handleGatewayCallback()` in `apps/web/lib/orders.ts`, which verifies signatures and amounts.
- **Before finishing a session:** run `pnpm test`, `pnpm typecheck` and `pnpm scan:self`, then update `progress.md` (Status, Done, Next steps, Session log), commit, and push to `origin main` (private GitHub repository).

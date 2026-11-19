import type { ProjectFile, Rule, ScanContext } from '../types.ts';
import { CODE_EXTS, extOf, isTestPath, usesEnvVars } from './helpers.ts';

const README_RE = /^readme(?:\.(?:md|mdx|txt|rst))?$/i;
const SETUP_RE =
  /\b(?:npm|pnpm|yarn|bun)\s+(?:install|i|ci|run|dev|start)\b|composer\s+install|pip\s+install|poetry\s+install|uv\s+sync|dotnet\s+(?:restore|run|build)|docker(?:\s+compose|-compose)\s+up|php\s+artisan|python\s+manage\.py|\bmake\s+\w+/i;

function rootFile(ctx: ScanContext, re: RegExp): ProjectFile | undefined {
  return ctx.files.find((f) => !f.path.includes('/') && re.test(f.path));
}

function anyPath(ctx: ScanContext, re: RegExp): boolean {
  for (const p of ctx.paths) if (re.test(p)) return true;
  return false;
}

const readme: Rule = {
  id: 'maintainability/readme',
  title: 'README missing or very short',
  category: 'maintainability',
  severity: 'medium',
  description: 'Without a useful README, buyers, teammates and AI coding tools have to guess what the project does and how to run it.',
  remediation: 'Add a README that says what the app does, what it needs (runtime, database, accounts), how to install and run it, and how to deploy it.',
  check(ctx) {
    const file = rootFile(ctx, README_RE);
    if (!file) return [{ message: 'The project has no README.' }];
    if (file.content.trim().length < 300) return [{ file: file.path, line: 1, severity: 'low', message: 'The README is very short.' }];
    return [];
  },
};

const setupSteps: Rule = {
  id: 'maintainability/setup-steps',
  title: 'README has no setup commands',
  category: 'maintainability',
  severity: 'low',
  description: 'The README does not show the commands to install and start the app, so a clean setup depends on guesswork.',
  remediation: 'Add a "Getting started" section with the exact commands, for example "npm ci", "npm run dev" and how to run migrations.',
  check(ctx) {
    const file = rootFile(ctx, README_RE);
    if (!file || SETUP_RE.test(file.content)) return [];
    return [{ file: file.path, line: 1, message: 'The README has no install or run commands.' }];
  },
};

const envExample: Rule = {
  id: 'maintainability/env-example',
  title: 'No .env.example',
  category: 'maintainability',
  severity: 'low',
  description: 'The code reads environment variables, but there is no example file listing which ones are needed.',
  remediation: 'Add a .env.example with every variable name and empty or dummy values, and explain each one in the README.',
  check(ctx) {
    if (!usesEnvVars(ctx)) return [];
    if (anyPath(ctx, /(^|\/)(?:\.env(?:\.[\w-]+)*\.(?:example|sample|template|dist)|(?:example|sample)\.env)$/i)) return [];
    if (anyPath(ctx, /(^|\/)appsettings(?:\.[\w-]+)?\.json$/i)) return [];
    return [{ message: 'The code reads environment variables but there is no .env.example.' }];
  },
};

const tests: Rule = {
  id: 'maintainability/tests',
  title: 'No automated tests',
  category: 'maintainability',
  severity: 'low',
  description: 'No test files were found, so every change, including changes made by AI tools, can break things silently.',
  remediation: 'Start with a few tests for the most important flows (sign-in, checkout, saving data) and run them in CI.',
  check(ctx) {
    if (ctx.codeFiles.length === 0) return [];
    const found = ctx.files.some((f) => isTestPath(f.path) && CODE_EXTS.has(extOf(f.path)));
    return found ? [] : [{ message: 'No test files were found.' }];
  },
};

const license: Rule = {
  id: 'maintainability/license',
  title: 'No licence file',
  category: 'maintainability',
  severity: 'info',
  description: 'There is no LICENSE file, so it is unclear what others may do with the code.',
  remediation: 'Add a LICENSE file. For software sold on a marketplace, use the marketplace licence or a commercial licence.',
  check(ctx) {
    return anyPath(ctx, /^(?:license|licence|copying)(?:\.(?:md|txt))?$/i) ? [] : [{ message: 'No LICENSE file at the project root.' }];
  },
};

const ci: Rule = {
  id: 'maintainability/ci',
  title: 'No continuous integration',
  category: 'maintainability',
  severity: 'info',
  description: 'No CI configuration was found, so tests and checks only run when someone remembers.',
  remediation: 'Add a CI workflow (for example .github/workflows/ci.yml) that installs, builds, runs tests and runs Prohori on every push.',
  check(ctx) {
    return anyPath(ctx, /^(?:\.github\/workflows\/[^/]+\.ya?ml|\.gitlab-ci\.yml|\.circleci\/config\.yml|azure-pipelines\.yml|bitbucket-pipelines\.yml)$/i)
      ? []
      : [{ message: 'No CI configuration found.' }];
  },
};

const agentGuide: Rule = {
  id: 'maintainability/agent-guide',
  title: 'No guide for AI coding tools',
  category: 'maintainability',
  severity: 'info',
  description: 'There is no AGENTS.md, CLAUDE.md or similar file. AI coding tools then change the project without knowing its rules, such as where secrets live or which tests to run.',
  remediation: 'Add an AGENTS.md (or CLAUDE.md) with how to run, test and deploy, the folder structure, and the rules to keep, for example "never put secrets in NEXT_PUBLIC_ variables".',
  check(ctx) {
    return anyPath(ctx, /(^|\/)(?:AGENTS\.md|CLAUDE\.md|GEMINI\.md|\.cursorrules|\.windsurfrules|\.github\/copilot-instructions\.md)$|(^|\/)\.cursor\/rules\//i)
      ? []
      : [{ message: 'No AGENTS.md or CLAUDE.md for AI coding tools.' }];
  },
};

export const maintainabilityRules: Rule[] = [readme, setupSteps, envExample, tests, license, ci, agentGuide];

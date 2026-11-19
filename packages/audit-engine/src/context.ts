import { extractDependencies } from './deps/extract.ts';
import { CODE_EXTS, extOf, hasDirective } from './rules/helpers.ts';
import type { Dependency, ProjectFile, ScanContext, StackId } from './types.ts';

export function isCodeFile(p: string): boolean {
  if (/\.d\.ts$/.test(p) || /\.min\.js$/.test(p)) return false;
  return CODE_EXTS.has(extOf(p));
}

function detectStacks(files: ProjectFile[], deps: Dependency[]): Set<StackId> {
  const stacks = new Set<StackId>();
  const names = new Set(deps.map((d) => d.name.toLowerCase()));
  const has = (n: string) => names.has(n);
  const hasPrefix = (prefix: string) => [...names].some((n) => n.startsWith(prefix));
  const anyPath = (re: RegExp) => files.some((f) => re.test(f.path));

  if (anyPath(/(^|\/)package\.json$/)) stacks.add('node');
  if (has('next')) {
    stacks.add('nextjs');
    stacks.add('react');
  }
  if (has('react')) stacks.add('react');
  if (has('vite')) stacks.add('vite');
  if (has('vue') || has('nuxt')) stacks.add('vue');
  if (has('svelte') || has('@sveltejs/kit')) stacks.add('svelte');
  if (has('express') || has('fastify') || has('koa') || has('hono')) stacks.add('express');
  if (has('@supabase/supabase-js') || has('@supabase/ssr') || anyPath(/(^|\/)supabase\/(migrations\/|config\.toml$)/)) stacks.add('supabase');
  if (has('firebase') || has('firebase-admin') || anyPath(/(^|\/)(firebase\.json|firestore\.rules|database\.rules\.json)$/)) stacks.add('firebase');
  if (has('prisma') || has('@prisma/client') || anyPath(/(^|\/)schema\.prisma$/)) stacks.add('prisma');
  if (has('stripe') || has('@stripe/stripe-js')) stacks.add('stripe');
  if (
    has('openai') ||
    has('@anthropic-ai/sdk') ||
    has('anthropic') ||
    has('ai') ||
    hasPrefix('@ai-sdk/') ||
    hasPrefix('@langchain/') ||
    has('langchain') ||
    has('@google/genai') ||
    has('@google/generative-ai') ||
    has('groq-sdk')
  ) {
    stacks.add('ai-sdk');
  }
  if (anyPath(/(^|\/)composer\.json$/)) stacks.add('php');
  if (has('laravel/framework')) stacks.add('laravel');
  if (anyPath(/(^|\/)(requirements[^/]*\.txt|pyproject\.toml|Pipfile|setup\.py)$/)) stacks.add('python');
  if (has('django')) stacks.add('django');
  if (has('flask')) stacks.add('flask');
  if (has('fastapi')) stacks.add('fastapi');
  if (anyPath(/\.(csproj|sln)$/)) stacks.add('dotnet');
  return stacks;
}

function isClientFile(file: ProjectFile, stacks: Set<StackId>): boolean {
  if (hasDirective(file, 'use client')) return true;
  const p = file.path;
  if (/\.(vue|svelte)$/.test(p) && !/\.server\./.test(p)) return true;
  if (/(^|\/)public\/.+\.js$/.test(p)) return true;
  if (
    !stacks.has('nextjs') &&
    (stacks.has('vite') || stacks.has('react')) &&
    /(^|\/)src\/.+\.(jsx?|tsx?)$/.test(p) &&
    !/(^|\/)(server|api|functions|backend|scripts)\//.test(p)
  ) {
    return true;
  }
  return false;
}

export function buildContext(projectName: string, files: ProjectFile[], paths: Set<string>): ScanContext {
  const { dependencies, lockfiles, manifests } = extractDependencies(files);
  const stacks = detectStacks(files, dependencies);
  return {
    projectName,
    files,
    byPath: new Map(files.map((f) => [f.path, f])),
    paths,
    codeFiles: files.filter((f) => isCodeFile(f.path)),
    stacks,
    dependencies,
    manifests,
    lockfiles,
    vulnerabilities: [],
    isClientFile: (file) => isClientFile(file, stacks),
  };
}

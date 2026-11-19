import type { Rule } from '../types.ts';
import { accessRules } from './access-control.ts';
import { codeRules } from './code-safety.ts';
import { dataAccessRules } from './data-access.ts';
import { dependencyRules } from './dependencies.ts';
import { maintainabilityRules } from './maintainability.ts';
import { productionRules } from './production.ts';
import { secretRules } from './secrets.ts';

export const ALL_RULES: Rule[] = [
  ...secretRules,
  ...dataAccessRules,
  ...accessRules,
  ...codeRules,
  ...dependencyRules,
  ...productionRules,
  ...maintainabilityRules,
];

export const RULES_BY_ID = new Map(ALL_RULES.map((r) => [r.id, r]));

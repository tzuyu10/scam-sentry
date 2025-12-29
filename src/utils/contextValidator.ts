// src/utils/contextValidator.ts

import type { Match, Category } from '../types/types';

/**
 * Contextual risk rules
 * Deterministic, rule-based, post-DFA
 */

interface ContextRule {
  when: Category[];
  boost: number;
  reason: string;
}

/**
 * Rules are ordered by severity
 */
const CONTEXT_RULES: ContextRule[] = [
  {
    when: ['URGENCY', 'URL'],
    boost: 0.25,
    reason: 'Urgent message with embedded link'
  },
  {
    when: ['PHISHING', 'URL'],
    boost: 0.3,
    reason: 'Phishing language combined with link'
  },
  {
    when: ['IMPERSONATION', 'URL'],
    boost: 0.35,
    reason: 'Brand impersonation with link'
  },
  {
    when: ['URGENCY', 'PHISHING'],
    boost: 0.2,
    reason: 'Urgency used to pressure user'
  },
  {
    when: ['URGENCY', 'PHISHING', 'URL'],
    boost: 0.4,
    reason: 'Classic high-risk scam pattern'
  }
];

/**
 * Apply context-based weight adjustment
 */
export function applyContextBoost(
  matches: Match[]
): { adjustedMatches: Match[]; contextBoost: number; reasons: string[] } {
  const presentCategories = new Set<Category>(
    matches.map(m => m.category)
  );

  let contextBoost = 0;
  const reasons: string[] = [];

  for (const rule of CONTEXT_RULES) {
    const satisfied = rule.when.every(cat =>
      presentCategories.has(cat)
    );

    if (satisfied) {
      contextBoost += rule.boost;
      reasons.push(rule.reason);
    }
  }

  return {
    adjustedMatches: matches,
    contextBoost,
    reasons
  };
}

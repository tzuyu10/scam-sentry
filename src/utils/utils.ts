// src/utils/utils.ts

import { PATTERNS } from '../data/patterns';
import { AhoCorasickDFA } from '../classes/AhoCorasickDFA';
import { URLDFA } from '../classes/URLDFA';
import { validateAndAdjustURLWeight, shouldFlagURL } from './urlValidator';
import type { Match, ScanResult, Category } from '../types/types';
import { applyContextBoost } from './contextValidator';

interface DFAConfig {
  dfa: AhoCorasickDFA;
  category: Category;
}

/**
 * Build DFAs ONCE (singleton instances)
 * DFA is immutable after construction (formal automata requirement)
 */
const dfaConfigs: DFAConfig[] = [
  { dfa: new AhoCorasickDFA(PATTERNS.URGENCY), category: 'URGENCY' },
  { dfa: new AhoCorasickDFA(PATTERNS.FINANCIAL), category: 'FINANCIAL' },
  { dfa: new AhoCorasickDFA(PATTERNS.PHISHING), category: 'PHISHING' },
  { dfa: new AhoCorasickDFA(PATTERNS.IMPERSONATION), category: 'IMPERSONATION' }
];

const urlDFA = new URLDFA(PATTERNS.URL);

/**
 * Main scan function
 * Combines DFA outputs with deterministic post-processing
 */
export function scanMessage(msg: string): ScanResult {
  const matches: Match[] = [];

  /* ---------- Step 1: Non-URL DFAs ---------- */
  for (const { dfa, category } of dfaConfigs) {
    const results = dfa.scan(msg);

    for (const r of results) {
      matches.push({
        pattern: r.pattern,
        weight: r.weight,
        start: r.start,
        end: r.end,
        category
      });
    }
  }

  /* ---------- Step 2: Context collection ---------- */
  const contextCategories = new Set<Category>();
  for (const m of matches) {
    contextCategories.add(m.category);
  }

  /* ---------- Step 3: URL DFA + validation ---------- */
  const urlMatches = urlDFA.scan(msg);

  for (const u of urlMatches) {
    const extractedUrl = msg.substring(u.start, u.end);

    const adjustedWeight = validateAndAdjustURLWeight(
      extractedUrl,
      u.weight
    );

    if (
      adjustedWeight > 0 &&
      shouldFlagURL(extractedUrl, contextCategories)
    ) {
      matches.push({
        pattern: u.pattern,
        weight: adjustedWeight,
        start: u.start,
        end: u.end,
        category: 'URL'
      });
    }
  }

  /* ---------- Step 4: De-duplicate overlaps ---------- */
  const uniqueMatches = new Map<string, Match>();

  for (const m of matches) {
    const key = `${m.category}:${m.start}:${m.end}`;

    // Keep the highest-weight match for overlapping entries
    if (
      !uniqueMatches.has(key) ||
      uniqueMatches.get(key)!.weight < m.weight
    ) {
      uniqueMatches.set(key, m);
    }
  }

/* ---------- Step 5: Context-aware scoring ---------- */
  const { contextBoost } = applyContextBoost(
    Array.from(uniqueMatches.values())
  );

  let totalWeight = contextBoost;

  for (const m of uniqueMatches.values()) {
    totalWeight += m.weight;
  }

  const score = Math.min(100, Math.round(totalWeight * 100));

  return {
    score,
    matches: Array.from(uniqueMatches.values())
  };
}

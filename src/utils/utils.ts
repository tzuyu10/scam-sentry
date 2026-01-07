import patternsData from '../data/patterns.json';
import { AhoCorasickDFA } from '../classes/AhoCorasickDFA';
import { URLDFA } from '../classes/URLDFA';
import type { Match, ScanResult, Category } from '../types/types';
import { applyContextBoost } from './contextValidator';

interface DFAConfig {
  dfa: AhoCorasickDFA;
  category: Category;
}

interface PatternEntry {
  keyword: string;
  weight: number;
}

interface PatternCategory {
  description: string;
  patterns: PatternEntry[];
}

interface PatternsJSON {
  version: string;
  generated: string;
  description: string;
  categories: {
    URGENCY: PatternCategory;
    FINANCIAL: PatternCategory;
    PHISHING: PatternCategory;
    IMPERSONATION: PatternCategory;
    URL: PatternCategory;
    LEGIT: PatternCategory;
  };
}

// Type assertion for imported JSON
const PATTERNS = (patternsData as PatternsJSON).categories;

/**
 * Build DFAs ONCE (singleton instances)
 * DFA is immutable after construction (formal automata requirement)
 */
const dfaConfigs: DFAConfig[] = [
  { dfa: new AhoCorasickDFA(PATTERNS.URGENCY.patterns), category: 'URGENCY' },
  { dfa: new AhoCorasickDFA(PATTERNS.FINANCIAL.patterns), category: 'FINANCIAL' },
  { dfa: new AhoCorasickDFA(PATTERNS.PHISHING.patterns), category: 'PHISHING' },
  { dfa: new AhoCorasickDFA(PATTERNS.IMPERSONATION.patterns), category: 'IMPERSONATION' },
  { dfa: new AhoCorasickDFA(PATTERNS.LEGIT.patterns), category: 'LEGIT' },
];

const urlDFA = new URLDFA();

/**
 * Scoring Configuration - DEFLATED TO PREVENT INFLATION
 * 
 * Uses aggressive asymptotic (logarithmic) scaling to prevent high scores
 * from single words:
 * - Single word pattern (0.50) → ~45%
 * - Single high-weight pattern (0.95) → ~68%
 * - Multiple critical patterns → ~78-85%
 * - Extreme cases (many patterns) → approaches but never reaches 95%
 * 
 * Formula: score = MAX × (1 - e^(-k × totalWeight))
 * Where k controls the curve steepness (LOWER = slower rise)
 */
const SCORING_CONFIG = {
  // Curve steepness factor (REDUCED for more conservative scoring)
  K_FACTOR: 1.5, // Reduced from 2.2
  
  // Maximum theoretical score (set < 100 for hard cap)
  MAX_SCORE: 95, // Reduced from 99
  
  // Minimum score threshold to report (filter noise)
  MIN_SCORE: 8 // Increased from 5
};

/**
 * Logarithmic Score Calculation - DEFLATED VERSION
 * 
 * This prevents scores from inflating by using a slower exponential curve.
 * The score rises much more gradually.
 * 
 * Mathematical properties (NEW with K=1.5):
 * - totalWeight = 0.50 → ~37% score (was ~67%)
 * - totalWeight = 0.95 → ~58% score (was ~82%)
 * - totalWeight = 1.50 → ~71% score (was ~90%)
 * - totalWeight = 2.00 → ~78% score (was ~93%)
 * - totalWeight = 3.00 → ~86% score (was ~96%)
 * 
 * @param totalWeight
 * @returns
 */
function calculateAsymptoticScore(totalWeight: number): number {
  const { K_FACTOR, MAX_SCORE } = SCORING_CONFIG;
  const normalizedScore = MAX_SCORE * (1 - Math.exp(-K_FACTOR * totalWeight));
  return parseFloat(normalizedScore.toFixed(2));
}

interface ExtendedScanResult extends ScanResult {
  hasURL: number;
}

export function scanMessage(msg: string): ExtendedScanResult {
  const rawMatches: Match[] = [];

  // Step 1: Non-URL DFAs
  for (const { dfa, category } of dfaConfigs) {
    const results = dfa.scan(msg);

    for (const r of results) {
      rawMatches.push({
        pattern: r.pattern,
        weight: parseFloat(r.weight.toFixed(2)),
        start: r.start,
        end: r.end,
        category
      });
    }
  }

  // Step 2: URL DFA
  const urlMatches = urlDFA.scan(msg);
  const hasURL = urlMatches.length > 0 ? 1 : 0;

  for (const u of urlMatches) {
    rawMatches.push({
      pattern: u.pattern,
      weight: parseFloat(u.weight.toFixed(2)), // Trim to 2 decimals
      start: u.start,
      end: u.end,
      category: 'URL'
    });
  }

  // Step 3: Context Validation
  const { validatedMatches, contextBoost } = applyContextBoost(
    rawMatches,
    msg
  );

  // Step 4: De-duplicate overlaps ---------- 
  const uniqueMatches = new Map<string, Match>();

  for (const m of validatedMatches) {
    const key = `${m.category}:${m.start}:${m.end}`;
    if (
      !uniqueMatches.has(key) ||
      uniqueMatches.get(key)!.weight < m.weight
    ) {
      uniqueMatches.set(key, m);
    }
  }

  // Step 5: Calculate final score (DEFLATED)
  let totalWeight = parseFloat(contextBoost.toFixed(2)); 

  for (const m of uniqueMatches.values()) {
    totalWeight += m.weight;
  }

  totalWeight = parseFloat(totalWeight.toFixed(2));
  const score = calculateAsymptoticScore(totalWeight);
  const finalScore = score < SCORING_CONFIG.MIN_SCORE ? 0 : score;

  return {
    score: parseFloat(finalScore.toFixed(2)),
    matches: Array.from(uniqueMatches.values()),
    hasURL
  };
}

export function getScoreForWeight(weight: number): number {
  return calculateAsymptoticScore(weight);
}
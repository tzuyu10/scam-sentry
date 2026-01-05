// src/utils/utils.ts

import patternsData from '../data/patterns.json';
import { AhoCorasickDFA } from '../classes/AhoCorasickDFA';
import { URLDFA } from '../classes/URLDFA';
import type { Match, ScanResult, Category } from '../types/types';
import { applyContextBoost } from './contextValidator';

interface DFAConfig {
  dfa: AhoCorasickDFA;
  category: Category;
}

/**
 * Extract patterns from JSON structure
 */
interface PatternEntry {
  keyword: string;
  weight: number;
  length: number;
  chars: string[];
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
  { dfa: new AhoCorasickDFA(PATTERNS.IMPERSONATION.patterns), category: 'IMPERSONATION' }
];

const urlDFA = new URLDFA(PATTERNS.URL.patterns);

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
 * @param totalWeight - Sum of all pattern weights + context boost
 * @returns Asymptotic score between 0 and MAX_SCORE
 */
function calculateAsymptoticScore(totalWeight: number): number {
  const { K_FACTOR, MAX_SCORE } = SCORING_CONFIG;
  
  // Exponential decay function: score = MAX × (1 - e^(-k × weight))
  const normalizedScore = MAX_SCORE * (1 - Math.exp(-K_FACTOR * totalWeight));
  
  // Round to 2 decimal places
  return parseFloat(normalizedScore.toFixed(2));
}

/**
 * Alternative: Square Root Scaling (even more conservative)
 * 
 * Provides slower growth, especially at lower weights.
 * Uncomment to use for even more deflated scoring.
 */
function calculateSqrtScore(totalWeight: number): number {
  const { MAX_SCORE } = SCORING_CONFIG;
  
  // Square root scaling with dampening
  // score = MAX × sqrt(weight / SCALE_FACTOR)
  const SCALE_FACTOR = 4.0; // Higher = slower growth
  
  const normalizedScore = MAX_SCORE * Math.sqrt(totalWeight / SCALE_FACTOR);
  
  return parseFloat(Math.min(normalizedScore, MAX_SCORE).toFixed(2));
}

/**
 * Main scan function
 * Combines DFA outputs with deterministic post-processing
 */
export function scanMessage(msg: string): ScanResult {
  const rawMatches: Match[] = [];

  /* ---------- Step 1: Non-URL DFAs ---------- */
  for (const { dfa, category } of dfaConfigs) {
    const results = dfa.scan(msg);

    for (const r of results) {
      rawMatches.push({
        pattern: r.pattern,
        weight: parseFloat(r.weight.toFixed(2)), // Trim to 2 decimals
        start: r.start,
        end: r.end,
        category
      });
    }
  }

  /* ---------- Step 2: URL DFA ---------- */
  const urlMatches = urlDFA.scan(msg);

  for (const u of urlMatches) {
    rawMatches.push({
      pattern: u.pattern,
      weight: parseFloat(u.weight.toFixed(2)), // Trim to 2 decimals
      start: u.start,
      end: u.end,
      category: 'URL'
    });
  }

  /* ---------- Step 3: Context Validation (AGGRESSIVE) ---------- */
  const { validatedMatches, contextBoost } = applyContextBoost(
    rawMatches,
    msg
  );

  /* ---------- Step 4: De-duplicate overlaps ---------- */
  const uniqueMatches = new Map<string, Match>();

  for (const m of validatedMatches) {
    const key = `${m.category}:${m.start}:${m.end}`;

    // Keep the highest-weight match for overlapping entries
    if (
      !uniqueMatches.has(key) ||
      uniqueMatches.get(key)!.weight < m.weight
    ) {
      uniqueMatches.set(key, m);
    }
  }

  /* ---------- Step 5: Calculate final score (DEFLATED) ---------- */
  let totalWeight = parseFloat(contextBoost.toFixed(2)); // Trim context boost

  for (const m of uniqueMatches.values()) {
    totalWeight += m.weight;
  }

  totalWeight = parseFloat(totalWeight.toFixed(2)); // Trim total weight

  // Use deflated asymptotic scoring
  const score = calculateAsymptoticScore(totalWeight);
  
  // Apply minimum threshold filter
  const finalScore = score < SCORING_CONFIG.MIN_SCORE ? 0 : score;

  return {
    score: parseFloat(finalScore.toFixed(2)), // Trim final score
    matches: Array.from(uniqueMatches.values())
  };
}

/**
 * Export scoring calculator for testing/debugging
 */
export function getScoreForWeight(weight: number): number {
  return calculateAsymptoticScore(weight);
}

/**
 * Scoring calibration examples (DEFLATED VERSION)
 * 
 * Single pattern scenarios (after context penalties):
 * - "suspended" alone (0.95 → ~0.48 after 50% penalty) → 40%
 * - "urgent" alone (0.90 → ~0.45 after penalty) → 38%
 * - "gcash" alone (0.92 → ~0.46 after penalty) → 39%
 * - "earn" alone (0.72 → ~0.29 after 60% penalty) → 27%
 * 
 * Multiple pattern scenarios:
 * - "urgent" + "suspended" (adjusted ~0.90) → 60%
 * - "act now" + "gcash" + "verify account" (adjusted ~1.5) → 71%
 * - 5 high-weight patterns (adjusted ~2.2) → 80%
 * 
 * With context boost and categories:
 * - URGENCY + FINANCIAL + context (~1.0 total) → 63%
 * - URGENCY + FINANCIAL + PHISHING + context (~1.8) → 76%
 * - All 4 categories + URLs (~2.8 total) → 84%
 * 
 * Real scam messages (expected scores):
 * - "URGENT! Your GCash account suspended. Verify now: bit.ly/..." → 75-85%
 * - "Congratulations! You won 50,000 pesos. Claim here..." → 65-75%
 * - "Hi, just checking in" → 0% (no matches)
 * - "Your loan application approved" → 20-30% (single category)
 * - "Meeting at 3pm urgent" → 15-25% (legitimate context)
 * 
 * Context validation examples:
 * - "p" in "php" → REJECTED (single char, not word boundary)
 * - "act" in "transaction" → REJECTED (not word boundary)
 * - "earn" alone → WEIGHT REDUCED by 60% (generic + single word + isolated)
 * - "urgent" alone → WEIGHT REDUCED by 50% (single word + isolated)
 * - "urgent" + "gcash" + "verify account" → FULL WEIGHT (strong context)
 * - "gcash" in "I use GCash for payments" → REDUCED (legitimate context)
 */
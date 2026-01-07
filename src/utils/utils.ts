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

const PATTERNS = (patternsData as PatternsJSON).categories;

const dfaConfigs: DFAConfig[] = [
  { dfa: new AhoCorasickDFA(PATTERNS.URGENCY.patterns), category: 'URGENCY' },
  { dfa: new AhoCorasickDFA(PATTERNS.FINANCIAL.patterns), category: 'FINANCIAL' },
  { dfa: new AhoCorasickDFA(PATTERNS.PHISHING.patterns), category: 'PHISHING' },
  { dfa: new AhoCorasickDFA(PATTERNS.IMPERSONATION.patterns), category: 'IMPERSONATION' },
  { dfa: new AhoCorasickDFA(PATTERNS.LEGIT.patterns), category: 'LEGIT' },
];

const urlDFA = new URLDFA();

const SCORING_CONFIG = {
  K_FACTOR: 1.5, 
  
  MAX_SCORE: 95, 
  
  MIN_SCORE: 8 
};

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

  const urlMatches = urlDFA.scan(msg);
  const hasURL = urlMatches.length > 0 ? 1 : 0;

  for (const u of urlMatches) {
    rawMatches.push({
      pattern: u.pattern,
      weight: parseFloat(u.weight.toFixed(2)), 
      start: u.start,
      end: u.end,
      category: 'URL'
    });
  }

  const { validatedMatches, contextBoost } = applyContextBoost(
    rawMatches,
    msg
  );

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

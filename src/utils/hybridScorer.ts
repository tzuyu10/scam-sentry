// src/utils/hybridScorer.ts

import type { ScanResult, Category } from '../types/types';

/**
 * Feature vector extracted from DFA results
 */
interface FeatureVector {
  totalMatches: number;
  totalWeight: number;
  uniqueCategories: number;
  hasURL: number;
  hasPhishing: number;
  hasUrgency: number;
  textLength: number;
}

/**
 * Simple ML model (logistic-style scoring)
 * This is intentionally simple & explainable
 */
function mlPredict(features: FeatureVector): number {
  let score = 0;

  score += features.totalMatches * 0.15;
  score += features.totalWeight * 0.4;
  score += features.uniqueCategories * 0.2;
  score += features.hasURL * 0.6;
  score += features.hasPhishing * 0.8;
  score += features.hasUrgency * 0.4;

  // normalize to 0–1
  return Math.min(1, score);
}

/**
 * Build feature vector from DFA output
 */
function extractFeatures(
  scan: ScanResult,
  text: string
): FeatureVector {
  const categories = new Set<Category>();

  for (const m of scan.matches) {
    categories.add(m.category);
  }

  return {
    totalMatches: scan.matches.length,
    totalWeight: scan.matches.reduce((s, m) => s + m.weight, 0),
    uniqueCategories: categories.size,
    hasURL: categories.has('URL') ? 1 : 0,
    hasPhishing: categories.has('PHISHING') ? 1 : 0,
    hasUrgency: categories.has('URGENCY') ? 1 : 0,
    textLength: text.length
  };
}

/**
 * Hybrid score = DFA + ML
 */
export function hybridAnalyze(scan: ScanResult, text: string) {
  const features = extractFeatures(scan, text);
  const mlConfidence = mlPredict(features);

  const dfaScore = scan.score;
  const mlScore = Math.round(mlConfidence * 100);

  // weighted hybrid
  const hybridScore = Math.round(
    dfaScore * 0.5 + mlScore * 0.5
  );

  let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH';
  if (hybridScore >= 70) riskLevel = 'HIGH';
  else if (hybridScore >= 40) riskLevel = 'MEDIUM';
  else riskLevel = 'LOW';

  return {
    dfaScore,
    mlScore,
    hybridScore,
    riskLevel,
    features
  };
}

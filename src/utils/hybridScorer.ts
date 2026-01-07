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
  hasFinancial: number;
  hasImpersonation: number;
  textLength: number;
  averageWeight: number;
}

function extractFeatures(
  scan: ScanResult,
  text: string
): FeatureVector {
  const categories = new Set<Category>();

  for (const m of scan.matches) {
    categories.add(m.category);
  }

  const totalWeight = Math.max(
    0,
    parseFloat(
      scan.matches.reduce((s, m) => s + m.weight, 0).toFixed(2)
    )
  );

  const averageWeight = scan.matches.length > 0
    ? parseFloat((totalWeight / scan.matches.length).toFixed(2)) : 0;

  return {
    totalMatches: scan.matches.length,
    totalWeight,
    uniqueCategories: categories.size,
    hasURL: categories.has('URL') ? 1 : 0,
    hasPhishing: categories.has('PHISHING') ? 1 : 0,
    hasUrgency: categories.has('URGENCY') ? 1 : 0,
    hasFinancial: categories.has('FINANCIAL') ? 1 : 0,
    hasImpersonation: categories.has('IMPERSONATION') ? 1 : 0,
    textLength: text.length,
    averageWeight,
  };
}

export function hybridAnalyze(scan: ScanResult, text: string) {
  const features = extractFeatures(scan, text);

  const dfaScore = parseFloat(scan.score.toFixed(2));
  const hybridScore = dfaScore;

  let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  if (hybridScore >= 80) riskLevel = 'CRITICAL';
  else if (hybridScore >= 60) riskLevel = 'HIGH';
  else if (hybridScore >= 35) riskLevel = 'MEDIUM';
  else riskLevel = 'LOW';

  const matchDensity = text.length > 0 
    ? parseFloat((features.totalMatches / (text.length / 10)).toFixed(2))
    : 0;
  
  const categoryDiversity = parseFloat(
    (features.uniqueCategories / 5).toFixed(2)
  );
  
  const confidence = parseFloat(
    Math.min(1, (matchDensity * 0.3 + categoryDiversity * 0.4 + features.averageWeight * 0.3)).toFixed(2)
  );

  return {
    dfaScore,
    enhancedScore: dfaScore,
    hybridScore, 
    riskLevel,
    features,
    categoryMultiplier: 1.0,
    combinationBonus: 0,
    confidence,
    analysis: {
      categoriesDetected: features.uniqueCategories,
      totalMatches: features.totalMatches,
      averageMatchWeight: features.averageWeight,
      flags: {
        hasURL: features.hasURL === 1,
        hasPhishing: features.hasPhishing === 1,
        hasUrgency: features.hasUrgency === 1,
        hasFinancial: features.hasFinancial === 1,
        hasImpersonation: features.hasImpersonation === 1
      }
    }
  };
}

export function explainScore(result: ReturnType<typeof hybridAnalyze>): string {
  const parts: string[] = [];
  
  parts.push(`DFA Score: ${result.dfaScore}%`);
  parts.push(`Risk Level: ${result.riskLevel}`);
  parts.push(`Confidence: ${(result.confidence * 100).toFixed(0)}%`);
  
  const { flags } = result.analysis;
  const presentCategories = Object.entries(flags)
    .filter(([_, present]) => present)
    .map(([category, _]) => category.replace('has', ''));
  
  if (presentCategories.length > 0) {
    parts.push(`Detected: ${presentCategories.join(', ')}`);
  }
  
  return parts.join('\n');
}
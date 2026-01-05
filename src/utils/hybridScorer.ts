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

/**
 * Category-based risk multipliers
 * These amplify the base DFA score based on which categories are present
 */
const CATEGORY_MULTIPLIERS = {
  URL: 1.15,
  PHISHING: 1.25,
  URGENCY: 1.10,
  FINANCIAL: 1.12,
  IMPERSONATION: 1.20
};

/**
 * Multi-category combination bonuses
 * When multiple categories appear together, it's more suspicious
 */
const COMBINATION_BONUSES = {
  // High-risk combinations
  'PHISHING+URL': 8.0,
  'PHISHING+URGENCY': 6.0,
  'PHISHING+IMPERSONATION': 7.0,
  'URGENCY+URL': 5.0,
  'FINANCIAL+URL': 5.5,
  'IMPERSONATION+URL': 6.5,
  
  // Medium-risk combinations
  'URGENCY+FINANCIAL': 4.0,
  'URGENCY+IMPERSONATION': 4.5,
  'FINANCIAL+IMPERSONATION': 4.0,
  
  // Three-category combinations
  'PHISHING+URGENCY+URL': 12.0,
  'PHISHING+IMPERSONATION+URL': 13.0,
  'URGENCY+FINANCIAL+URL': 10.0,
  'PHISHING+URGENCY+IMPERSONATION': 11.0,
  
  // Four-category combinations
  'PHISHING+URGENCY+FINANCIAL+URL': 18.0,
  'PHISHING+URGENCY+IMPERSONATION+URL': 20.0,
  
  // All categories present
  'PHISHING+URGENCY+FINANCIAL+IMPERSONATION+URL': 25.0
};

/**
 * Build feature vector from DFA output
 */
function extractFeatures(
  scan: ScanResult,
  text: string
): FeatureVector {
  const categories = new Set<Category>();
  const categoryBreakdown: Record<Category, number> = {
    URGENCY: 0,
    FINANCIAL: 0,
    PHISHING: 0,
    IMPERSONATION: 0,
    URL: 0
  };

  for (const m of scan.matches) {
    categories.add(m.category);
  }

  // Trim totalWeight to 2 decimal places
  const totalWeight = parseFloat(
    scan.matches.reduce((s, m) => s + m.weight, 0).toFixed(2)
  );

  const averageWeight = scan.matches.length > 0
    ? parseFloat((totalWeight / scan.matches.length).toFixed(2))
    : 0;

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

/**
 * Calculate category multiplier based on present categories
 */
function calculateCategoryMultiplier(features: FeatureVector): number {
  let multiplier = 1.0;

  if (features.hasURL) multiplier *= CATEGORY_MULTIPLIERS.URL;
  if (features.hasPhishing) multiplier *= CATEGORY_MULTIPLIERS.PHISHING;
  if (features.hasUrgency) multiplier *= CATEGORY_MULTIPLIERS.URGENCY;
  if (features.hasFinancial) multiplier *= CATEGORY_MULTIPLIERS.FINANCIAL;
  if (features.hasImpersonation) multiplier *= CATEGORY_MULTIPLIERS.IMPERSONATION;

  return parseFloat(multiplier.toFixed(2));
}

/**
 * Helper: Generate combinations of categories
 */
function getCombinations<T>(arr: T[], length: number): T[][] {
  if (length === 1) return arr.map(item => [item]);
  
  const result: T[][] = [];
  
  for (let i = 0; i <= arr.length - length; i++) {
    const head = arr[i];
    const tailCombos = getCombinations(arr.slice(i + 1), length - 1);
    
    for (const combo of tailCombos) {
      result.push([head, ...combo]);
    }
  }
  
  return result;
}

/**
 * Calculate combination bonus based on category patterns
 */
function calculateCombinationBonus(features: FeatureVector): number {
  const presentCategories: Category[] = [];
  
  if (features.hasPhishing) presentCategories.push('PHISHING');
  if (features.hasUrgency) presentCategories.push('URGENCY');
  if (features.hasFinancial) presentCategories.push('FINANCIAL');
  if (features.hasImpersonation) presentCategories.push('IMPERSONATION');
  if (features.hasURL) presentCategories.push('URL');

  // Sort for consistent key generation
  presentCategories.sort();

  // Try to find matching combination bonus
  for (let i = presentCategories.length; i >= 2; i--) {
    const combinations = getCombinations(presentCategories, i);
    
    for (const combo of combinations) {
      const key = combo.join('+');
      if (COMBINATION_BONUSES[key as keyof typeof COMBINATION_BONUSES]) {
        return COMBINATION_BONUSES[key as keyof typeof COMBINATION_BONUSES];
      }
    }
  }

  return 0;
}

/**
 * DFA-focused scoring with enhancements
 */
function enhancedDFAScore(scan: ScanResult, features: FeatureVector): number {
  // Start with base DFA score
  let score = scan.score;
  
  // Apply category multiplier
  const categoryMultiplier = calculateCategoryMultiplier(features);
  score *= categoryMultiplier;
  
  // Add combination bonus
  const combinationBonus = calculateCombinationBonus(features);
  score += combinationBonus;
  
  // Cap at 95 (matching DFA max)
  score = Math.min(95, score);
  
  return parseFloat(score.toFixed(2));
}

/**
 * Hybrid score = Enhanced DFA
 * Keeps the same return structure for compatibility
 */
export function hybridAnalyze(scan: ScanResult, text: string) {
  const features = extractFeatures(scan, text);

  const dfaScore = parseFloat(scan.score.toFixed(2));
  const enhancedScore = enhancedDFAScore(scan, features);
  const categoryMultiplier = calculateCategoryMultiplier(features);
  const combinationBonus = calculateCombinationBonus(features);

  // Use enhanced score as the final hybrid score
  const hybridScore = enhancedScore;

  let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  if (hybridScore >= 80) riskLevel = 'CRITICAL';
  else if (hybridScore >= 60) riskLevel = 'HIGH';
  else if (hybridScore >= 35) riskLevel = 'MEDIUM';
  else riskLevel = 'LOW';

  // Calculate confidence
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
    enhancedScore,
    hybridScore,  // This is what gets displayed
    riskLevel,
    features,
    // Additional detailed info
    categoryMultiplier,
    combinationBonus,
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

/**
 * Get human-readable explanation of the score
 */
export function explainScore(result: ReturnType<typeof hybridAnalyze>): string {
  const parts: string[] = [];
  
  parts.push(`Base DFA Score: ${result.dfaScore}%`);
  
  if (result.categoryMultiplier > 1) {
    parts.push(`Category Multiplier: ${result.categoryMultiplier}x (increases suspicion)`);
  }
  
  if (result.combinationBonus > 0) {
    parts.push(`Combination Bonus: +${result.combinationBonus} (multiple suspicious patterns)`);
  }
  
  parts.push(`Final Score: ${result.hybridScore}%`);
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
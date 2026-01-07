import type { Match, Category } from '../types/types';

const CONTEXT_CONFIG = {

  MIN_PATTERN_LENGTH: 3,
  
  REQUIRE_WORD_BOUNDARY: true,

  MULTI_CATEGORY_BOOST: 0.10,
  
  ISOLATED_MATCH_PENALTY: 0.30, 
  

  SINGLE_WORD_PENALTY: 0.50, 
  
  SUSPICIOUS_DENSITY_THRESHOLD: 3,
};


function validatePatternLength(match: Match, originalText: string): boolean {
  const matchedText = originalText.substring(match.start, match.end);
  const cleanText = matchedText.trim();
  
  if (cleanText.length < CONTEXT_CONFIG.MIN_PATTERN_LENGTH) {
    return false;
  }
  
  return true;
}


function validateWordBoundary(
  match: Match, 
  originalText: string
): boolean {
  if (!CONTEXT_CONFIG.REQUIRE_WORD_BOUNDARY) {
    return true;
  }
  
  const { start, end } = match;
  const textLower = originalText.toLowerCase();
  
  const charBefore = start > 0 ? textLower[start - 1] : ' ';
  const isWordBoundaryBefore = /[\s.,!?;:()\[\]{}"'`]/.test(charBefore);
  
  const charAfter = end < textLower.length ? textLower[end] : ' ';
  const isWordBoundaryAfter = /[\s.,!?;:()\[\]{}"'`]/.test(charAfter);
  
  return isWordBoundaryBefore && isWordBoundaryAfter;
}

function isSingleWordPattern(pattern: string): boolean {
  const trimmed = pattern.trim();
  return !trimmed.includes(' ');
}

function isLegitimateContext(
  originalText: string,
): boolean {
  const textLower = originalText.toLowerCase();
  
  const legitimateIndicators = [
    // Official transaction confirmations
    /transaction (reference|id|number):/i,
    /receipt number:/i,
    /confirmation code:/i,
    /order number:/i,
    
    /for assistance.*contact us at/i,
    /customer (service|support).*\d{3}-?\d{3,4}/i, 
    /call us at \d/i,
    
    /your order.*has been (shipped|delivered|processed)/i,
    /booking confirmed/i,
    /appointment scheduled/i,
    
    /balance.*as of/i,
    /statement period/i,
    /due date:/i,
    /transaction date:/i,
    
    /to (unsubscribe|opt-out|stop).*reply/i,
    /text stop to/i,
    /reply no to unsubscribe/i,
  ];
  
  for (const pattern of legitimateIndicators) {
    if (pattern.test(textLower)) {
      return true;
    }
  }
  
  return false;
}

function isGenericPattern(pattern: string): boolean {
  const genericPatterns = [
    'win', 'earn', 'money', 'cash', 'free', 'offer',
    'loan', 'prize', 'reward', 'pera', 'income',
    'profit', 'transfer', 'php', 'pesos',
    
    'click', 'register', 'apply', 'call', 'text',
    'claim', 'avail', 'update', 'verify',
    
    'urgent', 'asap', 'now', 'today', 'expire',
    
    'bank', 'gcash', 'bpi', 'bdo', 'smart', 'globe',
  ];
  
  const urlIndicators = ['://', 'http', 'https', 'bit.ly', '.com', '.ph', '.tk', '.ml'];
  if (urlIndicators.some(ind => pattern.includes(ind))) {
    return false; 
  }
  
  return genericPatterns.includes(pattern.toLowerCase().trim());
}

function isHighConfidencePattern(pattern: string): boolean {
  const highConfidencePatterns = [
    'act now', 'limited time offer', 'expires within',
    'urgent security alert', 'final warning', 'immediate action required',
    
    'instant pera', 'kumita ng malaki', 'you won', 'claim your prize',
    'free money', 'guaranteed profit', 'mabilis na yaman',
    
    'enter your otp', 'verify your identity', 'suspicious activity detected',
    'account suspended', 'confirm identity', 'security alert',
    
    'gcash official', 'from your bank', 'bsp notification',
  ];
  
  const urlIndicators = [
    '://', 'http://', 'https://',
    'bit.ly', 'tinyurl', 't.co', 'goo.gl',
    '.tk', '.ml', '.ga', '.xyz',
    '?verify=', '?token=', '?confirm=',
    'click here', 'click link', 'tap here'
  ];
  
  if (urlIndicators.some(ind => pattern.toLowerCase().includes(ind))) {
    return true; 
  }
  
  return highConfidencePatterns.some(hcp => 
    pattern.toLowerCase().includes(hcp)
  );
}


function calculateMatchDensity(
  matches: Match[], 
  textLength: number
): number {
  return (matches.length / Math.max(textLength, 1)) * 100;
}

function analyzeCategoryCombinations(matches: Match[]): {
  categories: Set<Category>;
  hasCriticalCombination: boolean;
  boost: number;
} {
  const categories = new Set<Category>();
  
  for (const match of matches) {
    categories.add(match.category);
  }
  
  const criticalCombinations = [
    ['URGENCY', 'FINANCIAL', 'PHISHING'],      
    ['URGENCY', 'IMPERSONATION', 'PHISHING'],  
    ['FINANCIAL', 'PHISHING', 'URL'],          
    ['URGENCY', 'FINANCIAL', 'URL'],           
    ['IMPERSONATION', 'PHISHING', 'URL'],      
  ];
  
  let hasCriticalCombination = false;
  
  for (const combo of criticalCombinations) {
    if (combo.every(cat => categories.has(cat as Category))) {
      hasCriticalCombination = true;
      break;
    }
  }
  
  let boost = 0;
  
  if (categories.size >= 4) {
    boost = CONTEXT_CONFIG.MULTI_CATEGORY_BOOST * 1.5;
  } else if (categories.size === 3 && hasCriticalCombination) {
    boost = CONTEXT_CONFIG.MULTI_CATEGORY_BOOST;
  } else if (categories.size === 2) {
    boost = CONTEXT_CONFIG.MULTI_CATEGORY_BOOST * 0.4;
  }
  
  return { categories, hasCriticalCombination, boost };
}

function adjustMatchWeight(
  match: Match, 
  originalText: string,
  allMatches: Match[],
  categoryInfo: { categories: Set<Category>; hasCriticalCombination: boolean }
): number {
  let adjustedWeight = match.weight;
  
  if (isSingleWordPattern(match.pattern) && !isHighConfidencePattern(match.pattern)) {
    if (categoryInfo.categories.size <= 1) {
      adjustedWeight *= (1 - CONTEXT_CONFIG.SINGLE_WORD_PENALTY);
    } else if (categoryInfo.categories.size === 2) {
      adjustedWeight *= 0.65;
    } else {
      adjustedWeight *= 0.80;
    }
  }
  
  if (isGenericPattern(match.pattern)) {
    if (categoryInfo.categories.size <= 1) {
      adjustedWeight *= 0.40; 
    } else if (categoryInfo.categories.size === 2) {
      adjustedWeight *= 0.60;
    } else {
      adjustedWeight *= 0.75;
    }
  }
  
  if (isLegitimateContext(originalText)) {
    adjustedWeight *= 0.50; 
  }
  
  if (categoryInfo.hasCriticalCombination) {
    adjustedWeight *= 1.15; 
  }
  
  if (isHighConfidencePattern(match.pattern) && !isSingleWordPattern(match.pattern)) {
    adjustedWeight *= 1.10;
  }
  
  return adjustedWeight;
}

export function applyContextBoost(
  matches: Match[],
  originalText?: string
): {
  validatedMatches: Match[];
  contextBoost: number;
  rejectedMatches: Match[];
} {
  const text = originalText || '';
  const validatedMatches: Match[] = [];
  const rejectedMatches: Match[] = [];
  
  for (const match of matches) {
    let isValid = true;
    
    if (!validatePatternLength(match, text)) {
      rejectedMatches.push({
        ...match,
        rejectionReason: 'Pattern too short'
      } as Match & { rejectionReason: string });
      continue;
    }
    
    if (text && !validateWordBoundary(match, text)) {
      rejectedMatches.push({
        ...match,
        rejectionReason: 'Not on word boundary'
      } as Match & { rejectionReason: string });
      continue;
    }
    
    if (isValid) {
      validatedMatches.push(match);
    }
  }
  
  const categoryInfo = analyzeCategoryCombinations(validatedMatches);
  
  const density = calculateMatchDensity(validatedMatches, text.length);
  const isDenseMessage = density >= CONTEXT_CONFIG.SUSPICIOUS_DENSITY_THRESHOLD;
  
  const adjustedMatches = validatedMatches.map(match => ({
    ...match,
    weight: adjustMatchWeight(match, text, validatedMatches, categoryInfo)
  }));
  
  let contextBoost = categoryInfo.boost;
  
  if (isDenseMessage) {
    contextBoost += 0.05; 
  }
  
  if (validatedMatches.length === 1 && !categoryInfo.hasCriticalCombination) {
    contextBoost -= CONTEXT_CONFIG.ISOLATED_MATCH_PENALTY;
  }
  
  contextBoost = Math.max(0, contextBoost);
  
  return {
    validatedMatches: adjustedMatches,
    contextBoost,
    rejectedMatches
  };
}

export function analyzeContext(
  matches: Match[],
  originalText: string
): {
  summary: string;
  statistics: {
    totalMatches: number;
    validMatches: number;
    rejectedMatches: number;
    categories: string[];
    density: number;
    hasCriticalCombination: boolean;
    contextBoost: number;
  };
  details: {
    validMatches: Match[];
    rejectedMatches: Array<Match & { rejectionReason: string }>;
  };
} {
  const { validatedMatches, contextBoost, rejectedMatches } = 
    applyContextBoost(matches, originalText);
  
  const categoryInfo = analyzeCategoryCombinations(validatedMatches);
  const density = calculateMatchDensity(validatedMatches, originalText.length);
  
  return {
    summary: `Validated ${validatedMatches.length}/${matches.length} matches with ${contextBoost.toFixed(2)} context boost`,
    statistics: {
      totalMatches: matches.length,
      validMatches: validatedMatches.length,
      rejectedMatches: rejectedMatches.length,
      categories: Array.from(categoryInfo.categories),
      density: parseFloat(density.toFixed(2)),
      hasCriticalCombination: categoryInfo.hasCriticalCombination,
      contextBoost: parseFloat(contextBoost.toFixed(2))
    },
    details: {
      validMatches: validatedMatches,
      rejectedMatches: rejectedMatches as Array<Match & { rejectionReason: string }>
    }
  };
}

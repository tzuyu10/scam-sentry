import type { Match, Category } from '../types/types';

/**
 * Context Validation Configuration
 * 
 * Prevents false positives from:
 * - Single character matches
 * - Overly generic patterns
 * - Legitimate business communications
 * - Common phrases taken out of context
 */
const CONTEXT_CONFIG = {
  // Minimum pattern length to avoid single-char inflation
  MIN_PATTERN_LENGTH: 3,
  
  // Minimum word boundary requirement (prevents partial word matches)
  REQUIRE_WORD_BOUNDARY: true,
  
  // Context boost when multiple high-risk categories combine
  MULTI_CATEGORY_BOOST: 0.10, // Reduced from 0.15
  
  // Penalty for isolated low-confidence matches
  ISOLATED_MATCH_PENALTY: 0.30, // Increased from 0.20
  
  // Penalty for single-word patterns without context
  SINGLE_WORD_PENALTY: 0.50, // NEW: Heavy penalty for isolated words
  
  // Density threshold: matches per 100 characters
  SUSPICIOUS_DENSITY_THRESHOLD: 3,
};

/**
 * Pattern Length Validator
 * 
 * Filters out single or very short character matches that could be
 * noise (e.g., 'p' matching in 'php', 'a' in 'act', etc.)
 */
function validatePatternLength(match: Match, originalText: string): boolean {
  const matchedText = originalText.substring(match.start, match.end);
  const cleanText = matchedText.trim();
  
  // Reject single character matches
  if (cleanText.length < CONTEXT_CONFIG.MIN_PATTERN_LENGTH) {
    return false;
  }
  
  return true;
}

/**
 * Word Boundary Validator
 * 
 * Ensures patterns match complete words, not substrings.
 * Example: "act" should not match in "transaction" or "action"
 */
function validateWordBoundary(
  match: Match, 
  originalText: string
): boolean {
  if (!CONTEXT_CONFIG.REQUIRE_WORD_BOUNDARY) {
    return true;
  }
  
  const { start, end } = match;
  const textLower = originalText.toLowerCase();
  
  // Check character before match
  const charBefore = start > 0 ? textLower[start - 1] : ' ';
  const isWordBoundaryBefore = /[\s.,!?;:()\[\]{}"'`]/.test(charBefore);
  
  // Check character after match
  const charAfter = end < textLower.length ? textLower[end] : ' ';
  const isWordBoundaryAfter = /[\s.,!?;:()\[\]{}"'`]/.test(charAfter);
  
  // Must have word boundaries on both sides
  return isWordBoundaryBefore && isWordBoundaryAfter;
}

/**
 * Single Word Detector
 * 
 * Identifies patterns that are single words without additional context.
 * These should receive heavy weight penalties.
 */
function isSingleWordPattern(pattern: string): boolean {
  const trimmed = pattern.trim();
  // Check if pattern contains no spaces (single word)
  return !trimmed.includes(' ');
}

/**
 * Legitimate Context Detector
 * 
 * Identifies legitimate business communications that use scam-like keywords.
 * Reduces false positives for actual bank/service notifications.
 */
function isLegitimateContext(
  match: Match, 
  originalText: string,
  allMatches: Match[]
): boolean {
  const textLower = originalText.toLowerCase();
  
  // Legitimate indicators (these phrases suggest real communication)
  const legitimateIndicators = [
    // Official transaction confirmations
    /transaction (reference|id|number):/i,
    /receipt number:/i,
    /confirmation code:/i,
    /order number:/i,
    
    // Real customer service with contact info
    /for assistance.*contact us at/i,
    /customer (service|support).*\d{3}-?\d{3,4}/i, // With phone number
    /call us at \d/i,
    
    // Actual notifications with details
    /your order.*has been (shipped|delivered|processed)/i,
    /booking confirmed/i,
    /appointment scheduled/i,
    
    // Legitimate financial terms
    /balance.*as of/i,
    /statement period/i,
    /due date:/i,
    /transaction date:/i,
    
    // Opt-out options (scams rarely provide these)
    /to (unsubscribe|opt-out|stop).*reply/i,
    /text stop to/i,
    /reply no to unsubscribe/i,
  ];
  
  // Check if any legitimate indicator is present
  for (const pattern of legitimateIndicators) {
    if (pattern.test(textLower)) {
      return true;
    }
  }
  
  return false;
}

/**
 * Generic Pattern Filter
 * 
 * Reduces weight for overly generic terms that need strong context.
 * Example: "win", "earn", "money" are too common on their own.
 * 
 * NOTE: URL patterns are NOT considered generic - any link in SMS is suspicious
 */
function isGenericPattern(pattern: string): boolean {
  const genericPatterns = [
    // Very generic financial terms
    'win', 'earn', 'money', 'cash', 'free', 'offer',
    'loan', 'prize', 'reward', 'pera', 'income',
    'profit', 'transfer', 'php', 'pesos',
    
    // Generic action words
    'click', 'register', 'apply', 'call', 'text',
    'claim', 'avail', 'update', 'verify',
    
    // Generic urgency
    'urgent', 'asap', 'now', 'today', 'expire',
    
    // Generic brands (too broad)
    'bank', 'gcash', 'bpi', 'bdo', 'smart', 'globe',
  ];
  
  // URL patterns should NOT be treated as generic
  // Any link in an unsolicited message is inherently suspicious
  const urlIndicators = ['://', 'http', 'https', 'bit.ly', '.com', '.ph', '.tk', '.ml'];
  if (urlIndicators.some(ind => pattern.includes(ind))) {
    return false; // Not generic - URLs are always notable
  }
  
  return genericPatterns.includes(pattern.toLowerCase().trim());
}

/**
 * High-Confidence Pattern Identifier
 * 
 * These patterns are suspicious even in isolation (multi-word, specific, or URLs)
 */
function isHighConfidencePattern(pattern: string): boolean {
  const highConfidencePatterns = [
    // Multi-word urgency + action
    'act now', 'limited time offer', 'expires within',
    'urgent security alert', 'final warning', 'immediate action required',
    
    // Specific financial scams
    'instant pera', 'kumita ng malaki', 'you won', 'claim your prize',
    'free money', 'guaranteed profit', 'mabilis na yaman',
    
    // Specific phishing
    'enter your otp', 'verify your identity', 'suspicious activity detected',
    'account suspended', 'confirm identity', 'security alert',
    
    // Impersonation with context
    'gcash official', 'from your bank', 'bsp notification',
  ];
  
  // ANY URL-related pattern is high confidence
  // Links in unsolicited messages are inherently suspicious
  const urlIndicators = [
    '://', 'http://', 'https://',
    'bit.ly', 'tinyurl', 't.co', 'goo.gl',
    '.tk', '.ml', '.ga', '.xyz',
    '?verify=', '?token=', '?confirm=',
    'click here', 'click link', 'tap here'
  ];
  
  if (urlIndicators.some(ind => pattern.toLowerCase().includes(ind))) {
    return true; // All URL patterns are high confidence
  }
  
  return highConfidencePatterns.some(hcp => 
    pattern.toLowerCase().includes(hcp)
  );
}

/**
 * Match Density Analyzer
 * 
 * Calculates the concentration of scam patterns per message length.
 * High density suggests deliberate manipulation.
 */
function calculateMatchDensity(
  matches: Match[], 
  textLength: number
): number {
  // Density = (number of matches / text length) × 100
  return (matches.length / Math.max(textLength, 1)) * 100;
}

/**
 * Category Combination Analyzer
 * 
 * Detects dangerous combinations of pattern categories.
 * Example: URGENCY + FINANCIAL + PHISHING = classic scam signature
 */
function analyzeCategoryCombinations(matches: Match[]): {
  categories: Set<Category>;
  hasCriticalCombination: boolean;
  boost: number;
} {
  const categories = new Set<Category>();
  
  for (const match of matches) {
    categories.add(match.category);
  }
  
  // Critical combinations (strong scam indicators)
  const criticalCombinations = [
    ['URGENCY', 'FINANCIAL', 'PHISHING'],      // Classic phishing scam
    ['URGENCY', 'IMPERSONATION', 'PHISHING'],  // Impersonation attack
    ['FINANCIAL', 'PHISHING', 'URL'],          // Smishing attack
    ['URGENCY', 'FINANCIAL', 'URL'],           // Urgent financial scam
    ['IMPERSONATION', 'PHISHING', 'URL'],      // Brand impersonation phishing
  ];
  
  let hasCriticalCombination = false;
  
  for (const combo of criticalCombinations) {
    if (combo.every(cat => categories.has(cat as Category))) {
      hasCriticalCombination = true;
      break;
    }
  }
  
  // Calculate boost based on category count
  let boost = 0;
  
  if (categories.size >= 4) {
    // All major categories present
    boost = CONTEXT_CONFIG.MULTI_CATEGORY_BOOST * 1.5;
  } else if (categories.size === 3 && hasCriticalCombination) {
    // Critical 3-category combination
    boost = CONTEXT_CONFIG.MULTI_CATEGORY_BOOST;
  } else if (categories.size === 2) {
    // Moderate 2-category overlap
    boost = CONTEXT_CONFIG.MULTI_CATEGORY_BOOST * 0.4;
  }
  
  return { categories, hasCriticalCombination, boost };
}

/**
 * Weight Adjuster for Context
 * 
 * Adjusts individual match weights based on surrounding context.
 */
function adjustMatchWeight(
  match: Match, 
  originalText: string,
  allMatches: Match[],
  categoryInfo: { categories: Set<Category>; hasCriticalCombination: boolean }
): number {
  let adjustedWeight = match.weight;
  
  // 1. MAJOR PENALTY: Single word patterns without strong context
  if (isSingleWordPattern(match.pattern) && !isHighConfidencePattern(match.pattern)) {
    if (categoryInfo.categories.size <= 1) {
      // Single word + single category = major reduction
      adjustedWeight *= (1 - CONTEXT_CONFIG.SINGLE_WORD_PENALTY);
    } else if (categoryInfo.categories.size === 2) {
      // Single word + two categories = moderate reduction
      adjustedWeight *= 0.65;
    } else {
      // Single word + 3+ categories = minor reduction
      adjustedWeight *= 0.80;
    }
  }
  
  // 2. Penalize generic patterns without strong context
  if (isGenericPattern(match.pattern)) {
    if (categoryInfo.categories.size <= 1) {
      // Isolated generic pattern - reduce significantly
      adjustedWeight *= 0.40; // Increased penalty from 0.5
    } else if (categoryInfo.categories.size === 2) {
      // Generic with 2 categories - moderate reduction
      adjustedWeight *= 0.60;
    } else {
      // Generic with 3+ categories - minor reduction
      adjustedWeight *= 0.75;
    }
  }
  
  // 3. Penalize if in legitimate context
  if (isLegitimateContext(match, originalText, allMatches)) {
    adjustedWeight *= 0.50; // Increased penalty from 0.6
  }
  
  // 4. Boost if part of critical combination
  if (categoryInfo.hasCriticalCombination) {
    adjustedWeight *= 1.15; // Slight increase from 1.1
  }
  
  // 5. Boost high-confidence multi-word patterns
  if (isHighConfidencePattern(match.pattern) && !isSingleWordPattern(match.pattern)) {
    adjustedWeight *= 1.10;
  }
  
  return adjustedWeight;
}

/**
 * Main Context Validation Function
 * 
 * Filters and adjusts matches based on context analysis.
 * Returns validated matches and context boost value.
 */
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
  
  // Step 1: Filter out invalid matches
  for (const match of matches) {
    let isValid = true;
    
    // Check pattern length
    if (!validatePatternLength(match, text)) {
      rejectedMatches.push({
        ...match,
        rejectionReason: 'Pattern too short'
      } as Match & { rejectionReason: string });
      continue;
    }
    
    // Check word boundaries (if text is available)
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
  
  // Step 2: Analyze category combinations
  const categoryInfo = analyzeCategoryCombinations(validatedMatches);
  
  // Step 3: Calculate match density
  const density = calculateMatchDensity(validatedMatches, text.length);
  const isDenseMessage = density >= CONTEXT_CONFIG.SUSPICIOUS_DENSITY_THRESHOLD;
  
  // Step 4: Adjust individual match weights
  const adjustedMatches = validatedMatches.map(match => ({
    ...match,
    weight: adjustMatchWeight(match, text, validatedMatches, categoryInfo)
  }));
  
  // Step 5: Calculate final context boost (more conservative)
  let contextBoost = categoryInfo.boost;
  
  // Add density bonus for suspiciously dense messages
  if (isDenseMessage) {
    contextBoost += 0.05; // Reduced from 0.08
  }
  
  // Reduce boost if matches seem isolated or weak
  if (validatedMatches.length === 1 && !categoryInfo.hasCriticalCombination) {
    contextBoost -= CONTEXT_CONFIG.ISOLATED_MATCH_PENALTY;
  }
  
  // Ensure boost is non-negative
  contextBoost = Math.max(0, contextBoost);
  
  return {
    validatedMatches: adjustedMatches,
    contextBoost,
    rejectedMatches
  };
}

/**
 * Diagnostic function for debugging context validation
 */
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
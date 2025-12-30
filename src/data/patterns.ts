import type { Category } from '../types/types';

/**
 * Pattern Definition for DFA Construction
 * Each pattern represents a complete sequence of characters that will be
 * converted into a state path in the DFA: q₀ → q₁ → q₂ → ... → qₙ
 */
type PatternDef = { 
  keyword: string;  // Character sequence for DFA path construction
  weight: number;   // Output weight λ(qₙ) for accepting state
};

/**
 * DFA Pattern Lookup Table
 * 
 * Formal Mapping: Category → Pattern Set → DFA Construction
 * 
 * For each category C and pattern P:
 * 1. P.keyword defines the character sequence σ₁σ₂...σₙ
 * 2. DFA builds state path: δ(q₀, σ₁) → q₁, δ(q₁, σ₂) → q₂, ..., δ(qₙ₋₁, σₙ) → qₙ
 * 3. qₙ becomes accepting state with output λ(qₙ) = {pattern: P.keyword, weight: P.weight}
 * 
 * All patterns are literal character sequences - NO REGEX.
 * The Aho-Corasick DFA processes these character-by-character.
 */
export const PATTERNS: Record<Category, PatternDef[]> = {
  /**
   * ═══════════════════════════════════════════════════════════════════════
   * FSA 1: URGENCY DETECTION DFA
   * ═══════════════════════════════════════════════════════════════════════
   * 
   * Objective: Detect temporal urgency and call-to-action phrases
   * 
   * Example DFA Path for "act now":
   * q₀ --a--> q₁ --c--> q₂ --t--> q₃ --[space]--> q₄ --n--> q₅ --o--> q₆ --w--> q₇
   * λ(q₇) = {pattern: "act now", weight: 0.85}
   * 
   * Research Foundation:
   * - ABS-CBN/Whoscall (2025): Urgent offers like credit limit increases rush victims
   * - BPI (2025): "Act now before it's too late!" is primary red flag
   */
  URGENCY: [
    // High urgency multi-word (0.80-0.85): Account threats with context
    { keyword: 'account will be suspended', weight: 0.85 },
    { keyword: 'expires within 24 hours', weight: 0.83 },
    { keyword: 'limited time offer', weight: 0.78 },
    { keyword: 'expire today', weight: 0.80 },
    { keyword: 'urgent security alert', weight: 0.85 },
    { keyword: 'immediate action required', weight: 0.82 },
    { keyword: 'final warning', weight: 0.80 },
    
    // Medium urgency (0.65-0.79): Strong pressure but generic
    { keyword: 'suspended', weight: 0.72 }, // Reduced - single word
    { keyword: 'expires', weight: 0.68 },
    { keyword: 'act now', weight: 0.70 },
    { keyword: 'urgent', weight: 0.70 }, // Reduced significantly
    { keyword: 'last chance', weight: 0.75 },
    { keyword: 'expiring soon', weight: 0.73 },
    { keyword: 'claim now', weight: 0.72 },
    { keyword: 'register now', weight: 0.68 },
    
    // Lower urgency (0.50-0.64): Common but needs context
    { keyword: 'immediate', weight: 0.60 },
    { keyword: 'now na', weight: 0.62 },
    { keyword: 'asap', weight: 0.58 },
    { keyword: 'hurry', weight: 0.62 },
    { keyword: 'expire', weight: 0.60 },
    { keyword: 'avail', weight: 0.55 }, // Very generic
    { keyword: 'i-click', weight: 0.58 },
    { keyword: 'agad', weight: 0.58 },
    { keyword: 'mabilis', weight: 0.55 },
  ],

  /**
   * ═══════════════════════════════════════════════════════════════════════
   * FSA 2: FINANCIAL/MONETARY DETECTION DFA
   * ═══════════════════════════════════════════════════════════════════════
   * 
   * Objective: Identify monetary requests, loan offers, prizes, investments
   * 
   * Example DFA Path for "loan":
   * q₀ --l--> q₁ --o--> q₂ --a--> q₃ --n--> q₄
   * λ(q₄) = {pattern: "loan", weight: 0.85}
   * 
   * Research Foundation:
   * - Whoscall (2025): Loan/reward offers are "mainstay" in PH scam reports
   * - Tookitaki (2025): Investment scams caused PHP 100B+ losses in 2024
   */
  FINANCIAL: [
    // High-risk multi-word (0.78-0.85): Specific scam patterns
    { keyword: 'instant pera', weight: 0.82 },
    { keyword: 'instant money', weight: 0.82 },
    { keyword: 'mabilis na yaman', weight: 0.83 },
    { keyword: 'kumita ng malaki', weight: 0.80 },
    { keyword: 'guaranteed profit', weight: 0.80 },
    { keyword: 'you are the winner', weight: 0.85 },
    { keyword: 'claim your prize', weight: 0.78 },
    { keyword: 'free money', weight: 0.75 },
    
    // Medium financial (0.65-0.77): Direct money keywords
    { keyword: 'instant loan', weight: 0.75 },
    { keyword: 'quick loan', weight: 0.75 },
    { keyword: 'cash loan', weight: 0.73 },
    { keyword: 'you won', weight: 0.72 },
    { keyword: 'pautang', weight: 0.70 },
    { keyword: 'prize', weight: 0.68 }, // Single word - reduced
    { keyword: 'reward', weight: 0.68 },
    { keyword: 'winner', weight: 0.72 },
    { keyword: 'claim', weight: 0.65 }, // Very generic
    { keyword: 'payout', weight: 0.70 },
    { keyword: 'free load', weight: 0.72 },
    { keyword: 'dagdag kita', weight: 0.70 },
    
    // Lower financial (0.50-0.64): Generic terms
    { keyword: 'loan', weight: 0.60 }, // Very common
    { keyword: 'congratulations', weight: 0.62 },
    { keyword: 'investment', weight: 0.58 },
    { keyword: 'profit', weight: 0.60 },
    { keyword: 'win', weight: 0.52 }, // Extremely generic
    { keyword: 'income', weight: 0.52 },
    { keyword: 'extra income', weight: 0.65 },
    { keyword: 'kumita', weight: 0.62 },
    { keyword: 'earn', weight: 0.50 }, // Very generic
    { keyword: 'pera', weight: 0.58 },
    { keyword: 'cash', weight: 0.50 },
    { keyword: 'money', weight: 0.48 }, // Extremely generic
    { keyword: 'libre', weight: 0.58 },
  ],

  /**
   * ═══════════════════════════════════════════════════════════════════════
   * FSA 3: PHISHING DETECTION DFA
   * ═══════════════════════════════════════════════════════════════════════
   * 
   * Objective: Detect account verification requests and credential phishing
   * 
   * Example DFA Path for "validate":
   * q₀ --v--> q₁ --a--> q₂ --l--> q₃ --i--> q₄ --d--> q₅ --a--> q₆ --t--> q₇ --e--> q₈
   * λ(q₈) = {pattern: "validate", weight: 0.90}
   * 
   * Research Foundation:
   * - Feedzai (2024): Phishing = #1 threat, PHP 623M losses, 6,595 incidents
   * - Cyberint (2025): True Login Phishing automates credential exfiltration
   */
  PHISHING: [
    // Critical multi-word phishing (0.85-0.90): Specific credential theft
    { keyword: 'enter your otp', weight: 0.90 },
    { keyword: 'send your otp', weight: 0.88 },
    { keyword: 'verify your identity', weight: 0.88 },
    { keyword: 'confirm your identity', weight: 0.88 },
    { keyword: 'urgent security alert', weight: 0.90 },
    { keyword: 'suspicious activity detected', weight: 0.87 },
    { keyword: 'unusual activity detected', weight: 0.85 },
    
    // High phishing (0.75-0.84): Account actions
    { keyword: 'verify your account', weight: 0.83 },
    { keyword: 'suspended account', weight: 0.82 },
    { keyword: 'account suspended', weight: 0.82 },
    { keyword: 'locked account', weight: 0.80 },
    { keyword: 'account locked', weight: 0.80 },
    { keyword: 'complete verification', weight: 0.82 },
    { keyword: 'security alert', weight: 0.80 },
    { keyword: 'verification code', weight: 0.78 },
    { keyword: 'security code', weight: 0.77 },
    
    // Medium phishing (0.60-0.74): General requests
    { keyword: 'verify account', weight: 0.72 },
    { keyword: 'update your account', weight: 0.73 },
    { keyword: 'confirm your account', weight: 0.73 },
    { keyword: 'enter otp', weight: 0.70 }, // Still serious but shorter
    { keyword: 'otp code', weight: 0.68 },
    { keyword: 'failed transaction', weight: 0.70 },
    { keyword: 'payment failed', weight: 0.70 },
    { keyword: 'i-verify', weight: 0.72 },
    { keyword: 'kailangan i-verify', weight: 0.75 },
    
    // Lower phishing (0.50-0.59): Generic single words
    { keyword: 'verify', weight: 0.58 }, // Very generic
    { keyword: 'validate', weight: 0.60 },
    { keyword: 'otp', weight: 0.62 }, // Single word
    { keyword: 'blocked', weight: 0.58 },
    { keyword: 'restricted', weight: 0.58 },
    { keyword: 'update', weight: 0.50 }, // Extremely generic
    { keyword: 'confirm', weight: 0.52 },
  ],

  /**
   * ═══════════════════════════════════════════════════════════════════════
   * FSA 4: IMPERSONATION DETECTION DFA
   * ═══════════════════════════════════════════════════════════════════════
   * 
   * Objective: Identify claims of authority or impersonation of entities
   * 
   * Example DFA Path for "gcash":
   * q₀ --g--> q₁ --c--> q₂ --a--> q₃ --s--> q₄ --h--> q₅
   * λ(q₅) = {pattern: "gcash", weight: 0.92}
   * 
   * Research Foundation:
   * - Cyberint (2024-2025): Enhanced brand impersonation in financial sector
   * - Williams et al. (2014): Authority cues increase click likelihood
   */
  IMPERSONATION: [
    // Critical multi-word impersonation (0.80-0.88): Context with brand
    { keyword: 'gcash official', weight: 0.88 },
    { keyword: 'from gcash', weight: 0.85 },
    { keyword: 'bsp notification', weight: 0.85 },
    { keyword: 'from your bank', weight: 0.82 },
    { keyword: 'bank alert', weight: 0.80 },
    { keyword: 'security team from', weight: 0.82 },
    
    // High impersonation (0.65-0.79): Major institutions with context
    { keyword: 'bpi bank', weight: 0.75 },
    { keyword: 'bdo bank', weight: 0.75 },
    { keyword: 'bangko sentral', weight: 0.78 },
    { keyword: 'government agency', weight: 0.72 },
    { keyword: 'authorized representative', weight: 0.70 },
    
    // Medium impersonation (0.50-0.64): Single brand names
    { keyword: 'gcash', weight: 0.62 }, // MAJOR reduction - too common
    { keyword: 'paymaya', weight: 0.60 },
    { keyword: 'bsp', weight: 0.65 },
    { keyword: 'bir', weight: 0.65 },
    { keyword: 'bpi', weight: 0.55 }, // Very generic
    { keyword: 'bdo', weight: 0.55 },
    { keyword: 'metrobank', weight: 0.58 },
    { keyword: 'unionbank', weight: 0.55 },
    { keyword: 'landbank', weight: 0.55 },
    { keyword: 'grabpay', weight: 0.60 },
    { keyword: 'coins.ph', weight: 0.60 },
    { keyword: 'sss', weight: 0.60 },
    { keyword: 'philhealth', weight: 0.60 },
    { keyword: 'pag-ibig', weight: 0.60 },
    
    // Lower impersonation (0.40-0.54): Generic terms
    { keyword: 'smart', weight: 0.48 }, // Too generic
    { keyword: 'globe', weight: 0.48 },
    { keyword: 'pldt', weight: 0.50 },
    { keyword: 'government', weight: 0.52 },
    { keyword: 'customer service', weight: 0.50 },
    { keyword: 'support team', weight: 0.50 },
    { keyword: 'official', weight: 0.45 }, // Very generic
    { keyword: 'authorized', weight: 0.48 },
  ],

  /**
   * ═══════════════════════════════════════════════════════════════════════
   * FSA 5: URL PATTERN DETECTION DFA
   * ═══════════════════════════════════════════════════════════════════════
   * 
   * Objective: Detect suspicious URL structures and link patterns
   * 
   * Example DFA Path for "bit.ly/":
   * q₀ --b--> q₁ --i--> q₂ --t--> q₃ --.--> q₄ --l--> q₅ --y--> q₆ --/--> q₇
   * λ(q₇) = {pattern: "bit.ly/", weight: 0.90}
   * 
   * Research Foundation:
   * - Home Credit (2025): Smishing involves clicking malicious links
   * - Whoscall (2025): "Any SMS from unknown with link is text scam"
   * 
   * NOTE: Complex regex patterns converted to common literal indicators
   */
  URL: [
    // Critical URL patterns (0.85-0.92): Obvious malicious indicators
    
    // HTTP (not HTTPS) for financial sites
    { keyword: 'http://gcash', weight: 0.92 },
    { keyword: 'http://bpi', weight: 0.92 },
    { keyword: 'http://bdo', weight: 0.92 },
    { keyword: 'http://metrobank', weight: 0.90 },
    { keyword: 'http://paymaya', weight: 0.90 },
    
    // IP address patterns (common formats)
    { keyword: '://192.168.', weight: 0.90 },
    { keyword: 'http://192', weight: 0.88 },
    { keyword: 'https://192', weight: 0.85 },
    
    // Misspelled domains
    { keyword: 'gcas.com', weight: 0.88 },
    { keyword: 'gcash1.com', weight: 0.87 },
    { keyword: 'gcash-ph.com', weight: 0.85 },
    { keyword: 'bpi-bank.com', weight: 0.85 },
    { keyword: 'bdo-online.com', weight: 0.85 },
    
    // High URL patterns (0.70-0.84): Common scam techniques
    
    // URL shorteners
    { keyword: 'bit.ly/', weight: 0.78 }, // Reduced - common legitimate use
    { keyword: 'tinyurl.com/', weight: 0.78 },
    { keyword: 't.co/', weight: 0.72 }, // Twitter links
    { keyword: 'goo.gl/', weight: 0.75 },
    
    // Suspicious TLDs
    { keyword: '.tk/', weight: 0.82 },
    { keyword: '.ml/', weight: 0.82 },
    { keyword: '.ga/', weight: 0.82 },
    { keyword: '.xyz/', weight: 0.75 },
    { keyword: '.tk', weight: 0.78 },
    { keyword: '.ml', weight: 0.78 },
    
    // Suspicious query parameters
    { keyword: '?verify=', weight: 0.75 },
    { keyword: '?token=', weight: 0.75 },
    { keyword: '?confirm=', weight: 0.75 },
    { keyword: '&verify=', weight: 0.73 },
    
    // Lower URL patterns (0.55-0.69): Needs strong context
    { keyword: 'http://', weight: 0.60 }, // HTTP alone is suspicious but common
    { keyword: 'https://', weight: 0.45 }, // HTTPS is normal
    { keyword: 'click here:', weight: 0.62 },
    { keyword: 'click link:', weight: 0.62 },
  ],
};

/**
 * Pattern Statistics (Auto-generated metadata)
 * This helps validate the DFA construction matches the formal specification
 */
export const PATTERN_STATS = {
  URGENCY: PATTERNS.URGENCY.length,
  FINANCIAL: PATTERNS.FINANCIAL.length,
  PHISHING: PATTERNS.PHISHING.length,
  IMPERSONATION: PATTERNS.IMPERSONATION.length,
  URL: PATTERNS.URL.length,
  TOTAL: Object.values(PATTERNS).reduce((sum, arr) => sum + arr.length, 0),
};

/**
 * Helper: Get all patterns as flat array for DFA construction
 */
export function getAllPatterns(): PatternDef[] {
  return Object.values(PATTERNS).flat();
}

/**
 * Helper: Get patterns by category for modular DFA construction
 */
export function getPatternsByCategory(category: Category): PatternDef[] {
  return PATTERNS[category];
}
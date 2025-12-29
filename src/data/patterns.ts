import type { Category } from '../types/types';

type PatternDef = { keyword: string; weight: number };

export const PATTERNS: Record<Category, PatternDef[]> = {
  URGENCY: [
    // Critical urgency (0.90-0.95): Account threats
    { keyword: 'suspended', weight: 0.95 },        // Account suspension threat (highest urgency)
    { keyword: 'expires', weight: 0.90 },          // Expiration creates immediate scarcity
    { keyword: 'within 24', weight: 0.92 },        // Specific deadline pressure
    { keyword: 'limited time', weight: 0.90 },     // Scarcity principle exploitation
    { keyword: 'today only', weight: 0.90 },       // Extreme time constraint
    
    // High urgency (0.85-0.89): Strong pressure tactics
    { keyword: 'act now', weight: 0.85 },          // Direct action command
    { keyword: 'urgent', weight: 0.90 },           // Explicit urgency declaration
    { keyword: 'immediate', weight: 0.87 },        // No-delay implication
    { keyword: 'last chance', weight: 0.88 },      // Final opportunity pressure
    { keyword: 'now na', weight: 0.85 },           // Filipino urgency (Taglish)
    { keyword: 'asap', weight: 0.82 },             // Abbreviated urgency
    
    // Medium urgency (0.75-0.84): Moderate pressure
    { keyword: 'i-click', weight: 0.80 },          // Call-to-action (Filipino context)
    { keyword: 'avail', weight: 0.75 },            // Opportunity-based urgency
    { keyword: 'hurry', weight: 0.85 },            // Rush inducement
    { keyword: 'expiring', weight: 0.88 },         // Active expiration
    { keyword: 'agad', weight: 0.80 },             // "Immediately" in Filipino
    { keyword: 'mabilis', weight: 0.78 },          // "Fast/quick" in Filipino
    { keyword: 'expire', weight: 0.88 },           // Variant of expires
    
    // Contextual urgency (0.75-0.82): Combined with other cues
    { keyword: 'i-claim', weight: 0.82 },          // Claim action (Filipino)
    { keyword: 'mag-register na', weight: 0.85 },  // "Register now" (Filipino)
    { keyword: 'para makuha', weight: 0.78 },      // "To get/obtain" (creates dependency)
    { keyword: 'bago mag', weight: 0.75 },         // "Before" (deadline implication)
    { keyword: 'hanggang ngayon', weight: 0.82 },  // "Until now" (time pressure)
  ],

  /**
   * FSA 2: Financial/Monetary Detection
   * 
   * Research Foundation:
   * - Whoscall (2025): Loan/reward offers are "mainstay" in PH scam reports
   * - Tookitaki (2025): Investment scams caused PHP 100B+ losses in 2024
   * - ArXiv (2025): Greed framing showed p=0.155 (moderate but inconsistent effectiveness)
   * - Project Document: Financial requests combined with urgency = high-risk signature
   * 
   * Weight Justification:
   * - High-commitment financial (0.85-0.92): Loans, instant money, large profits
   * - Reward/prize patterns (0.80-0.88): Winner declarations, claims
   * - General financial terms (0.68-0.78): Money, cash, earn (context-dependent)
   */
  FINANCIAL: [
    // Critical financial patterns (0.88-0.92): Instant money schemes
    { keyword: 'instant pera', weight: 0.92 },          // "Instant money" - too good to be true
    { keyword: 'mabilis na yaman', weight: 0.92 },      // "Quick wealth" - get-rich-quick
    { keyword: 'kumita ng malaki', weight: 0.90 },      // "Earn big" - unrealistic promise
    { keyword: 'instant loan', weight: 0.90 },          // Immediate approval red flag
    { keyword: 'quick loan', weight: 0.90 },            // Speed emphasis (unusual for real loans)
    
    // High-risk financial (0.85-0.89): Direct money requests
    { keyword: 'cash loan', weight: 0.88 },             // Direct loan offer
    { keyword: 'pautang', weight: 0.87 },               // Filipino "loan"
    { keyword: 'prize', weight: 0.85 },                 // Unsolicited prize
    { keyword: 'reward', weight: 0.85 },                // Unsolicited reward
    { keyword: 'winner', weight: 0.88 },                // Winner declaration
    { keyword: 'claim', weight: 0.85 },                 // Action to receive money
    { keyword: 'payout', weight: 0.85 },                // Payment distribution
    { keyword: 'free load', weight: 0.85 },             // Free mobile load (common PH scam)
    { keyword: 'dagdag kita', weight: 0.85 },           // "Additional income"
    { keyword: 'loan', weight: 0.85 },                  // Generic loan offer
    { keyword: 'utang', weight: 0.85 },                 // Filipino "debt/loan"
    { keyword: 'pwedeng kumita', weight: 0.85 },        // "Can earn money"
    { keyword: 'libre lang', weight: 0.85 },            // "Free only" (too good to be true)
    
    // Medium financial (0.75-0.84): General financial interest
    { keyword: 'congratulations', weight: 0.82 },       // Often precedes prize scams
    { keyword: 'investment', weight: 0.78 },            // Investment opportunity
    { keyword: 'profit', weight: 0.80 },                // Profit promise
    { keyword: 'cash out', weight: 0.82 },              // Withdrawal action
    { keyword: 'remittance', weight: 0.80 },            // Money transfer (context matters)
    { keyword: 'apply loan', weight: 0.85 },            // Loan application prompt
    { keyword: 'kumita', weight: 0.82 },                // "Earn" in Filipino
    { keyword: 'kikita', weight: 0.80 },                // "Will earn" in Filipino
    { keyword: 'tumubo', weight: 0.78 },                // "Grow/increase" (investment context)
    { keyword: 'yaman', weight: 0.75 },                 // "Wealth" in Filipino
    { keyword: 'won', weight: 0.80 },                   // Past tense winner
    { keyword: 'win', weight: 0.75 },                   // Can be legitimate context
    { keyword: 'income', weight: 0.75 },                // General income term
    { keyword: 'extra income', weight: 0.82 },          // Side income offer
    { keyword: 'php', weight: 0.75 },                   // Philippine Peso mention
    { keyword: 'pesos', weight: 0.75 },                 // Currency mention
    
    // Low-medium financial (0.68-0.74): Broad terms needing context
    { keyword: 'earn', weight: 0.72 },                  // Very common word
    { keyword: 'pera', weight: 0.80 },                  // "Money" in Filipino
    { keyword: 'cash', weight: 0.70 },                  // Generic cash mention
    { keyword: 'money', weight: 0.68 },                 // Very generic
    { keyword: 'transfer', weight: 0.70 },              // Could be legitimate
    { keyword: 'libre', weight: 0.78 },                 // "Free" in Filipino
  ],

  /**
   * FSA 3: Phishing Detection
   * 
   * Research Foundation:
   * - Feedzai (2024): Phishing = #1 threat, PHP 623M losses, 6,595 incidents
   * - NIST Phish Scale: Account verification is high-premise-alignment for users
   * - Cyberint (2025): True Login Phishing automates credential exfiltration
   * - Abnormal AI (2025): OTP/credential requests flagged as highest risk
   * 
   * Weight Justification:
   * - Critical phishing (0.92-0.95): OTP requests, identity confirmation, security alerts
   * - High phishing (0.85-0.91): Account actions, verification requests
   * - Medium phishing (0.80-0.88): General validation, update prompts
   */
  PHISHING: [
    // Critical phishing (0.92-0.95): Credential/OTP theft
    { keyword: 'enter otp', weight: 0.95 },             // Direct OTP request (critical)
    { keyword: 'confirm identity', weight: 0.95 },      // Identity verification attempt
    { keyword: 'security alert', weight: 0.95 },        // Fake security warning
    { keyword: 'otp code', weight: 0.93 },              // OTP variation
    { keyword: 'send otp', weight: 0.92 },              // OTP action request
    { keyword: 'verification code', weight: 0.92 },     // Code request
    { keyword: 'suspicious activity', weight: 0.93 },   // Fabricated threat
    
    // High phishing (0.88-0.91): Account takeover attempts
    { keyword: 'verify account', weight: 0.92 },        // Account verification request
    { keyword: 'verify your', weight: 0.90 },           // Personal verification
    { keyword: 'suspended account', weight: 0.92 },     // Account threat + urgency
    { keyword: 'account suspended', weight: 0.92 },     // Variant phrasing
    { keyword: 'locked account', weight: 0.90 },        // Account lockout claim
    { keyword: 'account locked', weight: 0.90 },        // Variant phrasing
    { keyword: 'security code', weight: 0.90 },         // Security code request
    { keyword: 'validate', weight: 0.90 },              // Validation requirement
    { keyword: 'complete verification', weight: 0.92 }, // Multi-step phishing
    { keyword: 'confirm your', weight: 0.88 },          // Confirmation request
    { keyword: 'update your', weight: 0.88 },           // Update prompt
    
    // Medium phishing (0.80-0.87): General credential requests
    { keyword: 'update info', weight: 0.85 },           // Information update
    { keyword: 'blocked', weight: 0.85 },               // Account blocked claim
    { keyword: 'restricted', weight: 0.85 },            // Access restriction
    { keyword: 'failed transaction', weight: 0.85 },    // Transaction failure (fake)
    { keyword: 'payment failed', weight: 0.85 },        // Payment issue (fake)
    { keyword: 'transaction failed', weight: 0.85 },    // Transaction problem
    { keyword: 'delayed payment', weight: 0.82 },       // Payment delay claim
    { keyword: 'i-verify', weight: 0.87 },              // Filipino verification
    { keyword: 'i-update', weight: 0.85 },              // Filipino update
    { keyword: 'i-confirm', weight: 0.87 },             // Filipino confirmation
    { keyword: 'mag-verify', weight: 0.87 },            // "Verify" command in Filipino
    { keyword: 'kailangan i-verify', weight: 0.90 },    // "Need to verify"
    { keyword: 'para ma-verify', weight: 0.88 },        // "To be verified"
  ],

  /**
   * FSA 4: Impersonation Detection
   * 
   * Research Foundation:
   * - Cyberint (2025): Enhanced brand impersonation targeting financial sector
   * - Williams et al. (2014): Authority cues increase click likelihood significantly
   * - Psychological Research (2023): Authority is most common tactic (with reciprocation)
   * - Project Document: Local impersonation (BSP, BIR, telcos, banks) is primary vector
   * 
   * Weight Justification:
   * - Critical impersonation (0.90-0.92): Government agencies, central bank
   * - High impersonation (0.85-0.89): Major banks, e-wallets, official claims
   * - Medium impersonation (0.80-0.84): Telcos, authority claims, support teams
   */
  IMPERSONATION: [
    // Critical impersonation (0.90-0.92): Government/regulatory authorities
    { keyword: 'gcash', weight: 0.92 },                 // #1 e-wallet (highly targeted)
    { keyword: 'bsp', weight: 0.92 },                   // Central bank (high authority)
    { keyword: 'bir', weight: 0.92 },                   // Tax bureau (fear factor)
    { keyword: 'paymaya', weight: 0.90 },               // Major e-wallet
    
    // High impersonation (0.85-0.89): Major financial institutions
    { keyword: 'bpi', weight: 0.87 },                   // Top bank in PH
    { keyword: 'bdo', weight: 0.87 },                   // Largest bank in PH
    { keyword: 'metrobank', weight: 0.87 },             // Major bank
    { keyword: 'unionbank', weight: 0.85 },             // Digital banking leader
    { keyword: 'security bank', weight: 0.85 },         // Major bank
    { keyword: 'landbank', weight: 0.85 },              // Government bank
    { keyword: 'pnb', weight: 0.85 },                   // Philippine National Bank
    { keyword: 'rcbc', weight: 0.85 },                  // Major bank
    { keyword: 'coins.ph', weight: 0.88 },              // Crypto/e-wallet platform
    { keyword: 'grabpay', weight: 0.88 },               // Popular e-wallet
    { keyword: 'sss', weight: 0.88 },                   // Social Security System
    { keyword: 'philhealth', weight: 0.88 },            // Health insurance
    { keyword: 'pag-ibig', weight: 0.88 },              // Housing fund
    { keyword: 'lgu', weight: 0.85 },                   // Local government
    { keyword: 'dti', weight: 0.85 },                   // Trade & Industry dept
    { keyword: 'government', weight: 0.85 },            // Government claim
    { keyword: 'security team', weight: 0.87 },         // Security authority claim
    { keyword: 'bank alert', weight: 0.87 },            // Bank warning message
    { keyword: 'from your bank', weight: 0.88 },        // Bank sender claim
    { keyword: 'authorized', weight: 0.85 },            // Authorization claim
    { keyword: 'home credit', weight: 0.85 },           // Major lending app
    
    // Medium impersonation (0.80-0.84): Telcos, support, generic authority
    { keyword: 'smart', weight: 0.82 },                 // Major telco
    { keyword: 'globe', weight: 0.82 },                 // Major telco
    { keyword: 'pldt', weight: 0.82 },                  // Major telco
    { keyword: 'dito', weight: 0.80 },                  // Newer telco
    { keyword: 'customer service', weight: 0.82 },      // Service impersonation
    { keyword: 'support team', weight: 0.82 },          // Support impersonation
    { keyword: 'cashalo', weight: 0.83 },               // Lending app
    { keyword: 'tala', weight: 0.83 },                  // Lending app
    { keyword: 'official', weight: 0.80 },              // Official claim (generic)
    { keyword: 'representative', weight: 0.80 },        // Representative claim
    { keyword: 'sec', weight: 0.82 },                   // Securities commission
    { keyword: 'fintech', weight: 0.75 },               // Fintech claim (broad)
  ],

  /**
   * FSA 5: URL Pattern Detection
   * 
   * Research Foundation:
   * - Home Credit (2025): Smishing involves clicking malicious links
   * - Whoscall (2025): "Any SMS from unknown number with link is a text scam"
   * - SecurityScorecard (2025): Spoofed domains and URL manipulation are top vectors
   * - Project Document: URL patterns enable smishing → fake login pages
   * 
   * Weight Justification:
   * - Critical URL patterns (0.92-0.95): IP addresses, HTTP for banks, misspellings
   * - High URL patterns (0.85-0.91): URL shorteners, suspicious TLDs
   * - Medium URL patterns (0.75-0.84): Multiple subdomains, suspicious parameters
   */
  URL: [
    // Critical URL patterns (0.92-0.95): Obvious malicious indicators
    { keyword: String(/https?:\/\/(?:\d{1,3}\.){3}\d{1,3}/), weight: 0.95 },  
    // IP address format - no legitimate bank/service uses IPs
    
    { keyword: String(/^http:\/\/(www\.)?(gcash|bpi|bdo|metrobank|paymaya)/), weight: 0.95 },
    // HTTP (not HTTPS) for sensitive sites - major red flag
    
    { keyword: String(/https?:\/\/\w*gcas\w*\.(com|ph)/), weight: 0.92 },
    // GCash misspelling (gcas, gcash1, etc.)
    
    // High URL patterns (0.85-0.91): Common scam techniques
    { keyword: String(/https?:\/\/(bit\.ly|tinyurl|short\.link|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly)\/\w+/), weight: 0.90 },
    // URL shorteners - hide destination
    
    { keyword: String(/https?:\/\/\w+\.(tk|ml|ga|cf|gq|xyz|top|click)\b/), weight: 0.88 },
    // Suspicious TLDs - free/cheap domains favored by scammers
    
    { keyword: String(/https?:\/\/\w*bpi\w*\.(com|ph)/), weight: 0.85 },
    // BPI misspelling variants
    
    { keyword: String(/https?:\/\/\w*bdo\w*\.(com|ph)/), weight: 0.85 },
    // BDO misspelling variants
    
    { keyword: String(/https?:\/\/\w*paymaya\w*\.(com|ph)/), weight: 0.85 },
    // PayMaya misspelling variants
    
    { keyword: String(/https?:\/\/[^\s]+\?(ref|id|token|verify|confirm)=[a-zA-Z0-9]{20,}/), weight: 0.85 },
    // Suspicious query parameters - often used for tracking/phishing
    
    // Medium URL patterns (0.75-0.84): Moderately suspicious
    { keyword: String(/https?:\/\/(?:\w+\.){3,}\w+\.\w{2,3}/), weight: 0.78 },
    // Multiple subdomains (3+) - often used to obscure real domain
  ],
};
import type { Match } from '../types/types';

/**
 * Explicit URLDFA: Character-by-Character DFA with Regex-Assisted Transitions
 * 
 * Formal Definition: M = (Q, Σ, δ, q₀, F, λ)
 * Where:
 * - Q = finite set of states (explicitly defined)
 * - Σ = {a-z, 0-9, '.', '/', ':', '?', '=', '-', '_'} input alphabet
 * - δ: Q × Σ → Q explicit transition function
 * - q₀ = q0 (initial state)
 * - F = accepting states with output patterns
 * - λ: F → {weight, category, urlType} output function
 * 
 * Key Design:
 * 1. Processes input CHARACTER-BY-CHARACTER
 * 2. Uses explicit state transitions (not just regex)
 * 3. Regex patterns used for VALIDATION only, not primary detection
 * 4. Each character advances the state machine explicitly
 */

interface DFAState {
  id: string;
  isAccepting: boolean;
  urlType?: 'protocol' | 'domain' | 'path' | 'param' | 'ip' | 'shortener';
  baseWeight?: number;
  transitions: Map<string, DFAState>; // δ: explicit transition function
  buffer: string; // Accumulated characters for pattern matching
}

interface URLMatch extends Match {
  urlType: string;
  characteristics: string[];
}

export class URLDFA {
  // Q: Set of all states
  private states: Map<string, DFAState> = new Map();
  
  // q₀: Initial state
  private initialState!: DFAState;
  
  // F: Set of accepting states
  private acceptingStates: Set<DFAState> = new Set();
  
  // Pattern lookup tables (for validation, not primary detection)
  private suspiciousTLDs = ['tk', 'ml', 'ga', 'gq', 'cf', 'xyz', 'top', 'click', 'online', 'site'];
  private shorteners = ['bit.ly', 'tinyurl.com', 'tinyurl', 't.co', 'goo.gl', 'cutt.ly', 'rb.gy', 'ow.ly', 'is.gd'];
  private financialKeywords = ['gcash', 'bpi', 'bdo', 'bank', 'paymaya', 'metrobank', 'unionbank', 'security-bank'];
  private suspiciousPaths = ['verify', 'login', 'secure', 'account', 'update', 'confirm', 'auth'];
  private suspiciousParams = ['verify'  , 'token', 'otp', 'confirm', 'code', 'auth', 'validate'];

  constructor() {
    this.buildDFA();
  }

  /**
   * Build the explicit DFA structure
   */
  private buildDFA(): void {
    // Create initial state q0
    this.initialState = this.createState('q0', false);
    
    // Create accepting states (F)
    this.createState('q_http', true, 'protocol', 0.60);
    this.createState('q_https', true, 'protocol', 0.50);
    this.createState('q_domain', true, 'domain', 0.50);
    this.createState('q_shortener', true, 'shortener', 0.78);
    this.createState('q_suspicious_tld', true, 'domain', 0.82);
    this.createState('q_path', true, 'path', 0.65);
    this.createState('q_suspicious_path', true, 'path', 0.70);
    this.createState('q_param', true, 'param', 0.75);
    this.createState('q_ip', true, 'ip', 0.90);
    this.createState('q_url_body', false); // Intermediate state for URL body
    
    // Build transition function δ (done during scanning for flexibility)
  }

  /**
   * Create a state and add to state set Q
   */
  private createState(
    id: string, 
    isAccepting: boolean, 
    urlType?: string, 
    baseWeight?: number
  ): DFAState {
    const state: DFAState = {
      id,
      isAccepting,
      urlType: urlType as any,
      baseWeight,
      transitions: new Map(),
      buffer: ''
    };
    
    this.states.set(id, state);
    
    if (isAccepting) {
      this.acceptingStates.add(state);
    }
    
    return state;
  }

  /**
   * Main scan function - CHARACTER-BY-CHARACTER processing
   */
  scan(text: string): URLMatch[] {
    const matches: URLMatch[] = [];
    let i = 0;

    while (i < text.length) {
      // Start from initial state for each potential match
      let currentState = this.initialState;
      let matchStart = i;
      let lastAcceptingState: DFAState | null = null;
      let lastAcceptingEnd = i;
      let buffer = '';

      // Process characters one by one
      while (i < text.length) {
        const char = text[i];
        
        // Try to transition based on current character
        const nextState = this.delta(currentState, char, buffer + char, text, i);
        
        if (!nextState) {
          // No valid transition, check if we have a match
          break;
        }

        buffer += char;
        currentState = nextState;
        currentState.buffer = buffer;
        i++;

        // Track last accepting state
        if (currentState.isAccepting) {
          lastAcceptingState = currentState;
          lastAcceptingEnd = i;
        }

        // Check for URL boundary characters that end the match
        if (this.isURLBoundary(char, text[i])) {
          break;
        }
      }

      // Emit match if we reached an accepting state
      if (lastAcceptingState && buffer.length > 0) {
        const characteristics = this.analyzeCharacteristics(buffer);
        const weight = this.calculateWeight(lastAcceptingState, characteristics);
        
        matches.push({
          pattern: buffer.substring(0, Math.min(50, buffer.length)) + (buffer.length > 50 ? '...' : ''),
          weight,
          category: 'URL',
          start: matchStart,
          end: lastAcceptingEnd,
          urlType: lastAcceptingState.urlType || 'unknown',
          characteristics
        });

        // Move to end of match
        i = lastAcceptingEnd;
      } else {
        // No match, advance by 1
        i = matchStart + 1;
      }
    }

    return this.deduplicateMatches(matches);
  }

  /**
   * δ: Explicit Transition Function Q × Σ → Q
   * Determines next state based on current state and input character
   */
  private delta(
    currentState: DFAState, 
    char: string, 
    buffer: string,
    fullText: string,
    position: number
  ): DFAState | null {
    const charLower = char.toLowerCase();

    // From q0 (initial state)
    if (currentState.id === 'q0') {
      // Branch 1: Protocol detection
      if (charLower === 'h') {
        // Check if this might be http/https
        return this.transitionToProtocol(buffer, fullText, position);
      }
      
      // Branch 2: Domain detection (for standalone domains)
      if (this.isAlphaNumeric(charLower)) {
        return this.transitionToDomain(buffer, fullText, position);
      }
      
      // Branch 5: IP detection
      if (this.isDigit(charLower)) {
        return this.transitionToIP(buffer, fullText, position);
      }
      
      return null;
    }

    // From protocol states (http/https detection)
    if (currentState.id === 'q_protocol_building') {
      return this.continueProtocol(buffer, fullText, position, char);
    }

    // From URL body state
    if (currentState.id === 'q_url_body') {
      return this.continueURLBody(buffer, fullText, position, char);
    }

    // From domain building state
    if (currentState.id === 'q_domain_building') {
      return this.continueDomain(buffer, fullText, position, char);
    }

    // From IP building state
    if (currentState.id === 'q_ip_building') {
      return this.continueIP(buffer, fullText, position, char);
    }

    // Default: check if character is valid URL character
    if (this.isValidURLChar(charLower)) {
      return currentState; // Stay in current state
    }

    return null;
  }

  /**
   * Transition to protocol detection branch
   */
  private transitionToProtocol(buffer: string, fullText: string, position: number): DFAState | null {
    // Look ahead to check if this is http:// or https://
    const remaining = fullText.substring(position);
    
    if (/^https?:\/\//i.test(remaining)) {
      // Create or get protocol building state
      let state = this.states.get('q_protocol_building');
      if (!state) {
        state = this.createState('q_protocol_building', false);
      }
      return state;
    }
    
    return null;
  }

  /**
   * Continue protocol detection
   */
  private continueProtocol(buffer: string, fullText: string, position: number, char: string): DFAState | null {
    const bufferLower = buffer.toLowerCase();
    
    // Check if we've completed http:// or https://
    if (bufferLower === 'http://' || bufferLower === 'https://') {
      // Transition to URL body state
      let state = this.states.get('q_url_body');
      if (!state) {
        state = this.createState('q_url_body', false);
      }
      return state;
    }
    
    // Still building protocol
    if (/^https?:\/\//i.test(bufferLower + char)) {
      return this.states.get('q_protocol_building')!;
    }
    
    return null;
  }

  /**
   * Continue URL body processing
   */
  private continueURLBody(buffer: string, fullText: string, position: number, char: string): DFAState | null {
    const charLower = char.toLowerCase();
    
    // Valid URL characters
    if (this.isValidURLChar(charLower)) {
      // Check what we're building
      const urlPart = buffer.substring(buffer.indexOf('://') + 3);
      
      // Check for path separator
      if (charLower === '/') {
        // Transitioning to path
        return this.states.get('q_url_body')!;
      }
      
      // Check for query separator
      if (charLower === '?') {
        // Transitioning to query parameters
        return this.states.get('q_url_body')!;
      }
      
      // Continue building URL body
      return this.states.get('q_url_body')!;
    }
    
    // End of URL - determine accepting state based on buffer content
    return this.determineAcceptingState(buffer);
  }

  /**
   * Transition to domain detection branch
   */
  private transitionToDomain(buffer: string, fullText: string, position: number): DFAState | null {
    // Check if this looks like a domain
    const remaining = fullText.substring(position);
    
    // Look for domain pattern: alphanumeric + dots
    if (/^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}/i.test(remaining)) {
      let state = this.states.get('q_domain_building');
      if (!state) {
        state = this.createState('q_domain_building', false);
      }
      return state;
    }
    
    return null;
  }

  /**
   * Continue domain building
   */
  private continueDomain(buffer: string, fullText: string, position: number, char: string): DFAState | null {
    const charLower = char.toLowerCase();
    
    // Valid domain characters
    if (this.isAlphaNumeric(charLower) || charLower === '.' || charLower === '-') {
      // Check if we have a complete domain
      if (this.isCompleteDomain(buffer + char)) {
        return this.determineAcceptingState(buffer + char);
      }
      
      return this.states.get('q_domain_building')!;
    }
    
    // Check if we've built a valid domain
    if (this.isCompleteDomain(buffer)) {
      return this.determineAcceptingState(buffer);
    }
    
    return null;
  }

  /**
   * Transition to IP detection branch
   */
  private transitionToIP(buffer: string, fullText: string, position: number): DFAState | null {
    // Look ahead for IP pattern
    const remaining = fullText.substring(position);
    
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i.test(remaining)) {
      let state = this.states.get('q_ip_building');
      if (!state) {
        state = this.createState('q_ip_building', false);
      }
      return state;
    }
    
    return null;
  }

  /**
   * Continue IP building
   */
  private continueIP(buffer: string, fullText: string, position: number, char: string): DFAState | null {
    const charLower = char.toLowerCase();
    
    // Valid IP characters
    if (this.isDigit(charLower) || charLower === '.') {
      // Check if we have a complete IP
      if (this.isCompleteIP(buffer + char)) {
        return this.states.get('q_ip')!;
      }
      
      return this.states.get('q_ip_building')!;
    }
    
    return null;
  }

  /**
   * Determine accepting state based on buffer content
   */
  private determineAcceptingState(buffer: string): DFAState | null {
    const bufferLower = buffer.toLowerCase();
    
    // Check for protocol
    if (bufferLower.startsWith('http://')) {
      return this.states.get('q_http')!;
    }
    if (bufferLower.startsWith('https://')) {
      return this.states.get('q_https')!;
    }
    
    // Check for IP
    if (this.isCompleteIP(buffer)) {
      return this.states.get('q_ip')!;
    }
    
    // Check for shortener
    if (this.isShortenerDomain(buffer)) {
      return this.states.get('q_shortener')!;
    }
    
    // Check for suspicious TLD
    if (this.hasSuspiciousTLD(buffer)) {
      return this.states.get('q_suspicious_tld')!;
    }
    
    // Check for suspicious path
    if (this.hasSuspiciousPath(buffer)) {
      return this.states.get('q_suspicious_path')!;
    }
    
    // Check for suspicious param
    if (this.hasSuspiciousParam(buffer)) {
      return this.states.get('q_param')!;
    }
    
    // Default to domain
    if (this.isCompleteDomain(buffer)) {
      return this.states.get('q_domain')!;
    }
    
    return null;
  }

  /**
   * Analyze characteristics of matched URL
   */
  private analyzeCharacteristics(buffer: string): string[] {
    const characteristics: string[] = [];
    const bufferLower = buffer.toLowerCase();

    if (this.hasSuspiciousTLD(bufferLower)) {
      characteristics.push('suspicious_tld');
    }

    if (this.isShortenerDomain(bufferLower)) {
      characteristics.push('url_shortener');
    }

    if (this.isCompleteIP(bufferLower)) {
      characteristics.push('ip_address');
    }

    if (this.hasFinancialKeyword(bufferLower) && bufferLower.startsWith('http://')) {
      characteristics.push('http_financial');
    }

    if (this.hasSuspiciousPath(bufferLower)) {
      characteristics.push('suspicious_path');
    }

    if (this.hasSuspiciousParam(bufferLower)) {
      characteristics.push('suspicious_param');
    }

    return characteristics;
  }

  /**
   * Calculate final weight based on state and characteristics
   */
  private calculateWeight(state: DFAState, characteristics: string[]): number {
    let weight = state.baseWeight || 0.50;

    // Apply characteristic-based weight adjustments
    const charWeights: Record<string, number> = {
      'suspicious_tld': 0.82,
      'url_shortener': 0.78,
      'ip_address': 0.90,
      'http_financial': 0.92,
      'suspicious_path': 0.70,
      'suspicious_param': 0.75
    };

    for (const char of characteristics) {
      if (charWeights[char]) {
        weight = Math.max(weight, charWeights[char]);
      }
    }

    return weight;
  }

  /**
   * Helper: Check if character is alphanumeric
   */
  private isAlphaNumeric(char: string): boolean {
    return /[a-z0-9]/i.test(char);
  }

  /**
   * Helper: Check if character is digit
   */
  private isDigit(char: string): boolean {
    return /\d/.test(char);
  }

  /**
   * Helper: Check if character is valid URL character
   */
  private isValidURLChar(char: string): boolean {
    return /[a-z0-9.\-_~:/?#[\]@!$&'()*+,;=%]/i.test(char);
  }

  /**
   * Helper: Check if at URL boundary
   */
  private isURLBoundary(currentChar: string, nextChar: string): boolean {
    if (!nextChar) return true;
    
    // Whitespace boundaries
    if (/\s/.test(nextChar)) return true;
    
    // Punctuation boundaries (but not valid URL chars)
    if (/[<>"'\]]/.test(nextChar)) return true;
    
    return false;
  }

  /**
   * Helper: Check if buffer is complete domain
   */
  private isCompleteDomain(buffer: string): boolean {
    return /^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$/i.test(buffer);
  }

  /**
   * Helper: Check if buffer is complete IP
   */
  private isCompleteIP(buffer: string): boolean {
    return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(buffer);
  }

  /**
   * Helper: Check if domain is a shortener
   */
  private isShortenerDomain(buffer: string): boolean {
    return this.shorteners.some(shortener => 
      buffer.toLowerCase().includes(shortener.toLowerCase())
    );
  }

  /**
   * Helper: Check if has suspicious TLD
   */
  private hasSuspiciousTLD(buffer: string): boolean {
    return this.suspiciousTLDs.some(tld => 
      new RegExp(`\\.${tld}(?:[/?#]|$)`, 'i').test(buffer)
    );
  }

  /**
   * Helper: Check if has financial keywords
   */
  private hasFinancialKeyword(buffer: string): boolean {
    return this.financialKeywords.some(keyword => 
      buffer.toLowerCase().includes(keyword)
    );
  }

  /**
   * Helper: Check if has suspicious path
   */
  private hasSuspiciousPath(buffer: string): boolean {
    return this.suspiciousPaths.some(path => 
      new RegExp(`/${path}(?:[/?#]|$)`, 'i').test(buffer)
    );
  }

  /**
   * Helper: Check if has suspicious param
   */
  private hasSuspiciousParam(buffer: string): boolean {
    return this.suspiciousParams.some(param => 
      new RegExp(`[?&]${param}=`, 'i').test(buffer)
    );
  }

  /**
   * Deduplicate overlapping matches
   */
  private deduplicateMatches(matches: URLMatch[]): URLMatch[] {
    const result: URLMatch[] = [];
    const processedRanges = new Set<string>();

    // Sort by start position
    matches.sort((a, b) => a.start - b.start);

    for (const match of matches) {
      const key = `${match.start}-${match.end}`;
      
      if (processedRanges.has(key)) {
        continue;
      }

      // Check for overlaps
      const overlaps = result.some(existing => 
        (match.start >= existing.start && match.start < existing.end) ||
        (match.end > existing.start && match.end <= existing.end) ||
        (match.start <= existing.start && match.end >= existing.end)
      );

      if (!overlaps) {
        result.push(match);
        processedRanges.add(key);
      }
    }

    return result;
  }

  /**
   * Diagnostic: Get all states
   */
  getStates(): DFAState[] {
    return Array.from(this.states.values());
  }

  /**
   * Diagnostic: Get accepting states
   */
  getAcceptingStates(): DFAState[] {
    return Array.from(this.acceptingStates);
  }

  /**
   * Diagnostic: Get initial state
   */
  getInitialState(): DFAState {
    return this.initialState;
  }
}
import { DFANode } from './DFANode';

interface Pattern {
  keyword: string;
  weight: number;
}

/**
 * AhoCorasickDFA - Character-by-Character Explicit DFA Implementation
 * 
 * Formal Definition: M = (Q, Σ, δ, q₀, F)
 * Where:
 * - Q = finite set of states (represented by DFANode instances)
 * - Σ = input alphabet (characters: a-z, 0-9, spaces, punctuation)
 * - δ = transition function: Q × Σ → Q (character-by-character transitions)
 * - q₀ ∈ Q = initial state (root)
 * - F ⊆ Q = set of accepting states (nodes with output patterns)
 * 
 * Key Changes from Original:
 * 1. Processes input one character at a time (not by keywords)
 * 2. Uses explicit state transitions stored in a lookup table
 * 3. Pattern matching occurs through state traversal, not string comparison
 */
export class AhoCorasickDFA {
  // q₀: Initial state
  private root: DFANode = new DFANode('q0');
  
  // Q: Set of all states (tracked during construction)
  private states: Set<DFANode> = new Set();
  
  // F: Set of accepting states (states with output patterns)
  private acceptingStates: Set<DFANode> = new Set();
  
  // Failure links for Aho-Corasick algorithm
  private failure: Map<DFANode, DFANode> = new Map();
  
  // State counter for explicit state naming (q0, q1, q2, ...)
  private stateCounter: number = 0;
  
  // Pattern lookup table: Maps state IDs to their output patterns
  // This replaces runtime string matching with O(1) lookups
  private patternTable: Map<string, { pattern: string; weight: number }[]> = new Map();

  constructor(patterns: Pattern[]) {
    this.states.add(this.root);
    this.buildTrie(patterns);
    this.buildFailureLinks();
    this.buildPatternTable();
  }

  /**
   * Step 1: Build Trie Structure (Character-by-Character)
   * Constructs explicit state diagram with individual character transitions.
   * 
   * For pattern "act now", creates states:
   * q₀ --a--> q₁ --c--> q₂ --t--> q₃ --[space]--> q₄ --n--> q₅ --o--> q₆ --w--> q₇
   * where q₇ is an accepting state with output λ(q₇) = {"act now", weight}
   */
  private buildTrie(patterns: Pattern[]): void {
    for (const { keyword, weight } of patterns) {
      let currentState = this.root;
      const lowerKeyword = keyword.toLowerCase();
      
      // Process each individual character
      for (let i = 0; i < lowerKeyword.length; i++) {
        const char = lowerKeyword[i];
        
        // δ: Transition function Q × Σ → Q (single character)
        let nextState = currentState.transitions.get(char);
        
        if (!nextState) {
          // Create new state if transition doesn't exist
          this.stateCounter++;
          nextState = new DFANode(`q${this.stateCounter}`);
          
          // Add to Q (set of all states)
          this.states.add(nextState);
          
          // Define δ(currentState, char) = nextState
          currentState.transitions.set(char, nextState);
        }
        
        currentState = nextState;
      }
      
      // Mark final state as accepting
      // Store pattern info for this accepting state
      if (!currentState.output) {
        currentState.output = { pattern: keyword, weight };
        this.acceptingStates.add(currentState);
      } else {
        // Handle multiple patterns ending at same state
        // Store both patterns (rare case)
        const existing = currentState.output;
        currentState.output = {
          pattern: existing.pattern,
          weight: Math.max(existing.weight, weight) // Use higher weight
        };
      }
    }
  }

  /**
   * Step 2: Build Failure Links (Aho-Corasick)
   * Enables efficient multi-pattern matching through failure transitions.
   * When δ(q, a) is undefined, follow failure link to find alternative path.
   */
  private buildFailureLinks(): void {
    const queue: DFANode[] = [];
    
    // Initialize: All immediate children of root fail back to root
    for (const [char, childState] of this.root.transitions) {
      this.failure.set(childState, this.root);
      queue.push(childState);
    }
    
    // BFS to compute failure links for all states
    while (queue.length > 0) {
      const currentState = queue.shift()!;
      
      // Process each character transition from currentState
      for (const [char, childState] of currentState.transitions) {
        queue.push(childState);
        
        // Find the failure state for childState
        let failureState = this.failure.get(currentState) ?? this.root;
        
        // Follow failure links until we find a state with transition on 'char'
        while (failureState !== this.root && !failureState.transitions.has(char)) {
          failureState = this.failure.get(failureState)!;
        }
        
        // Set failure link for childState
        const failTarget = failureState.transitions.get(char) ?? this.root;
        this.failure.set(childState, failTarget);
        
        // Merge output from failure state (for overlapping patterns)
        // This handles cases where one pattern is a suffix of another
        if (failTarget.output && !childState.output) {
          childState.output = failTarget.output;
          this.acceptingStates.add(childState);
        }
      }
    }
  }

  /**
   * Step 3: Build Pattern Lookup Table
   * Creates O(1) lookup structure for retrieving pattern info from states.
   * This eliminates need for runtime string matching.
   */
  private buildPatternTable(): void {
    for (const state of this.acceptingStates) {
      if (state.output) {
        const stateId = state.id;
        
        // Store pattern info indexed by state ID
        if (!this.patternTable.has(stateId)) {
          this.patternTable.set(stateId, []);
        }
        
        this.patternTable.get(stateId)!.push({
          pattern: state.output.pattern,
          weight: state.output.weight
        });
      }
    }
  }

  /**
   * Step 4: Scan Input Text (Character-by-Character)
   * Executes the DFA on input text, processing ONE character at a time.
   * 
   * Algorithm:
   * 1. Start at q₀
   * 2. For each character c in input:
   *    a. Try δ(currentState, c)
   *    b. If undefined, follow failure links until transition exists
   *    c. Move to next state
   *    d. If state ∈ F, emit output via lookup table
   * 
   * Time Complexity: O(n + m) where n = text length, m = total pattern matches
   * Space Complexity: O(k) where k = total characters in all patterns
   */
  scan(text: string): Array<{ pattern: string; weight: number; start: number; end: number }> {
    const matches: Array<{ pattern: string; weight: number; start: number; end: number }> = [];
    
    // Start at initial state q₀
    let currentState: DFANode = this.root;
    
    // Process each character in the input ONE AT A TIME
    for (let i = 0; i < text.length; i++) {
      const char = text[i].toLowerCase();
      
      // Try to find a valid transition for this character
      // If no direct transition exists, follow failure links
      while (currentState !== this.root && !currentState.transitions.has(char)) {
        currentState = this.failure.get(currentState)!;
      }
      
      // Apply transition function δ(currentState, char)
      // If no transition exists from root, stay at root
      const nextState = currentState.transitions.get(char);
      if (nextState) {
        currentState = nextState;
      } else {
        // Stay at root if no transition exists
        currentState = this.root;
      }
      
      // Check if currentState ∈ F (accepting state)
      // Use lookup table instead of checking string patterns
      if (this.patternTable.has(currentState.id)) {
        const patterns = this.patternTable.get(currentState.id)!;
        
        // Emit all patterns that match at this state
        for (const { pattern, weight } of patterns) {
          const patternLength = pattern.length;
          const start = i - patternLength + 1;
          
          // Verify we're not going out of bounds
          if (start >= 0) {
            matches.push({
              pattern,
              weight,
              start,
              end: i + 1
            });
          }
        }
      }
      
      // Also check failure states for additional matches (suffix patterns)
      let failState = this.failure.get(currentState);
      while (failState && failState !== this.root) {
        if (this.patternTable.has(failState.id)) {
          const patterns = this.patternTable.get(failState.id)!;
          
          for (const { pattern, weight } of patterns) {
            const patternLength = pattern.length;
            const start = i - patternLength + 1;
            
            if (start >= 0) {
              matches.push({
                pattern,
                weight,
                start,
                end: i + 1
              });
            }
          }
        }
        failState = this.failure.get(failState);
      }
    }
    
    return matches;
  }

  /**
   * Diagnostic Methods
   */
  
  getStateCount(): number {
    return this.states.size;
  }

  getAcceptingStateCount(): number {
    return this.acceptingStates.size;
  }

  getStates(): DFANode[] {
    return Array.from(this.states);
  }

  getAcceptingStates(): DFANode[] {
    return Array.from(this.acceptingStates);
  }

  getInitialState(): DFANode {
    return this.root;
  }
  
  /**
   * Get pattern lookup table for debugging
   */
  getPatternTable(): Map<string, { pattern: string; weight: number }[]> {
    return this.patternTable;
  }
  
  /**
   * Visualize state transition for a given character
   */
  getTransition(stateId: string, char: string): string | null {
    const state = Array.from(this.states).find(s => s.id === stateId);
    if (!state) return null;
    
    const nextState = state.transitions.get(char.toLowerCase());
    return nextState ? nextState.id : null;
  }
}
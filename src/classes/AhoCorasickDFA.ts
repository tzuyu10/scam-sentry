import { DFANode } from './DFANode';

interface Pattern {
  keyword: string;
  weight: number;
}

/**
 * AhoCorasickDFA - Explicit DFA Implementation
 * 
 * Formal Definition: M = (Q, Σ, δ, q₀, F)
 * Where:
 * - Q = finite set of states (represented by DFANode instances)
 * - Σ = input alphabet (characters, tokens)
 * - δ = transition function: Q × Σ → Q (implemented via transitions map)
 * - q₀ ∈ Q = initial state (root)
 * - F ⊆ Q = set of accepting states (nodes with output patterns)
 */
export class AhoCorasickDFA {
  // q₀: Initial state
  private root: DFANode = new DFANode('q0');
  
  // Q: Set of all states (tracked during construction)
  private states: Set<DFANode> = new Set();
  
  // F: Set of accepting states (states with output patterns)
  private acceptingStates: Set<DFANode> = new Set();
  
  // Failure links for Aho-Corasick algorithm (enables efficient multi-pattern matching)
  private failure: Map<DFANode, DFANode> = new Map();
  
  // State counter for explicit state naming (q0, q1, q2, ...)
  private stateCounter: number = 0;

  constructor(patterns: Pattern[]) {
    this.states.add(this.root);
    this.buildTrie(patterns);
    this.buildFailureLinks();
  }

  /**
   * Step 1: Build Trie Structure
   * Constructs the explicit state diagram by creating states and transitions
   * for each pattern keyword.
   * 
   * For each pattern, we create a path of states q₀ → q₁ → q₂ → ... → qₙ
   * where qₙ is an accepting state with output function λ(qₙ) = {pattern, weight}
   */
  private buildTrie(patterns: Pattern[]): void {
    for (const { keyword, weight } of patterns) {
      let currentState = this.root;
      const lowerKeyword = keyword.toLowerCase();
      
      // Build state path for this pattern
      for (let i = 0; i < lowerKeyword.length; i++) {
        const char = lowerKeyword[i];
        
        // δ: Transition function Q × Σ → Q
        let nextState = this.transitionFunction(currentState, char);
        
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
      
      // currentState is now in F (accepting state)
      // λ: Output function F → {pattern, weight, category}
      currentState.output = { pattern: keyword, weight };
      this.acceptingStates.add(currentState);
    }
  }

  /**
   * Step 2: Build Failure Links (Aho-Corasick specific)
   * Implements failure transitions for efficient multi-pattern matching.
   * This enables the DFA to continue matching after a partial match fails.
   * 
   * Failure links ensure that when a transition δ(q, a) is undefined,
   * we can follow the failure link to find an alternative path.
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
      
      // Process each transition from currentState
      for (const [char, childState] of currentState.transitions) {
        queue.push(childState);
        
        // Find the failure state for childState
        let failureState = this.failure.get(currentState) ?? this.root;
        
        // Follow failure links until we find a state with a transition on 'char'
        // or we reach the root
        while (failureState !== this.root && !this.transitionFunction(failureState, char)) {
          failureState = this.failure.get(failureState)!;
        }
        
        // Set failure link for childState
        const failTarget = this.transitionFunction(failureState, char) ?? this.root;
        this.failure.set(childState, failTarget);
        
        // Merge output from failure state (for overlapping patterns)
        if (failTarget.output && !childState.output) {
          childState.output = failTarget.output;
          this.acceptingStates.add(childState);
        }
      }
    }
  }

  /**
   * δ: Transition Function
   * Implements δ: Q × Σ → Q
   * 
   * Given a state q and input symbol a, returns the next state q'
   * Returns undefined if no transition exists (to be handled by failure links)
   */
  private transitionFunction(state: DFANode, char: string): DFANode | undefined {
    return state.transitions.get(char);
  }

  /**
   * Step 3: Scan Input Text
   * Executes the DFA on input text to detect all pattern matches.
   * 
   * This implements the recognition algorithm:
   * - Start at q₀
   * - For each character in input, apply δ or follow failure links
   * - When reaching a state in F, emit output via λ
   * 
   * Returns all matches with their positions and weights.
   */
  scan(text: string): Array<{ pattern: string; weight: number; start: number; end: number }> {
    const matches: Array<{ pattern: string; weight: number; start: number; end: number }> = [];
    
    // Start at initial state q₀
    let currentState: DFANode = this.root;
    
    // Process each character in the input
    for (let i = 0; i < text.length; i++) {
      const char = text[i].toLowerCase();
      
      // Try to transition with current character
      // If no direct transition exists, follow failure links
      while (currentState !== this.root && !this.transitionFunction(currentState, char)) {
        currentState = this.failure.get(currentState)!;
      }
      
      // Apply transition function δ(currentState, char)
      const nextState = this.transitionFunction(currentState, char) ?? this.root;
      currentState = nextState;
      
      // Check if currentState ∈ F (accepting state)
      // If so, apply output function λ(currentState)
      if (currentState.output) {
        const { pattern, weight } = currentState.output;
        const start = i - pattern.length + 1;
        
        matches.push({
          pattern,
          weight,
          start,
          end: i + 1
        });
      }
    }
    
    return matches;
  }

  /**
   * Diagnostic Methods
   * These methods help visualize and debug the DFA structure
   */
  
  /**
   * Get total number of states |Q|
   */
  getStateCount(): number {
    return this.states.size;
  }

  /**
   * Get number of accepting states |F|
   */
  getAcceptingStateCount(): number {
    return this.acceptingStates.size;
  }

  /**
   * Get all states Q
   */
  getStates(): DFANode[] {
    return Array.from(this.states);
  }

  /**
   * Get accepting states F
   */
  getAcceptingStates(): DFANode[] {
    return Array.from(this.acceptingStates);
  }

  /**
   * Get initial state q₀
   */
  getInitialState(): DFANode {
    return this.root;
  }
}
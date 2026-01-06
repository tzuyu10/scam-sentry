import { DFANode } from './DFANode';

interface Pattern {
  keyword: string;
  weight: number;
}

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

  private buildTrie(patterns: Pattern[]): void {
    for (const { keyword, weight } of patterns) {
      let currentState = this.root;
      const lowerKeyword = keyword.toLowerCase();
      
      for (let i = 0; i < lowerKeyword.length; i++) {
        const char = lowerKeyword[i];
        
        let nextState = currentState.transitions.get(char);
        
        if (!nextState) {
          this.stateCounter++;
          nextState = new DFANode(`q${this.stateCounter}`);
          
          this.states.add(nextState);
          
          currentState.transitions.set(char, nextState);
        }
        
        currentState = nextState;
      }
      
      if (!currentState.output) {
        currentState.output = { pattern: keyword, weight };
        this.acceptingStates.add(currentState);
      } else {
        const existing = currentState.output;
        currentState.output = {
          pattern: existing.pattern,
          weight: Math.max(existing.weight, weight)
        };
      }
    }
  }

  private buildFailureLinks(): void {
    const queue: DFANode[] = [];
    
    for (const [char, childState] of this.root.transitions) {
      this.failure.set(childState, this.root);
      queue.push(childState);
    }
    
    while (queue.length > 0) {
      const currentState = queue.shift()!;
      
      for (const [char, childState] of currentState.transitions) {
        queue.push(childState);
        
        let failureState = this.failure.get(currentState) ?? this.root;
        
        while (failureState !== this.root && !failureState.transitions.has(char)) {
          failureState = this.failure.get(failureState)!;
        }
        
        const failTarget = failureState.transitions.get(char) ?? this.root;
        this.failure.set(childState, failTarget);
        
        if (failTarget.output && !childState.output) {
          childState.output = failTarget.output;
          this.acceptingStates.add(childState);
        }
      }
    }
  }

  private buildPatternTable(): void {
    for (const state of this.acceptingStates) {
      if (state.output) {
        const stateId = state.id;
        
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

  scan(text: string): Array<{ pattern: string; weight: number; start: number; end: number }> {
    const matches: Array<{ pattern: string; weight: number; start: number; end: number }> = [];
    
    // Start at initial state q₀
    let currentState: DFANode = this.root;
    
    for (let i = 0; i < text.length; i++) {
      const char = text[i].toLowerCase();
      
      while (currentState !== this.root && !currentState.transitions.has(char)) {
        currentState = this.failure.get(currentState)!;
      }
      
      const nextState = currentState.transitions.get(char);
      if (nextState) {
        currentState = nextState;
      } else {
        currentState = this.root;
      }
      
      if (this.patternTable.has(currentState.id)) {
        const patterns = this.patternTable.get(currentState.id)!;
        
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
  

  // Get pattern lookup table for debugging
  getPatternTable(): Map<string, { pattern: string; weight: number }[]> {
    return this.patternTable;
  }
  

  //Visualize state transition for a given character
  getTransition(stateId: string, char: string): string | null {
    const state = Array.from(this.states).find(s => s.id === stateId);
    if (!state) return null;
    
    const nextState = state.transitions.get(char.toLowerCase());
    return nextState ? nextState.id : null;
  }
}
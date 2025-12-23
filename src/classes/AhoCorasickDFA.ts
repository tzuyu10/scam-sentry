import { DFANode } from './DFANode';

interface Pattern {
  keyword: string;
  weight: number;
}

export class AhoCorasickDFA {
  private root = new DFANode('root');
  private failure: Map<DFANode, DFANode> = new Map();

  constructor(patterns: Pattern[]) {
    this.buildTrie(patterns);
    this.buildFailureLinks();
  }

  /* ---------- 1. trie ---------- */
  private buildTrie(patterns: Pattern[]): void {
    for (const { keyword, weight } of patterns) {
      let curr = this.root;
      for (const ch of keyword.toLowerCase()) {
        let nxt = curr.next(ch);
        if (!nxt) {
          nxt = new DFANode(`${curr.id}->${ch}`);
          curr.transitions.set(ch, nxt);
        }
        curr = nxt;
      }
      curr.output = { pattern: keyword, weight };
    }
  }

  /* ---------- 2. failure links (BFS) ---------- */
  private buildFailureLinks(): void {
    const queue: DFANode[] = [];
    // root children fail to root
    for (const [, child] of this.root.transitions) {
      this.failure.set(child, this.root);
      queue.push(child);
    }
    while (queue.length) {
      const curr = queue.shift()!;
      for (const [ch, child] of curr.transitions) {
        queue.push(child);
        let fail = this.failure.get(curr) ?? this.root;
        while (fail !== this.root && !fail.next(ch)) fail = this.failure.get(fail)!;
        const failTo = fail.next(ch) ?? this.root;
        this.failure.set(child, failTo);
        // merge outputs
        if (failTo.output && !child.output) child.output = failTo.output;
      }
    }
  }

  /* ---------- 3. scan ---------- */
  scan(text: string): Array<{ pattern: string; weight: number; start: number; end: number }> {
    const res: Array<{ pattern: string; weight: number; start: number; end: number }> = [];
    let curr: DFANode = this.root;
    for (let i = 0; i < text.length; i++) {
      const ch = text[i].toLowerCase();
      while (curr !== this.root && !curr.next(ch)) curr = this.failure.get(curr)!;
      const nxt = curr.next(ch) ?? this.root;
      curr = nxt;
      if (curr.output) {
        const { pattern, weight } = curr.output;
        const start = i - pattern.length + 1;
        res.push({ pattern, weight, start, end: i + 1 });
      }
    }
    return res;
  }
}
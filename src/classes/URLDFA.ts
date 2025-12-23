import type { Match, Category } from '../types/types';

export class URLDFA {
  private regexes: Array<{ reg: RegExp; weight: number }> = [];

  constructor(patterns: { keyword: string; weight: number }[]) {
    for (const p of patterns) {
      // keyword field contains the regex source
      this.regexes.push({ reg: new RegExp(p.keyword.slice(1, -1), 'gi'), weight: p.weight });
    }
  }

  scan(text: string): Match[] {
    const out: Match[] = [];
    for (const { reg, weight } of this.regexes) {
      let m: RegExpExecArray | null;
      while ((m = reg.exec(text)) !== null) {
        out.push({
          pattern: m[0],
          weight,
          category: 'URL',
          start: m.index,
          end: m.index + m[0].length,
        });
      }
    }
    return out;
  }
}
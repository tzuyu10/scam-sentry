import { PATTERNS } from '../data/patterns';
import { AhoCorasickDFA } from '../classes/AhoCorasickDFA';
import { URLDFA } from '../classes/URLDFA';
import type { Match, ScanResult, Category } from '../types/types';

// Build once – singletons
const urgencyDFA   = new AhoCorasickDFA(PATTERNS.URGENCY);
const financialDFA = new AhoCorasickDFA(PATTERNS.FINANCIAL);
const phishingDFA  = new AhoCorasickDFA(PATTERNS.PHISHING);
const impersonateDFA = new AhoCorasickDFA(PATTERNS.IMPERSONATION);
const urlDFA       = new URLDFA(PATTERNS.URL);

export function scanMessage(msg: string): ScanResult {
  const matches: Match[] = [
    ...urgencyDFA.scan(msg).map(m => ({ ...m, category: 'URGENCY' as Category })),
    ...financialDFA.scan(msg).map(m => ({ ...m, category: 'FINANCIAL' as Category })),
    ...phishingDFA.scan(msg).map(m => ({ ...m, category: 'PHISHING' as Category })),
    ...impersonateDFA.scan(msg).map(m => ({ ...m, category: 'IMPERSONATION' as Category })),
    ...urlDFA.scan(msg),
  ];

  // simple weighted average 0-100
  const totalWeight = matches.reduce((s, x) => s + x.weight, 0);
  const score = Math.min(100, Math.round(totalWeight * 100));

  return { score, matches };
}
// Scam category that every DFA reports
export type Category =
  | 'URGENCY'
  | 'FINANCIAL'
  | 'PHISHING'
  | 'IMPERSONATION'
  | 'URL'
  | 'LEGIT';

export type CategoryWeights = Record<Category, number>;

// A single pattern that fired
export interface Match {
  pattern: string;   // e.g. "act now"
  weight:  number;   // 0-1 e.g. 0.85
  category: Category;
  start:   number;   // index in original text
  end:     number;
}

// What the composite controller returns
export interface ScanResult {
  score: number;          // 0-100
  matches: Match[];
}
import type { Category } from '../types/types';

type PatternDef = { keyword: string; weight: number };

export const PATTERNS: Record<Category, PatternDef[]> = {
  URGENCY: [
    { keyword: 'act now', weight: 0.85 },
    { keyword: 'urgent', weight: 0.90 },
    { keyword: 'i-click', weight: 0.80 },
    { keyword: 'suspended', weight: 0.95 },
    { keyword: 'avail', weight: 0.75 },
    { keyword: 'expires', weight: 0.90 },
    { keyword: 'limited time', weight: 0.90 },
    { keyword: 'now na', weight: 0.85 },
    { keyword: 'agad', weight: 0.80 },
  ],
  FINANCIAL: [
    { keyword: 'loan', weight: 0.80 },
    { keyword: 'prize', weight: 0.85 },
    { keyword: 'reward', weight: 0.85 },
    { keyword: 'pera', weight: 0.80 },
    { keyword: 'investment', weight: 0.75 },
    { keyword: 'profit', weight: 0.80 },
    { keyword: 'cash', weight: 0.70 },
    { keyword: 'win', weight: 0.75 },
    { keyword: 'payout', weight: 0.85 },
    { keyword: 'remittance', weight: 0.80 },
    { keyword: 'claim', weight: 0.85 },
    // Filipino
    { keyword: 'kumita ng malaki', weight: 0.90 },
    { keyword: 'instant pera', weight: 0.90 },
    { keyword: 'libre lang', weight: 0.85 },
    { keyword: 'mabilis na yaman', weight: 0.90 },
  ],
  PHISHING: [
    { keyword: 'verify account', weight: 0.90 },
    { keyword: 'confirm identity', weight: 0.95 },
    { keyword: 'enter otp', weight: 0.95 },
    { keyword: 'validate', weight: 0.90 },
    { keyword: 'security alert', weight: 0.95 },
    { keyword: 'suspended account', weight: 0.90 },
    { keyword: 'update info', weight: 0.85 },
    { keyword: 'i-verify', weight: 0.85 },
    { keyword: 'delayed payment', weight: 0.80 },
  ],
  IMPERSONATION: [
    { keyword: 'bsp', weight: 0.90 },
    { keyword: 'bir', weight: 0.90 },
    { keyword: 'bpi', weight: 0.85 },
    { keyword: 'bdo', weight: 0.85 },
    { keyword: 'gcash', weight: 0.90 },
    { keyword: 'official', weight: 0.80 },
    { keyword: 'government', weight: 0.85 },
    { keyword: 'bank alert', weight: 0.85 },
    { keyword: 'security team', weight: 0.85 },
    { keyword: 'customer service', weight: 0.80 },
    { keyword: 'authorized', weight: 0.85 },
    { keyword: 'representative', weight: 0.80 },
    { keyword: 'lgu', weight: 0.85 },
    { keyword: 'pldt', weight: 0.80 },
    { keyword: 'globe', weight: 0.80 },
    { keyword: 'smart', weight: 0.80 },
    { keyword: 'metrobank', weight: 0.85 },
  ],
  URL: [
    // regex strings – will be converted to DFA in URL module
    { keyword: String(/https?:\/\/(?:\d{1,3}\.){3}\d{1,3}/), weight: 0.95 }, // IP
    { keyword: String(/https?:\/\/(bit\.ly|tinyurl|short\.link)\/\w+/), weight: 0.90 }, // shortener
    { keyword: String(/https?:\/\/\w+\.(tk|ml|ga|cf)\b/), weight: 0.85 }, // suspicious TLD
    { keyword: String(/https?:\/\/\w*gcas\w*\.com/), weight: 0.90 }, // gcash misspell
    { keyword: String(/https?:\/\/(?:\w+\.){3,}\w+\.\w{2,3}/), weight: 0.75 }, // >3 sub-dom
  ],
};
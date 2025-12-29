// src/utils/urlValidator.ts

/**
 * Legitimate Domain Whitelist
 */
export const LEGITIMATE_DOMAINS = new Set([
  // Banks
  'bpi.com.ph',
  'bdo.com.ph',
  'metrobank.com.ph',
  'unionbank.com',
  'securitybank.com.ph',
  'landbank.com.ph',
  'pnb.com.ph',
  'rcbc.com.ph',

  // E-wallets
  'gcash.com',
  'paymaya.com',
  'coins.ph',
  'grab.com',
  'grabpay.ph',

  // Government
  'bsp.gov.ph',
  'bir.gov.ph',
  'sss.gov.ph',
  'philhealth.gov.ph',
  'pagibigfund.gov.ph',

  // Telcos
  'smart.com.ph',
  'globe.com.ph',
  'pldt.com.ph',
  'dito.ph'
]);

const SUSPICIOUS_TLDS = new Set([
  'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'click'
]);

const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd'
]);

/* ---------------- Helpers ---------------- */

function extractDomain(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    const m = url.match(/(?:https?:\/\/)?(?:www\.)?([^\/\s]+)/i);
    return m ? m[1].toLowerCase() : null;
  }
}

function extractTLD(domain: string): string {
  const parts = domain.split('.');
  return parts[parts.length - 1];
}

function isIPAddress(url: string): boolean {
  return /https?:\/\/(?:\d{1,3}\.){3}\d{1,3}/.test(url);
}

function isTyposquatting(domain: string): boolean {
  const patterns = [
    /gcas[h]?/i,
    /[bg]cash/i,
    /bp[il1]/i,
    /bd[o0]/i,
    /payma[iy]a/i,
    /metr[o0]bank/i
  ];
  return patterns.some(p => p.test(domain));
}

function hasExcessiveSubdomains(domain: string): boolean {
  return domain.split('.').length > 4;
}

function hasSuspiciousParams(url: string): boolean {
  try {
    const u = new URL(url);
    const suspiciousKeys = ['token', 'verify', 'confirm', 'id', 'ref'];
    for (const [k, v] of u.searchParams.entries()) {
      if (suspiciousKeys.includes(k.toLowerCase()) && v.length > 20) {
        return true;
      }
    }
  } catch {}
  return false;
}

/* ---------------- Public API ---------------- */

/**
 * Adjust URL weight using deterministic heuristics
 * (NO learning, NO external lookups)
 */
export function validateAndAdjustURLWeight(
  url: string,
  baseWeight: number
): number {
  const domain = extractDomain(url);
  if (!domain) return baseWeight;

  // Absolute whitelist
  if (LEGITIMATE_DOMAINS.has(domain)) return 0;

  let multiplier = 1.0;

  // Critical red flags
  if (isIPAddress(url)) multiplier += 0.5;
  if (url.startsWith('http://')) multiplier += 0.25;
  if (isTyposquatting(domain)) multiplier += 0.4;
  if (URL_SHORTENERS.has(domain)) multiplier += 0.2;

  // Moderate red flags
  if (SUSPICIOUS_TLDS.has(extractTLD(domain))) multiplier += 0.15;
  if (hasExcessiveSubdomains(domain)) multiplier += 0.1;
  if (hasSuspiciousParams(url)) multiplier += 0.1;

  // Trust reducers (do NOT override critical flags)
  if (url.startsWith('https://')) multiplier *= 0.85;
  if (domain.endsWith('.gov.ph') || domain.endsWith('.edu.ph')) multiplier *= 0.5;
  else if (domain.endsWith('.com.ph') || domain.endsWith('.ph')) multiplier *= 0.9;

  return Math.min(1, Math.max(0, baseWeight * multiplier));
}

/**
 * Context-aware URL decision
 */
export function shouldFlagURL(
  url: string,
  otherCategories: Set<string>
): boolean {
  const domain = extractDomain(url);
  if (!domain) return true;

  // Whitelisted domains are never flagged
  if (LEGITIMATE_DOMAINS.has(domain)) return false;

  // Always flag strong indicators
  if (isIPAddress(url) || isTyposquatting(domain)) return true;

  // Contextual risk
  if (
    URL_SHORTENERS.has(domain) &&
    (otherCategories.has('PHISHING') || otherCategories.has('URGENCY'))
  ) {
    return true;
  }

  if (SUSPICIOUS_TLDS.has(extractTLD(domain)) && otherCategories.size >= 2) {
    return true;
  }

  // URL alone is not enough
  return otherCategories.size > 0;
}

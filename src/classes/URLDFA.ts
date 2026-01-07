import type { Match } from '../types/types';

interface URLMatch extends Match {
  urlType: string;
  characteristics: string[];
}
type State = 0 | 1 | 2 | 3;

const State = {
  INIT: 0 as State,
  DOMAIN: 1 as State,
  PATH: 2 as State,
  QUERY: 3 as State
} as const;

export class URLDFA {
  private suspiciousTLDs = ['tk', 'ml', 'ga', 'gq', 'cf', 'xyz', 'top', 'click', 'online', 'site', 'icu'];
  private shorteners = ['bit.ly', 'tinyurl.com', 'tinyurl', 't.co', 'goo.gl', 'cutt.ly', 'rb.gy', 'ow.ly', 'is.gd', 'winplus10.icu'];
  private financialKeywords = ['gcash', 'bpi', 'bdo', 'bank', 'paymaya', 'metrobank', 'unionbank', 'security-bank'];
  private suspiciousPaths = ['verify', 'login', 'secure', 'account', 'update', 'confirm', 'auth'];
  private suspiciousParams = ['verify', 'token', 'otp', 'confirm', 'code', 'auth', 'validate'];

  scan(text: string): URLMatch[] {
    const matches: URLMatch[] = [];
    let i = 0;

    while (i < text.length) {
      const match = this.tryMatchURL(text, i);
      
      if (match) {
        matches.push(match);
        i = match.end;
      } else {
        i++;
      }
    }

    return this.deduplicateMatches(matches);
  }

  private tryMatchURL(text: string, startPos: number): URLMatch | null {
    let state = State.INIT;
    let buffer = '';
    let i = startPos;
    let hasProtocol = false;
    let hasDomain = false;

    while (i < text.length) {
      const char = text[i];
      const nextChar = text[i + 1] || '';

      // State transitions
      switch (state) {
        case State.INIT:
          // Check for protocol start
          if (this.startsWithProtocol(text, i)) {
            const protocol = text.substring(i, i + 8).toLowerCase().startsWith('https://') ? 'https://' : 'http://';
            buffer = protocol;
            i += protocol.length;
            state = State.DOMAIN;
            hasProtocol = true;
            continue;
          }
          // Check for domain start (no protocol)
          else if (this.isAlphaNumeric(char)) {
            buffer = char;
            i++;
            state = State.DOMAIN;
            continue;
          }
          // No URL found
          return null;

        case State.DOMAIN:
          // Valid domain characters (including digits for domains)
          if (this.isAlphaNumeric(char) || char === '.' || char === '-') {
            buffer += char;
            i++;
            
            // Check if we have a complete domain
            if (this.hasValidDomain(buffer, hasProtocol)) {
              hasDomain = true;
            }
            continue;
          }
          // Path separator
          else if (char === '/' && hasDomain) {
            buffer += char;
            i++;
            state = State.PATH;
            continue;
          }
          // Query separator
          else if (char === '?' && hasDomain) {
            buffer += char;
            i++;
            state = State.QUERY;
            continue;
          }
          // End of URL
          else {
            break;
          }

        case State.PATH:
          // Valid path characters
          if (this.isValidPathChar(char)) {
            buffer += char;
            i++;
            continue;
          }
          // Query separator
          else if (char === '?') {
            buffer += char;
            i++;
            state = State.QUERY;
            continue;
          }
          // End of URL
          else {
            break;
          }

        case State.QUERY:
          // Valid query characters
          if (this.isValidQueryChar(char)) {
            buffer += char;
            i++;
            continue;
          }
          // End of URL
          else {
            break;
          }
      }

      // If we get here, we've hit a boundary
      break;
    }

    // Validate and return match
    if (hasDomain && buffer.length > 0) {
      return this.createMatch(buffer, startPos, i, hasProtocol);
    }

    return null;
  }

  /**
   * Check if text starts with http:// or https:// at position
   */
  private startsWithProtocol(text: string, pos: number): boolean {
    const remaining = text.substring(pos).toLowerCase();
    return remaining.startsWith('http://') || remaining.startsWith('https://');
  }

  /**
   * Check if buffer contains a valid domain
   */
  private hasValidDomain(buffer: string, hasProtocol: boolean): boolean {
    // Extract domain part
    let domain = buffer;
    if (hasProtocol) {
      const protocolEnd = buffer.indexOf('://');
      if (protocolEnd !== -1) {
        domain = buffer.substring(protocolEnd + 3);
      }
    }

    // Remove path/query if present
    domain = domain.split('/')[0].split('?')[0];

    // Domain must not be empty
    if (!domain || domain.length === 0) {
      return false;
    }

    // Check for IP address (valid special case)
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) {
      return true;
    }

    // Check for valid domain format
    // Must have at least one dot and valid TLD
    if (domain.includes('.')) {
      const parts = domain.split('.');
      const tld = parts[parts.length - 1].toLowerCase();
      
      // TLD must be at least 2 characters and alphanumeric (letters and numbers)
      if (tld.length >= 2 && /^[a-z0-9]+$/i.test(tld) && /[a-z]/i.test(tld)) {
        // Also ensure the domain part before TLD is not empty
        if (parts.length >= 2 && parts[parts.length - 2].length > 0) {
          // MODIFICATION: Reject purely numeric domains (except IP addresses already handled above)
          // At least one part must contain a letter
          const hasLetter = parts.some(part => /[a-z]/i.test(part));
          if (hasLetter) {
            return true;
          }
        }
      }
    }

    return false;
  }

  private createMatch(buffer: string, start: number, end: number, hasProtocol: boolean): URLMatch {
    const characteristics = this.analyzeCharacteristics(buffer);
    const urlType = this.determineURLType(buffer, characteristics);
    const weight = this.calculateWeight(buffer, characteristics, hasProtocol);

    return {
      pattern: buffer.length > 50 ? buffer.substring(0, 50) + '...' : buffer,
      weight: parseFloat(weight.toFixed(2)),
      category: 'URL',
      start,
      end,
      urlType,
      characteristics
    };
  }
  
  private analyzeCharacteristics(url: string): string[] {
    const characteristics: string[] = [];
    const urlLower = url.toLowerCase();
    
    // Extract domain for more accurate matching
    let domain = urlLower;
    if (urlLower.includes('://')) {
      domain = urlLower.split('://')[1].split('/')[0].split('?')[0];
    } else {
      domain = urlLower.split('/')[0].split('?')[0];
    }
    
    // Check suspicious TLDs
    if (this.suspiciousTLDs.some(tld => new RegExp(`\\.${tld}(?:[/?#]|$)`).test(urlLower) || domain.endsWith(`.${tld}`))) {
      characteristics.push('suspicious_tld');
    }

    // Check URL shorteners (must match domain, not just substring)
    if (this.shorteners.some(s => domain === s || domain.startsWith(s + '/') || domain.startsWith(s + '?'))) {
      characteristics.push('url_shortener');
    }

    if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) {
      characteristics.push('ip_address');
    }

    if (urlLower.startsWith('http://') && this.financialKeywords.some(k => urlLower.includes(k))) {
      characteristics.push('http_financial');
    }

    if (this.suspiciousPaths.some(p => new RegExp(`/${p}(?:[/?#]|$)`, 'i').test(urlLower))) {
      characteristics.push('suspicious_path');
    }

    if (this.suspiciousParams.some(p => new RegExp(`[?&]${p}=`, 'i').test(urlLower))) {
      characteristics.push('suspicious_param');
    }

    return characteristics;
  }

  private determineURLType(url: string, characteristics: string[]): string {
    if (characteristics.includes('ip_address')) return 'ip';
    if (characteristics.includes('url_shortener')) return 'shortener';
    if (characteristics.includes('suspicious_tld')) return 'suspicious_domain';
    if (url.toLowerCase().startsWith('https://')) return 'https';
    if (url.toLowerCase().startsWith('http://')) return 'http';
    return 'domain';
  }

  private calculateWeight(url: string, characteristics: string[], hasProtocol: boolean): number {
    let weight = 0.50;
    const charWeights: Record<string, number> = {
      'ip_address': 0.90,
      'http_financial': 0.92,
      'suspicious_tld': 0.82,
      'url_shortener': 0.78,
      'suspicious_param': 0.75,
      'suspicious_path': 0.70
    };

    for (const char of characteristics) {
      if (charWeights[char]) {
        weight = Math.max(weight, charWeights[char]);
      }
    }
    if (url.toLowerCase().startsWith('http://')) {
      weight = Math.max(weight, 0.60);
    }

    return weight;
  }

  // Character validation helpers
  private isAlphaNumeric(char: string): boolean {
    return /[a-z0-9]/i.test(char);
  }

  private isValidPathChar(char: string): boolean {
    return /[a-z0-9.\-_~/?#@!$&'()*+,;=%]/i.test(char);
  }

  private isValidQueryChar(char: string): boolean {
    return /[a-z0-9.\-_~/?#@!$&'()*+,;=%]/i.test(char);
  }

  private deduplicateMatches(matches: URLMatch[]): URLMatch[] {
    if (matches.length === 0) return [];
    matches.sort((a, b) => {
      if (a.start !== b.start) return a.start - b.start;
      return (b.end - b.start) - (a.end - a.start);
    });

    const result: URLMatch[] = [];
    
    for (const match of matches) {
      const overlaps = result.some(existing => 
        (match.start >= existing.start && match.start < existing.end) ||
        (match.end > existing.start && match.end <= existing.end) ||
        (match.start <= existing.start && match.end >= existing.end)
      );

      if (!overlaps) {
        result.push(match);
      }
    }

    return result;
  }
}
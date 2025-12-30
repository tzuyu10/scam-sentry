import type { Match } from '../types/types';

/**
 * URLDFA: Dual-strategy URL detection
 * 1. Pattern matching: Check for suspicious literal patterns from PATTERNS.URL
 * 2. URL discovery: Find actual URLs and score them based on characteristics
 */
export class URLDFA {
  private literalPatterns: Array<{ keyword: string; weight: number }> = [];
  
  // Comprehensive URL detection regex
  private urlRegex = /(?:https?:\/\/|www\.)[^\s<>"\]]+|(?:[a-z0-9-]+\.)+(?:com|net|org|ph|tk|ml|ga|xyz|ly|co|io|gov|edu|info|biz)(?:\/[^\s<>"]*)?/gi;

  constructor(patterns: { keyword: string; weight: number }[]) {
    this.literalPatterns = patterns;
  }

  scan(text: string): Match[] {
    const matches: Match[] = [];
    const foundURLs = new Set<string>(); // Track URLs to avoid duplicates
    
    // Strategy 1: Find all actual URLs in text
    this.urlRegex.lastIndex = 0;
    let urlMatch: RegExpExecArray | null;
    
    while ((urlMatch = this.urlRegex.exec(text)) !== null) {
      const urlText = urlMatch[0];
      const urlLower = urlText.toLowerCase();
      const urlKey = `${urlMatch.index}-${urlText}`;
      
      if (foundURLs.has(urlKey)) continue;
      foundURLs.add(urlKey);
      
      // Check which literal patterns match this URL
      let maxWeight = 0.50; // Base weight for any detected URL
      let matchedPattern = 'url_detected';
      let hasSpecificMatch = false;
      
      for (const p of this.literalPatterns) {
        const patternLower = p.keyword.toLowerCase();
        
        if (urlLower.includes(patternLower)) {
          hasSpecificMatch = true;
          // Use highest matching weight
          if (p.weight > maxWeight) {
            maxWeight = p.weight;
            matchedPattern = p.keyword;
          }
        }
      }
      
      // Only add if URL has suspicious characteristics or matches a pattern
      if (hasSpecificMatch || this.isSuspiciousURL(urlLower)) {
        matches.push({
          pattern: matchedPattern,
          weight: maxWeight,
          category: 'URL',
          start: urlMatch.index,
          end: urlMatch.index + urlText.length,
        });
      }
    }
    
    // Strategy 2: Also check for literal pattern matches (for patterns that might not be full URLs)
    for (const p of this.literalPatterns) {
      const pattern = p.keyword.toLowerCase();
      let startIndex = 0;
      
      while ((startIndex = text.toLowerCase().indexOf(pattern, startIndex)) !== -1) {
        const matchKey = `${startIndex}-${pattern}`;
        
        // Avoid duplicate if already caught by URL regex
        const isDuplicate = matches.some(m => 
          m.start <= startIndex && m.end >= startIndex + pattern.length
        );
        
        if (!isDuplicate) {
          matches.push({
            pattern: p.keyword,
            weight: p.weight,
            category: 'URL',
            start: startIndex,
            end: startIndex + pattern.length,
          });
        }
        
        startIndex += pattern.length;
      }
    }
    
    return matches;
  }
  
  /**
   * Heuristic: Check if URL has suspicious characteristics
   */
  private isSuspiciousURL(url: string): boolean {
    // Suspicious TLDs
    if (/\.(tk|ml|ga|gq|cf)(?:\/|$)/i.test(url)) return true;
    
    // HTTP (not HTTPS) with financial keywords
    if (/^http:\/\//.test(url) && /gcash|bpi|bdo|bank|paymaya|metrobank/i.test(url)) return true;
    
    // IP addresses
    if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) return true;
    
    // URL shorteners
    if (/bit\.ly|tinyurl|goo\.gl|t\.co/i.test(url)) return true;
    
    // Suspicious query params
    if (/[?&](verify|validate|confirm|token|otp)=/i.test(url)) return true;
    
    return false;
  }
}
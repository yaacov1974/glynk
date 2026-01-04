/**
 * URL Validation Utility
 * 
 * Comprehensive URL validation before making API calls.
 * This prevents unnecessary calls to Cloudflare Worker and Google Safe Browsing API.
 */

/**
 * Validate URL structure and format
 * 
 * @param {string} urlString - The URL to validate
 * @returns {{isValid: boolean, error?: string, normalizedUrl?: string}}
 */
export function validateUrl(urlString) {
  // 1. Trim - Remove whitespace from start and end
  const trimmed = urlString.trim();
  
  if (!trimmed) {
    return {
      isValid: false,
      error: 'URL cannot be empty',
    };
  }

  // 2. Lowercase - Domains are case-insensitive
  const lowercased = trimmed.toLowerCase();

  // 3. Check for basic structure
  let urlToValidate = lowercased;
  let hasProtocol = false;

  // Check if has protocol
  if (lowercased.startsWith('http://') || lowercased.startsWith('https://')) {
    hasProtocol = true;
    urlToValidate = lowercased;
  } else {
    // Add https:// for validation
    urlToValidate = `https://${lowercased}`;
  }

  // 4. Try to parse as URL (basic syntax check)
  let urlObj;
  try {
    urlObj = new URL(urlToValidate);
  } catch (error) {
    return {
      isValid: false,
      error: 'Invalid URL format',
    };
  }

  // 5. Extract hostname (domain)
  const hostname = urlObj.hostname;

  if (!hostname || hostname.length === 0) {
    return {
      isValid: false,
      error: 'URL must contain a domain',
    };
  }

  // 6. Check for at least one dot
  if (!hostname.includes('.')) {
    return {
      isValid: false,
      error: 'Domain must contain at least one dot (e.g., domain.com)',
    };
  }

  // 7. Split domain into parts
  const domainParts = hostname.split('.');

  // 8. Check that we have at least 2 parts (domain + TLD)
  if (domainParts.length < 2) {
    return {
      isValid: false,
      error: 'Domain must include a top-level domain (TLD). Example: domain.com, not just "domain"',
    };
  }

  // 9. Check TLD (Top Level Domain)
  const tld = domainParts[domainParts.length - 1];
  if (!tld || tld.length === 0) {
    return {
      isValid: false,
      error: 'Domain extension (TLD) cannot be empty',
    };
  }

  // 10. Check that TLD contains only letters (no numbers or hyphens in TLD)
  const tldRegex = /^[a-z]+$/;
  if (!tldRegex.test(tld)) {
    return {
      isValid: false,
      error: 'Domain extension (TLD) can only contain letters',
    };
  }

  // 11. Check TLD length - must be between 2 and 63 characters, but typically 2-4
  // If TLD is longer than 6 characters, it's likely a domain name, not a TLD
  if (tld.length < 2) {
    return {
      isValid: false,
      error: 'Domain extension (TLD) must be at least 2 characters (e.g., .com, .io)',
    };
  }

  // 12. Check if TLD is suspiciously long (likely a domain name, not TLD)
  // Most common TLDs are 2-4 characters. Some newer ones are longer (like .technology)
  // But if it's longer than 10 characters, it's almost certainly not a TLD
  if (tld.length > 10) {
    return {
      isValid: false,
      error: `"${tld}" appears to be a domain name, not a top-level domain (TLD). Please include a valid TLD like .com, .org, .io, etc.`,
    };
  }

  // 13. Additional check: if we only have 2 parts and the "TLD" is longer than 4 chars,
  // it might be a domain name without TLD (e.g., "www.saasaipartners")
  if (domainParts.length === 2 && tld.length > 4) {
    // Check against common long TLDs to allow them
    const commonLongTlds = [
      'technology', 'photography', 'international', 'organization', 'foundation',
      'construction', 'engineering', 'management', 'consulting', 'enterprises',
      'productions', 'ventures', 'partners', 'holdings', 'solutions', 'services',
      'systems', 'industries', 'properties', 'developments', 'communications',
      'institutions', 'associations', 'corporation', 'university', 'education',
    ];
    
    if (!commonLongTlds.includes(tld.toLowerCase())) {
      return {
        isValid: false,
        error: `"${tld}" appears to be a domain name, not a top-level domain (TLD). Please include a valid TLD like .com, .org, .io, etc. Example: ${hostname}.com`,
      };
    }
  }

  // 11. Check each domain part (label)
  for (let i = 0; i < domainParts.length; i++) {
    const part = domainParts[i];
    
    // Check label length (max 63 characters)
    if (part.length > 63) {
      return {
        isValid: false,
        error: `Domain part "${part}" exceeds maximum length of 63 characters`,
      };
    }

    // Check for forbidden characters (only letters, numbers, and hyphens allowed)
    const validDomainRegex = /^[a-z0-9-]+$/;
    if (!validDomainRegex.test(part)) {
      return {
        isValid: false,
        error: 'Domain contains invalid characters. Only letters, numbers, and hyphens are allowed',
      };
    }

    // Check for hyphens at start or end (not allowed)
    if (part.startsWith('-') || part.endsWith('-')) {
      return {
        isValid: false,
        error: 'Domain parts cannot start or end with a hyphen',
      };
    }

    // Check for consecutive hyphens
    if (part.includes('--')) {
      return {
        isValid: false,
        error: 'Domain cannot contain consecutive hyphens',
      };
    }
  }

  // 12. Check total domain length (max 253 characters)
  if (hostname.length > 253) {
    return {
      isValid: false,
      error: 'Domain exceeds maximum length of 253 characters',
    };
  }

  // 13. Check for spaces (shouldn't exist after trim, but double-check)
  if (hostname.includes(' ')) {
    return {
      isValid: false,
      error: 'Domain cannot contain spaces',
    };
  }

  // 14. Check for special forbidden characters
  const forbiddenChars = ['@', '!', '#', '$', '%', '^', '&', '*', '(', ')', '+', '=', '[', ']', '{', '}', '|', '\\', ';', ':', '"', "'", '<', '>', ',', '?', '~', '`'];
  for (const char of forbiddenChars) {
    if (hostname.includes(char)) {
      return {
        isValid: false,
        error: `Domain cannot contain the character "${char}"`,
      };
    }
  }

  // 15. Check protocol (must be http or https)
  if (hasProtocol) {
    const protocol = urlObj.protocol;
    if (protocol !== 'http:' && protocol !== 'https:') {
      return {
        isValid: false,
        error: 'URL must use http:// or https:// protocol',
      };
    }
  }

  // 16. Check for valid port (if specified)
  if (urlObj.port) {
    const portNum = parseInt(urlObj.port, 10);
    if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
      return {
        isValid: false,
        error: 'Port number must be between 1 and 65535',
      };
    }
  }

  // 17. Check for localhost/private IPs (optional - can be allowed or blocked)
  // Uncomment if you want to block localhost:
  // if (hostname === 'localhost' || hostname.startsWith('127.') || hostname.startsWith('192.168.') || hostname.startsWith('10.')) {
  //   return {
  //     isValid: false,
  //     error: 'Localhost and private IP addresses are not allowed',
  //   };
  // }

  // 18. Check for suspicious subdomain patterns on well-known domains
  if (domainParts.length >= 2) {
    const subdomain = domainParts[0];
    const mainDomain = domainParts.slice(1).join('.');
    
    // List of well-known domains that shouldn't have suspicious subdomains
    const wellKnownDomains = [
      'google.com', 'google.co.il', 'google.co.uk', 'google.fr', 'google.de',
      'facebook.com', 'youtube.com', 'amazon.com', 'amazon.co.uk',
      'microsoft.com', 'apple.com', 'twitter.com', 'x.com',
      'instagram.com', 'linkedin.com', 'github.com', 'netflix.com',
      'paypal.com', 'ebay.com', 'walmart.com', 'target.com',
    ];
    
    // Check if main domain is well-known
    if (wellKnownDomains.includes(mainDomain)) {
      // Flag suspiciously short subdomains (1-3 characters) on well-known domains
      if (subdomain.length > 0 && subdomain.length <= 3) {
        // Allow common legitimate short subdomains
        const legitimateShortSubdomains = [
          'www', 'api', 'cdn', 'img', 'js', 'css', 'ftp', 'smtp', 'mail', 
          'pop', 'imap', 'vpn', 'ssh', 'git', 'dev', 'stg', 'prd', 'uat', 
          'test', 'qa', 'app', 'web', 'mob', 'ios', 'win', 'mac', 'old', 
          'new', 'tmp', 'bak', 'log', 'db', 'sql', 'node', 'php', 'py', 
          'go', 'rb', 'java', 'net', 'asp', 'jsp', 'html', 'xml', 'json',
        ];
        
        if (!legitimateShortSubdomains.includes(subdomain.toLowerCase())) {
          return {
            isValid: false,
            error: `Suspicious subdomain detected. "${subdomain}.${mainDomain}" may be a typo or phishing attempt. Please verify the URL is correct.`,
          };
        }
      }
    }
    
    // Check for suspiciously short main domain parts
    if (domainParts.length === 2) {
      const domainName = domainParts[0];
      if (domainName.length <= 1) {
        return {
          isValid: false,
          error: 'Domain name is too short. Please verify the URL is correct.',
        };
      }
    }
  }

  // 19. Check for common typos
  const commonTypos = {
    'http:///': 'http://',
    'https:///': 'https://',
    'http:/': 'http://',
    'https:/': 'https://',
  };

  // 20. Check for minimum domain part length (each part should be at least 1 char, but warn on very short)
  for (let i = 0; i < domainParts.length - 1; i++) {
    const part = domainParts[i];
    if (part.length === 0) {
      return {
        isValid: false,
        error: 'Domain parts cannot be empty',
      };
    }
  }

  // 21. Normalize URL - return with https:// if no protocol
  const normalizedUrl = hasProtocol ? lowercased : `https://${lowercased}`;

  // All validations passed
  return {
    isValid: true,
    normalizedUrl: normalizedUrl,
  };
}

/**
 * Quick validation check (lightweight)
 * Use this for real-time feedback while user is typing
 * 
 * @param {string} urlString - The URL to validate
 * @returns {boolean}
 */
export function isUrlFormatValid(urlString) {
  if (!urlString || !urlString.trim()) {
    return false;
  }

  const trimmed = urlString.trim().toLowerCase();
  
  // Basic checks only
  if (trimmed.length < 4) return false; // Minimum: a.co
  if (!trimmed.includes('.')) return false; // Must have a dot
  
  // Check for obvious invalid characters
  const invalidChars = [' ', '@', '!', '#', '$'];
  for (const char of invalidChars) {
    if (trimmed.includes(char)) return false;
  }

  return true;
}


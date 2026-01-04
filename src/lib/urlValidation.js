/**
 * URL Validation Utility
 * 
 * Comprehensive URL validation before making API calls.
 * This prevents unnecessary calls to Cloudflare Worker and Google Safe Browsing API.
 */

import isFQDN from 'validator/lib/isFQDN';
import isURL from 'validator/lib/isURL';

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

  // 6. Check for consecutive hyphens (double hyphens) - not allowed in domains
  if (hostname.includes('--')) {
    return {
      isValid: false,
      error: 'Domain cannot contain consecutive hyphens (--). Please remove the extra hyphen.',
    };
  }

  // 7. Check for hyphens at start or end of domain parts
  const domainParts = hostname.split('.');
  for (const part of domainParts) {
    if (part.startsWith('-') || part.endsWith('-')) {
      return {
        isValid: false,
        error: 'Domain parts cannot start or end with a hyphen',
      };
    }
  }

  // 8. Use validator library to check if hostname is a valid FQDN (Fully Qualified Domain Name)
  // This catches cases like "www.saasaipartners" (missing TLD)
  if (!isFQDN(hostname, {
    require_tld: true,        // Must have TLD
    allow_underscores: false, // No underscores allowed
    allow_trailing_dot: false, // No trailing dot
    allow_numeric_tld: false,  // TLD cannot be numeric
  })) {
    return {
      isValid: false,
      error: 'Invalid domain format. Domain must be a fully qualified domain name (FQDN) with a valid TLD. Example: domain.com',
    };
  }

  // 12. Check protocol (must be http or https)
  if (hasProtocol) {
    const protocol = urlObj.protocol;
    if (protocol !== 'http:' && protocol !== 'https:') {
      return {
        isValid: false,
        error: 'URL must use http:// or https:// protocol',
      };
    }
  }

  // 13. Check for valid port (if specified)
  if (urlObj.port) {
    const portNum = parseInt(urlObj.port, 10);
    if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
      return {
        isValid: false,
        error: 'Port number must be between 1 and 65535',
      };
    }
  }

  // 14. Check for localhost/private IPs (optional - can be allowed or blocked)
  // Uncomment if you want to block localhost:
  // if (hostname === 'localhost' || hostname.startsWith('127.') || hostname.startsWith('192.168.') || hostname.startsWith('10.')) {
  //   return {
  //     isValid: false,
  //     error: 'Localhost and private IP addresses are not allowed',
  //   };
  // }

  // 15. Check for suspicious subdomain patterns on well-known domains
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

  // 16. Check for common typos
  const commonTypos = {
    'http:///': 'http://',
    'https:///': 'https://',
    'http:/': 'http://',
    'https:/': 'https://',
  };

  // 17. Check for minimum domain part length (each part should be at least 1 char, but warn on very short)
  for (let i = 0; i < domainParts.length - 1; i++) {
    const part = domainParts[i];
    if (part.length === 0) {
      return {
        isValid: false,
        error: 'Domain parts cannot be empty',
      };
    }
  }

  // 18. Normalize URL - return with https:// if no protocol
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


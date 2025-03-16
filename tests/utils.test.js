// Import utility functions to test
// For demonstration purposes, we'll create mock functions
const utils = {
  calculateRiskScore: (url, visual, behavior) => {
    const weights = { url: 0.4, visual: 0.4, behavior: 0.2 };
    return (url * weights.url) + (visual * weights.visual) + (behavior * weights.behavior);
  },
  
  isPhishingUrl: (url) => {
    const suspiciousPatterns = [
      /paypal.*\.(?!paypal\.com$)/i,
      /bank.*\.(?!bankofamerica\.com$)/i,
      /secure.*\.com/i
    ];
    
    // Whitelist of legitimate domains
    const legitimateDomains = [
      'www.paypal.com',
      'www.bankofamerica.com',
      'www.google.com'
    ];
    
    // Check if URL is in the whitelist
    if (legitimateDomains.some(domain => url.includes(domain))) {
      return false;
    }
    
    return suspiciousPatterns.some(pattern => pattern.test(url));
  },
  
  sanitizeInput: (input) => {
    if (typeof input !== 'string') return '';
    return input.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
                .replace(/on\w+="[^"]*"/gi, '')
                .replace(/javascript:/gi, '');
  }
};

describe('Utility Functions', () => {
  describe('calculateRiskScore', () => {
    test('should calculate weighted risk score correctly', () => {
      const urlRisk = 0.8;
      const visualRisk = 0.6;
      const behaviorRisk = 0.4;
      
      const expectedScore = (0.8 * 0.4) + (0.6 * 0.4) + (0.4 * 0.2);
      const actualScore = utils.calculateRiskScore(urlRisk, visualRisk, behaviorRisk);
      
      expect(actualScore).toBeCloseTo(expectedScore);
    });
    
    test('should handle zero risk values', () => {
      expect(utils.calculateRiskScore(0, 0, 0)).toBe(0);
    });
    
    test('should handle maximum risk values', () => {
      expect(utils.calculateRiskScore(1, 1, 1)).toBe(1);
    });
  });
  
  describe('isPhishingUrl', () => {
    test('should identify suspicious URLs', () => {
      expect(utils.isPhishingUrl('https://paypal-secure.com')).toBe(true);
      expect(utils.isPhishingUrl('https://bankofamerica.secure-site.com')).toBe(true);
      expect(utils.isPhishingUrl('https://secure-login.com')).toBe(true);
    });
    
    test('should pass legitimate URLs', () => {
      expect(utils.isPhishingUrl('https://www.paypal.com')).toBe(false);
      expect(utils.isPhishingUrl('https://www.bankofamerica.com')).toBe(false);
      expect(utils.isPhishingUrl('https://www.google.com')).toBe(false);
    });
  });
  
  describe('sanitizeInput', () => {
    test('should remove script tags', () => {
      const input = 'Hello <script>alert("XSS")</script> World';
      expect(utils.sanitizeInput(input)).toBe('Hello  World');
    });
    
    test('should remove event handlers', () => {
      const input = '<div onclick="alert(\'clicked\')">Click me</div>';
      expect(utils.sanitizeInput(input)).toBe('<div >Click me</div>');
    });
    
    test('should remove javascript: protocol', () => {
      const input = '<a href="javascript:alert(\'XSS\')">Click me</a>';
      expect(utils.sanitizeInput(input)).toBe('<a href="alert(\'XSS\')">Click me</a>');
    });
    
    test('should handle non-string inputs', () => {
      expect(utils.sanitizeInput(null)).toBe('');
      expect(utils.sanitizeInput(undefined)).toBe('');
      expect(utils.sanitizeInput(123)).toBe('');
    });
  });
}); 
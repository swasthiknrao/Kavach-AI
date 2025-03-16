// Kavach AI Security - Demo Data Generator

// Generates realistic security analysis data for demonstration or when API is unavailable
function generateDemoData(url, domain) {
  // Generate realistic risk scores
  const urlRisk = Math.random() * 0.8;
  const visualRisk = Math.random() * 0.7;
  const behaviorRisk = Math.random() * 0.6;
  const sslRisk = Math.random() * 0.4;
  
  // Calculate overall risk (weighted average)
  const overallRisk = (urlRisk * 0.3 + visualRisk * 0.25 + behaviorRisk * 0.3 + sslRisk * 0.15);
  
  // Generate findings based on risk scores
  const findings = [];
  
  if (urlRisk > 0.6) {
    findings.push({
      type: "Suspicious URL Pattern",
      description: "This URL contains patterns commonly found in phishing sites",
      severity: urlRisk
    });
  }
  
  if (visualRisk > 0.5) {
    findings.push({
      type: "Brand Impersonation",
      description: "Visual elements on this page appear to mimic a legitimate brand",
      severity: visualRisk
    });
  }
  
  if (behaviorRisk > 0.5) {
    findings.push({
      type: "Suspicious Scripts",
      description: "This page contains scripts that exhibit potentially malicious behavior",
      severity: behaviorRisk
    });
  }
  
  if (sslRisk > 0.3) {
    findings.push({
      type: "Insecure Connection",
      description: "Connection to this site is not properly secured with SSL/TLS",
      severity: sslRisk
    });
  }
  
  // Create realistic recommendations
  const recommendations = [];
  
  if (overallRisk > 0.6) {
    recommendations.push({
      type: "action",
      priority: "high",
      message: "High security risk detected. We recommend not proceeding with this website."
    });
    
    recommendations.push({
      type: "warning",
      priority: "high",
      message: "This site has multiple suspicious characteristics of a phishing website."
    });
  } else if (overallRisk > 0.3) {
    recommendations.push({
      type: "warning",
      priority: "medium",
      message: "Some security concerns found. Proceed with caution on this website."
    });
    
    if (urlRisk > 0.4) {
      recommendations.push({
        type: "info",
        priority: "medium",
        message: "URL contains unusual patterns. Verify you're on the correct site."
      });
    }
  } else {
    recommendations.push({
      type: "info",
      priority: "low",
      message: "This website appears safe based on our analysis."
    });
  }
  
  // Add risk details for each component
  const risk_details = {
    url_details: urlRisk > 0.5 ? 
      "Potentially suspicious URL structure detected" : 
      "URL appears legitimate",
    
    visual_details: visualRisk > 0.5 ? 
      "Visual elements may imitate a legitimate brand" : 
      "No visual impersonation detected",
    
    behavior_details: behaviorRisk > 0.5 ? 
      "Some page behaviors raise security concerns" : 
      "Page behavior appears normal",
    
    ssl_details: sslRisk > 0.5 ? 
      "Connection security issues detected" : 
      "Connection is properly secured"
  };
  
  // Create the full response object
  return {
    url: url || "https://example.com",
    domain: domain || "example.com",
    timestamp: new Date().toISOString(),
    risk_score: overallRisk,
    confidence: 0.85,
    risk_level: overallRisk > 0.6 ? "High" : overallRisk > 0.3 ? "Medium" : "Low",
    findings: findings,
    recommendations: recommendations,
    component_scores: {
      url_risk: urlRisk,
      visual_risk: visualRisk,
      behavior_risk: behaviorRisk,
      ssl_risk: sslRisk
    },
    risk_details: risk_details,
    analysis_type: "comprehensive"
  };
}

// Generate specific risk scores based on domain
function generateRiskByDomain(domain) {
  if (!domain) return null;
  
  // High risk domains (for demonstration)
  const highRiskDomains = [
    'phishing', 'suspicious', 'login-verify', 'account-confirm',
    'secure-login', 'banking-secure', 'verify-account', 'signin'
  ];
  
  // Known trusted domains (for demonstration)
  const trustedDomains = [
    'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
    'facebook.com', 'github.com', 'linkedin.com', 'twitter.com'
  ];
  
  // Check if domain contains high risk terms
  let urlRisk = 0.2; // Base risk
  for (const term of highRiskDomains) {
    if (domain.includes(term)) {
      urlRisk += 0.3; // Increase risk for suspicious terms
      break;
    }
  }
  
  // Reduce risk for known trusted domains
  for (const trusted of trustedDomains) {
    if (domain.includes(trusted) || domain === trusted) {
      urlRisk = Math.max(0.05, urlRisk - 0.3); // Reduce risk but keep some minimal value
      break;
    }
  }
  
  return urlRisk;
}

// Make sure functions are accessible via window object
window.generateDemoData = generateDemoData;
window.generateRiskByDomain = generateRiskByDomain;

// Export functions
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    generateDemoData,
    generateRiskByDomain
  };
} 
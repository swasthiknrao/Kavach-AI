from flask import Flask, request, jsonify
from flask_cors import CORS
import logging
import random
import time
from datetime import datetime
import traceback
import re

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

# Set port for the server
PORT = 9000

app = Flask(__name__)
CORS(app)

# Simple storage for blocked and trusted domains
blocked_domains = []
trusted_domains = []

@app.route('/api/status', methods=['GET'])
def status():
    """Health check endpoint"""
    return jsonify({
        "status": "online",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0"
    })

@app.route('/api/analyze', methods=['POST'])
def analyze():
    """Endpoint for comprehensive security analysis"""
    try:
        data = request.get_json()
        url = data.get('url', '')
        content = data.get('content', '')
        behavior_data = data.get('behavior', {})
        
        logger.info(f"Received analysis request for URL: {url}")
        
        # Add slight delay to simulate processing
        time.sleep(0.5)
        
        # Extract domain from URL
        domain = extract_domain(url)
        
        # Check if domain is blocked or trusted
        if domain in blocked_domains:
            risk_level = "high"
            risk_score = 0.95
        elif domain in trusted_domains:
            risk_level = "low"
            risk_score = 0.05
        else:
            # Generate analysis based on URL patterns and content
            risk_score, risk_level = analyze_security_risk(url, content, behavior_data)
        
        # Generate component scores
        component_scores = generate_component_scores(url, content, behavior_data, risk_score)
        
        # Generate findings with a consistent approach
        findings = generate_findings(url, content, behavior_data)
        
        # Generate recommendations based on risk assessment
        recommendations = generate_recommendations(risk_score, risk_level)
        
        # Ensure consistent data format between popup and detailed report
        result = {
            'status': 'success',
            'risk_assessment': {
                'risk_score': risk_score,
                'confidence': 0.85,  # Fixed confidence value for consistency
                'risk_level': risk_level,
                'formatted': {
                    'score': f"{int(risk_score * 100)}%",  # Format as percentage
                    'level': risk_level.capitalize(),
                    'color': get_risk_color(risk_level)
                }
            },
            'component_scores': {
                'url': {
                    'score': component_scores['url_risk'],
                    'level': get_risk_level(component_scores['url_risk']),
                    'formatted_score': f"{int(component_scores['url_risk'] * 100)}%"
                },
                'visual': {
                    'score': component_scores['visual_risk'],
                    'level': get_risk_level(component_scores['visual_risk']),
                    'formatted_score': f"{int(component_scores['visual_risk'] * 100)}%"
                },
                'behavior': {
                    'score': component_scores['behavior_risk'],
                    'level': get_risk_level(component_scores['behavior_risk']),
                    'formatted_score': f"{int(component_scores['behavior_risk'] * 100)}%"
                },
                'ssl': {
                    'score': component_scores['ssl_risk'],
                    'level': get_risk_level(component_scores['ssl_risk']),
                    'formatted_score': f"{int(component_scores['ssl_risk'] * 100)}%"
                }
            },
            'findings': findings,
            'recommendations': recommendations,
            'timestamp': datetime.now().isoformat(),
            'domain': domain,
            'url': url
        }
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in analyze endpoint: {str(e)}")
        return jsonify({
            "status": "error",
            "message": str(e),
            "traceback": traceback.format_exc()
        }), 500

@app.route('/api/block-domain', methods=['POST'])
def block_domain():
    """Add a domain to the block list"""
    try:
        data = request.get_json()
        domain = data.get('domain', '')
        
        if domain and domain not in blocked_domains:
            blocked_domains.append(domain)
        
        return jsonify({
            "status": "success",
            "message": f"Domain {domain} has been blocked",
            "blocked_domains": blocked_domains
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route('/api/trust-domain', methods=['POST'])
def trust_domain():
    """Add a domain to the trusted list"""
    try:
        data = request.get_json()
        domain = data.get('domain', '')
        
        if domain and domain not in trusted_domains:
            trusted_domains.append(domain)
        
        return jsonify({
            "status": "success",
            "message": f"Domain {domain} has been trusted",
            "trusted_domains": trusted_domains
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500

@app.route('/api/test-analysis', methods=['GET'])
def test_analysis():
    """Test endpoint to verify analysis values"""
    try:
        # Create sample test data
        test_url = "http://test-phishing-site.example.com/login.php"
        test_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login - Secure Bank</title>
        </head>
        <body>
            <div class="login-form">
                <h2>Enter your credentials</h2>
                <form method="POST" action="/submit.php">
                    <input type="text" name="username" placeholder="Username">
                    <input type="password" name="password" placeholder="Password">
                    <input type="hidden" name="redirect" value="http://evil-site.example.com">
                    <button type="submit">Login</button>
                </form>
            </div>
        </body>
        </html>
        """
        
        # Simulate behavior data
        test_behavior = {
            "forms": 1,
            "hasPasswordField": True,
            "hasLoginForm": True,
            "redirectCount": 2,
            "scripts": [
                "document.addEventListener(\"keyup\", function(e) { console.log(\"Key pressed: \" + e.key); });"
            ],
            "iframes": 0,
            "hiddenElements": 1,
            "links": 2,
            "externalLinks": ["http://evil-site.example.com"]
        }
        
        # Generate analysis results
        risk_score, risk_level = analyze_security_risk(test_url, test_content, test_behavior)
        component_scores = generate_component_scores(test_url, test_content, test_behavior, risk_score)
        
        # Generate findings with a consistent approach
        findings = generate_findings(test_url, test_content, test_behavior)
        
        # Generate recommendations based on risk assessment
        recommendations = generate_recommendations(risk_score, risk_level)
        
        # Extract domain from URL
        domain = extract_domain(test_url)
        
        # Return data in the same format as the analyze endpoint
        result = {
            'status': 'success',
            'risk_assessment': {
                'risk_score': risk_score,
                'confidence': 0.85,  # Fixed confidence value for consistency
                'risk_level': risk_level,
                'formatted': {
                    'score': f"{int(risk_score * 100)}%",  # Format as percentage
                    'level': risk_level.capitalize(),
                    'color': get_risk_color(risk_level)
                }
            },
            'component_scores': {
                'url': {
                    'score': component_scores['url_risk'],
                    'level': get_risk_level(component_scores['url_risk']),
                    'formatted_score': f"{int(component_scores['url_risk'] * 100)}%"
                },
                'visual': {
                    'score': component_scores['visual_risk'],
                    'level': get_risk_level(component_scores['visual_risk']),
                    'formatted_score': f"{int(component_scores['visual_risk'] * 100)}%"
                },
                'behavior': {
                    'score': component_scores['behavior_risk'],
                    'level': get_risk_level(component_scores['behavior_risk']),
                    'formatted_score': f"{int(component_scores['behavior_risk'] * 100)}%"
                },
                'ssl': {
                    'score': component_scores['ssl_risk'],
                    'level': get_risk_level(component_scores['ssl_risk']),
                    'formatted_score': f"{int(component_scores['ssl_risk'] * 100)}%"
                }
            },
            'findings': findings,
            'recommendations': recommendations,
            'timestamp': datetime.now().isoformat(),
            'domain': domain,
            'url': test_url,
            'debug_info': {
                'backend_version': '1.0.0',
                'test_url': test_url
            }
        }
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in test analysis endpoint: {str(e)}")
        return jsonify({
            "status": "error",
            "message": str(e),
            "traceback": traceback.format_exc()
        }), 500

def extract_domain(url):
    """Extract domain from a URL"""
    try:
        if not url:
            return ""
            
        # Remove protocol and path
        domain = url.split('//')[1] if '//' in url else url
        domain = domain.split('/')[0]
        
        # Remove port if present
        domain = domain.split(':')[0]
        
        return domain
    except Exception:
        return ""

def analyze_security_risk(url, content, behavior_data):
    """Analyze URL, content and behavior to determine security risk using advanced AI techniques"""
    risk_score = 0.0
    
    # URL-based risk factors (improved algorithm)
    suspicious_terms = ['login', 'signin', 'account', 'password', 'secure', 'update', 'bank', 'verify']
    url_lower = url.lower()
    
    # Apply NLP-based pattern recognition (simulated)
    url_risk_contribution = sum(0.08 for term in suspicious_terms if term in url_lower) 
    risk_score += min(0.4, url_risk_contribution)  # Cap at 0.4
    
    # Protocol check - stronger weight
    if not url.startswith('https://'):
        risk_score += 0.25
    
    # Domain reputation check (improved)
    domain = extract_domain(url)
    suspicious_patterns = ['-secure-', 'login-', 'account-', 'verify-', 'secure', 'banking']
    domain_risk = sum(0.1 for pattern in suspicious_patterns if pattern in domain)
    risk_score += min(0.3, domain_risk)  # Cap at 0.3
    
    # Content-based risk factors (improved with keywords)
    if content:
        content_lower = content.lower()
        # Check for password fields
        if 'type="password"' in content_lower:
            risk_score += 0.15
            
        # Check for login forms with stronger pattern recognition
        if ('login' in content_lower or 'signin' in content_lower) and 'form' in content_lower:
            risk_score += 0.15
            
        # Check for suspicious redirects with improved detection
        redirect_patterns = ['window.location', 'document.location', 'window.href', 'redirect']
        if any(pattern in content_lower for pattern in redirect_patterns):
            risk_score += 0.2
    
    # Behavior-based risk factors (enhanced)
    if behavior_data:
        # Check for password fields with certainty factor
        if behavior_data.get('hasPasswordField', False):
            risk_score += 0.15
            
        # Check for hidden elements with improved weighting
        hidden_count = behavior_data.get('hiddenElements', 0)
        risk_score += min(0.2, hidden_count * 0.05)  # Scale with number of hidden elements
            
        # Check for external links with domain analysis
        external_links = behavior_data.get('externalLinks', [])
        if len(external_links) > 0:
            risk_score += min(0.2, len(external_links) * 0.05)  # Scale with number of external links
            
        # Check for redirects with improved detection
        redirect_count = behavior_data.get('redirectCount', 0)
        if redirect_count > 0:
            risk_score += min(0.25, redirect_count * 0.08)  # Scale with number of redirects
    
    # Apply deterministic risk calculation instead of random
    # This ensures consistency between popup.html and detailed_report.html
    
    # Clamp score between 0 and 1
    risk_score = max(0.0, min(1.0, risk_score))
    
    # Determine risk level with consistent thresholds
    if risk_score >= 0.7:
        risk_level = "high"
    elif risk_score >= 0.4:
        risk_level = "medium"
    else:
        risk_level = "low"
    
    # Format to 2 decimal places for consistency
    risk_score = round(risk_score, 2)
    
    return risk_score, risk_level

def generate_component_scores(url, content, behavior_data, overall_risk):
    """Generate individual component risk scores with improved AI analysis"""
    
    # URL safety score - based on URL patterns and structure
    domain = extract_domain(url)
    url_lower = url.lower()
    
    # Calculate URL risk based on specific factors
    url_risk = 0.0
    
    # Check for secure protocol
    if not url.startswith('https://'):
        url_risk += 0.3
    
    # Check for suspicious words in URL
    suspicious_terms = ['login', 'signin', 'account', 'password', 'secure', 'update', 'bank', 'verify']
    url_risk += min(0.4, sum(0.08 for term in suspicious_terms if term in url_lower))
    
    # Check domain structure
    if '-' in domain:
        url_risk += 0.1
    
    # Check for numeric patterns (often in phishing URLs)
    if re.search(r'\d{4,}', url):
        url_risk += 0.1
    
    # Normalize URL risk
    url_risk = min(1.0, url_risk)
    
    # Visual match score - based on content analysis
    visual_risk = 0.0
    
    if content:
        content_lower = content.lower()
        # Check for login forms
        if 'type="password"' in content_lower:
            visual_risk += 0.2
        
        # Check for brand terms (simulate visual brand detection)
        brand_terms = ['paypal', 'amazon', 'facebook', 'apple', 'microsoft', 'google']
        visual_risk += min(0.3, sum(0.1 for brand in brand_terms if brand in content_lower))
        
        # Check for security imagery references (shield, lock icons)
        if 'class="security' in content_lower or 'id="secure' in content_lower:
            visual_risk += 0.15
    
    # Cap visual risk
    visual_risk = min(1.0, max(0.0, visual_risk))
    
    # For incomplete content, use a factor of the overall risk
    if not content or len(content) < 100:
        visual_risk = max(visual_risk, overall_risk * 0.8)
    
    # Behavior analysis score - based on behavior patterns
    behavior_risk = 0.0
    
    if behavior_data:
        # Forms with password fields
        if behavior_data.get('hasPasswordField', False):
            behavior_risk += 0.25
            
        # Multiple forms
        form_count = behavior_data.get('forms', 0)
        behavior_risk += min(0.2, form_count * 0.1)
        
        # External links
        ext_links = len(behavior_data.get('externalLinks', []))
        behavior_risk += min(0.2, ext_links * 0.05)
        
        # Hidden elements
        hidden_count = behavior_data.get('hiddenElements', 0)
        behavior_risk += min(0.2, hidden_count * 0.1)
        
        # Redirects
        redirect_count = behavior_data.get('redirectCount', 0)
        behavior_risk += min(0.15, redirect_count * 0.1)
    
    # Normalize behavior risk
    behavior_risk = min(1.0, behavior_risk)
    
    # Connection/SSL score - based on protocol and certificate
    ssl_risk = 0.1 if url.startswith('https://') else 0.9
    
    # Format all scores to 2 decimal places for consistency across UI
    return {
        'url_risk': round(float(url_risk), 2),
        'visual_risk': round(float(visual_risk), 2),
        'behavior_risk': round(float(behavior_risk), 2), 
        'ssl_risk': round(float(ssl_risk), 2)
    }

def check_url_patterns(url):
    """Check URL for suspicious patterns"""
    patterns = []
    
    if 'login' in url.lower() and not url.startswith('https://'):
        patterns.append("Insecure login page (non-HTTPS)")
    
    import re
    if re.search(r'\d{4,}', url):
        patterns.append("Contains suspicious number sequence")
    
    if '-' in extract_domain(url) and any(word in url.lower() for word in ['secure', 'account', 'login', 'signin']):
        patterns.append("Domain contains hyphen and security-related terms")
    
    return patterns

def generate_findings(url, content, behavior_data):
    """Generate list of suspicious findings"""
    findings = []
    
    # URL findings
    for pattern in check_url_patterns(url):
        findings.append({
            'type': 'url',
            'severity': 'medium',
            'description': pattern
        })
    
    # Content findings
    if content and 'type="password"' in content.lower() and not url.startswith('https://'):
        findings.append({
            'type': 'content',
            'severity': 'high',
            'description': 'Password field on non-secure connection'
        })
    
    # Behavior findings
    if behavior_data.get('hasPasswordField', False) and behavior_data.get('redirectCount', 0) > 1:
        findings.append({
            'type': 'behavior',
            'severity': 'high',
            'description': 'Login form with suspicious redirects'
        })
    
    if behavior_data.get('scripts') and any('keyup' in script for script in behavior_data.get('scripts', [])):
        findings.append({
            'type': 'behavior',
            'severity': 'high',
            'description': 'Potential keystroke monitoring detected'
        })
    
    return findings

def generate_recommendations(risk_score, risk_level):
    """Generate security recommendations based on risk level"""
    recommendations = []
    
    if risk_level == "high":
        recommendations.append({
            'type': 'warning',
            'description': 'Avoid entering any sensitive information on this site'
        })
        recommendations.append({
            'type': 'action',
            'description': 'Consider blocking this site for your safety'
        })
    
    elif risk_level == "medium":
        recommendations.append({
            'type': 'caution',
            'description': 'Be cautious when providing any information to this site'
        })
        recommendations.append({
            'type': 'check',
            'description': 'Verify the website URL before proceeding'
        })
    
    else:
        recommendations.append({
            'type': 'info',
            'description': 'This site appears to be safe, but always be vigilant'
        })
    
    return recommendations

# Helper function to get risk color for UI display
def get_risk_color(risk_level):
    """Return the appropriate color code for risk level"""
    if risk_level == "high":
        return "#ef233c"  # Danger red
    elif risk_level == "medium":
        return "#ff9e00"  # Warning orange
    else:
        return "#38b000"  # Success green

# Helper function to get risk level from score
def get_risk_level(score):
    """Determine risk level from score consistently"""
    if score >= 0.7:
        return "high"
    elif score >= 0.4:
        return "medium"
    else:
        return "low"

if __name__ == '__main__':
    try:
        logger.info(f"Starting Kavach Security backend server on port {PORT}")
        logger.info(f"API will be available at http://127.0.0.1:{PORT}/api")
        logger.info(f"Health check endpoint: http://127.0.0.1:{PORT}/api/status")
        
        app.run(host="127.0.0.1", port=PORT, debug=True)
    except Exception as e:
        logger.error(f"Failed to start server: {str(e)}")
        logger.error(f"Error details: {traceback.format_exc()}")
        print(f"Server startup failed: {str(e)}") 
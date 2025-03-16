from flask import Flask, request, jsonify
from flask_cors import CORS
import logging
import random
import time
from datetime import datetime
import numpy as np
import os
import re
from PIL import Image
import io
import base64
import hashlib
import traceback

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
        
        # Generate analysis details
        analysis_details = generate_analysis_details(url, content, behavior_data)
        
        result = {
            'status': 'success',
            'risk_assessment': {
                'risk_score': risk_score,
                'confidence': 0.85,
                'risk_level': risk_level
            },
            'component_scores': component_scores,
            'analysis_details': analysis_details,
            'findings': generate_findings(url, content, behavior_data),
            'recommendations': generate_recommendations(risk_score, risk_level)
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
        analysis_details = generate_analysis_details(test_url, test_content, test_behavior)
        
        result = {
            'status': 'success',
            'risk_assessment': {
                'risk_score': risk_score,
                'confidence': 0.85,
                'risk_level': risk_level
            },
            'component_scores': component_scores,
            'analysis_details': analysis_details,
            'findings': generate_findings(test_url, test_content, test_behavior),
            'recommendations': generate_recommendations(risk_score, risk_level),
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
    """Analyze URL, content and behavior to determine security risk"""
    risk_score = 0.0
    
    # URL-based risk factors
    if any(word in url.lower() for word in ['login', 'signin', 'account', 'password', 'secure', 'update']):
        risk_score += 0.1
    
    # Protocol check
    if not url.startswith('https://'):
        risk_score += 0.2
    
    # Domain reputation check (simplified)
    domain = extract_domain(url)
    if any(suspicious in domain for suspicious in ['-secure-', 'login-', 'account-', 'verify-']):
        risk_score += 0.3
    
    # Content-based risk factors
    if content:
        # Check for password fields
        if 'type="password"' in content.lower():
            risk_score += 0.1
            
        # Check for login forms
        if 'login' in content.lower() or 'signin' in content.lower():
            risk_score += 0.1
            
        # Check for suspicious redirects
        if 'window.location' in content.lower():
            risk_score += 0.15
    
    # Behavior-based risk factors
    if behavior_data:
        # Check for password fields
        if behavior_data.get('hasPasswordField', False):
            risk_score += 0.1
            
        # Check for hidden elements
        if behavior_data.get('hiddenElements', 0) > 0:
            risk_score += 0.1
            
        # Check for external links
        if len(behavior_data.get('externalLinks', [])) > 0:
            risk_score += 0.1
            
        # Check for redirects
        if behavior_data.get('redirectCount', 0) > 1:
            risk_score += 0.2
    
    # Add randomness to simulate AI variability
    risk_score += random.uniform(-0.05, 0.05)
    
    # Clamp score between 0 and 1
    risk_score = max(0.0, min(1.0, risk_score))
    
    # Determine risk level
    if risk_score >= 0.7:
        risk_level = "high"
    elif risk_score >= 0.4:
        risk_level = "medium"
    else:
        risk_level = "low"
    
    return risk_score, risk_level

def generate_component_scores(url, content, behavior_data, overall_risk):
    """Generate individual component risk scores"""
    
    # URL safety score
    url_risk = min(1.0, overall_risk + random.uniform(-0.1, 0.1))
    
    # Visual match score (simulated)
    visual_risk = min(1.0, overall_risk + random.uniform(-0.15, 0.15))
    
    # Behavior analysis score
    behavior_risk = min(1.0, overall_risk + random.uniform(-0.1, 0.2))
    
    # Connection/SSL score
    ssl_risk = 0.1 if url.startswith('https://') else 0.8
    
    return {
        'url_risk': float(url_risk),
        'visual_risk': float(visual_risk),
        'behavior_risk': float(behavior_risk), 
        'ssl_risk': float(ssl_risk)
    }

def generate_analysis_details(url, content, behavior_data):
    """Generate detailed analysis for each component"""
    return {
        'url_analysis': {
            'suspicious_patterns': check_url_patterns(url),
            'domain_reputation': "Unknown",
            'similar_domains': []
        },
        'visual_analysis': {
            'brand_impersonation': {
                'detected': False,
                'brand': None,
                'confidence': 0.0
            },
            'suspicious_elements': []
        },
        'behavior_analysis': {
            'form_data_collection': behavior_data.get('hasPasswordField', False),
            'keyboard_monitoring': any('keyup' in script for script in behavior_data.get('scripts', [])),
            'suspicious_redirects': behavior_data.get('redirectCount', 0) > 1
        },
        'connection_analysis': {
            'protocol': url.split('://')[0] if '://' in url else 'unknown',
            'ssl_valid': url.startswith('https://'),
            'certificate_issues': []
        }
    }

def check_url_patterns(url):
    """Check URL for suspicious patterns"""
    patterns = []
    
    if 'login' in url.lower() and not url.startswith('https://'):
        patterns.append("Insecure login page (non-HTTPS)")
    
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
    if 'type="password"' in content.lower() and not url.startswith('https://'):
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
    
    if any('keyup' in script for script in behavior_data.get('scripts', [])):
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
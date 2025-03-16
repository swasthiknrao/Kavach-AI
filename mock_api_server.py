from flask import Flask, request, jsonify, abort
from flask_cors import CORS
import time
import random
import json
import re
from datetime import datetime, timedelta
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('kavach-mock-api')

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Cache to store analysis results
analysis_cache = {}

# Blocklist for known phishing domains
known_phishing_domains = [
    'phishing-example.com',
    'secure-bank-login.com',
    'paypal-account-verify.net',
    'netflix-account-update.com',
    'google-docs-share.net',
    'facebook-login-secure.com',
    'microsoft365-auth.net',
    'amazon-order-update.com',
    'apple-id-confirm.net',
    'instagram-verify.com'
]

@app.route('/api/status', methods=['GET'])
def status():
    """Endpoint to check if the API is available"""
    return jsonify({
        'status': 'online',
        'version': '1.0.0',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/analyze', methods=['POST'])
def analyze():
    """Main endpoint for analyzing URLs and page data"""
    if not request.json:
        abort(400, description="Request must be JSON")
    
    try:
        # Extract data from request
        data = request.json
        url = data.get('url', '')
        domain = data.get('domain', '')
        
        # Log the request
        logger.info(f"Received analysis request for: {url}")
        
        # Check if we already have an analysis (to avoid processing again)
        if url in analysis_cache:
            cached_result = analysis_cache[url]
            # Check if the cache is still valid (less than 1 hour old)
            cache_time = datetime.fromisoformat(cached_result['timestamp'])
            if datetime.now() - cache_time < timedelta(hours=1):
                logger.info(f"Returning cached result for: {url}")
                return jsonify(cached_result)
        
    # Simulate processing time
        time.sleep(0.5)
        
        # Generate analysis result
        result = generate_analysis_result(data)
        
        # Cache the result
        analysis_cache[url] = result
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Error processing request: {str(e)}")
        return jsonify({
            'error': str(e),
            'message': 'An error occurred while processing the request'
        }), 500

@app.route('/api/quick-scan', methods=['POST'])
def quick_scan():
    """Endpoint for quick URL analysis without full page data"""
    if not request.json:
        abort(400, description="Request must be JSON")
    
    try:
        data = request.json
        url = data.get('url', '')
        domain = data.get('domain', '')
        
        logger.info(f"Received quick scan request for: {url}")
        
        # Simulate processing time
        time.sleep(0.2)
        
        # Generate a simplified analysis result
        result = generate_quick_analysis(data)
        
        return jsonify(result)
    
    except Exception as e:
        logger.error(f"Error in quick scan: {str(e)}")
        return jsonify({
            'error': str(e),
            'message': 'An error occurred during quick scan'
        }), 500

@app.route('/api/detailed-analysis', methods=['POST'])
def detailed_analysis():
    """Endpoint for detailed analysis with comprehensive data"""
    if not request.json:
        abort(400, description="Request must be JSON")
    
    try:
        data = request.json
        url = data.get('url', '')
        
        logger.info(f"Received detailed analysis request for: {url}")
        
        # Simulate longer processing time for detailed analysis
        time.sleep(0.8)
        
        # Get basic analysis result first
        basic_result = generate_analysis_result(data)
        
        # Add additional detailed information
        detailed_result = enhance_with_details(basic_result, data)
        
        return jsonify(detailed_result)
    
    except Exception as e:
        logger.error(f"Error in detailed analysis: {str(e)}")
        return jsonify({
            'error': str(e),
            'message': 'An error occurred during detailed analysis'
        }), 500

def generate_quick_analysis(data):
    """Generate a quick analysis result based on URL and basic info"""
    url = data.get('url', '')
    domain = data.get('domain', '')
    timestamp = data.get('timestamp', datetime.now().isoformat())
    
    # Determine risk level based on domain
    risk_score = 0.0
    
    # Check for common phishing indicators in URL
    if is_suspicious_url(url, domain):
        risk_score += random.uniform(3.0, 6.0)
    
    # Check if domain is in known phishing list
    if any(phish_domain in domain for phish_domain in known_phishing_domains):
        risk_score += random.uniform(5.0, 8.0)
    
    # Add randomness for demo purposes
    risk_score += random.uniform(-0.5, 0.5)
    risk_score = max(0, min(10, risk_score))  # Clamp between 0-10
    
    # Determine findings based on risk score
    findings = []
    if risk_score > 3:
        findings.append({
            'type': 'Suspicious URL Pattern',
            'severity': 'medium' if risk_score < 7 else 'high',
            'description': 'The URL contains patterns commonly associated with phishing attempts.',
            'impact': 'May lead to confusion about the website identity.'
        })
    
    if 'login' in url.lower() or 'signin' in url.lower():
        findings.append({
            'type': 'Login Page',
            'severity': 'low',
            'description': 'This appears to be a login page. Always verify the domain before entering credentials.',
            'impact': 'Potential for credential theft if this is a spoofed login page.'
        })
    
    # Generate result
    result = {
        'url': url,
        'domain': domain,
        'timestamp': timestamp,
        'risk_score': round(risk_score, 1),
        'confidence': calculate_confidence(data),
        'findings': findings,
        'analysis_type': 'quick'
    }
    
    return result

def generate_analysis_result(data):
    """Generate a complete analysis result based on the provided data"""
    url = data.get('url', '')
    domain = data.get('domain', '')
    title = data.get('title', '')
    behavior_data = data.get('behavior_data', {})
    timestamp = data.get('timestamp', datetime.now().isoformat())
    
    # Initialize risk score
    risk_score = 0.0
    
    # URL-based analysis
    if is_suspicious_url(url, domain):
        risk_score += random.uniform(2.0, 4.0)
    
    # Check if domain is in known phishing list
    if any(phish_domain in domain for phish_domain in known_phishing_domains):
        risk_score += random.uniform(5.0, 7.0)
    
    # Check for login forms or password fields
    has_login = behavior_data.get('has_password_field', False)
    if has_login:
        # Login forms themselves aren't suspicious, but they're higher value targets
        risk_score += random.uniform(0.5, 1.0)
    
    # Check for suspicious behavior patterns
    if behavior_data.get('potential_keyloggers', 0) > 0:
        risk_score += random.uniform(2.0, 5.0)
    
    # Add slight randomness
    risk_score += random.uniform(-0.5, 0.5)
    
    # Clamp risk score between 0 and 10
    risk_score = max(0, min(10, risk_score))
    
    # Generate findings
    findings = generate_findings(data, risk_score)
    
    # Calculate confidence based on available data
    confidence = calculate_confidence(data)
    
    # Construct the final result
    result = {
        'url': url,
        'domain': domain,
        'timestamp': timestamp,
        'risk_score': round(risk_score, 1),
        'confidence': confidence,
        'findings': findings,
        'site_info': {
            'title': title,
            'has_login_form': has_login,
            'protocol': url.split('://')[0] if '://' in url else 'unknown',
            'external_links': behavior_data.get('external_links', 0),
            'scripts_count': len(behavior_data.get('scripts', [])),
            'redirects': behavior_data.get('redirects', 0)
        }
    }
    
    return result

def enhance_with_details(basic_result, data):
    """Add detailed analysis information to a basic result"""
    # Start with the basic result
    detailed = basic_result.copy()
    
    # Add security features information
    detailed['security_features'] = {
        'has_ssl': data.get('url', '').startswith('https'),
        'ssl_details': 'Valid certificate' if data.get('url', '').startswith('https') else 'No SSL/TLS encryption',
        'domain_age': f"{random.randint(1, 10)} years" if random.random() > 0.3 else f"{random.randint(1, 11)} months",
        'has_csp': random.random() > 0.5,
        'https_redirect': random.random() > 0.4
    }
    
    # Add behavioral analysis
    if basic_result['risk_score'] > 2:
        detailed['behavioral_analysis'] = {
            'form_collection_score': random.uniform(0, 10),
            'script_behavior_score': random.uniform(0, 10),
            'redirect_score': random.uniform(0, 10),
            'popup_score': random.uniform(0, 10),
            'dom_manipulation_score': random.uniform(0, 10),
            'notes': []
        }
        
        # Add behavioral notes
        if detailed['behavioral_analysis']['form_collection_score'] > 6:
            detailed['behavioral_analysis']['notes'].append(
                'The form submission behavior on this page appears suspicious and may be sending data to unauthorized servers.'
            )
        
        if detailed['behavioral_analysis']['script_behavior_score'] > 6:
            detailed['behavioral_analysis']['notes'].append(
                'Scripts on this page are exhibiting potentially malicious behavior patterns.'
            )
    
    # Add visual analysis if risk score is significant
    if basic_result['risk_score'] > 4:
        popular_brands = ['PayPal', 'Microsoft', 'Google', 'Facebook', 'Amazon', 'Apple', 'Netflix']
        target_brand = random.choice(popular_brands)
        
        detailed['visual_analysis'] = {
            'brand_impersonation': {
                'score': random.uniform(5, 9),
                'target_brand': target_brand,
                'details': f'This page appears to be imitating {target_brand} visual design elements.'
            },
            'suspicious_elements': {
                'count': random.randint(1, 5),
                'details': 'The page contains visual elements designed to appear trustworthy but with incorrect branding.'
            },
            'similarity_score': random.uniform(0.75, 0.95)
        }
    
    # Include raw data if requested
    if data.get('include_raw_data', False):
        # Simplified raw data for the mock version
        detailed['raw_data'] = {
            'url_analysis': {
                'domain_parts': data.get('domain', '').split('.'),
                'path': data.get('url', '').split('/')[-1] if '/' in data.get('url', '') else '',
                'query_params': len(data.get('url', '').split('?')) > 1
            }
        }
    
    return detailed

def is_suspicious_url(url, domain):
    """Check if URL has suspicious patterns"""
    suspicious_patterns = [
        r'paypal.*\.(?!paypal\.com)',  # PayPal not on paypal.com
        r'microsoft.*\.(?!microsoft\.com)',  # Microsoft not on microsoft.com
        r'apple.*\.(?!apple\.com)',  # Apple not on apple.com
        r'amazon.*\.(?!amazon\.com)',  # Amazon not on amazon.com
        r'facebook.*\.(?!facebook\.com)',  # Facebook not on facebook.com
        r'google.*\.(?!google\.com)',  # Google not on google.com
        r'secure.*login',
        r'account.*verify',
        r'signin.*secure',
        r'login.*account',
        r'update.*account',
        r'confirm.*identity',
        r'-?secure-?',
        r'\.com-[a-zA-Z0-9]+'  # Domain spoofing like "paypal.com-secure.phishingdomain.com"
    ]
    
    # Check for IP address URLs
    if re.match(r'^https?://\d+\.\d+\.\d+\.\d+', url):
        return True
    
    # Check for unusual number of subdomains
    if domain.count('.') > 3:
        return True
    
    # Check for very long domain
    if len(domain) > 40:
        return True
    
    # Check for suspicious patterns
    for pattern in suspicious_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            return True
    
    # Not suspicious
    return False

def calculate_confidence(data):
    """Calculate confidence in the analysis based on available data"""
    # Start with a base confidence
    confidence = 60
    
    # More data = more confidence
    if data.get('html'):
        confidence += 15
    
    if data.get('behavior_data', {}).get('forms_count') is not None:
        confidence += 5
    
    if data.get('behavior_data', {}).get('scripts'):
        confidence += 5
    
    if data.get('behavior_data', {}).get('event_listeners'):
        confidence += 5
    
    # For mock purposes, add a bit of randomness
    confidence += random.randint(-10, 10)
    
    # Clamp to valid range
    return max(30, min(99, confidence))

def generate_findings(data, risk_score):
    """Generate analysis findings based on data and risk score"""
    findings = []
    url = data.get('url', '')
    domain = data.get('domain', '')
    behavior_data = data.get('behavior_data', {})
    
    # If risk score is very low, likely no findings
    if risk_score < 2:
        return []
    
    # Check for suspicious URL patterns
    if is_suspicious_url(url, domain):
            findings.append({
            'type': 'Suspicious URL Pattern',
            'severity': 'medium' if risk_score < 7 else 'high',
            'description': 'The URL contains patterns commonly associated with phishing attempts.',
            'impact': 'Users may be misled about the website identity.'
        })
    
    # Check if domain is in known phishing list
    if any(phish_domain in domain for phish_domain in known_phishing_domains):
        findings.append({
            'type': 'Known Malicious Domain',
            'severity': 'high',
            'description': 'This domain has been identified as a source of phishing attacks.',
            'impact': 'High risk of credential theft or malware infection.'
        })
    
    # Check for login form in combination with other risk factors
    if behavior_data.get('has_password_field', False) and risk_score > 4:
        findings.append({
            'type': 'Suspicious Login Form',
            'severity': 'high',
            'description': 'This page contains a login form with suspicious characteristics.',
            'impact': 'Credentials entered may be stolen.'
        })
    
    # Check for potential keyloggers
    if behavior_data.get('potential_keyloggers', 0) > 0:
            findings.append({
            'type': 'Potential Keylogger',
            'severity': 'high',
            'description': 'Scripts on this page are monitoring keyboard input in a suspicious manner.',
            'impact': 'All typed information may be captured, including passwords.'
        })
    
    # Check if page has many external links (could be a scam page)
    if behavior_data.get('external_links', 0) > 20:
            findings.append({
            'type': 'Excessive External Links',
            'severity': 'low',
            'description': 'This page contains an unusually high number of external links.',
            'impact': 'May be attempting to redirect users to malicious sites.'
        })
    
    # Add an SSL warning for HTTP sites with login forms
    if data.get('url', '').startswith('http:') and not data.get('url', '').startswith('https:') and behavior_data.get('has_password_field', False):
            findings.append({
            'type': 'Insecure Login Form',
            'severity': 'medium',
            'description': 'This page contains a login form but does not use HTTPS encryption.',
            'impact': 'Login credentials may be intercepted by third parties.'
        })
    
    # Add some brand-specific findings based on URL patterns
    popular_brands = {
        'paypal': 'PayPal',
        'microsoft': 'Microsoft',
        'google': 'Google',
        'facebook': 'Facebook',
        'amazon': 'Amazon',
        'apple': 'Apple',
        'netflix': 'Netflix',
        'bank': 'Banking Services'
    }
    
    for keyword, brand in popular_brands.items():
        if keyword in domain.lower() and risk_score > 3:
            findings.append({
                'type': f'Potential {brand} Impersonation',
                'severity': 'high',
                'description': f'This site appears to be impersonating {brand}.',
                'impact': 'Users may be tricked into providing their credentials to attackers.'
            })
            break  # Only add one brand impersonation finding
    
    return findings

if __name__ == '__main__':
    print("Starting Kavach AI Security Mock API Server")
    app.run(host='127.0.0.1', port=9000, debug=True) 

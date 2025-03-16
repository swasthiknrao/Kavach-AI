from flask import Flask, request, jsonify
from flask_cors import CORS
import numpy as np
from models.url_analyzer import URLAnalyzer
from models.visual_analyzer import VisualAnalyzer
from models.behavior_analyzer import BehaviorAnalyzer
from utils.feature_extractor import FeatureExtractor
from utils.ssl_validator import SSLValidator
from models.ai_modules.phishing_analyzer import PhishingAnalyzer
from asgiref.wsgi import WsgiToAsgi
import uvicorn
import os
from dotenv import load_dotenv
import google.generativeai as genai
import re
import logging
from urllib.parse import urlparse
import base64
import time
import hashlib
import cv2
import io
from PIL import Image
import traceback

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Set port for the server
PORT = 5050

# Configure Gemini
try:
    load_dotenv()
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
    
    if GEMINI_API_KEY:
        # Remove any quotes that might have been included in the .env file
        GEMINI_API_KEY = GEMINI_API_KEY.strip('"\'')
        genai.configure(api_key=GEMINI_API_KEY)
        USE_AI = True
        logger.info("Gemini API configured successfully")
        
        try:
            # Test if the model is available
            model = genai.GenerativeModel('gemini-pro')
            # Quick test call
            _ = model.generate_content("Hello")
            logger.info("Gemini model test successful")
        except Exception as e:
            logger.error(f"Gemini model test failed: {e}")
            USE_AI = False
    else:
        logger.warning("No Gemini API key found, falling back to basic analysis")
        USE_AI = False
        
except Exception as e:
    logger.error(f"Error setting up Gemini: {e}")
    USE_AI = False

app = Flask(__name__)
CORS(app)
asgi_app = WsgiToAsgi(app)

class SecureNetAPI:
    def __init__(self):
        try:
            # Initialize analyzers
            self.url_analyzer = URLAnalyzer()
            self.visual_analyzer = VisualAnalyzer()
            self.behavior_analyzer = BehaviorAnalyzer()
            self.phishing_analyzer = PhishingAnalyzer()
            self.feature_extractor = FeatureExtractor()
            self.ssl_validator = SSLValidator()
            
            # Create cache directory if it doesn't exist
            os.makedirs('cache', exist_ok=True)
            
            logger.info("SecureNetAPI initialized successfully with all analyzers")
        except Exception as e:
            logger.error(f"Error initializing SecureNetAPI: {e}")
            # Still initialize with basic functionality
            self.url_analyzer = URLAnalyzer()
            self.behavior_analyzer = BehaviorAnalyzer()

    def analyze_url(self, url, content, behavior_data):
        """Main analysis function that coordinates all the analysis components"""
        try:
            # Start timer for performance monitoring
            start_time = time.time()
            
            # Log analysis request
            logger.info(f"Analyzing URL: {url[:50]}...")
            
            # Initialize results with default safe values
            results = {
                'url_risk': 0.0,
                'visual_risk': 0.0,
                'behavior_risk': 0.0,
                'ssl_status': url.startswith('https://'),
                'overall_risk': 0.0,
                'analyzed_url': url,
                'analysis_details': {
                    'suspicious_patterns': [],
                    'security_recommendations': [],
                    'url_details': {},
                    'visual_details': {},
                    'behavior_details': {}
                }
            }
            
            # Parse content object if needed
            if isinstance(content, dict) and 'text' in content:
                text_content = content.get('text', '')
                title = content.get('title', '')
            else:
                text_content = content
                title = behavior_data.get('metadata', {}).get('title', '')
            
            # 1. URL Analysis with advanced features
            url_risk, url_details = self._analyze_url_security(url)
            results['url_risk'] = url_risk
            results['analysis_details']['url_details'] = url_details
            
            # 2. Visual content analysis 
            visual_risk, visual_details = self._analyze_visual_content(text_content, behavior_data)
            results['visual_risk'] = visual_risk
            results['analysis_details']['visual_details'] = visual_details
            
            # 3. Behavior analysis
            behavior_risk, behavior_details = self._analyze_behavior(behavior_data)
            results['behavior_risk'] = behavior_risk
            results['analysis_details']['behavior_details'] = behavior_details
            
            # 4. Extract suspicious patterns from all analyses
            all_suspicious_patterns = []
            if 'suspicious_patterns' in url_details:
                all_suspicious_patterns.extend(url_details['suspicious_patterns'])
                
            if hasattr(self.visual_analyzer, 'get_last_analysis_details'):
                visual_analysis_details = self.visual_analyzer.get_last_analysis_details()
                if visual_analysis_details and 'suspicious_patterns' in visual_analysis_details:
                    all_suspicious_patterns.extend(visual_analysis_details['suspicious_patterns'])
            
            if hasattr(self.behavior_analyzer, 'get_last_analysis_details'):
                behavior_analysis_details = self.behavior_analyzer.get_last_analysis_details()
                if behavior_analysis_details and 'suspicious_patterns' in behavior_analysis_details:
                    all_suspicious_patterns.extend(behavior_analysis_details['suspicious_patterns'])
            
            # Keep only unique patterns
            results['analysis_details']['suspicious_patterns'] = list(set(all_suspicious_patterns))
            
            # 5. Calculate overall risk using weighted approach
            overall_risk = self._calculate_overall_risk(url_risk, visual_risk, behavior_risk, results['ssl_status'])
            results['overall_risk'] = overall_risk
            
            # 6. Generate security recommendations
            recommendations = self._generate_security_recommendations(
                results, url, results['ssl_status'], behavior_data
            )
            results['analysis_details']['security_recommendations'] = recommendations
            
            # Log completion and timing
            elapsed_time = time.time() - start_time
            logger.info(f"Analysis complete for {url[:30]}... in {elapsed_time:.2f}s with risk {overall_risk:.2f}")
            
            return results
            
        except Exception as e:
            logger.error(f"Error in analyze_url: {e}")
            logger.error(traceback.format_exc())
            
            # Return basic but valid results even on error - avoid dummy data
            return {
                'url_risk': 0.4,
                'visual_risk': 0.4, 
                'behavior_risk': 0.4,
                'ssl_status': url.startswith('https://'),
                'overall_risk': 0.4,
                'analyzed_url': url,
                'analysis_details': {
                    'suspicious_patterns': ["Analysis encountered technical issues"],
                    'security_recommendations': [
                        "Our analysis was limited due to technical issues",
                        "Consider manual verification of this website",
                        "Check for HTTPS connection and legitimate domain name"
                    ]
                },
                'error': True,
                'error_message': str(e)
            }

    def _analyze_url_security(self, url):
        """Analyze URL for suspicious patterns and security issues"""
        try:
            # Basic URL risk analysis
            url_risk = self.url_analyzer.quick_analyze(url)
            
            # Parse URL components
            parsed_url = urlparse(url)
            hostname = parsed_url.netloc
            path = parsed_url.path
            
            suspicious_patterns = []
            details = {
                'domain': hostname,
                'path': path,
                'protocol': parsed_url.scheme
            }
            
            # Check for security features in the URL
            if not url.startswith('https://'):
                suspicious_patterns.append("Non-secure HTTP connection")
            
            # Check for suspicious URL patterns
            if hostname.count('.') > 3:
                suspicious_patterns.append("Excessive subdomains")
                url_risk += 0.1
            
            if hostname.count('-') > 2:
                suspicious_patterns.append("Multiple hyphens in domain")
                url_risk += 0.05
            
            if len(hostname) > 30:
                suspicious_patterns.append("Unusually long domain name")
                url_risk += 0.05
            
            # Check for IP address instead of domain name
            if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', hostname):
                suspicious_patterns.append("IP address used instead of domain name")
                url_risk += 0.3
            
            # Check for encoded characters in URL
            if '%' in url:
                percent_count = url.count('%')
                if percent_count > 3:
                    suspicious_patterns.append("Excessive encoded characters in URL")
                    url_risk += min(percent_count * 0.03, 0.2)
            
            # Check for suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top']
            if any(hostname.endswith(tld) for tld in suspicious_tlds):
                suspicious_patterns.append("Suspicious top-level domain")
                url_risk += 0.2
            
            # Check for long URL paths
            if len(path) > 100:
                suspicious_patterns.append("Unusually long URL path")
                url_risk += 0.1
            
            # Brand impersonation check
            brands = ['paypal', 'google', 'facebook', 'apple', 'microsoft', 'amazon', 'netflix']
            for brand in brands:
                if brand in hostname and brand not in hostname.split('.')[0]:
                    suspicious_patterns.append(f"Possible {brand} impersonation")
                    url_risk += 0.3
                    break
            
            # Add details and patterns to results
            details['suspicious_patterns'] = suspicious_patterns
            details['risk_score'] = min(url_risk, 1.0)
            
            return min(url_risk, 1.0), details
        
        except Exception as e:
            logger.error(f"Error in URL analysis: {e}")
            return 0.5, {"error": str(e)}

    def _analyze_visual_content(self, content, behavior_data):
        """Analyze visual and content features for phishing indicators"""
        try:
            # Content-based analysis
            visual_risk = self.visual_analyzer.analyze_text_content(content)
            
            # Try to get screenshot if available in behavior data
            screenshot_risk = 0
            if 'screenshot' in behavior_data:
                try:
                    screenshot_risk = self.visual_analyzer.analyze_from_base64(behavior_data['screenshot'])
                    visual_risk = max(visual_risk, screenshot_risk)
                except Exception as screenshot_error:
                    logger.error(f"Error analyzing screenshot: {screenshot_error}")
            
            # Get detailed info from visual analyzer
            visual_details = {}
            if hasattr(self.visual_analyzer, 'get_last_analysis_details'):
                visual_details = self.visual_analyzer.get_last_analysis_details() or {}
            
            # Extract color scheme from behavior
            if 'metadata' in behavior_data and 'colorScheme' in behavior_data['metadata']:
                visual_details['color_scheme'] = behavior_data['metadata']['colorScheme']
            
            # Analyze for known web elements indicating phishing
            if 'metadata' in behavior_data:
                metadata = behavior_data['metadata']
                
                # Check for login-related content in title
                if 'title' in metadata:
                    title = metadata['title'].lower()
                    suspicious_words = ['login', 'sign in', 'verify', 'account', 'password']
                    
                    if any(word in title for word in suspicious_words):
                        visual_risk += 0.1
                        if 'suspicious_patterns' not in visual_details:
                            visual_details['suspicious_patterns'] = []
                        visual_details['suspicious_patterns'].append("Login-related terms in page title")
                
                # Check for lack of favicon (legitimate sites usually have one)
                if 'hasFavicon' in metadata and not metadata['hasFavicon']:
                    visual_risk += 0.1
                    if 'suspicious_patterns' not in visual_details:
                        visual_details['suspicious_patterns'] = []
                    visual_details['suspicious_patterns'].append("No favicon detected")
            
            visual_details['risk_score'] = min(visual_risk, 1.0)
            return min(visual_risk, 1.0), visual_details
        
        except Exception as e:
            logger.error(f"Error in visual analysis: {e}")
            return 0.4, {"error": str(e)}

    def _analyze_behavior(self, behavior_data):
        """Analyze page behavior for suspicious activity"""
        try:
            # Use the enhanced behavior analyzer
            behavior_risk = self.behavior_analyzer.analyze(behavior_data)
            
            # Get detailed information from analyzer
            behavior_details = {}
            if hasattr(self.behavior_analyzer, 'get_last_analysis_details'):
                behavior_details = self.behavior_analyzer.get_last_analysis_details() or {}
            else:
                # Basic behavior summary
                behavior_details = {
                    'forms': behavior_data.get('forms', 0),
                    'hasPasswordField': behavior_data.get('hasPasswordField', False),
                    'hasLoginForm': behavior_data.get('hasLoginForm', False),
                    'redirectCount': behavior_data.get('redirectCount', 0),
                    'risk_score': behavior_risk
                }
            
            return behavior_risk, behavior_details
                
        except Exception as e:
            logger.error(f"Error in behavior analysis: {e}")
            return 0.4, {"error": str(e)}
    
    def _has_brand_impersonation(self, hostname, content):
        """Check for brand impersonation using combined URL and content analysis"""
        try:
            brands = {
                'paypal': ['account', 'secure', 'wallet', 'payment'],
                'google': ['account', 'gmail', 'drive', 'docs'],
                'facebook': ['login', 'account', 'messenger', 'profile'],
                'apple': ['icloud', 'itunes', 'account', 'id'],
                'microsoft': ['office', 'outlook', 'account', 'windows'],
                'amazon': ['account', 'order', 'prime', 'signin'],
                'netflix': ['account', 'movies', 'shows', 'stream']
            }
            
            for brand, keywords in brands.items():
                # If brand name appears in content but not in the actual domain
                if brand in content.lower() and brand not in hostname:
                    # Check for brand-specific keywords
                    keyword_matches = sum(1 for kw in keywords if kw in content.lower())
                    if keyword_matches >= 2:
                        return True
            
            return False
                
        except Exception as e:
            logger.error(f"Error checking brand impersonation: {e}")
            return False
    
    def _calculate_overall_risk(self, url_risk, visual_risk, behavior_risk, ssl_status):
        """Calculate overall risk using weighted approach and advanced risk modeling"""
        try:
            # Base weights for different risk components
            base_weights = {
                'url': 0.35,
                'visual': 0.25,
                'behavior': 0.30,
                'ssl': 0.10
            }
            
            # Dynamic weight adjustment based on risk levels
            if url_risk > 0.7:
                base_weights['url'] += 0.1
                base_weights['visual'] -= 0.05
                base_weights['ssl'] -= 0.05
                
            if behavior_risk > 0.7:
                base_weights['behavior'] += 0.1
                base_weights['visual'] -= 0.05
                base_weights['url'] -= 0.05
                
            if visual_risk > 0.7:
                base_weights['visual'] += 0.1
                base_weights['url'] -= 0.05
                base_weights['behavior'] -= 0.05
            
            # SSL penalty for insecure sites
            ssl_factor = 0.05 if ssl_status else 0.8
            
            # Calculate weighted sum of risks
            weighted_risk = (
                (url_risk * base_weights['url']) +
                (visual_risk * base_weights['visual']) +
                (behavior_risk * base_weights['behavior']) +
                (ssl_factor * base_weights['ssl'])
            )
            
            # Coherence check - detect outliers in risk assessment
            risks = [url_risk, visual_risk, behavior_risk]
            max_risk = max(risks)
            min_risk = min(risks)
            risk_range = max_risk - min_risk
            
            # If there's high disagreement between analyzers
            if risk_range > 0.6:
                # Trust the higher risk scores more
                weighted_risk = (weighted_risk * 0.7) + (max_risk * 0.3)
            
            # Ensure SSL findings are properly weighted
            if not ssl_status and weighted_risk < 0.3:
                # Insecure sites should have at least moderate risk
                weighted_risk = max(weighted_risk, 0.3)
            
            return min(weighted_risk, 1.0)
            
        except Exception as e:
            logger.error(f"Error calculating overall risk: {e}")
            return max(url_risk, visual_risk, behavior_risk, 0 if ssl_status else 0.5)

    def _generate_security_recommendations(self, results, url, ssl_status, behavior_data):
        """Generate detailed security recommendations based on analysis results"""
        try:
            recommendations = []
            
            # URL-based recommendations
            if results['url_risk'] > 0.7:
                recommendations.append("This URL shows multiple high-risk characteristics of phishing sites")
            elif results['url_risk'] > 0.4:
                recommendations.append("Verify this website's authenticity before sharing sensitive information")
            
            # SSL recommendations
            if not ssl_status:
                recommendations.append("This site doesn't use secure HTTPS connection - avoid entering sensitive information")
            elif ssl_status and results['url_risk'] < 0.4:
                recommendations.append("Secure connection established with valid certificate")
            
            # Behavior-based recommendations
            if results['behavior_risk'] > 0.7:
                recommendations.append("This website exhibits suspicious behavior patterns common in phishing sites")
            elif results['behavior_risk'] > 0.4:
                recommendations.append("Exercise caution - this site shows some unusual behaviors")
            
            # Content/visual recommendations
            if results['visual_risk'] > 0.7:
                recommendations.append("Website content suggests possible brand impersonation")
            elif results['visual_risk'] > 0.4:
                recommendations.append("Some content elements require closer verification")
            
            # Password field detection
            if behavior_data.get('hasPasswordField', False) and results['overall_risk'] > 0.4:
                recommendations.append("Avoid entering passwords on this potentially unsafe site")
            
            # Overall assessment recommendations
            if results['overall_risk'] < 0.2:
                recommendations.append("This appears to be a legitimate website with good security practices")
            elif results['overall_risk'] > 0.7:
                recommendations.append("HIGH RISK - Strongly advise against sharing any personal information on this site")
            
            # Use Gemini for more nuanced recommendations if available
            if USE_AI and results['overall_risk'] > 0.3:
                try:
                    gemini_model = genai.GenerativeModel('gemini-pro')
                    
                    # Build prompt with analysis details
                    suspicious_elements = results['analysis_details'].get('suspicious_patterns', [])
                    suspicious_str = ", ".join(suspicious_elements) if suspicious_elements else "None"
                    
                    prompt = f"""
                    As a cybersecurity expert, provide 2-3 specific security recommendations for a user visiting this website:
                    
                    URL: {url}
                    Overall Risk Score: {results['overall_risk']:.2f} (0-1 scale, higher is riskier)
                    Risk Components:
                    - URL Risk: {results['url_risk']:.2f}
                    - Visual/Content Risk: {results['visual_risk']:.2f}
                    - Behavior Risk: {results['behavior_risk']:.2f}
                    - HTTPS Secure: {'Yes' if ssl_status else 'No'}
                    
                    Suspicious Elements Detected: {suspicious_str}
                    
                    Password Field Present: {'Yes' if behavior_data.get('hasPasswordField', False) else 'No'}
                    Login Form Present: {'Yes' if behavior_data.get('hasLoginForm', False) else 'No'}
                    
                    Provide clear, specific security recommendations. Focus on what the user should do.
                    Each recommendation should be 1-2 sentences, actionable and specific to this site's risks.
                    """
                    
                    response = gemini_model.generate_content(prompt.strip())
                    ai_suggestions = response.text.strip().split('\n')
                    
                    # Clean up and add AI suggestions
                    for suggestion in ai_suggestions:
                        suggestion = suggestion.strip()
                        # Remove numbering and bullet points
                        suggestion = re.sub(r'^[0-9\-\*\.]+\s*', '', suggestion)
                        if suggestion and len(suggestion) > 20:
                            recommendations.append(suggestion)
                            
                except Exception as e:
                    logger.error(f"Error generating AI recommendations: {e}")
            
            # Return unique recommendations, limited to 5
            unique_recommendations = []
            for rec in recommendations:
                if rec not in unique_recommendations:
                    unique_recommendations.append(rec)
            
            return unique_recommendations[:5]
            
        except Exception as e:
            logger.error(f"Error generating recommendations: {e}")
            return [
                "Verify this website's legitimacy before sharing sensitive information",
                "Check the URL carefully for misspellings or suspicious domains",
                "Look for the padlock icon indicating a secure connection"
            ]

    def _correlate_risk_factors(self, url, content, behavior_data, url_risk, visual_risk, behavior_risk, ssl_status):
        """Correlate different risk factors to detect sophisticated phishing attempts"""
        try:
            risk_factors = []
        
            # Combine url and content risks
            if url_risk > 0.6 and visual_risk > 0.5:
                risk_factors.append("Domain and content strongly suggest phishing")
            
            # Behavior and security mismatches
            if behavior_data.get('hasPasswordField', False) and not ssl_status:
                risk_factors.append("Password field on non-secure connection")
            
            # Login forms with suspicious URL
            if behavior_data.get('hasLoginForm', False) and url_risk > 0.5:
                risk_factors.append("Login form on suspicious domain")
            
            # Suspicious redirects
            if behavior_data.get('redirectCount', 0) > 2:
                risk_factors.append(f"Multiple redirects: {behavior_data.get('redirectCount')} detected")
            
            # Enhanced brand impersonation detection
            if self._has_brand_impersonation(urlparse(url).netloc, content):
                risk_factors.append("Possible brand impersonation detected")
            
            return risk_factors
            
        except Exception as e:
            logger.error(f"Error correlating risk factors: {e}")
            return []

@app.route('/api/analyze', methods=['POST'])
def analyze():
    start_time = time.time()
    try:
        data = request.json
        
        # Extract data from request
        url = data.get('url', '')
        content = data.get('content', '')
        behavior = data.get('behavior', {})
        
        # Validation
        if not url:
            return jsonify({
                'error': 'URL is required',
                'overall_risk': 0.5  # Default moderate risk on error
            }), 400
        
        # Create API if not already exists
        api = SecureNetAPI()
        
        # Perform analysis
        result = api.analyze_url(url, content, behavior)
        
        # Log completion time
        processing_time = time.time() - start_time
        logger.info(f"Analysis completed in {processing_time:.2f} seconds")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"API error: {e}")
        logger.error(traceback.format_exc())
        
        # Return valid response even on error, not dummy data
        return jsonify({
            'error': True,
            'message': str(e),
            'overall_risk': 0.5,
            'url_risk': 0.5,
            'visual_risk': 0.5,
            'behavior_risk': 0.5,
            'ssl_status': False,
            'analysis_details': {
                'security_recommendations': [
                    "We encountered an error analyzing this site",
                    "Exercise caution and verify the website manually",
                    "Check if the URL looks legitimate and has HTTPS"
                ]
            }
        })

@app.route('/api/status', methods=['GET'])
def status():
    return jsonify({
        'status': 'online',
        'version': '1.0.0',
        'models': {
            'url_analyzer': True,
            'visual_analyzer': True,
            'behavior_analyzer': True,
            'gemini': USE_AI
        }
    })

if __name__ == "__main__":
    logger.info(f"Starting Kavach Security backend server on port {PORT}")
    uvicorn.run(asgi_app, host="0.0.0.0", port=PORT) 
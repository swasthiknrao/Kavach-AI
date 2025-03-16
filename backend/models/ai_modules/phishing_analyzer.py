import google.generativeai as genai
from urllib.parse import urlparse
import re

class PhishingAnalyzer:
    def __init__(self):
        try:
            self.model = genai.GenerativeModel('gemini-pro')
        except Exception as e:
            print(f"Warning: Could not initialize Gemini model: {e}")
            self.model = None

    async def analyze_phishing_risk(self, url, screenshot=None, content=""):
        try:
            risk_assessment = {
                'overall_risk': 0.0,
                'url_risk_score': 0.0,
                'content_risk_score': 0.0,
                'indicators': [],
                'is_zero_day': False
            }

            # Basic URL analysis
            parsed_url = urlparse(url)
            suspicious_patterns = [
                r'paypal.*\.com',
                r'bank.*\.com',
                r'secure.*\.com',
                r'account.*\.com',
                r'login.*\.com'
            ]

            # Check URL for suspicious patterns
            for pattern in suspicious_patterns:
                if re.search(pattern, url.lower()):
                    risk_assessment['url_risk_score'] += 0.2
                    risk_assessment['indicators'].append(f"Suspicious URL pattern: {pattern}")

            # Use Gemini for content analysis if available
            if self.model and content:
                try:
                    analysis_prompt = f"""
                    Analyze this website content for phishing indicators:
                    URL: {url}
                    Content: {content[:1000]}
                    
                    Respond with a JSON-like format containing:
                    1. Risk level (0.0 to 1.0)
                    2. List of suspicious indicators found
                    3. Whether this might be a zero-day phishing attempt
                    """

                    response = self.model.generate_content(analysis_prompt)
                    if response.text:
                        # Parse response and update risk assessment
                        if "high risk" in response.text.lower():
                            risk_assessment['content_risk_score'] = 0.8
                        elif "medium risk" in response.text.lower():
                            risk_assessment['content_risk_score'] = 0.5
                        elif "low risk" in response.text.lower():
                            risk_assessment['content_risk_score'] = 0.2

                        # Extract indicators from response
                        indicators = re.findall(r'"([^"]*suspicious[^"]*)"', response.text)
                        risk_assessment['indicators'].extend(indicators)

                except Exception as e:
                    print(f"Gemini analysis error: {e}")

            # Calculate overall risk
            risk_assessment['overall_risk'] = max(
                risk_assessment['url_risk_score'],
                risk_assessment['content_risk_score']
            )

            return risk_assessment

        except Exception as e:
            print(f"Phishing analysis error: {e}")
            return {
                'overall_risk': 0.5,
                'url_risk_score': 0.5,
                'content_risk_score': 0.5,
                'indicators': ['Analysis error occurred'],
                'is_zero_day': False
            }

    def identify_url_risk_factors(self, url):
        """Identify specific URL-based risk factors"""
        return {
            'suspicious_tld': self.check_suspicious_tld(url),
            'character_manipulation': self.detect_character_manipulation(url),
            'brand_impersonation': self.detect_brand_impersonation(url),
            'url_length': len(url),
            'suspicious_patterns': self.detect_suspicious_patterns(url)
        }

    def identify_visual_risk_factors(self, screenshot):
        """Identify visual risk factors"""
        return {
            'logo_manipulation': self.detect_logo_manipulation(screenshot),
            'layout_similarity': self.analyze_layout_similarity(screenshot),
            'color_scheme_match': self.analyze_color_scheme(screenshot),
            'security_indicator_presence': self.check_security_indicators(screenshot)
        }

    def identify_content_risk_factors(self, content):
        """Identify content-based risk factors"""
        return {
            'urgency_indicators': self.detect_urgency_language(content),
            'sensitive_fields': self.detect_sensitive_form_fields(content),
            'brand_mentions': self.analyze_brand_mentions(content),
            'grammar_quality': self.analyze_grammar_quality(content)
        } 
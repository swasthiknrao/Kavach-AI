import cv2
import numpy as np
from textblob import TextBlob
from sklearn.feature_extraction.text import TfidfVectorizer
import whois
from datetime import datetime
import re
import pytesseract
from PIL import Image
import imagehash
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

class AdvancedAnalyzer:
    def __init__(self):
        self.sentiment_analyzer = TextBlob
        self.text_vectorizer = TfidfVectorizer()
        self.load_reference_data()

    def load_reference_data(self):
        self.legitimate_hashes = {}  # Load from database
        self.brand_typography = {}   # Load brand font standards
        self.safe_patterns = {}      # Load legitimate UI patterns

    def analyze_visual_safety(self, screenshot):
        """Comprehensive visual analysis"""
        results = {
            'logo_analysis': self.analyze_logo(screenshot),
            'layout_similarity': self.compare_layout(screenshot),
            'typography_check': self.check_typography(screenshot),
            'dark_patterns': self.detect_dark_patterns(screenshot),
            'visual_elements': self.analyze_visual_elements(screenshot)
        }
        return self.calculate_visual_risk(results)

    def analyze_logo(self, image):
        """Logo detection and quality analysis"""
        # Convert image to PIL format
        pil_image = Image.fromarray(cv2.cvtColor(image, cv2.COLOR_BGR2RGB))
        
        # Generate perceptual hash
        img_hash = str(imagehash.average_hash(pil_image))
        
        # Compare with known legitimate logos
        matches = []
        for brand, hash_value in self.legitimate_hashes.items():
            similarity = self.calculate_hash_similarity(img_hash, hash_value)
            if similarity > 0.85:  # High similarity threshold
                matches.append((brand, similarity))
        
        return {
            'potential_impersonation': len(matches) > 0,
            'matches': matches,
            'quality_score': self.analyze_logo_quality(image)
        }

    def analyze_domain_age(self, domain):
        """Domain age and registration analysis"""
        try:
            domain_info = whois.whois(domain)
            creation_date = domain_info.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            age = (datetime.now() - creation_date).days
            
            return {
                'age_days': age,
                'registrar': domain_info.registrar,
                'country': domain_info.country,
                'suspicious': age < 30  # Flag domains less than 30 days old
            }
        except Exception as e:
            return {'error': str(e), 'suspicious': True}

    def analyze_sentiment(self, text):
        """Detect urgent/threatening language"""
        blob = TextBlob(text)
        
        # Analyze sentiment
        sentiment = blob.sentiment
        
        # Look for urgent language patterns
        urgent_words = ['immediate', 'urgent', 'now', 'limited time', 'account suspended']
        urgency_score = sum(1 for word in urgent_words if word in text.lower())
        
        return {
            'polarity': sentiment.polarity,
            'subjectivity': sentiment.subjectivity,
            'urgency_level': urgency_score,
            'threatening': sentiment.polarity < -0.3
        }

    def generate_heatmap(self, screenshot, elements):
        """Generate security heatmap overlay"""
        heatmap = np.zeros(screenshot.shape[:2], dtype=np.float32)
        
        for element in elements:
            risk_score = element.get('risk_score', 0)
            bbox = element.get('bbox')
            if bbox:
                heatmap[bbox[1]:bbox[3], bbox[0]:bbox[2]] += risk_score
        
        # Normalize heatmap
        heatmap = cv2.normalize(heatmap, None, 0, 1, cv2.NORM_MINMAX)
        return heatmap

    def analyze_form_safety(self, form_elements):
        """Analyze form fields for security"""
        sensitive_fields = ['password', 'credit_card', 'ssn']
        encryption_status = {}
        
        for field in form_elements:
            field_type = field.get('type', '')
            if field_type in sensitive_fields:
                encryption_status[field_type] = {
                    'encrypted': self.check_field_encryption(field),
                    'secure_transmission': self.check_secure_transmission(field),
                    'risk_level': self.calculate_field_risk(field)
                }
        
        return encryption_status

    def detect_dark_patterns(self, screenshot):
        """Detect manipulative UI patterns"""
        patterns = {
            'countdown_timers': self.find_countdown_timers(screenshot),
            'hidden_costs': self.detect_hidden_costs(screenshot),
            'forced_actions': self.detect_forced_actions(screenshot),
            'misleading_buttons': self.find_misleading_buttons(screenshot)
        }
        
        return {
            'dark_patterns_found': any(patterns.values()),
            'pattern_types': [k for k, v in patterns.items() if v],
            'risk_score': sum(1 for v in patterns.values() if v) / len(patterns)
        }

    def analyze_behavioral_biometrics(self, user_data):
        """Analyze user behavior for signs of uncertainty"""
        metrics = {
            'hover_time': self.analyze_hover_patterns(user_data.get('mouse_movements', [])),
            'input_corrections': self.analyze_input_corrections(user_data.get('keystrokes', [])),
            'navigation_patterns': self.analyze_navigation(user_data.get('page_interactions', [])),
            'hesitation_score': self.calculate_hesitation(user_data)
        }
        
        return {
            'uncertainty_detected': any(m > 0.7 for m in metrics.values()),
            'risk_metrics': metrics,
            'confidence_score': 1 - (sum(metrics.values()) / len(metrics))
        }

    def analyze_price_anomalies(self, price_data, product_info):
        """Detect suspiciously low prices that might indicate scams"""
        try:
            market_price = self.get_market_price(product_info)
            price_ratio = float(price_data['price']) / market_price
            
            return {
                'price_ratio': price_ratio,
                'market_price': market_price,
                'suspicious': price_ratio < 0.5,  # Flag prices less than 50% of market value
                'confidence': self.calculate_price_confidence(price_data, market_price)
            }
        except Exception as e:
            return {'error': str(e), 'suspicious': True}

    def analyze_social_engineering(self, page_content):
        """Detect social engineering tactics"""
        tactics = {
            'urgency': self.detect_urgency_tactics(page_content),
            'scarcity': self.detect_scarcity_tactics(page_content),
            'authority': self.detect_authority_claims(page_content),
            'emotional': self.detect_emotional_manipulation(page_content),
            'pressure': self.detect_pressure_tactics(page_content)
        }
        
        return {
            'tactics_detected': [k for k, v in tactics.items() if v['detected']],
            'risk_score': sum(v['score'] for v in tactics.values()) / len(tactics),
            'details': tactics
        }

    def analyze_certificate_chain(self, cert_data):
        """Advanced SSL/TLS certificate analysis"""
        return {
            'cert_age': self.calculate_cert_age(cert_data),
            'issuer_reputation': self.check_issuer_reputation(cert_data['issuer']),
            'cert_transparency': self.check_certificate_transparency(cert_data),
            'validation_level': self.determine_validation_level(cert_data),
            'suspicious_patterns': self.detect_cert_anomalies(cert_data)
        }

    def analyze_content_consistency(self, content):
        """Check for language and content inconsistencies"""
        return {
            'language_mixing': self.detect_language_mixing(content),
            'brand_voice_match': self.analyze_brand_voice(content),
            'grammar_score': self.check_grammar_quality(content),
            'translation_artifacts': self.detect_translation_issues(content),
            'content_coherence': self.analyze_content_coherence(content)
        }

    def analyze_technical_indicators(self, page_data):
        """Analyze technical aspects of the page"""
        return {
            'js_obfuscation': self.detect_js_obfuscation(page_data['scripts']),
            'hidden_elements': self.find_hidden_elements(page_data['dom']),
            'redirect_chains': self.analyze_redirect_chain(page_data['navigation']),
            'resource_loading': self.analyze_resource_loading(page_data['resources']),
            'api_endpoints': self.analyze_api_endpoints(page_data['network'])
        }

    def analyze_user_context(self, user_data):
        """Analyze user-specific context"""
        return {
            'browsing_pattern_break': self.detect_pattern_break(user_data['history']),
            'time_context': self.analyze_time_context(user_data['timestamp']),
            'geo_anomalies': self.detect_geo_anomalies(user_data['location']),
            'device_consistency': self.check_device_consistency(user_data['device'])
        }

    def analyze_brand_impersonation(self, site_data):
        """Detect sophisticated brand impersonation attempts"""
        return {
            'visual_similarity': self.calculate_brand_similarity(site_data['visuals']),
            'content_mimicry': self.detect_content_mimicry(site_data['text']),
            'service_impersonation': self.detect_service_impersonation(site_data),
            'brand_assets_misuse': self.detect_asset_misuse(site_data['assets'])
        }

    def analyze_form_integrity(self, form_data):
        """Advanced form security analysis"""
        return {
            'field_encryption': self.analyze_field_encryption(form_data['fields']),
            'submission_endpoint': self.analyze_submission_endpoint(form_data['action']),
            'data_handling': self.analyze_data_handling(form_data),
            'input_validation': self.check_input_validation(form_data['validation'])
        }

    def generate_security_score(self, all_analyses):
        """Generate comprehensive security score"""
        weights = {
            'technical': 0.3,
            'visual': 0.2,
            'behavioral': 0.15,
            'contextual': 0.15,
            'historical': 0.1,
            'social': 0.1
        }
        
        scores = {
            'technical': self.calculate_technical_score(all_analyses),
            'visual': self.calculate_visual_score(all_analyses),
            'behavioral': self.calculate_behavioral_score(all_analyses),
            'contextual': self.calculate_contextual_score(all_analyses),
            'historical': self.calculate_historical_score(all_analyses),
            'social': self.calculate_social_score(all_analyses)
        }
        
        weighted_score = sum(score * weights[category] for category, score in scores.items())
        
        return {
            'overall_score': weighted_score,
            'category_scores': scores,
            'risk_level': self.determine_risk_level(weighted_score),
            'confidence': self.calculate_confidence_level(scores)
        }

    def generate_user_recommendations(self, analysis_results):
        """Generate personalized security recommendations"""
        return {
            'immediate_actions': self.get_immediate_actions(analysis_results),
            'preventive_measures': self.get_preventive_measures(analysis_results),
            'educational_resources': self.get_educational_resources(analysis_results),
            'security_tips': self.generate_security_tips(analysis_results)
        }

    def analyze_cross_device_patterns(self, device_data):
        """Analyze security patterns across user devices"""
        return {
            'device_consistency': self.check_cross_device_consistency(device_data),
            'sync_anomalies': self.detect_sync_anomalies(device_data),
            'auth_patterns': self.analyze_auth_patterns(device_data),
            'risk_propagation': self.assess_risk_propagation(device_data)
        } 
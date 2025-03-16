import tensorflow as tf
import numpy as np
import os
import re
import pickle
import logging
from urllib.parse import urlparse
from sklearn.feature_extraction.text import TfidfVectorizer

class AdvancedPhishingAnalyzer:
    def __init__(self, model_directory='models'):
        self.logger = logging.getLogger(__name__)
        
        # Initialize models
        self.url_model = None
        self.visual_model = None
        self.behavior_model = None
        self.ensemble_model = None
        
        # Initialize tokenizers and scalers
        self.char_tokenizer = None
        self.scaler = None
        
        # Load models
        self.load_models(model_directory)
    
    def load_models(self, model_directory):
        """Load all trained models from the specified directory"""
        try:
            # Create directory if it doesn't exist
            os.makedirs(model_directory, exist_ok=True)
            
            # Load URL model
            url_model_path = os.path.join(model_directory, 'url_model.h5')
            if os.path.exists(url_model_path):
                self.url_model = tf.keras.models.load_model(url_model_path)
                self.logger.info("URL model loaded successfully")
            
            # Load visual model
            visual_model_path = os.path.join(model_directory, 'visual_model.h5')
            if os.path.exists(visual_model_path):
                self.visual_model = tf.keras.models.load_model(visual_model_path)
                self.logger.info("Visual model loaded successfully")
            
            # Load behavior model
            behavior_model_path = os.path.join(model_directory, 'behavior_model.h5')
            if os.path.exists(behavior_model_path):
                self.behavior_model = tf.keras.models.load_model(behavior_model_path)
                self.logger.info("Behavior model loaded successfully")
            
            # Load ensemble model
            ensemble_model_path = os.path.join(model_directory, 'ensemble_model.h5')
            if os.path.exists(ensemble_model_path):
                self.ensemble_model = tf.keras.models.load_model(ensemble_model_path)
                self.logger.info("Ensemble model loaded successfully")
            
            # Load character tokenizer
            tokenizer_path = os.path.join(model_directory, 'char_tokenizer.pkl')
            if os.path.exists(tokenizer_path):
                with open(tokenizer_path, 'rb') as f:
                    self.char_tokenizer = pickle.load(f)
                self.logger.info("Character tokenizer loaded successfully")
            
            # Load feature scaler
            scaler_path = os.path.join(model_directory, 'feature_scaler.pkl')
            if os.path.exists(scaler_path):
                with open(scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
                self.logger.info("Feature scaler loaded successfully")
                
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading models: {str(e)}")
            return False
    
    def analyze_url(self, url):
        """Analyze a URL using the trained URL model"""
        if not self.url_model or not self.char_tokenizer:
            self.logger.error("URL model or tokenizer not loaded")
            return 0.5
        
        try:
            # Prepare character-level features
            char_features = np.array([self.tokenize_url(url)])
            
            # Prepare handcrafted features
            handcrafted_features = np.array([self.extract_url_features(url)])
            
            # Normalize features
            handcrafted_features = self.scaler.transform(handcrafted_features)
            
            # Make prediction
            prediction = self.url_model.predict([char_features, handcrafted_features])[0][0]
            
            self.logger.info(f"URL analysis complete: {url} - Risk score: {prediction:.4f}")
            return float(prediction)
            
        except Exception as e:
            self.logger.error(f"Error analyzing URL: {str(e)}")
            return 0.5
    
    def analyze_visual(self, screenshot_data):
        """Analyze website screenshot using the visual fingerprinting model"""
        if not self.visual_model:
            self.logger.error("Visual model not loaded")
            return 0.5
        
        try:
            # Extract visual features
            visual_features = self.extract_visual_features(screenshot_data)
            visual_features = np.expand_dims(visual_features, axis=0)
            
            # Make prediction
            prediction = self.visual_model.predict(visual_features)[0][0]
            
            self.logger.info(f"Visual analysis complete - Risk score: {prediction:.4f}")
            return float(prediction)
            
        except Exception as e:
            self.logger.error(f"Error analyzing visual: {str(e)}")
            return 0.5
    
    def analyze_behavior(self, behavior_data):
        """Analyze website behavior using the behavior analysis model"""
        if not self.behavior_model:
            self.logger.error("Behavior model not loaded")
            return 0.5
        
        try:
            # Extract behavior features
            behavior_features = self.extract_behavior_features(behavior_data)
            behavior_features = np.expand_dims(behavior_features, axis=0)
            
            # Make prediction
            prediction = self.behavior_model.predict(behavior_features)[0][0]
            
            self.logger.info(f"Behavior analysis complete - Risk score: {prediction:.4f}")
            return float(prediction)
            
        except Exception as e:
            self.logger.error(f"Error analyzing behavior: {str(e)}")
            return 0.5
    
    def analyze_comprehensive(self, url, screenshot_data=None, behavior_data=None, user_context=None):
        """Perform comprehensive analysis using all available models"""
        if not self.ensemble_model:
            self.logger.info("Ensemble model not loaded, using average of available models")
        
        try:
            # Default context if none provided
            if user_context is None:
                user_context = {
                    'visited_before': 0,
                    'bookmark_ratio': 0,
                    'domain_familiarity': 0,
                    'user_risk_tolerance': 0.5,
                    'sensitive_context': 0
                }
            
            # Get scores from individual models
            url_score = self.analyze_url(url)
            
            # If screenshot data is available, analyze visual
            visual_score = 0.5
            if screenshot_data is not None and self.visual_model:
                visual_score = self.analyze_visual(screenshot_data)
            
            # If behavior data is available, analyze behavior
            behavior_score = 0.5
            if behavior_data is not None and self.behavior_model:
                behavior_score = self.analyze_behavior(behavior_data)
            
            # Extract context features
            context_features = self.extract_context_features(user_context)
            
            # If ensemble model is available, use it for final prediction
            if self.ensemble_model:
                # Prepare inputs for ensemble model
                ensemble_inputs = [
                    np.array([[url_score]]),
                    np.array([[visual_score]]),
                    np.array([[behavior_score]]),
                    np.array([context_features])
                ]
                
                # Make prediction
                prediction = self.ensemble_model.predict(ensemble_inputs)[0][0]
            else:
                # Simple weighted average if ensemble model not available
                weights = [0.5, 0.3, 0.2]  # URL, visual, behavior weights
                scores = [url_score, visual_score, behavior_score]
                prediction = sum(w * s for w, s in zip(weights, scores)) / sum(weights)
            
            # Create detailed analysis result
            analysis_result = {
                'url': url,
                'risk_score': float(prediction),
                'risk_level': self._get_risk_level(prediction),
                'component_scores': {
                    'url_analysis': float(url_score),
                    'visual_analysis': float(visual_score),
                    'behavior_analysis': float(behavior_score)
                },
                'recommendations': self._get_recommendations(prediction, url)
            }
            
            self.logger.info(f"Comprehensive analysis complete: {url} - Risk score: {prediction:.4f}")
            return analysis_result
            
        except Exception as e:
            self.logger.error(f"Error in comprehensive analysis: {str(e)}")
            return {
                'url': url,
                'risk_score': 0.5,
                'risk_level': 'Unknown',
                'component_scores': {
                    'url_analysis': 0.5,
                    'visual_analysis': 0.5,
                    'behavior_analysis': 0.5
                },
                'recommendations': ['Error occurred during analysis. Exercise caution.']
            }
    
    def _get_risk_level(self, score):
        """Convert numeric score to risk level category"""
        if score < 0.2:
            return 'Safe'
        elif score < 0.4:
            return 'Low Risk'
        elif score < 0.6:
            return 'Medium Risk'
        elif score < 0.8:
            return 'High Risk'
        else:
            return 'Critical Risk'
    
    def _get_recommendations(self, score, url):
        """Generate recommendations based on risk score"""
        recommendations = []
        
        if score < 0.2:
            recommendations.append('This URL appears safe.')
        elif score < 0.4:
            recommendations.append('Exercise normal caution when using this site.')
            recommendations.append('Avoid entering sensitive information unless necessary.')
        elif score < 0.6:
            recommendations.append('Be cautious when using this site.')
            recommendations.append('Verify the legitimacy of the site before providing any information.')
            recommendations.append('Check for security indicators like HTTPS.')
        elif score < 0.8:
            recommendations.append('This site shows multiple suspicious indicators.')
            recommendations.append('Do not enter personal or financial information.')
            recommendations.append('Consider leaving this site immediately.')
        else:
            recommendations.append('This site is very likely to be malicious or fraudulent.')
            recommendations.append('Leave this site immediately.')
            recommendations.append('If you entered any information, consider it compromised.')
        
        # Add URL-specific recommendations
        parsed_url = urlparse(url)
        if parsed_url.scheme != 'https':
            recommendations.append('This site does not use HTTPS encryption, which is a security concern.')
        
        return recommendations
    
    def get_model_explanations(self, url):
        """Generate explanations for why a URL was flagged (for transparency)"""
        explanations = []
        
        # Basic checks
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc.lower()
        
        # HTTP vs HTTPS
        if parsed_url.scheme != 'https':
            explanations.append('This site does not use secure HTTPS encryption.')
        
        # IP address in hostname
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', hostname):
            explanations.append('This URL uses an IP address instead of a domain name, which is unusual for legitimate sites.')
        
        # URL length
        if len(url) > 100:
            explanations.append('This URL is unusually long, which can be an attempt to hide suspicious elements.')
        
        # Hostname length
        if len(hostname) > 30:
            explanations.append('The domain name is unusually long, which is often a characteristic of suspicious sites.')
        
        # Special characters
        special_char_ratio = sum(not c.isalnum() and c != '.' for c in hostname) / len(hostname) if hostname else 0
        if special_char_ratio > 0.2:
            explanations.append('The domain contains many special characters, which is uncommon for legitimate sites.')
        
        # Digit ratio
        digit_ratio = sum(c.isdigit() for c in hostname) / len(hostname) if hostname else 0
        if digit_ratio > 0.3:
            explanations.append('The domain contains many numbers, which can be a sign of a randomly generated domain.')
        
        # Subdomain analysis
        if hostname.count('.') > 2:
            explanations.append('This URL uses multiple subdomains, which can be an attempt to appear legitimate.')
        
        # Common sensitive terms in URL
        sensitive_terms = ['login', 'signin', 'account', 'bank', 'secure', 'verify', 'password', 'update']
        for term in sensitive_terms:
            if term in url.lower():
                explanations.append(f'This URL contains the sensitive term "{term}", which is common in phishing attempts.')
                break
        
        # If no explanations, add a default message
        if not explanations:
            explanations.append('This URL was analyzed using multiple factors including structure, content, and pattern matching.')
        
        return explanations

    def train_federated(self, model_updates):
        """Update models using federated learning approach (privacy-preserving)"""
        # In a real implementation, this would implement secure aggregation
        # For demo purposes, we'll implement a simple averaging approach
        try:
            if not self.url_model:
                self.logger.error("Model not initialized for federated learning")
                return False
                
            # Get current model weights
            current_weights = self.url_model.get_weights()
            
            # Apply federated updates (simple averaging)
            if model_updates:
                # Average the weights
                new_weights = []
                for i, layer_weights in enumerate(current_weights):
                    update_sum = np.zeros_like(layer_weights)
                    for update in model_updates:
                        update_sum += update[i]
                    avg_update = update_sum / len(model_updates)
                    
                    # Apply the update (with a learning rate)
                    learning_rate = 0.1
                    new_weights.append(layer_weights * (1 - learning_rate) + avg_update * learning_rate)
                
                # Set the new weights
                self.url_model.set_weights(new_weights)
                self.logger.info(f"Model updated with {len(model_updates)} federated updates")
                return True
                
            return False
            
        except Exception as e:
            self.logger.error(f"Error in federated learning: {str(e)}")
            return False
    
    def detect_age_restricted_content(self, url, content_data=None):
        """Detect if a site might contain age-restricted content"""
        # This is a placeholder for age verification screening
        # In a real implementation, this would use content analysis models
        
        age_restricted_indicators = {
            'keywords': ['adult', 'mature', '18+', 'gambling', 'betting', 'alcohol', 'tobacco'],
            'domains': ['casino', 'poker', 'bet', 'adult', 'xxx']
        }
        
        url_lower = url.lower()
        
        # Check for age-restricted keywords in URL
        for keyword in age_restricted_indicators['keywords']:
            if keyword in url_lower:
                return {
                    'is_age_restricted': True,
                    'confidence': 0.8,
                    'reason': f'URL contains age-restricted term: {keyword}'
                }
        
        # Check for age-restricted domains
        hostname = urlparse(url).netloc.lower()
        for domain in age_restricted_indicators['domains']:
            if domain in hostname:
                return {
                    'is_age_restricted': True,
                    'confidence': 0.9,
                    'reason': f'Domain associated with age-restricted content: {domain}'
                }
        
        # If content data is provided, analyze it (placeholder)
        if content_data:
            # Simulate content analysis
            # In a real implementation, this would use NLP/computer vision models
            return {
                'is_age_restricted': False,
                'confidence': 0.6,
                'reason': 'Content analysis did not detect age-restricted material'
            }
        
        return {
            'is_age_restricted': False,
            'confidence': 0.5,
            'reason': 'No age-restriction indicators detected'
        }
    
    # Helper methods that would need to be implemented
    def tokenize_url(self, url):
        """Tokenize URL for character-level features"""
        # Placeholder implementation
        return np.zeros((100,))
    
    def extract_url_features(self, url):
        """Extract handcrafted features from URL"""
        # Placeholder implementation
        return np.zeros((20,))
    
    def extract_visual_features(self, screenshot_data):
        """Extract features from screenshot"""
        # Placeholder implementation
        return np.zeros((100,))
    
    def extract_behavior_features(self, behavior_data):
        """Extract features from behavior data"""
        # Placeholder implementation
        return np.zeros((50,))
    
    def extract_context_features(self, user_context):
        """Extract features from user context"""
        # Placeholder implementation
        return np.zeros((10,)) 
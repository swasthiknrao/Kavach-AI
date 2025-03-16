import tensorflow as tf
from tensorflow.keras.layers import Input, Embedding, Conv1D, MaxPooling1D, LSTM, Dense, Dropout, Flatten, Concatenate
from tensorflow.keras.models import Model
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import re
from urllib.parse import urlparse
import logging
import pickle
import os
import json
from collections import Counter
import torch
from transformers import BertForSequenceClassification, BertTokenizer
from PIL import Image
from sklearn.ensemble import RandomForestClassifier
from tensorflow.keras.layers import GlobalAveragePooling2D
from tensorflow.keras.models import Sequential
from tensorflow.keras.applications import ResNet50

logger = logging.getLogger(__name__)

class PhishingDetector:
    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        
        # Initialize models
        self.url_model = None
        self.visual_model = None
        self.behavior_model = None
        self.ensemble_model = None
        self.url_tokenizer = None
        self.max_url_length = 200
        
        # For feature normalization
        self.scaler = StandardScaler()
        
        self.initialize_models()
        
    def initialize_models(self):
        """Initialize all required models."""
        try:
            # Initialize URL analysis model
            self.url_model = BertForSequenceClassification.from_pretrained('bert-base-uncased', num_labels=2)
            self.url_tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')
            
            # Initialize visual analysis model
            self.visual_model = ResNet50(weights='imagenet', include_top=False, input_shape=(224, 224, 3))
            self.visual_model = Model(inputs=self.visual_model.input, outputs=GlobalAveragePooling2D()(self.visual_model.output))
            
            # Initialize behavior analysis model
            self.behavior_model = Sequential([
                Dense(64, activation='relu', input_shape=(6,)),  # 6 behavior features
                Dropout(0.3),
                Dense(32, activation='relu'),
                Dense(1, activation='sigmoid')
            ])
            
            # Initialize ensemble model
            self.ensemble_model = RandomForestClassifier(n_estimators=100, random_state=42)
            
            self.logger.info("All models initialized successfully")
        except Exception as e:
            self.logger.error(f"Error initializing models: {str(e)}")
            raise
    
    def build_url_analyzer_model(self):
        """Build a deep learning model for URL analysis using character-level CNN-LSTM"""
        # Character-level input
        char_input = Input(shape=(self.max_url_length,), dtype='int32', name='char_input')
        
        # Embedding layer for character-level representation
        emb = Embedding(input_dim=128, output_dim=32, input_length=self.max_url_length)(char_input)
        
        # Convolutional layers for n-gram feature extraction
        conv1 = Conv1D(filters=64, kernel_size=3, activation='relu')(emb)
        pool1 = MaxPooling1D(pool_size=2)(conv1)
        
        conv2 = Conv1D(filters=128, kernel_size=5, activation='relu')(pool1)
        pool2 = MaxPooling1D(pool_size=2)(conv2)
        
        # LSTM for sequential pattern recognition
        lstm = LSTM(128, return_sequences=True)(pool2)
        lstm = LSTM(64)(lstm)
        
        # Feature input (handcrafted features)
        feature_input = Input(shape=(20,), name='feature_input')
        
        # Combine character-level features with handcrafted features
        combined = Concatenate()([lstm, feature_input])
        
        # Dense layers
        dense1 = Dense(128, activation='relu')(combined)
        dropout1 = Dropout(0.3)(dense1)
        
        dense2 = Dense(64, activation='relu')(dropout1)
        dropout2 = Dropout(0.3)(dense2)
        
        # Output layer
        output = Dense(1, activation='sigmoid')(dropout2)
        
        # Create model
        model = Model(inputs=[char_input, feature_input], outputs=output)
        model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])
        
        self.url_model = model
        self.logger.info("URL analyzer model built successfully")
        return model
    
    def build_visual_fingerprinting_model(self):
        """Build a deep learning model for visual fingerprinting comparison"""
        # This would typically be implemented as a computer vision model
        # For demo purposes, we're creating a placeholder model
        
        # Input: Screenshot embedding from a pre-trained CNN
        visual_input = Input(shape=(2048,), name='visual_input')
        
        # Dense layers for visual similarity detection
        dense1 = Dense(512, activation='relu')(visual_input)
        dropout1 = Dropout(0.4)(dense1)
        
        dense2 = Dense(256, activation='relu')(dropout1)
        dropout2 = Dropout(0.4)(dense2)
        
        # Optional: Add a similarity metric layer for brand comparison
        dense3 = Dense(128, activation='relu')(dropout2)
        
        # Output layer for phishing probability
        output = Dense(1, activation='sigmoid')(dense3)
        
        # Create model
        model = Model(inputs=visual_input, outputs=output)
        model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])
        
        self.visual_model = model
        self.logger.info("Visual fingerprinting model built successfully")
        return model
    
    def build_behavior_analysis_model(self):
        """Build a deep learning model for behavior analysis"""
        # Input: Sequence of user actions and page behaviors
        behavior_input = Input(shape=(50, 10), name='behavior_input')  # 50 timesteps, 10 features per step
        
        # LSTM for sequential behavior analysis
        lstm1 = LSTM(64, return_sequences=True)(behavior_input)
        lstm2 = LSTM(32)(lstm1)
        
        # Dense layers
        dense1 = Dense(64, activation='relu')(lstm2)
        dropout1 = Dropout(0.3)(dense1)
        
        # Output layer
        output = Dense(1, activation='sigmoid')(dropout1)
        
        # Create model
        model = Model(inputs=behavior_input, outputs=output)
        model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])
        
        self.behavior_model = model
        self.logger.info("Behavior analysis model built successfully")
        return model
    
    def build_ensemble_model(self):
        """Build an ensemble model to combine all detection methods"""
        # Inputs from each model's predictions
        url_input = Input(shape=(1,), name='url_score')
        visual_input = Input(shape=(1,), name='visual_score')
        behavior_input = Input(shape=(1,), name='behavior_score')
        context_input = Input(shape=(5,), name='context_features')  # User context features
        
        # Combine all inputs
        combined = Concatenate()([url_input, visual_input, behavior_input, context_input])
        
        # Dense layers for ensemble learning
        dense1 = Dense(16, activation='relu')(combined)
        dense2 = Dense(8, activation='relu')(dense1)
        
        # Output layer
        output = Dense(1, activation='sigmoid')(dense2)
        
        # Create model
        model = Model(inputs=[url_input, visual_input, behavior_input, context_input], outputs=output)
        model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])
        
        self.ensemble_model = model
        self.logger.info("Ensemble model built successfully")
        return model
    
    def create_char_tokenizer(self, urls):
        """Create a character-level tokenizer for URL encoding"""
        all_chars = set()
        for url in urls:
            all_chars.update(url)
        
        # Create a character-to-index mapping
        char_to_idx = {char: idx + 1 for idx, char in enumerate(sorted(all_chars))}
        char_to_idx['<PAD>'] = 0  # Add padding token
        
        self.url_tokenizer = char_to_idx
        return char_to_idx
    
    def tokenize_url(self, url):
        """Convert a URL to a sequence of character indices"""
        if not self.url_tokenizer:
            raise ValueError("Tokenizer not initialized. Call create_char_tokenizer first.")
        
        # Convert URL to character indices
        url_indices = [self.url_tokenizer.get(char, 0) for char in url[:self.max_url_length]]
        
        # Pad with zeros if necessary
        if len(url_indices) < self.max_url_length:
            url_indices += [0] * (self.max_url_length - len(url_indices))
        
        return np.array(url_indices)
    
    def extract_url_features(self, url):
        """Extract handcrafted features from a URL"""
        if not url:
            return np.zeros(20)
            
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        path = parsed_url.path
        query = parsed_url.query
        
        # Basic statistical features
        features = [
            len(url),                                               # URL length
            len(hostname),                                          # Hostname length
            len(path),                                              # Path length
            len(query),                                             # Query length
            sum(c.isdigit() for c in url) / max(1, len(url)),       # Digit ratio
            sum(not c.isalnum() for c in url) / max(1, len(url)),   # Special char ratio
            url.count('.'),                                         # Number of dots
            url.count('/'),                                         # Number of slashes
            url.count('-'),                                         # Number of hyphens
            url.count('_'),                                         # Number of underscores
            hostname.count('.'),                                    # Subdomain count
            len(path.split('/')),                                   # Path depth
            len(query.split('&')),                                  # Number of query parameters
            int(parsed_url.scheme == 'https'),                      # HTTPS flag
            int(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', hostname) is not None),  # IP in hostname
            int(hostname.count('-') > 0),                           # Hyphen in hostname
            int(any(c.isdigit() for c in hostname)),                # Digit in hostname
            self._calculate_entropy(hostname),                      # Hostname entropy
            int(len(hostname) > 30),                                # Long hostname flag
            int(len(url) > 100)                                     # Long URL flag
        ]
        
        return np.array(features)
    
    def _calculate_entropy(self, text):
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0
            
        # Count character frequencies
        char_counts = Counter(text)
        length = len(text)
        
        # Calculate entropy
        entropy = 0
        for count in char_counts.values():
            prob = count / length
            entropy -= prob * np.log2(prob)
            
        return entropy
    
    def extract_visual_features(self, screenshot_data):
        """Extract visual features from a screenshot (placeholder)"""
        # In a real implementation, this would process an actual screenshot
        # For demo purposes, we'll simulate a feature extractor
        
        # Simulated visual feature extraction
        features = np.random.randn(2048)  # Simulate features from a pre-trained CNN
        return features
    
    def extract_behavior_features(self, behavior_data):
        """Extract features from website/user behavior data (placeholder)"""
        # In a real implementation, this would process actual behavior data
        # For demo purposes, we'll simulate behavior sequences
        
        # Simulated behavior sequence (50 timesteps, 10 features each)
        features = np.random.randn(50, 10)
        return features
    
    def extract_context_features(self, user_context):
        """Extract user context features for personalized risk assessment"""
        # Features like browsing history familiarity, previous site interactions, etc.
        # For demo purposes, we'll create placeholder features
        context_features = np.array([
            float(user_context.get('visited_before', 0)),
            float(user_context.get('bookmark_ratio', 0)),
            float(user_context.get('domain_familiarity', 0)),
            float(user_context.get('user_risk_tolerance', 0.5)),
            float(user_context.get('sensitive_context', 0))
        ])
        
        return context_features
    
    def train_url_model(self, urls, labels, epochs=10, batch_size=32):
        """Train the URL analysis model"""
        if not self.url_model:
            self.build_url_analyzer_model()
        
        # Create character tokenizer if not already created
        if not self.url_tokenizer:
            self.create_char_tokenizer(urls)
        
        # Prepare character-level features
        char_features = np.array([self.tokenize_url(url) for url in urls])
        
        # Prepare handcrafted features
        handcrafted_features = np.array([self.extract_url_features(url) for url in urls])
        
        # Normalize features
        self.scaler.fit(handcrafted_features)
        handcrafted_features = self.scaler.transform(handcrafted_features)
        
        # Train the model
        history = self.url_model.fit(
            [char_features, handcrafted_features],
            np.array(labels),
            epochs=epochs,
            batch_size=batch_size,
            validation_split=0.2,
            verbose=1
        )
        
        self.logger.info("URL model training completed")
        return history
    
    def save_models(self, model_directory='phishing_detection_models'):
        """Save all trained models and tokenizers"""
        if not os.path.exists(model_directory):
            os.makedirs(model_directory)
        
        # Save URL model
        if self.url_model:
            self.url_model.save(os.path.join(model_directory, 'url_model.h5'))
        
        # Save visual model
        if self.visual_model:
            self.visual_model.save(os.path.join(model_directory, 'visual_model.h5'))
        
        # Save behavior model
        if self.behavior_model:
            self.behavior_model.save(os.path.join(model_directory, 'behavior_model.h5'))
        
        # Save ensemble model
        if self.ensemble_model:
            self.ensemble_model.save(os.path.join(model_directory, 'ensemble_model.h5'))
        
        # Save character tokenizer
        if self.url_tokenizer:
            with open(os.path.join(model_directory, 'url_tokenizer.pkl'), 'wb') as f:
                pickle.dump(self.url_tokenizer, f)
        
        # Save feature scaler
        with open(os.path.join(model_directory, 'feature_scaler.pkl'), 'wb') as f:
            pickle.dump(self.scaler, f)
        
        self.logger.info(f"All models and tokenizers saved to {model_directory}")
    
    def load_models(self, model_directory='phishing_detection_models'):
        """Load all trained models and tokenizers"""
        try:
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
            tokenizer_path = os.path.join(model_directory, 'url_tokenizer.pkl')
            if os.path.exists(tokenizer_path):
                with open(tokenizer_path, 'rb') as f:
                    self.url_tokenizer = pickle.load(f)
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
        """Analyze URL for phishing indicators."""
        try:
            if not url:
                return {
                    'risk_score': 0.5,
                    'confidence': 0.0,
                    'explanations': []
                }
            
            # Extract URL features
            features = self.extract_url_features(url)
            
            # Initialize explanations list
            explanations = []
            
            # Check for HTTPS
            if not url.startswith('https://'):
                explanations.append("This site does not use secure HTTPS encryption.")
            
            # Check for sensitive terms
            sensitive_terms = ['login', 'account', 'verify', 'secure', 'banking', 'payment']
            found_terms = [term for term in sensitive_terms if term in url.lower()]
            if found_terms:
                explanations.append(f"URL contains sensitive terms: {', '.join(found_terms)}")
            
            # Calculate risk score
            risk_score = 0.0
            
            # Base risk on features
            if features is not None:
                # Use model if available
                if self.url_model is not None:
                    try:
                        prediction = self.url_model.predict([features])[0]
                        risk_score = float(prediction)
                    except Exception as e:
                        logger.error(f"Error in URL model prediction: {e}")
                        risk_score = 0.5
                else:
                    # Simple heuristic scoring
                    risk_score = 0.3  # Base score
                    if not url.startswith('https://'):
                        risk_score += 0.2
                    risk_score += len(found_terms) * 0.1
                    risk_score = min(risk_score, 1.0)
            
            return {
                'risk_score': risk_score,
                'confidence': 0.8 if self.url_model is not None else 0.5,
                'explanations': explanations
            }
            
        except Exception as e:
            logger.error(f"Error analyzing URL: {str(e)}")
            return {
                'risk_score': 0.5,
                'confidence': 0.0,
                'explanations': ["Error analyzing URL"]
            }
    
    def analyze_visual(self, image_data):
        """Analyze visual elements for phishing indicators."""
        try:
            if self.visual_model is None:
                self.logger.error("Visual model not loaded")
                return 0.5
            
            # Ensure image is in correct format
            if isinstance(image_data, Image.Image):
                image_array = np.array(image_data)
                if len(image_array.shape) == 2:  # Grayscale
                    image_array = np.stack([image_array] * 3, axis=-1)
                elif len(image_array.shape) == 3 and image_array.shape[-1] == 4:  # RGBA
                    image_array = image_array[..., :3]
                
                # Resize and preprocess
                image_array = image_array.astype(np.float32) / 255.0
                if image_array.shape[:2] != (224, 224):
                    image = Image.fromarray((image_array * 255).astype(np.uint8))
                    image = image.resize((224, 224), Image.LANCZOS)
                    image_array = np.array(image).astype(np.float32) / 255.0
                
                # Add batch dimension
                image_array = np.expand_dims(image_array, axis=0)
                
                # Get prediction
                features = self.visual_model.predict(image_array)
                risk_score = np.mean(features)  # Simplified risk score
                
                return float(risk_score)
            else:
                self.logger.error("Invalid image format")
                return 0.5
        except Exception as e:
            self.logger.error(f"Error analyzing visual elements: {str(e)}")
            return 0.5
    
    def analyze_behavior(self, behavior_data):
        """Analyze user behavior for phishing indicators."""
        try:
            if self.behavior_model is None:
                self.logger.error("Behavior model not loaded")
                return 0.5
            
            # Extract behavior features
            features = [
                len(behavior_data.get('events', [])),
                len(behavior_data.get('interactions', [])),
                len(behavior_data.get('forms', [])),
                behavior_data.get('metadata', {}).get('redirectCount', 0),
                1 if behavior_data.get('metadata', {}).get('hasPasswordField', False) else 0,
                1 if behavior_data.get('metadata', {}).get('hasLoginForm', False) else 0
            ]
            
            # Convert to numpy array and reshape
            features = np.array(features, dtype=np.float32).reshape(1, -1)
            
            # Get prediction
            risk_score = self.behavior_model.predict(features)[0][0]
            
            return float(risk_score)
        except Exception as e:
            self.logger.error(f"Error analyzing behavior: {str(e)}")
            return 0.5
    
    async def analyze_content(self, url=None, visual_data=None, behavior_data=None):
        """Analyze content for phishing using multiple modalities."""
        try:
            results = {
                'risk_score': 0.0,
                'confidence': 0.0,
                'url_risk': 0.0,
                'visual_risk': 0.0,
                'behavior_risk': 0.0,
                'explanations': []
            }
            
            # Analyze URL if provided
            if url:
                url_analysis = self.analyze_url(url)
                results['url_risk'] = url_analysis.get('risk_score', 0.0)
                if url_analysis.get('explanations'):
                    results['explanations'].extend(url_analysis['explanations'])
            
            # Analyze visual content if provided
            if visual_data is not None:
                visual_analysis = self.analyze_visual(visual_data)
                results['visual_risk'] = visual_analysis.get('risk_score', 0.0)
                if visual_analysis.get('explanations'):
                    results['explanations'].extend(visual_analysis['explanations'])
            
            # Analyze behavior if provided
            if behavior_data:
                behavior_analysis = self.analyze_behavior(behavior_data)
                results['behavior_risk'] = behavior_analysis.get('risk_score', 0.0)
                if behavior_analysis.get('explanations'):
                    results['explanations'].extend(behavior_analysis['explanations'])
            
            # Calculate overall risk score
            valid_scores = [
                score for score in [
                    results['url_risk'],
                    results['visual_risk'],
                    results['behavior_risk']
                ] if score > 0
            ]
            
            if valid_scores:
                results['risk_score'] = float(np.mean(valid_scores))
                results['confidence'] = float(1 - np.std(valid_scores))
            else:
                results['risk_score'] = 0.5
                results['confidence'] = 0.0
            
            return results
            
        except Exception as e:
            logger.error(f"Error in phishing content analysis: {str(e)}")
            return {
                'risk_score': 0.5,
                'confidence': 0.0,
                'explanations': ['Error during analysis']
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
            recommendations.append('This URL appears safe to browse.')
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
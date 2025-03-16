import tensorflow as tf
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
import torch
from transformers import BertModel, BertTokenizer
from scipy.stats import entropy
import re
import logging

logger = logging.getLogger(__name__)

class ZeroDayDetector:
    def __init__(self):
        super().__init__()
        self.anomaly_detector = None
        self.feature_extractor = None
        self.initialize_models()

    def initialize_models(self):
        """Initialize anomaly detection and feature extraction models."""
        try:
            # Initialize anomaly detector
            self.anomaly_detector = IsolationForest(
                n_estimators=100,
                contamination=0.1,
                random_state=42
            )
            
            # Initialize feature extractor (using BERT)
            self.feature_extractor = BertModel.from_pretrained('bert-base-uncased')
            self.tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')
            
            # Initialize with some normal patterns
            self._initialize_normal_patterns()
            
            logger.info("Zero-day detection models initialized successfully")
        except Exception as e:
            logger.error(f"Error initializing zero-day detection models: {str(e)}")
            raise

    def _initialize_normal_patterns(self):
        """Initialize detector with some normal patterns."""
        # Example normal patterns for training
        normal_patterns = [
            "GET /index.html HTTP/1.1",
            "POST /login HTTP/1.1",
            "GET /api/v1/users HTTP/1.1",
            "PUT /api/v1/update HTTP/1.1"
        ]
        
        # Extract features from normal patterns
        features = self._extract_features_batch(normal_patterns)
        
        # Fit the anomaly detector
        self.anomaly_detector.fit(features)

    def _extract_features_batch(self, texts):
        """Extract features from a batch of texts."""
        features_list = []
        for text in texts:
            # Tokenize
            inputs = self.tokenizer(
                text,
                return_tensors="pt",
                truncation=True,
                max_length=128,
                padding=True
            )
            
            # Get embeddings
            with torch.no_grad():
                outputs = self.feature_extractor(**inputs)
                embeddings = outputs.last_hidden_state.mean(dim=1)  # Average pooling
            
            features_list.append(embeddings.numpy().flatten())
        
        return np.array(features_list)

    def _extract_features(self, data):
        """Extract features from input data."""
        try:
            # Initialize feature vector
            features = np.zeros(768)  # Match BERT embedding size
            
            # Extract URL features if available
            if 'url' in data and data['url']:
                url_features = self._extract_url_features(data['url'])
                features[:256] = url_features[:256]  # Take first 256 dimensions
            
            # Extract content features if available
            if 'content' in data and data['content']:
                content_features = self._extract_content_features(data['content'])
                features[256:512] = content_features[:256]  # Take next 256 dimensions
            
            # Extract behavior features if available
            if 'behavior' in data and data['behavior']:
                behavior_features = self._extract_behavior_features(data['behavior'])
                features[512:768] = behavior_features[:256]  # Take final 256 dimensions
            
            return features.reshape(1, -1)
            
        except Exception as e:
            logger.error(f"Error extracting features: {str(e)}")
            return np.zeros((1, 768))  # Return zero vector with correct dimensions
            
    def _extract_url_features(self, url):
        """Extract features from URL."""
        try:
            # Initialize feature vector
            features = np.zeros(256)
            
            if not url:
                return features
                
            # Basic URL statistics
            features[0] = len(url)
            features[1] = url.count('/')
            features[2] = url.count('.')
            features[3] = url.count('-')
            features[4] = url.count('_')
            features[5] = sum(c.isdigit() for c in url)
            features[6] = sum(not c.isalnum() for c in url)
            
            # Domain specific features
            from urllib.parse import urlparse
            parsed = urlparse(url)
            features[7] = len(parsed.netloc)
            features[8] = len(parsed.path)
            features[9] = len(parsed.query)
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting URL features: {str(e)}")
            return np.zeros(256)
            
    def _extract_content_features(self, content):
        """Extract features from content."""
        try:
            # Initialize feature vector
            features = np.zeros(256)
            
            if not content:
                return features
                
            # Basic content statistics
            features[0] = len(content)
            features[1] = content.count('\n')
            features[2] = len(content.split())
            features[3] = sum(c.isupper() for c in content)
            features[4] = sum(c.isdigit() for c in content)
            features[5] = sum(c.isspace() for c in content)
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting content features: {str(e)}")
            return np.zeros(256)
            
    def _extract_behavior_features(self, behavior):
        """Extract features from behavior data."""
        try:
            # Initialize feature vector
            features = np.zeros(256)
            
            if not behavior:
                return features
                
            # Extract event counts
            if 'events' in behavior:
                events = behavior['events']
                features[0] = len(events)
                features[1] = sum(1 for e in events if e.get('type') == 'click')
                features[2] = sum(1 for e in events if e.get('type') == 'input')
                features[3] = sum(1 for e in events if e.get('type') == 'submit')
            
            # Extract form data
            if 'forms' in behavior:
                forms = behavior['forms']
                features[4] = len(forms)
                features[5] = sum(1 for f in forms if any(field.get('type') == 'password' for field in f.get('fields', [])))
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting behavior features: {str(e)}")
            return np.zeros(256)

    def analyze_anomalies(self, data):
        """Analyze data for potential zero-day threats."""
        try:
            # Extract features
            features = self._extract_features(data)
            
            if features.size == 0:
                raise ValueError("No features could be extracted from the data")
            
            # Get anomaly scores
            scores = self.anomaly_detector.score_samples(features)
            predictions = self.anomaly_detector.predict(features)
            
            # Convert scores to probabilities
            score = float(scores[0])
            normalized_score = 1.0 / (1.0 + np.exp(-score))  # Sigmoid transformation
            
            # Determine if it's a potential zero-day threat
            is_zero_day = predictions[0] == -1  # -1 indicates anomaly
            
            # Calculate confidence based on the distance from the decision boundary
            confidence = float(abs(normalized_score - 0.5) * 2)  # Scale to [0, 1]
            
            # Analyze specific anomaly patterns
            anomaly_details = self._analyze_anomaly_patterns(data)
            
            return {
                'is_zero_day': bool(is_zero_day),
                'confidence': confidence,
                'anomaly_score': float(normalized_score),
                'anomaly_details': anomaly_details
            }
        except Exception as e:
            logger.error(f"Error in anomaly analysis: {str(e)}")
            return {
                'is_zero_day': False,
                'confidence': 0.0,
                'anomaly_score': 0.0,
                'anomaly_details': {'error': str(e)}
            }

    def _analyze_anomaly_patterns(self, data):
        """Analyze specific patterns that might indicate a zero-day attack."""
        patterns = {}
        
        # Analyze URL patterns
        if 'url' in data:
            url = data['url'].lower()
            patterns['url_analysis'] = {
                'suspicious_chars': bool(re.search(r'[<>\'"]', url)),
                'unusual_params': bool(re.search(r'\?.*?=.*?[;]', url)),
                'encoded_chars': bool(re.search(r'%[0-9a-fA-F]{2}', url))
            }
        
        # Analyze request patterns
        if 'request' in data:
            request = data['request']
            patterns['request_analysis'] = {
                'unusual_headers': any(
                    h for h in request.get('headers', {})
                    if h.lower() not in ['user-agent', 'accept', 'content-type', 'cookie']
                ),
                'payload_patterns': bool(re.search(
                    r'(?i)(select|union|insert|delete|update|drop|exec|eval)',
                    str(request.get('body', ''))
                ))
            }
        
        # Analyze behavior patterns
        if 'behavior' in data:
            behavior = data['behavior']
            patterns['behavior_analysis'] = {
                'rapid_requests': len(behavior.get('events', [])) > 10,
                'suspicious_forms': any(
                    f for f in behavior.get('forms', [])
                    if f.get('submit_count', 0) > 3
                )
            }
        
        return patterns

    def build_autoencoder(self):
        """Build deep autoencoder for anomaly detection"""
        encoder = tf.keras.Sequential([
            tf.keras.layers.Dense(128, activation='relu'),
            tf.keras.layers.Dense(64, activation='relu'),
            tf.keras.layers.Dense(32, activation='relu')
        ])
        
        decoder = tf.keras.Sequential([
            tf.keras.layers.Dense(64, activation='relu'),
            tf.keras.layers.Dense(128, activation='relu'),
            tf.keras.layers.Dense(256, activation='sigmoid')
        ])
        
        autoencoder = tf.keras.Sequential([encoder, decoder])
        autoencoder.compile(optimizer='adam', loss='mse')
        return autoencoder

    async def detect_zero_day_threats(self, url, content, behavior):
        """Detect previously unseen phishing patterns"""
        pattern_anomaly = self.detect_pattern_anomalies(url, content)
        behavior_anomaly = self.detect_behavior_anomalies(behavior)
        structure_anomaly = self.detect_structure_anomalies(content)
        
        return {
            'is_zero_day': any([
                pattern_anomaly['is_anomaly'],
                behavior_anomaly['is_anomaly'],
                structure_anomaly['is_anomaly']
            ]),
            'confidence': self.calculate_detection_confidence([
                pattern_anomaly['score'],
                behavior_anomaly['score'],
                structure_anomaly['score']
            ]),
            'anomaly_details': {
                'pattern': pattern_anomaly,
                'behavior': behavior_anomaly,
                'structure': structure_anomaly
            }
        }

    def detect_pattern_anomalies(self, url, content):
        """Detect anomalous patterns in URL and content"""
        features = self.extract_pattern_features(url, content)
        anomaly_score = self.anomaly_detector.predict([features])[0]
        
        return {
            'is_anomaly': anomaly_score == -1,
            'score': self.calculate_anomaly_score(features),
            'detected_patterns': self.identify_anomalous_patterns(features)
        }

    def detect_behavior_anomalies(self, behavior):
        """Detect anomalous behavior patterns using multiple techniques"""
        behavior_features = self.extract_behavior_features(behavior)
        
        # Scale features
        scaled_features = self.scaler.fit_transform(behavior_features.reshape(1, -1))
        
        # Isolation Forest detection
        if_score = self.anomaly_detector.predict(scaled_features)[0]
        
        # Autoencoder reconstruction error
        reconstructed = self.autoencoder.predict(scaled_features)
        reconstruction_error = np.mean(np.power(scaled_features - reconstructed, 2))
        
        # PCA transformation for dimensionality reduction
        pca_features = self.pca.fit_transform(scaled_features)
        pca_reconstructed = self.pca.inverse_transform(pca_features)
        pca_error = np.mean(np.power(scaled_features - pca_reconstructed, 2))
        
        # Combine scores
        anomaly_score = self.combine_anomaly_scores([
            if_score == -1,
            reconstruction_error > self.anomaly_threshold,
            pca_error > self.anomaly_threshold
        ])
        
        return {
            'is_anomaly': anomaly_score > self.anomaly_threshold,
            'score': anomaly_score,
            'anomalous_behaviors': self.identify_anomalous_behaviors(behavior),
            'detection_method': self.get_detection_method(if_score, reconstruction_error, pca_error)
        }

    def detect_structure_anomalies(self, content):
        """Detect anomalies in page structure using BERT and pattern analysis"""
        # Extract structure features
        structure_features = self.extract_structure_features(content)
        
        # Get BERT embeddings for content
        inputs = self.tokenizer(content, return_tensors="pt", truncation=True, max_length=512)
        with torch.no_grad():
            outputs = self.feature_extractor(**inputs)
        embeddings = outputs.last_hidden_state.mean(dim=1)
        
        # Combine with structure features
        combined_features = np.concatenate([
            structure_features,
            embeddings.numpy().flatten()
        ])
        
        # Scale and detect anomalies
        scaled_features = self.scaler.fit_transform(combined_features.reshape(1, -1))
        if_score = self.anomaly_detector.predict(scaled_features)[0]
        
        return {
            'is_anomaly': if_score == -1,
            'score': self.calculate_anomaly_score(scaled_features),
            'structural_anomalies': self.identify_structural_anomalies(content),
            'semantic_analysis': self.analyze_semantic_structure(embeddings)
        }

    def combine_anomaly_scores(self, scores):
        """Combine multiple anomaly detection scores"""
        weights = [0.4, 0.3, 0.3]  # Weights for different detection methods
        return sum(w * s for w, s in zip(weights, scores))
        
    def get_detection_method(self, if_score, recon_error, pca_error):
        """Determine which method detected the anomaly"""
        methods = []
        if if_score == -1:
            methods.append('Isolation Forest')
        if recon_error > self.anomaly_threshold:
            methods.append('Autoencoder')
        if pca_error > self.anomaly_threshold:
            methods.append('PCA')
        return methods if methods else ['No significant anomalies detected']
        
    def analyze_semantic_structure(self, embeddings):
        """Analyze semantic structure of content"""
        # Compare with known patterns
        similarity_scores = self.calculate_semantic_similarity(embeddings)
        return {
            'semantic_coherence': float(similarity_scores.mean()),
            'unusual_patterns': self.identify_unusual_patterns(similarity_scores),
            'confidence': self.calculate_confidence_score(similarity_scores)
        }

    def calculate_detection_confidence(self, scores):
        """Calculate detection confidence based on anomaly scores"""
        # This is a placeholder implementation. You might want to implement a more robust confidence calculation
        # based on your specific requirements.
        return np.mean(scores)

    def calculate_anomaly_score(self, features):
        """Calculate anomaly score based on features"""
        # This is a placeholder implementation. You might want to implement a more robust anomaly score calculation
        # based on your specific requirements.
        return np.mean(features)

    def identify_anomalous_patterns(self, features):
        """Identify anomalous patterns in features"""
        # This is a placeholder implementation. You might want to implement a more robust pattern identification
        # based on your specific requirements.
        return []

    def identify_anomalous_behaviors(self, behavior):
        """Identify anomalous behavior patterns"""
        # This is a placeholder implementation. You might want to implement a more robust behavior identification
        # based on your specific requirements.
        return []

    def identify_structural_anomalies(self, content):
        """Identify structural anomalies in content"""
        # This is a placeholder implementation. You might want to implement a more robust structural anomaly identification
        # based on your specific requirements.
        return []

    def extract_pattern_features(self, url, content):
        """Extract features from URL and content"""
        # This is a placeholder implementation. You might want to implement a more robust feature extraction
        # based on your specific requirements.
        return []

    def extract_behavior_features(self, behavior):
        """Extract features from behavior"""
        # This is a placeholder implementation. You might want to implement a more robust behavior feature extraction
        # based on your specific requirements.
        return []

    def extract_structure_features(self, content):
        """Extract features from content"""
        # This is a placeholder implementation. You might want to implement a more robust structure feature extraction
        # based on your specific requirements.
        return []

    def calculate_behavior_entropy(self, behavior_features):
        """Calculate behavior entropy"""
        # This is a placeholder implementation. You might want to implement a more robust behavior entropy calculation
        # based on your specific requirements.
        return 0.0

    def calculate_semantic_similarity(self, embeddings):
        """Calculate semantic similarity between embeddings"""
        # This is a placeholder implementation. You might want to implement a more robust semantic similarity calculation
        # based on your specific requirements.
        return []

    def identify_unusual_patterns(self, similarity_scores):
        """Identify unusual patterns in similarity scores"""
        # This is a placeholder implementation. You might want to implement a more robust unusual pattern identification
        # based on your specific requirements.
        return []

    def calculate_confidence_score(self, similarity_scores):
        """Calculate confidence score based on similarity scores"""
        # This is a placeholder implementation. You might want to implement a more robust confidence score calculation
        # based on your specific requirements.
        return 0.0 
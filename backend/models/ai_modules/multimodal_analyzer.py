import tensorflow as tf
import torch
from transformers import CLIPProcessor, CLIPModel
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import logging
from collections import Counter
from PIL import Image

logger = logging.getLogger(__name__)

class MultiModalAnalyzer:
    def __init__(self):
        super().__init__()
        self.clip_model = None
        self.ensemble_model = None
        self.text_tokenizer = None
        self.visual_processor = None
        self.initialize_models()
        self.data_adapters = {
            'image': self._adapt_image_data,
            'text': self._adapt_text_data,
            'behavior': self._adapt_behavior_data
        }
        self.feature_importance = {}
        
    def initialize_models(self):
        self.clip_model = CLIPModel.from_pretrained("openai/clip-vit-base-patch32")
        self.clip_processor = CLIPProcessor.from_pretrained("openai/clip-vit-base-patch32")
        self.ensemble_model = self.build_ensemble_model()
        
    def build_ensemble_model(self):
        """Build ensemble model for combining multiple modalities"""
        return RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        
    async def analyze_content(self, text_data, visual_data, behavior_data):
        """Perform multi-modal content analysis"""
        try:
            # Get embeddings from each modality
            text_features = await self.extract_text_features(text_data)
            visual_features = await self.extract_visual_features(visual_data)
            behavior_features = await self.extract_behavior_features(behavior_data)
            
            # Combine features
            combined_features = np.concatenate([
                text_features.reshape(1, -1),
                visual_features.reshape(1, -1),
                behavior_features.reshape(1, -1)
            ], axis=1)
            
            # Train the model with some initial data if not trained
            if not hasattr(self.ensemble_model, 'n_features_in_'):
                X_train = np.random.rand(100, combined_features.shape[1])
                y_train = np.random.randint(0, 2, 100)
                self.ensemble_model.fit(X_train, y_train)
            
            # Get predictions and confidence scores
            predictions = self.ensemble_model.predict_proba(combined_features)[0]
            
            # Calculate feature importance
            self.update_feature_importance(combined_features)
            
            return {
                'risk_score': float(predictions[1]),  # Probability of malicious class
                'confidence': self.calculate_confidence(predictions),
                'modality_scores': {
                    'text': self.calculate_modality_score(text_features),
                    'visual': self.calculate_modality_score(visual_features),
                    'behavior': self.calculate_modality_score(behavior_features)
                },
                'feature_importance': self.feature_importance,
                'anomaly_score': self.detect_cross_modal_anomalies(
                    text_features, visual_features, behavior_features
                )
            }
            
        except Exception as e:
            logger.error(f"Error in multi-modal analysis: {str(e)}")
            return None
            
    async def extract_text_features(self, text_data):
        """Extract features from text content"""
        try:
            # Process text with CLIP
            text_inputs = self.clip_processor(
                text=[text_data],
                return_tensors="pt",
                padding=True,
                truncation=True
            )
            
            # Get text embeddings
            with torch.no_grad():
                text_features = self.clip_model.get_text_features(**text_inputs)
                
            return text_features.numpy()
            
        except Exception as e:
            logger.error(f"Error extracting text features: {str(e)}")
            return np.zeros((1, 512))  # Default feature size
            
    async def extract_visual_features(self, visual_data):
        """Extract features from visual content"""
        try:
            # Process image with CLIP
            image_inputs = self.clip_processor(
                images=visual_data,
                return_tensors="pt"
            )
            
            # Get image embeddings
            with torch.no_grad():
                image_features = self.clip_model.get_image_features(**image_inputs)
                
            return image_features.numpy()
            
        except Exception as e:
            logger.error(f"Error extracting visual features: {str(e)}")
            return np.zeros((1, 512))  # Default feature size
            
    async def extract_behavior_features(self, behavior_data):
        """Extract features from behavior data"""
        try:
            features = []
            
            # Extract temporal features
            if 'events' in behavior_data:
                features.extend(self.extract_temporal_features(behavior_data['events']))
                
            # Extract interaction features
            if 'interactions' in behavior_data:
                features.extend(self.extract_interaction_features(behavior_data['interactions']))
                
            # Extract form features
            if 'forms' in behavior_data:
                features.extend(self.extract_form_features(behavior_data['forms']))
                
            # Pad or truncate to fixed size
            target_size = 512  # Match other feature sizes
            if len(features) > target_size:
                features = features[:target_size]
            else:
                features.extend([0] * (target_size - len(features)))
                
            return np.array(features).reshape(1, -1)
            
        except Exception as e:
            logger.error(f"Error extracting behavior features: {str(e)}")
            return np.zeros((1, 512))  # Default feature size
            
    def extract_temporal_features(self, events):
        """Extract temporal patterns from events"""
        if not events:
            return [0] * 32
            
        features = []
        timestamps = [e.get('timestamp', 0) for e in events]
        
        # Calculate time-based features
        features.extend([
            np.mean(np.diff(timestamps)),  # Average time between events
            np.std(np.diff(timestamps)),   # Variance in time between events
            len(events),                   # Number of events
            max(timestamps) - min(timestamps)  # Total session duration
        ])
        
        # Pad to fixed size
        features.extend([0] * (32 - len(features)))
        return features
        
    def extract_interaction_features(self, interactions):
        """Extract user interaction patterns"""
        if not interactions:
            return [0] * 32
            
        features = []
        
        # Count different types of interactions
        interaction_types = Counter(i.get('type') for i in interactions)
        
        features.extend([
            interaction_types.get('click', 0),
            interaction_types.get('scroll', 0),
            interaction_types.get('keypress', 0),
            interaction_types.get('mousemove', 0)
        ])
        
        # Pad to fixed size
        features.extend([0] * (32 - len(features)))
        return features
        
    def extract_form_features(self, forms):
        """Extract features from form interactions"""
        if not forms:
            return [0] * 32
            
        features = []
        
        # Analyze form fields and interactions
        for form in forms:
            fields = form.get('fields', [])
            features.extend([
                len(fields),
                sum(1 for f in fields if f.get('type') == 'password'),
                sum(1 for f in fields if f.get('type') == 'hidden'),
                form.get('submit_count', 0)
            ])
            
        # Pad to fixed size
        features.extend([0] * (32 - len(features)))
        return features
        
    def detect_cross_modal_anomalies(self, text_features, visual_features, behavior_features):
        """Detect anomalies across different modalities"""
        try:
            # Flatten features
            text_flat = text_features.flatten()
            visual_flat = visual_features.flatten()
            behavior_flat = behavior_features.flatten()
            
            # Calculate correlation between modalities
            text_visual_corr = np.corrcoef(text_flat, visual_flat)[0, 1]
            text_behavior_corr = np.corrcoef(text_flat, behavior_flat)[0, 1]
            visual_behavior_corr = np.corrcoef(visual_flat, behavior_flat)[0, 1]
            
            # Average correlation as anomaly score
            anomaly_score = 1 - np.mean([
                abs(text_visual_corr),
                abs(text_behavior_corr),
                abs(visual_behavior_corr)
            ])
            
            return float(anomaly_score)
            
        except Exception as e:
            logger.error(f"Error detecting cross-modal anomalies: {str(e)}")
            return 0.5
            
    def calculate_confidence(self, predictions):
        """Calculate confidence score for predictions"""
        # Use prediction probability spread as confidence
        return float(abs(predictions[1] - predictions[0]))
        
    def calculate_modality_score(self, features):
        """Calculate risk score for individual modality"""
        try:
            # Use feature statistics as score
            return float(np.mean(np.abs(features)))
        except Exception as e:
            logger.error(f"Error calculating modality score: {str(e)}")
            return 0.5
            
    def update_feature_importance(self, features):
        """Update feature importance tracking"""
        try:
            importances = self.ensemble_model.feature_importances_
            feature_size = features.shape[1] // 3
            self.feature_importance = {
                'text': float(np.mean(importances[:feature_size])),
                'visual': float(np.mean(importances[feature_size:2*feature_size])),
                'behavior': float(np.mean(importances[2*feature_size:]))
            }
        except Exception as e:
            logger.error(f"Error updating feature importance: {str(e)}")
            self.feature_importance = {
                'text': 0.33,
                'visual': 0.33,
                'behavior': 0.34
            } 

    def _adapt_image_data(self, image_data):
        """Convert image data to tensor format."""
        if isinstance(image_data, Image.Image):
            # Convert PIL Image to numpy array
            image_array = np.array(image_data)
            # Ensure correct shape and normalization
            if len(image_array.shape) == 2:  # Grayscale
                image_array = np.stack([image_array] * 3, axis=-1)
            elif len(image_array.shape) == 3 and image_array.shape[-1] == 4:  # RGBA
                image_array = image_array[..., :3]
            # Normalize to [0, 1]
            image_array = image_array.astype(np.float32) / 255.0
            # Resize if needed
            if image_array.shape[:2] != (224, 224):
                image = Image.fromarray((image_array * 255).astype(np.uint8))
                image = image.resize((224, 224), Image.LANCZOS)
                image_array = np.array(image).astype(np.float32) / 255.0
            return image_array
        return None

    def _adapt_text_data(self, text_data):
        """Convert text data to appropriate format."""
        if isinstance(text_data, str):
            return text_data
        elif isinstance(text_data, (list, tuple)) and all(isinstance(t, str) for t in text_data):
            return ' '.join(text_data)
        return None

    def _adapt_behavior_data(self, behavior_data):
        """Convert behavior data to feature vector."""
        if isinstance(behavior_data, dict):
            features = []
            # Extract relevant features from behavior data
            features.extend([
                len(behavior_data.get('events', [])),
                len(behavior_data.get('interactions', [])),
                len(behavior_data.get('forms', [])),
                behavior_data.get('metadata', {}).get('redirectCount', 0),
                1 if behavior_data.get('metadata', {}).get('hasPasswordField', False) else 0,
                1 if behavior_data.get('metadata', {}).get('hasLoginForm', False) else 0
            ])
            return np.array(features, dtype=np.float32)
        return None

    def extract_features(self, text_data=None, visual_data=None, behavior_data=None):
        """Extract features from multiple modalities."""
        features = {}
        
        # Adapt and extract text features
        if text_data is not None:
            adapted_text = self._adapt_text_data(text_data)
            if adapted_text is not None:
                features['text'] = self._extract_text_features(adapted_text)
        
        # Adapt and extract visual features
        if visual_data is not None:
            adapted_image = self._adapt_image_data(visual_data)
            if adapted_image is not None:
                features['visual'] = self._extract_visual_features(adapted_image)
        
        # Adapt and extract behavior features
        if behavior_data is not None:
            adapted_behavior = self._adapt_behavior_data(behavior_data)
            if adapted_behavior is not None:
                features['behavior'] = adapted_behavior
        
        return features 
import tensorflow as tf
import torch
from transformers import ViTImageProcessor, ViTForImageClassification
from transformers import BertTokenizer, BertForSequenceClassification
import numpy as np
from PIL import Image
from tensorflow.keras.applications import ResNet50
from tensorflow.keras.layers import GlobalAveragePooling2D
from tensorflow.keras.models import Model
import logging
from transformers import RobertaForSequenceClassification, RobertaTokenizer
from tensorflow.keras.layers import Dense, Dropout
from tensorflow.keras.models import Sequential

logger = logging.getLogger(__name__)

class AgeVerificationSystem:
    def __init__(self):
        super().__init__()
        self.text_model = None
        self.visual_model = None
        self.initialize_models()
        
        # Age-restricted content patterns
        self.age_restricted_patterns = self.load_age_restricted_patterns()
        
    def initialize_models(self):
        """Initialize text and visual models."""
        try:
            # Initialize text analysis model
            self.text_model = RobertaForSequenceClassification.from_pretrained('roberta-base', num_labels=4)  # age categories
            self.text_tokenizer = RobertaTokenizer.from_pretrained('roberta-base')
            
            # Initialize visual analysis model
            self.visual_model = ResNet50(weights='imagenet', include_top=False, input_shape=(224, 224, 3))
            self.visual_model = Model(inputs=self.visual_model.input, outputs=GlobalAveragePooling2D()(self.visual_model.output))
            
            logger.info("Age verification models initialized successfully")
        except Exception as e:
            logger.error(f"Error initializing age verification models: {str(e)}")
            raise

    def load_age_restricted_patterns(self):
        """Load patterns indicating age-restricted content"""
        return {
            'adult_content': ['explicit', 'adult', 'nsfw', '18+', 'xxx'],
            'violence': ['gore', 'violent', 'graphic', 'blood'],
            'gambling': ['casino', 'bet', 'poker', 'gambling'],
            'alcohol': ['alcohol', 'beer', 'wine', 'liquor'],
            'tobacco': ['cigarette', 'tobacco', 'smoking', 'vape']
        }

    def analyze_image_regions(self, image_data):
        """Analyze different regions of an image for age-restricted content."""
        try:
            if not isinstance(image_data, Image.Image):
                logger.error("Invalid image format")
                return {'is_restricted': False, 'confidence': 0.0, 'regions': []}
            
            # Convert image to array and preprocess
            image_array = np.array(image_data)
            if len(image_array.shape) == 2:  # Grayscale
                image_array = np.stack([image_array] * 3, axis=-1)
            elif len(image_array.shape) == 3 and image_array.shape[-1] == 4:  # RGBA
                image_array = image_array[..., :3]
            
            # Resize for model
            if image_array.shape[:2] != (224, 224):
                image = Image.fromarray(image_array)
                image = image.resize((224, 224), Image.LANCZOS)
                image_array = np.array(image)
            
            # Normalize
            image_array = image_array.astype(np.float32) / 255.0
            
            # Add batch dimension
            image_array = np.expand_dims(image_array, axis=0)
            
            # Get predictions
            features = self.visual_model.predict(image_array)
            
            # Simple scoring based on feature activation patterns
            region_scores = []
            height, width = image_array.shape[1:3]
            
            # Analyze regions (simplified for demo)
            regions = [
                (0, 0, width//2, height//2),
                (width//2, 0, width, height//2),
                (0, height//2, width//2, height),
                (width//2, height//2, width, height)
            ]
            
            for i, (x1, y1, x2, y2) in enumerate(regions):
                region_array = image_array[:, y1:y2, x1:x2, :]
                region_features = self.visual_model.predict(region_array)
                score = float(np.mean(region_features))
                region_scores.append({
                    'region': f'Region {i+1}',
                    'coordinates': [int(x1), int(y1), int(x2), int(y2)],
                    'score': score
                })
            
            # Determine if image is restricted based on region scores
            max_score = max(r['score'] for r in region_scores)
            is_restricted = max_score > 0.7  # Threshold for restriction
            
            return {
                'is_restricted': is_restricted,
                'confidence': float(max_score),
                'regions': region_scores
            }
        except Exception as e:
            logger.error(f"Error analyzing image regions: {str(e)}")
            return {
                'is_restricted': False,
                'confidence': 0.0,
                'regions': []
            }

    def analyze_text_content(self, text):
        """Analyze text content for age-restricted material."""
        try:
            if not text:
                return {'is_restricted': False, 'age_level': 'all', 'confidence': 0.0}
            
            # Tokenize text
            inputs = self.text_tokenizer(text, return_tensors="pt", truncation=True, max_length=512, padding=True)
            
            # Get prediction
            with torch.no_grad():
                outputs = self.text_model(**inputs)
                probabilities = torch.softmax(outputs.logits, dim=1)
                prediction = torch.argmax(probabilities, dim=1).item()
                confidence = torch.max(probabilities).item()
            
            # Map prediction to age levels
            age_levels = ['all', '13+', '16+', '18+']
            age_level = age_levels[prediction]
            
            # Check for restricted keywords
            restricted_keywords = ['adult', 'explicit', 'mature', 'nsfw', 'violence']
            found_keywords = [word for word in restricted_keywords if word in text.lower()]
            
            is_restricted = age_level != 'all' or len(found_keywords) > 0
            
            return {
                'is_restricted': is_restricted,
                'age_level': age_level,
                'confidence': float(confidence),
                'found_keywords': found_keywords if found_keywords else None
            }
        except Exception as e:
            logger.error(f"Error analyzing text content: {str(e)}")
            return {
                'is_restricted': False,
                'age_level': 'all',
                'confidence': 0.0
            }

    async def analyze_content(self, text=None, image_data=None):
        """Analyze content for age restrictions."""
        try:
            # Analyze text if provided
            text_analysis = await self.analyze_text_content(text) if text else {
                'is_restricted': False,
                'age_level': 'all',
                'confidence': 0.0
            }
            
            # Analyze image if provided
            image_analysis = self.analyze_image_regions(image_data) if image_data else {
                'is_restricted': False,
                'confidence': 0.0,
                'regions': []
            }
            
            # Analyze metadata
            metadata_results = self.analyze_metadata({})
            
            # Determine final restriction status
            restriction_status = self.determine_restriction_status(
                image_analysis,
                text_analysis,
                metadata_results
            )
            
            return {
                'is_restricted': restriction_status['is_restricted'],
                'confidence': restriction_status['confidence'],
                'age_level': restriction_status['restriction_level'],
                'reasons': restriction_status['reasons'],
                'text_analysis': text_analysis,
                'image_analysis': image_analysis
            }
        except Exception as e:
            logger.error(f"Error in content analysis: {str(e)}")
            return {
                'is_restricted': False,
                'age_level': 'all',
                'confidence': 0.0,
                'reasons': ['Error performing analysis']
            }

    def analyze_metadata(self, metadata):
        """Analyze page metadata for age indicators"""
        age_declarations = self.extract_age_declarations(metadata)
        content_warnings = self.extract_content_warnings(metadata)
        
        return {
            'age_declarations': age_declarations,
            'content_warnings': content_warnings,
            'regulatory_compliance': self.check_regulatory_compliance(metadata),
            'age_gate_present': self.detect_age_gate(metadata)
        }

    def determine_restriction_status(self, visual_score, text_score, metadata_score):
        """Determine if content should be age-restricted using weighted analysis"""
        # Weight the different components
        weights = {
            'visual': 0.4,
            'text': 0.4,
            'metadata': 0.2
        }
        
        weighted_score = (
            weights['visual'] * visual_score['risk_score'] +
            weights['text'] * text_score['content_rating']['score'] +
            weights['metadata'] * self.calculate_metadata_score(metadata_score)
        )
        
        restriction_info = {
            'is_restricted': weighted_score > 0.6,
            'confidence': min(weighted_score * 1.5, 1.0),
            'restriction_level': self.determine_age_level(weighted_score),
            'reasons': self.compile_restriction_reasons(visual_score, text_score, metadata_score)
        }
        
        return restriction_info
        
    def determine_age_level(self, risk_score):
        """Determine appropriate age restriction level"""
        if risk_score > 0.8:
            return 18
        elif risk_score > 0.6:
            return 16
        elif risk_score > 0.4:
            return 13
        return 0
        
    def compile_restriction_reasons(self, visual_score, text_score, metadata_score):
        """Compile detailed reasons for age restriction"""
        reasons = []
        
        if visual_score['risk_score'] > 0.6:
            reasons.extend([f"Visual content: {elem}" for elem in visual_score['detected_elements']])
            
        if text_score['content_rating']['score'] > 0.6:
            reasons.extend([f"Text content: {term}" for term in text_score['sensitive_terms']])
            
        if metadata_score['age_declarations']:
            reasons.extend([f"Metadata: {decl}" for decl in metadata_score['age_declarations']])
            
        return reasons 
import tensorflow as tf
import torch
import transformers
from tensorflow.keras.applications import VGG16, ResNet50
from transformers import RobertaTokenizer, RobertaModel, DistilBertTokenizer, DistilBertModel, CLIPProcessor, CLIPModel

class DeepLearningAnalyzer:
    def __init__(self):
        self.image_model = self.load_image_model()
        self.text_model = self.load_text_model()
        self.behavior_model = self.load_behavior_model()
        self.tokenizer = RobertaTokenizer.from_pretrained('roberta-base')
        self.clip_model = CLIPModel.from_pretrained("openai/clip-vit-base-patch32")
        self.clip_processor = CLIPProcessor.from_pretrained("openai/clip-vit-base-patch32")
        
    def load_image_model(self):
        """Load models for visual analysis including CLIP"""
        # Load pre-trained models for visual analysis
        base_model_vgg = VGG16(weights='imagenet', include_top=False)
        base_model_resnet = ResNet50(weights='imagenet', include_top=False)
        
        return {
            'vgg': base_model_vgg,
            'resnet': base_model_resnet
        }
    
    def load_text_model(self):
        """Load RoBERTa model for advanced URL and text analysis"""
        model = RobertaModel.from_pretrained('roberta-base')
        # Freeze base layers for transfer learning
        for param in model.base_model.parameters():
            param.requires_grad = False
        return model
    
    def load_behavior_model(self):
        # Custom behavior analysis model
        return tf.keras.models.Sequential([
            tf.keras.layers.LSTM(128, input_shape=(None, 50)),
            tf.keras.layers.Dense(64, activation='relu'),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(1, activation='sigmoid')
        ])

    async def analyze_visual_elements(self, image, brand_name=None):
        """Deep learning-based visual analysis with CLIP"""
        # Traditional CNN features
        features_vgg = self.image_model['vgg'].predict(image)
        features_resnet = self.image_model['resnet'].predict(image)
        
        # CLIP analysis for brand comparison
        if brand_name:
            # Process image and text with CLIP
            image_features = self.clip_processor(images=image, return_tensors="pt")
            text_features = self.clip_processor(text=[f"logo of {brand_name}", f"{brand_name} website"], return_tensors="pt")
            
            # Get similarity scores
            with torch.no_grad():
                image_features = self.clip_model.get_image_features(**image_features)
                text_features = self.clip_model.get_text_features(**text_features)
                similarity = torch.nn.functional.cosine_similarity(image_features, text_features)
        
        return {
            'vgg_features': features_vgg,
            'resnet_features': features_resnet,
            'similarity_score': self.calculate_similarity_score(features_vgg, features_resnet),
            'brand_similarity': float(similarity.mean()) if brand_name else None,
            'visual_elements': self.detect_visual_elements(image)
        }

    async def analyze_text_content(self, text):
        """Advanced NLP analysis using RoBERTa"""
        inputs = self.tokenizer(text, return_tensors="pt", truncation=True, max_length=512, padding=True)
        outputs = self.text_model(**inputs)
        
        # Get embeddings from last hidden state
        embeddings = outputs.last_hidden_state.mean(dim=1)  # Average pooling
        
        # Calculate attention scores for interpretability
        attention_weights = outputs.attentions[-1].mean(dim=1) if outputs.attentions else None
        
        # Extract semantic features
        semantic_score = self.calculate_semantic_score(embeddings)
        
        return {
            'embeddings': embeddings.detach().numpy(),
            'attention': attention_weights.detach().numpy() if attention_weights is not None else None,
            'semantic_score': semantic_score,
            'feature_importance': self.get_feature_importance(attention_weights) if attention_weights is not None else None
        }

    async def analyze_user_behavior(self, behavior_data):
        """LSTM-based behavior analysis"""
        sequence = self.preprocess_behavior_data(behavior_data)
        prediction = self.behavior_model.predict(sequence)
        
        return {
            'risk_score': float(prediction[0]),
            'patterns': self.extract_behavior_patterns(sequence),
            'anomalies': self.detect_behavior_anomalies(sequence)
        }

    def calculate_semantic_score(self, embeddings):
        """Calculate semantic similarity score using cosine similarity"""
        # Compare with known phishing patterns
        phishing_patterns = self.get_phishing_patterns()
        similarities = torch.nn.functional.cosine_similarity(embeddings, phishing_patterns)
        return float(similarities.mean())

    def detect_visual_elements(self, image):
        """Detect and analyze specific visual elements"""
        elements = {
            'logos': self.detect_logos(image),
            'input_fields': self.detect_input_fields(image),
            'security_indicators': self.detect_security_indicators(image),
            'layout_structure': self.analyze_layout(image)
        }
        return elements 
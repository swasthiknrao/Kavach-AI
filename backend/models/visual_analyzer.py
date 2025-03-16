import cv2
import numpy as np
import tensorflow as tf
import keras
from keras.applications import ResNet50
from keras.applications.resnet50 import preprocess_input
from sklearn.metrics.pairwise import cosine_similarity
import re
from collections import Counter
import logging
import base64
from io import BytesIO
from PIL import Image
import scipy.ndimage as ndi

# Configure logging
logger = logging.getLogger(__name__)

class VisualAnalyzer:
    def __init__(self):
        try:
            # Load the models and initialize parameters
            self.base_model = ResNet50(weights='imagenet', include_top=False)
            logger.info("ResNet model loaded successfully")
            self.known_logos = self.load_known_logos()
            self.similarity_threshold = 0.85
            
            # Enhanced suspicious word detection with weighted categories
            self.suspicious_words = {
                # Login and credentials (high weight)
                'login': 0.08, 'password': 0.08, 'verify': 0.07, 'account': 0.06, 
                'secure': 0.06, 'authentication': 0.08, 'signin': 0.08,
                
                # Financial terms (medium-high weight)
                'bank': 0.07, 'paypal': 0.08, 'credit': 0.06, 'debit': 0.06, 
                'card': 0.05, 'payment': 0.06, 'billing': 0.07,
                
                # Security related (medium weight)
                'security': 0.05, 'update': 0.04, 'confirm': 0.05, 'authenticate': 0.06,
                'verification': 0.06, 'validate': 0.05, 'identity': 0.05,
                
                # Urgent action (high weight)
                'urgent': 0.09, 'immediately': 0.08, 'required': 0.06, 'action': 0.05,
                'limited': 0.07, 'expires': 0.07, 'warning': 0.08
            }
            
            # Color patterns commonly used in phishing (brand colors)
            self.suspicious_color_schemes = {
                'paypal': {'primary': [0, 102, 255], 'secondary': [253, 216, 53]},
                'facebook': {'primary': [66, 103, 178], 'secondary': [255, 255, 255]},
                'microsoft': {'primary': [242, 80, 34], 'secondary': [127, 186, 0]},
                'apple': {'primary': [128, 128, 128], 'secondary': [255, 255, 255]},
                'amazon': {'primary': [254, 153, 0], 'secondary': [0, 0, 0]},
                'google': {'primary': [66, 133, 244], 'secondary': [219, 68, 55]}
            }
            
            # Initialize OpenCV feature detector for logo matching
            self.feature_detector = cv2.SIFT_create()
            logger.info("Visual analyzer initialized successfully")
            
        except Exception as e:
            logger.error(f"Error initializing VisualAnalyzer: {e}")
            # Still create a basic object that won't crash when used
            self.suspicious_words = {'login': 0.08, 'password': 0.08}

    def load_known_logos(self):
        # In a real implementation, we would load preprocessed logos here
        # For now, return a dictionary with information about international variants
        return {
            'wikipedia': {
                'base_domain': 'wikipedia.org',
                'international_variants': [
                    {'domain': 'en.wikipedia.org', 'language': 'English'},
                    {'domain': 'ja.wikipedia.org', 'language': 'Japanese'},
                    {'domain': 'de.wikipedia.org', 'language': 'German'},
                    {'domain': 'fr.wikipedia.org', 'language': 'French'},
                    {'domain': 'es.wikipedia.org', 'language': 'Spanish'},
                    {'domain': 'ru.wikipedia.org', 'language': 'Russian'},
                    {'domain': 'zh.wikipedia.org', 'language': 'Chinese'},
                    {'domain': 'ar.wikipedia.org', 'language': 'Arabic'},
                    # Add more language codes as needed
                ],
                'visual_elements': [
                    'puzzle globe logo', 'left sidebar', 'article layout', 
                    'edit button', 'language links', 'references section'
                ],
                'color_scheme': ['#f8f9fa', '#eaecf0', '#202122', '#3366cc']
            },
            'google': {
                'base_domain': 'google.com',
                'international_variants': [
                    {'domain': 'google.co.jp', 'language': 'Japanese'},
                    {'domain': 'google.de', 'language': 'German'},
                    {'domain': 'google.co.uk', 'language': 'British English'},
                    {'domain': 'google.fr', 'language': 'French'},
                    {'domain': 'google.com.br', 'language': 'Brazilian Portuguese'}
                ],
                'visual_elements': [
                    'colorful logo', 'search bar', 'minimalist design', 
                    'app grid icon', 'sign in button'
                ],
                'color_scheme': ['#4285f4', '#ea4335', '#fbbc05', '#34a853', '#ffffff']
            },
            'amazon': {
                'base_domain': 'amazon.com',
                'international_variants': [
                    {'domain': 'amazon.co.jp', 'language': 'Japanese'},
                    {'domain': 'amazon.de', 'language': 'German'},
                    {'domain': 'amazon.co.uk', 'language': 'British English'},
                    {'domain': 'amazon.fr', 'language': 'French'},
                    {'domain': 'amazon.it', 'language': 'Italian'}
                ],
                'visual_elements': [
                    'amazon smile logo', 'search bar', 'shopping cart', 
                    'product grid', 'navigation menu'
                ],
                'color_scheme': ['#232f3e', '#ff9900', '#ffffff', '#146eb4']
            }
        }

    def extract_features(self, image):
        """Extract visual features from an image for comparison and analysis"""
        try:
            # Preprocess the image for ResNet
            img_array = np.array(image)
            
            # Handle different image formats and color channels
            if len(img_array.shape) == 2:  # Grayscale
                img_array = np.stack((img_array,) * 3, axis=-1)
            elif img_array.shape[2] == 4:  # RGBA
                img_array = img_array[:, :, :3]
                
            # Resize for the model
            img_resized = cv2.resize(img_array, (224, 224))
            img_preprocessed = preprocess_input(np.expand_dims(img_resized, axis=0))
            
            # Extract features using ResNet
            features = self.base_model.predict(img_preprocessed)
            flattened_features = features.flatten()
            
            return flattened_features
        except Exception as e:
            logger.error(f"Error extracting visual features: {e}")
            return np.zeros(2048)  # Return empty features on error

    def detect_logos(self, image):
        """Detect logos using OpenCV feature matching"""
        try:
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            logos = []
            
            # Get keypoints and descriptors for the image
            keypoints, descriptors = self.feature_detector.detectAndCompute(gray, None)
            
            if descriptors is None:
                return []
                
            # Template matching with known logos
            for name, template_data in self.known_logos.items():
                if 'descriptors' in template_data:
                    # Use FLANN based matcher for faster matching
                    FLANN_INDEX_KDTREE = 1
                    index_params = dict(algorithm=FLANN_INDEX_KDTREE, trees=5)
                    search_params = dict(checks=50)
                    flann = cv2.FlannBasedMatcher(index_params, search_params)
                    
                    matches = flann.knnMatch(template_data['descriptors'], descriptors, k=2)
                    
                    # Apply ratio test
                    good_matches = []
                    for m, n in matches:
                        if m.distance < 0.7 * n.distance:
                            good_matches.append(m)
                    
                    if len(good_matches) > 10:
                        logos.append({'name': name, 'confidence': len(good_matches) / 100})
            
            return logos
        except Exception as e:
            logger.error(f"Error detecting logos: {e}")
            return []

    def analyze_layout(self, image):
        """Analyze page structure and layout for phishing indicators"""
        try:
            # Convert to grayscale
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            
            # Apply edge detection
            edges = cv2.Canny(gray, 100, 200)
            
            # Dilate edges to connect nearby edges
            kernel = np.ones((3, 3), np.uint8)
            dilated = cv2.dilate(edges, kernel, iterations=1)
            
            # Find contours
            contours, hierarchy = cv2.findContours(dilated, cv2.RETR_TREE, cv2.CHAIN_APPROX_SIMPLE)
            
            # Extract layout features
            layout_features = {
                'num_elements': len(contours),
                'symmetry': self.calculate_symmetry(contours, image.shape),
                'density': len(contours) / (image.shape[0] * image.shape[1]),
                'form_regions': self.detect_form_regions(gray, contours),
                'layout_complexity': self.calculate_layout_complexity(contours, image.shape)
            }
            
            return layout_features
        except Exception as e:
            logger.error(f"Error analyzing layout: {e}")
            return {
                'num_elements': 0,
                'symmetry': 0.5,
                'density': 0.5,
                'form_regions': 0,
                'layout_complexity': 0.5
            }

    def detect_form_regions(self, gray, contours):
        """Detect regions that may be forms (input fields, buttons)"""
        try:
            form_regions = 0
            for contour in contours:
                x, y, w, h = cv2.boundingRect(contour)
                aspect_ratio = float(w) / h
                # Forms typically have rectangular regions with specific aspect ratios
                if 0.9 < aspect_ratio < 6.0 and w > 50 and h > 20:
                    # Check if region has horizontal lines (typical of form fields)
                    roi = gray[y:y+h, x:x+w]
                    edges = cv2.Canny(roi, 50, 150)
                    lines = cv2.HoughLinesP(edges, 1, np.pi/180, threshold=30, minLineLength=w*0.5, maxLineGap=5)
                    if lines is not None and len(lines) > 0:
                        form_regions += 1
            return form_regions
        except Exception as e:
            logger.error(f"Error detecting form regions: {e}")
            return 0

    def calculate_symmetry(self, contours, shape):
        """Calculate how symmetrical the page layout is"""
        try:
            if not contours:
                return 0.5
            
            center_x = shape[1] / 2
            
            # Calculate moments for each contour
            valid_contours = []
            contour_centers = []
            
            for c in contours:
                M = cv2.moments(c)
                if M['m00'] != 0:
                    cx = int(M['m10'] / M['m00'])
                    valid_contours.append(c)
                    contour_centers.append(cx)
            
            if not contour_centers:
                return 0.5
                
            # Calculate distribution of elements relative to center
            distances = [abs(cx - center_x) for cx in contour_centers]
            left_count = sum(1 for cx in contour_centers if cx < center_x)
            right_count = len(contour_centers) - left_count
            
            # Perfect symmetry would have equal elements on both sides
            count_ratio = min(left_count, right_count) / max(left_count, right_count) if max(left_count, right_count) > 0 else 0.5
            
            # Average distance from center (normalized by image width)
            avg_distance = sum(distances) / len(distances) if distances else 0
            distance_score = 1 - (avg_distance / (shape[1] / 2))
            
            # Combine both metrics
            symmetry_score = (count_ratio * 0.7) + (distance_score * 0.3)
            return symmetry_score
        except Exception as e:
            logger.error(f"Error calculating symmetry: {e}")
            return 0.5

    def calculate_layout_complexity(self, contours, shape):
        """Calculate layout complexity based on contour distribution"""
        try:
            if not contours or len(contours) < 5:
                return 0.3
                
            # Create a binary image of contours
            canvas = np.zeros((shape[0], shape[1]), dtype=np.uint8)
            cv2.drawContours(canvas, contours, -1, 255, 1)
            
            # Calculate the fractal dimension using box counting
            # (simplified version using grid sampling)
            def count_boxes(img, box_size):
                boxes = 0
                for y in range(0, img.shape[0], box_size):
                    for x in range(0, img.shape[1], box_size):
                        if np.any(img[y:y+box_size, x:x+box_size] > 0):
                            boxes += 1
                return boxes
                
            # Calculate for different box sizes
            box_sizes = [2, 4, 8, 16, 32]
            counts = [count_boxes(canvas, size) for size in box_sizes]
            
            # Higher count means more complex layout
            complexity = sum(counts) / (shape[0] * shape[1] / 64)  # Normalize
            return min(max(complexity, 0.1), 1.0)
        except Exception as e:
            logger.error(f"Error calculating layout complexity: {e}")
            return 0.5

    def detect_color_scheme(self, image):
        """Analyze color scheme to detect brand impersonation"""
        try:
            # Convert to RGB for easier color comparison
            rgb = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
            
            # Get dominant colors
            pixels = rgb.reshape(-1, 3)
            from sklearn.cluster import KMeans
            kmeans = KMeans(n_clusters=5, n_init=10)
            kmeans.fit(pixels)
            dominant_colors = kmeans.cluster_centers_.astype(int)
            
            # Check for similarity to known brand colors
            color_matches = {}
            for brand, colors in self.suspicious_color_schemes.items():
                primary_similarity = 1 - np.min([np.linalg.norm(c - colors['primary']) / 441.7 for c in dominant_colors])
                secondary_similarity = 1 - np.min([np.linalg.norm(c - colors['secondary']) / 441.7 for c in dominant_colors])
                avg_similarity = (primary_similarity * 0.7) + (secondary_similarity * 0.3)
                if avg_similarity > 0.7:
                    color_matches[brand] = avg_similarity
            
            return color_matches
        except Exception as e:
            logger.error(f"Error detecting color scheme: {e}")
            return {}

    def analyze_text_content(self, content):
        """Analyze text content for phishing indicators"""
        try:
            if not content or len(content) < 20:
                return 0.5
                
            content = content.lower()
            words = re.findall(r'\w+', content)
            word_counts = Counter(words)
            
            risk_score = 0.0
            suspicious_patterns = []
            
            # Check for suspicious words with weighted scoring
            suspicious_score = 0
            max_suspicious_score = 0
            detected_suspicious_words = []
            
            for word, weight in self.suspicious_words.items():
                count = word_counts.get(word, 0)
                if count > 0:
                    detected_suspicious_words.append(word)
                    suspicious_score += count * weight
                max_suspicious_score += weight  # Maximum possible score if all words appear
            
            # Normalize suspicious word score (up to a maximum contribution)
            if max_suspicious_score > 0:
                normalized_suspicious = min(suspicious_score / (max_suspicious_score * 0.3), 1.0)
                risk_score += normalized_suspicious * 0.5  # Words contribute up to 50% of risk
            
            # Check for phrases indicating form submission
            form_phrases = ['submit', 'sign in', 'log in', 'continue']
            form_phrase_count = sum(1 for phrase in form_phrases if phrase in content)
            if form_phrase_count > 0:
                risk_score += min(form_phrase_count * 0.1, 0.3)
            
            # Check for urgent language (CAPITALS, exclamation marks)
            if re.search(r'urgent|immediate|warning|alert|limited time', content, re.I):
                risk_score += 0.2
                suspicious_patterns.append('Urgent language detected')
            
            # Count capital letters and exclamation marks
            capitals_ratio = sum(1 for c in content if c.isupper()) / max(len(content), 1)
            if capitals_ratio > 0.1:  # More than 10% capital letters
                risk_score += capitals_ratio * 0.4
                suspicious_patterns.append('Excessive use of capital letters')
            
            exclamation_count = content.count('!')
            if exclamation_count > 3:
                risk_score += min(exclamation_count * 0.05, 0.2)
                suspicious_patterns.append('Excessive exclamation marks')
            
            # Look for sensitive information requests
            sensitive_patterns = [
                r'social\s+security',
                r'credit\s+card\s+number',
                r'(cvv|cvc|security\s+code)',
                r'(password|pw|passwd)',
                r'mother\'s\s+maiden\s+name',
                r'bank\s+account'
            ]
            
            for pattern in sensitive_patterns:
                if re.search(pattern, content, re.I):
                    risk_score += 0.3
                    suspicious_patterns.append(f'Requests for sensitive information')
                    break
            
            # Final risk calculation with capping
            risk_score = min(risk_score, 1.0)
            
            # Store analysis details for reporting
            self.last_analysis = {
                'risk_score': risk_score,
                'suspicious_words': detected_suspicious_words[:5],  # Top 5 suspicious words
                'suspicious_patterns': suspicious_patterns
            }
            
            return risk_score
            
        except Exception as e:
            logger.error(f"Visual text analysis error: {e}")
            return 0.5
            
    def get_last_analysis_details(self):
        """Return details from the last analysis performed"""
        return getattr(self, 'last_analysis', {})
            
    def detect_international_site(self, domain, content):
        """Detect if a site is an international version of a legitimate website
        
        Args:
            domain: The domain to check
            content: Text content of the webpage
            
        Returns:
            dict: Information about the international variant if detected, None otherwise
        """
        try:
            # Check against our known international sites
            for brand, brand_info in self.known_logos.items():
                # Check if this is an international variant
                for variant in brand_info.get('international_variants', []):
                    if domain == variant['domain'] or domain.endswith('.' + variant['domain']):
                        logger.info(f"Detected international site: {variant['domain']} ({variant['language']})")
                        return {
                            'is_international': True,
                            'brand': brand,
                            'base_domain': brand_info['base_domain'],
                            'language': variant['language'],
                            'domain': variant['domain']
                        }
                    
                # Check for language-specific patterns in Wikipedia URLs
                if brand == 'wikipedia' and '.wikipedia.org' in domain:
                    lang_code = domain.split('.')[0]
                    if 2 <= len(lang_code) <= 3:  # Most language codes are 2-3 characters
                        return {
                            'is_international': True,
                            'brand': 'wikipedia',
                            'base_domain': 'wikipedia.org',
                            'language': f'{lang_code} language',
                            'domain': domain
                        }
            
            return None
        except Exception as e:
            logger.error(f"Error detecting international site: {e}")
            return None

    def analyze_from_base64(self, base64_image):
        """Analyze an image from a base64 string"""
        try:
            # Decode base64 image
            image_data = base64.b64decode(base64_image.split(',')[1] if ',' in base64_image else base64_image)
            image = Image.open(BytesIO(image_data))
            
            # Run analysis on the image
            features = self.extract_features(image)
            layout_analysis = self.analyze_layout(image)
            color_analysis = self.detect_color_scheme(image)
            
            # Look for logos
            logo_detection = self.detect_logos(image)
            
            # Combine all analysis data
            analysis_results = {
                'visual_risk': logo_detection.get('risk', 0.5),
                'logos_detected': logo_detection.get('logos_detected', []),
                'layout_analysis': layout_analysis,
                'color_scheme': color_analysis,
                'feature_vector_hash': hash(str(features.tolist())),
                'analysis_details': {
                    'symmetry': layout_analysis.get('symmetry', 0),
                    'complexity': layout_analysis.get('complexity', 0),
                    'form_elements': layout_analysis.get('form_regions', 0)
                }
            }
            
            return analysis_results
        except Exception as e:
            logger.error(f"Error analyzing image from base64: {e}")
            return {
                'visual_risk': 0.5,
                'error': str(e)
            } 
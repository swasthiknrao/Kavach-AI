import numpy as np
import re
from urllib.parse import urlparse

class FeatureExtractor:
    def extract_url_features(self, url):
        """Extract features from a URL for analysis"""
        return {
            'length': len(url),
            'has_https': url.startswith('https'),
            'dots_count': url.count('.'),
            'special_chars': sum(not c.isalnum() for c in url)
        }
    
    def extract_visual_features(self, image):
        """Extract features from an image for analysis"""
        # This would normally use computer vision techniques
        # For now, return a placeholder feature vector
        return np.random.random(100)
    
    def extract_behavior_features(self, behavior_data):
        """Extract features from behavior data for analysis"""
        features = np.zeros(100)
        
        if not behavior_data:
            return features
        
        # Extract features from behavior data if available
        if isinstance(behavior_data, dict):
            # Form submissions
            if 'form_submissions' in behavior_data:
                features[0] = behavior_data['form_submissions']
            
            # Redirects
            if 'redirects' in behavior_data:
                features[1] = behavior_data['redirects']
            
            # Popups
            if 'popups' in behavior_data:
                features[2] = behavior_data['popups']
            
            # Scripts
            if 'scripts' in behavior_data:
                features[3] = len(behavior_data['scripts'])
            
            # Input monitoring
            if 'input_monitoring' in behavior_data:
                features[4] = behavior_data['input_monitoring']
            
            # Clipboard access
            if 'clipboard_access' in behavior_data:
                features[5] = behavior_data['clipboard_access']
        
        return features 
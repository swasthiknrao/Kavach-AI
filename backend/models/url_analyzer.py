import tensorflow as tf
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
import re
import tld
from urllib.parse import urlparse
import math
import hashlib
from collections import Counter
import logging

class URLAnalyzer:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(1, 3), max_features=1000)
        self.logger = logging.getLogger(__name__)
        self.build_model()
        
        # Advanced patterns for various attack types
        self.suspicious_patterns = {
            'typosquatting': [
                r'paypal.*\.com',
                r'amaz[o0]n.*\.com',
                r'g[o0]{2}gle.*\.com',
                r'faceb[o0]{2}k.*\.com',
                r'netfl[i1]x.*\.com',
                r'micros[o0]ft.*\.com',
                r'[i1]nstagram.*\.com',
                r'tw[i1]tter.*\.com',
                r'l[i1]nked[i1]n.*\.com',
                r'.*\.c[o0]m$',
                r'.*\.[o0]rg$',
                r'apple[i1]d.*\.com'
            ],
            'phishing': [
                r'bank.*\.com',
                r'secure.*\.com',
                r'account.*\.(com|net|org)',
                r'login.*\.(com|net|org)',
                r'signin.*\.(com|net|org)',
                r'verify.*\.(com|net|org)',
                r'.*-secure-.*',
                r'.*-verify-.*',
                r'.*-login-.*',
                r'.*-account-.*',
                r'.*\.com-[a-z0-9]{4,}',
                r'support.*\.(com|net|org)',
                r'update.*\.(com|net|org)',
                r'confirm.*\.(com|net|org)'
            ],
            'malicious': [
                r'free.*\.(com|net|org)',
                r'win.*\.(com|net|org)',
                r'prize.*\.(com|net|org)',
                r'claim.*\.(com|net|org)',
                r'gift.*\.(com|net|org)',
                r'reward.*\.(com|net|org)',
            ],
            'suspicious_tlds': [
                r'.*\.(xyz|top|work|party|gq|ml|cf|ga|tk)$'
            ],
            'suspicious_structure': [
                r'.*[0-9]{5,}.*',
                r'.*[a-zA-Z0-9]{20,}.*',
                r'.*[a-f0-9]{32}.*',  # MD5 hash
                r'.*[?&][a-z]{1,3}=[0-9]{1,3}$',
                r'.*[?&]id=[0-9]+$',
                r'.*[?&]token=[a-zA-Z0-9]+$'
            ]
        }
        
        # Brand protection: key brands to protect
        self.protected_brands = [
            'google', 'amazon', 'facebook', 'instagram', 'apple', 'microsoft', 
            'paypal', 'netflix', 'twitter', 'linkedin', 'whatsapp', 'gmail',
            'youtube', 'bank', 'chase', 'wellsfargo', 'citibank', 'bankofamerica',
            'amex', 'mastercard', 'visa', 'discover', 'walmart', 'target', 'ebay'
        ]

    def build_model(self):
        """Build a neural network model for URL classification"""
        model = tf.keras.Sequential([
            tf.keras.layers.Dense(256, activation='relu', input_shape=(100,)),
            tf.keras.layers.BatchNormalization(),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(128, activation='relu'),
            tf.keras.layers.BatchNormalization(),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(64, activation='relu'),
            tf.keras.layers.Dense(1, activation='sigmoid')
        ])
        model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
        self.model = model

    def extract_features(self, url):
        """Extract comprehensive URL features for ML model"""
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        path = parsed_url.path
        query = parsed_url.query
        
        # Basic features
        features = {
            'length': len(url),
            'hostname_length': len(hostname),
            'path_length': len(path),
            'path_depth': len(path.split('/')),
            'query_length': len(query),
            'num_digits': sum(c.isdigit() for c in url),
            'num_params': len(query.split('&')),
            'num_special': sum(not c.isalnum() for c in url),
            'has_https': int(parsed_url.scheme == 'https'),
            'num_dots': url.count('.'),
            'num_subdomains': len(hostname.split('.'))-1 if hostname else 0,
            'has_port': int(hostname.find(':') > 0),
            'has_hyphen': int('-' in hostname),
            'has_underline': int('_' in hostname),
            'has_suspicious_tld': self.check_suspicious_tld(url),
            'entropy': self.calculate_entropy(url),
            'consonant_ratio': self.calculate_consonant_vowel_ratio(hostname),
            'digit_ratio': sum(c.isdigit() for c in hostname) / len(hostname) if hostname else 0,
            'special_ratio': sum(not c.isalnum() for c in hostname) / len(hostname) if hostname else 0,
            'has_brand': self.check_brand_similarity(hostname),
            'random_domain_score': self.calculate_randomness(hostname),
            'url_hash_density': self.calculate_hash_density(url),
            'suspicious_url_patterns': self.count_suspicious_patterns(url),
            'gib_value': self.gib_value(hostname)
        }
        
        return np.array(list(features.values()))

    def check_suspicious_tld(self, url):
        """Check if URL has a suspicious top-level domain"""
        try:
            domain = tld.get_tld(url, as_object=True)
            suspicious_tlds = {'xyz', 'top', 'work', 'party', 'gq', 'ml', 'cf', 'ga', 'tk', 'bid', 'loan'}
            return 1 if domain.suffix in suspicious_tlds else 0
        except:
            return 1

    def calculate_entropy(self, text):
        """Calculate Shannon entropy for a string - higher entropy means more random/complex"""
        if not text:
            return 0
        entropy = 0
        text_length = len(text)
        char_counts = Counter(text)
        
        for count in char_counts.values():
            probability = count / text_length
            entropy -= probability * math.log2(probability)
            
        return entropy
    
    def calculate_consonant_vowel_ratio(self, text):
        """Calculate ratio of consonants to vowels - unusual ratios may indicate synthetic domains"""
        if not text:
            return 0
            
        vowels = sum(c.lower() in 'aeiou' for c in text if c.isalpha())
        consonants = sum(c.lower() not in 'aeiou' for c in text if c.isalpha())
        
        if vowels == 0:
            return consonants
        return consonants / vowels
    
    def check_brand_similarity(self, domain):
        """Check if domain contains protected brand names with potential misspellings"""
        domain_lower = domain.lower()
        
        # Direct brand matching
        for brand in self.protected_brands:
            if brand in domain_lower:
                return 1
        
        # Check for brand with digit substitution (o -> 0, i -> 1, etc.)
        domain_normalized = domain_lower.replace('0', 'o').replace('1', 'i').replace('3', 'e')
        for brand in self.protected_brands:
            if brand in domain_normalized:
                return 1
        
        # Check for incomplete but recognizable brand names (goog -> google)
        for brand in self.protected_brands:
            if len(brand) > 4:
                brand_start = brand[:4]
                if brand_start in domain_lower:
                    return 0.8
        
        return 0
    
    def calculate_randomness(self, domain):
        """Calculate how random a domain appears - high randomness can indicate algorithmically generated domains"""
        if not domain:
            return 0
            
        # Remove TLD
        try:
            main_domain = domain.split('.')[0]
        except:
            main_domain = domain
            
        # Consecutive consonants
        consonant_groups = re.findall(r'[^aeiou]{4,}', main_domain)
        consonant_score = min(1.0, len(''.join(consonant_groups)) / len(main_domain) if main_domain else 0)
        
        # Random character distribution
        char_counts = Counter(main_domain)
        distribution_evenness = 1 - (max(char_counts.values()) / len(main_domain) if main_domain else 0)
        
        # Length-based randomness factor
        length_factor = min(1.0, len(main_domain) / 25.0) if main_domain else 0
        
        # Combine factors
        randomness = (consonant_score + distribution_evenness + length_factor) / 3
        return randomness
    
    def calculate_hash_density(self, url):
        """Calculate the density of hash-like patterns which can indicate obfuscation"""
        hash_patterns = re.findall(r'[a-f0-9]{8,}', url.lower())
        if not hash_patterns:
            return 0
        return min(1.0, sum(len(h) for h in hash_patterns) / len(url))
    
    def count_suspicious_patterns(self, url):
        """Count suspicious patterns in URL"""
        url_lower = url.lower()
        count = 0
        
        # Check all pattern categories
        for category, patterns in self.suspicious_patterns.items():
            for pattern in patterns:
                if re.search(pattern, url_lower):
                    count += 1
        
        # Normalize to 0-1 range
        return min(1.0, count / 10)
    
    def gib_value(self, text):
        """Calculate gibberish likelihood - higher means more likely to be nonsense text"""
        # Simplified implementation of gibberish detection
        common_bigrams = ['th', 'he', 'in', 'er', 'an', 're', 'on', 'at', 'en', 'nd']
        common_count = sum(bigram in text.lower() for bigram in common_bigrams)
        
        # Count repeating characters
        repeats = sum(1 for i in range(len(text)-1) if text[i] == text[i+1])
        
        # Higher score = more likely to be legitimate text
        score = (common_count - repeats) / max(1, len(text))
        # Invert and normalize to 0-1 where higher = more gibberish
        return max(0, min(1, 1 - (score + 0.5)))

    def quick_analyze(self, url):
        """Analyze URL for phishing or malicious indicators using multiple AI techniques"""
        try:
            if not url:
                return 0.5
                
            self.logger.info(f"Analyzing URL: {url}")
            
            # Start with base risk score
            risk_score = 0.0
            parsed_url = urlparse(url)
            hostname = parsed_url.netloc.lower()
            
            # ====== PRIMARY RISK INDICATORS ======
            
            # Check HTTP vs HTTPS
            if parsed_url.scheme != 'https':
                risk_score += 0.2
                self.logger.debug(f"Non-HTTPS protocol: +0.2")
            
            # Check for IP address in hostname
            if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', hostname):
                risk_score += 0.5
                self.logger.debug(f"IP address in hostname: +0.5")
            
            # ====== LEXICAL FEATURES ======
            
            # URL length (longer URLs are more suspicious)
            if len(url) > 100:
                risk_score += 0.1
                self.logger.debug(f"Long URL length: +0.1")
            
            # Hostname length
            if len(hostname) > 30:
                risk_score += 0.1
                self.logger.debug(f"Long hostname: +0.1")
            
            # Special character ratio
            special_char_ratio = sum(not c.isalnum() and c != '.' for c in hostname) / len(hostname) if hostname else 0
            if special_char_ratio > 0.2:
                risk_score += special_char_ratio
                self.logger.debug(f"High special char ratio: +{special_char_ratio:.2f}")
            
            # Digit ratio
            digit_ratio = sum(c.isdigit() for c in hostname) / len(hostname) if hostname else 0
            if digit_ratio > 0.3:
                risk_score += 0.2
                self.logger.debug(f"High digit ratio: +0.2")
            
            # ====== BRAND PROTECTION ======
            
            # Check for brand names in URL
            brand_similarity = self.check_brand_similarity(hostname)
            if brand_similarity > 0:
                # If it's a brand-like domain, increase risk
                hostname_parts = hostname.split('.')
                if len(hostname_parts) > 1:
                    main_domain = hostname_parts[-2]
                    # High entropy or unusual patterns with brand names suggest phishing
                    domain_entropy = self.calculate_entropy(main_domain)
                    if domain_entropy > 4 or self.gib_value(main_domain) > 0.6:
                        risk_score += 0.4
                        self.logger.debug(f"Brand with high entropy/gibberish: +0.4")
                
                # Check for suspicious tld with brand name
                if re.search(r'.*\.(xyz|top|work|party|gq|ml|cf|ga|tk)$', hostname):
                    risk_score += 0.5
                    self.logger.debug(f"Brand with suspicious TLD: +0.5")
            
            # ====== PATTERN MATCHING ======
            
            # Check for suspicious patterns
            for category, patterns in self.suspicious_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, url.lower()):
                        if category == 'typosquatting':
                            risk_score += 0.3
                            self.logger.debug(f"Typosquatting pattern match: +0.3")
                            break
                        elif category == 'phishing':
                            risk_score += 0.4
                            self.logger.debug(f"Phishing pattern match: +0.4")
                            break
                        elif category == 'malicious':
                            risk_score += 0.3
                            self.logger.debug(f"Malicious pattern match: +0.3")
                            break
                        elif category == 'suspicious_tlds':
                            risk_score += 0.2
                            self.logger.debug(f"Suspicious TLD match: +0.2")
                            break
                        elif category == 'suspicious_structure':
                            risk_score += 0.2
                            self.logger.debug(f"Suspicious structure match: +0.2")
                            break
            
            # ====== ADVANCED INDICATORS ======
            
            # Domain randomness/algorithmically generated
            randomness = self.calculate_randomness(hostname)
            if randomness > 0.7:
                risk_score += 0.3
                self.logger.debug(f"High domain randomness: +0.3")
            
            # Consonant-vowel ratio (abnormal language patterns)
            cv_ratio = self.calculate_consonant_vowel_ratio(hostname)
            if cv_ratio > 10 or cv_ratio == 0:
                risk_score += 0.2
                self.logger.debug(f"Abnormal consonant-vowel ratio: +0.2")
            
            # Entropy (measure of randomness)
            entropy = self.calculate_entropy(hostname)
            if entropy > 4.5:
                risk_score += 0.1
                self.logger.debug(f"High hostname entropy: +0.1")
            
            # Gibberish detection
            gib = self.gib_value(hostname)
            if gib > 0.7:
                risk_score += 0.3
                self.logger.debug(f"High gibberish score: +0.3")
            
            # URL Path analysis
            path = parsed_url.path.lower()
            if re.search(r'/(secure|login|signin|account|verify|confirm|update|auth)/', path):
                risk_score += 0.2
                self.logger.debug(f"Sensitive terms in path: +0.2")
            
            # Query string analysis
            query = parsed_url.query.lower()
            if re.search(r'(password|passwd|pwd|token|access|auth|account)', query):
                risk_score += 0.2
                self.logger.debug(f"Sensitive terms in query: +0.2")
            
            # ====== HEURISTIC ADJUSTMENTS ======
            
            # Legitimate site heuristics (reduce false positives)
            legitimate_signals = 0
            
            # Well-known TLDs reduce risk slightly
            if hostname.endswith(('.com', '.org', '.net', '.gov', '.edu')):
                legitimate_signals += 1
            
            # Moderate length hostnames
            if 5 <= len(hostname.split('.')[0]) <= 15:
                legitimate_signals += 1
            
            # Normal entropy
            if 2.5 <= entropy <= 4.0:
                legitimate_signals += 1
            
            # International domain variant detection
            # Check if this is a known international domain variant
            domain_parts = hostname.split('.')
            if len(domain_parts) >= 3:
                # Check for language code pattern (e.g., en.wikipedia.org, ja.wikipedia.org)
                subdomain = domain_parts[0]
                if len(subdomain) == 2 or len(subdomain) == 3:  # ISO language codes
                    main_domain = '.'.join(domain_parts[1:])
                    if main_domain in ['wikipedia.org', 'google.com', 'amazon.com']:
                        legitimate_signals += 2
                        self.logger.debug(f"Detected legitimate international variant: {hostname}")
            
            # Apply legitimate signals reduction
            risk_reduction = legitimate_signals * 0.05
            risk_score = max(0, risk_score - risk_reduction)
            
            # Apply neural network prediction if available
            try:
                features = self.extract_features(url)
                nn_prediction = self.model.predict(features.reshape(1, -1))[0][0]
                
                # Blend rule-based and neural network predictions
                risk_score = (risk_score * 0.7) + (float(nn_prediction) * 0.3)
                self.logger.debug(f"Neural network prediction: {nn_prediction:.2f}")
            except Exception as e:
                self.logger.warning(f"Neural network prediction failed: {e}")
            
            self.logger.info(f"Final URL risk score: {min(risk_score, 1.0):.2f}")
            
            return min(risk_score, 1.0)
            
        except Exception as e:
            self.logger.error(f"URL analysis error: {e}", exc_info=True)
            return 0.5 
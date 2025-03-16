from sklearn.ensemble import RandomForestClassifier
import numpy as np
import re
import logging
import json
from collections import Counter
import tensorflow as tf
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Configure logging
logger = logging.getLogger(__name__)

class BehaviorAnalyzer:
    def __init__(self):
        try:
            # Set sequence length and feature dimension first
            self.sequence_length = 50
            self.feature_dim = 12
            
            # Initialize risk patterns with weights
            self.risk_patterns = {
                'password_field': 0.3,
                'login_form': 0.2,
                'multiple_redirects': 0.3,
                'excessive_forms': 0.2,
                'suspicious_scripts': 0.4,
                'popup_blockers': 0.25,
                'iframe_usage': 0.15,
                'hidden_elements': 0.35,
                'clipboard_access': 0.45,
                'location_redirect': 0.3,
                'data_exfiltration': 0.6
            }
            
            # Initialize suspicious JS patterns
            self.suspicious_patterns = self.load_suspicious_patterns()
            
            # Initialize ML models and components
            self.build_model()
            self.lstm_model = self.build_lstm_model()
            self.isolation_forest = IsolationForest(contamination=0.1)
            self.scaler = StandardScaler()
            
            logger.info("Behavior analyzer initialized successfully")
        except Exception as e:
            logger.error(f"Error initializing BehaviorAnalyzer: {e}")
        
    def analyze(self, behavior_data):
        """Enhanced behavior analysis with LSTM and anomaly detection"""
        try:
            risk_score = 0.0
            suspicious_patterns = []
            
            # Extract sequence features
            sequence = self.extract_sequence_features(behavior_data)
            
            # LSTM prediction
            if sequence is not None:
                sequence = np.expand_dims(sequence, axis=0)
                lstm_prediction = self.lstm_model.predict(sequence)[0][0]
                risk_score += lstm_prediction * 0.4
                
            # Anomaly detection
            features = self.extract_features(behavior_data)
            scaled_features = self.scaler.fit_transform([features])
            anomaly_score = self.isolation_forest.fit_predict(scaled_features)[0]
            if anomaly_score == -1:  # Anomaly detected
                risk_score += 0.3
                suspicious_patterns.append("Anomalous behavior pattern detected")
            
            # Rule-based analysis
            rule_score = self.analyze_rules(behavior_data)
            risk_score += rule_score * 0.3
            
            # Store analysis details
            self.last_analysis = {
                'risk_score': min(risk_score, 1.0),
                'suspicious_patterns': suspicious_patterns,
                'lstm_score': lstm_prediction if sequence is not None else None,
                'anomaly_detected': anomaly_score == -1,
                'rule_score': rule_score
            }
            
            return min(risk_score, 1.0)
            
        except Exception as e:
            logger.error(f"Behavior analysis error: {e}")
            return 0.5

    def load_suspicious_patterns(self):
        """Load patterns of suspicious JavaScript behaviors"""
        return {
            # Authentication and form manipulation
            'form_submission': r'(document\.forms.*?submit|form\.submit\(\))',
            'password_access': r'(type=["|\']password["|\']|input\[type=["|\']password["|\'])',
            'credential_extraction': r'(username|password|user|email|account).*?(value|innerText|innerHTML)',
            
            # Redirects and navigation
            'redirect_chain': r'(window\.location|location\.href|location\.replace)',
            'history_manipulation': r'(history\.pushState|history\.replaceState)',
            'window_open': r'window\.open\(',
            
            # Browser features misuse
            'popup_spam': r'(window\.open|showModalDialog)',
            'popup_blocker_detection': r'(popupblocker|popup_blocker|popup blocker)',
            'clipboard_access': r'(navigator\.clipboard|document\.execCommand.*?copy)',
            
            # Event capturing for keylogging
            'keyboard_logging': r'(addEventListener.*?keyup|addEventListener.*?keydown|addEventListener.*?keypress)',
            'input_monitoring': r'(addEventListener.*?input|addEventListener.*?change)',
            
            # Obfuscation techniques
            'eval_usage': r'(eval\(|Function\(|new Function\()',
            'encoded_strings': r'(atob\(|btoa\(|escape\(|unescape\()',
            'document_write': r'document\.write\(',
            
            # Data exfiltration
            'ajax_post': r'(XMLHttpRequest.*?POST|fetch.*?POST|fetch.*?method:\s*[\'"]POST)',
            'external_script': r'(document\.createElement\([\'"]script[\'"]\)|\<script.*?src=)',
            'localStorage': r'(localStorage\.setItem|sessionStorage\.setItem)',
            
            # Iframe manipulation
            'iframe_creation': r'(createElement\([\'"]iframe[\'"]\)|<iframe)',
            'iframe_manipulation': r'(iframe\.src|iframe\.contentWindow)',
            
            # DOM manipulation
            'hidden_elements': r'(style.*?display:\s*none|style.*?visibility:\s*hidden|hidden\s*=\s*[\'"]true)',
            'dom_manipulation': r'(innerHTML|outerHTML|insertAdjacentHTML)'
        }

    def extract_features(self, behavior_data):
        """Extract numerical features from behavior data for ML model"""
        features = np.zeros(12)  # Initialize feature vector
        
        try:
            # Basic form and input features
            features[0] = behavior_data.get('forms', 0)
            features[1] = 1 if behavior_data.get('hasPasswordField', False) else 0
            features[2] = 1 if behavior_data.get('hasLoginForm', False) else 0
            features[3] = behavior_data.get('redirectCount', 0)
            
            # Script-related features
            features[4] = len(behavior_data.get('scripts', []))
            features[5] = behavior_data.get('iframes', 0)
            features[6] = behavior_data.get('hiddenElements', 0)
            
            # Link-related features
            features[7] = behavior_data.get('links', 0)
            features[8] = len(behavior_data.get('externalLinks', []))
            
            # Event listeners
            features[9] = len(behavior_data.get('eventListeners', {}).get('keyup', []))
            features[10] = len(behavior_data.get('eventListeners', {}).get('keydown', []))
            features[11] = len(behavior_data.get('eventListeners', {}).get('input', []))
            
            return features
        except Exception as e:
            logger.error(f"Error extracting behavior features: {e}")
            return features

    def analyze_scripts(self, scripts):
        """Analyze script content for suspicious patterns"""
        suspicious_count = 0
        findings = []
        
        try:
            if not scripts or not isinstance(scripts, list):
                return 0, []
                
            script_text = " ".join(scripts)
            
            # Check for each suspicious pattern
            for name, pattern in self.suspicious_patterns.items():
                matches = re.findall(pattern, script_text, re.I)
                if matches:
                    suspicious_count += len(matches)
                    
                    # Add specific findings based on pattern type
                    if name == 'form_submission' and len(matches) > 1:
                        findings.append("Multiple form submission methods detected")
                    elif name == 'redirect_chain' and len(matches) > 0:
                        findings.append("Page redirection script detected")
                    elif name == 'eval_usage':
                        findings.append("Obfuscated code execution (eval)")
                    elif name == 'keyboard_logging':
                        findings.append("Keyboard input monitoring")
                    elif name == 'clipboard_access':
                        findings.append("Clipboard access attempts")
                    elif name == 'ajax_post' and 'password' in script_text.lower():
                        findings.append("Data submission to external servers")
            
            # Calculate risk score based on suspicious count
            risk_score = min(suspicious_count * 0.05, self.risk_patterns['suspicious_scripts'])
            
            # Check for data exfiltration to suspicious domains
            if re.search(r'(fetch|ajax|XMLHttpRequest|post|send).*?(php|aspx|jsp)', script_text, re.I):
                risk_score += 0.15
                findings.append("Possible data exfiltration to external server")
                
            # Check for obfuscated code
            obfuscation_level = self.detect_obfuscation(script_text)
            if obfuscation_level > 0.5:
                risk_score += 0.2
                findings.append("Heavily obfuscated JavaScript detected")
            
            return risk_score, findings[:3]  # Return top 3 findings
            
        except Exception as e:
            logger.error(f"Error analyzing scripts: {e}")
            return min(suspicious_count * 0.05, 0.2), findings[:2]

    def detect_obfuscation(self, script_text):
        """Detect level of JavaScript obfuscation"""
        try:
            # Count various indicators of obfuscation
            indicators = [
                len(re.findall(r'\\x[0-9a-f]{2}', script_text)) > 5,  # Hex encoding
                len(re.findall(r'\\u[0-9a-f]{4}', script_text)) > 5,  # Unicode escapes
                len(re.findall(r'String\.fromCharCode', script_text)) > 2,  # Char code conversion
                len(re.findall(r'\w{30,}', script_text)) > 2,  # Very long identifiers
                len(re.findall(r'eval\(', script_text)) > 0,  # Eval usage
                len(re.findall(r'atob\(', script_text)) > 0,  # Base64 decoding
                len(re.findall(r'=\s*~[]', script_text)) > 0,  # JSFuck-like obfuscation
                len(re.findall(r'=\s*!\+\[\]', script_text)) > 0,  # JSFuck-like obfuscation
                len(re.findall(r'=\s*[\'"][^\'",;]{50,}[\'"]', script_text)) > 2,  # Long encoded strings
                len(re.findall(r'\[\s*[\'"][^\'"]{1,2}[\'"]\s*\+\s*[\'"]', script_text)) > 5,  # String splitting
            ]
            
            # Calculate obfuscation score
            obfuscation_score = sum(1 for i in indicators if i) / len(indicators)
            return obfuscation_score
            
        except Exception as e:
            logger.error(f"Error detecting obfuscation: {e}")
            return 0.2

    def analyze_event_listeners(self, event_listeners):
        """Analyze event listeners for suspicious behavior"""
        try:
            risk_score = 0
            
            # Check for keylogging-related events
            key_events = ['keyup', 'keydown', 'keypress']
            key_event_count = sum(len(event_listeners.get(evt, [])) for evt in key_events if evt in event_listeners)
            
            if key_event_count > 0:
                risk_score += min(key_event_count * 0.05, 0.2)
            
            # Check for input monitoring
            input_events = ['input', 'change', 'paste']
            input_event_count = sum(len(event_listeners.get(evt, [])) for evt in input_events if evt in event_listeners)
            
            if input_event_count > 0:
                risk_score += min(input_event_count * 0.04, 0.15)
            
            # Check for excessive event handlers (potential for event hijacking)
            total_events = sum(len(handlers) for handlers in event_listeners.values())
            if total_events > 10:
                risk_score += min((total_events - 10) * 0.01, 0.1)
            
            return risk_score
            
        except Exception as e:
            logger.error(f"Error analyzing event listeners: {e}")
            return 0.1

    def analyze_external_links(self, external_links):
        """Analyze external links for suspicious patterns"""
        try:
            if not external_links:
                return 0
                
            risk_score = 0
            
            # Suspicious TLDs that are often used in phishing
            suspicious_tlds = ['.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.info']
            tld_count = sum(1 for link in external_links if any(link.lower().endswith(tld) for tld in suspicious_tlds))
            
            risk_score += min(tld_count * 0.1, 0.3)
            
            # Look for excessive numeric or special characters in domains
            for link in external_links:
                try:
                    from urllib.parse import urlparse
                    domain = urlparse(link).netloc
                    
                    # Count numeric characters and hyphens
                    num_count = sum(1 for c in domain if c.isdigit())
                    hyphen_count = domain.count('-')
                    
                    if num_count > 4:
                        risk_score += 0.05
                    
                    if hyphen_count > 2:
                        risk_score += 0.05
                        
                    # Very long domains are suspicious
                    if len(domain) > 30:
                        risk_score += 0.1
                        
                except Exception as e:
                    continue
            
            return min(risk_score, 0.4)
            
        except Exception as e:
            logger.error(f"Error analyzing external links: {e}")
            return 0

    def build_model(self):
        """Build a simple model for behavior analysis (pre-trained)"""
        try:
            # Initialize a RandomForest model
            self.model = RandomForestClassifier(n_estimators=20, max_depth=5)
            
            # In a real implementation, we would load a pre-trained model here
            # For now, fit with some simple examples
            X = np.array([
                # Safe examples [forms, hasPassword, hasLogin, redirects, scripts, iframes, hidden, links, extLinks, keyup, keydown, input]
                [1, 0, 0, 0, 2, 0, 0, 10, 2, 0, 0, 0],  # Simple content site
                [2, 1, 1, 0, 5, 0, 1, 20, 3, 0, 0, 1],  # Legitimate login page
                [3, 1, 1, 0, 4, 1, 2, 15, 5, 1, 1, 1],  # Legitimate complex site
                
                # Suspicious examples
                [4, 1, 1, 3, 10, 3, 5, 30, 15, 3, 3, 2],  # High interaction, many redirects
                [2, 1, 1, 2, 8, 2, 6, 5, 10, 4, 4, 3],   # Keylogging behavior
                [5, 1, 1, 4, 15, 5, 8, 40, 20, 5, 5, 4]   # Extreme case
            ])
            
            y = np.array([0, 0, 0, 1, 1, 1])  # 0 = safe, 1 = suspicious
            
            # Fit the model
            self.model.fit(X, y)
            logger.info("Behavior analysis model trained successfully")
            
        except Exception as e:
            logger.error(f"Error building behavior model: {e}")
            self.model = None
    
    def get_last_analysis_details(self):
        """Return details from the last analysis performed"""
        return getattr(self, 'last_analysis', {})

    def build_lstm_model(self):
        """Build LSTM model for sequence analysis"""
        model = tf.keras.Sequential([
            tf.keras.layers.LSTM(128, input_shape=(self.sequence_length, self.feature_dim), return_sequences=True),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.LSTM(64),
            tf.keras.layers.Dense(32, activation='relu'),
            tf.keras.layers.Dense(1, activation='sigmoid')
        ])
        model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
        return model

    def extract_sequence_features(self, behavior_data):
        """Extract sequential features for LSTM"""
        try:
            sequence = []
            events = behavior_data.get('events', [])
            
            for event in events[:self.sequence_length]:
                features = [
                    event.get('type', 0),
                    event.get('timestamp', 0),
                    event.get('target', {}).get('type', 0),
                    event.get('keyCode', 0),
                    event.get('button', 0),
                    event.get('clientX', 0),
                    event.get('clientY', 0),
                    event.get('pageX', 0),
                    event.get('pageY', 0),
                    event.get('which', 0),
                    event.get('detail', 0),
                    event.get('pressure', 0)
                ]
                sequence.append(features)
                
            # Pad sequence if needed
            while len(sequence) < self.sequence_length:
                sequence.append([0] * self.feature_dim)
                
            return np.array(sequence)
            
        except Exception as e:
            logger.error(f"Error extracting sequence features: {e}")
            return None

    def analyze_rules(self, behavior_data):
        """Rule-based behavior analysis"""
        risk_score = 0.0
        
        # Form submission analysis
        forms = behavior_data.get('forms', [])
        if len(forms) > 0:
            for form in forms:
                if form.get('hasPassword', False):
                    risk_score += 0.2
                if form.get('hasHiddenInputs', False):
                    risk_score += 0.1
                    
        # Script analysis
        scripts = behavior_data.get('scripts', [])
        if len(scripts) > 10:  # Excessive scripts
            risk_score += 0.1
            
        # Redirect analysis
        if behavior_data.get('redirectCount', 0) > 2:
            risk_score += 0.2
            
        # Input monitoring
        if behavior_data.get('keyloggerDetected', False):
            risk_score += 0.4
            
        return min(risk_score, 1.0) 
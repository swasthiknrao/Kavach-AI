import re

class SecurityUtils:
    def calculate_hash_similarity(self, hash1, hash2):
        """Calculate similarity between two perceptual hashes"""
        return 1 - (bin(int(hash1, 16) ^ int(hash2, 16)).count('1') / 64)

    def detect_js_obfuscation(self, script_content):
        """Detect obfuscated JavaScript"""
        indicators = {
            'eval_usage': len(re.findall(r'eval\(', script_content)),
            'base64_strings': len(re.findall(r'base64,', script_content)),
            'string_manipulation': len(re.findall(r'String\.fromCharCode', script_content)),
            'suspicious_encoding': self.check_suspicious_encoding(script_content)
        }
        return self.calculate_obfuscation_score(indicators)

    def analyze_redirect_chain(self, navigation_data):
        """Analyze redirect chain for suspicious patterns"""
        chain = navigation_data.get('redirect_chain', [])
        return {
            'length': len(chain),
            'suspicious_hops': self.detect_suspicious_redirects(chain),
            'geo_dispersion': self.calculate_geo_dispersion(chain),
            'risk_score': self.calculate_redirect_risk(chain)
        }

    def check_device_consistency(self, device_data):
        """Check for device fingerprint consistency"""
        return {
            'fingerprint_match': self.verify_device_fingerprint(device_data),
            'location_consistency': self.check_location_consistency(device_data),
            'behavior_match': self.verify_behavior_patterns(device_data),
            'risk_level': self.calculate_device_risk(device_data)
        } 
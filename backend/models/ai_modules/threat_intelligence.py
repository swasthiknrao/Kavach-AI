import tensorflow as tf
import torch
from transformers import AutoTokenizer, AutoModel
import numpy as np
from sklearn.ensemble import IsolationForest
import logging
import json
from datetime import datetime, timedelta
from sklearn.ensemble import RandomForestClassifier
import re

logger = logging.getLogger(__name__)

class ThreatIntelligence:
    def __init__(self):
        super().__init__()
        self.tokenizer = AutoTokenizer.from_pretrained('bert-base-uncased')
        self.model = AutoModel.from_pretrained('bert-base-uncased')
        self.isolation_forest = IsolationForest(contamination=0.1)
        self.threat_database = {}
        self.pattern_memory = {}
        self.update_interval = timedelta(hours=1)
        self.last_update = datetime.now()
        self.threat_model = None
        self.pattern_detector = None
        self.initialize_models()
        
    async def process_threat_data(self, sources):
        """Process threat data from multiple sources"""
        try:
            threat_data = []
            
            for source in sources:
                data = await self.fetch_threat_data(source)
                if data:
                    processed_data = self.process_source_data(data, source['type'])
                    threat_data.extend(processed_data)
            
            # Update threat database
            self.update_threat_database(threat_data)
            
            # Analyze patterns
            patterns = self.analyze_threat_patterns(threat_data)
            
            # Generate threat intelligence report
            report = self.generate_threat_report(patterns)
            
            return report
            
        except Exception as e:
            logger.error(f"Error processing threat data: {e}")
            return None
            
    async def fetch_threat_data(self, source):
        """Fetch threat data from a source"""
        try:
            # Implement source-specific fetching logic
            if source['type'] == 'api':
                return await self.fetch_api_data(source)
            elif source['type'] == 'feed':
                return await self.fetch_feed_data(source)
            elif source['type'] == 'database':
                return await self.fetch_database_data(source)
            else:
                logger.warning(f"Unknown source type: {source['type']}")
                return None
                
        except Exception as e:
            logger.error(f"Error fetching threat data: {e}")
            return None
            
    def process_source_data(self, data, source_type):
        """Process data based on source type"""
        try:
            processed_data = []
            
            for item in data:
                # Extract relevant fields
                processed_item = {
                    'timestamp': item.get('timestamp', datetime.now().isoformat()),
                    'threat_type': item.get('type', 'unknown'),
                    'indicators': item.get('indicators', []),
                    'confidence': item.get('confidence', 0.5),
                    'source': source_type
                }
                
                # Extract and normalize features
                features = self.extract_threat_features(item)
                processed_item['features'] = features
                
                # Calculate threat score
                processed_item['threat_score'] = self.calculate_threat_score(item)
                
                processed_data.append(processed_item)
                
            return processed_data
            
        except Exception as e:
            logger.error(f"Error processing source data: {e}")
            return []
            
    def update_threat_database(self, threat_data):
        """Update internal threat database"""
        try:
            current_time = datetime.now()
            
            # Remove old entries
            self.threat_database = {
                k: v for k, v in self.threat_database.items()
                if current_time - v['last_seen'] <= timedelta(days=7)
            }
            
            # Add new threats
            for threat in threat_data:
                key = self.generate_threat_key(threat)
                
                if key in self.threat_database:
                    # Update existing entry
                    self.threat_database[key]['occurrence_count'] += 1
                    self.threat_database[key]['last_seen'] = current_time
                    self.threat_database[key]['confidence'] = max(
                        self.threat_database[key]['confidence'],
                        threat['confidence']
                    )
                else:
                    # Add new entry
                    self.threat_database[key] = {
                        'first_seen': current_time,
                        'last_seen': current_time,
                        'occurrence_count': 1,
                        'confidence': threat['confidence'],
                        'indicators': threat['indicators'],
                        'type': threat['threat_type']
                    }
                    
        except Exception as e:
            logger.error(f"Error updating threat database: {e}")
            
    def analyze_threat_patterns(self, threat_data):
        """Analyze patterns in threat data"""
        try:
            patterns = {
                'temporal': self.analyze_temporal_patterns(threat_data),
                'indicator': self.analyze_indicator_patterns(threat_data),
                'emerging': self.detect_emerging_threats(threat_data)
            }
            
            # Update pattern memory
            self.update_pattern_memory(patterns)
            
            return patterns
            
        except Exception as e:
            logger.error(f"Error analyzing threat patterns: {e}")
            return {}
            
    def generate_threat_report(self, patterns):
        """Generate comprehensive threat intelligence report"""
        try:
            report = {
                'timestamp': datetime.now().isoformat(),
                'summary': {
                    'total_threats': len(self.threat_database),
                    'new_threats': self.count_new_threats(),
                    'high_confidence_threats': self.count_high_confidence_threats()
                },
                'patterns': patterns,
                'recommendations': self.generate_recommendations(patterns),
                'emerging_threats': self.get_emerging_threats(),
                'trend_analysis': self.analyze_trends()
            }
            
            return report
            
        except Exception as e:
            logger.error(f"Error generating threat report: {e}")
            return None
            
    def extract_threat_features(self, threat_data):
        """Extract features from threat data for analysis"""
        try:
            # Convert text data to embeddings
            text_data = json.dumps(threat_data)
            inputs = self.tokenizer(
                text_data,
                return_tensors="pt",
                truncation=True,
                max_length=512
            )
            
            with torch.no_grad():
                outputs = self.model(**inputs)
                embeddings = outputs.last_hidden_state.mean(dim=1)
                
            return embeddings.numpy().flatten()
            
        except Exception as e:
            logger.error(f"Error extracting threat features: {e}")
            return np.zeros(768)  # BERT embedding size
            
    def calculate_threat_score(self, threat_data):
        """Calculate threat score based on multiple factors"""
        try:
            # Base score from confidence
            score = threat_data.get('confidence', 0.5)
            
            # Adjust based on severity
            severity_weight = {
                'critical': 1.0,
                'high': 0.8,
                'medium': 0.6,
                'low': 0.4
            }
            score *= severity_weight.get(threat_data.get('severity', 'medium'), 0.6)
            
            # Adjust based on number of indicators
            indicator_count = len(threat_data.get('indicators', []))
            score *= min(1.0, 0.5 + (indicator_count * 0.1))
            
            return min(1.0, score)
            
        except Exception as e:
            logger.error(f"Error calculating threat score: {e}")
            return 0.5
            
    def generate_threat_key(self, threat):
        """Generate unique key for threat data"""
        try:
            # Combine relevant fields for key generation
            key_data = f"{threat['threat_type']}_{sorted(threat['indicators'])}"
            return hash(key_data)
        except Exception as e:
            logger.error(f"Error generating threat key: {e}")
            return None
            
    def analyze_temporal_patterns(self, threat_data):
        """Analyze temporal patterns in threats"""
        try:
            timestamps = [
                datetime.fromisoformat(t['timestamp'])
                for t in threat_data
            ]
            
            return {
                'frequency': self.calculate_frequency(timestamps),
                'peak_times': self.identify_peak_times(timestamps),
                'temporal_clusters': self.detect_temporal_clusters(timestamps)
            }
            
        except Exception as e:
            logger.error(f"Error analyzing temporal patterns: {e}")
            return {}
            
    def analyze_indicator_patterns(self, threat_data):
        """Analyze patterns in threat indicators"""
        try:
            all_indicators = [
                indicator
                for threat in threat_data
                for indicator in threat['indicators']
            ]
            
            return {
                'common_indicators': self.find_common_indicators(all_indicators),
                'indicator_correlations': self.calculate_indicator_correlations(all_indicators),
                'emerging_indicators': self.detect_emerging_indicators(all_indicators)
            }
            
        except Exception as e:
            logger.error(f"Error analyzing indicator patterns: {e}")
            return {}
            
    def detect_emerging_threats(self, threat_data):
        """Detect emerging threat patterns"""
        try:
            # Extract features for anomaly detection
            features = np.array([
                self.extract_threat_features(threat)
                for threat in threat_data
            ])
            
            # Use Isolation Forest for anomaly detection
            anomaly_scores = self.isolation_forest.fit_predict(features)
            
            # Identify emerging threats
            emerging_threats = []
            for i, score in enumerate(anomaly_scores):
                if score == -1:  # Anomaly detected
                    threat = threat_data[i]
                    emerging_threats.append({
                        'threat': threat,
                        'anomaly_score': self.isolation_forest.score_samples([features[i]])[0],
                        'detection_time': datetime.now().isoformat()
                    })
            
            return emerging_threats
            
        except Exception as e:
            logger.error(f"Error detecting emerging threats: {e}")
            return []
            
    def update_pattern_memory(self, patterns):
        """Update pattern memory with new observations"""
        try:
            current_time = datetime.now()
            
            # Remove old patterns
            self.pattern_memory = {
                k: v for k, v in self.pattern_memory.items()
                if current_time - v['last_updated'] <= timedelta(days=30)
            }
            
            # Update with new patterns
            for pattern_type, pattern_data in patterns.items():
                if pattern_type not in self.pattern_memory:
                    self.pattern_memory[pattern_type] = {
                        'data': pattern_data,
                        'first_seen': current_time,
                        'last_updated': current_time,
                        'occurrence_count': 1
                    }
                else:
                    self.pattern_memory[pattern_type]['data'] = pattern_data
                    self.pattern_memory[pattern_type]['last_updated'] = current_time
                    self.pattern_memory[pattern_type]['occurrence_count'] += 1
                    
        except Exception as e:
            logger.error(f"Error updating pattern memory: {e}")
            
    def calculate_frequency(self, timestamps):
        """Calculate frequency distribution of threats"""
        try:
            if not timestamps:
                return {}
                
            # Calculate time differences
            sorted_timestamps = sorted(timestamps)
            time_diffs = [
                (t2 - t1).total_seconds()
                for t1, t2 in zip(sorted_timestamps[:-1], sorted_timestamps[1:])
            ]
            
            if not time_diffs:
                return {'average_interval': 0, 'frequency_per_hour': 0}
                
            # Calculate statistics
            avg_interval = sum(time_diffs) / len(time_diffs)
            freq_per_hour = 3600 / avg_interval if avg_interval > 0 else 0
            
            return {
                'average_interval': avg_interval,
                'frequency_per_hour': freq_per_hour
            }
            
        except Exception as e:
            logger.error(f"Error calculating frequency: {e}")
            return {}
            
    def identify_peak_times(self, timestamps):
        """Identify peak times for threat activity"""
        try:
            if not timestamps:
                return {}
                
            # Group by hour
            hour_counts = {}
            for ts in timestamps:
                hour = ts.hour
                hour_counts[hour] = hour_counts.get(hour, 0) + 1
                
            # Find peak hours
            if not hour_counts:
                return {'peak_hours': [], 'peak_count': 0}
                
            max_count = max(hour_counts.values())
            peak_hours = [
                hour for hour, count in hour_counts.items()
                if count == max_count
            ]
            
            return {
                'peak_hours': peak_hours,
                'peak_count': max_count
            }
            
        except Exception as e:
            logger.error(f"Error identifying peak times: {e}")
            return {}
            
    def detect_temporal_clusters(self, timestamps):
        """Detect temporal clusters of threat activity"""
        try:
            if not timestamps:
                return []
                
            clusters = []
            current_cluster = []
            
            # Sort timestamps
            sorted_timestamps = sorted(timestamps)
            
            # Initialize with first timestamp
            current_cluster.append(sorted_timestamps[0])
            
            # Cluster threshold (e.g., 1 hour)
            threshold = timedelta(hours=1)
            
            # Find clusters
            for ts in sorted_timestamps[1:]:
                if ts - current_cluster[-1] <= threshold:
                    current_cluster.append(ts)
                else:
                    if len(current_cluster) > 1:
                        clusters.append({
                            'start': current_cluster[0],
                            'end': current_cluster[-1],
                            'count': len(current_cluster)
                        })
                    current_cluster = [ts]
                    
            # Add last cluster
            if len(current_cluster) > 1:
                clusters.append({
                    'start': current_cluster[0],
                    'end': current_cluster[-1],
                    'count': len(current_cluster)
                })
                
            return clusters
            
        except Exception as e:
            logger.error(f"Error detecting temporal clusters: {e}")
            return []
            
    def find_common_indicators(self, indicators):
        """Find common indicators across threats"""
        try:
            if not indicators:
                return {}
                
            # Count indicator occurrences
            indicator_counts = {}
            for indicator in indicators:
                indicator_counts[indicator] = indicator_counts.get(indicator, 0) + 1
                
            # Sort by frequency
            sorted_indicators = sorted(
                indicator_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )
            
            return {
                'top_indicators': sorted_indicators[:10],
                'total_unique': len(indicator_counts)
            }
            
        except Exception as e:
            logger.error(f"Error finding common indicators: {e}")
            return {}
            
    def calculate_indicator_correlations(self, indicators):
        """Calculate correlations between different indicators"""
        try:
            if not indicators:
                return {}
                
            # Create correlation matrix
            unique_indicators = list(set(indicators))
            n = len(unique_indicators)
            correlation_matrix = np.zeros((n, n))
            
            # Calculate co-occurrence
            for i in range(n):
                for j in range(i + 1, n):
                    count_i = indicators.count(unique_indicators[i])
                    count_j = indicators.count(unique_indicators[j])
                    count_both = sum(
                        1 for k in range(len(indicators) - 1)
                        if indicators[k] == unique_indicators[i]
                        and indicators[k + 1] == unique_indicators[j]
                    )
                    
                    correlation = count_both / min(count_i, count_j) if min(count_i, count_j) > 0 else 0
                    correlation_matrix[i, j] = correlation
                    correlation_matrix[j, i] = correlation
                    
            return {
                'indicators': unique_indicators,
                'correlations': correlation_matrix.tolist()
            }
            
        except Exception as e:
            logger.error(f"Error calculating indicator correlations: {e}")
            return {}
            
    def detect_emerging_indicators(self, indicators):
        """Detect newly emerging or trending indicators"""
        try:
            if not indicators:
                return {}
                
            # Get historical indicators
            historical_indicators = set()
            for pattern in self.pattern_memory.values():
                if 'indicator' in pattern['data']:
                    historical_indicators.update(
                        ind for ind, _ in pattern['data'].get('common_indicators', {}).get('top_indicators', [])
                    )
                    
            # Find new indicators
            current_indicators = set(indicators)
            new_indicators = current_indicators - historical_indicators
            
            # Calculate frequency for new indicators
            new_indicator_freq = {
                indicator: indicators.count(indicator)
                for indicator in new_indicators
            }
            
            return {
                'new_indicators': sorted(
                    new_indicator_freq.items(),
                    key=lambda x: x[1],
                    reverse=True
                )
            }
            
        except Exception as e:
            logger.error(f"Error detecting emerging indicators: {e}")
            return {}
            
    def count_new_threats(self):
        """Count new threats in the last 24 hours"""
        try:
            current_time = datetime.now()
            return sum(
                1 for threat in self.threat_database.values()
                if current_time - threat['first_seen'] <= timedelta(days=1)
            )
        except Exception as e:
            logger.error(f"Error counting new threats: {e}")
            return 0
            
    def count_high_confidence_threats(self):
        """Count high confidence threats"""
        try:
            return sum(
                1 for threat in self.threat_database.values()
                if threat['confidence'] >= 0.8
            )
        except Exception as e:
            logger.error(f"Error counting high confidence threats: {e}")
            return 0
            
    def generate_recommendations(self, patterns):
        """Generate security recommendations based on threat patterns"""
        try:
            recommendations = []
            
            # Check temporal patterns
            if patterns.get('temporal', {}).get('frequency_per_hour', 0) > 10:
                recommendations.append({
                    'priority': 'high',
                    'type': 'monitoring',
                    'action': 'Increase monitoring frequency due to high threat activity'
                })
                
            # Check indicator patterns
            common_indicators = patterns.get('indicator', {}).get('common_indicators', {})
            if common_indicators.get('top_indicators'):
                recommendations.append({
                    'priority': 'medium',
                    'type': 'protection',
                    'action': 'Update security rules to address most common threat indicators'
                })
                
            # Check emerging threats
            if patterns.get('emerging'):
                recommendations.append({
                    'priority': 'high',
                    'type': 'investigation',
                    'action': 'Investigate newly detected threat patterns'
                })
                
            return recommendations
            
        except Exception as e:
            logger.error(f"Error generating recommendations: {e}")
            return []
            
    def get_emerging_threats(self):
        """Get list of emerging threats"""
        try:
            current_time = datetime.now()
            emerging_threats = []
            
            for threat_id, threat in self.threat_database.items():
                # Consider threats from last 24 hours with high confidence
                if (current_time - threat['first_seen'] <= timedelta(days=1)
                        and threat['confidence'] >= 0.7):
                    emerging_threats.append({
                        'id': threat_id,
                        'type': threat['type'],
                        'confidence': threat['confidence'],
                        'indicators': threat['indicators'],
                        'first_seen': threat['first_seen'].isoformat()
                    })
                    
            return sorted(
                emerging_threats,
                key=lambda x: x['confidence'],
                reverse=True
            )
            
        except Exception as e:
            logger.error(f"Error getting emerging threats: {e}")
            return []
            
    def analyze_trends(self):
        """Analyze threat trends over time"""
        try:
            trends = {
                'daily': self.calculate_daily_trends(),
                'weekly': self.calculate_weekly_trends(),
                'monthly': self.calculate_monthly_trends()
            }
            
            return trends
            
        except Exception as e:
            logger.error(f"Error analyzing trends: {e}")
            return {}
            
    def calculate_daily_trends(self):
        """Calculate daily threat trends"""
        try:
            current_time = datetime.now()
            daily_counts = {}
            
            # Count threats by day
            for threat in self.threat_database.values():
                day = threat['first_seen'].date()
                daily_counts[day] = daily_counts.get(day, 0) + 1
                
            # Calculate trend
            if len(daily_counts) >= 2:
                days = sorted(daily_counts.keys())
                trend = (daily_counts[days[-1]] - daily_counts[days[0]]) / len(days)
            else:
                trend = 0
                
            return {
                'counts': daily_counts,
                'trend': trend
            }
            
        except Exception as e:
            logger.error(f"Error calculating daily trends: {e}")
            return {}
            
    def calculate_weekly_trends(self):
        """Calculate weekly threat trends"""
        try:
            current_time = datetime.now()
            weekly_counts = {}
            
            # Count threats by week
            for threat in self.threat_database.values():
                week = threat['first_seen'].isocalendar()[1]
                weekly_counts[week] = weekly_counts.get(week, 0) + 1
                
            # Calculate trend
            if len(weekly_counts) >= 2:
                weeks = sorted(weekly_counts.keys())
                trend = (weekly_counts[weeks[-1]] - weekly_counts[weeks[0]]) / len(weeks)
            else:
                trend = 0
                
            return {
                'counts': weekly_counts,
                'trend': trend
            }
            
        except Exception as e:
            logger.error(f"Error calculating weekly trends: {e}")
            return {}
            
    def calculate_monthly_trends(self):
        """Calculate monthly threat trends"""
        try:
            current_time = datetime.now()
            monthly_counts = {}
            
            # Count threats by month
            for threat in self.threat_database.values():
                month = threat['first_seen'].strftime('%Y-%m')
                monthly_counts[month] = monthly_counts.get(month, 0) + 1
                
            # Calculate trend
            if len(monthly_counts) >= 2:
                months = sorted(monthly_counts.keys())
                trend = (monthly_counts[months[-1]] - monthly_counts[months[0]]) / len(months)
            else:
                trend = 0
                
            return {
                'counts': monthly_counts,
                'trend': trend
            }
            
        except Exception as e:
            logger.error(f"Error calculating monthly trends: {e}")
            return {}
            
    def initialize_models(self):
        """Initialize threat detection models."""
        try:
            # Initialize threat analysis model
            self.threat_model = RandomForestClassifier(n_estimators=100, random_state=42)
            
            # Initialize pattern detector
            self.pattern_detector = IsolationForest(
                n_estimators=100,
                contamination=0.1,
                random_state=42
            )
            
            # Initialize with baseline threat data
            self._initialize_threat_data()
            
            logger.info("Threat intelligence models initialized successfully")
        except Exception as e:
            logger.error(f"Error initializing threat intelligence models: {str(e)}")
            raise

    def _initialize_threat_data(self):
        """Initialize with baseline threat data."""
        # Example threat patterns
        threat_patterns = [
            {
                'type': 'phishing',
                'indicators': ['login', 'password', 'verify'],
                'severity': 'high'
            },
            {
                'type': 'malware',
                'indicators': ['download', 'exe', 'update'],
                'severity': 'critical'
            },
            {
                'type': 'data_theft',
                'indicators': ['admin', 'config', 'backup'],
                'severity': 'high'
            }
        ]
        
        # Convert patterns to features
        features = []
        labels = []
        
        for pattern in threat_patterns:
            # Create feature vector
            feature_vec = [
                len(pattern['indicators']),
                1 if pattern['severity'] == 'critical' else 0,
                1 if pattern['severity'] == 'high' else 0,
                1 if pattern['type'] == 'phishing' else 0,
                1 if pattern['type'] == 'malware' else 0,
                1 if pattern['type'] == 'data_theft' else 0
            ]
            features.append(feature_vec)
            labels.append(1)  # 1 for known threats
        
        # Add some non-threat patterns
        non_threats = [
            ['home', 'about', 'contact'],
            ['products', 'services', 'support'],
            ['news', 'blog', 'events']
        ]
        
        for indicators in non_threats:
            feature_vec = [
                len(indicators),
                0,  # not critical
                0,  # not high
                0,  # not phishing
                0,  # not malware
                0   # not data theft
            ]
            features.append(feature_vec)
            labels.append(0)  # 0 for non-threats
        
        # Train the models
        self.threat_model.fit(features, labels)
        self.pattern_detector.fit(features)

    def analyze_threat(self, data):
        """Analyze potential threats in the data."""
        try:
            # Extract features
            features = self._extract_threat_features(data)
            
            if features.size == 0:
                raise ValueError("No features could be extracted from the data")
            
            # Get threat prediction
            threat_prob = self.threat_model.predict_proba(features.reshape(1, -1))[0][1]
            
            # Get anomaly score
            anomaly_score = self.pattern_detector.score_samples(features.reshape(1, -1))[0]
            normalized_score = 1.0 / (1.0 + np.exp(-anomaly_score))
            
            # Analyze threat patterns
            threat_patterns = self._analyze_threat_patterns(data)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(threat_prob, normalized_score, threat_patterns)
            
            return {
                'threat_level': float(threat_prob),
                'confidence': float(normalized_score),
                'patterns': threat_patterns,
                'recommendations': recommendations
            }
        except Exception as e:
            logger.error(f"Error in threat analysis: {str(e)}")
            return {
                'threat_level': 0.5,
                'confidence': 0.0,
                'patterns': {},
                'recommendations': ['Error performing threat analysis']
            }

    def _extract_threat_features(self, data):
        """Extract features for threat analysis."""
        features = []
        
        # Count indicators
        indicators = self._extract_indicators(data)
        features.append(len(indicators))
        
        # Severity indicators
        severity_indicators = {
            'critical': ['password', 'admin', 'root', 'config'],
            'high': ['login', 'auth', 'token', 'key'],
            'medium': ['user', 'account', 'profile', 'settings']
        }
        
        features.extend([
            1 if any(ind in str(data).lower() for ind in severity_indicators['critical']) else 0,
            1 if any(ind in str(data).lower() for ind in severity_indicators['high']) else 0
        ])
        
        # Threat type indicators
        threat_types = {
            'phishing': ['verify', 'confirm', 'update', 'secure'],
            'malware': ['exe', 'download', 'update', 'install'],
            'data_theft': ['admin', 'config', 'backup', 'database']
        }
        
        features.extend([
            1 if any(ind in str(data).lower() for ind in threat_types['phishing']) else 0,
            1 if any(ind in str(data).lower() for ind in threat_types['malware']) else 0,
            1 if any(ind in str(data).lower() for ind in threat_types['data_theft']) else 0
        ])
        
        return np.array(features)

    def _extract_indicators(self, data):
        """Extract threat indicators from data."""
        indicators = []
        
        # Extract from URL if present
        if 'url' in data:
            url = data['url'].lower()
            indicators.extend([
                word for word in url.split('/')
                if len(word) > 3  # Filter out short segments
            ])
        
        # Extract from content if present
        if 'content' in data:
            content = data['content'].lower()
            # Extract words that might be indicators
            indicators.extend([
                word for word in re.findall(r'\w+', content)
                if len(word) > 3  # Filter out short words
            ])
        
        # Extract from behavior if present
        if 'behavior' in data:
            behavior = data['behavior']
            # Add event types
            indicators.extend([
                e.get('type', '') for e in behavior.get('events', [])
            ])
            # Add form field names
            for form in behavior.get('forms', []):
                indicators.extend([
                    f.get('name', '') for f in form.get('fields', [])
                ])
        
        return list(set(indicators))  # Remove duplicates

    def _analyze_threat_patterns(self, data):
        """Analyze specific patterns that might indicate threats."""
        patterns = {}
        
        # URL patterns
        if 'url' in data:
            url = data['url'].lower()
            patterns['url_patterns'] = {
                'suspicious_chars': bool(re.search(r'[<>\'"]', url)),
                'encoded_chars': bool(re.search(r'%[0-9a-fA-F]{2}', url)),
                'suspicious_keywords': [
                    word for word in ['admin', 'login', 'password', 'token']
                    if word in url
                ]
            }
        
        # Content patterns
        if 'content' in data:
            content = data['content'].lower()
            patterns['content_patterns'] = {
                'sensitive_terms': [
                    word for word in ['password', 'credit', 'ssn', 'secret']
                    if word in content
                ],
                'action_terms': [
                    word for word in ['verify', 'confirm', 'update', 'download']
                    if word in content
                ]
            }
        
        # Behavior patterns
        if 'behavior' in data:
            behavior = data['behavior']
            patterns['behavior_patterns'] = {
                'form_submissions': len(behavior.get('forms', [])),
                'suspicious_events': [
                    e.get('type') for e in behavior.get('events', [])
                    if e.get('type') in ['submit', 'download', 'redirect']
                ]
            }
        
        return patterns

    def _generate_recommendations(self, threat_prob, anomaly_score, patterns):
        """Generate security recommendations based on analysis."""
        recommendations = []
        
        # High-level threat recommendations
        if threat_prob > 0.7:
            recommendations.append("High threat level detected. Exercise extreme caution.")
        elif threat_prob > 0.4:
            recommendations.append("Moderate threat level detected. Proceed with caution.")
        
        # Pattern-specific recommendations
        if 'url_patterns' in patterns:
            url_patterns = patterns['url_patterns']
            if url_patterns.get('suspicious_chars'):
                recommendations.append("URL contains suspicious characters. Verify the destination.")
            if url_patterns.get('suspicious_keywords'):
                recommendations.append("URL contains sensitive terms. Verify the authenticity.")
        
        if 'content_patterns' in patterns:
            content_patterns = patterns['content_patterns']
            if content_patterns.get('sensitive_terms'):
                recommendations.append("Content requests sensitive information. Verify the source.")
            if content_patterns.get('action_terms'):
                recommendations.append("Content requires user action. Verify the request is legitimate.")
        
        if 'behavior_patterns' in patterns:
            behavior_patterns = patterns['behavior_patterns']
            if behavior_patterns.get('form_submissions', 0) > 2:
                recommendations.append("Multiple form submissions detected. Check for data harvesting.")
            if behavior_patterns.get('suspicious_events'):
                recommendations.append("Suspicious user events detected. Monitor for unauthorized actions.")
        
        # Anomaly-based recommendations
        if anomaly_score > 0.7:
            recommendations.append("Unusual patterns detected. This might be a new type of threat.")
        
        return recommendations 
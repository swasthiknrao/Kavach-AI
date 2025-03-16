from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import numpy as np
import tensorflow as tf

class AnomalyDetector:
    def __init__(self):
        self.isolation_forest = IsolationForest(contamination=0.1)
        self.autoencoder = self.build_autoencoder()
        self.scaler = StandardScaler()

    def build_autoencoder(self):
        """Build deep autoencoder for anomaly detection"""
        encoder = tf.keras.Sequential([
            tf.keras.layers.Dense(64, activation='relu'),
            tf.keras.layers.Dense(32, activation='relu'),
            tf.keras.layers.Dense(16, activation='relu')
        ])
        
        decoder = tf.keras.Sequential([
            tf.keras.layers.Dense(32, activation='relu'),
            tf.keras.layers.Dense(64, activation='relu'),
            tf.keras.layers.Dense(128, activation='sigmoid')
        ])
        
        return tf.keras.Sequential([encoder, decoder])

    async def detect_anomalies(self, data):
        """Multi-model anomaly detection"""
        scaled_data = self.scaler.fit_transform(data)
        
        # Isolation Forest detection
        if_scores = self.isolation_forest.fit_predict(scaled_data)
        
        # Autoencoder detection
        reconstructed = self.autoencoder.predict(scaled_data)
        reconstruction_error = np.mean(np.power(scaled_data - reconstructed, 2), axis=1)
        
        return {
            'isolation_forest_scores': if_scores,
            'reconstruction_errors': reconstruction_error,
            'combined_score': self.combine_anomaly_scores(if_scores, reconstruction_error)
        }

    def combine_anomaly_scores(self, if_scores, recon_errors):
        """Combine multiple anomaly detection methods"""
        normalized_if = (if_scores + 1) / 2  # Convert to [0,1] range
        normalized_recon = (recon_errors - min(recon_errors)) / (max(recon_errors) - min(recon_errors))
        
        return 0.6 * normalized_if + 0.4 * normalized_recon 
import tensorflow as tf
import numpy as np
from cryptography.fernet import Fernet
import json
import logging

class FederatedLearner:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.encryption_key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.encryption_key)
        self.local_model = None
        self.aggregated_weights = None
        self.min_clients = 3
        self.current_round = 0
        self.client_updates = []
        
    def initialize_model(self, model):
        """Initialize the local model for federated learning"""
        self.local_model = model
        self.base_weights = [layer.numpy() for layer in model.get_weights()]
        
    def prepare_local_update(self, model_weights, training_metadata):
        """Prepare local model update for federated learning"""
        try:
            # Add differential privacy noise
            noised_weights = self.add_differential_privacy(model_weights)
            
            # Encrypt weights for secure transmission
            encrypted_weights = self.encrypt_weights(noised_weights)
            
            # Prepare update package
            update_package = {
                'weights': encrypted_weights,
                'metadata': {
                    'round': self.current_round,
                    'timestamp': training_metadata.get('timestamp'),
                    'metrics': training_metadata.get('metrics'),
                    'client_id': training_metadata.get('client_id')
                }
            }
            
            return update_package
            
        except Exception as e:
            self.logger.error(f"Error preparing local update: {e}")
            return None
            
    def aggregate_updates(self, updates):
        """Aggregate model updates from multiple clients"""
        try:
            if len(updates) < self.min_clients:
                self.logger.warning(f"Not enough clients for aggregation: {len(updates)} < {self.min_clients}")
                return None
                
            # Decrypt and validate updates
            decrypted_updates = []
            for update in updates:
                try:
                    weights = self.decrypt_weights(update['weights'])
                    if self.validate_update(weights, update['metadata']):
                        decrypted_updates.append(weights)
                except Exception as e:
                    self.logger.error(f"Error processing update: {e}")
                    continue
            
            if not decrypted_updates:
                return None
                
            # Perform FedAvg aggregation
            aggregated = []
            for layer_weights in zip(*decrypted_updates):
                layer_avg = np.mean(layer_weights, axis=0)
                aggregated.append(layer_avg)
                
            self.aggregated_weights = aggregated
            self.current_round += 1
            
            return aggregated
            
        except Exception as e:
            self.logger.error(f"Error in update aggregation: {e}")
            return None
            
    def apply_global_update(self, model):
        """Apply aggregated update to local model"""
        if self.aggregated_weights is None:
            return False
            
        try:
            model.set_weights(self.aggregated_weights)
            return True
        except Exception as e:
            self.logger.error(f"Error applying global update: {e}")
            return False
            
    def add_differential_privacy(self, weights, epsilon=1.0):
        """Add differential privacy noise to weights"""
        try:
            noised_weights = []
            for layer in weights:
                # Add Gaussian noise scaled by sensitivity/epsilon
                sensitivity = np.std(layer) * 0.1  # Example sensitivity calculation
                noise_scale = sensitivity / epsilon
                noise = np.random.normal(0, noise_scale, layer.shape)
                noised_weights.append(layer + noise)
            return noised_weights
        except Exception as e:
            self.logger.error(f"Error adding differential privacy: {e}")
            return weights
            
    def encrypt_weights(self, weights):
        """Encrypt model weights for secure transmission"""
        try:
            weights_bytes = json.dumps([w.tolist() for w in weights]).encode()
            return self.cipher_suite.encrypt(weights_bytes)
        except Exception as e:
            self.logger.error(f"Error encrypting weights: {e}")
            return None
            
    def decrypt_weights(self, encrypted_weights):
        """Decrypt received model weights"""
        try:
            decrypted_bytes = self.cipher_suite.decrypt(encrypted_weights)
            weights_list = json.loads(decrypted_bytes.decode())
            return [np.array(w) for w in weights_list]
        except Exception as e:
            self.logger.error(f"Error decrypting weights: {e}")
            return None
            
    def validate_update(self, weights, metadata):
        """Validate received model update"""
        try:
            # Check if weights have the same structure as base model
            if len(weights) != len(self.base_weights):
                return False
                
            # Check if weights are within reasonable bounds
            for w, base_w in zip(weights, self.base_weights):
                if w.shape != base_w.shape:
                    return False
                if np.any(np.isnan(w)) or np.any(np.isinf(w)):
                    return False
                    
            # Validate metadata
            if metadata['round'] != self.current_round:
                return False
                
            return True
            
        except Exception as e:
            self.logger.error(f"Error validating update: {e}")
            return False 
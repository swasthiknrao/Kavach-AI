import tensorflow as tf
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import pickle
import os
import cv2

class MLModelUtils:
    """
    Utility class for machine learning model operations used across the project.
    Provides common functionality for model loading, saving, evaluation, and preprocessing.
    """
    
    @staticmethod
    def load_model(model_path, custom_objects=None):
        """
        Load a TensorFlow/Keras model from disk.
        
        Args:
            model_path (str): Path to the saved model
            custom_objects (dict): Dictionary of custom objects for the model
            
        Returns:
            The loaded model
        """
        try:
            if model_path.endswith('.h5'):
                return tf.keras.models.load_model(model_path, custom_objects=custom_objects)
            else:
                return tf.saved_model.load(model_path)
        except Exception as e:
            print(f"Error loading model from {model_path}: {str(e)}")
            return None
    
    @staticmethod
    def save_model(model, model_path):
        """
        Save a TensorFlow/Keras model to disk.
        
        Args:
            model: The model to save
            model_path (str): Path where to save the model
        """
        try:
            if model_path.endswith('.h5'):
                model.save(model_path)
            else:
                tf.saved_model.save(model, model_path)
            return True
        except Exception as e:
            print(f"Error saving model to {model_path}: {str(e)}")
            return False
    
    @staticmethod
    def load_sklearn_model(model_path):
        """
        Load a scikit-learn model from disk.
        
        Args:
            model_path (str): Path to the saved model
            
        Returns:
            The loaded model
        """
        try:
            with open(model_path, 'rb') as f:
                return pickle.load(f)
        except Exception as e:
            print(f"Error loading scikit-learn model from {model_path}: {str(e)}")
            return None
    
    @staticmethod
    def save_sklearn_model(model, model_path):
        """
        Save a scikit-learn model to disk.
        
        Args:
            model: The model to save
            model_path (str): Path where to save the model
        """
        try:
            with open(model_path, 'wb') as f:
                pickle.dump(model, f)
            return True
        except Exception as e:
            print(f"Error saving scikit-learn model to {model_path}: {str(e)}")
            return False
    
    @staticmethod
    def evaluate_model(model, X_test, y_test):
        """
        Evaluate a model's performance.
        
        Args:
            model: The model to evaluate
            X_test: Test features
            y_test: Test labels
            
        Returns:
            dict: Dictionary containing evaluation metrics
        """
        try:
            if isinstance(model, tf.keras.Model):
                # For Keras models
                loss, accuracy = model.evaluate(X_test, y_test, verbose=0)
                y_pred = (model.predict(X_test) > 0.5).astype(int)
            else:
                # For scikit-learn models
                y_pred = model.predict(X_test)
                accuracy = accuracy_score(y_test, y_pred)
            
            precision = precision_score(y_test, y_pred, average='weighted', zero_division=0)
            recall = recall_score(y_test, y_pred, average='weighted', zero_division=0)
            f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)
            
            return {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1_score': f1
            }
        except Exception as e:
            print(f"Error evaluating model: {str(e)}")
            return {
                'accuracy': 0,
                'precision': 0,
                'recall': 0,
                'f1_score': 0
            }
    
    @staticmethod
    def preprocess_image(image, target_size=(224, 224)):
        """
        Preprocess an image for neural network input.
        
        Args:
            image: Input image (numpy array or path to image)
            target_size: Target size for resizing
            
        Returns:
            Preprocessed image
        """
        try:
            # If image is a path, load it
            if isinstance(image, str):
                image = cv2.imread(image)
                
            # Resize image
            image = cv2.resize(image, target_size)
            
            # Convert to RGB if it's BGR
            if image.shape[-1] == 3:
                image = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
            
            # Normalize pixel values
            image = image.astype(np.float32) / 255.0
            
            # Add batch dimension if needed
            if len(image.shape) == 3:
                image = np.expand_dims(image, axis=0)
                
            return image
        except Exception as e:
            print(f"Error preprocessing image: {str(e)}")
            return None
    
    @staticmethod
    def create_ensemble_model(models, weights=None):
        """
        Create an ensemble model from multiple models.
        
        Args:
            models: List of models to ensemble
            weights: Optional weights for each model
            
        Returns:
            Function that takes input and returns ensemble prediction
        """
        if weights is None:
            weights = [1.0/len(models)] * len(models)
            
        def ensemble_predict(X):
            predictions = []
            for i, model in enumerate(models):
                pred = model.predict(X)
                if len(pred.shape) > 1 and pred.shape[1] > 1:
                    # For multi-class classification
                    predictions.append(pred * weights[i])
                else:
                    # For binary classification
                    predictions.append(pred.flatten() * weights[i])
            
            # Sum predictions and normalize
            ensemble_pred = np.sum(predictions, axis=0)
            if len(ensemble_pred.shape) > 1 and ensemble_pred.shape[1] > 1:
                # For multi-class, return class probabilities
                return ensemble_pred
            else:
                # For binary, threshold at 0.5
                return (ensemble_pred > 0.5).astype(int)
        
        return ensemble_predict 
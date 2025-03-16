"""
ONNX Runtime Utilities for Kavach AI Security

This module provides utility functions to work with ONNX models as a replacement for TensorFlow.
ONNX Runtime is a lightweight, high-performance inference engine for ONNX models.
"""

import os
import numpy as np
import onnxruntime as ort
import logging
from PIL import Image
import pickle
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)

class ONNXModelUtils:
    """Utility class for working with ONNX models"""
    
    @staticmethod
    def load_model(model_path):
        """
        Load an ONNX model from disk
        
        Args:
            model_path (str): Path to the ONNX model file
            
        Returns:
            onnxruntime.InferenceSession: The loaded ONNX model session
        """
        try:
            # Create an InferenceSession for the ONNX model
            session_options = ort.SessionOptions()
            session_options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
            
            # Check if the model file exists
            if not os.path.exists(model_path):
                logger.error(f"Model file not found: {model_path}")
                return None
                
            # Load the model
            session = ort.InferenceSession(model_path, session_options)
            logger.info(f"Successfully loaded ONNX model from {model_path}")
            return session
            
        except Exception as e:
            logger.error(f"Error loading ONNX model from {model_path}: {str(e)}")
            return None
    
    @staticmethod
    def run_inference(model, input_data, input_names=None):
        """
        Run inference with an ONNX model
        
        Args:
            model (onnxruntime.InferenceSession): The ONNX model session
            input_data (dict or numpy.ndarray): Input data for the model
            input_names (list): Optional list of input names for the model
            
        Returns:
            dict or numpy.ndarray: The model's output
        """
        try:
            # If input_data is a numpy array and input_names is not provided,
            # get the input name from the model
            if isinstance(input_data, np.ndarray) and input_names is None:
                input_names = [model.get_inputs()[0].name]
                input_dict = {input_names[0]: input_data}
            elif isinstance(input_data, dict):
                input_dict = input_data
            else:
                # Convert input data to the right format
                input_dict = {model.get_inputs()[0].name: input_data}
            
            # Run inference
            outputs = model.run(None, input_dict)
            
            # Return the output
            if len(outputs) == 1:
                return outputs[0]
            else:
                return dict(zip([o.name for o in model.get_outputs()], outputs))
                
        except Exception as e:
            logger.error(f"Error running inference with ONNX model: {str(e)}")
            return None
    
    @staticmethod
    def convert_image_to_input(image, target_size=(224, 224), preprocessing=None):
        """
        Convert an image to the input format expected by ONNX models
        
        Args:
            image (PIL.Image or str): The input image or path to the image
            target_size (tuple): The target size for the image
            preprocessing (callable): Optional preprocessing function
            
        Returns:
            numpy.ndarray: The processed image ready for inference
        """
        try:
            # Load the image if a string path is provided
            if isinstance(image, str):
                image = Image.open(image)
            
            # Resize the image
            image = image.resize(target_size)
            
            # Convert to numpy array
            img_array = np.array(image)
            
            # Apply preprocessing if provided
            if preprocessing:
                img_array = preprocessing(img_array)
            else:
                # Default preprocessing: scale to [0, 1]
                img_array = img_array.astype(np.float32) / 255.0
                
                # Add batch dimension if needed
                if len(img_array.shape) == 3:
                    img_array = np.expand_dims(img_array, axis=0)
            
            return img_array
            
        except Exception as e:
            logger.error(f"Error converting image to input: {str(e)}")
            return None
    
    @staticmethod
    def save_model(model, model_path):
        """
        Save an ONNX model to disk
        
        Args:
            model: The model to save (needs to be already converted to ONNX)
            model_path (str): Path where to save the model
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Ensure the directory exists
            os.makedirs(os.path.dirname(model_path), exist_ok=True)
            
            # Save the model
            with open(model_path, 'wb') as f:
                f.write(model.SerializeToString())
            
            logger.info(f"Successfully saved ONNX model to {model_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving ONNX model to {model_path}: {str(e)}")
            return False
    
    @staticmethod
    def evaluate_model(model, X_test, y_test, input_name=None):
        """
        Evaluate an ONNX model's performance
        
        Args:
            model (onnxruntime.InferenceSession): The ONNX model to evaluate
            X_test (numpy.ndarray): Test features
            y_test (numpy.ndarray): Test labels
            input_name (str): Optional input name for the model
            
        Returns:
            dict: Dictionary containing evaluation metrics
        """
        try:
            from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
            
            # Get the input name if not provided
            if input_name is None:
                input_name = model.get_inputs()[0].name
            
            # Run inference
            input_dict = {input_name: X_test}
            outputs = model.run(None, input_dict)
            y_pred = outputs[0]
            
            # Convert to binary predictions if needed
            if y_pred.shape[-1] == 1:
                y_pred = (y_pred > 0.5).astype(int)
            elif y_pred.shape[-1] > 1:
                y_pred = np.argmax(y_pred, axis=1)
            
            # Calculate metrics
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
            logger.error(f"Error evaluating ONNX model: {str(e)}")
            return {
                'accuracy': 0,
                'precision': 0,
                'recall': 0,
                'f1_score': 0
            }
    
class ONNXModelConverter:
    """
    Class for converting TensorFlow and PyTorch models to ONNX
    
    This class provides methods to convert existing TensorFlow/Keras and PyTorch models
    to the ONNX format for use with ONNX Runtime.
    """
    
    @staticmethod
    def keras_to_onnx(keras_model, output_path, opset_version=12):
        """
        Convert a Keras model to ONNX format
        
        Args:
            keras_model: The Keras model to convert
            output_path (str): Path where to save the ONNX model
            opset_version (int): ONNX opset version to use
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            import tf2onnx
            import tensorflow as tf
            
            # Get model specs
            spec = (tf.TensorSpec((None, *keras_model.input_shape[1:]), tf.float32, name="input"),)
            
            # Convert the model
            output_path = output_path if output_path.endswith('.onnx') else output_path + '.onnx'
            onnx_model, _ = tf2onnx.convert.from_keras(keras_model, input_signature=spec, opset=opset_version)
            
            # Save the model
            with open(output_path, "wb") as f:
                f.write(onnx_model.SerializeToString())
            
            logger.info(f"Successfully converted Keras model to ONNX and saved to {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error converting Keras model to ONNX: {str(e)}")
            return False
    
    @staticmethod
    def pytorch_to_onnx(pytorch_model, dummy_input, output_path, input_names=None, output_names=None):
        """
        Convert a PyTorch model to ONNX format
        
        Args:
            pytorch_model: The PyTorch model to convert
            dummy_input: Dummy input to trace the model
            output_path (str): Path where to save the ONNX model
            input_names (list): Optional list of input names
            output_names (list): Optional list of output names
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            import torch
            
            # Set default input and output names if not provided
            if input_names is None:
                input_names = ["input"]
            if output_names is None:
                output_names = ["output"]
            
            # Ensure the model is in evaluation mode
            pytorch_model.eval()
            
            # Export the model
            output_path = output_path if output_path.endswith('.onnx') else output_path + '.onnx'
            torch.onnx.export(
                pytorch_model,
                dummy_input,
                output_path,
                input_names=input_names,
                output_names=output_names,
                export_params=True,
                opset_version=12,
                do_constant_folding=True,
                verbose=False
            )
            
            logger.info(f"Successfully converted PyTorch model to ONNX and saved to {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error converting PyTorch model to ONNX: {str(e)}")
            return False 
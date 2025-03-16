#!/usr/bin/env python
"""
Convert TensorFlow/Keras models to ONNX format for Kavach AI Security

This script helps convert existing TensorFlow/Keras models to ONNX format
for more efficient deployment with ONNX Runtime.
"""

import os
import argparse
import logging
import numpy as np
import glob
from tqdm import tqdm

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def find_keras_models(models_dir):
    """Find all Keras models in the specified directory"""
    h5_files = glob.glob(os.path.join(models_dir, "**/*.h5"), recursive=True)
    saved_model_dirs = glob.glob(os.path.join(models_dir, "**/saved_model"), recursive=True)
    
    return h5_files, saved_model_dirs

def convert_h5_to_onnx(model_path, output_dir):
    """Convert a Keras .h5 model to ONNX format"""
    try:
        import tensorflow as tf
        import tf2onnx
        
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Load the model
        logger.info(f"Loading model from {model_path}")
        model = tf.keras.models.load_model(model_path)
        
        # Get output path
        model_name = os.path.splitext(os.path.basename(model_path))[0]
        output_path = os.path.join(output_dir, f"{model_name}.onnx")
        
        # Get model input shape
        input_shape = model.input_shape[1:]
        spec = (tf.TensorSpec((None, *input_shape), tf.float32, name="input"),)
        
        # Convert the model
        logger.info(f"Converting model {model_name} to ONNX")
        onnx_model, _ = tf2onnx.convert.from_keras(model, input_signature=spec, opset=12)
        
        # Save the ONNX model
        with open(output_path, "wb") as f:
            f.write(onnx_model.SerializeToString())
        
        logger.info(f"Successfully converted and saved to {output_path}")
        return True
    
    except Exception as e:
        logger.error(f"Error converting {model_path} to ONNX: {str(e)}")
        return False

def convert_saved_model_to_onnx(model_dir, output_dir):
    """Convert a TensorFlow SavedModel to ONNX format"""
    try:
        import tensorflow as tf
        import tf2onnx
        
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Get model name from directory structure
        model_name = os.path.basename(os.path.dirname(model_dir))
        output_path = os.path.join(output_dir, f"{model_name}.onnx")
        
        # Load the model
        logger.info(f"Loading SavedModel from {model_dir}")
        model = tf.saved_model.load(model_dir)
        
        # Convert the model
        logger.info(f"Converting SavedModel {model_name} to ONNX")
        onnx_model, _ = tf2onnx.convert.from_saved_model(
            model_dir, 
            output_path=output_path,
            opset=12
        )
        
        logger.info(f"Successfully converted and saved to {output_path}")
        return True
    
    except Exception as e:
        logger.error(f"Error converting SavedModel {model_dir} to ONNX: {str(e)}")
        return False

def convert_pytorch_to_onnx(model_path, output_dir, input_shape=(1, 3, 224, 224)):
    """Convert a PyTorch model to ONNX format"""
    try:
        import torch
        
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Load the model
        logger.info(f"Loading PyTorch model from {model_path}")
        model = torch.load(model_path)
        model.eval()
        
        # Get output path
        model_name = os.path.splitext(os.path.basename(model_path))[0]
        output_path = os.path.join(output_dir, f"{model_name}.onnx")
        
        # Create dummy input
        dummy_input = torch.randn(input_shape)
        
        # Export the model
        logger.info(f"Converting PyTorch model {model_name} to ONNX")
        torch.onnx.export(
            model,
            dummy_input,
            output_path,
            export_params=True,
            opset_version=12,
            do_constant_folding=True,
            input_names=["input"],
            output_names=["output"],
            dynamic_axes={"input": {0: "batch_size"}, "output": {0: "batch_size"}}
        )
        
        logger.info(f"Successfully converted and saved to {output_path}")
        return True
    
    except Exception as e:
        logger.error(f"Error converting PyTorch model {model_path} to ONNX: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Convert ML models to ONNX format")
    parser.add_argument("--models_dir", type=str, default="backend/models",
                        help="Directory containing the models to convert")
    parser.add_argument("--output_dir", type=str, default="backend/models/onnx",
                        help="Directory to save the converted ONNX models")
    parser.add_argument("--pytorch", action="store_true",
                        help="Convert PyTorch models instead of TensorFlow models")
    parser.add_argument("--input_shape", type=str, default="1,3,224,224",
                        help="Input shape for PyTorch models (comma-separated)")
    
    args = parser.parse_args()
    
    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)
    
    if args.pytorch:
        # Find PyTorch models (.pt or .pth files)
        pytorch_models = glob.glob(os.path.join(args.models_dir, "**/*.pt"), recursive=True)
        pytorch_models.extend(glob.glob(os.path.join(args.models_dir, "**/*.pth"), recursive=True))
        
        if not pytorch_models:
            logger.warning(f"No PyTorch models found in {args.models_dir}")
            return
        
        # Parse input shape
        input_shape = tuple(map(int, args.input_shape.split(",")))
        
        # Convert PyTorch models
        logger.info(f"Found {len(pytorch_models)} PyTorch models to convert")
        for model_path in tqdm(pytorch_models):
            convert_pytorch_to_onnx(model_path, args.output_dir, input_shape)
    
    else:
        # Find Keras/TF models
        h5_models, saved_models = find_keras_models(args.models_dir)
        
        if not h5_models and not saved_models:
            logger.warning(f"No Keras/TensorFlow models found in {args.models_dir}")
            return
        
        # Convert H5 models
        if h5_models:
            logger.info(f"Found {len(h5_models)} .h5 models to convert")
            for model_path in tqdm(h5_models):
                convert_h5_to_onnx(model_path, args.output_dir)
        
        # Convert SavedModel models
        if saved_models:
            logger.info(f"Found {len(saved_models)} SavedModel directories to convert")
            for model_dir in tqdm(saved_models):
                convert_saved_model_to_onnx(model_dir, args.output_dir)
    
    logger.info(f"Conversion complete. ONNX models saved to {args.output_dir}")

if __name__ == "__main__":
    main() 
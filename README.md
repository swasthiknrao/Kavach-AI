# Kavach AI Security

## Overview

Kavach AI Security is an advanced browser extension that employs multi-layered AI analysis to detect and neutralize phishing attempts in real-time. Unlike traditional solutions that rely on outdated blacklists, Kavach uses cutting-edge AI techniques to identify suspicious websites based on their content, behavior, and visual elements.

## Key Features

- **Deep URL Analysis**: Identifies suspicious patterns, typosquatting, and URL manipulation techniques
- **Visual Fingerprinting**: Compares website visual elements against legitimate sites to detect brand impersonation
- **Behavioral Analysis**: Monitors for suspicious behaviors like unauthorized form submissions or keyloggers
- **Contextual Trust Scoring**: Provides personalized risk assessments
- **Real-time Protection**: Analyzes websites as you browse without slowing down your experience
- **Detailed Reports**: Offers comprehensive security analysis with clear explanations of detected threats
- **Whitelist Support**: Allows you to whitelist trusted sites that should not be analyzed

## Installation

### Development Installation

1. Clone the repository:
   ```
   git clone https://github.com/kavach-ai/kavach-extension.git
   ```

2. **IMPORTANT**: Before loading the extension, remove any `__pycache__` directories as they can cause loading errors:
   - Use the provided cleanup script: `.\cleanup_before_load.ps1` (PowerShell) or `cleanup_before_load.bat` (Command Prompt)
   - Or manually remove all `__pycache__` directories from the project

3. Open Chrome or any Chromium-based browser (like Edge, Brave, etc.)

4. Go to extension management:
   - Chrome: `chrome://extensions/`
   - Edge: `edge://extensions/`
   - Brave: `brave://extensions/`

5. Enable "Developer mode" (toggle in the top-right corner)

6. Click "Load unpacked" and select the cloned repository folder

7. The extension should now be installed and active

### Troubleshooting Installation

If you encounter the error "Cannot load extension with file or directory name __pycache__":
1. Run the cleanup script mentioned above
2. Make sure no `__pycache__` directories remain in the project folder
3. Try loading the extension again

### Running the Mock API Server

For development and testing, a mock API server is included:

1. Install Python requirements:
   ```
   pip install -r requirements.txt
   ```

2. Start the mock API server:
   ```
   python mock_api_server.py
   ```

3. The server will run at `http://127.0.0.1:9000`

## Usage

### Basic Usage

1. Browse the web as usual
2. Kavach AI Security will automatically analyze each page you visit
3. The extension icon will show the security status of the current site:
   - Green: Safe
   - Yellow: Suspicious (caution advised)
   - Red: High risk (potential phishing)

4. Click on the extension icon to see a detailed risk assessment

### Detailed Report

For a comprehensive security analysis, click the "View Detailed Report" button in the popup to see:

- Risk score and confidence level
- Detailed security findings
- Site information
- Security features
- Behavioral analysis
- Visual similarity detection

### Options

Access the options page to:

- Enable/disable protection
- Set warning notification levels
- Configure automatic blocking of high-risk sites
- Manage your whitelist of trusted sites
- Control privacy settings

## Technology Stack

- **Frontend**: JavaScript, HTML/CSS with React for the extension interface
- **Backend**: Python with Flask for the API server
- **Machine Learning**: ONNX Runtime for efficient model inference, scikit-learn for traditional ML algorithms
- **Computer Vision**: OpenCV and Pillow for image processing and analysis
- **Security**: Enterprise-grade security with multiple protection layers

## Benefits of ONNX Runtime

Kavach AI Security uses ONNX Runtime for model inference instead of TensorFlow for several advantages:

1. **Lightweight Deployment**: ONNX Runtime has a much smaller footprint than TensorFlow, making the backend more efficient
2. **Cross-Platform Compatibility**: ONNX models can be deployed across different environments without modification
3. **Performance Optimization**: ONNX Runtime includes optimizations for faster inference on various hardware
4. **Framework Agnostic**: Models trained in different frameworks (PyTorch, TensorFlow, etc.) can be converted to ONNX format
5. **Reduced Dependencies**: Fewer dependencies mean easier deployment and maintenance

## Development and Contribution

Nithish Achar – nithishachar29@gmail.com

Raveendra Prabhu -raveendra5656@gmail.com


## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contact

Swasthik N Rao – Nraoswasthik2004@gmail.com

GitHub: github.com/swasthiknrao

LinkedIn: linkedin.com/in/swasthik-n-rao

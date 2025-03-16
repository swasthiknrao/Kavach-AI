# Testing Kavach AI Security Extension

This document provides instructions for testing the Kavach AI Security extension for the hackathon evaluation.

## Setup Instructions

### 1. Backend Setup

1. Clone the repository:
   ```
   git clone https://github.com/RaveendraPrabhu/kavach-ai-security.git
   cd kavach-ai-security
   ```

2. Create and activate a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

   **IMPORTANT**: This project requires Python 3.10.x specifically. Other versions are not supported.

3. Install the required Python packages:
   ```
   pip install -r requirements.txt
   ```

4. Install the tf-keras package (required for compatibility with Transformers):
   ```
   pip install tf-keras
   ```

5. Set up your environment variables:
   - Copy `.env.example` to `.env`
   - Add your OpenAI API key to the `.env` file

6. Generate the required model files:
   ```
   python scripts/generate_models.py
   ```
   This will create the necessary model files for both the backend and extension.

7. Start the backend server:
   ```
   python backend/app.py
   ```
   The server will run on http://localhost:5000

### 2. Extension Setup

1. Install the required npm packages:
   ```
   npm install
   ```

2. Add TensorFlow.js to the extension:
   ```
   npm install @tensorflow/tfjs
   ```

3. Build the extension:
   ```
   npm run build
   ```

4. Open Chrome and navigate to `chrome://extensions/`
5. Enable "Developer mode" using the toggle in the top-right corner
6. Click "Load unpacked" and select the `dist` folder from the repository
7. The Kavach AI Security extension should now be installed and visible in your extensions list

## Testing Scenarios

### 1. Phishing Detection

1. Visit a known safe website (e.g., google.com)
   - The extension should show a low risk score

2. Visit a simulated phishing website (for testing purposes):
   - https://phishing-test.com (simulated URL)
   - The extension should detect this as a potential phishing attempt

### 2. Visual Analysis

1. Visit a legitimate banking website
   - The extension should recognize it as legitimate

2. Visit a website that mimics a banking website
   - The extension should detect visual similarities and flag it

### 3. URL Analysis

1. Test with various URLs:
   - Legitimate: https://www.paypal.com
   - Suspicious: https://paypal-secure.com (simulated)

### 4. Extension UI

1. Click on the extension icon to open the popup
   - Verify that the UI is responsive and displays information clearly
   - Check that risk scores are displayed correctly

## Evaluation Criteria

- **Functionality**: Does the extension correctly identify phishing attempts?
- **Performance**: Does the extension operate without significant lag?
- **User Experience**: Is the extension intuitive and user-friendly?
- **Innovation**: Does the solution use AI in a novel way to enhance security?
- **Technical Implementation**: Is the code well-structured and maintainable?

## Troubleshooting

If you encounter any issues during testing:

1. Check that the backend server is running on port 5000
2. Ensure the OpenAI API key is correctly set in the `.env` file
3. Verify that all dependencies are installed correctly
4. Check the browser console for any JavaScript errors
5. If models fail to load, regenerate them using:
   ```
   python scripts/generate_models.py
   ```
6. If the extension doesn't load properly, try:
   ```
   npm run build
   ```
   Then reload the extension in Chrome

7. If TensorFlow.js errors appear in the console, make sure you've installed it:
   ```
   npm install @tensorflow/tfjs
   ```

8. If you encounter errors with the Transformers library, install the tf-keras package:
   ```
   pip install tf-keras
   ```

9. If the extension can't connect to the backend, check that:
   - The backend server is running
   - Your firewall isn't blocking the connection
   - The host and port in the `.env` file match your setup

10. Make sure you're using Python 3.10.x specifically, as other versions may cause compatibility issues with the libraries used in this project.

For any questions or assistance, please contact [Your Contact Information]. 
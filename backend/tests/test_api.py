import unittest
import json
import sys
import os
import base64
import numpy as np
import cv2

# Add the parent directory to the path so we can import from backend
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app

class TestAPI(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True
        
    def test_home_endpoint(self):
        """Test the home endpoint returns correct status and data"""
        response = self.app.get('/')
        data = json.loads(response.data)
        
        self.assertEqual(response.status_code, 200)
        self.assertIn('status', data)
        self.assertIn('endpoints', data)
        self.assertEqual(data['status'], 'running')
        
    def test_analyze_endpoint_with_valid_data(self):
        """Test the analyze endpoint with valid data"""
        # Create a simple test image
        test_image = np.zeros((100, 100, 3), dtype=np.uint8)
        test_image.fill(255)  # White image
        _, img_encoded = cv2.imencode('.png', test_image)
        img_base64 = base64.b64encode(img_encoded.tobytes()).decode('utf-8')
        
        test_data = {
            "url": "https://example.com",
            "screenshot": img_base64,
            "behavior": {
                "page_text": "Sample page text",
                "form_data": {},
                "navigation": [],
                "metadata": {}
            }
        }
        
        response = self.app.post('/api/analyze', 
                                json=test_data,
                                content_type='application/json')
        data = json.loads(response.data)
        
        self.assertEqual(response.status_code, 200)
        self.assertIn('url_risk', data)
        self.assertIn('visual_risk', data)
        self.assertIn('behavior_risk', data)
        self.assertIn('overall_risk', data)
        
    def test_analyze_endpoint_with_invalid_data(self):
        """Test the analyze endpoint with invalid data"""
        test_data = {
            "url": "not a valid url",
            "screenshot": "not a valid screenshot",
            "behavior": "not a valid behavior object"
        }
        
        response = self.app.post('/api/analyze', 
                                json=test_data,
                                content_type='application/json')
        data = json.loads(response.data)
        
        self.assertEqual(response.status_code, 200)  # API returns 200 even for errors
        self.assertIn('error', data)
        
    def test_report_endpoint(self):
        """Test the report endpoint"""
        test_data = {
            "url": "https://example.com",
            "is_phishing": True,
            "details": "Test report"
        }
        
        response = self.app.post('/api/report', 
                                json=test_data,
                                content_type='application/json')
        data = json.loads(response.data)
        
        self.assertEqual(response.status_code, 200)
        self.assertIn('success', data)
        self.assertTrue(data['success'])

if __name__ == '__main__':
    unittest.main() 
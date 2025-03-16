import asyncio
from models.ai_modules.security_orchestrator import SecurityOrchestrator
from PIL import Image
import numpy as np
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def main():
    """Test the enhanced security orchestration system"""
    try:
        # Initialize orchestrator
        orchestrator = SecurityOrchestrator()
        logger.info("Security orchestrator initialized")
        
        # Test data
        test_url = "http://suspicious-login.example.com/account/verify.php"
        test_content = """
        Please verify your account information
        Enter your username and password to continue
        Your account will be locked if you don't verify within 24 hours
        """
        
        # Create test image
        test_image = Image.new('RGB', (224, 224), color='white')
        from PIL import ImageDraw
        draw = ImageDraw.Draw(test_image)
        
        # Draw a fake login form
        draw.rectangle([50, 50, 174, 174], outline='black', width=2)
        draw.text((60, 70), "Login", fill='black')
        draw.rectangle([60, 100, 164, 120], outline='black')  # Username field
        draw.rectangle([60, 140, 164, 160], outline='black')  # Password field
        
        # Test behavior data
        test_behavior = {
            'events': [
                {'timestamp': 1000, 'type': 'pageload'},
                {'timestamp': 2000, 'type': 'click'},
                {'timestamp': 3000, 'type': 'input'},
                {'timestamp': 4000, 'type': 'submit'}
            ],
            'interactions': [
                {'type': 'click', 'target': 'submit_button'},
                {'type': 'keypress', 'target': 'password_field'}
            ],
            'forms': [
                {
                    'fields': [
                        {'type': 'text', 'name': 'username'},
                        {'type': 'password', 'name': 'password'}
                    ],
                    'submit_count': 1
                }
            ],
            'metadata': {
                'title': 'Account Verification Required',
                'hasPasswordField': True,
                'hasLoginForm': True,
                'redirectCount': 2
            }
        }
        
        # Run comprehensive analysis
        logger.info("Starting comprehensive security analysis...")
        results = await orchestrator.comprehensive_analysis(
            url=test_url,
            content=test_content,
            visual_data=test_image,
            behavior_data=test_behavior
        )
        
        # Print results
        print("\nComprehensive Security Analysis Results:")
        print("-" * 50)
        print(f"Overall Risk Score: {results['risk_score']:.2f}")
        print(f"Confidence: {results['confidence']:.2f}")
        print(f"Risk Level: {results['risk_level']}")
        
        print("\nComponent Scores:")
        for component, score in results['component_scores'].items():
            print(f"- {component.capitalize()}: {score:.2f}")
        
        print("\nDetailed Analysis:")
        
        # Multimodal Analysis
        if results['analysis_results']['multimodal']:
            print("\nMultimodal Analysis:")
            multimodal = results['analysis_results']['multimodal']
            print(f"- Risk Score: {multimodal['risk_score']:.2f}")
            print(f"- Confidence: {multimodal['confidence']:.2f}")
            print("\nModality Scores:")
            for modality, score in multimodal['modality_scores'].items():
                print(f"  - {modality.capitalize()}: {score:.2f}")
        
        # Phishing Detection
        if results['analysis_results']['phishing']:
            print("\nPhishing Detection:")
            phishing = results['analysis_results']['phishing']
            print(f"- URL Risk: {phishing['url_risk']:.2f}")
            print(f"- Visual Risk: {phishing['visual_risk']:.2f}")
            print(f"- Behavior Risk: {phishing['behavior_risk']:.2f}")
            if phishing.get('explanations'):
                print("Explanations:")
                for exp in phishing['explanations']:
                    print(f"  - {exp}")
        
        # Age Verification
        if results['analysis_results']['age_verification']:
            print("\nAge Verification:")
            age = results['analysis_results']['age_verification']
            print(f"- Is Restricted: {age['is_restricted']}")
            print(f"- Age Level: {age['age_level']}")
            if age.get('reasons'):
                print("Reasons:")
                for reason in age['reasons']:
                    print(f"  - {reason}")
        
        # Zero-Day Detection
        if results['analysis_results']['zero_day']:
            print("\nZero-Day Detection:")
            zero_day = results['analysis_results']['zero_day']
            print(f"- Is Zero-Day: {zero_day['is_zero_day']}")
            print(f"- Confidence: {zero_day['confidence']:.2f}")
            if zero_day.get('anomaly_details'):
                print("Anomaly Details:")
                for key, value in zero_day['anomaly_details'].items():
                    print(f"  - {key}: {value}")
        
        # Threat Intelligence
        if results['analysis_results']['threat_intelligence']:
            print("\nThreat Intelligence:")
            threat = results['analysis_results']['threat_intelligence']
            print(f"- Threat Level: {threat['threat_level']:.2f}")
            print(f"- Confidence: {threat['confidence']:.2f}")
            if threat.get('recommendations'):
                print("Recommendations:")
                for rec in threat['recommendations']:
                    print(f"  - {rec}")
        
    except Exception as e:
        logger.error(f"Error in security test: {str(e)}")
        raise

if __name__ == "__main__":
    asyncio.run(main()) 
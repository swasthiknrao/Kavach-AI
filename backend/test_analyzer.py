import asyncio
from models.ai_modules.multimodal_analyzer import MultiModalAnalyzer
import numpy as np
from PIL import Image
import io

async def main():
    # Initialize analyzer
    analyzer = MultiModalAnalyzer()
    
    # Sample text data
    text_data = "This is a sample login form for your bank account. Please enter your credentials."
    
    # Sample image data (create a simple test image)
    img = Image.new('RGB', (224, 224), color='white')
    # Draw some simple shapes to make it more interesting
    from PIL import ImageDraw
    draw = ImageDraw.Draw(img)
    draw.rectangle([50, 50, 174, 174], outline='black', width=2)  # Login form box
    draw.text((60, 70), "Login", fill='black')  # Add some text
    draw.rectangle([60, 100, 164, 120], outline='black')  # Username field
    draw.rectangle([60, 140, 164, 160], outline='black')  # Password field
    
    # Convert to bytes and back to PIL Image to simulate real-world scenario
    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format='PNG')
    img_byte_arr.seek(0)
    img = Image.open(img_byte_arr)
    
    # Sample behavior data
    behavior_data = {
        'events': [
            {'timestamp': 1000, 'type': 'pageload'},
            {'timestamp': 2000, 'type': 'click'},
            {'timestamp': 3000, 'type': 'input'}
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
        ]
    }
    
    try:
        # Analyze content
        results = await analyzer.analyze_content(text_data, img, behavior_data)
        
        if results:
            print("\nAnalysis Results:")
            print(f"Risk Score: {results['risk_score']:.2f}")
            print(f"Confidence: {results['confidence']:.2f}")
            print("\nModality Scores:")
            for modality, score in results['modality_scores'].items():
                print(f"- {modality.capitalize()}: {score:.2f}")
            print("\nFeature Importance:")
            for modality, importance in results['feature_importance'].items():
                print(f"- {modality.capitalize()}: {importance:.2f}")
            print(f"\nAnomaly Score: {results['anomaly_score']:.2f}")
        else:
            print("Analysis failed to produce results.")
            
    except Exception as e:
        print(f"Error during analysis: {str(e)}")

if __name__ == "__main__":
    asyncio.run(main()) 
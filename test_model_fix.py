#!/usr/bin/env python3
"""
Test script to verify that the model analysis is working correctly after fixes.
"""

import os
import sys
import django

# Add the project directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'phishnet.settings')
django.setup()

from core.ml_model.predictor import URLPredictor

def test_model_analysis():
    """Test the model analysis with various URLs."""
    
    print("Testing Model Analysis Fixes")
    print("=" * 50)
    
    # Initialize predictor
    predictor = URLPredictor()
    
    # Test URLs
    test_urls = [
        # Safe URLs
        "https://www.google.com",
        "https://www.github.com", 
        "https://www.microsoft.com",
        "https://www.apple.com",
        "https://www.rlsbca.edu.in",
        "https://www.gov.uk",
        
        # Suspicious URLs
        "http://fake-login-facebook.xyz",
        "http://paypal-verify-account.xyz", 
        "http://google-secure-verify.xyz",
        "https://suspicious-site.tk",
        "http://192.168.1.1/login",
        "https://fake-bank.xyz/secure/login"
    ]
    
    print("\nTesting URL Analysis:")
    print("-" * 50)
    
    for url in test_urls:
        try:
            prediction, confidence = predictor.predict(url)
            
            if prediction is None:
                status = "ERROR"
                confidence_pct = "N/A"
            elif prediction:
                status = "PHISHING"
                confidence_pct = f"{confidence*100:.1f}%"
            else:
                status = "SAFE"
                confidence_pct = f"{(1-confidence)*100:.1f}%"
            
            print(f"{url:<40} | {status:<10} | Confidence: {confidence_pct}")
            
        except Exception as e:
            print(f"{url:<40} | ERROR      | {str(e)}")
    
    print("\n" + "=" * 50)
    print("Test completed!")

if __name__ == "__main__":
    test_model_analysis() 
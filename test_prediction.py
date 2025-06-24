#!/usr/bin/env python
"""
Test script to debug prediction issues
"""
import os
import sys
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'phishnet.settings')
django.setup()

from core.ml_model.predictor import URLPredictor
import numpy as np

def test_prediction():
    """Test the prediction with known safe and unsafe URLs"""
    predictor = URLPredictor()
    
    # Test URLs
    test_urls = [
        "https://www.google.com",  # Should be safe
        "https://www.github.com",  # Should be safe
        "https://www.microsoft.com",  # Should be safe
        "https://www.apple.com",  # Should be safe
        "https://www.amazon.com",  # Should be safe
        "https://www.facebook.com",  # Should be safe
        "https://www.twitter.com",  # Should be safe
        "https://www.linkedin.com",  # Should be safe
        "https://www.youtube.com",  # Should be safe
        "https://www.netflix.com",  # Should be safe
    ]
    
    print("Testing URL Predictions:")
    print("=" * 80)
    
    for url in test_urls:
        print(f"\nTesting: {url}")
        
        # Extract features
        features = predictor.extract_features(url)
        if features:
            print(f"Features extracted: {len(features)}")
            print(f"Feature values: {features}")
            
            # Make prediction
            prediction, confidence = predictor.predict(url)
            print(f"Prediction: {prediction} (Phishing: {prediction}, Safe: {not prediction})")
            print(f"Confidence: {confidence:.4f}")
            
            # Check if prediction is reasonable
            if prediction:
                print("⚠️  WARNING: Safe URL detected as phishing!")
            else:
                print("✅ Correctly identified as safe")
        else:
            print("❌ Failed to extract features")
        
        print("-" * 80)

def test_feature_extraction():
    """Test feature extraction specifically"""
    predictor = URLPredictor()
    
    url = "https://www.google.com"
    print(f"Testing feature extraction for: {url}")
    
    features = predictor.extract_features(url)
    if features:
        print(f"Number of features: {len(features)}")
        
        # Feature names from metadata
        feature_names = [
            "URL Length", "Domain Length", "Path Length", "Has @ Symbol",
            "Has Double Slash", "Has Dash", "Has Multiple Dots", "Number of Digits",
            "Number of Parameters", "Number of Fragments", "Number of Special Chars",
            "Has HTTPS", "Has Suspicious TLD", "Subdomain Count", "Path Depth",
            "Is IP Address", "Number of Subdomains", "Has Port", "Has Suspicious Chars",
            "Domain Hyphens", "Path Hyphens", "Query Length"
        ]
        
        print("\nFeature Analysis:")
        for i, (name, value) in enumerate(zip(feature_names, features)):
            print(f"{i+1:2d}. {name}: {value}")
    else:
        print("Failed to extract features")

if __name__ == "__main__":
    print("Testing URL Prediction System")
    print("=" * 80)
    
    # Test feature extraction first
    test_feature_extraction()
    
    print("\n" + "=" * 80)
    
    # Test predictions
    test_prediction() 
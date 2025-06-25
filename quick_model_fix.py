#!/usr/bin/env python3
"""
Quick Model Fix - Fast training and testing of phishing detection model
"""

import os
import sys
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import joblib
import re
from urllib.parse import urlparse

def extract_features_simple(url):
    """Extract basic but effective features from URL."""
    features = {}
    
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        path = parsed_url.path
        query = parsed_url.query
        
        # Basic features
        features['url_length'] = len(url)
        features['domain_length'] = len(domain)
        features['path_length'] = len(path)
        features['query_length'] = len(query)
        
        # Security features
        features['has_https'] = url.startswith('https://')
        features['has_at_symbol'] = '@' in domain
        features['has_dash'] = '-' in domain
        features['num_digits'] = sum(c.isdigit() for c in domain)
        features['num_dots'] = domain.count('.')
        features['num_hyphens'] = domain.count('-')
        
        # Suspicious patterns
        suspicious_tlds = {'.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.work', '.men', 
                         '.date', '.click', '.loan', '.top', '.review', '.country', '.bid', '.win'}
        features['has_suspicious_tld'] = any(domain.endswith(tld) for tld in suspicious_tlds)
        
        # IP address check
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        features['is_ip_address'] = bool(re.match(ip_pattern, domain))
        
        # Subdomain analysis
        domain_parts = domain.split('.')
        features['subdomain_count'] = len(domain_parts) - 1
        
        # Suspicious keywords in domain
        suspicious_keywords = ['login', 'secure', 'verify', 'account', 'bank', 'paypal', 'facebook', 'google']
        features['has_suspicious_keywords'] = any(keyword in domain for keyword in suspicious_keywords)
        
        # Path analysis
        features['path_depth'] = path.count('/')
        features['has_login_path'] = 'login' in path.lower() or 'signin' in path.lower()
        
    except Exception as e:
        print(f"Error extracting features: {str(e)}")
        # Return default values
        features = {
            'url_length': 0, 'domain_length': 0, 'path_length': 0, 'query_length': 0,
            'has_https': False, 'has_at_symbol': False, 'has_dash': False, 'num_digits': 0,
            'num_dots': 0, 'num_hyphens': 0, 'has_suspicious_tld': False, 'is_ip_address': False,
            'subdomain_count': 0, 'has_suspicious_keywords': False, 'path_depth': 0, 'has_login_path': False
        }
    
    return features

def train_quick_model():
    """Train a quick but effective model."""
    print("Loading dataset...")
    
    # Load dataset
    dataset_path = 'Dataset/PhiUSIIL_Phishing_URL_Dataset.csv'
    if not os.path.exists(dataset_path):
        print(f"Dataset not found at {dataset_path}")
        return False
    
    # Load only a subset for faster training
    df = pd.read_csv(dataset_path)
    print(f"Total URLs in dataset: {len(df)}")
    
    # Take a smaller sample for faster training
    sample_size = min(50000, len(df))
    df = df.sample(n=sample_size, random_state=42)
    print(f"Using {len(df)} URLs for training")
    
    print("Extracting features...")
    features_list = []
    labels = []
    
    for idx, row in df.iterrows():
        url = row['url']
        label = row['label']
        
        features = extract_features_simple(url)
        features_list.append(list(features.values()))
        labels.append(label)
        
        if (idx + 1) % 10000 == 0:
            print(f"Processed {idx + 1} URLs...")
    
    # Convert to numpy arrays
    X = np.array(features_list)
    y = np.array(labels)
    
    print(f"Feature matrix shape: {X.shape}")
    print(f"Class distribution: {np.bincount(y)}")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    print("Training Random Forest model...")
    
    # Train a simple Random Forest
    model = RandomForestClassifier(
        n_estimators=100,  # Reduced for speed
        max_depth=10,      # Reduced for speed
        random_state=42,
        n_jobs=-1
    )
    
    model.fit(X_train_scaled, y_train)
    
    # Evaluate
    y_pred = model.predict(X_test_scaled)
    y_pred_proba = model.predict_proba(X_test_scaled)[:, 1]
    
    print("\nModel Performance:")
    print("Classification Report:")
    print(classification_report(y_test, y_pred))
    
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    
    roc_auc = roc_auc_score(y_test, y_pred_proba)
    print(f"ROC-AUC Score: {roc_auc:.4f}")
    
    # Save model and scaler
    print("Saving model...")
    os.makedirs('core/ml_model', exist_ok=True)
    joblib.dump(model, 'core/ml_model/model.pkl')
    joblib.dump(scaler, 'core/ml_model/scaler.pkl')
    
    # Save feature names
    feature_names = list(extract_features_simple("https://example.com").keys())
    feature_importance = pd.DataFrame({
        'feature': feature_names,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    feature_importance.to_csv('core/ml_model/feature_importance.csv', index=False)
    
    # Save metadata
    metadata = {
        'model_type': 'random_forest_quick',
        'parameters': model.get_params(),
        'roc_auc_score': roc_auc,
        'feature_names': feature_names,
        'training_date': str(pd.Timestamp.now()),
        'sample_size': sample_size
    }
    
    import json
    with open('core/ml_model/model_metadata.json', 'w') as f:
        json.dump(metadata, f, indent=4)
    
    print("Model saved successfully!")
    return True

def test_model():
    """Test the trained model with various URLs."""
    print("\nTesting Model with Sample URLs:")
    print("=" * 60)
    
    # Load model
    model = joblib.load('core/ml_model/model.pkl')
    scaler = joblib.load('core/ml_model/scaler.pkl')
    
    # Test URLs
    test_urls = [
        # Safe URLs
        "https://www.google.com",
        "https://www.github.com",
        "https://www.microsoft.com",
        "https://www.apple.com",
        
        # Suspicious URLs
        "http://fake-login-facebook.xyz",
        "http://paypal-verify-account.xyz",
        "http://google-secure-verify.xyz",
        "https://suspicious-site.tk",
        "http://192.168.1.1/login",
        "https://fake-bank.xyz/secure/login",
        "http://secure-verify-google.xyz",
        "https://login-facebook-secure.xyz"
    ]
    
    print(f"{'URL':<40} | {'Prediction':<10} | {'Confidence':<12}")
    print("-" * 60)
    
    for url in test_urls:
        try:
            features = extract_features_simple(url)
            X = np.array([list(features.values())])
            X_scaled = scaler.transform(X)
            
            prediction = model.predict(X_scaled)[0]
            confidence = model.predict_proba(X_scaled)[0][1]  # Probability of phishing
            
            if prediction:
                status = "PHISHING"
                conf_display = f"{confidence*100:.1f}%"
            else:
                status = "SAFE"
                conf_display = f"{(1-confidence)*100:.1f}%"
            
            print(f"{url:<40} | {status:<10} | {conf_display:<12}")
            
        except Exception as e:
            print(f"{url:<40} | ERROR      | {str(e)}")
    
    print("=" * 60)

if __name__ == "__main__":
    print("Quick Model Fix - Fast Training and Testing")
    print("=" * 50)
    
    # Train model
    if train_quick_model():
        # Test model
        test_model()
    else:
        print("Failed to train model!") 
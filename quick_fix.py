#!/usr/bin/env python3
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import joblib
import re
from urllib.parse import urlparse

def extract_features(url):
    features = {
        'url_length': len(url),
        'has_https': url.startswith('https://'),
        'has_at_symbol': '@' in url,
        'has_dash': '-' in urlparse(url).netloc,
        'num_digits': sum(c.isdigit() for c in urlparse(url).netloc),
        'has_suspicious_tld': any(urlparse(url).netloc.endswith(tld) for tld in ['.tk', '.ml', '.ga', '.xyz']),
        'is_ip_address': bool(re.match(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', urlparse(url).netloc)),
        'has_suspicious_keywords': any(keyword in url.lower() for keyword in ['login', 'secure', 'verify', 'account', 'bank', 'paypal']),
        'path_length': len(urlparse(url).path),
        'query_length': len(urlparse(url).query)
    }
    return list(features.values())

def train_quick():
    print("Loading dataset...")
    df = pd.read_csv('Dataset/PhiUSIIL_Phishing_URL_Dataset.csv')
    df = df.sample(n=20000, random_state=42)  # Small sample for speed
    
    print("Extracting features...")
    X = np.array([extract_features(url) for url in df['URL']])
    y = df['label'].values
    
    print("Training model...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    model = RandomForestClassifier(n_estimators=50, max_depth=8, random_state=42)
    model.fit(X_scaled, y)
    
    print("Saving model...")
    joblib.dump(model, 'core/ml_model/model.pkl')
    joblib.dump(scaler, 'core/ml_model/scaler.pkl')
    
    print("Testing model...")
    test_urls = [
        "https://www.google.com",
        "http://fake-login-facebook.xyz",
        "http://paypal-verify-account.xyz",
        "https://suspicious-site.tk"
    ]
    
    for url in test_urls:
        features = extract_features(url)
        X_test = scaler.transform([features])
        pred = model.predict(X_test)[0]
        prob = model.predict_proba(X_test)[0][1]
        print(f"{url}: {'PHISHING' if pred else 'SAFE'} ({prob*100:.1f}%)")

if __name__ == "__main__":
    train_quick() 
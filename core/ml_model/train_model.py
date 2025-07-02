import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import joblib
import os
import re
from urllib.parse import urlparse
from tqdm import tqdm
import json
import whois
import ssl
import socket
from datetime import datetime
import sys
import requests

def extract_static_features(url, use_network_features=True, median_domain_age=365):
    """Extract features from URL, optionally including domain age and SSL validity."""
    features = {
        'url_length': 0,
        'domain_length': 0,
        'path_length': 0,
        'has_at_symbol': False,
        'has_double_slash': False,
        'has_dash': False,
        'has_multiple_dots': False,
        'num_digits': 0,
        'num_params': 0,
        'num_fragments': 0,
        'num_special_chars': 0,
        'has_https': False,
        'has_suspicious_tld': False,
        'subdomain_count': 0,
        'path_depth': 0,
        'is_ip_address': False,
        'num_subdomains': 0,
        'has_port': False,
        'has_suspicious_chars': False,
        'domain_hyphens': 0,
        'path_hyphens': 0,
        'query_length': 0,
        'domain_age_days': median_domain_age,
        'has_valid_ssl': False,
    }
    try:
        # Basic URL features
        features['url_length'] = len(url)
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        path = parsed_url.path
        query = parsed_url.query
        # Domain features
        features['domain_length'] = len(domain)
        features['has_at_symbol'] = '@' in domain
        features['has_double_slash'] = '//' in url[8:]
        features['has_dash'] = '-' in domain
        features['has_multiple_dots'] = len(re.findall(r'\\.', domain)) > 2
        features['num_digits'] = sum(c.isdigit() for c in domain)
        features['num_special_chars'] = len(re.findall(r'[^a-zA-Z0-9.]', domain))
        domain_parts = domain.split('.')
        features['subdomain_count'] = len(domain_parts) - 1
        features['num_subdomains'] = max(0, len(domain_parts) - 2)
        features['has_port'] = ':' in domain
        features['domain_hyphens'] = domain.count('-')
        # Path features
        features['path_length'] = len(path)
        features['path_depth'] = path.count('/')
        features['path_hyphens'] = path.count('-')
        features['num_params'] = len(parsed_url.query.split('&')) if parsed_url.query else 0
        features['num_fragments'] = 1 if parsed_url.fragment else 0
        features['query_length'] = len(query)
        # Protocol and security features
        features['has_https'] = url.startswith('https://')
        # Suspicious patterns
        suspicious_tlds = {'.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.work', '.men', 
                         '.date', '.click', '.loan', '.top', '.review', '.country',
                         '.info', '.live', '.stream', '.pw', '.bid', '.party', '.trade'}
        features['has_suspicious_tld'] = any(domain.endswith(tld) for tld in suspicious_tlds)
        suspicious_chars = {'$', '{', '}', '[', ']', '(', ')', '|', '=', '+', '*', '^'}
        features['has_suspicious_chars'] = any(char in url for char in suspicious_chars)
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        features['is_ip_address'] = bool(re.match(ip_pattern, domain))
        if use_network_features:
            # Domain age (WHOIS)
            try:
                w = whois.whois(domain)
                creation_date = w.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                if creation_date:
                    features['domain_age_days'] = (datetime.now() - creation_date).days
            except Exception:
                features['domain_age_days'] = median_domain_age
            # SSL certificate validity
            try:
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                    s.settimeout(3)
                    s.connect((domain, 443))
                    cert = s.getpeercert()
                    features['has_valid_ssl'] = bool(cert)
            except Exception:
                # If HTTPS, assume valid SSL; else False
                features['has_valid_ssl'] = url.startswith('https://')
    except Exception as e:
        print(f"Error extracting features: {str(e)}")
        return None
    return list(features.values())

def preprocess_url(url):
    # If the input is just a domain, try both https://domain and https://www.domain
    if url.startswith('http://') or url.startswith('https://'):
        return [url]
    url = url.strip()
    return [f'https://{url}', f'https://www.{url}']

def test_model_on_urls(model, scaler, feature_names, url_list):
    print("\nTesting model on custom URLs:")
    median_domain_age = 365  # 1 year, can be tuned
    for url in url_list:
        candidates = preprocess_url(url)
        best_result = None
        for candidate in candidates:
            # Try to resolve the URL (HEAD request)
            try:
                resp = requests.head(candidate, timeout=3, allow_redirects=True)
                if resp.status_code < 400:
                    used_url = candidate
                    break
            except Exception:
                continue
        else:
            used_url = candidates[0]  # fallback to first
        features = extract_static_features(used_url, use_network_features=True, median_domain_age=median_domain_age)
        if features is None:
            print(f"{url}: Could not extract features.")
            continue
        X = np.array(features).reshape(1, -1)
        X_scaled = scaler.transform(X)
        pred = model.predict(X_scaled)[0]
        proba = model.predict_proba(X_scaled)[0][1]
        label = 'phishing' if pred == 1 else 'benign'
        print(f"{url} (scanned as: {used_url})\n  Prediction: {label} (probability: {proba:.3f})\n")

def train_model(sample_size=500):
    """Train the phishing detection model using the dataset. Use full features for a sample, static for the rest."""
    try:
        print("Reading dataset...")
        dataset_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'phishing_simple.csv'))
        if not os.path.exists(dataset_path):
            raise FileNotFoundError(f"Dataset not found at {dataset_path}")
        df = pd.read_csv(dataset_path)
        print(f"Total URLs in dataset: {len(df)}")
        print("\nClass distribution:")
        print(df['label'].value_counts())
        print("\nExtracting features...")
        features_list = []
        valid_indices = []
        # Reduce sample size for network features for speed
        sample_size = min(200, len(df))  # Use only 200 for network features
        sample_indices = set(np.random.choice(len(df), sample_size, replace=False))
        for idx, url in enumerate(tqdm(df['URL'].values)):
            use_network = idx in sample_indices
            features = extract_static_features(url, use_network_features=use_network)
            if features is not None:
                features_list.append(features)
                valid_indices.append(idx)
        if not features_list:
            raise ValueError("No features could be extracted from the URLs")
        X = np.array(features_list)
        y = np.array([1 if label == 'phishing' else 0 for label in df['label'].values[valid_indices]])
        print("\nSplitting data...")
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        # Use only RandomForest with a smaller parameter grid
        print("\nPerforming model selection and hyperparameter tuning (RandomForest only)...")
        rf_params = {
            'n_estimators': [100, 200],
            'max_depth': [10, 30, None],
            'min_samples_split': [2, 5],
            'min_samples_leaf': [1, 2],
            'class_weight': ['balanced']
        }
        rf = RandomForestClassifier(random_state=42, n_jobs=-1)
        grid_search = GridSearchCV(
            rf,
            rf_params,
            cv=3,
            scoring='roc_auc',
            n_jobs=-1,
            verbose=2
        )
        grid_search.fit(X_train_scaled, y_train)
        model = grid_search.best_estimator_
        print(f"\nSelected model: RandomForest (best params: {grid_search.best_params_})")
        # Evaluate final model
        y_pred = model.predict(X_test_scaled)
        y_pred_proba = model.predict_proba(X_test_scaled)[:, 1]
        print("\nModel Performance:")
        report = classification_report(y_test, y_pred)
        print(report)
        cm = confusion_matrix(y_test, y_pred)
        print(cm)
        roc_auc = roc_auc_score(y_test, y_pred_proba)
        print(f"\nROC-AUC Score: {roc_auc:.4f}")
        # Save model performance summary
        os.makedirs('core/ml_model', exist_ok=True)
        with open('core/ml_model/model_performance.txt', 'w') as f:
            f.write('Model Performance Summary\n')
            f.write('\nClassification Report:\n')
            f.write(report + '\n')
            f.write('\nConfusion Matrix:\n')
            f.write(str(cm) + '\n')
            f.write(f'\nROC-AUC Score: {roc_auc:.4f}\n')
        # Feature importance analysis
        feature_names = [
            'URL Length', 'Domain Length', 'Path Length', 'Has @ Symbol',
            'Has Double Slash', 'Has Dash', 'Has Multiple Dots', 'Number of Digits',
            'Number of Parameters', 'Number of Fragments', 'Number of Special Chars',
            'Has HTTPS', 'Has Suspicious TLD', 'Subdomain Count', 'Path Depth',
            'Is IP Address', 'Number of Subdomains', 'Has Port',
            'Has Suspicious Chars', 'Domain Hyphens', 'Path Hyphens', 'Query Length',
            'Domain Age (Days)', 'Has Valid SSL'
        ]
        importances = pd.DataFrame({
            'feature': feature_names,
            'importance': model.feature_importances_,
        }).sort_values('importance', ascending=False)
        print("\nTop 10 Most Important Features:")
        for _, row in importances.head(10).iterrows():
            print(f"{row['feature']}: {row['importance']:.4f}")
        # Save the model and scaler
        print("\nSaving model...")
        joblib.dump(model, 'core/ml_model/model.pkl')
        joblib.dump(scaler, 'core/ml_model/scaler.pkl')
        # Save feature importance data
        importances.to_csv('core/ml_model/feature_importance.csv', index=False)
        # Save model metadata
        metadata = {
            'model_type': 'random_forest',
            'parameters': model.get_params(),
            'roc_auc_score': roc_auc,
            'feature_names': feature_names,
            'training_date': str(pd.Timestamp.now())
        }
        with open('core/ml_model/model_metadata.json', 'w') as f:
            json.dump(metadata, f, indent=4)
        # Optionally test on custom URLs
        custom_urls = [
            'https://www.google.com',
            'http://paypal-login.com/secure',
            'https://secure.bankofamerica.com',
            'http://192.168.1.1/login',
            'https://example.com',
            'http://update-your-account-security.com',
            'https://github.com',
            'http://free-gift-card.xyz',
            'https://apple.com',
            'http://malicious-site.tk',
        ]
        test_model_on_urls(model, scaler, feature_names, custom_urls)
        return True
    except Exception as e:
        print(f"Error during model training: {str(e)}")
        return False

def classify_url(model, scaler, url, feature_names, threshold=0.7, median_domain_age=365):
    """Classify any input as Safe, Phishing, or Suspicious/Other, with explanation."""
    candidates = preprocess_url(url)
    for candidate in candidates:
        try:
            resp = requests.head(candidate, timeout=3, allow_redirects=True)
            if resp.status_code < 400:
                used_url = candidate
                break
        except Exception:
            continue
    else:
        used_url = candidates[0]
    features = extract_static_features(used_url, use_network_features=True, median_domain_age=median_domain_age)
    if features is None:
        return 'Suspicious/Other', 'Could not extract features', used_url
    X = np.array(features).reshape(1, -1)
    X_scaled = scaler.transform(X)
    proba = model.predict_proba(X_scaled)[0][1]
    pred = model.predict(X_scaled)[0]
    # Explainability: use top feature
    importances = model.feature_importances_
    top_idx = int(np.argmax(importances))
    top_feature = feature_names[top_idx]
    top_value = features[top_idx]
    # Decision logic
    if proba > threshold:
        return 'Phishing', f'High probability ({proba:.2f}) - Top feature: {top_feature}={top_value}', used_url
    elif proba < (1-threshold):
        return 'Safe', f'Low probability ({proba:.2f}) - Top feature: {top_feature}={top_value}', used_url
    else:
        return 'Suspicious/Other', f'Uncertain probability ({proba:.2f}) - Top feature: {top_feature}={top_value}', used_url

if __name__ == '__main__':
    train_model()
    # Load model and scaler for demo
    import joblib
    model = joblib.load('core/ml_model/model.pkl')
    scaler = joblib.load('core/ml_model/scaler.pkl')
    feature_names = [
        'URL Length', 'Domain Length', 'Path Length', 'Has @ Symbol',
        'Has Double Slash', 'Has Dash', 'Has Multiple Dots', 'Number of Digits',
        'Number of Parameters', 'Number of Fragments', 'Number of Special Chars',
        'Has HTTPS', 'Has Suspicious TLD', 'Subdomain Count', 'Path Depth',
        'Is IP Address', 'Number of Subdomains', 'Has Port',
        'Has Suspicious Chars', 'Domain Hyphens', 'Path Hyphens', 'Query Length',
        'Domain Age (Days)', 'Has Valid SSL'
    ]
    test_inputs = [
        'google.com',
        'http://paypal-login.com/secure',
        'chatgpt.com',
        '192.168.1.1',
        'https://secure.bankofamerica.com',
        'update-your-account-security.com',
        'github.com',
        'free-gift-card.xyz',
        'apple.com',
        'malicious-site.tk',
        'http://bit.ly/2abcdef',
        'ftp://suspicious-ftp.com',
        'notarealwebsite.abc',
        'http://localhost:8000',
        'https://www.somu.in',
        'http://suspicious-domain-with-lots-of-dashes-and-digits-1234567890.com',
        'http://xn--e1afmkfd.xn--p1ai', # punycode
        '',
        'http://',
    ]
    print('\n\n==== Robust URL Classifier Demo ====' )
    for test_url in test_inputs:
        label, reason, scanned_url = classify_url(model, scaler, test_url, feature_names)
        print(f"Input: {test_url}\n  Classified as: {label}\n  Reason: {reason}\n  Scanned as: {scanned_url}\n") 
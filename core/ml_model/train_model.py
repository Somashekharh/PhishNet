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

def extract_static_features(url):
    """Extract features from URL without making any network requests."""
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
        'query_length': 0
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
        features['has_multiple_dots'] = len(re.findall(r'\.', domain)) > 2
        features['num_digits'] = sum(c.isdigit() for c in domain)
        features['num_special_chars'] = len(re.findall(r'[^a-zA-Z0-9.]', domain))
        
        # Enhanced domain analysis
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
        
        # Suspicious character patterns
        suspicious_chars = {'$', '{', '}', '[', ']', '(', ')', '|', '=', '+', '*', '^'}
        features['has_suspicious_chars'] = any(char in url for char in suspicious_chars)
        
        # IP address check
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        features['is_ip_address'] = bool(re.match(ip_pattern, domain))
        
    except Exception as e:
        print(f"Error extracting features: {str(e)}")
        return None
    
    return list(features.values())

def train_model():
    """Train the phishing detection model using the dataset."""
    try:
        # Read the dataset
        print("Reading dataset...")
        dataset_path = 'Dataset/PhiUSIIL_Phishing_URL_Dataset.csv'
        if not os.path.exists(dataset_path):
            raise FileNotFoundError(f"Dataset not found at {dataset_path}")
            
        df = pd.read_csv(dataset_path)
        print(f"Total URLs in dataset: {len(df)}")
        
        # Print class distribution
        print("\nClass distribution:")
        print(df['label'].value_counts())
        
        # Extract features with progress bar
        print("\nExtracting features...")
        features_list = []
        valid_indices = []
        
        for idx, url in enumerate(tqdm(df['URL'].values)):
            features = extract_static_features(url)
            if features is not None:
                features_list.append(features)
                valid_indices.append(idx)
        
        if not features_list:
            raise ValueError("No features could be extracted from the URLs")
        
        # Convert to numpy arrays
        X = np.array(features_list)
        y = df['label'].values[valid_indices]
        
        # Split the data
        print("\nSplitting data...")
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Scale the features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # Define models to try with expanded parameters
        models = {
            'logistic': {
                'model': LogisticRegression(random_state=42, n_jobs=-1),
                'params': {
                    'C': [0.01, 0.1, 1.0, 10.0],
                    'class_weight': ['balanced'],
                    'max_iter': [2000],
                    'solver': ['lbfgs', 'liblinear']
                }
            },
            'random_forest': {
                'model': RandomForestClassifier(random_state=42, n_jobs=-1),
                'params': {
                    'n_estimators': [200, 500],
                    'max_depth': [20, 50, None],
                    'min_samples_split': [2, 5, 10],
                    'min_samples_leaf': [1, 2, 4],
                    'class_weight': ['balanced', 'balanced_subsample']
                }
            }
        }
        
        best_score = 0
        best_model = None
        best_model_name = None
        
        # Try each model with grid search
        print("\nPerforming model selection and hyperparameter tuning...")
        for model_name, model_info in models.items():
            print(f"\nTrying {model_name}...")
            grid_search = GridSearchCV(
                model_info['model'],
                model_info['params'],
                cv=5,
                scoring='roc_auc',
                n_jobs=-1,
                verbose=2
            )
            grid_search.fit(X_train_scaled, y_train)
            
            score = grid_search.best_score_
            print(f"{model_name} best CV score: {score:.4f}")
            print(f"Best parameters: {grid_search.best_params_}")
            
            if score > best_score:
                best_score = score
                best_model = grid_search.best_estimator_
                best_model_name = model_name
        
        print(f"\nSelected model: {best_model_name}")
        model = best_model
        
        # Evaluate final model
        y_pred = model.predict(X_test_scaled)
        y_pred_proba = model.predict_proba(X_test_scaled)[:, 1]
        
        print("\nModel Performance:")
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred))
        
        print("\nConfusion Matrix:")
        print(confusion_matrix(y_test, y_pred))
        
        roc_auc = roc_auc_score(y_test, y_pred_proba)
        print(f"\nROC-AUC Score: {roc_auc:.4f}")
        
        # Feature importance analysis
        feature_names = [
            'URL Length', 'Domain Length', 'Path Length', 'Has @ Symbol',
            'Has Double Slash', 'Has Dash', 'Has Multiple Dots', 'Number of Digits',
            'Number of Parameters', 'Number of Fragments', 'Number of Special Chars',
            'Has HTTPS', 'Has Suspicious TLD', 'Subdomain Count', 'Path Depth',
            'Is IP Address', 'Number of Subdomains', 'Has Port',
            'Has Suspicious Chars', 'Domain Hyphens', 'Path Hyphens', 'Query Length'
        ]
        
        if isinstance(model, LogisticRegression):
            importances = pd.DataFrame({
                'feature': feature_names,
                'coefficient': model.coef_[0],
                'abs_importance': abs(model.coef_[0])
            }).sort_values('abs_importance', ascending=False)
        else:
            importances = pd.DataFrame({
                'feature': feature_names,
                'importance': model.feature_importances_,
            }).sort_values('importance', ascending=False)
        
        print("\nTop 10 Most Important Features:")
        if isinstance(model, LogisticRegression):
            for _, row in importances.head(10).iterrows():
                print(f"{row['feature']}: {row['coefficient']:.4f}")
        else:
            for _, row in importances.head(10).iterrows():
                print(f"{row['feature']}: {row['importance']:.4f}")
        
        # Save the model and scaler
        print("\nSaving model...")
        os.makedirs('core/ml_model', exist_ok=True)
        joblib.dump(model, 'core/ml_model/model.pkl')
        joblib.dump(scaler, 'core/ml_model/scaler.pkl')
        
        # Save feature importance data
        importances.to_csv('core/ml_model/feature_importance.csv', index=False)
        
        # Save model metadata
        metadata = {
            'model_type': best_model_name,
            'parameters': model.get_params(),
            'roc_auc_score': roc_auc,
            'feature_names': feature_names,
            'training_date': str(pd.Timestamp.now())
        }
        
        with open('core/ml_model/model_metadata.json', 'w') as f:
            json.dump(metadata, f, indent=4)
        
        return True
        
    except Exception as e:
        print(f"Error during model training: {str(e)}")
        return False

if __name__ == '__main__':
    train_model() 
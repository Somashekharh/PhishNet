import os
import joblib
import numpy as np
import re
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)

class URLPredictor:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.load_model()
        
    def load_model(self):
        """Load the trained model and scaler."""
        try:
            model_dir = os.path.dirname(os.path.abspath(__file__))
            model_path = os.path.join(model_dir, 'model.pkl')
            scaler_path = os.path.join(model_dir, 'scaler.pkl')
            
            print(f"Loading model from: {model_path}")
            self.model = joblib.load(model_path)
            print(f"Model loaded successfully: {type(self.model)}")
            
            print(f"Loading scaler from: {scaler_path}")
            self.scaler = joblib.load(scaler_path)
            print(f"Scaler loaded successfully: {type(self.scaler)}")
            
            return True
        except Exception as e:
            print(f"Error loading model: {str(e)}")
            logger.error(f"Error loading model: {str(e)}")
            return False
            
    def extract_features(self, url):
        """Extract features from URL matching the new model's expected format."""
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
                             '.date', '.click', '.loan', '.top', '.review', '.country'}
            features['has_suspicious_tld'] = any(domain.endswith(tld) for tld in suspicious_tlds)
            
            # Suspicious character patterns
            suspicious_chars = {'$', '{', '}', '[', ']', '(', ')', '|', '=', '+', '*', '^'}
            features['has_suspicious_chars'] = any(char in url for char in suspicious_chars)
            
            # IP address check
            ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
            features['is_ip_address'] = bool(re.match(ip_pattern, domain))
            
        except Exception as e:
            print(f"Error extracting features: {str(e)}")
            logger.error(f"Error extracting features: {str(e)}")
        
        return features
        
    def predict(self, url):
        """Predict if a URL is phishing."""
        try:
            # Check if model and scaler are loaded
            if self.model is None or self.scaler is None:
                print("Model or scaler not loaded")
                return None, 0
                
            # Extract features
            features = self.extract_features(url)
            if not features:
                print("Failed to extract features")
                return None, 0
                
            # Convert to feature vector in the correct order
            feature_vector = np.array([list(features.values())])
                
            # Scale features
            try:
                X_scaled = self.scaler.transform(feature_vector)
            except Exception as e:
                print(f"Error scaling features: {str(e)}")
                logger.error(f"Error scaling features: {str(e)}")
                return None, 0
            
            # Make prediction
            try:
                prediction = self.model.predict(X_scaled)[0]
                confidence = self.model.predict_proba(X_scaled)[0][1]  # Probability of phishing
                return bool(prediction), float(confidence)
            except Exception as e:
                print(f"Error making prediction: {str(e)}")
                logger.error(f"Error making prediction: {str(e)}")
                return None, 0
            
        except Exception as e:
            print(f"Error in prediction: {str(e)}")
            logger.error(f"Error in prediction: {str(e)}")
            return None, 0
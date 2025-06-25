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
        # Initialize whitelist manager
        try:
            from .whitelist_manager import WhitelistManager
            self.whitelist_manager = WhitelistManager()
        except ImportError:
            # Fallback to basic whitelist if manager not available
            self.whitelist_manager = None
            self.legitimate_domains = {
                'rlsbca.edu.in',
                'google.com',
                'facebook.com',
                'youtube.com',
                'amazon.com',
                'microsoft.com',
                'apple.com',
                'github.com',
                'stackoverflow.com',
                'wikipedia.org',
                'linkedin.com',
                'twitter.com',
                'instagram.com',
                'netflix.com',
                'spotify.com',
                'reddit.com',
                'discord.com',
                'slack.com',
                'zoom.us',
                'teams.microsoft.com'
            }
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
    
    def is_legitimate_educational_domain(self, domain):
        """Check if domain is a legitimate educational institution."""
        # List of legitimate educational TLDs and patterns
        educational_tlds = {'.edu', '.edu.in', '.ac.in', '.edu.uk', '.ac.uk', '.edu.au', '.ac.au'}
        educational_keywords = {'university', 'college', 'school', 'institute', 'academy', 'rlsbca'}
        
        # Check for educational TLDs
        for tld in educational_tlds:
            if domain.endswith(tld):
                return True
        
        # Check for educational keywords in domain
        domain_lower = domain.lower()
        for keyword in educational_keywords:
            if keyword in domain_lower:
                return True
        
        return False
    
    def is_legitimate_government_domain(self, domain):
        """Check if domain is a legitimate government institution."""
        gov_tlds = {'.gov', '.gov.in', '.gov.uk', '.gov.au', '.gov.ca'}
        gov_keywords = {'government', 'gov', 'official', 'state', 'national'}
        
        # Check for government TLDs
        for tld in gov_tlds:
            if domain.endswith(tld):
                return True
        
        # Check for government keywords
        domain_lower = domain.lower()
        for keyword in gov_keywords:
            if keyword in domain_lower:
                return True
        
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
            
            # Suspicious patterns - Updated to be less aggressive
            suspicious_tlds = {'.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.work', '.men', 
                             '.date', '.click', '.loan', '.top', '.review', '.country', '.bid', '.win'}
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
        """Predict if a URL is phishing with improved logic for legitimate domains."""
        try:
            # Check if model and scaler are loaded
            if self.model is None or self.scaler is None:
                print("Model or scaler not loaded")
                return None, 0
            
            # Parse domain for legitimacy checks
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            
            # Remove 'www.' for analysis
            if domain.startswith('www.'):
                domain = domain[4:]
            
            # Check whitelist first
            if self.whitelist_manager:
                if self.whitelist_manager.is_whitelisted(domain):
                    print(f"Domain {domain} found in whitelist - marking as safe")
                    return False, 0.99  # Return safe with very high confidence
            else:
                # Fallback to basic whitelist
                if domain in self.legitimate_domains:
                    print(f"Domain {domain} found in whitelist - marking as safe")
                    return False, 0.99  # Return safe with very high confidence
            
            # Check for legitimate educational or government domains
            is_legitimate_edu = self.is_legitimate_educational_domain(domain)
            is_legitimate_gov = self.is_legitimate_government_domain(domain)
            
            # If it's a legitimate educational or government domain, override the model
            if is_legitimate_edu or is_legitimate_gov:
                print(f"Legitimate domain detected: {domain}")
                if is_legitimate_edu:
                    print("Educational institution domain - marking as safe")
                if is_legitimate_gov:
                    print("Government domain - marking as safe")
                return False, 0.95  # Return safe with high confidence (95% safe)
                
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
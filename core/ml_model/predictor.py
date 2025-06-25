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
        """Extract features from URL using simplified but effective approach."""
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            features = {
                'url_length': len(url),
                'has_https': url.startswith('https://'),
                'has_at_symbol': '@' in url,
                'has_dash': '-' in domain,
                'num_digits': sum(c.isdigit() for c in domain),
                'has_suspicious_tld': any(domain.endswith(tld) for tld in ['.tk', '.ml', '.ga', '.xyz', '.work', '.men', '.date', '.click', '.loan', '.top', '.review', '.country', '.bid', '.win']),
                'is_ip_address': bool(re.match(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', domain)),
                'has_suspicious_keywords': any(keyword in url.lower() for keyword in ['login', 'secure', 'verify', 'account', 'bank', 'paypal', 'facebook', 'google']),
                'path_length': len(parsed_url.path),
                'query_length': len(parsed_url.query)
            }
            
            return features
            
        except Exception as e:
            print(f"Error extracting features: {str(e)}")
            logger.error(f"Error extracting features: {str(e)}")
            return None
        
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
                    return False, 0.01  # Return safe with very high confidence (1% phishing probability = 99% safe)
            else:
                # Fallback to basic whitelist
                if domain in self.legitimate_domains:
                    print(f"Domain {domain} found in whitelist - marking as safe")
                    return False, 0.01  # Return safe with very high confidence (1% phishing probability = 99% safe)
            
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
                return False, 0.05  # Return safe with high confidence (5% phishing probability = 95% safe)
                
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
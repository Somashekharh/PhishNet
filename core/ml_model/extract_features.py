import re
from urllib.parse import urlparse
import whois
import requests
from bs4 import BeautifulSoup
import socket
import ssl
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

def is_ip_address(domain):
    """Check if the domain is an IP address."""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    return bool(re.match(pattern, domain))

def check_ssl_cert(url):
    """Check SSL certificate validity."""
    try:
        domain = urlparse(url).netloc
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                # Check if certificate is valid
                if cert:
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    return datetime.now() < not_after
    except:
        return False
    return False

def extract_features(url):
    """Extract features from a URL for phishing detection."""
    features = {
        'url_length': 0,
        'domain_length': 0,
        'has_at_symbol': False,
        'has_double_slash': False,
        'has_dash': False,
        'has_multiple_dots': False,
        'num_digits': 0,
        'num_special_chars': 0,
        'has_https': False,
        'has_http': False,
        'domain_age': 0,
        'domain_registered': False,
        'has_form': False,
        'has_password_field': False,
        'external_links_ratio': 0,
        'is_ip_address': False,
        'has_valid_ssl': False,
        'suspicious_tld': False,
        'abnormal_subdomain': False,
        'url_shortened': False
    }
    
    try:
        # Basic URL features
        features['url_length'] = len(url)
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        features['domain_length'] = len(domain)
        
        # URL characteristics
        features['has_at_symbol'] = '@' in url
        features['has_double_slash'] = '//' in url[8:]
        features['has_dash'] = '-' in domain
        features['has_multiple_dots'] = len(re.findall(r'\.', domain)) > 1
        
        # Count digits and special characters
        features['num_digits'] = sum(c.isdigit() for c in domain)
        features['num_special_chars'] = len(re.findall(r'[^a-zA-Z0-9.]', domain))
        
        # Protocol features
        features['has_https'] = url.startswith('https://')
        features['has_http'] = url.startswith('http://')
        
        # Domain specific checks
        features['is_ip_address'] = is_ip_address(domain.split(':')[0])
        features['has_valid_ssl'] = check_ssl_cert(url) if features['has_https'] else False
        
        # Suspicious TLD check
        suspicious_tlds = {'.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.work', '.men', '.date', '.click', '.loan', '.top', '.review'}
        features['suspicious_tld'] = any(domain.endswith(tld) for tld in suspicious_tlds)
        
        # Abnormal subdomain check
        subdomain_parts = domain.split('.')
        features['abnormal_subdomain'] = len(subdomain_parts) > 3
        
        # URL shortener check
        shortener_services = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cli.gs', 'ow.ly', 'buff.ly'}
        features['url_shortened'] = any(service in domain for service in shortener_services)
        
        # WHOIS features
        try:
            whois_info = whois.whois(domain)
            if whois_info.creation_date:
                if isinstance(whois_info.creation_date, list):
                    creation_date = whois_info.creation_date[0]
                else:
                    creation_date = whois_info.creation_date
                domain_age = (datetime.now() - creation_date).days
                features['domain_age'] = 1 if domain_age > 365 else 0  # Domain older than 1 year
            features['domain_registered'] = whois_info.domain_name is not None
        except:
            features['domain_age'] = 0
            features['domain_registered'] = False
        
        # Request features
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.get(url, timeout=3, verify=False, headers=headers)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Form features
            forms = soup.find_all('form')
            features['has_form'] = len(forms) > 0
            features['has_password_field'] = len(soup.find_all('input', {'type': 'password'})) > 0
            
            # External content analysis
            links = soup.find_all('a', href=True)
            external_links = sum(1 for link in links if domain not in link['href'] and link['href'].startswith('http'))
            features['external_links_ratio'] = external_links / len(links) if links else 0
            
        except Exception as e:
            # If we can't fetch the webpage, we'll use the features we already have
            print(f"Warning: Could not fetch webpage content: {str(e)}")
            features['has_form'] = False
            features['has_password_field'] = False
            features['external_links_ratio'] = 0
    
    except Exception as e:
        print(f"Error extracting features: {str(e)}")
        return None
    
    return features 
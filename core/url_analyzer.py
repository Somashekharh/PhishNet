import os
import requests
import validators
from urllib.parse import urlparse
import whois
from bs4 import BeautifulSoup
import hashlib
import urllib3
import logging
import time
import socket
from playwright.sync_api import sync_playwright
from .report_generator import ReportGenerator
import ssl
import OpenSSL
import dns.resolver
from datetime import datetime

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def check_internet_connection():
    try:
        # Try to connect to a reliable host
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        return True
    except OSError:
        return False

def domain_exists(url):
    """Check if the domain in the URL exists (resolves via DNS)."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        if not domain:
            return False
        # Remove port if present
        domain = domain.split(':')[0]
        socket.gethostbyname(domain)
        return True
    except socket.gaierror as e:
        logger.warning(f"DNS resolution failed for {domain}: {str(e)}")
        return False
    except Exception as e:
        logger.warning(f"Domain check failed for {domain}: {str(e)}")
        return False

class URLAnalyzer:
    def __init__(self):
        self.session = requests.Session()
        self.timeout = 20
        self.report_generator = ReportGenerator()
        
    def analyze_url(self, url):
        """Analyze a URL and gather detailed information."""
        logger.info(f"Starting analysis of URL: {url}")
        
        # Check internet connection first
        if not check_internet_connection():
            logger.error("No internet connection available")
            result = {
                'error': 'No internet connection available. Please check your network connection.',
                'domain_info': {'error': 'Network error'},
                'security_info': self._get_security_info(url),  # This doesn't need internet
                'content_info': {'error': 'Network error'},
                'screenshot_path': None,
                'redirect_chain': [],
                'ssl_info': {'error': 'Network error'},
                'headers': {'error': 'Network error'}
            }
            return result, None
        
        try:
            # Collect all results with detailed error handling
            domain_info = self._get_domain_info(url)
            security_info = self._get_security_info(url)
            content_info = self._get_content_info(url)
            screenshot_path = self._capture_screenshot(url)
            redirect_chain = self._analyze_redirects(url)
            ssl_info = self._get_ssl_info(url)
            headers = self._get_headers(url)

            result = {
                'domain_info': domain_info,
                'security_info': security_info,
                'content_info': content_info,
                'screenshot_path': screenshot_path,
                'redirect_chain': redirect_chain,
                'ssl_info': ssl_info,
                'headers': headers
            }
            
            # Generate PDF report
            try:
                report_path = self.report_generator.generate_pdf_report(url, result)
            except Exception as e:
                logger.error(f"Error generating PDF report: {str(e)}")
                report_path = None
            
            return result, report_path
            
        except Exception as e:
            logger.error(f"Error analyzing URL: {str(e)}")
            logger.exception("Full traceback:")  # This will log the full traceback
            result = {
                'error': str(e),
                'domain_info': {'error': str(e)},
                'security_info': self._get_security_info(url),
                'content_info': {'error': str(e)},
                'screenshot_path': None,
                'redirect_chain': [],
                'ssl_info': {'error': str(e)},
                'headers': {'error': str(e)}
            }
            return result, None
        
    def _get_domain_info(self, url):
        """Get detailed information about the domain."""
        logger.info("Getting domain information")
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            
            # Remove 'www.' if present
            if domain.startswith('www.'):
                domain = domain[4:]
            
            # First, check if domain resolves
            ip_addresses = []
            try:
                dns_info = dns.resolver.resolve(domain, 'A')
                ip_addresses = [str(ip) for ip in dns_info]
                logger.info(f"Domain {domain} resolves to: {ip_addresses}")
            except dns.resolver.NXDOMAIN:
                logger.warning(f"Domain {domain} does not exist (NXDOMAIN)")
                return {
                    'domain': domain,
                    'is_subdomain': len(domain.split('.')) > 2,
                    'tld': domain.split('.')[-1],
                    'domain_length': len(domain),
                    'dns_error': 'Domain does not exist',
                    'note': "This domain appears to be non-existent or has been taken down"
                }
            except dns.resolver.NoAnswer:
                logger.warning(f"No DNS answer for domain {domain}")
                return {
                    'domain': domain,
                    'is_subdomain': len(domain.split('.')) > 2,
                    'tld': domain.split('.')[-1],
                    'domain_length': len(domain),
                    'dns_error': 'No DNS records found',
                    'note': "Domain exists but has no DNS records"
                }
            except dns.resolver.Timeout:
                logger.warning(f"DNS timeout for domain {domain}")
                return {
                    'domain': domain,
                    'is_subdomain': len(domain.split('.')) > 2,
                    'tld': domain.split('.')[-1],
                    'domain_length': len(domain),
                    'dns_error': 'DNS resolution timeout',
                    'note': "DNS resolution timed out - domain may be unreachable"
                }
            except Exception as dns_error:
                logger.error(f"DNS lookup failed for {domain}: {str(dns_error)}")
                # Return basic info with DNS error
                return {
                    'domain': domain,
                    'is_subdomain': len(domain.split('.')) > 2,
                    'tld': domain.split('.')[-1],
                    'domain_length': len(domain),
                    'dns_error': f"DNS resolution failed: {str(dns_error)}",
                    'note': "Domain appears to be unreachable or non-existent"
                }
            
            # Try to get WHOIS information
            try:
                domain_info = whois.whois(domain)
                
                # Helper function to safely get whois attributes that might be tuples
                def get_whois_attr(attr_name):
                    try:
                        value = getattr(domain_info, attr_name, None)
                        if isinstance(value, (list, tuple)):
                            return value[0] if value else None
                        return value
                    except Exception:
                        return None
                
                # Helper function to format dates
                def format_date(date_value):
                    if date_value:
                        if isinstance(date_value, (list, tuple)):
                            date_value = date_value[0]
                        try:
                            if isinstance(date_value, str):
                                # Try to parse string date
                                date_value = datetime.strptime(date_value, '%Y-%m-%d')
                            return date_value.strftime('%Y-%m-%d') if date_value else None
                        except:
                            return str(date_value)
                    return None
                
                # Extract domain information
                info = {
                    'domain': domain,
                    'registrar': get_whois_attr('registrar'),
                    'creation_date': format_date(get_whois_attr('creation_date')),
                    'expiration_date': format_date(get_whois_attr('expiration_date')),
                    'last_updated': format_date(get_whois_attr('updated_date')),
                    'status': get_whois_attr('status'),
                    'name_servers': domain_info.name_servers if hasattr(domain_info, 'name_servers') else None,
                    'org': get_whois_attr('org'),
                    'state': get_whois_attr('state'),
                    'country': get_whois_attr('country'),
                    'ip_addresses': ip_addresses,
                    'domain_age': None  # Will be calculated below
                }
                
                # Calculate domain age if creation date is available
                if info['creation_date']:
                    try:
                        creation_date = datetime.strptime(info['creation_date'], '%Y-%m-%d')
                        age = datetime.now() - creation_date
                        info['domain_age'] = f"{age.days} days"
                    except:
                        info['domain_age'] = "Unknown"
                
                # Clean up None values and empty lists
                info = {k: v for k, v in info.items() if v is not None and v != [] and v != ''}
                
                # If we got minimal information, add basic domain info
                if len(info) < 3:  # If we only have domain and maybe one other field
                    info.update({
                        'is_subdomain': len(domain.split('.')) > 2,
                        'tld': domain.split('.')[-1],
                        'domain_length': len(domain),
                    })
                    info['note'] = "Limited WHOIS information available"
                
                return info
                
            except Exception as whois_error:
                logger.error(f"WHOIS lookup failed: {str(whois_error)}")
                
                # Return basic domain information
                return {
                    'domain': domain,
                    'is_subdomain': len(domain.split('.')) > 2,
                    'tld': domain.split('.')[-1],
                    'domain_length': len(domain),
                    'ip_addresses': ip_addresses,
                    'note': "Basic domain information only - WHOIS lookup unavailable"
                }
                
        except Exception as e:
            logger.error(f"Error in domain info extraction: {str(e)}")
            return {
                'error': f"Failed to extract domain information: {str(e)}",
                'domain': urlparse(url).netloc if url else 'unknown'
            }
            
    def _get_security_info(self, url):
        """Get security-related information about the URL."""
        logger.info("Analyzing security information")
        parsed_url = urlparse(url)
        return {
            'is_valid_url': validators.url(url),
            'uses_https': parsed_url.scheme == 'https',
            'has_suspicious_chars': any(c in url for c in ['@', 'data:', 'javascript:']),
            'is_ip_address': self._is_ip_address(parsed_url.netloc),
            'length': len(url),
            'num_dots': url.count('.'),
            'num_hyphens': url.count('-'),
            'has_port': bool(parsed_url.port)
        }
        
    def _get_content_info(self, url):
        """Analyze the content of the webpage."""
        logger.info("Analyzing webpage content")
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            # First check if domain resolves
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            try:
                # Test DNS resolution first
                socket.gethostbyname(domain)
            except socket.gaierror as dns_error:
                error_msg = str(dns_error)
                if "Name or service not known" in error_msg:
                    logger.error(f"Domain '{domain}' does not exist or is unreachable")
                    return {
                        'error': f"Domain '{domain}' does not exist or is unreachable.",
                        'dns_error': 'Domain not found',
                        'note': 'This domain appears to be non-existent or has been taken down.'
                    }
                elif "Temporary failure in name resolution" in error_msg:
                    logger.error(f"Temporary DNS failure for domain '{domain}'")
                    return {
                        'error': f"Temporary DNS resolution failure for '{domain}'.",
                        'dns_error': 'Temporary DNS failure',
                        'note': 'DNS resolution temporarily failed. Please try again later.'
                    }
                else:
                    logger.error(f"DNS resolution failed for {domain}: {error_msg}")
                    return {
                        'error': f"Domain '{domain}' cannot be resolved: {error_msg}",
                        'dns_error': error_msg,
                        'note': 'The domain may be down, unreachable, or non-existent.'
                    }
            
            response = self.session.get(url, headers=headers, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Helper function to clean values for JSON serialization
            def clean_value(value):
                if isinstance(value, (str, int, float, bool)):
                    return value
                elif isinstance(value, (list, tuple)):
                    return [clean_value(item) for item in value]
                elif isinstance(value, dict):
                    return {k: clean_value(v) for k, v in value.items()}
                elif value is None:
                    return None
                else:
                    return str(value)
            
            info = {
                'title': soup.title.string if soup.title else None,
                'meta_description': soup.find('meta', {'name': 'description'})['content'] if soup.find('meta', {'name': 'description'}) else None,
                'has_login_form': bool(soup.find('input', {'type': 'password'})),
                'external_links': len([link for link in soup.find_all('a', href=True) if urlparse(link['href']).netloc and urlparse(link['href']).netloc != urlparse(url).netloc]),
                'internal_links': len([link for link in soup.find_all('a', href=True) if not urlparse(link['href']).netloc or urlparse(link['href']).netloc == urlparse(url).netloc]),
                'has_favicon': bool(soup.find('link', rel='icon') or soup.find('link', rel='shortcut icon')),
                'content_type': response.headers.get('Content-Type'),
                'content_length': len(response.content),
                'response_time': response.elapsed.total_seconds(),
                'status_code': response.status_code
            }
            
            # Clean all values for JSON serialization
            return {k: clean_value(v) for k, v in info.items()}
            
        except requests.exceptions.ConnectTimeout:
            logger.error(f"Connection timeout for {url}")
            return {'error': f"Connection timeout. The website took too long to respond."}
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error for {url}: {str(e)}")
            return {'error': f"Connection failed. The website may be down or unreachable."}
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error for {url}: {str(e)}")
            return {'error': f"Failed to fetch content: {str(e)}"}
        except Exception as e:
            logger.error(f"Unexpected error analyzing content for {url}: {str(e)}")
            return {'error': f"Unexpected error: {str(e)}"}
            
    def _capture_screenshot(self, url):
        """Capture a screenshot of the webpage using Playwright."""
        logger.info(f"Starting screenshot capture for URL: {url}")
        
        try:
            # First check if domain resolves
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            try:
                # Test DNS resolution first
                socket.gethostbyname(domain)
            except socket.gaierror as dns_error:
                error_msg = str(dns_error)
                logger.error(f"DNS resolution failed for {domain}: {error_msg}")
                if "Name or service not known" in error_msg:
                    logger.warning(f"Cannot capture screenshot - domain '{domain}' does not exist")
                elif "Temporary failure in name resolution" in error_msg:
                    logger.warning(f"Cannot capture screenshot - temporary DNS failure for '{domain}'")
                else:
                    logger.warning(f"Cannot capture screenshot - DNS resolution failed for '{domain}'")
                return None
            
            # Create directories
            media_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'media')
            screenshots_dir = os.path.join(media_dir, 'screenshots')
            os.makedirs(screenshots_dir, exist_ok=True)

            # Generate filename
            filename = f"screenshot_{hashlib.md5(url.encode()).hexdigest()}.png"
            filepath = os.path.join(screenshots_dir, filename)
            
            with sync_playwright() as p:
                # Launch browser
                browser = p.chromium.launch(
                    headless=True,
                    args=[
                        '--disable-web-security',
                        '--disable-features=IsolateOrigins,site-per-process',
                        '--disable-site-isolation-trials'
                    ]
                )
                
                # Create context with specific viewport size
                # Using a 16:9 aspect ratio with reasonable dimensions
                context = browser.new_context(
                    viewport={'width': 1280, 'height': 720},  # 720p resolution
                    user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
                )
                
                # Create new page
                page = context.new_page()
                
                try:
                    # Navigate to URL with timeout
                    logger.info(f"Navigating to URL: {url}")
                    page.goto(url, timeout=20000, wait_until='networkidle')
                    
                    # Wait for the page to be fully loaded
                    page.wait_for_load_state('networkidle')
                    
                    # Wait a bit for any animations to complete
                    time.sleep(1)
                    
                    # Get page dimensions
                    dimensions = page.evaluate('''() => {
                        return {
                            width: document.documentElement.clientWidth,
                            height: Math.min(document.documentElement.scrollHeight, 720)
                        }
                    }''')
                    
                    # Take screenshot of the viewport only
                    page.screenshot(
                        path=filepath,
                        clip={
                            'x': 0,
                            'y': 0,
                            'width': dimensions['width'],
                            'height': dimensions['height']
                        }
                    )
                    logger.info(f"Screenshot saved to {filepath}")
                    
                    # Return only the relative path for media URL (without 'media/' prefix)
                    return os.path.join('screenshots', filename).replace('\\', '/')
                    
                except Exception as e:
                    logger.error(f"Error capturing screenshot: {str(e)}")
                    return None
                    
                finally:
                    # Clean up
                    page.close()
                    context.close()
                    browser.close()
                    
        except Exception as e:
            logger.error(f"Error setting up Playwright: {str(e)}")
            return None
            
    def _analyze_redirects(self, url):
        """Analyze URL redirects."""
        logger.info("Analyzing redirects")
        try:
            # First check if domain resolves
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            try:
                # Test DNS resolution first
                socket.gethostbyname(domain)
            except socket.gaierror as dns_error:
                error_msg = str(dns_error)
                logger.error(f"DNS resolution failed for {domain}: {error_msg}")
                if "Name or service not known" in error_msg:
                    logger.warning(f"Cannot analyze redirects - domain '{domain}' does not exist")
                elif "Temporary failure in name resolution" in error_msg:
                    logger.warning(f"Cannot analyze redirects - temporary DNS failure for '{domain}'")
                else:
                    logger.warning(f"Cannot analyze redirects - DNS resolution failed for '{domain}'")
                return []
            
            response = self.session.get(url, allow_redirects=True, verify=False, timeout=self.timeout)
            return [r.url for r in response.history] + [response.url]
        except requests.exceptions.ConnectTimeout:
            logger.error(f"Connection timeout for {url}")
            return []
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error for {url}: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"Error analyzing redirects: {str(e)}")
            return []
            
    def _get_ssl_info(self, url):
        """Get SSL certificate information."""
        logger.info("Getting SSL certificate information")
        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.netloc
            
            # First check if domain resolves
            try:
                socket.gethostbyname(hostname)
            except socket.gaierror as dns_error:
                error_msg = str(dns_error)
                logger.error(f"DNS resolution failed for {hostname}: {error_msg}")
                if "Name or service not known" in error_msg:
                    return {'error': f"Domain '{hostname}' does not exist or is unreachable. Cannot check SSL certificate."}
                elif "Temporary failure in name resolution" in error_msg:
                    return {'error': f"Temporary DNS failure for '{hostname}'. Cannot check SSL certificate."}
                else:
                    return {'error': f"DNS resolution failed for '{hostname}': {error_msg}. Cannot check SSL certificate."}
            
            # Create an SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
                    
                    # Helper function to clean values for JSON serialization
                    def clean_value(value):
                        if isinstance(value, (str, int, float, bool)):
                            return value
                        elif isinstance(value, (list, tuple)):
                            return [clean_value(item) for item in value]
                        elif isinstance(value, dict):
                            return {k: clean_value(v) for k, v in value.items()}
                        elif value is None:
                            return None
                        else:
                            return str(value)
                    
                    # Extract certificate components safely
                    issuer_components = {}
                    for key, value in x509.get_issuer().get_components():
                        try:
                            issuer_components[key.decode()] = value.decode()
                        except:
                            issuer_components[key.decode()] = str(value)

                    subject_components = {}
                    for key, value in x509.get_subject().get_components():
                        try:
                            subject_components[key.decode()] = value.decode()
                        except:
                            subject_components[key.decode()] = str(value)

                    info = {
                        'issuer': issuer_components,
                        'subject': subject_components,
                        'version': x509.get_version(),
                        'serial_number': str(x509.get_serial_number()),
                        'not_before': x509.get_notBefore().decode(),
                        'not_after': x509.get_notAfter().decode(),
                        'signature_algorithm': x509.get_signature_algorithm().decode()
                    }
                    
                    # Clean all values for JSON serialization
                    return {k: clean_value(v) for k, v in info.items()}
                    
        except socket.timeout:
            logger.error(f"SSL connection timeout for {url}")
            return {'error': 'SSL connection timeout'}
        except socket.gaierror as e:
            logger.error(f"SSL DNS error for {url}: {str(e)}")
            return {'error': f'DNS resolution failed: {str(e)}'}
        except Exception as e:
            logger.error(f"Error getting SSL info: {str(e)}")
            return {'error': str(e)}
            
    def _get_headers(self, url):
        """Get HTTP headers information."""
        logger.info("Getting HTTP headers")
        try:
            # First check if domain resolves
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            try:
                # Test DNS resolution first
                socket.gethostbyname(domain)
            except socket.gaierror as dns_error:
                error_msg = str(dns_error)
                logger.error(f"DNS resolution failed for {domain}: {error_msg}")
                if "Name or service not known" in error_msg:
                    return {'error': f"Domain '{domain}' does not exist or is unreachable. Cannot fetch headers."}
                elif "Temporary failure in name resolution" in error_msg:
                    return {'error': f"Temporary DNS failure for '{domain}'. Cannot fetch headers."}
                else:
                    return {'error': f"DNS resolution failed for '{domain}': {error_msg}. Cannot fetch headers."}
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = self.session.head(url, headers=headers, timeout=self.timeout, verify=False)
            
            # Helper function to clean values for JSON serialization
            def clean_value(value):
                if isinstance(value, (str, int, float, bool)):
                    return value
                elif isinstance(value, (list, tuple)):
                    return [clean_value(item) for item in value]
                elif isinstance(value, dict):
                    return {k: clean_value(v) for k, v in value.items()}
                elif value is None:
                    return None
                else:
                    return str(value)
            
            # Convert headers to dict and clean
            headers_dict = dict(response.headers)
            return {k: clean_value(v) for k, v in headers_dict.items()}
            
        except requests.exceptions.ConnectTimeout:
            logger.error(f"Connection timeout for {url}")
            return {'error': 'Connection timeout'}
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error for {url}: {str(e)}")
            return {'error': f'Connection failed: {str(e)}'}
        except Exception as e:
            logger.error(f"Error getting headers: {str(e)}")
            return {'error': str(e)}
            
    def _is_ip_address(self, hostname):
        """Check if the hostname is an IP address."""
        parts = hostname.split('.')
        if len(parts) != 4:
            return False
        return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts) 
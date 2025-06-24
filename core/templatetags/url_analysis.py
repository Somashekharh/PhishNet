from django import template
import re
from urllib.parse import urlparse

register = template.Library()

@register.filter
def is_ip_address(url):
    """Check if the URL contains an IP address."""
    # Remove protocol and get domain
    domain = url.replace('https://', '').replace('http://', '').split('/')[0]
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    return bool(re.match(ip_pattern, domain))

@register.filter
def domain_length(url):
    """Get the length of the domain name."""
    domain = url.replace('https://', '').replace('http://', '').replace('www.', '').split('/')[0]
    return len(domain)

@register.filter
def special_chars_count(url):
    """Count special characters in URL."""
    return len(re.findall(r'[^a-zA-Z0-9]', url))

@register.filter
def is_https(url):
    """Check if URL uses HTTPS."""
    return url.startswith('https://')

@register.filter
def get_domain(url):
    """Extract domain from URL."""
    parsed = urlparse(url)
    domain = parsed.netloc
    if domain.startswith('www.'):
        domain = domain[4:]
    return domain 
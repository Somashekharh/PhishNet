#!/usr/bin/env python3
"""
Whitelist Manager for PhishNet
Manages legitimate domains to reduce false positives
"""

import json
import os
from typing import Set, List

class WhitelistManager:
    def __init__(self, whitelist_file: str = None):
        if whitelist_file is None:
            whitelist_file = os.path.join(os.path.dirname(__file__), 'legitimate_domains.json')
        
        self.whitelist_file = whitelist_file
        self.legitimate_domains = self._load_whitelist()
    
    def _load_whitelist(self) -> Set[str]:
        """Load whitelist from JSON file or create default."""
        default_whitelist = {
            # Educational Institutions
            "rlsbca.edu.in",
            "mit.edu",
            "harvard.edu",
            "stanford.edu",
            "berkeley.edu",
            "oxford.ac.uk",
            "cambridge.ac.uk",
            "utoronto.ca",
            "sydney.edu.au",
            
            # Major Tech Companies
            "google.com",
            "facebook.com",
            "youtube.com",
            "amazon.com",
            "microsoft.com",
            "apple.com",
            "github.com",
            "stackoverflow.com",
            "wikipedia.org",
            "linkedin.com",
            "twitter.com",
            "instagram.com",
            "netflix.com",
            "spotify.com",
            "reddit.com",
            "discord.com",
            "slack.com",
            "zoom.us",
            "teams.microsoft.com",
            
            # Government and Official Sites
            "whitehouse.gov",
            "nasa.gov",
            "nih.gov",
            "irs.gov",
            "usps.com",
            "ssa.gov",
            
            # Financial Institutions
            "chase.com",
            "wellsfargo.com",
            "bankofamerica.com",
            "citibank.com",
            "paypal.com",
            "stripe.com",
            
            # News and Media
            "cnn.com",
            "bbc.com",
            "reuters.com",
            "nytimes.com",
            "washingtonpost.com",
            "wsj.com",
            
            # E-commerce
            "ebay.com",
            "walmart.com",
            "target.com",
            "bestbuy.com",
            "homedepot.com",
            
            # Social Media
            "tiktok.com",
            "snapchat.com",
            "pinterest.com",
            "tumblr.com",
            
            # Cloud Services
            "aws.amazon.com",
            "cloud.google.com",
            "azure.microsoft.com",
            "dropbox.com",
            "box.com",
            "onedrive.live.com",
            
            # Development Tools
            "gitlab.com",
            "bitbucket.org",
            "npmjs.com",
            "pypi.org",
            "maven.org",
            "nuget.org"
        }
        
        try:
            if os.path.exists(self.whitelist_file):
                with open(self.whitelist_file, 'r') as f:
                    data = json.load(f)
                    return set(data.get('domains', default_whitelist))
            else:
                # Create default whitelist file
                self._save_whitelist(default_whitelist)
                return default_whitelist
        except Exception as e:
            print(f"Error loading whitelist: {str(e)}")
            return default_whitelist
    
    def _save_whitelist(self, domains: Set[str]):
        """Save whitelist to JSON file."""
        try:
            data = {'domains': list(domains)}
            with open(self.whitelist_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Error saving whitelist: {str(e)}")
    
    def add_domain(self, domain: str) -> bool:
        """Add a domain to the whitelist."""
        try:
            # Clean domain
            domain = domain.lower().strip()
            if domain.startswith('www.'):
                domain = domain[4:]
            
            self.legitimate_domains.add(domain)
            self._save_whitelist(self.legitimate_domains)
            print(f"Added {domain} to whitelist")
            return True
        except Exception as e:
            print(f"Error adding domain: {str(e)}")
            return False
    
    def remove_domain(self, domain: str) -> bool:
        """Remove a domain from the whitelist."""
        try:
            domain = domain.lower().strip()
            if domain.startswith('www.'):
                domain = domain[4:]
            
            if domain in self.legitimate_domains:
                self.legitimate_domains.remove(domain)
                self._save_whitelist(self.legitimate_domains)
                print(f"Removed {domain} from whitelist")
                return True
            else:
                print(f"Domain {domain} not found in whitelist")
                return False
        except Exception as e:
            print(f"Error removing domain: {str(e)}")
            return False
    
    def is_whitelisted(self, domain: str) -> bool:
        """Check if a domain is in the whitelist."""
        try:
            domain = domain.lower().strip()
            if domain.startswith('www.'):
                domain = domain[4:]
            
            return domain in self.legitimate_domains
        except Exception as e:
            print(f"Error checking whitelist: {str(e)}")
            return False
    
    def get_all_domains(self) -> List[str]:
        """Get all whitelisted domains."""
        return sorted(list(self.legitimate_domains))
    
    def search_domains(self, query: str) -> List[str]:
        """Search for domains containing the query."""
        query = query.lower()
        return [domain for domain in self.legitimate_domains if query in domain]
    
    def export_whitelist(self, filename: str = None):
        """Export whitelist to a file."""
        if filename is None:
            filename = f"whitelist_export_{len(self.legitimate_domains)}_domains.txt"
        
        try:
            with open(filename, 'w') as f:
                f.write("# PhishNet Legitimate Domains Whitelist\n")
                f.write(f"# Total domains: {len(self.legitimate_domains)}\n")
                f.write("# Generated automatically\n\n")
                
                for domain in sorted(self.legitimate_domains):
                    f.write(f"{domain}\n")
            
            print(f"Whitelist exported to {filename}")
        except Exception as e:
            print(f"Error exporting whitelist: {str(e)}")

# Example usage
if __name__ == "__main__":
    manager = WhitelistManager()
    
    print("Current whitelist domains:")
    for domain in manager.get_all_domains()[:10]:  # Show first 10
        print(f"  • {domain}")
    
    print(f"\nTotal domains in whitelist: {len(manager.legitimate_domains)}")
    
    # Test adding a domain
    test_domain = "example.edu"
    if manager.add_domain(test_domain):
        print(f"Successfully added {test_domain}")
    
    # Test checking a domain
    if manager.is_whitelisted("rlsbca.edu.in"):
        print("rlsbca.edu.in is whitelisted ✓")
    
    # Export whitelist
    manager.export_whitelist() 
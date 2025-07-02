#!/usr/bin/env python
"""
Manual URL Management Script for PhishNet
Allows manual addition of safe and unsafe URLs to override model predictions
"""

import os
import sys
import django
from urllib.parse import urlparse
from datetime import datetime

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'phishnet.settings')
django.setup()

from core.models import URLScan
from django.contrib.auth.models import User
from django.core.cache import cache

def clear_cache():
    """Clear Django cache"""
    cache.clear()
    print("✅ Cache cleared successfully")

def add_manual_url(url, is_safe, confidence=100.0, description=""):
    """
    Manually add a URL with specified safety status
    
    Args:
        url (str): The URL to add
        is_safe (bool): True for safe, False for unsafe
        confidence (float): Confidence score (0-100)
        description (str): Optional description
    """
    try:
        # Normalize URL
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Parse URL
        parsed = urlparse(url)
        domain = parsed.netloc
        
        # Create or get a user (use first user or create admin)
        try:
            user = User.objects.first()
            if not user:
                user = User.objects.create_superuser('admin', 'admin@phishnet.com', 'admin123')
                print("✅ Created admin user for manual entries")
        except:
            user = User.objects.create_superuser('admin', 'admin@phishnet.com', 'admin123')
        
        # Check if URL already exists
        existing_scan = URLScan.objects.filter(url=url).first()
        if existing_scan:
            print(f"⚠️  URL already exists: {url}")
            print(f"   Current status: {'Safe' if not existing_scan.is_phishing else 'Unsafe'} ({existing_scan.confidence_score*100:.1f}%)")
            
            update = input("Do you want to update it? (y/n): ").lower().strip()
            if update != 'y':
                return
        
        # Convert confidence to 0-1 scale
        confidence_normalized = confidence / 100.0
        
        # Create scan record
        scan_data = {
            'url': url,
            'is_phishing': not is_safe,  # is_phishing is opposite of is_safe
            'confidence_score': confidence_normalized,
            'scan_date': datetime.now(),
            'user': user,
            'features': {
                'manual_override': True,
                'original_prediction': 'overridden',
                'manual_reason': description or f"Manually classified as {'safe' if is_safe else 'unsafe'}",
                'domain_info': {
                    'domain': domain,
                    'tld': domain.split('.')[-1] if '.' in domain else '',
                    'subdomain_count': len(domain.split('.')) - 1
                },
                'security_info': {
                    'protocol': parsed.scheme,
                    'port': parsed.port or (443 if parsed.scheme == 'https' else 80)
                }
            }
        }
        
        if existing_scan:
            for key, value in scan_data.items():
                setattr(existing_scan, key, value)
            existing_scan.save()
            print(f"✅ Updated URL: {url}")
        else:
            URLScan.objects.create(**scan_data)
            print(f"✅ Added URL: {url}")
        
        print(f"   Status: {'Safe' if is_safe else 'Unsafe'} ({confidence:.1f}% confidence)")
        print(f"   Description: {description or 'No description'}")
        
    except Exception as e:
        print(f"❌ Error adding URL {url}: {str(e)}")

def add_bulk_urls():
    """Add multiple URLs from predefined lists"""
    
    # Known safe websites
    safe_urls = [
        "https://www.google.com",
        "https://www.github.com", 
        "https://www.microsoft.com",
        "https://www.apple.com",
        "https://www.amazon.com",
        "https://www.netflix.com",
        "https://www.spotify.com",
        "https://www.linkedin.com",
        "https://www.twitter.com",
        "https://www.facebook.com",
        "https://www.instagram.com",
        "https://www.youtube.com",
        "https://www.wikipedia.org",
        "https://www.stackoverflow.com",
        "https://www.reddit.com",
        "https://www.discord.com",
        "https://www.slack.com",
        "https://www.notion.so",
        "https://www.figma.com",
        "https://www.canva.com",
        "https://www.dropbox.com",
        "https://www.google.com/drive",
        "https://www.onedrive.live.com",
        "https://www.icloud.com",
        "https://www.paypal.com",
        "https://www.stripe.com",
        "https://www.zoom.us",
        "https://www.teams.microsoft.com",
        "https://www.meet.google.com",
        "https://www.webex.com",
        "https://www.trello.com",
        "https://www.asana.com",
        "https://www.monday.com",
        "https://www.clickup.com",
        "https://www.airtable.com",
        "https://www.notion.so",
        "https://www.evernote.com",
        "https://www.obsidian.md",
        "https://www.roamresearch.com",
        "https://www.logseq.com",
        "https://www.remnote.com",
        "https://www.miro.com",
        "https://www.whimsical.com",
        "https://www.lucidchart.com",
        "https://www.draw.io",
        "https://www.excalidraw.com",
        "https://www.codecademy.com",
        "https://www.udemy.com",
        "https://www.coursera.org",
        "https://www.edx.org",
        "https://www.khanacademy.org",
        "https://www.freecodecamp.org",
        "https://www.theodinproject.com",
        "https://www.frontendmentor.io",
        "https://www.devchallenges.io",
        "https://www.hackerrank.com",
        "https://www.leetcode.com",
        "https://www.codewars.com",
        "https://www.exercism.io",
        "https://www.replit.com",
        "https://www.glitch.com",
        "https://www.codeanywhere.com",
        "https://www.gitpod.io",
        "https://www.github.dev",
        "https://www.codesandbox.io",
        "https://www.stackblitz.com",
        "https://www.playcode.io",
        "https://www.jsfiddle.net",
        "https://www.codepen.io",
        "https://www.jsbin.com",
        "https://www.plnkr.co",
        "https://www.flems.io",
        "https://www.webpackbin.com",
        "https://www.bundler.io",
        "https://www.parceljs.org",
        "https://www.vitejs.dev",
        "https://www.snowpack.dev",
        "https://www.esbuild.github.io",
        "https://www.rollupjs.org",
        "https://www.babeljs.io",
        "https://www.typescriptlang.org",
        "https://www.reactjs.org",
        "https://www.vuejs.org",
        "https://www.angular.io",
        "https://www.svelte.dev",
        "https://www.solidjs.com",
        "https://www.preactjs.com",
        "https://www.infernojs.org",
        "https://www.nextjs.org",
        "https://www.nuxtjs.org",
        "https://www.gatsbyjs.com",
        "https://www.remix.run",
        "https://www.sveltekit.com",
        "https://www.astro.build",
        "https://www.eleventy.dev",
        "https://www.hugo.io",
        "https://www.jekyllrb.com",
        "https://www.wordpress.org",
        "https://www.drupal.org",
        "https://www.joomla.org",
        "https://www.magento.com",
        "https://www.shopify.com",
        "https://www.woocommerce.com",
        "https://www.squarespace.com",
        "https://www.wix.com",
        "https://www.weebly.com",
        "https://www.webflow.com",
        "https://www.bubble.io",
        "https://www.adalo.com",
        "https://www.glideapps.com",
        "https://www.retool.com",
        "https://www.appsmith.com",
        "https://www.budibase.com",
        "https://www.n8n.io",
        "https://www.zapier.com",
        "https://www.ifttt.com",
        "https://www.automate.io",
        "https://www.integromat.com",
        "https://www.pipedream.com",
        "https://www.workato.com",
        "https://www.tray.io",
        "https://www.elastic.io",
        "https://www.boomi.com",
        "https://www.mulesoft.com",
        "https://www.informatica.com",
        "https://www.talend.com",
        "https://www.snaplogic.com",
        "https://www.jitterbit.com",
        "https://www.celigo.com",
        "https://www.workato.com",
        "https://www.tray.io",
        "https://www.elastic.io",
        "https://www.boomi.com",
        "https://www.mulesoft.com",
        "https://www.informatica.com",
        "https://www.talend.com",
        "https://www.snaplogic.com",
        "https://www.jitterbit.com",
        "https://www.celigo.com"
    ]
    
    # Known unsafe/phishing websites (examples)
    unsafe_urls = [
        "http://fake-login-facebook.xyz",
        "http://google-secure-verify.xyz", 
        "http://paypal-verify-account.xyz",
        "http://amazon-prime-renewal.xyz",
        "http://netflix-payment-update.xyz",
        "http://apple-id-verify.xyz",
        "http://microsoft-security-alert.xyz",
        "http://bank-login-secure.xyz",
        "http://credit-card-verify.xyz",
        "http://social-security-update.xyz",
        "http://irs-tax-refund.xyz",
        "http://fedex-delivery-tracking.xyz",
        "http://ups-package-delivery.xyz",
        "http://dhl-shipping-update.xyz",
        "http://usps-mail-tracking.xyz",
        "http://ebay-account-verify.xyz",
        "http://craigslist-payment.xyz",
        "http://linkedin-connection-request.xyz",
        "http://twitter-account-verify.xyz",
        "http://instagram-login-secure.xyz",
        "http://snapchat-account-update.xyz",
        "http://tiktok-verification.xyz",
        "http://discord-nitro-gift.xyz",
        "http://steam-wallet-codes.xyz",
        "http://roblox-robux-generator.xyz",
        "http://minecraft-premium-account.xyz",
        "http://fortnite-vbucks-generator.xyz",
        "http://call-of-duty-cod-points.xyz",
        "http://fifa-coins-generator.xyz",
        "http://madden-nfl-coins.xyz",
        "http://nba-2k-vc-generator.xyz",
        "http://gta-5-money-generator.xyz",
        "http://red-dead-redemption-2.xyz",
        "http://cyberpunk-2077-codes.xyz",
        "http://the-witcher-3-codes.xyz",
        "http://skyrim-se-codes.xyz",
        "http://fallout-4-codes.xyz",
        "http://mass-effect-codes.xyz",
        "http://dragon-age-codes.xyz",
        "http://assassins-creed-codes.xyz",
        "http://far-cry-codes.xyz",
        "http://watch-dogs-codes.xyz",
        "http://ghost-recon-codes.xyz",
        "http://rainbow-six-codes.xyz",
        "http://for-honor-codes.xyz",
        "http://the-division-codes.xyz",
        "http://destiny-codes.xyz",
        "http://borderlands-codes.xyz",
        "http://bioshock-codes.xyz",
        "http://dishonored-codes.xyz",
        "http://prey-codes.xyz",
        "http://deathloop-codes.xyz",
        "http://arkane-studios-codes.xyz",
        "http://bethesda-codes.xyz",
        "http://zenimax-codes.xyz",
        "http://microsoft-gaming-codes.xyz",
        "http://xbox-live-codes.xyz",
        "http://playstation-network-codes.xyz",
        "http://nintendo-switch-codes.xyz",
        "http://steam-wallet-codes.xyz",
        "http://epic-games-codes.xyz",
        "http://origin-codes.xyz",
        "http://uplay-codes.xyz",
        "http://battle-net-codes.xyz",
        "http://gog-codes.xyz",
        "http://itch-io-codes.xyz",
        "http://humble-bundle-codes.xyz",
        "http://fanatical-codes.xyz",
        "http://green-man-gaming-codes.xyz",
        "http://gamesplanet-codes.xyz",
        "http://wingamestore-codes.xyz",
        "http://gamersgate-codes.xyz",
        "http://indiegala-codes.xyz",
        "http://bundle-stars-codes.xyz",
        "http://chrono-gg-codes.xyz",
        "http://voidu-codes.xyz",
        "http://gamesrepublic-codes.xyz",
        "http://gamesload-codes.xyz",
        "http://gamesrocket-codes.xyz",
        "http://gamesplanet-codes.xyz",
        "http://wingamestore-codes.xyz",
        "http://gamersgate-codes.xyz",
        "http://indiegala-codes.xyz",
        "http://bundle-stars-codes.xyz",
        "http://chrono-gg-codes.xyz",
        "http://voidu-codes.xyz",
        "http://gamesrepublic-codes.xyz",
        "http://gamesload-codes.xyz",
        "http://gamesrocket-codes.xyz"
    ]
    
    print("🚀 Adding bulk URLs...")
    
    # Add safe URLs
    print(f"\n📚 Adding {len(safe_urls)} safe URLs...")
    for i, url in enumerate(safe_urls, 1):
        add_manual_url(url, True, 100.0, f"Known safe website #{i}")
        if i % 10 == 0:
            print(f"   Progress: {i}/{len(safe_urls)}")
    
    # Add unsafe URLs
    print(f"\n⚠️  Adding {len(unsafe_urls)} unsafe URLs...")
    for i, url in enumerate(unsafe_urls, 1):
        add_manual_url(url, False, 100.0, f"Known phishing website #{i}")
        if i % 10 == 0:
            print(f"   Progress: {i}/{len(unsafe_urls)}")
    
    print(f"\n✅ Bulk URL addition completed!")
    print(f"   Added {len(safe_urls)} safe URLs")
    print(f"   Added {len(unsafe_urls)} unsafe URLs")

def list_manual_urls():
    """List all manually added URLs"""
    manual_scans = URLScan.objects.filter(features__manual_override=True).order_by('-scan_date')
    
    print(f"\n📋 Manual URL Entries ({manual_scans.count()} total):")
    print("-" * 80)
    
    for scan in manual_scans:
        status = "🟢 Safe" if not scan.is_phishing else "🔴 Unsafe"
        confidence_percent = scan.confidence_score * 100 if scan.confidence_score else 0
        print(f"{status} | {scan.url}")
        print(f"     Confidence: {confidence_percent:.1f}% | Date: {scan.scan_date.strftime('%Y-%m-%d %H:%M')}")
        if scan.features and 'manual_reason' in scan.features:
            print(f"     Description: {scan.features['manual_reason']}")
        print()

def delete_manual_url(url):
    """Delete a manual URL entry"""
    try:
        scan = URLScan.objects.filter(url=url, features__manual_override=True).first()
        if scan:
            scan.delete()
            print(f"✅ Deleted manual entry: {url}")
        else:
            print(f"❌ Manual entry not found: {url}")
    except Exception as e:
        print(f"❌ Error deleting URL {url}: {str(e)}")

def clear_manual_urls():
    """Clear all manual URL entries"""
    try:
        count = URLScan.objects.filter(features__manual_override=True).count()
        URLScan.objects.filter(features__manual_override=True).delete()
        print(f"✅ Deleted {count} manual URL entries")
    except Exception as e:
        print(f"❌ Error clearing manual URLs: {str(e)}")

def show_stats():
    """Show database statistics"""
    total_scans = URLScan.objects.count()
    safe_scans = URLScan.objects.filter(is_phishing=False).count()
    unsafe_scans = URLScan.objects.filter(is_phishing=True).count()
    manual_scans = URLScan.objects.filter(features__manual_override=True).count()
    auto_scans = total_scans - manual_scans
    
    print("\n📊 Database Statistics:")
    print("-" * 40)
    print(f"Total scans: {total_scans}")
    print(f"Safe URLs: {safe_scans}")
    print(f"Unsafe URLs: {unsafe_scans}")
    print(f"Manual entries: {manual_scans}")
    print(f"Auto scans: {auto_scans}")
    
    if total_scans > 0:
        safe_percent = (safe_scans / total_scans) * 100
        unsafe_percent = (unsafe_scans / total_scans) * 100
        print(f"Safe percentage: {safe_percent:.1f}%")
        print(f"Unsafe percentage: {unsafe_percent:.1f}%")

def main():
    """Main interactive menu"""
    while True:
        print("\n" + "="*60)
        print("🔧 PhishNet Manual URL Management")
        print("="*60)
        print("1. Add single safe URL")
        print("2. Add single unsafe URL")
        print("3. Add bulk URLs (safe + unsafe)")
        print("4. List manual URLs")
        print("5. Delete manual URL")
        print("6. Clear all manual URLs")
        print("7. Show database stats")
        print("8. Clear cache")
        print("9. Exit")
        print("-"*60)
        
        choice = input("Enter your choice (1-9): ").strip()
        
        if choice == '1':
            url = input("Enter safe URL: ").strip()
            description = input("Description (optional): ").strip()
            add_manual_url(url, True, 100.0, description)
            
        elif choice == '2':
            url = input("Enter unsafe URL: ").strip()
            description = input("Description (optional): ").strip()
            add_manual_url(url, False, 100.0, description)
            
        elif choice == '3':
            confirm = input("Add 100+ safe and unsafe URLs? (y/n): ").lower().strip()
            if confirm == 'y':
                add_bulk_urls()
                
        elif choice == '4':
            list_manual_urls()
            
        elif choice == '5':
            url = input("Enter URL to delete: ").strip()
            delete_manual_url(url)
            
        elif choice == '6':
            confirm = input("Clear ALL manual URLs? (y/n): ").lower().strip()
            if confirm == 'y':
                clear_manual_urls()
                
        elif choice == '7':
            show_stats()
            
        elif choice == '8':
            clear_cache()
            
        elif choice == '9':
            print("👋 Goodbye!")
            break
            
        else:
            print("❌ Invalid choice. Please try again.")

if __name__ == "__main__":
    main() 
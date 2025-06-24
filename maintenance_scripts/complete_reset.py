#!/usr/bin/env python3
"""
Complete reset script for PhishNet
"""

import os
import django
import subprocess
import sys

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'phishnet.settings')
django.setup()

from django.core.cache import cache
from core.models import URLScan, Report

def complete_reset():
    """Complete reset of PhishNet system."""
    
    print("=== COMPLETE PHISHNET RESET ===")
    print("=" * 40)
    
    # 1. Clear Django cache
    print("\n1. Clearing Django cache...")
    try:
        cache.clear()
        print("✅ Django cache cleared")
    except Exception as e:
        print(f"❌ Error clearing cache: {e}")
    
    # 2. Clear all database data
    print("\n2. Clearing database data...")
    try:
        scan_count = URLScan.objects.count()
        report_count = Report.objects.count()
        
        URLScan.objects.all().delete()
        Report.objects.all().delete()
        
        print(f"✅ Deleted {scan_count} scans and {report_count} reports")
    except Exception as e:
        print(f"❌ Error clearing database: {e}")
    
    # 3. Clear any temporary files
    print("\n3. Clearing temporary files...")
    try:
        import shutil
        media_dir = os.path.join(os.path.dirname(__file__), 'media')
        if os.path.exists(media_dir):
            for item in os.listdir(media_dir):
                item_path = os.path.join(media_dir, item)
                if os.path.isfile(item_path):
                    os.remove(item_path)
                elif os.path.isdir(item_path):
                    shutil.rmtree(item_path)
            print("✅ Media files cleared")
        else:
            print("ℹ️  No media directory found")
    except Exception as e:
        print(f"❌ Error clearing media files: {e}")
    
    print("\n" + "=" * 40)
    print("✅ RESET COMPLETE!")
    print("\nNEXT STEPS:")
    print("1. Stop your Django server (Ctrl+C)")
    print("2. Start it again: python manage.py runserver")
    print("3. Go to your web interface")
    print("4. Scan: https://www.rlsbca.edu.in/")
    print("5. You should see: 'Safe Website' with 98.6% confidence")
    print("\nIf you still see 'Potential Phishing Website Detected':")
    print("- Clear your browser cache (Ctrl+Shift+Delete)")
    print("- Try a hard refresh (Ctrl+F5)")
    print("- Try in an incognito/private window")
    print("=" * 40)

if __name__ == "__main__":
    complete_reset() 
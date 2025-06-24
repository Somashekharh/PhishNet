#!/usr/bin/env python3
"""
Script to clear Django cache and all scan/report data
"""

import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'phishnet.settings')
django.setup()

from django.core.cache import cache
from core.models import URLScan, Report

def clear_all():
    try:
        cache.clear()
        print("✅ Django cache cleared successfully")
        URLScan.objects.all().delete()
        print("✅ All scan history deleted")
        Report.objects.all().delete()
        print("✅ All reports deleted")
    except Exception as e:
        print(f"❌ Error clearing data: {e}")

if __name__ == "__main__":
    clear_all() 
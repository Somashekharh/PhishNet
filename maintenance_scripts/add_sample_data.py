#!/usr/bin/env python3
"""
Script to add sample safe and phishing URLs to the database
"""

import os
import django
from django.utils import timezone

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'phishnet.settings')
django.setup()

from core.models import URLScan
from django.contrib.auth.models import User

# Get the first user (or create a demo user)
user = User.objects.first()
if not user:
    user = User.objects.create_user(username='demo', password='demo1234')
    print('Created demo user: demo / demo1234')

sample_data = [
    # Safe URLs
    {"url": "https://www.google.com", "is_phishing": False, "confidence_score": 0.99},
    {"url": "https://www.rlsbca.edu.in/", "is_phishing": False, "confidence_score": 0.98},
    {"url": "https://www.mit.edu/", "is_phishing": False, "confidence_score": 0.98},
    # Phishing URLs
    {"url": "http://secure-login-google.com/account/verify", "is_phishing": True, "confidence_score": 0.97},
    {"url": "http://paypal.com.user-login.security-alert.tk", "is_phishing": True, "confidence_score": 0.96},
    {"url": "http://amaz0n-support.com/reset-password", "is_phishing": True, "confidence_score": 0.95},
]

def add_samples():
    for entry in sample_data:
        URLScan.objects.create(
            user=user,
            url=entry["url"],
            is_phishing=entry["is_phishing"],
            confidence_score=entry["confidence_score"],
            scan_date=timezone.now()
        )
        print(f"Added: {entry['url']} ({'Phishing' if entry['is_phishing'] else 'Safe'})")

if __name__ == "__main__":
    add_samples() 
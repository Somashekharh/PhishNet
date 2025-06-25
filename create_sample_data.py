#!/usr/bin/env python3
"""
Script to create sample data for the PhishNet database.
"""
import os
import django
import random
from datetime import timedelta
from django.utils import timezone

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'phishnet.settings')
django.setup()

from django.contrib.auth.models import User
from core.models import URLScan, Report, Contact

# Create sample users
users = [
    {'username': 'alice', 'email': 'alice@example.com'},
    {'username': 'bob', 'email': 'bob@example.com'},
    {'username': 'charlie', 'email': 'charlie@example.com'},
]

for user_data in users:
    user, created = User.objects.get_or_create(username=user_data['username'], defaults={
        'email': user_data['email']
    })
    if created:
        user.set_password('password123')
        user.save()
    print(f"User: {user.username} (created={created})")

# Sample URLs
urls = [
    'https://www.google.com',
    'https://phishing-attack.com',
    'https://secure-bank.com',
    'https://malicious-site.xyz',
    'https://university.edu',
    'https://gov-portal.gov',
]

# Create sample URL scans
for i in range(10):
    user = User.objects.order_by('?').first()
    url = random.choice(urls)
    is_phishing = random.choice([True, False])
    confidence = round(random.uniform(0.7, 0.99) if not is_phishing else random.uniform(0.5, 0.95), 2)
    scan_date = timezone.now() - timedelta(days=random.randint(0, 30))
    features = {'url_length': len(url), 'has_https': url.startswith('https://')}
    scan = URLScan.objects.create(
        user=user,
        url=url,
        is_phishing=is_phishing,
        confidence_score=confidence,
        scan_date=scan_date,
        features=features
    )
    print(f"URLScan: {scan.url} ({'Phishing' if scan.is_phishing else 'Safe'}) - {scan.confidence_score}")

# Create sample reports
for i in range(5):
    user = User.objects.order_by('?').first()
    url = random.choice(urls)
    description = f"Suspicious activity detected on {url}."
    status = random.choice(['pending', 'verified', 'rejected'])
    reported_date = timezone.now() - timedelta(days=random.randint(0, 30))
    report = Report.objects.create(
        user=user,
        url=url,
        description=description,
        status=status,
        reported_date=reported_date
    )
    print(f"Report: {report.url} ({report.status})")

# Create sample contact messages
for i in range(3):
    name = random.choice(['Alice', 'Bob', 'Charlie', 'David'])
    email = f"{name.lower()}@example.com"
    subject = f"Help needed #{i+1}"
    message = f"This is a sample message from {name}."
    created_at = timezone.now() - timedelta(days=random.randint(0, 30))
    contact = Contact.objects.create(
        name=name,
        email=email,
        subject=subject,
        message=message,
        created_at=created_at
    )
    print(f"Contact: {contact.name} - {contact.subject}")

print("\nSample data creation complete!") 
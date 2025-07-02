#!/usr/bin/env python
"""
Add comprehensive test/demo data to the database:
- Creates a test user and a test admin (staff/superuser)
- Adds multiple scan results (phishing and non-phishing) for both
- Adds user reports (pending, verified, rejected)
- Generates reports and screenshots
- Prints all created objects for verification
"""
import os
import django
from datetime import datetime, timedelta

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'phishnet.settings')
django.setup()

from django.contrib.auth import get_user_model
from core.url_analyzer import URLAnalyzer
from core.models import URLScan, Report

# Test users
TEST_USER = {
    'username': 'testuser',
    'email': 'testuser@example.com',
    'password': 'testpass123',
}
TEST_ADMIN = {
    'username': 'adminuser',
    'email': 'admin@example.com',
    'password': 'adminpass123',
}

SCAN_URLS = [
    ('https://example.com', False, 0.95),
    ('https://phishing.test', True, 0.90),
    ('https://github.com', False, 0.98),
    ('http://suspicious-domain.biz', True, 0.85),
]

REPORT_URLS = [
    ('http://malicious-site.com', 'pending'),
    ('http://fake-login.com', 'verified'),
    ('http://benign-site.com', 'rejected'),
]

def get_or_create_user(user_dict, is_admin=False):
    User = get_user_model()
    user, created = User.objects.get_or_create(username=user_dict['username'], defaults={
        'email': user_dict['email'],
        'is_staff': is_admin,
        'is_superuser': is_admin,
    })
    if created:
        user.set_password(user_dict['password'])
        user.save()
        print(f"✅ Created {'admin' if is_admin else 'test'} user: {user.username}")
    else:
        print(f"ℹ️ {'Admin' if is_admin else 'Test'} user already exists: {user.username}")
    return user

def add_scans_for_user(user, analyzer):
    print(f"\nAdding scans for {user.username}...")
    for url, is_phishing, confidence in SCAN_URLS:
        print(f"Analyzing {url} (phishing={is_phishing})...")
        analysis, report_path = analyzer.analyze_url(url)
        scan = URLScan.objects.create(
            user=user,
            url=url,
            is_phishing=is_phishing,
            confidence_score=confidence,
            scan_date=datetime.now() - timedelta(days=SCAN_URLS.index((url, is_phishing, confidence)))
        )
        print(f"  - Scan ID={scan.id}, Report={report_path}, Screenshot={analysis.get('screenshot_path')}")

def add_reports_for_user(user, admin):
    print(f"\nAdding reports for {user.username}...")
    for url, status in REPORT_URLS:
        report = Report.objects.create(
            user=user,
            url=url,
            status=status,
            reported_date=datetime.now() - timedelta(days=REPORT_URLS.index((url, status))),
            reviewed_by=admin if status in ['verified', 'rejected'] else None,
            reviewed_date=datetime.now() if status in ['verified', 'rejected'] else None
        )
        print(f"  - Report ID={report.id}, URL={url}, Status={status}")

def main():
    analyzer = URLAnalyzer()
    # Create users
    test_user = get_or_create_user(TEST_USER, is_admin=False)
    admin_user = get_or_create_user(TEST_ADMIN, is_admin=True)
    # Add scans
    add_scans_for_user(test_user, analyzer)
    add_scans_for_user(admin_user, analyzer)
    # Add reports
    add_reports_for_user(test_user, admin_user)
    add_reports_for_user(admin_user, admin_user)
    print("\n✅ Demo/test data creation complete!")
    print(f"\nTest user login: {TEST_USER['username']} / {TEST_USER['password']}")
    print(f"Admin user login: {TEST_ADMIN['username']} / {TEST_ADMIN['password']}")

if __name__ == "__main__":
    main() 
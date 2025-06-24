from django.test import TestCase
from django.contrib.auth.models import User
from django.urls import reverse
from .models import URLScan, Report


class URLScanTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
    
    def test_scan_creation(self):
        """Test that URL scans can be created"""
        scan = URLScan.objects.create(
            user=self.user,
            url='https://example.com',
            is_phishing=False,
            confidence_score=0.95
        )
        self.assertEqual(scan.user, self.user)
        self.assertEqual(scan.url, 'https://example.com')
        self.assertFalse(scan.is_phishing)


class ViewTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
    
    def test_landing_page(self):
        """Test landing page loads correctly"""
        response = self.client.get(reverse('landing'))
        self.assertEqual(response.status_code, 200)
    
    def test_dashboard_requires_login(self):
        """Test dashboard requires authentication"""
        response = self.client.get(reverse('dashboard'))
        self.assertEqual(response.status_code, 302)  # Redirect to login

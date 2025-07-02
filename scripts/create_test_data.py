import random
import json
from datetime import timedelta
from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from django.utils import timezone
from core.models import URLScan, Report, Contact

class Command(BaseCommand):
    help = 'Creates test data for the PhishNet application'

    def add_arguments(self, parser):
        parser.add_argument('--users', type=int, default=5, help='Number of test users to create')
        parser.add_argument('--scans', type=int, default=50, help='Number of URL scans to create')
        parser.add_argument('--reports', type=int, default=20, help='Number of reports to create')
        parser.add_argument('--contacts', type=int, default=10, help='Number of contact messages to create')

    def handle(self, *args, **options):
        num_users = options['users']
        num_scans = options['scans']
        num_reports = options['reports']
        num_contacts = options['contacts']
        
        self.stdout.write(self.style.SUCCESS('Starting test data generation...'))
        
        # Create test users
        users = self.create_users(num_users)
        
        # Create test scans
        self.create_scans(users, num_scans)
        
        # Create test reports
        self.create_reports(users, num_reports)
        
        # Create test contact messages
        self.create_contacts(num_contacts)
        
        self.stdout.write(self.style.SUCCESS('Test data generation complete!'))

    def create_users(self, count):
        self.stdout.write(f'Creating {count} test users...')
        users = []
        
        # Always ensure admin user exists
        admin_user, created = User.objects.get_or_create(
            username='admin',
            defaults={
                'email': 'admin@phishnet.com',
                'is_staff': True,
                'is_superuser': True
            }
        )
        
        if created:
            admin_user.set_password('admin123')
            admin_user.save()
            self.stdout.write(f'Created admin user: admin/admin123')
        
        users.append(admin_user)
        
        # Create regular test users
        for i in range(1, count):
            username = f'user{i}'
            if not User.objects.filter(username=username).exists():
                user = User.objects.create_user(
                    username=username,
                    email=f'user{i}@example.com',
                    password=f'password{i}'
                )
                self.stdout.write(f'Created user: {username}/password{i}')
                users.append(user)
            else:
                users.append(User.objects.get(username=username))
        
        return users

    def create_scans(self, users, count):
        self.stdout.write(f'Creating {count} URL scans...')
        
        # Sample URLs for testing
        legitimate_urls = [
            'https://www.google.com',
            'https://www.microsoft.com',
            'https://www.amazon.com',
            'https://www.github.com',
            'https://www.youtube.com',
            'https://www.facebook.com',
            'https://www.twitter.com',
            'https://www.reddit.com',
            'https://www.wikipedia.org',
            'https://www.linkedin.com'
        ]
        
        phishing_urls = [
            'https://g00gle.com-secure.site',
            'https://amaz0n-security-check.com',
            'https://secure-facebook-login.net',
            'https://paypa1-account-verify.com',
            'https://microsoft-365-verify.net',
            'https://apple-icloud-signin.com',
            'https://banking-secure-portal.com',
            'https://netflix-account-billing.com',
            'https://instagram-verify-login.net',
            'https://twitter-account-secure.com'
        ]
        
        # Sample features that might be extracted
        feature_templates = {
            "legitimate": {
                "url_length": lambda: random.randint(10, 30),
                "domain_age_days": lambda: random.randint(500, 3000),
                "has_https": lambda: True,
                "has_suspicious_tld": lambda: False,
                "has_ip_address": lambda: False,
                "redirect_count": lambda: random.randint(0, 2),
                "has_suspicious_chars": lambda: False,
                "subdomain_count": lambda: random.randint(0, 2),
                "domain_in_path": lambda: False,
                "form_count": lambda: random.randint(0, 3),
                "external_favicon": lambda: False,
                "has_password_field": lambda: random.choice([True, False]),
                "has_suspicious_scripts": lambda: False,
                "domain_registration_length": lambda: random.randint(365, 3650),
                "alexa_rank": lambda: random.randint(1, 100000),
                "page_rank": lambda: random.uniform(5.0, 10.0),
                "google_index": lambda: True,
                "links_pointing": lambda: random.randint(50, 10000),
                "statistical_report": lambda: random.uniform(0.0, 0.3)
            },
            "phishing": {
                "url_length": lambda: random.randint(30, 100),
                "domain_age_days": lambda: random.randint(1, 30),
                "has_https": lambda: random.choice([True, False]),
                "has_suspicious_tld": lambda: True,
                "has_ip_address": lambda: random.choice([True, False]),
                "redirect_count": lambda: random.randint(2, 5),
                "has_suspicious_chars": lambda: True,
                "subdomain_count": lambda: random.randint(3, 6),
                "domain_in_path": lambda: True,
                "form_count": lambda: random.randint(1, 2),
                "external_favicon": lambda: True,
                "has_password_field": lambda: True,
                "has_suspicious_scripts": lambda: True,
                "domain_registration_length": lambda: random.randint(1, 180),
                "alexa_rank": lambda: random.randint(500000, 10000000),
                "page_rank": lambda: random.uniform(0.0, 2.0),
                "google_index": lambda: False,
                "links_pointing": lambda: random.randint(0, 5),
                "statistical_report": lambda: random.uniform(0.7, 1.0)
            }
        }
        
        # Create URL scans
        for i in range(count):
            is_phishing = random.choice([True, False])
            
            if is_phishing:
                url = random.choice(phishing_urls)
                feature_type = "phishing"
                confidence = random.uniform(0.70, 0.99)
            else:
                url = random.choice(legitimate_urls)
                feature_type = "legitimate"
                confidence = random.uniform(0.65, 0.95)
            
            # Generate features
            features = {}
            for feature, value_func in feature_templates[feature_type].items():
                features[feature] = value_func()
            
            # Random date within the last 30 days
            scan_date = timezone.now() - timedelta(
                days=random.randint(0, 30),
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59)
            )
            
            URLScan.objects.create(
                user=random.choice(users),
                url=url,
                is_phishing=is_phishing,
                scan_date=scan_date,
                features=features,
                confidence_score=confidence
            )
        
        self.stdout.write(self.style.SUCCESS(f'Created {count} URL scans'))

    def create_reports(self, users, count):
        self.stdout.write(f'Creating {count} reports...')
        
        # Sample suspicious URLs
        suspicious_urls = [
            'https://suspicious-login-portal.com',
            'https://fake-bank-website.net',
            'https://malware-download.site',
            'https://phishing-campaign.xyz',
            'https://credential-stealer.org',
            'https://fake-crypto-exchange.com',
            'https://suspicious-attachment.net',
            'https://fake-lottery-winner.com',
            'https://malicious-redirect.site',
            'https://data-stealer.xyz'
        ]
        
        # Sample descriptions
        descriptions = [
            "This site asked for my banking credentials and looked suspicious.",
            "The page has a similar layout to a legitimate site but the URL is different.",
            "I received an email with this link that asked for personal information.",
            "This site appears to be impersonating a legitimate service.",
            "The webpage contains suspicious download links and pop-ups.",
            "This URL was sent to me in a message claiming to be from my bank.",
            "The site has poor grammar and spelling mistakes but asks for sensitive information.",
            "I noticed this fake version of a popular website trying to steal login credentials.",
            "This URL redirects to multiple suspicious domains.",
            "The website claims to offer free services but requires payment information."
        ]
        
        # Statuses
        statuses = ['pending', 'verified', 'rejected']
        
        # Admin user for reviews
        admin_user = User.objects.filter(is_superuser=True).first()
        
        # Create reports
        for i in range(count):
            url = random.choice(suspicious_urls)
            description = random.choice(descriptions)
            status = random.choice(statuses)
            reported_date = timezone.now() - timedelta(
                days=random.randint(0, 60),
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59)
            )
            
            # If status is not pending, add review details
            reviewed_date = None
            reviewed_by = None
            
            if status != 'pending':
                reviewed_date = reported_date + timedelta(
                    days=random.randint(1, 5),
                    hours=random.randint(1, 12)
                )
                reviewed_by = admin_user
            
            Report.objects.create(
                user=random.choice(users),
                url=url,
                description=description,
                status=status,
                reported_date=reported_date,
                reviewed_date=reviewed_date,
                reviewed_by=reviewed_by
            )
        
        self.stdout.write(self.style.SUCCESS(f'Created {count} reports'))

    def create_contacts(self, count):
        self.stdout.write(f'Creating {count} contact messages...')
        
        # Sample names
        names = ['John Smith', 'Jane Doe', 'Robert Johnson', 'Mary Williams', 
                 'Michael Brown', 'Sarah Davis', 'David Miller', 'Lisa Wilson',
                 'James Moore', 'Jennifer Taylor']
        
        # Sample emails
        emails = ['john@example.com', 'jane@example.com', 'robert@example.com',
                  'mary@example.com', 'michael@example.com', 'sarah@example.com',
                  'david@example.com', 'lisa@example.com', 'james@example.com',
                  'jennifer@example.com']
        
        # Sample subjects
        subjects = ['Question about phishing detection', 'False positive report',
                    'Thank you for your service', 'Feature request',
                    'Technical issue with scanning', 'Account problem',
                    'API integration question', 'Security concern',
                    'Feedback on recent update', 'Partnership inquiry']
        
        # Sample messages
        messages = [
            "I've been using your service and wanted to know more about how the phishing detection works.",
            "I believe your system has incorrectly flagged a legitimate website as phishing. Can you review this?",
            "Thanks for creating such a useful tool. It has helped me avoid several suspicious websites.",
            "Would it be possible to add export functionality to download scan results?",
            "I'm experiencing an error when trying to scan certain URLs. The page just keeps loading.",
            "I can't seem to access my account history. Is there a way to recover this information?",
            "We're interested in integrating your API into our security solution. Do you have documentation?",
            "I wanted to report a potential security vulnerability I noticed on your platform.",
            "The new interface is much better! Just wanted to let you know it's a great improvement.",
            "Our organization is interested in a potential partnership. Who should we contact to discuss this?"
        ]
        
        # Statuses
        statuses = ['new', 'read', 'responded']
        
        # Admin user for replies
        admin_user = User.objects.filter(is_superuser=True).first()
        
        # Create contacts
        for i in range(count):
            name = random.choice(names)
            email = random.choice(emails)
            subject = random.choice(subjects)
            message = random.choice(messages)
            status = random.choice(statuses)
            created_at = timezone.now() - timedelta(
                days=random.randint(0, 30),
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59)
            )
            
            # If status is responded, add reply details
            reply = None
            replied_at = None
            replied_by = None
            
            if status == 'responded':
                reply = f"Thank you for contacting PhishNet support. {random.choice(['We appreciate your feedback.', 'We are looking into your issue.', 'We have resolved your problem.'])}"
                replied_at = created_at + timedelta(
                    days=random.randint(1, 3),
                    hours=random.randint(1, 8)
                )
                replied_by = admin_user
            
            Contact.objects.create(
                name=name,
                email=email,
                subject=subject,
                message=message,
                created_at=created_at,
                status=status,
                reply=reply,
                replied_at=replied_at,
                replied_by=replied_by
            )
        
        self.stdout.write(self.style.SUCCESS(f'Created {count} contact messages')) 
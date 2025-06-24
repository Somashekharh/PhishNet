from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

class URLScan(models.Model):
    user = models.ForeignKey(
        User, 
        on_delete=models.CASCADE,
        verbose_name="Scanned by",
        help_text="User who performed the scan",
        db_index=True  # Add index for faster user lookups
    )
    url = models.URLField(
        max_length=500,
        verbose_name="URL",
        help_text="The URL that was scanned for phishing",
        db_index=True  # Add index for URL searches
    )
    is_phishing = models.BooleanField(
        verbose_name="Is Phishing",
        help_text="Whether the URL was identified as a phishing attempt",
        db_index=True  # Add index for filtering by result
    )
    scan_date = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Scan Date",
        help_text="When the scan was performed",
        db_index=True  # Add index for date-based queries
    )
    features = models.JSONField(
        null=True, 
        blank=True,
        verbose_name="URL Features",
        help_text="Extracted features used for phishing detection"
    )
    confidence_score = models.FloatField(
        null=True, 
        blank=True,
        verbose_name="Confidence Score",
        help_text="Model's confidence in the prediction (0-1)",
        db_index=True  # Add index for confidence-based filtering
    )

    def __str__(self):
        return f"{self.url} - {'Phishing' if self.is_phishing else 'Legitimate'}"

    class Meta:
        ordering = ['-scan_date']
        verbose_name = "URL Scan"
        verbose_name_plural = "URL Scans"
        indexes = [
            models.Index(fields=['user', '-scan_date']),  # Compound index for user's recent scans
            models.Index(fields=['is_phishing', '-scan_date']),  # Compound index for filtering by result
        ]

class Report(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('verified', 'Verified'),
        ('rejected', 'Rejected'),
    ]

    user = models.ForeignKey(
        User, 
        on_delete=models.CASCADE,
        verbose_name="Reported by",
        help_text="User who reported the URL",
        db_index=True  # Add index for faster user lookups
    )
    url = models.URLField(
        max_length=500,
        verbose_name="Suspicious URL",
        help_text="The URL being reported as suspicious",
        db_index=True  # Add index for URL searches
    )
    description = models.TextField(
        verbose_name="Description",
        help_text="Detailed explanation of why this URL is suspicious"
    )
    status = models.CharField(
        max_length=10, 
        choices=STATUS_CHOICES, 
        default='pending',
        verbose_name="Review Status",
        help_text="Current status of the report review",
        db_index=True  # Add index for status filtering
    )
    reported_date = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Report Date",
        help_text="When the URL was reported",
        db_index=True  # Add index for date-based queries
    )
    reviewed_date = models.DateTimeField(
        null=True, 
        blank=True,
        verbose_name="Review Date",
        help_text="When the report was reviewed"
    )
    reviewed_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='reviewed_reports',
        verbose_name="Reviewed by",
        help_text="Admin who reviewed this report",
        db_index=True  # Add index for reviewer lookups
    )

    def __str__(self):
        return f"{self.url} - {self.status}"

    class Meta:
        ordering = ['-reported_date']
        verbose_name = "URL Report"
        verbose_name_plural = "URL Reports"
        indexes = [
            models.Index(fields=['user', '-reported_date']),  # Compound index for user's recent reports
            models.Index(fields=['status', '-reported_date']),  # Compound index for status filtering
        ]

class Contact(models.Model):
    STATUS_CHOICES = [
        ('new', 'New'),
        ('read', 'Read'),
        ('responded', 'Responded')
    ]
    
    name = models.CharField(max_length=100)
    email = models.EmailField()
    subject = models.CharField(max_length=200)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='new')
    reply = models.TextField(blank=True, null=True, verbose_name='Admin Reply')
    replied_at = models.DateTimeField(blank=True, null=True, verbose_name='Replied At')
    replied_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='contact_replies',
        verbose_name='Replied By'
    )

    def __str__(self):
        return f"{self.name} - {self.subject}"

    class Meta:
        ordering = ['-created_at']

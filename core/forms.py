from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from .models import Report, Contact
from urllib.parse import urlparse

class UserRegistrationForm(UserCreationForm):
    email = forms.EmailField(required=True)
    first_name = forms.CharField(required=True, max_length=30)
    last_name = forms.CharField(required=True, max_length=30)

    class Meta:
        model = User
        fields = ('username', 'email', 'first_name', 'last_name', 'password1', 'password2')


class URLScanForm(forms.Form):
    url = forms.URLField(
        required=True,
        widget=forms.URLInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter URL to scan...',
            'pattern': '.*',  # Allow any URL format
            'title': 'Enter a URL (http:// or https:// will be added if missing)'
        })
    )
    include_screenshot = forms.BooleanField(
        required=False,
        initial=False,
        label='Include Screenshot (slower)',
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )
    
    def clean_url(self):
        """Clean and normalize the URL."""
        url = self.cleaned_data['url'].strip()
        print(f"Original URL from form: {url}")
        
        # If scheme is missing, always add https://
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            print(f"Added https://: {url}")
        
        # Parse the URL
        parsed = urlparse(url)
        print(f"Parsed URL - scheme: {parsed.scheme}, netloc: {parsed.netloc}")
        
        # Always add www. if not present and not an IP
        if parsed.netloc and not parsed.netloc.startswith('www.') and '.' in parsed.netloc and not parsed.netloc.replace('.', '').isdigit():
            url = parsed._replace(netloc='www.' + parsed.netloc).geturl()
            print(f"Added www.: {url}")
        
        # Force scheme to https
        url = url.replace('http://', 'https://', 1)
        print(f"Final normalized URL: {url}")
        return url

class ReportForm(forms.ModelForm):
    class Meta:
        model = Report
        fields = ['url', 'description']
        widgets = {
            'url': forms.URLInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter suspicious URL...'
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'placeholder': 'Describe why you think this URL is suspicious...',
                'rows': 4
            })
        }

class ContactForm(forms.ModelForm):
    class Meta:
        model = Contact
        fields = ['name', 'email', 'subject', 'message']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Your Name'}),
            'email': forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'Your Email'}),
            'subject': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Subject'}),
            'message': forms.Textarea(attrs={'class': 'form-control', 'placeholder': 'Your Message', 'rows': 5}),
        } 
# PhishNet Setup Guide

## Quick Start

### Prerequisites
- Python 3.10 or higher
- Git (optional)
- Internet connection for downloading dependencies

### Installation Steps

1. **Clone or Navigate to Project Directory**
   ```bash
   # Navigate to your project directory
   cd path/to/project/PhishNet
   ```

2. **Create Virtual Environment**
   ```bash
   python -m venv venv
   ```

3. **Activate Virtual Environment**
   ```bash
   # Windows
   venv\Scripts\activate
   
   # PowerShell
   .\venv\Scripts\Activate.ps1
   
   # Linux/Mac
   source venv/bin/activate
   ```

4. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

5. **Install Playwright Browsers**
   ```bash
   playwright install
   ```

6. **Run Database Migrations**
   ```bash
   python manage.py migrate
   ```

7. **Start Development Server**
   ```bash
   python manage.py runserver
   ```

8. **Access Application**
   - Open browser and go to: `http://127.0.0.1:8000/`

## Troubleshooting

### Common Issues

1. **ModuleNotFoundError**
   - Ensure virtual environment is activated
   - Run: `pip install -r requirements.txt`

2. **Playwright Browser Issues**
   - Run: `playwright install`
   - Ensure internet connection is stable

3. **Scikit-learn Version Warnings**
   - Fixed in requirements.txt with version 1.3.2
   - If issues persist, run: `pip install scikit-learn==1.3.2`

4. **PDF Generation Issues**
   - Ensure wkhtmltopdf is installed
   - Check if `wkhtmltox.exe` exists in project root

### Environment Variables

Create a `.env` file in the project root if needed:
```
DEBUG=True
SECRET_KEY=your-secret-key-here
ALLOWED_HOSTS=localhost,127.0.0.1
```

## Development Commands

### Django Management
```bash
# Create superuser
python manage.py createsuperuser

# Collect static files
python manage.py collectstatic

# Run tests
python manage.py test

# Check for issues
python manage.py check
```

### Database Operations
```bash
# Make migrations
python manage.py makemigrations

# Apply migrations
python manage.py migrate

# Reset database (if needed)
python manage.py flush
```

## Project Structure

```
somNet/
├── core/                          # Main application
│   ├── models.py                  # Database models
│   ├── views.py                   # View controllers
│   ├── views_profile.py           # Profile view controllers
│   ├── urls.py                    # URL routing
│   ├── forms.py                   # Form definitions
│   ├── url_analyzer.py            # URL analysis functionality
│   ├── report_generator.py        # Report generation
│   ├── admin.py                   # Admin interface configuration
│   ├── ml_model/                  # Machine learning models
│   └── management/                # Custom management commands
├── templates/                     # HTML templates
│   ├── base.html                  # Base template with cyberpunk theme
│   ├── dashboard.html             # User dashboard
│   ├── scan_form.html             # URL scanning interface
│   ├── scan_result.html           # Scan results display
│   ├── admin/                     # Admin templates
│   └── registration/              # Authentication templates
├── media/                         # User uploaded files
│   └── screenshots/               # Captured webpage screenshots
├── phishnet/                      # Project configuration
│   ├── settings.py                # Django settings
│   ├── urls.py                    # Main URL configuration
│   └── wsgi.py                    # WSGI configuration
├── manage.py                      # Django management script
├── requirements.txt               # Python dependencies
└── db.sqlite3                     # SQLite database
```

## Features

- **URL Phishing Detection**: ML-powered analysis of URLs to identify phishing attempts
- **Screenshot Capture**: Automated webpage screenshots for visual verification
- **PDF Reports**: Comprehensive analysis reports with detailed findings
- **User Authentication**: Secure login system with password protection
- **Dashboard**: User activity tracking and statistics visualization
- **Modern UI**: Cyberpunk-themed responsive design with dark mode
- **Admin Interface**: Enhanced admin dashboard for site management

## Support

If you encounter any issues:
1. Check this setup guide
2. Verify all dependencies are installed
3. Ensure virtual environment is activated
4. Check Django logs for specific errors
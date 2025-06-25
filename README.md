# PhishNet - Advanced Phishing Detection & Cybersecurity Platform

🛡️ **AI-Powered Phishing Detection with Machine Learning**

PhishNet is a cutting-edge cybersecurity application that uses advanced machine learning algorithms to detect and prevent phishing attacks through comprehensive URL analysis. Built with Django and featuring a futuristic cyberpunk aesthetic, it provides real-time threat assessment with high accuracy.

## 🚀 Key Features

### 🔍 **Advanced URL Analysis**
- **Machine Learning Detection**: Random Forest classifier with 99.8% accuracy
- **Real-time Scanning**: Instant threat assessment with confidence scoring
- **Comprehensive Analysis**: Domain reputation, SSL certificates, content analysis
- **Visual Reports**: Screenshots and detailed security reports

### 🛡️ **Security Features**
- **Multi-layered Protection**: URL structure, domain analysis, content scanning
- **Whitelist Management**: Trusted domain verification
- **Educational/Government Domain Detection**: Automatic safe classification
- **Suspicious Pattern Recognition**: Advanced heuristic analysis

### 👤 **User Management**
- **Secure Authentication**: Django's built-in authentication system
- **Profile Management**: User settings and security preferences
- **Scan History**: Track all previous URL scans
- **Report System**: Submit and track phishing reports

### 🎨 **Cyberpunk UI/UX**
- **Futuristic Design**: Dark theme with neon accents
- **Responsive Layout**: Mobile-first design
- **Real-time Feedback**: Interactive elements and animations
- **Professional Admin Interface**: Dark-mode admin panel

## 🧠 Machine Learning Model

### **Current Model**: Random Forest Classifier
- **Algorithm**: `RandomForestClassifier` (scikit-learn)
- **Training Data**: 235,795 URLs from PhiUSIIL dataset
- **Features**: 10 optimized features for fast and accurate detection
- **Performance**: 99.8% detection accuracy

### **Model Features**:
- URL length and structure analysis
- HTTPS/HTTP protocol detection
- Suspicious TLD identification (.tk, .ml, .ga, .xyz, etc.)
- IP address detection
- Suspicious keyword analysis
- Domain reputation scoring
- Path and query analysis

### **Model Files**:
- `core/ml_model/model.pkl` - Trained model
- `core/ml_model/scaler.pkl` - Feature scaler
- `core/ml_model/feature_importance.csv` - Feature importance
- `core/ml_model/model_metadata.json` - Model metadata

## 🚀 Features

### Core Functionality
- **🔍 URL Scanning**: Advanced phishing detection using machine learning algorithms
- **📊 Real-time Analysis**: Instant threat assessment with confidence scoring
- **🛡️ Security Reports**: Comprehensive reporting system for suspicious URLs
- **👤 User Management**: Secure authentication and profile management
- **📞 Contact System**: Direct communication channel for security concerns
- **🎨 Cyberpunk UI**: Futuristic interface with animated elements and effects

### Security Features
- **Multi-factor Authentication**: Enhanced security protocols
- **Password Strength Validation**: Real-time password security assessment
- **Session Management**: Secure user session handling
- **Data Encryption**: Protected user data and communications
- **Threat Intelligence**: Advanced phishing detection algorithms

### User Interface
- **Responsive Design**: Mobile-first approach with cross-device compatibility
- **Dark Theme**: Cyberpunk-inspired dark interface
- **Animated Elements**: Smooth transitions and interactive components
- **Real-time Feedback**: Instant visual feedback for user actions
- **Accessibility**: WCAG compliant design principles

## 🛠️ Technology Stack

### Backend
- **Framework**: Django 4.x (Python)
- **Database**: SQLite (Development) / PostgreSQL (Production)
- **Authentication**: Django's built-in authentication system
- **API**: Django REST Framework
- **Security**: CSRF protection, XSS prevention, SQL injection protection

### Frontend
- **CSS Framework**: Bootstrap 5.x
- **Icons**: Font Awesome 6.x
- **JavaScript**: Vanilla JS with modern ES6+ features
- **Animations**: CSS3 animations and transitions
- **Responsive**: Mobile-first responsive design

### Machine Learning
- **Libraries**: scikit-learn 1.3.2, pandas, numpy, xgboost
- **Algorithms**: Random Forest, SVM, Neural Networks
- **Features**: URL structure analysis, domain reputation, content analysis
- **Web Scraping**: Playwright, BeautifulSoup4, Selenium
- **Report Generation**: pdfkit for PDF reports

## 🚀 Quick Start

For detailed setup instructions, see [SETUP.md](SETUP.md)

### Prerequisites
- Python 3.10 or higher
- Git (optional)
- Internet connection

### Installation
```bash
# Clone or navigate to project
cd phishnet

# Create virtual environment
python -m venv venv

# Activate virtual environment (Windows)
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install Playwright browsers
playwright install

# Run migrations
python manage.py migrate

# Start server
python manage.py runserver
```

### Access Application
Open your browser and go to: `http://127.0.0.1:8000/`

## 📁 Project Structure

```
PhishNet/
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
│   ├── profile.html               # User profile settings
│   ├── contact.html               # Contact form
│   ├── admin/                     # Admin templates
│   │   ├── base_site.html         # Admin base template
│   │   ├── index.html             # Admin index page
│   │   └── overview.html          # Admin overview dashboard
│   └── registration/              # Authentication templates
│       ├── login.html             # Login page
│       └── register.html          # Registration page
├── media/                        # User uploaded files
│   └── screenshots/              # Captured webpage screenshots
├── phishnet/                     # Project configuration
│   ├── settings.py               # Django settings
│   ├── urls.py                   # Main URL configuration
│   └── wsgi.py                   # WSGI configuration
├── manage.py                     # Django management script
├── requirements.txt              # Python dependencies
├── db.sqlite3                    # SQLite database
└── README.md                     # Project documentation
```

## 🗄️ Database Schema

### Models Overview

#### URLScan Model
```python
class URLScan(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    url = models.URLField(max_length=2000)
    is_phishing = models.BooleanField()
    scan_date = models.DateTimeField(auto_now_add=True)
    features = models.JSONField()
    confidence_score = models.FloatField()
    screenshot = models.ImageField(upload_to='screenshots/', null=True, blank=True)
```

#### Report Model
```python
class Report(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    url = models.URLField(max_length=2000)
    description = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    reported_date = models.DateTimeField(auto_now_add=True)
    reviewed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='reviewed_reports')
    review_notes = models.TextField(blank=True)
    review_date = models.DateTimeField(null=True, blank=True)
```

#### Contact Model
```python
class Contact(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    subject = models.CharField(max_length=200)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='unread')
    reply = models.TextField(blank=True)
    reply_date = models.DateTimeField(null=True, blank=True)
    replied_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='replied_contacts')
```

## 📋 Admin Features

- **Dashboard**: Overview of system statistics and recent activities
- **URL Management**: Review and manage scanned URLs
- **Report Management**: Process user-submitted phishing reports
- **Contact Management**: Respond to user inquiries
- **User Management**: Manage user accounts and permissions
- **Cyberpunk Theme**: Dark-mode admin interface with futuristic styling

## 🔒 Security Measures

- **CSRF Protection**: Enabled by default in Django
- **XSS Prevention**: Content Security Policy and template escaping
- **SQL Injection Protection**: Django ORM parameterized queries
- **Session Security**: Secure session cookies and management
- **Password Validation**: Strong password requirements

## 🎨 UI/UX Features

### Cyberpunk Theme
- **Dark Mode**: Eye-friendly dark interface with neon accents
- **Animated Elements**: Dynamic components with subtle animations
- **Responsive Design**: Mobile-first approach for all screen sizes
- **Interactive Components**: Real-time feedback on user actions
- **Accessibility**: High contrast and readable text throughout

## 📱 Mobile Responsiveness

The application is fully responsive and optimized for:
- Desktop computers
- Tablets
- Mobile phones

## 🚀 Future Enhancements

- **API Integration**: External threat intelligence integration
- **Browser Extensions**: Direct scanning from browsers
- **Enhanced ML Models**: Additional machine learning algorithms
- **Real-time Notifications**: Instant alerts for security threats
- **Expanded Reporting**: More detailed analysis reports

## 🚀 Installation & Setup

### Prerequisites
- Python 3.8 or higher
- pip (Python package installer)
- Git
- Virtual environment (recommended)

### Step-by-Step Installation

1. **Clone the Repository**
   ```bash
   git clone <repository-url>
   cd PhishNet
   ```

2. **Create Virtual Environment**
   ```bash
   python -m venv venv
   
   # On Windows
   venv\Scripts\activate
   
   # On macOS/Linux
   source venv/bin/activate
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Environment Configuration**
   Create a `.env` file in the project root:
   ```env
   SECRET_KEY=your-secret-key-here
   DEBUG=True
   DATABASE_URL=sqlite:///db.sqlite3
   ```

5. **Database Setup**
   ```bash
   python manage.py makemigrations
   python manage.py migrate
   python manage.py createsuperuser
   ```

6. **Collect Static Files**
   ```bash
   python manage.py collectstatic
   ```

7. **Run Development Server**
   ```bash
   python manage.py runserver
   ```

8. **Access the Application**
   Open your browser and navigate to `http://localhost:8000`

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|----------|
| `SECRET_KEY` | Django secret key | Required |
| `DEBUG` | Debug mode | `False` |
| `DATABASE_URL` | Database connection string | SQLite |
| `ALLOWED_HOSTS` | Allowed host names | `localhost,127.0.0.1` |
| `EMAIL_HOST` | SMTP server host | `localhost` |
| `EMAIL_PORT` | SMTP server port | `587` |
| `EMAIL_USE_TLS` | Use TLS for email | `True` |

### Security Settings

- **CSRF Protection**: Enabled by default
- **XSS Protection**: Content Security Policy headers
- **SQL Injection**: Django ORM protection
- **Session Security**: Secure session cookies
- **Password Validation**: Strong password requirements

## 🧪 Testing

### Running Tests
```bash
# Run all tests
python manage.py test

# Run specific app tests
python manage.py test core

# Run with coverage
coverage run --source='.' manage.py test
coverage report
```

### Test Coverage
- **Models**: Database model testing
- **Views**: HTTP response testing
- **Forms**: Form validation testing
- **Utils**: Utility function testing
- **Integration**: End-to-end testing

## 📊 Performance

### Optimization
- **Database Indexing**: Optimized database queries
- **Static File Compression**: Gzipped static files
- **Caching**: Redis-based caching (production)
- **CDN Integration**: Static file delivery
- **Lazy Loading**: Deferred content loading

### Monitoring
- **Error Tracking**: Comprehensive error logging
- **Performance Metrics**: Response time monitoring
- **User Analytics**: Usage pattern analysis
- **Security Monitoring**: Threat detection

## 🚀 Deployment

### Production Setup

1. **Environment Configuration**
   ```env
   DEBUG=False
   SECRET_KEY=production-secret-key
   DATABASE_URL=postgresql://user:pass@host:port/db
   ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com
   ```

2. **Database Migration**
   ```bash
   python manage.py migrate --settings=phishnet.settings.production
   ```

3. **Static Files**
   ```bash
   python manage.py collectstatic --settings=phishnet.settings.production
   ```

4. **Web Server Configuration**
   - **Nginx**: Reverse proxy configuration
   - **Gunicorn**: WSGI server setup
   - **SSL/TLS**: HTTPS certificate installation

### Docker Deployment

```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 8000

CMD ["gunicorn", "phishnet.wsgi:application", "--bind", "0.0.0.0:8000"]
```

## 🤝 Contributing

### Development Guidelines

1. **Code Style**: Follow PEP 8 standards
2. **Documentation**: Document all functions and classes
3. **Testing**: Write tests for new features
4. **Security**: Follow security best practices
5. **Performance**: Optimize for speed and efficiency

### Pull Request Process

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Update documentation
6. Submit a pull request

## 📝 API Documentation

### Endpoints

#### URL Scanning
```http
POST /api/scan/
Content-Type: application/json

{
    "url": "https://example.com"
}
```

#### Response
```json
{
    "is_phishing": false,
    "confidence_score": 0.95,
    "features": {
        "domain_age": 365,
        "ssl_certificate": true,
        "suspicious_keywords": 0
    },
    "scan_date": "2024-01-15T10:30:00Z"
}
```

## 🐛 Troubleshooting

### Common Issues

1. **Python Path Issues**
   - Ensure virtual environment is activated
   - Check Python installation path
   - Verify pip installation

2. **Database Errors**
   - Run migrations: `python manage.py migrate`
   - Check database permissions
   - Verify database URL

3. **Static Files Not Loading**
   - Run: `python manage.py collectstatic`
   - Check static file configuration
   - Verify file permissions

4. **Port Already in Use**
   - Use different port: `python manage.py runserver 8001`
   - Kill existing processes
   - Check for running services

### Debug Mode

Enable debug mode for development:
```python
# settings.py
DEBUG = True
ALLOWED_HOSTS = ['localhost', '127.0.0.1']
```

## 📞 Support

### Getting Help

- **Documentation**: Check this README and code comments
- **Issues**: Create GitHub issues for bugs
- **Discussions**: Use GitHub discussions for questions
- **Email**: Contact the development team

### Reporting Bugs

When reporting bugs, please include:
- Python version
- Django version
- Operating system
- Error messages
- Steps to reproduce

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Django Community**: For the excellent web framework
- **Bootstrap Team**: For the responsive CSS framework
- **Font Awesome**: For the comprehensive icon library
- **Security Researchers**: For phishing detection insights
- **Open Source Community**: For inspiration and contributions

## 🔮 Future Enhancements

### Planned Features
- **AI-Powered Detection**: Advanced machine learning models
- **Real-time Threat Intelligence**: Live threat feed integration
- **Mobile Application**: Native mobile app development
- **API Expansion**: Comprehensive REST API
- **Multi-language Support**: Internationalization
- **Advanced Analytics**: Detailed security analytics
- **Browser Extension**: Real-time browsing protection

### Roadmap

- **Q1 2024**: Enhanced ML algorithms
- **Q2 2024**: Mobile app development
- **Q3 2024**: API expansion
- **Q4 2024**: Enterprise features

---

**Built with ❤️ by the PhishNet Team**

*Protecting the digital realm, one URL at a time.*
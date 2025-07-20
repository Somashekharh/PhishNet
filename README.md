# PhishNet - AI-Powered Phishing Detection System

A comprehensive Django-based web application that uses machine learning to detect and analyze phishing URLs in real-time.

## 🚀 Features

- **AI-Powered Detection**: Uses RandomForest machine learning model for accurate phishing detection
- **Real-time URL Analysis**: Instant analysis of suspicious URLs with detailed reports
- **User Management**: Secure authentication and user profile management
- **Report Generation**: Generate detailed PDF reports of scan results
- **Admin Dashboard**: Comprehensive admin interface for managing reports and users
- **Modern UI**: Cyberpunk-themed responsive design

## 📁 Project Structure

```
PhishNet/
├── core/                   # Main Django application
│   ├── ml_model/          # Machine learning model files
│   ├── migrations/        # Database migrations
│   ├── templates/         # Template tags
│   ├── management/        # Custom management commands
│   └── ...               # Django app files
├── phishnet/             # Django project settings
├── templates/            # HTML templates
├── static/               # Static files (CSS, JS, images)
├── media/                # User uploads and generated files
├── docs/                 # Documentation files
├── scripts/              # Maintenance and utility scripts
├── tests/                # Test files
├── manage.py             # Django management script
├── requirements.txt      # Python dependencies
└── README.md            # This file
```

## 🛠️ Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd PhishNet
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run migrations**
   ```bash
   python manage.py migrate
   ```

5. **Create superuser (optional)**
   ```bash
   python manage.py createsuperuser
   ```

6. **Run the development server**
   ```bash
   python manage.py runserver
   ```

## 🎯 Usage

1. **Register/Login**: Create an account or login to access the system
2. **Scan URLs**: Enter suspicious URLs for AI-powered analysis
3. **View Results**: Get detailed analysis with confidence scores
4. **Generate Reports**: Create PDF reports of scan results
5. **Manage Profile**: Update account settings and security preferences

## 🤖 Machine Learning Model

- **Algorithm**: RandomForest Classifier
- **Features**: URL-based features including length, domain analysis, and security indicators
- **Accuracy**: High accuracy in detecting phishing URLs
- **Location**: `core/ml_model/model.pkl`

## 📚 Documentation

- **Setup Guide**: `docs/SETUP.md`
- **ML Improvements**: `docs/ML_Improvement_Report.md`
- **API Documentation**: Available in the admin interface

## 🧪 Testing

Run the test suite:
```bash
python tests/test_logout.py
```

## 🔧 Maintenance Scripts

Utility scripts for system maintenance:
- `scripts/complete_reset.py` - Reset the entire system
- `scripts/add_sample_data.py` - Add sample data for testing
- `scripts/clear_all_data.py` - Clear all user data
- `scripts/manual_url_management.py` - Manual URL management tools

## 🛡️ Security Features

- CSRF protection
- Secure authentication
- Input validation
- XSS protection
- SQL injection prevention

## 🌐 Technologies Used

- **Backend**: Django 5.0.2, Python 3.11
- **Frontend**: HTML5, CSS3, JavaScript, Bootstrap 5
- **Machine Learning**: scikit-learn, pandas, numpy
- **Database**: SQLite (development), PostgreSQL (production ready)
- **PDF Generation**: wkhtmltopdf
- **Security**: Django's built-in security features


## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📞 Support

For support and questions, please contact the development team or create an issue in the repository.

---

**PhishNet** - Defending against phishing attacks with AI-powered detection.

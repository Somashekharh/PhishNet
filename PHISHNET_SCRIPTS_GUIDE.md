# PhishNet - Cybersecurity Platform

## Overview
PhishNet is a Django-based cybersecurity platform that uses machine learning to detect phishing URLs. The platform features a cyberpunk-themed UI and provides real-time URL analysis with confidence scores.

## Project Structure
```
PhishNet/
├── core/                    # Main Django app
│   ├── ml_model/           # Machine learning models
│   │   ├── model.pkl       # Trained Random Forest model
│   │   ├── scaler.pkl      # Feature scaler
│   │   ├── predictor.py    # URL prediction logic
│   │   └── extract_features.py  # Feature extraction
│   ├── views.py            # Django views
│   ├── models.py           # Database models
│   └── url_analyzer.py     # URL analysis engine
├── templates/              # HTML templates
├── static/                 # CSS, JS, images
├── media/                  # User uploads and screenshots
├── phishnet/              # Django settings
└── manage.py              # Django management
```

## Key Features
- **ML-Powered Detection**: Random Forest classifier with 22 URL features
- **Real-time Analysis**: Instant phishing detection with confidence scores
- **Cyberpunk UI**: Modern, responsive interface with animations
- **URL Analysis**: Domain, SSL, content, and security analysis
- **Scan History**: Track and manage previous scans
- **Admin Dashboard**: Comprehensive admin interface
- **Report System**: User reporting and admin review system
- **Manual URL Management**: Override model predictions with manual entries

## Machine Learning Model
- **Algorithm**: Random Forest Classifier
- **Features**: 22 URL characteristics (length, domain analysis, suspicious patterns, etc.)
- **Performance**: 99.79% ROC-AUC score
- **Training**: Balanced dataset with class weights

## Available Scripts

### 1. `manual_url_management.py` ⭐ NEW
**Purpose**: Manually manage safe and unsafe URLs to override model predictions
**Usage**: `python manual_url_management.py`
**What it does**:
- Add individual safe/unsafe URLs with custom descriptions
- Bulk import 100+ known safe websites (Google, GitHub, Microsoft, etc.)
- Bulk import 100+ known phishing websites (fake domains)
- List, update, and delete manual URL entries
- View database statistics and clear cache
- Interactive menu system for easy management

**Features**:
- **Manual Override**: Force specific URLs as safe/unsafe regardless of model prediction
- **Bulk Import**: Add hundreds of known websites at once
- **Custom Descriptions**: Add notes explaining why URLs are marked safe/unsafe
- **Conflict Resolution**: Handle existing URLs with update prompts
- **Statistics**: View database composition and manual vs auto scans
- **Cache Management**: Clear Django cache to ensure fresh results

### 2. `complete_reset.py`
**Purpose**: Complete system reset and cleanup
**Usage**: `python complete_reset.py`
**What it does**:
- Clears Django cache
- Deletes all scan and report data
- Clears media files
- Provides step-by-step restart instructions

### 3. `clear_all_data.py`
**Purpose**: Clear cache and database data
**Usage**: `python clear_all_data.py`
**What it does**:
- Clears Django cache
- Deletes all URLScan records
- Deletes all Report records

### 4. `add_sample_data.py`
**Purpose**: Add sample URLs for testing/demo
**Usage**: `python add_sample_data.py`
**What it does**:
- Adds safe URLs (Google, RLS BCA, MIT)
- Adds phishing URLs (suspicious domains)
- Creates demo user if none exists

## Installation & Setup

### Prerequisites
- Python 3.7+
- Django 5.0.2
- scikit-learn
- Other dependencies in `requirements.txt`

### Setup Steps
1. **Clone/Download** the project
2. **Create virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
4. **Run migrations**:
   ```bash
   python manage.py migrate
   ```
5. **Create superuser**:
   ```bash
   python manage.py createsuperuser
   ```
6. **Start server**:
   ```bash
   python manage.py runserver
   ```

## Usage Guide

### For Users
1. **Register/Login** to the platform
2. **Scan URLs** using the scan form
3. **View Results** with confidence scores and analysis
4. **Check History** of previous scans
5. **Report Suspicious URLs** for admin review

### For Administrators
1. **Access Admin Dashboard** at `/dashboard/admin/`
2. **Review Reports** from users
3. **Monitor System Status** and statistics
4. **Manage Users** and scan data
5. **Use Manual URL Management** to override model predictions

### For Developers
1. **Model Training**: Use `ml_model/train_model.py` (if dataset available)
2. **Feature Engineering**: Modify `extract_features.py`
3. **UI Customization**: Edit templates in `templates/`
4. **API Integration**: Use `analyze_url` endpoint
5. **Manual URL Management**: Use `manual_url_management.py` for testing

## Manual URL Management

### When to Use Manual Management
- **Model Issues**: When the ML model gives incorrect predictions
- **Known Safe Sites**: Add legitimate websites that model flags as unsafe
- **Known Phishing**: Add confirmed phishing sites that model misses
- **Testing**: Create test datasets for model validation
- **Training Data**: Prepare datasets for model retraining

### How to Use the Script
```bash
# Run the interactive script
python manual_url_management.py

# Available options:
# 1. Add single safe URL
# 2. Add single unsafe URL  
# 3. Add bulk URLs (100+ safe + 100+ unsafe)
# 4. List manual URLs
# 5. Delete manual URL
# 6. Clear all manual URLs
# 7. Show database stats
# 8. Clear cache
# 9. Exit
```

### Manual URL Examples
**Safe URLs to Add**:
- `https://www.google.com` - Known legitimate search engine
- `https://www.github.com` - Trusted development platform
- `https://www.microsoft.com` - Official Microsoft website
- `https://www.apple.com` - Official Apple website

**Unsafe URLs to Add**:
- `http://fake-login-facebook.xyz` - Fake Facebook login
- `http://paypal-verify-account.xyz` - Fake PayPal verification
- `http://google-secure-verify.xyz` - Fake Google security page

### Manual Override Priority
1. **Manual entries** take priority over model predictions
2. **100% confidence** for manual entries
3. **Custom descriptions** explain the override reason
4. **Scan type** marked as 'manual' vs 'auto'

## URL Analysis Features

### Domain Analysis
- Domain length and structure
- Subdomain analysis
- TLD (Top Level Domain) checks
- IP address detection

### Security Analysis
- HTTPS/HTTP protocol
- SSL certificate validation
- Suspicious character detection
- Port number analysis

### Content Analysis
- Page title and meta description
- Login form detection
- External/internal link ratio
- Response time analysis

### ML Features
- URL length patterns
- Special character frequency
- Suspicious TLD detection
- Domain age analysis

## Confidence Score Explanation
- **Safe Website**: Model predicts URL is legitimate
- **Potential Phishing**: Model predicts URL is suspicious
- **Confidence Score**: Percentage confidence in the prediction
- **High Confidence**: >90% - Very certain about prediction
- **Medium Confidence**: 70-90% - Moderately certain
- **Low Confidence**: <70% - Less certain, manual review recommended
- **Manual Override**: 100% - User-defined safe/unsafe status

## Troubleshooting

### Common Issues
1. **Model Loading Errors**: Check if `model.pkl` and `scaler.pkl` exist
2. **Cache Issues**: Run `python complete_reset.py`
3. **Database Errors**: Run `python manage.py migrate`
4. **Permission Errors**: Check file permissions for media directory
5. **Incorrect Predictions**: Use `manual_url_management.py` to override

### Debug Commands
```bash
# Check model status
python -c "from core.ml_model.predictor import URLPredictor; p = URLPredictor(); print('Model loaded successfully')"

# Clear cache
python clear_all_data.py

# Add test data
python add_sample_data.py

# Complete reset
python complete_reset.py

# Manual URL management
python manual_url_management.py
```

### Model Prediction Issues
If the model gives incorrect predictions:
1. **Use Manual Management**: Add known safe/unsafe URLs manually
2. **Check Training Data**: Verify dataset labels and distribution
3. **Retrain Model**: Use balanced dataset with correct labels
4. **Feature Engineering**: Review feature extraction logic
5. **Model Validation**: Test with known URL examples

## API Endpoints

### Scan URL
- **URL**: `/scan/`
- **Method**: POST
- **Parameters**: `url` (string)
- **Response**: Scan results with analysis

### Analyze URL
- **URL**: `/api/analyze-url/`
- **Method**: POST
- **Parameters**: JSON with `url`
- **Response**: JSON analysis data

### Download Report
- **URL**: `/reports/download/<filename>/`
- **Method**: GET
- **Response**: PDF report file

## Security Features
- **CSRF Protection**: All forms protected
- **Authentication**: Login required for scans
- **Input Validation**: URL format validation
- **Rate Limiting**: Prevents abuse
- **Secure Headers**: HTTPS enforcement
- **Manual Override**: Admin control over predictions

## Performance Optimization
- **Caching**: 1-hour cache for scan results
- **Database Indexing**: Optimized queries
- **Async Processing**: Background URL analysis
- **CDN Ready**: Static files optimized
- **Manual Priority**: Manual entries bypass cache

## Contributing
1. Fork the repository
2. Create feature branch
3. Make changes
4. Test thoroughly
5. Submit pull request

## License
This project is licensed under the MIT License.

## Support
For issues and questions:
1. Check the troubleshooting section
2. Review the debug commands
3. Check Django logs for errors
4. Verify model files are present
5. Use manual URL management for testing

## Version History
- **v1.0**: Initial release with ML detection
- **v1.1**: Added confidence score improvements
- **v1.2**: Enhanced UI and admin features
- **v1.3**: Fixed model prediction issues and cache management
- **v1.4**: Added manual URL management system ⭐ NEW

---
**Last Updated**: June 2025
**Maintainer**: PhishNet Development Team 
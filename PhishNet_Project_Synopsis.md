# PhishNet: AI-Powered Cybersecurity URL Scanner and Reporting Platform

## 1. Project Overview
PhishNet is a full-stack web application designed to detect, analyze, and report phishing URLs using advanced machine learning techniques. The platform provides users with a modern, cyberpunk-themed interface to scan suspicious URLs, view detailed security reports, and manage their scan and report history. It is built with Django and integrates a custom-trained ML model for real-time threat analysis.

## 2. Key Features
### A. URL Scanning & Threat Detection
- **Scan Form:** Users can submit any URL for analysis via a stylish, animated scan form.
- **Scanning Animation:** A cyberpunk-themed, interactive animation overlays the screen during scanning, simulating a high-tech security protocol.
- **ML Integration:** The backend uses a pre-trained machine learning model (`model.pkl`) to extract features and predict the likelihood of phishing.
- **Progress Feedback:** Users see real-time progress, terminal-style logs, and a radar animation during the scan.

### B. Detailed Scan Reports
- **Result Dashboard:** After scanning, users receive a comprehensive report including:
  - Security score/confidence percentage
  - HTTPS and SSL certificate status
  - Domain and content analysis
  - External links and suspicious patterns
  - Downloadable PDF report (if available)
  - Website screenshot (if available)
- **Visual Indicators:** Results are color-coded and styled for quick risk assessment (e.g., green for safe, red for phishing).

### C. User Management
- **Authentication:** Users can register, log in, and log out securely.
- **Profile Page:** Users can view and manage their profile and see their scan/report history.

### D. Scan & Report History
- **Scan History:** Users can view a table of all URLs they have scanned, with timestamps and quick access to reports.
- **My Reports:** Users can view, review, and manage their submitted phishing reports.
- **Admin Dashboard:** Admins have access to a dashboard for reviewing and managing all reports and user activity.

### E. Theming & UX
- **Cyberpunk Theme:** The entire UI is styled with a dark, neon cyberpunk aesthetic, including glowing effects, animated elements, and responsive layouts.
- **Responsiveness:** All pages are optimized for desktop and laptop screens, with media queries for smaller devices.
- **Accessibility:** High-contrast colors and clear typography improve readability.

## 3. Technical Architecture
### A. Backend (Django)
- **App Structure:**
  - `core/`: Main app with models, views, forms, ML logic, and admin customizations.
  - `phishnet/`: Django project settings, URLs, and WSGI/ASGI entry points.
- **Models:** User, Scan, Report, and related models for storing scan data, user actions, and report statuses.
- **ML Model Integration:**
  - `ml_model/` contains the trained model (`model.pkl`), scaler, feature extraction scripts, and metadata.
  - `predictor.py` and `extract_features.py` handle feature extraction and prediction.
- **Management Commands:** Custom Django management commands for creating test data and managing the database.

### B. Frontend (Templates & Static)
- **Templates:** Modular HTML templates for each page: scan form, scan result, dashboard, history, reports, admin, etc.
- **Static Files:** Custom CSS, JavaScript, and images for animations and UI effects. FontAwesome icons for visual cues.

### C. Security
- **CSRF Protection:** All forms use Django's CSRF protection.
- **Input Validation:** URL fields are validated both client-side and server-side.
- **Session Management:** Secure user sessions and authentication.

### D. Reporting & Admin
- **Admin Interface:** Django admin is customized for managing users, reports, and scan data.
- **PDF Reports:** Users can download detailed PDF reports of scan results.

## 4. Machine Learning Pipeline
- **Feature Extraction:** Extracts features from URLs, domain info, SSL status, content patterns, etc.
- **Model Training:** Model is trained offline and saved as `model.pkl` with associated scaler and metadata.
- **Prediction:** On scan, features are extracted and passed to the model for real-time prediction.
- **Feature Importance:** `feature_importance.csv` provides insight into which features are most predictive.

## 5. User Flow
1. User visits the landing page.
2. Registers or logs in.
3. Navigates to the scan form and submits a URL.
4. Sees a scanning animation and progress feedback.
5. Receives a detailed scan report with risk assessment.
6. Can view scan/report history, download reports, or submit new scans.
7. Admins can review all reports and manage the system.

## 6. Notable Files & Directories
- `core/ml_model/`: ML model, feature extraction, and prediction scripts.
- `core/models.py`: Django models for users, scans, and reports.
- `core/views.py` & `core/views_profile.py`: Main and profile-related views.
- `core/forms.py`: Django forms for user input.
- `core/report_generator.py`: Generates downloadable reports.
- `templates/`: All HTML templates for user and admin interfaces.
- `static/`: CSS, JS, and image assets for the cyberpunk theme.
- `phishnet/settings.py`: Django settings, including static/media config and installed apps.
- `manage.py`: Django management script.

## 7. Setup & Deployment
- **Requirements:** Python 3.x, Django, scikit-learn, and other dependencies in `requirements.txt`.
- **Setup:** Install dependencies, run migrations, collect static files, and start the server.
- **Playwright:** Used for browser automation (e.g., screenshots).
- **Database:** Uses SQLite by default; can be configured for PostgreSQL or MySQL.

## 8. Extensibility & Customization
- Easily extendable for new ML models, additional security checks, or new UI themes.
- Modular codebase allows for adding new features (e.g., email alerts, API endpoints, advanced analytics).

## 9. Security & Best Practices
- Follows Django security best practices (CSRF, XSS, session management).
- Input validation and error handling throughout.
- Admin controls for managing users and reports.

## 10. Documentation
- **README.md:** Detailed setup, usage, and contribution instructions.
- **SETUP.md:** Step-by-step environment and deployment guide.
- **In-code comments** for clarity and maintainability.

## Conclusion
PhishNet is a robust, visually engaging, and technically advanced platform for phishing detection and reporting. It combines the power of machine learning with a user-friendly, cyberpunk-inspired interface, making it suitable for both end-users and cybersecurity professionals. 
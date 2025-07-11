from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.utils import timezone
import joblib
import os
from django.contrib.auth.models import User
from django.conf import settings
import pandas as pd
from django.core.cache import cache
import hashlib
from django.http import JsonResponse, FileResponse
import json
import numpy as np
import validators

from .forms import UserRegistrationForm, URLScanForm, ReportForm, ContactForm
from .models import URLScan, Report, Contact
from .ml_model.predictor import URLPredictor
from .url_analyzer import URLAnalyzer, domain_exists

# Load the ML model and scaler
model_path = os.path.join(os.path.dirname(__file__), 'ml_model', 'model.pkl')
scaler_path = os.path.join(os.path.dirname(__file__), 'ml_model', 'scaler.pkl')
feature_importance_path = os.path.join(os.path.dirname(__file__), 'ml_model', 'feature_importance.csv')

try:
    print(f"Attempting to load model from {model_path}")
    model = joblib.load(model_path)
    print(f"Model loaded successfully, type: {type(model)}")
    
    print(f"Attempting to load scaler from {scaler_path}")
    scaler = joblib.load(scaler_path)
    print(f"Scaler loaded successfully, type: {type(scaler)}")
    
    feature_importance_df = pd.read_csv(feature_importance_path) if os.path.exists(feature_importance_path) else None
    print(f"Feature importance loaded: {feature_importance_df is not None}")
except Exception as e:
    print(f"Error loading model or scaler: {str(e)}")
    print(f"Model path exists: {os.path.exists(model_path)}")
    print(f"Scaler path exists: {os.path.exists(scaler_path)}")
    model = None
    scaler = None
    feature_importance_df = None

# Initialize URL analyzer and predictor
url_analyzer = URLAnalyzer()
url_predictor = URLPredictor()

def landing_page(request):
    """
    Landing page view - shows landing page for non-authenticated users,
    redirects to home for authenticated users
    """
    if request.user.is_authenticated:
        return redirect('home')
    return render(request, 'landing.html')

@login_required
def home(request):
    """
    Home page view for authenticated users
    Shows welcome message and main features
    """
    return render(request, 'home.html')

@login_required
def dashboard(request):
    """
    Dashboard view for authenticated users
    Shows statistics and recent activity
    """
    user_scans = URLScan.objects.filter(user=request.user)
    user_reports = Report.objects.filter(user=request.user)
    
    # Get statistics
    total_scans = user_scans.count()
    phishing_detected = user_scans.filter(is_phishing=True).count()
    safe_sites = user_scans.filter(is_phishing=False).count()
    pending_reports = user_reports.filter(status='pending').count()
    
    # Get recent activity
    recent_scans = user_scans.order_by('-scan_date')[:5]
    recent_reports = user_reports.order_by('-reported_date')[:5]
    
    context = {
        'total_scans': total_scans,
        'phishing_detected': phishing_detected,
        'safe_sites': safe_sites,
        'pending_reports': pending_reports,
        'recent_scans': recent_scans,
        'recent_reports': recent_reports,
    }
    return render(request, 'dashboard.html', context)

def contact(request):
    if request.method == 'POST':
        form = ContactForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Your message has been sent successfully!')
            return redirect('contact')
    else:
        form = ContactForm()
    return render(request, 'contact.html', {'form': form})

def register(request):
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Registration successful! Please login.')
            return redirect('login')
    else:
        form = UserRegistrationForm()
    return render(request, 'registration/register.html', {'form': form})

def clean_for_cache(obj, depth=0):
    """Clean objects for caching to prevent recursion errors"""
    if depth > 5:  # Lower maximum depth to prevent recursion issues
        return str(obj)
    
    try:
        if isinstance(obj, (str, int, float, bool, type(None))):
            return obj
        elif isinstance(obj, (list, tuple)):
            return [clean_for_cache(item, depth + 1) for item in obj]
        elif isinstance(obj, dict):
            # Handle all dictionaries properly, including nested ones
            result = {}
            for k, v in obj.items():
                if not callable(v) and not k.startswith('_'):
                    result[str(k)] = clean_for_cache(v, depth + 1)
            return result
        else:
            # Convert any other objects to string
            return str(obj)
    except Exception as e:
        print(f"Error in clean_for_cache: {str(e)}")
        return str(obj)

@login_required
def scan_url(request):
    if request.method == 'POST':
        form = URLScanForm(request.POST)
        if form.is_valid():
            url = form.cleaned_data['url']
            include_screenshot = form.cleaned_data.get('include_screenshot', False)
            # Check if domain exists before proceeding
            if not domain_exists(url):
                messages.error(request, 'The domain does not exist or is unreachable. Please check the URL and try again.')
                return render(request, 'scan_form.html', {'form': form, 'error_details': 'Domain does not exist.'})
            force_rescan = request.POST.get('force_rescan') == 'true'
            
            try:
                # Always clear cache if force rescan
                cache_key = f'url_scan_{hashlib.md5(url.encode()).hexdigest()}_screenshot_{int(include_screenshot)}'
                if force_rescan:
                    cache.delete(cache_key)
                    messages.info(request, 'Performing fresh scan as requested.')
                
                # Try to get from cache
                cached_result = None
                if not force_rescan:
                    try:
                        cached_result = cache.get(cache_key)
                    except Exception as cache_error:
                        print(f"Cache retrieval error: {str(cache_error)}")
                        cached_result = None
                
                if cached_result and not force_rescan:
                    print("Using cached result")
                    cached_result['from_cache'] = True
                    
                    # For cached results, we still need to perform URL analysis to get fresh report
                    try:
                        print("Performing URL analysis for cached result...")
                        original_url = url  # This is after adding https:// if missing
                        url_analysis, report_path = url_analyzer.analyze_url(url, original_url=original_url, include_screenshot=include_screenshot)
                        print(f"URL analysis completed for cached result: {url_analysis}")
                        if url_analysis and isinstance(url_analysis, dict):
                            screenshot_path = url_analysis.get('screenshot_path')
                            if screenshot_path:
                                screenshot_path = screenshot_path.replace('\\', '/')
                                url_analysis['screenshot_path'] = screenshot_path
                                print(f"Screenshot path: {screenshot_path}")
                    except Exception as e:
                        print(f"URL analysis error for cached result: {str(e)}")
                        url_analysis = None
                        report_path = None
                    
                    # Update cached result with fresh analysis and report
                    context = {
                        'url': original_url,
                        'is_phishing': cached_result['is_phishing'],
                        'confidence': cached_result['confidence'],
                        'analysis': url_analysis,
                        'report_path': report_path,
                        'from_cache': True
                    }
                    
                    print(f"DEBUG CACHED: URL in context: {original_url}")
                    print(f"DEBUG CACHED: Cached result URL: {cached_result.get('url', 'Not found')}")
                    
                    messages.info(request, 'Retrieved from cache. Use the "Rescan" button for a fresh analysis.')
                    
                    # Save to database even for cached results
                    try:
                        URLScan.objects.create(
                            user=request.user,
                            url=original_url,
                            is_phishing=cached_result['is_phishing'],
                            confidence_score=cached_result['confidence'] / 10,  # Convert back to 0-1 scale
                            scan_date=timezone.now()
                        )
                        print(f"Saved cached scan result to database for {original_url}")
                    except Exception as db_error:
                        print(f"Database save error for cached result: {str(db_error)}")
                else:
                    # Always reload model and scaler to avoid stale files
                    url_predictor.load_model()
                    # Get prediction
                    try:
                        prediction, confidence = url_predictor.predict(url)
                        # Use confidence directly from predictor - no recalculation needed
                    except Exception as e:
                        print(f"Error making prediction: {str(e)}")
                        prediction = None
                        confidence = 0
                    
                    # Debug print
                    print(f"DEBUG: Scan result for {url} -> is_phishing={prediction}, confidence={confidence*100:.2f}%")

                    if prediction is None:
                        messages.error(request, 'Could not analyze this URL. Please try a different one.')
                        return render(request, 'scan_form.html', {
                            'form': form,
                            'error_details': 'Failed to analyze the URL. The URL might be invalid or inaccessible.'
                        })
                    
                    # Get URL analysis
                    try:
                        print("Starting URL analysis...")
                        original_url = url  # This is after adding https:// if missing
                        url_analysis, report_path = url_analyzer.analyze_url(url, original_url=original_url, include_screenshot=include_screenshot)
                        print(f"URL analysis completed: {url_analysis}")
                        print(f"Report path returned: {report_path}")
                        screenshot_error = None
                        if not include_screenshot and url_analysis and isinstance(url_analysis, dict):
                            url_analysis['screenshot_path'] = None
                        if include_screenshot and (not url_analysis or not url_analysis.get('screenshot_path')):
                            screenshot_error = 'Screenshot could not be captured. This may be due to Playwright not being installed, browser issues, or network problems.'
                        if url_analysis and isinstance(url_analysis, dict):
                            screenshot_path = url_analysis.get('screenshot_path')
                            if screenshot_path:
                                screenshot_path = screenshot_path.replace('\\', '/')
                                url_analysis['screenshot_path'] = screenshot_path
                                print(f"Screenshot path: {screenshot_path}")
                        else:
                            screenshot_path = None
                    except Exception as e:
                        print(f"URL analysis error: {str(e)}")
                        url_analysis = None
                        report_path = None
                    
                    # Create context
                    if prediction is not None:
                        if prediction:  # is_phishing == True
                            display_confidence = confidence * 10
                        else:
                            display_confidence = (1 - confidence) * 10
                    else:
                        display_confidence = 0

                    context = {
                        'url': original_url,
                        'is_phishing': prediction,
                        'confidence': display_confidence,  # Now out of 10
                        'analysis': url_analysis,
                        'report_path': report_path,
                        'from_cache': False,
                        'screenshot_error': screenshot_error
                    }
                    
                    print(f"Context created - report_path: {report_path}")
                    print(f"Context keys: {list(context.keys())}")
                    print(f"DEBUG: URL in context: {original_url}")
                    print(f"DEBUG: Original URL from form: {url}")
                    
                    # Try to cache the result
                    try:
                        cache_data = clean_for_cache(context)
                        cache.set(cache_key, cache_data, timeout=3600)
                    except Exception as cache_error:
                        print(f"Cache storage error: {str(cache_error)}")
                        pass
                    
                    # Save to database
                    try:
                        scan_record = URLScan.objects.create(
                            user=request.user,
                            url=original_url,
                            is_phishing=prediction,
                            confidence_score=confidence,
                            scan_date=timezone.now()
                        )
                        print(f"Saved new scan result to database: ID={scan_record.id}, URL={original_url}, Phishing={prediction}")
                    except Exception as db_error:
                        print(f"Database save error for new scan: {str(db_error)}")
                        # Continue without failing the scan
                
                return render(request, 'scan_result.html', context)
                
            except Exception as e:
                print(f"Error during URL analysis: {str(e)}")
                messages.error(request, 'An error occurred while analyzing the URL.')
                return render(request, 'scan_form.html', {
                    'form': form,
                    'error_details': str(e)
                })
    else:
        form = URLScanForm()
    
    return render(request, 'scan_form.html', {'form': form})

@login_required
def scan_history(request):
    scans = URLScan.objects.filter(user=request.user)
    
    # Count statistics
    safe_count = scans.filter(is_phishing=False).count()
    phishing_count = scans.filter(is_phishing=True).count()
    
    context = {
        'scans': scans,
        'safe_count': safe_count,
        'phishing_count': phishing_count
    }
    
    return render(request, 'scan_history.html', context)

@login_required
def delete_scan(request, scan_id):
    scan = get_object_or_404(URLScan, id=scan_id, user=request.user)
    scan.delete()
    messages.success(request, 'Scan deleted successfully.')
    return redirect('scan_history')

@login_required
def report_url(request):
    if request.method == 'POST':
        form = ReportForm(request.POST)
        if form.is_valid():
            report = form.save(commit=False)
            report.user = request.user
            report.save()
            messages.success(request, 'URL reported successfully.')
            return redirect('my_reports')
    else:
        form = ReportForm()
    return render(request, 'report_form.html', {'form': form})

@login_required
def my_reports(request):
    reports = Report.objects.filter(user=request.user)
    
    # Count statistics
    pending_count = reports.filter(status='pending').count()
    verified_count = reports.filter(status='verified').count()
    rejected_count = reports.filter(status='rejected').count()
    
    context = {
        'reports': reports,
        'pending_count': pending_count,
        'verified_count': verified_count,
        'rejected_count': rejected_count
    }
    
    return render(request, 'report_list.html', context)

def is_admin(user):
    return user.is_staff

@login_required
@user_passes_test(is_admin)
def admin_dashboard(request):
    # Clear any existing cache disable flag to reset the system
    if 'disable_cache' in request.session:
        del request.session['disable_cache']
    
    # Get statistics
    total_users = User.objects.count()
    total_scans = URLScan.objects.count()
    reports_by_status = {
        'pending': Report.objects.filter(status='pending').count(),
        'verified': Report.objects.filter(status='verified').count(),
        'rejected': Report.objects.filter(status='rejected').count()
    }
    
    # Get recent reports for display
    recent_reports = Report.objects.select_related('user').order_by('-reported_date')[:10]
    
    # Get system status
    system_status = {
        'ml_model': model is not None and scaler is not None,
        'database': True,  # If we can query the database, this is True
        'api': True,  # Assuming API services are working
        'cache': 'CACHES' in settings.__dict__
    }
    
    context = {
        'total_users': total_users,
        'total_scans': total_scans,
        'reports_by_status': reports_by_status,
        'recent_reports': recent_reports,
        'system_status': system_status
    }
    
    return render(request, 'admin_dashboard.html', context)

@login_required
@user_passes_test(is_admin)
def review_report(request, report_id):
    report = get_object_or_404(Report, id=report_id)
    
    if request.method == 'POST':
        new_status = request.POST.get('status')
        if new_status in ['verified', 'rejected']:
            report.status = new_status
            report.reviewed_by = request.user
            report.reviewed_date = timezone.now()
            report.save()
            messages.success(request, f'Report marked as {new_status}.')
        return redirect('admin_dashboard')
    
    return render(request, 'review_report.html', {'report': report})

@login_required
def analyze_url(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            url = data.get('url')
            
            if not url:
                return JsonResponse({'error': 'URL is required'}, status=400)
            
            # Validate URL format
            if not validators.url(url):
                return JsonResponse({'error': 'Invalid URL format'}, status=400)
                
            analyzer = URLAnalyzer()
            analysis_results, report_path = analyzer.analyze_url(url)
            
            response_data = {
                'analysis': analysis_results,
                'report_path': report_path
            }
            
            return JsonResponse(response_data)
            
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON data'}, status=400)
        except Exception as e:
            print(f"Error in analyze_url: {str(e)}")
            return JsonResponse({'error': f'Analysis failed: {str(e)}'}, status=500)
            
    return JsonResponse({'error': 'Method not allowed'}, status=405)

def download_report(request, filename):
    """Download a generated report (PDF or HTML)."""
    try:
        file_path = os.path.join(settings.MEDIA_ROOT, 'reports', filename)
        if os.path.exists(file_path):
            # Determine content type based on file extension
            if filename.endswith('.pdf'):
                content_type = 'application/pdf'
                disposition = f'attachment; filename="{filename}"'
            elif filename.endswith('.html'):
                content_type = 'text/html'
                disposition = f'inline; filename="{filename}"'
            else:
                content_type = 'application/octet-stream'
                disposition = f'attachment; filename="{filename}"'
            
            response = FileResponse(
                open(file_path, 'rb'),
                content_type=content_type
            )
            response['Content-Disposition'] = disposition
            return response
        else:
            return JsonResponse({'error': 'Report not found'}, status=404)
    except Exception as e:
        print(f"Error downloading report: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

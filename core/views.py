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

from .forms import UserRegistrationForm, URLScanForm, ReportForm, ContactForm
from .models import URLScan, Report, Contact
from .ml_model.predictor import URLPredictor
from .url_analyzer import URLAnalyzer

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
            force_rescan = request.POST.get('force_rescan') == 'true'
            
            try:
                # Always clear cache if force rescan
                cache_key = f'url_scan_{hashlib.md5(url.encode()).hexdigest()}'
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
                    context = cached_result
                    messages.info(request, 'Retrieved from cache. Use the "Rescan" button for a fresh analysis.')
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
                        url_analysis, report_path = url_analyzer.analyze_url(url)
                        print(f"URL analysis completed: {url_analysis}")
                        if url_analysis and isinstance(url_analysis, dict):
                            screenshot_path = url_analysis.get('screenshot_path')
                            if screenshot_path:
                                screenshot_path = screenshot_path.replace('\\', '/')
                                url_analysis['screenshot_path'] = screenshot_path
                                print(f"Screenshot path: {screenshot_path}")
                    except Exception as e:
                        print(f"URL analysis error: {str(e)}")
                        url_analysis = None
                    
                    # Create context
                    context = {
                        'url': url,
                        'is_phishing': prediction,
                        'confidence': confidence * 100,
                        'analysis': url_analysis,
                        'report_path': report_path,
                        'from_cache': False
                    }
                    
                    # Try to cache the result
                    try:
                        cache_data = clean_for_cache(context)
                        cache.set(cache_key, cache_data, timeout=3600)
                    except Exception as cache_error:
                        print(f"Cache storage error: {str(cache_error)}")
                        pass
                    
                    # Save to database
                    URLScan.objects.create(
                        user=request.user,
                        url=url,
                        is_phishing=prediction,
                        confidence_score=confidence,
                        scan_date=timezone.now()
                    )
                
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

def analyze_url(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            url = data.get('url')
            
            if not url:
                return JsonResponse({'error': 'URL is required'}, status=400)
                
            analyzer = URLAnalyzer()
            analysis_results, report_path = analyzer.analyze_url(url)
            
            response_data = {
                'analysis': analysis_results,
                'report_path': report_path
            }
            
            return JsonResponse(response_data)
            
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
            
    return JsonResponse({'error': 'Method not allowed'}, status=405)

def download_report(request, filename):
    """Download a generated PDF report."""
    try:
        file_path = os.path.join(settings.MEDIA_ROOT, 'reports', filename)
        if os.path.exists(file_path):
            response = FileResponse(
                open(file_path, 'rb'),
                content_type='application/pdf'
            )
            response['Content-Disposition'] = f'attachment; filename="{filename}"'
            return response
        else:
            return JsonResponse({'error': 'Report not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

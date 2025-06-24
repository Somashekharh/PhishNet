from django.urls import path
from django.contrib.auth import views as auth_views
from . import views
from . import views_profile

urlpatterns = [
    # Landing and Authentication URLs
    path('', views.landing_page, name='landing'),
    path('home/', views.home, name='home'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('contact/', views.contact, name='contact'),
    path('register/', views.register, name='register'),
    path('login/', auth_views.LoginView.as_view(template_name='registration/login.html'), name='login'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    
    # Profile URLs
    path('profile/', views_profile.profile, name='profile'),
    path('profile/security/', views_profile.profile_security, name='profile_security'),
    path('profile/delete/', views_profile.profile_delete, name='profile_delete'),
    
    # Scan URLs
    path('scan/', views.scan_url, name='scan'),
    path('scan/history/', views.scan_history, name='scan_history'),
    path('scan/<int:scan_id>/delete/', views.delete_scan, name='delete_scan'),
    
    # Report URLs
    path('report/', views.report_url, name='report'),
    path('reports/', views.my_reports, name='my_reports'),
    path('reports/download/<str:filename>/', views.download_report, name='download_report'),
    path('api/analyze-url/', views.analyze_url, name='analyze_url'),
    
    # Admin URLs
    path('dashboard/admin/', views.admin_dashboard, name='admin_dashboard'),
    path('dashboard/admin/report/<int:report_id>/review/', views.review_report, name='review_report'),
]
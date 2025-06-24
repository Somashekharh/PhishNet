from django.contrib import admin
from django.contrib.admin import AdminSite
from django.contrib.auth.models import User
from django.contrib.auth.admin import UserAdmin
from django.utils.html import format_html
from django.core.mail import send_mail, EmailMultiAlternatives
from django.utils import timezone
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.urls import path
from django.shortcuts import redirect, render
from django.db.models import Count
from .models import URLScan, Report, Contact

class PhishNetAdminSite(AdminSite):
    site_header = 'PhishNet Security Admin'
    site_title = 'PhishNet Admin'
    index_title = 'Security Operations Center'
    site_url = '/'
    
    def get_app_list(self, request, app_label=None):
        app_list = super().get_app_list(request)
        app_list.sort(key=lambda x: x['name'].lower())
        return app_list
    
    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path('dashboard/', self.admin_dashboard_redirect, name='admin_dashboard_redirect'),
            path('', self.admin_overview, name='admin_overview'),
        ]
        return custom_urls + urls
    
    def admin_dashboard_redirect(self, request):
        return redirect('/dashboard/admin/')
        
    def admin_overview(self, request):
        """Custom admin dashboard with summary statistics"""
        context = {
            'title': 'PhishNet Admin Dashboard',
            'user_count': User.objects.count(),
            'scan_count': URLScan.objects.count(),
            'phishing_count': URLScan.objects.filter(is_phishing=True).count(),
            'safe_count': URLScan.objects.filter(is_phishing=False).count(),
            'pending_reports': Report.objects.filter(status='pending').count(),
            'recent_scans': URLScan.objects.all().order_by('-scan_date')[:5],
            'recent_reports': Report.objects.all().order_by('-reported_date')[:5],
            'unread_contacts': Contact.objects.filter(status='new').count(),
            'has_permission': True,
            'is_nav_sidebar_enabled': True,
            'available_apps': self.get_app_list(request),
        }
        return render(request, 'admin/overview.html', context)

admin_site = PhishNetAdminSite(name='phishnet_admin')

class CustomUserAdmin(UserAdmin):
    list_display = ('username', 'email', 'first_name', 'last_name', 'is_staff', 'is_active', 'date_joined')
    list_filter = ('is_staff', 'is_active', 'date_joined')
    search_fields = ('username', 'email', 'first_name', 'last_name')
    ordering = ('-date_joined',)
    
    fieldsets = (
        ('User Information', {'fields': ('username', 'email', 'password')}),
        ('Personal Info', {'fields': ('first_name', 'last_name')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important Dates', {'fields': ('last_login', 'date_joined')}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'password1', 'password2', 'is_staff'),
        }),
    )
    
    def get_form(self, request, obj=None, **kwargs):
        form = super().get_form(request, obj, **kwargs)
        is_superuser = request.user.is_superuser
        if not is_superuser:
            form.base_fields['is_superuser'].disabled = True
        return form

class URLScanAdmin(admin.ModelAdmin):
    list_display = ('url_display', 'user', 'scan_result', 'confidence_display', 'scan_date')
    list_filter = ('is_phishing', 'scan_date')
    search_fields = ('url', 'user__username', 'user__email')
    ordering = ('-scan_date',)
    readonly_fields = ('scan_date', 'features_display')
    date_hierarchy = 'scan_date'
    list_per_page = 20

    def url_display(self, obj):
        return format_html('<a href="{}" target="_blank" title="{}">{}</a>', 
                         obj.url, 
                         obj.url,
                         obj.url[:50] + '...' if len(obj.url) > 50 else obj.url)
    url_display.short_description = 'URL'

    def scan_result(self, obj):
        if obj.is_phishing:
            return format_html('<span style="color: #FF3A33; font-weight: bold;">⚠️ Phishing</span>')
        return format_html('<span style="color: #33FF57; font-weight: bold;">✓ Safe</span>')
    scan_result.short_description = 'Result'
    
    def confidence_display(self, obj):
        if obj.confidence_score is None:
            return 'N/A'
        
        confidence = int(obj.confidence_score * 100)
        color = '#33FF57' if not obj.is_phishing else '#FF3A33'
        
        return format_html(
            '<div style="width:100px; background-color: #333; border-radius: 4px; padding: 2px;">'
            '<div style="width:{}%; background-color: {}; height: 18px; border-radius: 3px; text-align: center; color: #000;">'
            '{}%</div></div>', 
            confidence, color, confidence
        )
    confidence_display.short_description = 'Confidence'
    
    def features_display(self, obj):
        if not obj.features:
            return 'No feature data available'
            
        html = '<table style="width:100%; border-collapse: collapse;">'
        html += '<tr><th style="text-align:left; padding:8px; border-bottom:1px solid #444;">Feature</th>'
        html += '<th style="text-align:left; padding:8px; border-bottom:1px solid #444;">Value</th></tr>'
        
        if isinstance(obj.features, dict):
            for key, value in obj.features.items():
                html += f'<tr><td style="padding:8px; border-bottom:1px solid #333;">{key}</td>'
                html += f'<td style="padding:8px; border-bottom:1px solid #333;">{value}</td></tr>'
        
        html += '</table>'
        return format_html(html)
    features_display.short_description = 'Feature Details'

    fieldsets = [
        ('Scan Information', {
            'fields': ('url', 'user', 'is_phishing', 'confidence_score', 'scan_date')
        }),
        ('Technical Details', {
            'fields': ('features_display',),
            'classes': ('collapse',)
        }),
    ]

class ReportAdmin(admin.ModelAdmin):
    list_display = ('url_display', 'user', 'status_display', 'reported_date', 'review_status')
    list_filter = ('status', 'reported_date')
    search_fields = ('url', 'user__username', 'user__email', 'description')
    ordering = ('-reported_date',)
    actions = ['mark_as_verified', 'mark_as_rejected']
    date_hierarchy = 'reported_date'
    list_per_page = 20

    def url_display(self, obj):
        return format_html('<a href="{}" target="_blank" title="{}">{}</a>', 
                         obj.url, 
                         obj.url,
                         obj.url[:50] + '...' if len(obj.url) > 50 else obj.url)
    url_display.short_description = 'URL'

    def status_display(self, obj):
        colors = {
            'pending': '#FFA500',
            'verified': '#FF3A33',
            'rejected': '#33FF57'
        }
        icons = {
            'pending': '⏳',
            'verified': '⚠️',
            'rejected': '✓'
        }
        return format_html('<span style="color: {}; font-weight: bold;">{} {}</span>',
                         colors.get(obj.status, 'black'),
                         icons.get(obj.status, ''),
                         obj.status.title())
    status_display.short_description = 'Status'
    
    def review_status(self, obj):
        if obj.reviewed_by:
            return format_html('Reviewed by {} on {}', 
                             obj.reviewed_by.username,
                             obj.reviewed_date.strftime('%Y-%m-%d %H:%M'))
        return 'Pending Review'
    review_status.short_description = 'Review Status'
    
    readonly_fields = ('reported_date', 'review_status')
    
    fieldsets = [
        ('Report Details', {
            'fields': ('url', 'user', 'description', 'status', 'reported_date')
        }),
        ('Review Information', {
            'fields': ('reviewed_by', 'reviewed_date', 'review_status')
        }),
    ]

    def mark_as_verified(self, request, queryset):
        updated = queryset.update(status='verified', reviewed_by=request.user, reviewed_date=timezone.now())
        self.message_user(request, f'{updated} reports marked as verified phishing.')
    mark_as_verified.short_description = "Mark as Phishing"

    def mark_as_rejected(self, request, queryset):
        updated = queryset.update(status='rejected', reviewed_by=request.user, reviewed_date=timezone.now())
        self.message_user(request, f'{updated} reports marked as safe.')
    mark_as_rejected.short_description = "Mark as Safe"

class ContactAdmin(admin.ModelAdmin):
    list_display = ('name', 'email', 'subject', 'status_display', 'created_at', 'has_reply')
    list_filter = ('status', 'created_at')
    search_fields = ('name', 'email', 'subject', 'message', 'reply')
    ordering = ('-created_at',)
    actions = ['mark_as_read']
    readonly_fields = ('created_at', 'replied_at', 'replied_by')
    date_hierarchy = 'created_at'
    list_per_page = 20

    def has_reply(self, obj):
        return bool(obj.reply)
    has_reply.boolean = True
    has_reply.short_description = 'Replied'

    def status_display(self, obj):
        colors = {
            'new': '#00D4FF',
            'read': '#FFA500',
            'responded': '#33FF57'
        }
        icons = {
            'new': '🔔',
            'read': '👁️',
            'responded': '✉️'
        }
        return format_html('<span style="color: {}; font-weight: bold;">{} {}</span>',
                         colors.get(obj.status, 'black'),
                         icons.get(obj.status, ''),
                         obj.status.title())
    status_display.short_description = 'Status'

    fieldsets = [
        ('Contact Information', {
            'fields': ('name', 'email', 'created_at')
        }),
        ('Message', {
            'fields': ('subject', 'message', 'status')
        }),
        ('Reply', {
            'fields': ('reply', 'replied_at', 'replied_by'),
            'description': 'Compose your reply to the contact message here. The reply will be sent via email.'
        }),
    ]

    def save_model(self, request, obj, form, change):
        if 'reply' in form.changed_data:
            # Update reply metadata
            obj.replied_at = timezone.now()
            obj.replied_by = request.user
            obj.status = 'responded'
            
            # Prepare email content
            context = {
                'name': obj.name,
                'message': obj.message,
                'reply': obj.reply,
                'subject': obj.subject,
                'admin_name': request.user.get_full_name() or request.user.username,
                'site_name': 'PhishNet'
            }
            
            # Render email templates
            html_content = render_to_string('emails/contact_reply.html', context)
            text_content = strip_tags(html_content)
            
            # Create email message
            email = EmailMultiAlternatives(
                subject=f'Re: {obj.subject}',
                body=text_content,
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[obj.email],
                reply_to=[settings.DEFAULT_FROM_EMAIL]
            )
            
            # Attach HTML version
            email.attach_alternative(html_content, "text/html")
            
            # Send email
            try:
                email.send(fail_silently=False)
                self.message_user(
                    request,
                    f'Reply sent successfully to {obj.email}!',
                    level='success'
                )
            except Exception as e:
                self.message_user(
                    request,
                    f'Error sending email: {str(e)}',
                    level='error'
                )
                # Print to console for debugging
                print(f"\nEmail that would have been sent:")
                print(f"To: {obj.email}")
                print(f"Subject: Re: {obj.subject}")
                print(f"Content:\n{text_content}\n")
        
        super().save_model(request, obj, form, change)

    def mark_as_read(self, request, queryset):
        queryset.update(status='read')
        self.message_user(request, f'{queryset.count()} messages marked as read.')
    mark_as_read.short_description = "Mark as Read"

# Register with admin site
admin_site.register(User, CustomUserAdmin)
admin_site.register(URLScan, URLScanAdmin)
admin_site.register(Report, ReportAdmin)
admin_site.register(Contact, ContactAdmin)

# Replace default admin site
admin.site = admin_site

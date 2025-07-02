import os
from datetime import datetime
from django.template.loader import render_to_string
from django.conf import settings
import json
import tempfile

class ReportGenerator:
    def __init__(self):
        self.options = {
            'quiet': '',
            'enable-local-file-access': None,
            'no-outline': None,
            'encoding': "UTF-8",
            'no-images': None,  # Disable images to avoid permission issues
        }
        
    def _prepare_report_data(self, url, analysis_results):
        """Prepare data for the report, handling any recursive structures."""
        def clean_value(value):
            """Convert complex objects to simple types."""
            if isinstance(value, (str, int, float, bool)):
                return value
            elif isinstance(value, (list, tuple)):
                return [clean_value(item) for item in value]
            elif isinstance(value, dict):
                if any(k in ['issuer', 'subject'] for k in value.keys()):
                    # Special handling for SSL certificate information
                    return {k: clean_value(v) for k, v in value.items()}
                return {k: clean_value(v) for k, v in value.items()}
            elif value is None:
                return None
            else:
                return str(value)
        
        # Clean the analysis results
        cleaned_results = {
            'domain_info': clean_value(analysis_results.get('domain_info', {})),
            'security_info': clean_value(analysis_results.get('security_info', {})),
            'content_info': clean_value(analysis_results.get('content_info', {})),
            'ssl_info': clean_value(analysis_results.get('ssl_info', {})),
            'headers': clean_value(analysis_results.get('headers', {})),
            'redirect_chain': clean_value(analysis_results.get('redirect_chain', [])),
            'screenshot_path': analysis_results.get('screenshot_path')
        }
        
        return {
            'url': url,
            'analysis_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            **cleaned_results
        }

    def generate_html_report(self, url, analysis_results):
        """Generate HTML report as fallback when PDF generation is not available."""
        try:
            # Create reports directory if it doesn't exist
            reports_dir = os.path.join(settings.MEDIA_ROOT, 'reports')
            os.makedirs(reports_dir, exist_ok=True)
            
            # Generate unique filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            safe_url = url.replace('://', '_').replace('/', '_').replace(':', '_')[:30]
            filename = f"report_{safe_url}_{timestamp}.html"
            html_path = os.path.join(reports_dir, filename)
            
            # Prepare data for template
            template_data = {
                'url': url,
                'analysis': analysis_results,
                'analysis_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            }
            
            # Generate HTML content
            html_content = render_to_string('html_report.html', template_data)
            
            # Save HTML file
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            # Return relative path for media URL
            return os.path.join('reports', filename)
            
        except Exception as e:
            print(f"HTML report generation error: {str(e)}")
            return None

    def generate_pdf_report(self, url, analysis_results):
        try:
            # Check if wkhtmltopdf is available
            if not hasattr(settings, 'WKHTMLTOPDF_PATH') or not settings.WKHTMLTOPDF_PATH:
                print("PDF generation skipped: wkhtmltopdf not available")
                # Fallback to HTML report
                return self.generate_html_report(url, analysis_results)
            
            # Import pdfkit only if wkhtmltopdf is available
            try:
                import pdfkit
            except ImportError:
                print("PDF generation skipped: pdfkit not installed")
                # Fallback to HTML report
                return self.generate_html_report(url, analysis_results)
            
            # Create temp directory for report
            with tempfile.TemporaryDirectory() as temp_dir:
                # Generate HTML content
                html_content = render_to_string('pdf_report.html', {
                    'url': url,
                    'analysis': analysis_results,
                    'analysis_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                })
                
                # Save HTML to temp file
                html_path = os.path.join(temp_dir, 'report.html')
                with open(html_path, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                
                # Create reports directory if it doesn't exist
                reports_dir = os.path.join(settings.MEDIA_ROOT, 'reports')
                os.makedirs(reports_dir, exist_ok=True)
                
                # Generate unique filename
                filename = f"report_{url.replace('://', '_').replace('/', '_')[:50]}.pdf"
                pdf_path = os.path.join(reports_dir, filename)
                
                # Configure pdfkit
                config = pdfkit.configuration(wkhtmltopdf=settings.WKHTMLTOPDF_PATH)
                
                # Generate PDF
                pdfkit.from_file(
                    html_path,
                    pdf_path,
                    options=self.options,
                    configuration=config
                )
                
                # Return relative path for media URL
                return os.path.join('reports', filename)
                
        except Exception as e:
            print(f"PDF generation error: {str(e)}")
            # Fallback to HTML report
            return self.generate_html_report(url, analysis_results) 
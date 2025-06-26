# Report Generation Setup Guide

## Overview

PhishNet supports two types of report generation:

1. **PDF Reports** (requires wkhtmltopdf installation)
2. **HTML Reports** (fallback, works without additional software)

## Current Status

The report generation feature is now working with the following improvements:

### ✅ What's Fixed

1. **Fixed Template Issue**: The report button now correctly checks for `report_path` instead of `analysis.report_path`
2. **Added Fallback System**: When PDF generation fails, the system automatically generates an HTML report
3. **Better Error Handling**: Improved error messages and user feedback
4. **Debug Information**: Added debug section to show report generation status
5. **Dynamic Button**: The button changes based on report availability and type

### 🔧 How It Works Now

1. **Automatic Report Generation**: Reports are generated automatically during URL scanning
2. **Fallback System**: If wkhtmltopdf is not available, HTML reports are generated instead
3. **User-Friendly Interface**: Clear buttons showing report type (PDF or HTML)
4. **Download/View Options**: PDF reports download, HTML reports open in new tab

## Installation Options

### Option 1: Install wkhtmltopdf for PDF Reports (Recommended)

#### Windows
1. Download wkhtmltopdf from: https://wkhtmltopdf.org/downloads.html
2. Install the Windows installer
3. Add to PATH or specify path in settings

#### Linux (Ubuntu/Debian)
```bash
sudo apt-get install wkhtmltopdf
```

#### macOS
```bash
brew install wkhtmltopdf
```

### Option 2: Use HTML Reports Only (No Installation Required)

HTML reports work out of the box and provide the same information as PDF reports. They can be:
- Viewed in any web browser
- Printed to PDF using browser print function
- Saved as HTML files

## Testing the Feature

1. **Scan a URL**: Go to the scan form and enter any URL
2. **Check Debug Info**: Look at the debug section to see report status
3. **Generate Report**: If no report exists, click "Generate Report"
4. **View/Download**: Click the appropriate button based on report type

## Troubleshooting

### Report Button Not Showing
- Check the debug information section
- Ensure the scan completed successfully
- Look for any error messages in the console

### PDF Generation Fails
- Verify wkhtmltopdf is installed: `wkhtmltopdf --version`
- Check if the path is correctly set in settings
- The system will automatically fallback to HTML reports

### HTML Report Issues
- Check if the media/reports directory exists
- Ensure proper file permissions
- Check Django logs for any errors

## File Locations

- **PDF Reports**: `media/reports/report_*.pdf`
- **HTML Reports**: `media/reports/report_*.html`
- **Templates**: 
  - PDF: `templates/pdf_report.html`
  - HTML: `templates/html_report.html`

## Configuration

The system automatically detects wkhtmltopdf availability. If you want to force HTML reports only, you can modify `settings.py`:

```python
# Force HTML reports only
WKHTMLTOPDF_PATH = None
```

## Future Enhancements

1. **Email Reports**: Send reports via email
2. **Report Templates**: Multiple report styles
3. **Batch Reports**: Generate reports for multiple URLs
4. **Report Scheduling**: Automatic report generation
5. **API Integration**: Generate reports via API calls

## Support

If you encounter issues:

1. Check the debug information in the scan results
2. Look at Django console output for error messages
3. Verify file permissions in the media directory
4. Test with a simple URL first

The system is designed to be robust and will always provide some form of report, even if PDF generation fails. 
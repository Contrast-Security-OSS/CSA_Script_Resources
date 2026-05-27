# Contrast Security - Top Vulnerability Report Generator

Generate comprehensive Markdown reports for the highest priority vulnerability in your Contrast Security applications. The tool automatically selects the most critical vulnerability using intelligent priority scoring and generates a detailed report with story, data flow, HTTP request details, remediation guidance, and more.

## Features

✅ **Smart Priority Selection** - Automatically finds the top vulnerability using weighted scoring:
  - Severity (Critical: 1000 pts, High: 500 pts, Medium: 200 pts, Low: 100 pts)
  - Likelihood (High: 100 pts, Medium: 50 pts, Low: 25 pts)
  - Rule Priority (Critical: 1000 pts, High: 500 pts, Medium: 200 pts, Low: 100 pts)

✅ **Comprehensive Reporting** - Generates detailed sections including:
  - 📖 **Vulnerability Story** - Narrative explanation from Contrast
  - 📋 **Details (Data Flow)** - Complete event-by-event breakdown with stack traces
  - 🌐 **HTTP Request Info** - Full HTTP request that triggered the vulnerability
  - 🔧 **How to Fix** - Detailed remediation guidance
  - 📝 **Notes** - Team comments with timestamps
  - ⏱️ **Timeline** - First/last detected dates
  - 🎯 **Risk Assessment** - Severity, likelihood, impact, and confidence

✅ **Interactive Selection** - Choose from your licensed applications
✅ **Status Filtering** - Focuses on open vulnerabilities (Reported, Confirmed, Suspicious)

## Prerequisites

- Python 3.7+
- Contrast Security account with API access
- Valid Contrast API credentials (API Key, Authorization header, Organization ID)

## Installation

### 1. Create Virtual Environment (Recommended)

```bash
python3 -m venv .venv
source .venv/bin/activate  # On macOS/Linux
# OR
.venv\Scripts\activate     # On Windows
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure API Credentials

Copy the template and add your Contrast Security credentials:

```bash
cp .env.template .env
```

Edit `.env` and add your credentials:

```ini
[Staging Auth]
CONTRAST_API_KEY = your_api_key_here
CONTRAST_AUTHORIZATION = your_authorization_header_here
CONTRAST_ORG_ID = your_org_id_here
CONTRAST_BASE_URL = https://your-contrast-instance.com
```

**Finding your credentials:**
1. Log in to Contrast Security
2. Go to **User Settings** → **Your Keys**
3. Copy the **API Key** and **Authorization** header
4. Your **Organization ID** is in the URL or User Settings

## Usage

### Run the Script

```bash
python3 generate_single_vuln_report.py
```

### Interactive Workflow

1. **Application List** - View all licensed applications
2. **Select Application** - Enter the number of your chosen app
3. **Automatic Priority Selection** - Script finds the top vulnerability
4. **Report Generation** - Creates detailed Markdown file

### Output File

Generated file format:
```
top_vuln_{app_name}_{timestamp}.md
```

Example: `top_vuln_my-application_20260326_123615.md`

## Report Sections Explained

### 📖 Vulnerability Story
The narrative explanation of how the vulnerability works, extracted from Contrast's vulnerability story chapters.

### 📋 Details (Data Flow / Stack Traces)
Complete event-by-event breakdown showing:
- Source of tainted data (e.g., HTTP parameters)
- Data flow through the application
- Stack traces with file paths and line numbers
- Code snippets at each event
- Important events highlighted

### 🌐 HTTP Request Info
The complete HTTP request that triggered the vulnerability:
- HTTP method (GET, POST, etc.)
- Full headers
- Request parameters
- POST body content

### 🔧 How to Fix
Detailed remediation guidance from Contrast Security's recommendation engine, including:
- Secure coding practices
- Code examples
- Library recommendations

### 📝 Notes
Team member comments with:
- Author name
- Timestamp
- Note content

### ⏱️ Timeline
- First time detected
- Last time detected
- Total time vulnerability has been open

### 🎯 Risk Assessment
- Severity level (Critical, High, Medium, Low)
- Likelihood (High, Medium, Low)
- Impact description
- Confidence level

## Example Output

```markdown
# Top Vulnerability Report: SQL Injection

**Application:** my-application  
**Vulnerability UUID:** XXXX-XXXX-XXXX-XXXX  
**Severity:** CRITICAL  
**Status:** Reported  
**First Detected:** 2023-08-15 10:23:45  
**Last Detected:** 2023-09-20 14:15:30  

## 📖 Vulnerability Story

This SQL Injection vulnerability occurs when user-supplied data flows from an HTTP parameter directly into a SQL query without proper sanitization...

## 📋 Details (Data Flow / Stack Traces)

### Event 1: Source
**Type:** SOURCE  
**Description:** HTTP Request Parameter "cc"  
**Location:** ProfileServlet.java:45  

```java
String cc = request.getParameter("cc");
```

### Event 2: Propagation
**Type:** PROPAGATION  
**Description:** Data flows through method call  
**Location:** DatabaseHelper.java:123  

## 🌐 HTTP Request Info

```http
POST /api/endpoint HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

param1=value1&param2=value2
```

## 🔧 How to Fix

Use parameterized queries instead of string concatenation. Replace vulnerable code with PreparedStatement...

```

## Troubleshooting

### Authentication Errors
- **Check credentials**: Verify API Key, Authorization header, and Org ID in `.env`
- **Test manually**: Try the credentials in Contrast UI → User Settings → Your Keys
- **Check expiration**: Ensure API key hasn't expired

### No Vulnerabilities Found
- **Verify severity**: Application must have Critical or High severity vulnerabilities
- **Check status**: Vulnerabilities must be in Reported, Confirmed, or Suspicious state
- **Archived vulnerabilities**: Script only shows open vulnerabilities

### Missing Sections in Report
Some sections may not appear for all vulnerabilities:
- **Notes**: Only if team members added comments
- **HTTP Request**: Only for runtime vulnerabilities (not configuration issues)
- **Events**: Number varies by vulnerability type

### Script Errors
```bash
# If you see module errors, reinstall dependencies:
pip install --upgrade -r requirements.txt

# If .env parsing fails, check file encoding:
file .env  # Should be ASCII or UTF-8
```

## API Endpoints Reference

The script uses these Contrast Security API v3 endpoints:

| Endpoint | Purpose |
|----------|---------|
| `/ng/{orgId}/applications` | List licensed applications |
| `/ng/{orgId}/traces/{appId}/filter` | Get vulnerabilities for app |
| `/ng/{orgId}/traces/{uuid}/story` | Get vulnerability story with chapters |
| `/ng/{orgId}/traces/{uuid}/events/summary` | Get event details and stack traces |
| `/ng/{orgId}/traces/{uuid}/httprequest` | Get HTTP request that triggered vuln |
| `/ng/{orgId}/traces/{uuid}/recommendation` | Get remediation guidance |
| `/ng/{orgId}/applications/{appId}/traces/{uuid}/notes` | Get team notes |

## Files in This Directory

### Essential Files (Keep These)
- **`generate_single_vuln_report.py`** - Main script
- **`requirements.txt`** - Python dependencies
- **`.env.template`** - Configuration template
- **`.env`** - Your credentials (gitignored)
- **`.gitignore`** - Git ignore rules
- **`README.md`** - This file

### Generated Reports
- **`top_vuln_*.md`** - Generated vulnerability reports (can be deleted)

## Advanced Usage

### Modify Priority Scoring

Edit the scoring in `get_top_vulnerability()` method:

```python
# Adjust these weights in generate_single_vuln_report.py
severity_scores = {
    'CRITICAL': 1000,
    'HIGH': 500,
    'MEDIUM': 200,
    'LOW': 100
}
```

### Change Severity Filter

To include Medium and Low severity vulnerabilities, modify the filter:

```python
payload = {
    "severities": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],  # Add more levels
    # ...
}
```

### Use Different Environment

Add another section to `.env`:

```ini
[Production Auth]
CONTRAST_API_KEY = prod_api_key
CONTRAST_AUTHORIZATION = prod_auth
CONTRAST_ORG_ID = prod_org_id
CONTRAST_BASE_URL = https://app.contrastsecurity.com
```

Then modify the script to use `section='Production Auth'`.

## Support

- **Contrast Documentation**: https://docs.contrastsecurity.com
- **API Reference**: Check your Contrast instance at `/Contrast/static/ng/index.html#/api`
- **Issues**: Check API response errors in script output for debugging

## License

MIT License - Internal tool for Contrast Security API users


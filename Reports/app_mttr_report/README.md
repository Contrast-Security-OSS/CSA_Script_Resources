# Application KPI Dashboard Report Generator

Generate comprehensive per-application KPI dashboards from Contrast Security data.

## Features

- **Route Coverage Metrics**: Track how much of your application's attack surface has been exercised
- **MTTR Analysis**: Calculate Mean Time To Remediate overall and per severity level
- **Vulnerability Statistics**: Current open and closed vulnerabilities within a timeframe
- **Critical Libraries**: Identify libraries with security issues and actual class usage
- **Merged Application Support**: Automatically treats merged applications as a single entity

## Usage

### Basic Usage

```bash
python3 generate_app_kpi_report.py \
  --env-file ../../.env \
  --env-section "Staging Auth" \
  --app-name "MyApplication"
```

### By Application ID

```bash
python3 generate_app_kpi_report.py \
  --env-file ../../.env \
  --env-section "Production Auth" \
  --app-id "abc-123-def-456" \
  --days 90
```

### Custom Output Path

```bash
python3 generate_app_kpi_report.py \
  --env-file ../../.env \
  --env-section "Staging Auth" \
  --app-name "critical-app" \
  --days 180 \
  --output custom_reports/critical_app_Q1.md
```

## Parameters

| Parameter | Required | Description | Default |
|-----------|----------|-------------|---------|
| `--env-file` | Yes | Path to .env credentials file | - |
| `--env-section` | Yes | Section name in .env (e.g., "Staging Auth") | - |
| `--app-name` | Either app-name or app-id | Application name (case-insensitive) | - |
| `--app-id` | Either app-name or app-id | Application ID (UUID) | - |
| `--days` | No | Analysis timeframe in days | 365 |
| `--output` | No | Custom output file path | `{app_name}_KPI_{date}.md` |

## Output Report

The generated Markdown report includes:

### KPI Summary
- Route coverage percentage
- Total open vulnerabilities
- Closed vulnerabilities in timeframe
- Overall MTTR
- Critical library count

### Detailed Sections
1. **Route Coverage**: Total, exercised, unexercised, vulnerable routes
2. **Open Vulnerabilities**: Breakdown by severity (Critical, High, Medium, Low, Note)
3. **Closed Vulnerabilities**: Breakdown by severity within analysis timeframe
4. **MTTR by Severity**: Average remediation time for each severity level
5. **Critical Libraries**: Libraries with security grades and class usage
6. **Methodology**: Explains data collection and metric definitions

## .env Configuration

Your `.env` file should have credentials in sections:

```ini
[Staging Auth]
TeamserverURL=https://teamserver-staging.contsec.com/
ORG_UUID=your-org-uuid-here
AUTH=your-base64-auth-here
API_KEY=your-api-key-here

[Production Auth]
TeamserverURL=https://production.contrastsecurity.com/
ORG_UUID=your-org-uuid-here
AUTH=your-base64-auth-here
API_KEY=your-api-key-here
```

## Examples

### Generate quarterly report for production app
```bash
python3 generate_app_kpi_report.py \
  --env-file ../../.env \
  --env-section "Production Auth" \
  --app-name "my-application" \
  --days 90 \
  --output quarterly_reports/Q1_2026_report.md
```

### Generate annual report for all apps
```bash
# Create a script to loop through all apps
for app in "app1" "app2" "app3"; do
  python3 generate_app_kpi_report.py \
    --env-file ../../.env \
    --env-section "Production Auth" \
    --app-name "$app" \
    --days 365
done
```

## Merged Applications

The script automatically handles merged applications by using the current application ID. When you specify an app name that has been merged, the API will return the master application, and all metrics will reflect the combined data.

## API Endpoints and Data Fields

### Route Coverage
- **Endpoint**: `GET /applications/{app_id}/route`
- **Metric**: Routes with `exercised` timestamp / total routes
- **Filters**: None (all routes included)
- **Fields Used**: 
  - `exercised`: Timestamp when route was last exercised (present = exercised, null = unexercised)
  - `vulnerabilities`: Number of vulnerabilities affecting this route (integer)
  - `critical_vulnerabilities`: Number of critical vulnerabilities (integer)
- **Routes with Vulnerabilities**: Count routes where `vulnerabilities` > 0

### Open Vulnerabilities
- **Endpoint**: `GET /traces/{app_id}/filter`
- **Status Filter**: `Reported`, `Confirmed`, `Suspicious`
- **Confidence**: All levels included (High, Medium, Low)
- **Timeframe**: No time filter applied (all open vulnerabilities regardless of age)
- **Fields Used**: `severity`, `status`

### Closed Vulnerabilities
- **Endpoint**: `GET /traces/{app_id}/filter`
- **Status Filter**: `Fixed`, `Remediated`, `NotAProblem`, `AutoRemediated`
  - `AutoRemediated` captures "Remediated - Auto-Verified" vulnerabilities
- **Timeframe**: Only vulnerabilities **closed** within specified `--days`
  - **Important**: Filtered by `closed_time`, not `first_time_seen`
  - Example: A vulnerability first detected 500 days ago but remediated today **will be included** in a 365-day report
  - This ensures accurate MTTR calculation for all vulnerabilities remediated in the timeframe
- **Fields Used**: `severity`, `status`, `status_keycode`, `first_time_seen`, `closed_time`
- **Filtering Logic**: 
  - Fetches all closed vulnerabilities (no time restriction in API call)
  - Manually filters results where `closed_time >= since_date`
  - This is required because the API only supports filtering by `first_time_seen`, not `closed_time`

### MTTR Calculation
- **Formula**: `(closed_time - first_time_seen) / 1000 / 86400` (converts ms to days)
- **Closure Time**: The `closed_time` field contains epoch milliseconds when vulnerability status changed to a closed state
- **First Detected**: The `first_time_seen` field contains epoch milliseconds when vulnerability was first discovered

### Critical Libraries
- **Endpoint**: `POST /libraries/filter`
- **Filters Applied**:
  - `quickFilter`: `VULNERABLE` (has CVEs)
  - `severities`: `["CRITICAL"]` (critical CVEs only)
  - `includeUsed`: `true` (has class usage)
  - `includeUnused`: `false` (excludes unused libraries)
- **Fields Used**: `file_name`, `file_version`, `grade`, `classes_used`, `class_count`, `total_vulnerabilities`
  - `total_vulnerabilities`: Total CVE count for the library
  - `critical_vulnerabilities`, `high_vulnerabilities`: Breakdown by severity
  - `classes_used` / `class_count`: Used classes out of total classes in library

## Troubleshooting

### "Application not found"
- Verify the application name matches exactly (case-insensitive)
- Try using `--app-id` instead if you know the UUID
- Check that the application is not archived

### "401 Unauthorized" for routes/libraries
- The API credentials may not have permissions for these endpoints
- The script will continue and generate the report with available data
- Contact your Contrast administrator to grant additional permissions

### "No closed vulnerabilities" / MTTR shows N/A
- No vulnerabilities were closed within the specified timeframe
- Try increasing `--days` to capture more historical data
- Verify vulnerabilities are being marked as Fixed/Remediated in Contrast

## Requirements

- Python 3.7+
- `requests` library
- Valid Contrast Security API credentials
- Application must be licensed and non-archived

## API Endpoints Used

- `GET /api/ng/{org}/applications` - Application lookup
- `GET /api/ng/{org}/traces/{app}/filter` - Vulnerability data
- `GET /api/ng/{org}/routes/{app}` - Route coverage (optional)
- `GET /api/ng/{org}/libraries/{app}` - Library data (optional)

Optional endpoints (routes, libraries) will gracefully fail if credentials lack permissions.

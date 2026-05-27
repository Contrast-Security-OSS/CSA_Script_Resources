# Reports CLI Usage

This directory contains script-based report generators.

All commands below are run from repository root and use the root `.env` file by default.

## Shared CLI Behavior

- Credentials are loaded from `./.env` unless `--env-file` is provided.
- No section selection is required.
- Default output location: each script writes to `Reports/<report>/Output/`.

Required `.env` keys:

```ini
TEAMSERVER_URL=https://your_saas_instance.contrastsecurity.com/
ORG_UUID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
CONTRAST_AUTH=base64_encoded_authorization_header_value
CONTRAST_API_KEY=your_api_key_here
```

Legacy key names are still accepted (`TeamserverURL`, `AUTH`, `API_KEY`).

## 1) Application KPI Report

Script:

- `Reports/app_mttr_report/generate_app_kpi_report.py`

Examples:

```bash
python3 Reports/app_mttr_report/generate_app_kpi_report.py \
  --app-name "target-app"

python3 Reports/app_mttr_report/generate_app_kpi_report.py \
  --app-id "abc-123-def-456" \
  --days 90

python3 Reports/app_mttr_report/generate_app_kpi_report.py \
  --env-file .env \
  --app-name "target-app" \
  --output Reports/app_mttr_report/Output/custom_name.md
```

Key args:

- `--app-name` or `--app-id` (one required)
- `--days`
- `--output`
- `--env-file`

## 2) Full Application Assessment Report

Script:

- `Reports/full-app-report/generate_app_report.py`

Examples:

```bash
python3 Reports/full-app-report/generate_app_report.py

python3 Reports/full-app-report/generate_app_report.py \
  --app-name "target-app" \
  --report-name "Security Assessment" \
  --output Reports/full-app-report/Output/security_assessment.md

python3 Reports/full-app-report/generate_app_report.py \
  --tag "target-tag" \
  --report-name "Security Assessment" \
  --days 90

python3 Reports/full-app-report/generate_app_report.py \
  --tag "target-tag" \
  --report-name "Security Assessment" \
  --skip-staleness \
  --skip-servers
```

Key args:

- one selector: `--app-name`, `--tag`, or interactive mode
- `--report-name`
- `--days`
- `--output` (`.md` or `.pdf`)
- `--skip-staleness`
- `--skip-servers`
- `--env-file`

## 3) Top Vulnerability Report

Script:

- `Reports/top-vulns-report/generate_single_vuln_report.py`

Examples:

```bash
python3 Reports/top-vulns-report/generate_single_vuln_report.py \
  --app-name "target-app"

python3 Reports/top-vulns-report/generate_single_vuln_report.py

python3 Reports/top-vulns-report/generate_single_vuln_report.py \
  --app-name "target-app" \
  --output Reports/top-vulns-report/Output/top_vuln_target-app.md
```

Key args:

- `--app-name` (optional; interactive if omitted)
- `--output`
- `--env-file`

## 4) Used OSS by Application Report

Script:

- `Reports/used_OSS_by_app/generate_used_oss_by_app_report.py`

Examples:

```bash
python3 Reports/used_OSS_by_app/generate_used_oss_by_app_report.py

python3 Reports/used_OSS_by_app/generate_used_oss_by_app_report.py \
  --env-file .env

python3 Reports/used_OSS_by_app/generate_used_oss_by_app_report.py \
  --page-size 100
```

Key args:

- `--quick-filter`
- `--page-size`
- `--env-file`

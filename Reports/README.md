# Reports CLI Usage

This directory contains script-based report generators.

All commands below are run from repository root.

## Shared CLI Behavior

- Default credentials file: `.env` at repository root.
- `--env-file` is optional and only needed for non-default credential file paths.
- `--env-section` is optional and only needed for legacy sectioned `.env` files.
- Default output location: each script writes to its own `Reports/<report>/Output/` directory.

## 1) Application KPI Report

Script:

- `Reports/app_mttr_report/generate_app_kpi_report.py`

Examples:

```bash
python3 Reports/app_mttr_report/generate_app_kpi_report.py \
  --app-name "my-application"

python3 Reports/app_mttr_report/generate_app_kpi_report.py \
  --app-id "abc-123-def-456" \
  --days 90

python3 Reports/app_mttr_report/generate_app_kpi_report.py \
  --env-file .env \
  --env-section "Staging Auth" \
  --app-name "my-application" \
  --output Reports/app_mttr_report/Output/custom_name.md
```

Key args:

- `--app-name` or `--app-id` (one required)
- `--days`
- `--output`
- `--env-file`
- `--env-section`

## 2) Full Application Assessment Report

Script:

- `Reports/full-app-report/generate_app_report.py`

Examples:

```bash
python3 Reports/full-app-report/generate_app_report.py

python3 Reports/full-app-report/generate_app_report.py \
  --app-name "my-application" \
  --customer-name "Acme" \
  --output Reports/full-app-report/Output/acme_report.md

python3 Reports/full-app-report/generate_app_report.py \
  --tag "my-tag" \
  --customer-name "Acme" \
  --days 90

python3 Reports/full-app-report/generate_app_report.py \
  --tag "my-tag" \
  --customer-name "Acme" \
  --skip-staleness \
  --skip-servers
```

Key args:

- one selector: `--app-name`, `--tag`, or interactive mode
- `--customer-name`
- `--days`
- `--output` (`.md` or `.pdf`)
- `--skip-staleness`
- `--skip-servers`
- `--env-file`
- `--env-section`

## 3) Top Vulnerability Report

Script:

- `Reports/top-vulns-report/generate_single_vuln_report.py`

Examples:

```bash
python3 Reports/top-vulns-report/generate_single_vuln_report.py \
  --app-name "my-application"

python3 Reports/top-vulns-report/generate_single_vuln_report.py

python3 Reports/top-vulns-report/generate_single_vuln_report.py \
  --app-name "my-application" \
  --output Reports/top-vulns-report/Output/my_app_top_vuln.md
```

Key args:

- `--app-name` (optional; interactive if omitted)
- `--output`
- `--env-file`
- `--env-section`

## 4) Used OSS by Application Report

Script:

- `Reports/used_OSS_by_app/generate_used_oss_by_app_report.py`

Examples:

```bash
python3 Reports/used_OSS_by_app/generate_used_oss_by_app_report.py

python3 Reports/used_OSS_by_app/generate_used_oss_by_app_report.py \
  --env-file .env \
  --env-section "Staging Auth"

python3 Reports/used_OSS_by_app/generate_used_oss_by_app_report.py \
  --page-size 100
```

Key args:

- `--quick-filter`
- `--page-size`
- `--env-file`
- `--env-section`

## Related Report Docs

Per-report README files remain available:

- `Reports/app_mttr_report/README.md`
- `Reports/full-app-report/README.md`
- `Reports/top-vulns-report/README.md`
- `Reports/used_OSS_by_app/README.md`

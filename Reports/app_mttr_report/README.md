# Application KPI Dashboard Report Generator

Generate per-application KPI dashboards from Contrast Security data.

## Usage

Run from repository root:

```bash
python3 Reports/app_mttr_report/generate_app_kpi_report.py \
  --app-name "target-app"
```

By application ID:

```bash
python3 Reports/app_mttr_report/generate_app_kpi_report.py \
  --app-id "abc-123-def-456" \
  --days 90
```

Custom output path:

```bash
python3 Reports/app_mttr_report/generate_app_kpi_report.py \
  --app-name "target-app" \
  --days 180 \
  --output Reports/app_mttr_report/Output/custom_report.md
```

## Parameters

| Parameter | Required | Description | Default |
|-----------|----------|-------------|---------|
| `--app-name` | Either app-name or app-id | Application name (case-insensitive) | - |
| `--app-id` | Either app-name or app-id | Application ID (UUID) | - |
| `--days` | No | Analysis timeframe in days | 365 |
| `--output` | No | Custom output file path | `Reports/app_mttr_report/Output/{app_name}_KPI_{date}.md` |
| `--env-file` | No | Path to .env file | `./.env` |

## .env Configuration

Use root `.env` with flat keys:

```ini
TEAMSERVER_URL=https://your_saas_instance.contrastsecurity.com/
ORG_UUID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
CONTRAST_AUTH=base64_encoded_authorization_header_value
CONTRAST_API_KEY=your_api_key_here
```

# Full Application IAST Assessment Report

Generates a comprehensive Contrast Security IAST assessment report for one or more applications.

## Usage

Run from repository root:

```bash
# Interactive mode
python3 Reports/full-app-report/generate_app_report.py

# Single app by name
python3 Reports/full-app-report/generate_app_report.py \
  --app-name "target-app" \
  --report-name "Security Assessment" \
  --output Reports/full-app-report/Output/security_assessment.md

# Filter by tag
python3 Reports/full-app-report/generate_app_report.py \
  --tag "target-tag" \
  --report-name "Security Assessment" \
  --days 90

# Faster run
python3 Reports/full-app-report/generate_app_report.py \
  --tag "target-tag" \
  --report-name "Security Assessment" \
  --skip-staleness \
  --skip-servers
```

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `--env-file` | No | `./.env` | Path to credentials file |
| `--tag` | One selector option | - | Filter by application tag |
| `--app-name` | One selector option | - | Select single app by name |
| interactive | One selector option | - | Select apps interactively |
| `--report-name` | No | prompt | Name shown in report title and filename |
| `--output` | No | auto | Output file path |
| `--days` | No | 365 | Lookback for closed vulns / MTTR |
| `--skip-staleness` | No | false | Skip route staleness analysis |
| `--skip-servers` | No | false | Skip server / agent-version fetch |

## .env Configuration

Use root `.env` with flat keys:

```ini
TEAMSERVER_URL=https://your_saas_instance.contrastsecurity.com/
ORG_UUID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
CONTRAST_AUTH=base64_encoded_authorization_header_value
CONTRAST_API_KEY=your_api_key_here
```

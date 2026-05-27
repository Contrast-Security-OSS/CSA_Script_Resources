# Top Vulnerability Report Generator

Generates a Markdown report for the highest-priority open vulnerability in a selected application.

## Usage

Run from repository root:

```bash
# Interactive app selection
python3 Reports/top-vulns-report/generate_single_vuln_report.py

# Select app by name
python3 Reports/top-vulns-report/generate_single_vuln_report.py \
  --app-name "target-app"

# Custom output path
python3 Reports/top-vulns-report/generate_single_vuln_report.py \
  --app-name "target-app" \
  --output Reports/top-vulns-report/Output/top_vuln_target-app.md
```

## Parameters

| Parameter | Required | Description | Default |
|-----------|----------|-------------|---------|
| `--app-name` | No | Application name; omit for interactive selection | interactive |
| `--output` | No | Custom output path | `Reports/top-vulns-report/Output/top_vuln_{app}_{timestamp}.md` |
| `--env-file` | No | Path to .env file | `./.env` |

## .env Configuration

Use root `.env` with flat keys:

```ini
TEAMSERVER_URL=https://your_saas_instance.contrastsecurity.com/
ORG_UUID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
CONTRAST_AUTH=base64_encoded_authorization_header_value
CONTRAST_API_KEY=your_api_key_here
```

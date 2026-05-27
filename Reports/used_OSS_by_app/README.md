# Used OSS by Application Report

Generates an organization-wide OSS report using the Contrast libraries filter endpoint.

## Usage

Run from repository root:

```bash
python3 Reports/used_OSS_by_app/generate_used_oss_by_app_report.py
```

Optional examples:

```bash
python3 Reports/used_OSS_by_app/generate_used_oss_by_app_report.py --env-file .env
python3 Reports/used_OSS_by_app/generate_used_oss_by_app_report.py --quick-filter ALL --page-size 250
```

## Output Files

Output is written to:

- `Reports/used_OSS_by_app/Output/used_oss_by_app_YYYY-MM-DD.md`
- `Reports/used_OSS_by_app/Output/used_oss_by_app_YYYY-MM-DD.csv`

## .env Configuration

Use root `.env` with flat keys:

```ini
TEAMSERVER_URL=https://your_saas_instance.contrastsecurity.com/
ORG_UUID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
CONTRAST_AUTH=base64_encoded_authorization_header_value
CONTRAST_API_KEY=your_api_key_here
```

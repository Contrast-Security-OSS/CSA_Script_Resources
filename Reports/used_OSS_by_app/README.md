# Used OSS by Application Report

Generates an organization-wide OSS report using:

- `POST /Contrast/api/ng/{ORG_UUID}/libraries/filter`
- Pagination via `offset` + `limit` until all entries are collected

Outputs:

- Markdown summary grouped by application and environment
- CSV containing flattened row-level library data

## Usage

From the repository root:

```bash
python3 Reports/used_OSS_by_app/generate_used_oss_by_app_report.py \
  --env-file .env \
  --env-section "Staging Auth"
```

Optional arguments:

- `--quick-filter ALL` (default: `ALL`)
- `--page-size 250` (requested page size; script auto-falls back to `50` if API enforces lower max)

## Output Files

Output is always written to the repository `Output/` directory.

Filename pattern:

- `Output/{auth_name}_used_oss_by_app_YYYY-MM-DD.md`
- `Output/{auth_name}_used_oss_by_app_YYYY-MM-DD.csv`

Where `{auth_name}` is derived from the selected `.env` section name, with a trailing `Auth` removed.

Examples:

- `[Staging Auth]` -> `Staging`
- `[Acme Auth]` -> `Acme`
- `[Acme Corp Auth]` -> `Acme_Corp`

CSV columns include the requested fields:

- `library_name`
- `version`
- `latest_version`
- `cves`
- `usage`
- `application`
- `score`

Additional columns are included for filtering and traceability:

- `sha1_hash`, `application_id`, `environment`, `grade`, `classes_used`, `total_classes`

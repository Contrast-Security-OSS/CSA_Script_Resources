# Full Application IAST Assessment Report

Generates a comprehensive Contrast Security IAST assessment report covering all
pillars of an IAST program for one or more applications.

## Report Structure

The report is organized into two main sections for clarity:

### 1. **Portfolio Summary** (Metrics across all tagged applications)
- Executive Summary table (9 apps total, combined metrics)
- Open Vulnerability Severity Distribution
- Portfolio-Wide Top Vulnerability Types
- Overall MTTR, route coverage %, possibly remediated count, etc.

### 2. **Individual Application Details** (Detailed breakdown per app)
- Custom code vulnerabilities (open by severity, MTTR on closed)
- OSS / library risk (critical libraries with class usage)
- Route coverage (total, exercised, unexercised, with vulnerabilities)
- Route staleness analysis (possibly-remediated routes)
- Servers & agent version compliance (with upgrade recommendations)

## Report Sections

| Section | Source |
|---------|--------|
| Open vulnerabilities (custom code) | `/traces/{app_id}/filter` |
| Closed vulnerabilities + MTTR | `/traces/{app_id}/filter` (closed statuses) |
| Route coverage | `/applications/{app_id}/route` |
| OSS / library risk | `POST /libraries/filter` |
| Route staleness (possibly remediated) | Route × trace timestamp comparison |
| Servers & agent version compliance | `POST /servers/filter` |

## Usage

```bash
# Default: Interactive mode (guided prompts)
python generate_app_report.py

# Save as markdown report
python generate_app_report.py \
    --env-file ../../.env \
    --env-section "Production Auth" \
    --tag "my-tag" \
    --output ../../Output/my_tag_report.md

# Save as PDF report (requires pandoc: brew install pandoc)
python generate_app_report.py \
    --env-file ../../.env \
    --env-section "Production Auth" \
    --tag "my-tag" \
    --output ../../Output/my_tag_report.pdf

# Single app by name
python generate_app_report.py \
    --env-file ../../.env \
    --env-section "Staging Auth" \
    --app-name "my-application" \
    --output ../../Output/my_app_report.md

# Faster run — skip staleness + server checks
python generate_app_report.py \
    --env-file ../../.env \
    --env-section "Production Auth" \
    --tag "my-tag" \
    --skip-staleness \
    --skip-servers
```

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `--env-file` | No | `.env` | Path to credentials file |
| `--env-section` | **Yes** | — | Section name in .env file |
| `--interactive` | One of three | — | Interactively select apps |
| `--tag TAG` | One of three | — | Filter by application tag |
| `--app-name NAME` | One of three | — | Select single app by name |
| `--output PATH` | No | stdout | Write report to file |
| `--days N` | No | 365 | Lookback for closed vulns / MTTR |
| `--skip-staleness` | No | false | Skip route staleness analysis |
| `--skip-servers` | No | false | Skip server / agent-version fetch |

## `.env` File Format

```ini
[Production Auth]
TeamserverURL=https://eval.contrastsecurity.com/
ORG_UUID=your-org-uuid
AUTH=your-base64-auth-header
API_KEY=your-api-key

[Staging Auth]
TeamserverURL=https://eval.contrastsecurity.com/
ORG_UUID=your-staging-org-uuid
AUTH=your-staging-auth-header
API_KEY=your-staging-api-key
```

## Agent Version Compliance

Servers are evaluated using a **best-practice compliance rule**:

> **COMPLIANT** if agent version is within **top-3 latest releases** OR released **within 3 months** of the latest version

The compliance check uses reference data from [contrast_agent_versions.json](contrast_agent_versions.json), which is automatically bundled with the script and contains:
- Latest version for each language
- Top 3 versions list
- Release dates for all versions
- Versions behind count
- Age in days

### Updating Agent Version Reference Data

The `contrast_agent_versions.json` file is pre-populated from the authoritative Healthchecks repo. To refresh it:

```bash
# From the Healthchecks project root:
python scripts/fetch_all_agent_versions.py

# Then copy the generated file:
cp data/contrast_agent_versions_all.json \
   ../CSA_Script_Resources/Reports/full-app-report/contrast_agent_versions.json
```

### Example Compliance Results

| Version | Latest | Behind | Age | Status |
|---------|--------|--------|-----|--------|
| 6.27.0 | 6.27.0 | 0 | 0d | ✓ PASS (in top-3) |
| 6.25.1 | 6.27.0 | 2 | 44d | ✓ PASS (in top-3) |
| 6.24.0 | 6.27.0 | 4 | 78d | ✓ PASS (within 3 months) |
| 6.16.0 | 6.27.0 | 14 | 342d | ✗ UPGRADE (too old) |

The server table shows **`✓ PASS`** or **`✗ UPGRADE`** with versions behind and age in days.

## Requirements

```bash
pip install requests
```

### Optional: PDF Export

To export reports as PDF files, install pandoc:

```bash
# macOS (Homebrew)
brew install pandoc

# Ubuntu/Debian
sudo apt-get install pandoc

# Or download from: https://pandoc.org/installing.html
```

Without pandoc, reports will be saved as markdown (.md) files. You can still convert them manually:
```bash
pandoc report.md -o report.pdf
```

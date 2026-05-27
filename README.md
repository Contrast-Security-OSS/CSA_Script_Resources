# CSA Script Resources

This repository provides Contrast Security reporting in two workflows:

- Notebook workflow (`notebooks/`) for guided, interactive execution in Jupyter.
- Script workflow (`Reports/`) for direct CLI execution and automation.

## Shared Setup (Common to Both Workflows)

From repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

Install Jupyter only if you plan to run notebooks:

```bash
pip install jupyterlab notebook
```

## Optional: Pre-Commit for Notebook Output Cleanup

Use pre-commit if you want `.ipynb` outputs and execution counts stripped automatically before commit.

One-time setup from repository root:

```bash
pip install -r requirements-dev.txt
pre-commit install
```

Run once against all files (optional):

```bash
pre-commit run --all-files
```

## Shared Authentication Configuration (Common to Both)

All workflows default to one root `.env` file.

```bash
cp example.env .env
```

Set these values in `.env`:

```ini
TEAMSERVER_URL=https://your_saas_instance.contrastsecurity.com/
ORG_UUID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
CONTRAST_AUTH=base64_encoded_authorization_header_value
CONTRAST_API_KEY=your_api_key_here
```

Notes:

- `.env` is git-ignored.
- `example.env` is the committed template.
- Scripts and notebooks both support legacy key names (`TeamserverURL`, `AUTH`, `API_KEY`) in addition to the flat keys shown above.
- `--env-section` is only needed when using a legacy sectioned `.env` file.

## Notebook / Jupyter Workflow

Use this for interactive, cell-by-cell execution.

Start Jupyter from repository root:

```bash
jupyter lab
```

or

```bash
jupyter notebook
```

Available notebooks:

- `notebooks/app_mttr_report/generate_app_kpi_report.ipynb`
- `notebooks/full-app-report/generate_app_report.ipynb`
- `notebooks/top-vulns-report/generate_single_vuln_report.ipynb`
- `notebooks/used_OSS_by_app/generate_used_oss_by_app_report.ipynb`

Notebook outputs are written to `notebooks/<report>/Output/`.

## Script / Reports Workflow

Use this for CLI execution, automation, and pipelines.

Run scripts from repository root, for example:

```bash
python3 Reports/used_OSS_by_app/generate_used_oss_by_app_report.py
```

Script outputs are written to `Reports/<report>/Output/` by default.

Detailed report-by-report script usage has moved to:

- `Reports/README.md`

## API Documentation

Reference docs are in `API documentation/`:

- `saas-restapi-v1/`
- `saas-restapi-v2/`
- `saas-restapi-v3/`

## Security

- Do not commit `.env`.
- Keep `CONTRAST_AUTH` and `CONTRAST_API_KEY` private.
- Treat generated reports as potentially sensitive.

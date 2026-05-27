#!/usr/bin/env python3
"""
Generate organization-wide OSS usage reports from Contrast libraries/filter.

Outputs:
- Markdown summary grouped by application and environment
- CSV with flattened library/app/environment rows

Example:
  python3 generate_used_oss_by_app_report.py \
    --env-file .env
"""

import argparse
import csv
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests


def find_repo_root(start: Path) -> Path:
    current = start.resolve()
    for candidate in [current, *current.parents]:
        if (candidate / "notebooks").exists() and (candidate / "README.md").exists():
            return candidate
    return current


def load_env_file(env_path: Path) -> dict:
    """Parse flat .env credentials and return normalized keys."""
    if not env_path.exists():
        raise FileNotFoundError(f".env file not found: {env_path}")

    cfg = {}
    current_section = None

    with open(env_path, "r", encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("[") and line.endswith("]"):
                current_section = line[1:-1].strip()
                continue
            if "=" not in line:
                continue

            # Flat mode: only parse top-level key/value pairs.
            if current_section is None:
                key, value = line.split("=", 1)
                cfg[key.strip()] = value.strip().strip('"').strip("'")

    normalized = {
        "TeamserverURL": cfg.get("TEAMSERVER_URL") or cfg.get("TeamserverURL") or cfg.get("url"),
        "ORG_UUID": cfg.get("ORG_UUID") or cfg.get("organizationId"),
        "AUTH": cfg.get("CONTRAST_AUTH") or cfg.get("AUTH") or cfg.get("authHeader"),
        "API_KEY": cfg.get("CONTRAST_API_KEY") or cfg.get("API_KEY") or cfg.get("apiKey"),
    }

    required = ["TeamserverURL", "ORG_UUID", "AUTH", "API_KEY"]
    missing = [k for k in required if not normalized.get(k)]
    if missing:
        raise ValueError(f"Missing required keys in {env_path}: {', '.join(missing)}")

    return normalized


def normalize_base_url(raw: str) -> str:
    return raw.rstrip("/") + "/"


def build_headers(creds: dict) -> dict:
    return {
        "Authorization": creds["AUTH"],
        "API-Key": creds["API_KEY"],
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def extract_app_id(app: dict) -> str:
    return (
        app.get("app_id")
        or app.get("appID")
        or app.get("id")
        or app.get("application_id")
        or app.get("applicationId")
        or ""
    )


def extract_app_name(app: dict) -> str:
    return app.get("name") or app.get("label") or "UNKNOWN"


def fetch_all_applications(base_url: str, org_uuid: str, headers: dict) -> Dict[str, str]:
    """Fetch all applications and return app_id -> app_name mapping."""
    url = f"{base_url}Contrast/api/ng/{org_uuid}/applications"
    app_map: Dict[str, str] = {}
    offset = 0
    limit = 100

    while True:
        params = {
            "includeOnlyLicensed": "true",
            "includeArchived": "false",
            "offset": offset,
            "limit": limit,
        }
        resp = requests.get(url, headers=headers, params=params, timeout=60)
        resp.raise_for_status()

        data = resp.json()
        batch = data.get("applications", [])
        if not batch:
            break

        for app in batch:
            app_id = extract_app_id(app)
            if app_id:
                app_map[app_id] = app.get("name", app_id)

        total = data.get("count", len(batch))
        offset += len(batch)
        print(f"  Applications fetched: {offset}/{total}")
        if offset >= total:
            break

    return app_map


def fetch_all_servers(base_url: str, org_uuid: str, headers: dict) -> List[dict]:
    """Fetch all servers so we can map application -> environments."""
    url = f"{base_url}Contrast/api/ng/{org_uuid}/servers/filter"
    servers: List[dict] = []
    offset = 0
    limit = 100
    payload = {
        "quickFilter": "ALL",
        "tags": [],
        "applicationsIds": [],
        "logLevels": [],
        "serverEnvironments": [],
        "agentVersions": [],
    }

    while True:
        params = {
            "expand": "applications,assess_protect_status_locked",
            "sort": "serverName",
            "offset": offset,
            "limit": limit,
        }

        resp = requests.post(url, headers=headers, params=params, json=payload, timeout=60)
        resp.raise_for_status()

        data = resp.json()
        batch = data.get("servers", [])
        if not batch:
            break

        servers.extend(batch)
        total = data.get("count", len(batch))
        offset += len(batch)
        print(f"  Servers fetched: {offset}/{total}")
        if offset >= total:
            break

    return servers


def build_app_environment_map(servers: List[dict]) -> Dict[str, List[str]]:
    """Return app_id -> sorted unique environments from server associations."""
    app_envs: Dict[str, set] = defaultdict(set)

    for srv in servers:
        env = (srv.get("environment") or "UNKNOWN").upper()
        apps = srv.get("applications") or []
        for app in apps:
            app_id = extract_app_id(app)
            if app_id:
                app_envs[app_id].add(env)

    return {k: sorted(v) for k, v in app_envs.items()}


def fetch_all_libraries(
    base_url: str,
    org_uuid: str,
    headers: dict,
    quick_filter: str,
    page_size: int,
) -> List[dict]:
    """Fetch all libraries with offset/limit pagination."""
    url = f"{base_url}Contrast/api/ng/{org_uuid}/libraries/filter"
    all_libs: List[dict] = []
    offset = 0

    payload = {
        "q": "",
        "quickFilter": quick_filter,
        "apps": [],
        "servers": [],
        "environments": [],
        "grades": [],
        "languages": [],
        "licenses": [],
        "status": [],
        "severities": [],
        "tags": [],
        "includeUnused": False,
        "includeUsed": True,
    }

    current_limit = page_size

    while True:
        params = {
            "expand": "skip_links,apps,quickFilters,vulns,status,usage_counts",
            "offset": offset,
            "limit": current_limit,
            "sort": "score",
        }

        try:
            resp = requests.post(url, headers=headers, params=params, json=payload, timeout=90)
            resp.raise_for_status()
        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else None
            # Some deployments enforce smaller limits than requested.
            if status in (400, 413, 422) and current_limit > 50:
                current_limit = 50
                print("  API rejected requested page size; falling back to limit=50")
                continue
            raise

        data = resp.json()
        batch = data.get("libraries", [])
        total = data.get("count", len(batch))

        if not batch:
            break

        all_libs.extend(batch)
        offset += len(batch)
        print(f"  Libraries fetched: {offset}/{total} (limit={current_limit})")

        if offset >= total:
            break

    return all_libs


def _extract_any(lib: dict, *keys, default=""):
    for key in keys:
        if key in lib and lib[key] is not None:
            return lib[key]
    return default


def _extract_apps_for_library(lib: dict) -> List[Tuple[str, str]]:
    apps = lib.get("apps")
    if not isinstance(apps, list) or not apps:
        return [("", "UNSCOPED")]

    pairs: List[Tuple[str, str]] = []
    for app in apps:
        if not isinstance(app, dict):
            continue
        app_id = extract_app_id(app)
        app_name = extract_app_name(app)
        pairs.append((app_id, app_name))

    return pairs or [("", "UNSCOPED")]


def flatten_library_rows(
    libraries: List[dict],
    app_name_map: Dict[str, str],
    app_env_map: Dict[str, List[str]],
) -> List[dict]:
    """Flatten libraries into CSV-ready rows per library/app/environment."""
    rows: List[dict] = []

    for lib in libraries:
        lib_name = _extract_any(lib, "file_name", "fileName", default="UNKNOWN")
        version = _extract_any(lib, "file_version", "version", default="")
        latest_version = _extract_any(lib, "latest_version", "latestVersion", default="")
        sha1_hash = _extract_any(
            lib,
            "sha1",
            "sha1_hash",
            "sha1Hash",
            "hash",
            "file_hash",
            "fileHash",
            default="",
        )
        score = _extract_any(lib, "score", default="")
        grade = str(_extract_any(lib, "grade", default="")).upper()

        classes_used = int(_extract_any(lib, "classes_used", "classesUsed", default=0) or 0)
        class_count = int(_extract_any(lib, "class_count", "totalClasses", default=0) or 0)
        usage = f"{classes_used}/{class_count}" if class_count else str(classes_used)

        cves = int(
            _extract_any(lib, "total_vulnerabilities", "totalVulnerabilities", default=0)
            or 0
        )

        app_pairs = _extract_apps_for_library(lib)

        for app_id, app_name_from_lib in app_pairs:
            app_name = app_name_map.get(app_id) or app_name_from_lib or "UNSCOPED"
            envs = app_env_map.get(app_id) or ["UNKNOWN"]

            for env in envs:
                rows.append(
                    {
                        "library_name": lib_name,
                        "version": version,
                        "latest_version": latest_version,
                        "sha1_hash": sha1_hash,
                        "cves": cves,
                        "usage": usage,
                        "application": app_name,
                        "application_id": app_id,
                        "environment": env,
                        "score": score,
                        "grade": grade,
                        "classes_used": classes_used,
                        "total_classes": class_count,
                    }
                )

    return rows


def build_markdown(rows: List[dict], generated_at: datetime, quick_filter: str) -> str:
    """Build markdown summary by application and environment."""
    lines: List[str] = []

    unique_libs = {(r["library_name"], r["version"]) for r in rows}
    unique_apps = {r["application"] for r in rows}

    lines.append("# Used OSS by Application and Environment")
    lines.append("")
    lines.append(f"**Generated:** {generated_at.strftime('%Y-%m-%d %H:%M:%S')} UTC  ")
    lines.append(f"**Library quick filter:** {quick_filter}  ")
    lines.append(f"**Total flattened rows:** {len(rows)}  ")
    lines.append(f"**Unique libraries:** {len(unique_libs)}  ")
    lines.append(f"**Applications:** {len(unique_apps)}  ")
    lines.append("")

    # Summary by app + environment
    group: Dict[Tuple[str, str], List[dict]] = defaultdict(list)
    for row in rows:
        group[(row["application"], row["environment"])].append(row)

    lines.append("## Summary by Application and Environment")
    lines.append("")
    lines.append("| Application | Environment | Libraries | Libraries with CVEs | Total CVEs | Avg Score |")
    lines.append("|-------------|-------------|-----------|---------------------|------------|-----------|")

    for (app, env), entries in sorted(group.items()):
        libs = {(e["library_name"], e["version"]) for e in entries}
        libs_with_cves = {
            (e["library_name"], e["version"])
            for e in entries
            if int(e.get("cves", 0) or 0) > 0
        }
        total_cves = sum(int(e.get("cves", 0) or 0) for e in entries)

        scores = [float(e["score"]) for e in entries if str(e.get("score", "")).strip() != ""]
        avg_score = f"{(sum(scores) / len(scores)):.1f}" if scores else "N/A"

        lines.append(
            f"| {app} | {env} | {len(libs)} | {len(libs_with_cves)} | {total_cves} | {avg_score} |"
        )

    # Top libraries per app
    per_app: Dict[str, List[dict]] = defaultdict(list)
    for row in rows:
        per_app[row["application"]].append(row)

    lines.append("")
    lines.append("## Top Libraries per Application")
    lines.append("")

    for app_name in sorted(per_app):
        entries = per_app[app_name]
        lines.append(f"### {app_name}")
        lines.append("")

        lib_rollup: Dict[Tuple[str, str], dict] = {}
        for e in entries:
            key = (e["library_name"], e["version"])
            existing = lib_rollup.get(key)
            if existing is None or int(e.get("cves", 0) or 0) > int(existing.get("cves", 0) or 0):
                lib_rollup[key] = e

        top = sorted(lib_rollup.values(), key=lambda x: (int(x.get("cves", 0) or 0), str(x.get("score", ""))), reverse=True)[:10]

        if not top:
            lines.append("No libraries found.")
            lines.append("")
            continue

        lines.append("| Library | Version | Latest | CVEs | Usage | Score | Environment(s) |")
        lines.append("|---------|---------|--------|------|-------|-------|----------------|")

        env_map: Dict[Tuple[str, str], set] = defaultdict(set)
        for e in entries:
            env_map[(e["library_name"], e["version"])].add(e["environment"])

        for lib in top:
            envs = ", ".join(sorted(env_map[(lib["library_name"], lib["version"])]))
            latest = lib.get("latest_version") or "-"
            lines.append(
                f"| {lib['library_name']} | {lib['version']} | {latest} | {lib['cves']} | {lib['usage']} | {lib['score']} | {envs} |"
            )

        lines.append("")

    return "\n".join(lines)


def write_csv(path: Path, rows: List[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "library_name",
        "version",
        "latest_version",
        "sha1_hash",
        "cves",
        "usage",
        "application",
        "application_id",
        "environment",
        "score",
        "grade",
        "classes_used",
        "total_classes",
    ]

    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_markdown(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate used OSS reports (Markdown + CSV) grouped by application and environment"
    )
    parser.add_argument("--env-file", help="Path to .env file (default: [repo-root]/.env)")
    parser.add_argument(
        "--quick-filter",
        default="ALL",
        help="Library quickFilter value for /libraries/filter (default: ALL)",
    )
    parser.add_argument(
        "--page-size",
        type=int,
        default=250,
        help="Requested page size for /libraries/filter (default: 250)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    repo_root = find_repo_root(Path.cwd())
    env_path = Path(args.env_file) if args.env_file else (repo_root / ".env")

    try:
        creds = load_env_file(env_path)
    except Exception as exc:
        print(f"ERROR loading credentials: {exc}", file=sys.stderr)
        return 1

    base_url = normalize_base_url(creds["TeamserverURL"])
    org_uuid = creds["ORG_UUID"]
    headers = build_headers(creds)

    generated_at = datetime.now(timezone.utc)
    date_stamp = generated_at.strftime("%Y-%m-%d")
    output_dir = Path(__file__).resolve().parent / "Output"
    md_path = output_dir / f"used_oss_by_app_{date_stamp}.md"
    csv_path = output_dir / f"used_oss_by_app_{date_stamp}.csv"

    print("Fetching applications...")
    app_name_map = fetch_all_applications(base_url, org_uuid, headers)

    print("Fetching servers for environment mapping...")
    servers = fetch_all_servers(base_url, org_uuid, headers)
    app_env_map = build_app_environment_map(servers)

    print("Fetching libraries (paginated)...")
    libraries = fetch_all_libraries(
        base_url=base_url,
        org_uuid=org_uuid,
        headers=headers,
        quick_filter=args.quick_filter,
        page_size=max(1, args.page_size),
    )

    print("Flattening rows...")
    rows = flatten_library_rows(
        libraries=libraries,
        app_name_map=app_name_map,
        app_env_map=app_env_map,
    )

    print("Writing CSV...")
    write_csv(csv_path, rows)

    print("Writing Markdown...")
    md_content = build_markdown(rows, generated_at=generated_at, quick_filter=args.quick_filter)
    write_markdown(md_path, md_content)

    print("\nDone.")
    print(f"  Markdown: {md_path}")
    print(f"  CSV     : {csv_path}")
    print(f"  Rows    : {len(rows)}")
    print(f"  Libraries fetched: {len(libraries)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

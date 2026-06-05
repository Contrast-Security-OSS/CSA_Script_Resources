#!/usr/bin/env python3
"""
Generate organization-wide OSS usage reports from Contrast libraries/filter.

Uses TeamServer-provided CVE metadata, including:
- KEV indicator (`cisa`)
- EPSS score (`epss_score`)

Outputs:
- Markdown summary with KEV highlights, CVE inventory by severity, and per-app breakdown
- CSV with one row per library (apps/envs/CVE IDs as pipe-separated values)

Example:
  python3 generate_used_oss_by_app_report.py \
    --env-file .env
"""

import argparse
import csv
import re
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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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


def _extract_cves_for_library(lib: dict) -> List[dict]:
    """Return list of CVE dicts from the vulns expand field.

    Each item has keys: cve_id (str), severity (str), summary (str),
    cisa (bool), epss_score (float).
    Severity is normalized to CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN.
    """
    vulns = lib.get("vulns") or lib.get("vulnerabilities") or []
    if not isinstance(vulns, list):
        return []

    SEV_NORM = {
        "critical": "CRITICAL",
        "high": "HIGH",
        "medium": "MEDIUM",
        "moderate": "MEDIUM",
        "low": "LOW",
        "note": "LOW",
        "info": "LOW",
    }

    results = []
    cve_pattern = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
    for v in vulns:
        if not isinstance(v, dict):
            continue

        # Tenant payloads commonly send CVE in `name`.
        cve_id = (
            v.get("cve")
            or v.get("cveId")
            or v.get("cve_id")
            or v.get("name")
            or ""
        ).strip()
        match = cve_pattern.search(cve_id)
        if match:
            cve_id = match.group(0).upper()

        if not cve_id:
            continue

        raw_sev = str(v.get("severityToUse") or v.get("severity") or v.get("cvss_3_severity_code") or "").lower()
        severity = SEV_NORM.get(raw_sev, "UNKNOWN")
        summary = str(v.get("summary") or v.get("description") or "")

        try:
            epss_score = float(v.get("epss_score", 0) or 0)
        except (TypeError, ValueError):
            epss_score = 0.0

        results.append(
            {
                "cve_id": cve_id,
                "severity": severity,
                "summary": summary,
                "cisa": bool(v.get("cisa", False)),
                "epss_score": epss_score,
            }
        )
    return results


# ---------------------------------------------------------------------------
# Aggregate libraries into one-row-per-library dicts (TeamServer data only)
# ---------------------------------------------------------------------------

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def aggregate_library_rows(
    libraries: List[dict],
    app_name_map: Dict[str, str],
    app_env_map: Dict[str, List[str]],
) -> List[dict]:
    """Return one dict per unique (library_name, version), with TeamServer CVE data only."""

    rollup: Dict[Tuple[str, str], dict] = {}

    for lib in libraries:
        lib_name = _extract_any(lib, "file_name", "fileName", default="UNKNOWN")
        version = _extract_any(lib, "file_version", "version", default="")
        key = (lib_name, version)

        if key not in rollup:
            latest_version = _extract_any(lib, "latest_version", "latestVersion", default="")
            sha1_hash = _extract_any(lib, "sha1", "sha1_hash", "sha1Hash", "hash", "file_hash", "fileHash", default="")
            score = _extract_any(lib, "score", default="")
            grade = str(_extract_any(lib, "grade", default="")).upper()
            classes_used = int(_extract_any(lib, "classes_used", "classesUsed", default=0) or 0)
            class_count = int(_extract_any(lib, "class_count", "totalClasses", default=0) or 0)
            usage = f"{classes_used}/{class_count}" if class_count else str(classes_used)

            rollup[key] = {
                "library_name": lib_name,
                "version": version,
                "latest_version": latest_version,
                "sha1_hash": sha1_hash,
                "score": score,
                "grade": grade,
                "classes_used": classes_used,
                "total_classes": class_count,
                "usage": usage,
                "_app_ids": set(),
                "_app_names": set(),
                "_envs": set(),
                # CVE data: {cve_id: {severity, summary}}
                "_cves": {},
            }

        row = rollup[key]

        # Collect app + environment associations
        for app_id, app_name_from_lib in _extract_apps_for_library(lib):
            resolved_name = app_name_map.get(app_id) or app_name_from_lib or "UNSCOPED"
            row["_app_names"].add(resolved_name)
            if app_id:
                row["_app_ids"].add(app_id)
            for env in app_env_map.get(app_id) or ["UNKNOWN"]:
                row["_envs"].add(env)

        # Collect CVEs
        for cve in _extract_cves_for_library(lib):
            cid = cve["cve_id"]
            if cid not in row["_cves"]:
                row["_cves"][cid] = cve

    # Build final rows
    rows = []
    for row in rollup.values():
        cve_map = row.pop("_cves")
        app_names = sorted(row.pop("_app_names"))
        row.pop("_app_ids")
        envs = sorted(row.pop("_envs"))

        by_sev: Dict[str, List[str]] = defaultdict(list)
        for cve_id, info in cve_map.items():
            by_sev[info["severity"]].append(cve_id)

        for sev in SEVERITY_ORDER:
            by_sev[sev].sort()

        kev_matches = sorted(cid for cid, info in cve_map.items() if bool(info.get("cisa", False)))

        all_cve_ids = list(cve_map.keys())
        epss_pairs = [(cid, float(cve_map[cid].get("epss_score", 0.0))) for cid in all_cve_ids]
        if epss_pairs:
            max_cve, max_epss = max(epss_pairs, key=lambda x: x[1])
        else:
            max_cve, max_epss = "", ""

        row["applications"] = " | ".join(app_names) if app_names else "UNSCOPED"
        row["environments"] = " | ".join(envs) if envs else "UNKNOWN"
        row["total_cves"] = len(cve_map)
        row["critical_count"] = len(by_sev["CRITICAL"])
        row["high_count"] = len(by_sev["HIGH"])
        row["medium_count"] = len(by_sev["MEDIUM"])
        row["low_count"] = len(by_sev["LOW"])
        row["kev_count"] = len(kev_matches)
        row["kev_cves"] = " | ".join(kev_matches)
        row["critical_cve_ids"] = " | ".join(by_sev["CRITICAL"])
        row["high_cve_ids"] = " | ".join(by_sev["HIGH"])
        row["medium_cve_ids"] = " | ".join(by_sev["MEDIUM"])
        row["low_cve_ids"] = " | ".join(by_sev["LOW"])
        row["max_epss_score"] = f"{max_epss:.4f}" if isinstance(max_epss, float) else ""
        row["max_epss_cve"] = max_cve
        # Keep full CVE map for markdown use
        row["_cve_details"] = cve_map
        row["_epss"] = {
            cid: float(info.get("epss_score", 0.0))
            for cid, info in cve_map.items()
        }
        rows.append(row)

    # Sort: KEVs first, then by critical count desc
    rows.sort(key=lambda r: (-r["kev_count"], -r["critical_count"], -r["high_count"], r["library_name"]))
    return rows


# ---------------------------------------------------------------------------
# CSV output
# ---------------------------------------------------------------------------

CSV_FIELDS = [
    "library_name",
    "version",
    "latest_version",
    "sha1_hash",
    "score",
    "grade",
    "usage",
    "classes_used",
    "total_classes",
    "applications",
    "environments",
    "total_cves",
    "critical_count",
    "high_count",
    "medium_count",
    "low_count",
    "kev_count",
    "kev_cves",
    "critical_cve_ids",
    "high_cve_ids",
    "medium_cve_ids",
    "low_cve_ids",
    "max_epss_score",
    "max_epss_cve",
]


def write_csv(path: Path, rows: List[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


# ---------------------------------------------------------------------------
# Markdown output
# ---------------------------------------------------------------------------

def _fmt_epss(score: float) -> str:
    if not isinstance(score, float):
        return "-"
    pct = score * 100
    return f"{pct:.1f}%"


def build_markdown(
    rows: List[dict],
    generated_at: datetime,
    quick_filter: str,
) -> str:
    lines: List[str] = []

    total_libs = len(rows)
    total_cves = sum(r["total_cves"] for r in rows)
    total_critical = sum(r["critical_count"] for r in rows)
    total_high = sum(r["high_count"] for r in rows)
    total_medium = sum(r["medium_count"] for r in rows)
    total_low = sum(r["low_count"] for r in rows)
    total_kev = sum(r["kev_count"] for r in rows)
    unique_apps: set = set()
    for r in rows:
        for a in r["applications"].split(" | "):
            unique_apps.add(a.strip())
    unique_apps.discard("UNSCOPED")

    lines += [
        "# OSS Inventory — CVE & KEV Report",
        "",
        f"**Generated:** {generated_at.strftime('%Y-%m-%d %H:%M:%S')} UTC  ",
        f"**Library filter:** {quick_filter}  ",
        f"**Unique libraries:** {total_libs}  ",
        f"**Applications:** {len(unique_apps)}  ",
        f"**Total CVEs:** {total_cves} "
        f"(Critical: {total_critical} | High: {total_high} | Medium: {total_medium} | Low: {total_low})  ",
        f"**CISA KEV matches:** {total_kev}  ",
        "",
        "> CVE severity sourced from Contrast Security. "
        "EPSS and KEV indicators are sourced from TeamServer library vulnerability data.",
        "",
    ]

    # ------------------------------------------------------------------
    # 1. CISA KEV Section
    # ------------------------------------------------------------------
    kev_rows = [r for r in rows if r["kev_count"] > 0]
    lines += ["## 🚨 CISA Known Exploited Vulnerabilities (KEV)", ""]
    if not kev_rows:
        lines += ["No libraries with CISA KEV entries found.", ""]
    else:
        lines += [
            f"**{sum(r['kev_count'] for r in kev_rows)} KEV CVEs across {len(kev_rows)} libraries.**",
            "",
            "| Library | Version | KEV CVEs | Max EPSS | Applications |",
            "|---------|---------|----------|----------|--------------|",
        ]
        for r in kev_rows:
            kev_list = r["kev_cves"].replace(" | ", ", ")
            epss_disp = _fmt_epss(float(r["max_epss_score"])) if r["max_epss_score"] else "-"
            apps_short = r["applications"][:80] + ("…" if len(r["applications"]) > 80 else "")
            lines.append(
                f"| {r['library_name']} | {r['version']} | {kev_list} | {epss_disp} | {apps_short} |"
            )
        lines.append("")

    # ------------------------------------------------------------------
    # 2. CVE Inventory by Severity
    # ------------------------------------------------------------------
    lines += ["## CVE Inventory by Severity", ""]

    # Build a flat CVE -> {severity, epss, kev, libraries, apps} map
    kev_set = {c for r in rows for c in r.get("kev_cves", "").split(" | ") if c}
    cve_index: Dict[str, dict] = {}
    for r in rows:
        cve_details = r.get("_cve_details", {})
        epss_map = r.get("_epss", {})
        for cve_id, info in cve_details.items():
            if cve_id not in cve_index:
                cve_index[cve_id] = {
                    "severity": info["severity"],
                    "summary": info["summary"],
                    "epss": epss_map.get(cve_id, 0.0),
                    "kev": cve_id in kev_set or bool(info.get("cisa", False)),
                    "libraries": [],
                    "apps": set(),
                }
            entry = cve_index[cve_id]
            entry["libraries"].append(f"{r['library_name']} {r['version']}")
            for a in r["applications"].split(" | "):
                entry["apps"].add(a.strip())

    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        tier = {cid: info for cid, info in cve_index.items() if info["severity"] == severity}
        if not tier:
            continue

        emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}[severity]
        lines += [
            f"### {emoji} {severity} ({len(tier)})",
            "",
            "| CVE | EPSS | KEV | Affected Libraries | Affected Applications |",
            "|-----|------|-----|--------------------|-----------------------|",
        ]
        # Sort by EPSS descending within each severity tier
        for cve_id, info in sorted(tier.items(), key=lambda x: x[1]["epss"], reverse=True):
            epss_disp = _fmt_epss(info["epss"])
            kev_flag = "✅ YES" if info["kev"] else "No"
            lib_list = ", ".join(sorted(set(info["libraries"])))[:80]
            app_list = ", ".join(sorted(info["apps"]))[:80]
            lines.append(f"| {cve_id} | {epss_disp} | {kev_flag} | {lib_list} | {app_list} |")
        lines.append("")

    # ------------------------------------------------------------------
    # 3. Summary by Application
    # ------------------------------------------------------------------
    lines += ["## Library Summary by Application", ""]

    # Invert: app -> list of library rows
    app_to_libs: Dict[str, List[dict]] = defaultdict(list)
    for r in rows:
        for app in r["applications"].split(" | "):
            app = app.strip()
            if app:
                app_to_libs[app].append(r)

    lines += [
        "| Application | Libraries | Total CVEs | Critical | High | KEVs |",
        "|-------------|-----------|------------|----------|------|------|",
    ]
    for app in sorted(app_to_libs):
        entries = app_to_libs[app]
        num_libs = len(entries)
        t_cves = sum(e["total_cves"] for e in entries)
        t_crit = sum(e["critical_count"] for e in entries)
        t_high = sum(e["high_count"] for e in entries)
        t_kev = sum(e["kev_count"] for e in entries)
        lines.append(f"| {app} | {num_libs} | {t_cves} | {t_crit} | {t_high} | {t_kev} |")
    lines.append("")

    # ------------------------------------------------------------------
    # 4. Top Libraries per Application (priority-sorted)
    # ------------------------------------------------------------------
    lines += ["## Top Libraries per Application", ""]

    for app in sorted(app_to_libs):
        entries = app_to_libs[app]
        lines += [f"### {app}", ""]

        # Sort: KEVs → critical → high → library name
        top = sorted(
            entries,
            key=lambda r: (-r["kev_count"], -r["critical_count"], -r["high_count"], r["library_name"]),
        )[:15]

        lines += [
            "| Library | Version | Latest | Critical | High | Med | Low | KEVs | Max EPSS |",
            "|---------|---------|--------|----------|------|-----|-----|------|----------|",
        ]
        for lib in top:
            latest = lib.get("latest_version") or "-"
            epss_disp = _fmt_epss(float(lib["max_epss_score"])) if lib["max_epss_score"] else "-"
            kev_disp = str(lib["kev_count"]) if lib["kev_count"] > 0 else "-"
            lines.append(
                f"| {lib['library_name']} | {lib['version']} | {latest} "
                f"| {lib['critical_count']} | {lib['high_count']} "
                f"| {lib['medium_count']} | {lib['low_count']} "
                f"| {kev_disp} | {epss_disp} |"
            )
        lines.append("")

    return "\n".join(lines)


def write_markdown(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate OSS CVE/KEV reports (Markdown + CSV) per library"
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

    print("Aggregating library rows...")
    rows = aggregate_library_rows(
        libraries=libraries,
        app_name_map=app_name_map,
        app_env_map=app_env_map,
    )

    print("Writing CSV...")
    write_csv(csv_path, rows)

    print("Writing Markdown...")
    md_content = build_markdown(rows, generated_at=generated_at, quick_filter=args.quick_filter)
    write_markdown(md_path, md_content)

    kev_lib_count = sum(1 for r in rows if r["kev_count"] > 0)
    total_cve_count = sum(r["total_cves"] for r in rows)

    print("\nDone.")
    print(f"  Markdown : {md_path}")
    print(f"  CSV      : {csv_path}")
    print(f"  Libraries: {len(rows)}")
    print(f"  CVEs     : {total_cve_count}")
    print(f"  KEV libs : {kev_lib_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

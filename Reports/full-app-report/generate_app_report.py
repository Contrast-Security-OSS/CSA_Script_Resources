#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Contrast Security Full Application IAST Assessment Report Generator

Generates a comprehensive security assessment report covering all aspects of an
IAST program for one or more applications:

  - Custom code vulnerabilities (open by severity + MTTR on closed)
  - OSS / library risk (critical libraries with class-usage data)
  - Route coverage & staleness (possibly-remediated detection)
  - Server & agent health (version compliance against best-practice minimums)

Run with no arguments for a fully guided experience:

    python generate_app_report.py

Or pass flags to skip prompts:

    python generate_app_report.py --env-file .env --tag "my-tag"
    python generate_app_report.py --env-file .env --app-name "MyApp"
    python generate_app_report.py --env-file .env --output report.md

Options
-------
  --env-file PATH       .env file path (default: .env)
  --tag TAG             Filter apps by tag instead of picking interactively
  --app-name NAME       Select a single app by name instead of picking interactively
  --output PATH         Write report to PATH instead of stdout
  --days N              Closed-vuln / MTTR lookback window (default 365)
  --skip-staleness      Skip route-staleness analysis (faster)
  --skip-servers        Skip server / agent-version fetch (faster)
"""

import argparse
import base64
import json
import re
import sys
import requests
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Logo paths (bundled alongside this script)
# ---------------------------------------------------------------------------
_SCRIPT_DIR = Path(__file__).parent
_LOGO_DARK_PATH  = _SCRIPT_DIR / "logos" / "CS_logo_RGB_reverse.png"   # white logo for dark bg
_LOGO_LIGHT_PATH = _SCRIPT_DIR / "logos" / "CS_logo_RGB_color.png"     # color logo for light bg


def _logo_b64(path: Path) -> str:
    """Return a base64 data-URI for the given image, or empty string if not found."""
    try:
        data = path.read_bytes()
        return "data:image/png;base64," + base64.b64encode(data).decode()
    except Exception:
        return ""

# ---------------------------------------------------------------------------
# Best-practice minimum agent versions for production Assess deployment
# Source: Contrast Security CSA best practices
# ---------------------------------------------------------------------------
MINIMUM_PRODUCTION_VERSIONS: Dict[str, str] = {
    "Java": "6.6.0",
    "Node.js": "5.20.0",
    "Python": "9.4.0",
    ".NET Core": "4.3.0",
    ".NET Framework": "51.1.0",
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NOTE"]


# ===========================================================================
# Credential helpers
# ===========================================================================

def find_repo_root(start: Path) -> Path:
    current = start.resolve()
    for candidate in [current, *current.parents]:
        if (candidate / "notebooks").exists() and (candidate / "README.md").exists():
            return candidate
    return current


def load_root_credentials(env_path: Path) -> dict:
    """Load credentials from flat root .env."""
    if not env_path.exists():
        raise FileNotFoundError(f".env file not found: {env_path}")

    cfg: dict = {}
    current_section: Optional[str] = None

    with open(env_path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("[") and line.endswith("]"):
                current_section = line[1:-1].strip()
                continue
            if "=" not in line:
                continue

            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")

            if current_section is None:
                cfg[key] = value

    normalized = {
        "TeamserverURL": cfg.get("TEAMSERVER_URL") or cfg.get("TeamserverURL") or cfg.get("url"),
        "ORG_UUID": cfg.get("ORG_UUID") or cfg.get("organizationId"),
        "AUTH": cfg.get("CONTRAST_AUTH") or cfg.get("AUTH") or cfg.get("authHeader"),
        "API_KEY": cfg.get("CONTRAST_API_KEY") or cfg.get("API_KEY") or cfg.get("apiKey"),
    }

    required = ["TeamserverURL", "ORG_UUID", "AUTH", "API_KEY"]
    missing = [k for k in required if not normalized.get(k)]
    if missing:
        raise ValueError(f"Missing required env keys in {env_path}: {', '.join(missing)}")

    return normalized


def build_headers(creds: dict) -> dict:
    return {
        "Authorization": creds["AUTH"],
        "API-Key": creds["API_KEY"],
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def normalise_base_url(raw: str) -> str:
    """Ensure base URL ends with a single trailing slash."""
    return raw.rstrip("/") + "/"


# ===========================================================================
# Application listing & selection
# ===========================================================================

def fetch_all_applications(base_url: str, org_uuid: str, headers: dict) -> List[dict]:
    """Return all licensed, non-archived applications."""
    url = f"{base_url}Contrast/api/ng/{org_uuid}/applications"
    apps: List[dict] = []
    offset = 0
    limit = 100

    while True:
        params = {
            "includeOnlyLicensed": "true",
            "includeArchived": "false",
            "offset": offset,
            "limit": limit,
        }
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        batch = data.get("applications", [])
        apps.extend(batch)
        total = data.get("count", len(batch))
        offset += len(batch)
        if offset >= total or not batch:
            break

    # Normalise app_id field
    for app in apps:
        if "app_id" not in app and "appID" in app:
            app["app_id"] = app["appID"]

    return apps


def filter_apps_by_tag(apps: List[dict], tag: str) -> List[dict]:
    tag_lower = tag.lower()
    return [
        a for a in apps
        if tag_lower in [t.lower() for t in a.get("tags", [])]
    ]


def interactive_app_selection(apps: List[dict]) -> List[dict]:
    """
    Present a numbered list of applications grouped by tag.
    User enters comma-separated numbers (or 'all') to select apps.
    """
    # Build display
    print("\n" + "=" * 70)
    print("  APPLICATION SELECTION")
    print("=" * 70)

    # Gather all tags for quick overview
    all_tags: dict = defaultdict(list)
    for app in apps:
        for t in app.get("tags", []):
            all_tags[t].append(app["name"])

    if all_tags:
        print("\nAvailable tags:")
        for tag, tag_apps in sorted(all_tags.items()):
            print(f"  [{tag}] — {len(tag_apps)} app(s): {', '.join(tag_apps[:5])}"
                  + (" ..." if len(tag_apps) > 5 else ""))

    print("\nAll applications:")
    for i, app in enumerate(apps, 1):
        tags_str = ", ".join(app.get("tags", [])) or "(no tags)"
        status = app.get("status", "unknown").upper()
        lang = app.get("language", "?")
        print(f"  [{i:>3}]  {app['name']:<45}  {lang:<12}  {status:<8}  tags: {tags_str}")

    print("\nEnter selection:")
    print("  • Numbers: 1,3,5-7")
    print("  • Tag name: tag:my-tag")
    print("  • All: all")
    print()

    while True:
        raw = input("Selection > ").strip()
        if not raw:
            continue

        selected: List[dict] = []

        if raw.lower() == "all":
            return apps

        if raw.lower().startswith("tag:"):
            tag_name = raw[4:].strip()
            selected = filter_apps_by_tag(apps, tag_name)
            if not selected:
                print(f"  No apps found with tag '{tag_name}'. Try again.")
                continue
            return selected

        # Parse numbers / ranges
        indices: List[int] = []
        valid = True
        for part in raw.replace(" ", "").split(","):
            if "-" in part:
                try:
                    lo, hi = part.split("-", 1)
                    indices.extend(range(int(lo) - 1, int(hi)))
                except ValueError:
                    valid = False
                    break
            else:
                try:
                    indices.append(int(part) - 1)
                except ValueError:
                    valid = False
                    break

        if not valid:
            print("  Invalid input. Use numbers like: 1,3,5-7  or  tag:MyTag  or  all")
            continue

        selected = [apps[i] for i in indices if 0 <= i < len(apps)]
        if not selected:
            print("  No valid apps selected. Try again.")
            continue

        return selected


# ===========================================================================
# Vulnerability helpers
# ===========================================================================

def fetch_vulnerabilities(
    base_url: str,
    org_uuid: str,
    headers: dict,
    app_id: str,
    statuses: List[str],
    since_ms: Optional[int] = None,
    is_closed: bool = False,
) -> List[dict]:
    """Paginate through /traces/{app_id}/filter for given statuses."""
    url = f"{base_url}Contrast/api/ng/{org_uuid}/traces/{app_id}/filter"
    all_vulns: List[dict] = []
    offset = 0
    limit = 100

    while True:
        params: dict = {
            "expand": "application",
            "status": ",".join(statuses),
            "offset": offset,
            "limit": limit,
        }
        # For open vulns we can filter server-side by first_time_seen
        if since_ms and not is_closed:
            params["timestampFilter"] = "FIRST"
            params["startDate"] = since_ms

        resp = requests.get(url, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        batch = data.get("traces", [])
        all_vulns.extend(batch)
        total = data.get("count", 0)
        offset += len(batch)
        if offset >= total or not batch:
            break

    # For closed vulns, manually filter by closed_time
    if since_ms and is_closed:
        all_vulns = [
            v for v in all_vulns
            if (v.get("closed_time") or v.get("closedTime") or 0) >= since_ms
        ]

    return all_vulns


# ===========================================================================
# MTTR helper
# ===========================================================================

def calculate_mttr(closed_vulns: List[dict]) -> Dict[str, Optional[float]]:
    """Return overall + per-severity MTTR (days) from closed vulnerabilities."""
    severity_times: Dict[str, List[float]] = {s: [] for s in SEVERITY_ORDER}
    all_times: List[float] = []

    for v in closed_vulns:
        first = v.get("first_time_seen")
        closed = v.get("closed_time") or v.get("closedTime")
        if not first or not closed:
            continue
        try:
            if isinstance(first, (int, float)):
                first_dt = datetime.fromtimestamp(first / 1000, tz=timezone.utc)
            else:
                first_dt = datetime.fromisoformat(str(first).replace("Z", "+00:00"))
            if isinstance(closed, (int, float)):
                closed_dt = datetime.fromtimestamp(closed / 1000, tz=timezone.utc)
            else:
                closed_dt = datetime.fromisoformat(str(closed).replace("Z", "+00:00"))
            days = (closed_dt - first_dt).total_seconds() / 86400
            if days >= 0:
                all_times.append(days)
                sev = v.get("severity", "").upper()
                if sev in severity_times:
                    severity_times[sev].append(days)
        except Exception:
            continue

    result: Dict[str, Optional[float]] = {
        "overall": sum(all_times) / len(all_times) if all_times else None
    }
    for sev, times in severity_times.items():
        result[sev] = sum(times) / len(times) if times else None
    return result


# ===========================================================================
# Route coverage
# ===========================================================================

def fetch_route_coverage(
    base_url: str, org_uuid: str, headers: dict, app_id: str
) -> dict:
    """Return route coverage summary for one application."""
    url = f"{base_url}Contrast/api/ng/{org_uuid}/applications/{app_id}/route"
    try:
        resp = requests.get(url, headers=headers, params={"limit": 2000}, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        routes = data.get("routes", [])
        total = len(routes)
        exercised = sum(1 for r in routes if r.get("exercised"))
        with_vulns = sum(1 for r in routes if r.get("vulnerabilities", 0) > 0)
        pct = (exercised / total * 100) if total else 0.0
        return {
            "total": total,
            "exercised": exercised,
            "unexercised": total - exercised,
            "with_vulns": with_vulns,
            "coverage_pct": pct,
        }
    except Exception as exc:
        print(f"  Warning: Could not fetch route coverage: {exc}", file=sys.stderr)
        return {"total": 0, "exercised": 0, "unexercised": 0, "with_vulns": 0, "coverage_pct": 0.0}


# ===========================================================================
# Route staleness
# ===========================================================================

def fetch_vulnerable_routes(
    base_url: str, org_uuid: str, headers: dict, app_id: str
) -> List[dict]:
    url = f"{base_url}Contrast/api/ng/{org_uuid}/applications/{app_id}/route"
    routes: List[dict] = []
    offset = 0
    limit = 100
    while True:
        params = {"quickFilter": "VULNERABLE", "offset": offset, "limit": limit}
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        batch = data.get("routes", [])
        routes.extend(batch)
        total = data.get("count", 0)
        offset += len(batch)
        if offset >= total or not batch:
            break
    return routes


def fetch_vulns_for_route(
    base_url: str, org_uuid: str, headers: dict, app_id: str, route_hash: str
) -> List[dict]:
    url = f"{base_url}Contrast/api/ng/{org_uuid}/traces/{app_id}/filter"
    traces: List[dict] = []
    offset = 0
    limit = 100
    while True:
        params = {
            "expand": "application",
            "routes": route_hash,
            "status": "Reported",
            "offset": offset,
            "limit": limit,
        }
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        batch = data.get("traces", [])
        traces.extend(batch)
        total = data.get("count", 0)
        offset += len(batch)
        if offset >= total or not batch:
            break
    return traces


def _parse_ts(ts) -> Optional[datetime]:
    if ts is None:
        return None
    try:
        if isinstance(ts, (int, float)):
            return datetime.fromtimestamp(ts / 1000, tz=timezone.utc)
        s = str(ts).strip().replace("Z", "+00:00")
        return datetime.fromisoformat(s) if s else None
    except Exception:
        return None


def _fmt_ts(dt: Optional[datetime]) -> str:
    return dt.strftime("%Y-%m-%d %H:%M UTC") if dt else "unknown"


def _days_ago(dt: Optional[datetime]) -> Optional[int]:
    if dt is None:
        return None
    return (datetime.now(tz=timezone.utc) - dt).days


def analyse_staleness(
    base_url: str, org_uuid: str, headers: dict, app_id: str
) -> dict:
    """Return staleness analysis dict for an application."""
    routes = fetch_vulnerable_routes(base_url, org_uuid, headers, app_id)
    candidate_routes = [r for r in routes if r.get("status") == "EXERCISED"]
    findings: List[dict] = []

    for route in candidate_routes:
        route_hash = route.get("route_hash_string", "")
        last_exercised = _parse_ts(route.get("exercised"))
        if not route_hash:
            continue
        for trace in fetch_vulns_for_route(
            base_url, org_uuid, headers, app_id, route_hash
        ):
            last_detected = _parse_ts(
                trace.get("last_time_seen") or trace.get("lastSeenAt")
            )
            stale = False
            days_stale = None
            if last_exercised and last_detected and last_exercised > last_detected:
                stale = True
                days_stale = (last_exercised - last_detected).days
            findings.append(
                {
                    "signature": route.get("signature", "unknown"),
                    "vuln_uuid": trace.get("uuid", ""),
                    "vuln_title": trace.get("title", ""),
                    "rule_name": trace.get("rule_name", ""),
                    "severity": trace.get("severity", "UNKNOWN"),
                    "last_exercised": last_exercised,
                    "last_detected": last_detected,
                    "stale": stale,
                    "days_stale": days_stale,
                }
            )

    stale_count = sum(1 for f in findings if f["stale"])
    return {
        "total_routes": len(candidate_routes),
        "total_vulns": len(findings),
        "possibly_remediated": stale_count,
        "findings": findings,
    }


# ===========================================================================
# Library risk
# ===========================================================================

def fetch_critical_libraries(
    base_url: str, org_uuid: str, headers: dict, app_id: str
) -> List[dict]:
    """Return critical-severity libraries with class-usage data for an app."""
    url = f"{base_url}Contrast/api/ng/{org_uuid}/libraries/filter"
    libs: List[dict] = []
    offset = 0
    limit = 50

    try:
        while True:
            params = {
                "expand": "skip_links,apps,quickFilters,vulns,status,usage_counts",
                "offset": offset,
                "limit": limit,
                "sort": "score",
            }
            body = {
                "q": "",
                "quickFilter": "VULNERABLE",
                "apps": [app_id],
                "servers": [],
                "environments": [],
                "grades": [],
                "languages": [],
                "licenses": [],
                "status": [],
                "severities": ["CRITICAL", "HIGH"],
                "tags": [],
                "includeUnused": False,
                "includeUsed": True,
            }
            resp = requests.post(
                url, headers=headers, params=params, json=body, timeout=30
            )
            resp.raise_for_status()
            data = resp.json()
            batch = data.get("libraries", [])
            libs.extend(batch)
            total = data.get("count", len(batch))
            offset += len(batch)
            if offset >= total or not batch:
                break

        grade_order = {"F": 0, "D": 1, "C": 2, "B": 3, "A": 4}
        result = []
        for lib in libs:
            classes_used = lib.get("classes_used", 0) or lib.get("classesUsed", 0)
            grade = lib.get("grade", "").upper()
            result.append(
                {
                    "name": lib.get("file_name") or lib.get("fileName", "Unknown"),
                    "version": lib.get("file_version") or lib.get("version", "Unknown"),
                    "grade": grade,
                    "classes_used": classes_used,
                    "total_classes": lib.get("class_count") or lib.get("totalClasses", 0),
                    "cve_count": lib.get("total_vulnerabilities")
                    or lib.get("totalVulnerabilities", 0),
                    "latest_version": lib.get("latest_version", ""),
                }
            )
        result.sort(key=lambda x: (grade_order.get(x["grade"], 5), -x["classes_used"]))
        return result
    except Exception as exc:
        print(f"  Warning: Could not fetch libraries: {exc}", file=sys.stderr)
        return []


# ===========================================================================
# Server & agent version helpers
# ===========================================================================

def fetch_servers_for_app(
    base_url: str, org_uuid: str, headers: dict, app_id: str
) -> List[dict]:
    """Return all servers associated with a specific application."""
    url = f"{base_url}Contrast/api/ng/{org_uuid}/servers/filter"
    servers: List[dict] = []
    offset = 0
    limit = 100

    payload = {
        "quickFilter": "ALL",
        "tags": [],
        "applicationsIds": [app_id],
        "logLevels": [],
        "serverEnvironments": [],
        "agentVersions": [],
    }

    try:
        while True:
            params = {
                "expand": "applications,assess_protect_status_locked",
                "sort": "serverName",
                "offset": offset,
                "limit": limit,
            }
            resp = requests.post(
                url, headers=headers, params=params, json=payload, timeout=30
            )
            resp.raise_for_status()
            data = resp.json()
            batch = data.get("servers", [])
            servers.extend(batch)
            total = data.get("count", 0)
            offset += len(batch)
            if offset >= total or not batch:
                break
        return servers
    except Exception as exc:
        print(f"  Warning: Could not fetch servers: {exc}", file=sys.stderr)
        return []


def _parse_version(v: str) -> Tuple[int, ...]:
    """Parse a version string into a comparable tuple."""
    try:
        return tuple(int(p) for p in str(v).split(".") if p.isdigit())
    except Exception:
        return (0,)


def _normalize_version(v: str) -> str:
    """Strip trailing .0 segments beyond the third position (e.g. '51.5.3.0' -> '51.5.3')."""
    if not v:
        return v
    parts = v.split(".")
    while len(parts) > 3 and parts[-1] == "0":
        parts.pop()
    return ".".join(parts)


# Language key normalisation map (API values -> JSON keys)
_LANG_MAP = {
    "java": "Java",
    "node": "Node",
    "node.js": "Node",
    "javascript": "Node",
    "python": "Python",
    ".net": ".NET Core",
    ".net core": ".NET Core",
    ".net framework": ".NET Framework",
    "dotnet": ".NET Core",
    "dotnetcore": ".NET Core",
    "ruby": "Ruby",
}

# Default path for agent version reference data (relative to this script)
_DEFAULT_VERSION_REF = Path(__file__).parent / "contrast_agent_versions.json"


def load_version_reference(ref_path: Optional[Path] = None) -> dict:
    """
    Load agent version reference JSON.  Falls back to the bundled file next
    to this script.  Returns an empty dict if the file cannot be found.
    """
    path = ref_path or _DEFAULT_VERSION_REF
    if not path.exists():
        print(
            f"  Warning: Agent version reference not found at {path}. "
            "Compliance checks will be skipped.",
            file=sys.stderr,
        )
        return {}
    with open(path) as fh:
        return json.load(fh)


def check_agent_compliance(
    agent_version: str, language: str, reference_data: dict
) -> dict:
    """
    Check whether an agent version meets the CSA best practice:
      COMPLIANT if within top-3 versions OR within 3 months of the latest release.

    Falls back to the hardcoded minimum-version check when no reference data
    is available for the language.
    """
    lang_key = _LANG_MAP.get(language.lower(), language)
    lang_data = reference_data.get("languages", {}).get(lang_key) if reference_data else None

    # ---- Reference-data path (preferred) ----
    if lang_data:
        norm_agent = _normalize_version(agent_version)

        # Locate this version in the reference list
        version_info = next(
            (v for v in lang_data["versions"]
             if _normalize_version(v["version"]) == norm_agent),
            None,
        )

        if not version_info:
            # Version not in the reference list at all
            latest = lang_data["latest_version"]
            return {
                "compliant": False,
                "status": "UNKNOWN_VERSION",
                "latest_version": latest,
                "versions_behind": "?",
                "age_days": "?",
                "message": f"{agent_version} not found in reference data — update to {latest}",
                "recommendation": f"Update to {latest}",
            }

        # top-3 check
        top_3_norm = [_normalize_version(v) for v in lang_data["top_3_versions"]]
        in_top_3 = norm_agent in top_3_norm

        # 3-month check
        latest_date = datetime.fromisoformat(lang_data["latest_release_date"])
        version_date = datetime.fromisoformat(version_info["release_date"])
        age_days = (latest_date - version_date).days
        within_3_months = age_days <= 90

        compliant = in_top_3 or within_3_months

        # How many positions back is this version?
        versions_behind = next(
            (i for i, v in enumerate(lang_data["versions"])
             if _normalize_version(v["version"]) == norm_agent),
            len(lang_data["versions"]),
        )

        latest = lang_data["latest_version"]
        if compliant:
            reason = "top-3" if in_top_3 else "within 3 months"
            msg = f"{agent_version} is compliant ({reason})"
        else:
            msg = (
                f"{agent_version} is NON-COMPLIANT — "
                f"{versions_behind} version(s) behind, {age_days} days old — "
                f"update to {latest}"
            )

        return {
            "compliant": compliant,
            "status": "COMPLIANT" if compliant else "NON-COMPLIANT",
            "latest_version": latest,
            "versions_behind": versions_behind,
            "age_days": age_days,
            "in_top_3": in_top_3,
            "within_3_months": within_3_months,
            "message": msg,
            "recommendation": "Up to date" if compliant else f"Update to {latest}",
        }

    # ---- Fallback: hardcoded minimum version only ----
    minimum = MINIMUM_PRODUCTION_VERSIONS.get(lang_key)
    if not minimum:
        return {
            "compliant": True,
            "status": "NO_DATA",
            "message": f"No reference data for {language}",
            "versions_behind": "N/A",
            "age_days": "N/A",
            "latest_version": "N/A",
            "recommendation": "N/A",
        }

    current = _parse_version(agent_version)
    minver = _parse_version(minimum)
    compliant = current >= minver
    return {
        "compliant": compliant,
        "status": "PASS" if compliant else "FAIL",
        "message": (
            f"{agent_version} meets hardcoded minimum {minimum}"
            if compliant
            else f"{agent_version} is below hardcoded minimum {minimum}"
        ),
        "versions_behind": "N/A",
        "age_days": "N/A",
        "latest_version": "N/A",
        "recommendation": f"Update to at least {minimum}" if not compliant else "N/A",
    }


def summarise_servers(
    servers: List[dict], app_language: str, version_reference: dict
) -> dict:
    """Return a structured summary of server/agent health."""
    if not servers:
        return {"count": 0, "online": 0, "offline": 0, "agents": [], "compliance_issues": []}

    online = sum(1 for s in servers if s.get("status") == "ONLINE")
    offline = len(servers) - online

    agents = []
    compliance_issues = []

    for srv in servers:
        name = srv.get("name") or srv.get("serverName", "Unknown")
        env = srv.get("environment", "UNKNOWN")
        version = srv.get("agent_version") or srv.get("agentVersion", "Unknown")
        status = srv.get("status", "UNKNOWN")
        lang = srv.get("language") or app_language or "Unknown"

        comp = check_agent_compliance(version, lang, version_reference)
        agents.append(
            {
                "name": name,
                "environment": env,
                "status": status,
                "language": lang,
                "agent_version": version,
                "compliant": comp["compliant"],
                "compliance_msg": comp["message"],
                "latest_version": comp.get("latest_version", "N/A"),
                "versions_behind": comp.get("versions_behind", "N/A"),
                "age_days": comp.get("age_days", "N/A"),
                "recommendation": comp.get("recommendation", ""),
            }
        )
        if not comp["compliant"] and version not in ("Unknown", ""):
            compliance_issues.append(
                {"server": name, "version": version, "language": lang,
                 "issue": comp["message"], "recommendation": comp.get("recommendation", "")}
            )

    return {
        "count": len(servers),
        "online": online,
        "offline": offline,
        "agents": agents,
        "compliance_issues": compliance_issues,
    }


# ===========================================================================
# Report renderer
# ===========================================================================

def _pct(part: int, total: int) -> str:
    if total == 0:
        return "0.0%"
    return f"{part / total * 100:.1f}%"


_CSS = """
<style>
  /* Contrast Security Brand — v1 Feb 2025
     Primary:   Emerald Green #38B885 | Charcoal Black #181818 | White #FFFFFF
     Secondary: Teal Blue #005A70 | Dark Cyan #083C5A | Deep Navy #1C2343
     Accent:    Light Gray #F3F3F3
  */
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
    font-size: 11px;
    color: #181818;
    background: #fff;
    line-height: 1.5;
  }

  /* Cover page */
  .cs-cover {
    background: #083C5A;
    color: #fff;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    padding: 60px 72px;
    page-break-after: always;
  }
  .cs-cover-logo { margin-bottom: 64px; }
  .cs-cover-logo img { height: 52px; }
  .cs-cover-accent {
    width: 64px; height: 4px;
    background: #38B885;
    margin-bottom: 32px;
  }
  .cs-cover-customer {
    font-size: 38px;
    font-weight: 700;
    color: #fff;
    margin-bottom: 12px;
    line-height: 1.15;
  }
  .cs-cover-subtitle {
    font-size: 18px;
    font-weight: 300;
    color: rgba(255,255,255,0.80);
    margin-bottom: 8px;
  }
  .cs-cover-scope {
    font-size: 13px;
    color: rgba(255,255,255,0.65);
    margin-top: 8px;
  }
  .cs-cover-footer {
    margin-top: auto;
    padding-top: 24px;
    border-top: 1px solid rgba(255,255,255,0.20);
    font-size: 10px;
    color: rgba(255,255,255,0.55);
  }

  /* Report body */
  .cs-body { padding: 48px 72px; }

  h1 {
    font-size: 22px;
    font-weight: 700;
    color: #181818;
    border-bottom: 3px solid #38B885;
    padding-bottom: 8px;
    margin-top: 36px;
    margin-bottom: 12px;
  }
  h2 {
    font-size: 16px;
    font-weight: 700;
    color: #181818;
    border-bottom: 2px solid #38B885;
    padding-bottom: 6px;
    margin-top: 32px;
    margin-bottom: 10px;
  }
  h3 {
    font-size: 13px;
    font-weight: 600;
    color: #005A70;
    margin-top: 22px;
    margin-bottom: 8px;
  }
  h4 {
    font-size: 11px;
    font-weight: 600;
    color: #181818;
    margin-top: 16px;
    margin-bottom: 6px;
  }

  table {
    border-collapse: collapse;
    width: 100%;
    margin: 12px 0;
    font-size: 10px;
  }
  th {
    background: #005A70;
    color: #fff;
    padding: 6px 10px;
    text-align: left;
    font-weight: 600;
    font-size: 10px;
  }
  td {
    padding: 5px 10px;
    border-bottom: 1px solid #e8e8e8;
    color: #181818;
  }
  tr:nth-child(even) td { background: #F3F3F3; }

  hr { border: none; border-top: 2px solid #38B885; margin: 28px 0; }
  code {
    background: #F3F3F3;
    padding: 1px 5px;
    border-radius: 3px;
    font-size: 10px;
    font-family: 'Courier New', monospace;
  }
  pre {
    background: #F3F3F3;
    padding: 12px;
    border-radius: 4px;
    overflow-x: auto;
    border-left: 3px solid #38B885;
  }
  em { color: #555; }
  strong { color: #181818; font-weight: 600; }
  p { margin: 6px 0; }
  ul, ol { margin: 6px 0 6px 20px; }
  li { margin: 2px 0; }

  @media print {
    h1, h2, h3 { page-break-after: avoid; }
    table { page-break-inside: avoid; }
    .cs-cover { page-break-after: always; min-height: 100vh; }
  }
</style>
"""


def _md_to_html(
    markdown_text: str,
    customer_name: str = "",
    selection_label: str = "",
    date_str: str = "",
) -> str:
    """
    Convert markdown to a fully branded HTML document with Contrast Security
    cover page.  Uses the 'markdown' package if available, otherwise pandoc.
    """
    if not date_str:
        date_str = datetime.now().strftime("%B %d, %Y")

    # Build cover page HTML
    logo_src = _logo_b64(_LOGO_DARK_PATH)
    logo_tag = (
        f'<img src="{logo_src}" alt="Contrast Security" style="height:52px;">'
        if logo_src
        else '<span style="font-size:18px;font-weight:700;color:#38B885;">CONTRAST SECURITY</span>'
    )
    cover_customer = customer_name or "Security Assessment"
    cover_scope = f"Scope: {selection_label}" if selection_label else ""
    cover_html = f"""
<div class="cs-cover">
  <div class="cs-cover-logo">{logo_tag}</div>
  <div class="cs-cover-accent"></div>
  <div class="cs-cover-customer">{cover_customer}</div>
  <div class="cs-cover-subtitle">Contrast Security IAST Assessment Report</div>
  {'<div class="cs-cover-scope">' + cover_scope + '</div>' if cover_scope else ''}
  <div class="cs-cover-footer">
    Confidential &nbsp;|&nbsp; {date_str} &nbsp;|&nbsp; Prepared by Contrast Security
  </div>
</div>
"""

    # Convert markdown body
    body = ""
    try:
        import markdown as md_lib
        body = md_lib.markdown(markdown_text, extensions=["tables", "fenced_code"])
    except ImportError:
        pass

    if not body:
        try:
            result = subprocess.run(
                ["pandoc", "-f", "markdown", "-t", "html"],
                input=markdown_text,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                body = result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    if not body:
        return ""

    return (
        f"<!DOCTYPE html><html><head><meta charset='utf-8'>{_CSS}</head>"
        f"<body>{cover_html}<div class='cs-body'>{body}</div></body></html>"
    )


def convert_to_pdf(
    markdown_path: Path,
    output_path: Path,
    customer_name: str = "",
    selection_label: str = "",
    date_str: str = "",
) -> bool:
    """
    Convert markdown report to PDF via HTML using Chrome/Chromium headless.
    No LaTeX required.
    Returns True if successful, False otherwise.
    """
    if not markdown_path.exists():
        print(f"  Error: Markdown file not found: {markdown_path}", file=sys.stderr)
        return False

    # Step 1 — build styled HTML with branded cover page
    html_content = _md_to_html(
        markdown_path.read_text(),
        customer_name=customer_name,
        selection_label=selection_label,
        date_str=date_str,
    )
    if not html_content:
        print(
            "  Error: Could not convert markdown to HTML.\n"
            "  Install the markdown package:  pip install markdown",
            file=sys.stderr,
        )
        return False

    html_path = output_path.with_suffix(".html")
    html_path.write_text(html_content, encoding="utf-8")

    # Step 2 — Chrome/Chromium headless print-to-PDF (no extra installs on macOS)
    chrome_candidates = [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
        "google-chrome",
        "chromium",
        "chromium-browser",
    ]

    for chrome in chrome_candidates:
        try:
            result = subprocess.run(
                [
                    chrome,
                    "--headless=new",
                    "--disable-gpu",
                    "--no-sandbox",
                    f"--print-to-pdf={output_path.resolve()}",
                    "--print-to-pdf-no-header",
                    html_path.resolve().as_uri(),
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode == 0 and output_path.exists():
                html_path.unlink()  # Clean up temp HTML
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        except Exception:
            continue

    # Chrome not found — keep HTML for manual printing
    print(
        f"\n  Could not find Chrome/Chromium for PDF conversion.\n"
        f"  HTML report saved: {html_path}\n"
        f"  To generate PDF: open the HTML file in Chrome → File → Print → Save as PDF",
        file=sys.stderr,
    )
    return False



def render_report(
    tag_or_label: str,
    applications: List[dict],
    open_vulns_map: Dict[str, List[dict]],
    closed_vulns_map: Dict[str, List[dict]],
    mttr_map: Dict[str, dict],
    coverage_map: Dict[str, dict],
    libraries_map: Dict[str, List[dict]],
    staleness_map: Dict[str, dict],
    servers_map: Dict[str, dict],
    timeframe_days: int,
    customer_name: str = "",
) -> str:
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = []

    # -----------------------------------------------------------------------
    # Title & metadata
    # -----------------------------------------------------------------------
    report_title = (
        f"{customer_name} — Contrast Security IAST Assessment"
        if customer_name
        else "Contrast Security IAST Assessment"
    )
    lines += [
        f"# {report_title}",
        "",
        f"**Report Generated:** {now}  ",
        f"**Scope:** {tag_or_label}  ",
        f"**Applications:** {len(applications)}  ",
        f"**Analysis Window:** {timeframe_days} days  ",
        "",
        "---",
        "",
    ]

    # -----------------------------------------------------------------------
    # Portfolio executive summary
    # -----------------------------------------------------------------------
    all_open = [v for vs in open_vulns_map.values() for v in vs]
    all_closed = [v for vs in closed_vulns_map.values() for v in vs]
    total_open = len(all_open)
    sev_counts = Counter(v.get("severity", "UNKNOWN").upper() for v in all_open)
    vuln_types = Counter(
        v.get("rule_name") or v.get("type", "unknown") for v in all_open
    )

    total_routes = sum(c.get("total", 0) for c in coverage_map.values())
    total_exercised = sum(c.get("exercised", 0) for c in coverage_map.values())
    avg_coverage = (
        sum(c.get("coverage_pct", 0) for c in coverage_map.values()) / len(coverage_map)
        if coverage_map
        else 0.0
    )
    total_stale = sum(
        d.get("possibly_remediated", 0) for d in staleness_map.values()
    )
    total_servers = sum(d.get("count", 0) for d in servers_map.values())
    total_server_issues = sum(
        len(d.get("compliance_issues", [])) for d in servers_map.values()
    )
    total_libs = sum(len(ls) for ls in libraries_map.values())

    online_apps = [a for a in applications if a.get("status") == "online"]

    lines += [
        "## Executive Summary",
        "",
        "### Portfolio Overview",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Total Applications | {len(applications)} |",
        f"| Online Applications | {len(online_apps)} |",
        f"| Total Open Vulnerabilities | {total_open} |",
        f"| Total Closed Vulnerabilities (last {timeframe_days}d) | {len(all_closed)} |",
        f"| Portfolio Route Coverage (avg) | {avg_coverage:.1f}% ({total_exercised}/{total_routes}) |",
        f"| Possibly Remediated Vulnerabilities* | {total_stale} |",
        f"| Critical/High Libraries Detected | {total_libs} |",
        f"| Servers Monitored | {total_servers} |",
        f"| Agent Compliance Issues | {total_server_issues} |",
        "",
        "*Routes exercised after last vulnerability detection — may indicate remediation*",
        "",
        "### Open Vulnerability Severity Distribution",
        "",
        "| Severity | Count | % |",
        "|----------|-------|---|",
    ]
    for sev in SEVERITY_ORDER:
        count = sev_counts.get(sev, 0)
        lines.append(f"| {sev.title()} | {count} | {_pct(count, total_open)} |")
    lines += [f"| **Total** | **{total_open}** | **100%** |", ""]

    # -----------------------------------------------------------------------
    # MTTR Summary
    # -----------------------------------------------------------------------
    mttr_overall_vals = [m["overall"] for m in mttr_map.values() if m.get("overall") is not None]
    portfolio_mttr_overall = sum(mttr_overall_vals) / len(mttr_overall_vals) if mttr_overall_vals else None
    mttr_by_sev = {}
    for _sev in SEVERITY_ORDER:
        _sev_vals = [m[_sev] for m in mttr_map.values() if isinstance(m.get(_sev), (int, float))]
        mttr_by_sev[_sev] = sum(_sev_vals) / len(_sev_vals) if _sev_vals else None

    lines += [
        "### MTTR Summary (Mean Time To Remediate)",
        "",
        f"Portfolio-wide average across all {len(applications)} applications (last {timeframe_days} days):",
        "",
        "| Severity | Portfolio Avg MTTR (days) |",
        "|----------|--------------------------|",
        f"| **Overall** | **{f'{portfolio_mttr_overall:.1f}' if portfolio_mttr_overall is not None else 'N/A'}** |",
    ]
    for _sev in SEVERITY_ORDER:
        _v = mttr_by_sev.get(_sev)
        lines.append(f"| {_sev.title()} | {f'{_v:.1f}' if _v is not None else 'N/A'} |")
    lines += ["",
        "**Per-Application MTTR (days):**",
        "",
        "| Application | Overall | Critical | High | Medium | Low |",
        "|-------------|---------|----------|------|--------|-----|",
    ]
    for _app in sorted(applications, key=lambda a: a["name"]):
        _m = mttr_map.get(_app["app_id"], {})
        def _fmt(val):
            return f"{val:.1f}" if val is not None else "N/A"
        lines.append(
            f"| {_app['name']} "
            f"| {_fmt(_m.get('overall'))} "
            f"| {_fmt(_m.get('CRITICAL'))} "
            f"| {_fmt(_m.get('HIGH'))} "
            f"| {_fmt(_m.get('MEDIUM'))} "
            f"| {_fmt(_m.get('LOW'))} |"
        )
    lines += [""]

    # -----------------------------------------------------------------------
    # OSS Summary
    # -----------------------------------------------------------------------
    _all_libs_flat = [lib for ls in libraries_map.values() for lib in ls]
    _grade_counts = Counter(lib["grade"] for lib in _all_libs_flat)
    _apps_with_libs = sum(1 for ls in libraries_map.values() if ls)
    _total_cve_exposure = sum(lib.get("cve_count", 0) for lib in _all_libs_flat)
    _libs_needing_upgrade = sum(
        1 for lib in _all_libs_flat
        if lib.get("latest_version") and lib.get("latest_version") != lib.get("version")
    )

    lines += [
        "### OSS / Library Risk Summary",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Applications with Critical/High Libraries | {_apps_with_libs} of {len(applications)} |",
        f"| Total Critical/High Library Instances | {total_libs} |",
        f"| Total CVE Exposures | {_total_cve_exposure} |",
        f"| Libraries Needing Upgrade | {_libs_needing_upgrade} |",
        "",
        "**Grade Distribution:**",
        "",
        "| Grade | Count |",
        "|-------|-------|",
    ]
    for _grade in ["F", "D", "C", "B", "A"]:
        _cnt = _grade_counts.get(_grade, 0)
        if _cnt:
            lines.append(f"| {_grade} | {_cnt} |")
    lines += [""]

    # -----------------------------------------------------------------------
    # Agent Version Compliance Summary
    # -----------------------------------------------------------------------
    _all_agents = [agent for sd in servers_map.values() for agent in sd.get("agents", [])]
    _compliant_agents = sum(1 for a in _all_agents if a["compliant"])
    _non_compliant_agents = len(_all_agents) - _compliant_agents
    _pass_rate = _pct(_compliant_agents, len(_all_agents)) if _all_agents else "N/A"
    _apps_with_issues = sum(1 for sd in servers_map.values() if sd.get("compliance_issues"))

    lines += [
        "### Agent Version Compliance Summary",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Total Agents Monitored | {len(_all_agents)} |",
        f"| Compliant (Top-3 or ≤90 days old) | {_compliant_agents} ({_pass_rate}) |",
        f"| Non-Compliant (Needs Upgrade) | {_non_compliant_agents} |",
        f"| Applications with Agent Issues | {_apps_with_issues} |",
        "",
    ]
    if _non_compliant_agents > 0:
        lines += [
            "**Non-Compliant Agents:**",
            "",
            "| Application | Server | Agent Version | Latest | Behind | Age (days) |",
            "|-------------|--------|---------------|--------|--------|------------|",
        ]
        for _app in applications:
            _sd = servers_map.get(_app["app_id"], {})
            for _agent in _sd.get("agents", []):
                if not _agent["compliant"]:
                    _latest = _agent.get("latest_version", "N/A")
                    _behind = _agent.get("versions_behind", "N/A")
                    _age = _agent.get("age_days", "N/A")
                    lines.append(
                        f"| {_app['name'][:35]} | {_agent['name'][:35]} "
                        f"| {_agent['agent_version']} | {_latest} | {_behind} | {_age} |"
                    )
        lines += [""]

    lines += ["---", ""]

    # -----------------------------------------------------------------------
    # Per-application details
    # -----------------------------------------------------------------------
    # Sort by open vuln count descending
    sorted_apps = sorted(
        applications,
        key=lambda a: len(open_vulns_map.get(a["app_id"], [])),
        reverse=True,
    )

    lines += ["", "---", "", "# INDIVIDUAL APPLICATION DETAILS", "", ""]

    for app in sorted_apps:
        app_id = app["app_id"]
        app_name = app["name"]
        status = app.get("status", "unknown").upper()
        language = app.get("language", "Unknown")
        last_seen = _parse_ts(
            app.get("last_seen") or app.get("last_time_seen") or app.get("lastSeenAt")
        )
        technologies = ", ".join(app.get("technologies", []) or app.get("techs", []))
        days_since = _days_ago(last_seen)
        days_str = f"{days_since} days ago" if days_since is not None else "unknown"

        open_v = open_vulns_map.get(app_id, [])
        closed_v = closed_vulns_map.get(app_id, [])
        mttr = mttr_map.get(app_id, {})
        coverage = coverage_map.get(app_id, {})
        libs = libraries_map.get(app_id, [])
        stale = staleness_map.get(app_id, {})
        srv_summary = servers_map.get(app_id, {})

        open_sev = Counter(v.get("severity", "UNKNOWN").upper() for v in open_v)
        closed_sev = Counter(v.get("severity", "UNKNOWN").upper() for v in closed_v)
        open_types = Counter(
            v.get("rule_name") or v.get("type", "unknown") for v in open_v
        )

        lines += [
            f"### {app_name}",
            "",
            f"**Status:** {status}  ",
            f"**Language:** {language}  ",
            f"**Last Seen:** {_fmt_ts(last_seen)} ({days_str})  ",
        ]
        if technologies:
            lines.append(f"**Technologies:** {technologies}  ")
        lines.append("")

        # ---- Route Coverage ----
        lines += [
            "#### Route Coverage",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Total Routes | {coverage.get('total', 0)} |",
            f"| Exercised Routes | {coverage.get('exercised', 0)} |",
            f"| Unexercised Routes | {coverage.get('unexercised', 0)} |",
            f"| Routes with Vulnerabilities | {coverage.get('with_vulns', 0)} |",
            f"| **Coverage** | **{coverage.get('coverage_pct', 0):.1f}%** |",
            "",
        ]

        # ---- Open Vulnerabilities ----
        lines += [
            "#### Open Vulnerabilities (Custom Code)",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]
        for sev in SEVERITY_ORDER:
            c = open_sev.get(sev, 0)
            if c:
                lines.append(f"| {sev.title()} | {c} |")
        lines += [f"| **Total** | **{len(open_v)}** |", ""]

        # Top vuln types
        if open_types:
            lines += [
                "**Top Vulnerability Types:**",
                "",
                "| Type | Count |",
                "|------|-------|",
            ]
            for vtype, cnt in open_types.most_common(10):
                lines.append(f"| {vtype} | {cnt} |")
            lines.append("")

        # ---- Closed Vulnerabilities + MTTR ----
        lines += [
            f"#### Closed Vulnerabilities (Last {timeframe_days} Days)",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]
        for sev in SEVERITY_ORDER:
            c = closed_sev.get(sev, 0)
            if c:
                lines.append(f"| {sev.title()} | {c} |")
        lines += [f"| **Total** | **{len(closed_v)}** |", ""]

        lines += [
            "**Mean Time To Remediate (MTTR):**",
            "",
            "| Severity | MTTR (days) |",
            "|----------|-------------|",
        ]
        overall = mttr.get("overall")
        lines.append(
            f"| Overall | {f'{overall:.1f}' if overall is not None else 'N/A'} |"
        )
        for sev in SEVERITY_ORDER:
            v = mttr.get(sev)
            lines.append(f"| {sev.title()} | {f'{v:.1f}' if v is not None else 'N/A'} |")
        lines.append("")

        # ---- OSS Library Risk ----
        lines += [
            "#### OSS / Library Risk",
            "",
        ]
        if libs:
            lines += [
                "| Library | Version | Grade | Classes Used | CVEs | Latest |",
                "|---------|---------|-------|--------------|------|--------|",
            ]
            for lib in libs[:20]:
                usage = (
                    f"{lib['classes_used']}/{lib['total_classes']}"
                    if lib["total_classes"]
                    else str(lib["classes_used"])
                )
                latest = lib.get("latest_version") or "—"
                lines.append(
                    f"| {lib['name']} | {lib['version']} | {lib['grade']} "
                    f"| {usage} | {lib['cve_count']} | {latest} |"
                )
            if len(libs) > 20:
                lines.append(f"")
                lines.append(f"_Showing top 20 of {len(libs)} critical/high libraries._")
        else:
            lines.append("_No critical or high-severity libraries detected._")
        lines.append("")

        # ---- Route Staleness ----
        if stale:
            lines += [
                "#### Route Staleness Analysis",
                "",
                "| Metric | Count |",
                "|--------|-------|",
                f"| Vulnerable Routes (Exercised) | {stale.get('total_routes', 0)} |",
                f"| Open Vulnerabilities on Routes | {stale.get('total_vulns', 0)} |",
                f"| Possibly Remediated | {stale.get('possibly_remediated', 0)} |",
                "",
            ]
            stale_findings = sorted(
                [f for f in stale.get("findings", []) if f["stale"]],
                key=lambda x: x.get("days_stale") or 0,
                reverse=True,
            )
            if stale_findings:
                lines += [
                    "**Top Potentially Remediated Vulnerabilities:**",
                    "",
                    "| Severity | Vulnerability | Days Since Route Re-exercised |",
                    "|----------|---------------|-------------------------------|",
                ]
                for f in stale_findings[:5]:
                    title = f["vuln_title"][:60]
                    lines.append(
                        f"| {f['severity']} | {title} | {f.get('days_stale', '?')} |"
                    )
                lines.append("")

        # ---- Servers & Agent Health ----
        lines += ["#### Servers & Agent Health", ""]
        if srv_summary.get("count", 0) == 0:
            lines.append("_No server data available._")
            lines.append("")
        else:
            lines += [
                "| Metric | Value |",
                "|--------|-------|",
                f"| Total Servers | {srv_summary['count']} |",
                f"| Online | {srv_summary['online']} |",
                f"| Offline | {srv_summary['offline']} |",
                f"| Agent Compliance Issues | {len(srv_summary.get('compliance_issues', []))} |",
                "",
                "| Server | Environment | Status | Agent Version | Latest | Behind | Age (days) | Compliance |",
                "|--------|-------------|--------|---------------|--------|--------|------------|------------|",
            ]
            for agent in srv_summary.get("agents", [])[:25]:
                comp_icon = "✓ PASS" if agent["compliant"] else "✗ UPGRADE"
                latest = agent.get("latest_version", "N/A")
                behind = agent.get("versions_behind", "N/A")
                age = agent.get("age_days", "N/A")
                lines.append(
                    f"| {agent['name'][:40]} | {agent['environment']} "
                    f"| {agent['status']} | {agent['agent_version']} "
                    f"| {latest} | {behind} | {age} | {comp_icon} |"
                )
            if len(srv_summary.get("agents", [])) > 25:
                lines.append(
                    f"\n_Showing first 25 of {srv_summary['count']} servers._"
                )
            lines.append("")

        lines += ["---", ""]

    # -----------------------------------------------------------------------
    # Portfolio-wide top vulnerability types
    # -----------------------------------------------------------------------
    lines += [
        "## Portfolio-Wide Top Vulnerability Types",
        "",
        "| Vulnerability Type | Count |",
        "|-------------------|-------|",
    ]
    for vt, cnt in vuln_types.most_common(15):
        lines.append(f"| {vt} | {cnt} |")
    lines += ["", "---", ""]

    lines += ["*Report generated by Contrast Security Assessment Script*"]

    return "\n".join(lines)


# ===========================================================================
# Main
# ===========================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Generate a comprehensive Contrast Security IAST assessment report"
    )
    parser.add_argument(
        "--env-file", type=Path,
        help="Path to .env file with credentials (default: [repo-root]/.env)"
    )

    # Selection modes — all optional; defaults to interactive
    sel = parser.add_mutually_exclusive_group()
    sel.add_argument("--tag", type=str, help="Filter apps by tag (skips app-selection prompt)")
    sel.add_argument("--app-name", type=str, help="Select a single app by name (skips prompt)")

    parser.add_argument(
        "--output", type=Path,
        help="Output file path (default: print to stdout)"
    )
    parser.add_argument(
        "--report-name", type=str,
        help="Report title prefix (skips prompt when provided)"
    )
    parser.add_argument(
        "--days", type=int, default=365,
        help="Lookback window for closed vulns / MTTR (default: 365)"
    )
    parser.add_argument(
        "--skip-staleness", action="store_true",
        help="Skip route staleness analysis"
    )
    parser.add_argument(
        "--skip-servers", action="store_true",
        help="Skip server / agent-version fetch"
    )

    args = parser.parse_args()

    # ------------------------------------------------------------------
    # Step 1 — credential loading from root .env
    # ------------------------------------------------------------------
    repo_root = find_repo_root(Path.cwd())
    env_file = args.env_file if args.env_file else (repo_root / ".env")

    print(f"Loading credentials from {env_file} ...")

    creds = load_root_credentials(env_file)
    base_url = normalise_base_url(creds["TeamserverURL"])
    org_uuid = creds["ORG_UUID"]
    headers = build_headers(creds)

    # ------------------------------------------------------------------
    # Application selection
    # ------------------------------------------------------------------
    print("Fetching application list ...")
    all_apps = fetch_all_applications(base_url, org_uuid, headers)
    print(f"  {len(all_apps)} licensed applications found")

    if args.tag is None and args.app_name is None:
        # Default: always prompt interactively
        selected_apps = interactive_app_selection(all_apps)
        # Build a readable label from actual app names
        if len(selected_apps) == 1:
            label = selected_apps[0]["name"]
        elif len(selected_apps) <= 4:
            label = ", ".join(a["name"] for a in selected_apps)
        else:
            label = f"{len(selected_apps)} Applications"
    elif args.tag:
        selected_apps = filter_apps_by_tag(all_apps, args.tag)
        label = args.tag
        print(f"  {len(selected_apps)} apps match tag '{args.tag}'")
    else:
        name_lower = args.app_name.lower()
        selected_apps = [a for a in all_apps if a["name"].lower() == name_lower]
        if not selected_apps:
            print(f"ERROR: Application '{args.app_name}' not found.", file=sys.stderr)
            sys.exit(1)
        label = selected_apps[0]["name"]

    if not selected_apps:
        print("No applications selected. Exiting.")
        sys.exit(0)

    print(f"\n  Selected {len(selected_apps)} application(s):")
    for a in selected_apps:
        print(f"    • {a['name']} ({a.get('language', '?')}) — {a.get('status', '?')}")

    # Report name for title and filename
    report_name = args.report_name or ""
    if not report_name:
        print("\nReport name (for report title and filename): ", end="", flush=True)
        report_name = input().strip()

    # ------------------------------------------------------------------
    # Load agent version reference data (for proper top-3 / 3-month check)
    # ------------------------------------------------------------------
    version_reference = load_version_reference()
    if version_reference:
        ref_date = version_reference.get("generated_date", "unknown")
        print(f"  Agent version reference loaded (generated: {ref_date})")
        java_latest = version_reference.get("languages", {}).get("Java", {}).get("latest_version", "?")
        print(f"  Java latest: {java_latest} | Rule: top-3 versions OR within 3 months")
    else:
        print("  Warning: No agent version reference — falling back to hardcoded minimums")

    # ------------------------------------------------------------------
    # Data collection
    # ------------------------------------------------------------------
    since_ms = int(
        (datetime.now(tz=timezone.utc) - timedelta(days=args.days)).timestamp() * 1000
    )

    open_vulns_map: Dict[str, List[dict]] = {}
    closed_vulns_map: Dict[str, List[dict]] = {}
    mttr_map: Dict[str, dict] = {}
    coverage_map: Dict[str, dict] = {}
    libraries_map: Dict[str, List[dict]] = {}
    staleness_map: Dict[str, dict] = {}
    servers_map: Dict[str, dict] = {}

    total = len(selected_apps)

    for i, app in enumerate(selected_apps, 1):
        app_id = app["app_id"]
        app_name = app["name"]
        lang = app.get("language", "Unknown")
        prefix = f"  [{i}/{total}] {app_name}"

        print(f"\n{prefix}")

        # Open vulns
        print(f"    Fetching open vulnerabilities ...")
        open_v = fetch_vulnerabilities(
            base_url, org_uuid, headers, app_id,
            ["Reported", "Confirmed", "Suspicious"],
        )
        open_vulns_map[app_id] = open_v
        print(f"      {len(open_v)} open vulnerabilities")

        # Closed vulns + MTTR
        print(f"    Fetching closed vulnerabilities (last {args.days}d) ...")
        closed_v = fetch_vulnerabilities(
            base_url, org_uuid, headers, app_id,
            ["Fixed", "Remediated", "NotAProblem", "AutoRemediated"],
            since_ms=since_ms,
            is_closed=True,
        )
        closed_vulns_map[app_id] = closed_v
        mttr = calculate_mttr(closed_v)
        mttr_map[app_id] = mttr
        mttr_str = f"{mttr['overall']:.1f}d" if mttr.get("overall") else "N/A"
        print(f"      {len(closed_v)} closed  |  MTTR: {mttr_str}")

        # Route coverage
        print(f"    Fetching route coverage ...")
        cov = fetch_route_coverage(base_url, org_uuid, headers, app_id)
        coverage_map[app_id] = cov
        print(f"      {cov['coverage_pct']:.1f}% ({cov['exercised']}/{cov['total']} routes)")

        # Libraries
        print(f"    Fetching critical/high libraries ...")
        libs = fetch_critical_libraries(base_url, org_uuid, headers, app_id)
        libraries_map[app_id] = libs
        print(f"      {len(libs)} critical/high libraries")

        # Staleness
        if not args.skip_staleness:
            print(f"    Analysing route staleness ...")
            stale = analyse_staleness(base_url, org_uuid, headers, app_id)
            staleness_map[app_id] = stale
            print(
                f"      {stale['total_routes']} vulnerable routes, "
                f"{stale['possibly_remediated']} possibly remediated"
            )
        else:
            staleness_map[app_id] = {}

        # Servers
        if not args.skip_servers:
            print(f"    Fetching servers ...")
            raw_servers = fetch_servers_for_app(base_url, org_uuid, headers, app_id)
            servers_map[app_id] = summarise_servers(raw_servers, lang, version_reference)
            srv = servers_map[app_id]
            issues = len(srv.get("compliance_issues", []))
            print(
                f"      {srv['count']} servers  |  {issues} agent compliance issue(s)"
            )
        else:
            servers_map[app_id] = {}

    # ------------------------------------------------------------------
    # Render report
    # ------------------------------------------------------------------
    print("\nRendering report ...")
    report = render_report(
        tag_or_label=label,
        applications=selected_apps,
        open_vulns_map=open_vulns_map,
        closed_vulns_map=closed_vulns_map,
        mttr_map=mttr_map,
        coverage_map=coverage_map,
        libraries_map=libraries_map,
        staleness_map=staleness_map,
        servers_map=servers_map,
        timeframe_days=args.days,
        customer_name=report_name,
    )

    # ------------------------------------------------------------------
    # Determine output path — prompt if not supplied via --output
    # ------------------------------------------------------------------
    if args.output:
        output_path = args.output
        wants_pdf = output_path.suffix.lower() == ".pdf"
    else:
        date_str = datetime.now().strftime("%Y-%m-%d")

        # Build safe filename components from customer name + label
        def _safe(s: str) -> str:
            return re.sub(r'[^\w\-]', '_', s).strip('_')

        safe_customer = _safe(report_name) if report_name else "Contrast"
        safe_label = _safe(label.split("(")[0])

        # Ask about PDF export
        print("\nExport as PDF? (y/n) [n]: ", end="", flush=True)
        pdf_choice = input().strip().lower()
        wants_pdf = pdf_choice in ("y", "yes")

        ext = ".pdf" if wants_pdf else ".md"
        default_path = Path(__file__).resolve().parent / "Output" / f"{safe_customer}_{safe_label}_{date_str}{ext}"

        print(f"\nOutput file [default: {default_path}]: ", end="", flush=True)
        user_path = input().strip()
        output_path = Path(user_path) if user_path else default_path

    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Determine if PDF export is requested (based on file extension)
    is_pdf = output_path.suffix.lower() == ".pdf"

    if is_pdf:
        # Save markdown temporarily, then convert to branded PDF
        md_path = output_path.with_suffix(".md")
        print(f"\n  Saving intermediate markdown: {md_path}")
        md_path.write_text(report)

        print(f"  Converting to PDF: {output_path}")
        if convert_to_pdf(
            md_path,
            output_path,
            customer_name=report_name,
            selection_label=label,
            date_str=datetime.now().strftime("%B %d, %Y"),
        ):
            print(f"\n✓ Report written to: {output_path}")
        else:
            print(f"  Warning: PDF conversion failed. Markdown saved at: {md_path}")
    else:
        # Save as markdown directly
        output_path.write_text(report)
        print(f"\n✓ Report written to: {output_path}")

    # Summary
    print(f"\n✓ Done!")
    print(f"  Applications analysed : {len(selected_apps)}")
    print(f"  Open vulnerabilities  : {sum(len(v) for v in open_vulns_map.values())}")
    print(f"  Closed (last {args.days}d)  : {sum(len(v) for v in closed_vulns_map.values())}")
    print(f"  Avg route coverage    : "
          f"{sum(c.get('coverage_pct', 0) for c in coverage_map.values()) / len(coverage_map):.1f}%"
          if coverage_map else "  Avg route coverage    : N/A")
    if not args.skip_staleness:
        print(f"  Possibly remediated   : {sum(d.get('possibly_remediated', 0) for d in staleness_map.values())}")
    if not args.skip_servers:
        print(f"  Servers monitored     : {sum(d.get('count', 0) for d in servers_map.values())}")
        print(f"  Agent issues          : {sum(len(d.get('compliance_issues', [])) for d in servers_map.values())}")


if __name__ == "__main__":
    main()

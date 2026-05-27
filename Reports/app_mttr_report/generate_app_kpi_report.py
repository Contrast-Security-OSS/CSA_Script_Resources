#!/usr/bin/env python3
"""
Generate per-application KPI dashboard reports from Contrast Security data.

This script produces comprehensive KPI metrics for individual applications including:
- Route coverage metrics
- Mean Time To Remediate (MTTR) - global and per severity
- Current open vulnerabilities
- Closed vulnerabilities (within timeframe)
- Critical libraries with class usage

Usage:
    python3 generate_app_kpi_report.py --env-file .env --app-name "MyApp"
    python3 generate_app_kpi_report.py --env-file .env --app-id "abc-123" --days 365
"""

import argparse
import requests
import sys
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, List, Tuple
from collections import Counter
from pathlib import Path


def find_repo_root(start: Path) -> Path:
    current = start.resolve()
    for candidate in [current, *current.parents]:
        if (candidate / "notebooks").exists() and (candidate / "README.md").exists():
            return candidate
    return current


def load_env_file(env_path: str) -> dict:
    """
    Parse a flat .env file and return normalized credentials.
    
    Args:
        env_path: Path to .env file
    Returns:
        Dictionary with TeamserverURL, ORG_UUID, AUTH, API_KEY
    """
    path = Path(env_path)
    if not path.exists():
        raise FileNotFoundError(f".env file not found: {path}")

    config = {}
    current_section = None

    with open(path, 'r', encoding='utf-8') as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            if line.startswith('[') and line.endswith(']'):
                current_section = line[1:-1]
                continue
            if '=' not in line:
                continue
            key, value = line.split('=', 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")

            # Flat mode ignores sectioned key/value pairs.
            if current_section is None:
                config[key] = value

    # Allow both notebook-style and legacy key names.
    normalized = {
        'TeamserverURL': config.get('TEAMSERVER_URL') or config.get('TeamserverURL') or config.get('url'),
        'ORG_UUID': config.get('ORG_UUID') or config.get('organizationId'),
        'AUTH': config.get('CONTRAST_AUTH') or config.get('AUTH') or config.get('authHeader'),
        'API_KEY': config.get('CONTRAST_API_KEY') or config.get('API_KEY') or config.get('apiKey'),
    }

    required = ['TeamserverURL', 'ORG_UUID', 'AUTH', 'API_KEY']
    missing = [k for k in required if not normalized.get(k)]
    if missing:
        raise ValueError(f"Missing required env config: {missing}")

    return normalized


def get_application(base_url: str, org_uuid: str, headers: dict, app_id: str = None, app_name: str = None) -> dict:
    """
    Get application details by ID or name.
    
    Args:
        base_url: Contrast TeamServer URL
        org_uuid: Organization UUID
        headers: Request headers with auth
        app_id: Application ID (optional)
        app_name: Application name (optional)
    
    Returns:
        Application dictionary
    """
    if app_id:
        url = f"{base_url}Contrast/api/ng/{org_uuid}/applications/{app_id}"
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        return resp.json().get('application', {})
    
    elif app_name:
        # Search by name
        url = f"{base_url}Contrast/api/ng/{org_uuid}/applications"
        params = {'includeArchived': 'false'}
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        apps = resp.json().get('applications', [])
        
        # Find matching app (case-insensitive)
        app_name_lower = app_name.lower()
        for app in apps:
            if app.get('name', '').lower() == app_name_lower:
                # Normalize app_id field
                if 'app_id' not in app and 'appID' in app:
                    app['app_id'] = app['appID']
                return app
        
        raise ValueError(f"Application '{app_name}' not found")
    
    else:
        raise ValueError("Must provide either app_id or app_name")


def get_route_coverage(base_url: str, org_uuid: str, headers: dict, app_id: str) -> dict:
    """
    Get route coverage metrics for an application.
    
    Args:
        base_url: Contrast TeamServer URL
        org_uuid: Organization UUID
        headers: Request headers
        app_id: Application ID
    
    Returns:
        Dictionary with coverage metrics
    """
    # Correct endpoint is /applications/{app_id}/route (singular, not plural)
    url = f"{base_url}Contrast/api/ng/{org_uuid}/applications/{app_id}/route"
    
    try:
        # Fetch all routes to get accurate counts
        resp = requests.get(url, headers=headers, params={'limit': 1000}, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        
        # Response includes: count (total), exercised_count, discovered_count, routes[]
        # count = total routes, exercised_count = routes with exercise timestamp
        routes = data.get('routes', [])
        total = len(routes)  # Use actual count from routes list
        exercised = sum(1 for r in routes if r.get('exercised'))  # Count routes with exercised timestamp
        
        # Calculate coverage percentage
        coverage_pct = (exercised / total * 100) if total > 0 else 0.0
        
        # Count routes with vulnerabilities (field name is 'vulnerabilities')
        routes_with_vulns = sum(1 for r in routes if r.get('vulnerabilities', 0) > 0)
        
        return {
            'total_routes': total,
            'exercised_routes': exercised,
            'unexercised_routes': total - exercised,
            'coverage_percent': coverage_pct,
            'routes_with_vulns': routes_with_vulns,
        }
    except Exception as e:
        print(f"  Warning: Could not fetch route coverage: {e}", file=sys.stderr)
        return {
            'total_routes': 0,
            'exercised_routes': 0,
            'unexercised_routes': 0,
            'coverage_percent': 0.0,
            'routes_with_vulns': 0,
        }


def get_vulnerabilities(base_url: str, org_uuid: str, headers: dict, app_id: str, 
                       status: List[str] = None, since_date: datetime = None) -> List[dict]:
    """
    Get vulnerabilities for an application with optional filtering.
    
    Args:
        base_url: Contrast TeamServer URL
        org_uuid: Organization UUID
        headers: Request headers
        app_id: Application ID
        status: List of statuses to filter (e.g., ['Reported', 'Confirmed'])
        since_date: Only include vulnerabilities detected/closed since this date
                   For closed statuses, filters by closed_time
                   For open statuses, filters by first_time_seen
    
    Returns:
        List of vulnerability dictionaries
    """
    url = f"{base_url}Contrast/api/ng/{org_uuid}/traces/{app_id}/filter"
    all_vulns = []
    offset = 0
    limit = 100
    
    # Determine if we're fetching closed vulnerabilities
    closed_statuses = {'Fixed', 'Remediated', 'NotAProblem', 'AutoRemediated'}
    is_closed = status and any(s in closed_statuses for s in status)
    
    while True:
        params = {
            'offset': offset,
            'limit': limit,
            'expand': 'skip_links,application',
        }
        
        # Add status filter if provided
        if status:
            params['status'] = ','.join(status)
        
        # For open vulnerabilities, filter by first_time_seen using API
        # For closed vulnerabilities, we'll filter manually by closed_time after fetching
        if since_date and not is_closed:
            # Convert to epoch milliseconds
            since_ms = int(since_date.timestamp() * 1000)
            params['timestampFilter'] = 'FIRST'
            params['startDate'] = since_ms
        
        resp = requests.get(url, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        
        batch = data.get('traces', [])
        all_vulns.extend(batch)
        
        total = data.get('count', len(batch))
        offset += len(batch)
        if offset >= total or not batch:
            break
    
    # For closed vulnerabilities, manually filter by closed_time
    if since_date and is_closed:
        since_ms = int(since_date.timestamp() * 1000)
        filtered_vulns = []
        for vuln in all_vulns:
            closed_time = vuln.get('closed_time') or vuln.get('closedTime')
            if closed_time and closed_time >= since_ms:
                filtered_vulns.append(vuln)
        return filtered_vulns
    
    return all_vulns


def calculate_mttr(vulnerabilities: List[dict]) -> Dict[str, float]:
    """
    Calculate Mean Time To Remediate (MTTR) in days.
    
    Args:
        vulnerabilities: List of closed vulnerability dictionaries
    
    Returns:
        Dictionary with overall MTTR and per-severity MTTR
    """
    mttr_data = {
        'overall': None,
        'CRITICAL': None,
        'HIGH': None,
        'MEDIUM': None,
        'LOW': None,
        'NOTE': None,
    }
    
    severity_times = {
        'CRITICAL': [],
        'HIGH': [],
        'MEDIUM': [],
        'LOW': [],
        'NOTE': [],
    }
    
    all_times = []
    
    for vuln in vulnerabilities:
        # Get first seen and closed timestamps
        first_seen = vuln.get('first_time_seen')
        closed_time = vuln.get('closed_time') or vuln.get('closedTime')
        
        if not first_seen or not closed_time:
            continue
        
        # Parse timestamps (handle both epoch ms and ISO strings)
        try:
            if isinstance(first_seen, (int, float)):
                first_dt = datetime.fromtimestamp(first_seen / 1000, tz=timezone.utc)
            else:
                first_dt = datetime.fromisoformat(str(first_seen).replace('Z', '+00:00'))
            
            if isinstance(closed_time, (int, float)):
                closed_dt = datetime.fromtimestamp(closed_time / 1000, tz=timezone.utc)
            else:
                closed_dt = datetime.fromisoformat(str(closed_time).replace('Z', '+00:00'))
            
            # Calculate days to remediate
            days_to_remediate = (closed_dt - first_dt).total_seconds() / 86400
            
            if days_to_remediate >= 0:  # Sanity check
                all_times.append(days_to_remediate)
                
                severity = vuln.get('severity', 'UNKNOWN').upper()
                if severity in severity_times:
                    severity_times[severity].append(days_to_remediate)
        
        except Exception:
            continue
    
    # Calculate averages
    if all_times:
        mttr_data['overall'] = sum(all_times) / len(all_times)
    
    for severity, times in severity_times.items():
        if times:
            mttr_data[severity] = sum(times) / len(times)
    
    return mttr_data


def get_libraries(base_url: str, org_uuid: str, headers: dict, app_id: str) -> List[dict]:
    """
    Get vulnerable libraries for an application with critical severity and class usage.
    
    Args:
        base_url: Contrast TeamServer URL
        org_uuid: Organization UUID
        headers: Request headers
        app_id: Application ID
    
    Returns:
        List of library dictionaries with class usage
    """
    # Correct endpoint is /libraries/filter with POST body
    url = f"{base_url}Contrast/api/ng/{org_uuid}/libraries/filter"
    all_libs = []
    offset = 0
    limit = 50
    
    try:
        while True:
            params = {
                'expand': 'skip_links,apps,quickFilters,vulns,status,usage_counts',
                'offset': offset,
                'limit': limit,
                'sort': 'score'
            }
            
            # POST body with filters
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
                "severities": ["CRITICAL"],
                "tags": [],
                "includeUnused": False,
                "includeUsed": True
            }
            
            resp = requests.post(url, headers=headers, params=params, json=body, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            
            batch = data.get('libraries', [])
            all_libs.extend(batch)
            
            total = data.get('count', len(batch))
            offset += len(batch)
            if offset >= total or not batch:
                break
        
        # Format library data
        critical_libs = []
        for lib in all_libs:
            classes_used = lib.get('classes_used', 0) or lib.get('classesUsed', 0)
            grade = lib.get('grade', '').upper()
            
            critical_libs.append({
                'name': lib.get('file_name', lib.get('fileName', 'Unknown')),
                'version': lib.get('file_version', lib.get('version', 'Unknown')),
                'grade': grade,
                'classes_used': classes_used,
                'total_classes': lib.get('class_count', lib.get('totalClasses', 0)),
                'cve_count': lib.get('total_vulnerabilities', lib.get('totalVulnerabilities', 0)),
            })
        
        # Sort by grade (worst first: F, D, C, B, A) then by class usage
        grade_order = {'F': 0, 'D': 1, 'C': 2, 'B': 3, 'A': 4}
        critical_libs.sort(key=lambda x: (grade_order.get(x['grade'], 5), -x['classes_used']))
        
        return critical_libs
    
    except Exception as e:
        print(f"  Warning: Could not fetch libraries: {e}", file=sys.stderr)
        return []


def generate_report(app: dict, coverage: dict, open_vulns: List[dict], 
                   closed_vulns: List[dict], mttr: dict, libraries: List[dict],
                   timeframe_days: int, output_path: str):
    """
    Generate a Markdown KPI report for an application.
    
    Args:
        app: Application dictionary
        coverage: Route coverage metrics
        open_vulns: List of open vulnerabilities
        closed_vulns: List of closed vulnerabilities
        mttr: MTTR metrics dictionary
        libraries: List of critical libraries
        timeframe_days: Number of days in the analysis timeframe
        output_path: Path to write the report
    """
    app_name = app.get('name', 'Unknown')
    app_id = app.get('app_id') or app.get('appID', 'Unknown')
    language = app.get('language', 'Unknown')
    
    # Calculate severity distribution for open vulns
    open_severity_counts = Counter(v.get('severity', 'UNKNOWN').upper() for v in open_vulns)
    
    # Calculate closed vulnerability stats
    closed_severity_counts = Counter(v.get('severity', 'UNKNOWN').upper() for v in closed_vulns)
    
    # Generate report content
    lines = []
    lines.append(f"# Application KPI Dashboard: {app_name}")
    lines.append("")
    lines.append(f"**Report Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')} UTC  ")
    lines.append(f"**Application ID:** {app_id}  ")
    lines.append(f"**Language:** {language}  ")
    lines.append(f"**Analysis Timeframe:** {timeframe_days} days  ")
    lines.append("")
    lines.append("---")
    lines.append("")
    
    # KPI Summary
    lines.append("## KPI Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Route Coverage | {coverage['coverage_percent']:.1f}% ({coverage['exercised_routes']}/{coverage['total_routes']}) |")
    lines.append(f"| Open Vulnerabilities | {len(open_vulns)} |")
    lines.append(f"| Closed Vulnerabilities (Last {timeframe_days} days) | {len(closed_vulns)} |")
    
    if mttr['overall'] is not None:
        lines.append(f"| Mean Time To Remediate (Overall) | {mttr['overall']:.1f} days |")
    else:
        lines.append(f"| Mean Time To Remediate (Overall) | N/A |")
    
    lines.append(f"| Critical Libraries (with class usage) | {len(libraries)} |")
    lines.append("")
    
    # Route Coverage Details
    lines.append("## Route Coverage")
    lines.append("")
    lines.append("| Metric | Count |")
    lines.append("|--------|-------|")
    lines.append(f"| Total Routes | {coverage['total_routes']} |")
    lines.append(f"| Exercised Routes | {coverage['exercised_routes']} |")
    lines.append(f"| Unexercised Routes | {coverage['unexercised_routes']} |")
    lines.append(f"| Routes with Vulnerabilities | {coverage['routes_with_vulns']} |")
    lines.append(f"| **Coverage Percentage** | **{coverage['coverage_percent']:.1f}%** |")
    lines.append("")
    
    # Open Vulnerabilities
    lines.append("## Open Vulnerabilities")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NOTE']:
        count = open_severity_counts.get(sev, 0)
        lines.append(f"| {sev.title()} | {count} |")
    lines.append(f"| **Total** | **{len(open_vulns)}** |")
    lines.append("")
    
    # Closed Vulnerabilities
    lines.append(f"## Closed Vulnerabilities (Last {timeframe_days} days)")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NOTE']:
        count = closed_severity_counts.get(sev, 0)
        lines.append(f"| {sev.title()} | {count} |")
    lines.append(f"| **Total** | **{len(closed_vulns)}** |")
    lines.append("")
    
    # MTTR
    lines.append("## Mean Time To Remediate (MTTR)")
    lines.append("")
    lines.append("| Severity | MTTR (days) |")
    lines.append("|----------|-------------|")
    
    if mttr['overall'] is not None:
        lines.append(f"| **Overall** | **{mttr['overall']:.1f}** |")
    else:
        lines.append(f"| **Overall** | **N/A** |")
    
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NOTE']:
        if mttr[sev] is not None:
            lines.append(f"| {sev.title()} | {mttr[sev]:.1f} |")
        else:
            lines.append(f"| {sev.title()} | N/A |")
    lines.append("")
    
    # Critical Libraries
    lines.append("## Critical Libraries (with Class Usage)")
    lines.append("")
    
    if libraries:
        lines.append("| Library | Version | Grade | Classes Used | CVEs |")
        lines.append("|---------|---------|-------|--------------|------|")
        
        for lib in libraries[:20]:  # Limit to top 20
            name = lib['name']
            version = lib['version']
            grade = lib['grade']
            classes_used = lib['classes_used']
            total_classes = lib['total_classes']
            cve_count = lib['cve_count']
            
            usage_str = f"{classes_used}/{total_classes}" if total_classes > 0 else str(classes_used)
            lines.append(f"| {name} | {version} | {grade} | {usage_str} | {cve_count} |")
        
        if len(libraries) > 20:
            lines.append("")
            lines.append(f"_Showing top 20 of {len(libraries)} libraries with class usage_")
    else:
        lines.append("No critical libraries with class usage detected.")
    
    lines.append("")
    lines.append("---")
    lines.append("")
    
    # Methodology
    lines.append("## Methodology")
    lines.append("")
    lines.append("### Data Collection")
    lines.append("")
    lines.append("- **Source:** Contrast Security Platform API (v3)")
    lines.append(f"- **Timeframe:** Last {timeframe_days} days")
    lines.append("- **Merged Applications:** Treated as single entity")
    lines.append("")
    lines.append("### Metrics Definitions")
    lines.append("")
    lines.append("- **Route Coverage:** Percentage of discovered routes that have been exercised")
    lines.append("- **Open Vulnerabilities:** Currently active vulnerabilities (Reported, Confirmed, Suspicious)")
    lines.append("- **Closed Vulnerabilities:** Vulnerabilities remediated or fixed within the timeframe")
    lines.append("- **MTTR:** Average days between vulnerability first detection and closure")
    lines.append("- **Critical Libraries:** Libraries with security grade and actual class usage in application")
    lines.append("")
    
    # Write to file
    with open(output_path, 'w') as f:
        f.write('\n'.join(lines))


def main():
    parser = argparse.ArgumentParser(
        description='Generate per-application KPI dashboard report from Contrast Security data'
    )
    parser.add_argument('--env-file', help='Path to .env file (default: [repo-root]/.env)')
    parser.add_argument('--app-id', help='Application ID')
    parser.add_argument('--app-name', help='Application name')
    parser.add_argument('--days', type=int, default=365, help='Analysis timeframe in days (default: 365)')
    parser.add_argument('--output', help='Output report path (default: Reports/app_mttr_report/{app_name}_KPI_{date}.md)')
    
    args = parser.parse_args()
    
    if not args.app_id and not args.app_name:
        parser.error("Must provide either --app-id or --app-name")
    
    # Load credentials
    repo_root = find_repo_root(Path.cwd())
    env_path = Path(args.env_file) if args.env_file else (repo_root / '.env')
    print(f"Loading credentials from {env_path} ...")
    config = load_env_file(str(env_path))
    
    base_url = config['TeamserverURL']
    if not base_url.endswith('/'):
        base_url += '/'
    
    org_uuid = config['ORG_UUID']
    
    headers = {
        'Authorization': config['AUTH'],
        'API-Key': config['API_KEY'],
        'Accept': 'application/json',
    }
    
    # Get application
    print(f"\nFetching application details ...")
    app = get_application(base_url, org_uuid, headers, args.app_id, args.app_name)
    app_name = app.get('name', 'Unknown')
    app_id = app.get('app_id') or app.get('appID')
    
    print(f"  Application: {app_name} (ID: {app_id})")
    
    # Calculate timeframe
    since_date = datetime.now(timezone.utc) - timedelta(days=args.days)
    
    # Get route coverage
    print(f"\nFetching route coverage ...")
    coverage = get_route_coverage(base_url, org_uuid, headers, app_id)
    print(f"  Coverage: {coverage['coverage_percent']:.1f}% ({coverage['exercised_routes']}/{coverage['total_routes']} routes)")
    
    # Get open vulnerabilities
    print(f"\nFetching open vulnerabilities ...")
    open_vulns = get_vulnerabilities(
        base_url, org_uuid, headers, app_id,
        status=['Reported', 'Confirmed', 'Suspicious']
    )
    print(f"  {len(open_vulns)} open vulnerabilities")
    
    # Get closed vulnerabilities (within timeframe)
    print(f"\nFetching closed vulnerabilities (last {args.days} days) ...")
    closed_vulns = get_vulnerabilities(
        base_url, org_uuid, headers, app_id,
        status=['Fixed', 'Remediated', 'NotAProblem', 'AutoRemediated'],
        since_date=since_date
    )
    print(f"  {len(closed_vulns)} closed vulnerabilities")
    
    # Calculate MTTR
    print(f"\nCalculating MTTR ...")
    mttr = calculate_mttr(closed_vulns)
    if mttr['overall']:
        print(f"  Overall MTTR: {mttr['overall']:.1f} days")
    else:
        print(f"  Overall MTTR: N/A (no closed vulnerabilities)")
    
    # Get critical libraries
    print(f"\nFetching critical libraries ...")
    libraries = get_libraries(base_url, org_uuid, headers, app_id)
    print(f"  {len(libraries)} libraries with class usage")
    
    # Generate report
    print(f"\nGenerating report ...")
    
    if args.output:
        output_path = args.output
    else:
        # Default output path
        safe_name = app_name.replace(' ', '_').replace('/', '_')
        date_str = datetime.now().strftime('%Y-%m-%d')
        output_path = str(Path(__file__).resolve().parent / 'Output' / f"{safe_name}_KPI_{date_str}.md")
    
    # Ensure output directory exists
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    
    generate_report(app, coverage, open_vulns, closed_vulns, mttr, libraries, args.days, output_path)
    
    print(f"\n✓ Report written to: {output_path}")
    print(f"\n✓ KPI report generation complete!")
    print(f"  Open vulnerabilities: {len(open_vulns)}")
    print(f"  Closed vulnerabilities: {len(closed_vulns)}")
    print(f"  Route coverage: {coverage['coverage_percent']:.1f}%")


if __name__ == '__main__':
    main()

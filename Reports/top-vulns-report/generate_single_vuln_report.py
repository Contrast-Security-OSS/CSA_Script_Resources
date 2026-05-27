#!/usr/bin/env python3
"""
Generate Top Vulnerability Report (Single Vulnerability) - FIXED VERSION
=========================================================================
Pull the #1 critical/high severity vulnerability from an application
and generate a comprehensive Markdown report with all available details.

This version correctly handles the actual Contrast API data structures.
"""

import requests
import json
import argparse
from datetime import datetime
from typing import Dict, List, Optional
import sys
import re
from pathlib import Path


def find_repo_root(start: Path) -> Path:
    current = start.resolve()
    for candidate in [current, *current.parents]:
        if (candidate / "notebooks").exists() and (candidate / "README.md").exists():
            return candidate
    return current


def load_credentials(env_file: Path, env_section: Optional[str] = None) -> Dict[str, str]:
    if not env_file.exists():
        raise FileNotFoundError(f".env file not found: {env_file}")

    cfg: Dict[str, str] = {}
    current_section: Optional[str] = None
    with open(env_file, "r", encoding="utf-8") as f:
        for raw in f:
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

            if env_section is None:
                if current_section is None:
                    cfg[key] = value
            elif current_section == env_section:
                cfg[key] = value

    base_url = cfg.get("TEAMSERVER_URL") or cfg.get("TeamserverURL") or cfg.get("url")
    org_id = cfg.get("ORG_UUID") or cfg.get("organizationId")
    api_key = cfg.get("CONTRAST_API_KEY") or cfg.get("API_KEY") or cfg.get("apiKey")
    auth_header = cfg.get("CONTRAST_AUTH") or cfg.get("AUTH") or cfg.get("authHeader")

    missing = []
    if not base_url:
        missing.append("TEAMSERVER_URL/TeamserverURL")
    if not org_id:
        missing.append("ORG_UUID")
    if not api_key:
        missing.append("CONTRAST_API_KEY/API_KEY")
    if not auth_header:
        missing.append("CONTRAST_AUTH/AUTH")
    if missing:
        where = f"[{env_section}] in {env_file}" if env_section else str(env_file)
        raise ValueError(f"Missing required keys in {where}: {', '.join(missing)}")

    return {
        "url": base_url,
        "organizationId": org_id,
        "apiKey": api_key,
        "authHeader": auth_header,
    }


class SingleVulnReportGenerator:
    """Generate a detailed report for the top 1 vulnerability"""
    
    def __init__(self, env_file: Optional[str] = None, env_section: Optional[str] = None):
        """Initialize with credentials from root .env or optional legacy section."""
        repo_root = find_repo_root(Path.cwd())
        path = Path(env_file) if env_file else (repo_root / ".env")
        auth_config = load_credentials(path, env_section)

        self.base_url = auth_config['url']
        self.org_id = auth_config['organizationId']
        self.api_key = auth_config['apiKey']
        self.auth_header = auth_config['authHeader']
        
        self.headers = {
            'API-Key': self.api_key,
            'Authorization': self.auth_header,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
    
    def _make_request(self, endpoint: str, method: str = 'GET', params: Optional[Dict] = None, 
                     json_data: Optional[Dict] = None) -> Optional[Dict]:
        """Make HTTP request to Contrast API"""
        url = f"{self.base_url}{endpoint}"
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=self.headers, params=params, timeout=30)
            elif method == 'POST':
                response = requests.post(url, headers=self.headers, params=params,
                                       json=json_data, timeout=30)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            response.raise_for_status()
            return response.json()
        
        except requests.exceptions.RequestException as e:
            if hasattr(e, 'response') and e.response is not None:
                print(f"    ⚠ API Error: {e.response.status_code}")
            else:
                print(f"    ⚠ Request failed: {str(e)[:100]}")
            return None
    
    def get_licensed_applications(self) -> List[Dict]:
        """Fetch all licensed, unarchived applications"""
        print("🔍 Fetching licensed applications...")
        
        endpoint = f"/Contrast/api/ng/{self.org_id}/applications/name"
        params = {'includeArchived': 'False', 'includeOnlyLicensed': 'True'}
        
        data = self._make_request(endpoint, params=params)
        
        if data and 'applications' in data:
            apps = data['applications']
            print(f"✅ Found {len(apps)} licensed applications\n")
            return apps
        
        print("❌ No applications found")
        return []
    
    def select_application(self, apps: List[Dict]) -> Optional[Dict]:
        """Present application list and get user selection"""
        if not apps:
            return None
        
        print("=" * 70)
        print("AVAILABLE APPLICATIONS")
        print("=" * 70)
        
        for idx, app in enumerate(apps, 1):
            name = app.get('name', 'Unknown')
            app_id = app.get('app_id') or app.get('appId')
            language = app.get('language', 'N/A')
            print(f"{idx}. {name}")
            print(f"   ID: {app_id}")
            print(f"   Language: {language}")
            print()
        
        while True:
            try:
                choice = input(f"Select an application (1-{len(apps)}) or 'q' to quit: ").strip()
                
                if choice.lower() == 'q':
                    print("Exiting...")
                    return None
                
                idx = int(choice) - 1
                if 0 <= idx < len(apps):
                    return apps[idx]
                else:
                    print(f"❌ Please enter a number between 1 and {len(apps)}")
            
            except ValueError:
                print("❌ Invalid input. Please enter a number.")
    
    def get_top_vulnerability(self, app_id: str) -> Optional[Dict]:
        """Get the top 1 critical/high severity vulnerability"""
        print(f"\n🔍 Fetching top critical/high vulnerability...")
        
        # Fetch top vulnerabilities with combined sorting
        payload = {
            "quickFilter": "OPEN",
            "modules": [app_id],
            "timestampFilter": "LAST",
            "severities": ["CRITICAL", "HIGH"],
            "status": ["Reported", "Confirmed", "Suspicious"],
            "sort": "-severity,-likelihood",  # Sort by severity, then likelihood
            "expand": "skip_links",
            "limit": 10  # Get top 10 to prioritize by rule severity
        }
        
        endpoint = f"/Contrast/api/ng/{self.org_id}/orgtraces/filter"
        data = self._make_request(endpoint, method='POST', json_data=payload)
        
        if data and 'traces' in data and len(data['traces']) > 0:
            # Prioritize vulnerabilities by rule severity score
            # SQL Injection, XXE, Command Injection should rank highest
            high_priority_rules = {
                'sql-injection': 1000,
                'cmd-injection': 950,
                'xxe': 940,
                'path-traversal': 930,
                'ldap-injection': 920,
                'crypto-bad-mac': 910,
                'crypto-weak-randomness': 900,
                'unvalidated-redirect': 850,
                'xss': 800,
                'trust-boundary-violation': 750,
                'header-injection': 700,
                'verb-tampering': 500,  # Lower priority
            }
            
            vulns = data['traces']
            
            # Score each vulnerability
            for vuln in vulns:
                rule_name = vuln.get('rule_name', '').lower()
                severity = vuln.get('severity', 'LOW')
                likelihood = vuln.get('likelihood', 'LOW')
                
                # Base score from severity
                severity_score = {'CRITICAL': 10000, 'HIGH': 5000, 'MEDIUM': 2500, 'LOW': 1000}.get(severity, 0)
                
                # Add likelihood score
                likelihood_score = {'HIGH': 500, 'MEDIUM': 250, 'LOW': 100}.get(likelihood, 0)
                
                # Add rule priority bonus
                rule_bonus = high_priority_rules.get(rule_name, 600)
                
                vuln['_calculated_score'] = severity_score + likelihood_score + rule_bonus
            
            # Sort by calculated score
            vulns.sort(key=lambda v: v.get('_calculated_score', 0), reverse=True)
            
            top_vuln = vulns[0]
            print(f"✅ Found vulnerability: {top_vuln.get('title', 'Unknown')}")
            print(f"   Rule: {top_vuln.get('rule_name', 'Unknown')}")
            print(f"   Severity: {top_vuln.get('severity', 'Unknown')} | Likelihood: {top_vuln.get('likelihood', 'Unknown')}")
            print(f"   Score: {top_vuln.get('_calculated_score', 0)}\n")
            return top_vuln
        
        print("🎉 No critical/high vulnerabilities found!")
        return None
    
    def get_vulnerability_details(self, app_id: str, trace_uuid: str) -> Optional[Dict]:
        """Get comprehensive vulnerability details using the filter endpoint"""
        print(f"📋 Loading vulnerability details...")
        
        # This is the main endpoint the UI uses - it returns everything
        endpoint = f"/Contrast/api/ng/{self.org_id}/traces/{app_id}/filter/{trace_uuid}"
        params = {'expand': 'events,notes_count,application,server_environments,violations,skip_links'}
        
        data = self._make_request(endpoint, params=params)
        
        if data and 'trace' in data:
            print(f"✅ Loaded vulnerability details")
            return data['trace']
        
        print("⚠️  Could not load detailed info")
        return None
    
    def get_story(self, trace_uuid: str) -> Optional[str]:
        """Get vulnerability story - returns formatted chapters"""
        print(f"  → Fetching story...")
        endpoint = f"/Contrast/api/ng/{self.org_id}/traces/{trace_uuid}/story"
        params = {'expand': 'skip_links'}
        data = self._make_request(endpoint, params=params)
        
        if data and 'story' in data and 'chapters' in data['story']:
            chapters = data['story']['chapters']
            if chapters:
                print(f"  ✓ Story retrieved ({len(chapters)} chapters)")
                # Combine all chapters into formatted text
                story_parts = []
                for chapter in chapters:
                    intro = chapter.get('introText', '')
                    body = chapter.get('body', '')
                    if intro:
                        story_parts.append(self._clean_html(intro))
                    if body:
                        story_parts.append(f"\n```\n{body}\n```")
                return '\n\n'.join(story_parts) if story_parts else None
        
        print(f"  ✗ No story data")
        return None
    
    def get_recommendation(self, trace_uuid: str) -> Optional[str]:
        """Get vulnerability recommendation"""
        print(f"  → Fetching recommendation...")
        endpoint = f"/Contrast/api/ng/{self.org_id}/traces/{trace_uuid}/recommendation"
        params = {'expand': 'skip_links'}
        data = self._make_request(endpoint, params=params)
        
        if data and 'recommendation' in data:
            rec_data = data['recommendation']
            result = rec_data.get('formattedText') or rec_data.get('text')
            if result:
                print(f"  ✓ Recommendation retrieved ({len(result)} chars)")
                return result
        
        print(f"  ✗ No recommendation data")
        return None
    
    def get_events(self, trace_uuid: str) -> List[Dict]:
        """Get vulnerability events (data flow / stack traces) - Details tab"""
        print(f"  → Fetching events (Details tab)...")
        endpoint = f"/Contrast/api/ng/{self.org_id}/traces/{trace_uuid}/events/summary"
        params = {'expand': 'skip_links', 'legacy': 'false'}
        data = self._make_request(endpoint, params=params)
        
        if data and 'events' in data:
            events = data['events']
            print(f"  ✓ Events retrieved ({len(events)} events)")
            return events
        
        print(f"  ✗ No events data")
        return []
    
    def get_notes(self, app_id: str, trace_uuid: str) -> List[Dict]:
        """Get vulnerability notes"""
        print(f"  → Fetching notes...")
        endpoint = f"/Contrast/api/ng/{self.org_id}/applications/{app_id}/traces/{trace_uuid}/notes"
        params = {'expand': 'skip_links'}
        data = self._make_request(endpoint, params=params)
        
        if data and 'notes' in data:
            notes = data['notes']
            if notes:
                print(f"  ✓ Notes retrieved ({len(notes)} notes)")
            else:
                print(f"  ℹ No notes found")
            return notes
        
        print(f"  ✗ Could not fetch notes")
        return []
    
    def get_http_request(self, trace_uuid: str) -> Optional[str]:
        """Get HTTP request that triggered the vulnerability"""
        print(f"  → Fetching HTTP request...")
        endpoint = f"/Contrast/api/ng/{self.org_id}/traces/{trace_uuid}/httprequest"
        params = {'expand': 'skip_links'}
        data = self._make_request(endpoint, params=params)
        
        if data and 'http_request' in data:
            http_req = data['http_request']
            # Get the raw text of the HTTP request
            request_text = http_req.get('text', '')
            if request_text:
                print(f"  ✓ HTTP request retrieved")
                return request_text
        
        print(f"  ℹ No HTTP request data available")
        return None
    
    def _format_event(self, event: Dict) -> str:
        """Format a single event for display"""
        lines = []
        
        # Event header
        event_type = event.get('type', 'Unknown')
        description = event.get('description', '')
        important = event.get('important', False)
        marker = "**" if important else ""
        
        lines.append(f"{marker}{description}{marker}")
        
        # Code view
        if 'codeView' in event and 'lines' in event['codeView']:
            code_lines = event['codeView']['lines']
            if code_lines:
                code_text = '\n'.join([line.get('text', '') for line in code_lines])
                lines.append(f"```java\n{self._clean_html(code_text)}\n```")
        
        # Location
        if 'probableStartLocationView' in event and 'lines' in event['probableStartLocationView']:
            loc_lines = event['probableStartLocationView']['lines']
            if loc_lines:
                location = '\n'.join([line.get('text', '') for line in loc_lines])
                lines.append(f"*Location:* `{self._clean_html(location)}`")
        
        # Data view
        if 'dataView' in event and 'lines' in event['dataView']:
            data_lines = event['dataView']['lines']
            if data_lines:
                data_text = '\n'.join([line.get('text', '') for line in data_lines])
                lines.append(f"*Data:* `{self._clean_html(data_text)}`")
        
        return '\n\n'.join(lines)
    
    def _clean_html(self, html: str) -> str:
        """Basic HTML entity and tag removal for markdown"""
        if not html:
            return ""
        
        # Decode HTML entities
        html = html.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&')
        html = html.replace('&quot;', '"').replace('&#39;', "'")
        
        # Simple tag removal
        text = re.sub(r'<br\s*/?>', '\n', html)
        text = re.sub(r'<p>', '\n', text)
        text = re.sub(r'</p>', '\n', text)
        text = re.sub(r'<li>', '\n- ', text)
        text = re.sub(r'<[^>]+>', '', text)
        # Clean up extra newlines
        text = re.sub(r'\n\n+', '\n\n', text)
        return text.strip()
    
    def generate_markdown_report(self, app: Dict, vuln: Dict, vuln_details: Optional[Dict],
                                app_id: str, filename: Optional[str] = None) -> str:
        """Generate comprehensive Markdown report"""
        
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            app_name = app.get('name', 'app').replace(' ', '_')
            output_dir = Path(__file__).resolve().parent / "Output"
            filename = str(output_dir / f"top_vuln_{app_name}_{timestamp}.md")
        
        print(f"\n📝 Generating report: {filename}")
        print(f"🔍 Gathering vulnerability data...\n")
        
        # Extract basic info
        trace_uuid = vuln.get('uuid') or vuln.get('trace_uuid')
        title = vuln.get('title', 'Unknown Vulnerability')
        severity = vuln.get('severity', 'UNKNOWN')
        status = vuln.get('status', 'Unknown')
        rule = vuln.get('rule_name') or vuln.get('rule', 'N/A')
        language = vuln.get('language', app.get('language', 'N/A'))
        
        # Start building report
        lines = []
        lines.append(f"# Top Vulnerability Report")
        lines.append(f"\n**Application:** {app.get('name', 'Unknown')}")
        lines.append(f"\n**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("\n---\n")
        
        # Vulnerability Overview
        lines.append(f"## {title}")
        lines.append(f"\n**Severity:** `{severity}`")
        lines.append(f"\n**Status:** `{status}`")
        lines.append(f"\n**Rule:** {rule}")
        lines.append(f"\n**Language:** {language}")
        lines.append(f"\n**UUID:** `{trace_uuid}`")
        
        # Add tags if available  
        if vuln_details and 'tags' in vuln_details:
            tags = vuln_details.get('tags', [])
            if tags:
                tag_names = [tag.get('name') for tag in tags if tag.get('name')]
                if tag_names:
                    lines.append(f"\n**Tags:** {', '.join(tag_names)}")
        
        # Server environments
        if vuln_details and 'server_environments' in vuln_details:
            envs = vuln_details.get('server_environments', [])
            if envs:
                lines.append(f"\n**Environments:** {', '.join(envs)}")
        
        lines.append("\n")
        
        # Get story
        story = self.get_story(trace_uuid)
        if story:
            lines.append("## 📖 Vulnerability Story")
            lines.append(f"\n{story}\n")
        
        # Add evidence from comprehensive endpoint
        if vuln_details and 'evidence' in vuln_details:
            evidence = vuln_details.get('evidence', '')
            if evidence:
                lines.append("## 🔍 Evidence")
                lines.append(f"\n```\n{evidence}\n```\n")
        
        # Get events (Details tab - stack traces / data flow)
        events = self.get_events(trace_uuid)
        if events:
            lines.append("## 📋 Details (Data Flow / Stack Traces)")
            lines.append(f"\n*Showing {len(events)} event(s) in the vulnerability data flow*\n")
            
            # Display important events first
            important_events = [e for e in events if e.get('important', False)]
            other_events = [e for e in events if not e.get('important', False)]
            
            for idx, event in enumerate(important_events + other_events, 1):
                lines.append(f"### Event {idx}: {event.get('description', 'Unknown')}")
                lines.append(self._format_event(event))
                lines.append("")  # Add spacing between events
        
        # Get HTTP request info
        http_request = self.get_http_request(trace_uuid)
        if http_request:
            lines.append("## 🌐 HTTP Request Info")
            lines.append("\n*The HTTP request that triggered this vulnerability:*\n")
            lines.append(f"```http\n{http_request}\n```\n")
        
        # Get recommendation (moved AFTER Details and HTTP Info)
        recommendation = self.get_recommendation(trace_uuid)
        if recommendation:
            lines.append("## 🔧 How to Fix")
            lines.append(f"\n{self._clean_html(recommendation)}\n")
        
        # Get notes
        notes = self.get_notes(app_id, trace_uuid)
        if notes:
            lines.append("## 📝 Notes")
            for note in notes:
                creator = note.get('creator') or {}
                if not isinstance(creator, dict):
                    creator = {}
                username = creator.get('name', 'Unknown User')
                timestamp = note.get('creation', 0)
                note_text = note.get('note', '')
                
                if timestamp:
                    time_str = datetime.fromtimestamp(timestamp/1000).strftime('%Y-%m-%d %H:%M:%S')
                    lines.append(f"\n**{username}** ({time_str}):")
                else:
                    lines.append(f"\n**{username}**:")
                
                lines.append(f"{note_text}\n")
        
        # Vulnerability Details from the comprehensive endpoint
        if vuln_details:
            # Add first/last detected
            first_seen = vuln_details.get('first_time_seen')
            last_seen = vuln_details.get('last_time_seen')
            if first_seen or last_seen:
                lines.append("## 📅 Timeline")
                if first_seen:
                    lines.append(f"\n**First Detected:** {datetime.fromtimestamp(first_seen/1000).strftime('%Y-%m-%d %H:%M:%S')}")
                if last_seen:
                    lines.append(f"\n**Last Detected:** {datetime.fromtimestamp(last_seen/1000).strftime('%Y-%m-%d %H:%M:%S')}")
                
                total_traces = vuln_details.get('total_traces_received', 0)
                if total_traces:
                    lines.append(f"\n**Total Instances:** {total_traces}")
                lines.append("\n")
            
            # Impact, Likelihood, Confidence
            impact = vuln_details.get('impact', '')
            likelihood = vuln_details.get('likelihood', '')
            confidence = vuln_details.get('confidence', '')
            
            if impact or likelihood or confidence:
                lines.append("## 📊 Risk Assessment")
                if impact:
                    lines.append(f"\n**Impact:** {vuln_details.get('impact_label', impact)}")
                if likelihood:
                    lines.append(f"\n**Likelihood:** {vuln_details.get('likelihood_label', likelihood)}")
                if confidence:
                    lines.append(f"\n**Confidence:** {vuln_details.get('confidence_label', confidence)}")
                lines.append("\n")
        
        # Activity/Violations if available
        if vuln_details and 'violations' in vuln_details:
            violations = vuln_details.get('violations', [])
            if violations:
                lines.append("## ⚠️ Policy Violations")
                for violation in violations:
                    policy = violation.get('policy_name', 'Unknown Policy')
                    lines.append(f"- {policy}")
                lines.append("")
        
        lines.append("\n---\n")
        lines.append(f"\n*Report generated by Contrast Security Vulnerability Reporter*")
        
        # Write to file
        content = '\n'.join(lines)
        
        out_path = Path(filename)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        # Summary of what was collected
        print(f"\n📊 Data Collection Summary:")
        print(f"  Vulnerability Details: {'✓' if vuln_details else '✗'}")
        print(f"  Story: {'✓' if story else '✗'}")
        print(f"  Evidence: {'✓' if (vuln_details and vuln_details.get('evidence')) else '✗'}")
        print(f"  Events (Details): {'✓' if events else '✗'} ({len(events) if events else 0} events)")
        print(f"  HTTP Request: {'✓' if http_request else '✗'}")
        print(f"  Recommendation: {'✓' if recommendation else '✗'}")
        print(f"  Notes: {'✓' if notes else '✗'} ({len(notes) if notes else 0} notes)")
        print(f"  Timeline: {'✓' if (vuln_details and vuln_details.get('first_time_seen')) else '✗'}")
        print(f"  Risk Assessment: {'✓' if (vuln_details and vuln_details.get('impact')) else '✗'}")
        
        print(f"\n✅ Report generated successfully!\n")
        return str(out_path)


def select_application_by_name(apps: List[Dict], app_name: str) -> Optional[Dict]:
    target = app_name.lower().strip()
    for app in apps:
        if app.get('name', '').lower() == target:
            return app
    return None


def main():
    """Main execution flow"""
    print("=" * 70)
    print("CONTRAST TOP VULNERABILITY REPORT GENERATOR")
    print("=" * 70)
    print()
    
    try:
        parser = argparse.ArgumentParser(description="Generate top vulnerability report")
        parser.add_argument('--env-file', help='Path to .env file (default: [repo-root]/.env)')
        parser.add_argument('--env-section', help='Optional section in legacy sectioned .env file')
        parser.add_argument('--app-name', help='Application name (skip interactive selection)')
        parser.add_argument('--output', help='Output markdown path (default: script Output folder)')
        args = parser.parse_args()

        # Initialize generator
        generator = SingleVulnReportGenerator(args.env_file, args.env_section)
        
        # Step 1: Get licensed applications
        apps = generator.get_licensed_applications()
        if not apps:
            print("No applications available. Exiting.")
            sys.exit(1)
        
        # Step 2: Select an application
        if args.app_name:
            selected_app = select_application_by_name(apps, args.app_name)
            if not selected_app:
                print(f"Application '{args.app_name}' not found.")
                sys.exit(1)
        else:
            selected_app = generator.select_application(apps)
        if not selected_app:
            sys.exit(0)
        
        app_id = selected_app.get('app_id') or selected_app.get('appId')
        app_name = selected_app.get('name', 'Unknown')
        
        print(f"\n✓ Selected: {app_name}")
        
        # Step 3: Get top 1 vulnerability
        vuln = generator.get_top_vulnerability(app_id)
        if not vuln:
            print(f"\n🎉 No critical/high vulnerabilities found in {app_name}")
            sys.exit(0)
        
        trace_uuid = vuln.get('uuid') or vuln.get('trace_uuid')
        
        # Step 4: Get detailed vulnerability info
        vuln_details = generator.get_vulnerability_details(app_id, trace_uuid)
        
        # Step 5: Generate report  
        report_file = generator.generate_markdown_report(selected_app, vuln, vuln_details, app_id, args.output)
        
        print("=" * 70)
        print(f"✅ REPORT COMPLETE: {report_file}")
        print("=" * 70)
    
    except KeyboardInterrupt:
        print("\n\n❌ Operation cancelled by user")
        sys.exit(1)
    
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
CVE Extractor and Sorter for Live CVE Benchmark

This script extracts CVE records from the cvelistV5 repository and sorts them
by publication date to help build a live benchmark for testing code agent repair capabilities.
"""

import json
import os
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional
import argparse


def parse_datetime(date_str: Optional[str]) -> Optional[datetime]:
    """Parse ISO 8601 datetime string and ensure timezone-aware result."""
    if not date_str:
        return None
    try:
        from datetime import timezone
        # Replace 'Z' with '+00:00' for ISO format parsing
        dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        # Ensure the datetime is timezone-aware
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, AttributeError):
        return None


def extract_cve_info(file_path: Path) -> Optional[Dict]:
    """Extract relevant information from a CVE JSON file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Extract metadata
        metadata = data.get('cveMetadata', {})
        cve_id = metadata.get('cveId', '')
        state = metadata.get('state', '')

        # Skip non-published CVEs
        if state != 'PUBLISHED':
            return None

        date_reserved = metadata.get('dateReserved')
        date_published = metadata.get('datePublished')
        date_updated = metadata.get('dateUpdated')

        # Skip CVEs without publication date
        if not date_published:
            return None

        # Extract CNA container info
        cna = data.get('containers', {}).get('cna', {})

        # Extract description
        descriptions = cna.get('descriptions', [])
        description = ''
        if descriptions:
            description = descriptions[0].get('value', '')

        # Extract CVSS score (try v4, v3.1, v3.0, v2)
        cvss_score = None
        cvss_severity = None
        metrics = cna.get('metrics', [])
        for metric in metrics:
            if 'cvssV4_0' in metric:
                cvss_score = metric['cvssV4_0'].get('baseScore')
                cvss_severity = metric['cvssV4_0'].get('baseSeverity')
                break
            elif 'cvssV3_1' in metric:
                cvss_score = metric['cvssV3_1'].get('baseScore')
                cvss_severity = metric['cvssV3_1'].get('baseSeverity')
                break
            elif 'cvssV3_0' in metric:
                cvss_score = metric['cvssV3_0'].get('baseScore')
                cvss_severity = metric['cvssV3_0'].get('baseSeverity')
                break
            elif 'cvssV2_0' in metric:
                cvss_score = metric['cvssV2_0'].get('baseScore')
                break

        # Extract affected products
        affected = cna.get('affected', [])
        products = []
        for item in affected:
            vendor = item.get('vendor', 'Unknown')
            product = item.get('product', 'Unknown')
            products.append(f"{vendor} {product}")

        # Check for exploits in references
        has_exploit = False
        references = cna.get('references', [])
        for ref in references:
            tags = ref.get('tags', [])
            if 'exploit' in tags or 'technical-description' in tags:
                has_exploit = True
                break

        # Also check ADP containers for exploits
        adp_containers = data.get('containers', {}).get('adp', [])
        for adp in adp_containers:
            adp_refs = adp.get('references', [])
            for ref in adp_refs:
                tags = ref.get('tags', [])
                if 'exploit' in tags:
                    has_exploit = True
                    break

        return {
            'cve_id': cve_id,
            'state': state,
            'date_reserved': parse_datetime(date_reserved),
            'date_published': parse_datetime(date_published),
            'date_updated': parse_datetime(date_updated),
            'description': description[:200] + '...' if len(description) > 200 else description,
            'cvss_score': cvss_score,
            'cvss_severity': cvss_severity,
            'products': products,
            'has_exploit': has_exploit,
            'file_path': str(file_path)
        }

    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return None


def find_all_cve_files(base_dir: Path) -> List[Path]:
    """Find all CVE JSON files in the repository."""
    cve_files = []
    cves_dir = base_dir / 'cves'

    if not cves_dir.exists():
        print(f"Error: CVEs directory not found at {cves_dir}")
        return []

    # Recursively find all JSON files
    for json_file in cves_dir.rglob('CVE-*.json'):
        cve_files.append(json_file)

    return cve_files


def main():
    parser = argparse.ArgumentParser(
        description='Extract and sort CVE records for live benchmark testing'
    )
    parser.add_argument(
        '--sort-by',
        choices=['published', 'updated', 'reserved'],
        default='published',
        help='Field to sort by (default: published)'
    )
    parser.add_argument(
        '--days',
        type=int,
        default=None,
        help='Only show CVEs from the last N days'
    )
    parser.add_argument(
        '--min-cvss',
        type=float,
        default=None,
        help='Minimum CVSS score to include'
    )
    parser.add_argument(
        '--exploits-only',
        action='store_true',
        help='Only show CVEs with known exploits'
    )
    parser.add_argument(
        '--limit',
        type=int,
        default=50,
        help='Maximum number of CVEs to display (default: 50)'
    )
    parser.add_argument(
        '--output',
        choices=['table', 'json', 'csv'],
        default='table',
        help='Output format (default: table)'
    )
    parser.add_argument(
        '--year',
        type=int,
        default=None,
        help='Filter by year (e.g., 2025)'
    )

    args = parser.parse_args()

    # Find repository root
    base_dir = Path(__file__).parent

    print(f"Scanning CVE files in {base_dir / 'cves'}...")
    cve_files = find_all_cve_files(base_dir)
    print(f"Found {len(cve_files)} CVE files")

    # Extract CVE information
    print("Processing CVE records...")
    cves = []
    for cve_file in cve_files:
        cve_info = extract_cve_info(cve_file)
        if cve_info:
            cves.append(cve_info)

    print(f"Extracted {len(cves)} published CVE records")

    # Apply filters
    filtered_cves = cves

    # Filter by year
    if args.year:
        filtered_cves = [
            cve for cve in filtered_cves
            if cve['date_published'] and cve['date_published'].year == args.year
        ]
        print(f"Filtered to {len(filtered_cves)} CVEs from year {args.year}")

    # Filter by days
    if args.days:
        from datetime import timezone, timedelta
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=args.days)
        cutoff_date = cutoff_date.replace(hour=0, minute=0, second=0, microsecond=0)

        filtered_cves = [
            cve for cve in filtered_cves
            if cve['date_published'] and cve['date_published'] >= cutoff_date
        ]
        print(f"Filtered to {len(filtered_cves)} CVEs from the last {args.days} days")

    # Filter by CVSS score
    if args.min_cvss:
        filtered_cves = [
            cve for cve in filtered_cves
            if cve['cvss_score'] and cve['cvss_score'] >= args.min_cvss
        ]
        print(f"Filtered to {len(filtered_cves)} CVEs with CVSS >= {args.min_cvss}")

    # Filter by exploits
    if args.exploits_only:
        filtered_cves = [
            cve for cve in filtered_cves
            if cve['has_exploit']
        ]
        print(f"Filtered to {len(filtered_cves)} CVEs with known exploits")

    # Sort CVEs
    sort_field_map = {
        'published': 'date_published',
        'updated': 'date_updated',
        'reserved': 'date_reserved'
    }
    sort_field = sort_field_map[args.sort_by]

    # Create a timezone-aware minimum datetime for comparison
    from datetime import timezone
    min_datetime = datetime.min.replace(tzinfo=timezone.utc)

    filtered_cves.sort(
        key=lambda x: x[sort_field] if x[sort_field] else min_datetime,
        reverse=True
    )

    # Limit results
    display_cves = filtered_cves[:args.limit]

    # Output results
    if args.output == 'table':
        print(f"\n{'='*120}")
        print(f"Top {len(display_cves)} CVEs (sorted by {args.sort_by} date, newest first)")
        print(f"{'='*120}\n")

        for i, cve in enumerate(display_cves, 1):
            print(f"{i}. {cve['cve_id']}")
            print(f"   Published: {cve['date_published'].strftime('%Y-%m-%d %H:%M:%S UTC') if cve['date_published'] else 'N/A'}")
            print(f"   Updated:   {cve['date_updated'].strftime('%Y-%m-%d %H:%M:%S UTC') if cve['date_updated'] else 'N/A'}")

            cvss_str = f"{cve['cvss_score']}" if cve['cvss_score'] else "N/A"
            if cve['cvss_severity']:
                cvss_str += f" ({cve['cvss_severity']})"
            print(f"   CVSS:      {cvss_str}")

            exploit_marker = " [HAS EXPLOIT]" if cve['has_exploit'] else ""
            print(f"   Exploit:   {exploit_marker if cve['has_exploit'] else 'No known exploit'}")

            if cve['products']:
                print(f"   Products:  {', '.join(cve['products'][:3])}")

            print(f"   Description: {cve['description']}")
            print(f"   File: {cve['file_path']}")
            print()

    elif args.output == 'json':
        # Convert datetime to string for JSON serialization
        output_data = []
        for cve in display_cves:
            cve_copy = cve.copy()
            cve_copy['date_reserved'] = cve['date_reserved'].isoformat() if cve['date_reserved'] else None
            cve_copy['date_published'] = cve['date_published'].isoformat() if cve['date_published'] else None
            cve_copy['date_updated'] = cve['date_updated'].isoformat() if cve['date_updated'] else None
            output_data.append(cve_copy)

        print(json.dumps(output_data, indent=2, ensure_ascii=False))

    elif args.output == 'csv':
        import csv
        import sys

        writer = csv.DictWriter(
            sys.stdout,
            fieldnames=['cve_id', 'date_published', 'date_updated', 'cvss_score',
                       'cvss_severity', 'has_exploit', 'products', 'file_path']
        )
        writer.writeheader()

        for cve in display_cves:
            row = {
                'cve_id': cve['cve_id'],
                'date_published': cve['date_published'].isoformat() if cve['date_published'] else '',
                'date_updated': cve['date_updated'].isoformat() if cve['date_updated'] else '',
                'cvss_score': cve['cvss_score'] or '',
                'cvss_severity': cve['cvss_severity'] or '',
                'has_exploit': 'Yes' if cve['has_exploit'] else 'No',
                'products': '; '.join(cve['products']),
                'file_path': cve['file_path']
            }
            writer.writerow(row)

    print(f"\n{'='*120}")
    print(f"Total CVEs matching criteria: {len(filtered_cves)}")
    print(f"Displayed: {len(display_cves)}")
    print(f"{'='*120}")


if __name__ == '__main__':
    main()

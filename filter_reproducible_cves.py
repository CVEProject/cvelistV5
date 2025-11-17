#!/usr/bin/env python3
"""
Filter Reproducible CVEs for Live Benchmark

This script identifies CVEs that are feasible to reproduce in a containerized environment
for testing code agent repair capabilities.
"""

import json
import re
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Optional, Set
import argparse


# Products/vendors that are typically easy to reproduce (open-source web applications)
EASY_TO_REPRODUCE_PATTERNS = [
    # CMS and frameworks
    r'\bwordpress\b', r'\bdrupal\b', r'\bjoomla\b', r'\bmagento\b',
    r'\blaravel\b', r'\bdjango\b', r'\bflask\b', r'\bexpress\b',
    r'\bruby on rails\b', r'\bspring\b', r'\bstruts\b',

    # Common web servers and services
    r'\bnginx\b', r'\bapache\b', r'\btomcat\b', r'\bnode\.?js\b',
    r'\bphp\b', r'\bpython\b', r'\bjava\b', r'\bgo\b',

    # Databases
    r'\bmysql\b', r'\bpostgresql\b', r'\bmongodb\b', r'\bredis\b',
    r'\bmariadb\b', r'\bcassandra\b',

    # Common open-source applications
    r'\bowncloud\b', r'\bnextcloud\b', r'\bgitlab\b', r'\bgit\b',
    r'\bjenkins\b', r'\bdocker\b', r'\bkubernetes\b',
    r'\bphpmyadmin\b', r'\badminer\b', r'\bgrafana\b',

    # Generic indicators
    r'\bopen.?source\b', r'\bfree.?ware\b', r'\bgithub\b',
]

# Products/vendors that are typically hard to reproduce
HARD_TO_REPRODUCE_PATTERNS = [
    # Hardware/firmware
    r'\bfirmware\b', r'\brouter\b', r'\bswitch\b', r'\bfirewall\b',
    r'\bios\b', r'\bprinter\b', r'\bcamera\b', r'\bip camera\b',

    # Enterprise/proprietary software
    r'\boracle\b', r'\bsap\b', r'\bmicrosoft\b', r'\bwindows\b',
    r'\bexchange server\b', r'\bsharepoint\b', r'\bactive directory\b',
    r'\bcisco\b', r'\bjuniper\b', r'\bpalo alto\b', r'\bfortinet\b',
    r'\bvmware\b', r'\bcitrix\b', r'\bsonicwall\b',

    # Mobile
    r'\bandroid\b', r'\bios app\b', r'\biphone\b', r'\bipad\b',
    r'\bmobile app\b', r'\bapk\b',

    # Desktop applications
    r'\bmacos\b', r'\bmac os\b', r'\bwindows application\b',
    r'\bdesktop\b', r'\belectron\b',

    # OS/Kernel
    r'\bkernel\b', r'\blinux kernel\b', r'\bwindows kernel\b',
    r'\bdriver\b', r'\bbios\b', r'\buefi\b',
]

# CVE weakness types that are typically reproducible
REPRODUCIBLE_CWE_TYPES = {
    'CWE-89',   # SQL Injection
    'CWE-79',   # XSS
    'CWE-22',   # Path Traversal
    'CWE-78',   # OS Command Injection
    'CWE-434',  # Unrestricted Upload
    'CWE-918',  # SSRF
    'CWE-306',  # Missing Authentication
    'CWE-285',  # Improper Authorization
    'CWE-798',  # Hard-coded Credentials
    'CWE-611',  # XXE
    'CWE-502',  # Deserialization
    'CWE-73',   # External Control of File Name
    'CWE-94',   # Code Injection
    'CWE-352',  # CSRF
    'CWE-601',  # Open Redirect
}


def parse_datetime(date_str: Optional[str]) -> Optional[datetime]:
    """Parse ISO 8601 datetime string."""
    if not date_str:
        return None
    try:
        dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, AttributeError):
        return None


def check_github_links(references: List[Dict]) -> bool:
    """Check if CVE has GitHub repository links (indicates open-source)."""
    for ref in references:
        url = ref.get('url', '').lower()
        tags = ref.get('tags', [])

        # GitHub repo link (not just exploit)
        if 'github.com' in url and 'exploit' not in tags:
            # Check if it's a repo link (not just an issue or gist)
            if '/blob/' in url or '/tree/' in url or '/releases/' in url:
                return True
    return False


def check_exploit_availability(references: List[Dict], adp_containers: List[Dict]) -> tuple:
    """Check if CVE has exploit/POC and return (has_exploit, has_poc, exploit_url)."""
    has_exploit = False
    has_poc = False
    exploit_urls = []

    # Check CNA references
    for ref in references:
        tags = ref.get('tags', [])
        url = ref.get('url', '')

        if 'exploit' in tags or 'technical-description' in tags:
            has_exploit = True
            exploit_urls.append(url)

        # GitHub exploit repos
        if 'github.com' in url.lower() and any(keyword in url.lower() for keyword in ['exploit', 'poc', 'cve']):
            has_poc = True
            exploit_urls.append(url)

    # Check ADP containers
    for adp in adp_containers:
        adp_refs = adp.get('references', [])
        for ref in adp_refs:
            tags = ref.get('tags', [])
            if 'exploit' in tags:
                has_exploit = True
                exploit_urls.append(ref.get('url', ''))

    return has_exploit, has_poc, exploit_urls[:3]  # Limit to 3 URLs


def calculate_reproducibility_score(cve_data: Dict) -> tuple:
    """
    Calculate a reproducibility score (0-100) based on various factors.
    Returns (score, reasons)
    """
    score = 0
    reasons = []

    cna = cve_data.get('containers', {}).get('cna', {})
    metadata = cve_data.get('cveMetadata', {})
    adp = cve_data.get('containers', {}).get('adp', [])

    # Factor 1: Attack Vector (20 points)
    metrics = cna.get('metrics', [])
    is_network_attack = False
    for metric in metrics:
        for cvss_ver in ['cvssV4_0', 'cvssV3_1', 'cvssV3_0', 'cvssV2_0']:
            if cvss_ver in metric:
                cvss = metric[cvss_ver]
                av = cvss.get('attackVector', cvss.get('vectorString', ''))
                if isinstance(av, str) and ('NETWORK' in av.upper() or 'AV:N' in av.upper()):
                    score += 20
                    is_network_attack = True
                    reasons.append("Network-accessible vulnerability")
                break
        if is_network_attack:
            break

    # Factor 2: Product type (25 points)
    affected = cna.get('affected', [])
    product_text = ''
    for item in affected:
        vendor = item.get('vendor', '').lower()
        product = item.get('product', '').lower()
        product_text += f"{vendor} {product} "

    description = ''
    for desc in cna.get('descriptions', []):
        description += desc.get('value', '').lower() + ' '

    full_text = product_text + description

    # Check if easy to reproduce
    easy_matches = 0
    for pattern in EASY_TO_REPRODUCE_PATTERNS:
        if re.search(pattern, full_text, re.IGNORECASE):
            easy_matches += 1

    # Check if hard to reproduce
    hard_matches = 0
    for pattern in HARD_TO_REPRODUCE_PATTERNS:
        if re.search(pattern, full_text, re.IGNORECASE):
            hard_matches += 1

    if easy_matches > 0 and hard_matches == 0:
        score += 25
        reasons.append(f"Open-source/common software ({easy_matches} indicators)")
    elif hard_matches > 0:
        score -= 20
        reasons.append(f"Difficult platform ({hard_matches} indicators)")

    # Factor 3: Exploit/POC availability (20 points)
    references = cna.get('references', [])
    has_exploit, has_poc, exploit_urls = check_exploit_availability(references, adp)

    if has_exploit and has_poc:
        score += 20
        reasons.append(f"Has exploit + POC (GitHub)")
    elif has_exploit:
        score += 15
        reasons.append("Has exploit code")
    elif has_poc:
        score += 10
        reasons.append("Has POC")

    # Factor 4: CWE type (15 points)
    problem_types = cna.get('problemTypes', [])
    cwe_ids = set()
    for pt in problem_types:
        for desc in pt.get('descriptions', []):
            cwe_id = desc.get('cweId', '')
            if cwe_id:
                cwe_ids.add(cwe_id)

    reproducible_cwes = cwe_ids.intersection(REPRODUCIBLE_CWE_TYPES)
    if reproducible_cwes:
        score += 15
        reasons.append(f"Common vulnerability type: {', '.join(reproducible_cwes)}")

    # Factor 5: Has version info (10 points)
    has_specific_version = False
    for item in affected:
        versions = item.get('versions', [])
        if versions and len(versions) > 0:
            has_specific_version = True
            break

    if has_specific_version:
        score += 10
        reasons.append("Specific version information available")

    # Factor 6: Technical details (10 points)
    has_tech_details = False
    for ref in references:
        tags = ref.get('tags', [])
        if 'technical-description' in tags or 'patch' in tags:
            has_tech_details = True
            break

    if has_tech_details:
        score += 10
        reasons.append("Technical description/patch available")

    # Factor 7: GitHub source code link (bonus 10 points)
    if check_github_links(references):
        score += 10
        reasons.append("GitHub repository link found")

    # Factor 8: Tags
    tags = cna.get('tags', [])
    if 'x_freeware' in tags:
        score += 5
        reasons.append("Marked as freeware")

    return min(score, 100), reasons


def extract_cve_info(file_path: Path) -> Optional[Dict]:
    """Extract CVE information with reproducibility scoring."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        metadata = data.get('cveMetadata', {})
        if metadata.get('state') != 'PUBLISHED':
            return None

        date_published = metadata.get('datePublished')
        if not date_published:
            return None

        cna = data.get('containers', {}).get('cna', {})

        # Extract basic info
        cve_id = metadata.get('cveId', '')

        # Get description
        descriptions = cna.get('descriptions', [])
        description = descriptions[0].get('value', '')[:300] if descriptions else ''

        # Get CVSS
        cvss_score = None
        cvss_severity = None
        metrics = cna.get('metrics', [])
        for metric in metrics:
            for cvss_ver in ['cvssV4_0', 'cvssV3_1', 'cvssV3_0']:
                if cvss_ver in metric:
                    cvss_score = metric[cvss_ver].get('baseScore')
                    cvss_severity = metric[cvss_ver].get('baseSeverity')
                    break
            if cvss_score:
                break

        # Get products
        affected = cna.get('affected', [])
        products = []
        for item in affected:
            vendor = item.get('vendor', 'Unknown')
            product = item.get('product', 'Unknown')
            products.append(f"{vendor}/{product}")

        # Get CWE
        problem_types = cna.get('problemTypes', [])
        cwes = []
        for pt in problem_types:
            for desc in pt.get('descriptions', []):
                cwe_id = desc.get('cweId', '')
                if cwe_id:
                    cwes.append(cwe_id)

        # Get exploit info
        references = cna.get('references', [])
        adp = data.get('containers', {}).get('adp', [])
        has_exploit, has_poc, exploit_urls = check_exploit_availability(references, adp)

        # Calculate reproducibility score
        repro_score, repro_reasons = calculate_reproducibility_score(data)

        return {
            'cve_id': cve_id,
            'date_published': parse_datetime(date_published),
            'date_updated': parse_datetime(metadata.get('dateUpdated')),
            'description': description,
            'cvss_score': cvss_score,
            'cvss_severity': cvss_severity,
            'products': products[:3],  # Limit to 3
            'cwes': cwes,
            'has_exploit': has_exploit,
            'has_poc': has_poc,
            'exploit_urls': exploit_urls,
            'reproducibility_score': repro_score,
            'reproducibility_reasons': repro_reasons,
            'file_path': str(file_path)
        }

    except Exception as e:
        return None


def main():
    parser = argparse.ArgumentParser(
        description='Filter CVEs by reproducibility for live benchmark testing'
    )
    parser.add_argument(
        '--min-score',
        type=int,
        default=50,
        help='Minimum reproducibility score (0-100, default: 50)'
    )
    parser.add_argument(
        '--year',
        type=int,
        default=2025,
        help='Filter by year (default: 2025)'
    )
    parser.add_argument(
        '--min-cvss',
        type=float,
        default=None,
        help='Minimum CVSS score'
    )
    parser.add_argument(
        '--require-exploit',
        action='store_true',
        help='Only show CVEs with exploit/POC'
    )
    parser.add_argument(
        '--limit',
        type=int,
        default=100,
        help='Maximum number of CVEs to display (default: 100)'
    )
    parser.add_argument(
        '--output',
        choices=['table', 'json', 'csv'],
        default='table',
        help='Output format (default: table)'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Show detailed reproducibility reasons'
    )

    args = parser.parse_args()

    base_dir = Path(__file__).parent
    cves_dir = base_dir / 'cves'

    print(f"Scanning CVE files for year {args.year}...")

    # Find CVE files for the specified year
    year_dir = cves_dir / str(args.year)
    if not year_dir.exists():
        print(f"Error: No CVEs found for year {args.year}")
        return

    cve_files = list(year_dir.rglob('CVE-*.json'))
    print(f"Found {len(cve_files)} CVE files for {args.year}")

    # Process CVEs
    print("Processing and scoring CVEs...")
    cves = []
    for cve_file in cve_files:
        cve_info = extract_cve_info(cve_file)
        if cve_info:
            cves.append(cve_info)

    print(f"Extracted {len(cves)} published CVE records")

    # Apply filters
    filtered_cves = cves

    # Filter by reproducibility score
    filtered_cves = [
        cve for cve in filtered_cves
        if cve['reproducibility_score'] >= args.min_score
    ]
    print(f"Filtered to {len(filtered_cves)} CVEs with score >= {args.min_score}")

    # Filter by CVSS
    if args.min_cvss:
        filtered_cves = [
            cve for cve in filtered_cves
            if cve['cvss_score'] and cve['cvss_score'] >= args.min_cvss
        ]
        print(f"Filtered to {len(filtered_cves)} CVEs with CVSS >= {args.min_cvss}")

    # Filter by exploit
    if args.require_exploit:
        filtered_cves = [
            cve for cve in filtered_cves
            if cve['has_exploit'] or cve['has_poc']
        ]
        print(f"Filtered to {len(filtered_cves)} CVEs with exploit/POC")

    # Sort by reproducibility score
    filtered_cves.sort(key=lambda x: (x['reproducibility_score'], x['cvss_score'] or 0), reverse=True)

    # Limit results
    display_cves = filtered_cves[:args.limit]

    # Output results
    if args.output == 'table':
        print(f"\n{'='*140}")
        print(f"Top {len(display_cves)} Most Reproducible CVEs")
        print(f"{'='*140}\n")

        for i, cve in enumerate(display_cves, 1):
            print(f"{i}. {cve['cve_id']} - Reproducibility Score: {cve['reproducibility_score']}/100")
            print(f"   Published: {cve['date_published'].strftime('%Y-%m-%d')}")

            cvss_str = f"{cve['cvss_score']}" if cve['cvss_score'] else "N/A"
            if cve['cvss_severity']:
                cvss_str += f" ({cve['cvss_severity']})"
            print(f"   CVSS: {cvss_str}")

            if cve['products']:
                print(f"   Products: {', '.join(cve['products'])}")

            if cve['cwes']:
                print(f"   CWEs: {', '.join(cve['cwes'])}")

            exploit_status = []
            if cve['has_exploit']:
                exploit_status.append("Exploit")
            if cve['has_poc']:
                exploit_status.append("POC")
            if exploit_status:
                print(f"   Available: {', '.join(exploit_status)}")

            if cve['exploit_urls'] and args.verbose:
                for url in cve['exploit_urls']:
                    print(f"      - {url}")

            if args.verbose and cve['reproducibility_reasons']:
                print(f"   Why reproducible:")
                for reason in cve['reproducibility_reasons']:
                    print(f"      • {reason}")

            print(f"   Description: {cve['description']}")
            print(f"   File: {cve['file_path']}")
            print()

    elif args.output == 'json':
        output_data = []
        for cve in display_cves:
            cve_copy = cve.copy()
            cve_copy['date_published'] = cve['date_published'].isoformat()
            cve_copy['date_updated'] = cve['date_updated'].isoformat() if cve['date_updated'] else None
            output_data.append(cve_copy)

        print(json.dumps(output_data, indent=2, ensure_ascii=False))

    elif args.output == 'csv':
        import csv
        import sys

        writer = csv.DictWriter(
            sys.stdout,
            fieldnames=['cve_id', 'reproducibility_score', 'date_published', 'cvss_score',
                       'has_exploit', 'has_poc', 'cwes', 'products', 'file_path']
        )
        writer.writeheader()

        for cve in display_cves:
            row = {
                'cve_id': cve['cve_id'],
                'reproducibility_score': cve['reproducibility_score'],
                'date_published': cve['date_published'].strftime('%Y-%m-%d'),
                'cvss_score': cve['cvss_score'] or '',
                'has_exploit': 'Yes' if cve['has_exploit'] else 'No',
                'has_poc': 'Yes' if cve['has_poc'] else 'No',
                'cwes': '; '.join(cve['cwes']),
                'products': '; '.join(cve['products']),
                'file_path': cve['file_path']
            }
            writer.writerow(row)

    print(f"\n{'='*140}")
    print(f"Statistics:")
    print(f"  Total matching CVEs: {len(filtered_cves)}")
    print(f"  Displayed: {len(display_cves)}")
    if filtered_cves:
        avg_score = sum(c['reproducibility_score'] for c in filtered_cves) / len(filtered_cves)
        print(f"  Average reproducibility score: {avg_score:.1f}/100")
        with_exploit = sum(1 for c in filtered_cves if c['has_exploit'] or c['has_poc'])
        print(f"  CVEs with exploit/POC: {with_exploit} ({with_exploit*100//len(filtered_cves)}%)")
    print(f"{'='*140}")


if __name__ == '__main__':
    main()

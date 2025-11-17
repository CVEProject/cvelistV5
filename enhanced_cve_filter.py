#!/usr/bin/env python3
"""
Enhanced CVE Reproducibility Filter - 融合版本
结合了两个脚本的优势
"""

import json
import os
import re
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Optional, Set
import argparse
from dataclasses import dataclass, field


@dataclass
class CVEReproducibility:
    """CVE可复现性评分 - 使用dataclass简化数据结构"""
    cve_id: str
    score: int = 0
    reasons: List[str] = field(default_factory=list)

    # 基本信息
    product: str = ""
    vendor: str = ""
    version: str = ""
    description: str = ""

    # 漏洞信息
    cvss_score: float = 0.0
    cvss_severity: str = ""
    cwes: List[str] = field(default_factory=list)

    # Exploit信息
    poc_url: Optional[str] = None
    exploit_urls: List[str] = field(default_factory=list)
    has_exploit: bool = False
    has_poc: bool = False

    # 时间信息
    date_published: Optional[datetime] = None
    date_updated: Optional[datetime] = None

    # 文件路径
    file_path: str = ""


# 从我的脚本 - 易/难复现产品模式
EASY_TO_REPRODUCE_PATTERNS = [
    r'\bwordpress\b', r'\bdrupal\b', r'\bjoomla\b', r'\bmagento\b',
    r'\blaravel\b', r'\bdjango\b', r'\bflask\b', r'\bexpress\b',
    r'\bruby on rails\b', r'\bspring\b', r'\bstruts\b',
    r'\bnginx\b', r'\bapache\b', r'\btomcat\b', r'\bnode\.?js\b',
    r'\bphp\b', r'\bpython\b', r'\bgithub\b',
]

HARD_TO_REPRODUCE_PATTERNS = [
    r'\bfirmware\b', r'\brouter\b', r'\bswitch\b', r'\bfirewall\b',
    r'\boracle\b', r'\bsap\b', r'\bcisco\b', r'\bpalo alto\b',
    r'\bwindows\b', r'\bmacos\b', r'\bandroid\b', r'\bios\b',
    r'\bkernel\b', r'\bdriver\b',
]

# 从我的脚本 - 可复现的CWE类型
REPRODUCIBLE_CWE_TYPES = {
    'CWE-89', 'CWE-79', 'CWE-22', 'CWE-78', 'CWE-434',
    'CWE-918', 'CWE-306', 'CWE-285', 'CWE-798', 'CWE-611',
    'CWE-502', 'CWE-73', 'CWE-94', 'CWE-352', 'CWE-601',
}


class EnhancedCVEFilter:
    """增强版CVE筛选器 - 融合两个脚本的优势"""

    def __init__(self, cves_dir: str = "cves"):
        self.cves_dir = Path(cves_dir)
        self.results: List[CVEReproducibility] = []

    def parse_datetime(self, date_str: Optional[str]) -> Optional[datetime]:
        """解析ISO 8601日期时间"""
        if not date_str:
            return None
        try:
            dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except (ValueError, AttributeError):
            return None

    def check_exploit_availability(self, references: List[Dict], adp_containers: List[Dict]) -> tuple:
        """检查exploit/POC可用性"""
        has_exploit = False
        has_poc = False
        exploit_urls = []

        # 检查CNA references
        for ref in references:
            tags = ref.get('tags', [])
            url = ref.get('url', '')

            if 'exploit' in tags or 'technical-description' in tags:
                has_exploit = True
                exploit_urls.append(url)

            if 'github.com' in url.lower() and any(k in url.lower() for k in ['exploit', 'poc', 'cve']):
                has_poc = True
                exploit_urls.append(url)

        # 检查ADP containers
        for adp in adp_containers:
            for ref in adp.get('references', []):
                if 'exploit' in ref.get('tags', []):
                    has_exploit = True
                    exploit_urls.append(ref.get('url', ''))

        return has_exploit, has_poc, list(set(exploit_urls[:3]))

    def calculate_reproducibility_score(self, cve_data: Dict, result: CVEReproducibility) -> None:
        """计算可复现性评分 - 融合两个脚本的评分逻辑"""
        cna = cve_data.get('containers', {}).get('cna', {})
        adp = cve_data.get('containers', {}).get('adp', [])

        # === 从我的脚本 - 8维度评分系统 ===

        # 1. 攻击向量 (20分)
        metrics = cna.get('metrics', [])
        for metric in metrics:
            for cvss_ver in ['cvssV4_0', 'cvssV3_1', 'cvssV3_0']:
                if cvss_ver in metric:
                    cvss = metric[cvss_ver]
                    av = cvss.get('attackVector', cvss.get('vectorString', ''))
                    if isinstance(av, str) and ('NETWORK' in av.upper() or 'AV:N' in av.upper()):
                        result.score += 20
                        result.reasons.append("Network-accessible vulnerability")
                        break
            if result.score > 0:
                break

        # 2. 产品类型 (25分) - 使用正则模式匹配
        full_text = f"{result.vendor} {result.product} {result.description}".lower()

        easy_matches = sum(1 for p in EASY_TO_REPRODUCE_PATTERNS if re.search(p, full_text, re.I))
        hard_matches = sum(1 for p in HARD_TO_REPRODUCE_PATTERNS if re.search(p, full_text, re.I))

        if easy_matches > 0 and hard_matches == 0:
            result.score += 25
            result.reasons.append(f"Open-source/common software ({easy_matches} indicators)")
        elif hard_matches > 0:
            result.score -= 20
            result.reasons.append(f"Difficult platform ({hard_matches} indicators)")

        # 3. Exploit可用性 (20分)
        if result.has_exploit and result.has_poc:
            result.score += 20
            result.reasons.append("Has exploit + POC (GitHub)")
        elif result.has_exploit:
            result.score += 15
            result.reasons.append("Has exploit code")
        elif result.has_poc:
            result.score += 10
            result.reasons.append("Has POC")

        # 4. CWE类型 (15分)
        reproducible_cwes = set(result.cwes).intersection(REPRODUCIBLE_CWE_TYPES)
        if reproducible_cwes:
            result.score += 15
            result.reasons.append(f"Common vulnerability type: {', '.join(reproducible_cwes)}")

        # 5. 版本信息 (10分)
        if result.version not in ['n/a', 'Unknown', 'unspecified', '', 'N/A']:
            result.score += 10
            result.reasons.append(f"Specific version: {result.version}")

        # 6. 技术细节 (10分)
        references = cna.get('references', [])
        if any('technical-description' in ref.get('tags', []) or 'patch' in ref.get('tags', [])
               for ref in references):
            result.score += 10
            result.reasons.append("Technical description/patch available")

        # 7. GitHub链接 (10分)
        for ref in references:
            url = ref.get('url', '').lower()
            if 'github.com' in url and '/blob/' in url or '/tree/' in url:
                result.score += 10
                result.reasons.append("GitHub repository link found")
                break

        # 8. Freeware标签 (5分)
        if 'x_freeware' in cna.get('tags', []):
            result.score += 5
            result.reasons.append("Marked as freeware")

        # === 从主分支脚本 - CISA SSVC评估 (额外加分) ===
        for adp_item in adp:
            if adp_item.get('providerMetadata', {}).get('shortName') == 'CISA-ADP':
                for metric in adp_item.get('metrics', []):
                    if 'other' in metric and metric['other'].get('type') == 'ssvc':
                        options = metric['other'].get('content', {}).get('options', [])
                        for option in options:
                            if option.get('Exploitation') == 'poc':
                                result.score += 20
                                result.reasons.append("CISA confirmed POC available")
                            elif option.get('Exploitation') == 'active':
                                result.score += 25
                                result.reasons.append("CISA confirmed active exploitation")

        # === 从主分支脚本 - 攻击细节检测 (额外加分) ===
        attack_keywords = ['payload', 'request', 'parameter', 'endpoint', 'uri']
        if any(kw in result.description.lower() for kw in attack_keywords):
            result.score += 5
            result.reasons.append("Description contains attack details")

        # 限制最高分
        result.score = min(result.score, 120)  # 允许超过100分表示特别好复现的

    def analyze_cve(self, cve_path: Path) -> Optional[CVEReproducibility]:
        """分析单个CVE"""
        try:
            with open(cve_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except:
            return None

        metadata = data.get('cveMetadata', {})
        if metadata.get('state') != 'PUBLISHED':
            return None

        cna = data.get('containers', {}).get('cna', {})
        adp = data.get('containers', {}).get('adp', [])

        # 创建结果对象
        result = CVEReproducibility(cve_id=metadata.get('cveId', 'Unknown'))

        # 基本信息
        affected = cna.get('affected', [])
        if affected:
            result.vendor = affected[0].get('vendor', 'Unknown')
            result.product = affected[0].get('product', 'Unknown')
            versions = affected[0].get('versions', [])
            if versions:
                result.version = versions[0].get('version', 'Unknown')

        # 描述
        descriptions = cna.get('descriptions', [])
        if descriptions:
            result.description = descriptions[0].get('value', '')[:300]

        # CVSS分数
        for metric in cna.get('metrics', []):
            for cvss_ver in ['cvssV4_0', 'cvssV3_1', 'cvssV3_0']:
                if cvss_ver in metric:
                    result.cvss_score = metric[cvss_ver].get('baseScore', 0.0)
                    result.cvss_severity = metric[cvss_ver].get('baseSeverity', '')
                    break
            if result.cvss_score:
                break

        # CWE
        for pt in cna.get('problemTypes', []):
            for desc in pt.get('descriptions', []):
                if desc.get('cweId'):
                    result.cwes.append(desc['cweId'])

        # Exploit信息
        references = cna.get('references', [])
        result.has_exploit, result.has_poc, result.exploit_urls = \
            self.check_exploit_availability(references, adp)
        if result.exploit_urls:
            result.poc_url = result.exploit_urls[0]

        # 时间信息
        result.date_published = self.parse_datetime(metadata.get('datePublished'))
        result.date_updated = self.parse_datetime(metadata.get('dateUpdated'))

        # 文件路径
        result.file_path = str(cve_path)

        # 计算可复现性分数
        self.calculate_reproducibility_score(data, result)

        return result

    def scan_latest_cves(self, latest_count: int = 1000, year: Optional[str] = None):
        """从主分支借鉴 - 扫描最新的N个CVE（按datePublished排序）"""
        print(f"Finding latest {latest_count} CVE files...")

        # 确定搜索范围
        if year:
            search_years = [year]
        else:
            search_years = ['2025', '2024', '2023']

        cve_files = []
        for yr in search_years:
            year_path = self.cves_dir / yr
            if year_path.exists():
                year_files = list(year_path.glob('**/*.json'))
                cve_files.extend([f for f in year_files if 'delta' not in f.name.lower()])

        print(f"Reading {len(cve_files)} CVE files to get publish dates...")

        # 读取发布日期
        cve_with_dates = []
        for i, cve_file in enumerate(cve_files):
            if i % 5000 == 0:
                print(f"Processed {i}/{len(cve_files)} files...")

            try:
                with open(cve_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                date_published = data.get('cveMetadata', {}).get('datePublished')
                if date_published:
                    dt = self.parse_datetime(date_published)
                    if dt:
                        cve_with_dates.append((dt, cve_file))
            except:
                continue

        print(f"Found {len(cve_with_dates)} CVEs with valid publish dates")

        # 按发布日期排序
        cve_with_dates.sort(key=lambda x: x[0], reverse=True)
        latest_files = [f for _, f in cve_with_dates[:latest_count]]

        print(f"Analyzing {len(latest_files)} latest CVE files...")

        for i, cve_file in enumerate(latest_files, 1):
            if i % 100 == 0:
                print(f"Processed {i}/{len(latest_files)} files...")

            result = self.analyze_cve(cve_file)
            if result:
                self.results.append(result)

        # 按分数排序
        self.results.sort(key=lambda x: x.score, reverse=True)
        print(f"Found {len(self.results)} reproducible CVEs")

    def generate_markdown(self, result: CVEReproducibility, cve_data: Dict) -> str:
        """从主分支借鉴 - 生成MD文档"""
        # 这里可以实现完整的MD生成逻辑
        # 为了简洁，这里只提供框架
        md = f"# {result.cve_id}\n\n"
        md += f"**Reproducibility Score**: {result.score}/120\n\n"
        md += f"**Product**: {result.vendor} {result.product} {result.version}\n\n"
        md += f"**CVSS**: {result.cvss_score} ({result.cvss_severity})\n\n"

        if result.reasons:
            md += "## Why Reproducible\n\n"
            for reason in result.reasons:
                md += f"- {reason}\n"
            md += "\n"

        md += "## Description\n\n"
        md += f"{result.description}\n\n"

        if result.exploit_urls:
            md += "## Exploit/POC URLs\n\n"
            for url in result.exploit_urls:
                md += f"- {url}\n"
            md += "\n"

        md += "## Next Steps for LiveCVEBench\n\n"
        md += "1. Create Dockerfile with vulnerable version\n"
        md += "2. Setup docker-compose.yaml\n"
        md += "3. Write test_func.py and test_vuln.py\n"
        md += "4. Create solution.sh\n"
        md += "5. Generate task.yaml\n\n"

        return md

    def generate_reproduce_files(self, min_score: int = 50, output_dir: str = None):
        """从主分支借鉴 - 生成复现文件"""
        if output_dir is None:
            output_dir = f"reproduce_cves_score{min_score}"

        os.makedirs(output_dir, exist_ok=True)

        filtered = [r for r in self.results if r.score >= min_score]

        print(f"\nGenerating reproduction files for {len(filtered)} CVEs...")

        summary = {
            'generated_at': datetime.now().isoformat(),
            'filter_score': min_score,
            'total_analyzed': len(self.results),
            'total_reproducible': len(filtered),
            'cves': []
        }

        for i, result in enumerate(filtered, 1):
            if i % 10 == 0:
                print(f"Processing {i}/{len(filtered)}...")

            # 读取完整CVE数据
            try:
                with open(result.file_path, 'r', encoding='utf-8') as f:
                    cve_data = json.load(f)
            except:
                continue

            # 生成MD
            md_content = self.generate_markdown(result, cve_data)
            md_file = os.path.join(output_dir, f"{result.cve_id}.md")
            with open(md_file, 'w', encoding='utf-8') as f:
                f.write(md_content)

            # 添加到汇总
            summary['cves'].append({
                'cve_id': result.cve_id,
                'score': result.score,
                'vendor': result.vendor,
                'product': result.product,
                'cvss_score': result.cvss_score,
                'reasons': result.reasons,
                'file_path': f"{result.cve_id}.md"
            })

        # 保存汇总
        with open(os.path.join(output_dir, 'summary.json'), 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)

        print(f"\n✅ Generated {len(filtered)} files in {output_dir}/")
        return summary

    def print_results(self, limit: int = None, verbose: bool = False):
        """从我的脚本 - 打印表格结果"""
        display_cves = self.results[:limit] if limit else self.results

        print(f"\n{'='*140}")
        print(f"Top {len(display_cves)} Most Reproducible CVEs")
        print(f"{'='*140}\n")

        for i, cve in enumerate(display_cves, 1):
            print(f"{i}. {cve.cve_id} - Score: {cve.score}/120")
            if cve.date_published:
                print(f"   Published: {cve.date_published.strftime('%Y-%m-%d')}")
            print(f"   CVSS: {cve.cvss_score} ({cve.cvss_severity})")
            print(f"   Product: {cve.vendor}/{cve.product}")

            if cve.has_exploit or cve.has_poc:
                status = []
                if cve.has_exploit:
                    status.append("Exploit")
                if cve.has_poc:
                    status.append("POC")
                print(f"   Available: {', '.join(status)}")

            if verbose and cve.reasons:
                print(f"   Why reproducible:")
                for reason in cve.reasons:
                    print(f"      • {reason}")

            print(f"   Description: {cve.description[:150]}...")
            print()


def main():
    parser = argparse.ArgumentParser(
        description='Enhanced CVE Reproducibility Filter - 融合版本'
    )
    parser.add_argument('--year', type=str, help='Filter by year (e.g., 2025)')
    parser.add_argument('--latest', type=int, help='Analyze latest N CVEs by datePublished')
    parser.add_argument('--min-score', type=int, default=50, help='Minimum reproducibility score')
    parser.add_argument('--min-cvss', type=float, help='Minimum CVSS score')
    parser.add_argument('--require-exploit', action='store_true', help='Only CVEs with exploit/POC')
    parser.add_argument('--limit', type=int, default=100, help='Display limit')
    parser.add_argument('--verbose', action='store_true', help='Show detailed reasons')
    parser.add_argument('--generate-files', action='store_true', help='Generate MD files and summary.json')
    parser.add_argument('--output-dir', type=str, help='Output directory for generated files')

    args = parser.parse_args()

    filter_tool = EnhancedCVEFilter()

    print("=== Enhanced CVE Reproducibility Filter ===\n")

    # 扫描CVE
    if args.latest:
        filter_tool.scan_latest_cves(latest_count=args.latest, year=args.year)
    else:
        # 实现全扫描逻辑（这里简化）
        print("Please use --latest for now")
        return

    # 过滤
    filtered = filter_tool.results

    if args.min_score:
        filtered = [r for r in filtered if r.score >= args.min_score]

    if args.min_cvss:
        filtered = [r for r in filtered if r.cvss_score >= args.min_cvss]

    if args.require_exploit:
        filtered = [r for r in filtered if r.has_exploit or r.has_poc]

    filter_tool.results = filtered

    # 显示结果
    filter_tool.print_results(limit=args.limit, verbose=args.verbose)

    # 生成文件
    if args.generate_files:
        filter_tool.generate_reproduce_files(
            min_score=args.min_score,
            output_dir=args.output_dir
        )

    # 统计
    print(f"\n{'='*140}")
    print(f"Statistics:")
    print(f"  Total reproducible: {len(filtered)}")
    if filtered:
        avg_score = sum(r.score for r in filtered) / len(filtered)
        print(f"  Average score: {avg_score:.1f}/120")
        with_exploit = sum(1 for r in filtered if r.has_exploit or r.has_poc)
        print(f"  With exploit/POC: {with_exploit} ({with_exploit*100//len(filtered)}%)")
    print(f"{'='*140}")


if __name__ == '__main__':
    main()

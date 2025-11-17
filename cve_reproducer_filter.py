#!/usr/bin/env python3
"""
CVE可复现性筛选脚本
根据CVE记录的特征，筛选出可能可以在Docker中复现的漏洞
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, field
import re


@dataclass
class CVEReproducibility:
    """CVE可复现性评分"""
    cve_id: str
    score: int = 0
    reasons: List[str] = field(default_factory=list)
    product: str = ""
    vendor: str = ""
    version: str = ""
    description: str = ""
    poc_url: Optional[str] = None
    exploit_available: bool = False
    cvss_score: float = 0.0
    cwe_id: str = ""


class CVEReproducibilityFilter:
    """CVE可复现性筛选器"""

    def __init__(self, cves_dir: str = "cves"):
        self.cves_dir = Path(cves_dir)
        self.results: List[CVEReproducibility] = []

    def analyze_cve(self, cve_path: Path) -> Optional[CVEReproducibility]:
        """分析单个CVE的可复现性"""
        try:
            with open(cve_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            print(f"Error reading {cve_path}: {e}")
            return None

        cve_id = data.get('cveMetadata', {}).get('cveId', 'Unknown')
        result = CVEReproducibility(cve_id=cve_id)

        # 获取基本信息
        containers = data.get('containers', {})
        cna = containers.get('cna', {})

        # 1. 分析受影响的产品
        affected = cna.get('affected', [])
        if affected:
            first_affected = affected[0]
            result.vendor = first_affected.get('vendor', 'Unknown')
            result.product = first_affected.get('product', 'Unknown')

            versions = first_affected.get('versions', [])
            if versions:
                result.version = versions[0].get('version', 'Unknown')

        # 2. 获取描述
        descriptions = cna.get('descriptions', [])
        if descriptions:
            result.description = descriptions[0].get('value', '')

        # 3. 分析参考链接，寻找POC/Exploit
        references = cna.get('references', [])
        poc_keywords = ['poc', 'exploit', 'github', 'proof-of-concept', 'demo']

        for ref in references:
            url = ref.get('url', '').lower()
            if any(keyword in url for keyword in poc_keywords):
                result.poc_url = ref.get('url')
                result.score += 30
                result.reasons.append(f"Found POC/Exploit URL: {url}")
                result.exploit_available = True
                break

        # 4. 分析CVE Program Container和ADP容器寻找额外的POC
        adp_containers = containers.get('adp', [])
        for adp in adp_containers:
            adp_refs = adp.get('references', [])
            for ref in adp_refs:
                url = ref.get('url', '').lower()
                if any(keyword in url for keyword in poc_keywords):
                    if not result.poc_url:
                        result.poc_url = ref.get('url')
                        result.score += 25
                        result.reasons.append(f"Found POC in ADP: {url}")
                        result.exploit_available = True

        # 5. 获取CVSS评分
        metrics = cna.get('metrics', [])
        for metric in metrics:
            if 'cvssV3_1' in metric:
                result.cvss_score = metric['cvssV3_1'].get('baseScore', 0.0)
                if result.cvss_score >= 7.0:
                    result.score += 10
                    result.reasons.append(f"High CVSS score: {result.cvss_score}")
                break

        # 也检查ADP容器中的CVSS评分
        for adp in adp_containers:
            adp_metrics = adp.get('metrics', [])
            for metric in adp_metrics:
                if 'cvssV3_1' in metric and result.cvss_score == 0.0:
                    result.cvss_score = metric['cvssV3_1'].get('baseScore', 0.0)
                    if result.cvss_score >= 7.0:
                        result.score += 10
                        result.reasons.append(f"High CVSS score (ADP): {result.cvss_score}")
                    break

        # 6. 记录CWE类型但不给额外加分（避免偏置）
        problem_types = cna.get('problemTypes', [])
        for pt in problem_types:
            for desc in pt.get('descriptions', []):
                cwe_id = desc.get('cweId', '')
                if cwe_id:
                    result.cwe_id = cwe_id
                    break
            if result.cwe_id:
                break

        # 也检查ADP容器中的CWE
        if not result.cwe_id:
            for adp in adp_containers:
                adp_problems = adp.get('problemTypes', [])
                for pt in adp_problems:
                    for desc in pt.get('descriptions', []):
                        cwe_id = desc.get('cweId', '')
                        if cwe_id:
                            result.cwe_id = cwe_id
                            break
                    if result.cwe_id:
                        break
                if result.cwe_id:
                    break

        # 7. 早期过滤难以复现的大厂商产品（资源优化）
        excluded_vendors = ['apple', 'microsoft', 'google android', 'ios']
        excluded_products = ['windows', 'macos', 'ios', 'android', 'chrome os']
        
        vendor_lower = result.vendor.lower()
        product_lower = result.product.lower()
        
        # 检查是否是难以复现的系统级产品
        is_hard_to_reproduce = False
        if any(vendor.lower() in vendor_lower for vendor in excluded_vendors):
            # 但允许这些厂商的开源/Web产品通过
            if not any(keyword in product_lower for keyword in 
                      ['asp.net', 'core', 'gvisor', 'chrome', 'chromium', 'edge']):
                is_hard_to_reproduce = True
        
        if any(product.lower() in product_lower for product in excluded_products):
            is_hard_to_reproduce = True
            
        if is_hard_to_reproduce:
            result.score -= 30
            result.reasons.append(f"Difficult to dockerize: {result.vendor} {result.product}")

        # 8. 检查是否有具体版本号（而不是"n/a"或"unspecified"）
        if result.version not in ['n/a', 'Unknown', 'unspecified', '']:
            result.score += 10
            result.reasons.append(f"Specific version available: {result.version}")

        # 9. 检查CISA的SSVC评估
        for adp in adp_containers:
            if adp.get('providerMetadata', {}).get('shortName') == 'CISA-ADP':
                adp_metrics = adp.get('metrics', [])
                for metric in adp_metrics:
                    if 'other' in metric and metric['other'].get('type') == 'ssvc':
                        content = metric['other'].get('content', {})
                        options = content.get('options', [])
                        for option in options:
                            if option.get('Exploitation') == 'poc':
                                result.score += 20
                                result.reasons.append("CISA confirmed POC available")
                            elif option.get('Exploitation') == 'active':
                                result.score += 25
                                result.reasons.append("CISA confirmed active exploitation")

        # 10. 检查描述中是否提到具体的攻击方法
        attack_keywords = [
            'payload', 'request', 'parameter', 'endpoint', 'uri', 'url',
            'input', 'form', 'field', 'cookie', 'header', 'body'
        ]

        desc_lower = result.description.lower()
        if any(keyword in desc_lower for keyword in attack_keywords):
            result.score += 5
            result.reasons.append("Description contains attack details")

        return result

    def scan_all_cves(self, year: Optional[str] = None, limit: Optional[int] = None):
        """扫描所有CVE文件"""
        if year:
            search_path = self.cves_dir / year
        else:
            search_path = self.cves_dir

        cve_files = list(search_path.glob('**/*.json'))

        # 排除delta文件
        cve_files = [f for f in cve_files if 'delta' not in f.name.lower()]

        if limit:
            cve_files = cve_files[:limit]

        print(f"Scanning {len(cve_files)} CVE files...")

        for i, cve_file in enumerate(cve_files, 1):
            if i % 1000 == 0:
                print(f"Processed {i}/{len(cve_files)} files...")

            result = self.analyze_cve(cve_file)
            if result and result.score > 0:
                self.results.append(result)

        # 按分数排序
        self.results.sort(key=lambda x: x.score, reverse=True)

    def scan_latest_cves(self, latest_count: int = 1000):
        """扫描最新的N个CVE文件（按datePublished排序）"""
        from datetime import datetime, timezone
        
        print(f"Finding latest {latest_count} CVE files...")
        
        # 只扫描最近几年的CVE文件
        cve_files = []
        for year in ['2025', '2024', '2023']:
            year_path = self.cves_dir / year
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
                    # 解析日期
                    try:
                        dt = datetime.fromisoformat(date_published.replace('Z', '+00:00'))
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        cve_with_dates.append((dt, cve_file))
                    except:
                        continue
            except:
                continue
        
        print(f"Found {len(cve_with_dates)} CVEs with valid publish dates")
        
        # 按发布日期排序，最新的在前
        cve_with_dates.sort(key=lambda x: x[0], reverse=True)
        
        # 取最新的N个
        latest_files = [cve_file for _, cve_file in cve_with_dates[:latest_count]]
        
        print(f"Analyzing {len(latest_files)} latest CVE files...")
        
        for i, cve_file in enumerate(latest_files, 1):
            if i % 100 == 0:
                print(f"Processed {i}/{len(latest_files)} files...")

            result = self.analyze_cve(cve_file)
            if result and result.score > 0:
                self.results.append(result)

        # 按分数排序
        self.results.sort(key=lambda x: x.score, reverse=True)
        
        print(f"Found {len(self.results)} reproducible CVEs from latest {latest_count}")

    def extract_full_cve_info(self, cve_path: Path) -> Dict:
        """提取CVE的完整信息用于复现"""
        try:
            with open(cve_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            return {}
        
        containers = data.get('containers', {})
        cna = containers.get('cna', {})
        metadata = data.get('cveMetadata', {})
        
        # 提取所有有用信息
        full_info = {
            'cve_id': metadata.get('cveId', ''),
            'date_published': metadata.get('datePublished', ''),
            'date_updated': metadata.get('dateUpdated', ''),
            
            # 产品信息
            'affected': cna.get('affected', []),
            
            # 描述
            'descriptions': cna.get('descriptions', []),
            
            # 问题类型
            'problem_types': cna.get('problemTypes', []),
            
            # 指标
            'metrics': cna.get('metrics', []),
            
            # 参考链接
            'references': cna.get('references', []),
            
            # 配置
            'configurations': cna.get('configurations', []),
            
            # 解决方案
            'solutions': cna.get('solutions', []),
            
            # 漏洞利用
            'exploits': cna.get('exploits', []),
            
            # 时间线
            'timeline': cna.get('timeline', []),
            
            # ADP信息（包含CISA评估）
            'adp': containers.get('adp', [])
        }
        
        return full_info
    
    def generate_reproduce_files(self, min_score: int = 30, output_dir: str = None):
        """生成可复现CVE的MD文档和汇总JSON"""
        import os
        from datetime import datetime
        
        if output_dir is None:
            output_dir = f"reproduce_cves_score{min_score}"
        
        # 创建输出目录
        os.makedirs(output_dir, exist_ok=True)
        
        filtered_results = [r for r in self.results if r.score >= min_score]
        
        # 汇总信息
        summary = {
            'generated_at': datetime.now().isoformat(),
            'filter_score': min_score,
            'total_analyzed': len(self.results),
            'total_reproducible': len(filtered_results),
            'cves': []
        }
        
        print(f"\nGenerating reproduction files for {len(filtered_results)} CVEs...")
        
        for i, result in enumerate(filtered_results, 1):
            if i % 10 == 0:
                print(f"Processing {i}/{len(filtered_results)}...")
            
            # 获取完整信息
            cve_file = None
            for year in ['2025', '2024', '2023', '2022', '2021']:
                potential_path = self.cves_dir / year
                if potential_path.exists():
                    found_files = list(potential_path.glob(f"**/{result.cve_id}.json"))
                    if found_files:
                        cve_file = found_files[0]
                        break
            
            if not cve_file:
                print(f"Warning: Cannot find JSON file for {result.cve_id}")
                continue
            
            full_info = self.extract_full_cve_info(cve_file)
            
            # 生成MD文档
            md_content = self.generate_cve_md(result, full_info)
            md_filename = os.path.join(output_dir, f"{result.cve_id}.md")
            with open(md_filename, 'w', encoding='utf-8') as f:
                f.write(md_content)
            
            # 添加到汇总信息
            summary['cves'].append({
                'cve_id': result.cve_id,
                'score': result.score,
                'vendor': result.vendor,
                'product': result.product,
                'version': result.version,
                'cvss_score': result.cvss_score,
                'cwe_id': result.cwe_id,
                'poc_url': result.poc_url,
                'exploit_available': result.exploit_available,
                'reasons': result.reasons,
                'date_published': full_info.get('date_published', ''),
                'file_path': f"{result.cve_id}.md"
            })
        
        # 创建按发布时间排序的CVE列表
        cves_by_date = sorted(
            summary['cves'],
            key=lambda x: x.get('date_published', ''),
            reverse=True
        )
        summary['cves_by_date'] = cves_by_date

        # 保存汇总JSON
        summary_file = os.path.join(output_dir, 'summary.json')
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        
        print(f"\n✅ Generated {len(filtered_results)} reproduction files in {output_dir}/")
        print(f"   - Individual CVE markdown files")
        print(f"   - summary.json with metadata")
        
        return summary
    
    def generate_cve_md(self, result: CVEReproducibility, full_info: Dict) -> str:
        """生成单个CVE的Markdown文档"""
        md = f"# {result.cve_id}\n\n"
        
        # 基本信息
        md += "## Basic Information\n\n"
        md += f"- **Score**: {result.score}\n"
        md += f"- **Vendor**: {result.vendor}\n"
        md += f"- **Product**: {result.product}\n"
        md += f"- **Version**: {result.version}\n"
        md += f"- **CVSS Score**: {result.cvss_score}\n"
        md += f"- **CWE**: {result.cwe_id}\n"
        md += f"- **Date Published**: {full_info.get('date_published', 'N/A')}\n"
        md += f"- **Exploit Available**: {result.exploit_available}\n\n"
        
        # 描述
        md += "## Description\n\n"
        for desc in full_info.get('descriptions', []):
            if desc.get('lang') == 'en':
                md += f"{desc.get('value', '')}\n\n"
                break
        
        # 受影响的产品详情
        md += "## Affected Products\n\n"
        for affected in full_info.get('affected', []):
            md += f"### {affected.get('vendor', 'Unknown')} - {affected.get('product', 'Unknown')}\n\n"
            
            # 版本信息
            versions = affected.get('versions', [])
            if versions:
                md += "**Versions:**\n"
                for v in versions:
                    status = v.get('status', 'affected')
                    version = v.get('version', 'unknown')
                    version_type = v.get('versionType', '')
                    less_than = v.get('lessThan', '')
                    
                    if less_than:
                        md += f"- {status}: < {less_than}\n"
                    else:
                        md += f"- {status}: {version}"
                        if version_type:
                            md += f" ({version_type})"
                        md += "\n"
                md += "\n"
            
            # 平台信息
            platforms = affected.get('platforms', [])
            if platforms:
                md += f"**Platforms**: {', '.join(platforms)}\n\n"
            
            # 仓库信息
            repo = affected.get('repo')
            if repo:
                md += f"**Repository**: {repo}\n\n"
            
            # 模块信息
            modules = affected.get('modules', [])
            if modules:
                md += f"**Modules**: {', '.join(modules)}\n\n"
            
            # 程序例程
            program_routines = affected.get('programRoutines', [])
            if program_routines:
                md += "**Program Routines**:\n"
                for routine in program_routines:
                    md += f"- {routine.get('name', 'Unknown')}\n"
                md += "\n"
        
        # 漏洞类型
        md += "## Vulnerability Types\n\n"
        for pt in full_info.get('problem_types', []):
            for desc in pt.get('descriptions', []):
                cwe = desc.get('cweId', '')
                description = desc.get('description', '')
                if cwe:
                    md += f"- {cwe}: {description}\n"
        md += "\n"
        
        # CVSS详情
        md += "## CVSS Metrics\n\n"
        for metric in full_info.get('metrics', []):
            if 'cvssV3_1' in metric:
                cvss = metric['cvssV3_1']
                md += f"**CVSS v3.1**:\n"
                md += f"- Base Score: {cvss.get('baseScore', 'N/A')}\n"
                md += f"- Base Severity: {cvss.get('baseSeverity', 'N/A')}\n"
                md += f"- Vector: {cvss.get('vectorString', 'N/A')}\n\n"
                break
        
        # POC和参考链接
        md += "## References and POCs\n\n"
        
        # 先找POC链接
        poc_refs = []
        other_refs = []
        
        for ref in full_info.get('references', []):
            url = ref.get('url', '')
            tags = ref.get('tags', [])
            
            if any(tag in ['exploit', 'poc', 'proof-of-concept'] for tag in tags):
                poc_refs.append(ref)
            else:
                other_refs.append(ref)
        
        if poc_refs:
            md += "### POC/Exploits\n\n"
            for ref in poc_refs:
                md += f"- [{ref.get('name', ref.get('url', ''))}]({ref.get('url', '')})"
                tags = ref.get('tags', [])
                if tags:
                    md += f" (tags: {', '.join(tags)})"
                md += "\n"
            md += "\n"
        
        if other_refs:
            md += "### Other References\n\n"
            for ref in other_refs[:10]:  # 限制数量
                md += f"- [{ref.get('name', ref.get('url', ''))}]({ref.get('url', '')})"
                tags = ref.get('tags', [])
                if tags:
                    md += f" (tags: {', '.join(tags)})"
                md += "\n"
            md += "\n"
        
        # CISA评估
        md += "## CISA Assessment\n\n"
        for adp in full_info.get('adp', []):
            if adp.get('providerMetadata', {}).get('shortName') == 'CISA-ADP':
                metrics = adp.get('metrics', [])
                for metric in metrics:
                    if 'other' in metric and metric['other'].get('type') == 'ssvc':
                        content = metric['other'].get('content', {})
                        options = content.get('options', [])
                        md += "**SSVC Decision Points**:\n"
                        for option in options:
                            for key, value in option.items():
                                md += f"- {key}: {value}\n"
                        md += "\n"
        
        # 解决方案
        solutions = full_info.get('solutions', [])
        if solutions:
            md += "## Solutions\n\n"
            for solution in solutions:
                md += f"{solution.get('value', '')}\n\n"

        return md
    


def main():
    """主函数"""
    import argparse

    parser = argparse.ArgumentParser(description='CVE可复现性筛选工具')
    parser.add_argument('--year', type=str, help='指定年份，如2024')
    parser.add_argument('--limit', type=int, help='限制扫描数量（用于测试）')
    parser.add_argument('--latest', type=int, help='分析最新的N个CVE（如1000）')
    parser.add_argument('--min-score', type=int, default=30, help='最低分数阈值（默认30）')
    parser.add_argument('--top', type=int, help='只显示前N个结果')

    args = parser.parse_args()

    filter_tool = CVEReproducibilityFilter()

    print("=== CVE可复现性筛选工具（去偏置版本）===\n")
    
    if args.latest:
        print(f"分析最新的 {args.latest} 个CVE...")
        filter_tool.scan_latest_cves(latest_count=args.latest)
    else:
        filter_tool.scan_all_cves(year=args.year, limit=args.limit)

    print(f"\nGenerating reproduction files...")
    
    # 直接生成LiveCVEBench复现文件
    filter_tool.generate_reproduce_files(min_score=args.min_score)

    print(f"\n=== 筛选完成 ===")
    print(f"总扫描: {len(filter_tool.results)}")
    filtered_count = len([r for r in filter_tool.results if r.score >= args.min_score])
    print(f"可复现: {filtered_count}")
    print(f"成功率: {filtered_count/len(filter_tool.results)*100:.2f}%" if filter_tool.results else "N/A")


if __name__ == "__main__":
    main()

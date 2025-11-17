# CVE Live Benchmark 筛选指南

本指南说明如何使用提供的脚本筛选出适合复现的CVE，以构建live benchmark测试code agent的修复能力。

## 脚本说明

### 1. extract_cves.py - CVE基础提取脚本

这个脚本用于从CVE数据库中提取和排序CVE记录。

**主要功能：**
- 按发布时间（datePublished）排序CVE
- 过滤特定年份、CVSS分数、是否有exploit等
- 支持多种输出格式（table, json, csv）

**使用示例：**

```bash
# 获取2025年最新的50个CVE
python3 extract_cves.py --year 2025 --limit 50

# 获取最近30天的高危CVE（CVSS >= 7.0）且有exploit
python3 extract_cves.py --days 30 --min-cvss 7.0 --exploits-only

# 导出为JSON格式
python3 extract_cves.py --year 2025 --output json > cves_2025.json

# 导出为CSV格式用于分析
python3 extract_cves.py --year 2025 --output csv > cves_2025.csv
```

**命令行参数：**
- `--sort-by {published,updated,reserved}` - 排序字段（默认：published）
- `--year YEAR` - 按年份过滤
- `--days DAYS` - 最近N天的CVE
- `--min-cvss SCORE` - 最低CVSS分数
- `--exploits-only` - 仅显示有exploit的CVE
- `--limit N` - 显示数量限制
- `--output {table,json,csv}` - 输出格式

---

### 2. filter_reproducible_cves.py - 可复现性筛选脚本（推荐）

这个脚本专门用于筛选**适合复现的CVE**，为每个CVE打分(0-100)评估其可复现性。

## 可复现性评分标准

脚本根据以下8个维度对CVE进行评分（总分100分）：

### 1. 攻击向量 (20分)
- **网络可访问**（CVSS攻击向量为NETWORK）
- ✅ 容易复现：Web应用、API、网络服务
- ❌ 难以复现：需要本地访问、物理访问

### 2. 产品类型 (25分)
**容易复现的产品：**
- 开源Web应用（WordPress, Drupal, Joomla等）
- 常见框架（Laravel, Django, Flask, Express等）
- Web服务器（Nginx, Apache, Tomcat等）
- 数据库（MySQL, PostgreSQL, MongoDB等）
- DevOps工具（GitLab, Jenkins, Docker等）

**难以复现的产品：**
- 硬件设备（路由器、防火墙、打印机等）
- 企业软件（Oracle, SAP, Microsoft Exchange等）
- 操作系统内核
- 移动应用（Android, iOS）

### 3. Exploit/POC可用性 (20分)
- GitHub上有POC代码
- 有公开的exploit
- 有技术细节文档

### 4. 漏洞类型 (15分)
**常见可复现的CWE类型：**
- CWE-89: SQL注入
- CWE-79: XSS
- CWE-78: 命令注入
- CWE-434: 文件上传
- CWE-22: 路径遍历
- CWE-918: SSRF
- CWE-306: 缺少认证
- CWE-502: 反序列化

### 5. 版本信息明确性 (10分)
- 有具体的受影响版本号
- 便于确定测试环境

### 6. 技术细节 (10分)
- 有technical-description标签
- 有patch链接
- 有详细的漏洞分析

### 7. GitHub仓库链接 (10分)
- references中包含项目源码仓库
- 表明项目开源且易于获取

### 8. 免费软件标识 (5分)
- 有x_freeware标签

## 使用示例

### 基础筛选

```bash
# 筛选2025年可复现性得分≥50的CVE（前100个）
python3 filter_reproducible_cves.py --min-score 50 --limit 100

# 查看详细的可复现性原因
python3 filter_reproducible_cves.py --min-score 60 --verbose --limit 20
```

### 高质量CVE筛选

```bash
# 筛选高可复现性(80分以上) + 高危(CVSS≥9) + 必须有exploit
python3 filter_reproducible_cves.py --min-score 80 --min-cvss 9.0 --require-exploit --limit 50

# 筛选满分CVE（最容易复现）
python3 filter_reproducible_cves.py --min-score 100 --verbose
```

### 导出数据

```bash
# 导出JSON格式用于自动化处理
python3 filter_reproducible_cves.py --min-score 70 --output json > reproducible_cves.json

# 导出CSV格式用于Excel分析
python3 filter_reproducible_cves.py --min-score 70 --output csv > reproducible_cves.csv
```

### 针对特定需求

```bash
# 只要SQL注入类的CVE（查看输出的CWEs字段，人工筛选）
python3 filter_reproducible_cves.py --min-score 60 --require-exploit

# 查找WordPress相关漏洞
python3 filter_reproducible_cves.py --min-score 50 | grep -i wordpress

# 查找最近发布的可复现CVE
python3 filter_reproducible_cves.py --min-score 70 --limit 30
```

## 命令行参数

```
--min-score SCORE       最低可复现性分数 (0-100, 默认: 50)
--year YEAR            年份过滤 (默认: 2025)
--min-cvss SCORE       最低CVSS分数
--require-exploit      仅显示有exploit/POC的CVE
--limit N              显示数量限制 (默认: 100)
--output FORMAT        输出格式: table, json, csv (默认: table)
--verbose              显示详细的可复现性评分原因
```

## 推荐筛选策略

### 策略1: 快速原型验证（最容易复现）

```bash
python3 filter_reproducible_cves.py \
  --min-score 90 \
  --require-exploit \
  --limit 20 \
  --verbose
```

**特点：**
- 可复现性极高（90分以上）
- 必须有现成的exploit
- 适合快速验证benchmark框架

### 策略2: 平衡质量和数量

```bash
python3 filter_reproducible_cves.py \
  --min-score 70 \
  --min-cvss 7.0 \
  --limit 100 \
  --output json > benchmark_cves.json
```

**特点：**
- 中等可复现性（70分以上）
- 中高危漏洞（CVSS >= 7.0）
- 数量适中，适合构建标准benchmark

### 策略3: 大规模benchmark

```bash
python3 filter_reproducible_cves.py \
  --min-score 60 \
  --limit 500 \
  --output csv > large_benchmark.csv
```

**特点：**
- 较低门槛（60分）
- 大量样本
- 适合全面测试code agent能力

### 策略4: 关键漏洞（高危+高可复现）

```bash
python3 filter_reproducible_cves.py \
  --min-score 80 \
  --min-cvss 9.0 \
  --require-exploit \
  --verbose
```

**特点：**
- 高可复现性（80分以上）
- 关键漏洞（CVSS >= 9.0）
- 有exploit代码
- 最能体现修复能力的测试集

## 实际工作流程

### 第一步：筛选候选CVE

```bash
# 筛选出高质量的可复现CVE
python3 filter_reproducible_cves.py \
  --min-score 75 \
  --min-cvss 7.0 \
  --require-exploit \
  --limit 200 \
  --output json > candidates.json
```

### 第二步：人工验证

根据输出的信息，重点关注：
1. **Products** - 确认是否能获取到软件/源码
2. **exploit_urls** - 检查exploit是否可用
3. **CWEs** - 确认漏洞类型符合测试需求
4. **reproducibility_reasons** - 了解为什么这个CVE可复现

### 第三步：构建复现环境

对于每个选中的CVE，你需要：

1. **Dockerfile** - 容器化受影响的应用版本
2. **docker-compose.yaml** - 定义完整的测试环境
3. **test_vuln.py** - 验证漏洞存在的测试脚本
4. **test_func.py** - 验证功能正常的测试脚本
5. **run-tests.sh** - 自动化测试脚本
6. **solution.sh** - 标准修复方案（可选）

### 第四步：批量处理

```python
import json

# 读取筛选结果
with open('candidates.json', 'r') as f:
    cves = json.load(f)

# 按产品分组
by_product = {}
for cve in cves:
    for product in cve['products']:
        if product not in by_product:
            by_product[product] = []
        by_product[product].append(cve)

# 优先处理同一产品的多个CVE，可复用环境
for product, product_cves in sorted(by_product.items(),
                                     key=lambda x: len(x[1]),
                                     reverse=True):
    print(f"{product}: {len(product_cves)} CVEs")
```

## 输出示例解读

```
1. CVE-2025-59832 - Reproducibility Score: 100/100
   Published: 2025-09-25
   CVSS: 9.9 (CRITICAL)
   Products: horilla-opensource/horilla
   CWEs: CWE-79
   Available: Exploit, POC
   Why reproducible:
      • Network-accessible vulnerability          # 网络可访问
      • Open-source/common software (1 indicators) # 开源软件
      • Has exploit + POC (GitHub)                # 有GitHub上的POC
      • Common vulnerability type: CWE-79         # 常见漏洞类型（XSS）
      • Specific version information available    # 有明确版本
      • GitHub repository link found              # 有源码仓库链接
```

**这个CVE非常适合复现，因为：**
1. ✅ 开源HRMS系统（horilla）
2. ✅ 有GitHub仓库
3. ✅ XSS漏洞类型简单
4. ✅ 有完整的POC
5. ✅ 网络攻击向量
6. ✅ 高CVSS分数

## 统计信息

运行脚本后会显示：

```
Statistics:
  Total matching CVEs: 9743              # 符合条件的总数
  Displayed: 100                         # 实际显示数量
  Average reproducibility score: 73.6/100 # 平均可复现性
  CVEs with exploit/POC: 5750 (59%)      # 有exploit的比例
```

## 建议

### 对于Live CVE Benchmark：

1. **初期测试**：使用 `--min-score 90` 获取最容易复现的10-20个CVE
2. **标准集**：使用 `--min-score 75 --min-cvss 7.0` 获取50-100个平衡的CVE
3. **挑战集**：使用 `--min-score 60` 获取更多样化的CVE

### 优先级排序：

1. **P0**: Score≥90, CVSS≥9.0, 有exploit - 最容易成功
2. **P1**: Score≥80, CVSS≥7.0, 有exploit - 高价值
3. **P2**: Score≥70, CVSS≥5.0 - 标准测试集
4. **P3**: Score≥60 - 扩展测试集

### 数据分析：

使用CSV输出可以在Excel/pandas中进一步分析：

```python
import pandas as pd

df = pd.read_csv('reproducible_cves.csv')

# 按产品统计
df.groupby('products').size().sort_values(ascending=False).head(20)

# 按CWE类型统计
df['cwes'].str.split(';').explode().value_counts().head(10)

# 分数分布
df['reproducibility_score'].describe()
```

## 时间排序的重要性

**为什么使用 datePublished 排序？**

1. **真实场景** - CVE公开后，开发者才知道需要修复
2. **稳定性** - 发布时间不会改变，适合基准测试
3. **时效性** - "最新CVE"通常指最近发布的
4. **信息完整度** - 新发布的CVE通常有更详细的技术信息

**不推荐使用 dateUpdated 的原因：**
- 旧CVE可能因为更新而排在前面
- 更新可能只是minor修正，不影响复现性
- 难以追踪"真正的新漏洞"

## 总结

使用 `filter_reproducible_cves.py` 可以大大提高CVE筛选效率：

- ✅ 自动化评分，节省人工筛选时间
- ✅ 多维度评估，确保可复现性
- ✅ 灵活过滤，满足不同测试需求
- ✅ 详细说明，了解每个CVE的特点

开始使用：

```bash
# 快速开始 - 获取最适合复现的20个CVE
python3 filter_reproducible_cves.py --min-score 85 --require-exploit --limit 20 --verbose
```

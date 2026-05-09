# -*- coding: utf-8 -*-
"""
CNVD 国家信息安全漏洞库 爬虫模块
自动爬取最新漏洞公告，提取漏洞信息
"""
import urllib.request
import urllib.error
import re
import json
import ssl
import time
from datetime import datetime


# CNVD公开页面
CNVD_BASE = "https://www.cnvd.org.cn"
CNVD_LIST_URL = f"{CNVD_BASE}/flaw/list"
CNVD_DETAIL_URL = f"{CNVD_BASE}/flaw/show"

# 创建不验证SSL的context（部分内网环境需要）
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "Referer": CNVD_BASE,
}


def fetch_page(url, timeout=20, retries=3):
    """获取网页内容（带重试机制）"""
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=HEADERS)
            with urllib.request.urlopen(req, timeout=timeout, context=SSL_CTX) as resp:
                content = resp.read().decode("utf-8", errors="ignore")
                if len(content) > 500:  # 有效页面通常大于500字节
                    return content
                print(f"[CNVD爬虫] 页面内容过短({len(content)}字节)，重试 {attempt+1}/{retries}")
        except urllib.error.HTTPError as e:
            print(f"[CNVD爬虫] HTTP错误 {e.code}: {url}，重试 {attempt+1}/{retries}")
        except urllib.error.URLError as e:
            print(f"[CNVD爬虫] 网络错误: {e.reason}，重试 {attempt+1}/{retries}")
        except Exception as e:
            print(f"[CNVD爬虫] 请求异常: {e}，重试 {attempt+1}/{retries}")
        if attempt < retries - 1:
            time.sleep(2 * (attempt + 1))  # 递增延迟
    return ""


def parse_cnvd_list(html):
    """
    解析CNVD漏洞列表页面
    返回漏洞条目列表
    """
    vulns = []

    # 匹配漏洞条目：CNVD编号、标题、危害等级、提交时间
    # 表格行格式：<a href="/flaw/show/CNVD-xxxx-xxxxx">标题</a>
    pattern = r'<a\s+href="/flaw/show/(CNVD-\d+-\d+)"[^>]*>([^<]+)</a>'
    matches = re.findall(pattern, html)

    # 匹配危害等级
    level_pattern = r'<td[^>]*>\s*(超危|高危|中危|低危)\s*</td>'
    levels = re.findall(level_pattern, html)

    # 匹配时间
    time_pattern = r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})'
    times = re.findall(time_pattern, html)

    for i, (cnvd_id, title) in enumerate(matches):
        level = levels[i] if i < len(levels) else "中危"
        pub_time = times[i] if i < len(times) else ""

        # 等级映射
        level_map = {"超危": "严重", "高危": "高危", "中危": "中危", "低危": "低危"}

        vulns.append({
            "cnvd_id": cnvd_id.strip(),
            "title": title.strip(),
            "level": level_map.get(level, "中危"),
            "publish_time": pub_time,
            "source": "CNVD"
        })

    return vulns


def get_cnvd_detail(cnvd_id):
    """
    获取CNVD漏洞详情
    返回漏洞详细信息
    """
    url = f"{CNVD_DETAIL_URL}/{cnvd_id}"
    html = fetch_page(url)

    if not html:
        return None

    detail = {
        "cnvd_id": cnvd_id,
        "title": "",
        "level": "",
        "description": "",
        "solution": "",
        "cve_id": "",
        "affected_products": "",
        "reference_links": "",
    }

    # 提取标题
    m = re.search(r'<h1[^>]*>([^<]+)</h1>', html)
    if m:
        detail["title"] = m.group(1).strip()

    # 提取危害级别
    m = re.search(r'危害级别[：:]\s*<[^>]*>\s*(超危|高危|中危|低危)', html)
    if m:
        level_map = {"超危": "严重", "高危": "高危", "中危": "中危", "低危": "低危"}
        detail["level"] = level_map.get(m.group(1), "中危")

    # 提取CVE编号
    m = re.search(r'(CVE-\d{4}-\d+)', html)
    if m:
        detail["cve_id"] = m.group(1)

    # 提取描述
    m = re.search(r'漏洞描述[：:](.*?)</(?:div|td|p)', html, re.DOTALL)
    if m:
        desc = re.sub(r'<[^>]+>', '', m.group(1)).strip()
        detail["description"] = desc[:500]

    # 提取解决方案
    m = re.search(r'漏洞修复建议[：:](.*?)</(?:div|td|p)', html, re.DOTALL)
    if m:
        sol = re.sub(r'<[^>]+>', '', m.group(1)).strip()
        detail["solution"] = sol[:500]

    # 提取受影响产品
    m = re.search(r'受影响产品[：:](.*?)</(?:div|td|p)', html, re.DOTALL)
    if m:
        prod = re.sub(r'<[^>]+>', '', m.group(1)).strip()
        detail["affected_products"] = prod[:300]

    return detail


def crawl_cnvd_latest(pages=1, get_details=False):
    """
    爬取CNVD最新漏洞列表

    参数:
        pages: 爬取页数（每页约20条）
        get_details: 是否获取每条漏洞的详情（较慢）

    返回:
        漏洞列表
    """
    all_vulns = []

    for page in range(1, pages + 1):
        url = f"{CNVD_LIST_URL}?flag=true&page={page}"
        html = fetch_page(url)

        if not html:
            print(f"[CNVD爬虫] 第{page}页获取失败")
            continue

        vulns = parse_cnvd_list(html)
        print(f"[CNVD爬虫] 第{page}页解析到 {len(vulns)} 条漏洞")

        if get_details:
            for v in vulns:
                detail = get_cnvd_detail(v["cnvd_id"])
                if detail:
                    v.update({
                        "description": detail.get("description", ""),
                        "solution": detail.get("solution", ""),
                        "cve_id": detail.get("cve_id", ""),
                        "affected_products": detail.get("affected_products", ""),
                    })
                time.sleep(0.5)  # 礼貌爬取

        all_vulns.extend(vulns)

        if page < pages:
            time.sleep(1)  # 页间延迟

    return all_vulns


def convert_to_scan_rules(cnvd_vulns):
    """
    将CNVD漏洞转换为扫描规则格式
    （需要人工确认端口映射，这里做智能推断）
    """
    rules = {}

    # 常见产品端口映射
    product_port_map = {
        "apache": [80, 443, 8080],
        "nginx": [80, 443],
        "tomcat": [8080, 8443],
        "iis": [80, 443],
        "mysql": [3306],
        "postgresql": [5432],
        "redis": [6379],
        "mongodb": [27017],
        "elasticsearch": [9200],
        "docker": [2375, 2376],
        "kubernetes": [6443, 8080],
        "jenkins": [8080, 8443],
        "weblogic": [7001, 7002],
        "jboss": [8080, 9990],
        "spring": [8080],
        "struts2": [8080, 8443],
        "fastjson": [8080],
        "log4j": [8080, 8443, 9200],
        "vmware": [443, 902],
        "exchange": [443, 587],
        "openssl": [443, 8443],
        "samba": [445],
        "openssh": [22],
        "vsftpd": [21],
    }

    for v in cnvd_vulns:
        title_lower = v.get("title", "").lower()
        desc_lower = v.get("description", "").lower()
        product_lower = v.get("affected_products", "").lower()
        combined = f"{title_lower} {desc_lower} {product_lower}"

        # 推断端口
        matched_ports = []
        for keyword, ports in product_port_map.items():
            if keyword in combined:
                matched_ports.extend(ports)

        if not matched_ports:
            matched_ports = [80, 443]  # 默认

        for port in set(matched_ports):
            rule_name = f"CNVD-{v.get('cnvd_id', '未知')}-{v.get('title', '未知')[:30]}"
            rules[rule_name] = {
                "port": port,
                "level": v.get("level", "中危"),
                "desc": v.get("description", v.get("title", "")),
                "solution": v.get("solution", "请参考CNVD官方公告进行修复"),
                "cve": v.get("cve_id", ""),
                "cnvd": v.get("cnvd_id", ""),
                "enabled": False,  # 默认禁用，需人工确认
                "auto_import": True,  # 标记为自动导入
                "import_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

    return rules


def crawl_and_format(pages=2):
    """
    爬取CNVD并格式化为可导入的规则
    返回 (规则字典, 统计信息)
    """
    print(f"[CNVD爬虫] 开始爬取最新漏洞（{pages}页）...")
    vulns = crawl_cnvd_latest(pages=pages, get_details=False)

    if not vulns:
        return {}, {"total": 0, "rules_count": 0, "by_level": {},
                     "message": "爬取失败：无法连接CNVD服务器，请检查网络或稍后重试",
                     "crawl_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

    rules = convert_to_scan_rules(vulns)

    stats = {
        "total": len(vulns),
        "rules_count": len(rules),
        "by_level": {},
        "crawl_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    for r in rules.values():
        level = r.get("level", "未知")
        stats["by_level"][level] = stats["by_level"].get(level, 0) + 1

    return rules, stats

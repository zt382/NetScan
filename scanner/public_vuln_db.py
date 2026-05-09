# -*- coding: utf-8 -*-
"""
公开漏洞库查询模块
- OSV (Open Source Vulnerabilities) - Google开源漏洞数据库
- GitHub Advisory Database - GitHub安全公告
两者均为公开API，无需认证，无法律风险
"""
import urllib.request
import urllib.error
import json
import ssl
import re
from datetime import datetime

# SSL上下文（兼容内网环境）
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

HEADERS_JSON = {
    "Content-Type": "application/json",
    "User-Agent": "NetScan/1.0",
    "Accept": "application/json",
}

HEADERS_GITHUB = {
    "Accept": "application/vnd.github+json",
    "User-Agent": "NetScan/1.0",
}


def _fetch(url, data=None, headers=None, timeout=15):
    """通用请求封装"""
    try:
        req = urllib.request.Request(url, data=data, headers=headers or HEADERS_JSON)
        with urllib.request.urlopen(req, timeout=timeout, context=SSL_CTX) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        print(f"[公开漏洞库] 请求失败 {url}: {e}")
        return None


# ==================== OSV API ====================

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_VULN_URL = "https://api.osv.dev/vulns"

# 常见组件包名映射（用于OSV查询）
ECOSYSTEM_MAP = {
    "PyPI": ["flask", "django", "requests", "urllib3", "pillow", "pyyaml", "jinja2",
             "cryptography", "paramiko", "werkzeug", "sqlalchemy", "celery"],
    "npm": ["express", "lodash", "axios", "webpack", "react", "vue", "next",
            "jsonwebtoken", "node-fetch", "minimist"],
    "Maven": ["org.apache.struts:struts2-core", "org.springframework:spring-core",
              "com.fasterxml.jackson.core:jackson-databind", "log4j:log4j"],
    "Go": ["github.com/gin-gonic/gin", "github.com/gorilla/mux"],
    "crates.io": ["tokio", "hyper", "serde"],
}


def query_osv_package(package_name, ecosystem="PyPI"):
    """按包名查询OSV漏洞"""
    data = json.dumps({
        "package": {"name": package_name, "ecosystem": ecosystem}
    }).encode()
    result = _fetch(OSV_QUERY_URL, data=data, headers=HEADERS_JSON)
    if result and "vulns" in result:
        return result["vulns"]
    return []


def query_osv_cve(cve_id):
    """按CVE编号查询OSV"""
    data = json.dumps({"cve": cve_id}).encode()
    result = _fetch(OSV_QUERY_URL, data=data, headers=HEADERS_JSON)
    if result and "vulns" in result:
        return result["vulns"]
    return []


def osv_to_scan_rule(vuln):
    """将OSV漏洞转换为扫描规则格式"""
    vuln_id = vuln.get("id", "")
    summary = vuln.get("summary", vuln.get("details", "")[:200])
    details = vuln.get("details", "")

    # 提取CVE编号
    cve_id = ""
    for alias in vuln.get("aliases", []):
        if alias.startswith("CVE-"):
            cve_id = alias
            break

    # 提取严重等级
    severity = "中危"
    for s in vuln.get("severity", []):
        if s.get("type") == "CVSS_V3":
            score_str = s.get("score", "")
            # 从CVSS向量中提取基础分数
            match = re.search(r'CVSS:3\.\d/.*', score_str)
            if match:
                # 简单判断
                if "CRITICAL" in score_str.upper():
                    severity = "严重"
                elif "HIGH" in score_str.upper():
                    severity = "高危"
                elif "LOW" in score_str.upper():
                    severity = "低危"
                else:
                    severity = "中危"

    # 提取受影响版本
    affected = vuln.get("affected", [])
    affected_versions = ""
    for a in affected:
        pkg = a.get("package", {})
        ranges = a.get("ranges", [])
        for r in ranges:
            events = r.get("events", [])
            for e in events:
                if "introduced" in e:
                    affected_versions += f">={e['introduced']} "
                if "fixed" in e:
                    affected_versions += f"<{e['fixed']} "
    affected_versions = affected_versions.strip()

    # 提取修复建议
    solution = ""
    for ref in vuln.get("references", []):
        url = ref.get("url", "")
        if "advisory" in url or "patch" in url or "fix" in url:
            solution = f"参考: {url}"
            break
    if not solution and affected_versions:
        solution = f"升级到安全版本: {affected_versions}"

    # 推断端口（基于常见组件）
    port = _guess_port(summary + " " + details)

    rule_name = f"OSV-{vuln_id}"

    return {
        "name": rule_name,
        "port": port,
        "level": severity,
        "desc": summary[:300],
        "solution": solution or "请参考官方安全公告进行修复",
        "cve": cve_id,
        "cnvd": "",
    }


def fetch_osv_batch(package_list=None, ecosystem="PyPI", max_count=50):
    """
    批量查询OSV漏洞
    返回: (规则字典, 统计信息)
    """
    if package_list is None:
        package_list = ECOSYSTEM_MAP.get(ecosystem, [])

    rules = {}
    total_found = 0
    errors = 0

    for pkg in package_list:
        try:
            vulns = query_osv_package(pkg, ecosystem)
            for v in vulns[:5]:  # 每个包最多取5个漏洞
                rule = osv_to_scan_rule(v)
                if rule["name"] not in rules:
                    rules[rule["name"]] = {
                        "port": rule["port"],
                        "level": rule["level"],
                        "desc": rule["desc"],
                        "solution": rule["solution"],
                        "cve": rule["cve"],
                        "cnvd": rule["cnvd"],
                        "enabled": False,
                        "source": "OSV",
                        "import_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    }
                    total_found += 1
            if len(rules) >= max_count:
                break
        except Exception as e:
            errors += 1
            print(f"[OSV] 查询 {pkg} 失败: {e}")

    stats = {
        "total": total_found,
        "errors": errors,
        "source": "OSV",
        "ecosystem": ecosystem,
        "crawl_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    return rules, stats


# ==================== GitHub Advisory API ====================

GH_ADVISORY_URL = "https://api.github.com/advisories"


def fetch_github_advisories(severity=None, ecosystem=None, per_page=30):
    """
    获取GitHub安全公告
    severity: critical, high, medium, low
    ecosystem: pip, npm, maven, go, rust 等
    """
    params = f"?per_page={per_page}"
    if severity:
        params += f"&severity={severity}"
    if ecosystem:
        params += f"&ecosystem={ecosystem}"

    url = GH_ADVISORY_URL + params
    result = _fetch(url, headers=HEADERS_GITHUB, timeout=20)
    if isinstance(result, list):
        return result
    return []


def github_to_scan_rule(advisory):
    """将GitHub Advisory转换为扫描规则"""
    ghsa_id = advisory.get("ghsa_id", "")
    cve_id = advisory.get("cve_id", "")
    summary = advisory.get("summary", "")
    description = advisory.get("description", "")[:300]
    severity = advisory.get("severity", "medium")

    # 等级映射
    level_map = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危"}
    level = level_map.get(severity, "中危")

    # 提取受影响包信息
    vulns_info = advisory.get("vulnerabilities", [])
    affected_desc = ""
    port = 80
    for v in vulns_info:
        pkg = v.get("package", {})
        ecosystem = pkg.get("ecosystem", "")
        name = pkg.get("name", "")
        affected_desc += f"{ecosystem}/{name} "

    # 从描述推断端口
    port = _guess_port(summary + " " + description + " " + affected_desc)

    # 修复建议
    solution = ""
    for ref in advisory.get("references", []):
        url = ref.get("url", "")
        if any(kw in url.lower() for kw in ["patch", "fix", "commit", "release"]):
            solution = f"参考修复: {url}"
            break
    if not solution:
        html_url = advisory.get("html_url", "")
        if html_url:
            solution = f"详见: {html_url}"

    rule_name = f"GH-{ghsa_id}"
    if cve_id:
        rule_name = f"{cve_id}-{ghsa_id}"

    return {
        "name": rule_name,
        "port": port,
        "level": level,
        "desc": summary or description[:200],
        "solution": solution or "请参考GitHub安全公告",
        "cve": cve_id,
        "cnvd": "",
    }


def fetch_github_batch(severity=None, ecosystem=None, max_count=50):
    """
    批量获取GitHub安全公告
    返回: (规则字典, 统计信息)
    """
    advisories = fetch_github_advisories(severity=severity, ecosystem=ecosystem, per_page=min(max_count, 100))
    rules = {}

    for adv in advisories[:max_count]:
        rule = github_to_scan_rule(adv)
        rules[rule["name"]] = {
            "port": rule["port"],
            "level": rule["level"],
            "desc": rule["desc"],
            "solution": rule["solution"],
            "cve": rule["cve"],
            "cnvd": rule["cnvd"],
            "enabled": False,
            "source": "GitHub",
            "import_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

    stats = {
        "total": len(rules),
        "source": "GitHub",
        "severity": severity or "全部",
        "ecosystem": ecosystem or "全部",
        "crawl_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    return rules, stats


# ==================== 辅助函数 ====================

def _guess_port(text):
    """根据文本内容推断端口"""
    text = text.lower()
    port_keywords = {
        80: ["http", "web", "apache", "nginx", "iis", "tomcat", "web server", "struts", "spring"],
        443: ["https", "ssl", "tls"],
        22: ["ssh", "openssh"],
        21: ["ftp", "vsftpd"],
        3306: ["mysql", "mariadb"],
        5432: ["postgresql", "postgres"],
        6379: ["redis"],
        27017: ["mongodb", "mongo"],
        9200: ["elasticsearch", "elastic"],
        8080: ["tomcat", "jenkins", "spring boot", "weblogic"],
        3389: ["rdp", "远程桌面"],
        445: ["smb", "samba"],
        23: ["telnet"],
        25: ["smtp", "邮件"],
        53: ["dns"],
        1433: ["mssql", "sql server"],
    }

    for port, keywords in port_keywords.items():
        for kw in keywords:
            if kw in text:
                return port
    return 80

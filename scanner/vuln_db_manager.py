# -*- coding: utf-8 -*-
"""
漏洞库管理模块
- 从外部JSON文件加载规则
- 支持手动编辑更新
- 支持CNVD/NVD在线更新（可选）
"""
import json
import os
import urllib.request
import urllib.error
from datetime import datetime
import config


VULN_DB_PATH = os.path.join(config.BASE_DIR, "vuln_db", "vuln_rules.json")
CNVD_API = "https://www.cnvd.org.cn/flaw/list"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def load_rules():
    """从JSON文件加载漏洞规则"""
    if not os.path.exists(VULN_DB_PATH):
        print(f"[漏洞库] 规则文件不存在: {VULN_DB_PATH}")
        return {}

    try:
        with open(VULN_DB_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        rules = data.get("rules", {})
        enabled = {k: v for k, v in rules.items() if v.get("enabled", True)}
        print(f"[漏洞库] 加载 {len(enabled)}/{len(rules)} 条规则 (版本: {data.get('version', '未知')})")
        return enabled
    except Exception as e:
        print(f"[漏洞库] 加载失败: {e}")
        return {}


def save_rules(rules, version=None):
    """保存规则到JSON文件"""
    data = {
        "version": version or datetime.now().strftime("%Y.%m.%d"),
        "update_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "description": "网络安全资产扫描系统 - 漏洞检测规则库",
        "rules": rules
    }
    os.makedirs(os.path.dirname(VULN_DB_PATH), exist_ok=True)
    with open(VULN_DB_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"[漏洞库] 保存成功，共 {len(rules)} 条规则")


def add_rule(name, port, level, desc, solution, cve="", cnvd=""):
    """添加新规则"""
    rules = load_rules()
    rules[name] = {
        "port": port,
        "level": level,
        "desc": desc,
        "solution": solution,
        "cve": cve,
        "cnvd": cnvd,
        "enabled": True
    }
    save_rules(rules)
    return True


def delete_rule(name):
    """删除规则"""
    rules = load_rules()
    if name in rules:
        del rules[name]
        save_rules(rules)
        return True
    return False


def toggle_rule(name, enabled=True):
    """启用/禁用规则"""
    rules = load_rules()
    if name in rules:
        rules[name]["enabled"] = enabled
        save_rules(rules)
        return True
    return False


def get_db_info():
    """获取漏洞库信息"""
    if not os.path.exists(VULN_DB_PATH):
        return {"version": "未安装", "count": 0, "update_time": "无"}
    try:
        with open(VULN_DB_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {
            "version": data.get("version", "未知"),
            "count": len(data.get("rules", {})),
            "enabled_count": len([r for r in data.get("rules", {}).values() if r.get("enabled", True)]),
            "update_time": data.get("update_time", "未知")
        }
    except Exception:
        return {"version": "损坏", "count": 0, "update_time": "无"}


def import_from_text(text_content):
    """
    从文本格式导入规则
    格式（每行一条，逗号分隔）:
    规则名,端口,等级,描述,修复建议,CVE编号,CNVD编号
    """
    count = 0
    rules = load_rules()
    for line in text_content.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) >= 4:
            name = parts[0]
            rules[name] = {
                "port": int(parts[1]),
                "level": parts[2],
                "desc": parts[3],
                "solution": parts[4] if len(parts) > 4 else "",
                "cve": parts[5] if len(parts) > 5 else "",
                "cnvd": parts[6] if len(parts) > 6 else "",
                "enabled": True
            }
            count += 1
    save_rules(rules)
    return count


def export_rules_text():
    """导出规则为文本格式"""
    rules = load_rules()
    lines = ["# 漏洞规则导出 - " + datetime.now().strftime("%Y-%m-%d %H:%M:%S")]
    lines.append("# 格式: 规则名,端口,等级,描述,修复建议,CVE编号,CNVD编号")
    for name, rule in rules.items():
        lines.append(f"{name},{rule.get('port','')},{rule.get('level','')},{rule.get('desc','')},{rule.get('solution','')},{rule.get('cve','')},{rule.get('cnvd','')}")
    return "\n".join(lines)


def check_updates_online():
    """
    检查CNVD是否有新的高危漏洞公告（仅检查，不自动导入）
    返回最新公告列表
    """
    try:
        # 使用CNVD公开接口获取最新漏洞
        url = "https://www.cnvd.org.cn/flaw/list?flag=true"
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        with urllib.request.urlopen(req, timeout=10) as resp:
            html = resp.read().decode("utf-8", errors="ignore")

        # 简单解析（实际项目中建议用BeautifulSoup）
        import re
        vulns = []
        # 提取CNVD编号和标题
        matches = re.findall(r'CNVD-\d+-\d+.*?<a[^>]*>([^<]+)</a>', html)
        for m in matches[:10]:
            vulns.append({"name": m.strip(), "source": "CNVD"})

        return vulns
    except Exception as e:
        return [{"error": f"获取CNVD更新失败: {str(e)}"}]


# 初始化检查
if not os.path.exists(VULN_DB_PATH):
    print(f"[漏洞库] 首次运行，将在 {VULN_DB_PATH} 创建规则文件")

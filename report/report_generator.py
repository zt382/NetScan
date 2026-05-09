# -*- coding: utf-8 -*-
"""
报告生成模块 - 生成HTML格式的安全扫描报告
"""
import os
from datetime import datetime
from database import db_manager
import config


def generate_html_report():
    """生成HTML安全扫描报告"""
    stats = db_manager.get_dashboard_stats()
    assets = db_manager.get_all_assets()
    vulns = db_manager.get_vulnerabilities()
    changes = db_manager.get_asset_changes(limit=50)
    tasks = db_manager.get_scan_tasks(limit=20)

    now = datetime.now().strftime("%Y年%m月%d日 %H:%M:%S")

    # 漏洞统计
    vuln_stats = {"严重": [], "高危": [], "中危": [], "低危": []}
    for v in vulns:
        level = v.get("vuln_level", "低危")
        if level in vuln_stats:
            vuln_stats[level].append(v)

    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>网络安全扫描报告</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: "Microsoft YaHei", sans-serif; color: #333; background: #f5f5f5; padding: 20px; }}
        .container {{ max-width: 1000px; margin: 0 auto; background: #fff; padding: 40px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ text-align: center; color: #1a5276; margin-bottom: 10px; font-size: 28px; }}
        .subtitle {{ text-align: center; color: #666; margin-bottom: 30px; }}
        h2 {{ color: #1a5276; border-bottom: 2px solid #1a5276; padding-bottom: 5px; margin: 25px 0 15px; }}
        .stat-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 15px 0; }}
        .stat-card {{ background: #f8f9fa; border-radius: 8px; padding: 15px; text-align: center; border-left: 4px solid #3498db; }}
        .stat-card .num {{ font-size: 28px; font-weight: bold; color: #2c3e50; }}
        .stat-card .label {{ font-size: 13px; color: #666; margin-top: 5px; }}
        .danger {{ border-left-color: #e74c3c; }}
        .warning {{ border-left-color: #f39c12; }}
        .success {{ border-left-color: #27ae60; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; font-size: 13px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px 10px; text-align: left; }}
        th {{ background: #1a5276; color: #fff; }}
        tr:nth-child(even) {{ background: #f9f9f9; }}
        .tag {{ display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 12px; color: #fff; }}
        .tag-critical {{ background: #c0392b; }}
        .tag-high {{ background: #e74c3c; }}
        .tag-medium {{ background: #f39c12; }}
        .tag-low {{ background: #3498db; }}
        .footer {{ text-align: center; color: #999; margin-top: 30px; font-size: 12px; border-top: 1px solid #eee; padding-top: 15px; }}
    </style>
</head>
<body>
<div class="container">
    <h1>🔒 网络安全资产扫描报告</h1>
    <p class="subtitle">报告生成时间：{now} | 网络安全资产扫描系统</p>

    <h2>一、概览统计</h2>
    <div class="stat-grid">
        <div class="stat-card success"><div class="num">{stats['资产总数']}</div><div class="label">资产总数</div></div>
        <div class="stat-card"><div class="num">{stats['在线资产']}</div><div class="label">在线资产</div></div>
        <div class="stat-card warning"><div class="num">{stats['开放端口']}</div><div class="label">开放端口</div></div>
        <div class="stat-card danger"><div class="num">{stats['漏洞总数']}</div><div class="label">漏洞总数</div></div>
    </div>
    <div class="stat-grid">
        <div class="stat-card danger"><div class="num">{stats['严重漏洞']}</div><div class="label">严重漏洞</div></div>
        <div class="stat-card danger"><div class="num">{stats['高危漏洞']}</div><div class="label">高危漏洞</div></div>
        <div class="stat-card warning"><div class="num">{stats['中危漏洞']}</div><div class="label">中危漏洞</div></div>
        <div class="stat-card"><div class="num">{stats['低危漏洞']}</div><div class="label">低危漏洞</div></div>
    </div>

    <h2>二、资产清单</h2>
    <table>
        <tr><th>序号</th><th>IP地址</th><th>主机名</th><th>操作系统</th><th>状态</th><th>最后发现时间</th></tr>
"""
    for i, a in enumerate(assets, 1):
        html += f"        <tr><td>{i}</td><td>{a['ip']}</td><td>{a['hostname'] or '-'}</td><td>{a['os_guess'] or '-'}</td><td>{a['status']}</td><td>{a['last_seen']}</td></tr>\n"

    html += """    </table>

    <h2>三、漏洞详情</h2>
"""
    for level in ["严重", "高危", "中危", "低危"]:
        level_vulns = vuln_stats[level]
        tag_class = {"严重": "tag-critical", "高危": "tag-high", "中危": "tag-medium", "低危": "tag-low"}[level]
        if level_vulns:
            html += f"    <h3><span class='tag {tag_class}'>{level}</span> ({len(level_vulns)}个)</h3>\n"
            html += "    <table><tr><th>IP地址</th><th>漏洞名称</th><th>描述</th><th>修复建议</th><th>状态</th></tr>\n"
            for v in level_vulns:
                html += f"    <tr><td>{v['ip']}</td><td>{v['vuln_name']}</td><td>{v['vuln_desc']}</td><td>{v['vuln_solution']}</td><td>{v['status']}</td></tr>\n"
            html += "    </table>\n"

    html += f"""
    <h2>四、资产变化记录</h2>
    <table>
        <tr><th>时间</th><th>IP地址</th><th>变化类型</th><th>详情</th></tr>
"""
    for c in changes[:20]:
        html += f"        <tr><td>{c['scan_time']}</td><td>{c['ip']}</td><td>{c['change_type']}</td><td>{c['detail']}</td></tr>\n"

    html += f"""    </table>

    <div class="footer">
        <p>本报告由「网络安全资产扫描系统」自动生成 | {now}</p>
        <p>⚠️ 本报告仅供内部安全评估使用，请妥善保管</p>
    </div>
</div>
</body>
</html>"""

    # 保存报告
    report_path = os.path.join(config.REPORT_DIR, "scan_report.html")
    os.makedirs(config.REPORT_DIR, exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)

    return report_path

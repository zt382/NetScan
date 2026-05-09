# -*- coding: utf-8 -*-
"""
漏洞扫描模块 - 基于端口服务特征的漏洞检测
漏洞规则从外部JSON文件加载，支持在线更新
"""
import socket
import ssl
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import config
from database import db_manager
from scanner import asset_scanner
from scanner.vuln_db_manager import load_rules


# 从外部JSON加载漏洞规则
VULN_RULES = load_rules()


def check_http_headers(ip, port=80):
    """
    检测HTTP响应头安全配置
    """
    vulns = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        if port == 443 or port == 8443:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=ip)
        sock.connect((ip, port))
        sock.send(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
        response = sock.recv(4096).decode("utf-8", errors="ignore")
        sock.close()

        headers = response.lower()

        # 检测缺失安全头
        if "x-frame-options" not in headers:
            vulns.append({
                "name": "缺少X-Frame-Options响应头",
                "level": "低危",
                "desc": "Web应用缺少X-Frame-Options头，可能被Clickjacking攻击",
                "solution": "添加 X-Frame-Options: DENY 或 SAMEORIGIN 响应头"
            })

        if "x-content-type-options" not in headers:
            vulns.append({
                "name": "缺少X-Content-Type-Options响应头",
                "level": "低危",
                "desc": "缺少此响应头，浏览器可能进行MIME类型嗅探",
                "solution": "添加 X-Content-Type-Options: nosniff 响应头"
            })

        if "strict-transport-security" not in headers and (port == 443 or port == 8443):
            vulns.append({
                "name": "缺少HSTS响应头",
                "level": "中危",
                "desc": "HTTPS站点缺少HSTS头，可能遭受SSL剥离攻击",
                "solution": "添加 Strict-Transport-Security 响应头"
            })

        # 检测服务器信息泄露
        if "server:" in headers:
            server_match = re.search(r"server:\s*(.+)", headers)
            if server_match:
                vulns.append({
                    "name": "服务器信息泄露",
                    "level": "低危",
                    "desc": f"HTTP响应头泄露了服务器信息: {server_match.group(1).strip()}",
                    "solution": "移除或修改Server响应头，不显示具体版本信息"
                })

        # 检测X-Powered-By信息泄露
        if "x-powered-by" in headers:
            vulns.append({
                "name": "技术栈信息泄露",
                "level": "低危",
                "desc": "X-Powered-By头泄露了后端技术栈信息",
                "solution": "移除X-Powered-By响应头"
            })

    except Exception:
        pass

    return vulns


def check_ssl_cert(ip, port=443):
    """
    检测SSL证书问题
    """
    vulns = []
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((ip, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                cert_der = ssock.getpeercert()

                # 检查证书是否为空（自签名）
                if not cert_der:
                    vulns.append({
                        "name": "SSL自签名证书",
                        "level": "中危",
                        "desc": "服务器使用自签名SSL证书，可能存在中间人攻击风险",
                        "solution": "使用受信任CA机构签发的SSL证书"
                    })
    except ssl.SSLCertVerificationError:
        vulns.append({
            "name": "SSL证书验证失败",
            "level": "中危",
            "desc": "SSL证书验证失败，可能已过期或配置错误",
            "solution": "更新或重新配置SSL证书"
        })
    except Exception:
        pass

    return vulns


def check_ftp_anonymous(ip, port=21):
    """
    检测FTP匿名登录
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode("utf-8", errors="ignore")

        sock.send(b"USER anonymous\r\n")
        resp = sock.recv(1024).decode("utf-8", errors="ignore")

        sock.send(b"PASS anonymous@\r\n")
        resp2 = sock.recv(1024).decode("utf-8", errors="ignore")

        sock.close()

        if "230" in resp2:
            return [{
                "name": "FTP匿名登录",
                "level": "严重",
                "desc": "FTP服务允许匿名登录，服务器文件可被任意访问",
                "solution": "禁用FTP匿名登录功能"
            }]
    except Exception:
        pass

    return []


def check_redis_unauth(ip, port=6379):
    """
    检测Redis未授权访问
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((ip, port))

        sock.send(b"INFO\r\n")
        resp = sock.recv(4096).decode("utf-8", errors="ignore")

        sock.close()

        if "redis_version" in resp:
            return [{
                "name": "Redis未授权访问",
                "level": "严重",
                "desc": "Redis服务未设置密码保护，可直接读取数据甚至写入文件获取服务器权限",
                "solution": "设置requirepass密码，绑定内网IP，重命名危险命令"
            }]
    except Exception:
        pass

    return []


def run_vuln_scan(target_str=None, task_id=None, callback=None, stop_check=None):
    """
    执行漏洞扫描

    参数:
        target_str: 目标IP（为None则扫描已知资产）
        task_id: 任务ID
        callback: 进度回调
        stop_check: 停止检查函数 stop_check() -> bool

    返回:
        扫描结果
    """
    # 获取要扫描的资产
    if target_str:
        all_ips = asset_scanner.parse_targets(target_str)
        assets = []
        existing_ips = set()

        # 先从数据库快速获取已知资产
        for ip in all_ips:
            asset = db_manager.get_asset_by_ip(ip)
            if asset:
                assets.append(asset)
                existing_ips.add(ip)

        # 对未知IP并发探测：ping → 端口扫描 → OS识别 → 入库
        unknown_ips = [ip for ip in all_ips if ip not in existing_ips]
        if unknown_ips:
            def discover_host(ip):
                """探测单个主机的完整信息"""
                if not asset_scanner.ping_host(ip):
                    return None
                open_ports = asset_scanner.scan_host_ports(ip, timeout=config.SCAN_TIMEOUT)
                hostname = asset_scanner.get_hostname(ip)
                os_name, os_category, os_detail = asset_scanner.detect_os(ip, open_ports)
                # 入库
                asset_id = db_manager.upsert_asset(ip, hostname=hostname, os_guess=os_name)
                for p in open_ports:
                    db_manager.upsert_port(asset_id, p["port"], state=p["state"],
                                           service=p["service"], version=p.get("version", ""),
                                           banner=p["banner"])
                return db_manager.get_asset_by_ip(ip)

            with ThreadPoolExecutor(max_workers=min(len(unknown_ips), 100)) as executor:
                future_map = {executor.submit(discover_host, ip): ip for ip in unknown_ips}
                for future in as_completed(future_map):
                    if stop_check and stop_check():
                        break
                    try:
                        asset = future.result()
                        if asset:
                            assets.append(asset)
                    except Exception:
                        pass
    else:
        assets = db_manager.get_all_assets()

    total = len(assets)
    if total == 0:
        if task_id:
            db_manager.update_scan_task(task_id, status="已完成", progress=100,
                                        result_summary="无资产可扫描")
        return {"total": 0, "vulns_found": 0}

    vulns_found = 0

    for idx, asset in enumerate(assets):
        # 检查是否请求停止
        if stop_check and stop_check():
            if callback:
                callback(progress, "漏洞扫描已被用户停止")
            break

        ip = asset["ip"]
        asset_id = asset["id"]
        progress = int((idx + 1) / total * 100)

        if callback:
            callback(progress, f"正在扫描 {ip} 的漏洞 ({idx + 1}/{total})")
        if task_id:
            db_manager.update_scan_task(task_id, progress=progress)

        # 获取该资产的端口
        ports = db_manager.get_ports_by_asset(asset_id)
        port_nums = [p["port"] for p in ports if p["state"] == "开放"]

        # 深度检测覆盖的端口，跳过规则匹配避免重复
        deep_check_ports = {21, 6379, 80, 443, 8080, 8443, 8888}

        # 1. 基于端口的规则匹配（仅作为"服务暴露"告警，不声称具体CVE）
        for rule_name, rule in VULN_RULES.items():
            if rule["port"] in port_nums and rule["port"] not in deep_check_ports:
                existing = db_manager.get_vulnerabilities(asset_id=asset_id)
                already_exists = any(v["vuln_name"] == rule_name for v in existing)
                if not already_exists:
                    db_manager.add_vulnerability(
                        asset_id=asset_id,
                        vuln_name=rule_name,
                        vuln_level=rule["level"],
                        vuln_desc=rule["desc"],
                        vuln_solution=rule["solution"]
                    )
                    vulns_found += 1

        # 2. 深度检测（实际验证漏洞是否存在）
        if 21 in port_nums:
            ftp_vulns = check_ftp_anonymous(ip)
            for v in ftp_vulns:
                db_manager.add_vulnerability(asset_id, v["name"], v["level"],
                                             v["desc"], v["solution"])
                vulns_found += 1
            # FTP端口开放但未检测到匿名登录，记录为暴露风险
            if not ftp_vulns:
                existing = db_manager.get_vulnerabilities(asset_id=asset_id)
                if not any(v["vuln_name"] == "FTP服务暴露" for v in existing):
                    db_manager.add_vulnerability(asset_id, "FTP服务暴露", "中危",
                        "FTP服务对外开放，可能存在匿名登录或明文传输风险",
                        "建议关闭FTP服务，改用SFTP；如必须使用，禁止匿名登录并启用FTPS加密")
                    vulns_found += 1

        if 6379 in port_nums:
            redis_vulns = check_redis_unauth(ip)
            if redis_vulns:
                for v in redis_vulns:
                    db_manager.add_vulnerability(asset_id, v["name"], v["level"],
                                                 v["desc"], v["solution"])
                    vulns_found += 1
            else:
                # Redis有密码保护，记录为低危暴露
                existing = db_manager.get_vulnerabilities(asset_id=asset_id)
                if not any(v["vuln_name"] == "Redis服务暴露" for v in existing):
                    db_manager.add_vulnerability(asset_id, "Redis服务暴露", "低危",
                        "Redis服务对外开放（已设置密码认证）",
                        "建议绑定内网IP，仅允许可信来源访问")
                    vulns_found += 1

        # HTTP安全头检测
        for p in port_nums:
            if p in [80, 443, 8080, 8443, 8888]:
                http_vulns = check_http_headers(ip, p)
                for v in http_vulns:
                    existing = db_manager.get_vulnerabilities(asset_id=asset_id)
                    already_exists = any(ev["vuln_name"] == v["name"] for ev in existing)
                    if not already_exists:
                        db_manager.add_vulnerability(asset_id, v["name"], v["level"],
                                                     v["desc"], v["solution"])
                        vulns_found += 1

        # SSL检测
        if 443 in port_nums or 8443 in port_nums:
            ssl_port = 443 if 443 in port_nums else 8443
            ssl_vulns = check_ssl_cert(ip, ssl_port)
            for v in ssl_vulns:
                existing = db_manager.get_vulnerabilities(asset_id=asset_id)
                already_exists = any(ev["vuln_name"] == v["name"] for ev in existing)
                if not already_exists:
                    db_manager.add_vulnerability(asset_id, v["name"], v["level"],
                                                 v["desc"], v["solution"])
                    vulns_found += 1

    scanned = idx + 1 if 'idx' in dir() else 0
    if stop_check and stop_check():
        summary = f"漏洞扫描已停止：扫描{scanned}/{total}个资产，发现{vulns_found}个新漏洞"
    else:
        summary = f"漏洞扫描完成：扫描{total}个资产，发现{vulns_found}个新漏洞"
    if task_id:
        db_manager.update_scan_task(task_id, status="已完成", progress=100, result_summary=summary)

    if callback:
        callback(100, summary)

    return {"total": total, "vulns_found": vulns_found}

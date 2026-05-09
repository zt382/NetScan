# -*- coding: utf-8 -*-
"""
资产扫描引擎 - 基于纯Python Socket实现，无需外部依赖
支持：主机存活探测、端口扫描、服务识别、操作系统识别
"""
import socket
import struct
import ipaddress
import threading
import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import config
from database import db_manager
from scanner.os_detect import detect_os, extract_service_version


# 常见服务指纹（端口 -> 服务名）
SERVICE_FINGERPRINTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-代理",
    8443: "HTTPS-备", 8888: "HTTP-备2", 9090: "管理端口", 27017: "MongoDB",
    11211: "Memcached", 9200: "Elasticsearch", 888: "宝塔面板",
    2181: "ZooKeeper", 8088: "Hadoop", 50070: "HDFS", 6443: "Kubernetes-API",
    2379: "Etcd", 8649: "Ganglia", 161: "SNMP", 389: "LDAP",
    636: "LDAPS", 88: "Kerberos", 464: "Kerberos-管理", 749: "Kerberos-管理2",
    1099: "RMI", 2049: "NFS", 512: "Rexec", 513: "Rlogin", 514: "Rsh",
}


def parse_targets(target_str):
    """
    解析目标字符串，支持以下格式：
    - 单个IP: 192.168.1.1
    - IP范围: 192.168.1.1-192.168.1.254
    - CIDR: 192.168.1.0/24
    - 多个目标（逗号分隔）: 192.168.1.1,192.168.2.0/24
    """
    targets = []
    for part in target_str.replace(" ", "").split(","):
        part = part.strip()
        if not part:
            continue
        if "/" in part:
            # CIDR格式
            try:
                network = ipaddress.ip_network(part, strict=False)
                targets.extend([str(ip) for ip in network.hosts()])
            except ValueError:
                targets.append(part)
        elif "-" in part and "." in part:
            # 范围格式
            try:
                start_ip, end_ip = part.split("-")
                start = int(ipaddress.ip_address(start_ip.strip()))
                end = int(ipaddress.ip_address(end_ip.strip()))
                for ip_int in range(start, end + 1):
                    targets.append(str(ipaddress.ip_address(ip_int)))
            except ValueError:
                targets.append(part)
        else:
            targets.append(part)
    return targets


def ping_host(ip, timeout=1):
    """
    探测主机是否存活（TCP Connect方式，比ICMP更通用）
    """
    # 尝试连接常见端口来判断主机是否在线（含Windows动态端口）
    test_ports = [80, 443, 22, 445, 135, 3389, 21, 23, 5985, 49152, 49153, 49154]
    for port in test_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                return True
        except Exception:
            continue
    return False


def scan_port(ip, port, timeout=2):
    """
    扫描单个端口
    返回: (port, state, service, version, banner, ttl, window_size)
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        # 记录TTL和窗口大小（通过原始socket获取有限信息）
        ttl_val = 0
        window_size = 0
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 64)
        except Exception:
            pass

        result = sock.connect_ex((ip, port))

        if result == 0:
            service = SERVICE_FINGERPRINTS.get(port, "未知")
            version = ""
            banner = ""

            # 尝试获取Banner信息
            try:
                sock.settimeout(1.5)
                if port in [80, 8080, 8443, 8888, 9090]:
                    sock.send(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\nUser-Agent: NetScan/1.0\r\n\r\n")
                elif port == 22:
                    pass  # SSH服务会主动发送banner
                elif port == 21:
                    pass  # FTP服务会主动发送banner
                elif port == 25:
                    sock.send(b"EHLO\r\n")
                elif port == 3306:
                    pass  # MySQL会主动发送greeting
                elif port == 5432:
                    sock.send(b"\x00\x00\x00\x08\x04\xd2\x16/")
                elif port == 6379:
                    sock.send(b"INFO\r\n")
                elif port == 27017:
                    pass
                else:
                    sock.send(b"\r\n")

                banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            except Exception:
                pass

            # 从banner提取版本信息
            version = extract_service_version(banner, port)

            sock.close()
            return (port, "开放", service, version, banner)
        else:
            sock.close()
            return (port, "关闭", "", "", "")
    except socket.timeout:
        return (port, "关闭", "", "", "")
    except Exception:
        return (port, "关闭", "", "", "")


def extract_version(banner, port):
    """从Banner中提取版本信息"""
    if not banner:
        return ""
    import re

    # SSH版本
    if port == 22 and banner.startswith("SSH-"):
        return banner.split("\n")[0].strip()

    # FTP版本
    if port == 21:
        m = re.search(r"(220\s*.+)", banner)
        if m:
            return m.group(1).strip()

    # HTTP Server头
    if port in [80, 443, 8080, 8443]:
        m = re.search(r"[Ss]erver:\s*(.+?)(?:\r|\n)", banner)
        if m:
            return m.group(1).strip()

    # MySQL版本
    if port == 3306:
        m = re.search(r"([\d.]+-MariaDB|[\d.]+-MySQL|[\d.]+)", banner)
        if m:
            return "MySQL " + m.group(1)

    # Redis版本
    if port == 6379:
        m = re.search(r"redis_version:([\d.]+)", banner)
        if m:
            return "Redis " + m.group(1)

    # SMTP
    if port == 25:
        m = re.search(r"(220\s*.+)", banner)
        if m:
            return m.group(1).strip()

    # 通用版本提取
    m = re.search(r"(?:version|ver|v)[/\s]*([\d.]+)", banner, re.IGNORECASE)
    if m:
        return m.group(1)

    return ""


def detect_os_by_ttl(ip, timeout=2):
    """
    通过TTL值初步判断操作系统
    不同OS的默认TTL:
      - Windows: 128
      - Linux/Unix: 64
      - macOS: 64
      - Cisco/网络设备: 255
      - Solaris/AIX: 254
    """
    try:
        # 通过创建TCP连接时的TTL来判断
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        # 尝试连接一个可能开放的端口来获取连接信息
        test_ports = [80, 443, 22, 445, 135, 3389]
        for port in test_ports:
            try:
                result = sock.connect_ex((ip, port))
                if result == 0:
                    # 获取socket选项中的TTL信息
                    try:
                        # 尝试获取TCP窗口大小
                        window = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
                        sock.close()

                        # 通过Windows机器名特征判断
                        if port == 3389 or port == 445 or port == 135:
                            return 128  # Windows特征端口
                        elif port == 22:
                            return 64   # Linux特征端口
                    except Exception:
                        pass
                    break
            except Exception:
                continue
        sock.close()
    except Exception:
        pass
    return 0


def detect_os_by_nbtstat(ip, timeout=2):
    """
    通过NetBIOS信息判断Windows版本
    """
    try:
        # NetBIOS Name Query (UDP 137)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        # 构造NetBIOS Name Query请求包
        query = bytes([
            0x80, 0x94, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21,
            0x00, 0x01
        ])

        sock.sendto(query, (ip, 137))
        data, addr = sock.recvfrom(1024)
        sock.close()

        if len(data) > 57:
            # 解析NetBIOS名称
            names = []
            num_names = data[56]
            for i in range(num_names):
                offset = 57 + (i * 18)
                if offset + 18 <= len(data):
                    name = data[offset:offset+15].decode("ascii", errors="ignore").strip()
                    suffix = data[offset+15]
                    if suffix == 0x00:  # Workstation Service
                        names.append(name)
            if names:
                return names[0]
    except Exception:
        pass
    return ""


def detect_os_comprehensive(ip, open_ports, banners):
    """
    综合多维度信息识别操作系统

    参数:
        ip: 目标IP
        open_ports: 开放端口列表 [{"port": int, "service": str, "banner": str}, ...]
        banners: 端口banner字典

    返回:
        (os_name, os_detail) - 操作系统名称和详细信息
    """
    port_nums = [p["port"] for p in open_ports]
    all_banners = " ".join([p.get("banner", "") for p in open_ports]).lower()

    os_scores = {}  # 操作系统得分

    # ====== 1. Banner分析 ======

    # Windows特征
    windows_keywords = ["microsoft", "windows", "iis", "asp.net", "exchange", "outlook",
                        "sharepoint", "microsoft-iis", "win32", "win64", "x-powered-by: asp.net"]
    for kw in windows_keywords:
        if kw in all_banners:
            os_scores["Windows"] = os_scores.get("Windows", 0) + 3

    # Linux特征
    linux_keywords = ["ubuntu", "debian", "centos", "redhat", "red hat", "fedora", "suse",
                      "linux", "apache", "nginx", "openssh", "ubuntu", "debian", "ubuntu"]
    for kw in linux_keywords:
        if kw in all_banners:
            os_scores["Linux"] = os_scores.get("Linux", 0) + 3

    # macOS特征
    macos_keywords = ["darwin", "macos", "mac os", "apple"]
    for kw in macos_keywords:
        if kw in all_banners:
            os_scores["macOS"] = os_scores.get("macOS", 0) + 3

    # ====== 2. 服务版本分析 ======

    for p in open_ports:
        banner = p.get("banner", "").lower()
        service = p.get("service", "").lower()
        version = p.get("version", "").lower()

        # IIS → Windows
        if "iis" in banner or "iis" in service or "iis" in version:
            os_scores["Windows"] = os_scores.get("Windows", 0) + 5
            # IIS版本细分
            import re
            m = re.search(r"iis/(\d+\.\d+)", banner)
            if m:
                iis_ver = m.group(1)
                if iis_ver.startswith("10."):
                    os_scores["Windows 10/Server 2016+"] = os_scores.get("Windows 10/Server 2016+", 0) + 5
                elif iis_ver.startswith("8."):
                    os_scores["Windows 8/Server 2012"] = os_scores.get("Windows 8/Server 2012", 0) + 5
                elif iis_ver.startswith("7."):
                    os_scores["Windows 7/Server 2008"] = os_scores.get("Windows 7/Server 2008", 0) + 5

        # Apache/Nginx版本 → Linux
        if "apache" in banner:
            os_scores["Linux"] = os_scores.get("Linux", 0) + 4
        if "nginx" in banner:
            os_scores["Linux"] = os_scores.get("Linux", 0) + 4

        # OpenSSH版本 → Linux/Unix
        if "openssh" in banner:
            os_scores["Linux"] = os_scores.get("Linux", 0) + 4
            import re
            m = re.search(r"openssh[_\s](\d+\.\d+)", banner)
            if m:
                ssh_ver = m.group(1)
                if "ubuntu" in banner:
                    os_scores["Ubuntu"] = os_scores.get("Ubuntu", 0) + 5
                if "debian" in banner:
                    os_scores["Debian"] = os_scores.get("Debian", 0) + 5

        # MySQL/MariaDB版本
        if "mysql" in banner or "mariadb" in banner:
            os_scores["Linux"] = os_scores.get("Linux", 0) + 2

        # Windows特有服务
        if p["port"] == 3389:  # RDP
            os_scores["Windows"] = os_scores.get("Windows", 0) + 6
        if p["port"] == 135:   # MSRPC
            os_scores["Windows"] = os_scores.get("Windows", 0) + 5
        if p["port"] == 139:   # NetBIOS
            os_scores["Windows"] = os_scores.get("Windows", 0) + 4

        # SSH → Linux/Unix
        if p["port"] == 22:
            os_scores["Linux"] = os_scores.get("Linux", 0) + 3

    # ====== 3. 端口组合分析 ======

    # Windows经典组合
    if 135 in port_nums and 445 in port_nums:
        os_scores["Windows"] = os_scores.get("Windows", 0) + 4
    if 3389 in port_nums and 135 in port_nums:
        os_scores["Windows"] = os_scores.get("Windows", 0) + 3
    if 135 in port_nums and 139 in port_nums and 445 in port_nums:
        os_scores["Windows"] = os_scores.get("Windows", 0) + 5

    # Linux经典组合
    if 22 in port_nums and (80 in port_nums or 443 in port_nums):
        os_scores["Linux"] = os_scores.get("Linux", 0) + 3

    # ====== 4. NetBIOS探测（仅对Windows有效） ======
    if 137 in port_nums or 135 in port_nums or 445 in port_nums:
        nb_name = detect_os_by_nbtstat(ip)
        if nb_name:
            os_scores["Windows"] = os_scores.get("Windows", 0) + 5
            os_scores["NetBIOS名"] = 0  # 记录但不计入分数

    # ====== 5. 综合判定 ======
    if not os_scores:
        return "未知", "未检测到足够的指纹信息"

    # 找到得分最高的OS
    # 过滤掉非OS名称的key
    os_only = {k: v for k, v in os_scores.items() if k not in ["NetBIOS名"]}

    if not os_only:
        return "未知", "未检测到足够的指纹信息"

    best_os = max(os_only, key=os_only.get)
    best_score = os_only[best_os]

    # 构建详细信息
    detail_parts = []

    # 添加主要OS
    detail_parts.append(best_os)

    # 添加细分版本
    for k in os_only:
        if k != best_os and os_only[k] >= 4:
            detail_parts.append(f"{k}(得分:{os_only[k]})")

    # 添加NetBIOS名
    if "NetBIOS名" in os_scores:
        detail_parts.append(f"NetBIOS: {os_scores['NetBIOS名']}")

    # 添加Banner摘要
    for p in open_ports:
        if p.get("version"):
            detail_parts.append(f"{p['service']}:{p['version']}")
            break

    detail = " | ".join(detail_parts) if detail_parts else best_os

    return best_os, detail


def scan_host_ports(ip, ports=None, timeout=2, max_threads=50):
    """
    扫描单个主机的所有端口
    """
    if ports is None:
        ports = config.DEFAULT_PORTS

    open_ports = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(scan_port, ip, port, timeout): port for port in ports}
        for future in as_completed(futures):
            port, state, service, version, banner = future.result()
            if state == "开放":
                open_ports.append({
                    "port": port,
                    "state": state,
                    "service": service,
                    "version": version,
                    "banner": banner
                })

    open_ports.sort(key=lambda x: x["port"])
    return open_ports


def get_hostname(ip):
    """
    获取主机名 - 多方式识别，过滤Docker/容器假名
    """
    import platform
    import os

    hostname = ""

    # 1. 本机IP直接取本机主机名（最准确）
    if ip in ("127.0.0.1", "::1", "localhost"):
        hostname = platform.node() or os.environ.get("COMPUTERNAME", "") or os.environ.get("HOSTNAME", "")
        if hostname:
            return hostname

    # 2. 判断是否是本机其他IP
    try:
        local_ips = socket.gethostbyname_ex(socket.gethostname())[2]
        if ip in local_ips:
            hostname = socket.gethostname()
            if hostname and not _is_docker_hostname(hostname):
                return hostname
    except Exception:
        pass

    # 3. 反向DNS解析
    try:
        rev = socket.gethostbyaddr(ip)[0]
        if rev and not _is_docker_hostname(rev):
            return rev
        # 如果反向DNS返回的是Docker假名，但本机名更可靠
        if _is_docker_hostname(rev) and ip in ("127.0.0.1", "::1"):
            return platform.node() or socket.gethostname()
    except Exception:
        pass

    # 4. NetBIOS名称查询（局域网Windows机器）
    try:
        from scanner.os_detect import grab_netbios_name
        nb = grab_netbios_name(ip, timeout=1.5)
        if nb:
            return nb
    except Exception:
        pass

    return hostname


def _is_docker_hostname(name):
    """判断是否是Docker/K8s等容器假主机名"""
    docker_keywords = [
        "kubernetes", "docker", "k8s", "container",
        "minikube", "kind", "rancher", "openshift"
    ]
    name_lower = name.lower()
    return any(kw in name_lower for kw in docker_keywords)


def run_asset_scan(target_str, task_id=None, ports=None, scan_mode="快速", callback=None, stop_check=None):
    """
    执行完整的资产扫描 - 支持2000+目标的批量并发扫描

    参数:
        target_str: 目标字符串
        task_id: 扫描任务ID
        ports: 自定义端口列表（为None则根据scan_mode自动选择）
        scan_mode: 扫描模式 - "快速"/"中速"/"全端口"
        callback: 进度回调函数 callback(progress, message)
        stop_check: 停止检查函数 stop_check() -> bool，返回True表示需要停止

    返回:
        扫描结果字典
    """
    targets = parse_targets(target_str)
    total = len(targets)

    # 根据扫描模式选择端口和线程数
    if ports is None:
        if scan_mode == "全端口":
            ports = list(range(1, 65536))
        elif scan_mode == "中速":
            ports = sorted(config.TOP_1000_PORTS)
        else:
            ports = config.DEFAULT_PORTS

    port_count = len(ports)
    max_threads = config.FULL_SCAN_THREADS if scan_mode == "全端口" else config.SCAN_THREADS
    batch_size = config.BATCH_SIZE  # 每批处理的目标数

    mode_label = {"快速": f"快速({port_count}端口)", "中速": f"中速({port_count}端口)", "全端口": "全端口(65535)"}
    results = {"total": total, "alive": 0, "dead": 0, "hosts": [], "new_assets": [], "offline_assets": [],
               "scan_mode": scan_mode, "port_count": port_count}

    # 记录扫描前已有的资产
    existing_assets = {a["ip"]: a for a in db_manager.get_all_assets()}

    # ====== 分批并发扫描 ======
    batches = [targets[i:i+batch_size] for i in range(0, total, batch_size)]
    scanned_count = 0

    for batch_idx, batch in enumerate(batches):
        # 检查是否请求停止
        if stop_check and stop_check():
            if callback:
                callback(progress, "扫描已被用户停止")
            break

        # 批量并发探测存活
        alive_ips = []
        with ThreadPoolExecutor(max_workers=min(len(batch), 100)) as executor:
            future_map = {executor.submit(ping_host, ip, config.SCAN_TIMEOUT): ip for ip in batch}
            for future in as_completed(future_map):
                # 检查是否请求停止
                if stop_check and stop_check():
                    break
                ip = future_map[future]
                scanned_count += 1
                try:
                    if future.result():
                        alive_ips.append(ip)
                        results["alive"] += 1
                    else:
                        results["dead"] += 1
                except Exception:
                    results["dead"] += 1

                # 更新进度
                progress = int(scanned_count / total * 100)
                if callback and scanned_count % 10 == 0:
                    callback(progress, f"[{mode_label.get(scan_mode, scan_mode)}] 存活探测 {scanned_count}/{total} (存活:{results['alive']})")
                if task_id and scanned_count % 20 == 0:
                    db_manager.update_scan_task(task_id, progress=int(progress * 0.3))  # 存活探测占30%

        # 检查是否请求停止
        if stop_check and stop_check():
            break

        # 对存活主机并发扫描端口和OS识别
        def scan_single_host(ip):
            """扫描单个主机的完整信息"""
            hostname = get_hostname(ip)
            # 全端口模式用更多线程，快速/中速模式用50线程
            port_threads = min(max_threads, 200) if scan_mode == "全端口" else 50
            open_ports = scan_host_ports(ip, ports, timeout=config.SCAN_TIMEOUT, max_threads=port_threads)
            os_name, os_category, os_detail = detect_os(ip, open_ports)
            return {
                "ip": ip, "hostname": hostname,
                "os_guess": os_name, "os_category": os_category, "os_detail": os_detail,
                "open_ports": open_ports, "port_count": len(open_ports)
            }

        if alive_ips:
            with ThreadPoolExecutor(max_workers=min(len(alive_ips), 20)) as executor:
                host_futures = {executor.submit(scan_single_host, ip): ip for ip in alive_ips}
                for future in as_completed(host_futures):
                    # 检查是否请求停止
                    if stop_check and stop_check():
                        executor.shutdown(wait=False, cancel_futures=True)
                        break
                    ip = host_futures[future]
                    try:
                        host_result = future.result()

                        # 保存到数据库
                        asset_id = db_manager.upsert_asset(ip, hostname=host_result["hostname"],
                                                           os_guess=host_result["os_guess"])
                        for p in host_result["open_ports"]:
                            db_manager.upsert_port(asset_id, p["port"], state=p["state"],
                                                   service=p["service"], version=p.get("version", ""),
                                                   banner=p["banner"])

                        results["hosts"].append(host_result)

                        # 检测新资产
                        if ip not in existing_assets:
                            results["new_assets"].append(ip)
                            db_manager.add_asset_change(ip, "新增",
                                f"扫描模式: {scan_mode}，开放端口: {host_result['port_count']}个")

                    except Exception as e:
                        pass

                    scanned_port_count = len(results["hosts"])
                    if callback:
                        progress = 30 + int(scanned_port_count / max(len(alive_ips), 1) * 60)
                        callback(progress, f"端口扫描 {scanned_port_count}/{len(alive_ips)} 存活主机")

            if task_id:
                db_manager.update_scan_task(task_id, progress=90)

        # 批次间短暂延迟，避免网络拥塞
        if batch_idx < len(batches) - 1:
            time.sleep(config.BATCH_DELAY)

    # 检测离线资产
    scanned_ips = set(targets)
    for ip, asset in existing_assets.items():
        if ip in scanned_ips and ip not in [h["ip"] for h in results["hosts"]]:
            results["offline_assets"].append(ip)
            db_manager.add_asset_change(ip, "离线", "资产不在线")

    if task_id:
        summary = f"扫描完成[{scan_mode}]: 共{total}个目标，存活{results['alive']}个，扫描{port_count}个端口，新增{len(results['new_assets'])}个资产"
        db_manager.update_scan_task(task_id, status="已完成", progress=100, result_summary=summary)

    if callback:
        callback(100, f"扫描完成: {total}个目标，{results['alive']}个存活")

    return results


# ==================== 端口扫描服务识别 ====================

def grab_banner(ip, port, timeout=2):
    """
    深度Banner抓取，用于服务版本识别
    """
    probes = {
        80: b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n",
        443: b"\x16\x03\x01\x00\x05\x01\x00\x00\x00\x00",
        22: b"SSH-2.0-Scan\r\n",
        21: b"USER anonymous\r\n",
        25: b"EHLO scan\r\n",
        3306: b"\x00\x00\x00\x00\x00",
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        probe = probes.get(port, b"\r\n")
        sock.send(probe)

        time.sleep(0.5)
        banner = sock.recv(1024)
        sock.close()

        return banner.decode("utf-8", errors="ignore").strip()
    except Exception:
        return ""

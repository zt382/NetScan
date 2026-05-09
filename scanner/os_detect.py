# -*- coding: utf-8 -*-
"""
操作系统识别模块
支持：Windows全系列、Linux发行版、国产信创系统（银河麒麟、统信UOS、openEuler、中科方德、深度等）
识别方式：SSH Banner、HTTP Banner、SMB指纹、NetBIOS、端口组合、nmap-service-probes指纹
"""
import socket
import re


# ==================== 信创/国产OS指纹库 ====================

# SSH Banner指纹 → OS
SSH_FINGERPRINTS = [
    # 国产信创系统（优先匹配）
    (r"Kylin|kylin", "银河麒麟", "信创OS"),
    (r"UOS|UnionTech|uniontechos|uos-server", "统信UOS", "信创OS"),
    (r"openEuler|openeuler", "openEuler", "信创OS"),
    (r"NeoKylin|neokylin", "中标麒麟", "信创OS"),
    (r"Fedora-Server|Kylinsec", "麒麟信安", "信创OS"),
    (r"Fangde|fangde", "中科方德", "信创OS"),
    (r"StartOS|startos", "起点操作系统", "信创OS"),
    (r"TurboLinux|turbolinux", "拓林思Linux", "信创OS"),
    (r"Red Flag|redflag|红旗", "红旗Linux", "信创OS"),
    (r"Deepin|deepin", "深度Deepin", "信创OS"),

    # 国际Linux发行版
    (r"Ubuntu", "Ubuntu", "Linux"),
    (r"Debian", "Debian", "Linux"),
    (r"CentOS", "CentOS", "Linux"),
    (r"Red Hat|RedHat|RHEL", "Red Hat Enterprise", "Linux"),
    (r"Rocky", "Rocky Linux", "Linux"),
    (r"AlmaLinux", "AlmaLinux", "Linux"),
    (r"Oracle", "Oracle Linux", "Linux"),
    (r"Fedora", "Fedora", "Linux"),
    (r"SUSE|SLES", "SUSE Linux", "Linux"),
    (r"Arch", "Arch Linux", "Linux"),
    (r"Alpine", "Alpine Linux", "Linux"),
    (r"Gentoo", "Gentoo Linux", "Linux"),
    (r"FreeBSD", "FreeBSD", "Unix"),
    (r"OpenBSD", "OpenBSD", "Unix"),
    (r"NetBSD", "NetBSD", "Unix"),
    (r"SunOS|Solaris", "Solaris", "Unix"),
    (r"AIX", "IBM AIX", "Unix"),
    (r"Darwin|macOS", "macOS", "macOS"),
    (r"OpenSSH", "Linux/Unix", "Linux"),
    (r"Dropbear", "嵌入式Linux", "Linux"),
    (r"Cisco", "Cisco IOS", "网络设备"),
    (r"Huawei|huawei", "华为VRP", "网络设备"),
    (r"H3C|h3c", "华三Comware", "网络设备"),
    (r"ZTE|zte", "中兴ROS", "网络设备"),
    (r"Ruijie|ruijie", "锐捷RGOS", "网络设备"),
]

# HTTP Server头指纹 → OS
HTTP_FINGERPRINTS = [
    # 国产信创Web服务器
    (r"TongWeb", "东方通TongWeb", "信创中间件"),
    (r"INSPUR|Inspur", "浪潮", "信创OS"),
    (r"Isoftserver|isoft", "浪潮iSoft Server", "信创OS"),

    # 国际Web服务器
    (r"Microsoft-IIS", "Windows Server (IIS)", "Windows"),
    (r"Apache.*Ubuntu", "Ubuntu (Apache)", "Linux"),
    (r"Apache.*CentOS", "CentOS (Apache)", "Linux"),
    (r"Apache.*Debian", "Debian (Apache)", "Linux"),
    (r"Apache.*Red Hat", "RHEL (Apache)", "Linux"),
    (r"Apache.*Kylin", "银河麒麟 (Apache)", "信创OS"),
    (r"Apache.*UOS", "统信UOS (Apache)", "信创OS"),
    (r"Apache.*openEuler", "openEuler (Apache)", "信创OS"),
    (r"nginx", "Linux (Nginx)", "Linux"),
    (r"Apache", "Linux (Apache)", "Linux"),
    (r"LiteSpeed", "Linux (LiteSpeed)", "Linux"),
    (r"Caddy", "Linux (Caddy)", "Linux"),
]

# SMB/NetBIOS指纹 → Windows版本
SMB_FINGERPRINTS = [
    (r"Windows Server 2025", "Windows Server 2025", "Windows"),
    (r"Windows Server 2022", "Windows Server 2022", "Windows"),
    (r"Windows Server 2019", "Windows Server 2019", "Windows"),
    (r"Windows Server 2016", "Windows Server 2016", "Windows"),
    (r"Windows Server 2012 R2", "Windows Server 2012 R2", "Windows"),
    (r"Windows Server 2012", "Windows Server 2012", "Windows"),
    (r"Windows Server 2008 R2", "Windows Server 2008 R2", "Windows"),
    (r"Windows Server 2008", "Windows Server 2008", "Windows"),
    (r"Windows Server 2003", "Windows Server 2003", "Windows"),
    (r"Windows 11", "Windows 11", "Windows"),
    (r"Windows 10", "Windows 10", "Windows"),
    (r"Windows 8\.1", "Windows 8.1", "Windows"),
    (r"Windows 8", "Windows 8", "Windows"),
    (r"Windows 7", "Windows 7", "Windows"),
    (r"Windows Vista", "Windows Vista", "Windows"),
    (r"Windows XP", "Windows XP", "Windows"),
    (r"Samba", "Linux (Samba)", "Linux"),
]

# 数据库Banner指纹
DB_FINGERPRINTS = [
    (r"MariaDB", "MariaDB", "数据库"),
    (r"MySQL", "MySQL", "数据库"),
    (r"PostgreSQL", "PostgreSQL", "数据库"),
    (r"Microsoft SQL Server|MSSQL", "SQL Server", "数据库"),
    (r"Oracle Database", "Oracle Database", "数据库"),
    (r"Redis", "Redis", "数据库"),
    (r"MongoDB", "MongoDB", "数据库"),
    (r"Elasticsearch", "Elasticsearch", "数据库"),
]

# 网络设备指纹
NETWORK_FINGERPRINTS = [
    (r"Huawei|HUAWEI|huawei|VRP", "华为设备", "网络设备"),
    (r"H3C|h3c|Comware", "华三设备", "网络设备"),
    (r"Cisco|cisco", "思科设备", "网络设备"),
    (r"ZTE|zte", "中兴设备", "网络设备"),
    (r"Ruijie|ruijie|锐捷", "锐捷设备", "网络设备"),
    (r"TP-Link|tp-link", "TP-Link设备", "网络设备"),
    (r"D-Link|d-link", "D-Link设备", "网络设备"),
    (r"Fortinet|FortiGate", "飞塔防火墙", "安全设备"),
    (r"Palo Alto", "Palo Alto防火墙", "安全设备"),
    (r"深信服|Sangfor", "深信服设备", "安全设备"),
    (r"奇安信|QiAnXin", "奇安信设备", "安全设备"),
    (r"天融信|TopSec", "天融信设备", "安全设备"),
    (r"绿盟|NSFOCUS", "绿盟设备", "安全设备"),
    (r"启明星辰|Venustech", "启明星辰设备", "安全设备"),
    (r"山石网科|Hillstone", "山石网科设备", "安全设备"),
    (r"网御星云|Leadsec", "网御星云设备", "安全设备"),
    (r"安恒|DBAPPSecurity", "安恒设备", "安全设备"),
]


def grab_ssh_banner(ip, timeout=2):
    """获取SSH Banner"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, 22))
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()
        return banner
    except Exception:
        return ""


def grab_http_banner(ip, port=80, timeout=2):
    """获取HTTP Server头"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        host = ip
        sock.send(f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n\r\n".encode())
        resp = sock.recv(4096).decode("utf-8", errors="ignore")
        sock.close()

        # 提取Server头
        m = re.search(r"[Ss]erver:\s*(.+?)(?:\r|\n)", resp)
        if m:
            return m.group(1).strip()
        return ""
    except Exception:
        return ""


def grab_smb_os(ip, timeout=2):
    """通过SMB协议获取Windows版本"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, 445))

        # SMB Negotiate Protocol Request
        # 这是一个简化的SMB2 Negotiate请求
        smb_negotiate = bytes([
            0x00, 0x00, 0x00, 0xd4,  # NetBIOS Session
            0xff, 0x53, 0x4d, 0x42,  # SMB Magic
            0x72,                      # Negotiate
            0x00, 0x00, 0x00, 0x00,  # Status
            0x18, 0x53, 0xc8,        # Flags
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xfe,
            0x00, 0x00, 0x00, 0x00,
            0x00,                      # Word Count
            0x62, 0x00,               # Byte Count
            0x02, 0x50, 0x43, 0x20, 0x4e, 0x45, 0x54, 0x57,
            0x4f, 0x52, 0x4b, 0x20, 0x50, 0x52, 0x4f, 0x47,
            0x52, 0x41, 0x4d, 0x20, 0x31, 0x2e, 0x30, 0x00,
            0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x31,
            0x2e, 0x30, 0x00,
            0x02, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73,
            0x20, 0x66, 0x6f, 0x72, 0x20, 0x57, 0x6f, 0x72,
            0x6b, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x73, 0x20,
            0x33, 0x2e, 0x31, 0x61, 0x00,
            0x02, 0x4c, 0x4d, 0x31, 0x2e, 0x32, 0x58, 0x30,
            0x30, 0x32, 0x00,
            0x02, 0x53, 0x41, 0x4d, 0x42, 0x41, 0x00,
            0x02, 0x4e, 0x54, 0x20, 0x4c, 0x41, 0x4e, 0x4d,
            0x41, 0x4e, 0x20, 0x31, 0x2e, 0x30, 0x00,
            0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30,
            0x2e, 0x31, 0x32, 0x00,
        ])

        sock.send(smb_negotiate)
        resp = sock.recv(4096)
        sock.close()

        # 解析SMB响应中的OS字符串
        # SMB1响应中OS名称通常在数据部分
        if len(resp) > 72:
            # 尝试从响应中提取文本
            text = resp[72:].decode("utf-8", errors="ignore")
            # 查找Windows版本字符串
            for pattern, os_name, os_type in SMB_FINGERPRINTS:
                if re.search(pattern, text, re.IGNORECASE):
                    return os_name, os_type
            # 如果找到Samba
            if "Samba" in text:
                return "Linux (Samba)", "Linux"
    except Exception:
        pass
    return "", ""


def grab_netbios_name(ip, timeout=2):
    """通过NetBIOS获取机器名和OS"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        # NetBIOS Name Status Query
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
            names = []
            num_names = data[56]
            for i in range(num_names):
                offset = 57 + (i * 18)
                if offset + 18 <= len(data):
                    name = data[offset:offset+15].decode("ascii", errors="ignore").strip()
                    suffix = data[offset+15]
                    if suffix == 0x00:  # Workstation
                        names.append(name)
                    elif suffix == 0x20:  # File Server
                        names.append(name)
            if names:
                return names[0]
    except Exception:
        pass
    return ""


def match_fingerprint(text, fingerprints):
    """通用指纹匹配"""
    if not text:
        return "", ""
    for pattern, os_name, os_type in fingerprints:
        if re.search(pattern, text, re.IGNORECASE):
            return os_name, os_type
    return "", ""


def detect_os(ip, open_ports, banners=None):
    """
    综合OS识别主函数

    参数:
        ip: 目标IP
        open_ports: 开放端口列表 [{"port": int, "service": str, "banner": str}, ...]
        banners: 额外banner信息

    返回:
        (os_name, os_category, os_detail)
        os_name: 具体OS名称 如 "银河麒麟V10" "Windows Server 2019"
        os_category: 分类 如 "信创OS" "Windows" "Linux" "网络设备"
        os_detail: 详细识别依据
    """
    port_nums = [p["port"] for p in open_ports]

    # 收集所有banner信息
    all_banners = []
    for p in open_ports:
        if p.get("banner"):
            all_banners.append(p["banner"])
    if banners:
        all_banners.extend(banners)

    all_text = " ".join(all_banners)

    results = []  # [(os_name, os_category, confidence, source)]

    # ====== 1. SSH Banner识别（最准确） ======
    if 22 in port_nums:
        # 先用已有banner
        ssh_banner = ""
        for p in open_ports:
            if p["port"] == 22 and p.get("banner"):
                ssh_banner = p["banner"]
                break

        # 如果没有，主动抓取
        if not ssh_banner:
            ssh_banner = grab_ssh_banner(ip)

        if ssh_banner:
            os_name, os_type = match_fingerprint(ssh_banner, SSH_FINGERPRINTS)
            if os_name:
                # 提取版本号
                version = ""
                m = re.search(r"([\w.-]+)[\s/]", ssh_banner)
                if m:
                    version = m.group(1)
                results.append((os_name, os_type, 90, f"SSH: {ssh_banner[:60]}"))

            # 通用SSH判断
            if not os_name:
                results.append(("Linux/Unix", "Linux", 60, f"SSH: {ssh_banner[:60]}"))

    # ====== 2. HTTP Server头识别 ======
    web_ports = [p for p in port_nums if p in [80, 443, 8080, 8443, 8888, 9090, 8000, 8001]]
    for wp in web_ports:
        server = ""
        for p in open_ports:
            if p["port"] == wp and p.get("banner"):
                # 尝试从banner中提取Server头
                m = re.search(r"[Ss]erver:\s*(.+?)(?:\r|\n)", p["banner"])
                if m:
                    server = m.group(1).strip()
                    break

        if not server:
            server = grab_http_banner(ip, wp)

        if server:
            os_name, os_type = match_fingerprint(server, HTTP_FINGERPRINTS)
            if os_name:
                results.append((os_name, os_type, 80, f"HTTP Server({wp}): {server}"))

    # ====== 3. SMB/NetBIOS识别（Windows精确版本） ======
    if 445 in port_nums or 139 in port_nums:
        # 尝试SMB OS获取
        smb_os, smb_type = grab_smb_os(ip)
        if smb_os:
            results.append((smb_os, smb_type, 95, f"SMB指纹: {smb_os}"))

        # NetBIOS获取机器名
        nb_name = grab_netbios_name(ip)
        if nb_name:
            results.append(("Windows", "Windows", 70, f"NetBIOS: {nb_name}"))

    # ====== 4. 数据库Banner识别 ======
    for p in open_ports:
        if p.get("banner"):
            db_name, db_type = match_fingerprint(p["banner"], DB_FINGERPRINTS)
            if db_name:
                results.append((db_name, db_type, 30, f"DB({p['port']}): {db_name}"))

    # ====== 5. 网络设备识别 ======
    for p in open_ports:
        if p.get("banner"):
            dev_name, dev_type = match_fingerprint(p["banner"], NETWORK_FINGERPRINTS)
            if dev_name:
                results.append((dev_name, dev_type, 85, f"设备({p['port']}): {dev_name}"))

    # ====== 6. 端口组合推测 ======
    # Windows特征
    if 135 in port_nums and 445 in port_nums:
        windows_score = 75
        if 3389 in port_nums:
            windows_score = 85
        if 139 in port_nums:
            windows_score += 5
        results.append(("Windows Server", "Windows", windows_score, "端口组合: 135+445(+3389)"))

    # Linux特征
    if 22 in port_nums and 445 not in port_nums and 135 not in port_nums:
        linux_score = 65
        if 80 in port_nums or 443 in port_nums:
            linux_score = 70
        results.append(("Linux/Unix", "Linux", linux_score, "端口组合: 22(无SMB/RPC)"))

    # ====== 7. 综合判定 ======
    if not results:
        return "未知", "未知", "未检测到足够指纹信息"

    # 按置信度排序
    results.sort(key=lambda x: x[2], reverse=True)

    # 取最高分结果
    best_os, best_type, best_conf, best_source = results[0]

    # 构建详细信息
    detail_parts = [f"识别结果: {best_os} (置信度:{best_conf}%)"]
    detail_parts.append(f"依据: {best_source}")

    # 添加其他识别结果
    if len(results) > 1:
        other = [f"{r[0]}({r[2]}%)" for r in results[1:3] if r[2] >= 50]
        if other:
            detail_parts.append(f"其他: {', '.join(other)}")

    detail = " | ".join(detail_parts)

    # 如果最佳结果置信度太低，标记为不确定
    if best_conf < 50:
        best_os = f"疑似{best_os}"

    return best_os, best_type, detail


# ==================== 服务版本提取 ====================

def extract_service_version(banner, port):
    """从Banner中提取服务版本信息"""
    if not banner:
        return ""

    # SSH版本
    if port == 22:
        m = re.match(r"(SSH-[\d.]+-\S+)", banner)
        if m:
            return m.group(1)

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
            return m.group(1)

    # Redis版本
    if port == 6379:
        m = re.search(r"redis_version:([\d.]+)", banner)
        if m:
            return "Redis " + m.group(1)

    # PostgreSQL版本
    if port == 5432:
        m = re.search(r"PostgreSQL\s*([\d.]+)", banner, re.IGNORECASE)
        if m:
            return "PostgreSQL " + m.group(1)

    return ""

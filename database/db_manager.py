# -*- coding: utf-8 -*-
"""
数据库管理模块 - 使用SQLite存储扫描数据
"""
import sqlite3
import os
import config


def get_connection():
    """获取数据库连接"""
    db_path = config.DATABASE_PATH
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA encoding='UTF-8'")
    return conn


def init_database():
    """初始化数据库表结构"""
    conn = get_connection()
    cursor = conn.cursor()

    # 资产表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            hostname TEXT DEFAULT '',
            os_guess TEXT DEFAULT '',
            mac_address TEXT DEFAULT '',
            status TEXT DEFAULT '在线',
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(ip)
        )
    """)

    # 端口表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT DEFAULT 'tcp',
            state TEXT DEFAULT '开放',
            service TEXT DEFAULT '',
            version TEXT DEFAULT '',
            banner TEXT DEFAULT '',
            scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
            UNIQUE(asset_id, port, protocol)
        )
    """)

    # 漏洞表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER NOT NULL,
            port_id INTEGER,
            vuln_name TEXT NOT NULL,
            vuln_level TEXT DEFAULT '低危',
            vuln_desc TEXT DEFAULT '',
            vuln_solution TEXT DEFAULT '',
            vuln_cve TEXT DEFAULT '',
            vuln_cnvd TEXT DEFAULT '',
            scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT '未修复',
            FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
            FOREIGN KEY (port_id) REFERENCES ports(id) ON DELETE SET NULL
        )
    """)

    # 扫描任务表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_name TEXT NOT NULL,
            target TEXT NOT NULL,
            scan_type TEXT DEFAULT '资产扫描',
            status TEXT DEFAULT '等待中',
            progress INTEGER DEFAULT 0,
            result_summary TEXT DEFAULT '',
            start_time TIMESTAMP,
            end_time TIMESTAMP,
            created_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 扫描历史表（资产变化追踪）
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS asset_changes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            change_type TEXT NOT NULL,
            detail TEXT DEFAULT '',
            scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 用户表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            display_name TEXT DEFAULT '',
            role TEXT DEFAULT 'user',
            is_active INTEGER DEFAULT 1,
            created_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    """)

    # 创建默认admin账户（如果不存在）
    import hashlib
    default_password = hashlib.sha256("admin123".encode()).hexdigest()
    cursor.execute("""
        INSERT OR IGNORE INTO users (username, password_hash, display_name, role)
        VALUES (?, ?, ?, ?)
    """, ("admin", default_password, "系统管理员", "admin"))

    # 定时扫描任务表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scheduled_tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            target TEXT NOT NULL,
            scan_type TEXT DEFAULT '资产扫描',
            scan_mode TEXT DEFAULT '快速',
            cron_expression TEXT NOT NULL,
            is_active INTEGER DEFAULT 1,
            last_run_time TIMESTAMP,
            next_run_time TIMESTAMP,
            created_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_by TEXT DEFAULT ''
        )
    """)

    conn.commit()
    conn.close()
    print("[数据库] 初始化完成")


# ==================== 资产操作 ====================

def upsert_asset(ip, hostname="", os_guess="", mac_address=""):
    """插入或更新资产"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO assets (ip, hostname, os_guess, mac_address, status, last_seen)
        VALUES (?, ?, ?, ?, '在线', CURRENT_TIMESTAMP)
        ON CONFLICT(ip) DO UPDATE SET
            hostname = CASE WHEN excluded.hostname != '' THEN excluded.hostname ELSE hostname END,
            os_guess = CASE WHEN excluded.os_guess != '' THEN excluded.os_guess ELSE os_guess END,
            mac_address = CASE WHEN excluded.mac_address != '' THEN excluded.mac_address ELSE mac_address END,
            status = '在线',
            last_seen = CURRENT_TIMESTAMP
    """, (ip, hostname, os_guess, mac_address))
    asset_id = cursor.execute("SELECT id FROM assets WHERE ip = ?", (ip,)).fetchone()["id"]
    conn.commit()
    conn.close()
    return asset_id


def get_all_assets():
    """获取所有资产（含端口数和漏洞数）"""
    conn = get_connection()
    rows = conn.execute("""
        SELECT a.*,
            (SELECT COUNT(*) FROM ports p WHERE p.asset_id = a.id AND p.state = '开放') AS port_count,
            (SELECT COUNT(*) FROM vulnerabilities v WHERE v.asset_id = a.id) AS vuln_count
        FROM assets a
        ORDER BY a.last_seen DESC
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_asset_by_ip(ip):
    """根据IP获取资产"""
    conn = get_connection()
    row = conn.execute("SELECT * FROM assets WHERE ip = ?", (ip,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_asset_count():
    """获取资产总数"""
    conn = get_connection()
    count = conn.execute("SELECT COUNT(*) as cnt FROM assets").fetchone()["cnt"]
    conn.close()
    return count


def delete_asset(asset_id):
    """删除单个资产（级联删除关联的端口和漏洞）"""
    conn = get_connection()
    row = conn.execute("SELECT ip FROM assets WHERE id = ?", (asset_id,)).fetchone()
    if not row:
        conn.close()
        return False, "资产不存在"
    ip = row["ip"]
    conn.execute("DELETE FROM assets WHERE id = ?", (asset_id,))
    conn.commit()
    conn.close()
    return True, f"资产 {ip} 已删除"


def delete_assets_batch(asset_ids):
    """批量删除资产"""
    if not asset_ids:
        return 0, "未选择资产"
    conn = get_connection()
    placeholders = ",".join(["?"] * len(asset_ids))
    # 记录被删除的IP用于日志
    rows = conn.execute(f"SELECT id, ip FROM assets WHERE id IN ({placeholders})", asset_ids).fetchall()
    deleted_ips = [r["ip"] for r in rows]
    conn.execute(f"DELETE FROM assets WHERE id IN ({placeholders})", asset_ids)
    conn.commit()
    conn.close()
    return len(deleted_ips), f"已删除 {len(deleted_ips)} 个资产: {', '.join(deleted_ips[:5])}{'...' if len(deleted_ips) > 5 else ''}"


# ==================== 端口操作 ====================

def upsert_port(asset_id, port, protocol="tcp", state="开放", service="", version="", banner=""):
    """插入或更新端口信息"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO ports (asset_id, port, protocol, state, service, version, banner, scan_time)
        VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(asset_id, port, protocol) DO UPDATE SET
            state = excluded.state,
            service = excluded.service,
            version = excluded.version,
            banner = excluded.banner,
            scan_time = CURRENT_TIMESTAMP
    """, (asset_id, port, protocol, state, service, version, banner))
    port_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return port_id


def get_ports_by_asset(asset_id):
    """获取资产的所有端口"""
    conn = get_connection()
    rows = conn.execute("SELECT * FROM ports WHERE asset_id = ? ORDER BY port", (asset_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_open_port_count():
    """获取开放端口总数"""
    conn = get_connection()
    count = conn.execute("SELECT COUNT(*) as cnt FROM ports WHERE state = '开放'").fetchone()["cnt"]
    conn.close()
    return count


# ==================== 漏洞操作 ====================

def add_vulnerability(asset_id, vuln_name, vuln_level="低危", vuln_desc="",
                      vuln_solution="", vuln_cve="", vuln_cnvd="", port_id=None):
    """添加漏洞"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO vulnerabilities (asset_id, port_id, vuln_name, vuln_level, vuln_desc,
                                     vuln_solution, vuln_cve, vuln_cnvd)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (asset_id, port_id, vuln_name, vuln_level, vuln_desc, vuln_solution, vuln_cve, vuln_cnvd))
    vuln_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return vuln_id


def get_vulnerabilities(asset_id=None, level=None):
    """获取漏洞列表"""
    conn = get_connection()
    query = "SELECT v.*, a.ip FROM vulnerabilities v JOIN assets a ON v.asset_id = a.id WHERE 1=1"
    params = []
    if asset_id:
        query += " AND v.asset_id = ?"
        params.append(asset_id)
    if level:
        query += " AND v.vuln_level = ?"
        params.append(level)
    query += " ORDER BY CASE v.vuln_level WHEN '严重' THEN 1 WHEN '高危' THEN 2 WHEN '中危' THEN 3 ELSE 4 END, v.scan_time DESC"
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_vuln_count(level=None):
    """获取漏洞总数"""
    conn = get_connection()
    if level:
        count = conn.execute("SELECT COUNT(*) as cnt FROM vulnerabilities WHERE vuln_level = ?", (level,)).fetchone()["cnt"]
    else:
        count = conn.execute("SELECT COUNT(*) as cnt FROM vulnerabilities").fetchone()["cnt"]
    conn.close()
    return count


def update_vuln_status(vuln_id, status):
    """更新漏洞状态"""
    conn = get_connection()
    conn.execute("UPDATE vulnerabilities SET status = ? WHERE id = ?", (status, vuln_id))
    conn.commit()
    conn.close()


# ==================== 扫描任务操作 ====================

def create_scan_task(task_name, target, scan_type="资产扫描"):
    """创建扫描任务"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scan_tasks (task_name, target, scan_type, status, start_time)
        VALUES (?, ?, ?, '执行中', CURRENT_TIMESTAMP)
    """, (task_name, target, scan_type))
    task_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return task_id


def update_scan_task(task_id, status=None, progress=None, result_summary=None):
    """更新扫描任务"""
    conn = get_connection()
    updates = []
    params = []
    if status:
        updates.append("status = ?")
        params.append(status)
    if progress is not None:
        updates.append("progress = ?")
        params.append(progress)
    if result_summary:
        updates.append("result_summary = ?")
        params.append(result_summary)
    if status == "已完成":
        updates.append("end_time = CURRENT_TIMESTAMP")
    if updates:
        params.append(task_id)
        conn.execute(f"UPDATE scan_tasks SET {', '.join(updates)} WHERE id = ?", params)
        conn.commit()
    conn.close()


def get_scan_tasks(limit=50):
    """获取扫描任务列表"""
    conn = get_connection()
    rows = conn.execute("SELECT * FROM scan_tasks ORDER BY created_time DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ==================== 资产变化 ====================

def add_asset_change(ip, change_type, detail=""):
    """记录资产变化"""
    conn = get_connection()
    conn.execute("""
        INSERT INTO asset_changes (ip, change_type, detail) VALUES (?, ?, ?)
    """, (ip, change_type, detail))
    conn.commit()
    conn.close()


def get_asset_changes(limit=100):
    """获取资产变化记录"""
    conn = get_connection()
    rows = conn.execute("SELECT * FROM asset_changes ORDER BY scan_time DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ==================== 统计 ====================

def get_dashboard_stats():
    """获取仪表盘统计数据"""
    conn = get_connection()
    stats = {
        "资产总数": conn.execute("SELECT COUNT(*) as cnt FROM assets").fetchone()["cnt"],
        "在线资产": conn.execute("SELECT COUNT(*) as cnt FROM assets WHERE status = '在线'").fetchone()["cnt"],
        "开放端口": conn.execute("SELECT COUNT(*) as cnt FROM ports WHERE state = '开放'").fetchone()["cnt"],
        "漏洞总数": conn.execute("SELECT COUNT(*) as cnt FROM vulnerabilities").fetchone()["cnt"],
        "严重漏洞": conn.execute("SELECT COUNT(*) as cnt FROM vulnerabilities WHERE vuln_level = '严重'").fetchone()["cnt"],
        "高危漏洞": conn.execute("SELECT COUNT(*) as cnt FROM vulnerabilities WHERE vuln_level = '高危'").fetchone()["cnt"],
        "中危漏洞": conn.execute("SELECT COUNT(*) as cnt FROM vulnerabilities WHERE vuln_level = '中危'").fetchone()["cnt"],
        "低危漏洞": conn.execute("SELECT COUNT(*) as cnt FROM vulnerabilities WHERE vuln_level = '低危'").fetchone()["cnt"],
        "扫描任务": conn.execute("SELECT COUNT(*) as cnt FROM scan_tasks").fetchone()["cnt"],
    }
    conn.close()
    return stats


# ==================== 用户管理 ====================

def get_all_users():
    """获取所有用户"""
    conn = get_connection()
    rows = conn.execute("""
        SELECT id, username, display_name, role, is_active, created_time, last_login
        FROM users ORDER BY created_time DESC
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_user_by_username(username):
    """根据用户名获取用户"""
    conn = get_connection()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return dict(row) if row else None


def create_user(username, password, display_name="", role="user"):
    """创建新用户"""
    import hashlib
    conn = get_connection()
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    try:
        conn.execute("""
            INSERT INTO users (username, password_hash, display_name, role)
            VALUES (?, ?, ?, ?)
        """, (username, password_hash, display_name, role))
        conn.commit()
        conn.close()
        return True, "用户创建成功"
    except Exception as e:
        conn.close()
        return False, f"创建失败: {str(e)}"


def update_user(user_id, display_name=None, role=None, is_active=None, password=None):
    """更新用户信息"""
    import hashlib
    conn = get_connection()
    updates = []
    params = []
    
    if display_name is not None:
        updates.append("display_name = ?")
        params.append(display_name)
    if role is not None:
        updates.append("role = ?")
        params.append(role)
    if is_active is not None:
        updates.append("is_active = ?")
        params.append(1 if is_active else 0)
    if password:
        updates.append("password_hash = ?")
        params.append(hashlib.sha256(password.encode()).hexdigest())
    
    if updates:
        params.append(user_id)
        conn.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", params)
        conn.commit()
    conn.close()
    return True, "用户更新成功"


def delete_user(user_id):
    """删除用户"""
    conn = get_connection()
    # 不允许删除admin用户
    user = conn.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
    if user and user["username"] == "admin":
        conn.close()
        return False, "不能删除管理员账户"
    
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return True, "用户已删除"


def verify_user(username, password):
    """验证用户登录"""
    import hashlib
    conn = get_connection()
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    row = conn.execute("""
        SELECT * FROM users WHERE username = ? AND password_hash = ? AND is_active = 1
    """, (username, password_hash)).fetchone()
    
    if row:
        # 更新最后登录时间
        conn.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", (row["id"],))
        conn.commit()
        conn.close()
        return dict(row)
    
    conn.close()
    return None


def change_password(user_id, old_password, new_password):
    """修改密码"""
    import hashlib
    conn = get_connection()
    
    # 验证旧密码
    old_hash = hashlib.sha256(old_password.encode()).hexdigest()
    user = conn.execute("SELECT * FROM users WHERE id = ? AND password_hash = ?", (user_id, old_hash)).fetchone()
    
    if not user:
        conn.close()
        return False, "旧密码错误"
    
    # 更新密码
    new_hash = hashlib.sha256(new_password.encode()).hexdigest()
    conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user_id))
    conn.commit()
    conn.close()
    return True, "密码修改成功"


# ==================== 定时扫描任务操作 ====================

def create_scheduled_task(name, target, scan_type, scan_mode, cron_expression, created_by=""):
    """创建定时扫描任务"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scheduled_tasks (name, target, scan_type, scan_mode, cron_expression, created_by)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (name, target, scan_type, scan_mode, cron_expression, created_by))
    task_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return task_id


def get_scheduled_tasks():
    """获取所有定时扫描任务"""
    conn = get_connection()
    rows = conn.execute("SELECT * FROM scheduled_tasks ORDER BY created_time DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_active_scheduled_tasks():
    """获取所有启用的定时扫描任务"""
    conn = get_connection()
    rows = conn.execute("SELECT * FROM scheduled_tasks WHERE is_active = 1").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_scheduled_task(task_id, **kwargs):
    """更新定时扫描任务"""
    conn = get_connection()
    updates = []
    params = []
    for key, value in kwargs.items():
        if value is not None:
            updates.append(f"{key} = ?")
            params.append(value)
    if updates:
        params.append(task_id)
        conn.execute(f"UPDATE scheduled_tasks SET {', '.join(updates)} WHERE id = ?", params)
        conn.commit()
    conn.close()
    return True


def delete_scheduled_task(task_id):
    """删除定时扫描任务"""
    conn = get_connection()
    conn.execute("DELETE FROM scheduled_tasks WHERE id = ?", (task_id,))
    conn.commit()
    conn.close()
    return True


def toggle_scheduled_task(task_id, is_active):
    """启用/禁用定时扫描任务"""
    conn = get_connection()
    conn.execute("UPDATE scheduled_tasks SET is_active = ? WHERE id = ?", (1 if is_active else 0, task_id))
    conn.commit()
    conn.close()
    return True

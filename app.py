# -*- coding: utf-8 -*-
"""
网络安全资产扫描系统 - 主应用
全中文界面 | 零外部依赖扫描 | 可移植部署
"""
import os
import sys
import json
import threading
import time
import random
import string
import hashlib
import io
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, jsonify, send_file, session, redirect, url_for
from database import db_manager
from scanner import asset_scanner, vuln_scanner
from scanner import vuln_db_manager
from report import report_generator
import config
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

# 初始化Flask应用
app = Flask(__name__)
app.secret_key = config.SECRET_KEY
app.config['SESSION_TYPE'] = 'filesystem'
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SESSION_TIMEOUT'] = config.SESSION_TIMEOUT

# 全局扫描状态
scan_status = {"running": False, "type": "", "progress": 0, "message": "", "task_id": None, "stop_requested": False}

# 验证码存储（内存中，重启后清除）
captcha_store = {}

# 初始化定时任务调度器
scheduler = BackgroundScheduler(daemon=True)


def run_scheduled_scan(task_id):
    """执行定时扫描任务的回调函数"""
    global scan_status
    # 获取任务详情
    tasks = db_manager.get_scheduled_tasks()
    task = next((t for t in tasks if t["id"] == task_id), None)
    if not task:
        return

    # 检查是否有其他扫描在运行
    if scan_status["running"]:
        print(f"[定时任务] 任务 {task['name']} 跳过：有其他扫描正在执行")
        return

    target = task["target"]
    scan_type = task["scan_type"]
    scan_mode = task["scan_mode"]

    # 创建扫描任务记录
    db_task_id = db_manager.create_scan_task(
        f"[定时] {task['name']}", target,
        f"{scan_type}-{scan_mode}")

    scan_status = {"running": True, "type": f"[定时]{scan_type}", "progress": 0,
                   "message": f"定时任务执行中: {task['name']}", "task_id": db_task_id,
                   "stop_requested": False}

    try:
        def progress_cb(progress, message):
            scan_status["progress"] = progress
            scan_status["message"] = f"[定时] {message}"

        if scan_type == "资产扫描":
            result = asset_scanner.run_asset_scan(target, task_id=db_task_id,
                                                   scan_mode=scan_mode, callback=progress_cb)
            summary = f"定时资产扫描完成: 发现{result['alive']}个在线资产"
        else:
            result = vuln_scanner.run_vuln_scan(target, task_id=db_task_id, callback=progress_cb)
            summary = f"定时漏洞扫描完成: 发现{result['vulns_found']}个新漏洞"

        scan_status["progress"] = 100
        scan_status["message"] = summary
        db_manager.update_scan_task(db_task_id, status="已完成", progress=100, result_summary=summary)
    except Exception as e:
        scan_status["message"] = f"定时扫描出错: {str(e)}"
        db_manager.update_scan_task(db_task_id, status="失败", result_summary=str(e))
    finally:
        # 更新最后执行时间
        from datetime import datetime
        db_manager.update_scheduled_task(task_id,
            last_run_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        time.sleep(3)
        scan_status["running"] = False
        scan_status["stop_requested"] = False


def sync_scheduled_tasks():
    """同步数据库中的定时任务到调度器"""
    # 移除所有现有任务
    scheduler.remove_all_jobs()
    # 加载启用的任务
    tasks = db_manager.get_active_scheduled_tasks()
    for task in tasks:
        try:
            cron_expr = task["cron_expression"]
            # 解析 cron 表达式 (分 时 日 月 周)
            parts = cron_expr.strip().split()
            if len(parts) == 5:
                trigger = CronTrigger(
                    minute=parts[0], hour=parts[1],
                    day=parts[2], month=parts[3], day_of_week=parts[4]
                )
                scheduler.add_job(
                    run_scheduled_scan, trigger,
                    args=[task["id"]],
                    id=f"scheduled_{task['id']}",
                    name=task["name"],
                    replace_existing=True
                )
                # 更新下次执行时间
                job = scheduler.get_job(f"scheduled_{task['id']}")
                if job and job.next_run_time:
                    db_manager.update_scheduled_task(task["id"],
                        next_run_time=job.next_run_time.strftime("%Y-%m-%d %H:%M:%S"))
                print(f"[定时任务] 已加载: {task['name']} ({cron_expr})")
        except Exception as e:
            print(f"[定时任务] 加载失败: {task['name']} - {e}")


@app.before_request
def check_session_timeout():
    """检查会话是否超时（30分钟无操作强制退出）"""
    # 跳过不需要认证的路径
    skip_paths = ['/login', '/api/login', '/api/captcha', '/api/logout',
                  '/static', '/certs']
    if any(request.path.startswith(p) for p in skip_paths):
        return

    if 'user_id' in session:
        last_active = session.get('last_active', 0)
        now = time.time()
        if now - last_active > config.SESSION_TIMEOUT:
            # 超时，清除会话
            username = session.get('username', '')
            session.clear()
            if request.path.startswith('/api/'):
                return jsonify({"success": False, "message": "会话已过期，请重新登录", "code": 401}), 401
            return redirect(url_for('login_page'))
        # 更新活跃时间
        session['last_active'] = now


def generate_captcha():
    """生成随机验证码"""
    # 生成4位随机数字
    code = ''.join(random.choices(string.digits, k=4))
    # 生成唯一ID
    captcha_id = hashlib.md5(f"{time.time()}{random.random()}".encode()).hexdigest()[:16]
    # 存储验证码（5分钟过期）
    captcha_store[captcha_id] = {
        'code': code,
        'expire': time.time() + 300
    }
    # 清理过期验证码
    expired_ids = [k for k, v in captcha_store.items() if v['expire'] < time.time()]
    for k in expired_ids:
        del captcha_store[k]
    return captcha_id, code


def verify_captcha(captcha_id, user_input):
    """验证验证码"""
    if not captcha_id or not user_input:
        return False
    stored = captcha_store.get(captcha_id)
    if not stored:
        return False
    # 验证后删除，防止重用
    del captcha_store[captcha_id]
    return stored['code'] == user_input.strip()


def generate_captcha_image(code):
    """生成验证码图片（纯Python实现，无需PIL）"""
    # 简单的SVG验证码
    width, height = 120, 40
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">
        <rect width="{width}" height="{height}" fill="#f0f0f0"/>
        <line x1="0" y1="{random.randint(5,35)}" x2="{width}" y2="{random.randint(5,35)}" 
              stroke="#ccc" stroke-width="1"/>
        <line x1="{random.randint(10,110)}" y1="0" x2="{random.randint(10,110)}" y2="{height}" 
              stroke="#ccc" stroke-width="1"/>'''
    
    # 添加噪点
    for _ in range(30):
        x, y = random.randint(0, width), random.randint(0, height)
        svg += f'<circle cx="{x}" cy="{y}" r="1" fill="#ddd"/>'
    
    # 绘制字符
    colors = ['#c0392b', '#2980b9', '#27ae60', '#8e44ad', '#f39c12']
    for i, char in enumerate(code):
        x = 15 + i * 25
        y = random.randint(20, 35)
        color = random.choice(colors)
        size = random.randint(18, 24)
        rotate = random.randint(-15, 15)
        svg += f'<text x="{x}" y="{y}" font-family="Arial" font-size="{size}" '
        svg += f'fill="{color}" transform="rotate({rotate},{x},{y})">{char}</text>'
    
    svg += '</svg>'
    return svg


# 登录检查装饰器
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            # API请求返回401
            if request.path.startswith('/api/'):
                return jsonify({"success": False, "message": "请先登录", "code": 401}), 401
            # 页面请求重定向到登录页
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function


# 管理员权限检查装饰器
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if request.path.startswith('/api/'):
                return jsonify({"success": False, "message": "请先登录", "code": 401}), 401
            return redirect(url_for('login_page'))
        if session.get('user_role') != 'admin':
            if request.path.startswith('/api/'):
                return jsonify({"success": False, "message": "需要管理员权限", "code": 403}), 403
            return "需要管理员权限", 403
        return f(*args, **kwargs)
    return decorated_function


def init_app():
    """初始化应用"""
    db_manager.init_database()
    # 自动清理上次进程遗留的"执行中"任务
    try:
        conn = db_manager.get_connection()
        rows = conn.execute("SELECT id, task_name FROM scan_tasks WHERE status = '执行中'").fetchall()
        for row in rows:
            conn.execute("UPDATE scan_tasks SET status = '已停止', result_summary = '进程重启，自动标记停止' WHERE id = ?", (row["id"],))
            print(f"[清理] 任务 #{row['id']} {row['task_name']} -> 已停止")
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[清理] 操作失败: {e}")
    # 启动定时任务调度器
    scheduler.start()
    sync_scheduled_tasks()
    print("=" * 50)
    print("  网络安全资产扫描系统")
    print("  启动地址: http://localhost:" + str(config.WEB_PORT))
    print("=" * 50)


# ==================== 认证路由 ====================

@app.route("/login")
def login_page():
    """登录页面"""
    if 'user_id' in session:
        return redirect(url_for('index'))
    return render_template("login.html")


@app.route("/api/captcha")
def api_captcha():
    """获取验证码"""
    captcha_id, code = generate_captcha()
    svg = generate_captcha_image(code)
    # 返回JSON格式，包含captcha_id和SVG图片
    return jsonify({
        "captcha_id": captcha_id,
        "image": svg
    })


@app.route("/api/login", methods=["POST"])
def api_login():
    """用户登录"""
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    captcha = data.get("captcha", "").strip()
    captcha_id = request.headers.get("X-Captcha-Id", "")
    
    # 验证验证码
    if not verify_captcha(captcha_id, captcha):
        return jsonify({"success": False, "message": "验证码错误或已过期"})
    
    # 验证用户名密码
    if not username or not password:
        return jsonify({"success": False, "message": "请输入用户名和密码"})
    
    user = db_manager.verify_user(username, password)
    if not user:
        return jsonify({"success": False, "message": "用户名或密码错误"})
    
    # 设置session
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['display_name'] = user['display_name']
    session['user_role'] = user['role']
    session['last_active'] = time.time()
    session.permanent = True
    
    return jsonify({"success": True, "message": "登录成功", "redirect": "/"})


@app.route("/api/logout")
def api_logout():
    """用户登出"""
    session.clear()
    return redirect(url_for('login_page'))


@app.route("/api/user/info")
@login_required
def api_user_info():
    """获取当前用户信息"""
    remaining = int(config.SESSION_TIMEOUT - (time.time() - session.get('last_active', time.time())))
    return jsonify({
        "success": True,
        "session_remaining": max(0, remaining),
        "session_timeout": config.SESSION_TIMEOUT,
        "user": {
            "id": session.get('user_id'),
            "username": session.get('username'),
            "display_name": session.get('display_name'),
            "role": session.get('user_role')
        }
    })


# ==================== 用户管理路由（管理员） ====================

@app.route("/users")
@admin_required
def users_page():
    """用户管理页面"""
    users = db_manager.get_all_users()
    return render_template("users.html", users=users)


@app.route("/api/users/add", methods=["POST"])
@admin_required
def api_users_add():
    """添加用户"""
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    display_name = data.get("display_name", "").strip()
    role = data.get("role", "user")
    
    if not username or not password:
        return jsonify({"success": False, "message": "用户名和密码不能为空"})
    
    if len(password) < 6:
        return jsonify({"success": False, "message": "密码长度不能少于6位"})
    
    success, message = db_manager.create_user(username, password, display_name, role)
    return jsonify({"success": success, "message": message})


@app.route("/api/users/update", methods=["POST"])
@admin_required
def api_users_update():
    """更新用户"""
    data = request.get_json() or {}
    user_id = data.get("user_id")
    
    if not user_id:
        return jsonify({"success": False, "message": "缺少用户ID"})
    
    success, message = db_manager.update_user(
        user_id,
        display_name=data.get("display_name"),
        role=data.get("role"),
        is_active=data.get("is_active")
    )
    return jsonify({"success": success, "message": message})


@app.route("/api/users/delete", methods=["POST"])
@admin_required
def api_users_delete():
    """删除用户"""
    data = request.get_json() or {}
    user_id = data.get("user_id")
    
    if not user_id:
        return jsonify({"success": False, "message": "缺少用户ID"})
    
    # 不允许删除自己
    if user_id == session.get('user_id'):
        return jsonify({"success": False, "message": "不能删除当前登录的用户"})
    
    success, message = db_manager.delete_user(user_id)
    return jsonify({"success": success, "message": message})


@app.route("/api/users/reset-password", methods=["POST"])
@admin_required
def api_users_reset_password():
    """重置用户密码"""
    data = request.get_json() or {}
    user_id = data.get("user_id")
    password = data.get("password", "").strip()
    
    if not user_id or not password:
        return jsonify({"success": False, "message": "缺少参数"})
    
    if len(password) < 6:
        return jsonify({"success": False, "message": "密码长度不能少于6位"})
    
    success, message = db_manager.update_user(user_id, password=password)
    return jsonify({"success": success, "message": message})


# ==================== 页面路由 ====================

@app.route("/")
@login_required
def index():
    """仪表盘首页"""
    stats = db_manager.get_dashboard_stats()
    recent_tasks = db_manager.get_scan_tasks(limit=5)
    recent_changes = db_manager.get_asset_changes(limit=10)
    return render_template("dashboard.html", stats=stats, tasks=recent_tasks, changes=recent_changes)


@app.route("/assets")
@login_required
def assets_page():
    """资产管理页面"""
    assets = db_manager.get_all_assets()
    return render_template("assets.html", assets=assets)


@app.route("/assets/<int:asset_id>")
@login_required
def asset_detail(asset_id):
    """资产详情页面"""
    conn = db_manager.get_connection()
    asset = conn.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()
    if not asset:
        return "资产不存在", 404
    asset = dict(asset)
    ports = db_manager.get_ports_by_asset(asset_id)
    vulns = db_manager.get_vulnerabilities(asset_id=asset_id)
    conn.close()
    return render_template("asset_detail.html", asset=asset, ports=ports, vulns=vulns)


@app.route("/vulns")
@login_required
def vulns_page():
    """漏洞管理页面"""
    level = request.args.get("level", "")
    if level:
        vulns = db_manager.get_vulnerabilities(level=level)
    else:
        vulns = db_manager.get_vulnerabilities()
    return render_template("vulns.html", vulns=vulns, current_level=level)


@app.route("/tasks")
@login_required
def tasks_page():
    """扫描任务页面"""
    tasks = db_manager.get_scan_tasks()
    return render_template("tasks.html", tasks=tasks)


@app.route("/report")
@login_required
def report_page():
    """报告页面"""
    return render_template("report.html")


@app.route("/settings")
@login_required
def settings_page():
    """设置页面"""
    import platform
    return render_template("settings.html", python_version=platform.python_version())


# ==================== API接口 ====================

@app.route("/api/scan/asset", methods=["POST"])
@login_required
def api_scan_asset():
    """启动资产扫描"""
    global scan_status
    if scan_status["running"]:
        return jsonify({"success": False, "message": "已有扫描任务正在执行，请等待完成"})

    data = request.get_json()
    target = data.get("target", "")
    scan_mode = data.get("scan_mode", "快速")
    if not target:
        return jsonify({"success": False, "message": "请输入扫描目标"})

    # 创建扫描任务
    mode_label = {"快速": "快速", "中速": "TOP1000", "全端口": "全端口65535"}
    task_id = db_manager.create_scan_task(f"资产扫描[{mode_label.get(scan_mode, scan_mode)}]-{target}", target, f"资产扫描-{scan_mode}")

    def scan_thread():
        global scan_status
        scan_status = {"running": True, "type": "资产扫描", "progress": 0,
                       "message": "正在初始化...", "task_id": task_id, "stop_requested": False}
        try:
            def progress_cb(progress, message):
                scan_status["progress"] = progress
                scan_status["message"] = message

            def stop_check():
                return scan_status.get("stop_requested", False)

            result = asset_scanner.run_asset_scan(target, task_id=task_id, scan_mode=scan_mode,
                                                   callback=progress_cb, stop_check=stop_check)
            if scan_status.get("stop_requested"):
                scan_status["message"] = f"扫描已手动停止：已完成{result['alive']}个在线资产"
                db_manager.update_scan_task(task_id, status="已停止", result_summary=f"手动停止，已发现{result['alive']}个在线资产")
            else:
                scan_status["progress"] = 100
                scan_status["message"] = f"扫描完成：发现{result['alive']}个在线资产"
        except Exception as e:
            scan_status["message"] = f"扫描出错: {str(e)}"
            scan_status["progress"] = 100
            db_manager.update_scan_task(task_id, status="失败", result_summary=str(e))
        finally:
            time.sleep(3)
            scan_status["running"] = False
            scan_status["stop_requested"] = False

    t = threading.Thread(target=scan_thread, daemon=True)
    t.start()

    return jsonify({"success": True, "message": "资产扫描已启动", "task_id": task_id})


@app.route("/api/scan/vuln", methods=["POST"])
@login_required
def api_scan_vuln():
    """启动漏洞扫描"""
    global scan_status
    if scan_status["running"]:
        return jsonify({"success": False, "message": "已有扫描任务正在执行，请等待完成"})

    data = request.get_json()
    target = data.get("target", "")

    task_id = db_manager.create_scan_task(
        f"漏洞扫描-{target or '全部资产'}", target or "全部", "漏洞扫描")

    def scan_thread():
        global scan_status
        scan_status = {"running": True, "type": "漏洞扫描", "progress": 0,
                       "message": "正在初始化...", "task_id": task_id, "stop_requested": False}
        try:
            def progress_cb(progress, message):
                scan_status["progress"] = progress
                scan_status["message"] = message

            def stop_check():
                return scan_status.get("stop_requested", False)

            result = vuln_scanner.run_vuln_scan(target or None, task_id=task_id,
                                                 callback=progress_cb, stop_check=stop_check)
            if scan_status.get("stop_requested"):
                scan_status["message"] = f"漏洞扫描已手动停止：已发现{result['vulns_found']}个新漏洞"
                db_manager.update_scan_task(task_id, status="已停止",
                    result_summary=f"手动停止，已发现{result['vulns_found']}个新漏洞")
            else:
                scan_status["message"] = f"漏洞扫描完成：发现{result['vulns_found']}个新漏洞"
        except Exception as e:
            scan_status["message"] = f"扫描出错: {str(e)}"
            db_manager.update_scan_task(task_id, status="失败", result_summary=str(e))
        finally:
            time.sleep(2)
            scan_status["running"] = False
            scan_status["stop_requested"] = False

    t = threading.Thread(target=scan_thread, daemon=True)
    t.start()

    return jsonify({"success": True, "message": "漏洞扫描已启动", "task_id": task_id})


@app.route("/api/scan/status")
@login_required
def api_scan_status():
    """获取扫描状态"""
    return jsonify(scan_status)


@app.route("/api/scan/stop", methods=["POST"])
@login_required
def api_scan_stop():
    """停止当前扫描任务"""
    if not scan_status["running"]:
        return jsonify({"success": False, "message": "当前没有正在执行的扫描任务"})
    scan_status["stop_requested"] = True
    scan_status["message"] = "正在停止扫描..."
    return jsonify({"success": True, "message": "已发送停止信号，扫描将在完成当前批次后停止"})


@app.route("/api/stats")
@login_required
def api_stats():
    """获取统计数据"""
    return jsonify(db_manager.get_dashboard_stats())


@app.route("/api/assets")
@login_required
def api_assets():
    """获取资产列表"""
    return jsonify(db_manager.get_all_assets())


@app.route("/api/assets/<int:asset_id>/ports")
@login_required
def api_asset_ports(asset_id):
    """获取资产端口"""
    return jsonify(db_manager.get_ports_by_asset(asset_id))


@app.route("/api/assets/delete", methods=["POST"])
@login_required
@admin_required
def api_assets_delete():
    """删除资产（支持单个和批量）"""
    data = request.get_json() or {}
    asset_id = data.get("asset_id")
    asset_ids = data.get("asset_ids", [])

    if asset_id:
        # 单个删除
        success, message = db_manager.delete_asset(asset_id)
        return jsonify({"success": success, "message": message})
    elif asset_ids:
        # 批量删除
        count, message = db_manager.delete_assets_batch(asset_ids)
        return jsonify({"success": count > 0, "message": message, "deleted": count})
    else:
        return jsonify({"success": False, "message": "请选择要删除的资产"})


@app.route("/api/vulns")
@login_required
def api_vulns():
    """获取漏洞列表"""
    level = request.args.get("level")
    return jsonify(db_manager.get_vulnerabilities(level=level))


@app.route("/api/vulns/<int:vuln_id>/status", methods=["POST"])
@login_required
def api_update_vuln_status(vuln_id):
    """更新漏洞状态"""
    data = request.get_json()
    status = data.get("status", "未修复")
    db_manager.update_vuln_status(vuln_id, status)
    return jsonify({"success": True})


@app.route("/api/changes")
@login_required
def api_changes():
    """获取资产变化记录"""
    return jsonify(db_manager.get_asset_changes())


@app.route("/api/tasks")
@login_required
def api_tasks():
    """获取扫描任务列表"""
    return jsonify(db_manager.get_scan_tasks())


# ==================== 漏洞库管理API ====================

@app.route("/api/vulndb/info")
@login_required
def api_vulndb_info():
    """获取漏洞库信息"""
    return jsonify(vuln_db_manager.get_db_info())


@app.route("/api/vulndb/rules")
@login_required
def api_vulndb_rules():
    """获取所有漏洞规则"""
    return jsonify(vuln_db_manager.load_rules())


@app.route("/api/vulndb/add", methods=["POST"])
@login_required
def api_vulndb_add():
    """添加漏洞规则"""
    data = request.get_json()
    try:
        vuln_db_manager.add_rule(
            name=data["name"],
            port=int(data["port"]),
            level=data["level"],
            desc=data["desc"],
            solution=data.get("solution", ""),
            cve=data.get("cve", ""),
            cnvd=data.get("cnvd", "")
        )
        return jsonify({"success": True, "message": "规则添加成功"})
    except Exception as e:
        return jsonify({"success": False, "message": f"添加失败: {str(e)}"})


@app.route("/api/vulndb/delete", methods=["POST"])
@login_required
def api_vulndb_delete():
    """删除漏洞规则"""
    data = request.get_json()
    if vuln_db_manager.delete_rule(data["name"]):
        return jsonify({"success": True, "message": "规则已删除"})
    return jsonify({"success": False, "message": "规则不存在"})


@app.route("/api/vulndb/toggle", methods=["POST"])
@login_required
def api_vulndb_toggle():
    """启用/禁用漏洞规则"""
    data = request.get_json()
    if vuln_db_manager.toggle_rule(data["name"], data.get("enabled", True)):
        return jsonify({"success": True, "message": "规则状态已更新"})
    return jsonify({"success": False, "message": "规则不存在"})


@app.route("/api/vulndb/export")
@login_required
def api_vulndb_export():
    """导出漏洞规则"""
    text = vuln_db_manager.export_rules_text()
    return jsonify({"success": True, "content": text})


@app.route("/api/vulndb/import", methods=["POST"])
@login_required
def api_vulndb_import():
    """导入漏洞规则"""
    data = request.get_json()
    content = data.get("content", "")
    count = vuln_db_manager.import_from_text(content)
    return jsonify({"success": True, "message": f"成功导入 {count} 条规则"})


# ==================== 报告API ====================

@app.route("/api/report/generate", methods=["POST"])
@login_required
def api_generate_report():
    """生成报告"""
    try:
        report_path = report_generator.generate_html_report()
        return jsonify({"success": True, "message": "报告生成成功", "path": report_path})
    except Exception as e:
        return jsonify({"success": False, "message": f"报告生成失败: {str(e)}"})


@app.route("/api/report/download")
@login_required
def api_download_report():
    """下载报告"""
    report_path = os.path.join(config.REPORT_DIR, "scan_report.html")
    if os.path.exists(report_path):
        return send_file(report_path, as_attachment=True, download_name="安全扫描报告.html")
    return jsonify({"success": False, "message": "报告不存在，请先生成"}), 404


# ==================== CSV导出API ====================

@app.route("/api/export/assets")
@login_required
def api_export_assets():
    """导出资产为CSV"""
    import csv
    import io
    from flask import Response

    assets = db_manager.get_all_assets()
    output = io.StringIO()
    output.write('\ufeff')  # BOM头，Excel中文兼容
    writer = csv.writer(output)
    writer.writerow(["序号", "IP地址", "主机名", "操作系统", "状态", "首次发现", "最后发现"])

    for i, a in enumerate(assets, 1):
        writer.writerow([i, a["ip"], a.get("hostname", ""), a.get("os_guess", ""),
                        a["status"], a["first_seen"], a["last_seen"]])

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename=assets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"}
    )


@app.route("/api/export/vulns")
@login_required
def api_export_vulns():
    """导出漏洞为CSV"""
    import csv
    import io
    from flask import Response

    level = request.args.get("level")
    vulns = db_manager.get_vulnerabilities(level=level)

    output = io.StringIO()
    output.write('\ufeff')
    writer = csv.writer(output)
    writer.writerow(["序号", "IP地址", "漏洞名称", "等级", "描述", "修复建议", "CVE", "CNVD", "状态", "发现时间"])

    for i, v in enumerate(vulns, 1):
        writer.writerow([i, v.get("ip", ""), v["vuln_name"], v["vuln_level"],
                        v.get("vuln_desc", ""), v.get("vuln_solution", ""),
                        v.get("vuln_cve", ""), v.get("vuln_cnvd", ""),
                        v.get("status", ""), v.get("scan_time", "")])

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename=vulns_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"}
    )


# ==================== CNVD爬虫API ====================

@app.route("/api/vulndb/cnvd/crawl", methods=["POST"])
@login_required
def api_cnvd_crawl():
    """爬取CNVD最新漏洞"""
    data = request.get_json() or {}
    pages = data.get("pages", 2)

    def crawl_thread():
        global scan_status
        scan_status = {"running": True, "type": "CNVD爬取", "progress": 0,
                       "message": f"正在爬取CNVD漏洞库（{pages}页）...", "task_id": None}
        try:
            from scanner.cnvd_crawler import crawl_and_format
            rules, stats = crawl_and_format(pages=pages)
            scan_status["progress"] = 80

            if stats.get("total", 0) == 0:
                # 爬取失败或无数据
                scan_status["message"] = stats.get("message", "爬取失败，未获取到数据")
                scan_status["progress"] = 100
                scan_status["result"] = stats
                scan_status["success"] = False
            else:
                scan_status["message"] = f"爬取完成，发现{stats.get('total',0)}条漏洞"

                # 保存为待审核文件
                import json
                pending_path = os.path.join(config.BASE_DIR, "vuln_db", "cnvd_pending.json")
                with open(pending_path, "w", encoding="utf-8") as f:
                    json.dump({"rules": rules, "stats": stats}, f, ensure_ascii=False, indent=2)

                scan_status["progress"] = 100
                scan_status["message"] = f"爬取完成！{stats.get('total',0)}条漏洞已保存待审核"
                scan_status["result"] = stats
                scan_status["success"] = True
        except Exception as e:
            scan_status["message"] = f"爬取失败: {str(e)}"
            scan_status["success"] = False
        finally:
            time.sleep(3)
            scan_status["running"] = False

    t = threading.Thread(target=crawl_thread, daemon=True)
    t.start()
    return jsonify({"success": True, "message": f"开始爬取CNVD漏洞库（{pages}页）"})


@app.route("/api/vulndb/cnvd/pending")
@login_required
def api_cnvd_pending():
    """获取待审核的CNVD漏洞"""
    pending_path = os.path.join(config.BASE_DIR, "vuln_db", "cnvd_pending.json")
    if os.path.exists(pending_path):
        with open(pending_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return jsonify(data)
    return jsonify({"rules": {}, "stats": {}})


@app.route("/api/vulndb/cnvd/import", methods=["POST"])
@login_required
def api_cnvd_import():
    """导入审核后的CNVD漏洞规则"""
    data = request.get_json() or {}
    selected = data.get("selected", [])  # 选中的规则名列表

    pending_path = os.path.join(config.BASE_DIR, "vuln_db", "cnvd_pending.json")
    if not os.path.exists(pending_path):
        return jsonify({"success": False, "message": "无待审核数据"})

    with open(pending_path, "r", encoding="utf-8") as f:
        pending = json.load(f)

    rules = pending.get("rules", {})
    imported = 0

    # 如果没有指定选中的，则导入全部
    to_import = selected if selected else list(rules.keys())

    for name in to_import:
        if name in rules:
            rules[name]["enabled"] = True  # 导入时启用
            vuln_db_manager.add_rule(
                name=name,
                port=rules[name]["port"],
                level=rules[name]["level"],
                desc=rules[name]["desc"],
                solution=rules[name]["solution"],
                cve=rules[name].get("cve", ""),
                cnvd=rules[name].get("cnvd", "")
            )
            imported += 1

    return jsonify({"success": True, "message": f"成功导入 {imported} 条CNVD漏洞规则"})


# ==================== 公开漏洞库API（OSV + GitHub） ====================

@app.route("/api/vulndb/osv/categories")
@login_required
def api_osv_categories():
    """获取OSV支持的生态系统"""
    from scanner.public_vuln_db import ECOSYSTEM_MAP
    return jsonify({"success": True, "categories": list(ECOSYSTEM_MAP.keys()),
                    "details": {k: len(v) for k, v in ECOSYSTEM_MAP.items()}})


@app.route("/api/vulndb/osv/query", methods=["POST"])
@login_required
def api_osv_query():
    """按关键词查询OSV"""
    data = request.get_json() or {}
    keyword = data.get("keyword", "")
    if not keyword:
        return jsonify({"success": False, "message": "请输入搜索关键词"})

    def query_thread():
        global scan_status
        scan_status = {"running": True, "type": "OSV查询", "progress": 0,
                       "message": f"正在查询OSV: {keyword}...", "task_id": None, "success": None}
        try:
            from scanner.public_vuln_db import query_osv_package, osv_to_scan_rule
            vulns = query_osv_package(keyword)
            rules = {}
            for v in vulns:
                rule = osv_to_scan_rule(v)
                rules[rule["name"]] = {
                    "port": rule["port"], "level": rule["level"],
                    "desc": rule["desc"], "solution": rule["solution"],
                    "cve": rule["cve"], "cnvd": rule["cnvd"],
                    "enabled": False, "source": "OSV",
                }

            pending_path = os.path.join(config.BASE_DIR, "vuln_db", "osv_pending.json")
            with open(pending_path, "w", encoding="utf-8") as f:
                json.dump({"rules": rules, "keyword": keyword,
                           "total": len(rules),
                           "crawl_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
                          f, ensure_ascii=False, indent=2)

            scan_status["message"] = f"OSV查询完成: {keyword}，发现 {len(rules)} 个漏洞"
            scan_status["progress"] = 100
            scan_status["success"] = True
        except Exception as e:
            scan_status["message"] = f"OSV查询失败: {str(e)}"
            scan_status["success"] = False
        finally:
            time.sleep(2)
            scan_status["running"] = False

    t = threading.Thread(target=query_thread, daemon=True)
    t.start()
    return jsonify({"success": True, "message": f"开始查询OSV: {keyword}"})


@app.route("/api/vulndb/osv/batch", methods=["POST"])
@login_required
def api_osv_batch():
    """批量查询OSV常见组件"""
    data = request.get_json() or {}
    ecosystem = data.get("ecosystem", "PyPI")
    max_count = data.get("max_count", 30)

    def batch_thread():
        global scan_status
        scan_status = {"running": True, "type": "OSV批量查询", "progress": 0,
                       "message": f"正在查询 {ecosystem} 生态系统漏洞...", "task_id": None, "success": None}
        try:
            from scanner.public_vuln_db import fetch_osv_batch
            rules, stats = fetch_osv_batch(ecosystem=ecosystem, max_count=max_count)

            pending_path = os.path.join(config.BASE_DIR, "vuln_db", "osv_pending.json")
            with open(pending_path, "w", encoding="utf-8") as f:
                json.dump({"rules": rules, "stats": stats}, f, ensure_ascii=False, indent=2)

            scan_status["message"] = f"OSV查询完成: {stats.get('total', 0)} 个漏洞"
            scan_status["progress"] = 100
            scan_status["success"] = True
        except Exception as e:
            scan_status["message"] = f"OSV查询失败: {str(e)}"
            scan_status["success"] = False
        finally:
            time.sleep(2)
            scan_status["running"] = False

    t = threading.Thread(target=batch_thread, daemon=True)
    t.start()
    return jsonify({"success": True, "message": f"开始查询 {ecosystem} 生态系统漏洞"})


@app.route("/api/vulndb/osv/pending")
@login_required
def api_osv_pending():
    """获取待审核的OSV漏洞"""
    pending_path = os.path.join(config.BASE_DIR, "vuln_db", "osv_pending.json")
    if os.path.exists(pending_path):
        with open(pending_path, "r", encoding="utf-8") as f:
            return jsonify(json.load(f))
    return jsonify({"rules": {}, "stats": {}})


@app.route("/api/vulndb/github/query", methods=["POST"])
@login_required
def api_github_query():
    """查询GitHub Advisory"""
    data = request.get_json() or {}
    severity = data.get("severity", "")
    ecosystem = data.get("ecosystem", "")
    max_count = data.get("max_count", 30)

    def gh_thread():
        global scan_status
        scan_status = {"running": True, "type": "GitHub查询", "progress": 0,
                       "message": "正在查询GitHub安全公告...", "task_id": None, "success": None}
        try:
            from scanner.public_vuln_db import fetch_github_batch
            rules, stats = fetch_github_batch(severity=severity or None,
                                              ecosystem=ecosystem or None,
                                              max_count=max_count)

            pending_path = os.path.join(config.BASE_DIR, "vuln_db", "github_pending.json")
            with open(pending_path, "w", encoding="utf-8") as f:
                json.dump({"rules": rules, "stats": stats}, f, ensure_ascii=False, indent=2)

            scan_status["message"] = f"GitHub查询完成: {stats.get('total', 0)} 个安全公告"
            scan_status["progress"] = 100
            scan_status["success"] = True
        except Exception as e:
            scan_status["message"] = f"GitHub查询失败: {str(e)}"
            scan_status["success"] = False
        finally:
            time.sleep(2)
            scan_status["running"] = False

    t = threading.Thread(target=gh_thread, daemon=True)
    t.start()
    return jsonify({"success": True, "message": "开始查询GitHub安全公告"})


@app.route("/api/vulndb/github/pending")
@login_required
def api_github_pending():
    """获取待审核的GitHub漏洞"""
    pending_path = os.path.join(config.BASE_DIR, "vuln_db", "github_pending.json")
    if os.path.exists(pending_path):
        with open(pending_path, "r", encoding="utf-8") as f:
            return jsonify(json.load(f))
    return jsonify({"rules": {}, "stats": {}})


@app.route("/api/vulndb/import/pending", methods=["POST"])
@login_required
def api_import_pending():
    """导入待审核的漏洞规则（OSV/GitHub共用）"""
    data = request.get_json() or {}
    source = data.get("source", "osv")  # osv 或 github
    selected = data.get("selected", [])

    pending_file = f"{source}_pending.json"
    pending_path = os.path.join(config.BASE_DIR, "vuln_db", pending_file)
    if not os.path.exists(pending_path):
        return jsonify({"success": False, "message": "无待审核数据"})

    with open(pending_path, "r", encoding="utf-8") as f:
        pending = json.load(f)

    rules = pending.get("rules", {})
    to_import = selected if selected else list(rules.keys())
    imported = 0

    for name in to_import:
        if name in rules:
            vuln_db_manager.add_rule(
                name=name,
                port=rules[name].get("port", 80),
                level=rules[name].get("level", "中危"),
                desc=rules[name].get("desc", ""),
                solution=rules[name].get("solution", ""),
                cve=rules[name].get("cve", ""),
                cnvd=rules[name].get("cnvd", "")
            )
            imported += 1

    return jsonify({"success": True, "message": f"成功导入 {imported} 条漏洞规则"})


# ==================== 文件导入API ====================

@app.route("/api/vulndb/import/file", methods=["POST"])
@login_required
def api_vulndb_import_file():
    """从上传的CSV/JSON文件导入漏洞规则"""
    import csv
    import io

    if "file" not in request.files:
        return jsonify({"success": False, "message": "未上传文件"})

    file = request.files["file"]
    filename = file.filename.lower()
    content = file.read().decode("utf-8-sig")  # utf-8-sig 兼容BOM头

    try:
        if filename.endswith(".json"):
            data = json.loads(content)
            rules_data = data.get("rules", data) if isinstance(data, dict) else data
            count = 0
            for name, rule in rules_data.items() if isinstance(rules_data, dict) else []:
                if isinstance(rule, dict) and "port" in rule:
                    vuln_db_manager.add_rule(
                        name=name, port=int(rule["port"]),
                        level=rule.get("level", "中危"),
                        desc=rule.get("desc", ""),
                        solution=rule.get("solution", ""),
                        cve=rule.get("cve", ""),
                        cnvd=rule.get("cnvd", "")
                    )
                    count += 1
            return jsonify({"success": True, "message": f"从JSON文件导入 {count} 条规则"})

        elif filename.endswith(".csv"):
            reader = csv.DictReader(io.StringIO(content))
            count = 0
            for row in reader:
                name = row.get("规则名") or row.get("name") or row.get("规则名称", "")
                port = row.get("端口") or row.get("port", "80")
                if name and port:
                    vuln_db_manager.add_rule(
                        name=name, port=int(port),
                        level=row.get("等级") or row.get("level", "中危"),
                        desc=row.get("描述") or row.get("desc", ""),
                        solution=row.get("修复建议") or row.get("solution", ""),
                        cve=row.get("CVE") or row.get("cve", ""),
                        cnvd=row.get("CNVD") or row.get("cnvd", "")
                    )
                    count += 1
            return jsonify({"success": True, "message": f"从CSV文件导入 {count} 条规则"})

        else:
            return jsonify({"success": False, "message": "不支持的文件格式，请上传 .csv 或 .json 文件"})

    except Exception as e:
        return jsonify({"success": False, "message": f"导入失败: {str(e)}"})


# ==================== 常见漏洞模板API ====================

VULN_TEMPLATES = {
    "Web服务漏洞": {
        "Apache路径遍历(CVE-2021-41773)": {"port": 80, "level": "严重", "desc": "Apache HTTP Server 2.4.49路径遍历漏洞，可读取任意文件", "solution": "升级Apache至2.4.51或更高版本", "cve": "CVE-2021-41773"},
        "Nginx越界读取(CVE-2017-7529)": {"port": 80, "level": "高危", "desc": "Nginx range filter模块整数溢出漏洞", "solution": "升级Nginx至最新稳定版", "cve": "CVE-2017-7529"},
        "Tomcat弱口令": {"port": 8080, "level": "高危", "desc": "Tomcat管理后台使用默认弱口令tomcat/tomcat", "solution": "修改默认密码，限制管理后台访问IP"},
        "IIS短文件名泄露": {"port": 80, "level": "中危", "desc": "IIS短文件名枚举漏洞，可探测后台路径", "solution": "禁用NTFS 8.3短文件名功能"},
        "WebLogic反序列化(CVE-2023-21839)": {"port": 7001, "level": "严重", "desc": "WebLogic T3/IIOP反序列化远程代码执行", "solution": "安装最新补丁或禁用T3协议", "cve": "CVE-2023-21839"},
    },
    "数据库漏洞": {
        "MySQL弱口令": {"port": 3306, "level": "严重", "desc": "MySQL数据库使用弱密码或空密码", "solution": "设置强密码，限制远程访问"},
        "Redis未授权访问": {"port": 6379, "level": "严重", "desc": "Redis未设置密码认证，可远程执行命令", "solution": "设置requirepass，绑定内网IP", "cve": "CVE-2022-0543"},
        "MongoDB未授权访问": {"port": 27017, "level": "严重", "desc": "MongoDB未开启认证，数据可被直接访问", "solution": "开启auth认证，限制访问IP"},
        "PostgreSQL弱口令": {"port": 5432, "level": "高危", "desc": "PostgreSQL使用默认或弱密码", "solution": "设置强密码，配置pg_hba.conf限制访问"},
        "Elasticsearch未授权访问": {"port": 9200, "level": "严重", "desc": "Elasticsearch未配置认证，可远程访问所有索引", "solution": "启用X-Pack安全功能或配置Nginx代理认证"},
    },
    "远程服务漏洞": {
        "SSH弱口令": {"port": 22, "level": "严重", "desc": "SSH服务使用弱密码，可能被暴力破解", "solution": "使用密钥登录，禁用密码认证"},
        "RDP弱口令(CVE-2019-0708)": {"port": 3389, "level": "严重", "desc": "远程桌面服务存在BlueKeep漏洞或弱口令", "solution": "安装补丁，启用NLA，设置强密码", "cve": "CVE-2019-0708"},
        "SMB漏洞(MS17-010)": {"port": 445, "level": "严重", "desc": "Windows SMB远程代码执行漏洞(永恒之蓝)", "solution": "安装MS17-010补丁，关闭SMBv1", "cve": "CVE-2017-0144"},
        "FTP匿名登录": {"port": 21, "level": "高危", "desc": "FTP服务允许匿名登录", "solution": "禁用匿名访问，使用SFTP替代"},
        "Telnet明文传输": {"port": 23, "level": "高危", "desc": "Telnet协议明文传输凭据", "solution": "使用SSH替代Telnet"},
    },
    "常见组件漏洞": {
        "Log4j2远程代码执行(CVE-2021-44228)": {"port": 8080, "level": "严重", "desc": "Apache Log4j2 JNDI注入漏洞(Log4Shell)", "solution": "升级Log4j至2.17.0或更高版本", "cve": "CVE-2021-44228"},
        "Fastjson反序列化": {"port": 8080, "level": "严重", "desc": "Fastjson反序列化远程代码执行漏洞", "solution": "升级Fastjson至最新安全版本", "cve": "CVE-2022-25845"},
        "Spring4Shell(CVE-2022-22965)": {"port": 8080, "level": "严重", "desc": "Spring Framework远程代码执行漏洞", "solution": "升级Spring Framework至5.3.18+或5.2.20+", "cve": "CVE-2022-22965"},
        "Struts2命令执行(S2-045)": {"port": 8080, "level": "严重", "desc": "Apache Struts2 Jakarta Multipart解析器RCE", "solution": "升级Struts至2.3.32+或2.5.10.1+", "cve": "CVE-2017-5638"},
        "Docker未授权访问": {"port": 2375, "level": "严重", "desc": "Docker Remote API未认证，可接管宿主机", "solution": "启用TLS认证，限制API访问"},
        "Kubernetes API未授权": {"port": 6443, "level": "严重", "desc": "Kubernetes API Server未正确配置认证", "solution": "启用RBAC，配置TLS客户端证书认证"},
    }
}


@app.route("/api/vulndb/templates")
@login_required
def api_vulndb_templates():
    """获取漏洞模板列表"""
    result = {}
    for category, rules in VULN_TEMPLATES.items():
        result[category] = len(rules)
    return jsonify({"success": True, "templates": result, "categories": list(VULN_TEMPLATES.keys())})


@app.route("/api/vulndb/templates/<category>")
@login_required
def api_vulndb_template_detail(category):
    """获取模板详情"""
    if category in VULN_TEMPLATES:
        return jsonify({"success": True, "rules": VULN_TEMPLATES[category]})
    return jsonify({"success": False, "message": "模板不存在"})


@app.route("/api/vulndb/import/template", methods=["POST"])
@login_required
def api_vulndb_import_template():
    """导入漏洞模板"""
    data = request.get_json() or {}
    category = data.get("category", "")

    if category == "all":
        # 导入全部模板
        count = 0
        for cat_rules in VULN_TEMPLATES.values():
            for name, rule in cat_rules.items():
                vuln_db_manager.add_rule(
                    name=name, port=rule["port"], level=rule["level"],
                    desc=rule["desc"], solution=rule.get("solution", ""),
                    cve=rule.get("cve", ""), cnvd=rule.get("cnvd", "")
                )
                count += 1
        return jsonify({"success": True, "message": f"已导入全部 {count} 条模板规则"})
    elif category in VULN_TEMPLATES:
        rules = VULN_TEMPLATES[category]
        for name, rule in rules.items():
            vuln_db_manager.add_rule(
                name=name, port=rule["port"], level=rule["level"],
                desc=rule["desc"], solution=rule.get("solution", ""),
                cve=rule.get("cve", ""), cnvd=rule.get("cnvd", "")
            )
        return jsonify({"success": True, "message": f"已导入 [{category}] {len(rules)} 条模板规则"})
    return jsonify({"success": False, "message": "模板不存在"})


# ==================== 定时扫描API ====================

@app.route("/scheduled")
@login_required
@admin_required
def scheduled_page():
    """定时扫描页面"""
    tasks = db_manager.get_scheduled_tasks()
    return render_template("scheduled.html", tasks=tasks)


@app.route("/api/scheduled/list")
@login_required
def api_scheduled_list():
    """获取定时扫描任务列表"""
    return jsonify(db_manager.get_scheduled_tasks())


@app.route("/api/scheduled/add", methods=["POST"])
@login_required
@admin_required
def api_scheduled_add():
    """添加定时扫描任务"""
    data = request.get_json() or {}
    name = data.get("name", "").strip()
    target = data.get("target", "").strip()
    scan_type = data.get("scan_type", "资产扫描")
    scan_mode = data.get("scan_mode", "快速")
    cron_expression = data.get("cron_expression", "").strip()

    if not name or not target or not cron_expression:
        return jsonify({"success": False, "message": "请填写完整的任务信息"})

    # 验证 cron 表达式格式
    parts = cron_expression.split()
    if len(parts) != 5:
        return jsonify({"success": False, "message": "Cron表达式格式错误，应为: 分 时 日 月 周"})

    try:
        # 验证 cron 表达式是否合法
        CronTrigger(
            minute=parts[0], hour=parts[1],
            day=parts[2], month=parts[3], day_of_week=parts[4]
        )
    except Exception as e:
        return jsonify({"success": False, "message": f"无效的Cron表达式: {str(e)}"})

    task_id = db_manager.create_scheduled_task(
        name=name, target=target, scan_type=scan_type,
        scan_mode=scan_mode, cron_expression=cron_expression,
        created_by=session.get("username", ""))

    # 同步到调度器
    sync_scheduled_tasks()

    return jsonify({"success": True, "message": f"定时任务 [{name}] 创建成功", "task_id": task_id})


@app.route("/api/scheduled/delete", methods=["POST"])
@login_required
@admin_required
def api_scheduled_delete():
    """删除定时扫描任务"""
    data = request.get_json() or {}
    task_id = data.get("task_id")
    if not task_id:
        return jsonify({"success": False, "message": "缺少任务ID"})

    db_manager.delete_scheduled_task(task_id)
    sync_scheduled_tasks()
    return jsonify({"success": True, "message": "定时任务已删除"})


@app.route("/api/scheduled/toggle", methods=["POST"])
@login_required
@admin_required
def api_scheduled_toggle():
    """启用/禁用定时扫描任务"""
    data = request.get_json() or {}
    task_id = data.get("task_id")
    is_active = data.get("is_active", True)
    if not task_id:
        return jsonify({"success": False, "message": "缺少任务ID"})

    db_manager.toggle_scheduled_task(task_id, is_active)
    sync_scheduled_tasks()
    return jsonify({"success": True, "message": f"定时任务已{'启用' if is_active else '禁用'}"})


@app.route("/api/scheduled/run", methods=["POST"])
@login_required
@admin_required
def api_scheduled_run():
    """立即执行一次定时扫描任务"""
    global scan_status
    if scan_status["running"]:
        return jsonify({"success": False, "message": "已有扫描任务正在执行，请等待完成"})

    data = request.get_json() or {}
    task_id = data.get("task_id")
    if not task_id:
        return jsonify({"success": False, "message": "缺少任务ID"})

    # 在后台线程中执行
    t = threading.Thread(target=run_scheduled_scan, args=[task_id], daemon=True)
    t.start()

    return jsonify({"success": True, "message": "已触发立即执行"})


# ==================== 启动 ====================

if __name__ == "__main__":
    init_app()

    ssl_context = None
    if config.USE_HTTPS:
        # 检查证书是否存在
        if os.path.exists(config.SSL_CERT) and os.path.exists(config.SSL_KEY):
            ssl_context = (config.SSL_CERT, config.SSL_KEY)
            protocol = "HTTPS"
        else:
            print("[SSL] 证书不存在，正在生成...")
            from gen_cert import generate_cert
            if generate_cert():
                ssl_context = (config.SSL_CERT, config.SSL_KEY)
                protocol = "HTTPS"
            else:
                print("[SSL] 证书生成失败，降级为HTTP")
                protocol = "HTTP"
    else:
        protocol = "HTTP"

    print(f"[服务] {protocol} 服务启动于: {protocol.lower()}://localhost:{config.WEB_PORT}")
    app.run(host=config.WEB_HOST, port=config.WEB_PORT, debug=False, threaded=True,
            ssl_context=ssl_context)

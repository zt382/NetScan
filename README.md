# NetScan
# 网络安全资产扫描系统

> 全中文界面 | 零外部依赖扫描引擎 | 可移植部署 | 支持2000+目标并发扫描

## 一、项目简介

网络安全资产扫描系统是一套轻量级的网络安全资产管理平台，基于纯 Python Socket 实现端口扫描和服务识别，无需依赖 Nmap 等外部工具。系统提供 Web 管理界面，支持资产发现、端口扫描、漏洞检测、报告生成等完整工作流。

## 二、核心功能

| 功能模块 | 说明 |
|---------|------|
| **资产发现** | TCP Connect 存活探测，支持 CIDR、IP 范围、多目标格式 |
| **端口扫描** | 快速(115端口) / 中速(1000+端口) / 全端口(65535) 三种模式 |
| **服务识别** | 基于 Banner 抓取的服务版本识别 |
| **操作系统识别** | 多维度指纹匹配（SSH/HTTP/SMB/NetBIOS/端口组合），支持国产信创系统 |
| **漏洞检测** | 规则库匹配 + 深度验证（FTP匿名/Redis未授权/HTTP安全头/SSL证书） |
| **资产监控** | 自动记录资产新增/离线变化 |
| **定时扫描** | Cron 表达式配置定时任务 |
| **安全报告** | 一键生成 HTML 格式安全报告 |
| **多用户** | 角色权限管理（管理员/普通用户） |

## 三、系统架构

```
NetScan/
├── app.py                  # Flask 主应用（路由、定时任务、用户管理）
├── config.py               # 全局配置（端口、线程、路径）
├── gen_cert.py             # SSL 证书生成工具
├── 启动.bat                # Windows 一键启动脚本
│
├── database/
│   └── db_manager.py       # SQLite 数据库管理（资产/端口/漏洞/任务）
│
├── scanner/
│   ├── asset_scanner.py    # 资产扫描引擎（存活探测、端口扫描、服务识别）
│   ├── vuln_scanner.py     # 漏洞扫描引擎（规则匹配 + 深度检测）
│   ├── os_detect.py        # 操作系统识别模块
│   ├── vuln_db_manager.py  # 漏洞规则库管理
│   ├── cnvd_crawler.py     # CNVD 漏洞爬虫（可选）
│   └── public_vuln_db.py   # 公共漏洞库接口（可选）
│
├── report/
│   └── report_generator.py # HTML 报告生成器
│
├── templates/              # Jinja2 HTML 模板
├── static/                 # 静态资源（CSS/JS/图标）
├── vuln_db/                # 漏洞规则库（JSON）
├── certs/                  # SSL 证书
├── data/                   # SQLite 数据库文件
├── reports/                # 生成的报告文件
└── docs/                   # 项目文档
```

## 四、技术栈

| 组件 | 技术 |
|------|------|
| 后端框架 | Flask 3.x |
| 数据库 | SQLite 3（Python 内置） |
| 定时任务 | APScheduler 3.x |
| 扫描引擎 | 纯 Python Socket（零外部依赖） |
| 前端 | Bootstrap 5 + Jinja2 模板 |
| 图表 | Plotly.js |

## 五、快速启动

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 启动服务
python app.py

# 3. 访问系统
# https://localhost:20260
# 默认账号：admin / admin123
```

## 六、许可证

仅供内部安全评估使用，请勿用于非法用途。


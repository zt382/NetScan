# 网络安全资产扫描系统

> **零外部依赖** | **全中文界面** | **纯Python Socket扫描** | **可移植部署**

基于纯Python实现的内网资产发现与漏洞管理系统，无需安装nmap、masscan等外部工具。

## 快速启动

```bash
# Windows
双击 启动.bat

# Linux / 命令行
pip install -r requirements.txt
python app.py
```

访问: https://localhost:20260 | 默认账号: `admin` / `admin123`

## 📖 文档

| 文档 | 说明 |
|------|------|
| [项目说明](docs/README.md) | 功能特性、系统架构、技术栈 |
| [操作手册](docs/操作手册.md) | 各功能使用指南、常见问题 |
| [移植部署文档](docs/移植部署文档.md) | 服务器配置、依赖版本、部署方式、数据备份 |

## 系统要求

- Python 3.8+（推荐 3.10~3.14）
- 依赖：Flask 3.x + APScheduler 3.x + SQLite3
- 详细要求见 [移植部署文档](docs/移植部署文档.md)

## 注意事项

1. **扫描授权**：请确保已获得目标网络的扫描授权
2. **防火墙**：服务器需能访问目标网段
3. **扫描时间**：建议在业务低峰期执行大规模扫描

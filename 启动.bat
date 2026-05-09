@echo off
chcp 65001 >nul
echo ============================================
echo   网络安全资产扫描系统 - 启动脚本
echo ============================================
echo.

:: 检查Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [错误] 未检测到Python，请先安装Python 3.10+
    pause
    exit /b 1
)

:: 安装依赖
echo [1/3] 检查依赖...
pip install -r requirements.txt -q

:: 生成SSL证书
echo [2/3] 检查SSL证书...
if not exist "certs\cert.pem" (
    echo   正在生成自签名SSL证书...
    python gen_cert.py
)

:: 启动服务
echo [3/3] 启动服务...
echo.
echo   HTTPS访问地址: https://localhost:20260
echo   首次访问浏览器会提示"不安全"，点击"高级"-"继续访问"即可
echo   按 Ctrl+C 停止服务
echo.
python app.py
pause

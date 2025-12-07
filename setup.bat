@echo off
title Network Monitor - Setup & Launch
color 0A

echo.
echo ========================================================
echo    Network Change Detector ^& Anomaly Monitor
echo    Blue Team Security Tool - One-Click Setup
echo ========================================================
echo.

:: Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH!
    echo.
    echo Please install Python from: https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

echo [+] Python found!
python --version
echo.

:: Check if Nmap is installed
where nmap >nul 2>&1
if %errorlevel% neq 0 (
    :: Check common installation paths
    if exist "C:\Program Files (x86)\Nmap\nmap.exe" (
        echo [+] Nmap found in Program Files ^(x86^)
    ) else if exist "C:\Program Files\Nmap\nmap.exe" (
        echo [+] Nmap found in Program Files
    ) else (
        echo [WARNING] Nmap not found. Some features may not work.
        echo.
        echo To enable network scanning, install Nmap from:
        echo https://nmap.org/download.html
        echo.
        echo You can still use Demo Mode without Nmap!
        echo.
    )
) else (
    echo [+] Nmap found!
)

echo.
echo [*] Installing Python dependencies...
echo.
pip install -r requirements.txt --quiet

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Failed to install dependencies!
    echo Please run manually: pip install -r requirements.txt
    pause
    exit /b 1
)

echo.
echo [+] Dependencies installed successfully!
echo.
echo ========================================================
echo    Starting Dashboard...
echo    Opening browser at: http://localhost:8501
echo ========================================================
echo.
echo Press Ctrl+C to stop the server.
echo.

:: Start the Streamlit dashboard
streamlit run app.py --server.headless true

pause

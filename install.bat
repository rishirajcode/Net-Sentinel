@echo off
setlocal enabledelayedexpansion

echo ====================================================================
echo         Net Sentinel - Network Monitoring by Software Vantage
echo ====================================================================
echo.
echo [1/4] Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in your system PATH!
    echo Please install Python 3.10 or newer from https://www.python.org/
    echo Make sure to check "Add Python to PATH" during installation.
    pause
    exit /b 1
)

for /f "tokens=*" %%i in ('python --version') do set PYTHON_VER=%%i
echo [OK] Detected %PYTHON_VER%

echo.
echo [2/4] Setting up Python virtual environment...
if not exist "venv" (
    echo Creating virtual environment in .\venv ...
    python -m venv venv
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
)
echo [OK] Virtual environment ready.

echo.
echo [3/4] Installing dependencies from requirements.txt...
call .\venv\Scripts\activate.bat
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install requirements. Please check your internet connection.
    pause
    exit /b 1
)
echo [OK] Dependencies installed successfully.

echo.
echo [4/4] Checking Network Discovery tools...
where nmap >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] Nmap detected on this system.
) else (
    echo [NOTE] Nmap is not currently installed or not in PATH.
    echo Net Sentinel will use high-speed native Windows ARP and ICMP discovery.
    echo (Optional) To enable deep OS fingerprinting, download Nmap from https://nmap.org/download.html
)

echo.
echo Initializing database...
python -c "from app.database import init_db; init_db(); print('Database initialized.')"

echo.
echo ====================================================================
echo Installation Complete!
echo You can now launch Net Sentinel by double-clicking 'start.bat'
echo ====================================================================
pause

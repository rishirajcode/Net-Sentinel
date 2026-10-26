@echo off
setlocal

echo ====================================================================
echo         Net Sentinel - Starting Dashboard Server
echo         by Software Vantage
echo ====================================================================
echo.

if not exist "venv\Scripts\activate.bat" (
    echo [ERROR] Virtual environment not found. Please run install.bat first!
    pause
    exit /b 1
)

call .\venv\Scripts\activate.bat

echo Starting local web server on http://127.0.0.1:8000 ...
echo Press Ctrl+C in this window to stop the server.
echo.

:: Open default browser after 2 seconds
start "" /B cmd /c "timeout /t 2 >nul & start http://127.0.0.1:8000"

:: Start Uvicorn web server using the virtual environment Python
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000

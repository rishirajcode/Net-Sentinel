@echo off
setlocal

echo Stopping Net Sentinel server running on port 8000...

for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8000" ^| findstr "LISTENING"') do (
    echo Terminating process PID %%a ...
    taskkill /f /pid %%a >nul 2>&1
)

echo Net Sentinel stopped cleanly.
pause

@echo off
setlocal
cd /d "%~dp0"

:: Check for Administrator privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator privileges to configure firewall, power settings, and autostart...
    powershell -Command "Start-Process cmd -ArgumentList '/c \"\"%~f0\"\"' -Verb RunAs"
    exit /b
)

:: Run setup.ps1 with execution policy bypass
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup.ps1"

if %errorlevel% neq 0 (
    echo.
    echo An error occurred during setup. Please inspect setup-diagnostics.log.
    pause
)

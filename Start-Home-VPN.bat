@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

set "PYTHON_EXE="

:: 1. Check LocalAppData for Python 3.12 / 3.11 / 3.10
for /d %%D in ("%LOCALAPPDATA%\Programs\Python\Python3*") do (
    if exist "%%D\python.exe" (
        set "PYTHON_EXE=%%D\python.exe"
        goto :RunPortal
    )
)

:: 2. Check Program Files
for /d %%D in ("%ProgramFiles%\Python3*") do (
    if exist "%%D\python.exe" (
        set "PYTHON_EXE=%%D\python.exe"
        goto :RunPortal
    )
)

:: 3. Check py launcher
where py.exe >nul 2>nul
if %errorlevel% equ 0 (
    set "PYTHON_EXE=py -3"
    goto :RunPortal
)

:: 4. Fallback to system path python
where python.exe >nul 2>nul
if %errorlevel% equ 0 (
    set "PYTHON_EXE=python"
    goto :RunPortal
)

set "PYTHON_EXE=python"

:RunPortal
if "%PYTHON_EXE:~0,3%"=="py " (
    %PYTHON_EXE% portal.py
) else (
    "%PYTHON_EXE%" portal.py
)

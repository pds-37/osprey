@echo off
title Osprey — Supply Chain Attack Path Control Plane
echo =====================================================================
echo  [Osprey] Supply Chain Attack Path Control Plane (v2.0)
echo  One-Command Plug-and-Play Launcher
echo =====================================================================
echo.

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python 3.10+ is required but was not found in your PATH.
    pause
    exit /b 1
)

echo [*] Starting Osprey interactive control plane...
python cli.py ui
pause

@echo off
:: Shellockolm - Windows Quick Setup
:: Double-click this file to install everything

echo.
echo ========================================
echo   Shellockolm - Quick Setup
echo ========================================
echo.

:: Check if running as admin (optional, but good practice)
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Running with administrator privileges...
) else (
    echo Note: Not running as administrator
    echo Some features may require elevated privileges
    echo.
)

:: Run PowerShell installer
powershell -ExecutionPolicy Bypass -File "%~dp0install.ps1"

:: Keep window open if there was an error
if %errorLevel% neq 0 (
    echo.
    echo Installation failed. Press any key to exit...
    pause >nul
)

@echo off
REM Guardian Antivirus - Install Dependencies
REM Run this file first to set up Guardian Antivirus

cd /d "%~dp0"

echo ====================================
echo Guardian Antivirus - Setup
echo ====================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8+ from https://python.org
    echo Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

echo Python found:
python --version
echo.

echo Installing dependencies...
echo.

pip install --upgrade pip
pip install -r requirements.txt

echo.
echo ====================================
echo Setup Complete!
echo ====================================
echo.
echo To start Guardian Antivirus:
echo   1. Double-click Guardian.bat
echo   OR
echo   2. Run: python main.py
echo.
echo To start minimized to tray:
echo   Run: python main.py --minimized
echo.
pause

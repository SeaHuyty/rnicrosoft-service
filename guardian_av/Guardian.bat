@echo off
REM Someth Antivirus Launcher
REM Run this file to start Someth Antivirus

cd /d "%~dp0"

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo Python is not installed or not in PATH
    echo Please install Python 3.8+ from https://python.org
    pause
    exit /b 1
)

REM Check if dependencies are installed
python -c "import PyQt5" >nul 2>&1
if errorlevel 1 (
    echo Installing dependencies...
    pip install -r requirements.txt
)

REM Run Someth Antivirus
echo Starting Someth Antivirus...
pythonw main.py %*

exit /b 0

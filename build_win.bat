@echo off
title Build check.exe for Windows
echo =======================================================
echo              BUILDING CHECK.EXE FOR WINDOWS
echo =======================================================
echo.

:: Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH.
    echo Please install Python first (https://www.python.org/downloads/)
    echo and make sure to check "Add Python to PATH" during setup.
    echo.
    pause
    exit /b 1
)

:: Install PyInstaller
echo [*] Installing/Updating PyInstaller...
pip install --upgrade pyinstaller
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install PyInstaller using pip.
    echo.
    pause
    exit /b 1
)

:: Compile check.py
echo [*] Compiling check.py into a single check.exe file...
pyinstaller --onefile --console check.py
if %errorlevel% neq 0 (
    echo [ERROR] PyInstaller compilation failed.
    echo.
    pause
    exit /b 1
)

echo.
echo =======================================================
echo [✓] SUCCESS! check.exe has been created.
echo You can find it inside the "dist" folder:
echo.
echo      dist\check.exe
echo.
echo You can share dist\check.exe with anyone on Windows.
echo =======================================================
echo.
pause

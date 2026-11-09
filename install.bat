@echo off
setlocal enabledelayedexpansion

echo =====================================================================
echo   REA-Neural Automated Windows Installer
echo   Continuous Semantic Reverse Engineering & Binary Analysis
echo =====================================================================
echo.

:: 1. Check Python existence
where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    where py >nul 2>nul
    if %ERRORLEVEL% neq 0 (
        echo [ERROR] Python is not found on your system PATH!
        echo Please install Python 3.10 or higher from https://www.python.org/
        echo Make sure to check "Add Python to PATH" during installation.
        pause
        exit /b 1
    ) else (
        set "PY_CMD=py -3"
    )
) else (
    set "PY_CMD=python"
)

echo [*] Detected Python launcher: %PY_CMD%

:: 2. Verify Python version >= 3.10
%PY_CMD% -c "import sys; exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Python version must be 3.10 or higher.
    %PY_CMD% --version
    pause
    exit /b 1
)

:: 3. Install runtime dependencies and REA-Neural
echo [*] Installing dependencies and registering REA-Neural package...
%PY_CMD% -m pip install --upgrade pip >nul 2>nul
%PY_CMD% -m pip install -e "%~dp0."
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Package installation failed. Check network or permissions.
    pause
    exit /b 1
)

:: 4. Verify CLI executable existence in PATH
echo.
echo [*] Verifying command line availability...
where rea-neural >nul 2>nul
if %ERRORLEVEL% neq 0 (
    for /f "tokens=*" %%i in ('%PY_CMD% -c "import sysconfig; print(sysconfig.get_path('scripts'))"') do set "SCRIPTS_DIR=%%i"
    echo [WARNING] 'rea-neural' is installed in:
    echo           !SCRIPTS_DIR!
    echo           However, this directory is not in your system PATH yet.
    echo.
    echo [*] You can run the PowerShell installer (install.ps1) to add it automatically,
    echo     or add it manually to your User Environment Variables.
) else (
    echo [OK] 'rea-neural' command is directly accessible in your PATH!
)

:: 5. Smoke Test
echo.
echo [*] Running smoke test on 10-Sense Sensory Cortex...
%PY_CMD% -m cli sense --hex "90 90" >nul 2>nul
if %ERRORLEVEL% equ 0 (
    echo [OK] Sensory Cortex and Security Kernel passed smoke test!
) else (
    echo [WARNING] Smoke test returned exit code %ERRORLEVEL%.
)

echo.
echo =====================================================================
echo   Installation Complete!
echo =====================================================================
echo   Available commands:
echo     rea-neural --help     Unified Reverse Engineering CLI
echo     rea-mcp               JSON-RPC 2.0 stdio Model Context Protocol
echo.
echo   For Claude Desktop or Cursor MCP setup, see the MCP section in README.md.
echo =====================================================================
echo.
pause

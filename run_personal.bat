@echo off
setlocal

if "%~1"=="" (
    echo Right-click a configuration file, then Send to, netblur ^(secrets and personal data^).
    echo You can also drag one or more files onto this file.
    echo Original files are never modified.
    pause
    exit /b 1
)

where py >nul 2>nul
if %errorlevel%==0 (
    py "%~dp0netblur.py" --personal %*
) else (
    python "%~dp0netblur.py" --personal %*
)

echo.
echo Read the result and any flagged lines above.
echo The PERSONAL-DATA-MAP file contains real data: keep it on this PC, never share it.
pause

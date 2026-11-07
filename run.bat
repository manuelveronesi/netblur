@echo off
setlocal

if "%~1"=="" (
    echo Right-click a configuration file, then Send to, netblur ^(secrets only^).
    echo You can also drag one or more files onto this file.
    echo Original files are never modified.
    pause
    exit /b 1
)

where py >nul 2>nul
if %errorlevel%==0 (
    py "%~dp0netblur.py" %*
) else (
    python "%~dp0netblur.py" %*
)

echo.
echo Read the result and any flagged lines above.
pause

@echo off
REM ============================================================
REM  wifi-sentry :: double-click launcher
REM  Opens the desktop UI. No install, no dependencies.
REM ============================================================
title wifi-sentry
cd /d "%~dp0"

REM Prefer the Windows Python launcher, fall back to python on PATH.
where py >nul 2>nul && (set "PY=py") || (set "PY=python")

echo.
echo   Starting wifi-sentry ...
echo   (this console window can be minimised; close it to quit)
echo.

%PY% -m wifisentry gui
if errorlevel 1 (
    echo.
    echo   Could not start. Is Python 3.10+ installed and on PATH?
    echo   Try running:  python --version
    echo.
    pause
)

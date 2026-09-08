@echo off
title PhishScan Setup
cd /d "%~dp0"
echo.
echo  PhishScan Setup
echo  ---------------
echo  Dipli klik = egkatastasi ston ypologisti sas.
echo  Den xreiazetai administrator.
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0installer\Install-PhishScan.ps1"
if errorlevel 1 (
  echo.
  echo H egkatastasi apetyche.
  pause
  exit /b 1
)
echo.
pause

@echo off
setlocal
cd /d "%~dp0"

where py >nul 2>&1
if %errorlevel%==0 (
  py -3 -c "import tkinter" 2>nul
  if %errorlevel%==0 goto :shortcut
)
where python >nul 2>&1
if %errorlevel%==0 (
  python -c "import tkinter" 2>nul
  if %errorlevel%==0 goto :shortcut
)

echo.
echo Den vrethike Python 3 me tkinter.
echo Katevaste to apo https://www.python.org/downloads/
echo Sto installer tsekarate: Add python.exe to PATH
echo.
pause
exit /b 1

:shortcut
set "TARGET=%~dp0PhishScan.bat"
set "DESKTOP=%USERPROFILE%\Desktop"
if not exist "%DESKTOP%" set "DESKTOP=%USERPROFILE%\OneDrive\Desktop"
powershell -NoProfile -Command ^
  "$s=(New-Object -ComObject WScript.Shell).CreateShortcut('%DESKTOP%\PhishScan.lnk'); $s.TargetPath='%~dp0PhishScan.bat'; $s.WorkingDirectory='%~dp0'; $s.Description='Topikos elegxos phishing syndesmon'; $s.Save()"
echo.
echo OK. Syntomesi "PhishScan" stin epifaneia ergasias.
echo Dipli klik ekei, i sto PhishScan.bat.
echo.
pause

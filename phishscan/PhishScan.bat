@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>&1
if %errorlevel%==0 (
  py -3 phishscan.py --gui
  goto :eof
)
where python >nul 2>&1
if %errorlevel%==0 (
  python phishscan.py --gui
  goto :eof
)
echo.
echo Den vrethike Python 3.
echo Katevaste to apo https://www.python.org/downloads/
echo kai tsekarate "Add python.exe to PATH".
echo.
pause

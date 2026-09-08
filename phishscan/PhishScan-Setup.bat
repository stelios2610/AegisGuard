@echo off
setlocal EnableExtensions
title PhishScan Setup
cd /d "%~dp0"

echo.
echo  PhishScan Setup
echo  ---------------
echo.

if not exist "%~dp0phishscan.py" (
  echo Den vrethike to phishscan.py se auton ton fakelo.
  echo Trexte to PhishScan-Setup.bat APO MESA apo ton fakelo phishscan.
  echo.
  pause
  exit /b 1
)

REM Corporate PCs often strip .ps1 from zip. The installer is this .bat file.
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$root = [IO.Path]::GetFullPath('%~dp0'); $lines = Get-Content -LiteralPath '%~f0'; $i = 0; while ($i -lt $lines.Count -and $lines[$i].Trim() -ne ':PS') { $i++ }; if ($i -ge $lines.Count) { throw 'Installer payload missing' }; $script = ($lines[($i+1)..($lines.Count-1)] -join [Environment]::NewLine); $tmp = Join-Path $env:TEMP 'phishscan-setup.ps1'; Set-Content -LiteralPath $tmp -Value $script -Encoding UTF8; & $tmp -Root $root; $code = $LASTEXITCODE; if ($null -eq $code) { $code = 0 }; exit $code"

if errorlevel 1 (
  echo.
  echo H egkatastasi apetyche.
  echo Enallaktika dipli klik sto PhishScan.bat gia na trexei xoris egkatastasi.
  echo.
)
pause
exit /b %ERRORLEVEL%

:PS
param([string]$Root)
$ErrorActionPreference = "Stop"
$Root = [IO.Path]::GetFullPath($Root)
$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\PhishScan"
$StartMenu = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\PhishScan"
$UninstallKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\PhishScan"

function Write-Step($msg) { Write-Host " * $msg" }

function Find-Python {
    foreach ($cmd in @(
            @{ File = "py"; Args = @("-3") },
            @{ File = "python"; Args = @() },
            @{ File = "python3"; Args = @() }
        )) {
        $p = Get-Command $cmd.File -ErrorAction SilentlyContinue
        if (-not $p) { continue }
        try {
            $ver = & $p.Source @($cmd.Args + @("-c", "import sys,tkinter; print(sys.executable)")) 2>$null
            if ($LASTEXITCODE -eq 0 -and $ver) { return $ver.Trim() }
        } catch { }
    }
    return $null
}

Write-Host "Egkatastasi PhishScan"
Write-Host ""

$py = Find-Python
if (-not $py) {
    Write-Step "Python den vrethike. Prospatheia winget..."
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget) {
        & winget install -e --id Python.Python.3.12 --scope user --accept-package-agreements --accept-source-agreements
        $env:Path = [Environment]::GetEnvironmentVariable("Path", "User") + ";" + [Environment]::GetEnvironmentVariable("Path", "Machine")
        $py = Find-Python
    }
}
if (-not $py) {
    Write-Host "Egkatasteste Python 3 apo https://www.python.org/downloads/"
    Write-Host "TSEKARATE: Add python.exe to PATH  kai xanatrexte to Setup."
    exit 1
}
Write-Step "Python: $py"

Write-Step "Antigrafi se $InstallDir"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
foreach ($f in @("phishscan.py", "analyzer.py", "gui.py", "README.md")) {
    $src = Join-Path $Root $f
    if (Test-Path -LiteralPath $src) { Copy-Item -LiteralPath $src (Join-Path $InstallDir $f) -Force }
}

$launch = @"
@echo off
cd /d "%~dp0"
"$py" "%~dp0phishscan.py" --gui
if errorlevel 1 pause
"@
Set-Content -Path (Join-Path $InstallDir "PhishScan.bat") -Value $launch -Encoding ASCII

$uninst = @"
@echo off
rd /s /q "%LOCALAPPDATA%\Programs\PhishScan"
del /q "%USERPROFILE%\Desktop\PhishScan.lnk" 2>nul
rd /s /q "%APPDATA%\Microsoft\Windows\Start Menu\Programs\PhishScan"
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\PhishScan" /f
echo PhishScan apegkatastathike.
pause
"@
Set-Content -Path (Join-Path $InstallDir "Uninstall.bat") -Value $uninst -Encoding ASCII

function New-Shortcut($path, $target) {
    $w = New-Object -ComObject WScript.Shell
    $s = $w.CreateShortcut($path)
    $s.TargetPath = $target
    $s.WorkingDirectory = $InstallDir
    $s.Description = "PhishScan"
    $s.Save()
}

Write-Step "Syntomeseis"
New-Item -ItemType Directory -Force -Path $StartMenu | Out-Null
$desktop = [Environment]::GetFolderPath("Desktop")
New-Shortcut (Join-Path $desktop "PhishScan.lnk") (Join-Path $InstallDir "PhishScan.bat")
New-Shortcut (Join-Path $StartMenu "PhishScan.lnk") (Join-Path $InstallDir "PhishScan.bat")
New-Shortcut (Join-Path $StartMenu "Apegkatastasi PhishScan.lnk") (Join-Path $InstallDir "Uninstall.bat")

Write-Step "Programs and Features"
New-Item -Path $UninstallKey -Force | Out-Null
New-ItemProperty -Path $UninstallKey -Name "DisplayName" -Value "PhishScan" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $UninstallKey -Name "Publisher" -Value "PhishScan" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $UninstallKey -Name "DisplayVersion" -Value "1.0.1" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $UninstallKey -Name "InstallLocation" -Value $InstallDir -PropertyType String -Force | Out-Null
New-ItemProperty -Path $UninstallKey -Name "UninstallString" -Value (Join-Path $InstallDir "Uninstall.bat") -PropertyType String -Force | Out-Null
New-ItemProperty -Path $UninstallKey -Name "NoModify" -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $UninstallKey -Name "NoRepair" -Value 1 -PropertyType DWord -Force | Out-Null

Write-Host ""
Write-Host "Egine. Anoixte to PhishScan apo tin epifaneia ergasias."
Write-Host ""
exit 0

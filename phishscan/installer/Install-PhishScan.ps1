# PhishScan Windows installer. Run via PhishScan-Setup.bat (no admin needed).
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$AppName = "PhishScan"
$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\PhishScan"
$StartMenu = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\PhishScan"
$UninstallKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\PhishScan"
$Root = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path (Join-Path $Root "phishscan.py"))) {
    $Root = $PSScriptRoot
}

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
            if ($LASTEXITCODE -eq 0 -and $ver) { return @{ Exe = $ver.Trim(); Launcher = $p.Source; Args = $cmd.Args } }
        } catch { }
    }
    return $null
}

function Install-PythonIfNeeded {
    $py = Find-Python
    if ($py) { Write-Step "Python OK: $($py.Exe)"; return $py }
    Write-Step "Python 3 + tkinter den vrethike. Prospatheia ekatastasis (winget)..."
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget) {
        & winget install -e --id Python.Python.3.12 --scope user --accept-package-agreements --accept-source-agreements
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "User") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "Machine")
        $py = Find-Python
        if ($py) { return $py }
    }
    Write-Host ""
    Write-Host "Egkatasteste Python 3 apo https://www.python.org/downloads/"
    Write-Host "Sto installer TSEKARATE: Add python.exe to PATH"
    Write-Host "Meta xanatrexte to PhishScan-Setup.bat"
    Write-Host ""
    exit 1
}

function New-Shortcut($path, $target, $workdir, $desc) {
    $w = New-Object -ComObject WScript.Shell
    $s = $w.CreateShortcut($path)
    $s.TargetPath = $target
    $s.WorkingDirectory = $workdir
    $s.Description = $desc
    $s.Save()
}

Write-Host ""
Write-Host "===================================="
Write-Host "  PhishScan  -  egkatastasi"
Write-Host "===================================="
Write-Host ""

$py = Install-PythonIfNeeded

Write-Step "Antigrafi arxeion se $InstallDir"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$files = @("phishscan.py", "analyzer.py", "gui.py", "README.md", "PhishScan.bat")
foreach ($f in $files) {
    $src = Join-Path $Root $f
    if (Test-Path $src) {
        Copy-Item $src (Join-Path $InstallDir $f) -Force
    }
}

$launch = @"
@echo off
setlocal
cd /d "%~dp0"
"$($py.Exe)" "%~dp0phishscan.py" --gui
if errorlevel 1 pause
"@
Set-Content -Path (Join-Path $InstallDir "PhishScan.bat") -Value $launch -Encoding ASCII

$uninstallBat = @"
@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Uninstall-PhishScan.ps1"
"@
Set-Content -Path (Join-Path $InstallDir "Uninstall.bat") -Value $uninstallBat -Encoding ASCII
Copy-Item (Join-Path $PSScriptRoot "Uninstall-PhishScan.ps1") (Join-Path $InstallDir "Uninstall-PhishScan.ps1") -Force

Write-Step "Syntomeseis (Desktop + Start Menu)"
New-Item -ItemType Directory -Force -Path $StartMenu | Out-Null
$desktop = [Environment]::GetFolderPath("Desktop")
New-Shortcut (Join-Path $desktop "$AppName.lnk") (Join-Path $InstallDir "PhishScan.bat") $InstallDir "Topikos elegxos phishing syndesmon"
New-Shortcut (Join-Path $StartMenu "$AppName.lnk") (Join-Path $InstallDir "PhishScan.bat") $InstallDir "Topikos elegxos phishing syndesmon"
New-Shortcut (Join-Path $StartMenu "Apegkatastasi PhishScan.lnk") (Join-Path $InstallDir "Uninstall.bat") $InstallDir "Apegkatastasi PhishScan"

Write-Step "Eggrafi sto Programs and Features"
New-Item -Path $UninstallKey -Force | Out-Null
New-ItemProperty -Path $UninstallKey -Name "DisplayName" -Value "PhishScan" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $UninstallKey -Name "Publisher" -Value "PhishScan" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $UninstallKey -Name "DisplayVersion" -Value "1.0.0" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $UninstallKey -Name "InstallLocation" -Value $InstallDir -PropertyType String -Force | Out-Null
New-ItemProperty -Path $UninstallKey -Name "UninstallString" -Value "`"$(Join-Path $InstallDir 'Uninstall.bat')`"" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $UninstallKey -Name "NoModify" -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $UninstallKey -Name "NoRepair" -Value 1 -PropertyType DWord -Force | Out-Null

Write-Host ""
Write-Host "Egine. PhishScan: $InstallDir"
Write-Host "Anoixte to apo tin epifaneia ergasias i to Start Menu."
Write-Host ""

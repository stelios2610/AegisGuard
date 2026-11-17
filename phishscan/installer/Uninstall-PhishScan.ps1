# Removes PhishScan from this user account.
$ErrorActionPreference = "SilentlyContinue"
$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\PhishScan"
$StartMenu = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\PhishScan"
$UninstallKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\PhishScan"
$desktop = [Environment]::GetFolderPath("Desktop")

Remove-Item (Join-Path $desktop "PhishScan.lnk") -Force
Remove-Item $StartMenu -Recurse -Force
Remove-Item $UninstallKey -Recurse -Force
Remove-Item $InstallDir -Recurse -Force

Write-Host "PhishScan apegkatastathike."
Start-Sleep -Seconds 2

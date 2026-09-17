@echo off
rem Launches Get-StorageHogs.ps1 with the execution policy bypassed for this run only.
rem Nothing on the system is changed. Right-click > Run as administrator for full coverage.
setlocal
set "PS=powershell.exe"
where pwsh.exe >nul 2>&1 && set "PS=pwsh.exe"
"%PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Get-StorageHogs.ps1" -Interactive %*
echo.
pause

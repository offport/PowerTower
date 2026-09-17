@echo off
rem Launches Find-DeletedFiles.ps1 elevated with the execution policy bypassed for this run only.
setlocal
set "PS=powershell.exe"
where pwsh.exe >nul 2>&1 && set "PS=pwsh.exe"
"%PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Find-DeletedFiles.ps1" -Interactive %*
echo.
pause

@echo off
rem Launches Watch-Connections.ps1 with the execution policy bypassed for this run only.
rem Right-click > Run as administrator to see owning processes for system services.
setlocal
set "PS=powershell.exe"
"%PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Watch-Connections.ps1" -Interactive %*
echo.
pause

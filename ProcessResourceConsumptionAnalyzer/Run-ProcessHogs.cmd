@echo off
rem Launches Watch-ProcessHogs.ps1 with the execution policy bypassed for this run only.
rem Nothing on the system is changed. Right-click > Run as administrator to see every process.
setlocal
set "PS=powershell.exe"
where pwsh.exe >nul 2>&1 && set "PS=pwsh.exe"
"%PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Watch-ProcessHogs.ps1" -Interactive %*
echo.
pause

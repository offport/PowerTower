@echo off
rem Block-Hosts launcher. Right-click > Run as administrator.
rem Drag a .txt/.csv onto this file to block the hosts in it.
setlocal
set "PS=powershell.exe"
if "%~1"=="" (
  "%PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Block-Hosts.ps1" -Interactive
) else (
  "%PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Block-Hosts.ps1" -Action add -Path "%~1" -Interactive
)
echo.
pause

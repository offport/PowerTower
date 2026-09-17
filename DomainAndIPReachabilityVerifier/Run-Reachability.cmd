@echo off
rem Launches Test-Reachability.ps1 with the execution policy bypassed for this run only.
rem Tip: drag a .txt or .csv onto this .cmd to test it directly.
setlocal
set "PS=powershell.exe"
where pwsh.exe >nul 2>&1 && set "PS=pwsh.exe"
if "%~1"=="" (
  "%PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Test-Reachability.ps1" -Interactive
) else (
  "%PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Test-Reachability.ps1" -Path "%~1" -Interactive
)
echo.
pause

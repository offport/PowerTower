@echo off
rem Builds PowerTower.exe (the app) and Tests.exe (the engine tests) with the C# compiler that ships
rem inside Windows (.NET Framework 4.x). Nothing to install. Run after changing any .cs file.
setlocal
set "CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" set "CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not exist "%CSC%" ( echo csc.exe not found - .NET Framework 4.x is required. & exit /b 1 )
cd /d "%~dp0"
set "REFS=/r:System.dll /r:System.Core.dll /r:System.Windows.Forms.dll /r:System.Drawing.dll /r:Microsoft.CSharp.dll /r:System.Management.dll /r:Microsoft.VisualBasic.dll"
"%CSC%" /nologo /codepage:65001 /target:winexe /optimize+ /out:PowerTower.exe /win32manifest:app.manifest %REFS% Program.cs Ui.cs Panels.cs VulnPanel.cs ReconPanel.cs FilesPanel.cs ChecklistPanel.cs MapPanel.cs SoftwarePanel.cs Net.cs Sys.cs Vuln.cs Recon.cs Files.cs Checklist.cs Trust.cs Autoruns.cs Events.cs Secrets.cs Dupes.cs Firewall.cs Creds.cs Sqlite.cs Browser.cs BrowserCreds.cs Geo.cs BrowserPanel.cs NetMapPanel.cs ConnSidebar.cs AutorunsPanel.cs EventsPanel.cs SecretsPanel.cs DupesPanel.cs FirewallPanel.cs CredsPanel.cs AboutPanel.cs ModuleViewer.cs
if errorlevel 1 ( echo app build failed & exit /b 1 )
echo built PowerTower.exe
"%CSC%" /nologo /codepage:65001 /target:exe /optimize+ /out:Tests.exe /r:System.dll /r:System.Core.dll /r:Microsoft.CSharp.dll /r:System.Management.dll Tests.cs Net.cs Sys.cs Vuln.cs Recon.cs Files.cs Checklist.cs Trust.cs Autoruns.cs Events.cs Secrets.cs Dupes.cs Firewall.cs Creds.cs Sqlite.cs Browser.cs BrowserCreds.cs
if errorlevel 1 ( echo tests build failed & exit /b 1 )
echo built Tests.exe

@echo off
rem Builds PowerTower.exe (the desktop app), PowerTowerCli.exe (the same tools on the command line) and
rem Tests.exe (the engine tests) with the C# compiler that ships inside Windows (.NET Framework 4.x).
rem Nothing to install. Run after changing any .cs file.
setlocal
set "CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" set "CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not exist "%CSC%" ( echo csc.exe not found - .NET Framework 4.x is required. & exit /b 1 )
cd /d "%~dp0"
rem the engines and the shared, UI-free view kit (columns, filters, CSV, settings, the tool registry) - every exe gets these
set "SHARED=Table.cs Columns.cs Net.cs Sys.cs Vuln.cs Recon.cs Files.cs Checklist.cs Trust.cs Autoruns.cs Events.cs Secrets.cs Dupes.cs Firewall.cs Creds.cs Sqlite.cs Browser.cs BrowserCreds.cs Geo.cs Bundle.cs Collect.cs Enrich.cs FeedPack.cs EngagementTool.cs Report.cs HostsWrite.cs FirewallWrite.cs FileCrypto.cs ActiveTests.cs AutorunsWrite.cs"
set "REFS=/r:System.dll /r:System.Core.dll /r:Microsoft.CSharp.dll /r:System.Management.dll /r:Microsoft.VisualBasic.dll /r:System.Security.dll"

"%CSC%" /nologo /codepage:65001 /target:winexe /optimize+ /out:PowerTower.exe /win32manifest:app.manifest %REFS% /r:System.Windows.Forms.dll /r:System.Drawing.dll Program.cs Ui.cs Panels.cs VulnPanel.cs ReconPanel.cs FilesPanel.cs ChecklistPanel.cs MapPanel.cs SoftwarePanel.cs BrowserPanel.cs NetMapPanel.cs ConnSidebar.cs AutorunsPanel.cs EventsPanel.cs SecretsPanel.cs DupesPanel.cs FirewallPanel.cs CredsPanel.cs AboutPanel.cs ModuleViewer.cs Common.cs RemoteAudit.cs RemoteAuditSupport.cs RemoteTransport.cs %SHARED%
if errorlevel 1 ( echo app build failed & exit /b 1 )
echo built PowerTower.exe

"%CSC%" /nologo /codepage:65001 /target:exe /optimize+ /out:PowerTowerCli.exe %REFS% Cli.cs CliTools.cs Repl.cs RemoteAudit.cs RemoteAuditSupport.cs RemoteTransport.cs %SHARED%
if errorlevel 1 ( echo cli build failed & exit /b 1 )
echo built PowerTowerCli.exe

rem the collector: the read-only engines only. The mutating halves live in HostsWrite.cs FirewallWrite.cs FileCrypto.cs ActiveTests.cs
rem AutorunsWrite.cs and are not compiled in, nor are credentials, browser data, duplicates/recycle, Sqlite or geo. Tests.exe proves it by reflection.
"%CSC%" /nologo /codepage:65001 /target:exe /optimize+ /out:PowerTowerCollect.exe %REFS% CollectMain.cs Collect.cs Bundle.cs Enrich.cs Table.cs Net.cs Sys.cs Vuln.cs Recon.cs Files.cs Checklist.cs Trust.cs Autoruns.cs Events.cs Secrets.cs Firewall.cs
if errorlevel 1 ( echo collector build failed & exit /b 1 )
echo built PowerTowerCollect.exe

"%CSC%" /nologo /codepage:65001 /target:exe /optimize+ /out:Tests.exe %REFS% Tests.cs RemoteAudit.cs RemoteAuditSupport.cs %SHARED%
if errorlevel 1 ( echo tests build failed & exit /b 1 )
echo built Tests.exe

#Requires -Version 5.1
<#
.SYNOPSIS
    Get-StorageHogs — find what is eating your disks, visually, from the terminal.

.DESCRIPTION
    Run with no arguments and you get an interactive menu: pick drives, pick a
    scan profile, optionally exclude paths or export a CSV. Run with arguments
    and it skips the menu entirely (good for scheduled or scripted use).

    The report shows drive usage bars, the largest files and folders, space by
    category, and a CLEANUP section listing known junk locations MEASURED on this
    machine, each tagged SAFE / REVIEW / KEEP with the exact command to reclaim it.

    This script only READS. It never deletes anything.

.PARAMETER Drive        Drive letters to scan, e.g. -Drive C,D. Default: all fixed drives.
.PARAMETER Top          Largest files to show. Default 25.
.PARAMETER TopFolders   Largest folders to show. Default 15.
.PARAMETER MinSizeMB    Ignore files smaller than this for the top-files list. Default 50.
.PARAMETER FolderDepth  Roll folder sizes up to this many levels below the root. Default 3.
.PARAMETER Exclude      Path prefixes to skip, e.g. -Exclude 'D:\Backups'.
.PARAMETER NoColor      Plain output.
.PARAMETER ExportCsv    Also write the top-files list to this CSV path.
.PARAMETER Interactive  Force the menu even when other arguments are given.

.EXAMPLE
    .\Get-StorageHogs.ps1                         # interactive menu
    .\Get-StorageHogs.ps1 -Drive C -Top 40        # no menu
    .\Get-StorageHogs.ps1 -Exclude 'D:\Archive' -ExportCsv .\hogs.csv

.NOTES
    If Windows refuses to run it ("not digitally signed"), either:
        Unblock-File .\Get-StorageHogs.ps1
    or double-click the companion Run-StorageHogs.cmd, which bypasses the
    execution policy for this one run without changing any system setting.
#>
[CmdletBinding()]
param(
    [string[]]$Drive,
    [int]$Top = 25,
    [int]$TopFolders = 15,
    [int]$MinSizeMB = 50,
    [int]$FolderDepth = 3,
    [string[]]$Exclude = @(),
    [switch]$NoColor,
    [string]$ExportCsv,
    [switch]$Interactive
)

# ═══════════════════════════════ rendering ═══════════════════════════════

$script:Esc = [char]27
$script:UseColor = (-not $NoColor) -and ($Host.UI.SupportsVirtualTerminal -or $env:WT_SESSION -or $PSVersionTable.PSVersion.Major -ge 7)

function C {
    param([string]$Name, [string]$Text)
    if (-not $script:UseColor) { return $Text }
    $map = @{
        teal  = "$Esc[38;2;47;217;197m";  amber = "$Esc[38;2;240;165;60m"; rose = "$Esc[38;2;255;107;94m"
        dim   = "$Esc[38;2;95;128;146m";  faint = "$Esc[38;2;60;87;102m";  ink  = "$Esc[38;2;214;233;240m"
        bold  = "$Esc[1m"
    }
    return "$($map[$Name])$Text$Esc[0m"
}

function Format-Size {
    param([double]$Bytes)
    if ($Bytes -ge 1TB) { return ('{0,7:N2} TB' -f ($Bytes / 1TB)) }
    if ($Bytes -ge 1GB) { return ('{0,7:N2} GB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0,7:N1} MB' -f ($Bytes / 1MB)) }
    if ($Bytes -ge 1KB) { return ('{0,7:N0} KB' -f ($Bytes / 1KB)) }
    return ('{0,7:N0}  B' -f $Bytes)
}

function Bar {
    param([double]$Fraction, [int]$Width = 24, [string]$Color = 'teal')
    if ($Fraction -lt 0) { $Fraction = 0 }; if ($Fraction -gt 1) { $Fraction = 1 }
    $filled = [int][math]::Round($Fraction * $Width)
    return (C $Color ('█' * $filled)) + (C faint ('░' * ($Width - $filled)))
}

function Truncate-Path {
    param([string]$Path, [int]$Max)
    if ($Max -lt 12) { $Max = 12 }
    if ($Path.Length -le $Max) { return $Path }
    $keep = [int](($Max - 3) / 2)
    return $Path.Substring(0, $keep) + '...' + $Path.Substring($Path.Length - ($Max - 3 - $keep))
}

function Get-Width {
    try { $w = $Host.UI.RawUI.WindowSize.Width } catch { $w = 0 }
    if (-not $w -or $w -lt 40) { $w = 120 }
    return [math]::Max(80, [math]::Min(140, $w - 2))
}

function Section {
    param([string]$Title, [string]$Tag = '')
    $w = Get-Width
    $line = '─' * [math]::Max(4, ($w - $Title.Length - 6))
    Write-Host ''
    Write-Host ('  ' + (C teal '┌─ ') + (C bold (C ink $Title)) + ' ' + (C faint $line) + (C dim $Tag))
}

function Age-Label {
    param([datetime]$Date)
    $days = ((Get-Date) - $Date).TotalDays
    if ($days -lt 1)   { return 'today' }
    if ($days -lt 30)  { return ('{0}d' -f [int]$days) }
    if ($days -lt 365) { return ('{0}mo' -f [int]($days / 30)) }
    return ('{0}y' -f [math]::Round($days / 365, 1))
}

function Ask {
    # Ask 'prompt' 'default'  → string (default if blank)
    param([string]$Prompt, [string]$Default = '')
    $suffix = if ($Default -ne '') { (C dim " [$Default]") } else { '' }
    Write-Host ('  ' + (C teal '?') + ' ' + (C ink $Prompt) + $suffix + ' ') -NoNewline
    $r = Read-Host
    if ([string]::IsNullOrWhiteSpace($r)) { return $Default }
    return $r.Trim()
}

# ═══════════════════════════════ categories ═══════════════════════════════

$script:CategoryMap = @{}
$cats = @{
    'Video'        = 'mp4 mkv avi mov wmv m4v webm ts flv mts m2ts'
    'Audio'        = 'mp3 flac wav m4a aac ogg wma aiff'
    'Images'       = 'jpg jpeg png heic gif bmp tif tiff raw cr2 nef arw dng psd webp'
    'Archives'     = 'zip rar 7z tar gz bz2 xz zst cab'
    'Disk images'  = 'iso img vhd vhdx vmdk vdi qcow2 ova ovf wim esd'
    'AI models'    = 'gguf safetensors ckpt pt pth onnx ggml bin'
    'Installers'   = 'exe msi msix msixbundle appx appxbundle'
    'Documents'    = 'pdf docx doc xlsx xls pptx ppt txt md csv'
    'Logs & dumps' = 'log dmp etl evtx trace'
    'Databases'    = 'db sqlite sqlite3 mdf ldf ndf accdb'
    'Code & pkgs'  = 'jar war nupkg whl tgz node'
}
foreach ($k in $cats.Keys) { foreach ($ext in $cats[$k].Split(' ')) { $script:CategoryMap[$ext] = $k } }
$script:CategoryColor = @{
    'Video' = 'amber'; 'Disk images' = 'rose'; 'AI models' = 'rose'; 'Archives' = 'amber'; 'Installers' = 'amber'
    'Logs & dumps' = 'rose'; 'Audio' = 'teal'; 'Images' = 'teal'; 'Documents' = 'teal'; 'Databases' = 'dim'
    'Code & pkgs' = 'dim'; 'Other' = 'dim'
}
function Get-Category {
    param([string]$Ext)
    if ([string]::IsNullOrEmpty($Ext)) { return 'Other' }
    $e = $Ext.TrimStart('.').ToLowerInvariant()
    if ($script:CategoryMap.ContainsKey($e)) { return $script:CategoryMap[$e] }
    return 'Other'
}

# ═══════════════════════════════ scanning ═══════════════════════════════

function Test-Excluded {
    param([string]$Path)
    $p = $Path.ToLowerInvariant()
    foreach ($x in $script:ExcludeNorm) { if ($p -eq $x -or $p.StartsWith($x + '\')) { return $true } }
    return $false
}

function Scan-Drive {
    param([string]$Root, [long]$MinBytes, [int]$Depth)
    $rootLen = $Root.Length
    $stack = New-Object 'System.Collections.Generic.Stack[string]'
    $stack.Push($Root)
    $tick = 0
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        $di = $null
        try { $di = New-Object System.IO.DirectoryInfo($dir) } catch { continue }

        try {
            foreach ($sub in $di.EnumerateDirectories()) {
                if (($sub.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
                if (Test-Excluded $sub.FullName) { continue }
                $stack.Push($sub.FullName)
            }
        } catch { $script:Denied++ }

        try {
            foreach ($f in $di.EnumerateFiles()) {
                $script:FileCount++
                $len = $f.Length
                if ($len -le 0) { continue }

                $cat = Get-Category $f.Extension
                $script:ByCategory[$cat] = [long]$script:ByCategory[$cat] + $len

                $rel = $f.DirectoryName
                if ($rel.Length -gt $rootLen) {
                    $parts = $rel.Substring($rootLen).TrimStart('\').Split('\')
                    $take = [math]::Min($Depth, $parts.Length)
                    $key = $Root + [string]::Join('\', $parts[0..($take - 1)])
                } else { $key = $Root }
                $script:Folders[$key] = [long]$script:Folders[$key] + $len

                if ($len -ge $MinBytes) {
                    $script:Candidates.Add([pscustomobject]@{ Path = $f.FullName; Bytes = $len; Modified = $f.LastWriteTime; Category = $cat })
                }

                $tick++
                if (($tick % 4000) -eq 0) {
                    Write-Progress -Activity "Scanning $Root" -Status ('{0:N0} files · {1:N0}s · {2}' -f $script:FileCount, $sw.Elapsed.TotalSeconds, (Truncate-Path $dir 60))
                }
            }
        } catch { $script:Denied++ }
    }
    Write-Progress -Activity "Scanning $Root" -Completed
}

# ═══════════════════════════════ cleanup targets ═══════════════════════════════

function Measure-Path {
    param([string]$Path)
    $total = [long]0
    try {
        foreach ($it in @(Get-Item -Path $Path -Force -ErrorAction SilentlyContinue)) {
            if ($null -eq $it) { continue }
            if ($it.PSIsContainer) {
                $s = Get-ChildItem -LiteralPath $it.FullName -Recurse -Force -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum
                if ($s.Sum) { $total += [long]$s.Sum }
            } else { $total += [long]$it.Length }
        }
    } catch {}
    return $total
}

function Get-CleanupTargets {
    param([string]$SysDrive)
    $LA = $env:LOCALAPPDATA; $UP = $env:USERPROFILE; $PD = $env:ProgramData
    $W  = "${SysDrive}Windows"
    @(
        @{ Name='User temp';                     Risk='SAFE';   Path="$env:TEMP";                                       How="Remove-Item `"$env:TEMP\*`" -Recurse -Force -EA SilentlyContinue" }
        @{ Name='Windows temp';                  Risk='SAFE';   Path="$W\Temp";                                         How="Remove-Item `"$W\Temp\*`" -Recurse -Force -EA SilentlyContinue  (admin)" }
        @{ Name='Windows Update download cache'; Risk='SAFE';   Path="$W\SoftwareDistribution\Download";                How="Stop-Service wuauserv; Remove-Item `"$W\SoftwareDistribution\Download\*`" -Recurse -Force; Start-Service wuauserv  (admin)" }
        @{ Name='Delivery Optimization cache';   Risk='SAFE';   Path="$W\SoftwareDistribution\DeliveryOptimization";    How="Delete-DeliveryOptimizationCache -Force  (admin), or Settings > Storage > Temporary files" }
        @{ Name='Recycle Bin';                   Risk='SAFE';   Path="$SysDrive`$Recycle.Bin";                          How="Clear-RecycleBin -Force" }
        @{ Name='Thumbnail cache';               Risk='SAFE';   Path="$LA\Microsoft\Windows\Explorer\thumbcache_*.db";  How="Settings > Storage > Temporary files > Thumbnails (rebuilt automatically)" }
        @{ Name='Crash dumps (user)';            Risk='SAFE';   Path="$LA\CrashDumps";                                  How="Remove-Item `"$LA\CrashDumps\*`" -Force" }
        @{ Name='Minidumps (system)';            Risk='SAFE';   Path="$W\Minidump";                                     How="Remove-Item `"$W\Minidump\*`" -Force  (admin)" }
        @{ Name='Full memory dump';              Risk='SAFE';   Path="$W\MEMORY.DMP";                                   How="Remove-Item `"$W\MEMORY.DMP`" -Force  (admin) — only needed if you're debugging a BSOD" }
        @{ Name='Windows Error Reporting';       Risk='SAFE';   Path="$PD\Microsoft\Windows\WER";                       How="Remove-Item `"$PD\Microsoft\Windows\WER\*`" -Recurse -Force  (admin)" }
        @{ Name='CBS / servicing logs';          Risk='SAFE';   Path="$W\Logs\CBS";                                     How="Remove-Item `"$W\Logs\CBS\*.log`" -Force  (admin)" }
        @{ Name='Chrome cache';                  Risk='SAFE';   Path="$LA\Google\Chrome\User Data\*\Cache*";            How="Close Chrome, then delete the Cache folders, or Chrome > Clear browsing data > Cached images" }
        @{ Name='Edge cache';                    Risk='SAFE';   Path="$LA\Microsoft\Edge\User Data\*\Cache*";           How="Close Edge, then delete the Cache folders, or Edge > Clear browsing data > Cached images" }
        @{ Name='npm cache';                     Risk='SAFE';   Path="$LA\npm-cache";                                   How="npm cache clean --force" }
        @{ Name='pip cache';                     Risk='SAFE';   Path="$LA\pip\Cache";                                   How="pip cache purge" }
        @{ Name='NuGet package cache';           Risk='SAFE';   Path="$UP\.nuget\packages";                             How="dotnet nuget locals all --clear  (re-downloads on next restore)" }
        @{ Name='Previous Windows install';      Risk='SAFE';   Path="${SysDrive}Windows.old";                          How="Settings > Storage > Temporary files > Previous Windows installation(s). Do NOT delete by hand." }

        @{ Name='Downloads folder';              Risk='REVIEW'; Path="$UP\Downloads";                                   How="Sort by size; delete installers you've already run and archives you've already extracted" }
        @{ Name='Hibernation file';              Risk='REVIEW'; Path="${SysDrive}hiberfil.sys";                         How="powercfg /h off  (admin) — disables hibernate and Fast Startup; fine on a desktop, think twice on a laptop" }
        @{ Name='Ollama models';                 Risk='REVIEW'; Path="$UP\.ollama\models";                              How="ollama list, then ollama rm <model> for ones you don't use" }
        @{ Name='LM Studio models';              Risk='REVIEW'; Path="$UP\.lmstudio\models";                            How="Remove unused models from within LM Studio" }
        @{ Name='Hugging Face cache';            Risk='REVIEW'; Path="$UP\.cache\huggingface";                          How="huggingface-cli delete-cache, or delete the hub folder to re-download on demand" }
        @{ Name='Docker Desktop WSL disk';       Risk='REVIEW'; Path="$LA\Docker\wsl";                                  How="docker system prune -a, then compact the VHDX: wsl --shutdown; Optimize-VHD or diskpart compact" }
        @{ Name='WSL distro disks';              Risk='REVIEW'; Path="$LA\Packages\*\LocalState\ext4.vhdx";             How="Free space inside the distro first, then wsl --shutdown and compact the VHDX — deleting it removes the whole distro" }
        @{ Name='OneDrive local copies';         Risk='REVIEW'; Path="$UP\OneDrive";                                    How="Right-click folders > Free up space to keep them cloud-only" }

        @{ Name='Page file';                     Risk='KEEP';   Path="${SysDrive}pagefile.sys";                         How="Leave it. Resize only via System Properties > Advanced > Performance > Virtual memory" }
        @{ Name='Swap file';                     Risk='KEEP';   Path="${SysDrive}swapfile.sys";                         How="Leave it — used by Store apps" }
        @{ Name='WinSxS component store';        Risk='KEEP';   Path="$W\WinSxS";                                       How="Never delete manually. Safe reclaim: Dism /Online /Cleanup-Image /StartComponentCleanup /ResetBase  (admin)" }
        @{ Name='Windows Installer cache';       Risk='KEEP';   Path="$W\Installer";                                    How="Never delete manually — uninstallers and repairs depend on it" }
        @{ Name='Prefetch';                      Risk='KEEP';   Path="$W\Prefetch";                                     How="Tiny and speeds up app launches. Leave it." }
    )
}

# ═══════════════════════════════ error guidance ═══════════════════════════════

function Show-Failure {
    param($Err)
    $msg = "$($Err.Exception.Message)"
    $id  = "$($Err.FullyQualifiedErrorId)"
    $me  = $PSCommandPath
    Write-Progress -Activity ' ' -Completed
    Write-Host ''
    Write-Host ('  ' + (C rose '✖ The script stopped.') + '  ' + (C dim (Truncate-Path $msg 100)))
    Write-Host ''
    Write-Host ('  ' + (C bold (C ink 'What to try:')))

    $advised = $false
    if ($msg -match 'not digitally signed|execution polic|UnauthorizedAccess' -or $id -match 'PSSecurityException') {
        $advised = $true
        Write-Host ('  ' + (C teal '1.') + ' ' + (C ink 'Windows is blocking the script file. Unblock it once, permanently:'))
        Write-Host ('       ' + (C amber "Unblock-File `"$me`""))
        Write-Host ('  ' + (C teal '2.') + ' ' + (C ink 'Or bypass policy for this run only (changes nothing on the system):'))
        Write-Host ('       ' + (C amber "powershell -ExecutionPolicy Bypass -File `"$me`""))
        Write-Host ('  ' + (C teal '3.') + ' ' + (C ink 'Or just double-click ') + (C amber 'Run-StorageHogs.cmd') + (C ink ' next to this script.'))
    }
    elseif ($msg -match 'Access is denied|access to the path|PermissionDenied' -or $id -match 'PermissionDenied') {
        $advised = $true
        Write-Host ('  ' + (C teal '1.') + ' ' + (C ink 'A folder needs administrator rights. Re-run elevated:'))
        Write-Host ('       ' + (C amber "Start-Process powershell -Verb RunAs -ArgumentList '-ExecutionPolicy Bypass -File `"$me`" -Interactive'"))
        Write-Host ('  ' + (C teal '2.') + ' ' + (C ink 'Or exclude the folder:  ') + (C amber '-Exclude ''C:\That\Folder'''))
    }
    elseif ($msg -match 'Win32_LogicalDisk|CIM|WMI|RPC server') {
        $advised = $true
        Write-Host ('  ' + (C teal '1.') + ' ' + (C ink 'Could not query drives via WMI. Restart the service and retry:'))
        Write-Host ('       ' + (C amber 'Restart-Service Winmgmt -Force   (admin)'))
    }
    elseif ($msg -match 'Cannot find drive|does not exist|ObjectNotFound' -or $id -match 'ObjectNotFound') {
        $advised = $true
        Write-Host ('  ' + (C teal '1.') + ' ' + (C ink 'A drive or path you gave does not exist. Check the letter:  ') + (C amber 'Get-PSDrive -PSProvider FileSystem'))
    }
    elseif ($msg -match 'RawUI|WindowSize|VirtualTerminal|console') {
        $advised = $true
        Write-Host ('  ' + (C teal '1.') + ' ' + (C ink 'This console cannot draw the visuals. Run it in Windows Terminal, or:'))
        Write-Host ('       ' + (C amber "powershell -ExecutionPolicy Bypass -File `"$me`" -NoColor"))
    }
    elseif ($msg -match 'OutOfMemory') {
        $advised = $true
        Write-Host ('  ' + (C teal '1.') + ' ' + (C ink 'Too many large files tracked. Raise the threshold:  ') + (C amber '-MinSizeMB 500'))
    }
    if (-not $advised) {
        Write-Host ('  ' + (C teal '1.') + ' ' + (C ink 'Unexpected error. The combination that works on almost any machine:'))
        Write-Host ('       ' + (C amber "powershell -NoProfile -ExecutionPolicy Bypass -File `"$me`" -NoColor -Interactive"))
        Write-Host ('  ' + (C teal '2.') + ' ' + (C ink 'If it still fails, run it elevated (see Run-StorageHogs.cmd) and send the line below with the error.'))
    }
    Write-Host ''
    Write-Host ('  ' + (C dim ('at: ' + $Err.InvocationInfo.PositionMessage -replace '\s+', ' ')))
    Write-Host ''
}

# ═══════════════════════════════ interactive menu ═══════════════════════════════

function Invoke-Menu {
    param($Disks, $IsAdmin, $Me)

    Write-Host ''
    Write-Host ('  ' + (C teal '▌') + ' ' + (C bold (C ink 'STORAGE HOGS')) + '  ' + (C dim 'interactive setup — Enter accepts the default'))
    Write-Host ''

    # ── elevation ──
    if (-not $IsAdmin) {
        Write-Host ('  ' + (C amber '▲') + ' ' + (C ink 'Not running as Administrator. System folders (Windows Update cache, WinSxS, other users) will be partly skipped.'))
        $e = Ask 'Relaunch as Administrator now? (y/n)' 'y'
        if ($e -match '^y') {
            $argLine = "-NoProfile -ExecutionPolicy Bypass -File `"$Me`" -Interactive"
            if ($script:UseColor -eq $false) { $argLine += ' -NoColor' }
            try { Start-Process powershell -Verb RunAs -ArgumentList $argLine; exit 0 }
            catch { Write-Host ('  ' + (C dim 'Elevation was cancelled — continuing without it.')) }
        }
        Write-Host ''
    }

    # ── drives ──
    Write-Host ('  ' + (C bold (C ink 'Drives')))
    $i = 0
    foreach ($d in $Disks) {
        $i++
        $used = $d.Size - $d.FreeSpace
        $frac = if ($d.Size) { $used / $d.Size } else { 0 }
        $col  = if ($frac -ge 0.9) { 'rose' } elseif ($frac -ge 0.75) { 'amber' } else { 'teal' }
        $label = if ($d.VolumeName) { $d.VolumeName } else { 'Local Disk' }
        Write-Host ('   ' + (C teal ('{0}.' -f $i)) + ' ' + (C bold (C ink $d.DeviceID)) + '  ' + (Bar $frac 20 $col) + '  ' +
                    (C ink (Format-Size $used)) + (C dim ' / ') + (C ink (Format-Size $d.Size)) + '  ' + (C $col ('{0,4:P0}' -f $frac)) + '  ' + (C dim $label))
    }
    $sel = Ask 'Which drives? (numbers or letters, comma-separated, or "all")' 'all'
    $chosen = @()
    if ($sel -eq 'all') { $chosen = @($Disks) }
    else {
        foreach ($tok in ($sel -split '[,\s]+' | Where-Object { $_ })) {
            if ($tok -match '^\d+$' -and [int]$tok -ge 1 -and [int]$tok -le $Disks.Count) { $chosen += $Disks[[int]$tok - 1] }
            else {
                $letter = $tok.TrimEnd(':', '\').ToUpper() + ':'
                $m = $Disks | Where-Object { $_.DeviceID -eq $letter }
                if ($m) { $chosen += $m } else { Write-Host ('  ' + (C amber "  ignoring '$tok' — not a fixed drive")) }
            }
        }
        if (-not $chosen) { Write-Host ('  ' + (C amber '  nothing valid selected — scanning all')); $chosen = @($Disks) }
    }
    Write-Host ''

    # ── profile ──
    Write-Host ('  ' + (C bold (C ink 'Scan profile')))
    Write-Host ('   ' + (C teal '1.') + ' ' + (C ink 'Quick    ') + (C dim '— top 15 files ≥ 200 MB, folders 2 deep. Fastest.'))
    Write-Host ('   ' + (C teal '2.') + ' ' + (C ink 'Standard ') + (C dim '— top 25 files ≥ 50 MB, folders 3 deep.'))
    Write-Host ('   ' + (C teal '3.') + ' ' + (C ink 'Deep     ') + (C dim '— top 50 files ≥ 10 MB, folders 4 deep. Slow on multi-TB drives.'))
    Write-Host ('   ' + (C teal '4.') + ' ' + (C ink 'Custom   ') + (C dim '— set each number yourself.'))
    $p = Ask 'Profile' '2'
    switch ($p) {
        '1' { $script:Cfg.Top = 15; $script:Cfg.MinSizeMB = 200; $script:Cfg.FolderDepth = 2; $script:Cfg.TopFolders = 10 }
        '3' { $script:Cfg.Top = 50; $script:Cfg.MinSizeMB = 10;  $script:Cfg.FolderDepth = 4; $script:Cfg.TopFolders = 25 }
        '4' {
            $script:Cfg.Top         = [int](Ask 'Largest files to show'          "$($script:Cfg.Top)")
            $script:Cfg.MinSizeMB   = [int](Ask 'Ignore files smaller than (MB)' "$($script:Cfg.MinSizeMB)")
            $script:Cfg.TopFolders  = [int](Ask 'Largest folders to show'        "$($script:Cfg.TopFolders)")
            $script:Cfg.FolderDepth = [int](Ask 'Folder roll-up depth'           "$($script:Cfg.FolderDepth)")
        }
        default { $script:Cfg.Top = 25; $script:Cfg.MinSizeMB = 50; $script:Cfg.FolderDepth = 3; $script:Cfg.TopFolders = 15 }
    }
    Write-Host ''

    # ── extras ──
    $ex = Ask 'Paths to exclude? (comma-separated, blank for none)' ''
    if ($ex) { $script:Cfg.Exclude = @($ex -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
    $csv = Ask 'Export largest files to CSV? (path, blank to skip)' ''
    if ($csv) { $script:Cfg.ExportCsv = $csv }
    Write-Host ''

    # ── confirm ──
    Write-Host ('  ' + (C dim ('Scanning ' + (($chosen | ForEach-Object { $_.DeviceID }) -join ' ') +
                 " · top $($script:Cfg.Top) files ≥ $($script:Cfg.MinSizeMB) MB · folders $($script:Cfg.FolderDepth) deep" +
                 $(if ($script:Cfg.Exclude) { ' · excluding ' + ($script:Cfg.Exclude -join ', ') } else { '' }))))
    $go = Ask 'Start? (y/n)' 'y'
    if ($go -notmatch '^y') { Write-Host ('  ' + (C dim 'Cancelled.')); exit 0 }
    return $chosen
}

# ═══════════════════════════════ report ═══════════════════════════════

function Invoke-Report {
    param($Disks, $IsAdmin)
    $cfg = $script:Cfg
    $SysDrive = $env:SystemDrive + '\'
    $script:ExcludeNorm = @($cfg.Exclude | ForEach-Object { $_.TrimEnd('\').ToLowerInvariant() })
    $script:Candidates = New-Object 'System.Collections.Generic.List[object]'
    $script:Folders = @{}; $script:ByCategory = @{}; $script:FileCount = 0; $script:Denied = 0

    Write-Host ''
    Write-Host ('  ' + (C teal '▌') + ' ' + (C bold (C ink 'STORAGE HOGS')) + '  ' + (C dim ('scan of ' + (($Disks | ForEach-Object { $_.DeviceID }) -join ' ') + ' · ' + (Get-Date -Format 'yyyy-MM-dd HH:mm'))))
    if (-not $IsAdmin) { Write-Host ('  ' + (C amber '▲') + ' ' + (C dim 'not elevated — system folders partly skipped')) }

    Section 'DRIVES'
    foreach ($d in $Disks) {
        $used = $d.Size - $d.FreeSpace
        $frac = if ($d.Size) { $used / $d.Size } else { 0 }
        $col  = if ($frac -ge 0.9) { 'rose' } elseif ($frac -ge 0.75) { 'amber' } else { 'teal' }
        $label = if ($d.VolumeName) { $d.VolumeName } else { 'Local Disk' }
        Write-Host ('  ' + (C bold (C ink $d.DeviceID)) + '  ' + (Bar $frac 30 $col) + '  ' +
                    (C ink (Format-Size $used)) + (C dim ' used of ') + (C ink (Format-Size $d.Size)) + '  ' +
                    (C $col ('{0,5:P0}' -f $frac)) + '  ' + (C dim ((Format-Size $d.FreeSpace).Trim() + ' free · ' + $label)))
    }

    $swTotal = [System.Diagnostics.Stopwatch]::StartNew()
    foreach ($d in $Disks) { Scan-Drive ($d.DeviceID + '\') ([long]$cfg.MinSizeMB * 1MB) $cfg.FolderDepth }
    $swTotal.Stop()
    Write-Host ''
    Write-Host ('  ' + (C dim ('scanned {0:N0} files in {1:N0}s · {2:N0} folders inaccessible' -f $script:FileCount, $swTotal.Elapsed.TotalSeconds, $script:Denied)))
    if ($script:Denied -gt 200 -and -not $IsAdmin) { Write-Host ('  ' + (C amber ('  many folders were inaccessible — re-run as Administrator for the full picture'))) }

    $width = Get-Width

    $topFiles = @($script:Candidates | Sort-Object Bytes -Descending | Select-Object -First $cfg.Top)
    Section 'LARGEST FILES' ("  top $($cfg.Top) ≥ $($cfg.MinSizeMB) MB")
    if (-not $topFiles) { Write-Host ('  ' + (C dim "no files ≥ $($cfg.MinSizeMB) MB found — try a lower threshold")) }
    else {
        $max = $topFiles[0].Bytes; $pathW = $width - 60; $i = 0
        foreach ($f in $topFiles) {
            $i++
            Write-Host ('  ' + (C dim ('{0,2}' -f $i)) + ' ' + (Bar ($f.Bytes / $max) 18 $script:CategoryColor[$f.Category]) + ' ' +
                        (C ink (Format-Size $f.Bytes)) + ' ' + (C dim ('{0,-12}' -f $f.Category)) + (C faint ('{0,5} ' -f (Age-Label $f.Modified))) +
                        (C ink (Truncate-Path $f.Path $pathW)))
        }
    }

    $topDirs = @($script:Folders.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First $cfg.TopFolders)
    Section 'LARGEST FOLDERS' ("  rolled up to depth $($cfg.FolderDepth)")
    if ($topDirs) {
        $max = $topDirs[0].Value
        foreach ($e in $topDirs) {
            Write-Host ('  ' + (Bar ($e.Value / $max) 18 'teal') + ' ' + (C ink (Format-Size $e.Value)) + '  ' + (C ink (Truncate-Path $e.Key ($width - 40))))
        }
    }

    $totalScanned = [long]0; foreach ($v in $script:ByCategory.Values) { $totalScanned += $v }
    Section 'BY CATEGORY'
    foreach ($e in ($script:ByCategory.GetEnumerator() | Sort-Object Value -Descending)) {
        $frac = if ($totalScanned) { $e.Value / $totalScanned } else { 0 }
        Write-Host ('  ' + (C dim ('{0,-13}' -f $e.Key)) + (Bar $frac 30 $script:CategoryColor[$e.Key]) + ' ' + (C ink (Format-Size $e.Value)) + '  ' + (C dim ('{0,5:P1}' -f $frac)))
    }

    Section 'CLEANUP' '  measured on this machine · nothing is deleted by this script'
    $targets = Get-CleanupTargets $SysDrive
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $n = 0
    foreach ($t in $targets) {
        $n++
        Write-Progress -Activity 'Measuring cleanup targets' -Status $t.Name -PercentComplete ([int](100 * $n / $targets.Count))
        $b = Measure-Path $t.Path
        if ($b -gt 0) { $rows.Add([pscustomobject]@{ Name = $t.Name; Risk = $t.Risk; Bytes = $b; Path = $t.Path; How = $t.How }) }
    }
    Write-Progress -Activity 'Measuring cleanup targets' -Completed

    $riskOrder = @{ SAFE = 0; REVIEW = 1; KEEP = 2 }
    $safeTotal = [long]0; $reviewTotal = [long]0
    foreach ($grp in ($rows | Group-Object Risk | Sort-Object { $riskOrder[$_.Name] })) {
        $col  = switch ($grp.Name) { 'SAFE' { 'teal' } 'REVIEW' { 'amber' } default { 'rose' } }
        $hint = switch ($grp.Name) { 'SAFE' { 'caches and leftovers — rebuilt automatically' } 'REVIEW' { 'real data or trade-offs — decide per item' } default { "large by design — don't touch by hand" } }
        Write-Host ''
        Write-Host ('  ' + (C bold (C $col $grp.Name)) + '  ' + (C dim $hint))
        foreach ($r in ($grp.Group | Sort-Object Bytes -Descending)) {
            if ($grp.Name -eq 'SAFE')   { $safeTotal   += $r.Bytes }
            if ($grp.Name -eq 'REVIEW') { $reviewTotal += $r.Bytes }
            if ($r.Bytes -lt 1MB -and $grp.Name -ne 'KEEP') { continue }
            Write-Host ('   ' + (C $col '●') + ' ' + (C ink (Format-Size $r.Bytes)) + '  ' + (C ink ('{0,-28}' -f $r.Name)) + (C faint (Truncate-Path $r.Path ($width - 50))))
            Write-Host ('     ' + (C dim '↳ ') + (C dim $r.How))
        }
    }

    Section 'SUMMARY'
    Write-Host ('  ' + (C teal  '■ ') + (C ink (Format-Size $safeTotal))   + (C dim '  reclaimable now, safely'))
    Write-Host ('  ' + (C amber '■ ') + (C ink (Format-Size $reviewTotal)) + (C dim '  more if you review the amber items'))
    $biggestCat = $script:ByCategory.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1
    if ($biggestCat) { Write-Host ('  ' + (C dim ('largest category is ' + $biggestCat.Key + ' — that is where the real space is, not in the caches'))) }
    Write-Host ('  ' + (C dim 'Windows'' own tool covers most SAFE items in one go:  ') + (C ink 'cleanmgr /sageset:1  then  cleanmgr /sagerun:1'))
    Write-Host ''

    if ($cfg.ExportCsv) {
        try {
            $topFiles | Select-Object Path, @{ n = 'SizeGB'; e = { [math]::Round($_.Bytes / 1GB, 3) } }, Category, Modified |
                Export-Csv -Path $cfg.ExportCsv -NoTypeInformation -Encoding UTF8
            Write-Host ('  ' + (C dim ('top files exported to ' + $cfg.ExportCsv)))
        } catch { Write-Warning "CSV export failed: $($_.Exception.Message)" }
    }
}

# ═══════════════════════════════ main ═══════════════════════════════

$script:Cfg = @{ Top = $Top; TopFolders = $TopFolders; MinSizeMB = $MinSizeMB; FolderDepth = $FolderDepth; Exclude = $Exclude; ExportCsv = $ExportCsv }

try {
    $IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    $allDisks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop | Sort-Object DeviceID)
    if (-not $allDisks) { throw 'No fixed drives were found (Win32_LogicalDisk returned nothing).' }

    # menu when: explicitly asked, or no scan-related argument was given
    $scanArgs = @('Drive', 'Top', 'TopFolders', 'MinSizeMB', 'FolderDepth', 'Exclude', 'ExportCsv')
    $gaveScanArgs = $false
    foreach ($a in $scanArgs) { if ($PSBoundParameters.ContainsKey($a)) { $gaveScanArgs = $true } }
    $useMenu = $Interactive -or (-not $gaveScanArgs)

    if ($useMenu) {
        $disks = Invoke-Menu -Disks $allDisks -IsAdmin $IsAdmin -Me $PSCommandPath
    } else {
        $disks = $allDisks
        if ($Drive) {
            $want = $Drive | ForEach-Object { $_.TrimEnd(':', '\').ToUpper() + ':' }
            $disks = @($allDisks | Where-Object { $want -contains $_.DeviceID })
            if (-not $disks) { throw "Cannot find drive: none of '$($Drive -join ', ')' is a fixed drive. Fixed drives here: $(($allDisks | ForEach-Object { $_.DeviceID }) -join ' ')" }
        }
    }

    Invoke-Report -Disks $disks -IsAdmin $IsAdmin
}
catch {
    Show-Failure $_
    exit 1
}

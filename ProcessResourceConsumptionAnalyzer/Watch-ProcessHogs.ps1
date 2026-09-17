#Requires -Version 5.1
<#
.SYNOPSIS
    Watch-ProcessHogs — live process monitor with CUMULATIVE accounting since launch.

.DESCRIPTION
    Refreshes in place every second and shows which processes have consumed the most
    CPU time, memory and disk I/O since the moment you started it — not just right now.
    A process that burned 40 CPU-seconds and then quit stays in the table, greyed out.

    Graph mode shows the top 10 as a grid of sparklines: one row per process, one graph
    per resource, over the last 60 samples.

    Keys while running:
        q  quit            g  toggle graph mode      n  group by name / by PID
        s  cycle sort      p  pause                  r  reset cumulative counters
        +  slower          -  faster

    Nothing is modified. The script only reads process information.

.PARAMETER Interval    Seconds between samples. Default 1.
.PARAMETER Top         Rows in list mode. Default 20.
.PARAMETER GraphTop    Rows in graph mode. Default 10.
.PARAMETER ByName      Start grouped by process name (chrome = one row).
.PARAMETER Graph       Start in graph mode.
.PARAMETER Duration    Stop automatically after this many seconds.
.PARAMETER Log         Append every sample to this CSV.
.PARAMETER NoColor     Plain output, no colour.
.PARAMETER Ascii       Draw with plain ASCII (no block or sparkline glyphs). Automatic when the
                       console cannot be switched to UTF-8.
.PARAMETER Interactive Force the setup menu even when other arguments are given.
.PARAMETER Hold        Wait for a key before exiting, so a window opened just for this script
                       (the elevated relaunch uses it) does not vanish with its message.

.EXAMPLE
    .\Watch-ProcessHogs.ps1                       # setup menu
    .\Watch-ProcessHogs.ps1 -ByName -Graph        # straight in
    .\Watch-ProcessHogs.ps1 -Duration 300 -Log .\samples.csv

.NOTES
    Run elevated to see CPU and I/O for system and other users' processes.
    Needs a real console (Windows Terminal, conhost). Does not work in the ISE.
    If Windows refuses to run it: Unblock-File .\Watch-ProcessHogs.ps1, or double-click Run-ProcessHogs.cmd.
#>
[CmdletBinding()]
param(
    [double]$Interval = 1,
    [int]$Top = 20,
    [int]$GraphTop = 10,
    [switch]$ByName,
    [switch]$Graph,
    [int]$Duration = 0,
    [string]$Log,
    [switch]$NoColor,
    [switch]$Ascii,
    [switch]$Interactive,
    [switch]$Hold
)

# ═══════════════════════════════ console: colour and glyphs ═══════════════════════════════

$script:Esc = [char]27
$script:UseColor = (-not $NoColor) -and ($Host.UI.SupportsVirtualTerminal -or $env:WT_SESSION -or $PSVersionTable.PSVersion.Major -ge 7)

# The block, sparkline and arrow glyphs only exist in UTF-8. Windows PowerShell starts the console
# in the OEM code page (437 / 850) where they print as "?", so switch it for the run and put it back.
$script:PrevOutEnc = $null
$script:UseGlyphs = -not $Ascii
if ($script:UseGlyphs) {
    try {
        $script:PrevOutEnc = [Console]::OutputEncoding
        if ($script:PrevOutEnc.CodePage -ne 65001) { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) }
    } catch { $script:UseGlyphs = $false; $script:PrevOutEnc = $null }
}
function Restore-Console {
    if ($script:PrevOutEnc -and $script:PrevOutEnc.CodePage -ne 65001) { try { [Console]::OutputEncoding = $script:PrevOutEnc } catch {} }
}

if ($script:UseGlyphs) {
    $script:G = @{ bar = '█'; empty = '░'; spark = @('▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'); dot = '·'; prompt = '›'; mark = '▌'; dead = '×'; warn = '▲'; ok = '●'; err = '✖'; ell = '…'; rule = '─'; sep = '│'; tl = '┌'; tr = '┐'; bl = '└'; br = '┘'; times = '×'; arrow = '→'; hist = '▏' }
} else {
    $script:G = @{ bar = '#'; empty = '.'; spark = @('_', '.', ':', '-', '=', '+', '*', '#'); dot = '.'; prompt = '>'; mark = '|'; dead = 'x'; warn = '!'; ok = '*'; err = 'X'; ell = '~'; rule = '-'; sep = '|'; tl = '+'; tr = '+'; bl = '+'; br = '+'; times = 'x'; arrow = '->'; hist = '|' }
}

$script:Palette = @{
    teal  = "$Esc[38;2;47;217;197m";  amber = "$Esc[38;2;240;165;60m";  rose = "$Esc[38;2;255;107;94m"
    green = "$Esc[38;2;120;220;140m"; blue  = "$Esc[38;2;120;170;255m"
    ink   = "$Esc[38;2;222;236;242m"; dim   = "$Esc[38;2;120;150;166m"; faint = "$Esc[38;2;70;96;110m"
    bold  = "$Esc[1m";                band  = "$Esc[48;2;16;42;50m$Esc[38;2;222;236;242m"; key = "$Esc[48;2;36;60;72m$Esc[38;2;230;240;244m"
    tealbg = "$Esc[48;2;20;70;66m$Esc[38;2;222;236;242m"
}
function C {
    # C <style> <text>  → coloured text, reset after
    param([string]$Name, [string]$Text)
    if (-not $script:UseColor) { return $Text }
    return "$($script:Palette[$Name])$Text$Esc[0m"
}
function Vis { param([string]$S) return ([regex]::Replace($S, "$([char]27)\[[0-9;?]*[A-Za-z]", '')).Length }   # visible length
function PadTo { param([string]$S, [int]$W) $n = $W - (Vis $S); if ($n -gt 0) { return $S + (' ' * $n) } return $S }

function Format-Size {
    param([double]$Bytes)
    if ($Bytes -ge 1TB) { return ('{0:N2}T' -f ($Bytes / 1TB)) }
    if ($Bytes -ge 1GB) { return ('{0:N2}G' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N1}M' -f ($Bytes / 1MB)) }
    if ($Bytes -ge 1KB) { return ('{0:N0}K' -f ($Bytes / 1KB)) }
    return ('{0:N0}B' -f $Bytes)
}
function Format-Secs {
    param([double]$S)
    if ($S -ge 3600) { return ('{0:N1}h' -f ($S / 3600)) }
    if ($S -ge 60)   { return ('{0:N1}m' -f ($S / 60)) }
    return ('{0:N1}s' -f $S)
}
function Format-Span { param([TimeSpan]$T) if ($T.TotalHours -ge 1) { return $T.ToString('h\:mm\:ss') } return $T.ToString('m\:ss') }

function Bar {
    # Bar <fraction> <width> <colour>  → filled/empty gauge
    param([double]$Fraction, [int]$Width = 12, [string]$Color = 'teal')
    if ($Fraction -lt 0) { $Fraction = 0 }; if ($Fraction -gt 1) { $Fraction = 1 }
    $filled = [int][math]::Round($Fraction * $Width)
    return (C $Color ($script:G.bar * $filled)) + (C faint ($script:G.empty * ($Width - $filled)))
}
function Heat { param([double]$Frac) if ($Frac -ge 0.85) { return 'rose' } if ($Frac -ge 0.6) { return 'amber' } return 'teal' }

function Spark {
    # Spark <list> <width> <colour>  → sparkline of the last <width> values, auto-scaled to their max
    param($Values, [int]$Width, [string]$Color)
    $n = 0; if ($Values) { $n = $Values.Count }
    $start = [math]::Max(0, $n - $Width)
    $slice = @(); for ($i = $start; $i -lt $n; $i++) { $slice += [double]$Values[$i] }
    $max = 0.0; foreach ($v in $slice) { if ($v -gt $max) { $max = $v } }
    $sb = New-Object System.Text.StringBuilder
    $pad = $Width - $slice.Count
    if ($pad -gt 0) { [void]$sb.Append((C faint ($script:G.dot * $pad))) }
    $hot = ''; $cold = ''
    foreach ($v in $slice) {
        if ($max -le 0 -or $v -le 0) { $cold += $script:G.spark[0]; if ($hot) { [void]$sb.Append((C $Color $hot)); $hot = '' }; continue }
        if ($cold) { [void]$sb.Append((C faint $cold)); $cold = '' }
        $lvl = [int][math]::Min(7, [math]::Floor($v / $max * 7.999))
        $hot += $script:G.spark[$lvl]
    }
    if ($hot) { [void]$sb.Append((C $Color $hot)) }
    if ($cold) { [void]$sb.Append((C faint $cold)) }
    return $sb.ToString()
}

function Cell4 {
    # Cell4 <value> <kind>  → a 4-character cell: pct "42%", mb "728M"/"8.3G", rate "0.8"/"123"
    param([double]$V, [string]$Kind)
    switch ($Kind) {
        'pct'  { return ('{0,3:N0}%' -f [math]::Min(999, $V)) }
        'mb'   { if ($V -ge 10240) { return ('{0,3:N0}G' -f ($V / 1024)) } if ($V -ge 1024) { return ('{0,3:N1}G' -f ($V / 1024)) } return ('{0,3:N0}M' -f $V) }
        default { if ($V -ge 100) { return ('{0,4:N0}' -f $V) } return ('{0,4:N1}' -f $V) }
    }
}
function Trunc { param([string]$S, [int]$N) if ($S.Length -le $N) { return $S.PadRight($N) } return ($S.Substring(0, $N - 1) + $script:G.ell) }
function Rule { param([int]$W) return (C faint ($script:G.rule * $W)) }
function Keycap { param([string]$K, [string]$What) return (C key " $K ") + (C dim " $What") }

# ═══════════════════════════════ disk I/O via Win32 ═══════════════════════════════

$script:IoAvailable = $false
try {
    if (-not ('PH.Io' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace PH {
    public static class Io {
        [StructLayout(LayoutKind.Sequential)]
        public struct IO_COUNTERS {
            public ulong ReadOperationCount; public ulong WriteOperationCount; public ulong OtherOperationCount;
            public ulong ReadTransferCount;  public ulong WriteTransferCount;  public ulong OtherTransferCount;
        }
        [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetProcessIoCounters(IntPtr h, out IO_COUNTERS c);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr h);
        const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        public static bool TryGet(int pid, out ulong read, out ulong write) {
            read = 0; write = 0;
            IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (h == IntPtr.Zero) return false;
            try { IO_COUNTERS c; if (!GetProcessIoCounters(h, out c)) return false; read = c.ReadTransferCount; write = c.WriteTransferCount; return true; }
            finally { CloseHandle(h); }
        }
    }
}
'@ -ErrorAction Stop
    }
    $script:IoAvailable = $true
} catch { $script:IoAvailable = $false; $script:IoError = $_.Exception.Message }

# ═══════════════════════════════ state ═══════════════════════════════

$script:Cores   = [Environment]::ProcessorCount
$script:HistLen = 120
$script:Procs   = @{}     # key "pid|name" → state
$script:Groups  = @{}     # name → state (for by-name view)
$script:Sys     = @{ CpuHist = New-Object 'System.Collections.Generic.List[double]'; RamTotal = 0; RamUsed = 0; RamHist = New-Object 'System.Collections.Generic.List[double]'; IoHist = New-Object 'System.Collections.Generic.List[double]' }
$script:StartedAt = Get-Date
$script:LastSample = $null
$script:SortModes = @('CPU cumulative', 'CPU now', 'Memory now', 'Memory peak', 'Disk I/O cumulative', 'Disk I/O now')
$script:SortIdx = 0
$script:Paused = $false
$script:View = if ($ByName) { 'name' } else { 'pid' }
$script:GraphMode = [bool]$Graph
$script:IntervalSec = [math]::Max(0.25, $Interval)
$script:Ticks = 0
$script:ForceWidth = 0    # tests can pin the frame width

# The leading comma matters: PowerShell unrolls a returned collection into the pipeline, and an
# EMPTY list unrolls to nothing, so without it every history came back $null and the first
# Push-Hist crashed the monitor right after the menu.
function New-Hist { return ,(New-Object 'System.Collections.Generic.List[double]') }
function Push-Hist { param($List, [double]$V) $List.Add($V); if ($List.Count -gt $script:HistLen) { $List.RemoveAt(0) } }
function Max-Of { param($List) $m = 0.0; if ($List) { foreach ($v in $List) { if ($v -gt $m) { $m = $v } } } return $m }

function New-State {
    param([string]$Name, [int]$ProcId)
    return [pscustomobject]@{
        Name = $Name; Pid = $ProcId; Alive = $true; FirstSeen = Get-Date; LastSeen = Get-Date
        CpuStart = 0.0; CpuLast = 0.0; CpuCum = 0.0; CpuPct = 0.0
        MemCur = 0.0; MemPeak = 0.0; MemSum = 0.0; MemN = 0
        IoStartR = [uint64]0; IoStartW = [uint64]0; IoLastR = [uint64]0; IoLastW = [uint64]0; IoCumR = 0.0; IoCumW = 0.0; IoRate = 0.0
        CpuHist = New-Hist; MemHist = New-Hist; IoHist = New-Hist
        Count = 1
    }
}

function Reset-Cumulative {
    foreach ($p in $script:Procs.Values) {
        $p.CpuStart = $p.CpuLast; $p.CpuCum = 0; $p.MemPeak = $p.MemCur; $p.MemSum = 0; $p.MemN = 0
        $p.IoStartR = $p.IoLastR; $p.IoStartW = $p.IoLastW; $p.IoCumR = 0; $p.IoCumW = 0
        $p.CpuHist.Clear(); $p.MemHist.Clear(); $p.IoHist.Clear()
    }
    $script:Groups = @{}
    $script:Sys.CpuHist.Clear(); $script:Sys.RamHist.Clear(); $script:Sys.IoHist.Clear()
    $script:StartedAt = Get-Date
}

function Take-Sample {
    $now = Get-Date
    $elapsed = if ($script:LastSample) { ($now - $script:LastSample).TotalSeconds } else { $script:IntervalSec }
    if ($elapsed -le 0) { $elapsed = $script:IntervalSec }
    $script:LastSample = $now

    $seen = @{}
    $sysCpuDelta = 0.0; $sysIo = 0.0
    $procs = Get-Process -ErrorAction SilentlyContinue

    foreach ($pr in $procs) {
        if ($pr.Id -eq 0) { continue }
        $key = "$($pr.Id)|$($pr.ProcessName)"
        $seen[$key] = $true
        $st = $script:Procs[$key]
        $isNew = $false
        if (-not $st) { $st = New-State $pr.ProcessName $pr.Id; $script:Procs[$key] = $st; $isNew = $true }
        $st.Alive = $true; $st.LastSeen = $now

        # CPU
        $cpuNow = 0.0
        try { $cpuNow = $pr.TotalProcessorTime.TotalSeconds } catch { $cpuNow = $st.CpuLast }
        if ($isNew) { $st.CpuStart = $cpuNow; $st.CpuLast = $cpuNow }
        $d = $cpuNow - $st.CpuLast; if ($d -lt 0) { $d = 0 }
        $st.CpuPct = ($d / $elapsed) * 100.0 / $script:Cores
        $st.CpuLast = $cpuNow
        $st.CpuCum = [math]::Max(0, $cpuNow - $st.CpuStart)
        $sysCpuDelta += $d

        # Memory
        $mem = [double]$pr.WorkingSet64
        $st.MemCur = $mem; if ($mem -gt $st.MemPeak) { $st.MemPeak = $mem }
        $st.MemSum += $mem; $st.MemN++

        # Disk I/O
        if ($script:IoAvailable) {
            $r = [uint64]0; $w = [uint64]0
            if ([PH.Io]::TryGet($pr.Id, [ref]$r, [ref]$w)) {
                if ($isNew) { $st.IoStartR = $r; $st.IoStartW = $w; $st.IoLastR = $r; $st.IoLastW = $w }
                $dr = [double]($r - $st.IoLastR); $dw = [double]($w - $st.IoLastW)
                if ($dr -lt 0) { $dr = 0 }; if ($dw -lt 0) { $dw = 0 }
                $st.IoRate = ($dr + $dw) / $elapsed
                $st.IoLastR = $r; $st.IoLastW = $w
                $st.IoCumR = [double]($r - $st.IoStartR); $st.IoCumW = [double]($w - $st.IoStartW)
                $sysIo += $st.IoRate
            } else { $st.IoRate = 0 }
        }

        Push-Hist $st.CpuHist $st.CpuPct
        Push-Hist $st.MemHist ($mem / 1MB)
        Push-Hist $st.IoHist ($st.IoRate / 1MB)
    }

    # processes that vanished: keep if they did meaningful work, else drop
    $drop = @()
    foreach ($key in $script:Procs.Keys) {
        if ($seen[$key]) { continue }
        $st = $script:Procs[$key]
        if ($st.Alive) { $st.Alive = $false; $st.CpuPct = 0; $st.IoRate = 0; $st.MemCur = 0 }
        if ($st.CpuCum -lt 0.5 -and ($st.IoCumR + $st.IoCumW) -lt 10MB) { $drop += $key; continue }
        Push-Hist $st.CpuHist 0; Push-Hist $st.MemHist 0; Push-Hist $st.IoHist 0
    }
    foreach ($k in $drop) { $script:Procs.Remove($k) }

    # by-name aggregation
    $agg = @{}
    foreach ($st in $script:Procs.Values) {
        $g = $agg[$st.Name]
        if (-not $g) {
            $g = [pscustomobject]@{ Name = $st.Name; Pid = 0; Alive = $false; CpuCum = 0.0; CpuPct = 0.0; MemCur = 0.0; MemPeak = 0.0; MemSum = 0.0; MemN = 0; IoCumR = 0.0; IoCumW = 0.0; IoRate = 0.0; Count = 0; CpuHist = $null; MemHist = $null; IoHist = $null }
            $agg[$st.Name] = $g
        }
        $g.CpuCum += $st.CpuCum; $g.CpuPct += $st.CpuPct; $g.MemCur += $st.MemCur
        $g.IoCumR += $st.IoCumR; $g.IoCumW += $st.IoCumW; $g.IoRate += $st.IoRate
        if ($st.Alive) { $g.Alive = $true; $g.Count++ }
    }
    foreach ($name in $agg.Keys) {
        $g = $agg[$name]
        $prev = $script:Groups[$name]
        if (-not $prev) { $prev = [pscustomobject]@{ MemPeak = 0.0; MemSum = 0.0; MemN = 0; CpuHist = New-Hist; MemHist = New-Hist; IoHist = New-Hist }; $script:Groups[$name] = $prev }
        if ($g.MemCur -gt $prev.MemPeak) { $prev.MemPeak = $g.MemCur }
        $prev.MemSum += $g.MemCur; $prev.MemN++
        Push-Hist $prev.CpuHist $g.CpuPct; Push-Hist $prev.MemHist ($g.MemCur / 1MB); Push-Hist $prev.IoHist ($g.IoRate / 1MB)
        $g.MemPeak = $prev.MemPeak; $g.MemSum = $prev.MemSum; $g.MemN = $prev.MemN
        $g.CpuHist = $prev.CpuHist; $g.MemHist = $prev.MemHist; $g.IoHist = $prev.IoHist
    }
    $script:GroupRows = @($agg.Values)

    # system
    $sysCpu = ($sysCpuDelta / $elapsed) * 100.0 / $script:Cores
    Push-Hist $script:Sys.CpuHist ([math]::Min(100, $sysCpu))
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $script:Sys.RamTotal = [double]$os.TotalVisibleMemorySize * 1KB
        $script:Sys.RamUsed  = ([double]$os.TotalVisibleMemorySize - [double]$os.FreePhysicalMemory) * 1KB
    } catch {}
    Push-Hist $script:Sys.RamHist ($script:Sys.RamUsed / 1MB)
    Push-Hist $script:Sys.IoHist ($sysIo / 1MB)
    $script:Ticks++

    if ($Log) {
        try {
            $rows = foreach ($st in $script:Procs.Values) {
                if (-not $st.Alive) { continue }
                [pscustomobject]@{ Time = $now.ToString('s'); Pid = $st.Pid; Name = $st.Name; CpuPct = [math]::Round($st.CpuPct, 2); CpuCumSec = [math]::Round($st.CpuCum, 2); MemMB = [math]::Round($st.MemCur / 1MB, 1); IoRateMBs = [math]::Round($st.IoRate / 1MB, 3); IoCumMB = [math]::Round(($st.IoCumR + $st.IoCumW) / 1MB, 1) }
            }
            $rows | Export-Csv -Path $Log -NoTypeInformation -Append -Encoding UTF8
        } catch {}
    }
}

function Get-Rows {
    $rows = if ($script:View -eq 'name') { $script:GroupRows } else { @($script:Procs.Values) }
    switch ($script:SortIdx) {
        0 { $rows = $rows | Sort-Object CpuCum -Descending }
        1 { $rows = $rows | Sort-Object CpuPct -Descending }
        2 { $rows = $rows | Sort-Object MemCur -Descending }
        3 { $rows = $rows | Sort-Object MemPeak -Descending }
        4 { $rows = $rows | Sort-Object { $_.IoCumR + $_.IoCumW } -Descending }
        5 { $rows = $rows | Sort-Object IoRate -Descending }
    }
    return @($rows)
}

# ═══════════════════════════════ frame ═══════════════════════════════

function Get-Size {
    if ($script:ForceWidth -gt 0) { return @($script:ForceWidth, 40) }
    try { $w = $Host.UI.RawUI.WindowSize.Width; $h = $Host.UI.RawUI.WindowSize.Height } catch { $w = 0; $h = 0 }
    if (-not $w -or $w -lt 60) { $w = 120 }; if (-not $h -or $h -lt 10) { $h = 40 }
    return @($w, $h)
}

function Build-Frame {
    $sb = New-Object System.Text.StringBuilder
    $EL = "$Esc[K"   # erase to end of line
    $size = Get-Size; $w = $size[0]; $h = $size[1]
    $line = { param($s) [void]$sb.Append($s).Append($EL).Append("`n") }
    $G = $script:G

    # ── title band ──
    $up = Format-Span ((Get-Date) - $script:StartedAt)
    $mode = if ($script:GraphMode) { 'GRAPHS' } else { 'LIST' }
    $by = if ($script:View -eq 'name') { 'by NAME' } else { 'by PID' }
    $left = " $($G.mark) PROCESS HOGS   $mode $($G.dot) $by $($G.dot) sort $($script:SortModes[$script:SortIdx]) $($G.dot) every $($script:IntervalSec)s"
    $right = "up $up "
    if ($script:Paused) { $right = "PAUSED  " + $right }
    if ($left.Length + $right.Length + 1 -gt $w) { $left = (Trunc $left ($w - $right.Length - 1)).TrimEnd() }
    $gap = $w - $left.Length - $right.Length; if ($gap -lt 1) { $gap = 1 }
    if ($script:UseColor) {
        $band = $script:Palette.band
        $pausedTxt = if ($script:Paused) { "$($script:Palette.amber)$Esc[48;2;16;42;50mPAUSED$band  " } else { '' }
        & $line ("$band" + " $($script:Palette.teal)$($G.mark)$band $($script:Palette.bold)PROCESS HOGS$Esc[0m$band   $mode $($G.dot) $by $($G.dot) sort $($script:SortModes[$script:SortIdx]) $($G.dot) every $($script:IntervalSec)s" + (' ' * $gap) + $pausedTxt + "up $up $Esc[0m")
    } else {
        & $line ($left + (' ' * $gap) + $right)
    }

    # ── system panel: three rows, gauge + value + sparkline ──
    $sysCpu = if ($script:Sys.CpuHist.Count) { $script:Sys.CpuHist[$script:Sys.CpuHist.Count - 1] } else { 0 }
    $ramFrac = if ($script:Sys.RamTotal) { $script:Sys.RamUsed / $script:Sys.RamTotal } else { 0 }
    $sysIo = if ($script:Sys.IoHist.Count) { $script:Sys.IoHist[$script:Sys.IoHist.Count - 1] } else { 0 }
    $ioMax = [math]::Max(10, (Max-Of $script:Sys.IoHist)); $ioFrac = $sysIo / $ioMax
    $gw = if ($w -ge 100) { 20 } else { 12 }
    $sw = [math]::Min(60, $w - 2 - 6 - $gw - 2 - 22 - 13); if ($sw -lt 10) { $sw = 10 }
    $ramTxt = (Format-Size $script:Sys.RamUsed) + ' / ' + (Format-Size $script:Sys.RamTotal)
    & $line ('  ' + (C dim 'CPU   ') + (Bar ($sysCpu / 100) $gw (Heat ($sysCpu / 100))) + '  ' + (C ink ('{0,-22}' -f ('{0:N1}%' -f $sysCpu))) + (Spark $script:Sys.CpuHist $sw 'teal'))
    & $line ('  ' + (C dim 'RAM   ') + (Bar $ramFrac $gw (Heat $ramFrac)) + '  ' + (C ink ('{0,-22}' -f $ramTxt)) + (Spark $script:Sys.RamHist $sw 'amber'))
    & $line ('  ' + (C dim 'DISK  ') + (Bar $ioFrac $gw 'blue') + '  ' + (C ink ('{0,-22}' -f ('{0:N1} MB/s' -f $sysIo))) + (Spark $script:Sys.IoHist $sw 'blue') + (C faint ('{0,12}' -f "$($script:Cores) cores")))
    & $line (' ' + (Rule ($w - 2)))

    $rows = Get-Rows

    if ($script:GraphMode) {
        # ── graph grid: rank, name, three sparkline columns with now/max ──
        $nameW = [math]::Max(14, [math]::Min(24, [math]::Floor($w / 5)))
        $avail = $w - 2 - 4 - $nameW - 1                                # what the three graph columns share
        $gW = [math]::Floor(($avail - 36) / 3); if ($gW -lt 6) { $gW = 6 }   # each column: graph + " now/max"(10) + " │ "(3), no trailing sep
        $hdr = ('  ' + (C dim ('{0,3} ' -f '#')) + (C dim (('{0,-' + $nameW + '} ') -f 'PROCESS')))
        $titles = @('CPU %  now/max', 'MEMORY  now/max', 'DISK MB/s  now/max')
        for ($ci = 0; $ci -lt 3; $ci++) { $hdr += (C dim (('{0,-' + ($gW + 10) + '}') -f $titles[$ci])); if ($ci -lt 2) { $hdr += (C faint (' ' + $G.sep + ' ')) } }
        & $line $hdr
        $shown = 0
        foreach ($r in $rows) {
            if ($shown -ge $GraphTop) { break }
            if ($null -eq $r.CpuHist) { continue }
            $shown++
            $label = if ($script:View -eq 'name') { "$($r.Name) $($G.times)$($r.Count)" } else { "$($r.Name) [$($r.Pid)]" }
            $nc = if ($r.Alive) { 'ink' } else { 'faint' }
            $cpuMax = Max-Of $r.CpuHist; $memMax = Max-Of $r.MemHist; $ioMx = Max-Of $r.IoHist
            $row = '  ' + (C faint ('{0,3} ' -f $shown)) + (C $nc (Trunc $label $nameW)) + ' '
            $row += (Spark $r.CpuHist $gW 'teal')  + ' ' + (C ink (Cell4 $r.CpuPct 'pct')) + (C faint ('/' + (Cell4 $cpuMax 'pct'))) + (C faint (' ' + $G.sep + ' '))
            $row += (Spark $r.MemHist $gW 'amber') + ' ' + (C ink (Cell4 ($r.MemCur / 1MB) 'mb')) + (C faint ('/' + (Cell4 $memMax 'mb'))) + (C faint (' ' + $G.sep + ' '))
            $row += (Spark $r.IoHist $gW 'blue')   + ' ' + (C ink (Cell4 ($r.IoRate / 1MB) 'rate')) + (C faint ('/' + (Cell4 $ioMx 'rate')))
            & $line $row
        }
        if ($shown -eq 0) { & $line ('  ' + (C dim ('collecting' + $G.ell))) }
        & $line ('  ' + (C faint ("each graph: the last $gW samples, scaled to that row's own maximum; now/max beside it")))
    }
    else {
        # ── list: rank, name, cpu now, cpu time, share gauge, trend, mem, peak, io ──
        $showIo = $script:IoAvailable -and $w -ge 118
        $showTrend = $w -ge 100
        $showPeak = $w -ge 90
        $fixed = 2 + 4 + 7 + 8 + 16 + 8 + $(if ($showTrend) { 9 } else { 0 }) + $(if ($showPeak) { 8 } else { 0 }) + $(if ($showIo) { 28 } else { 0 })
        $nameW = [math]::Max(14, [math]::Min(32, $w - $fixed))
        $hdr = '  ' + (C dim ('{0,3} ' -f '#')) + (C dim (('{0,-' + $nameW + '} ') -f 'PROCESS')) + (C dim ('{0,6} ' -f 'CPU%')) + (C dim ('{0,7} ' -f 'CPU⏱')) + (C dim ('{0,-15} ' -f 'SHARE OF CPU⏱'))
        if ($showTrend) { $hdr += (C dim ('{0,-8} ' -f 'TREND')) }
        $hdr += (C dim ('{0,7} ' -f 'MEM'))
        if ($showPeak) { $hdr += (C dim ('{0,7} ' -f 'PEAK')) }
        if ($showIo) { $hdr += (C dim ('{0,8} {1,8} {2,9}' -f 'IO READ', 'IO WRITE', 'IO NOW')) }
        if (-not $script:UseGlyphs) { $hdr = $hdr -replace 'CPU⏱', 'CPU t' }
        & $line $hdr
        $maxRows = [math]::Min($Top, $h - 10)
        $totalCpuCum = 0.0; foreach ($r in $rows) { $totalCpuCum += $r.CpuCum }
        $shown = 0
        foreach ($r in $rows) {
            if ($shown -ge $maxRows) { break }
            $shown++
            $label = if ($script:View -eq 'name') { "$($r.Name) $($G.times)$($r.Count)" } else { "$($r.Name) [$($r.Pid)]" }
            $nc = if ($r.Alive) { 'ink' } else { 'faint' }
            $rank = if ($r.Alive) { (C faint ('{0,3} ' -f $shown)) } else { (C rose ('{0,2}{1} ' -f $shown, $G.dead)) }
            $share = if ($totalCpuCum) { $r.CpuCum / $totalCpuCum } else { 0 }
            $cpuCol = if ($r.CpuPct -ge 50) { 'rose' } elseif ($r.CpuPct -ge 15) { 'amber' } else { 'ink' }
            $row = '  ' + $rank + (C $nc (Trunc $label $nameW)) + ' ' + (C $cpuCol ('{0,6:N1}' -f $r.CpuPct)) + ' ' + (C ink ('{0,7}' -f (Format-Secs $r.CpuCum))) + ' ' + (Bar $share 10 'teal') + (C dim ('{0,4:P0}' -f $share)) + ' '
            if ($showTrend) { $row += (Spark $r.CpuHist 8 'teal') + ' ' }
            $row += (C ink ('{0,7}' -f (Format-Size $r.MemCur))) + ' '
            if ($showPeak) { $row += (C dim ('{0,7}' -f (Format-Size $r.MemPeak))) + ' ' }
            if ($showIo) { $row += (C ink ('{0,8}' -f (Format-Size $r.IoCumR))) + ' ' + (C ink ('{0,8}' -f (Format-Size $r.IoCumW))) + ' ' + (C blue ('{0,9}' -f ('{0:N1} MB/s' -f ($r.IoRate / 1MB)))) }
            & $line $row
        }
        if ($shown -eq 0) { & $line ('  ' + (C dim ('collecting' + $G.ell))) }
        $note = if ($script:IoAvailable -and -not $showIo) { 'widen the window to see disk I/O' } elseif (-not $script:IoAvailable) { 'disk I/O counters unavailable: ' + $script:IoError } else { $G.dead + ' = exited, kept because its totals still count' }
        & $line ('  ' + (C faint $note))
    }

    # ── footer ──
    & $line (' ' + (Rule ($w - 2)))
    & $line ('  ' + (Keycap 'q' 'quit') + '  ' + (Keycap 'g' 'graphs') + '  ' + (Keycap 'n' 'name/pid') + '  ' + (Keycap 's' 'sort') + '  ' + (Keycap 'p' 'pause') + '  ' + (Keycap 'r' 'reset') + '  ' + (Keycap '+ -' 'speed'))
    [void]$sb.Append("$Esc[J")   # clear anything below
    return $sb.ToString()
}

# ═══════════════════════════════ boxes, menu, errors ═══════════════════════════════

function Box-Top { param([string]$Title, [int]$W) $t = " $Title "; return ('  ' + (C teal ($script:G.tl + $script:G.rule)) + (C bold (C ink $t)) + (C teal ($script:G.rule * ($W - 3 - $t.Length) + $script:G.tr))) }
function Box-Row { param([string]$Text, [int]$W) return ('  ' + (C teal $script:G.sep) + ' ' + (PadTo $Text ($W - 4)) + ' ' + (C teal $script:G.sep)) }
function Box-Bottom { param([int]$W) return ('  ' + (C teal ($script:G.bl + ($script:G.rule * ($W - 2)) + $script:G.br))) }

function Ask {
    # Ask <step> <question> <default> [<options>]  → the answer, or the default on Enter
    param([string]$Step, [string]$Prompt, [string]$Default = '', [string[]]$Options = @())
    Write-Host ''
    Write-Host ('  ' + (C teal $Step) + '  ' + (C bold (C ink $Prompt)) + $(if ($Default -ne '') { (C dim "   Enter = $Default") } else { (C dim '   Enter = skip') }))
    foreach ($o in $Options) { Write-Host ('       ' + $o) }
    Write-Host ('       ' + (C teal $script:G.prompt) + ' ') -NoNewline
    $r = Read-Host
    if ([string]::IsNullOrWhiteSpace($r)) { return $Default }
    return $r.Trim()
}
function Opt { param([string]$Key, [string]$Name, [string]$Note = '') return ((C amber $Key) + '  ' + (C ink ('{0,-16}' -f $Name)) + (C dim $Note)) }

function Wait-Close {
    # only when asked to (-Hold): the elevated relaunch opens its own window, which would close on exit
    if (-not $Hold) { return }
    Write-Host ('  ' + (C dim 'Press any key to close this window.'))
    try { [void][Console]::ReadKey($true) } catch { try { [void](Read-Host) } catch {} }
}

function Show-Failure {
    param($Err)
    $msg = "$($Err.Exception.Message)"; $me = $PSCommandPath; $W = 76
    Write-Host ''
    Write-Host (Box-Top 'The monitor stopped' $W)
    Write-Host (Box-Row ((C rose ($script:G.err + ' ')) + (C ink (Trunc $msg ($W - 8)))) $W)
    Write-Host (Box-Row '' $W)
    if ($msg -match 'ReadKey|KeyAvailable|not supported|redirected|console') {
        Write-Host (Box-Row ((C amber '1 ') + (C ink 'This needs a real console: Windows Terminal or a PowerShell window,')) $W)
        Write-Host (Box-Row ((C ink '   not the ISE, the VS Code output pane, or a redirected shell.')) $W)
        Write-Host (Box-Row ((C amber '2 ') + (C ink 'Or double-click ') + (C teal 'Run-ProcessHogs.cmd') + (C ink ', which opens its own window.')) $W)
    }
    elseif ($msg -match 'Add-Type|compil|csc') {
        Write-Host (Box-Row ((C amber '1 ') + (C ink 'The disk I/O helper could not compile; it should have fallen back. Report:')) $W)
        Write-Host (Box-Row ((C teal ('   ' + (Trunc $msg ($W - 10))))) $W)
    }
    elseif ($msg -match 'Access is denied|PermissionDenied') {
        Write-Host (Box-Row ((C amber '1 ') + (C ink 'Re-run elevated to read every process:')) $W)
        Write-Host (Box-Row ((C teal ("   Start-Process powershell -Verb RunAs -ArgumentList '-ExecutionPolicy Bypass -File `"$me`" -Interactive'"))) $W)
    }
    elseif ($msg -match 'not digitally signed|execution polic') {
        Write-Host (Box-Row ((C amber '1 ') + (C teal "Unblock-File `"$me`"") + (C ink '   or double-click Run-ProcessHogs.cmd')) $W)
    }
    else {
        Write-Host (Box-Row ((C amber '1 ') + (C ink 'The combination that works on almost any machine:')) $W)
        Write-Host (Box-Row ((C teal "   powershell -NoProfile -ExecutionPolicy Bypass -File `"$me`" -NoColor -Ascii -Interactive")) $W)
    }
    Write-Host (Box-Row '' $W)
    Write-Host (Box-Row (C faint ('at: ' + (Trunc (("$($Err.InvocationInfo.PositionMessage)" -replace '\s+', ' ')) ($W - 10)))) $W)
    Write-Host (Box-Bottom $W)
    Write-Host ''
}

function Invoke-Menu {
    param($IsAdmin, $Me)
    $W = 72; $G = $script:G
    Write-Host ''
    Write-Host (Box-Top 'PROCESS HOGS' $W)
    Write-Host (Box-Row ((C ink 'Live process monitor that counts CPU time, memory and disk I/O')) $W)
    Write-Host (Box-Row ((C ink 'cumulatively from the moment it starts.  Read-only.')) $W)
    Write-Host (Box-Row '' $W)
    Write-Host (Box-Row ((C dim ('Four questions. Press Enter to accept the default shown after each one.'))) $W)
    Write-Host (Box-Bottom $W)
    if (-not $IsAdmin) {
        Write-Host ''
        Write-Host ('  ' + (C amber ($G.warn + ' Not running as Administrator.')) + (C dim '  CPU time and disk I/O of system and other users'' processes will read as zero.'))
        $e = Ask 'Admin' 'Relaunch as Administrator now?' 'y' @((Opt 'y' 'yes' 'opens an elevated window, this one closes'), (Opt 'n' 'no' 'continue here with what is visible'))
        if ($e -match '^y') {
            $argLine = "-NoProfile -ExecutionPolicy Bypass -File `"$Me`" -Interactive -Hold"
            if (-not $script:UseColor) { $argLine += ' -NoColor' }
            if (-not $script:UseGlyphs) { $argLine += ' -Ascii' }
            try { Start-Process powershell -Verb RunAs -ArgumentList $argLine; Restore-Console; exit 0 }
            catch { Write-Host ('  ' + (C dim 'Elevation was cancelled — continuing without it.')) }
        }
    }
    $v = Ask '1/4' 'View' '2' @((Opt '1' 'List by PID' 'every process its own row'), (Opt '2' 'List by name' "chrome $($G.times)38 is one row"), (Opt '3' 'Graphs by PID' 'top 10, a sparkline per resource'), (Opt '4' 'Graphs by name' ''))
    switch ($v) {
        '1' { $script:View = 'pid';  $script:GraphMode = $false }
        '3' { $script:View = 'pid';  $script:GraphMode = $true }
        '4' { $script:View = 'name'; $script:GraphMode = $true }
        default { $script:View = 'name'; $script:GraphMode = $false }
    }
    $i = Ask '2/4' 'Refresh interval, in seconds' "$($script:IntervalSec)" @((C dim '0.25 to 10; + and - change it while running'))
    $parsed = 0.0; if ([double]::TryParse($i, [ref]$parsed) -and $parsed -ge 0.25) { $script:IntervalSec = [math]::Min(10, $parsed) }
    $d = Ask '3/4' 'Stop automatically after how many seconds?' '' @((C dim 'blank = run until you press q'))
    $pd = 0; if ([int]::TryParse($d, [ref]$pd) -and $pd -gt 0) { $script:Duration = $pd } else { $script:Duration = 0 }
    $l = Ask '4/4' 'Log every sample to a CSV file?' '' @((C dim 'a path such as .\samples.csv; blank = no log'))
    if ($l) { $script:Log = $l }
    Write-Host ''
    Write-Host ('  ' + (C teal ($G.ok + ' ')) + (C ink 'Starting.') + (C dim '  q stops it, g switches to graphs, n switches name/PID, s changes the sort.'))
    Start-Sleep -Milliseconds 900
}

# ═══════════════════════════════ main ═══════════════════════════════

$script:Duration = $Duration; $script:Log = $Log
$cursorHidden = $false
try {
    $IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    $gave = $false
    foreach ($a in @('Interval', 'Top', 'GraphTop', 'ByName', 'Graph', 'Duration', 'Log')) { if ($PSBoundParameters.ContainsKey($a)) { $gave = $true } }
    if ($Interactive -or -not $gave) { Invoke-Menu -IsAdmin $IsAdmin -Me $PSCommandPath }
    $Log = $script:Log

    # console sanity
    try { [void][Console]::KeyAvailable } catch { throw 'ReadKey/KeyAvailable is not supported in this host — a real console is required.' }

    if ($script:UseColor) { [Console]::Write("$Esc[?25l"); $cursorHidden = $true }
    [Console]::Write("$Esc[2J$Esc[H")

    Take-Sample   # prime
    $stopAt = if ($script:Duration -gt 0) { (Get-Date).AddSeconds($script:Duration) } else { $null }
    $running = $true
    while ($running) {
        if (-not $script:Paused) { Take-Sample }
        [Console]::Write("$Esc[H" + (Build-Frame))

        $deadline = (Get-Date).AddSeconds($script:IntervalSec)
        while ((Get-Date) -lt $deadline) {
            if ([Console]::KeyAvailable) {
                $k = [Console]::ReadKey($true)
                switch ($k.KeyChar) {
                    'q' { $running = $false; break }
                    'g' { $script:GraphMode = -not $script:GraphMode }
                    'n' { $script:View = if ($script:View -eq 'name') { 'pid' } else { 'name' } }
                    's' { $script:SortIdx = ($script:SortIdx + 1) % $script:SortModes.Count }
                    'p' { $script:Paused = -not $script:Paused }
                    'r' { Reset-Cumulative }
                    '+' { $script:IntervalSec = [math]::Min(10, $script:IntervalSec + 0.5) }
                    '=' { $script:IntervalSec = [math]::Min(10, $script:IntervalSec + 0.5) }
                    '-' { $script:IntervalSec = [math]::Max(0.25, $script:IntervalSec - 0.5) }
                }
                if (-not $running) { break }
                [Console]::Write("$Esc[H" + (Build-Frame))   # redraw immediately on key
            }
            Start-Sleep -Milliseconds 60
        }
        if ($stopAt -and (Get-Date) -ge $stopAt) { $running = $false }
    }
}
catch {
    if ($cursorHidden) { [Console]::Write("$Esc[?25h$Esc[0m") }
    Show-Failure $_
    Wait-Close
    Restore-Console
    exit 1
}
finally {
    if ($cursorHidden) { [Console]::Write("$Esc[?25h$Esc[0m") }
}

# final static summary so it survives in scroll-back
$up = (Get-Date) - $script:StartedAt
$W = 76
Write-Host ''
Write-Host (Box-Top ('Stopped after ' + (Format-Span $up) + "  $($script:G.dot)  $($script:Ticks) samples") $W)
Write-Host (Box-Row ((C dim ('{0,-28} {1,8} {2,9} {3,9}' -f 'top 5 by cumulative CPU', 'CPU time', 'peak mem', 'disk I/O'))) $W)
foreach ($r in ($script:Procs.Values | Sort-Object CpuCum -Descending | Select-Object -First 5)) {
    Write-Host (Box-Row ((C ink (Trunc "$($r.Name) [$($r.Pid)]" 28)) + ' ' + (C teal ('{0,8}' -f (Format-Secs $r.CpuCum))) + ' ' + (C amber ('{0,9}' -f (Format-Size $r.MemPeak))) + ' ' + (C blue ('{0,9}' -f (Format-Size ($r.IoCumR + $r.IoCumW))))) $W)
}
if ($Log) { Write-Host (Box-Row (C dim ('log: ' + $Log)) $W) }
Write-Host (Box-Bottom $W)
Write-Host ''
Wait-Close
Restore-Console

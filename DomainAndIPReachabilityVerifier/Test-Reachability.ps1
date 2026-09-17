#Requires -Version 5.1
<#
.SYNOPSIS
    Test-Reachability — pull every IP and domain out of a messy text or CSV file and check if you can reach them.

.DESCRIPTION
    Reads a .txt (one entry per line, or free text) or a .csv (any columns), extracts every
    IPv4, IPv6 and domain name it can find — even inside URLs, emails, log lines, "defanged"
    indicators like hxxp://evil[.]com, or host:port pairs — de-duplicates them, then tests
    each one on the ports you choose (default 80 and 443) with parallel TCP connects.

    For every target you get: DNS resolution, and per port: OPEN with latency, REFUSED,
    TIMEOUT, or no route. Optional ICMP ping. Results go to the screen and, if you want, a CSV.

    A host:port found in the file (e.g. 10.0.0.5:8443) is tested on that port too, automatically.

    Nothing is sent beyond a TCP handshake (and an ICMP echo if you ask for it). No HTTP requests,
    no banners, no data.

.PARAMETER Path        The .txt or .csv to read.
.PARAMETER Port        Ports to test. Default 80,443.
.PARAMETER Timeout     Seconds to wait per connection. Default 3.
.PARAMETER Concurrency Parallel connections in flight. Default 64.
.PARAMETER Ping        Also send an ICMP echo to each resolved address.
.PARAMETER ExportCsv   Write results here.
.PARAMETER ShowSources Print which line(s) each target came from.
.PARAMETER NoColor     Plain output.
.PARAMETER Interactive Force the menu.

.EXAMPLE
    .\Test-Reachability.ps1                              # menu: asks for the file and ports
    .\Test-Reachability.ps1 -Path .\iocs.txt
    .\Test-Reachability.ps1 -Path .\hosts.csv -Port 22,443,3389 -Ping -ExportCsv .\reach.csv

.NOTES
    Works without elevation. Firewalls and proxies between you and the target affect results —
    TIMEOUT usually means a firewall drops the packet, REFUSED means the host answered "nothing here".
    If Windows refuses to run it: Unblock-File .\Test-Reachability.ps1, or use Run-Reachability.cmd.
#>
[CmdletBinding()]
param(
    [string]$Path,
    [int[]]$Port,
    [double]$Timeout = 3,
    [int]$Concurrency = 64,
    [switch]$Ping,
    [string]$ExportCsv,
    [switch]$ShowSources,
    [switch]$NoColor,
    [switch]$Interactive
)

# ═══════════════════════════════ rendering ═══════════════════════════════

$script:Esc = [char]27
$script:UseColor = (-not $NoColor) -and ($Host.UI.SupportsVirtualTerminal -or $env:WT_SESSION -or $PSVersionTable.PSVersion.Major -ge 7)
function C { param([string]$Name, [string]$Text)
    if (-not $script:UseColor) { return $Text }
    $map = @{ teal = "$Esc[38;2;47;217;197m"; amber = "$Esc[38;2;240;165;60m"; rose = "$Esc[38;2;255;107;94m"; dim = "$Esc[38;2;95;128;146m"; faint = "$Esc[38;2;60;87;102m"; ink = "$Esc[38;2;214;233;240m"; bold = "$Esc[1m"; violet = "$Esc[38;2;170;140;255m" }
    return "$($map[$Name])$Text$Esc[0m" }
function Get-Width { try { $w = $Host.UI.RawUI.WindowSize.Width } catch { $w = 0 }; if (-not $w -or $w -lt 40) { $w = 120 }; return [math]::Max(80, [math]::Min(160, $w - 2)) }
function Section { param([string]$Title, [string]$Tag = '') $w = Get-Width; Write-Host ''; Write-Host ('  ' + (C teal '┌─ ') + (C bold (C ink $Title)) + ' ' + (C faint ('─' * [math]::Max(4, $w - $Title.Length - 6))) + (C dim $Tag)) }
function Trunc { param([string]$S, [int]$N) if ($null -eq $S) { $S = '' }; if ($S.Length -le $N) { return $S.PadRight($N) }; return ($S.Substring(0, $N - 1) + '…') }
function Ask { param([string]$Prompt, [string]$Default = '') $s = if ($Default -ne '') { (C dim " [$Default]") } else { '' }; Write-Host ('  ' + (C teal '?') + ' ' + (C ink $Prompt) + $s + ' ') -NoNewline; $r = Read-Host; if ([string]::IsNullOrWhiteSpace($r)) { return $Default }; return $r.Trim().Trim('"', "'") }

# ═══════════════════════════════ extraction ═══════════════════════════════

$script:KnownTld = @{}
foreach ($t in ('com net org edu gov mil int arpa io dev app ai co info biz me tv cc xyz cloud online site tech store shop blog news email network systems solutions services digital software agency company global group live media space today top club win vip pro museum name mobi asia cat jobs tel travel xxx aero coop post security cyber tools zone host link click download page web world one run team life works studio design center city expert guru ninja rocks fund money finance bank insurance health care clinic doctor dental legal law tax cash trade market sale deals bargains discount codes coupon gift gifts toys games game play fun party events wedding photo photos pictures video film movie music audio radio fm tube chat social community forum wiki review reviews ratings directory guide help support training academy school college university education institute science research lab labs data analytics ninja cloud server hosting domains email mail app apps mobile phone computer pc software hardware tech technology engineering construction builders repair plumbing electric energy solar green eco farm garden pizza cafe restaurant bar pub wine beer coffee kitchen food recipes fitness gym yoga sport sports football golf tennis bike ski surf boats cars auto moto rent rental taxi flights hotel holiday vacation travel tours cruises casino bet poker lotto ltd llc inc gmbh plc srl sarl'.Split(' '))) { $script:KnownTld[$t] = 1 }
# 2-letter TLDs are all valid ccTLDs; these collide with common file extensions and are skipped when the candidate is a bare "name.ext"
$script:ExtCollide = @{ md = 1; sh = 1; py = 1; pl = 1; rs = 1; ps = 1; so = 1; cs = 1; gz = 1; db = 1; js = 1; ts = 1; rb = 1; go = 1; vb = 1 }

$script:RxIPv4   = [regex]'(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])'
$script:RxIPv6   = [regex]'(?i)(?<![:\w])(?:[0-9a-f]{1,4}:){2,7}(?::|[0-9a-f]{1,4})(?:%\d+)?(?![:\w])|(?<![:\w])::(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4}(?![:\w])'
$script:RxDomain = [regex]'(?i)(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:xn--[a-z0-9-]{2,59}|[a-z]{2,24})(?![\w-])'
$script:RxPort   = [regex]'^(.+?):(\d{1,5})$'

function Normalize-Line {
    param([string]$L)
    $s = $L
    $s = $s -replace '(?i)hxxps?://', 'http://'
    $s = $s -replace '(?i)\[\s*(?:\.|dot)\s*\]|\(\s*(?:\.|dot)\s*\)|\{\s*(?:\.|dot)\s*\}', '.'
    $s = $s -replace '(?i)\[\s*:\s*\]|\(\s*:\s*\)', ':'
    $s = $s -replace '(?i)\[\s*(?:@|at)\s*\]', '@'
    $s = $s -replace '\\\.', '.'
    $s = $s -replace '(?i)\bwww\s+dot\s+', 'www.'
    return $s
}

function Get-Targets {
    # returns hashtable: key(lowercase host) → @{ Host; Type; Lines=list; Ports=set }
    param([string[]]$Lines)
    $t = @{}
    $ln = 0
    foreach ($raw in $Lines) {
        $ln++
        if ([string]::IsNullOrWhiteSpace($raw)) { continue }
        $line = Normalize-Line $raw
        $found = @()

        foreach ($m in $script:RxIPv4.Matches($line)) { $found += @{ Host = $m.Value; Type = 'ipv4'; Idx = $m.Index; Len = $m.Length } }
        foreach ($m in $script:RxIPv6.Matches($line)) {
            $ip = $null
            if ($m.Value -match '::' -or ($m.Value.Split(':').Count -eq 8)) {
                if ([System.Net.IPAddress]::TryParse($m.Value, [ref]$ip) -and $ip.AddressFamily -eq 'InterNetworkV6') { $found += @{ Host = $m.Value; Type = 'ipv6'; Idx = $m.Index; Len = $m.Length } }
            }
        }
        foreach ($m in $script:RxDomain.Matches($line)) {
            $d = $m.Value.ToLowerInvariant().TrimEnd('.')
            # skip if this span is inside an IPv4 match (e.g. 10.0.0.1 also matches the domain regex loosely)
            $inside = $false; foreach ($f in $found) { if ($f.Type -eq 'ipv4' -and $m.Index -ge $f.Idx -and $m.Index -lt ($f.Idx + $f.Len)) { $inside = $true; break } }
            if ($inside) { continue }
            $labels = $d.Split('.'); $tld = $labels[-1]
            if ($tld -match '^\d+$') { continue }
            $ok = $false
            if ($tld.StartsWith('xn--')) { $ok = $true }
            elseif ($script:KnownTld.ContainsKey($tld)) { $ok = $true }
            elseif ($tld.Length -eq 2) { $ok = -not ($script:ExtCollide.ContainsKey($tld) -and $script:ExtCollide[$tld] -eq 1 -and $labels.Count -eq 2) }
            if (-not $ok) { continue }
            if ($labels.Count -eq 2 -and $labels[0] -match '^(localhost|example|test|invalid)$') { continue }
            $found += @{ Host = $d; Type = 'domain'; Idx = $m.Index; Len = $m.Length }
        }

        foreach ($f in $found) {
            $key = $f.Host.ToLowerInvariant()
            $e = $t[$key]
            if (-not $e) { $e = @{ Host = $f.Host; Type = $f.Type; Lines = New-Object 'System.Collections.Generic.List[int]'; Ports = @{} }; $t[$key] = $e }
            if (-not $e.Lines.Contains($ln)) { $e.Lines.Add($ln) }
            # host:port right after the match?
            $after = $line.Substring($f.Idx + $f.Len)
            if ($f.Type -eq 'ipv6') { if ($after -match '^\]:(\d{1,5})') { $p = [int]$matches[1]; if ($p -ge 1 -and $p -le 65535) { $e.Ports[$p] = 1 } } }
            elseif ($after -match '^:(\d{1,5})(?![\d.])') { $p = [int]$matches[1]; if ($p -ge 1 -and $p -le 65535) { $e.Ports[$p] = 1 } }
        }
    }
    return $t
}

function Test-PrivateIp {
    param([System.Net.IPAddress]$Ip)
    if ($Ip.AddressFamily -eq 'InterNetwork') {
        $b = $Ip.GetAddressBytes()
        if ($b[0] -eq 10 -or $b[0] -eq 127 -or ($b[0] -eq 192 -and $b[1] -eq 168) -or ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or ($b[0] -eq 169 -and $b[1] -eq 254) -or $b[0] -ge 224 -or $b[0] -eq 0) { return $true }
        return $false
    }
    return ($Ip.IsIPv6LinkLocal -or $Ip.IsIPv6SiteLocal -or [System.Net.IPAddress]::IPv6Loopback.Equals($Ip) -or $Ip.ToString().StartsWith('fc') -or $Ip.ToString().StartsWith('fd'))
}

# ═══════════════════════════════ testing ═══════════════════════════════

function Invoke-Batch {
    # Generic async runner: $Items each get a task via $Start; result via $Finish(item, task, elapsedMs)
    param($Items, [scriptblock]$Start, [scriptblock]$Finish, [double]$TimeoutSec, [int]$Parallel, [string]$Activity)
    $pending = New-Object 'System.Collections.Generic.List[object]'
    $queue = New-Object 'System.Collections.Generic.Queue[object]'; foreach ($i in $Items) { $queue.Enqueue($i) }
    $total = $Items.Count; $done = 0
    while ($queue.Count -gt 0 -or $pending.Count -gt 0) {
        while ($pending.Count -lt $Parallel -and $queue.Count -gt 0) {
            $it = $queue.Dequeue()
            $task = $null; try { $task = & $Start $it } catch { $task = $null }
            $pending.Add(@{ Item = $it; Task = $task; Sw = [Diagnostics.Stopwatch]::StartNew() })
        }
        Start-Sleep -Milliseconds 40
        $still = New-Object 'System.Collections.Generic.List[object]'
        foreach ($p in $pending) {
            $t = $p.Task
            if ($null -eq $t) { & $Finish $p.Item $null 0 'error'; $done++; continue }
            if ($t.IsCompleted) { $p.Sw.Stop(); & $Finish $p.Item $t $p.Sw.Elapsed.TotalMilliseconds 'done'; $done++; continue }
            if ($p.Sw.Elapsed.TotalSeconds -ge $TimeoutSec) { $p.Sw.Stop(); & $Finish $p.Item $t $p.Sw.Elapsed.TotalMilliseconds 'timeout'; $done++; continue }
            $still.Add($p)
        }
        $pending = $still
        if ($total) { Write-Progress -Activity $Activity -Status ("{0} / {1} · {2} in flight" -f $done, $total, $pending.Count) -PercentComplete ([int](100 * $done / $total)) }
    }
    Write-Progress -Activity $Activity -Completed
}

# ═══════════════════════════════ error guidance ═══════════════════════════════

function Show-Failure {
    param($Err)
    $msg = "$($Err.Exception.Message)"; $me = $PSCommandPath
    Write-Progress -Activity ' ' -Completed
    Write-Host ''; Write-Host ('  ' + (C rose '✖ The script stopped.') + '  ' + (C dim (Trunc $msg 100))); Write-Host ''
    Write-Host ('  ' + (C bold (C ink 'What to try:')))
    if ($msg -match 'Cannot find path|does not exist|could not find|not found') {
        Write-Host ('  ' + (C teal '1.') + ' ' + (C ink 'The input file was not found. Drag the file onto the window to paste its full path, or run:'))
        Write-Host ('       ' + (C amber "& `"$me`" -Path 'C:\full\path\to\file.txt'"))
    }
    elseif ($msg -match 'No IPs or domains') {
        Write-Host ('  ' + (C teal '1.') + ' ' + (C ink 'Nothing extractable in that file. Check it is text (not a PDF/Excel binary) and contains hosts, IPs or URLs.'))
        Write-Host ('  ' + (C teal '2.') + ' ' + (C ink 'For .xlsx, save as CSV first.'))
    }
    elseif ($msg -match 'not digitally signed|execution polic') {
        Write-Host ('  ' + (C teal '1.') + ' ' + (C amber "Unblock-File `"$me`"") + (C ink '   or use Run-Reachability.cmd'))
    }
    elseif ($msg -match 'port') {
        Write-Host ('  ' + (C teal '1.') + ' ' + (C ink 'Ports must be 1–65535, comma-separated, e.g. ') + (C amber '-Port 80,443,8443'))
    }
    else {
        Write-Host ('  ' + (C teal '1.') + ' ' + (C ink 'The combination that works on almost any machine:'))
        Write-Host ('       ' + (C amber "powershell -NoProfile -ExecutionPolicy Bypass -File `"$me`" -NoColor -Interactive"))
    }
    Write-Host ''; Write-Host ('  ' + (C dim ('at: ' + ("$($Err.InvocationInfo.PositionMessage)" -replace '\s+', ' ')))); Write-Host ''
}

# ═══════════════════════════════ menu ═══════════════════════════════

function Invoke-Menu {
    Write-Host ''; Write-Host ('  ' + (C teal '▌') + ' ' + (C bold (C ink 'REACHABILITY')) + '  ' + (C dim 'interactive setup — Enter accepts the default')); Write-Host ''
    if (-not $script:Cfg.Path) {
        do { $p = Ask 'File to read (.txt or .csv — drag it here to paste the path)' ''; if ($p -and -not (Test-Path -LiteralPath $p)) { Write-Host ('  ' + (C amber '  not found: ') + (C dim $p)); $p = '' } } while (-not $p)
        $script:Cfg.Path = $p
    }
    $pt = Ask 'Ports to test (comma-separated)' (($script:Cfg.Port | ForEach-Object { $_ }) -join ',')
    $ports = @(); foreach ($x in ($pt -split '[,\s]+' | Where-Object { $_ })) { $n = 0; if ([int]::TryParse($x, [ref]$n) -and $n -ge 1 -and $n -le 65535) { $ports += $n } }
    if ($ports) { $script:Cfg.Port = $ports }
    $to = Ask 'Timeout per connection (seconds)' "$($script:Cfg.Timeout)"; $d = 0.0; if ([double]::TryParse($to, [ref]$d) -and $d -gt 0) { $script:Cfg.Timeout = $d }
    $pg = Ask 'Also ICMP ping each address? (y/n)' 'n'; $script:Cfg.Ping = ($pg -match '^y')
    $ss = Ask 'Show which lines each target came from? (y/n)' 'n'; $script:Cfg.ShowSources = ($ss -match '^y')
    $cs = Ask 'Export results to CSV? (path, blank to skip)' ''; if ($cs) { $script:Cfg.ExportCsv = $cs }
    Write-Host ''
}

# ═══════════════════════════════ main ═══════════════════════════════

$script:Cfg = @{ Path = $Path; Port = $(if ($Port) { @($Port) } else { @(80, 443) }); Timeout = $Timeout; Ping = [bool]$Ping; ShowSources = [bool]$ShowSources; ExportCsv = $ExportCsv }
try {
    $gave = $false; foreach ($a in @('Path', 'Port', 'Timeout', 'Ping', 'ExportCsv', 'ShowSources', 'Concurrency')) { if ($PSBoundParameters.ContainsKey($a)) { $gave = $true } }
    if ($Interactive -or -not $gave -or -not $script:Cfg.Path) { Invoke-Menu }
    $cfg = $script:Cfg
    foreach ($p in $cfg.Port) { if ($p -lt 1 -or $p -gt 65535) { throw "Invalid port $p" } }
    if (-not (Test-Path -LiteralPath $cfg.Path)) { throw "Cannot find path '$($cfg.Path)'." }

    # ── read & extract ──
    $lines = @(Get-Content -LiteralPath $cfg.Path -ErrorAction Stop)
    $targets = Get-Targets $lines
    if ($targets.Count -eq 0) { throw 'No IPs or domains were found in that file.' }
    $ipCount = @($targets.Values | Where-Object { $_.Type -ne 'domain' }).Count; $domCount = $targets.Count - $ipCount
    $extraPorts = @{}; foreach ($e in $targets.Values) { foreach ($p in $e.Ports.Keys) { $extraPorts[$p] = 1 } }

    Write-Host ''
    Write-Host ('  ' + (C teal '▌') + ' ' + (C bold (C ink 'REACHABILITY')) + '  ' + (C dim ((Split-Path $cfg.Path -Leaf) + " · $($lines.Count) lines · ports " + ($cfg.Port -join ',') + $(if ($extraPorts.Count) { ' +' + $extraPorts.Count + ' from file' } else { '' }) + " · timeout $($cfg.Timeout)s · " + (Get-Date -Format 'yyyy-MM-dd HH:mm'))))
    Write-Host ('  ' + (C dim ("extracted $domCount domain(s) and $ipCount IP(s) — $($targets.Count) unique targets")))

    # ── DNS ──
    $rows = @{}
    foreach ($key in $targets.Keys) {
        $e = $targets[$key]
        $rows[$key] = [pscustomobject]@{ Host = $e.Host; Type = $e.Type; Lines = ($e.Lines -join ','); Addresses = @(); Dns = ''; DnsMs = 0; Private = $false; Ping = ''; PingMs = 0; Ports = @{}; PortOrder = @() }
    }
    $domains = @($targets.Values | Where-Object { $_.Type -eq 'domain' } | ForEach-Object { $_.Host })
    foreach ($e in ($targets.Values | Where-Object { $_.Type -ne 'domain' })) {
        $ip = $null; if ([System.Net.IPAddress]::TryParse($e.Host, [ref]$ip)) { $r = $rows[$e.Host.ToLowerInvariant()]; $r.Addresses = @($ip); $r.Dns = 'n/a'; $r.Private = Test-PrivateIp $ip }
    }
    if ($domains.Count) {
        Invoke-Batch -Items $domains -TimeoutSec ([math]::Max(2, $cfg.Timeout)) -Parallel $Concurrency -Activity 'Resolving domains' `
            -Start  { param($d) [System.Net.Dns]::GetHostAddressesAsync($d) } `
            -Finish { param($d, $t, $ms, $how)
                $r = $rows[$d.ToLowerInvariant()]; $r.DnsMs = [int]$ms
                if ($how -eq 'done' -and $t.Status -eq 'RanToCompletion' -and $t.Result.Count) { $r.Addresses = @($t.Result | Sort-Object { $_.AddressFamily -ne 'InterNetwork' }); $r.Dns = 'ok'; $r.Private = Test-PrivateIp $r.Addresses[0] }
                elseif ($how -eq 'timeout') { $r.Dns = 'timeout' } else { $r.Dns = 'NXDOMAIN' } }
    }

    # ── TCP ──
    $jobs = @()
    foreach ($key in $rows.Keys) {
        $r = $rows[$key]; if (-not $r.Addresses.Count) { continue }
        $ports = @($cfg.Port) + @($targets[$key].Ports.Keys) | Select-Object -Unique
        $r.PortOrder = @($ports)
        foreach ($p in $ports) { $jobs += @{ Key = $key; Ip = $r.Addresses[0]; Port = [int]$p } }
    }
    Invoke-Batch -Items $jobs -TimeoutSec $cfg.Timeout -Parallel $Concurrency -Activity 'Testing ports' `
        -Start  { param($j) $c = New-Object System.Net.Sockets.TcpClient($j.Ip.AddressFamily); $j.Client = $c; $c.ConnectAsync($j.Ip, $j.Port) } `
        -Finish { param($j, $t, $ms, $how)
            $r = $rows[$j.Key]; $res = ''
            if ($how -eq 'done') {
                if ($t.Status -eq 'RanToCompletion') { $res = 'open' }
                else {
                    $ex = $t.Exception; if ($ex -and $ex.InnerException) { $ex = $ex.InnerException }
                    $code = if ($ex -and $ex.PSObject.Properties['SocketErrorCode']) { "$($ex.SocketErrorCode)" } else { '' }
                    $res = switch -Regex ($code) { 'ConnectionRefused' { 'refused' } 'HostUnreachable|NetworkUnreachable' { 'no route' } 'TimedOut' { 'timeout' } default { 'error' } }
                }
            } elseif ($how -eq 'timeout') { $res = 'timeout' } else { $res = 'error' }
            $r.Ports[$j.Port] = @{ Result = $res; Ms = [int]$ms }
            try { if ($j.Client) { $j.Client.Close() } } catch {} }

    # ── ICMP ──
    if ($cfg.Ping) {
        $pj = @(); foreach ($key in $rows.Keys) { $r = $rows[$key]; if ($r.Addresses.Count) { $pj += @{ Key = $key; Ip = $r.Addresses[0] } } }
        Invoke-Batch -Items $pj -TimeoutSec $cfg.Timeout -Parallel $Concurrency -Activity 'Pinging' `
            -Start  { param($j) $p = New-Object System.Net.NetworkInformation.Ping; $j.Pinger = $p; $p.SendPingAsync($j.Ip, [int]($cfg.Timeout * 1000)) } `
            -Finish { param($j, $t, $ms, $how)
                $r = $rows[$j.Key]
                if ($how -eq 'done' -and $t.Status -eq 'RanToCompletion' -and $t.Result.Status -eq 'Success') { $r.Ping = 'reply'; $r.PingMs = [int]$t.Result.RoundtripTime } else { $r.Ping = 'no reply' }
                try { if ($j.Pinger) { $j.Pinger.Dispose() } } catch {} }
    }

    # ── report ──
    $w = Get-Width
    $allPorts = @($cfg.Port) + @($extraPorts.Keys) | Select-Object -Unique | Sort-Object
    Section 'RESULTS' ("  ✓ open · ✗ refused · ⏱ timeout · ∅ no route · dns✗ unresolved")
    $hostW = [math]::Max(24, [math]::Min(48, $w - 40 - 12 * $allPorts.Count))
    $hdr = ('  ' + (C dim (Trunc 'TARGET' $hostW)) + ' ' + (C dim ('{0,-16}' -f 'RESOLVED')) + $(if ($cfg.Ping) { (C dim ('{0,-10}' -f 'PING')) } else { '' }))
    foreach ($p in $allPorts) { $hdr += (C dim ('{0,-12}' -f (':' + $p))) }
    Write-Host $hdr
    $ordered = $rows.Values | Sort-Object @{ Expression = { $_.Type -ne 'domain' } }, Host
    $openCount = 0; $unreach = 0; $dnsFail = 0
    foreach ($r in $ordered) {
        $hostCol = if ($r.Type -eq 'domain') { 'ink' } else { 'violet' }
        $addr = if ($r.Dns -eq 'ok' -or $r.Dns -eq 'n/a') { $r.Addresses[0].ToString() } else { $r.Dns }
        if ($r.Private) { $addr += ' ⌂' }
        $addrCol = if ($r.Dns -eq 'ok' -or $r.Dns -eq 'n/a') { 'dim' } else { 'rose' }
        $lineTxt = ('  ' + (C $hostCol (Trunc $r.Host $hostW)) + ' ' + (C $addrCol (Trunc $addr 16)))
        if ($cfg.Ping) { $lineTxt += $(if ($r.Ping -eq 'reply') { (C teal (Trunc ('↔ ' + $r.PingMs + 'ms') 10)) } elseif ($r.Ping) { (C faint (Trunc '·' 10)) } else { (Trunc '' 10) }) }
        $anyOpen = $false
        foreach ($p in $allPorts) {
            if (-not $r.Addresses.Count) { $lineTxt += (C rose (Trunc 'dns✗' 12)); continue }
            if (-not $r.Ports.ContainsKey($p)) { $lineTxt += (C faint (Trunc '' 12)); continue }
            $pr = $r.Ports[$p]
            switch ($pr.Result) {
                'open'     { $lineTxt += (C teal  (Trunc ('✓ ' + $pr.Ms + 'ms') 12)); $anyOpen = $true }
                'refused'  { $lineTxt += (C amber (Trunc '✗ refused' 12)) }
                'timeout'  { $lineTxt += (C faint (Trunc '⏱ timeout' 12)) }
                'no route' { $lineTxt += (C rose  (Trunc '∅ no route' 12)) }
                default    { $lineTxt += (C rose  (Trunc '! error' 12)) }
            }
        }
        if (-not $r.Addresses.Count) { $dnsFail++ } elseif ($anyOpen) { $openCount++ } else { $unreach++ }
        Write-Host $lineTxt
        if ($cfg.ShowSources) { Write-Host ('    ' + (C faint ('↳ line ' + $r.Lines))) }
    }

    Section 'SUMMARY'
    Write-Host ('  ' + (C teal '■ ') + (C ink ("{0,4}" -f $openCount)) + (C dim '  reachable on at least one tested port'))
    Write-Host ('  ' + (C amber '■ ') + (C ink ("{0,4}" -f $unreach)) + (C dim '  resolved but nothing open on the tested ports'))
    Write-Host ('  ' + (C rose '■ ') + (C ink ("{0,4}" -f $dnsFail)) + (C dim '  did not resolve'))
    Write-Host ('  ' + (C dim '⌂ marks private/reserved addresses. TIMEOUT usually means a firewall dropped the packet; REFUSED means the host answered but nothing listens there.'))
    Write-Host ''

    if ($cfg.ExportCsv) {
        try {
            $out = foreach ($r in $ordered) {
                $o = [ordered]@{ Target = $r.Host; Type = $r.Type; Lines = $r.Lines; Resolved = (($r.Addresses | ForEach-Object { $_.ToString() }) -join ' '); DNS = $r.Dns; DnsMs = $r.DnsMs; Private = $r.Private; Ping = $r.Ping; PingMs = $r.PingMs }
                foreach ($p in $allPorts) { $pr = $r.Ports[$p]; $o["Port$p"] = $(if ($pr) { $pr.Result } else { '' }); $o["Port${p}Ms"] = $(if ($pr -and $pr.Result -eq 'open') { $pr.Ms } else { '' }) }
                [pscustomobject]$o
            }
            $out | Export-Csv -Path $cfg.ExportCsv -NoTypeInformation -Encoding UTF8
            Write-Host ('  ' + (C dim ('exported ' + @($out).Count + ' rows to ' + $cfg.ExportCsv))); Write-Host ''
        } catch { Write-Warning "CSV export failed: $($_.Exception.Message)" }
    }
}
catch { Show-Failure $_; exit 1 }

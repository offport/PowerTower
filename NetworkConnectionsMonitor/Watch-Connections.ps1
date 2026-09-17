#Requires -Version 5.1
<#
.SYNOPSIS
    Watch-Connections — live view of every IP, port, domain and protocol this machine is talking to.

.DESCRIPTION
    Refreshes in place. For each connection you see protocol, detected service (https, dns,
    rdp, smb…), owning process, local and remote endpoints, the DOMAIN behind the remote IP,
    state, and how long it has existed. New connections light up; closed ones fade for a few
    seconds and then drop.

    Domains come from two places: the machine's own DNS client cache (the name the app actually
    asked for — best), then a reverse lookup as a fallback. Lookups are asynchronous so the
    display never stalls.

    Filter at startup (menu or arguments) or at any time by pressing f:
        port:443,53   proc:chrome   host:google   svc:https   proto:tcp   remote:104.18   state:established
    Press c to clear. Toggles: t TCP, u UDP, l listening sockets, i loopback/link-local.

    Keys:  q quit   f filter   c clear   g group by remote host   n name resolution
           s sort   p pause   t/u/l/i toggles   +/- interval

    Reads only. Never touches a connection.

.PARAMETER Protocol      tcp, udp or both. Default both.
.PARAMETER Port          Only these ports (local or remote), e.g. -Port 443,53.
.PARAMETER Process       Only processes whose name contains this text.
.PARAMETER RemoteHost    Only remote hosts whose domain or IP contains this text.
.PARAMETER Filter        Free-form filter string, same syntax as the f key.
.PARAMETER IncludeListening   Show LISTEN sockets and unconnected UDP endpoints.
.PARAMETER IncludeLoopback    Show 127.x / ::1 / link-local.
.PARAMETER NoResolve     Skip name resolution (IPs only).
.PARAMETER Interval      Seconds between refreshes. Default 1.
.PARAMETER Log           Append every NEW connection to this CSV.
.PARAMETER NoColor       Plain output.
.PARAMETER Interactive   Force the setup menu.

.EXAMPLE
    .\Watch-Connections.ps1
    .\Watch-Connections.ps1 -Port 443 -Process chrome
    .\Watch-Connections.ps1 -Filter 'svc:https host:amazon' -Log .\conns.csv

.NOTES
    Works without elevation. Elevate to see the owning process of system services.
    UDP is connectionless: Windows keeps no "remote peer" table for it, so UDP rows show the
    local endpoint and owning process only. DNS names still appear via the DNS client cache.
    Needs a real console (Windows Terminal / conhost), not the ISE.
#>
[CmdletBinding()]
param(
    [ValidateSet('tcp', 'udp', 'both')][string]$Protocol = 'both',
    [int[]]$Port,
    [string]$Process,
    [string]$RemoteHost,
    [string]$Filter,
    [switch]$IncludeListening,
    [switch]$IncludeLoopback,
    [switch]$NoResolve,
    [double]$Interval = 1,
    [string]$Log,
    [switch]$NoColor,
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
        bold  = "$Esc[1m"; violet = "$Esc[38;2;170;140;255m"
    }
    return "$($map[$Name])$Text$Esc[0m"
}
function Trunc { param([string]$S, [int]$N) if ($null -eq $S) { $S = '' }; if ($S.Length -le $N) { return $S.PadRight($N) } return ($S.Substring(0, $N - 1) + '…') }
function Ask { param([string]$Prompt, [string]$Default = '') $s = if ($Default -ne '') { (C dim " [$Default]") } else { '' }; Write-Host ('  ' + (C teal '?') + ' ' + (C ink $Prompt) + $s + ' ') -NoNewline; $r = Read-Host; if ([string]::IsNullOrWhiteSpace($r)) { return $Default }; return $r.Trim() }
function Format-Age { param([double]$S) if ($S -ge 3600) { return ('{0:N1}h' -f ($S / 3600)) }; if ($S -ge 60) { return ('{0:N0}m' -f ($S / 60)) }; return ('{0:N0}s' -f $S) }

# ═══════════════════════════════ service map ═══════════════════════════════

$script:Svc = @{
    20='ftp-data'; 21='ftp'; 22='ssh'; 23='telnet'; 25='smtp'; 53='dns'; 67='dhcp'; 68='dhcp'; 80='http'; 88='kerberos'; 110='pop3'; 123='ntp'
    135='rpc'; 137='netbios'; 138='netbios'; 139='netbios'; 143='imap'; 161='snmp'; 389='ldap'; 443='https'; 445='smb'; 465='smtps'; 500='ike'
    514='syslog'; 587='smtp-sub'; 636='ldaps'; 853='dns-tls'; 993='imaps'; 995='pop3s'; 1194='openvpn'; 1234='lmstudio'; 1433='mssql'; 1521='oracle'
    1701='l2tp'; 1723='pptp'; 1900='ssdp'; 3000='http-dev'; 3306='mysql'; 3389='rdp'; 3478='stun'; 4500='ipsec-nat'; 5060='sip'; 5061='sips'
    5222='xmpp'; 5353='mdns'; 5355='llmnr'; 5432='postgres'; 5900='vnc'; 5985='winrm'; 5986='winrm-s'; 6379='redis'; 8000='http-alt'; 8080='http-alt'
    8443='https-alt'; 8888='http-alt'; 9200='elastic'; 11434='ollama'; 27017='mongo'; 51820='wireguard'
}
function Get-SvcName { param([int]$Remote, [int]$Local, [bool]$Listening)
    if ($Listening) { if ($script:Svc.ContainsKey($Local)) { return $script:Svc[$Local] }; return '' }
    if ($script:Svc.ContainsKey($Remote)) { return $script:Svc[$Remote] }
    if ($script:Svc.ContainsKey($Local)) { return $script:Svc[$Local] }
    return '' }

function Test-Loopback { param([string]$Ip)
    return ($Ip -match '^(127\.|::1$|0\.0\.0\.0$|::$|169\.254\.|fe80:|ff0|224\.|239\.|255\.255)') }

# ═══════════════════════════════ name resolution ═══════════════════════════════

$script:DnsCache = @{}        # ip → name (from DNS client cache)
$script:Ptr      = @{}        # ip → name | '' (pending) | '-' (none)
$script:PtrTasks = @{}        # ip → Task
$script:DnsTick  = 0

function Update-DnsCache {
    try {
        foreach ($e in (Get-DnsClientCache -ErrorAction Stop | Where-Object { $_.Type -eq 1 -or $_.Type -eq 28 })) {
            if ($e.Data -and $e.Entry) { $script:DnsCache[$e.Data] = $e.Entry.ToLowerInvariant() }
        }
    } catch {}
}
function Resolve-Name {
    param([string]$Ip)
    if (-not $Ip -or (Test-Loopback $Ip)) { return '' }
    if ($script:DnsCache.ContainsKey($Ip)) { return $script:DnsCache[$Ip] }
    if ($script:NoResolveNow) { return '' }
    if ($script:Ptr.ContainsKey($Ip)) { $v = $script:Ptr[$Ip]; if ($v -eq '-') { return '' }; return $v }
    try { $script:PtrTasks[$Ip] = [System.Net.Dns]::GetHostEntryAsync($Ip); $script:Ptr[$Ip] = '' } catch { $script:Ptr[$Ip] = '-' }
    return ''
}
function Poll-Ptr {
    $done = @()
    foreach ($ip in $script:PtrTasks.Keys) {
        $t = $script:PtrTasks[$ip]
        if (-not $t.IsCompleted) { continue }
        $done += $ip
        if ($t.Status -eq 'RanToCompletion' -and $t.Result -and $t.Result.HostName) { $script:Ptr[$ip] = $t.Result.HostName.ToLowerInvariant() } else { $script:Ptr[$ip] = '-' }
    }
    foreach ($ip in $done) { $script:PtrTasks.Remove($ip) }
}

# ═══════════════════════════════ filter ═══════════════════════════════

$script:F = @{ Port = @(); Proc = ''; Host = ''; Svc = ''; Proto = ''; Remote = ''; State = ''; Raw = '' }

function Set-Filter {
    param([string]$Text)
    $f = @{ Port = @(); Proc = ''; Host = ''; Svc = ''; Proto = ''; Remote = ''; State = ''; Raw = $Text.Trim() }
    foreach ($tok in ($Text -split '\s+' | Where-Object { $_ })) {
        if ($tok -match '^(\w+):(.+)$') {
            $k = $matches[1].ToLower(); $v = $matches[2]
            switch ($k) {
                'port'   { $f.Port = @($v -split ',' | ForEach-Object { $n = 0; if ([int]::TryParse($_, [ref]$n)) { $n } }) }
                'proc'   { $f.Proc = $v.ToLower() }
                'host'   { $f.Host = $v.ToLower() }
                'svc'    { $f.Svc = $v.ToLower() }
                'proto'  { $f.Proto = $v.ToLower() }
                'remote' { $f.Remote = $v.ToLower() }
                'ip'     { $f.Remote = $v.ToLower() }
                'state'  { $f.State = $v.ToLower() }
            }
        } elseif ($tok -match '^\d+$') { $f.Port += [int]$tok }
        else { $f.Host = $tok.ToLower() }
    }
    $script:F = $f
}

function Test-Filter {
    param($R)
    $f = $script:F
    if ($f.Port.Count -and -not ($f.Port -contains $R.LPort -or $f.Port -contains $R.RPort)) { return $false }
    if ($f.Proc   -and $R.Proc.ToLower().IndexOf($f.Proc) -lt 0) { return $false }
    if ($f.Host   -and (($R.Name + ' ' + $R.RIp).ToLower().IndexOf($f.Host) -lt 0)) { return $false }
    if ($f.Svc    -and $R.Svc.ToLower().IndexOf($f.Svc) -lt 0) { return $false }
    if ($f.Proto  -and $R.Proto.ToLower() -ne $f.Proto) { return $false }
    if ($f.Remote -and $R.RIp.ToLower().IndexOf($f.Remote) -lt 0) { return $false }
    if ($f.State  -and $R.State.ToLower().IndexOf($f.State) -lt 0) { return $false }
    return $true
}

# ═══════════════════════════════ sampling ═══════════════════════════════

$script:Conns = @{}          # key → row
$script:ProcNames = @{}
$script:StartedAt = Get-Date
$script:Stats = @{ New = 0; Closed = 0 }
$script:ShowTcp = $true; $script:ShowUdp = $true
$script:ShowListen = [bool]$IncludeListening; $script:ShowLoop = [bool]$IncludeLoopback
$script:NoResolveNow = [bool]$NoResolve
$script:Group = $false; $script:Paused = $false
$script:SortModes = @('newest', 'process', 'remote host', 'service', 'oldest'); $script:SortIdx = 0
$script:IntervalSec = [math]::Max(0.5, $Interval)
$script:FadeSec = 6

function Update-ProcNames {
    $script:ProcNames = @{}
    foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) { $script:ProcNames[[int]$p.Id] = $p.ProcessName }
    $script:ProcNames[0] = 'System Idle'; $script:ProcNames[4] = 'System'
}

function Take-Sample {
    $now = Get-Date
    if (($script:DnsTick % 5) -eq 0) { Update-ProcNames; if (-not $script:NoResolveNow) { Update-DnsCache } }
    $script:DnsTick++
    Poll-Ptr
    $seen = @{}

    if ($script:ShowTcp) {
        foreach ($c in (Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
            $listening = ($c.State -eq 'Listen')
            if ($listening -and -not $script:ShowListen) { continue }
            $rip = "$($c.RemoteAddress)"
            if (-not $listening -and -not $script:ShowLoop -and (Test-Loopback $rip)) { continue }
            $key = "tcp|$($c.LocalAddress):$($c.LocalPort)|$rip`:$($c.RemotePort)|$($c.OwningProcess)"
            $seen[$key] = $true
            $r = $script:Conns[$key]
            if (-not $r) {
                $pn = $script:ProcNames[[int]$c.OwningProcess]; if (-not $pn) { $pn = "pid $($c.OwningProcess)" }
                $r = [pscustomobject]@{ Key = $key; Proto = 'TCP'; Proc = $pn; ProcId = [int]$c.OwningProcess; LIp = "$($c.LocalAddress)"; LPort = [int]$c.LocalPort; RIp = $rip; RPort = [int]$c.RemotePort
                                       State = "$($c.State)"; Svc = (Get-SvcName ([int]$c.RemotePort) ([int]$c.LocalPort) $listening); Name = ''; First = $now; Last = $now; Closed = $null; Listening = $listening }
                $script:Conns[$key] = $r; $script:Stats.New++
                if ($Log) { try { [pscustomobject]@{ Time = $now.ToString('s'); Proto = 'TCP'; Process = $pn; Pid = $r.ProcId; Local = "$($r.LIp):$($r.LPort)"; Remote = "$rip`:$($r.RPort)"; Service = $r.Svc; State = $r.State } | Export-Csv -Path $Log -NoTypeInformation -Append -Encoding UTF8 } catch {} }
            } else { $r.State = "$($c.State)"; $r.Last = $now; $r.Closed = $null }
            if (-not $listening -and -not $r.Name) { $r.Name = Resolve-Name $rip }
        }
    }
    if ($script:ShowUdp -and $script:ShowListen) {
        foreach ($u in (Get-NetUDPEndpoint -ErrorAction SilentlyContinue)) {
            $lip = "$($u.LocalAddress)"
            if (-not $script:ShowLoop -and (Test-Loopback $lip) -and $lip -ne '0.0.0.0' -and $lip -ne '::') { continue }
            $key = "udp|$lip`:$($u.LocalPort)|*|$($u.OwningProcess)"
            $seen[$key] = $true
            $r = $script:Conns[$key]
            if (-not $r) {
                $pn = $script:ProcNames[[int]$u.OwningProcess]; if (-not $pn) { $pn = "pid $($u.OwningProcess)" }
                $r = [pscustomobject]@{ Key = $key; Proto = 'UDP'; Proc = $pn; ProcId = [int]$u.OwningProcess; LIp = $lip; LPort = [int]$u.LocalPort; RIp = ''; RPort = 0
                                       State = 'open'; Svc = (Get-SvcName 0 ([int]$u.LocalPort) $true); Name = ''; First = $now; Last = $now; Closed = $null; Listening = $true }
                $script:Conns[$key] = $r; $script:Stats.New++
            } else { $r.Last = $now; $r.Closed = $null }
        }
    }

    # fade & drop
    $drop = @()
    foreach ($key in $script:Conns.Keys) {
        if ($seen[$key]) { continue }
        $r = $script:Conns[$key]
        if (-not $r.Closed) { $r.Closed = $now; $script:Stats.Closed++ }
        elseif (($now - $r.Closed).TotalSeconds -gt $script:FadeSec) { $drop += $key }
    }
    foreach ($k in $drop) { $script:Conns.Remove($k) }

    # late name fills
    foreach ($r in $script:Conns.Values) { if (-not $r.Name -and -not $r.Listening -and $r.RIp) { $r.Name = Resolve-Name $r.RIp } }
}

function Get-Rows {
    $rows = @($script:Conns.Values | Where-Object { Test-Filter $_ })
    switch ($script:SortIdx) {
        0 { $rows = $rows | Sort-Object @{ Expression = 'Closed'; Descending = $false }, @{ Expression = 'First'; Descending = $true } }
        1 { $rows = $rows | Sort-Object Proc, First }
        2 { $rows = $rows | Sort-Object @{ Expression = { if ($_.Name) { $_.Name } else { $_.RIp } } }, First }
        3 { $rows = $rows | Sort-Object Svc, First }
        4 { $rows = $rows | Sort-Object First }
    }
    return @($rows)
}

# ═══════════════════════════════ frame ═══════════════════════════════

function Build-Frame {
    $sb = New-Object System.Text.StringBuilder
    $EL = "$Esc[K"
    $line = { param($s) [void]$sb.Append($s).Append($EL).Append("`n") }
    try { $w = $Host.UI.RawUI.WindowSize.Width; $h = $Host.UI.RawUI.WindowSize.Height } catch { $w = 0; $h = 0 }
    if (-not $w -or $w -lt 60) { $w = 140 }; if (-not $h -or $h -lt 10) { $h = 40 }
    $now = Get-Date
    $up = $now - $script:StartedAt; $upStr = if ($up.TotalHours -ge 1) { $up.ToString('h\:mm\:ss') } else { $up.ToString('m\:ss') }

    $rows = Get-Rows
    $live = @($rows | Where-Object { -not $_.Closed })
    $hosts = @{}; foreach ($r in $live) { if ($r.RIp) { $hosts[$r.RIp] = 1 } }
    $procs = @{}; foreach ($r in $live) { $procs[$r.Proc] = 1 }

    $tog = (C $(if ($script:ShowTcp) { 'teal' } else { 'faint' }) 'TCP') + ' ' + (C $(if ($script:ShowUdp) { 'teal' } else { 'faint' }) 'UDP') + ' ' +
           (C $(if ($script:ShowListen) { 'teal' } else { 'faint' }) 'LISTEN') + ' ' + (C $(if ($script:ShowLoop) { 'teal' } else { 'faint' }) 'LOOPBACK') + ' ' +
           (C $(if (-not $script:NoResolveNow) { 'teal' } else { 'faint' }) 'NAMES')
    $paused = if ($script:Paused) { (C amber '  PAUSED') } else { '' }
    & $line ('  ' + (C teal '▌') + ' ' + (C bold (C ink 'CONNECTIONS')) + '  ' + (C dim ("since launch $upStr · " + $(if ($script:Group) { 'BY HOST' } else { 'LIST' }) + " · sort: $($script:SortModes[$script:SortIdx]) · every $($script:IntervalSec)s")) + $paused)
    & $line ('  ' + $tog + (C dim ('   live ' + $live.Count + ' · hosts ' + $hosts.Count + ' · processes ' + $procs.Count + ' · opened ' + $script:Stats.New + ' · closed ' + $script:Stats.Closed + ' · pending lookups ' + $script:PtrTasks.Count)))
    $ftxt = if ($script:F.Raw) { (C amber ('  filter: ' + $script:F.Raw)) } else { (C faint '  no filter') }
    & $line ($ftxt)
    & $line ''

    $maxRows = $h - 8
    $shown = 0
    if ($script:Group) {
        $g = @{}
        foreach ($r in $rows) {
            if ($r.Listening) { continue }
            $hk = if ($r.Name) { $r.Name } else { $r.RIp }
            if (-not $hk) { continue }
            $e = $g[$hk]
            if (-not $e) { $e = [pscustomobject]@{ Host = $hk; Ip = $r.RIp; Conns = 0; Live = 0; Procs = @{}; Svcs = @{}; Ports = @{}; First = $r.First }; $g[$hk] = $e }
            $e.Conns++; if (-not $r.Closed) { $e.Live++ }
            $e.Procs[$r.Proc] = 1; if ($r.Svc) { $e.Svcs[$r.Svc] = 1 }; $e.Ports[$r.RPort] = 1
            if ($r.First -lt $e.First) { $e.First = $r.First }
        }
        & $line ('  ' + (C dim ('{0,-42} {1,-16} {2,5} {3,5}  {4,-22} {5,-16} {6}' -f 'REMOTE HOST', 'IP', 'LIVE', 'ALL', 'PROCESSES', 'SERVICES', 'PORTS')))
        foreach ($e in ($g.Values | Sort-Object Live, Conns -Descending)) {
            $shown++; if ($shown -gt $maxRows) { break }
            $hc = if ($e.Live) { 'ink' } else { 'faint' }
            & $line ('  ' + (C $hc (Trunc $e.Host 42)) + ' ' + (C dim (Trunc $e.Ip 16)) + ' ' + (C teal ('{0,5}' -f $e.Live)) + ' ' + (C dim ('{0,5}' -f $e.Conns)) + '  ' +
                     (C ink (Trunc (($e.Procs.Keys | Sort-Object) -join ',') 22)) + ' ' + (C violet (Trunc (($e.Svcs.Keys | Sort-Object) -join ',') 16)) + ' ' + (C dim (Trunc ((($e.Ports.Keys | Sort-Object) | Select-Object -First 8) -join ',') 30)))
        }
    }
    else {
        $nameW = [math]::Max(20, $w - 96)
        & $line ('  ' + (C dim (('{0,-4} {1,-10} {2,-18} {3,6} {4,-22} {5,-' + $nameW + '} {6,-12} {7,5}') -f 'PROTO', 'SERVICE', 'PROCESS', 'LPORT', 'REMOTE', 'DOMAIN', 'STATE', 'AGE')))
        foreach ($r in $rows) {
            $shown++; if ($shown -gt $maxRows) { & $line ('  ' + (C dim ('… ' + ($rows.Count - $maxRows) + ' more — narrow with f'))); break }
            $age = ($now - $r.First).TotalSeconds
            $isNew = $age -lt 3
            $pc = if ($r.Closed) { 'faint' } elseif ($isNew) { 'teal' } else { 'ink' }
            $sc = if ($r.Closed) { 'faint' } else { switch -Regex ($r.State) { 'Established|open' { 'ink' } 'Listen' { 'dim' } 'SynSent|SynReceived' { 'amber' } 'TimeWait|CloseWait|FinWait|Closing|LastAck' { 'rose' } default { 'dim' } } }
            $remote = if ($r.Listening) { $(if ($r.Proto -eq 'UDP') { '*' } else { 'listening' }) } else { "$($r.RIp):$($r.RPort)" }
            $name = if ($r.Listening) { '' } elseif ($r.Name) { $r.Name } elseif ($script:Ptr.ContainsKey($r.RIp) -and $script:Ptr[$r.RIp] -eq '') { '…' } else { '' }
            $svcCol = if ($r.Closed) { 'faint' } else { 'violet' }
            $mark = if ($r.Closed) { (C rose '×') } elseif ($isNew) { (C teal '+') } else { ' ' }
            & $line ($mark + ' ' + (C $pc ('{0,-4}' -f $r.Proto)) + ' ' + (C $svcCol (Trunc $r.Svc 10)) + ' ' + (C $pc (Trunc $r.Proc 18)) + ' ' + (C dim ('{0,6}' -f $r.LPort)) + ' ' +
                     (C $pc (Trunc $remote 22)) + ' ' + (C $(if ($r.Closed) { 'faint' } else { 'amber' }) (Trunc $name $nameW)) + ' ' + (C $sc (Trunc $r.State 12)) + ' ' + (C dim ('{0,5}' -f (Format-Age $age))))
        }
    }
    if ($shown -eq 0) { & $line ('  ' + (C dim 'nothing matches — press c to clear the filter, l to include listening sockets, i for loopback')) }
    & $line ''
    & $line ('  ' + (C dim 'q') + (C faint ' quit ') + (C dim 'f') + (C faint ' filter ') + (C dim 'c') + (C faint ' clear ') + (C dim 'g') + (C faint ' by host ') + (C dim 's') + (C faint ' sort ') + (C dim 'p') + (C faint ' pause ') +
             (C dim 't') + (C faint ' tcp ') + (C dim 'u') + (C faint ' udp ') + (C dim 'l') + (C faint ' listen ') + (C dim 'i') + (C faint ' loopback ') + (C dim 'n') + (C faint ' names ') + (C dim '+/-') + (C faint ' interval'))
    [void]$sb.Append("$Esc[J")
    return $sb.ToString()
}

# ═══════════════════════════════ error guidance ═══════════════════════════════

function Show-Failure {
    param($Err)
    $msg = "$($Err.Exception.Message)"; $me = $PSCommandPath
    Write-Host ''; Write-Host ('  ' + (C rose '✖ The monitor stopped.') + '  ' + (C dim (Trunc $msg 100))); Write-Host ''
    Write-Host ('  ' + (C bold (C ink 'What to try:')))
    if ($msg -match 'ReadKey|KeyAvailable|not supported|redirected|console') {
        Write-Host ('  ' + (C teal '1.') + ' ' + (C ink 'This needs a real console — Windows Terminal or a PowerShell window, not the ISE or a redirected shell.'))
        Write-Host ('  ' + (C teal '2.') + ' ' + (C ink 'Or double-click ') + (C amber 'Run-Connections.cmd') + (C ink ' which opens its own window.'))
    }
    elseif ($msg -match 'Get-NetTCPConnection|Get-NetUDPEndpoint|NetTCPIP|not recognized') {
        Write-Host ('  ' + (C teal '1.') + ' ' + (C ink 'The NetTCPIP module is missing or blocked. Check:  ') + (C amber 'Get-Module -ListAvailable NetTCPIP'))
        Write-Host ('  ' + (C teal '2.') + ' ' + (C ink 'On Windows PowerShell 5.1 it is built in; on PowerShell 7 it loads through compatibility — try running with ') + (C amber 'powershell.exe') + (C ink ' instead of pwsh.'))
    }
    elseif ($msg -match 'Access is denied|PermissionDenied') {
        Write-Host ('  ' + (C teal '1.') + ' ' + (C ink 'Re-run elevated to see owning processes for system services:'))
        Write-Host ('       ' + (C amber "Start-Process powershell -Verb RunAs -ArgumentList '-ExecutionPolicy Bypass -File `"$me`" -Interactive'"))
    }
    elseif ($msg -match 'not digitally signed|execution polic') {
        Write-Host ('  ' + (C teal '1.') + ' ' + (C amber "Unblock-File `"$me`"") + (C ink '   or use Run-Connections.cmd'))
    }
    else {
        Write-Host ('  ' + (C teal '1.') + ' ' + (C ink 'The combination that works on almost any machine:'))
        Write-Host ('       ' + (C amber "powershell -NoProfile -ExecutionPolicy Bypass -File `"$me`" -NoColor -Interactive"))
    }
    Write-Host ''; Write-Host ('  ' + (C dim ('at: ' + ("$($Err.InvocationInfo.PositionMessage)" -replace '\s+', ' ')))); Write-Host ''
}

# ═══════════════════════════════ menu ═══════════════════════════════

function Invoke-Menu {
    Write-Host ''; Write-Host ('  ' + (C teal '▌') + ' ' + (C bold (C ink 'CONNECTIONS')) + '  ' + (C dim 'interactive setup — Enter accepts the default')); Write-Host ''
    Write-Host ('  ' + (C bold (C ink 'Protocols')))
    Write-Host ('   ' + (C teal '1.') + ' ' + (C ink 'TCP and UDP'))
    Write-Host ('   ' + (C teal '2.') + ' ' + (C ink 'TCP only'))
    Write-Host ('   ' + (C teal '3.') + ' ' + (C ink 'UDP only  ') + (C dim '— local endpoints; Windows keeps no remote-peer table for UDP'))
    $p = Ask 'Protocols' '1'
    switch ($p) { '2' { $script:ShowUdp = $false } '3' { $script:ShowTcp = $false; $script:ShowListen = $true } }
    $ports = Ask 'Only these ports? (comma-separated, blank for all)' ''
    $proc  = Ask 'Only this process? (name contains, blank for all)' ''
    $hst   = Ask 'Only this remote host? (domain or IP contains, blank for all)' ''
    $ftxt = ''
    if ($ports) { $ftxt += " port:$($ports -replace '\s','')" }; if ($proc) { $ftxt += " proc:$proc" }; if ($hst) { $ftxt += " host:$hst" }
    if ($ftxt) { Set-Filter $ftxt }
    $l = Ask 'Show listening sockets too? (y/n)' $(if ($script:ShowListen) { 'y' } else { 'n' }); $script:ShowListen = ($l -match '^y')
    $n = Ask 'Resolve domain names? (y/n)' 'y'; $script:NoResolveNow = ($n -notmatch '^y')
    $i = Ask 'Refresh interval in seconds' "$($script:IntervalSec)"; $d = 0.0; if ([double]::TryParse($i, [ref]$d) -and $d -ge 0.5) { $script:IntervalSec = $d }
    $lg = Ask 'Log new connections to CSV? (path, blank to skip)' ''; if ($lg) { $script:LogPath = $lg }
    Write-Host ''; Write-Host ('  ' + (C dim 'Starting. Press f at any time to change the filter, q to stop.')); Start-Sleep -Milliseconds 800
}

function Prompt-Filter {
    # leave the live screen, ask, come back
    [Console]::Write("$Esc[?25h$Esc[2J$Esc[H")
    Write-Host ''; Write-Host ('  ' + (C bold (C ink 'Filter')) + (C dim '  tokens: port:443,53  proc:chrome  host:google  svc:https  proto:tcp  ip:104.18  state:established  — a bare number is a port, bare text is a host'))
    if ($script:F.Raw) { Write-Host ('  ' + (C dim 'current: ') + (C amber $script:F.Raw)) }
    $t = Ask 'Filter (blank clears)' ''
    Set-Filter $t
    [Console]::Write("$Esc[2J$Esc[H"); if ($script:UseColor) { [Console]::Write("$Esc[?25l") }
}

# ═══════════════════════════════ main ═══════════════════════════════

$script:LogPath = $Log
$cursorHidden = $false
try {
    if (-not (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)) { throw 'Get-NetTCPConnection is not available — the NetTCPIP module could not be loaded.' }

    $gave = $false
    foreach ($a in @('Protocol', 'Port', 'Process', 'RemoteHost', 'Filter', 'IncludeListening', 'IncludeLoopback', 'NoResolve', 'Interval', 'Log')) { if ($PSBoundParameters.ContainsKey($a)) { $gave = $true } }
    if ($Protocol -eq 'tcp') { $script:ShowUdp = $false } elseif ($Protocol -eq 'udp') { $script:ShowTcp = $false; $script:ShowListen = $true }
    $ftxt = ''
    if ($Port) { $ftxt += ' port:' + ($Port -join ',') }; if ($Process) { $ftxt += " proc:$Process" }; if ($RemoteHost) { $ftxt += " host:$RemoteHost" }; if ($Filter) { $ftxt += " $Filter" }
    if ($ftxt) { Set-Filter $ftxt }
    if ($Interactive -or -not $gave) { Invoke-Menu }
    $Log = $script:LogPath

    try { [void][Console]::KeyAvailable } catch { throw 'ReadKey/KeyAvailable is not supported in this host — a real console is required.' }
    if ($script:UseColor) { [Console]::Write("$Esc[?25l"); $cursorHidden = $true }
    [Console]::Write("$Esc[2J$Esc[H")

    Update-ProcNames; if (-not $script:NoResolveNow) { Update-DnsCache }
    $running = $true
    while ($running) {
        if (-not $script:Paused) { Take-Sample }
        [Console]::Write("$Esc[H" + (Build-Frame))
        $deadline = (Get-Date).AddSeconds($script:IntervalSec)
        while ((Get-Date) -lt $deadline) {
            if ([Console]::KeyAvailable) {
                $k = [Console]::ReadKey($true)
                switch ($k.KeyChar) {
                    'q' { $running = $false }
                    'f' { Prompt-Filter }
                    'c' { Set-Filter '' }
                    'g' { $script:Group = -not $script:Group }
                    's' { $script:SortIdx = ($script:SortIdx + 1) % $script:SortModes.Count }
                    'p' { $script:Paused = -not $script:Paused }
                    't' { $script:ShowTcp = -not $script:ShowTcp }
                    'u' { $script:ShowUdp = -not $script:ShowUdp }
                    'l' { $script:ShowListen = -not $script:ShowListen }
                    'i' { $script:ShowLoop = -not $script:ShowLoop }
                    'n' { $script:NoResolveNow = -not $script:NoResolveNow; if (-not $script:NoResolveNow) { Update-DnsCache } }
                    '+' { $script:IntervalSec = [math]::Min(10, $script:IntervalSec + 0.5) }
                    '=' { $script:IntervalSec = [math]::Min(10, $script:IntervalSec + 0.5) }
                    '-' { $script:IntervalSec = [math]::Max(0.5, $script:IntervalSec - 0.5) }
                }
                if (-not $running) { break }
                [Console]::Write("$Esc[H" + (Build-Frame))
            }
            Start-Sleep -Milliseconds 60
        }
    }
}
catch { if ($cursorHidden) { [Console]::Write("$Esc[?25h") }; Show-Failure $_; exit 1 }
finally { if ($cursorHidden) { [Console]::Write("$Esc[?25h$Esc[0m") } }

# static summary that survives in scroll-back
$up = (Get-Date) - $script:StartedAt
Write-Host ''
Write-Host ('  ' + (C teal '■ ') + (C ink ('stopped after ' + $up.ToString('h\:mm\:ss') + " · $($script:Stats.New) connections opened · $($script:Stats.Closed) closed")) + $(if ($Log) { (C dim " · log: $Log") } else { '' }))
$hostCount = @{}
foreach ($r in $script:Conns.Values) { if ($r.RIp -and -not $r.Listening) { $hk = if ($r.Name) { $r.Name } else { $r.RIp }; $hostCount[$hk] = [int]$hostCount[$hk] + 1 } }
if ($hostCount.Count) {
    Write-Host ('  ' + (C dim 'remote hosts still in view at exit:'))
    foreach ($e in ($hostCount.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 8)) { Write-Host ('    ' + (C ink (Trunc $e.Key 50)) + ' ' + (C dim ('×' + $e.Value))) }
}
Write-Host ''

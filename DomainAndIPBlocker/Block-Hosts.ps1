#Requires -Version 5.1
<#
.SYNOPSIS
    Block-Hosts — block domains (hosts file) and IPs (Windows Firewall) from a messy text/CSV file, reversibly.

.DESCRIPTION
    Extracts every domain and IP from the input file (same extractor as Test-Reachability:
    handles URLs, log lines, defanged indicators like evil[.]com and hxxp://), then:

      • DOMAINS → the Windows hosts file, mapped to 0.0.0.0 (fails fast). Each domain also gets
        its www. variant. Every line the tool adds is tagged with a marker so it can later be
        removed exactly, without touching anything you added by hand.

      • IPs → one outbound Windows Firewall block rule (the only mechanism that actually blocks
        an IP; the hosts file cannot). The rule is named so it can be found and removed.

    ACTIONS:  add (default) · list · remove · restore
    Everything is reversible. Every hosts-file change is backed up first. Nothing you didn't
    add through this tool is ever modified.

.PARAMETER Action     add | list | remove | restore. Default add.
.PARAMETER Path       The .txt or .csv of domains/IPs to block (for add / remove).
.PARAMETER DnsSink    Address domains point to. Default 0.0.0.0.
.PARAMETER NoFirewall Skip the IP/firewall part; only touch the hosts file.
.PARAMETER NoHosts    Skip the hosts part; only manage the firewall rule.
.PARAMETER Yes        Don't prompt for confirmation before writing.
.PARAMETER NoColor    Plain output.
.PARAMETER Interactive Force the menu.

.EXAMPLE
    .\Block-Hosts.ps1                              # menu
    .\Block-Hosts.ps1 -Action add -Path .\block.txt
    .\Block-Hosts.ps1 -Action list
    .\Block-Hosts.ps1 -Action remove -Path .\block.txt
    .\Block-Hosts.ps1 -Action restore            # roll hosts file back to the last backup

.NOTES
    Requires Administrator (writing the hosts file and firewall rules).
    Marker: lines this tool adds end with '# BLOCK-HOSTS'. Do not edit that tag by hand.
    If Windows refuses to run it: Unblock-File .\Block-Hosts.ps1, or use Run-BlockHosts.cmd.
#>
[CmdletBinding()]
param(
    [ValidateSet('add', 'list', 'remove', 'restore')][string]$Action = 'add',
    [string]$Path,
    [string]$DnsSink = '0.0.0.0',
    [switch]$NoFirewall,
    [switch]$NoHosts,
    [switch]$Yes,
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
function Confirm { param([string]$Prompt) if ($script:Cfg.Yes) { return $true } $r = Ask ($Prompt + ' (y/n)') 'n'; return ($r -match '^y') }

# ═══════════════════════════════ constants ═══════════════════════════════

$script:Marker    = '# BLOCK-HOSTS'
$script:RuleName  = 'BLOCK-HOSTS blocked IPs'
$script:HostsPath = "$env:WinDir\System32\drivers\etc\hosts"
$script:BackupDir = Join-Path $env:ProgramData 'BlockHosts\backups'

# ═══════════════════════════════ extraction (shared with Test-Reachability) ═══════════════════════════════

$script:KnownTld = @{}
foreach ($t in ('com net org edu gov mil int arpa io dev app ai co info biz me tv cc xyz cloud online site tech store shop blog news email network systems solutions services digital software agency company global group live media space today top club vip pro museum name mobi asia jobs tel travel aero coop post cyber tools zone host link click download page web world run team life works studio design center city expert guru ninja rocks fund money finance bank health care clinic legal law tax market sale deals codes gift games game play events photo photos video film movie music audio radio social community forum wiki review directory guide academy school college university institute science research lab data analytics server hosting domains mail mobile phone software hardware technology energy farm garden cafe restaurant bar coffee kitchen food fitness gym sport sports golf tennis cars auto rent taxi hotel holiday travel casino bet poker ltd llc inc gmbh plc srl'.Split(' '))) { $script:KnownTld[$t] = 1 }
$script:ExtCollide = @{ md=1;sh=1;py=1;pl=1;rs=1;ps=1;so=1;cs=1;gz=1;db=1;js=1;ts=1;rb=1;go=1;vb=1 }
$script:RxIPv4   = [regex]'(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])'
$script:RxIPv6   = [regex]'(?i)(?<![:\w])(?:[0-9a-f]{1,4}:){2,7}(?::|[0-9a-f]{1,4})(?![:\w])|(?<![:\w])::(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4}(?![:\w])'
$script:RxDomain = [regex]'(?i)(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:xn--[a-z0-9-]{2,59}|[a-z]{2,24})(?![\w-])'

function Normalize-Line {
    param([string]$L)
    $s = $L
    $s = $s -replace '(?i)hxxps?://', 'http://'
    $s = $s -replace '(?i)\[\s*(?:\.|dot)\s*\]|\(\s*(?:\.|dot)\s*\)|\{\s*(?:\.|dot)\s*\}', '.'
    $s = $s -replace '(?i)\[\s*:\s*\]|\(\s*:\s*\)', ':'
    $s = $s -replace '\\\.', '.'
    $s = $s -replace '(?i)\bdot\b', '.' -replace '\s*\.\s*', '.'
    return $s
}

function Get-Targets {
    param([string[]]$Lines)
    $domains = [ordered]@{}; $ips = [ordered]@{}
    foreach ($raw in $Lines) {
        if ([string]::IsNullOrWhiteSpace($raw)) { continue }
        if ($raw.TrimStart().StartsWith('#')) { continue }
        $line = Normalize-Line $raw
        $v4 = @()
        foreach ($m in $script:RxIPv4.Matches($line)) { $v4 += @{ I = $m.Index; L = $m.Length }; $ip = $null; if ([System.Net.IPAddress]::TryParse($m.Value, [ref]$ip)) { $ips[$m.Value] = 1 } }
        foreach ($m in $script:RxIPv6.Matches($line)) { $ip = $null; if (($m.Value -match '::' -or $m.Value.Split(':').Count -eq 8) -and [System.Net.IPAddress]::TryParse($m.Value, [ref]$ip) -and $ip.AddressFamily -eq 'InterNetworkV6') { $ips[$ip.ToString()] = 1 } }
        foreach ($m in $script:RxDomain.Matches($line)) {
            $inside = $false; foreach ($f in $v4) { if ($m.Index -ge $f.I -and $m.Index -lt ($f.I + $f.L)) { $inside = $true; break } }
            if ($inside) { continue }
            $d = $m.Value.ToLowerInvariant().TrimEnd('.'); $labels = $d.Split('.'); $tld = $labels[-1]
            if ($tld -match '^\d+$') { continue }
            $ok = $false
            if ($tld.StartsWith('xn--')) { $ok = $true }
            elseif ($script:KnownTld.ContainsKey($tld)) { $ok = $true }
            elseif ($tld.Length -eq 2) { $ok = -not ($script:ExtCollide.ContainsKey($tld) -and $labels.Count -eq 2) }
            if (-not $ok) { continue }
            if ($labels.Count -eq 2 -and $labels[0] -match '^(localhost|example|test|invalid)$') { continue }
            $domains[$d] = 1
        }
    }
    return @{ Domains = @($domains.Keys); Ips = @($ips.Keys) }
}

function Expand-Domains {
    # add www. variant for bare registrable names; keep subdomains as-is
    param([string[]]$Domains)
    $set = [ordered]@{}
    foreach ($d in $Domains) {
        $set[$d] = 1
        if (($d.Split('.').Count -eq 2) -and -not $d.StartsWith('www.')) { $set["www.$d"] = 1 }
    }
    return @($set.Keys)
}

# ═══════════════════════════════ hosts file ═══════════════════════════════

function Backup-Hosts {
    if (-not (Test-Path $script:BackupDir)) { New-Item -ItemType Directory -Path $script:BackupDir -Force | Out-Null }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $dest = Join-Path $script:BackupDir "hosts-$stamp.bak"
    Copy-Item -LiteralPath $script:HostsPath -Destination $dest -Force
    return $dest
}

function Read-Hosts { if (Test-Path $script:HostsPath) { return @(Get-Content -LiteralPath $script:HostsPath -ErrorAction Stop) } return @() }
function Write-Hosts { param([string[]]$Lines) Set-Content -LiteralPath $script:HostsPath -Value $Lines -Encoding ASCII -Force }

function Get-BlockedInHosts {
    $out = @()
    foreach ($l in (Read-Hosts)) { if ($l -match [regex]::Escape($script:Marker) + '\s*$') { $parts = ($l -replace [regex]::Escape($script:Marker), '').Trim() -split '\s+'; if ($parts.Count -ge 2) { $out += $parts[1] } } }
    return $out
}

# ═══════════════════════════════ firewall ═══════════════════════════════

function Get-BlockedIps {
    try { $r = Get-NetFirewallRule -DisplayName $script:RuleName -ErrorAction Stop; return @(($r | Get-NetFirewallAddressFilter).RemoteAddress) } catch { return @() }
}

function Set-FirewallIps {
    # replace the rule's address set with $Ips (empty removes the rule)
    param([string[]]$Ips)
    $existing = $null; try { $existing = Get-NetFirewallRule -DisplayName $script:RuleName -ErrorAction Stop } catch {}
    if (-not $Ips -or $Ips.Count -eq 0) { if ($existing) { $existing | Remove-NetFirewallRule }; return }
    if ($existing) {
        Set-NetFirewallRule -DisplayName $script:RuleName -RemoteAddress $Ips | Out-Null
    } else {
        New-NetFirewallRule -DisplayName $script:RuleName -Description 'Outbound block list managed by Block-Hosts.ps1' -Direction Outbound -Action Block -RemoteAddress $Ips -Profile Any -Enabled True | Out-Null
    }
}

# ═══════════════════════════════ actions ═══════════════════════════════

function Do-List {
    Section 'HOSTS FILE' "  domains blocked via $($script:HostsPath)"
    $h = Get-BlockedInHosts
    if (-not $h.Count) { Write-Host ('  ' + (C dim 'none blocked by this tool')) }
    else { $h | Sort-Object | ForEach-Object { Write-Host ('  ' + (C rose '●') + ' ' + (C ink $_)) }; Write-Host ('  ' + (C dim ("$($h.Count) domain(s)"))) }

    Section 'FIREWALL' "  IPs blocked via rule '$($script:RuleName)'"
    $f = Get-BlockedIps
    if (-not $f.Count -or ($f.Count -eq 1 -and $f[0] -eq 'Any')) { Write-Host ('  ' + (C dim 'no block rule present')) }
    else { $f | Sort-Object | ForEach-Object { Write-Host ('  ' + (C rose '●') + ' ' + (C violet $_)) }; Write-Host ('  ' + (C dim ("$($f.Count) address(es)"))) }
    Write-Host ''
}

function Do-Add {
    param($Targets)
    $domains = if ($script:Cfg.NoHosts) { @() } else { Expand-Domains $Targets.Domains }
    $ips = if ($script:Cfg.NoFirewall) { @() } else { $Targets.Ips }

    Section 'TO BLOCK' "  extracted from $(Split-Path $script:Cfg.Path -Leaf)"
    Write-Host ('  ' + (C ink ("$($domains.Count) domain(s)")) + (C dim ' → hosts file → ' + $script:Cfg.DnsSink) + (C dim $(if ($script:Cfg.NoHosts) { '  (skipped)' } else { '' })))
    Write-Host ('  ' + (C ink ("$($ips.Count) IP(s)")) + (C dim ' → firewall outbound block') + (C dim $(if ($script:Cfg.NoFirewall) { '  (skipped)' } else { '' })))
    if ($domains.Count -eq 0 -and $ips.Count -eq 0) { Write-Host ('  ' + (C amber '  nothing to block after filtering.')); return }
    $preview = @($domains + $ips | Select-Object -First 12); Write-Host ('  ' + (C dim ('e.g. ' + ($preview -join ', ') + $(if (($domains.Count + $ips.Count) -gt 12) { ' …' } else { '' }))))

    if (-not (Confirm 'Proceed?')) { Write-Host ('  ' + (C dim 'cancelled.')); return }

    # hosts
    $addedH = 0; $skipH = 0
    if ($domains.Count) {
        $backup = Backup-Hosts
        $lines = Read-Hosts
        $present = @{}; foreach ($l in $lines) { foreach ($tok in ($l -split '\s+')) { if ($tok -and $tok -notmatch '^#' -and $tok -notmatch '^\d') { $present[$tok.ToLower()] = 1 } } }
        $append = New-Object 'System.Collections.Generic.List[string]'
        foreach ($d in $domains) {
            if ($present.ContainsKey($d.ToLower())) { $skipH++; continue }
            $append.Add(("{0}`t{1}`t{2}" -f $script:Cfg.DnsSink, $d, $script:Marker)); $addedH++
        }
        if ($append.Count) {
            if ($lines.Count -and $lines[-1].Trim() -ne '') { $lines += '' }
            $lines += ('# added by Block-Hosts ' + (Get-Date -Format 'yyyy-MM-dd HH:mm'))
            $lines += @($append)
            Write-Hosts $lines
        }
        Write-Host ('  ' + (C teal '✓') + ' ' + (C ink ("hosts: added $addedH, skipped $skipH already-present")) + (C dim ("  backup: $backup")))
    }

    # firewall
    if ($ips.Count) {
        $current = @(Get-BlockedIps | Where-Object { $_ -and $_ -ne 'Any' })
        $merged = @($current + $ips | Select-Object -Unique)
        $new = @($ips | Where-Object { $current -notcontains $_ })
        Set-FirewallIps $merged
        Write-Host ('  ' + (C teal '✓') + ' ' + (C ink ("firewall: added $($new.Count), rule now holds $($merged.Count) address(es)")))
    }

    Write-Host ''
    Write-Host ('  ' + (C dim 'Browsers may cache DNS. To apply immediately:  ') + (C amber 'ipconfig /flushdns'))
    Write-Host ('  ' + (C dim 'Undo everything from this file later with:  ') + (C amber ".\Block-Hosts.ps1 -Action remove -Path `"$($script:Cfg.Path)`""))
    Write-Host ''
}

function Do-Remove {
    param($Targets)
    $domains = Expand-Domains $Targets.Domains
    $ips = $Targets.Ips

    Section 'TO UNBLOCK' "  from $(Split-Path $script:Cfg.Path -Leaf)"
    Write-Host ('  ' + (C ink ("$($domains.Count) domain(s), $($ips.Count) IP(s)")))
    if (-not (Confirm 'Remove these from the block lists?')) { Write-Host ('  ' + (C dim 'cancelled.')); return }

    # hosts: drop only OUR tagged lines whose host is in the set
    if (-not $script:Cfg.NoHosts -and $domains.Count) {
        $set = @{}; foreach ($d in $domains) { $set[$d.ToLower()] = 1 }
        $backup = Backup-Hosts
        $kept = New-Object 'System.Collections.Generic.List[string]'; $removed = 0
        foreach ($l in (Read-Hosts)) {
            if ($l -match [regex]::Escape($script:Marker) + '\s*$') {
                $parts = ($l -replace [regex]::Escape($script:Marker), '').Trim() -split '\s+'
                if ($parts.Count -ge 2 -and $set.ContainsKey($parts[1].ToLower())) { $removed++; continue }
            }
            $kept.Add($l)
        }
        Write-Hosts @($kept)
        Write-Host ('  ' + (C teal '✓') + ' ' + (C ink ("hosts: removed $removed line(s)")) + (C dim ("  backup: $backup")))
    }
    # firewall
    if (-not $script:Cfg.NoFirewall -and $ips.Count) {
        $current = @(Get-BlockedIps | Where-Object { $_ -and $_ -ne 'Any' })
        $keep = @($current | Where-Object { $ips -notcontains $_ })
        Set-FirewallIps $keep
        Write-Host ('  ' + (C teal '✓') + ' ' + (C ink ("firewall: removed $($current.Count - $keep.Count), $($keep.Count) remain")))
    }
    Write-Host ''
}

function Do-Restore {
    Section 'RESTORE'
    if (-not (Test-Path $script:BackupDir)) { Write-Host ('  ' + (C amber 'no backups exist yet.')); return }
    $backups = @(Get-ChildItem -Path $script:BackupDir -Filter 'hosts-*.bak' | Sort-Object LastWriteTime -Descending)
    if (-not $backups.Count) { Write-Host ('  ' + (C amber 'no backups exist yet.')); return }
    Write-Host ('  ' + (C dim 'most recent hosts backups:'))
    $i = 0; foreach ($b in ($backups | Select-Object -First 8)) { $i++; Write-Host ('   ' + (C teal ('{0}.' -f $i)) + ' ' + (C ink $b.Name) + (C dim ('   ' + $b.LastWriteTime))) }
    $sel = Ask 'Restore which? (number, or blank to cancel)' ''
    $n = 0; if (-not [int]::TryParse($sel, [ref]$n) -or $n -lt 1 -or $n -gt [math]::Min(8, $backups.Count)) { Write-Host ('  ' + (C dim 'cancelled.')); return }
    $chosen = $backups[$n - 1]
    if (-not (Confirm ("Overwrite the current hosts file with $($chosen.Name)?"))) { Write-Host ('  ' + (C dim 'cancelled.')); return }
    $safety = Backup-Hosts
    Copy-Item -LiteralPath $chosen.FullName -Destination $script:HostsPath -Force
    Write-Host ('  ' + (C teal '✓') + ' ' + (C ink 'hosts file restored') + (C dim ("  (current state saved first as $safety)")))
    Write-Host ('  ' + (C dim 'This restores the hosts file only; firewall IPs are unchanged. Use -Action remove or list for those.'))
    Write-Host ''
}

# ═══════════════════════════════ error guidance ═══════════════════════════════

function Show-Failure {
    param($Err)
    $msg = "$($Err.Exception.Message)"; $me = $PSCommandPath
    Write-Host ''; Write-Host ('  ' + (C rose '✖ The script stopped.') + '  ' + (C dim (Trunc $msg 100))); Write-Host ''
    Write-Host ('  ' + (C bold (C ink 'What to try:')))
    if ($msg -match 'Administrator|Access.*denied|UnauthorizedAccess|denied') {
        Write-Host ('  ' + (C teal '1.') + ' ' + (C ink 'Writing the hosts file and firewall rules needs elevation:'))
        Write-Host ('       ' + (C amber "Start-Process powershell -Verb RunAs -ArgumentList '-ExecutionPolicy Bypass -File `"$me`" -Interactive'"))
        Write-Host ('  ' + (C teal '2.') + ' ' + (C ink 'Or right-click ') + (C amber 'Run-BlockHosts.cmd') + (C ink ' → Run as administrator.'))
        Write-Host ('  ' + (C teal '3.') + ' ' + (C ink 'If it is still denied, security software may be protecting the hosts file (Defender “Tamper”/controlled folder access). Allow this script or the hosts path.'))
    }
    elseif ($msg -match 'Cannot find path|does not exist|not found') {
        Write-Host ('  ' + (C teal '1.') + ' ' + (C ink 'Input file not found. Drag it onto the window, or:  ') + (C amber "& `"$me`" -Action add -Path 'C:\path\block.txt'"))
    }
    elseif ($msg -match 'NetFirewall|not recognized') {
        Write-Host ('  ' + (C teal '1.') + ' ' + (C ink 'Firewall cmdlets unavailable. Run with ') + (C amber '-NoFirewall') + (C ink ' to block domains only, or use ') + (C amber 'powershell.exe') + (C ink ' (not pwsh).'))
    }
    elseif ($msg -match 'not digitally signed|execution polic') {
        Write-Host ('  ' + (C teal '1.') + ' ' + (C amber "Unblock-File `"$me`"") + (C ink '   or use Run-BlockHosts.cmd'))
    }
    else {
        Write-Host ('  ' + (C teal '1.') + ' ' + (C ink 'The combination that works on almost any machine (elevated):'))
        Write-Host ('       ' + (C amber "powershell -NoProfile -ExecutionPolicy Bypass -File `"$me`" -Interactive"))
    }
    Write-Host ''; Write-Host ('  ' + (C dim ('at: ' + ("$($Err.InvocationInfo.PositionMessage)" -replace '\s+', ' ')))); Write-Host ''
}

# ═══════════════════════════════ menu ═══════════════════════════════

function Invoke-Menu {
    Write-Host ''; Write-Host ('  ' + (C teal '▌') + ' ' + (C bold (C ink 'BLOCK-HOSTS')) + '  ' + (C dim 'interactive setup — Enter accepts the default')); Write-Host ''
    Write-Host ('  ' + (C bold (C ink 'Action')))
    Write-Host ('   ' + (C teal '1.') + ' ' + (C ink 'Block    ') + (C dim '— add domains/IPs from a file'))
    Write-Host ('   ' + (C teal '2.') + ' ' + (C ink 'List     ') + (C dim '— show what is currently blocked by this tool'))
    Write-Host ('   ' + (C teal '3.') + ' ' + (C ink 'Unblock  ') + (C dim '— remove the entries listed in a file'))
    Write-Host ('   ' + (C teal '4.') + ' ' + (C ink 'Restore  ') + (C dim '— roll the hosts file back to a backup'))
    $a = Ask 'Action' '1'
    switch ($a) { '2' { $script:Cfg.Action = 'list' } '3' { $script:Cfg.Action = 'remove' } '4' { $script:Cfg.Action = 'restore' } default { $script:Cfg.Action = 'add' } }

    if ($script:Cfg.Action -in @('add', 'remove')) {
        if (-not $script:Cfg.Path) {
            do { $p = Ask 'File of domains/IPs (drag it here to paste the path)' ''; if ($p -and -not (Test-Path -LiteralPath $p)) { Write-Host ('  ' + (C amber '  not found')); $p = '' } } while (-not $p)
            $script:Cfg.Path = $p
        }
    }
    if ($script:Cfg.Action -eq 'add') {
        $m = Ask 'Block what? (1) domains+IPs (2) domains only (3) IPs only' '1'
        switch ($m) { '2' { $script:Cfg.NoFirewall = $true } '3' { $script:Cfg.NoHosts = $true } }
        $sink = Ask 'Point blocked domains at which address?' $script:Cfg.DnsSink; $script:Cfg.DnsSink = $sink
    }
    Write-Host ''
}

# ═══════════════════════════════ main ═══════════════════════════════

$script:Cfg = @{ Action = $Action; Path = $Path; DnsSink = $DnsSink; NoFirewall = [bool]$NoFirewall; NoHosts = [bool]$NoHosts; Yes = [bool]$Yes }
try {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    $gave = $false; foreach ($a in @('Action', 'Path', 'DnsSink', 'NoFirewall', 'NoHosts')) { if ($PSBoundParameters.ContainsKey($a)) { $gave = $true } }
    if ($Interactive -or -not $gave) { Invoke-Menu }
    $cfg = $script:Cfg

    $needsAdmin = $cfg.Action -in @('add', 'remove', 'restore')
    if ($needsAdmin -and -not $isAdmin) {
        Write-Host ''; Write-Host ('  ' + (C amber '▲') + ' ' + (C ink 'This action writes the hosts file / firewall and needs Administrator.'))
        $e = Ask 'Relaunch as Administrator now? (y/n)' 'y'
        if ($e -match '^y') {
            $argLine = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Action $($cfg.Action)"
            if ($cfg.Path) { $argLine += " -Path `"$($cfg.Path)`"" }
            if ($cfg.NoFirewall) { $argLine += ' -NoFirewall' }; if ($cfg.NoHosts) { $argLine += ' -NoHosts' }
            if ($cfg.DnsSink -ne '0.0.0.0') { $argLine += " -DnsSink $($cfg.DnsSink)" }
            if (-not $script:UseColor) { $argLine += ' -NoColor' }
            try { Start-Process powershell -Verb RunAs -ArgumentList $argLine; exit 0 } catch {}
        }
        throw 'Administrator rights are required for this action.'
    }

    Write-Host ''
    Write-Host ('  ' + (C teal '▌') + ' ' + (C bold (C ink 'BLOCK-HOSTS')) + '  ' + (C dim ("action: $($cfg.Action) · " + (Get-Date -Format 'yyyy-MM-dd HH:mm'))))

    switch ($cfg.Action) {
        'list'    { Do-List }
        'restore' { Do-Restore }
        default {
            if (-not (Test-Path -LiteralPath $cfg.Path)) { throw "Cannot find path '$($cfg.Path)'." }
            $t = Get-Targets @(Get-Content -LiteralPath $cfg.Path -ErrorAction Stop)
            if ($t.Domains.Count -eq 0 -and $t.Ips.Count -eq 0) { throw 'No domains or IPs found in that file.' }
            if ($cfg.Action -eq 'remove') { Do-Remove $t } else { Do-Add $t }
        }
    }
}
catch { Show-Failure $_; exit 1 }

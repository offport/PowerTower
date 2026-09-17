# Watch-Connections

A live, in-terminal view of every IP, port, **domain** and protocol this machine is talking to — with the owning process, the detected service, and filters you can set before you start or change at any moment while it runs.

**The script only reads. It never touches a connection.**

---

## Quick start

Put both files in the same folder.

| You want to… | Do this |
|---|---|
| Just run it | Double-click **`Run-Connections.cmd`** |
| See owning processes for system services | Right-click `Run-Connections.cmd` → **Run as administrator** |
| From a PowerShell prompt | `.\Watch-Connections.ps1` |
| Skip the menu | `.\Watch-Connections.ps1 -Port 443 -Process chrome` |

Works without elevation for everything except attributing system-service sockets to their process. If Windows says *not digitally signed*: `Unblock-File .\Watch-Connections.ps1`, or use the `.cmd`.

Needs a real console — Windows Terminal or a PowerShell window, not the ISE.

---

## Filtering

Filters can be set three ways and they all use the same syntax.

**Before it starts** — the menu asks for ports, process and host; or pass arguments.

**While it runs** — press `f`, type a filter, Enter. Press `c` to clear.

**Syntax** — space-separated tokens, all must match:

| Token | Matches |
|---|---|
| `port:443,53` | local **or** remote port is one of these |
| `proc:chrome` | process name contains |
| `host:google` | domain **or** IP contains |
| `svc:https` | detected service contains (https, dns, rdp, smb, ssh…) |
| `proto:tcp` / `proto:udp` | protocol |
| `ip:104.18` | remote IP contains |
| `state:established` | TCP state contains |
| `443` | a bare number is a port |
| `amazon` | bare text is a host |

Examples: `svc:https host:amazon` · `proc:ollama` · `port:53 proto:udp` · `state:synsent`

**Toggles** (one key each, on/off, shown lit in the header): `t` TCP · `u` UDP · `l` listening sockets · `i` loopback and link-local · `n` name resolution.

---

## Keys

| Key | Action |
|---|---|
| `q` | Quit — prints a summary of remote hosts that stays in scroll-back |
| `f` | Set a filter |
| `c` | Clear the filter |
| `g` | Toggle **group by remote host** |
| `s` | Cycle sort: newest → process → remote host → service → oldest |
| `p` | Pause sampling |
| `t` `u` `l` `i` `n` | Toggles above |
| `+` / `-` | Slower / faster refresh (0.5 s – 10 s) |

---

## What you see

### Header

```
  ▌ CONNECTIONS  since launch 2:41 · LIST · sort: newest · every 1s
  TCP UDP LISTEN LOOPBACK NAMES   live 47 · hosts 31 · processes 9 · opened 212 · closed 165 · pending lookups 3
  filter: svc:https host:google
```

Lit toggles are teal, off ones dim. The counters are cumulative since launch.

### List mode

```
  PROTO SERVICE    PROCESS            LPORT REMOTE                 DOMAIN                                STATE        AGE
+ TCP  https      chrome              61042 142.250.72.14:443      lhr48s29-in-f14.1e100.net             Established    2s
  TCP  https      Code                60911 20.42.73.29:443        default.exp-tas.com                   Established   4m
  TCP  ollama     ollama              11434 127.0.0.1:52210        ·                                     Established  12m
× TCP  https      msedge              60877 13.107.42.16:443       api.bing.com                          TimeWait      9m
  UDP  dns        svchost                53 *                                                            open          2h
```

| Mark | Meaning |
|---|---|
| `+` teal row | Opened in the last 3 seconds |
| `×` grey row | Closed — fades for 6 seconds, then drops |
| `…` in DOMAIN | Reverse lookup still in flight |

State colours: established white, SYN amber (connecting), TIME_WAIT / CLOSE_WAIT red (tearing down), LISTEN dim.

### Group by host (`g`)

One row per remote domain: live and total connection counts, which processes talk to it, which services, and which ports. This is the "who is my machine actually talking to" view, sorted by activity.

---

## Where the domain names come from

Two sources, in order of preference:

1. **The DNS client cache** — the name the application *actually resolved* before connecting. This is the accurate one: `api.github.com`, not the CDN node's hostname. Refreshed every few seconds.
2. **Reverse DNS** — for IPs with no cache entry. Often gives a CDN or ISP name (`ec2-…compute.amazonaws.com`) or nothing at all. Lookups run asynchronously in the background so the display never stalls; `…` shows one in flight.

`n` turns resolution off entirely if you just want IPs.

---

## Services

Detected from the well-known port on either end: http, https, dns, dns-tls, ssh, rdp, smb, ldap, kerberos, ntp, smtp/imap/pop, winrm, vnc, mysql/postgres/mssql/mongo/redis/elastic, openvpn, wireguard, ipsec, stun, sip, mdns, llmnr, ssdp, and a few local-dev ones (ollama, lmstudio, http-dev, http-alt). Unknown ports show blank — the port number is still in the row.

---

## Arguments

Give any of these and the menu is skipped. Add `-Interactive` to get the menu anyway.

| Parameter | Default | What it does |
|---|---|---|
| `-Protocol tcp\|udp\|both` | both | Transport protocols to show |
| `-Port 443,53` | all | Only these ports (local or remote) |
| `-Process chrome` | all | Process name contains |
| `-RemoteHost google` | all | Domain or IP contains |
| `-Filter 'svc:https state:established'` | none | Free-form, same syntax as the `f` key |
| `-IncludeListening` | off | Show LISTEN sockets and UDP endpoints |
| `-IncludeLoopback` | off | Show 127.x / ::1 / link-local / multicast |
| `-NoResolve` | off | IPs only |
| `-Interval 1` | 1 | Seconds between refreshes (min 0.5) |
| `-Log .\conns.csv` | none | Append every **new** connection: time, protocol, process, PID, local, remote, service, state |
| `-NoColor` | off | Plain text |
| `-Interactive` | off | Force the menu |

```powershell
.\Watch-Connections.ps1 -Port 443 -Process chrome
.\Watch-Connections.ps1 -Filter 'svc:https host:amazon' -Log .\conns.csv
.\Watch-Connections.ps1 -Protocol udp -IncludeListening
```

---

## Honest limits

**UDP has no remote peer.** UDP is connectionless and Windows keeps no table of who a UDP socket last spoke to — `netstat` can't show it either. UDP rows therefore show the local endpoint and owning process only (`*` in REMOTE). The DNS cache still tells you which names were looked up, which covers the most common UDP traffic. Seeing UDP peers needs packet capture (`pktmon`, Wireshark).

**No byte counts.** Per-connection throughput isn't exposed by the connection table. The tool shows *who* and *for how long*, not *how much*. For bytes per process, use the companion Watch-ProcessHogs; for bytes per connection you need capture.

**Reverse DNS lies a little.** A PTR record names the server, not the site — `104.18.x.x` reverse-resolves to nothing useful, though the DNS cache will usually have the real name.

---

## Error handling

| What happened | What it tells you |
|---|---|
| Not a real console | Use Windows Terminal or the `.cmd` |
| `Get-NetTCPConnection` unavailable | Check the NetTCPIP module; on PowerShell 7 try `powershell.exe` instead of `pwsh` (the launcher already does) |
| Access denied | The exact elevation command with the script's own path |
| `not digitally signed` | `Unblock-File` or the `.cmd` |
| Anything else | The one combination that works almost anywhere, plus the line number |

The cursor is restored on every exit path.

---

## Requirements

- Windows 10 / 11 (NetTCPIP module — built in)
- Windows PowerShell 5.1 recommended; PowerShell 7 works via module compatibility
- A console with VT support for colour; `-NoColor` otherwise

---

## Files

| File | Purpose |
|---|---|
| `Watch-Connections.ps1` | The monitor |
| `Run-Connections.cmd` | Launcher — bypasses execution policy for one run; uses Windows PowerShell for NetTCPIP compatibility |
| `README-Connections.md` | This file |

Companions: **Watch-ProcessHogs** (what's running), **Get-StorageHogs** (what's on disk), **Find-DeletedFiles** (what was deleted).

# Test-Reachability

Feed it any text or CSV file — an IOC dump, a firewall export, a log, a list of servers, a threat-intel report — and it pulls out every IP and domain it can find, de-duplicates them, and checks whether you can reach each one on the ports you choose. Results on screen, optionally to CSV.

**It sends nothing but a TCP handshake** (and an ICMP echo if you ask). No HTTP requests, no banners, no data.

---

## Quick start

| You want to… | Do this |
|---|---|
| Just run it | Double-click **`Run-Reachability.cmd`** — it asks for the file and ports |
| Fastest | **Drag the .txt or .csv onto `Run-Reachability.cmd`** |
| From PowerShell | `.\Test-Reachability.ps1 -Path .\iocs.txt` |
| Custom ports | `.\Test-Reachability.ps1 -Path .\hosts.csv -Port 22,443,3389` |

No elevation needed. If Windows says *not digitally signed*: `Unblock-File .\Test-Reachability.ps1`, or use the `.cmd`.

---

## What it extracts

The file can be messy. Each line is scanned for:

| Kind | Examples it handles |
|---|---|
| **IPv4** | `10.0.0.5`, `203.0.113.7:8443`, inside URLs or log text |
| **IPv6** | `2001:db8::1`, `[2001:db8::1]:443` — validated, so timestamps like `12:30:45` don't match |
| **Domains** | `api.example.com`, `https://cdn.example.net/path`, `user@corp.example.org`, `xn--…` punycode |
| **Defanged indicators** | `hxxp://evil[.]com`, `evil(.)com`, `evil{dot}com`, `evil\.com`, `bad[:]443`, `user[at]host` |
| **host:port** | A port found right after a host (`10.0.0.5:8443`, `db.internal:5432`) is **tested on that port too**, automatically |

Domains are validated against a list of common TLDs plus all two-letter country codes, so `report.docx`, `script.ps1` and `image.png` are ignored. Two-letter TLDs that collide with file extensions (`.md`, `.sh`, `.py`, `.pl`, `.rs`, `.js`…) are skipped only when the candidate is a bare `name.ext` — `docs.example.md` still counts.

CSV files are read as text, so it doesn't matter which column the hosts are in or whether the quoting is tidy.

---

## What you see

```
  ▌ REACHABILITY  iocs.txt · 412 lines · ports 80,443 +2 from file · timeout 3s · 2026-09-14 22:10
  extracted 61 domain(s) and 18 IP(s) — 79 unique targets

  ┌─ RESULTS ────────────────────────────────  ✓ open · ✗ refused · ⏱ timeout · ∅ no route · dns✗ unresolved
  TARGET                            RESOLVED         :80         :443        :8443
  api.github.com                    140.82.113.5     ✓ 41ms      ✓ 38ms
  cdn.example.net                   NXDOMAIN         dns✗        dns✗
  db.internal                       10.20.3.11 ⌂     ✗ refused   ✗ refused   ✓ 2ms
  203.0.113.7                       203.0.113.7      ⏱ timeout   ⏱ timeout

  ┌─ SUMMARY
  ■   54  reachable on at least one tested port
  ■   17  resolved but nothing open on the tested ports
  ■    8  did not resolve
```

Domains are white, IPs violet. `⌂` marks private or reserved addresses. Per-port results:

| Result | What it means |
|---|---|
| `✓ 41ms` | TCP connection completed — something is listening |
| `✗ refused` | The host answered, but nothing listens on that port (RST) |
| `⏱ timeout` | No answer at all — almost always a firewall silently dropping the packet |
| `∅ no route` | Your side has no route to that network |
| `dns✗` | The domain didn't resolve; nothing was tested |

`-ShowSources` adds a line under each target saying which line number(s) of the file it came from.

---

## Arguments

Give any of these and the menu is skipped. `-Interactive` forces it.

| Parameter | Default | What it does |
|---|---|---|
| `-Path .\file.txt` | asks | Input file, `.txt` or `.csv` |
| `-Port 80,443` | 80,443 | Ports to test on every target. Ports found in the file are added per target |
| `-Timeout 3` | 3 | Seconds per connection attempt |
| `-Concurrency 64` | 64 | Connections in flight at once |
| `-Ping` | off | Also send an ICMP echo; shows round-trip time |
| `-ExportCsv .\reach.csv` | none | One row per target with resolution, ping, and a result + latency column per port |
| `-ShowSources` | off | Show source line numbers |
| `-NoColor` | off | Plain text |
| `-Interactive` | off | Force the menu |

```powershell
.\Test-Reachability.ps1 -Path .\iocs.txt
.\Test-Reachability.ps1 -Path .\servers.csv -Port 22,3389,5985 -Ping -ExportCsv .\reach.csv
.\Test-Reachability.ps1 -Path .\report.txt -Port 443 -Timeout 1.5 -Concurrency 128
```

---

## How it works

- Domains are resolved first, in parallel, with the same timeout as connections. IPv4 addresses are preferred when a name has both.
- Each target × port becomes one async TCP connect. Up to `-Concurrency` run at once; each is timed individually, so latency is real per-connection time, not batch time.
- Only the **first** resolved address is tested. If a name round-robins across many IPs, the CSV lists all of them.
- Everything is closed and disposed after the check. The handshake is the only traffic.

A few hundred targets on two ports typically finishes in under a minute; the limit is mostly your timeout multiplied by however many targets silently drop.

---

## Interpreting results honestly

**Reachability is from *this* machine.** A corporate proxy, VPN, or egress firewall changes the answer completely. `⏱ timeout` on port 443 to a known-good site usually means *your* network blocks direct outbound, not that the site is down.

**Open ≠ safe, closed ≠ blocked.** An open port only means a TCP listener exists. It says nothing about what's behind it.

**Domains are tested at resolution time.** If you're checking threat-intel indicators, note that malicious domains are often parked or sinkholed — resolving and answering on 443 is not evidence of activity.

---

## Error handling

| What happened | What it tells you |
|---|---|
| File not found | Drag-and-drop tip and the exact `-Path` invocation |
| Nothing extracted | Check it's text, not a PDF/Excel binary; save `.xlsx` as CSV first |
| Bad port | Valid range and the syntax |
| `not digitally signed` | `Unblock-File` or the `.cmd` |
| Anything else | The combination that works on almost any machine, plus the line number |

---

## Files

| File | Purpose |
|---|---|
| `Test-Reachability.ps1` | The script |
| `Run-Reachability.cmd` | Launcher — bypasses execution policy for one run; drag a file onto it to test that file |
| `README-Reachability.md` | This file |

Companions: **Watch-Connections** (live view of what the machine is talking to), **Watch-ProcessHogs**, **Get-StorageHogs**, **Find-DeletedFiles**.

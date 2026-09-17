# Block-Hosts

Takes a messy text or CSV file of domains and IPs and blocks them — domains through the Windows **hosts file**, IPs through a **Windows Firewall** rule — and can cleanly undo everything it did.

Same extractor as Test-Reachability, so URLs, log lines and defanged indicators (`evil[.]com`, `hxxp://…`) all work as input.

---

## Read this first: two mechanisms, on purpose

A hosts file **cannot block an IP address**, and it blocks a domain name **exactly**, not its subdomains. So this tool splits the job:

| Input | Mechanism | Why |
|---|---|---|
| **Domains** | hosts file → `0.0.0.0` | The standard way. `0.0.0.0` fails instantly; `127.0.0.1` makes your PC wait to refuse its own connection. |
| **IPs** | one Firewall outbound-block rule | The *only* thing that blocks an IP. The hosts file can't. |

**The subdomain caveat that trips everyone up:** blocking `doubleclick.net` in the hosts file does **not** block `ads.doubleclick.net`. There's no wildcard in a hosts file. This tool auto-adds the `www.` variant of bare domains, but any other subdomain you care about must be in your input file explicitly. If you need true wildcard blocking, that's a DNS-level job (Pi-hole, AdGuard Home, or a DNS server) — see the note at the end.

Everything this tool writes is **tagged** and **backed up**, so removal is exact and your own hosts entries are never touched.

---

## Quick start

Requires Administrator.

| You want to… | Do this |
|---|---|
| Block from a file | Right-click **`Run-BlockHosts.cmd`** → Run as administrator |
| Fastest | Drag a `.txt`/`.csv` onto `Run-BlockHosts.cmd` |
| From an elevated prompt | `.\Block-Hosts.ps1 -Action add -Path .\block.txt` |
| See what's blocked | `.\Block-Hosts.ps1 -Action list` |
| Undo one file | `.\Block-Hosts.ps1 -Action remove -Path .\block.txt` |
| Roll hosts back | `.\Block-Hosts.ps1 -Action restore` |

Run non-elevated and it offers to relaunch itself. If Windows says *not digitally signed*: `Unblock-File .\Block-Hosts.ps1`, or use the `.cmd`.

---

## Actions

**add** (default) — extract, show a preview and counts, ask to confirm, then write. Domains that already exist in the hosts file (yours or anyone's) are skipped, not duplicated. IPs are merged into the single firewall rule.

**list** — everything this tool has blocked, in both mechanisms. Reads the marker tag and the named rule; doesn't touch anything.

**remove** — extract from a file and remove exactly those entries. Only lines carrying this tool's marker are eligible, so a domain you added to the hosts file by hand is never removed even if it's in the file.

**restore** — pick from the timestamped hosts-file backups and roll back. The current file is itself backed up first, so restore is also undoable. (Restore covers the hosts file only; use list/remove for firewall IPs.)

---

## Safety model

- **Backup before every write.** Copies of the hosts file go to `%ProgramData%\BlockHosts\backups\hosts-<timestamp>.bak` before any add, remove or restore.
- **Marker tag.** Every line the tool adds ends with `# BLOCK-HOSTS`. Removal matches on that tag, so the tool only ever deletes its own lines. Don't edit the tag by hand.
- **Named firewall rule.** All blocked IPs live in one rule, `BLOCK-HOSTS blocked IPs`. You can see it in `wf.msc` and delete it there too if you ever want to.
- **Confirmation.** Every write is previewed and confirmed unless you pass `-Yes`.
- **Never touches your entries.** Existing hosts lines and other firewall rules are left exactly as they were.

---

## Arguments

| Parameter | Default | What it does |
|---|---|---|
| `-Action add\|list\|remove\|restore` | add | What to do |
| `-Path .\block.txt` | asks | Input file (add / remove) |
| `-DnsSink 0.0.0.0` | 0.0.0.0 | Address blocked domains resolve to |
| `-NoFirewall` | off | Domains only; skip IPs |
| `-NoHosts` | off | IPs only; skip the hosts file |
| `-Yes` | off | Don't prompt before writing |
| `-NoColor` | off | Plain text |
| `-Interactive` | off | Force the menu |

```powershell
.\Block-Hosts.ps1 -Action add -Path .\adservers.txt
.\Block-Hosts.ps1 -Action add -Path .\malware-ips.csv -NoHosts        # firewall only
.\Block-Hosts.ps1 -Action list
.\Block-Hosts.ps1 -Action remove -Path .\adservers.txt -Yes
.\Block-Hosts.ps1 -Action restore
```

---

## After blocking

Domains take effect immediately for new connections, but browsers and the OS cache DNS. To force it:

```powershell
ipconfig /flushdns
```

Chrome and Edge keep their own cache too — `chrome://net-internals/#dns` → Clear, or just restart the browser.

---

## Limits worth knowing

- **No subdomain wildcards.** As above — the hosts file matches exact names only.
- **DoH bypasses the hosts file for name lookups**, but not for the connection: once a browser using DNS-over-HTTPS resolves a name, it still connects to the IP, and the hosts entry pointing the name at `0.0.0.0` still applies because the hosts file is consulted by the OS resolver the app hands the name to… except when the app resolves over DoH *itself* (some browsers do). For those, block the IP via the firewall instead, or turn off the browser's secure DNS.
- **Firewall blocks by IP, and IPs move.** CDNs and fast-flux hosts change addresses; an IP block is a point-in-time measure.
- **This is host-level, one machine.** For the whole network, block at the router or a DNS sink (see below).

---

## When you outgrow this

For network-wide, wildcard-capable, self-updating blocking, a DNS sinkhole is the right tool: **Pi-hole** or **AdGuard Home** on a Raspberry Pi or small always-on box, with your router handing out its address. That blocks whole domains including all subdomains, for every device, and takes subscription block-lists. This script is the right tool for one machine, a specific list, or something you need on and off quickly.

---

## Error handling

| What happened | What it tells you |
|---|---|
| Not elevated | Offers to relaunch; otherwise the exact command |
| Access denied even when elevated | Security software may be protecting the hosts file (Defender tamper protection / controlled folder access) — allow this script or the hosts path |
| Firewall cmdlets missing | Use `-NoFirewall`, or run under `powershell.exe` not `pwsh` |
| File not found / nothing extracted | Path and drag-drop tips |
| `not digitally signed` | `Unblock-File` or the `.cmd` |

---

## Files

| File | Purpose |
|---|---|
| `Block-Hosts.ps1` | The script |
| `Run-BlockHosts.cmd` | Launcher — run as administrator; drag a file onto it to block that file |
| `README-BlockHosts.md` | This file |

Companions: **Test-Reachability** (check the same lists are reachable *before* blocking), **Watch-Connections**, **Find-DeletedFiles**, **Watch-ProcessHogs**, **Get-StorageHogs**.

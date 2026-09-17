# PowerTower — tool reference

> The overview with screenshots is the [repository README](../README.md); this page is the tool-by-tool reference.

A portable Windows desktop app with the same jobs as the scripts in the folders beside this one,
done as rows you can sort, search, tick and act on instead of console text. One `.exe`, no
installer: it runs on the .NET Framework that is already part of Windows 10 and 11. Copy the whole
`PowerTower` folder anywhere and double-click `Toolbox\PowerTower.exe`.

**The scripts are untouched.** The app is a separate copy of their logic in C# (`Net.cs`, `Sys.cs`,
`Vuln.cs`), rebuilt so every result is an object with columns rather than a line of text. The
`.ps1` files and their `Run-*.cmd` launchers keep working exactly as before.

```
┌ sidebar ─────────────┐┌ Vulnerability Management ────────────────────────────────────────────────┐
│ Domain and IP Blocker││ [Findings][Missing updates][Software][Hotfixes]  [Scan this machine][Cancel]│
│ Reachability Verifier││ [x] Windows Update [x] Microsoft CVEs [x] third-party (NVD) [x] KEV [x] EPSS │
│ Connections Monitor  ││ ┌OS BUILD────────┐┌REBOOT──┐┌CRITICAL┐┌HIGH┐┌KNOWN EXPLOITED┐┌MISSING┐┌SOFTWARE┐│
│ Resource Usage       ││ │10.0.26200.6584 ││pending ││   1    ││ 3  ││      2        ││   3   ││ 50/12  ││
│ Disk Usage           ││ └────────────────┘└────────┘└────────┘└────┘└───────────────┘└───────┘└────────┘│
│ Deleted Files Finder ││ [Grid][Details][Tree] [search…] [Select all][None][Invert][Export CSV…] filters │
│ Vulnerability Mgmt   ││ [ ] CVE-2026-31234  Critical 9.8  KEV   vulnerable  Windows 11 25H2 …  KB5066000│
│                      ││ [x] CVE-2026-27101  High     8.8        vulnerable  Google Chrome   …  upgrade… │
│ [Restart as admin]   ││ 2 findings selected  [Copy CVE IDs][Open advisories][Copy as text][Export…]     │
└──────────────────────┘└────────────────────────────────────────────────────────────────────────────┘
```

---

## What it is - and what it is not

**It is**

- **Twenty-two tools, one window.** Every tool has its own icon in the sidebar; **About & Guide** lists them all. Audit the system, block domains and IPs, verify reachability, watch
  live connections, monitor resource usage, analyze disk usage, find deleted files, browse and act on
  files, find files by name or hash, manage vulnerabilities, inventory software and its CVEs, run a security checklist, map the findings.
- **Rows, not text.** Every tool shows its results in the same view: a **grid**, a **details** pane
  (the row plus every property), or a **tree** (grouped: by kind, by folder, by source). Type to
  search, click a header to sort, tick rows (shift-click for a range, `Space` toggles, `Ctrl+A`
  selects all, `Ctrl+C` copies), then act on the ticked rows from the bar that appears at the bottom.
- **Filters on every column.** *Filter* opens a rule bar: pick a column (or *any column*), an
  operator - *contains*, *does not contain*, *equals*, *does not equal*, *starts with*, *ends with*,
  *matches regex*, *is empty*, *is not empty*, *greater than*, *less than*, *at least*, *at most* -
  and a value. Rules stack as chips (click one to remove it) and combine with AND; the number
  operators understand units, so `Size at least 10 MB` and `DNS less than 50` work on the values you
  see. Or click the small **funnel** in any column header to filter that column from a checklist of
  its distinct values (with counts) or a contains box; the funnel turns teal when that column is
  filtered. Right-click any cell for the quick versions: filter on that value, exclude it, copy the
  cell, the row, or the whole column.
- **Visible progress.** Long scans (the audit, the vulnerability scan) show a step strip: each stage
  with its state and result count, a progress line, the current action and the elapsed time.
- **Editable where it makes sense.** In the blocker a value can be retyped in its row and is
  re-classified as a domain, IPv4 or IPv6 on the spot.
- **Exportable.** *Export CSV…* on every view writes what is shown, or only the ticked rows.
- **Portable and reversible.** Settings live in `settings.ini` next to the exe; downloaded feeds in
  `cache\`. The hosts file is backed up before every change; IPs go into one named firewall rule.
- **Themes.** Pick one in the sidebar footer and the whole app re-tints in place, no restart: **Dark teal**
  (default), **Hacker green** (phosphor green on black), **Red**, or **Windows** (light mica grey, white cards,
  Windows-blue accent — including a light, paper-style network map). The choice is remembered in `settings.ini`;
  `--theme <name>` overrides it for one run.
- **Honest about rights.** Tools that need administrator rights say so in the header; *Restart as
  administrator* relaunches elevated and comes back on the same tool.

**It is not**

- **Not a script runner.** Nothing is executed through `powershell.exe`; the app has its own
  engines. If you change a script, the app does not change with it (and the other way round).
- **Not an installer of anything.** No service, no scheduled task, no registry settings outside
  the hosts file and firewall rule you ask for.
- **Not a remote tool.** Everything is about this machine. The vulnerability feeds are the only
  network traffic, all of it outbound to public APIs, and each can be switched off.

---

## The tools

### 1 · 🚫 Domain and IP Blocker

Load domains and IPs from any file (*Add from file…*), a paste (*Paste…*) or by typing (*Add entry*).
The extractor pulls hosts out of URLs, log lines, CSV cells, prose and defanged forms
(`evil[.]com`, `hxxps://`), keeps the source line number, and drops file names that look like
domains (`setup.ps1`, `notes.md`).

| Column | Meaning |
|---|---|
| Domain / IP | the value; editable in place |
| Kind | domain · IPv4 · IPv6 · invalid |
| Status | blocked · not blocked · not a valid domain or IP |
| Blocked by | hosts file · firewall · both |
| Line · Source line | where it came from |

*Block selected* writes domains to the hosts file (tagged `# BLOCK-HOSTS`, resolving to the
address in *resolve to*, with a `www.` twin when ticked) and IPs to the firewall rule
`BLOCK-HOSTS blocked IPs`. *Unblock selected* removes them. **Blocked now** switches the rows to what
is currently in the hosts file and the rule, so anything can be unblocked later. *Backups…* lists
the hosts-file backups (`%ProgramData%\BlockHosts\backups`) and restores one; *Flush DNS* runs
`ipconfig /flushdns`. Writing needs administrator rights; listing does not.

### 2 · 📡 Reachability Verifier

Same loaders. For every target: DNS (and what it resolves to), an optional ping, and a TCP connect
to each port you list (`443, 80, 8443`), with a timeout and a parallelism you choose. Status is
**reachable**, **ping only**, **resolves**, **unreachable** or **no DNS**; each port gets its own
column with the connect time. *Send to blocker* hands the ticked rows to tool 1.

### 3 · 🔗 Connections Monitor

Every TCP and UDP endpoint (v4 and v6) the machine has, refreshed every second: protocol, process,
PID, local and remote address and port, state, remote host name (reverse DNS in the background),
first and last seen. Filters for protocol, state, loopback and process; closed connections linger
greyed for 30 s so short-lived ones are not missed. *Pause* freezes the table. *Block remote IPs*
sends the ticked rows' addresses to the blocker; *Copy remote IPs* puts them on the clipboard.

### 4 · 📈 Resource Usage

Three gauges (CPU, memory, disk I/O) with sparklines, and one row per process (or per process
name when *group by name* is ticked): CPU %, CPU time since you opened the tool, share of all CPU
time, a trend sparkline, memory and its peak, bytes read and written. Exited processes stay,
greyed, because what they used still counts. *Reset counters* starts the accounting again.
*End selected processes…* asks first.

### 5 · 💽 Disk Usage

Pick a drive or a folder and a minimum file size, then *Scan*. **Show** switches between the
largest files, the biggest folders and the file types; the **tree** view is the folder tree with
sizes and each folder's share of its parent. Actions on ticked rows: *Open in Explorer*, *Copy
paths*, *Move to Recycle Bin…* (asks first; the bin, so it is reversible).

### 6 · 🗑️ Deleted Files Finder

What was deleted on each drive in the last *n* days and whether it can come back. Sources: the NTFS
change journal (needs administrator rights), the directory tables of exFAT drives read raw (no
rights needed; works on external SSDs), shadow copies that still hold the file, and sets of files
emptied from the Recycle Bin (shown as cards with the deletion time). Filters for source and
*recoverable only*; a path filter; *include noise* shows temp and cache files too. Narrow the scan up
front by **type** (extensions), **name has** (a substring) and a **size** range with a KB/MB/GB unit, and
watch a per-drive step strip while it runs. *Recover selected to…* copies the ticked rows to another
drive (never the same one, so nothing is overwritten). "Recoverable" is "yes" only for exFAT files whose
data is still intact, or NTFS files still held in a shadow copy; the change journal records the deletion,
not the data.

### 7 · 📁 File Explorer

A two-pane browser: a folder tree on the left, the current folder's files on the right, with a path
box, *Up*, *Refresh*, *New folder* and *show hidden*. The file list is the same view as everywhere
else, so you can search, sort, filter and multi-select across it. Folders show teal, encrypted `.enc`
files show amber. The actions on the ticked files:

- **Encrypt…** — AES-256 with a password you set. Each file is written to a new `.enc`, verified that
  it decrypts, and only then the original is permanently deleted. **A lost password cannot be
  recovered** — the key is derived from the password alone (PBKDF2, 200k iterations), and the file is
  authenticated with HMAC-SHA256 so a wrong password or a corrupted file is rejected, not mis-decrypted.
- **Decrypt…** — the reverse, with the same password. The decrypted file is written next to the `.enc`,
  which is kept. A wrong password stops before writing anything.
- **Permanent delete…** — bypasses the Recycle Bin. Not recoverable. Asks first, showing the count and
  total size.
- **Secure wipe…** — overwrites each file with random data, then a zero pass, then deletes it. Asks
  twice. On SSDs, wear-levelling means it defeats casual recovery, not forensic recovery.

### 8 · 🔎 Find Files

One panel, two modes.

- **By name** — type a full or partial name, or a `*.ext` / `data????.csv` wildcard, pick a drive or
  *all fixed drives*, and it walks the tree on several threads, streaming matches as they turn up.
- **By hash** — paste one or more MD5, SHA-1 or SHA-256 hashes (an IOC list, one per line, `#` comments
  ignored) and it reports every file whose hash matches, with the algorithm and path. A **max file
  size** cap (default 100 MB) and a *skip Windows folder* toggle keep it fast; both are adjustable.

*Open location*, *Copy paths* and *Export results* act on the selection. Results stream in live with a
running count of folders scanned.

The **hash** box takes **many hashes of mixed types at once** — paste a plain list, a log line, JSON or a
threat-intel report and every MD5, SHA-1 and SHA-256 in it is pulled out by regex wherever it sits (a 64-char
SHA-256 is never mis-split into shorter hashes); **Add from file…** loads them straight from a file. Both
name and hash searches show a **live progress strip**: folders walked, files seen, matches so far and the file
being read, with the elapsed time.

### 9 · 🛡️ Vulnerability Management

The goal of the *patchproof* project, for this machine, offline-capable:

| Step | Source | What it produces |
|---|---|---|
| Inventory | registry, `Win32_QuickFixEngineering`, the CBS servicing store, Windows Update history | OS build with UBR, installed hotfixes and the set of known KBs, pending-reboot signals, installed software (64-bit, 32-bit and per-user uninstall hives; never `Win32_Product`) |
| Windows Update | `Microsoft.Update.Session` | the updates offered to this machine right now, with severity, kind, size and the CVEs each one fixes |
| Microsoft CVEs | MSRC CVRF monthly releases (public API) | one finding per applicable CVE: **build comparison** (host UBR ≥ the fix's FixedBuild → patched) first, **KB + supersedence graph** for products without a FixedBuild (Office, .NET…), **reboot pending** when the KB is installed but the running build has not moved |
| Third-party | NVD 2.0, per installed program in the product map (7-Zip, Chrome, Firefox, Git, VLC, Wireshark, Nmap, Edge, VS Code, Notepad++, PuTTY, WinRAR, Node.js, VirtualBox …) | findings only where the installed version falls inside a vulnerable range or matches exactly; NVD entries with no version bounds are listed as *unconfirmed*, never as vulnerable |
| Priority | CISA KEV, EPSS | *Exploited* column (KEV, ransomware, or Microsoft's own "Exploited: Yes"), EPSS probability, and the sort order: open findings first, exploited first among them, then severity and CVSS |

Every finding carries its **evidence** (`build comparison: host 10.0.26200.6584 < fixed
10.0.26200.6900 (KB5066000) → not patched`, `installed 24.08 vs 7-zip:7-zip: ✓ < 24.09`). Four row
sets share the view: **Findings** (filters: severity, status, source, exploited only), **Missing
updates**, **Software** (with *Look up CVEs for selected* to query the NVD for just those programs),
**Hotfixes** (QFE, CBS and Windows Update history side by side). Actions: *Copy CVE IDs*, *Open
advisories*, *Copy as text*, *Send fix KBs to clipboard*, *Copy KBs*, *Open Windows Update*,
*Export CSV…*. Double-click a row to open its advisory.

Feeds are cached in `cache\` (the MSRC month is about 15 MB; KEV 2 MB; NVD answers are small) so a
second scan is quick and an offline scan uses the last copy. *Feed cache…* shows and clears them;
*Log…* shows every step and any problem. The NVD allows 5 requests per 30 s without a key, so a
scan with ten mapped programs waits about a minute on that step; a free key
(nvd.nist.gov/developers/request-an-api-key) in the *NVD key* box makes it near-instant. *months*
is how many monthly Microsoft releases to check; a machine that has not been updated for a year
needs 12.

No administrator rights are needed for any of this.

### 10 · 📦 Software Inventory

Every program installed on this machine — name, version, publisher, install date, scope — read from the
uninstall registry hives (64-bit, 32-bit and per-user), never `Win32_Product`. *Scan for CVEs* then looks
up each program that is in the CVE product map against the NVD at its exact version and flags the
vulnerable ones: the row is tinted by severity, with the **worst CVE**, its **CVSS**, whether it is
**known-exploited** (CISA KEV), its **EPSS** probability, and the **version to upgrade to**. Summary cards
count the vulnerable, critical, high and exploited programs.

The filtering is the advanced kind: the shared **column-header funnels** and the **Filter** rule bar work
on every column, plus dedicated *vulnerable only*, *exploited only*, *severity* and *in CVE map only*
toggles. Actions: *Scan selected* (look up just the ticked programs), *Copy CVE list*, *Copy names +
versions*, *Open on NVD*, *Export*. It shares the NVD key and the feed cache with Vulnerability Management,
so if you scanned there already, this is instant.

### 11 · ✅ Security Checklist

A pass or fail review of the most common endpoint audit items, scored out of 100, each check showing
its evidence. It covers:

| Area | Checks |
|---|---|
| Accounts & credentials | admin account with no password required, any blank-password account, built-in Administrator and Guest state, a stored auto-logon password. A *default / manufacturer credentials* note explains what an endpoint scan can and cannot prove. |
| Disk encryption | BitLocker protection per volume (needs administrator rights). |
| Antivirus & security products | antivirus present and enabled, Defender real-time protection and running mode (active vs passive), every product registered with the Windows Security Center with its enabled / up-to-date state, and known EDR or monitoring agents by service and process name. |
| Remote access | inbound Remote Desktop, and remote-access tools (TeamViewer, AnyDesk, VNC, RustDesk, ScreenConnect, Splashtop, LogMeIn …) found installed or running. |
| VPN | VPN clients (NordVPN, Tailscale, OpenVPN, WireGuard, AnyConnect, GlobalProtect …). |
| Peripheral & USB control | whether USB mass storage and removable drives are blocked by policy. |
| Firewall & updates | firewall on for every profile, and whether a reboot is pending. |

**Active tests** (a separate button, because they drop test files on purpose): the **EICAR** anti-malware
test writes the standard harmless test file and checks that real-time antivirus removes it (the EICAR
string is built in memory so the app itself is never quarantined); the **application-control** check reads the
AppLocker / SRP / WDAC / SmartScreen policy from the registry and reports whether execution is controlled
— it does not run or drop anything. Only the EICAR file touches disk; expect your antivirus to alert on it.

Filter by category or by result, *Copy as text* the ticked checks, and *Save Markdown / JSON / PDF*
for the whole report. Without administrator rights, BitLocker and a few reads report *N/A* rather than
failing.

### 12 · 🧱 Firewall Rules

Every Windows Firewall rule as a sortable table, with the risky ones flagged — inbound **Allow** rules open
to **any** remote address, rules that open **all ports**, and rules not tied to a program (worse on the
public profile). The stat bar shows whether the firewall is actually **on** for each profile and its default
inbound action. Filter to *risky only*, a direction, or *enabled only*.

### 13 · ♻️ Duplicate Finder

Find files whose **contents** are identical: group by size, then a partial hash, then a full SHA-256 only
where those still collide — so it is fast even on large trees. Each group shows the space it wastes; the
oldest copy is marked *keep*. *Select all but newest per group*, then send the rest to the **Recycle Bin**
(reversible).

### 14 · ▶️ Autoruns

Every place Windows starts a program on its own — **run keys** and RunOnce, **startup folders**, **scheduled
tasks**, **services**, **Winlogon**, **image hijacks** (IFEO/SilentProcessExit), **AppInit DLLs**, **boot
execute**, **Active Setup** and **WMI event subscriptions** — with the program each one runs, its
**Authenticode signer** (embedded or catalog), where it lives on disk, and a **risk flag** (unsigned or
invalid in a writable folder, a dangling target, a hijack, a non-default Winlogon value). *Disable* moves an
entry aside (the Sysinternals `AutorunsDisabled` convention), *Enable* restores it, *Delete* removes it.
Needs administrator rights to change machine-wide entries.

### 15 · 📜 Event Log Triage

The security-relevant records from the Windows event logs over a time range: **failed and successful
logons**, explicit-credential and special-privilege logons, **account lockouts** and changes, **new
services** (7045/4697) and **scheduled tasks** (4698), **PowerShell script blocks** (4104), **Defender
detections**, **process creation** (4688) and **cleared audit logs** (1102). Each record is parsed into
account and detail fields and tinted by risk. Reading the Security log needs administrator rights.

### 16 · 🔑 Secrets Scanner

Walk a folder or drive for **exposed secrets** — private keys (PEM/PuTTY), AWS/Google/GitHub/Slack/Stripe
keys, JWTs, bearer tokens, connection-string and generic passwords — in `.env` and config files. Each hit
shows the file, line, kind and a **masked preview**; the whole secret is never put on screen. High-entropy
filtering and a placeholder skip cut the obvious false positives.

### 17 · 📶 Wi-Fi & Credentials

The secrets saved on this machine: **Wi-Fi profiles** with their security type — **open**, **WEP** and
legacy **WPA** are flagged — and, when elevated, the stored key; plus the **Windows Credential Manager
vault** (generic and domain credentials). Keys and secrets are hidden until you click **Reveal**, which
confirms first, since it puts a real password on screen.

### 18 · 🔏 Signatures woven in

There is no separate "signature checker" — Authenticode verification is folded into the tools that need it.
**File Explorer** shows a *Signature* column, **Resource Usage** has a *Loaded modules…* action that lists a
process's DLLs and flags the unsigned ones, and **Autoruns** verifies every autostart program.

### · 🌍 Network Map

This machine's **live connections on a world map**, in the style of the big threat maps. The world is a
dense grid of small dots drawn from **real country shapes** (Natural Earth polygons rasterized and packed
into ~19 KB inside the exe — nothing is downloaded to draw it), with country **borders** picked out in
brighter dots. **Hover a country** and its whole shape lights up with its name. Every connection to a
public address is drawn as an animated **great-circle arc** from the red **"You are here"** pin to the
remote end, pulses travelling along it — **teal outbound, amber inbound**. **Hover a connection or an
endpoint** for the city, ISP, direction and the **ports, protocols and processes** behind it. A
top-countries list, live ticker and legend sit over the map; scroll to zoom, drag to pan. Placing points
needs **geolocation**, which is opt-in and confirmed: each remote IP is looked up via the free ip-api.com
service (the one place this tool uses the network) and cached to disk.

### 20 · 🌐 Browsing Data

History, downloads, searches and **saved passwords** from every browser on this machine — Chrome, Edge,
Brave, Vivaldi, Opera and **Firefox** (classic and Microsoft Store builds) — read straight from their SQLite stores by a small **dependency-free
SQLite reader** written for this app (no external library). Switch between **History** (URL, title, visit
count, last visit, site), **Domains** (every unique site ranked by total visits, with page counts, a share bar, first/last seen and which browsers), **Downloads** (file, size, state, source), **Searches** and **Passwords**. The
tree view groups by site, so you can see where the time went; the cards show the record count, distinct
sites, the busiest site and the date span. Saved passwords are **masked until you click Reveal** and confirm
— exactly like the Wi-Fi reveal; Chromium passwords are decrypted locally with DPAPI + AES-256-GCM, Firefox
through the NSS library it ships. Entries protected by newer **app-bound encryption** (recent Chrome/Edge)
or a Firefox master password can't be shown and say so.

### 19 · 🕸️ Findings Map

*Now a live **force-directed** graph — nodes repel, edges pull, a gentle gravity centres it, so it settles smoothly and every node can be dragged. Each node is a themed **icon** (the endpoint a monitor, Firewall a brick wall, Wi-Fi signal arcs, Vulnerabilities a shield…), tinted by severity. It captures the newer tools too: autoruns, firewall, Wi-Fi, browsers and recent events. Every node is a small flat icon in one theme colour; **drag a node and it stays where you drop it**, right-click to release it, and **Reformat** re-flows the whole map. Big groups fan out so many items stay readable.*

This machine as one node at the centre of a graph, wired to what was found: **Users**, **Network**
(addresses, listening ports, active connections), **Software**, the **Security checklist** (grouped into
failed / to review / passed) and **Vulnerabilities** (the open findings from a scan run this session).
Click a node to expand or collapse it, drag to pan, scroll to zoom, *Fit* to recentre. Nodes are coloured
by risk, so the red branches show where to look first. *Build map* gathers everything in the background
with a step strip; ticking *include security checklist* adds its findings and about twenty seconds.

---

## Files

```
Toolbox\PowerTower.exe   the app
Toolbox\Program.cs            entry point; flags --tool <PanelName>, --selftest <report.txt>, --shots <folder>
Toolbox\Ui.cs                 theme, DataView (grid / details / tree, filter rules), step strip, selection bar, shell
Toolbox\Panels.cs             blocker, reachability, connections, resource usage, disk usage, deleted files
Toolbox\ReconPanel.cs         System Recon & Audit
Toolbox\FilesPanel.cs         File Explorer and Find Files
Toolbox\VulnPanel.cs          Vulnerability Management
Toolbox\SoftwarePanel.cs      Software Inventory
Toolbox\ChecklistPanel.cs     Security Checklist (and the EICAR / execution active tests)
Toolbox\FirewallPanel.cs      Firewall Rules      (engine: Firewall.cs -> WinFirewall)
Toolbox\DupesPanel.cs         Duplicate Finder    (engine: Dupes.cs)
Toolbox\AutorunsPanel.cs      Autoruns            (engine: Autoruns.cs)
Toolbox\EventsPanel.cs        Event Log Triage    (engine: Events.cs -> EventHunt)
Toolbox\SecretsPanel.cs       Secrets Scanner     (engine: Secrets.cs)
Toolbox\CredsPanel.cs         Wi-Fi & Credentials (engine: Creds.cs)
Toolbox\ModuleViewer.cs       Loaded-modules window (Resource Usage)
Toolbox\AboutPanel.cs         About & Guide
Toolbox\Trust.cs             Authenticode / catalog signatures, loaded modules, image-path parsing
Toolbox\BrowserPanel.cs       Browsing Data (engines: Sqlite.cs, Browser.cs, BrowserCreds.cs)
Toolbox\MapPanel.cs           Findings Map (the graph control and its collectors)
Toolbox\Net.cs                extractor, hosts file, firewall rule, reachability, connection tables
Toolbox\Sys.cs                process sampling, storage scan, change journal, exFAT reader, shadow copies
Toolbox\Recon.cs              recon collectors, JSON reader shared, the minimal PDF writer, the report
Toolbox\Vuln.cs               inventory, JSON reader, feeds (MSRC, NVD, KEV, EPSS), resolvers, the scan
Toolbox\Files.cs              parallel file walker, AES file crypto, secure wipe, name/hash search
Toolbox\Checklist.cs          the hardening checks and their report
Toolbox\Tests.cs              engine tests (Tests.exe; exit code = failures)
Toolbox\crash.log             written only if something ever throws in the UI; the app stays open
Toolbox\build.cmd             rebuilds both exes with the C# compiler that ships in Windows
Toolbox\app.manifest          asInvoker + per-monitor DPI; embedded at build time
Toolbox\settings.ini          created on first run: window size, last choices, NVD key (delete to reset)
Toolbox\cache\                downloaded vulnerability feeds (safe to delete)
```

## Rebuild after changing a `.cs` file

Double-click `build.cmd`, or from a prompt in this folder:

```
build.cmd
Tests.exe
```

It uses `%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe` (C# 5, .NET Framework 4.8); no SDK
or Visual Studio needed. `Tests.exe` runs the engine tests without the UI; the ones that touch the
machine are read-only (hosts-file edits happen on a temporary copy, the exFAT scan is capped, the
feed tests are skipped offline). `PowerTower.exe --selftest report.txt` exercises every panel
in the real UI - it loads real data into each tool, then switches every mode and view, sorts every
column both ways, searches, applies and clears filter rules, selects and exports CSV - and writes a
report; `--shots folder` saves a screenshot of each panel. If anything ever throws inside the UI,
the app logs it to `crash.log` next to the exe and stays open instead of closing.

# Get-StorageHogs

Find what is eating your disks — visually, from the terminal — and get told exactly what is safe to delete.

Scans every fixed drive on a Windows machine, then renders drive usage bars, the largest files and folders, space by category, and a **cleanup section** that measures known junk locations on *your* machine and tags each one **SAFE**, **REVIEW** or **KEEP** with the exact command to reclaim it.

**The script only reads. It never deletes anything.**

---

## Quick start

Put both files in the same folder.

| You want to… | Do this |
|---|---|
| Just run it | Double-click **`Run-StorageHogs.cmd`** |
| Full coverage of system folders | Right-click `Run-StorageHogs.cmd` → **Run as administrator** |
| Run from a PowerShell prompt | `.\Get-StorageHogs.ps1` |
| Skip the menu | `.\Get-StorageHogs.ps1 -Drive C -Top 40` |

The `.cmd` launcher bypasses the execution policy for that one run only. Nothing on the system is changed.

---

## If Windows refuses to run it

> `Get-StorageHogs.ps1 is not digitally signed. You cannot run this script on the current system.`

Windows marks downloaded files as untrusted. Any one of these fixes it:

```powershell
# Permanent, this file only — the cleanest option
Unblock-File .\Get-StorageHogs.ps1

# This session only — changes nothing on the system
Set-ExecutionPolicy -Scope Process Bypass

# One-shot, from any prompt
powershell -ExecutionPolicy Bypass -File .\Get-StorageHogs.ps1
```

Or just use `Run-StorageHogs.cmd`, which does the last one for you.

This error happens *before* PowerShell loads the script, so the script cannot catch it itself. Every error *after* the script starts is caught and answered with the specific command that will work — see [Error handling](#error-handling).

---

## Interactive mode

Run with no arguments and you get a guided setup:

```
  ▌ STORAGE HOGS  interactive setup — Enter accepts the default

  ▲ Not running as Administrator. System folders will be partly skipped.
  ? Relaunch as Administrator now? (y/n) [y]

  Drives
   1. C:  ████████████████░░░░   811.20 GB / 953.87 GB   85%  Windows
   2. D:  ██████░░░░░░░░░░░░░░   1.02 TB / 3.64 TB       28%  Data
  ? Which drives? (numbers or letters, comma-separated, or "all") [all]

  Scan profile
   1. Quick    — top 15 files ≥ 200 MB, folders 2 deep. Fastest.
   2. Standard — top 25 files ≥ 50 MB, folders 3 deep.
   3. Deep     — top 50 files ≥ 10 MB, folders 4 deep. Slow on multi-TB drives.
   4. Custom   — set each number yourself.
  ? Profile [2]

  ? Paths to exclude? (comma-separated, blank for none)
  ? Export largest files to CSV? (path, blank to skip)
  ? Start? (y/n) [y]
```

Enter accepts every default, so the fastest path is: double-click, press Enter until it starts.

---

## Arguments

Give any of these and the menu is skipped. Add `-Interactive` to get the menu anyway.

| Parameter | Default | What it does |
|---|---|---|
| `-Drive C,D` | all fixed drives | Drive letters to scan |
| `-Top 25` | 25 | Largest files to show |
| `-TopFolders 15` | 15 | Largest folders to show |
| `-MinSizeMB 50` | 50 | Ignore files smaller than this for the top-files list. Lower for detail, raise for speed |
| `-FolderDepth 3` | 3 | Roll folder sizes up to this many levels below the drive root |
| `-Exclude 'D:\Backups','C:\VMs'` | none | Path prefixes to skip entirely |
| `-ExportCsv .\hogs.csv` | none | Also write the top-files list to a CSV |
| `-NoColor` | off | Plain text, no ANSI colour |
| `-Interactive` | off | Force the menu even with other arguments |

Examples:

```powershell
.\Get-StorageHogs.ps1 -Drive C -Top 40 -MinSizeMB 20
.\Get-StorageHogs.ps1 -Exclude 'D:\Archive' -ExportCsv .\hogs.csv
.\Get-StorageHogs.ps1 -NoColor > report.txt
Get-Help .\Get-StorageHogs.ps1 -Full
```

---

## What the report shows

**DRIVES** — one bar per drive, coloured teal / amber / red at 75% and 90% full.

**LARGEST FILES** — proportional bars, size, category, file age, and the path (middle-truncated to fit your window). Categories are colour-coded: red for the things that are usually the real culprit (disk images, AI models, dumps), amber for the usual suspects (video, archives, installers).

**LARGEST FOLDERS** — sizes rolled up to `-FolderDepth` levels. Depth 3 means `C:\Users\you\Downloads` is one line; depth 4 splits it further.

**BY CATEGORY** — total space by file type. Categories include *Disk images* (ISO, VHDX, VMDK…), *AI models* (GGUF, safetensors, checkpoints), *Archives*, *Video*, *Installers*, *Logs & dumps* and more. On a machine used for VMs or local inference this is usually where the space went — not in temp folders.

**CLEANUP** — every known junk location, actually measured on your machine, in three groups:

| Group | Meaning | Examples |
|---|---|---|
| **SAFE** | Caches and leftovers. Rebuilt automatically. | User and Windows temp, Windows Update download cache, Delivery Optimization, Recycle Bin, thumbnail cache, crash dumps, browser caches, npm / pip / NuGet caches, `Windows.old` |
| **REVIEW** | Real data, or reclaiming it involves a trade-off. Decide per item. | Downloads folder, hibernation file, Ollama / LM Studio / Hugging Face models, Docker and WSL virtual disks, OneDrive local copies |
| **KEEP** | Large by design. Don't touch by hand. | Page file, swap file, WinSxS, Windows Installer cache, Prefetch |

Each line prints the exact command to reclaim that space, and marks the ones that need an admin prompt. KEEP items are listed *because* they're what people find with a generic "largest folder" tool and then break Windows deleting — each one says what to do instead (DISM for WinSxS, `powercfg` for hibernation, nothing for the rest).

**SUMMARY** — total reclaimable now, total more if you review the amber items, and which category is actually the biggest.

---

## Error handling

Anything that goes wrong after the script starts is caught and answered with a specific fix rather than a stack trace:

| What happened | What it tells you to do |
|---|---|
| Access denied on a folder | The exact `Start-Process … -Verb RunAs` command with the script's own path filled in, or how to `-Exclude` the folder |
| A drive letter that doesn't exist | The list of fixed drives it *can* see |
| WMI / CIM can't enumerate drives | `Restart-Service Winmgmt` |
| The console can't draw the visuals | Run in Windows Terminal, or the `-NoColor` command |
| Too many large files tracked | Raise `-MinSizeMB` |
| Anything unrecognised | The one combination that works on almost any machine, plus the line number to report |

---

## Requirements

- Windows 10 1809+ or Windows 11
- Windows PowerShell 5.1 (built in) or PowerShell 7+
- For colour: Windows Terminal, or any console with VT support. `-NoColor` otherwise.
- Administrator rights are optional but recommended — without them, system folders and other users' profiles are partly skipped, and the script says so.

---

## Performance

The scan is a single pass per drive, so time scales with file count rather than size. A 1 TB NVMe with a few hundred thousand files takes about a minute; a 4 TB drive with millions of small files can take several. Use the **Quick** profile or a higher `-MinSizeMB` for a first look, then go deeper on the drive that matters.

Junctions and symlinks are skipped, so it won't loop on `C:\Users\All Users`-style reparse points or double-count.

---

## Safety

- Nothing is deleted, moved, or modified. Ever.
- No network access.
- No changes to execution policy or any system setting. The `.cmd` launcher uses `-ExecutionPolicy Bypass` for its own process only.
- The commands it prints under **CLEANUP** are for *you* to run. Read the risk tag first.

---

## Files

| File | Purpose |
|---|---|
| `Get-StorageHogs.ps1` | The script |
| `Run-StorageHogs.cmd` | Double-click launcher. Bypasses execution policy for one run, prefers PowerShell 7 if installed, pauses at the end so the window stays open |
| `README.md` | This file |

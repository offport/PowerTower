# Find-DeletedFiles

Lists what was **permanently deleted** on your drives in the last N days — bypassing the Recycle Bin, or after it was emptied — and tells you which of those files can still be recovered, with the exact copy command.

**The script only reads. It never deletes, restores, or modifies anything.**

---

## Read this first: what Windows actually keeps

Windows does not keep a log of deleted files. Any tool that claims to "show everything ever deleted" is either using forensic carving or lying. What Windows *does* keep:

| Source | What it gives you | Caveat |
|---|---|---|
| **NTFS USN Change Journal** | Every create / rename / delete on the volume, with filename, folder reference and timestamp | It's a ring buffer. Default size (32 MB) holds a few **days** on a busy system drive, **months** on a quiet data drive. |
| **Volume Shadow Copies** | Actual copies of files as they were when the snapshot was taken | Only if System Protection / restore points are on for that drive |
| **Security event log (ID 4660)** | Who deleted what, from which process | Only if object-access auditing was enabled beforehand. It isn't by default. |
| **Recycle Bin** | Files that are *not* permanently deleted yet | Emptying it removes this trace too |

This script reads the journal for the list, checks shadow copies for recoverability, and reports the other two for context. **It tells you how far back each drive can actually see** — that number matters more than the 30-day window you asked for.

---

## Quick start

Must run as Administrator — reading the journal requires it.

| You want to… | Do this |
|---|---|
| Just run it | Right-click **`Run-DeletedFiles.cmd`** → **Run as administrator** |
| From an elevated PowerShell prompt | `.\Find-DeletedFiles.ps1` |
| Skip the menu | `.\Find-DeletedFiles.ps1 -Drive C -Days 7` |

Run non-elevated and it offers to relaunch itself elevated. If Windows says *not digitally signed*: `Unblock-File .\Find-DeletedFiles.ps1`, or use the `.cmd`.

---

## What the report shows

**Per drive — journal coverage**

```
  ┌─ C: — USN journal
  ● 1,204,331 records · oldest 2026-09-09 03:12   → this drive can see back 5.4 days
    the journal is shorter than your window — deletions before 2026-09-09 03:12 are invisible.
    enlarge it for next time (1 GB, keeps months on most drives):  fsutil usn createjournal m=0x40000000 a=0x1000000 C:
```

Green if coverage meets your window, amber if it covers at least half, red if not. This is the single most important line in the output.

**DELETED** — one row per path, newest first. A path deleted repeatedly (autosaves, build outputs) collapses to one row with `×N`. Folders are amber. `✓` in the REC column means a shadow copy still has it.

**RECOVERABLE** — every `✓` item with the newest snapshot that still holds it and a ready-to-run `Copy-Item` line. The source path uses the `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN\` form, which PowerShell's `-LiteralPath` reads directly — no mounting required.

**OTHER SOURCES** — Recycle Bin count (those aren't permanently gone), whether delete-audit events exist, and a reminder that anything older than journal coverage needs forensic tooling.

---

## Noise filtering

By default the script hides deletions that are almost never what you're looking for: temp folders, browser and app caches, `node_modules`, `.git`, Office lock files (`~$…`), `.tmp`, `.log`, `.crdownload`, Windows servicing directories, and so on. The count of hidden items is shown; `-ShowAll` (or the menu question) includes them.

---

## Arguments

| Parameter | Default | What it does |
|---|---|---|
| `-Drive C,D` | every drive with a journal | Drives to read; a drive without a journal prints why and what still works |
| `-Days 30` | 30 | Look-back window |
| `-Path 'C:\Users\me'` | none | Only show deletions under this prefix |
| `-ShowAll` | off | Include temp / cache / lock-file noise |
| `-NoShadowCheck` | off | Skip the shadow-copy recoverability pass |
| `-ExportCsv .\deleted.csv` | none | Full results including the shadow source path, exFAT state and size |
| `-RecoverTo 'C:\Recovered'` | none | exFAT only: copy the intact deleted files there, folder structure kept; must be another drive |
| `-RecoverMax 50` | 50 | Cap for `-RecoverTo` |
| `-NoColor` | off | Plain output |
| `-Ascii` | off | Plain ASCII marks instead of `● ✓ ↳` glyphs; automatic when the console cannot be switched to UTF-8 |
| `-Interactive` | off | Force the menu |
| `-Hold` | off | Wait for a key before the window closes (the elevated relaunch passes it, so a report or an error stays readable) |

```powershell
.\Find-DeletedFiles.ps1 -Drive C -Days 7 -Path 'C:\Users\me\Documents'
.\Find-DeletedFiles.ps1 -ShowAll -ExportCsv .\deleted.csv
```

The report caps at 400 rows on screen; the CSV has everything.

---

## How paths are rebuilt

Journal records carry a filename and the ID of the parent folder, not a full path. For parents that still exist, the script opens them by ID and asks Windows for the current path — fast and exact. For parents that were deleted too, it walks the chain of directory records in the journal itself. When neither works, the path shows as `C:\<unknown>\name` rather than being dropped.

Renames are not followed: a file deleted under a different name than it was created with is shown under the name it had when it was deleted.

---

## Making this work better next time

Two settings turn this from "maybe" into "reliable":

**Enlarge the journal** so it holds months instead of days. 1 GB is a reasonable size on a modern drive:
```powershell
fsutil usn createjournal m=0x40000000 a=0x1000000 C:
```

**Turn on System Protection** for the drives that matter (System Properties → System Protection → Configure). Shadow copies are what make a deletion recoverable rather than merely known.

---

## Error handling

| What happened | What it tells you |
|---|---|
| Not elevated | Offers to relaunch; otherwise prints the exact elevation command |
| `fsutil` missing or failing | Where it should be |
| No active journal on a drive | Says so, and prints the command to create one |
| Path resolver won't compile | Falls back to journal-only path rebuilding and says so |
| `not digitally signed` | `Unblock-File` or the `.cmd` |
| Anything else | The one combination that works on almost any machine, plus the line number |

---

## External drives, SD cards, cloud-drive letters

The menu lists every fixed and removable drive with its file system. **NTFS and ReFS** volumes keep a change journal and are read as described above, fixed or removable, internal or USB.

**exFAT** drives (most external SSDs as sold, including the Samsung T7) keep no journal, but they do leave a deleted file's directory entry on disk — name, size, timestamps, first cluster — with one bit cleared, until the slot is reused. The script reads the drive's directory tables raw (elevated, read-only, a few seconds even on a 1 TB drive) and lists every deleted entry still present, then checks the allocation bitmap to say whether the file's clusters are still unallocated:

| State | Meaning |
|---|---|
| `intact` | contiguous file, none of its clusters handed out again — can be copied out whole |
| `intact (fragmented)` | its cluster chain is still in the FAT and all clusters are free — can be copied out |
| `partly overwritten` / `overwritten` | some or all clusters belong to something else now |
| `chain lost` | fragmented and the chain is gone — a carving tool may still find pieces |

**The Recycle Bin on an exFAT drive.** Deleting through the bin renames the file to `$R<id>.<ext>` inside `\$RECYCLE.BIN` and writes a small `$I<id>` record with the original path and the time; emptying the bin deletes both. The script pairs them up: the report opens with an *emptied from the Recycle Bin* section, one line per item, with the deletion time (the `$I` record's own timestamp, which survives even when its data is gone), the original name when the record's data is still intact, and how many files inside are intact. Those files are listed with the deletion time as WHEN, so the day window works for them.

Two honest limits: for everything else, exFAT records **no deletion time**, so the list shows last-modified times instead; and "intact" means *not yet* overwritten — anything written to the drive can destroy it, so copy out soon. Note that Windows' exFAT driver does not update a folder's timestamp on delete, so folder dates say nothing about when a deletion happened.

`-RecoverTo 'C:\Recovered'` (or the menu question) copies the intact files to a folder on **another** drive, keeping the folder structure (bin items land under `Recycle Bin\<name or $R-id (deleted date)>`), up to `-RecoverMax` (500) files; `-RecoverMax 0` removes the cap. To copy out only what was emptied from the bin: `-Drive D -Path 'D:\$RECYCLE.BIN' -RecoverTo 'C:\Recovered' -RecoverMax 0`. The exFAT drive itself is never written to; the script refuses a destination on the same drive. A raw read of an external exFAT drive works without elevation, but the script as a whole still asks for it because the journal does.

**FAT32** drives and virtual drives such as Google Drive: nothing to read. The script shows the reason and what still works — the drive's own Recycle Bin if anything is in it, or a carving tool (Recuva, PhotoRec, TestDisk) run before anything else is written to the drive.

Card-reader slots with no media are listed as *no media* and skipped.

---

## Requirements

- Windows 10 / 11; the change journal exists on NTFS and ReFS volumes only
- Administrator
- Windows PowerShell 5.1 or PowerShell 7+
- A console with VT support for colour; `-NoColor` otherwise

Notes:
- The script switches the console to UTF-8 for its run (and back on exit) so the `● ✓ ↳` marks render instead of `?`; `-Ascii` avoids them altogether.
- `fsutil usn readjournal … csv` has two layouts: Windows 10 2004 and later (and Windows 11) print a four-line preamble and 16 quoted fields per record; older builds print 13 unquoted fields. The parser reads both from the right-hand end, so a filename containing commas or quotes is still recovered whole.
- `fsutil` output is decoded with the console's code page, so filenames in some non-Latin scripts may show substituted characters. The paths still resolve correctly for the shadow-copy check.
- A file deleted while a program still had it open is parked by NTFS under `\$Extend\$Deleted\<id>`; those records are treated as noise, as are SQLite `-wal` / `-shm` / `-journal` sidecars.

---

## Files

| File | Purpose |
|---|---|
| `Find-DeletedFiles.ps1` | The script |
| `Run-DeletedFiles.cmd` | Launcher — bypasses execution policy for one run. Right-click → Run as administrator |
| `README-DeletedFiles.md` | This file |

Companions: **Get-StorageHogs** (what's on the disk), **Watch-ProcessHogs** (what's running).

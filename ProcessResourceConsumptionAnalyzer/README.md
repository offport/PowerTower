# Watch-ProcessHogs

A live, in-terminal process monitor that accounts **cumulatively from the moment you start it** — not just what's busy right now.

Task Manager tells you what's hot this second. This tells you which process has burned the most CPU time, held the most memory, and moved the most disk I/O since you launched it, and keeps a process in the table even after it exits. Graph mode shows the top 10 as a grid of sparklines, one per process per resource.

**The script only reads. It never touches a process.**

---

## Quick start

Put both files in the same folder.

| You want to… | Do this |
|---|---|
| Just run it | Double-click **`Run-ProcessHogs.cmd`** |
| See every process, including system ones | Right-click `Run-ProcessHogs.cmd` → **Run as administrator** |
| Run from a PowerShell prompt | `.\Watch-ProcessHogs.ps1` |
| Skip the menu | `.\Watch-ProcessHogs.ps1 -ByName -Graph` |

If Windows says the script is *not digitally signed*, run `Unblock-File .\Watch-ProcessHogs.ps1` once, or just use the `.cmd`.

It needs a real console — Windows Terminal or a PowerShell window. It will not run in the ISE or a VS Code output pane, and it tells you so.

---

## Keys while it runs

| Key | Action |
|---|---|
| `q` | Quit — prints a final top-5 summary that stays in your scroll-back |
| `g` | Toggle **graph mode** |
| `n` | Toggle grouping: **by name** (chrome ×38 = one row) / **by PID** |
| `s` | Cycle sort: CPU cumulative → CPU now → Memory now → Memory peak → Disk I/O cumulative → Disk I/O now |
| `p` | Pause sampling (screen keeps updating on key presses) |
| `r` | Reset all cumulative counters to zero, keep running |
| `+` / `-` | Slower / faster refresh (0.25 s – 10 s) |

---

## What you see

### Header — always visible

```
  ▌ PROCESS HOGS  since launch 4:12 · LIST · by NAME · sort: CPU cumulative · every 1s
  CPU ████████░░░░░░░░░░░░ 38.2%   RAM ██████████████░░░░░░ 41.3G / 95.9G   DISK    12.4 MB/s   16 cores
  cpu ▁▂▃▅▇█▆▄▃▂▁▁▂▃▅▆▇█▇▅▃▂▁  ram ▄▄▄▄▅▅▅▅▅▆▆▆▆▆▆  io ▁▁▁▁▃▁▁▁▁█▂▁▁▁▁
```

System-wide CPU, RAM and disk throughput, each with a rolling sparkline so you can see the last two minutes at a glance.

### List mode

| Column | Meaning |
|---|---|
| `×` | Process has exited — row is greyed but kept, because its cumulative numbers still count |
| **CPU%** | Live CPU right now, red above 50%, amber above 15% |
| **CPU⏱** | Total CPU time consumed **since launch** |
| **share** | This process's fraction of all CPU time consumed since launch |
| **MEM / PEAK** | Working set now and the highest seen |
| **IO READ / IO WRITE** | Bytes read and written **since launch** |
| **IO NOW** | Live disk throughput |

Sort by any of these with `s`. The default — cumulative CPU — is the one that answers "what has actually been using my machine while I wasn't looking."

### Graph mode

```
  PROCESS                CPU %  now/max                MEM MB  now/max               DISK MB/s  now/max
  chrome ×41             ▂▃▅▆▇█▇▅▃▂▁▁▂▃▅▆▇▆▄▂▁   14/62    ▅▅▅▆▆▆▆▇▇▇▇▇▇██████   3812/3990  ▁▁▁▂▁▁▁▁▃▁▁▁▁▁▁▁▁▁▁▁  0.2/8.1
  ollama [18204]         ▁▁▁▁▁▁████████▇▆▃▁▁▁▁▁    0/94    ▁▁▁▁▁▁▂▅████████████  11240/11240 ▁▁▁▁▁▁█▅▂▁▁▁▁▁▁▁▁▁▁▁  0.0/412
  Code ×9                ▂▂▃▂▂▂▂▃▂▂▂▂▂▂▃▂▂▂▂▂▂    4/7     ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄   1408/1420  ▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁  0.0/0.3
```

Top 10 by the current sort. Each sparkline is the last 60–120 samples, auto-scaled to that row's own maximum, with `now/max` beside it. Dead processes flat-line to `▁` rather than disappearing.

### Final summary on quit

The live screen is left as-is and a static top-5 by cumulative CPU is printed underneath, so it survives in scroll-back and can be copied.

---

## Arguments

Give any of these and the menu is skipped. Add `-Interactive` to get the menu anyway.

| Parameter | Default | What it does |
|---|---|---|
| `-Interval 1` | 1 | Seconds between samples (min 0.25) |
| `-Top 20` | 20 | Rows in list mode (also capped by window height) |
| `-GraphTop 10` | 10 | Rows in graph mode |
| `-ByName` | off | Start grouped by process name |
| `-Graph` | off | Start in graph mode |
| `-Duration 300` | 0 (until `q`) | Stop automatically after N seconds |
| `-Log .\samples.csv` | none | Append every sample of every live process to a CSV |
| `-NoColor` | off | Plain text |
| `-Ascii` | off | Plain ASCII instead of block and sparkline glyphs. Automatic when the console cannot be switched to UTF-8. |
| `-Interactive` | off | Force the setup menu |
| `-Hold` | off | Wait for a key before the window closes (the elevated relaunch passes it, so an error stays readable) |

```powershell
.\Watch-ProcessHogs.ps1 -ByName -Graph
.\Watch-ProcessHogs.ps1 -Duration 600 -Log .\ten-minutes.csv
.\Watch-ProcessHogs.ps1 -Interval 0.5 -Top 30
```

The CSV has one row per process per sample: time, PID, name, CPU %, cumulative CPU seconds, memory MB, I/O rate, cumulative I/O — ready for Excel or a chart.

---

## How the numbers are produced

- **CPU** — delta of each process's total processor time between samples, divided by elapsed time and core count. Cumulative is the delta from the first sample, so a process that was already running when you started is counted from zero.
- **Memory** — working set. Peak and average are tracked per process and, in by-name view, per group.
- **Disk I/O** — `GetProcessIoCounters` via a small Win32 call, which is far faster and more reliable than performance counters and doesn't suffer from the `chrome#7` instance-naming problem. If the helper can't compile on a locked-down machine, the I/O columns switch off and the footer says why; everything else keeps working.
- **Exited processes** stay in the table if they consumed more than half a CPU-second or 10 MB of I/O; short-lived noise (conhost, cmd, dllhost) is dropped so the table doesn't fill with ghosts.
- **Screen** is redrawn in place with cursor positioning, not cleared, so there's no flicker.

---

## Error handling

Errors after the script starts are caught and answered with the specific fix:

| What happened | What it tells you |
|---|---|
| Not a real console (ISE, redirected output) | Use Windows Terminal or `Run-ProcessHogs.cmd` |
| Access denied on a process | The exact elevation command with the script's own path filled in |
| The I/O helper failed to compile | Falls back automatically; reports the compiler line if it can't |
| `not digitally signed` | `Unblock-File` or the `.cmd` |
| Anything else | The one combination that works on almost any machine, plus the line number |

The cursor is restored on every exit path, so a crash never leaves you with an invisible cursor.

---

## Requirements

- Windows 10 1809+ or Windows 11
- Windows PowerShell 5.1 or PowerShell 7+
- A console with VT support for colour and sparklines (Windows Terminal recommended); `-NoColor` otherwise
- The script switches the console to UTF-8 for its run (and switches it back on exit) so the block, sparkline and arrow glyphs render instead of `?`; if the console refuses, it falls back to ASCII automatically, and `-Ascii` forces that
- Administrator rights are optional but recommended: without them, CPU time and disk I/O for system processes and other users' processes read as zero

---

## Files

| File | Purpose |
|---|---|
| `Watch-ProcessHogs.ps1` | The monitor |
| `Run-ProcessHogs.cmd` | Double-click launcher — bypasses execution policy for one run, opens its own window, prefers PowerShell 7 if installed |
| `README-ProcessHogs.md` | This file |

Companion tool: **Get-StorageHogs** does the same job for disk space — what's on the drives rather than what's running.

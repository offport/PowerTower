#Requires -Version 5.1
<#
.SYNOPSIS
    Find-DeletedFiles — what was permanently deleted in the last N days, and whether it can come back.

.DESCRIPTION
    Windows keeps no "deleted files" log by default. What it does keep is the NTFS USN
    Change Journal — a rolling record of every create / rename / delete on the volume.
    This script reads it, keeps the delete records inside your window, rebuilds the
    original full paths, and then checks each one against Volume Shadow Copies to tell
    you which files are still recoverable and exactly where to copy them from.

    HONESTY FIRST: the journal is a ring buffer. On a busy system drive it may only
    hold a few days; on a quiet data drive, months. The report states the oldest record
    it found so you know how far back it can actually see. Deletions older than that
    are invisible to any tool short of forensic carving.

    The script only reads. It never deletes, restores or modifies anything — it prints
    the copy command for recoverable files and you run it.

.PARAMETER Drive          Drive letters, e.g. -Drive C,D. Default: all NTFS drives.
.PARAMETER Days           Look back this many days. Default 30.
.PARAMETER Path           Only show deletions under this path prefix, e.g. 'C:\Users\me'.
.PARAMETER ShowAll        Include temp / cache / lock-file noise that is hidden by default.
.PARAMETER NoShadowCheck  Skip the Volume Shadow Copy recoverability check.
.PARAMETER ExportCsv      Write the results to this CSV.
.PARAMETER RecoverTo      exFAT drives only: copy the deleted files whose clusters are still intact into this folder
                          (on ANOTHER drive), keeping their folder structure. The source drive is never written to.
.PARAMETER RecoverMax     Cap for -RecoverTo. Default 500 files; 0 = no cap.
.PARAMETER NoColor        Plain output.
.PARAMETER Ascii          Plain ASCII marks instead of ● ✓ ↳ glyphs. Automatic when the console cannot be switched to UTF-8.
.PARAMETER Interactive    Force the menu.
.PARAMETER Hold           Wait for a key before exiting (the elevated relaunch uses it so its window does not vanish).

.EXAMPLE
    .\Find-DeletedFiles.ps1
    .\Find-DeletedFiles.ps1 -Drive C -Days 7 -Path 'C:\Users\me\Documents'
    .\Find-DeletedFiles.ps1 -ShowAll -ExportCsv .\deleted.csv

.NOTES
    Must run as Administrator (reading the journal requires it).
    If Windows refuses to run it: Unblock-File .\Find-DeletedFiles.ps1, or use Run-DeletedFiles.cmd.
#>
[CmdletBinding()]
param(
    [string[]]$Drive,
    [int]$Days = 30,
    [string]$Path,
    [switch]$ShowAll,
    [switch]$NoShadowCheck,
    [string]$ExportCsv,
    [string]$RecoverTo,
    [int]$RecoverMax = 500,
    [switch]$NoColor,
    [switch]$Ascii,
    [switch]$Interactive,
    [switch]$Hold
)

# ═══════════════════════════════ rendering ═══════════════════════════════

$script:Esc = [char]27
$script:UseColor = (-not $NoColor) -and ($Host.UI.SupportsVirtualTerminal -or $env:WT_SESSION -or $PSVersionTable.PSVersion.Major -ge 7)

# The ● ✓ ↳ … glyphs only exist in UTF-8; Windows PowerShell starts the console in the OEM code page where
# they print as "?". Switch it for the run and put it back on exit.
$script:PrevOutEnc = $null
$script:UseGlyphs = -not $Ascii
if ($script:UseGlyphs) {
    try { $script:PrevOutEnc = [Console]::OutputEncoding; if ($script:PrevOutEnc.CodePage -ne 65001) { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } }
    catch { $script:UseGlyphs = $false; $script:PrevOutEnc = $null }
}
function Restore-Console { if ($script:PrevOutEnc -and $script:PrevOutEnc.CodePage -ne 65001) { try { [Console]::OutputEncoding = $script:PrevOutEnc } catch {} } }
$script:G = if ($script:UseGlyphs) { @{ dot = '●'; ok = '✓'; no = '-'; arrow = '↳'; warn = '▲'; err = '✖'; mark = '▌'; ell = '…'; times = '×'; to = '→'; tl = '┌─ '; rule = '─'; prompt = '›' } }
             else { @{ dot = '*'; ok = 'Y'; no = '-'; arrow = '->'; warn = '!'; err = 'X'; mark = '|'; ell = '~'; times = 'x'; to = '->'; tl = '+- '; rule = '-'; prompt = '>' } }

function C {
    param([string]$Name, [string]$Text)
    if (-not $script:UseColor) { return $Text }
    $map = @{
        teal  = "$Esc[38;2;47;217;197m";  amber = "$Esc[38;2;240;165;60m"; rose = "$Esc[38;2;255;107;94m"
        dim   = "$Esc[38;2;95;128;146m";  faint = "$Esc[38;2;60;87;102m";  ink  = "$Esc[38;2;214;233;240m"
        bold  = "$Esc[1m"
    }
    return "$($map[$Name])$Text$Esc[0m"
}
function Get-Width { try { $w = $Host.UI.RawUI.WindowSize.Width } catch { $w = 0 }; if (-not $w -or $w -lt 40) { $w = 120 }; return [math]::Max(80, [math]::Min(160, $w - 2)) }
function Section { param([string]$Title, [string]$Tag = '') $w = Get-Width; Write-Host ''; Write-Host ('  ' + (C teal $script:G.tl) + (C bold (C ink $Title)) + ' ' + (C faint ($script:G.rule * [math]::Max(4, $w - $Title.Length - 6))) + (C dim $Tag)) }
function Truncate-Path { param([string]$P, [int]$Max) if ($Max -lt 12) { $Max = 12 }; if ($P.Length -le $Max) { return $P }; $k = [int](($Max - 3) / 2); return $P.Substring(0, $k) + '...' + $P.Substring($P.Length - ($Max - 3 - $k)) }
function Ask {
    # Ask <question> <default> [<step>] [<hint>]  → the answer, or the default on Enter
    param([string]$Prompt, [string]$Default = '', [string]$Step = '', [string]$Hint = '')
    Write-Host ''
    Write-Host ('  ' + (C teal $Step) + $(if ($Step) { '  ' } else { '' }) + (C bold (C ink $Prompt)) + $(if ($Default -ne '') { (C dim "   Enter = $Default") } else { (C dim '   Enter = skip') }))
    if ($Hint) { Write-Host ('       ' + (C dim $Hint)) }
    Write-Host ('       ' + (C teal $script:G.prompt) + ' ') -NoNewline
    $r = Read-Host; if ([string]::IsNullOrWhiteSpace($r)) { return $Default }; return $r.Trim()
}
function Wait-Close {
    if (-not $Hold) { return }
    Write-Host ('  ' + (C dim 'Press any key to close this window.'))
    try { [void][Console]::ReadKey($true) } catch { try { [void](Read-Host) } catch {} }
}

# ═══════════════════════════════ Win32: file-id → path ═══════════════════════════════

$script:ResolverOk = $false
try {
    if (-not ('FD.Res' -as [type])) {
        Add-Type -TypeDefinition @'
using System; using System.Text; using System.Runtime.InteropServices;
namespace FD {
  public static class Res {
    [StructLayout(LayoutKind.Explicit, Size = 24)]
    struct FILE_ID_DESCRIPTOR { [FieldOffset(0)] public uint dwSize; [FieldOffset(4)] public int Type; [FieldOffset(8)] public long FileId; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr CreateFileW(string n, uint a, uint s, IntPtr sa, uint d, uint f, IntPtr t);
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenFileById(IntPtr v, ref FILE_ID_DESCRIPTOR id, uint a, uint s, IntPtr sa, uint f);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern uint GetFinalPathNameByHandleW(IntPtr h, StringBuilder b, uint len, uint f);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern uint GetFileAttributesW(string p);
    static readonly IntPtr INVALID = new IntPtr(-1);
    public static bool Exists(string p) { return GetFileAttributesW(p) != 0xFFFFFFFF; }
    public static IntPtr OpenVolume(string drive) { IntPtr h = CreateFileW(@"\\.\" + drive, 0, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero); return h == INVALID ? IntPtr.Zero : h; }
    public static string PathById(IntPtr vol, long id) {
      FILE_ID_DESCRIPTOR d = new FILE_ID_DESCRIPTOR(); d.dwSize = 24; d.Type = 0; d.FileId = id;
      IntPtr h = OpenFileById(vol, ref d, 0, 7, IntPtr.Zero, 0x02000000);
      if (h == INVALID || h == IntPtr.Zero) return null;
      try { StringBuilder sb = new StringBuilder(2048); uint n = GetFinalPathNameByHandleW(h, sb, 2048, 0); if (n == 0) return null; string s = sb.ToString(); if (s.StartsWith(@"\\?\")) s = s.Substring(4); return s; }
      finally { CloseHandle(h); }
    }
    public static void Close(IntPtr h) { if (h != IntPtr.Zero) CloseHandle(h); }
  }
}
'@ -ErrorAction Stop
    }
    $script:ResolverOk = $true
} catch { $script:ResolverError = $_.Exception.Message }

# ═══════════════════════════════ exFAT: deleted entries straight from the directory tables ═══════════════════════════════
# exFAT has no change journal, but a deleted file's directory entry set stays on disk with one bit cleared
# (0x85→0x05 file, 0xC0→0x40 stream, 0xC1→0x41 name) until the slot is reused. Reading the directory
# clusters - not the whole disk - lists them with name, size, timestamps and first cluster; the allocation
# bitmap says whether their clusters have been handed out again. Contiguous files (the exFAT norm) can be
# copied out whole. This is the "quick scan" of every undelete tool, done here read-only.
$script:ExFatOk = $false
try {
    if (-not ('FD.ExFat' -as [type])) {
        Add-Type -TypeDefinition @'
using System; using System.IO; using System.Text; using System.Collections.Generic;
namespace FD {
  public class XEntry {
    public string Path; public string Name; public bool IsDir; public long Size; public long ValidSize; public uint FirstCluster; public bool Contiguous;
    public DateTime Modified; public DateTime Created; public string State; public bool ParentDeleted; public int Depth;
    public DateTime FolderChanged;   // last-modified time of the folder it sat in: deleting an entry updates that, so it bounds the deletion time
    public int Times = 1;
  }
  public class ExFat : IDisposable {
    FileStream fs; public int SectorSize; public int ClusterSize; public uint FatOffset, FatLength, HeapOffset, ClusterCount, RootCluster;
    byte[] bitmap; public bool BitmapOk; public int DirsScanned, EntriesSeen, Skipped; public int MaxDirs = 250000; public int MaxDeletedDepth = 12;
    public DateTime Since = DateTime.MinValue;   // entries whose folder last changed before this are certainly older: not kept
    public string PathPrefix = null;             // only entries under this path (without the drive letter), case-insensitive
    public int MaxKeep = 1000000; public int OlderThanWindow, OutsidePrefix, Dropped, Duplicates;
    public List<XEntry> Deleted = new List<XEntry>();
    Dictionary<string, XEntry> byPath = new Dictionary<string, XEntry>(StringComparer.OrdinalIgnoreCase);
    public bool Done; public string ScanError; public int IntactCount; public long IntactBytes;
    HashSet<uint> onPath = new HashSet<uint>();      // clusters of the directories currently being walked: stops cycles, not reuse
    public long ClustersRead;
    Dictionary<long, byte[]> secCache = new Dictionary<long, byte[]>();
    public static ExFat Open(string letter) {
      ExFat x = new ExFat();
      x.fs = new FileStream(@"\\.\" + letter + ":", FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 4096, FileOptions.None);
      byte[] b = new byte[4096]; x.fs.Seek(0, SeekOrigin.Begin); int n = x.fs.Read(b, 0, 4096);
      if (n < 512 || Encoding.ASCII.GetString(b, 3, 8) != "EXFAT   ") { x.fs.Dispose(); throw new InvalidDataException("not an exFAT volume"); }
      x.SectorSize = 1 << b[108]; x.ClusterSize = 1 << (b[108] + b[109]);
      x.FatOffset = BitConverter.ToUInt32(b, 80); x.FatLength = BitConverter.ToUInt32(b, 84); x.HeapOffset = BitConverter.ToUInt32(b, 88);
      x.ClusterCount = BitConverter.ToUInt32(b, 92); x.RootCluster = BitConverter.ToUInt32(b, 96);
      if (x.SectorSize < 512 || x.ClusterSize < 512 || x.ClusterSize > (32 << 20)) { x.fs.Dispose(); throw new InvalidDataException("implausible exFAT geometry"); }
      return x;
    }
    public void Dispose() { if (fs != null) { fs.Dispose(); fs = null; } }
    long ClusterOffset(uint c) { return (long)HeapOffset * SectorSize + (long)(c - 2) * ClusterSize; }
    public bool ValidCluster(uint c) { return c >= 2 && c < ClusterCount + 2; }
    byte[] ReadCluster(uint c) { byte[] b = new byte[ClusterSize]; fs.Seek(ClusterOffset(c), SeekOrigin.Begin); int got = 0; while (got < ClusterSize) { int r = fs.Read(b, got, ClusterSize - got); if (r <= 0) break; got += r; } return b; }
    byte[] ReadSector(long sector) { byte[] b; if (secCache.TryGetValue(sector, out b)) return b; b = new byte[SectorSize]; fs.Seek(sector * SectorSize, SeekOrigin.Begin); int got = 0; while (got < SectorSize) { int r = fs.Read(b, got, SectorSize - got); if (r <= 0) break; got += r; } if (secCache.Count > 16384) secCache.Clear(); secCache[sector] = b; return b; }
    public uint FatNext(uint c) { long off = (long)FatOffset * SectorSize + (long)c * 4; byte[] sec = ReadSector(off / SectorSize); return BitConverter.ToUInt32(sec, (int)(off % SectorSize)); }
    // dataLen < 0 = unknown length: follow the FAT to its end
    public List<uint> Chain(uint first, long dataLen, bool contiguous, int cap) {
      List<uint> list = new List<uint>(); if (!ValidCluster(first)) return list;
      long need = dataLen < 0 ? cap : (dataLen == 0 ? 1 : (dataLen + ClusterSize - 1) / ClusterSize); if (need > cap) need = cap;
      if (contiguous) { for (long i = 0; i < need; i++) { uint c = (uint)(first + i); if (!ValidCluster(c)) break; list.Add(c); } return list; }
      uint cur = first;
      while (ValidCluster(cur) && list.Count < need) { list.Add(cur); uint nx = FatNext(cur); if (nx >= 0xFFFFFFF8 || nx == 0 || nx == cur) break; cur = nx; }
      return list;
    }
    public bool ChainIntact(uint first, long dataLen) {
      long need = (dataLen + ClusterSize - 1) / ClusterSize; if (need <= 0) return true; uint cur = first; long n = 0;
      while (ValidCluster(cur)) { n++; if (n >= need) return true; uint nx = FatNext(cur); if (nx >= 0xFFFFFFF8 || nx == 0 || nx == cur) return false; cur = nx; }
      return false;
    }
    public bool IsFree(uint c) { if (!BitmapOk || !ValidCluster(c)) return false; long bit = c - 2; long idx = bit / 8; if (idx >= bitmap.Length) return false; return (bitmap[idx] & (1 << (int)(bit % 8))) == 0; }
    static DateTime Ts(uint t) {
      int year = 1980 + (int)((t >> 25) & 0x7F), month = (int)((t >> 21) & 0x0F), day = (int)((t >> 16) & 0x1F), hour = (int)((t >> 11) & 0x1F), min = (int)((t >> 5) & 0x3F), sec = (int)(t & 0x1F) * 2;
      try { return new DateTime(year, month == 0 ? 1 : month, day == 0 ? 1 : day, hour > 23 ? 0 : hour, min > 59 ? 0 : min, sec > 59 ? 0 : sec); } catch { return DateTime.MinValue; }
    }
    public void Scan() {
      List<uint> root = Chain(RootCluster, -1, false, 1 << 16);
      foreach (uint c in root) {                                   // the allocation bitmap lives in the root directory
        byte[] blk = ReadCluster(c); bool found = false;
        for (int o = 0; o + 32 <= blk.Length; o += 32) { byte t = blk[o]; if (t == 0) break; if (t != 0x81) continue;
          uint first = BitConverter.ToUInt32(blk, o + 20); long len = BitConverter.ToInt64(blk, o + 24);
          if (len > 0 && len < (256L << 20) && ValidCluster(first)) { bitmap = new byte[len]; long done = 0; foreach (uint bc in Chain(first, len, false, 1 << 20)) { byte[] bb = ReadCluster(bc); int n = (int)Math.Min((long)ClusterSize, len - done); Buffer.BlockCopy(bb, 0, bitmap, (int)done, n); done += n; if (done >= len) break; } BitmapOk = done >= len; }
          found = true; break; }
        if (found) break;
      }
      WalkDir("", root, false, 0, DateTime.MinValue);
      Deleted = new List<XEntry>(byPath.Values);
      foreach (XEntry e in Deleted) { if (!e.IsDir && e.State.StartsWith("intact")) { IntactCount++; IntactBytes += e.Size; } }
      Deleted.Sort(delegate(XEntry a, XEntry b) { int c = b.FolderChanged.CompareTo(a.FolderChanged); return c != 0 ? c : b.Modified.CompareTo(a.Modified); });
    }
    public void ScanInBackground() {
      System.Threading.Thread t = new System.Threading.Thread(delegate() { try { Scan(); } catch (Exception e) { ScanError = e.Message; } finally { Done = true; } });
      t.IsBackground = true; t.Start();
    }
    void Keep(XEntry x) {
      XEntry old;
      if (byPath.TryGetValue(x.Path, out old)) { old.Times++; Duplicates++; if (x.Modified > old.Modified) { x.Times = old.Times; byPath[x.Path] = x; } return; }
      if (byPath.Count >= MaxKeep) { Dropped++; return; }
      byPath[x.Path] = x;
    }
    bool UnderPrefix(string full) { return PathPrefix == null || full.StartsWith(PathPrefix, StringComparison.OrdinalIgnoreCase); }
    bool MayContainPrefix(string full) { return PathPrefix == null || UnderPrefix(full) || PathPrefix.StartsWith(full + "\\", StringComparison.OrdinalIgnoreCase); }
    string Assess(XEntry x) {
      if (x.IsDir) return "folder"; if (x.Size <= 0) return "empty"; if (!ValidCluster(x.FirstCluster)) return "unknown"; if (!BitmapOk) return "unknown";
      long need = (x.Size + ClusterSize - 1) / ClusterSize;
      if (x.Contiguous) { long free = 0, seen = 0; for (long i = 0; i < need; i++) { uint c = (uint)(x.FirstCluster + i); if (!ValidCluster(c)) break; seen++; if (IsFree(c)) free++; } if (seen < need) return "unknown"; if (free == need) return "intact"; return free == 0 ? "overwritten" : "partly overwritten"; }
      if (ChainIntact(x.FirstCluster, x.Size)) { List<uint> ch = Chain(x.FirstCluster, x.Size, false, 1 << 20); long free = 0; foreach (uint c in ch) if (IsFree(c)) free++; if (free == ch.Count) return "intact (fragmented)"; return free == 0 ? "overwritten" : "partly overwritten"; }
      return "chain lost";
    }
    void WalkDir(string path, List<uint> clusters, bool parentDeleted, int depth, DateTime dirModified) {
      if (DirsScanned >= MaxDirs) { Skipped++; return; }
      bool inWindow = Since == DateTime.MinValue || dirModified == DateTime.MinValue || dirModified >= Since;
      DirsScanned++;
      List<byte[]> entries = new List<byte[]>(); bool end = false; List<uint> mine = new List<uint>();
      foreach (uint c in clusters) { if (onPath.Contains(c)) break; onPath.Add(c); mine.Add(c); ClustersRead++; byte[] blk = ReadCluster(c);
        for (int o = 0; o + 32 <= blk.Length; o += 32) { if (blk[o] == 0) { end = true; break; } byte[] e = new byte[32]; Buffer.BlockCopy(blk, o, e, 0, 32); entries.Add(e); }
        if (end) break; }
      try {
      EntriesSeen += entries.Count;
      List<object[]> subdirs = new List<object[]>();
      for (int i = 0; i < entries.Count; i++) {
        byte t = entries[i][0]; if ((t & 0x7F) != 0x05) continue;      // 0x85 live file set, 0x05 deleted file set
        bool deleted = (t & 0x80) == 0; byte[] f = entries[i]; int sec = f[1];
        if (sec < 2 || sec > 18 || i + sec >= entries.Count) continue;
        byte[] st = entries[i + 1]; if ((st[0] & 0x7F) != 0x40 || (((st[0] & 0x80) == 0) != deleted)) continue;
        int nameLen = st[3]; if (nameLen < 1 || nameLen > 255) continue;
        StringBuilder sb = new StringBuilder();
        for (int k = 2; k <= sec; k++) { byte[] ne = entries[i + k]; if ((ne[0] & 0x7F) != 0x41) break; sb.Append(Encoding.Unicode.GetString(ne, 2, 30)); }
        string name = sb.Length >= nameLen ? sb.ToString(0, nameLen) : sb.ToString();
        if (name.Length == 0 || name.IndexOf('\0') >= 0 || name == "." || name == "..") continue;
        ushort attr = BitConverter.ToUInt16(f, 4); bool isDir = (attr & 0x10) != 0;
        bool contiguous = (st[1] & 0x02) != 0; long validLen = BitConverter.ToInt64(st, 8); uint first = BitConverter.ToUInt32(st, 20); long len = BitConverter.ToInt64(st, 24);
        string full = path + "\\" + name;
        DateTime modified = Ts(BitConverter.ToUInt32(f, 12));
        if (deleted) {
          if (!inWindow) { OlderThanWindow++; i += sec; continue; }          // the folder has not changed since the window began, so this went earlier
          if (!UnderPrefix(full)) { OutsidePrefix++; }
          else {
            XEntry x = new XEntry(); x.Path = full; x.Name = name; x.IsDir = isDir; x.Size = len; x.ValidSize = validLen; x.FirstCluster = first; x.Contiguous = contiguous;
            x.Modified = modified; x.Created = Ts(BitConverter.ToUInt32(f, 8)); x.ParentDeleted = parentDeleted; x.Depth = depth; x.FolderChanged = dirModified;
            x.State = Assess(x); Keep(x);
          }
          // a deleted folder's own modified time is when its last entry was removed - a good deletion-time bound for what it held
          if (isDir && depth < MaxDeletedDepth && ValidCluster(first) && len > 0 && len < (64L << 20) && MayContainPrefix(full)) subdirs.Add(new object[] { full, first, len, contiguous, true, modified });
        } else if (isDir && ValidCluster(first) && MayContainPrefix(full)) subdirs.Add(new object[] { full, first, len, contiguous, false, modified });
        i += sec;
      }
      foreach (object[] sd in subdirs) {
        string sp = (string)sd[0]; uint first = (uint)sd[1]; long len = (long)sd[2]; bool contiguous = (bool)sd[3]; bool del = (bool)sd[4]; DateTime m = (DateTime)sd[5];
        // a folder's modified time covers only its direct children, so a live folder is always descended (its subfolders may be newer);
        // a DELETED folder was emptied before its own last change, so one older than the window can be skipped whole
        if (del && Since != DateTime.MinValue && m != DateTime.MinValue && m < Since) { continue; }
        List<uint> ch;
        if (del) ch = contiguous ? Chain(first, len, true, 4096) : (ChainIntact(first, len) ? Chain(first, len, false, 4096) : Chain(first, ClusterSize, true, 1));
        else ch = Chain(first, len, contiguous, 1 << 20);
        WalkDir(sp, ch, parentDeleted || del, depth + 1, m);
      }
      } finally { foreach (uint c in mine) onPath.Remove(c); }
    }
    public byte[] ReadHead(XEntry x, int max) {
      long want = Math.Min((long)max, x.Size); if (want <= 0 || !ValidCluster(x.FirstCluster)) return new byte[0];
      List<uint> ch = Chain(x.FirstCluster, want, x.Contiguous, 64); byte[] outb = new byte[want]; long done = 0;
      foreach (uint c in ch) { if (done >= want) break; byte[] blk = ReadCluster(c); int n = (int)Math.Min((long)ClusterSize, want - done); Buffer.BlockCopy(blk, 0, outb, (int)done, n); done += n; }
      return outb;
    }
    // copies a deleted file's clusters to dest; only the destination is written
    public long Recover(XEntry x, string dest) {
      if (x.IsDir) throw new InvalidOperationException("that is a folder");
      List<uint> ch = Chain(x.FirstCluster, x.Size, x.Contiguous, 1 << 22);
      long remaining = x.Size, written = 0;
      string dir = System.IO.Path.GetDirectoryName(dest); if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
      using (FileStream o = new FileStream(dest, FileMode.Create, FileAccess.Write, FileShare.None)) {
        foreach (uint c in ch) { if (remaining <= 0) break; byte[] b = ReadCluster(c); int n = (int)Math.Min((long)ClusterSize, remaining); o.Write(b, 0, n); remaining -= n; written += n; }
      }
      return written;
    }
  }
}
'@ -ErrorAction Stop
    }
    $script:ExFatOk = $true
} catch { $script:ExFatError = $_.Exception.Message }
$script:ExFatVols = @{}

function Scan-ExFat {
    # lists the deleted entries still present in an exFAT drive's directory tables; returns @{ Rows; Hidden }
    param($Disk, [string]$PathFilter, [bool]$ShowAll)
    $L = $Disk.DeviceID.TrimEnd(':'); $info = Describe-Drive $Disk; $G = $script:G
    Section "$($Disk.DeviceID) — exFAT directory tables ($($info.Kind), $($info.Label), $($info.Size))"
    $out = @{ Rows = (New-Object 'System.Collections.Generic.List[object]'); Hidden = 0 }
    if (-not $script:ExFatOk) { Write-Host ('  ' + (C amber $G.warn) + ' ' + (C dim ('the exFAT reader could not compile: ' + $script:ExFatError))); Show-NoJournalDrive $Disk; return $out }
    $x = $null
    try { $x = [FD.ExFat]::Open($L) } catch { Write-Host ('  ' + (C amber $G.warn) + ' ' + (C ink 'Could not open the volume for a raw read') + (C dim (' — ' + $_.Exception.Message + '. This needs an elevated prompt.'))); Show-NoJournalDrive $Disk; return $out }
    $script:ExFatVols[$L] = $x
    if ($PathFilter -and $PathFilter.Length -gt 2 -and $PathFilter.Substring(0, 2) -eq "$L`:".ToLowerInvariant()) { $x.PathPrefix = $PathFilter.Substring(2) }
    Write-Host ('  ' + (C dim ('{0} KB clusters · {1:N0} clusters · reading the directory tables only, nothing is written to the drive' -f ($x.ClusterSize / 1KB), $x.ClusterCount)))
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $x.ScanInBackground()
    while (-not $x.Done) { Start-Sleep -Milliseconds 250; Write-Progress -Activity "Reading exFAT directory tables on $($Disk.DeviceID)" -Status ('{0:N0} folders · {1:N0} entries · {2:N1}s' -f $x.DirsScanned, $x.EntriesSeen, $sw.Elapsed.TotalSeconds) }
    Write-Progress -Activity "Reading exFAT directory tables on $($Disk.DeviceID)" -Completed
    if ($x.ScanError) { Write-Host ('  ' + (C amber $G.warn) + ' ' + (C dim ('scan stopped early: ' + $x.ScanError))) }
    $intact = $x.IntactCount
    Write-Host ('  ' + (C teal $G.dot) + ' ' + (C ink ('{0:N0} folders read · {1:N0} distinct deleted entries still present · {2:N0} files with their data intact ({3})' -f $x.DirsScanned, $x.Deleted.Count, $intact, (Format-Bytes $x.IntactBytes))) + (C dim (' · {0:N1}s' -f $sw.Elapsed.TotalSeconds)))
    if ($x.Dropped) { Write-Host ('  ' + (C amber $G.warn) + ' ' + (C dim ('{0:N0} more entries were not kept (cap {1:N0}); narrow with a folder path' -f $x.Dropped, $x.MaxKeep))) }
    if (-not $x.BitmapOk) { Write-Host ('  ' + (C amber $G.warn) + ' ' + (C dim 'the allocation bitmap could not be read, so whether a file''s data is still intact is unknown')) }

    # The Recycle Bin on exFAT: a deletion via the bin renames the file to $R<id>.<ext> inside \$RECYCLE.BIN and writes a
    # small $I<id> record (original path + deletion time). Emptying the bin deletes both. If the $I record's data is still
    # intact, the original name and the real deletion time come back; otherwise the $R name and extension are all that is left.
    $binInfo = @{}
    foreach ($e in $x.Deleted) {
        if ($e.IsDir -or $e.Path -notmatch '^\\\$RECYCLE\.BIN\\\$I([A-Z0-9]{6})') { continue }
        $id = $matches[1]
        # the record's own timestamp is the moment the file went into the bin, and it survives even when the record's data is gone
        $binInfo[$id] = @{ Path = $null; When = $e.Modified }
        if ($e.Size -lt 24 -or $e.Size -gt 4096 -or $e.State -notlike 'intact*') { continue }
        try {
            $bytes = $x.ReadHead($e, [int]$e.Size)
            $ver = [BitConverter]::ToInt64($bytes, 0); if ($ver -lt 1 -or $ver -gt 2) { continue }
            $ft = [BitConverter]::ToInt64($bytes, 16); $when = [datetime]::FromFileTime($ft)
            if ($when.Year -lt 2000 -or $when -gt (Get-Date).AddDays(1)) { continue }
            if ($ver -eq 2) { $n = [BitConverter]::ToInt32($bytes, 24); if ($n -lt 2 -or 28 + $n * 2 -gt $bytes.Length) { continue }; $orig = [Text.Encoding]::Unicode.GetString($bytes, 28, ($n - 1) * 2) }
            else { $orig = [Text.Encoding]::Unicode.GetString($bytes, 24, [math]::Min(520, $bytes.Length - 24)); $z = $orig.IndexOf([char]0); if ($z -ge 0) { $orig = $orig.Substring(0, $z) } }
            if ($orig -notmatch '^[A-Za-z]:\\') { continue }
            $binInfo[$id] = @{ Path = $orig; When = $when }
        } catch {}
    }
    $named = @($binInfo.Values | Where-Object { $_.Path }).Count
    if ($binInfo.Count) { Write-Host ('  ' + (C teal $G.dot) + ' ' + (C ink ('{0:N0} Recycle Bin record(s) found: the deletion time is known for all of them, the original name for {1:N0}' -f $binInfo.Count, $named))) }
    Write-Host ('  ' + (C dim $G.dot) + ' ' + (C dim 'exFAT records no deletion time, so the day window does not apply here: WHEN is the entry''s own last-modified time, except for files emptied from the Recycle Bin whose record survived. Entries vanish for good when their directory slot is reused.'))
    if ($intact -gt 0) { Write-Host ('  ' + (C dim $G.dot) + ' ' + (C dim ('"intact" = its clusters are unallocated now; anything written to the drive can still destroy it - copy it out with -RecoverTo (or the menu question) soon.'))) }
    $bins = @{}; $ri = 0; $rn = $x.Deleted.Count
    foreach ($e in $x.Deleted) {
        $ri++; if (($ri % 5000) -eq 0) { Write-Progress -Activity "Sorting out $($Disk.DeviceID) entries" -Status ('{0:N0} / {1:N0}' -f $ri, $rn) -PercentComplete ([int](100 * $ri / $rn)) }
        $full = "$L`:" + $e.Path; $when = $e.Modified; $note = ''; $binId = ''
        if ($e.Path -match '^\\\$RECYCLE\.BIN\\\$([IR])([A-Z0-9]{6})(.*)$') {
            if ($matches[1] -eq 'I') { if (-not $ShowAll) { $out.Hidden++; continue } ; $note = 'Recycle Bin record' }
            else {
                $binId = $matches[2]; $rest = $matches[3]; $bi = $binInfo[$binId]
                if ($bi -and $bi.Path) { $full = $bi.Path + $rest; $when = $bi.When; $note = 'emptied from the Recycle Bin' }
                elseif ($bi) { $when = $bi.When; $note = 'emptied from the Recycle Bin - original name lost' }
                else { $note = 'emptied from the Recycle Bin - record gone' }
                $b = $bins[$binId]
                if (-not $b) { $b = @{ Id = $binId; Name = $(if ($bi -and $bi.Path) { $bi.Path } else { "$L`:\`$RECYCLE.BIN\`$R$binId" }); Named = [bool]($bi -and $bi.Path); When = $(if ($bi) { $bi.When } else { $null }); IsDir = $false; Files = 0; Intact = 0; Bytes = 0L; Empty = 0; TopModified = $e.Modified }; $bins[$binId] = $b }
                if ($rest -eq '' -or $rest -notlike '\*') { $b.IsDir = $e.IsDir; $b.TopModified = $e.Modified; if (-not $b.Named) { $b.Name += $rest } }
                if (-not $e.IsDir) { if ($e.State -eq 'empty') { $b.Empty++ } else { $b.Files++ }; if ($e.State -like 'intact*') { $b.Intact++; $b.Bytes += $e.Size } }
                if ($e.State -eq 'empty' -and -not $ShowAll) { $out.Hidden++; continue }
            }
            $noise = $false
        } else {
            $noise = (Test-Noise $full $e.Name) -or ($e.State -eq 'empty')
            if ($noise -and -not $ShowAll) { $out.Hidden++; continue }
        }
        $out.Rows.Add([pscustomobject]@{ When = $when; Path = $full; Type = $(if ($e.IsDir) { 'folder' } else { 'file' }); Noise = $noise; Drive = $L; Shadow = $null; Source = 'exfat'; State = $e.State; Size = $e.Size; Ex = $e; Times = $e.Times; Note = $note; BinId = $binId })
    }
    Write-Progress -Activity "Sorting out $($Disk.DeviceID) entries" -Completed
    if ($bins.Count) {
        Section "$($Disk.DeviceID) — emptied from the Recycle Bin" ("  {0} item(s); their contents are listed under DELETED and can be copied out with -RecoverTo" -f $bins.Count)
        Write-Host ('  ' + (C dim 'A deletion through the bin keeps the file''s data in place and only renames it; emptying the bin then deletes the renamed copy. Where the bin''s own record survived, the original name and the moment of deletion are shown; otherwise the $R name and the item''s last-modified time.'))
        foreach ($b in ($bins.Values | Sort-Object { if ($_.When) { $_.When } else { $_.TopModified } } -Descending)) {
            $whenTxt = if ($b.When) { 'deleted ' + $b.When.ToString('yyyy-MM-dd HH:mm') } else { 'deletion time unknown · last modified ' + $b.TopModified.ToString('yyyy-MM-dd HH:mm') }
            $kind = if ($b.IsDir) { 'folder' } else { 'file' }
            Write-Host ('  ' + (C teal $G.dot) + ' ' + (C ink (Truncate-Path $b.Name 70)) + (C dim ("  $kind · $whenTxt")))
            Write-Host ('       ' + (C dim ('{0:N0} files inside, {1:N0} intact ({2}), {3:N0} empty' -f $b.Files, $b.Intact, (Format-Bytes $b.Bytes), $b.Empty)) + $(if (-not $b.Named) { (C faint '  · original name lost: the bin record''s data was overwritten') } else { '' }))
        }
    }
    return $out
}

# ═══════════════════════════════ helpers ═══════════════════════════════

$script:NoisePatterns = @(
    '\\AppData\\Local\\Temp\\', '\\Windows\\Temp\\', '\\Temp\\', '\\tmp\\', '\\Cache\\', '\\Cache2\\', '\\Code Cache\\', '\\GPUCache\\',
    '\\AppData\\Local\\Microsoft\\Windows\\INetCache\\', '\\AppData\\Local\\Packages\\', '\\node_modules\\', '\\\.git\\', '\\__pycache__\\',
    '\\Windows\\Prefetch\\', '\\Windows\\SoftwareDistribution\\', '\\ProgramData\\Microsoft\\Windows Defender\\', '\\WinSxS\\', '\\Windows\\Logs\\',
    '\\\$Recycle\.Bin\\', '\\System Volume Information\\', '\\AppData\\Local\\CrashDumps\\', '\\Windows\\ServiceProfiles\\',
    '\\\$Extend\\',                     # NTFS parks a file deleted while still open under \$Extend\$Deleted\<id>: not a user deletion
    '\\MSI[0-9a-f]{4,6}\.tmp\\'         # Windows Installer scratch folders
)
$script:NoiseNames = '^(~\$|~WRL|\.~lock)|\.(tmp|temp|log|etl|dmp|part|crdownload|partial|bak~|swp|lock|ldb|journal|db-shm|db-wal|db-journal|vscdb-journal|writable)$|^thumbs\.db$|^desktop\.ini$'

# Only NTFS and ReFS keep a USN change journal. exFAT / FAT32 externals, SD cards and cloud-drive letters do not,
# so nothing on them can be listed after the fact - they are shown with the reason instead of being hidden.
function Test-Journalable { param($Disk) return ($Disk.FileSystem -in @('NTFS', 'ReFS')) }
function Describe-Drive {
    param($Disk)
    $kind = switch ([int]$Disk.DriveType) { 2 { 'removable' } 3 { 'fixed' } 4 { 'network' } 5 { 'optical' } 6 { 'RAM disk' } default { 'unknown' } }
    $label = if ($Disk.VolumeName) { $Disk.VolumeName } else { 'Local Disk' }
    $size = if ($Disk.Size) { ('{0:N0} GB' -f ($Disk.Size / 1GB)) } else { 'no media' }
    return [pscustomobject]@{ Kind = $kind; Label = $label; Size = $size; Fs = $(if ($Disk.FileSystem) { $Disk.FileSystem } else { '-' }); Ok = (Test-Journalable $Disk)
        Why = $(if (-not $Disk.FileSystem) { 'no media inserted' } elseif (Test-Journalable $Disk) { '' } else { "$($Disk.FileSystem) keeps no change journal" }) }
}
function Show-NoJournalDrive {
    # what can still be done for a drive without a journal: its own recycle bin, and carving tools
    param($Disk)
    $L = $Disk.DeviceID.TrimEnd(':'); $info = Describe-Drive $Disk
    Section "$($Disk.DeviceID) — $($info.Fs) ($($info.Kind), $($info.Label), $($info.Size))"
    Write-Host ('  ' + (C amber $script:G.dot) + ' ' + (C ink "$($info.Fs) has no NTFS change journal, so Windows kept no record of what was deleted here.") )
    $binCount = 0
    try {
        $binRoot = "$($Disk.DeviceID)\`$RECYCLE.BIN"
        $bin = @(Get-ChildItem -LiteralPath $binRoot -Force -File -ErrorAction Stop | Where-Object { $_.Name -like '$R*' })                       # flat layout (exFAT, FAT32)
        $bin += @(Get-ChildItem -LiteralPath $binRoot -Force -Directory -ErrorAction SilentlyContinue | ForEach-Object { Get-ChildItem -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '$R*' } })   # per-user subfolders (NTFS)
        $binCount = $bin.Count
    } catch {}
    if ($binCount) { Write-Host ('  ' + (C teal $script:G.dot) + ' ' + (C ink ("This drive's own Recycle Bin still holds {0:N0} item(s)" -f $binCount)) + (C dim ' — open the Recycle Bin and restore them; they are not gone yet.')) }
    else { Write-Host ('  ' + (C dim $script:G.dot) + ' ' + (C dim "Nothing in this drive's Recycle Bin (removable drives usually bypass it).")) }
    Write-Host ('  ' + (C dim $script:G.dot) + ' ' + (C dim 'What still works: stop writing to the drive, then run a carving tool (Recuva, PhotoRec, TestDisk) against it — it finds file contents that have not been overwritten, but not their names or folders.'))
    Write-Host ('  ' + (C dim $script:G.dot) + ' ' + (C dim 'For the future: an external drive formatted as NTFS gets a journal, and this script can read it. Reformatting erases the drive, so copy it off first.'))
}

function Format-Bytes { param([double]$B) if ($B -ge 1GB) { return ('{0:N2} GB' -f ($B / 1GB)) } if ($B -ge 1MB) { return ('{0:N1} MB' -f ($B / 1MB)) } if ($B -ge 1KB) { return ('{0:N0} KB' -f ($B / 1KB)) } return ('{0:N0} B' -f $B) }

$script:NoisePathRe = New-Object System.Text.RegularExpressions.Regex (($script:NoisePatterns -join '|'), ([System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Compiled))
$script:NoiseNameRe = New-Object System.Text.RegularExpressions.Regex ($script:NoiseNames, ([System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Compiled))
function Test-Noise {
    param([string]$FullPath, [string]$Name)
    if ($script:NoisePathRe.IsMatch($FullPath)) { return $true }
    if ($script:NoiseNameRe.IsMatch($Name)) { return $true }
    return $false
}

function Parse-Id { param([string]$Hex) $h = $Hex.Trim(); if ($h.StartsWith('0x')) { $h = $h.Substring(2) }; if ($h.Length -gt 16) { $h = $h.Substring($h.Length - 16) }; try { return [Convert]::ToInt64($h, 16) } catch { return 0 } }
function Parse-Time { param([string]$S) $t = $S.Trim().Trim('"'); $d = [datetime]::MinValue
    # fsutil writes M/d/yyyy H:mm:ss regardless of locale (24-hour); try that exactly first, then the loose parsers
    if ([datetime]::TryParseExact($t, @('M/d/yyyy H:mm:ss', 'M/d/yyyy h:mm:ss tt', 'yyyy-MM-dd HH:mm:ss', 'yyyy-MM-dd HH:mm:ss.ffff'), [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$d)) { return $d }
    if ([datetime]::TryParse($t, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$d)) { return $d }
    if ([datetime]::TryParse($t, [Globalization.CultureInfo]::CurrentCulture, [Globalization.DateTimeStyles]::None, [ref]$d)) { return $d }
    return [datetime]::MinValue }
function Unquote { param([string]$S) $t = $S.Trim(); if ($t.Length -ge 2 -and $t[0] -eq '"' -and $t[$t.Length - 1] -eq '"') { $t = $t.Substring(1, $t.Length - 2) }; return $t.Replace('""', '"') }

# ═══════════════════════════════ USN journal ═══════════════════════════════

function Read-Journal {
    # Returns @{ Deleted = list; Dirs = map FRN→(Name,Parent); Oldest = datetime; Records = count; Active = bool }
    param([string]$Letter, [datetime]$Since)
    $vol = "$Letter`:"
    $out = @{ Deleted = New-Object 'System.Collections.Generic.List[object]'; Dirs = @{}; Oldest = [datetime]::MaxValue; Records = 0; Active = $false; Error = $null }

    $q = & fsutil usn queryjournal $vol 2>&1
    if ($LASTEXITCODE -ne 0 -or ($q -join ' ') -match 'not active|no USN|Error') { $out.Error = ($q -join ' ').Trim(); return $out }
    $out.Active = $true

    $sw = [Diagnostics.Stopwatch]::StartNew()
    & fsutil usn readjournal $vol csv 2>&1 | ForEach-Object {
        $line = $_
        if ($line -isnot [string]) { return }
        # preamble ("USN Journal ID : …", "First USN : …") and any header: records start with the decimal USN
        if ($line.Length -lt 20 -or -not [char]::IsDigit($line[0])) { return }
        $out.Records++
        if (($out.Records % 20000) -eq 0) { Write-Progress -Activity "Reading USN journal on $vol" -Status ("{0:N0} records · {1:N0}s" -f $out.Records, $sw.Elapsed.TotalSeconds) }

        # Two layouts, both parsed from the END because only the file name can contain commas:
        #   new (Win10 2004+, Win11), 16 fields:
        #     Usn,"File name",NameLen,ReasonHex,"Reason text","Time stamp",AttrHex,"Attr text",FileID,ParentID,Source,"SecurityID",?,Major,Minor,RecLen
        #   old, 13 fields, unquoted:
        #     Usn,File name,NameLen,Reason,Time stamp,Attr,FileID,ParentID,Source,SecurityID,Major,Minor,RecLen
        $f = $line.Split(',')
        $n = $f.Count
        if ($n -lt 13) { return }
        if ($n -ge 16 -and $f[1].StartsWith('"')) {
            $name = Unquote ($f[1..($n - 15)] -join ',')
            $reason = $f[$n - 13]; $reasonText = Unquote $f[$n - 12]; $ts = $f[$n - 11]; $attr = $f[$n - 10]; $fid = $f[$n - 8]; $pidRaw = $f[$n - 7]
        } else {
            $name = ($f[1..($n - 12)] -join ',').Trim(); $reasonText = ''
            $reason = $f[$n - 10]; $ts = $f[$n - 9]; $attr = $f[$n - 8]; $fid = $f[$n - 7]; $pidRaw = $f[$n - 6]
        }

        $when = Parse-Time $ts
        if ($when -ne [datetime]::MinValue -and $when -lt $out.Oldest) { $out.Oldest = $when }

        $attrVal = 0; try { $attrVal = [Convert]::ToInt64($attr.Trim().Replace('0x', ''), 16) } catch {}
        $isDir = ($attrVal -band 0x10) -ne 0
        $frn = Parse-Id $fid; $parent = Parse-Id $pidRaw

        if ($isDir -and $frn) { $out.Dirs[$frn] = @{ Name = $name; Parent = $parent } }

        $isDelete = $false
        if ($reason -match '0x([0-9a-fA-F]+)') { try { $isDelete = (([Convert]::ToInt64($matches[1], 16)) -band 0x200) -ne 0 } catch {} }
        if (-not $isDelete -and ($reason -match 'File delete' -or $reasonText -match 'File delete')) { $isDelete = $true }
        if (-not $isDelete) { return }
        if ($when -lt $Since) { return }

        $out.Deleted.Add([pscustomobject]@{ Name = $name; When = $when; IsDir = $isDir; Frn = $frn; Parent = $parent; Drive = $Letter })
    }
    Write-Progress -Activity "Reading USN journal on $vol" -Completed
    return $out
}

function Resolve-Parent {
    param([long]$Frn, [string]$Letter, $Dirs, $Vol, $Cache, [int]$Depth = 0)
    if ($Frn -eq 0 -or $Depth -gt 64) { return $null }
    if ($Cache.ContainsKey($Frn)) { return $Cache[$Frn] }
    $p = $null
    if ($Vol -ne [IntPtr]::Zero) { $p = [FD.Res]::PathById($Vol, $Frn) }
    if (-not $p -and $Dirs.ContainsKey($Frn)) {
        $d = $Dirs[$Frn]
        $pp = Resolve-Parent $d.Parent $Letter $Dirs $Vol $Cache ($Depth + 1)
        if ($pp) { $p = Join-Path $pp $d.Name } else { $p = "$Letter`:\<deleted>\$($d.Name)" }
    }
    $Cache[$Frn] = $p
    return $p
}

# ═══════════════════════════════ shadow copies ═══════════════════════════════

function Get-Shadows {
    param([string]$Letter)
    $list = @()
    try {
        $vols = Get-CimInstance Win32_Volume -ErrorAction Stop | Where-Object { $_.DriveLetter -eq "$Letter`:" }
        $ids = @($vols | ForEach-Object { $_.DeviceID })
        $sc = Get-CimInstance Win32_ShadowCopy -ErrorAction Stop | Where-Object { $ids -contains $_.VolumeName }
        foreach ($s in ($sc | Sort-Object InstallDate -Descending)) {
            $list += [pscustomobject]@{ Id = $s.ID; Date = $s.InstallDate; Device = $s.DeviceObject; Root = ($s.DeviceObject + '\') }
        }
    } catch {}
    return $list
}

function Test-InShadow {
    # returns the first snapshot (newest first) that still has the file, or $null
    param([string]$FullPath, $Shadows, [string]$Letter)
    if (-not $Shadows -or $FullPath.Length -lt 3) { return $null }
    $rel = $FullPath.Substring(3)
    foreach ($s in $Shadows) {
        $p = $s.Root + $rel
        try { if ($script:ResolverOk) { if ([FD.Res]::Exists($p)) { return $s } } elseif ([System.IO.File]::Exists($p) -or [System.IO.Directory]::Exists($p)) { return $s } } catch {}
    }
    return $null
}

# ═══════════════════════════════ error guidance ═══════════════════════════════

function Show-Failure {
    param($Err)
    $msg = "$($Err.Exception.Message)"; $me = $PSCommandPath
    Write-Progress -Activity ' ' -Completed
    Write-Host ''; Write-Host ('  ' + (C rose ($script:G.err + ' The script stopped.')) + '  ' + (C dim (Truncate-Path $msg 100))); Write-Host ''
    Write-Host ('  ' + (C bold (C ink 'What to try:')))
    if ($msg -match 'Administrator|elevat|Access is denied|PermissionDenied') {
        Write-Host ('  ' + (C teal '1.') + ' ' + (C ink 'Reading the USN journal needs an elevated prompt:'))
        Write-Host ('       ' + (C amber "Start-Process powershell -Verb RunAs -ArgumentList '-ExecutionPolicy Bypass -File `"$me`" -Interactive'"))
        Write-Host ('  ' + (C teal '2.') + ' ' + (C ink 'Or right-click ') + (C amber 'Run-DeletedFiles.cmd') + (C ink ' → Run as administrator.'))
    }
    elseif ($msg -match 'fsutil|not recognized') {
        Write-Host ('  ' + (C teal '1.') + ' ' + (C ink 'fsutil.exe was not found or failed. It ships with Windows; check ') + (C amber 'C:\Windows\System32\fsutil.exe') + (C ink ' exists and PATH includes System32.'))
    }
    elseif ($msg -match 'not digitally signed|execution polic') {
        Write-Host ('  ' + (C teal '1.') + ' ' + (C amber "Unblock-File `"$me`"") + (C ink '   or use Run-DeletedFiles.cmd'))
    }
    elseif ($msg -match 'Add-Type|compil') {
        Write-Host ('  ' + (C teal '1.') + ' ' + (C ink 'The path resolver could not compile; the script falls back to journal-only resolution. Report this if paths look wrong:'))
        Write-Host ('       ' + (C amber $msg))
    }
    else {
        Write-Host ('  ' + (C teal '1.') + ' ' + (C ink 'The combination that works on almost any machine (elevated):'))
        Write-Host ('       ' + (C amber "powershell -NoProfile -ExecutionPolicy Bypass -File `"$me`" -NoColor -Interactive"))
    }
    Write-Host ''; Write-Host ('  ' + (C dim ('at: ' + ("$($Err.InvocationInfo.PositionMessage)" -replace '\s+', ' ')))); Write-Host ''
}

# ═══════════════════════════════ menu ═══════════════════════════════

function Invoke-Menu {
    param($Disks)
    Write-Host ''; Write-Host ('  ' + (C teal $script:G.mark) + ' ' + (C bold (C ink 'DELETED FILES')) + '  ' + (C dim 'what was permanently deleted, and what a shadow copy can still give back'))
    Write-Host ('  ' + (C dim 'Six questions. Press Enter to accept the default shown after each one.'))
    Write-Host ''
    Write-Host ('  ' + (C bold (C ink 'Drives on this machine')) + (C dim '   only NTFS and ReFS keep a change journal; the others are listed so you can see why they cannot be read'))
    $i = 0
    foreach ($d in $Disks) {
        $i++; $info = Describe-Drive $d
        $line = '       ' + (C amber ('{0}' -f $i)) + '  ' + (C ink ('{0,-4}' -f $d.DeviceID)) + (C $(if ($info.Ok -or $d.FileSystem -eq 'exFAT') { 'ink' } else { 'dim' }) ('{0,-7}' -f $info.Fs)) + (C dim ('{0,-10}' -f $info.Kind)) + (C dim ('{0,-9}' -f $info.Size)) + (C dim $info.Label)
        if ($info.Ok) { $line += (C teal '   journal') } elseif ($d.FileSystem -eq 'exFAT') { $line += (C teal '   directory scan') + (C dim ' (no journal: deleted entries still on disk, no deletion time)') } elseif ($info.Why) { $line += (C amber ('   ' + $info.Why)) }
        Write-Host $line
    }
    $sel = Ask 'Which drives?' 'all' '1/6' 'numbers or letters separated by spaces, or all (= every drive with a journal)'
    $chosen = @()
    if ($sel -eq 'all') { $chosen = @($Disks | Where-Object { (Test-Journalable $_) -or $_.FileSystem -eq 'exFAT' }) }
    else {
        foreach ($tok in ($sel -split '[,\s]+' | Where-Object { $_ })) {
            if ($tok -match '^\d+$' -and [int]$tok -ge 1 -and [int]$tok -le $Disks.Count) { $chosen += $Disks[[int]$tok - 1] }
            else { $l = $tok.TrimEnd(':', '\').ToUpper() + ':'; $m = $Disks | Where-Object { $_.DeviceID -eq $l }; if ($m) { $chosen += $m } }
        }
        if (-not $chosen) { $chosen = @($Disks | Where-Object { (Test-Journalable $_) -or $_.FileSystem -eq 'exFAT' }) }
    }
    $dd = Ask 'Look back how many days?' "$($script:Cfg.Days)" '2/6' 'the journal itself decides how far back is possible; the report says'; $n = 0; if ([int]::TryParse($dd, [ref]$n) -and $n -gt 0) { $script:Cfg.Days = $n }
    $pp = Ask 'Only under one folder?' '' '3/6' 'a path such as C:\Users\me\Documents; blank = the whole drive'; if ($pp) { $script:Cfg.Path = $pp }
    $sa = Ask 'Show temp, cache and lock-file noise too?' 'n' '4/6' 'y or n'; $script:Cfg.ShowAll = ($sa -match '^y')
    $sc = Ask 'Check Volume Shadow Copies for recoverable copies?' 'y' '5/6' 'y or n; needs System Protection to have been on'; $script:Cfg.NoShadowCheck = ($sc -notmatch '^y')
    $cs = Ask 'Export the list to a CSV file?' '' '6/6' 'a path such as .\deleted.csv; blank = no file'; if ($cs) { $script:Cfg.ExportCsv = $cs }
    if ($chosen | Where-Object { $_.FileSystem -eq 'exFAT' }) {
        $rt = Ask 'Copy recoverable files from the exFAT drive to a folder?' '' 'exFAT' "a folder on ANOTHER drive, e.g. C:\Recovered - folder structure kept, up to $($script:Cfg.RecoverMax) files (-RecoverMax 0 = all); blank = only list them"
        if ($rt) { $script:Cfg.RecoverTo = $rt }
    }
    Write-Host ''
    return $chosen
}

# ═══════════════════════════════ main ═══════════════════════════════

$script:Cfg = @{ Days = $Days; Path = $Path; ShowAll = [bool]$ShowAll; NoShadowCheck = [bool]$NoShadowCheck; ExportCsv = $ExportCsv; RecoverTo = $RecoverTo; RecoverMax = $RecoverMax }
$volHandles = @{}
try {
    $IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $IsAdmin) {
        Write-Host ''; Write-Host ('  ' + (C amber $script:G.warn) + ' ' + (C ink 'Reading the USN journal requires Administrator.'))
        $e = Ask 'Relaunch as Administrator now?' 'y' 'Admin' 'y opens an elevated window (this one closes); n stops here'
        if ($e -match '^y') {
            $argLine = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Interactive -Hold"; if (-not $script:UseColor) { $argLine += ' -NoColor' }; if (-not $script:UseGlyphs) { $argLine += ' -Ascii' }
            try { Start-Process powershell -Verb RunAs -ArgumentList $argLine; Restore-Console; exit 0 } catch {}
        }
        throw 'Administrator rights are required to read the USN journal.'
    }

    $all = @(Get-CimInstance Win32_LogicalDisk -Filter "DriveType=2 OR DriveType=3" -ErrorAction Stop | Sort-Object DeviceID)
    if (-not $all) { throw 'No local drives found.' }
    if (-not ($all | Where-Object { Test-Journalable $_ })) { throw 'No NTFS or ReFS drive found - only those keep a change journal.' }

    $gave = $false; foreach ($a in @('Drive', 'Days', 'Path', 'ShowAll', 'NoShadowCheck', 'ExportCsv')) { if ($PSBoundParameters.ContainsKey($a)) { $gave = $true } }
    if ($Interactive -or -not $gave) { $disks = Invoke-Menu -Disks $all }
    else {
        $disks = $all
        # started with -File (the .cmd, the elevated relaunch), "-Drive C,D" arrives as the single string "C,D": split it here
        if ($Drive) { $want = @($Drive | ForEach-Object { $_ -split '[,;\s]+' } | Where-Object { $_ } | ForEach-Object { $_.TrimEnd(':', '\').ToUpper() + ':' }); $disks = @($all | Where-Object { $want -contains $_.DeviceID }); if (-not $disks) { throw "None of '$($want -join ', ')' is a local drive here (found: $(($all | ForEach-Object { $_.DeviceID }) -join ' '))." } }
        else { $disks = @($all | Where-Object { (Test-Journalable $_) -or $_.FileSystem -eq 'exFAT' }) }
    }
    $cfg = $script:Cfg
    $since = (Get-Date).AddDays(-$cfg.Days)
    $pathFilter = if ($cfg.Path) { $cfg.Path.TrimEnd('\').ToLowerInvariant() } else { $null }

    Write-Host ''
    Write-Host ('  ' + (C teal $script:G.mark) + ' ' + (C bold (C ink 'DELETED FILES')) + '  ' + (C dim ("last $($cfg.Days) days · " + (($disks | ForEach-Object { $_.DeviceID }) -join ' ') + ' · ' + (Get-Date -Format 'yyyy-MM-dd HH:mm'))))
    if (-not $script:ResolverOk) { Write-Host ('  ' + (C amber $script:G.warn) + ' ' + (C dim 'path resolver unavailable — folders will be rebuilt from the journal only')) }

    $results = New-Object 'System.Collections.Generic.List[object]'
    $noiseHidden = 0

    foreach ($d in $disks) {
        $L = $d.DeviceID.TrimEnd(':')
        if (-not $d.FileSystem) { Section "$($d.DeviceID) — no media"; Write-Host ('  ' + (C dim $script:G.dot) + ' ' + (C dim 'Nothing is inserted in this slot - skipped.')); continue }
        if ($d.FileSystem -eq 'exFAT') { $ex = Scan-ExFat -Disk $d -PathFilter $pathFilter -ShowAll $cfg.ShowAll; foreach ($row in $ex.Rows) { $results.Add($row) }; $noiseHidden += $ex.Hidden; continue }
        if (-not (Test-Journalable $d)) { Show-NoJournalDrive $d; continue }
        Section "$($d.DeviceID) — USN journal"
        $j = Read-Journal -Letter $L -Since $since
        if (-not $j.Active) {
            Write-Host ('  ' + (C rose $script:G.dot) + ' ' + (C ink 'No active USN journal on this volume — nothing to read.') + '  ' + (C dim $j.Error))
            Write-Host ('  ' + (C dim '  Turn it on for the future:  ') + (C amber "fsutil usn createjournal m=0x40000000 a=0x1000000 $($d.DeviceID)"))
            continue
        }
        $coverage = if ($j.Oldest -eq [datetime]::MaxValue) { 'unknown' } else { $j.Oldest.ToString('yyyy-MM-dd HH:mm') }
        $covDays = if ($j.Oldest -eq [datetime]::MaxValue) { 0 } else { ((Get-Date) - $j.Oldest).TotalDays }
        $covCol = if ($covDays -ge $cfg.Days) { 'teal' } elseif ($covDays -ge $cfg.Days / 2) { 'amber' } else { 'rose' }
        Write-Host ('  ' + (C $covCol $script:G.dot) + ' ' + (C ink ('{0:N0} records · oldest {1}' -f $j.Records, $coverage)) + '  ' + (C $covCol ("$($script:G.to) this drive can see back {0:N1} days" -f $covDays)))
        if ($covDays -lt $cfg.Days) {
            Write-Host ('  ' + (C amber ("  the journal is shorter than your window — deletions before $coverage are invisible.")))
            Write-Host ('  ' + (C dim '  enlarge it for next time (1 GB, keeps months on most drives):  ') + (C amber "fsutil usn createjournal m=0x40000000 a=0x1000000 $($d.DeviceID)"))
        }

        $vol = [IntPtr]::Zero
        if ($script:ResolverOk) { $vol = [FD.Res]::OpenVolume("$L`:"); $volHandles[$L] = $vol }
        $cache = @{}
        $shadows = @(); if (-not $cfg.NoShadowCheck) { $shadows = @(Get-Shadows $L | Where-Object { $_.Date -ge $since.AddDays(-1) }) }

        $n = 0
        foreach ($rec in $j.Deleted) {
            $n++
            if (($n % 500) -eq 0) { Write-Progress -Activity "Resolving paths on $($d.DeviceID)" -Status ("{0:N0} / {1:N0}" -f $n, $j.Deleted.Count) -PercentComplete ([int](100 * $n / $j.Deleted.Count)) }
            $parentPath = Resolve-Parent $rec.Parent $L $j.Dirs $vol $cache
            $full = if ($parentPath) { Join-Path $parentPath $rec.Name } else { "$L`:\<unknown>\$($rec.Name)" }
            if ($pathFilter -and -not $full.ToLowerInvariant().StartsWith($pathFilter)) { continue }
            $noise = Test-Noise $full $rec.Name
            if ($noise -and -not $cfg.ShowAll) { $noiseHidden++; continue }
            $results.Add([pscustomobject]@{ When = $rec.When; Path = $full; Type = $(if ($rec.IsDir) { 'folder' } else { 'file' }); Noise = $noise; Drive = $L; Shadow = $null; Source = 'journal'; State = ''; Size = $null; Ex = $null; Times = 1; Note = ''; BinId = '' })
        }
        Write-Progress -Activity "Resolving paths on $($d.DeviceID)" -Completed

        if ($shadows.Count -gt 0) {
            Write-Host ('  ' + (C dim ('{0} shadow cop{1} in range — checking recoverability' -f $shadows.Count, $(if ($shadows.Count -eq 1) { 'y' } else { 'ies' }))))
            $mine = @($results | Where-Object { $_.Drive -eq $L -and $_.Source -eq 'journal' })
            $k = 0
            foreach ($r in $mine) { $k++; if (($k % 200) -eq 0) { Write-Progress -Activity 'Checking shadow copies' -PercentComplete ([int](100 * $k / $mine.Count)) }; $r.Shadow = Test-InShadow $r.Path $shadows $L }
            Write-Progress -Activity 'Checking shadow copies' -Completed
        } elseif (-not $cfg.NoShadowCheck) {
            Write-Host ('  ' + (C dim 'no Volume Shadow Copies in range on this drive — nothing here is recoverable that way. Turn on System Protection to have them next time.'))
        }
    }

    # dedupe: same path deleted repeatedly → one row with a count and the latest time
    $byPath = @{}
    foreach ($r in $results) {
        $k = $r.Path.ToLowerInvariant(); $g = $byPath[$k]
        if (-not $g) { $byPath[$k] = @{ Latest = $r; Count = [int]$r.Times } }
        else { $g.Count += [int]$r.Times; if ($r.When -gt $g.Latest.When) { $g.Latest = $r } }
    }
    $grouped = foreach ($g in $byPath.Values) {
        $latest = $g.Latest
        $exOk = ($latest.Source -eq 'exfat' -and $latest.State -like 'intact*' -and $latest.Type -eq 'file')
        [pscustomobject]@{ When = $latest.When; Path = $latest.Path; Type = $latest.Type; Times = $g.Count; Recoverable = ([bool]$latest.Shadow -or $exOk); ShadowDate = $(if ($latest.Shadow) { $latest.Shadow.Date } else { $null }); ShadowRoot = $(if ($latest.Shadow) { $latest.Shadow.Root } else { $null }); Drive = $latest.Drive; Source = $latest.Source; State = $latest.State; Size = $latest.Size; Ex = $latest.Ex; RecoveredTo = ''; Note = $latest.Note; BinId = $latest.BinId }
    }
    $grouped = @($grouped | Sort-Object When -Descending)

    # ── report ──
    $w = Get-Width
    Section 'DELETED' ("  {0:N0} items · {1:N0} noise hidden{2}" -f $grouped.Count, $noiseHidden, $(if ($noiseHidden -and -not $cfg.ShowAll) { ' (-ShowAll to include)' } else { '' }))
    if ($grouped.Count -eq 0) { Write-Host ('  ' + (C dim 'nothing in the window that survived the filters.')) }
    else {
        $recov = @($grouped | Where-Object { $_.Recoverable })
        Write-Host ('  ' + (C dim ('{0,-16} {1,-6} {2,-4} {3}' -f 'WHEN', 'TYPE', 'REC', 'PATH')))
        $shown = 0
        foreach ($r in $grouped) {
            $shown++
            if ($shown -gt 400) { Write-Host ('  ' + (C dim ($script:G.ell + ' {0:N0} more — use -ExportCsv to get them all' -f ($grouped.Count - 400)))); break }
            $rec = if ($r.Recoverable) { (C teal (' ' + $script:G.ok + '  ')) } else { (C faint ' -  ') }
            $tc = if ($r.Type -eq 'folder') { 'amber' } else { 'ink' }
            $times = if ($r.Times -gt 1) { (C dim (' ' + $script:G.times + $r.Times)) } else { '' }
            $st = if ($r.Source -eq 'exfat' -and $r.Type -eq 'file') { (C $(if ($r.State -like 'intact*') { 'teal' } elseif ($r.State -match 'partly') { 'amber' } else { 'faint' }) ('  ' + $r.State)) + (C faint (' · ' + (Format-Bytes $r.Size))) } else { '' }
            if ($r.Note) { $st += (C faint (' · ' + $r.Note)) }
            Write-Host ('  ' + (C dim $r.When.ToString('yyyy-MM-dd HH:mm')) + ' ' + (C $tc ('{0,-6}' -f $r.Type)) + $rec + (C ink (Truncate-Path $r.Path ($w - 34 - $(if ($st) { 24 } else { 0 })))) + $times + $st)
        }

        if ($recov.Count -gt 0) {
            $exRecov = @($recov | Where-Object { $_.Source -eq 'exfat' }); $shRecov = @($recov | Where-Object { $_.Source -ne 'exfat' })
            Section 'RECOVERABLE' ("  {0:N0} in a shadow copy · {1:N0} intact on exFAT" -f $shRecov.Count, $exRecov.Count)
            if ($exRecov.Count -gt 0) {
                if ($cfg.RecoverTo) {
                    $bad = @($exRecov | Where-Object { $cfg.RecoverTo.TrimStart('\').Substring(0, 1).ToUpper() -eq $_.Drive }).Count
                    if ($bad) { Write-Host ('  ' + (C rose $script:G.err) + ' ' + (C ink "Refusing to recover onto the same drive ($($cfg.RecoverTo)) - that would overwrite the very data being recovered. Choose a folder on another drive.")) }
                    else {
                        $done = 0; $bytes = 0L
                        foreach ($r in $exRecov) {
                            if ($cfg.RecoverMax -gt 0 -and $done -ge $cfg.RecoverMax) { Write-Host ('  ' + (C dim ("stopped at the cap of {0} files; -RecoverMax raises it, 0 removes it ({1:N0} recoverable in total)" -f $cfg.RecoverMax, $exRecov.Count))); break }
                            $dest = Join-Path $cfg.RecoverTo ($r.Drive + $r.Path.Substring(2))
                            if ($r.BinId) {
                                if ($r.Path -match '^[A-Za-z]:\\\$RECYCLE\.BIN\\\$R[A-Z0-9]{6}(.*)$') { $dest = Join-Path $cfg.RecoverTo ($r.Drive + '\Recycle Bin\$R' + $r.BinId + ' (deleted ' + $r.When.ToString('yyyy-MM-dd HH-mm') + ')' + $matches[1]) }
                                else { $dest = Join-Path $cfg.RecoverTo ($r.Drive + '\Recycle Bin' + $r.Path.Substring(2)) }
                            }
                            try { $n = $script:ExFatVols[$r.Drive].Recover($r.Ex, $dest); $done++; $bytes += $n; $r.RecoveredTo = $dest }
                            catch { Write-Host ('  ' + (C rose $script:G.err) + ' ' + (C dim ($r.Path + ': ' + $_.Exception.Message))) }
                        }
                        Write-Host ('  ' + (C teal $script:G.ok) + ' ' + (C ink ('{0:N0} file(s), {1} copied to {2}' -f $done, (Format-Bytes $bytes), $cfg.RecoverTo)) + (C dim '  — open a few to confirm they are whole; a file whose clusters were reused will look damaged.'))
                    }
                } else {
                    Write-Host ('  ' + (C dim ('exFAT files marked intact can be copied out with ' + $script:G.arrow + ' ')) + (C amber ("-RecoverTo 'C:\Recovered' -RecoverMax 0")) + (C dim ' (or answer the menu question). Nothing is written to the exFAT drive itself.'))
                    $binDrives = @($exRecov | Where-Object { $_.BinId } | ForEach-Object { $_.Drive } | Sort-Object -Unique)
                    foreach ($bd in $binDrives) { Write-Host ('  ' + (C dim ('only what was emptied from the Recycle Bin on ' + $bd + ': ' + $script:G.arrow + ' ')) + (C amber ("-Drive $bd -Path '$bd`:\`$RECYCLE.BIN' -RecoverTo 'C:\Recovered' -RecoverMax 0"))) }
                }
                $shown = 0
                foreach ($r in $exRecov) {
                    $shown++; if ($shown -gt 60) { Write-Host ('  ' + (C dim ($script:G.ell + ' {0:N0} more in the CSV' -f ($exRecov.Count - 60)))); break }
                    Write-Host ('  ' + (C teal $script:G.dot) + ' ' + (C ink (Truncate-Path $r.Path ($w - 44))) + (C dim ('  ' + (Format-Bytes $r.Size) + ' · ' + $r.State + ' · ' + $r.When.ToString('yyyy-MM-dd HH:mm') + $(if ($r.Note) { ' · ' + $r.Note } else { '' }))) + $(if ($r.RecoveredTo) { (C teal ('  ' + $script:G.arrow + ' ' + $r.RecoveredTo)) } else { '' }))
                }
            }
            if ($shRecov.Count -gt 0) { Write-Host ('  ' + (C dim 'Shadow-copy files: copy them back yourself — the script does not restore. Newest snapshot that still has the file is shown.')) }
            $shown = 0
            foreach ($r in $shRecov) {
                $shown++; if ($shown -gt 60) { Write-Host ('  ' + (C dim ($script:G.ell + ' {0:N0} more in the CSV' -f ($shRecov.Count - 60)))); break }
                $src = $r.ShadowRoot + $r.Path.Substring(3)
                Write-Host ('  ' + (C teal $script:G.dot) + ' ' + (C ink (Truncate-Path $r.Path ($w - 30))) + (C dim ('  snapshot ' + $r.ShadowDate.ToString('yyyy-MM-dd HH:mm'))))
                Write-Host ('    ' + (C dim ($script:G.arrow + ' ')) + (C amber ("Copy-Item -LiteralPath '$src' -Destination '$($r.Path)'" + $(if ($r.Type -eq 'folder') { ' -Recurse' } else { '' }))))
            }
        }
    }

    # ── other sources, for context ──
    Section 'OTHER SOURCES'
    try {
        $shell = New-Object -ComObject Shell.Application; $rb = $shell.NameSpace(0xA); $cnt = @($rb.Items()).Count
        Write-Host ('  ' + (C dim $script:G.dot) + ' ' + (C ink ("Recycle Bin currently holds {0:N0} item(s)" -f $cnt)) + (C dim ' — those are not permanently deleted; restore them from the bin.'))
    } catch {}
    try {
        $ev = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4660; StartTime = $since } -MaxEvents 1 -ErrorAction Stop
        Write-Host ('  ' + (C teal $script:G.dot) + ' ' + (C ink 'Security log has object-delete audit events (4660) in this window') + (C dim ' — auditing is on; Event Viewer can attribute deletions to a user and process.'))
    } catch {
        Write-Host ('  ' + (C dim $script:G.dot) + ' ' + (C dim 'No delete audit events (ID 4660) — file auditing is off, so nothing attributes a deletion to a user. That is the default.'))
    }
    Write-Host ('  ' + (C dim $script:G.dot) + ' ' + (C dim 'Anything older than the journal coverage above is only reachable with forensic tools that carve unallocated MFT entries.'))
    Write-Host ''

    if ($cfg.ExportCsv) {
        try {
            $grouped | Select-Object When, Type, Times, Recoverable, Source, State, Size, Note, RecoveredTo, ShadowDate, Path, @{ n = 'ShadowSource'; e = { if ($_.ShadowRoot) { $_.ShadowRoot + $_.Path.Substring(3) } else { '' } } } |
                Export-Csv -Path $cfg.ExportCsv -NoTypeInformation -Encoding UTF8
            Write-Host ('  ' + (C dim ('exported ' + $grouped.Count + ' rows to ' + $cfg.ExportCsv))); Write-Host ''
        } catch { Write-Warning "CSV export failed: $($_.Exception.Message)" }
    }
}
catch { Show-Failure $_; Wait-Close; Restore-Console; exit 1 }
finally { if ($script:ResolverOk) { foreach ($h in $volHandles.Values) { [FD.Res]::Close($h) } }; foreach ($xv in $script:ExFatVols.Values) { try { $xv.Dispose() } catch {} } }
Wait-Close
Restore-Console

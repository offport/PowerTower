// System engines: the process sampler, the storage scanner, and the deleted-files finder (USN journal,
// path resolver, shadow copies, the exFAT directory-table reader, Recycle Bin pairing, recovery).
// Ported from the scripts in the folders beside this one. Pure logic, no UI.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace PSTools
{
    public static class Fmt
    {
        public static string Bytes(double b)
        {
            if (b >= 1099511627776.0) return (b / 1099511627776.0).ToString("N2") + " TB";
            if (b >= 1073741824.0) return (b / 1073741824.0).ToString("N2") + " GB";
            if (b >= 1048576.0) return (b / 1048576.0).ToString("N1") + " MB";
            if (b >= 1024.0) return (b / 1024.0).ToString("N0") + " KB";
            return b.ToString("N0") + " B";
        }
        public static string Secs(double s) { if (s >= 3600) return (s / 3600).ToString("N1") + " h"; if (s >= 60) return (s / 60).ToString("N1") + " m"; return s.ToString("N1") + " s"; }
        public static string CsvQ(string s) { if (s == null) return ""; double num; if (s.Length > 0 && "=+-@\t\r".IndexOf(s[0]) >= 0 && !double.TryParse(s, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out num)) s = "'" + s; /* spreadsheet formula injection: =cmd, +x, -x, @SUM; real numbers (-5) stay as they are */ return (s.IndexOfAny(new char[] { ',', '"', '\n', '\r' }) >= 0) ? "\"" + s.Replace("\"", "\"\"") + "\"" : s; }
        /// <summary>A one-line sparkline of the last `width` values, in block characters.</summary>
        public static string Spark(List<double> h, int width)
        {
            if (h == null || h.Count == 0) return ""; string blocks = "▁▂▃▄▅▆▇█"; double max = 0; int start = Math.Max(0, h.Count - width);
            for (int i = start; i < h.Count; i++) if (h[i] > max) max = h[i];
            StringBuilder sb = new StringBuilder(); for (int i = start; i < h.Count; i++) { double v = h[i]; sb.Append(max <= 0 || v <= 0 ? '▁' : blocks[Math.Min(7, (int)Math.Floor(v / max * 7.999))]); }
            return sb.ToString();
        }
    }

    // ───────────────────────────── process sampler ─────────────────────────────
    public static class Win32
    {
        [StructLayout(LayoutKind.Sequential)] public struct IO_COUNTERS { public ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes; }
        [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetProcessIoCounters(IntPtr h, out IO_COUNTERS c);
        [DllImport("kernel32.dll", SetLastError = true)] public static extern bool CloseHandle(IntPtr h);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] public static extern IntPtr CreateFileW(string n, uint a, uint s, IntPtr sa, uint d, uint f, IntPtr t);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] public static extern uint GetFileAttributesW(string p);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] public static extern bool CopyFileW(string src, string dst, bool failIfExists);
        [StructLayout(LayoutKind.Explicit, Size = 24)] public struct FILE_ID_DESCRIPTOR { [FieldOffset(0)] public uint dwSize; [FieldOffset(4)] public int Type; [FieldOffset(8)] public long FileId; }
        [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr OpenFileById(IntPtr v, ref FILE_ID_DESCRIPTOR id, uint a, uint s, IntPtr sa, uint f);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] public static extern uint GetFinalPathNameByHandleW(IntPtr h, StringBuilder b, uint len, uint f);
        [StructLayout(LayoutKind.Sequential)] public struct MEMORYSTATUSEX { public uint Length, MemoryLoad; public ulong TotalPhys, AvailPhys, TotalPageFile, AvailPageFile, TotalVirtual, AvailVirtual, AvailExtendedVirtual; }
        [DllImport("kernel32.dll", SetLastError = true)] public static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX b);
        public static readonly IntPtr INVALID = new IntPtr(-1);
        public static bool TryIo(int pid, out ulong read, out ulong write)
        {
            read = 0; write = 0; IntPtr h = OpenProcess(0x1000, false, pid); if (h == IntPtr.Zero) return false;
            try { IO_COUNTERS c; if (!GetProcessIoCounters(h, out c)) return false; read = c.ReadBytes; write = c.WriteBytes; return true; } finally { CloseHandle(h); }
        }
        public static bool PathExists(string p) { return GetFileAttributesW(p) != 0xFFFFFFFF; }
    }

    public class ProcRow
    {
        public string Name; public int Pid; public bool Alive = true; public DateTime FirstSeen, LastSeen;
        public double CpuStart, CpuLast, CpuCum, CpuPct, MemCur, MemPeak, IoCumR, IoCumW, IoRate; public ulong IoStartR, IoStartW, IoLastR, IoLastW;
        public List<double> CpuHist = new List<double>(); public int Count = 1; public double Share;
        public string Key { get { return Pid + "|" + Name; } }
    }

    public class ProcSampler
    {
        public readonly Dictionary<string, ProcRow> Procs = new Dictionary<string, ProcRow>();
        public double SysCpu, RamUsed, RamTotal, SysIo; public List<double> SysCpuHist = new List<double>(), SysIoHist = new List<double>(); public DateTime StartedAt = DateTime.Now; public int Ticks;
        readonly int cores = Environment.ProcessorCount; DateTime last = DateTime.MinValue; const int HistLen = 60;
        static void Push(List<double> l, double v) { l.Add(v); if (l.Count > HistLen) l.RemoveAt(0); }
        public void Reset() { foreach (ProcRow p in Procs.Values) { p.CpuStart = p.CpuLast; p.CpuCum = 0; p.MemPeak = p.MemCur; p.IoStartR = p.IoLastR; p.IoStartW = p.IoLastW; p.IoCumR = 0; p.IoCumW = 0; p.CpuHist.Clear(); } SysCpuHist.Clear(); SysIoHist.Clear(); StartedAt = DateTime.Now; }
        public void Sample()
        {
            DateTime now = DateTime.Now; double elapsed = last == DateTime.MinValue ? 1.0 : (now - last).TotalSeconds; if (elapsed <= 0) elapsed = 1; last = now;
            HashSet<string> seen = new HashSet<string>(); double sysDelta = 0, sysIo = 0;
            foreach (Process pr in Process.GetProcesses())
            {
                try
                {
                    if (pr.Id == 0) continue;
                    string key = pr.Id + "|" + pr.ProcessName; seen.Add(key);
                    ProcRow st; bool isNew = !Procs.TryGetValue(key, out st);
                    if (isNew) { st = new ProcRow(); st.Name = pr.ProcessName; st.Pid = pr.Id; st.FirstSeen = now; Procs[key] = st; }
                    st.Alive = true; st.LastSeen = now;
                    double cpuNow = st.CpuLast; try { cpuNow = pr.TotalProcessorTime.TotalSeconds; } catch { }
                    if (isNew) { st.CpuStart = cpuNow; st.CpuLast = cpuNow; }
                    double d = cpuNow - st.CpuLast; if (d < 0) d = 0;
                    st.CpuPct = d / elapsed * 100.0 / cores; st.CpuLast = cpuNow; st.CpuCum = Math.Max(0, cpuNow - st.CpuStart); sysDelta += d;
                    double mem = 0; try { mem = pr.WorkingSet64; } catch { }
                    st.MemCur = mem; if (mem > st.MemPeak) st.MemPeak = mem;
                    ulong r, w;
                    if (Win32.TryIo(pr.Id, out r, out w))
                    {
                        if (isNew) { st.IoStartR = r; st.IoStartW = w; st.IoLastR = r; st.IoLastW = w; }
                        double dr = r >= st.IoLastR ? (double)(r - st.IoLastR) : 0, dw = w >= st.IoLastW ? (double)(w - st.IoLastW) : 0;
                        st.IoRate = (dr + dw) / elapsed; st.IoLastR = r; st.IoLastW = w; st.IoCumR = (double)(r - st.IoStartR); st.IoCumW = (double)(w - st.IoStartW); sysIo += st.IoRate;
                    }
                    else st.IoRate = 0;
                    Push(st.CpuHist, st.CpuPct);
                }
                catch { }
                finally { pr.Dispose(); }
            }
            List<string> drop = new List<string>();
            foreach (KeyValuePair<string, ProcRow> kv in Procs)
            {
                if (seen.Contains(kv.Key)) continue; ProcRow st = kv.Value;
                if (st.Alive) { st.Alive = false; st.CpuPct = 0; st.IoRate = 0; st.MemCur = 0; }
                if (st.CpuCum < 0.5 && st.IoCumR + st.IoCumW < 10 * 1048576.0) { drop.Add(kv.Key); continue; }
                Push(st.CpuHist, 0);
            }
            foreach (string k in drop) Procs.Remove(k);
            double total = 0; foreach (ProcRow p in Procs.Values) total += p.CpuCum; foreach (ProcRow p in Procs.Values) p.Share = total > 0 ? p.CpuCum / total : 0;
            SysCpu = Math.Min(100, sysDelta / elapsed * 100.0 / cores); Push(SysCpuHist, SysCpu);
            Win32.MEMORYSTATUSEX m = new Win32.MEMORYSTATUSEX(); m.Length = (uint)Marshal.SizeOf(typeof(Win32.MEMORYSTATUSEX)); if (Win32.GlobalMemoryStatusEx(ref m)) { RamTotal = m.TotalPhys; RamUsed = m.TotalPhys - m.AvailPhys; }
            SysIo = sysIo; Push(SysIoHist, sysIo / 1048576.0); Ticks++;
        }
        /// <summary>Rows grouped by process name (chrome ×38 = one row); histories summed.</summary>
        public List<ProcRow> Grouped()
        {
            Dictionary<string, ProcRow> g = new Dictionary<string, ProcRow>();
            foreach (ProcRow p in Procs.Values)
            {
                ProcRow r; if (!g.TryGetValue(p.Name, out r)) { r = new ProcRow(); r.Name = p.Name; r.Pid = 0; r.Alive = false; r.Count = 0; r.CpuHist = new List<double>(); g[p.Name] = r; }
                r.CpuCum += p.CpuCum; r.CpuPct += p.CpuPct; r.MemCur += p.MemCur; r.MemPeak += p.MemPeak; r.IoCumR += p.IoCumR; r.IoCumW += p.IoCumW; r.IoRate += p.IoRate; r.Share += p.Share;
                if (p.Alive) { r.Alive = true; r.Count++; }
                for (int i = 0; i < p.CpuHist.Count; i++) { int idx = r.CpuHist.Count - p.CpuHist.Count + i; if (idx < 0) { r.CpuHist.Insert(0, p.CpuHist[i]); } else r.CpuHist[idx] += p.CpuHist[i]; }
            }
            return new List<ProcRow>(g.Values);
        }
    }

    // ───────────────────────────── storage scanner ─────────────────────────────
    public class Node
    {
        public string Name, Path; public bool IsDir; public long Size; public int Files, Dirs; public DateTime Modified; public Node Parent; public List<Node> Children; public string Error;
        public int Depth { get { int d = 0; Node n = Parent; while (n != null) { d++; n = n.Parent; } return d; } }
        public double ShareOfParent { get { return Parent != null && Parent.Size > 0 ? (double)Size / Parent.Size : 1; } }
        public string Ext { get { if (IsDir) return ""; string e = System.IO.Path.GetExtension(Name); return e.Length > 1 ? e.Substring(1).ToLowerInvariant() : "(none)"; } }
    }
    public class ExtStat { public string Ext; public long Bytes; public int Count; }

    public class Storage
    {
        public Node Root; public long TotalBytes; public int TotalFiles, TotalDirs, Denied; public List<Node> LargestFiles = new List<Node>(); public List<Node> AllDirs = new List<Node>(); public Dictionary<string, ExtStat> ByExt = new Dictionary<string, ExtStat>();
        public int KeepFiles = 2000; public long MinFileBytes = 0; public volatile bool Cancel; public Stopwatch Clock = new Stopwatch();
        long smallestKept = 0;
        public Node Scan(string root)
        {
            Cancel = false; Clock.Restart(); TotalBytes = 0; TotalFiles = 0; TotalDirs = 0; Denied = 0; LargestFiles.Clear(); AllDirs.Clear(); ByExt.Clear(); smallestKept = 0;
            Root = new Node(); Root.Name = root; Root.Path = root; Root.IsDir = true; Root.Children = new List<Node>();
            Walk(Root); Clock.Stop(); LargestFiles.Sort(delegate (Node a, Node b) { return b.Size.CompareTo(a.Size); });
            AllDirs.Sort(delegate (Node a, Node b) { return b.Size.CompareTo(a.Size); });
            return Root;
        }
        void Walk(Node dir)
        {
            if (Cancel) return;
            IEnumerable<FileSystemInfo> items;
            try { items = new DirectoryInfo(dir.Path).EnumerateFileSystemInfos(); } catch (Exception ex) { dir.Error = ex.GetType().Name; Denied++; return; }
            try
            {
                foreach (FileSystemInfo fi in items)
                {
                    if (Cancel) return;
                    try
                    {
                        if ((fi.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                        if ((fi.Attributes & FileAttributes.Directory) != 0)
                        {
                            Node n = new Node(); n.Name = fi.Name; n.Path = fi.FullName; n.IsDir = true; n.Parent = dir; n.Children = new List<Node>(); n.Modified = fi.LastWriteTime;
                            dir.Children.Add(n); TotalDirs++; Walk(n); dir.Size += n.Size; dir.Files += n.Files; dir.Dirs += n.Dirs + 1;
                        }
                        else
                        {
                            long len = ((FileInfo)fi).Length; TotalBytes += len; TotalFiles++; dir.Size += len; dir.Files++;
                            string ext = fi.Extension.Length > 1 ? fi.Extension.Substring(1).ToLowerInvariant() : "(none)";
                            ExtStat es; if (!ByExt.TryGetValue(ext, out es)) { es = new ExtStat(); es.Ext = ext; ByExt[ext] = es; } es.Bytes += len; es.Count++;
                            if (len >= MinFileBytes && (LargestFiles.Count < KeepFiles || len > smallestKept))
                            {
                                Node f = new Node(); f.Name = fi.Name; f.Path = fi.FullName; f.Size = len; f.Parent = dir; f.Modified = fi.LastWriteTime;
                                LargestFiles.Add(f);
                                if (LargestFiles.Count > KeepFiles * 2) { LargestFiles.Sort(delegate (Node a, Node b) { return b.Size.CompareTo(a.Size); }); LargestFiles.RemoveRange(KeepFiles, LargestFiles.Count - KeepFiles); smallestKept = LargestFiles[LargestFiles.Count - 1].Size; }
                            }
                        }
                    }
                    catch { Denied++; }
                }
            }
            catch { dir.Error = "partial"; Denied++; }
            dir.Children.Sort(delegate (Node a, Node b) { return b.Size.CompareTo(a.Size); });
            AllDirs.Add(dir);
        }
    }

    // ───────────────────────────── deleted files ─────────────────────────────
    public class DriveInfoRow { public string Letter, Fs, Label, Kind; public long Size, Free; public bool Journalable { get { return Fs == "NTFS" || Fs == "ReFS"; } } public bool ExFat { get { return Fs == "exFAT"; } } public string Why { get { return string.IsNullOrEmpty(Fs) ? "no media" : Journalable ? "change journal" : ExFat ? "directory scan (no deletion time)" : Fs + " keeps no change journal"; } } }

    public class DeletedRow
    {
        public DateTime When; public string Type, Path, Source, State = "", Note = "", Drive, ShadowSource = "", RecoveredTo = ""; public long Size; public int Times = 1; public bool Recoverable, Noise; public XEntry Ex; public string BinId = "";
        public string Folder { get { int i = Path.LastIndexOf('\\'); return i > 0 ? Path.Substring(0, i) : Path; } }
        public string Name { get { int i = Path.LastIndexOf('\\'); return i >= 0 ? Path.Substring(i + 1) : Path; } }
    }
    public class BinItem { public string Id, Name; public DateTime? When; public bool IsDir, Named; public int Files, Intact, Empty; public long Bytes; public DateTime TopModified; }
    public class JournalInfo { public bool Active; public string Error = ""; public long Records; public DateTime Oldest = DateTime.MaxValue; public double CoverageDays; public List<DeletedRec> Deleted = new List<DeletedRec>(); public Dictionary<long, DirRec> Dirs = new Dictionary<long, DirRec>(); }
    public class DeletedRec { public string Name; public DateTime When; public bool IsDir; public long Frn, Parent; }
    public class DirRec { public string Name; public long Parent; }
    public class Shadow { public string Id, Device, Root; public DateTime Date; }

    public static class Noise
    {
        static readonly Regex PathRe = new Regex(@"\\AppData\\Local\\Temp\\|\\Windows\\Temp\\|\\Temp\\|\\tmp\\|\\Cache\\|\\Cache2\\|\\Code Cache\\|\\GPUCache\\|\\AppData\\Local\\Microsoft\\Windows\\INetCache\\|\\AppData\\Local\\Packages\\|\\node_modules\\|\\\.git\\|\\__pycache__\\|\\Windows\\Prefetch\\|\\Windows\\SoftwareDistribution\\|\\ProgramData\\Microsoft\\Windows Defender\\|\\WinSxS\\|\\Windows\\Logs\\|\\\$Recycle\.Bin\\|\\System Volume Information\\|\\AppData\\Local\\CrashDumps\\|\\Windows\\ServiceProfiles\\|\\\$Extend\\|\\MSI[0-9a-f]{4,6}\.tmp\\", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        static readonly Regex NameRe = new Regex(@"^(~\$|~WRL|\.~lock)|\.(tmp|temp|log|etl|dmp|part|crdownload|partial|bak~|swp|lock|ldb|journal|db-shm|db-wal|db-journal|vscdb-journal|writable)$|^thumbs\.db$|^desktop\.ini$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        public static bool Is(string fullPath, string name) { return PathRe.IsMatch(fullPath) || NameRe.IsMatch(name); }
    }

    public static class Drives
    {
        public static List<DriveInfoRow> List()
        {
            List<DriveInfoRow> l = new List<DriveInfoRow>();
            try
            {
                foreach (ManagementObject d in new ManagementObjectSearcher("SELECT DeviceID, DriveType, FileSystem, VolumeName, Size, FreeSpace FROM Win32_LogicalDisk WHERE DriveType=2 OR DriveType=3").Get())
                {
                    DriveInfoRow r = new DriveInfoRow(); r.Letter = ((string)d["DeviceID"]).TrimEnd(':'); r.Fs = d["FileSystem"] as string ?? ""; r.Label = d["VolumeName"] as string ?? ""; uint t = Convert.ToUInt32(d["DriveType"]); r.Kind = t == 2 ? "removable" : "fixed";
                    r.Size = d["Size"] == null ? 0 : (long)Convert.ToUInt64(d["Size"]); r.Free = d["FreeSpace"] == null ? 0 : (long)Convert.ToUInt64(d["FreeSpace"]); l.Add(r);
                }
            }
            catch { foreach (DriveInfo di in DriveInfo.GetDrives()) { if (di.DriveType != DriveType.Fixed && di.DriveType != DriveType.Removable) continue; DriveInfoRow r = new DriveInfoRow(); r.Letter = di.Name.Substring(0, 1); try { r.Fs = di.DriveFormat; r.Label = di.VolumeLabel; r.Size = di.TotalSize; r.Free = di.AvailableFreeSpace; } catch { r.Fs = ""; } r.Kind = di.DriveType == DriveType.Removable ? "removable" : "fixed"; l.Add(r); } }
            l.Sort(delegate (DriveInfoRow a, DriveInfoRow b) { return string.CompareOrdinal(a.Letter, b.Letter); });
            return l;
        }
    }

    /// <summary>The NTFS change journal via fsutil (needs administrator), both csv layouts.</summary>
    public static class Journal
    {
        static long ParseId(string hex) { string h = hex.Trim(); if (h.StartsWith("0x")) h = h.Substring(2); if (h.Length > 16) h = h.Substring(h.Length - 16); try { return Convert.ToInt64(h, 16); } catch { return 0; } }
        static readonly string[] TimeFormats = { "M/d/yyyy H:mm:ss", "M/d/yyyy h:mm:ss tt", "yyyy-MM-dd HH:mm:ss", "yyyy-MM-dd HH:mm:ss.ffff" };
        public static DateTime ParseTime(string s)
        {
            string t = s.Trim().Trim('"'); DateTime d;
            if (DateTime.TryParseExact(t, TimeFormats, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out d)) return d;
            if (DateTime.TryParse(t, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out d)) return d;
            if (DateTime.TryParse(t, out d)) return d;
            return DateTime.MinValue;
        }
        static string Unquote(string s) { string t = s.Trim(); if (t.Length >= 2 && t[0] == '"' && t[t.Length - 1] == '"') t = t.Substring(1, t.Length - 2); return t.Replace("\"\"", "\""); }
        /// <summary>One csv record line → a record (null for preamble / unparsable lines).</summary>
        public static bool ParseLine(string line, out string name, out DateTime when, out bool isDir, out long frn, out long parent, out bool isDelete)
        {
            name = null; when = DateTime.MinValue; isDir = false; frn = 0; parent = 0; isDelete = false;
            if (line.Length < 20 || !char.IsDigit(line[0])) return false;
            string[] f = line.Split(','); int n = f.Length; if (n < 13) return false;
            string reason, reasonText, ts, attr, fid, pidRaw;
            if (n >= 16 && f[1].StartsWith("\""))
            {
                name = Unquote(string.Join(",", f, 1, n - 15)); reason = f[n - 13]; reasonText = Unquote(f[n - 12]); ts = f[n - 11]; attr = f[n - 10]; fid = f[n - 8]; pidRaw = f[n - 7];
            }
            else { name = string.Join(",", f, 1, n - 12).Trim(); reasonText = ""; reason = f[n - 10]; ts = f[n - 9]; attr = f[n - 8]; fid = f[n - 7]; pidRaw = f[n - 6]; }
            when = ParseTime(ts);
            long attrVal = 0; try { attrVal = Convert.ToInt64(attr.Trim().Replace("0x", ""), 16); } catch { }
            isDir = (attrVal & 0x10) != 0; frn = ParseId(fid); parent = ParseId(pidRaw);
            Match m = Regex.Match(reason, "0x([0-9a-fA-F]+)"); if (m.Success) { try { isDelete = (Convert.ToInt64(m.Groups[1].Value, 16) & 0x200) != 0; } catch { } }
            if (!isDelete && (reason.IndexOf("File delete", StringComparison.OrdinalIgnoreCase) >= 0 || reasonText.IndexOf("File delete", StringComparison.OrdinalIgnoreCase) >= 0)) isDelete = true;
            return true;
        }
        public static JournalInfo Read(string letter, DateTime since, Action<long> progress, Func<bool> cancelled)
        {
            JournalInfo j = new JournalInfo();
            string q = RunFsutil("usn queryjournal " + letter + ":");
            if (q == null || Regex.IsMatch(q, "not active|no USN|Error", RegexOptions.IgnoreCase)) { j.Error = (q ?? "fsutil failed").Trim(); return j; }
            j.Active = true;
            ProcessStartInfo si = new ProcessStartInfo("fsutil.exe", "usn readjournal " + letter + ": csv"); si.UseShellExecute = false; si.CreateNoWindow = true; si.RedirectStandardOutput = true; si.RedirectStandardError = true;
            using (Process p = Process.Start(si))
            {
                string line;
                while ((line = p.StandardOutput.ReadLine()) != null)
                {
                    if (cancelled != null && cancelled()) { try { p.Kill(); } catch { } break; }
                    string name; DateTime when; bool isDir, isDel; long frn, parent;
                    if (!ParseLine(line, out name, out when, out isDir, out frn, out parent, out isDel)) continue;
                    j.Records++; if (progress != null && j.Records % 20000 == 0) progress(j.Records);
                    if (when != DateTime.MinValue && when < j.Oldest) j.Oldest = when;
                    if (isDir && frn != 0) { DirRec dr = new DirRec(); dr.Name = name; dr.Parent = parent; j.Dirs[frn] = dr; }
                    if (!isDel || when < since) continue;
                    DeletedRec r = new DeletedRec(); r.Name = name; r.When = when; r.IsDir = isDir; r.Frn = frn; r.Parent = parent; j.Deleted.Add(r);
                }
                p.WaitForExit();
            }
            j.CoverageDays = j.Oldest == DateTime.MaxValue ? 0 : (DateTime.Now - j.Oldest).TotalDays;
            return j;
        }
        static string RunFsutil(string args)
        {
            try { ProcessStartInfo si = new ProcessStartInfo("fsutil.exe", args); si.UseShellExecute = false; si.CreateNoWindow = true; si.RedirectStandardOutput = true; si.RedirectStandardError = true; using (Process p = Process.Start(si)) { string o = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd(); p.WaitForExit(); return p.ExitCode == 0 ? o : "Error: " + o; } }
            catch (Exception ex) { return "Error: " + ex.Message; }
        }
    }

    /// <summary>File-reference → current path for parents that still exist; journal chain for the rest.</summary>
    public class Resolver : IDisposable
    {
        IntPtr vol = IntPtr.Zero; readonly string letter; readonly Dictionary<long, DirRec> dirs; readonly Dictionary<long, string> cache = new Dictionary<long, string>();
        public Resolver(string letter, Dictionary<long, DirRec> dirs) { this.letter = letter; this.dirs = dirs; try { vol = Win32.CreateFileW(@"\\.\" + letter + ":", 0, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero); if (vol == Win32.INVALID) vol = IntPtr.Zero; } catch { vol = IntPtr.Zero; } }
        public void Dispose() { if (vol != IntPtr.Zero) { Win32.CloseHandle(vol); vol = IntPtr.Zero; } }
        string ById(long id)
        {
            if (vol == IntPtr.Zero) return null;
            Win32.FILE_ID_DESCRIPTOR d = new Win32.FILE_ID_DESCRIPTOR(); d.dwSize = 24; d.Type = 0; d.FileId = id;
            IntPtr h = Win32.OpenFileById(vol, ref d, 0, 7, IntPtr.Zero, 0x02000000); if (h == Win32.INVALID || h == IntPtr.Zero) return null;
            try { StringBuilder sb = new StringBuilder(2048); uint n = Win32.GetFinalPathNameByHandleW(h, sb, 2048, 0); if (n == 0) return null; string s = sb.ToString(); if (s.StartsWith(@"\\?\")) s = s.Substring(4); return s; } finally { Win32.CloseHandle(h); }
        }
        public string Path(long frn, int depth)
        {
            if (frn == 0 || depth > 64) return null;
            string p; if (cache.TryGetValue(frn, out p)) return p;
            p = ById(frn);
            DirRec d;
            if (p == null && dirs.TryGetValue(frn, out d)) { string pp = Path(d.Parent, depth + 1); p = pp != null ? System.IO.Path.Combine(pp, d.Name) : letter + @":\<deleted>\" + d.Name; }
            cache[frn] = p; return p;
        }
    }

    public static class Shadows
    {
        public static List<Shadow> For(string letter)
        {
            List<Shadow> l = new List<Shadow>();
            try
            {
                List<string> ids = new List<string>();
                foreach (ManagementObject v in new ManagementObjectSearcher("SELECT DeviceID, DriveLetter FROM Win32_Volume").Get()) { if ((v["DriveLetter"] as string) == letter + ":") ids.Add((string)v["DeviceID"]); }
                foreach (ManagementObject s in new ManagementObjectSearcher("SELECT ID, InstallDate, DeviceObject, VolumeName FROM Win32_ShadowCopy").Get())
                {
                    if (!ids.Contains((string)s["VolumeName"])) continue;
                    Shadow sh = new Shadow(); sh.Id = (string)s["ID"]; sh.Device = (string)s["DeviceObject"]; sh.Root = sh.Device + "\\"; sh.Date = ManagementDateTimeConverter.ToDateTime((string)s["InstallDate"]); l.Add(sh);
                }
            }
            catch { }
            l.Sort(delegate (Shadow a, Shadow b) { return b.Date.CompareTo(a.Date); });
            return l;
        }
        public static Shadow Holding(string fullPath, List<Shadow> shadows)
        {
            if (shadows == null || fullPath.Length < 3) return null; string rel = fullPath.Substring(3);
            foreach (Shadow s in shadows) { if (Win32.PathExists(s.Root + rel)) return s; }
            return null;
        }
    }

    // ───────────────────────────── exFAT directory tables ─────────────────────────────
    public class XEntry
    {
        public string Path, Name; public bool IsDir, Contiguous, ParentDeleted; public long Size, ValidSize; public uint FirstCluster; public DateTime Modified, Created; public string State; public int Depth, Times = 1;
    }
    public class ExFat : IDisposable
    {
        FileStream fs; public int SectorSize, ClusterSize; public uint FatOffset, FatLength, HeapOffset, ClusterCount, RootCluster;
        byte[] bitmap; public bool BitmapOk; public int DirsScanned, EntriesSeen, Skipped, MaxDirs = 250000, MaxDeletedDepth = 12, MaxKeep = 1000000, OutsidePrefix, Dropped, Duplicates, IntactCount; public long IntactBytes, ClustersRead;
        public string PathPrefix; public List<XEntry> Deleted = new List<XEntry>(); readonly Dictionary<string, XEntry> byPath = new Dictionary<string, XEntry>(StringComparer.OrdinalIgnoreCase);
        public bool Done; public string ScanError; readonly HashSet<uint> onPath = new HashSet<uint>(); readonly Dictionary<long, byte[]> secCache = new Dictionary<long, byte[]>(); public volatile bool Cancel;
        public static ExFat Open(string letter)
        {
            ExFat x = new ExFat();
            // FileStream refuses "\\.\D:" by name; open the device with CreateFile and hand the handle over
            IntPtr h = Win32.CreateFileW(@"\\.\" + letter + ":", 0x80000000, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
            if (h == Win32.INVALID || h == IntPtr.Zero) throw new IOException("cannot open volume " + letter + ": (error " + Marshal.GetLastWin32Error() + ")");
            x.fs = new FileStream(new Microsoft.Win32.SafeHandles.SafeFileHandle(h, true), FileAccess.Read, 4096, false);
            byte[] b = new byte[4096]; x.fs.Seek(0, SeekOrigin.Begin); int n = x.fs.Read(b, 0, 4096);
            if (n < 512 || Encoding.ASCII.GetString(b, 3, 8) != "EXFAT   ") { x.fs.Dispose(); throw new InvalidDataException("not an exFAT volume"); }
            x.SectorSize = 1 << b[108]; x.ClusterSize = 1 << (b[108] + b[109]);
            x.FatOffset = BitConverter.ToUInt32(b, 80); x.FatLength = BitConverter.ToUInt32(b, 84); x.HeapOffset = BitConverter.ToUInt32(b, 88); x.ClusterCount = BitConverter.ToUInt32(b, 92); x.RootCluster = BitConverter.ToUInt32(b, 96);
            if (x.SectorSize < 512 || x.ClusterSize < 512 || x.ClusterSize > (32 << 20)) { x.fs.Dispose(); throw new InvalidDataException("implausible exFAT geometry"); }
            return x;
        }
        public void Dispose() { if (fs != null) { fs.Dispose(); fs = null; } }
        long ClusterOffset(uint c) { return (long)HeapOffset * SectorSize + (long)(c - 2) * ClusterSize; }
        public bool ValidCluster(uint c) { return c >= 2 && c < ClusterCount + 2; }
        byte[] ReadCluster(uint c) { byte[] b = new byte[ClusterSize]; fs.Seek(ClusterOffset(c), SeekOrigin.Begin); int got = 0; while (got < ClusterSize) { int r = fs.Read(b, got, ClusterSize - got); if (r <= 0) break; got += r; } return b; }
        byte[] ReadSector(long sector) { byte[] b; if (secCache.TryGetValue(sector, out b)) return b; b = new byte[SectorSize]; fs.Seek(sector * SectorSize, SeekOrigin.Begin); int got = 0; while (got < SectorSize) { int r = fs.Read(b, got, SectorSize - got); if (r <= 0) break; got += r; } if (secCache.Count > 16384) secCache.Clear(); secCache[sector] = b; return b; }
        public uint FatNext(uint c) { long off = (long)FatOffset * SectorSize + (long)c * 4; byte[] sec = ReadSector(off / SectorSize); return BitConverter.ToUInt32(sec, (int)(off % SectorSize)); }
        public List<uint> Chain(uint first, long dataLen, bool contiguous, int cap)
        {
            List<uint> list = new List<uint>(); if (!ValidCluster(first)) return list;
            long need = dataLen < 0 ? cap : (dataLen == 0 ? 1 : (dataLen + ClusterSize - 1) / ClusterSize); if (need > cap) need = cap;
            if (contiguous) { for (long i = 0; i < need; i++) { uint c = (uint)(first + i); if (!ValidCluster(c)) break; list.Add(c); } return list; }
            uint cur = first; while (ValidCluster(cur) && list.Count < need) { list.Add(cur); uint nx = FatNext(cur); if (nx >= 0xFFFFFFF8 || nx == 0 || nx == cur) break; cur = nx; }
            return list;
        }
        public bool ChainIntact(uint first, long dataLen) { long need = (dataLen + ClusterSize - 1) / ClusterSize; if (need <= 0) return true; uint cur = first; long n = 0; while (ValidCluster(cur)) { n++; if (n >= need) return true; uint nx = FatNext(cur); if (nx >= 0xFFFFFFF8 || nx == 0 || nx == cur) return false; cur = nx; } return false; }
        public bool IsFree(uint c) { if (!BitmapOk || !ValidCluster(c)) return false; long bit = c - 2; long idx = bit / 8; if (idx >= bitmap.Length) return false; return (bitmap[idx] & (1 << (int)(bit % 8))) == 0; }
        static DateTime Ts(uint t) { int year = 1980 + (int)((t >> 25) & 0x7F), month = (int)((t >> 21) & 0x0F), day = (int)((t >> 16) & 0x1F), hour = (int)((t >> 11) & 0x1F), min = (int)((t >> 5) & 0x3F), sec = (int)(t & 0x1F) * 2; try { return new DateTime(year, month == 0 ? 1 : month, day == 0 ? 1 : day, hour > 23 ? 0 : hour, min > 59 ? 0 : min, sec > 59 ? 0 : sec); } catch { return DateTime.MinValue; } }
        public void Scan()
        {
            List<uint> root = Chain(RootCluster, -1, false, 1 << 16);
            foreach (uint c in root)
            {
                byte[] blk = ReadCluster(c); bool found = false;
                for (int o = 0; o + 32 <= blk.Length; o += 32)
                {
                    byte t = blk[o]; if (t == 0) break; if (t != 0x81) continue;
                    uint first = BitConverter.ToUInt32(blk, o + 20); long len = BitConverter.ToInt64(blk, o + 24);
                    if (len > 0 && len < (256L << 20) && ValidCluster(first)) { bitmap = new byte[len]; long done = 0; foreach (uint bc in Chain(first, len, false, 1 << 20)) { byte[] bb = ReadCluster(bc); int n = (int)Math.Min((long)ClusterSize, len - done); Buffer.BlockCopy(bb, 0, bitmap, (int)done, n); done += n; if (done >= len) break; } BitmapOk = done >= len; }
                    found = true; break;
                }
                if (found) break;
            }
            WalkDir("", root, false, 0);
            Deleted = new List<XEntry>(byPath.Values);
            Deleted.Sort(delegate (XEntry a, XEntry b) { return b.Modified.CompareTo(a.Modified); });
            foreach (XEntry e in Deleted) if (!e.IsDir && e.State.StartsWith("intact")) { IntactCount++; IntactBytes += e.Size; }
        }
        public void ScanInBackground() { Thread t = new Thread(delegate () { try { Scan(); } catch (Exception e) { ScanError = e.Message; } finally { Done = true; } }); t.IsBackground = true; t.Start(); }
        void Keep(XEntry x) { XEntry old; if (byPath.TryGetValue(x.Path, out old)) { old.Times++; Duplicates++; if (x.Modified > old.Modified) { x.Times = old.Times; byPath[x.Path] = x; } return; } if (byPath.Count >= MaxKeep) { Dropped++; return; } byPath[x.Path] = x; }
        bool UnderPrefix(string full) { return PathPrefix == null || full.StartsWith(PathPrefix, StringComparison.OrdinalIgnoreCase); }
        bool MayContainPrefix(string full) { return PathPrefix == null || UnderPrefix(full) || PathPrefix.StartsWith(full + "\\", StringComparison.OrdinalIgnoreCase); }
        string Assess(XEntry x)
        {
            if (x.IsDir) return "folder"; if (x.Size <= 0) return "empty"; if (!ValidCluster(x.FirstCluster) || !BitmapOk) return "unknown";
            long need = (x.Size + ClusterSize - 1) / ClusterSize;
            if (x.Contiguous) { long free = 0, seen = 0; for (long i = 0; i < need; i++) { uint c = (uint)(x.FirstCluster + i); if (!ValidCluster(c)) break; seen++; if (IsFree(c)) free++; } if (seen < need) return "unknown"; if (free == need) return "intact"; return free == 0 ? "overwritten" : "partly overwritten"; }
            if (ChainIntact(x.FirstCluster, x.Size)) { List<uint> ch = Chain(x.FirstCluster, x.Size, false, 1 << 20); long free = 0; foreach (uint c in ch) if (IsFree(c)) free++; if (free == ch.Count) return "intact (fragmented)"; return free == 0 ? "overwritten" : "partly overwritten"; }
            return "chain lost";
        }
        void WalkDir(string path, List<uint> clusters, bool parentDeleted, int depth)
        {
            if (Cancel || DirsScanned >= MaxDirs) { Skipped++; return; }
            DirsScanned++;
            List<byte[]> entries = new List<byte[]>(); bool end = false; List<uint> mine = new List<uint>();
            foreach (uint c in clusters) { if (onPath.Contains(c)) break; onPath.Add(c); mine.Add(c); ClustersRead++; byte[] blk = ReadCluster(c); for (int o = 0; o + 32 <= blk.Length; o += 32) { if (blk[o] == 0) { end = true; break; } byte[] e = new byte[32]; Buffer.BlockCopy(blk, o, e, 0, 32); entries.Add(e); } if (end) break; }
            try
            {
                EntriesSeen += entries.Count; List<object[]> subdirs = new List<object[]>();
                for (int i = 0; i < entries.Count; i++)
                {
                    byte t = entries[i][0]; if ((t & 0x7F) != 0x05) continue;
                    bool deleted = (t & 0x80) == 0; byte[] f = entries[i]; int sec = f[1]; if (sec < 2 || sec > 18 || i + sec >= entries.Count) continue;
                    byte[] st = entries[i + 1]; if ((st[0] & 0x7F) != 0x40 || (((st[0] & 0x80) == 0) != deleted)) continue;
                    int nameLen = st[3]; if (nameLen < 1 || nameLen > 255) continue;
                    StringBuilder sb = new StringBuilder(); for (int k = 2; k <= sec; k++) { byte[] ne = entries[i + k]; if ((ne[0] & 0x7F) != 0x41) break; sb.Append(Encoding.Unicode.GetString(ne, 2, 30)); }
                    string name = sb.Length >= nameLen ? sb.ToString(0, nameLen) : sb.ToString();
                    if (name.Length == 0 || name.IndexOf('\0') >= 0 || name == "." || name == "..") continue;
                    ushort attr = BitConverter.ToUInt16(f, 4); bool isDir = (attr & 0x10) != 0; bool contiguous = (st[1] & 0x02) != 0; long validLen = BitConverter.ToInt64(st, 8); uint first = BitConverter.ToUInt32(st, 20); long len = BitConverter.ToInt64(st, 24);
                    string full = path + "\\" + name; DateTime modified = Ts(BitConverter.ToUInt32(f, 12));
                    if (deleted)
                    {
                        if (!UnderPrefix(full)) OutsidePrefix++;
                        else { XEntry x = new XEntry(); x.Path = full; x.Name = name; x.IsDir = isDir; x.Size = len; x.ValidSize = validLen; x.FirstCluster = first; x.Contiguous = contiguous; x.Modified = modified; x.Created = Ts(BitConverter.ToUInt32(f, 8)); x.ParentDeleted = parentDeleted; x.Depth = depth; x.State = Assess(x); Keep(x); }
                        if (isDir && depth < MaxDeletedDepth && ValidCluster(first) && len > 0 && len < (64L << 20) && MayContainPrefix(full)) subdirs.Add(new object[] { full, first, len, contiguous, true });
                    }
                    else if (isDir && ValidCluster(first) && MayContainPrefix(full)) subdirs.Add(new object[] { full, first, len, contiguous, false });
                    i += sec;
                }
                foreach (object[] sd in subdirs)
                {
                    string sp = (string)sd[0]; uint first = (uint)sd[1]; long len = (long)sd[2]; bool contiguous = (bool)sd[3]; bool del = (bool)sd[4];
                    List<uint> ch = del ? (contiguous ? Chain(first, len, true, 4096) : (ChainIntact(first, len) ? Chain(first, len, false, 4096) : Chain(first, ClusterSize, true, 1))) : Chain(first, len, contiguous, 1 << 20);
                    WalkDir(sp, ch, parentDeleted || del, depth + 1);
                }
            }
            finally { foreach (uint c in mine) onPath.Remove(c); }
        }
        public byte[] ReadHead(XEntry x, int max)
        {
            long want = Math.Min((long)max, x.Size); if (want <= 0 || !ValidCluster(x.FirstCluster)) return new byte[0];
            List<uint> ch = Chain(x.FirstCluster, want, x.Contiguous, 64); byte[] outb = new byte[want]; long done = 0;
            foreach (uint c in ch) { if (done >= want) break; byte[] blk = ReadCluster(c); int n = (int)Math.Min((long)ClusterSize, want - done); Buffer.BlockCopy(blk, 0, outb, (int)done, n); done += n; }
            return outb;
        }
        public long Recover(XEntry x, string dest)
        {
            if (x.IsDir) throw new InvalidOperationException("that is a folder");
            List<uint> ch = Chain(x.FirstCluster, x.Size, x.Contiguous, 1 << 22); long remaining = x.Size, written = 0;
            string dir = System.IO.Path.GetDirectoryName(dest); if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            using (FileStream o = new FileStream(dest, FileMode.Create, FileAccess.Write, FileShare.None)) { foreach (uint c in ch) { if (remaining <= 0) break; byte[] b = ReadCluster(c); int n = (int)Math.Min((long)ClusterSize, remaining); o.Write(b, 0, n); remaining -= n; written += n; } }
            return written;
        }
        /// <summary>The Recycle Bin's $I record: original path and deletion time. Null path when its data is gone.</summary>
        public static bool ParseBinRecord(byte[] b, out string path, out DateTime when)
        {
            path = null; when = DateTime.MinValue;
            try
            {
                if (b.Length < 28) return false; long ver = BitConverter.ToInt64(b, 0); if (ver < 1 || ver > 2) return false;
                when = DateTime.FromFileTime(BitConverter.ToInt64(b, 16)); if (when.Year < 2000 || when > DateTime.Now.AddDays(1)) return false;
                string orig;
                if (ver == 2) { int n = BitConverter.ToInt32(b, 24); if (n < 2 || 28 + n * 2 > b.Length) return false; orig = Encoding.Unicode.GetString(b, 28, (n - 1) * 2); }
                else { orig = Encoding.Unicode.GetString(b, 24, Math.Min(520, b.Length - 24)); int z = orig.IndexOf('\0'); if (z >= 0) orig = orig.Substring(0, z); }
                if (!Regex.IsMatch(orig, @"^[A-Za-z]:\\")) return false;
                path = orig; return true;
            }
            catch { return false; }
        }
    }

    /// <summary>The whole deleted-files run for one drive: journal or exFAT, shadow copies, bin pairing, noise.</summary>
    public class DeletedScan
    {
        public DriveInfoRow Drive; public int Days = 30; public string PathFilter; public bool ShowNoise, CheckShadows = true;
        /// <summary>Optional scan-time filters: only matching rows are kept. ExtFilter is a comma list of extensions ("jpg, png, docx"); NameContains is a substring of the file name; MinBytes/MaxBytes bound the size (0 = no bound, and rows of unknown size - the NTFS journal never records size - pass the size test).</summary>
        public string ExtFilter, NameContains; public long MinBytes, MaxBytes;
        HashSet<string> _exts; string _name;
        void ParseFilters() { _exts = ParseExts(ExtFilter); _name = string.IsNullOrEmpty(NameContains) ? null : (NameContains.Trim().Length > 0 ? NameContains.Trim().ToLowerInvariant() : null); }
        /// <summary>"jpg, .png, *.docx" -> {jpg, png, docx}, or null if empty.</summary>
        public static HashSet<string> ParseExts(string extFilter)
        {
            if (string.IsNullOrEmpty(extFilter)) return null; HashSet<string> s = new HashSet<string>();
            foreach (string raw in extFilter.Split(new char[] { ',', ';', ' ', '\t', '|' }, StringSplitOptions.RemoveEmptyEntries)) { string e = raw.Trim().TrimStart('*', '.').ToLowerInvariant(); if (e.Length > 0) s.Add(e); }
            return s.Count == 0 ? null : s;
        }
        /// <summary>The pure filter test: does a file/folder of this name, kind and size pass? Size is only tested when known (the NTFS journal never records size).</summary>
        public static bool Matches(string name, bool isDir, long size, bool sizeKnown, HashSet<string> exts, string nameLower, long minBytes, long maxBytes)
        {
            if (exts != null) { if (isDir) return false; int dot = name.LastIndexOf('.'); string ext = dot >= 0 && dot < name.Length - 1 ? name.Substring(dot + 1).ToLowerInvariant() : ""; if (!exts.Contains(ext)) return false; }
            if (nameLower != null && name.ToLowerInvariant().IndexOf(nameLower) < 0) return false;
            if (sizeKnown) { if (minBytes > 0 && size < minBytes) return false; if (maxBytes > 0 && size > maxBytes) return false; }
            return true;
        }
        bool KeepRow(string full, bool isDir, long size, bool sizeKnown)
        {
            if (_exts == null && _name == null && MinBytes <= 0 && MaxBytes <= 0) return true;
            string name = full; int slash = full.LastIndexOf('\\'); if (slash >= 0 && slash < full.Length - 1) name = full.Substring(slash + 1);
            return Matches(name, isDir, size, sizeKnown, _exts, _name, MinBytes, MaxBytes);
        }
        public JournalInfo Journal; public ExFat Ex; public List<Shadow> ShadowsFound = new List<Shadow>(); public List<DeletedRow> Rows = new List<DeletedRow>(); public List<BinItem> Bins = new List<BinItem>(); public int NoiseHidden; public string Message = "";
        public Action<string> Progress; public Func<bool> Cancelled;

        public void Run()
        {
            DateTime since = DateTime.Now.AddDays(-Days); string L = Drive.Letter; string prefix = string.IsNullOrEmpty(PathFilter) ? null : PathFilter.TrimEnd('\\').ToLowerInvariant();
            ParseFilters();
            if (Drive.ExFat) { RunExFat(L, prefix); return; }
            if (!Drive.Journalable) { Message = Drive.Why; return; }
            Report("reading the change journal…");
            Journal = PSTools.Journal.Read(L, since, delegate (long n) { Report(n.ToString("N0") + " journal records read"); }, Cancelled);
            if (!Journal.Active) { Message = "No active USN journal on this volume: " + Journal.Error; return; }
            if (CheckShadows) { Report("looking for shadow copies…"); ShadowsFound = Shadows.For(L); ShadowsFound.RemoveAll(delegate (Shadow s) { return s.Date < since.AddDays(-1); }); }
            using (Resolver res = new Resolver(L, Journal.Dirs))
            {
                int n = 0;
                foreach (DeletedRec rec in Journal.Deleted)
                {
                    n++; if (n % 500 == 0) Report("resolving paths " + n.ToString("N0") + " / " + Journal.Deleted.Count.ToString("N0")); if (Cancelled != null && Cancelled()) break;
                    string parent = res.Path(rec.Parent, 0); string full = parent != null ? Path.Combine(parent, rec.Name) : L + @":\<unknown>\" + rec.Name;
                    if (prefix != null && !full.ToLowerInvariant().StartsWith(prefix)) continue;
                    bool noise = Noise.Is(full, rec.Name); if (noise && !ShowNoise) { NoiseHidden++; continue; }
                    DeletedRow r = new DeletedRow(); r.When = rec.When; r.Path = full; r.Type = rec.IsDir ? "folder" : "file"; r.Source = "journal"; r.Drive = L; r.Noise = noise;
                    if (ShadowsFound.Count > 0) { Shadow s = Shadows.Holding(full, ShadowsFound); if (s != null) { r.Recoverable = true; r.ShadowSource = s.Root + full.Substring(3); r.Note = "in shadow copy of " + s.Date.ToString("yyyy-MM-dd HH:mm"); } }
                    if (!KeepRow(full, rec.IsDir, 0, false)) continue;
                    Rows.Add(r);
                }
            }
            Dedupe();
        }
        void RunExFat(string L, string prefix)
        {
            Report("opening the volume…");
            try { Ex = ExFat.Open(L); } catch (Exception ex) { Message = "Could not open the exFAT volume for a raw read: " + ex.Message; return; }
            if (prefix != null && prefix.Length > 2 && prefix.Substring(0, 2) == (L + ":").ToLowerInvariant()) Ex.PathPrefix = prefix.Substring(2);
            Ex.ScanInBackground();
            while (!Ex.Done) { Thread.Sleep(200); Report(Ex.DirsScanned.ToString("N0") + " folders · " + Ex.EntriesSeen.ToString("N0") + " entries read"); if (Cancelled != null && Cancelled()) Ex.Cancel = true; }
            if (Ex.ScanError != null) Message = "scan stopped early: " + Ex.ScanError;
            // bin records: the $I entry's own timestamp is the deletion time even when its data is gone
            Dictionary<string, object[]> binInfo = new Dictionary<string, object[]>();
            foreach (XEntry e in Ex.Deleted)
            {
                if (e.IsDir) continue; Match m = Regex.Match(e.Path, @"^\\\$RECYCLE\.BIN\\\$I([A-Z0-9]{6})", RegexOptions.IgnoreCase); if (!m.Success) continue;
                string id = m.Groups[1].Value; binInfo[id] = new object[] { null, e.Modified };
                if (e.Size < 24 || e.Size > 4096 || !e.State.StartsWith("intact")) continue;
                string orig; DateTime when; if (ExFat.ParseBinRecord(Ex.ReadHead(e, (int)e.Size), out orig, out when)) binInfo[id] = new object[] { orig, when };
            }
            Dictionary<string, BinItem> bins = new Dictionary<string, BinItem>();
            foreach (XEntry e in Ex.Deleted)
            {
                string full = L + ":" + e.Path; DateTime when = e.Modified; string note = "", binId = ""; bool noise;
                Match m = Regex.Match(e.Path, @"^\\\$RECYCLE\.BIN\\\$([IR])([A-Z0-9]{6})(.*)$", RegexOptions.IgnoreCase);
                if (m.Success)
                {
                    if (m.Groups[1].Value.ToUpper() == "I") { if (!ShowNoise) { NoiseHidden++; continue; } note = "Recycle Bin record"; }
                    else
                    {
                        binId = m.Groups[2].Value; string rest = m.Groups[3].Value; object[] bi; binInfo.TryGetValue(binId, out bi);
                        if (bi != null && bi[0] != null) { full = (string)bi[0] + rest; when = (DateTime)bi[1]; note = "emptied from the Recycle Bin"; }
                        else if (bi != null) { when = (DateTime)bi[1]; note = "emptied from the Recycle Bin · original name lost"; }
                        else note = "emptied from the Recycle Bin · record gone";
                        BinItem b; if (!bins.TryGetValue(binId, out b)) { b = new BinItem(); b.Id = binId; b.Named = bi != null && bi[0] != null; b.Name = b.Named ? (string)bi[0] : L + @":\$RECYCLE.BIN\$R" + binId; b.When = bi != null ? (DateTime?)(DateTime)bi[1] : null; b.TopModified = e.Modified; bins[binId] = b; }
                        if (rest == "" || !rest.StartsWith("\\")) { b.IsDir = e.IsDir; b.TopModified = e.Modified; if (!b.Named) b.Name += rest; }
                        if (!e.IsDir) { if (e.State == "empty") b.Empty++; else b.Files++; if (e.State.StartsWith("intact")) { b.Intact++; b.Bytes += e.Size; } }
                        if (e.State == "empty" && !ShowNoise) { NoiseHidden++; continue; }
                    }
                    noise = false;
                }
                else { noise = Noise.Is(full, e.Name) || e.State == "empty"; if (noise && !ShowNoise) { NoiseHidden++; continue; } }
                DeletedRow r = new DeletedRow(); r.When = when; r.Path = full; r.Type = e.IsDir ? "folder" : "file"; r.Source = "exFAT"; r.State = e.State; r.Size = e.Size; r.Drive = L; r.Note = note; r.BinId = binId; r.Ex = e; r.Times = e.Times; r.Noise = noise;
                r.Recoverable = !e.IsDir && e.State.StartsWith("intact");
                if (!KeepRow(full, e.IsDir, e.Size, !e.IsDir)) continue;
                Rows.Add(r);
            }
            Bins = new List<BinItem>(bins.Values); Bins.Sort(delegate (BinItem a, BinItem b) { DateTime da = a.When ?? a.TopModified, db = b.When ?? b.TopModified; return db.CompareTo(da); });
            Dedupe();
        }
        void Dedupe()
        {
            Dictionary<string, DeletedRow> byPath = new Dictionary<string, DeletedRow>(StringComparer.OrdinalIgnoreCase);
            foreach (DeletedRow r in Rows) { DeletedRow g; if (!byPath.TryGetValue(r.Path, out g)) byPath[r.Path] = r; else { g.Times += r.Times; if (r.When > g.When) { r.Times = g.Times; byPath[r.Path] = r; } } }
            Rows = new List<DeletedRow>(byPath.Values); Rows.Sort(delegate (DeletedRow a, DeletedRow b) { return b.When.CompareTo(a.When); });
        }
        void Report(string s) { if (Progress != null) Progress(s); }
        /// <summary>Copies a recoverable row to destRoot (another drive). Returns the destination or throws.</summary>
        public string Recover(DeletedRow r, string destRoot)
        {
            if (!r.Recoverable) throw new InvalidOperationException("not recoverable");
            if (destRoot.Length >= 1 && destRoot.Substring(0, 1).ToUpper() == r.Drive.ToUpper() && r.Source == "exFAT") throw new InvalidOperationException("choose a folder on another drive: writing to the same drive can overwrite the very data being recovered");
            string rel = r.Path.Length > 2 ? r.Path.Substring(2) : "\\" + r.Name; string dest;
            if (r.BinId.Length > 0)
            {
                Match m = Regex.Match(r.Path, @"^[A-Za-z]:\\\$RECYCLE\.BIN\\\$R[A-Z0-9]{6}(.*)$", RegexOptions.IgnoreCase);
                dest = m.Success ? Path.Combine(destRoot, r.Drive + @"\Recycle Bin\$R" + r.BinId + " (deleted " + r.When.ToString("yyyy-MM-dd HH-mm") + ")" + m.Groups[1].Value) : Path.Combine(destRoot, r.Drive + @"\Recycle Bin" + rel);
            }
            else dest = Path.Combine(destRoot, r.Drive + rel);
            Directory.CreateDirectory(Path.GetDirectoryName(dest));
            if (r.Source == "exFAT") { if (Ex == null) throw new InvalidOperationException("the exFAT volume is no longer open - scan again"); Ex.Recover(r.Ex, dest); }
            else { if (!Win32.CopyFileW(r.ShadowSource, dest, false)) throw new IOException("copy failed (error " + Marshal.GetLastWin32Error() + ")"); }
            r.RecoveredTo = dest; return dest;
        }
        public void Close() { if (Ex != null) { Ex.Dispose(); Ex = null; } }
    }
}

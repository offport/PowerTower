// Vulnerability management engine (no UI). What the patchproof project does, for this machine:
//   inventory  - OS build + UBR (registry), hotfixes (Win32_QuickFixEngineering), CBS packages (registry),
//                Windows Update history and the updates it is offering right now (WUA COM), installed
//                software (uninstall registry hives, native + WOW64 + per-user), pending-reboot signals.
//   feeds      - MSRC CVRF monthly releases, NVD 2.0 per product, CISA KEV, EPSS. Cached on disk.
//   resolvers  - build comparison (host UBR >= fixed build) with a KB supersedence fallback for Microsoft
//                CVEs; version range matching for third-party software; missing updates from WUA.
// Every finding carries the evidence that decided it. Ported from patchproof's vulndata/*.py and
// agent/collector/*.py, with the same confirm-only philosophy: an unparseable version is "not a match".
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Management;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32;

namespace PSTools
{
    // ───────────────────────────── a small JSON reader ─────────────────────────────
    /// <summary>Parses JSON into Dictionary&lt;string,object&gt; / List&lt;object&gt; / string / double / bool / null.</summary>
    public static class Json
    {
        public static object Parse(string s) { int i = 0; object v = Value(s, ref i); Ws(s, ref i); if (i != s.Length) throw new FormatException("trailing characters at " + i); return v; }
        static void Ws(string s, ref int i) { while (i < s.Length) { char c = s[i]; if (c == ' ' || c == '\t' || c == '\r' || c == '\n') i++; else break; } }
        /// <summary>Deepest nesting Parse (and JsonWrite) accept. Bundles nest under 10; past this, recursion on hostile input would end in an uncatchable StackOverflow (PT-23).</summary>
        public const int MaxDepth = 200;
        static object Value(string s, ref int i) { return Value(s, ref i, 0); }
        static object Value(string s, ref int i, int depth)
        {
            if (depth > MaxDepth) throw new FormatException("nesting too deep (more than " + MaxDepth + " levels) at " + i);
            Ws(s, ref i); if (i >= s.Length) throw new FormatException("unexpected end of JSON");
            char c = s[i];
            if (c == '{')
            {
                i++; Dictionary<string, object> d = new Dictionary<string, object>(); Ws(s, ref i); if (i < s.Length && s[i] == '}') { i++; return d; }
                while (true)
                {
                    Ws(s, ref i); if (i >= s.Length || s[i] != '"') throw new FormatException("expected a key at " + i);
                    string k = Str(s, ref i); Ws(s, ref i); if (i >= s.Length || s[i] != ':') throw new FormatException("expected ':' at " + i); i++;
                    d[k] = Value(s, ref i, depth + 1); Ws(s, ref i);
                    if (i < s.Length && s[i] == ',') { i++; continue; }
                    if (i < s.Length && s[i] == '}') { i++; return d; }
                    throw new FormatException("expected ',' or '}' at " + i);
                }
            }
            if (c == '[')
            {
                i++; List<object> l = new List<object>(); Ws(s, ref i); if (i < s.Length && s[i] == ']') { i++; return l; }
                while (true)
                {
                    l.Add(Value(s, ref i, depth + 1)); Ws(s, ref i);
                    if (i < s.Length && s[i] == ',') { i++; continue; }
                    if (i < s.Length && s[i] == ']') { i++; return l; }
                    throw new FormatException("expected ',' or ']' at " + i);
                }
            }
            if (c == '"') return Str(s, ref i);
            if (c == 't' && string.CompareOrdinal(s, i, "true", 0, 4) == 0) { i += 4; return true; }
            if (c == 'f' && string.CompareOrdinal(s, i, "false", 0, 5) == 0) { i += 5; return false; }
            if (c == 'n' && string.CompareOrdinal(s, i, "null", 0, 4) == 0) { i += 4; return null; }
            int st = i; while (i < s.Length && "+-0123456789.eE".IndexOf(s[i]) >= 0) i++;
            if (i == st) throw new FormatException("unexpected '" + c + "' at " + i);
            double dv; if (!double.TryParse(s.Substring(st, i - st), NumberStyles.Float, CultureInfo.InvariantCulture, out dv)) throw new FormatException("bad number at " + st);
            return dv;
        }
        static string Str(string s, ref int i)
        {
            i++; int st = i;
            while (i < s.Length && s[i] != '"' && s[i] != '\\') i++;
            if (i < s.Length && s[i] == '"') { string r = s.Substring(st, i - st); i++; return r; }
            StringBuilder sb = new StringBuilder(); sb.Append(s, st, i - st);
            while (i < s.Length)
            {
                char c = s[i++]; if (c == '"') return sb.ToString(); if (c != '\\') { sb.Append(c); continue; } if (i >= s.Length) break;
                char e = s[i++];
                switch (e)
                {
                    case '"': sb.Append('"'); break; case '\\': sb.Append('\\'); break; case '/': sb.Append('/'); break; case 'b': sb.Append('\b'); break; case 'f': sb.Append('\f'); break; case 'n': sb.Append('\n'); break; case 'r': sb.Append('\r'); break; case 't': sb.Append('\t'); break;
                    case 'u': if (i + 4 > s.Length) throw new FormatException("bad \\u escape"); sb.Append((char)int.Parse(s.Substring(i, 4), NumberStyles.HexNumber)); i += 4; break;
                    default: sb.Append(e); break;
                }
            }
            throw new FormatException("unterminated string");
        }
        public static Dictionary<string, object> Obj(object o) { return o as Dictionary<string, object>; }
        /// <summary>A JSON array, or any in-process list (List&lt;string&gt;, arrays) read the same way - trees built in code are read before they are ever serialised.</summary>
        public static List<object> Arr(object o) { List<object> l = o as List<object>; if (l != null) return l; System.Collections.IEnumerable e = o as System.Collections.IEnumerable; l = new List<object>(); if (e != null && !(o is string) && !(o is System.Collections.IDictionary)) foreach (object x in e) l.Add(x); return l; }
        public static string S(object o) { if (o == null) return null; if (o is string) return (string)o; if (o is double) return ((double)o).ToString(CultureInfo.InvariantCulture); if (o is DateTime) { DateTime dt = (DateTime)o; return (dt.Kind == DateTimeKind.Utc ? dt : dt.ToUniversalTime()).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture); } if (o is int || o is long || o is float || o is decimal || o is short || o is byte) return Convert.ToString(o, CultureInfo.InvariantCulture); if (o is bool) return (bool)o ? "true" : "false"; return null; }
        public static double? N(object o) { if (o is double) return (double)o; if (o is int || o is long || o is float || o is decimal || o is short || o is byte) return Convert.ToDouble(o, CultureInfo.InvariantCulture);   /* trees built in-process carry boxed ints, not the doubles the parser makes */ string s = o as string; if (s != null) { double d; if (double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out d)) return d; } return null; }
        public static object Get(object o, params string[] path) { foreach (string p in path) { Dictionary<string, object> d = o as Dictionary<string, object>; if (d == null || !d.TryGetValue(p, out o)) return null; } return o; }
        public static string GetS(object o, params string[] path) { return S(Get(o, path)); }
        public static string Quote(string s) { if (s == null) return "null"; StringBuilder sb = new StringBuilder("\""); foreach (char c in s) { if (c == '"') sb.Append("\\\""); else if (c == '\\') sb.Append("\\\\"); else if (c < ' ') sb.Append("\\u").Append(((int)c).ToString("x4")); else sb.Append(c); } return sb.Append('"').ToString(); }
    }

    // ───────────────────────────── HTTP + on-disk feed cache ─────────────────────────────
    public class HttpError : Exception { public int Status; public string Url; public HttpError(int status, string msg, string url) : base(msg) { Status = status; Url = url; } }
    public static class Http
    {
        public static int TimeoutMs = 60000;
        public static string Get(string url, Dictionary<string, string> headers, int timeoutMs)
        {
            try { ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12; } catch { }
            HttpWebRequest r = (HttpWebRequest)WebRequest.Create(url); r.Method = "GET"; r.Timeout = timeoutMs; r.ReadWriteTimeout = timeoutMs; r.UserAgent = "PowerTower/2.0 (vulnerability management)"; r.Accept = "application/json"; r.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;
            if (headers != null) foreach (KeyValuePair<string, string> h in headers) { if (h.Key == "Accept") r.Accept = h.Value; else if (h.Key == "User-Agent") r.UserAgent = h.Value; else r.Headers[h.Key] = h.Value; }
            try { using (HttpWebResponse resp = (HttpWebResponse)r.GetResponse()) using (StreamReader sr = new StreamReader(resp.GetResponseStream(), Encoding.UTF8)) return sr.ReadToEnd(); }
            catch (WebException ex)
            {
                HttpWebResponse er = ex.Response as HttpWebResponse;
                if (er != null) { string body = ""; try { using (StreamReader sr = new StreamReader(er.GetResponseStream())) body = sr.ReadToEnd(); } catch { } if (body.Length > 160) body = body.Substring(0, 160) + "…"; throw new HttpError((int)er.StatusCode, "HTTP " + (int)er.StatusCode + " " + er.StatusDescription + (body.Length > 0 ? " · " + body.Replace('\n', ' ') : ""), url); }
                throw new HttpError(0, ex.Message, url);
            }
        }
        public static string Get(string url) { return Get(url, null, TimeoutMs); }
        public static bool Online() { try { if (!System.Net.NetworkInformation.NetworkInterface.GetIsNetworkAvailable()) return false; return Dns.GetHostAddresses("api.first.org").Length > 0 || Dns.GetHostAddresses("services.nvd.nist.gov").Length > 0; } catch { return false; } }
    }

    /// <summary>Feed responses cached as files so repeated scans are instant and offline scans still work.</summary>
    public class FeedCache
    {
        public readonly string Dir;
        /// <summary>Never touch the network: serve the cached copy whatever its age, fail when there is none. For feed packs on air-gapped boxes and for deterministic tests.</summary>
        public bool Offline;
        public FeedCache(string dir) { Dir = dir; try { Directory.CreateDirectory(dir); } catch { } }
        public string PathOf(string name) { return Path.Combine(Dir, name); }
        public string Read(string name, TimeSpan maxAge) { try { string p = PathOf(name); if (!File.Exists(p)) return null; if (DateTime.UtcNow - File.GetLastWriteTimeUtc(p) > maxAge) return null; return File.ReadAllText(p, Encoding.UTF8); } catch { return null; } }
        public string ReadAny(string name) { return Read(name, TimeSpan.FromDays(3650)); }
        public void Write(string name, string text) { try { File.WriteAllText(PathOf(name), text, new UTF8Encoding(false)); } catch { } }
        public DateTime? Stamp(string name) { try { string p = PathOf(name); return File.Exists(p) ? File.GetLastWriteTime(p) : (DateTime?)null; } catch { return null; } }
        public int Clear() { int n = 0; try { foreach (string f in Directory.GetFiles(Dir, "*.json")) { File.Delete(f); n++; } } catch { } return n; }
        public long Size() { long t = 0; try { foreach (string f in Directory.GetFiles(Dir, "*.json")) t += new FileInfo(f).Length; } catch { } return t; }
        /// <summary>Fetch through the cache: a fresh file wins, else the network, else a stale file (offline) with a note.</summary>
        public string Fetch(string name, string url, Dictionary<string, string> headers, TimeSpan maxAge, int timeoutMs, out string note)
        {
            if (Offline) { string any = ReadAny(name); if (any != null) { note = "offline pack · copy from " + Stamp(name).Value.ToString("yyyy-MM-dd HH:mm"); return any; } throw new InvalidOperationException("offline: the feed pack has no copy of " + name); }
            note = ""; string t = Read(name, maxAge); if (t != null) { note = "cached " + Stamp(name).Value.ToString("yyyy-MM-dd HH:mm"); return t; }
            try { t = Http.Get(url, headers, timeoutMs); Write(name, t); note = "downloaded"; return t; }
            catch (Exception ex) { string stale = ReadAny(name); if (stale != null) { note = "offline, using the copy from " + Stamp(name).Value.ToString("yyyy-MM-dd") + " (" + ex.Message + ")"; return stale; } throw; }
        }
    }

    // ───────────────────────────── late-bound COM (Windows Update Agent) ─────────────────────────────
    static class Com
    {
        public static object Create(string progId) { Type t = Type.GetTypeFromProgID(progId, true); return Activator.CreateInstance(t); }
        public static object Prop(object o, string name, params object[] args) { return o.GetType().InvokeMember(name, BindingFlags.GetProperty, null, o, args); }
        public static object Call(object o, string name, params object[] args) { return o.GetType().InvokeMember(name, BindingFlags.InvokeMethod, null, o, args); }
        public static void Set(object o, string name, object v) { o.GetType().InvokeMember(name, BindingFlags.SetProperty, null, o, new object[] { v }); }
        public static int Count(object coll) { return coll == null ? 0 : Convert.ToInt32(Prop(coll, "Count")); }
        public static object Item(object coll, int i) { return Prop(coll, "Item", i); }
        public static string S(object o, string name) { try { object v = Prop(o, name); return v == null ? "" : Convert.ToString(v, CultureInfo.InvariantCulture); } catch { return ""; } }
        public static List<string> Strings(object coll) { List<string> l = new List<string>(); try { int n = Count(coll); for (int i = 0; i < n; i++) { string s = Convert.ToString(Item(coll, i)); if (!string.IsNullOrEmpty(s)) l.Add(s); } } catch { } return l; }
        public static DateTime? Date(object o, string name) { try { object v = Prop(o, name); if (v is DateTime) { DateTime d = (DateTime)v; return d.Year > 1900 ? d : (DateTime?)null; } } catch { } return null; }
    }

    // ───────────────────────────── inventory ─────────────────────────────
    public class OsInfo
    {
        public string ProductName = "", Edition = "", DisplayVersion = "", Arch = "", Host = ""; public int Major, Minor, Build, Ubr; public DateTime? Installed;   // when this build was installed (registry InstallDate)
        public string Family { get { return Major + "." + Minor + "." + Build; } }
        /// <summary>major.minor.build.UBR - the one string the resolvers compare against FixedBuild.</summary>
        public string FullBuild { get { return Major + "." + Minor + "." + Build + "." + Ubr; } }
        public string Summary { get { return ProductName + (DisplayVersion.Length > 0 ? " " + DisplayVersion : "") + " · build " + FullBuild + " · " + Arch; } }
    }
    public class Hotfix
    {
        public string Kb = "", Description = "", Source = "", Title = "", Result = ""; public DateTime? InstalledOn;
        public string When { get { return InstalledOn.HasValue ? InstalledOn.Value.ToString("yyyy-MM-dd") : ""; } }
    }
    public class Software
    {
        public string Name = "", Version = "", Publisher = "", InstallDate = "", Scope = "", Vendor, Product, Status = "", VersionQuery = ""; public int Cves = -1;
        // vulnerability summary (filled by the Software Inventory scan): the worst confirmed CVE at this version
        public string WorstSeverity = "", WorstCve = "", Fix = ""; public double? WorstCvss, WorstEpss; public bool Kev, Exploited; public int Unconfirmed;
        public bool Vulnerable { get { return Cves > 0; } }
        public string VulnState { get { return Cves < 0 ? "" : Cves > 0 ? "vulnerable" : Mapped ? "clean" : "not checked"; } }
        public string ExploitText { get { return Kev && Exploited ? "KEV · exploited" : Kev ? "KEV" : Exploited ? "exploited" : ""; } }
        public bool Mapped { get { return Vendor != null; } }
        public string Cpe { get { return Vendor == null ? "" : Vendor + ":" + Product; } }
        public string Installed { get { if (InstallDate.Length == 8) return InstallDate.Substring(0, 4) + "-" + InstallDate.Substring(4, 2) + "-" + InstallDate.Substring(6, 2); return InstallDate; } }
    }
    public class MissingUpdate
    {
        public string Kb = "", Title = "", Severity = "", Kind = "", UpdateId = "", Reboot = "", Categories = ""; public List<string> Cves = new List<string>(); public bool Downloaded, Mandatory; public double SizeBytes; public DateTime? Published;
        public string CveText { get { return Cves.Count == 0 ? "" : Cves.Count <= 3 ? string.Join(", ", Cves.ToArray()) : Cves.Count + " CVEs: " + Cves[0] + ", " + Cves[1] + ", …"; } }
        public string PublishedText { get { return Published.HasValue ? Published.Value.ToString("yyyy-MM-dd") : ""; } }
    }
    public class RebootInfo
    {
        public bool Cbs, WindowsUpdate, PendingFileRename;
        public bool Pending { get { return Cbs || WindowsUpdate || PendingFileRename; } }
        public string Why { get { List<string> l = new List<string>(); if (Cbs) l.Add("CBS RebootPending"); if (WindowsUpdate) l.Add("Windows Update RebootRequired"); if (PendingFileRename) l.Add("PendingFileRenameOperations"); return l.Count == 0 ? "no reboot pending" : string.Join(" + ", l.ToArray()); } }
    }

    public static class Inventory
    {
        static readonly Regex KbRx = new Regex(@"KB\s?(\d{5,8})", RegexOptions.IgnoreCase), CbsRx = new Regex(@"_for_KB(\d+)~", RegexOptions.IgnoreCase), SidRx = new Regex(@"^S-1-5-21-\d+-\d+-\d+-\d+$");
        static object V(RegistryKey k, string name) { try { return k == null ? null : k.GetValue(name); } catch { return null; } }
        static string VS(RegistryKey k, string name) { object o = V(k, name); return o == null ? "" : Convert.ToString(o, CultureInfo.InvariantCulture).Trim(); }
        static int VI(RegistryKey k, string name) { object o = V(k, name); if (o == null) return 0; try { return Convert.ToInt32(o, CultureInfo.InvariantCulture); } catch { int i; return int.TryParse(Convert.ToString(o), out i) ? i : 0; } }

        /// <summary>The build identity Windows itself treats as authoritative for update compliance: major.minor.build.UBR.</summary>
        public static OsInfo Os()
        {
            OsInfo o = new OsInfo(); o.Host = Environment.MachineName; o.Arch = Environment.Is64BitOperatingSystem ? (Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE") == "ARM64" ? "arm64" : "x64") : "x86";
            using (RegistryKey b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)) using (RegistryKey k = b.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
            {
                o.ProductName = VS(k, "ProductName"); o.Edition = VS(k, "EditionID"); o.DisplayVersion = VS(k, "DisplayVersion"); if (o.DisplayVersion.Length == 0) o.DisplayVersion = VS(k, "ReleaseId");
                int.TryParse(VS(k, "CurrentBuildNumber"), out o.Build); o.Ubr = VI(k, "UBR");
                object maj = V(k, "CurrentMajorVersionNumber"); if (maj != null) { o.Major = Convert.ToInt32(maj); o.Minor = VI(k, "CurrentMinorVersionNumber"); }
                else { string[] cv = VS(k, "CurrentVersion").Split('.'); int.TryParse(cv[0], out o.Major); if (cv.Length > 1) int.TryParse(cv[1], out o.Minor); if (o.Major == 0) o.Major = 10; }
                // "Windows 10 Pro" is what the registry says on Windows 11 too - build 22000+ is Windows 11
                if (o.Build >= 22000 && o.ProductName.StartsWith("Windows 10")) o.ProductName = "Windows 11" + o.ProductName.Substring(10);
                object inst = V(k, "InstallDate"); if (inst != null) { try { long secs = Convert.ToInt64(inst, CultureInfo.InvariantCulture); if (secs > 0) o.Installed = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(secs).ToLocalTime(); } catch { } }
            }
            return o;
        }

        /// <summary>Hotfixes per Win32_QuickFixEngineering: fast, but stops listing a KB once a newer cumulative update supersedes it.</summary>
        public static List<Hotfix> Qfe()
        {
            List<Hotfix> l = new List<Hotfix>();
            using (ManagementObjectSearcher s = new ManagementObjectSearcher("SELECT HotFixID, Description, InstalledOn FROM Win32_QuickFixEngineering"))
                foreach (ManagementObject m in s.Get())
                {
                    string id = Convert.ToString(m["HotFixID"]) ?? ""; Match mm = KbRx.Match(id); if (!mm.Success) continue;
                    Hotfix h = new Hotfix(); h.Kb = mm.Groups[1].Value; h.Description = Convert.ToString(m["Description"]) ?? ""; h.Source = "QFE"; h.Title = id;
                    string on = Convert.ToString(m["InstalledOn"]) ?? ""; DateTime d;
                    if (DateTime.TryParse(on, CultureInfo.GetCultureInfo("en-US"), DateTimeStyles.None, out d) || DateTime.TryParse(on, CultureInfo.InvariantCulture, DateTimeStyles.None, out d)) h.InstalledOn = d;
                    l.Add(h);
                }
            return l;
        }

        /// <summary>CBS packages from the registry mirror of the servicing store - catches KBs that QFE no longer lists once superseded. No elevation needed.</summary>
        public static List<Hotfix> Cbs(out int pendingCount)
        {
            List<Hotfix> l = new List<Hotfix>(); pendingCount = 0; Dictionary<string, Hotfix> seen = new Dictionary<string, Hotfix>();
            using (RegistryKey b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)) using (RegistryKey k = b.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages"))
            {
                if (k == null) return l;
                foreach (string name in k.GetSubKeyNames())
                {
                    Match m = CbsRx.Match(name); if (!m.Success) continue; string kb = m.Groups[1].Value;
                    int state = -1; try { using (RegistryKey p = k.OpenSubKey(name)) { object st = V(p, "CurrentState"); if (st != null) state = Convert.ToInt32(st); } } catch { }
                    // 112 installed · 128 permanent · 80 superseded (was installed, then replaced) · 96 install pending (needs a reboot)
                    string txt = state == 112 ? "installed" : state == 128 ? "permanent" : state == 80 ? "superseded" : state == 96 ? "install pending" : state == 64 ? "staged" : state == 0 ? "absent" : state == 5 ? "uninstall pending" : state < 0 ? "installed" : "state " + state;
                    if (state == 96) pendingCount++;
                    if (!(state == 112 || state == 128 || state == 80 || state == 96 || state < 0)) continue;
                    Hotfix h; if (seen.TryGetValue(kb, out h)) { if (state == 112 && h.Result != "installed") h.Result = txt; continue; }
                    h = new Hotfix(); h.Kb = kb; h.Source = "CBS"; h.Title = name; h.Result = txt; h.Description = "servicing package"; seen[kb] = h; l.Add(h);
                }
            }
            return l;
        }

        /// <summary>Windows Update history via the WUA COM API: what was installed, when, and whether it actually succeeded.</summary>
        public static List<Hotfix> WuHistory(int limit)
        {
            List<Hotfix> l = new List<Hotfix>();
            object session = Com.Create("Microsoft.Update.Session"); object searcher = Com.Call(session, "CreateUpdateSearcher");
            int total = Convert.ToInt32(Com.Call(searcher, "GetTotalHistoryCount")); if (total <= 0) return l;
            object hist = Com.Call(searcher, "QueryHistory", 0, Math.Min(limit, total)); int n = Com.Count(hist);
            for (int i = 0; i < n; i++)
            {
                object e = Com.Item(hist, i); string title = Com.S(e, "Title"); int op = 0, rc = 0; int.TryParse(Com.S(e, "Operation"), out op); int.TryParse(Com.S(e, "ResultCode"), out rc);
                Hotfix h = new Hotfix(); h.Title = title; h.Source = "WU history"; Match m = KbRx.Match(title); h.Kb = m.Success ? m.Groups[1].Value : ""; h.InstalledOn = Com.Date(e, "Date");
                h.Description = op == 1 ? "installation" : op == 2 ? "uninstallation" : "operation " + op;
                h.Result = rc == 2 ? "succeeded" : rc == 3 ? "succeeded with errors" : rc == 4 ? "failed" : rc == 5 ? "aborted" : rc == 1 ? "in progress" : "not started";
                l.Add(h);
            }
            return l;
        }

        /// <summary>The updates Windows Update is offering this machine right now (IsInstalled=0), with the CVEs each one fixes. Slow: 20 s to a few minutes.</summary>
        public static List<MissingUpdate> WuMissing(Action<string> progress)
        {
            List<MissingUpdate> l = new List<MissingUpdate>();
            object session = Com.Create("Microsoft.Update.Session"); object searcher = Com.Call(session, "CreateUpdateSearcher");
            try { Com.Set(searcher, "Online", true); } catch { }
            if (progress != null) progress("asking Windows Update which updates apply here (this can take a minute)…");
            object result = Com.Call(searcher, "Search", "IsInstalled=0 and IsHidden=0"); object ups = Com.Prop(result, "Updates"); int n = Com.Count(ups);
            for (int i = 0; i < n; i++)
            {
                object u = Com.Item(ups, i); MissingUpdate m = new MissingUpdate(); m.Title = Com.S(u, "Title"); m.Severity = Com.S(u, "MsrcSeverity");
                List<string> kbs = Com.Strings(SafeProp(u, "KBArticleIDs")); m.Kb = kbs.Count > 0 ? kbs[0] : (KbRx.IsMatch(m.Title) ? KbRx.Match(m.Title).Groups[1].Value : "");
                m.Cves = Com.Strings(SafeProp(u, "CveIDs")); m.UpdateId = Com.S(SafeProp(u, "Identity"), "UpdateID");
                m.Downloaded = Com.S(u, "IsDownloaded") == "True"; m.Mandatory = Com.S(u, "IsMandatory") == "True"; double.TryParse(Com.S(u, "MaxDownloadSize"), NumberStyles.Float, CultureInfo.InvariantCulture, out m.SizeBytes); m.Published = Com.Date(u, "LastDeploymentChangeTime");
                List<string> cats = new List<string>(); try { object cc = Com.Prop(u, "Categories"); int cn = Com.Count(cc); for (int j = 0; j < cn; j++) cats.Add(Com.S(Com.Item(cc, j), "Name")); } catch { }
                m.Categories = string.Join(", ", cats.ToArray()); m.Kind = KindOf(cats, m.Title);
                try { string rb = Com.S(Com.Prop(u, "InstallationBehavior"), "RebootBehavior"); m.Reboot = rb == "1" ? "always" : rb == "2" ? "may ask" : "no"; } catch { }
                l.Add(m);
            }
            return l;
        }
        static object SafeProp(object o, string name) { try { return Com.Prop(o, name); } catch { return null; } }
        static string KindOf(List<string> cats, string title)
        {
            string all = string.Join("|", cats.ToArray()).ToLowerInvariant(); string t = title.ToLowerInvariant();
            if (all.Contains("security") || t.Contains("security")) return "security"; if (all.Contains("critical")) return "critical"; if (all.Contains("definition") || t.Contains("security intelligence") || t.Contains("antivirus")) return "definitions";
            if (all.Contains("driver")) return "driver"; if (all.Contains("feature pack") || all.Contains("upgrades")) return "feature"; return "other";
        }

        /// <summary>Installed software from the uninstall hives: 64-bit, 32-bit (WOW6432Node), the current user and every loaded user profile. Never Win32_Product (slow, triggers MSI repairs).</summary>
        public static List<Software> Installed()
        {
            List<Software> l = new List<Software>(); HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            const string U = @"Software\Microsoft\Windows\CurrentVersion\Uninstall";
            using (RegistryKey b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)) ReadUninstall(b, U, "machine", l, seen);
            using (RegistryKey b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32)) ReadUninstall(b, U, "machine (32-bit)", l, seen);
            using (RegistryKey b = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Registry64))
            {
                string[] sids; try { sids = b.GetSubKeyNames(); } catch { sids = new string[0]; }
                foreach (string sid in sids) if (SidRx.IsMatch(sid)) ReadUninstall(b, sid + "\\" + U, "user", l, seen);
            }
            l.Sort(delegate (Software a, Software c) { return string.Compare(a.Name, c.Name, StringComparison.OrdinalIgnoreCase); });
            foreach (Software s in l) { string v, p; if (ProductMap.Map(s.Name, out v, out p)) { s.Vendor = v; s.Product = p; s.Status = Ver.Parse(s.Version) == null ? "version not comparable" : "in the product map"; } else s.Status = "not in the product map"; }
            return l;
        }
        static void ReadUninstall(RegistryKey root, string path, string scope, List<Software> l, HashSet<string> seen)
        {
            RegistryKey k = null; try { k = root.OpenSubKey(path); } catch { } if (k == null) return;
            using (k)
                foreach (string sub in k.GetSubKeyNames())
                {
                    try
                    {
                        using (RegistryKey e = k.OpenSubKey(sub))
                        {
                            string name = VS(e, "DisplayName"); if (name.Length == 0) continue;
                            if (VI(e, "SystemComponent") == 1 && !name.StartsWith("Microsoft Edge", StringComparison.OrdinalIgnoreCase)) continue; // hidden components (runtimes' sub-packages, update stubs)
                            string rel = VS(e, "ReleaseType"); if (rel == "Update" || rel == "Security Update" || rel == "Hotfix" || rel == "Service Pack") continue; // per-product patches, not products
                            Software s = new Software(); s.Name = name; s.Version = VS(e, "DisplayVersion"); s.Publisher = VS(e, "Publisher"); s.InstallDate = VS(e, "InstallDate"); s.Scope = scope;
                            string key = name + "|" + s.Version + "|" + scope; if (!seen.Add(key)) continue;
                            l.Add(s);
                        }
                    }
                    catch { }
                }
        }

        /// <summary>Three independent reboot-pending signals: an update can be "installed" while the running OS still has the old files.</summary>
        public static RebootInfo Reboot()
        {
            RebootInfo r = new RebootInfo();
            using (RegistryKey b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
            {
                try { using (RegistryKey k = b.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending")) r.Cbs = k != null; } catch { }
                try { using (RegistryKey k = b.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired")) r.WindowsUpdate = k != null; } catch { }
                try { using (RegistryKey k = b.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Session Manager")) r.PendingFileRename = k != null && k.GetValue("PendingFileRenameOperations") != null; } catch { }
            }
            return r;
        }
    }

    // ───────────────────────────── product map + versions ─────────────────────────────
    public class ProductEntry { public Regex Name; public string Vendor, Product; public bool Verified; }
    /// <summary>DisplayName → NVD CPE vendor:product. A maintained table, not a fuzzy match: unmapped software is "not covered yet", never matched to the wrong product.</summary>
    public static class ProductMap
    {
        public static readonly List<ProductEntry> Table = new List<ProductEntry>();
        static void Add(string rx, string vendor, string product, bool verified) { ProductEntry e = new ProductEntry(); e.Name = new Regex(rx, RegexOptions.IgnoreCase); e.Vendor = vendor; e.Product = product; e.Verified = verified; Table.Add(e); }
        static ProductMap()
        {
            // checked live against NVD by patchproof
            Add(@"^7-Zip\b", "7-zip", "7-zip", true); Add(@"^VLC media player$", "videolan", "vlc_media_player", true); Add(@"^Google Chrome$", "google", "chrome", true); Add(@"^Mozilla Firefox", "mozilla", "firefox", true);
            Add(@"^Git$", "git-scm", "git", true); Add(@"^Wireshark", "wireshark", "wireshark", true); Add(@"^Nmap\b", "nmap", "nmap", true);
            // well-known CPE names, added here; the version check still decides
            Add(@"^Microsoft Edge$", "microsoft", "edge_chromium", false); Add(@"^(Microsoft )?Visual Studio Code", "microsoft", "visual_studio_code", false); Add(@"^PowerShell 7", "microsoft", "powershell", false);
            Add(@"^Notepad\+\+", "notepad-plus-plus", "notepad++", false); Add(@"^PuTTY", "putty", "putty", false); Add(@"^WinRAR", "rarlab", "winrar", false); Add(@"^Node\.js", "nodejs", "node.js", false);
            Add(@"^Mozilla Thunderbird", "mozilla", "thunderbird", false); Add(@"^LibreOffice", "libreoffice", "libreoffice", false); Add(@"^WinSCP", "winscp", "winscp", false); Add(@"^KeePass Password Safe", "keepass", "keepass", false);
            Add(@"^Oracle VM VirtualBox", "oracle", "vm_virtualbox", false); Add(@"^FileZilla Client", "filezilla-project", "filezilla_client", false); Add(@"^TeamViewer", "teamviewer", "teamviewer", false); Add(@"^OBS Studio", "obsproject", "obs_studio", false);
            Add(@"^OpenVPN\b", "openvpn", "openvpn", false); Add(@"^Docker Desktop", "docker", "desktop", false); Add(@"^Brave$", "brave", "brave", false); Add(@"^Opera( GX)?( Stable)?$", "opera", "opera_browser", false); Add(@"^Vivaldi", "vivaldi", "vivaldi", false);
            Add(@"^Slack$", "slack", "slack", false); Add(@"^qBittorrent", "qbittorrent", "qbittorrent", false); Add(@"^Audacity", "audacityteam", "audacity", false); Add(@"^GIMP", "gimp", "gimp", false); Add(@"^Inkscape", "inkscape", "inkscape", false); Add(@"^Blender", "blender", "blender", false);
            Add(@"^SumatraPDF", "sumatrapdfreader", "sumatrapdf", false); Add(@"^Foxit PDF Reader", "foxit", "pdf_reader", false); Add(@"^Adobe Acrobat Reader", "adobe", "acrobat_reader_dc", false); Add(@"^ImageMagick", "imagemagick", "imagemagick", false);
            Add(@"^TortoiseGit", "tortoisegit", "tortoisegit", false); Add(@"^TortoiseSVN", "tortoisesvn", "tortoisesvn", false); Add(@"^CMake", "kitware", "cmake", false); Add(@"^HandBrake", "handbrake", "handbrake", false); Add(@"^Telegram Desktop", "telegram", "telegram_desktop", false);
            Add(@"^Dropbox$", "dropbox", "dropbox", false); Add(@"^calibre", "calibre-ebook", "calibre", false); Add(@"^MobaXterm", "mobatek", "mobaxterm", false); Add(@"^mRemoteNG", "mremoteng", "mremoteng", false); Add(@"^MySQL Workbench", "oracle", "mysql_workbench", false);
            Add(@"^PostgreSQL \d", "postgresql", "postgresql", false); Add(@"^Greenshot", "greenshot", "greenshot", false); Add(@"^Malwarebytes", "malwarebytes", "malwarebytes", false); Add(@"^OpenSSL", "openssl", "openssl", false); Add(@"^NordVPN", "nordvpn", "nordvpn", false); Add(@"^Tailscale", "tailscale", "tailscale", false);
            Add(@"^Zoom( Workplace)?$", "zoom", "zoom", false); Add(@"^Bitwarden", "bitwarden", "bitwarden", false); Add(@"^Signal", "signal", "signal-desktop", false); Add(@"^Discord$", "discord", "discord", false); Add(@"^Steam$", "valvesoftware", "steam", false);
        }
        public static bool Map(string displayName, out string vendor, out string product)
        {
            vendor = product = null; string n = (displayName ?? "").Trim();
            foreach (ProductEntry e in Table) if (e.Name.IsMatch(n)) { vendor = e.Vendor; product = e.Product; return true; }
            return false;
        }
    }

    /// <summary>Dotted-numeric version comparison. Anything unparseable compares as "unknown", never as a guess.</summary>
    public static class Ver
    {
        public static int[] Parse(string v)
        {
            if (string.IsNullOrEmpty(v)) return null; string[] parts = v.Trim().Split('.'); int[] r = new int[parts.Length];
            for (int i = 0; i < parts.Length; i++) { int j = 0; while (j < parts[i].Length && char.IsDigit(parts[i][j])) j++; if (j == 0) return null; long n; if (!long.TryParse(parts[i].Substring(0, j), out n)) return null; r[i] = (int)Math.Min(int.MaxValue, n); }
            return r;
        }
        public static string Canon(string v) { int[] p = Parse(v); if (p == null) return null; string[] s = new string[p.Length]; for (int i = 0; i < p.Length; i++) s[i] = p[i].ToString(); return string.Join(".", s); }
        public static bool TryCompare(string a, string b, out int result)
        {
            result = 0; int[] x = Parse(a), y = Parse(b); if (x == null || y == null) return false; int n = Math.Max(x.Length, y.Length);
            for (int i = 0; i < n; i++) { int xi = i < x.Length ? x[i] : 0, yi = i < y.Length ? y[i] : 0; if (xi != yi) { result = xi < yi ? -1 : 1; return true; } }
            return true;
        }
        public static int Compare(string a, string b) { int r; if (!TryCompare(a, b, out r)) throw new FormatException("cannot compare non-numeric versions '" + a + "' and '" + b + "'"); return r; }
        public static bool InRange(string v, string startInc, string startExc, string endInc, string endExc)
        {
            int r;
            if (startInc != null) { if (!TryCompare(v, startInc, out r) || r < 0) return false; }
            if (startExc != null) { if (!TryCompare(v, startExc, out r) || r <= 0) return false; }
            if (endInc != null) { if (!TryCompare(v, endInc, out r) || r > 0) return false; }
            if (endExc != null) { if (!TryCompare(v, endExc, out r) || r >= 0) return false; }
            return Parse(v) != null;
        }
    }

    // ───────────────────────────── feeds ─────────────────────────────
    public class CpeMatch
    {
        public string Criteria = "", Vendor = "", Product = "", ExactVersion, StartInc, StartExc, EndInc, EndExc;
        public bool Unbounded { get { return ExactVersion == null && StartInc == null && StartExc == null && EndInc == null && EndExc == null; } }
        public string Range { get { if (ExactVersion != null) return "= " + ExactVersion; List<string> l = new List<string>(); if (StartInc != null) l.Add(">= " + StartInc); if (StartExc != null) l.Add("> " + StartExc); if (EndInc != null) l.Add("<= " + EndInc); if (EndExc != null) l.Add("< " + EndExc); return l.Count == 0 ? "any version" : string.Join(" and ", l.ToArray()); } }
        public static CpeMatch From(object m)
        {
            CpeMatch c = new CpeMatch(); c.Criteria = Json.GetS(m, "criteria") ?? ""; string[] p = c.Criteria.Split(':');
            if (p.Length > 4) { c.Vendor = p[3]; c.Product = p[4]; } if (p.Length > 5 && p[5] != "*" && p[5] != "-") c.ExactVersion = p[5];
            c.StartInc = Json.GetS(m, "versionStartIncluding"); c.StartExc = Json.GetS(m, "versionStartExcluding"); c.EndInc = Json.GetS(m, "versionEndIncluding"); c.EndExc = Json.GetS(m, "versionEndExcluding");
            return c;
        }
        /// <summary>Does the installed version fall inside this match? Exact criteria compare equal; wildcards with no bounds are "unknown" (false).</summary>
        public bool Hits(string installed)
        {
            if (ExactVersion != null) { int r; return Ver.TryCompare(installed, ExactVersion, out r) && r == 0; }
            if (Unbounded) return false;
            return Ver.InRange(installed, StartInc, StartExc, EndInc, EndExc);
        }
    }
    public class CveRecord { public string Id = "", Description = "", Severity = ""; public double? Cvss; public DateTime? Published; public List<CpeMatch> Matches = new List<CpeMatch>(); }

    /// <summary>NVD API 2.0. Unauthenticated: 5 requests per 30 s, so one product every 6.5 s; with a free key: 50 per 30 s.</summary>
    public static class Nvd
    {
        public const string Base = "https://services.nvd.nist.gov/rest/json/cves/2.0";
        static DateTime lastCall = DateTime.MinValue; static readonly object gate = new object();
        static void Pace(bool keyed) { lock (gate) { double gap = keyed ? 0.8 : 6.5; double wait = gap - (DateTime.UtcNow - lastCall).TotalSeconds; if (wait > 0) Thread.Sleep((int)(wait * 1000)); lastCall = DateTime.UtcNow; } }
        public static string CacheName(string vendor, string product, string version) { string s = (vendor + "-" + product + "-" + version).ToLowerInvariant(); foreach (char c in Path.GetInvalidFileNameChars()) s = s.Replace(c, '_'); return "nvd-" + s.Replace('+', 'p') + ".json"; }
        /// <summary>Every CVE whose configuration covers vendor:product at exactly this version (server-side range filter), parsed; version filtering is then re-done locally for the evidence.</summary>
        public static List<CveRecord> ForProduct(string vendor, string product, string version, string apiKey, FeedCache cache, Action<string> progress, out string note)
        {
            string canon = Ver.Canon(version); if (canon == null) throw new FormatException("version '" + version + "' is not comparable");
            string name = CacheName(vendor, product, canon); string cached = cache == null ? null : cache.Read(name, TimeSpan.FromHours(24));
            if (cached != null) { note = "cached " + cache.Stamp(name).Value.ToString("yyyy-MM-dd HH:mm"); return Parse(cached); }
            if (cache != null && cache.Offline) { string any = cache.ReadAny(name); if (any == null) throw new InvalidOperationException("offline: the feed pack has no NVD record for " + vendor + ":" + product + " " + canon); note = "offline pack · copy from " + cache.Stamp(name).Value.ToString("yyyy-MM-dd HH:mm"); return Parse(any); }
            bool keyed = !string.IsNullOrEmpty(apiKey); Dictionary<string, string> h = new Dictionary<string, string>(); if (keyed) h["apiKey"] = apiKey.Trim();
            string match = Uri.EscapeDataString("cpe:2.3:a:" + vendor + ":" + product); List<object> all = new List<object>(); int start = 0, total = 0; const int page = 500; StringBuilder raw = new StringBuilder();
            while (true)
            {
                string url = Base + "?virtualMatchString=" + match + "&versionStart=" + Uri.EscapeDataString(canon) + "&versionStartType=including&versionEnd=" + Uri.EscapeDataString(canon) + "&versionEndType=including&resultsPerPage=" + page + "&startIndex=" + start;
                if (progress != null) progress("NVD · " + vendor + ":" + product + " " + canon + (start > 0 ? " · page " + (start / page + 1) : ""));
                string body = null;
                for (int attempt = 0; attempt < 3; attempt++)
                {
                    Pace(keyed);
                    try { body = Http.Get(url, h, 60000); break; }
                    catch (HttpError e) { if ((e.Status == 403 || e.Status == 429 || e.Status == 503) && attempt < 2) { if (progress != null) progress("NVD rate limit hit, waiting 30 s…"); Thread.Sleep(30000); continue; } throw; }
                }
                object doc = Json.Parse(body); List<object> v = Json.Arr(Json.Get(doc, "vulnerabilities")); all.AddRange(v);
                double? tr = Json.N(Json.Get(doc, "totalResults")); total = tr.HasValue ? (int)tr.Value : all.Count; start += page;
                if (start >= total || v.Count == 0) break;
            }
            // store a normalised document so the cache reader is the same code path
            raw.Append("{\"totalResults\":").Append(all.Count).Append(",\"vulnerabilities\":["); for (int i = 0; i < all.Count; i++) { if (i > 0) raw.Append(','); raw.Append(Slim(all[i])); } raw.Append("]}");
            if (cache != null) cache.Write(name, raw.ToString()); note = "downloaded";
            return Parse(raw.ToString());
        }
        /// <summary>Keeps only what the resolver needs (id, English description, primary CVSS, vulnerable cpeMatch entries) so the cache stays small.</summary>
        static string Slim(object item)
        {
            CveRecord r = ParseOne(item); StringBuilder sb = new StringBuilder();
            sb.Append("{\"cve\":{\"id\":").Append(Json.Quote(r.Id)).Append(",\"published\":").Append(Json.Quote(r.Published.HasValue ? r.Published.Value.ToString("s") : "")).Append(",\"descriptions\":[{\"lang\":\"en\",\"value\":").Append(Json.Quote(r.Description)).Append("}]");
            sb.Append(",\"metrics\":{\"cvssMetricV31\":[{\"type\":\"Primary\",\"cvssData\":{\"baseScore\":").Append(r.Cvss.HasValue ? r.Cvss.Value.ToString(CultureInfo.InvariantCulture) : "null").Append(",\"baseSeverity\":").Append(Json.Quote(r.Severity)).Append("}}]}");
            sb.Append(",\"configurations\":[{\"nodes\":[{\"cpeMatch\":[");
            for (int i = 0; i < r.Matches.Count; i++)
            {
                CpeMatch m = r.Matches[i]; if (i > 0) sb.Append(','); sb.Append("{\"vulnerable\":true,\"criteria\":").Append(Json.Quote(m.Criteria));
                if (m.StartInc != null) sb.Append(",\"versionStartIncluding\":").Append(Json.Quote(m.StartInc)); if (m.StartExc != null) sb.Append(",\"versionStartExcluding\":").Append(Json.Quote(m.StartExc));
                if (m.EndInc != null) sb.Append(",\"versionEndIncluding\":").Append(Json.Quote(m.EndInc)); if (m.EndExc != null) sb.Append(",\"versionEndExcluding\":").Append(Json.Quote(m.EndExc)); sb.Append('}');
            }
            return sb.Append("]}]}]}}").ToString();
        }
        public static List<CveRecord> Parse(string json) { List<CveRecord> l = new List<CveRecord>(); object doc = Json.Parse(json); foreach (object item in Json.Arr(Json.Get(doc, "vulnerabilities"))) l.Add(ParseOne(item)); return l; }
        public static CveRecord ParseOne(object item)
        {
            CveRecord r = new CveRecord(); object cve = Json.Get(item, "cve"); r.Id = Json.GetS(cve, "id") ?? "";
            foreach (object d in Json.Arr(Json.Get(cve, "descriptions"))) if (Json.GetS(d, "lang") == "en") { r.Description = Json.GetS(d, "value") ?? ""; break; }
            DateTime pub; if (DateTime.TryParse(Json.GetS(cve, "published"), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out pub)) r.Published = pub;
            object metrics = Json.Get(cve, "metrics"); List<object> cv = null;
            foreach (string key in new string[] { "cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2" }) { List<object> l = Json.Get(metrics, key) as List<object>; if (l != null && l.Count > 0) { cv = l; break; } }
            if (cv != null)
            {
                object primary = null; foreach (object m in cv) if (Json.GetS(m, "type") == "Primary") { primary = m; break; } if (primary == null) primary = cv[0];
                r.Cvss = Json.N(Json.Get(primary, "cvssData", "baseScore")); r.Severity = Json.GetS(primary, "cvssData", "baseSeverity") ?? Json.GetS(primary, "baseSeverity") ?? "";
            }
            foreach (object cfg in Json.Arr(Json.Get(cve, "configurations"))) foreach (object node in Json.Arr(Json.Get(cfg, "nodes"))) foreach (object m in Json.Arr(Json.Get(node, "cpeMatch")))
            { object vul = Json.Get(m, "vulnerable"); if (vul is bool && !(bool)vul) continue; r.Matches.Add(CpeMatch.From(m)); }
            return r;
        }
    }

    public class MsrcRec { public string Cve = "", Title = "", Severity = "", Kb = "", SupersedesKb, FixedBuild, ProductId = "", ProductName = "", Release = "", Url = ""; public double? Cvss; public bool Exploited, Disclosed; }
    /// <summary>Microsoft's CVRF feed: one record per (CVE, fixing KB, product), with FixedBuild and supersedence. Public, no key.</summary>
    public static class Msrc
    {
        public const string Base = "https://api.msrc.microsoft.com/cvrf/v3.0";
        /// <summary>Release IDs ("2026-Sep") newest first, only those already published.</summary>
        public static List<string> Releases(FeedCache cache, out string note)
        {
            string body = cache.Fetch("msrc-releases.json", Base + "/updates", null, TimeSpan.FromHours(12), 30000, out note);
            List<KeyValuePair<DateTime, string>> l = new List<KeyValuePair<DateTime, string>>();
            foreach (object r in Json.Arr(Json.Get(Json.Parse(body), "value")))
            {
                string id = Json.GetS(r, "ID"); DateTime d; if (string.IsNullOrEmpty(id)) continue;
                if (!DateTime.TryParse(Json.GetS(r, "InitialReleaseDate"), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out d)) continue;
                if (d > DateTime.UtcNow.AddDays(1)) continue; l.Add(new KeyValuePair<DateTime, string>(d, id));
            }
            l.Sort(delegate (KeyValuePair<DateTime, string> a, KeyValuePair<DateTime, string> b) { return b.Key.CompareTo(a.Key); });
            List<string> ids = new List<string>(); foreach (KeyValuePair<DateTime, string> p in l) ids.Add(p.Value); return ids;
        }
        public static string Fetch(string release, FeedCache cache, out string note)
        {
            // the current month's document gets revised; older ones are effectively frozen. Http.Get always sends Accept: application/json.
            bool recent = false; DateTime d; if (DateTime.TryParseExact(release, "yyyy-MMM", CultureInfo.InvariantCulture, DateTimeStyles.None, out d)) recent = (DateTime.UtcNow - d).TotalDays < 45;
            return cache.Fetch("msrc-" + release + ".json", Base + "/cvrf/" + release, null, recent ? TimeSpan.FromDays(2) : TimeSpan.FromDays(120), 180000, out note);
        }
        /// <summary>Flattens a CVRF document. Only Type 2 (Vendor Fix) remediations carry KB, FixedBuild and Supercedence.</summary>
        public static List<MsrcRec> Parse(string json, string release)
        {
            object doc = Json.Parse(json); Dictionary<string, string> products = new Dictionary<string, string>();
            foreach (object p in Json.Arr(Json.Get(doc, "ProductTree", "FullProductName"))) { string id = Json.GetS(p, "ProductID"); if (id != null) products[id] = Json.GetS(p, "Value") ?? ""; }
            List<MsrcRec> l = new List<MsrcRec>();
            foreach (object v in Json.Arr(Json.Get(doc, "Vulnerability")))
            {
                string cve = Json.GetS(v, "CVE"); if (string.IsNullOrEmpty(cve)) continue; string title = Json.GetS(v, "Title", "Value") ?? "";
                string sev = ""; bool exploited = false, disclosed = false;
                foreach (object t in Json.Arr(Json.Get(v, "Threats")))
                {
                    double? ty = Json.N(Json.Get(t, "Type")); string desc = Json.GetS(t, "Description", "Value") ?? "";
                    if (ty == 3 && sev.Length == 0 && desc.Length > 0) sev = desc;
                    if (ty == 1) { if (desc.IndexOf("Exploited:Yes", StringComparison.OrdinalIgnoreCase) >= 0) exploited = true; if (desc.IndexOf("Publicly Disclosed:Yes", StringComparison.OrdinalIgnoreCase) >= 0) disclosed = true; }
                }
                double? cvss = null; List<object> sets = Json.Arr(Json.Get(v, "CVSSScoreSets")); if (sets.Count > 0) cvss = Json.N(Json.Get(sets[0], "BaseScore"));
                foreach (object rem in Json.Arr(Json.Get(v, "Remediations")))
                {
                    if (Json.N(Json.Get(rem, "Type")) != 2) continue; string kb = Json.GetS(rem, "Description", "Value") ?? ""; if (kb.Length == 0 || !IsDigits(kb)) continue;
                    List<object> pids = Json.Arr(Json.Get(rem, "ProductID")); if (pids.Count == 0) pids.Add(null);
                    foreach (object pid in pids)
                    {
                        MsrcRec r = new MsrcRec(); r.Cve = cve; r.Title = title; r.Severity = sev; r.Cvss = cvss; r.Kb = kb; r.SupersedesKb = Json.GetS(rem, "Supercedence"); if (r.SupersedesKb != null && r.SupersedesKb.Length == 0) r.SupersedesKb = null;
                        r.FixedBuild = Json.GetS(rem, "FixedBuild"); if (r.FixedBuild != null && r.FixedBuild.Length == 0) r.FixedBuild = null; r.ProductId = Json.S(pid) ?? ""; string pn; r.ProductName = products.TryGetValue(r.ProductId, out pn) ? pn : ""; r.Release = release; r.Url = Json.GetS(rem, "URL") ?? "";
                        r.Exploited = exploited; r.Disclosed = disclosed; l.Add(r);
                    }
                }
            }
            return l;
        }
        static bool IsDigits(string s) { foreach (char c in s) if (c < '0' || c > '9') return false; return true; }
    }

    public class KevEntry { public string Cve = "", Vendor = "", Product = "", Name = "", DateAdded = "", DueDate = ""; public bool Ransomware; }
    /// <summary>CISA's Known Exploited Vulnerabilities catalogue: known-exploited CVEs get top priority regardless of CVSS.</summary>
    public static class Kev
    {
        public const string Url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
        public static Dictionary<string, KevEntry> Load(FeedCache cache, out string note)
        {
            string body = cache.Fetch("kev.json", Url, null, TimeSpan.FromHours(24), 60000, out note); return Parse(body);
        }
        public static Dictionary<string, KevEntry> Parse(string json)
        {
            Dictionary<string, KevEntry> d = new Dictionary<string, KevEntry>(StringComparer.OrdinalIgnoreCase);
            foreach (object v in Json.Arr(Json.Get(Json.Parse(json), "vulnerabilities")))
            {
                KevEntry e = new KevEntry(); e.Cve = Json.GetS(v, "cveID") ?? ""; if (e.Cve.Length == 0) continue; e.Vendor = Json.GetS(v, "vendorProject") ?? ""; e.Product = Json.GetS(v, "product") ?? ""; e.Name = Json.GetS(v, "vulnerabilityName") ?? "";
                e.DateAdded = Json.GetS(v, "dateAdded") ?? ""; e.DueDate = Json.GetS(v, "dueDate") ?? ""; e.Ransomware = (Json.GetS(v, "knownRansomwareCampaignUse") ?? "").StartsWith("Known", StringComparison.OrdinalIgnoreCase); d[e.Cve] = e;
            }
            return d;
        }
    }

    /// <summary>EPSS: probability (0-1) that a CVE is exploited in the next 30 days. Missing = unscored, not zero.</summary>
    public static class Epss
    {
        public const string Base = "https://api.first.org/data/v1/epss";
        public static Dictionary<string, double> Scores(IEnumerable<string> cves, FeedCache cache, Action<string> progress) { string asOf; return Scores(cves, cache, progress, out asOf); }
        static List<string> Sorted(IEnumerable<string> cves) { List<string> u = new List<string>(new HashSet<string>(cves, StringComparer.OrdinalIgnoreCase)); u.Sort(StringComparer.OrdinalIgnoreCase); return u; }
        /// <summary>The cache file the first batch of these CVEs is kept in - so a feed pack or a test can be seeded for exactly this request.</summary>
        public static string CacheName(IEnumerable<string> cves) { List<string> u = Sorted(cves); List<string> batch = u.GetRange(0, Math.Min(100, u.Count)); return "epss-" + Hash(string.Join(",", batch.ToArray())) + ".json"; }
        /// <summary>asOf: the scoring date the responses carried ("2026-10-12", or "a..b" when batches differ), empty when none.</summary>
        public static Dictionary<string, double> Scores(IEnumerable<string> cves, FeedCache cache, Action<string> progress, out string asOf)
        {
            string minD = null, maxD = null;
            Dictionary<string, double> d = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase); List<string> u = Sorted(cves);
            for (int i = 0; i < u.Count; i += 100)
            {
                List<string> batch = u.GetRange(i, Math.Min(100, u.Count - i)); string joined = string.Join(",", batch.ToArray()); string name = "epss-" + Hash(joined) + ".json"; string note;
                if (progress != null) progress("EPSS · " + (i + batch.Count) + " of " + u.Count + " CVEs");
                string body = cache.Fetch(name, Base + "?cve=" + joined, null, TimeSpan.FromHours(24), 30000, out note);
                foreach (object e in Json.Arr(Json.Get(Json.Parse(body), "data"))) { string c = Json.GetS(e, "cve"); double? s = Json.N(Json.Get(e, "epss")); string dt = Json.GetS(e, "date"); if (dt != null) { if (minD == null || string.CompareOrdinal(dt, minD) < 0) minD = dt; if (maxD == null || string.CompareOrdinal(dt, maxD) > 0) maxD = dt; } if (c != null && s.HasValue) d[c] = s.Value; }
            }
            asOf = minD == null ? "" : minD == maxD ? minD : minD + ".." + maxD; return d;
        }
        static string Hash(string s) { using (MD5 md5 = MD5.Create()) { byte[] h = md5.ComputeHash(Encoding.UTF8.GetBytes(s)); StringBuilder sb = new StringBuilder(); for (int i = 0; i < 8; i++) sb.Append(h[i].ToString("x2")); return sb.ToString(); } }
    }

    // ───────────────────────────── resolvers ─────────────────────────────
    public class Finding
    {
        public string Cve = "", Title = "", Severity = "", Source = "", Product = "", Installed = "", Fix = "", Status = "", Evidence = "", Description = "", Url = "", Release = ""; public double? Cvss, Epss; public bool Kev, Exploited, Ransomware; public string KevDue = "";
        /// <summary>Exploit-validation write-back (the SPECTRE loop): confirmed · not exploitable · untested - the default, because these findings are version/build-based and never exploit-validated here.</summary>
        public string Validated = "untested";
        /// <summary>Critical / High / Medium / Low, from MSRC (Critical, Important, Moderate, Low) or NVD/CVSS wording.</summary>
        public string SeverityNorm { get { return Resolve.NormSeverity(Severity); } }
        public string ExploitText { get { if (Kev && Ransomware) return "KEV · ransomware"; if (Kev) return "KEV"; if (Exploited) return "exploited"; return ""; } }
        public bool Open { get { return Status == "vulnerable" || Status == "update available" || Status == "reboot pending"; } }
        public string Key { get { return Cve + "|" + Product; } }
        public double SortScore { get { double s = Open ? 1000 : 0; if (Kev) s += 500; if (Exploited) s += 200; s += Resolve.SevRank(SeverityNorm) * 20; if (Cvss.HasValue) s += Cvss.Value; if (Epss.HasValue) s += Epss.Value * 10; return s; } }
    }

    public class Supersedence
    {
        readonly Dictionary<string, HashSet<string>> newerOf = new Dictionary<string, HashSet<string>>();
        public void Add(string newerKb, string olderKb) { if (string.IsNullOrEmpty(newerKb) || string.IsNullOrEmpty(olderKb) || newerKb == olderKb) return; HashSet<string> s; if (!newerOf.TryGetValue(olderKb, out s)) newerOf[olderKb] = s = new HashSet<string>(); s.Add(newerKb); }
        /// <summary>Installed directly, or any installed KB supersedes it transitively (a rollup of a rollup of the fix still counts).</summary>
        public bool Satisfies(HashSet<string> installed, string kb, out string by)
        {
            by = kb; if (installed.Contains(kb)) return true; HashSet<string> seen = new HashSet<string>(); seen.Add(kb); Queue<string> q = new Queue<string>(); HashSet<string> first; if (newerOf.TryGetValue(kb, out first)) foreach (string n in first) q.Enqueue(n);
            while (q.Count > 0) { string k = q.Dequeue(); if (!seen.Add(k)) continue; if (installed.Contains(k)) { by = k; return true; } HashSet<string> next; if (newerOf.TryGetValue(k, out next)) foreach (string n in next) q.Enqueue(n); }
            return false;
        }
        public static Supersedence Build(IEnumerable<MsrcRec> recs) { Supersedence g = new Supersedence(); foreach (MsrcRec r in recs) if (r.SupersedesKb != null) g.Add(r.Kb, r.SupersedesKb); return g; }
    }

    public static class Resolve
    {
        public static string NormSeverity(string s) { string t = (s ?? "").Trim().ToLowerInvariant(); if (t == "critical") return "Critical"; if (t == "important" || t == "high") return "High"; if (t == "moderate" || t == "medium") return "Medium"; if (t == "low") return "Low"; return ""; }
        public static int SevRank(string norm) { switch (norm) { case "Critical": return 4; case "High": return 3; case "Medium": return 2; case "Low": return 1; default: return 0; } }
        public static int[] ParseBuild(string b) { if (string.IsNullOrEmpty(b)) return null; string[] p = b.Split('.'); if (p.Length != 4) return null; int[] r = new int[4]; for (int i = 0; i < 4; i++) if (!int.TryParse(p[i], out r[i])) return null; return r; }
        static readonly string[] Suffixes = { " for x64-based systems", " for 32-bit systems", " for 64-bit systems", " for arm64-based systems", " for x86-based systems", " (64-bit)", " (32-bit)", " 64-bit edition", " 32-bit edition", " (x64)", " (x86)" };
        static readonly Regex Locale = new Regex(@"\s*-\s*[a-z]{2}-[a-z]{2}$", RegexOptions.IgnoreCase);
        /// <summary>Product names as MSRC writes them vs. as the uninstall hive writes them: strip architecture and locale suffixes before comparing.</summary>
        public static string NormProduct(string n)
        {
            n = (n ?? "").Trim().ToLowerInvariant(); n = Locale.Replace(n, ""); bool again = true;
            while (again) { again = false; foreach (string s in Suffixes) if (n.EndsWith(s)) { n = n.Substring(0, n.Length - s.Length).TrimEnd(); again = true; } }
            return n;
        }
        static bool NameMatch(string product, HashSet<string> softwareNames) { string p = NormProduct(product); if (p.Length < 4) return false; foreach (string s in softwareNames) if (s.Length >= 4 && (p.Contains(s) || s.Contains(p))) return true; return false; }

        /// <summary>One finding per Microsoft CVE that applies to this host. Build comparison first (host UBR ≥ fixed UBR of the same build family), KB + supersedence for products without FixedBuild.</summary>
        public static List<Finding> Msrc(List<MsrcRec> records, OsInfo os, HashSet<string> knownKbs, IEnumerable<Software> software, RebootInfo reboot)
        {
            int[] host = ParseBuild(os.FullBuild); HashSet<string> names = new HashSet<string>(); foreach (Software s in software) names.Add(NormProduct(s.Name));
            Supersedence graph = Supersedence.Build(records); Dictionary<string, List<MsrcRec>> byCve = new Dictionary<string, List<MsrcRec>>(); List<string> order = new List<string>();
            foreach (MsrcRec r in records) { List<MsrcRec> l; if (!byCve.TryGetValue(r.Cve, out l)) { byCve[r.Cve] = l = new List<MsrcRec>(); order.Add(r.Cve); } l.Add(r); }
            List<Finding> out_ = new List<Finding>();
            foreach (string cve in order)
            {
                List<MsrcRec> applicable = new List<MsrcRec>();
                foreach (MsrcRec r in byCve[cve])
                {
                    int[] fixedB = ParseBuild(r.FixedBuild);
                    if (fixedB != null) { if (host != null && fixedB[0] == host[0] && fixedB[1] == host[1] && fixedB[2] == host[2]) applicable.Add(r); }
                    else if (r.ProductName.Length > 0 && NameMatch(r.ProductName, names)) applicable.Add(r);
                }
                if (applicable.Count == 0) continue;
                MsrcRec a0 = applicable[0]; Finding f = new Finding(); f.Cve = cve; f.Title = a0.Title; f.Severity = a0.Severity; f.Cvss = a0.Cvss; f.Source = "MSRC"; f.Release = a0.Release; f.Exploited = a0.Exploited; f.Url = "https://msrc.microsoft.com/update-guide/vulnerability/" + cve;
                f.Product = a0.ProductName.Length > 0 ? a0.ProductName : os.ProductName; f.Installed = os.FullBuild; f.Description = a0.Title;
                List<string> ev = new List<string>(); bool patched = false; string fix = ""; string status = "vulnerable";
                foreach (MsrcRec r in applicable)
                {
                    int[] fixedB = ParseBuild(r.FixedBuild); if (fixedB == null) continue;
                    bool ok = host[3] >= fixedB[3]; fix = "KB" + r.Kb + " · build " + r.FixedBuild;
                    ev.Add("build comparison: host " + os.FullBuild + (ok ? " ≥ " : " < ") + "fixed " + r.FixedBuild + " (KB" + r.Kb + ")" + (ok ? " → patched" : " → not patched"));
                    if (ok) { patched = true; break; }
                }
                if (!patched) foreach (MsrcRec r in applicable)
                    {
                        if (ParseBuild(r.FixedBuild) != null) continue; string by; bool ok = graph.Satisfies(knownKbs, r.Kb, out by); if (fix.Length == 0) fix = "KB" + r.Kb;
                        ev.Add("KB check: KB" + r.Kb + (ok ? (by == r.Kb ? " is installed" : " is superseded by installed KB" + by) : " not installed and nothing installed supersedes it") + " (" + NormProduct(r.ProductName) + ")");
                        if (ok) { patched = true; break; }
                    }
                if (patched) status = "patched";
                else if (reboot != null && reboot.Pending) { foreach (MsrcRec r in applicable) if (knownKbs.Contains(r.Kb)) { status = "reboot pending"; ev.Add("KB" + r.Kb + " is installed but the running build is still " + os.FullBuild + " · " + reboot.Why); break; } }
                f.Status = status; f.Fix = fix; f.Evidence = string.Join(" | ", ev.ToArray()); out_.Add(f);
            }
            return out_;
        }

        /// <summary>Findings for one installed product against the NVD records fetched for it: only versions that actually fall in a vulnerable range (or match exactly) count.</summary>
        public static List<Finding> ThirdParty(Software sw, List<CveRecord> cves)
        {
            List<Finding> l = new List<Finding>(); if (sw.Vendor == null || string.IsNullOrEmpty(sw.Version)) return l;
            foreach (CveRecord c in cves)
            {
                List<CpeMatch> hits = new List<CpeMatch>(); foreach (CpeMatch m in c.Matches) if (string.Equals(m.Vendor, sw.Vendor, StringComparison.OrdinalIgnoreCase) && string.Equals(m.Product, sw.Product, StringComparison.OrdinalIgnoreCase)) hits.Add(m);
                if (hits.Count == 0) continue;
                List<string> ev = new List<string>(); bool matched = false, unbounded = false;
                foreach (CpeMatch m in hits) { bool h = m.Hits(sw.Version); if (h) matched = true; if (m.Unbounded) unbounded = true; ev.Add((h ? "✓ " : "✗ ") + m.Range); }
                Finding f = new Finding(); f.Cve = c.Id; f.Title = c.Description.Length > 140 ? c.Description.Substring(0, 140).TrimEnd() + "…" : c.Description; f.Description = c.Description; f.Severity = c.Severity; f.Cvss = c.Cvss; f.Source = "NVD"; f.Product = sw.Name; f.Installed = sw.Version; f.Url = "https://nvd.nist.gov/vuln/detail/" + c.Id;
                f.Fix = FixHint(hits); f.Release = c.Published.HasValue ? c.Published.Value.ToString("yyyy-MM") : "";
                if (matched) { f.Status = "vulnerable"; f.Evidence = "installed " + sw.Version + " vs " + sw.Cpe + ": " + string.Join("; ", ev.ToArray()); }
                else if (unbounded) { f.Status = "unconfirmed"; f.Evidence = "NVD lists " + sw.Cpe + " with no version bounds; not verifiable against " + sw.Version; }
                else continue; // NVD returned it for this version but the local check disagrees: the confirm-only rule wins
                l.Add(f);
            }
            return l;
        }
        static string FixHint(List<CpeMatch> hits) { string best = null; foreach (CpeMatch m in hits) { string e = m.EndExc; if (e == null) continue; int r; if (best == null || (Ver.TryCompare(e, best, out r) && r > 0)) best = e; } return best != null ? "upgrade to " + best + " or later" : ""; }

        /// <summary>What Windows Update itself says is missing: one finding per CVE named by an offered security update.</summary>
        public static List<Finding> FromWindowsUpdate(List<MissingUpdate> missing, OsInfo os)
        {
            List<Finding> l = new List<Finding>();
            foreach (MissingUpdate m in missing) foreach (string cve in m.Cves)
                {
                    Finding f = new Finding(); f.Cve = cve; f.Title = m.Title; f.Severity = m.Severity; f.Source = "Windows Update"; f.Product = ProductOf(m.Title, os); f.Installed = os.FullBuild; f.Fix = m.Kb.Length > 0 ? "KB" + m.Kb : m.Title; f.Status = "update available";
                    f.Evidence = "Windows Update offers " + (m.Kb.Length > 0 ? "KB" + m.Kb : "this update") + " (" + m.Kind + (m.Downloaded ? ", downloaded" : ", not downloaded") + ") and lists " + cve + " among the CVEs it fixes"; f.Url = "https://msrc.microsoft.com/update-guide/vulnerability/" + cve; f.Description = m.Title;
                    l.Add(f);
                }
            return l;
        }
        static string ProductOf(string title, OsInfo os)
        {
            string t = title ?? ""; int i = t.IndexOf(" for ", StringComparison.OrdinalIgnoreCase); if (i > 0) { string p = t.Substring(i + 5); int j = p.IndexOf(" (KB", StringComparison.OrdinalIgnoreCase); if (j > 0) p = p.Substring(0, j); j = p.IndexOf(" for ", StringComparison.OrdinalIgnoreCase); if (j > 0) p = p.Substring(0, j); return p.Trim(); }
            return os.ProductName;
        }
    }

    // ───────────────────────────── the scan ─────────────────────────────
    /// <summary>Runs inventory, feeds and resolvers in order, reporting progress; results are read by the UI after each phase.</summary>
    public class VulnScan
    {
        public bool DoWua = true, DoMsrc = true, DoNvd = true, DoKev = true, DoEpss = true; public int Months = 3, HistoryLimit = 1000; public string NvdApiKey = ""; public FeedCache Cache; public int NvdLimit = int.MaxValue;   // Months: the fewest MSRC releases to check; Run() widens it to the host's patch level (MsrcWindow)
        public OsInfo Os; public RebootInfo Reboot = new RebootInfo(); public readonly List<Hotfix> Hotfixes = new List<Hotfix>(); public readonly List<Software> Software = new List<Software>(); public readonly List<MissingUpdate> Missing = new List<MissingUpdate>(); public readonly List<Finding> Findings = new List<Finding>();
        public readonly HashSet<string> KnownKbs = new HashSet<string>(); public readonly List<string> Log = new List<string>(), Errors = new List<string>(), Releases = new List<string>(); public Dictionary<string, KevEntry> KevCatalog = new Dictionary<string, KevEntry>();
        public event Action<string> Progress; public event Action Phase; public event Action Finished; public volatile bool Cancel; public bool Running; public DateTime StartedAt, FinishedAt; public string Stage = "";
        /// <summary>(step label, state, note) - pending · running · done · failed · skipped - for the progress strip.</summary>
        public event Action<string, string, string> Step; public volatile float Fraction = -1;
        public static readonly string[] StepLabels = { "Inventory", "Windows Update", "Microsoft CVEs", "Third-party (NVD)", "KEV", "EPSS" };
        /// <summary>The most monthly MSRC releases a scan will ever fetch, however stale the host.</summary>
        public const int MaxMonths = 36;
        /// <summary>The date of the newest installed OS update - the host's patch level. QFE rows (OS servicing) win; failing those, successful Windows Update installations of Windows updates. Definitions, Defender platform, MSRT and driver rows never count: Windows Update keeps installing those on a host whose cumulative updates are months behind.</summary>
        public static DateTime? NewestUpdateDate(IEnumerable<Hotfix> hotfixes)
        {
            DateTime? qfe = null, wu = null;
            foreach (Hotfix h in hotfixes)
            {
                if (!h.InstalledOn.HasValue) continue;
                if (h.Source == "QFE") { if (!qfe.HasValue || h.InstalledOn.Value > qfe.Value) qfe = h.InstalledOn; }
                else if (h.Source == "WU history" && h.Description == "installation" && h.Result == "succeeded" && h.Kb.Length > 0 && IsWindowsServicing(h.Title)) { if (!wu.HasValue || h.InstalledOn.Value > wu.Value) wu = h.InstalledOn; }
            }
            return qfe.HasValue ? qfe : wu;
        }
        static bool IsWindowsServicing(string title)
        {
            string t = (title ?? "").ToLowerInvariant(); if (!t.Contains("windows")) return false;
            foreach (string skip in new string[] { "security intelligence", "antivirus", "defender", "definition", "malicious software removal", "driver" }) if (t.Contains(skip)) return false;
            return true;
        }
        /// <summary>How many monthly MSRC releases to check: the months since the newest installed update, plus one so the release that update came from is included - never fewer than the configured minimum, never more than MaxMonths. Without a dated update the OS install date stands in; without that, the cap: a host that cannot show its patch level gets the widest check, not the narrowest. A fixed 3 months made a host that was a year behind look clean, because its missing fixes were all in older releases.</summary>
        /// <summary>A patch-level date more than a day ahead of now cannot be true; callers flag it and MsrcWindow ignores it.</summary>
        public static bool FutureDate(DateTime? d, DateTime now) { return d.HasValue && d.Value > now.AddDays(1); }
        public static int MsrcWindow(DateTime? newestUpdate, DateTime? osInstalled, DateTime now, int minimum)
        {
            DateTime? since = newestUpdate.HasValue ? newestUpdate : osInstalled;
            // a date after today is not a patch level (a doctored bundle, a wrong clock): it gets the widest window, never the narrowest (PT-38)
            int months = MaxMonths; if (since.HasValue && !FutureDate(since, now)) months = (now.Year - since.Value.Year) * 12 + (now.Month - since.Value.Month) + 1;
            return Math.Max(Math.Max(1, minimum), Math.Min(MaxMonths, months));
        }
        void StepTo(string label, string state, string note) { if (Step != null) Step(label, state, note); }
        readonly object sync = new object();
        void Say(string s) { Stage = s; lock (sync) Log.Add(DateTime.Now.ToString("HH:mm:ss") + "  " + s); if (Progress != null) Progress(s); }
        void Fail(string what, Exception ex) { string m = what + ": " + ex.Message; lock (sync) Errors.Add(m); Say("✗ " + m); }
        void Done() { if (Phase != null) Phase(); }
        public void RunInBackground() { Thread t = new Thread(Run); t.IsBackground = true; t.Name = "vuln-scan"; t.Start(); }
        public void Run()
        {
            Running = true; StartedAt = DateTime.Now;
            try
            {
                // 1 · inventory
                StepTo("Inventory", "running", null); if (!DoWua) StepTo("Windows Update", "skipped", null); if (!DoMsrc) StepTo("Microsoft CVEs", "skipped", null); if (!DoNvd) StepTo("Third-party (NVD)", "skipped", null); if (!DoKev) StepTo("KEV", "skipped", null); if (!DoEpss) StepTo("EPSS", "skipped", null);
                Say("reading the OS build and pending-reboot state…"); Os = Inventory.Os(); Reboot = Inventory.Reboot(); Done();
                Say("listing installed software…"); try { lock (sync) { Software.Clear(); Software.AddRange(Inventory.Installed()); } } catch (Exception ex) { Fail("installed software", ex); } Done();
                Say("reading hotfixes (QFE) and the servicing store (CBS)…");
                lock (sync) Hotfixes.Clear();
                try { foreach (Hotfix h in Inventory.Qfe()) lock (sync) Hotfixes.Add(h); } catch (Exception ex) { Fail("hotfixes (WMI)", ex); }
                try { int pend; foreach (Hotfix h in Inventory.Cbs(out pend)) lock (sync) Hotfixes.Add(h); } catch (Exception ex) { Fail("CBS packages", ex); }
                Done(); if (Cancel) return;
                StepTo("Inventory", "done", Software.Count + " programs · " + Hotfixes.Count + " hotfix rows");
                if (DoWua)
                {
                    StepTo("Windows Update", "running", null); Say("reading the Windows Update history…");
                    try { foreach (Hotfix h in Inventory.WuHistory(HistoryLimit)) lock (sync) Hotfixes.Add(h); } catch (Exception ex) { Fail("Windows Update history", ex); }
                    Done(); if (Cancel) return;
                }
                lock (sync) foreach (Hotfix h in Hotfixes) if (h.Kb.Length > 0 && (h.Source != "WU history" || (h.Result == "succeeded" && h.Description == "installation"))) KnownKbs.Add(h.Kb);
                if (DoWua)
                {
                    try { List<MissingUpdate> mm = Inventory.WuMissing(Say); lock (sync) { Missing.Clear(); Missing.AddRange(mm); } Say("Windows Update offers " + mm.Count + " update(s)"); StepTo("Windows Update", "done", mm.Count + " offered"); }
                    catch (Exception ex) { Fail("Windows Update search", ex); StepTo("Windows Update", "failed", ex.Message.Length > 40 ? ex.Message.Substring(0, 40) + "…" : ex.Message); }
                    Done(); if (Cancel) return;
                }
                // 2 · feeds + resolve, 3 · enrichment: VulnEnrich (Enrich.cs), the same code `enrich` runs on a connected box from a collected bundle
                VulnEnrich en = NewEnricher(); en.Run(); KevCatalog = en.KevCatalog; lock (sync) { Releases.Clear(); Releases.AddRange(en.Releases); }
                int openN = 0; foreach (Finding f in Findings) if (f.Open) openN++;
                Say((Cancel ? "cancelled · " : "done · ") + openN + " open finding(s), " + Findings.Count + " total, in " + Fmt.Secs((DateTime.Now - StartedAt).TotalSeconds));
            }
            catch (Exception ex) { Fail("scan", ex); }
            finally { Running = false; FinishedAt = DateTime.Now; if (Finished != null) Finished(); }
        }
        /// <summary>The enricher wired to this scan: the inventory it just collected in; findings, progress and steps out. The same class runs `enrich` on a connected box from a bundle.</summary>
        VulnEnrich NewEnricher()
        {
            VulnEnrich e = new VulnEnrich(); e.Os = Os; e.Reboot = Reboot; e.Software = SoftwareSnapshot(); e.KnownKbs = KnownKbs; e.Missing = MissingSnapshot(); e.NewestUpdate = NewestUpdateDate(HotfixSnapshot());
            e.DoWua = DoWua; e.DoMsrc = DoMsrc; e.DoNvd = DoNvd; e.DoKev = DoKev; e.DoEpss = DoEpss; e.Months = Months; e.NvdLimit = NvdLimit; e.NvdApiKey = NvdApiKey; e.Cache = Cache; e.KevCatalog = KevCatalog;
            e.Progress = Say; e.Step = StepTo; e.Failed = Fail; e.Cancelled = delegate { return Cancel; }; e.FractionChanged = delegate (float f) { Fraction = f; };
            e.Published = delegate (List<Finding> l) { lock (sync) { Findings.Clear(); Findings.AddRange(l); } Done(); };
            return e;
        }
        /// <summary>Look up just these programs (the Software view's action) and merge the results into the existing findings.</summary>
        public void LookupInBackground(List<Software> items)
        {
            Thread t = new Thread(delegate ()
            {
                Running = true;
                try { VulnEnrich e = NewEnricher(); e.Seed(FindingsSnapshot()); e.LookupSoftware(items); KevCatalog = e.KevCatalog; }
                catch (Exception ex) { Fail("lookup", ex); }
                finally { Running = false; if (Finished != null) Finished(); }
            });
            t.IsBackground = true; t.Name = "vuln-lookup"; t.Start();
        }
        public List<Finding> FindingsSnapshot() { lock (sync) return new List<Finding>(Findings); }
        public List<Software> SoftwareSnapshot() { lock (sync) return new List<Software>(Software); }
        public List<Hotfix> HotfixSnapshot() { lock (sync) return new List<Hotfix>(Hotfixes); }
        public List<MissingUpdate> MissingSnapshot() { lock (sync) return new List<MissingUpdate>(Missing); }
        public List<string> LogSnapshot() { lock (sync) return new List<string>(Log); }
    }
}

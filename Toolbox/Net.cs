// Network engines: the domain/IP extractor, the hosts file, the firewall rule, reachability checks and the
// live connection table. Ported from the scripts in the folders beside this one so the app is compatible with
// what they wrote (same "# BLOCK-HOSTS" marker, same rule name, same backup folder). Pure logic, no UI.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace PSTools
{
    // ───────────────────────────── extraction ─────────────────────────────
    public enum Kind { Domain, IPv4, IPv6, Invalid }

    public class Target
    {
        public string Value; public Kind Kind; public string Source; public int Line;
        public override string ToString() { return Value; }
    }

    public static class Extractor
    {
        static readonly HashSet<string> KnownTld = new HashSet<string>(("com net org edu gov mil int arpa io dev app ai co info biz me tv cc xyz cloud online site tech store shop blog news email network systems solutions services digital software agency company global group live media space today top club vip pro museum name mobi asia jobs tel travel aero coop post cyber tools zone host link click download page web world run team life works studio design center city expert guru ninja rocks fund money finance bank health care clinic legal law tax market sale deals codes gift games game play events photo photos video film movie music audio radio social community forum wiki review directory guide academy school college university institute science research lab data analytics server hosting domains mail mobile phone software hardware technology energy farm garden cafe restaurant bar coffee kitchen food fitness gym sport sports golf tennis cars auto rent taxi hotel holiday travel casino bet poker ltd llc inc gmbh plc srl").Split(' '));
        static readonly HashSet<string> ExtCollide = new HashSet<string>("md sh py pl rs ps so cs gz db js ts rb go vb".Split(' '));
        static readonly Regex RxIPv4 = new Regex(@"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])", RegexOptions.Compiled);
        // candidate runs of hex groups and colons; IPAddress.TryParse decides (the script's pattern could not match the "beef::1" form)
        static readonly Regex RxIPv6 = new Regex(@"(?i)(?<![\w:.])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![\w:.])", RegexOptions.Compiled);
        static readonly Regex RxDomain = new Regex(@"(?i)(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:xn--[a-z0-9-]{2,59}|[a-z]{2,24})(?![\w-])", RegexOptions.Compiled);

        public static string Normalize(string l)
        {
            string s = l;
            s = Regex.Replace(s, @"(?i)hxxps?://", "http://");
            s = Regex.Replace(s, @"(?i)\[\s*(?:\.|dot)\s*\]|\(\s*(?:\.|dot)\s*\)|\{\s*(?:\.|dot)\s*\}", ".");
            s = Regex.Replace(s, @"(?i)\[\s*:\s*\]|\(\s*:\s*\)", ":");
            s = s.Replace("\\.", ".");
            s = Regex.Replace(s, @"(?i)\bdot\b", ".");
            s = Regex.Replace(s, @"\s*\.\s*", ".");
            return s;
        }

        /// <summary>Every domain and IP in the lines, first-seen order, de-duplicated.</summary>
        public static List<Target> Extract(IEnumerable<string> lines)
        {
            List<Target> outp = new List<Target>(); Dictionary<string, Target> seen = new Dictionary<string, Target>(StringComparer.OrdinalIgnoreCase);
            int no = 0;
            foreach (string raw in lines)
            {
                no++;
                if (string.IsNullOrWhiteSpace(raw) || raw.TrimStart().StartsWith("#")) continue;
                string line = Normalize(raw);
                List<int[]> v4 = new List<int[]>();
                foreach (Match m in RxIPv4.Matches(line))
                {
                    v4.Add(new int[] { m.Index, m.Length });
                    IPAddress ip; if (IPAddress.TryParse(m.Value, out ip)) Add(outp, seen, m.Value, Kind.IPv4, raw, no);
                }
                foreach (Match m in RxIPv6.Matches(line))
                {
                    IPAddress ip; string v = m.Value;
                    if ((v.Contains("::") || v.Split(':').Length == 8) && v.IndexOf(':') != v.LastIndexOf(':') && IPAddress.TryParse(v, out ip) && ip.AddressFamily == AddressFamily.InterNetworkV6) Add(outp, seen, ip.ToString(), Kind.IPv6, raw, no);
                }
                foreach (Match m in RxDomain.Matches(line))
                {
                    bool inside = false; foreach (int[] f in v4) if (m.Index >= f[0] && m.Index < f[0] + f[1]) { inside = true; break; }
                    if (inside) continue;
                    string d = m.Value.ToLowerInvariant().TrimEnd('.');
                    if (IsDomain(d, false)) Add(outp, seen, d, Kind.Domain, raw, no);
                }
            }
            return outp;
        }
        /// <summary>The script's domain rule: a known TLD (or punycode, or any 2-letter one that is not a file extension), and not localhost/example/test/invalid unless allowed.</summary>
        public static bool IsDomain(string d, bool allowReserved)
        {
            if (string.IsNullOrEmpty(d)) return false; Match m = RxDomain.Match(d); if (!m.Success || m.Value.Length != d.Length) return false;
            string[] labels = d.Split('.'); string tld = labels[labels.Length - 1];
            if (Regex.IsMatch(tld, @"^\d+$")) return false;
            bool ok = false;
            if (tld.StartsWith("xn--")) ok = true; else if (KnownTld.Contains(tld)) ok = true; else if (tld.Length == 2) ok = !(ExtCollide.Contains(tld) && labels.Length == 2);
            if (!ok) return false;
            if (!allowReserved && labels.Length == 2 && Regex.IsMatch(labels[0], "^(localhost|example|test|invalid)$")) return false;
            return true;
        }
        static void Add(List<Target> outp, Dictionary<string, Target> seen, string v, Kind k, string src, int line)
        {
            if (seen.ContainsKey(v)) return;
            Target t = new Target(); t.Value = v; t.Kind = k; t.Source = src.Trim(); t.Line = line; seen[v] = t; outp.Add(t);
        }
        /// <summary>What a single typed value is: a domain, an IP, or nothing usable.</summary>
        public static Kind Classify(string value)
        {
            string v = (value ?? "").Trim().ToLowerInvariant();
            if (v.Length == 0) return Kind.Invalid;
            IPAddress ip;
            if (IPAddress.TryParse(v, out ip)) return ip.AddressFamily == AddressFamily.InterNetworkV6 ? Kind.IPv6 : (RxIPv4.IsMatch(v) && RxIPv4.Match(v).Value == v ? Kind.IPv4 : Kind.Invalid);
            return IsDomain(v.TrimEnd('.'), true) ? Kind.Domain : Kind.Invalid;   // a typed value: example.com or localhost are allowed on purpose
        }
        /// <summary>The www. variant for bare registrable names; subdomains stay as they are.</summary>
        public static List<string> ExpandDomains(IEnumerable<string> domains)
        {
            List<string> outp = new List<string>(); HashSet<string> set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string d in domains)
            {
                if (set.Add(d)) outp.Add(d);
                if (d.Split('.').Length == 2 && !d.StartsWith("www.")) { string w = "www." + d; if (set.Add(w)) outp.Add(w); }
            }
            return outp;
        }
    }

    // ───────────────────────────── the hosts file ─────────────────────────────
    public class HostsEntry { public string Host, Sink; public int LineNo; public bool Ours; }

    public class Hosts
    {
        public const string Marker = "# BLOCK-HOSTS";
        public string Path = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32\\drivers\\etc\\hosts");
        public string BackupDir = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "BlockHosts\\backups");

        public string[] Read() { return File.Exists(Path) ? File.ReadAllLines(Path) : new string[0]; }
        public void Write(IList<string> lines) { File.WriteAllLines(Path, lines, Encoding.ASCII); }
        public string Backup()
        {
            Directory.CreateDirectory(BackupDir);
            string dest = System.IO.Path.Combine(BackupDir, "hosts-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".bak");
            if (File.Exists(Path)) File.Copy(Path, dest, true); else File.WriteAllText(dest, "");
            return dest;
        }
        public List<FileInfo> Backups()
        {
            List<FileInfo> l = new List<FileInfo>();
            if (Directory.Exists(BackupDir)) foreach (string f in Directory.GetFiles(BackupDir, "hosts-*.bak")) l.Add(new FileInfo(f));
            l.Sort(delegate (FileInfo a, FileInfo b) { return b.LastWriteTime.CompareTo(a.LastWriteTime); });
            return l;
        }
        /// <summary>Entries this tool added (the marker) and, when asked, every other mapping too.</summary>
        public List<HostsEntry> Entries(bool includeOthers)
        {
            List<HostsEntry> l = new List<HostsEntry>(); int n = 0;
            foreach (string line in Read())
            {
                n++;
                string t = line.Trim(); if (t.Length == 0 || t.StartsWith("#")) continue;
                bool ours = Regex.IsMatch(line, Regex.Escape(Marker) + @"\s*$");
                string body = ours ? Regex.Replace(line, Regex.Escape(Marker), "") : line;
                int hash = body.IndexOf('#'); if (hash >= 0) body = body.Substring(0, hash);
                string[] parts = Regex.Split(body.Trim(), @"\s+");
                if (parts.Length < 2) continue;
                if (!ours && !includeOthers) continue;
                for (int i = 1; i < parts.Length; i++) { HostsEntry e = new HostsEntry(); e.Sink = parts[0]; e.Host = parts[i]; e.LineNo = n; e.Ours = ours; l.Add(e); }
            }
            return l;
        }
        public class AddResult { public int Added, Skipped; public string Backup; public List<string> AddedHosts = new List<string>(); }
        public AddResult Add(IEnumerable<string> domains, string sink)
        {
            AddResult r = new AddResult(); r.Backup = Backup();
            List<string> lines = new List<string>(Read());
            HashSet<string> present = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string l in lines) foreach (string tok in Regex.Split(l, @"\s+")) if (tok.Length > 0 && !tok.StartsWith("#") && !char.IsDigit(tok[0])) present.Add(tok);
            List<string> append = new List<string>();
            foreach (string d in domains)
            {
                if (present.Contains(d)) { r.Skipped++; continue; }
                append.Add(sink + "\t" + d + "\t" + Marker); r.AddedHosts.Add(d); present.Add(d); r.Added++;
            }
            if (append.Count > 0)
            {
                if (lines.Count > 0 && lines[lines.Count - 1].Trim().Length > 0) lines.Add("");
                lines.Add("# added by Block-Hosts " + DateTime.Now.ToString("yyyy-MM-dd HH:mm"));
                lines.AddRange(append);
                Write(lines);
            }
            return r;
        }
        public class RemoveResult { public int Removed; public string Backup; }
        /// <summary>Drops only lines carrying the marker whose host is in the set. Hand-written lines are never touched.</summary>
        public RemoveResult Remove(IEnumerable<string> hosts)
        {
            RemoveResult r = new RemoveResult(); HashSet<string> set = new HashSet<string>(hosts, StringComparer.OrdinalIgnoreCase);
            r.Backup = Backup();
            List<string> kept = new List<string>();
            foreach (string l in Read())
            {
                if (Regex.IsMatch(l, Regex.Escape(Marker) + @"\s*$"))
                {
                    string[] parts = Regex.Split(Regex.Replace(l, Regex.Escape(Marker), "").Trim(), @"\s+");
                    if (parts.Length >= 2 && set.Contains(parts[1])) { r.Removed++; continue; }
                }
                kept.Add(l);
            }
            Write(kept);
            return r;
        }
        public string Restore(string backupFile) { string safety = Backup(); File.Copy(backupFile, Path, true); return safety; }
    }

    // ───────────────────────────── the firewall rule (COM, no cmdlets needed) ─────────────────────────────
    public static class Firewall
    {
        public const string RuleName = "BLOCK-HOSTS blocked IPs";
        static dynamic Policy() { Type t = Type.GetTypeFromProgID("HNetCfg.FwPolicy2"); if (t == null) throw new InvalidOperationException("Windows Firewall COM API not available"); return Activator.CreateInstance(t); }
        static dynamic FindRule(dynamic pol) { foreach (dynamic r in pol.Rules) { if (r.Name == RuleName) return r; } return null; }
        static string Clean(string a)
        {
            string s = a.Trim();
            if (s.EndsWith("/255.255.255.255")) s = s.Substring(0, s.Length - 16); if (s.EndsWith("/32")) s = s.Substring(0, s.Length - 3); if (s.EndsWith("/128")) s = s.Substring(0, s.Length - 4);
            int dash = s.IndexOf('-'); if (dash > 0 && s.IndexOf(':') < 0) { string x = s.Substring(0, dash), y = s.Substring(dash + 1); if (x == y) s = x; }   // the COM API reports a single address as "a-a"
            return s;
        }
        public static bool Available() { try { Policy(); return true; } catch { return false; } }
        /// <summary>The addresses in the rule; empty when the rule does not exist.</summary>
        public static List<string> GetBlocked()
        {
            List<string> l = new List<string>();
            try
            {
                dynamic r = FindRule(Policy()); if (r == null) return l;
                string addrs = (string)r.RemoteAddresses;
                if (string.IsNullOrEmpty(addrs) || addrs == "*") return l;
                foreach (string a in addrs.Split(',')) { string c = Clean(a); if (c.Length > 0 && !l.Contains(c)) l.Add(c); }
            }
            catch { }
            return l;
        }
        /// <summary>Replaces the rule's address set; an empty set removes the rule. Needs administrator.</summary>
        public static void SetBlocked(IList<string> ips)
        {
            dynamic pol = Policy(); dynamic r = FindRule(pol);
            if (ips == null || ips.Count == 0) { if (r != null) pol.Rules.Remove(RuleName); return; }
            string joined = string.Join(",", ips);
            if (r != null) { r.RemoteAddresses = joined; return; }
            dynamic rule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));
            rule.Name = RuleName; rule.Description = "Outbound block list managed by Block-Hosts / PowerTower";
            rule.Direction = 2;            // NET_FW_RULE_DIR_OUT
            rule.Action = 0;               // NET_FW_ACTION_BLOCK
            rule.Protocol = 256;           // any
            rule.Profiles = 0x7FFFFFFF;    // all
            rule.RemoteAddresses = joined; rule.Enabled = true;
            pol.Rules.Add(rule);
        }
    }

    // ───────────────────────────── reachability ─────────────────────────────
    public class PortResult { public int Port; public bool Ok; public int Ms; public string Error; }
    public class ReachRow
    {
        public Target Target; public List<string> Resolved = new List<string>(); public int DnsMs = -1; public string DnsError;
        public int PingMs = -2;                 // -2 not run, -1 timeout / failed
        public Dictionary<int, PortResult> Ports = new Dictionary<int, PortResult>();
        public string Status = "pending"; public bool Done;
        public string Value { get { return Target.Value; } }
        public string PortsSummary { get { List<string> l = new List<string>(); foreach (KeyValuePair<int, PortResult> p in Ports) l.Add(p.Key + (p.Value.Ok ? " ✓" : " ✗")); return string.Join("  ", l); } }
    }

    public class Reach
    {
        public int[] Ports = new int[] { 80, 443 }; public double TimeoutSec = 3; public int Concurrency = 32; public bool DoPing = true;
        public event Action<ReachRow> RowDone; public event Action<int, int> Progress; public event Action Finished;
        volatile bool cancel; public void Cancel() { cancel = true; }

        public void Run(List<ReachRow> rows)
        {
            cancel = false; int done = 0, total = rows.Count;
            Thread t = new Thread(delegate ()
            {
                using (SemaphoreSlim sem = new SemaphoreSlim(Math.Max(1, Concurrency)))
                {
                    List<ManualResetEvent> waits = new List<ManualResetEvent>();
                    foreach (ReachRow row in rows)
                    {
                        if (cancel) break;
                        sem.Wait(); ManualResetEvent ev = new ManualResetEvent(false); waits.Add(ev); ReachRow r = row;
                        ThreadPool.QueueUserWorkItem(delegate { try { Check(r); } finally { r.Done = true; int d = Interlocked.Increment(ref done); if (RowDone != null) RowDone(r); if (Progress != null) Progress(d, total); sem.Release(); ev.Set(); } });
                    }
                    foreach (ManualResetEvent ev in waits) ev.WaitOne();
                }
                if (Finished != null) Finished();
            });
            t.IsBackground = true; t.Start();
        }
        void Check(ReachRow r)
        {
            int timeoutMs = (int)(TimeoutSec * 1000);
            List<IPAddress> addrs = new List<IPAddress>();
            if (r.Target.Kind == Kind.Domain)
            {
                Stopwatch sw = Stopwatch.StartNew();
                try { foreach (IPAddress a in Dns.GetHostAddresses(r.Target.Value)) { addrs.Add(a); r.Resolved.Add(a.ToString()); } r.DnsMs = (int)sw.ElapsedMilliseconds; }
                catch (Exception ex) { r.DnsError = ex.Message; r.DnsMs = -1; }
            }
            else { IPAddress ip; if (IPAddress.TryParse(r.Target.Value, out ip)) { addrs.Add(ip); r.Resolved.Add(ip.ToString()); r.DnsMs = 0; } }
            if (addrs.Count == 0) { r.Status = r.Target.Kind == Kind.Domain ? "no DNS" : "invalid"; return; }
            IPAddress first = addrs[0];
            if (DoPing && !cancel)
            {
                try { using (Ping p = new Ping()) { PingReply rep = p.Send(first, timeoutMs); r.PingMs = rep.Status == IPStatus.Success ? (int)rep.RoundtripTime : -1; } } catch { r.PingMs = -1; }
            }
            foreach (int port in Ports)
            {
                if (cancel) break;
                PortResult pr = new PortResult(); pr.Port = port; Stopwatch sw = Stopwatch.StartNew();
                Socket s = null;
                try
                {
                    s = new Socket(first.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                    IAsyncResult ar = s.BeginConnect(first, port, null, null);
                    if (ar.AsyncWaitHandle.WaitOne(timeoutMs)) { s.EndConnect(ar); pr.Ok = true; } else { pr.Error = "timeout"; }
                }
                catch (Exception ex) { pr.Error = ex.Message; }
                finally { try { if (s != null) s.Close(); } catch { } }
                pr.Ms = (int)sw.ElapsedMilliseconds; lock (r.Ports) r.Ports[port] = pr;
            }
            bool anyPort = false; foreach (PortResult p in r.Ports.Values) if (p.Ok) anyPort = true;
            r.Status = anyPort ? "reachable" : (r.PingMs >= 0 ? "ping only" : (Ports.Length == 0 && !DoPing ? "resolves" : "unreachable"));
        }
    }

    // ───────────────────────────── live connections (iphlpapi) ─────────────────────────────
    public class Conn
    {
        public string Proto, Local, Remote, State, Process, Host; public int LocalPort, RemotePort, Pid; public DateTime FirstSeen, LastSeen; public bool Alive = true;
        public string Key { get { return Proto + "|" + Local + ":" + LocalPort + "|" + Remote + ":" + RemotePort + "|" + Pid; } }
        public bool Loopback { get { return Remote == "127.0.0.1" || Remote == "::1" || Local == "127.0.0.1" || Local == "::1" || Remote == "0.0.0.0" || Remote == "::"; } }
    }

    public static class ConnTable
    {
        [DllImport("iphlpapi.dll", SetLastError = true)] static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int family, int tableClass, uint reserved);
        [DllImport("iphlpapi.dll", SetLastError = true)] static extern uint GetExtendedUdpTable(IntPtr table, ref int size, bool order, int family, int tableClass, uint reserved);
        static readonly string[] States = { "", "CLOSED", "LISTENING", "SYN_SENT", "SYN_RCVD", "ESTABLISHED", "FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT", "CLOSING", "LAST_ACK", "TIME_WAIT", "DELETE_TCB" };
        static int Port(uint netOrder) { return (int)(((netOrder & 0xFF) << 8) | ((netOrder >> 8) & 0xFF)); }
        static string V4(uint a) { return new IPAddress(a).ToString(); }
        static string V6(byte[] b) { return new IPAddress(b).ToString(); }

        /// <summary>A snapshot of every TCP and UDP endpoint with its owning PID.</summary>
        public static List<Conn> Snapshot(bool tcp, bool udp)
        {
            List<Conn> l = new List<Conn>(); DateTime now = DateTime.Now;
            if (tcp) { Tcp4(l, now); Tcp6(l, now); }
            if (udp) { Udp4(l, now); Udp6(l, now); }
            return l;
        }
        static IntPtr Fetch(bool tcpTable, int family, int cls, out int size)
        {
            size = 0;
            if (tcpTable) GetExtendedTcpTable(IntPtr.Zero, ref size, true, family, cls, 0); else GetExtendedUdpTable(IntPtr.Zero, ref size, true, family, cls, 0);
            IntPtr buf = Marshal.AllocHGlobal(size);
            uint rc = tcpTable ? GetExtendedTcpTable(buf, ref size, true, family, cls, 0) : GetExtendedUdpTable(buf, ref size, true, family, cls, 0);
            if (rc != 0) { Marshal.FreeHGlobal(buf); return IntPtr.Zero; }
            return buf;
        }
        static void Tcp4(List<Conn> l, DateTime now)
        {
            int size; IntPtr buf = Fetch(true, 2, 5, out size); if (buf == IntPtr.Zero) return;
            try
            {
                int n = Marshal.ReadInt32(buf); IntPtr p = (IntPtr)((long)buf + 4);
                for (int i = 0; i < n; i++)
                {
                    uint state = (uint)Marshal.ReadInt32(p, 0), la = (uint)Marshal.ReadInt32(p, 4), lp = (uint)Marshal.ReadInt32(p, 8), ra = (uint)Marshal.ReadInt32(p, 12), rp = (uint)Marshal.ReadInt32(p, 16); int pid = Marshal.ReadInt32(p, 20);
                    Conn c = new Conn(); c.Proto = "TCP"; c.Local = V4(la); c.LocalPort = Port(lp); c.Remote = V4(ra); c.RemotePort = Port(rp); c.State = state < States.Length ? States[state] : state.ToString(); c.Pid = pid; c.FirstSeen = c.LastSeen = now;
                    if (c.State == "LISTENING") { c.Remote = ""; c.RemotePort = 0; }
                    l.Add(c); p = (IntPtr)((long)p + 24);
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
        static void Tcp6(List<Conn> l, DateTime now)
        {
            int size; IntPtr buf = Fetch(true, 23, 5, out size); if (buf == IntPtr.Zero) return;
            try
            {
                int n = Marshal.ReadInt32(buf); IntPtr p = (IntPtr)((long)buf + 4);
                for (int i = 0; i < n; i++)
                {
                    byte[] la = new byte[16]; Marshal.Copy(p, la, 0, 16); uint lp = (uint)Marshal.ReadInt32(p, 20); byte[] ra = new byte[16]; Marshal.Copy((IntPtr)((long)p + 24), ra, 0, 16); uint rp = (uint)Marshal.ReadInt32(p, 44); uint state = (uint)Marshal.ReadInt32(p, 48); int pid = Marshal.ReadInt32(p, 52);
                    Conn c = new Conn(); c.Proto = "TCP6"; c.Local = V6(la); c.LocalPort = Port(lp); c.Remote = V6(ra); c.RemotePort = Port(rp); c.State = state < States.Length ? States[state] : state.ToString(); c.Pid = pid; c.FirstSeen = c.LastSeen = now;
                    if (c.State == "LISTENING") { c.Remote = ""; c.RemotePort = 0; }
                    l.Add(c); p = (IntPtr)((long)p + 56);
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
        static void Udp4(List<Conn> l, DateTime now)
        {
            int size; IntPtr buf = Fetch(false, 2, 1, out size); if (buf == IntPtr.Zero) return;
            try
            {
                int n = Marshal.ReadInt32(buf); IntPtr p = (IntPtr)((long)buf + 4);
                for (int i = 0; i < n; i++)
                {
                    uint la = (uint)Marshal.ReadInt32(p, 0), lp = (uint)Marshal.ReadInt32(p, 4); int pid = Marshal.ReadInt32(p, 8);
                    Conn c = new Conn(); c.Proto = "UDP"; c.Local = V4(la); c.LocalPort = Port(lp); c.Remote = ""; c.State = "bound"; c.Pid = pid; c.FirstSeen = c.LastSeen = now;
                    l.Add(c); p = (IntPtr)((long)p + 12);
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
        static void Udp6(List<Conn> l, DateTime now)
        {
            int size; IntPtr buf = Fetch(false, 23, 1, out size); if (buf == IntPtr.Zero) return;
            try
            {
                int n = Marshal.ReadInt32(buf); IntPtr p = (IntPtr)((long)buf + 4);
                for (int i = 0; i < n; i++)
                {
                    byte[] la = new byte[16]; Marshal.Copy(p, la, 0, 16); uint lp = (uint)Marshal.ReadInt32(p, 20); int pid = Marshal.ReadInt32(p, 24);
                    Conn c = new Conn(); c.Proto = "UDP6"; c.Local = V6(la); c.LocalPort = Port(lp); c.Remote = ""; c.State = "bound"; c.Pid = pid; c.FirstSeen = c.LastSeen = now;
                    l.Add(c); p = (IntPtr)((long)p + 28);
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
    }

    /// <summary>Process names by PID, refreshed lazily, and reverse DNS in the background.</summary>
    public class NameCache
    {
        readonly Dictionary<int, string> procs = new Dictionary<int, string>(); DateTime procsAt = DateTime.MinValue;
        readonly Dictionary<string, string> hosts = new Dictionary<string, string>(); readonly HashSet<string> pending = new HashSet<string>();
        public event Action HostResolved;
        public string ProcessName(int pid)
        {
            lock (procs)
            {
                if ((DateTime.Now - procsAt).TotalSeconds > 3) { procs.Clear(); foreach (Process p in Process.GetProcesses()) { try { procs[p.Id] = p.ProcessName; } catch { } } procsAt = DateTime.Now; procs[0] = "System Idle"; procs[4] = "System"; }
                string n; return procs.TryGetValue(pid, out n) ? n : "?";
            }
        }
        public string HostOf(string ip)
        {
            if (string.IsNullOrEmpty(ip)) return "";
            lock (hosts)
            {
                string h; if (hosts.TryGetValue(ip, out h)) return h;
                if (pending.Add(ip))
                {
                    ThreadPool.QueueUserWorkItem(delegate
                    {
                        string name = "";
                        try { IAsyncResult ar = Dns.BeginGetHostEntry(ip, null, null); if (ar.AsyncWaitHandle.WaitOne(2500)) { IPHostEntry e = Dns.EndGetHostEntry(ar); name = e.HostName; } } catch { }
                        lock (hosts) { hosts[ip] = name; pending.Remove(ip); }
                        if (HostResolved != null) HostResolved();
                    });
                }
                return "…";
            }
        }
    }
}

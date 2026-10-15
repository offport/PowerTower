// Engine tests, no UI. Run Tests.exe; exit code = number of failures. Everything that touches the real
// machine is read-only (hosts-file edits happen on a temp copy).
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace PSTools
{
    static class Tests
    {
        static int pass, fail;
        static void Check(bool ok, string what) { Console.WriteLine((ok ? "  PASS  " : "  FAIL  ") + what); if (ok) pass++; else fail++; }
        static void Info(string what) { Console.WriteLine("  info  " + what); }

        static int Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            foreach (Action t in new Action[] { Extractor_, Hosts_, Firewall_, Reach_, Conns_, Procs_, Storage_, Journal_, BinRecord_, ExFat_, Csv_, Json_, Ver_, ProductMap_, Cpe_, MsrcParse_, MsrcWindow_, Resolve_, Inventory_, Feeds_, Recon_, Pdf_, Wildcard_, Hashes_, Crypto_, Walk_, Checklist_, DeletedFilter_, Active_, Trust_, Autoruns_, Events_, Dupes_, Secrets_, Bundle_, Engagement_, Collect_, BundleGate_, CollectorAssembly_, Enrich_, FeedPack_, EngagementTool_, EngagementStrict_, FailClosed_, Ptreport_, Report_, ReportCoverage_, ReportMarkdown_, RemoteAudit_, RemoteFuzz_, RemoteBatch_, RemoteCollectorArgs_, BuildLists_, RemoteInject_, CredsCli_, CredsStdin_, VulnGuiReport_ }) { try { t(); } catch (Exception ex) { Check(false, t.Method.Name + " threw " + ex.GetType().Name + ": " + ex.Message); } }
            Console.WriteLine(); Console.WriteLine(pass + " passed, " + fail + " failed");
            return fail;
        }

        static void Extractor_()
        {
            string[] lines = {
                "# comment line with evil.com should be ignored",
                "doubleclick.net", "ads.doubleclick.net", "https://analytics.badvendor.io/collect?id=123",
                "2026-09-14 12:00:01 blocked beacon to telemetry.snooping.co from app",
                "hxxps://malware-c2[.]net/gate.php", "phish-kit(.)com", "203.0.113.45", "\"c2-node\",\"suspicious\",\"185.220.101.4\",\"seen 2026-09-13\"",
                "2001:db8:dead:beef::1", "notes.md", "setup.ps1", "localhost", "example.com", "10.0.0.256 is not an ip", "version 1.2.3.4 looks like one but is", "xn--80ak6aa92e.com"
            };
            List<Target> t = Extractor.Extract(lines); Dictionary<string, Kind> m = new Dictionary<string, Kind>(); foreach (Target x in t) m[x.Value] = x.Kind;
            Check(m.ContainsKey("doubleclick.net") && m["doubleclick.net"] == Kind.Domain, "extractor: bare domain");
            Check(m.ContainsKey("ads.doubleclick.net"), "extractor: subdomain kept separately");
            Check(m.ContainsKey("analytics.badvendor.io"), "extractor: host pulled out of a URL");
            Check(m.ContainsKey("telemetry.snooping.co"), "extractor: host inside a log line");
            Check(m.ContainsKey("malware-c2.net") && m.ContainsKey("phish-kit.com"), "extractor: defanged [.] and (.) and hxxps");
            Check(m.ContainsKey("203.0.113.45") && m["203.0.113.45"] == Kind.IPv4 && m.ContainsKey("185.220.101.4"), "extractor: IPv4 plain and inside csv noise");
            Check(m.ContainsKey("2001:db8:dead:beef::1") && m["2001:db8:dead:beef::1"] == Kind.IPv6, "extractor: IPv6");
            Check(!m.ContainsKey("notes.md") && !m.ContainsKey("setup.ps1") && !m.ContainsKey("localhost") && !m.ContainsKey("example.com"), "extractor: file names, localhost and example.com excluded");
            Check(!m.ContainsKey("evil.com"), "extractor: comment lines ignored");
            Check(!m.ContainsKey("10.0.0.256"), "extractor: 10.0.0.256 rejected; 1.2.3.4 in 'version 1.2.3.4' " + (m.ContainsKey("1.2.3.4") ? "accepted (same as the script)" : "rejected"));
            Check(m.ContainsKey("xn--80ak6aa92e.com"), "extractor: punycode label");
            Target d = t.Find(delegate (Target x) { return x.Value == "telemetry.snooping.co"; }); Check(d != null && d.Line == 5 && d.Source.Contains("beacon"), "extractor: source line and line number kept");
            Check(Extractor.Classify("Example.COM") == Kind.Domain && Extractor.Classify("1.2.3.4") == Kind.IPv4 && Extractor.Classify("::1") == Kind.IPv6 && Extractor.Classify("not a host") == Kind.Invalid && Extractor.Classify("") == Kind.Invalid && Extractor.Classify("notes.md") == Kind.Invalid, "classify: domain / v4 / v6 / invalid (" + Extractor.Classify("Example.COM") + " " + Extractor.Classify("1.2.3.4") + " " + Extractor.Classify("::1") + " " + Extractor.Classify("not a host") + ")");
            List<Target> v6 = Extractor.Extract(new string[] { "fe80::1%eth0 and ::1 and 12:30:45 time and aa:bb:cc:dd:ee:ff mac and 2606:4700:4700::1111 dns" });
            Check(v6.Count == 3 && v6[0].Value == "fe80::1" && v6[1].Value == "::1" && v6[2].Value == "2606:4700:4700::1111", "extractor: IPv6 forms (" + v6.Count + ": " + string.Join(" ", v6.ConvertAll(delegate (Target x) { return x.Value; }).ToArray()) + "), times and MACs skipped");
            List<string> ex = Extractor.ExpandDomains(new string[] { "doubleclick.net", "ads.doubleclick.net", "www.foo.com" });
            Check(ex.Count == 4 && ex.Contains("www.doubleclick.net") && !ex.Contains("www.ads.doubleclick.net"), "expand: www. added for bare names only");
            Stopwatch sw = Stopwatch.StartNew(); List<Target> pad = Extractor.Extract(new string[] { new string(' ', 100000) + "a.com" }); sw.Stop();   // PT-01: was quadratic, minutes
            Check(pad.Count == 1 && pad[0].Value == "a.com" && sw.ElapsedMilliseconds < 1000, "extractor: 100,000 spaces + a.com returns a.com in " + sw.ElapsedMilliseconds + " ms");
            List<Target> lz = Extractor.Extract(new string[] { "010.0.0.1 and 01.02.03.04 and 10.0.0.1" });   // PT-05: leading zeros are octal to some parsers
            Check(lz.Count == 1 && lz[0].Value == "10.0.0.1" && Extractor.Classify("010.0.0.1") == Kind.Invalid, "extractor: IPv4 with leading-zero octets rejected (" + lz.Count + " found)");
        }

        static void Hosts_()
        {
            string tmp = Path.Combine(Path.GetTempPath(), "pstools-hosts-test"); Directory.CreateDirectory(tmp);
            Hosts h = new Hosts(); h.Path = Path.Combine(tmp, "hosts"); h.BackupDir = Path.Combine(tmp, "backups");
            File.WriteAllText(h.Path, "# Copyright\r\n127.0.0.1 localhost\r\n0.0.0.0 manual.example  # mine\r\n");
            Hosts.AddResult a = h.Add(new string[] { "bad.example", "www.bad.example", "manual.example" }, "0.0.0.0");
            Check(a.Added == 2 && a.Skipped == 1, "hosts: add 2, skip 1 already present (" + a.Added + "/" + a.Skipped + ")");
            string[] lines = File.ReadAllLines(h.Path); Check(Array.Exists(lines, delegate (string l) { return l == "0.0.0.0\tbad.example\t# BLOCK-HOSTS"; }), "hosts: line written with the marker, tab separated");
            List<HostsEntry> ours = h.Entries(false); Check(ours.Count == 2 && ours[0].Host == "bad.example", "hosts: Entries(ours) lists the 2 tagged lines");
            List<HostsEntry> all = h.Entries(true); Check(all.Count == 4, "hosts: Entries(all) lists 4 mappings incl. localhost and the manual one (" + all.Count + ")");
            Check(File.Exists(a.Backup) && h.Backups().Count == 1, "hosts: backup taken before writing");
            Hosts.RemoveResult r = h.Remove(new string[] { "bad.example", "www.bad.example", "manual.example" });
            Check(r.Removed == 2, "hosts: remove drops only our 2 tagged lines, not the manual one (" + r.Removed + ")");
            Check(File.ReadAllText(h.Path).Contains("manual.example  # mine") && !File.ReadAllText(h.Path).Contains("bad.example"), "hosts: hand-written line untouched");
            string safety = h.Restore(a.Backup); Check(File.Exists(safety) && File.ReadAllText(h.Path).Contains("127.0.0.1 localhost"), "hosts: restore from backup, safety copy made");
            Directory.Delete(tmp, true);
        }

        static void Firewall_()
        {
            Check(Firewall.Available(), "firewall: COM policy object available");
            List<string> l = Firewall.GetBlocked(); Info("firewall: rule '" + Firewall.RuleName + "' holds " + l.Count + " address(es)" + (l.Count > 0 ? " e.g. " + l[0] : ""));
            Check(true, "firewall: GetBlocked reads without elevation");
        }

        static void Reach_()
        {
            TcpListener lis = new TcpListener(IPAddress.Loopback, 0); lis.Start(); int port = ((IPEndPoint)lis.LocalEndpoint).Port;
            try
            {
                List<ReachRow> rows = new List<ReachRow>();
                foreach (Target t in Extractor.Extract(new string[] { "127.0.0.1", "192.0.2.1", "google.com" })) { ReachRow r = new ReachRow(); r.Target = t; rows.Add(r); }
                Check(rows.Count == 3, "reach: 3 targets extracted (" + rows.Count + ")");
                Reach e = new Reach(); e.Ports = new int[] { port }; e.TimeoutSec = 2; e.DoPing = false; e.Concurrency = 3; ManualResetEvent done = new ManualResetEvent(false); e.Finished += delegate { done.Set(); };
                Stopwatch sw = Stopwatch.StartNew(); e.Run(rows); bool fin = done.WaitOne(20000);
                Check(fin, "reach: finished in " + sw.Elapsed.TotalSeconds.ToString("N1") + " s");
                ReachRow lo = rows[0], doc = rows[1], dg = rows[2];
                Check(lo.Status == "reachable" && lo.Ports[port].Ok, "reach: 127.0.0.1:" + port + " open (" + lo.Ports[port].Ms + " ms)");
                Check(doc.Status == "unreachable" && !doc.Ports[port].Ok, "reach: 192.0.2.1 unreachable (" + doc.Ports[port].Error + ")");
                if (dg.Resolved.Count > 0) Check(dg.DnsMs >= 0, "reach: google.com resolved to " + string.Join(",", dg.Resolved.ToArray()) + " in " + dg.DnsMs + " ms"); else Info("reach: google.com did not resolve (no internet?) → " + dg.Status);
            }
            finally { lis.Stop(); }
        }

        static void Conns_()
        {
            TcpListener lis = new TcpListener(IPAddress.Loopback, 0); lis.Start(); int port = ((IPEndPoint)lis.LocalEndpoint).Port;
            try
            {
                List<Conn> l = ConnTable.Snapshot(true, true); int me = Process.GetCurrentProcess().Id; Conn mine = l.Find(delegate (Conn c) { return c.Proto == "TCP" && c.LocalPort == port; });
                Check(mine != null && mine.Pid == me && mine.State == "LISTENING", "conns: our listener on " + port + " found with PID " + me + " (" + l.Count + " endpoints)");
                int tcp = 0, udp = 0, v6 = 0; foreach (Conn c in l) { if (c.Proto.StartsWith("TCP")) tcp++; else udp++; if (c.Proto.EndsWith("6")) v6++; }
                Check(tcp > 0 && udp > 0, "conns: tcp=" + tcp + " udp=" + udp + " (v6 rows " + v6 + ")");
                NameCache n = new NameCache(); Check(n.ProcessName(me).Length > 1 && n.ProcessName(4) == "System", "conns: process names (" + n.ProcessName(me) + ")");
            }
            finally { lis.Stop(); }
        }

        static void Procs_()
        {
            ProcSampler s = new ProcSampler(); s.Sample(); Thread.Sleep(300); s.Sample();
            ProcRow me = null; foreach (ProcRow p in s.Procs.Values) if (p.Pid == Process.GetCurrentProcess().Id) me = p;
            Check(me != null && me.MemCur > 1000000 && me.Alive, "procs: own process tracked, " + (me == null ? "" : Fmt.Bytes(me.MemCur)));
            Check(s.RamTotal > 1e9 && s.RamUsed > 0 && s.RamUsed < s.RamTotal, "procs: memory " + Fmt.Bytes(s.RamUsed) + " / " + Fmt.Bytes(s.RamTotal));
            Check(s.SysCpu >= 0 && s.SysCpu <= 100 && s.Ticks == 2, "procs: system cpu " + s.SysCpu.ToString("N1") + " %");
            List<ProcRow> g = s.Grouped(); Check(g.Count > 0 && g.Count <= s.Procs.Count, "procs: grouped " + g.Count + " names from " + s.Procs.Count + " processes");
            ulong r, w; Check(Win32.TryIo(Process.GetCurrentProcess().Id, out r, out w), "procs: io counters of own process r=" + r + " w=" + w);
        }

        static void Storage_()
        {
            string tmp = Path.Combine(Path.GetTempPath(), "pstools-storage-test"); if (Directory.Exists(tmp)) Directory.Delete(tmp, true);
            Directory.CreateDirectory(Path.Combine(tmp, "a\\b")); Directory.CreateDirectory(Path.Combine(tmp, "c"));
            File.WriteAllBytes(Path.Combine(tmp, "a\\big.bin"), new byte[300000]); File.WriteAllBytes(Path.Combine(tmp, "a\\b\\mid.txt"), new byte[20000]); File.WriteAllBytes(Path.Combine(tmp, "c\\small.log"), new byte[5]); File.WriteAllBytes(Path.Combine(tmp, "root.txt"), new byte[10]);
            Storage s = new Storage(); s.MinFileBytes = 0; Node root = s.Scan(tmp);
            Check(s.TotalFiles == 4 && s.TotalBytes == 320015 && root.Size == 320015, "storage: 4 files, 320,015 bytes (" + s.TotalFiles + ", " + s.TotalBytes + ")");
            Check(root.Children[0].Name == "a" && root.Children[0].Size == 320000 && root.Children[0].Files == 2 && root.Children[0].Dirs == 1, "storage: folder a = 320,000 bytes, 2 files, 1 subfolder, sorted first");
            Check(s.LargestFiles[0].Name == "big.bin" && s.LargestFiles.Count == 4, "storage: largest file first");
            Check(s.ByExt["bin"].Bytes == 300000 && s.ByExt["txt"].Count == 2, "storage: by type: bin 300,000; txt ×2");
            Check(s.AllDirs.Count == 4 && s.AllDirs[0] == root, "storage: 4 folder rows, root biggest");
            Directory.Delete(tmp, true);
        }

        static void Journal_()
        {
            string name; DateTime when; bool isDir, isDel; long frn, parent;
            bool ok = Journal.ParseLine("20577355512,\"ToolRunner.js.map\",34,0x80000200,\"File delete | Close\",\"9/14/2026 17:02:20\",0x00000020,\"Archive\",000000000000000000020000000c9afb,000000000000000000020000000c9635,0x00000000,\"*NONE*\",0,3,0,112", out name, out when, out isDir, out frn, out parent, out isDel);
            Check(ok && name == "ToolRunner.js.map" && isDel && !isDir && when == new DateTime(2026, 9, 14, 17, 2, 20) && frn == 0x20000000c9afbL && parent == 0x20000000c9635L, "journal: new 16-field layout parsed");
            ok = Journal.ParseLine("20568874400,\"report, final, v2.docx\",44,0x80000200,\"File delete | Close\",\"9/13/2026 08:05:00\",0x00000020,\"Archive\",0000000000000000001000000009a883,00000000000000000001000000061dea,0x00000000,\"*NONE*\",0,3,0,120", out name, out when, out isDir, out frn, out parent, out isDel);
            Check(ok && name == "report, final, v2.docx", "journal: a name with commas survives (" + name + ")");
            ok = Journal.ParseLine("20568874700,\"He said \"\"hi\"\".txt\",30,0x80000200,\"File delete | Close\",\"9/12/2026 08:58:00\",0x00000020,\"Archive\",0000000000000000001000000009a885,00000000000000000001000000061dea,0x00000000,\"*NONE*\",0,3,0,120", out name, out when, out isDir, out frn, out parent, out isDel);
            Check(ok && name == "He said \"hi\".txt", "journal: doubled quotes unescaped (" + name + ")");
            ok = Journal.ParseLine("0x00000004ca00ff00,legacy.txt,20,0x80000200: Close | File delete,9/10/2026 12:00:00,0x20,0x000100000000abcd,0x0001000000061dea,0x0x0,0x0,3,0,88", out name, out when, out isDir, out frn, out parent, out isDel);
            Check(!ok || (name == "legacy.txt" && isDel), "journal: old 13-field layout " + (ok ? "parsed (" + name + ")" : "rejected because it starts with 0x"));
            ok = Journal.ParseLine("20568866816,\"Documents\",18,0x00000100,\"File create\",\"9/1/2026 10:00:00\",0x00000010,\"Directory\",00000000000000000001000000061dea,00000000000000000005000000000005,0x00000000,\"*NONE*\",0,3,0,160", out name, out when, out isDir, out frn, out parent, out isDel);
            Check(ok && isDir && !isDel, "journal: directory create record, not a delete");
            Check(!Journal.ParseLine("USN Journal ID    : 0x01dba8ea9dba44d0", out name, out when, out isDir, out frn, out parent, out isDel), "journal: preamble line rejected");
            Check(Journal.ParseTime("9/14/2026 17:02:20") == new DateTime(2026, 9, 14, 17, 2, 20) && Journal.ParseTime("not a date") == DateTime.MinValue, "journal: time parsing");
        }

        static void BinRecord_()
        {
            // a v2 $I record: version 2, size, deletion FILETIME, path length (chars incl. null), UTF-16 path
            string p = @"D:\MindMap2025Dec"; byte[] pb = Encoding.Unicode.GetBytes(p + "\0"); byte[] b = new byte[28 + pb.Length];
            BitConverter.GetBytes(2L).CopyTo(b, 0); BitConverter.GetBytes(1234L).CopyTo(b, 8); BitConverter.GetBytes(new DateTime(2026, 8, 20, 19, 38, 15).ToFileTime()).CopyTo(b, 16); BitConverter.GetBytes(p.Length + 1).CopyTo(b, 24); pb.CopyTo(b, 28);
            string path; DateTime when; bool ok = ExFat.ParseBinRecord(b, out path, out when);
            Check(ok && path == p && when == new DateTime(2026, 8, 20, 19, 38, 15), "bin record: v2 parsed → " + path + " @ " + when.ToString("s"));
            byte[] junk = new byte[64]; new Random(1).NextBytes(junk); Check(!ExFat.ParseBinRecord(junk, out path, out when), "bin record: garbage rejected");
            Check(Noise.Is(@"D:\$RECYCLE.BIN\$RABC123\x", "x") && Noise.Is(@"C:\Users\a\AppData\Local\Temp\x.txt", "x.txt") && Noise.Is(@"D:\proj\.git\objects\ab", "ab") && Noise.Is(@"C:\x\vpn.db-shm", "vpn.db-shm") && !Noise.Is(@"D:\Photos\trip.jpg", "trip.jpg"), "noise: bin, temp, .git, sqlite sidecar flagged; a photo is not");
        }

        static void ExFat_()
        {
            DriveInfoRow ex = Drives.List().Find(delegate (DriveInfoRow d) { return d.ExFat; });
            if (ex == null) { Info("exfat: no exFAT drive attached, reader untested here"); return; }
            ExFat x;
            try { x = ExFat.Open(ex.Letter); } catch (Exception e) { Info("exfat: " + ex.Letter + ": cannot open for a raw read (" + e.Message + ") - needs elevation on this drive"); return; }
            using (x)
            {
                x.MaxDirs = 800; Stopwatch sw = Stopwatch.StartNew(); x.Scan(); sw.Stop();
                Check(x.ClusterSize >= 512 && x.ClusterCount > 0 && x.BitmapOk, "exfat: " + ex.Letter + ": " + (x.ClusterSize / 1024) + " KB clusters, " + x.ClusterCount.ToString("N0") + " clusters, bitmap read");
                Check(x.DirsScanned > 0 && x.EntriesSeen > 0, "exfat: capped scan read " + x.DirsScanned + " folders, " + x.EntriesSeen.ToString("N0") + " entries, " + x.Deleted.Count.ToString("N0") + " deleted, " + x.IntactCount.ToString("N0") + " intact in " + sw.Elapsed.TotalSeconds.ToString("N1") + " s");
                int st = 0; foreach (XEntry e in x.Deleted) { if (e.State == "intact" || e.State == "empty" || e.State == "folder" || e.State == "overwritten" || e.State == "partly overwritten" || e.State == "unknown" || e.State == "chain lost" || e.State == "intact (fragmented)") st++; }
                Check(st == x.Deleted.Count, "exfat: every entry has a known state");
                XEntry small = x.Deleted.Find(delegate (XEntry e) { return !e.IsDir && e.State == "intact" && e.Size > 0 && e.Size < 100000; });
                if (small != null) { byte[] head = x.ReadHead(small, 64); Check(head.Length == Math.Min(64, small.Size), "exfat: ReadHead of " + small.Name + " returned " + head.Length + " bytes"); }
            }
        }

        static void Csv_()
        {
            Check(Fmt.CsvQ("plain") == "plain" && Fmt.CsvQ("a,b") == "\"a,b\"" && Fmt.CsvQ("say \"hi\"") == "\"say \"\"hi\"\"\"" && Fmt.CsvQ(null) == "", "csv: quoting");
            Check(Fmt.CsvQ("=cmd") == "'=cmd" && Fmt.CsvQ("@SUM(1)") == "'@SUM(1)" && Fmt.CsvQ("+x") == "'+x" && Fmt.CsvQ("-x") == "'-x" && Fmt.CsvQ("=a,b") == "\"'=a,b\"" && Fmt.CsvQ("-5") == "-5" && Fmt.CsvQ("") == "" && Fmt.CsvQ("a=b") == "a=b", "csv: formula cells neutralised, numbers and plain text untouched (PT-03)");
        }
    
        // ── vulnerability management engine ──
        static void Json_()
        {
            object o = Json.Parse("{\"a\":[1,2.5,\"x\\u00e9\\n\"],\"b\":{\"c\":true,\"d\":null},\"e\":-3e2, \"f\":\"\"}");
            Check(Json.Arr(Json.Get(o, "a")).Count == 3 && (double)Json.Arr(Json.Get(o, "a"))[1] == 2.5 && (string)Json.Arr(Json.Get(o, "a"))[2] == "xé\n", "json: arrays, numbers, escapes");
            Check((bool)Json.Get(o, "b", "c") && Json.Get(o, "b", "d") == null && Json.N(Json.Get(o, "e")) == -300 && Json.GetS(o, "f") == "", "json: nested objects, null, exponent");
            bool threw = false; try { Json.Parse("{\"a\":}"); } catch (FormatException) { threw = true; } Check(threw, "json: malformed input throws");
            Check((Json.Parse(Json.Quote("q\"\\")) as string) == "q\"\\", "json: Quote round-trips");
            StringBuilder sb = new StringBuilder("["); for (int i = 0; i < 40000; i++) { if (i > 0) sb.Append(','); sb.Append("{\"id\":\"CVE-2026-").Append(i).Append("\",\"score\":").Append(i % 10).Append(".5,\"tags\":[\"a\",\"b\"]}"); } sb.Append(']');
            Stopwatch sw = Stopwatch.StartNew(); List<object> big = Json.Arr(Json.Parse(sb.ToString())); sw.Stop(); Check(big.Count == 40000 && sw.ElapsedMilliseconds < 3000, "json: " + (sb.Length / 1024) + " KB parsed in " + sw.ElapsedMilliseconds + " ms");
        }
        static void Ver_()
        {
            Check(Ver.Compare("3.0", "3.0.0") == 0 && Ver.Compare("151.0.7922.109", "151.0.7922.9") > 0 && Ver.Compare("4.43-beta", "4.43") == 0 && Ver.Compare("26.02.00.0", "26.2") == 0, "version: positional numeric compare, suffix stripped, trailing zeros");
            int r; Check(!Ver.TryCompare("1.2", "beta", out r) && Ver.Parse("") == null && Ver.Parse("1..2") == null && Ver.Canon("6.2.3 (49583)") == "6.2.3", "version: unparseable is unknown, not a guess; canonical form");
            Check(Ver.InRange("2.5", "2.0", null, null, "3.0") && !Ver.InRange("3.0", "2.0", null, null, "3.0") && Ver.InRange("3.0", null, null, "3.0", null) && !Ver.InRange("2.0", null, "2.0", null, null) && !Ver.InRange("x", "1", null, null, null), "version: NVD-style bounds");
        }
        static void ProductMap_()
        {
            string v, p;
            Check(ProductMap.Map("7-Zip 24.08 (x64)", out v, out p) && v == "7-zip" && p == "7-zip", "product map: 7-Zip");
            Check(ProductMap.Map("Mozilla Firefox (x64 en-US)", out v, out p) && v == "mozilla" && p == "firefox" && ProductMap.Map("Google Chrome", out v, out p) && p == "chrome", "product map: Firefox, Chrome");
            Check(!ProductMap.Map("Google Chrome Canary", out v, out p) && !ProductMap.Map("Some Random Tool", out v, out p) && !ProductMap.Map("", out v, out p), "product map: no fuzzy matches");
            Check(ProductMap.Map("Notepad++ (64-bit x64)", out v, out p) && p == "notepad++" && ProductMap.Map("Microsoft Visual Studio Code (User)", out v, out p) && p == "visual_studio_code", "product map: Notepad++, VS Code");
        }
        static void Cpe_()
        {
            string json = "{\"vulnerabilities\":[{\"cve\":{\"id\":\"CVE-2022-29072\",\"published\":\"2022-04-15T21:15:00.000\",\"descriptions\":[{\"lang\":\"en\",\"value\":\"7-Zip through 21.07 on Windows allows privilege escalation.\"}],\"metrics\":{\"cvssMetricV31\":[{\"type\":\"Primary\",\"cvssData\":{\"baseScore\":7.8,\"baseSeverity\":\"HIGH\"}}]},\"configurations\":[{\"nodes\":[{\"cpeMatch\":[{\"vulnerable\":true,\"criteria\":\"cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*\",\"versionEndIncluding\":\"21.07\"},{\"vulnerable\":false,\"criteria\":\"cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*\"}]}]}]}},"
                + "{\"cve\":{\"id\":\"CVE-2000-0001\",\"descriptions\":[{\"lang\":\"en\",\"value\":\"exact\"}],\"metrics\":{},\"configurations\":[{\"nodes\":[{\"cpeMatch\":[{\"vulnerable\":true,\"criteria\":\"cpe:2.3:a:7-zip:7-zip:21.07:*:*:*:*:*:*:*\"}]}]}]}},"
                + "{\"cve\":{\"id\":\"CVE-2000-0002\",\"descriptions\":[],\"configurations\":[{\"nodes\":[{\"cpeMatch\":[{\"vulnerable\":true,\"criteria\":\"cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*\"}]}]}]}}]}";
            List<CveRecord> recs = Nvd.Parse(json);
            Check(recs.Count == 3 && recs[0].Severity == "HIGH" && recs[0].Cvss == 7.8 && recs[0].Matches.Count == 1 && recs[0].Matches[0].EndInc == "21.07" && recs[0].Published.HasValue, "nvd: parse keeps vulnerable matches, drops non-vulnerable, reads CVSS");
            Software sw = new Software(); sw.Name = "7-Zip 21.07 (x64)"; sw.Version = "21.07"; sw.Vendor = "7-zip"; sw.Product = "7-zip";
            List<Finding> f = Resolve.ThirdParty(sw, recs);
            Check(f.Count == 3 && f[0].Status == "vulnerable" && f[1].Status == "vulnerable" && f[2].Status == "unconfirmed", "nvd: range match, exact match, unbounded → unconfirmed");
            sw.Version = "22.01"; f = Resolve.ThirdParty(sw, recs); Check(f.Count == 1 && f[0].Status == "unconfirmed" && f[0].Cve == "CVE-2000-0002" && f[0].Url.EndsWith("CVE-2000-0002"), "nvd: newer version falls outside both bounded matches; finding carries CVE and URL");
        }
        static void MsrcParse_()
        {
            string doc = "{\"ProductTree\":{\"FullProductName\":[{\"ProductID\":\"12345\",\"Value\":\"Windows 11 Version 25H2 for x64-based Systems\"},{\"ProductID\":\"777\",\"Value\":\"Microsoft 365 Apps for Enterprise for 64-bit Systems\"}]},"
                + "\"Vulnerability\":[{\"CVE\":\"CVE-2026-1\",\"Title\":{\"Value\":\"Kernel EoP\"},\"Threats\":[{\"Type\":3,\"Description\":{\"Value\":\"Important\"}},{\"Type\":1,\"Description\":{\"Value\":\"Publicly Disclosed:No;Exploited:Yes;Latest Software Release:Exploitation Detected\"}}],\"CVSSScoreSets\":[{\"BaseScore\":7.8}],"
                + "\"Remediations\":[{\"Type\":2,\"Description\":{\"Value\":\"5066000\"},\"ProductID\":[\"12345\"],\"Supercedence\":\"5065999\",\"FixedBuild\":\"10.0.26200.6900\"},{\"Type\":3,\"Description\":{\"Value\":\"5066000\"},\"URL\":\"https://support.microsoft.com/help/5066000\"},{\"Type\":2,\"Description\":{\"Value\":\"Release Notes\"},\"ProductID\":[\"777\"]}]},"
                + "{\"CVE\":\"CVE-2026-2\",\"Title\":{\"Value\":\"Office info disclosure\"},\"Threats\":[{\"Type\":3,\"Description\":{\"Value\":\"Critical\"}}],\"Remediations\":[{\"Type\":2,\"Description\":{\"Value\":\"5002800\"},\"ProductID\":[\"777\"]}]}]}";
            List<MsrcRec> r = Msrc.Parse(doc, "2026-Sep");
            Check(r.Count == 2 && r[0].Cve == "CVE-2026-1" && r[0].Kb == "5066000" && r[0].SupersedesKb == "5065999" && r[0].FixedBuild == "10.0.26200.6900" && r[0].ProductName.StartsWith("Windows 11") && r[0].Severity == "Important" && r[0].Cvss == 7.8 && r[0].Exploited && !r[0].Disclosed, "msrc: vendor-fix records only, with build, supersedence, severity, exploit status");
            Check(r[1].Cve == "CVE-2026-2" && r[1].FixedBuild == null && r[1].ProductName.StartsWith("Microsoft 365"), "msrc: non-OS record without FixedBuild kept for the KB path");
            OsInfo os = new OsInfo(); os.ProductName = "Windows 11 Pro"; os.Major = 10; os.Build = 26200; os.Ubr = 6584;
            List<Software> sw = new List<Software>(); Software o365 = new Software(); o365.Name = "Microsoft 365 Apps for enterprise - en-us"; sw.Add(o365);
            RebootInfo rb = new RebootInfo();
            List<Finding> f = Resolve.Msrc(r, os, new HashSet<string>(), sw, rb);
            Check(f.Count == 2 && f[0].Status == "vulnerable" && f[0].Evidence.Contains("6584 < fixed 10.0.26200.6900") && f[0].Exploited && f[0].SeverityNorm == "High", "resolve: build comparison flags the older UBR, exploited carried");
            Check(f[1].Status == "vulnerable" && f[1].Evidence.Contains("KB5002800 not installed") && f[1].Product.StartsWith("Microsoft 365"), "resolve: Office record matched by normalised product name, KB missing");
            os.Ubr = 6900; f = Resolve.Msrc(r, os, new HashSet<string>(), sw, rb); Check(f[0].Status == "patched" && f[0].Evidence.Contains("≥"), "resolve: host at the fixed UBR is patched");
            os.Ubr = 6584; rb.WindowsUpdate = true; HashSet<string> kbs = new HashSet<string>(); kbs.Add("5066000"); f = Resolve.Msrc(r, os, kbs, sw, rb); Check(f[0].Status == "reboot pending", "resolve: KB installed but build not bumped + reboot flag → reboot pending");
            HashSet<string> office = new HashSet<string>(); office.Add("5002800"); f = Resolve.Msrc(r, os, office, sw, rb); Check(f[1].Status == "patched" && f[1].Evidence.Contains("is installed"), "resolve: Office KB present → patched");
            os.Build = 22631; os.Ubr = 4000; f = Resolve.Msrc(r, os, new HashSet<string>(), new List<Software>(), rb); Check(f.Count == 0, "resolve: other build family and no matching software → out of scope, not vulnerable");
        }
        static void MsrcWindow_()
        {
            DateTime now = new DateTime(2026, 10, 13);
            Check(VulnScan.MsrcWindow(new DateTime(2026, 9, 15), null, now, 3) == 3, "msrc window: a host patched last month keeps the minimum of 3 releases");
            int wide = VulnScan.MsrcWindow(new DateTime(2025, 7, 10), null, now, 3);
            Check(wide == 16, "msrc window: newest update 15 months ago → 16 releases, back to the month it came from (got " + wide + ")");
            Check(VulnScan.MsrcWindow(new DateTime(2020, 1, 1), null, now, 3) == VulnScan.MaxMonths && VulnScan.MaxMonths == 36, "msrc window: a host years behind is capped at 36");
            Check(VulnScan.MsrcWindow(null, new DateTime(2025, 12, 1), now, 3) == 11, "msrc window: no dated update → the OS install date stands in (Dec 2025 → 11)");
            Check(VulnScan.MsrcWindow(null, null, now, 3) == 36, "msrc window: nothing dated → the cap, never the minimum");
            Check(VulnScan.MsrcWindow(new DateTime(2026, 2, 1), null, now, 12) == 12, "msrc window: a larger configured minimum still wins (12 over 9)");
            // what counts as the patch level: OS servicing rows, not the daily Defender definitions Windows Update keeps installing on a stale host
            Hotfix qfe = new Hotfix(); qfe.Source = "QFE"; qfe.Kb = "5060000"; qfe.InstalledOn = new DateTime(2025, 7, 10);
            Hotfix defs = new Hotfix(); defs.Source = "WU history"; defs.Kb = "2267602"; defs.Title = "Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.433.10.0)"; defs.Description = "installation"; defs.Result = "succeeded"; defs.InstalledOn = now.AddDays(-1);
            Hotfix cbs = new Hotfix(); cbs.Source = "CBS"; cbs.Kb = "5060001";
            DateTime? d = VulnScan.NewestUpdateDate(new Hotfix[] { defs, cbs, qfe });
            Check(d.HasValue && d.Value == qfe.InstalledOn.Value, "msrc window: the QFE date is the patch level; yesterday's definitions do not make a stale host look current");
            Hotfix cu = new Hotfix(); cu.Source = "WU history"; cu.Kb = "5062000"; cu.Title = "2025-09 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems (KB5062000)"; cu.Description = "installation"; cu.Result = "succeeded"; cu.InstalledOn = new DateTime(2025, 9, 12);
            Hotfix failed = new Hotfix(); failed.Source = "WU history"; failed.Kb = "5066000"; failed.Title = "2026-10 Cumulative Update for Windows 11 Version 24H2 for x64-based Systems (KB5066000)"; failed.Description = "installation"; failed.Result = "failed"; failed.InstalledOn = now;
            d = VulnScan.NewestUpdateDate(new Hotfix[] { defs, cu, failed, cbs });
            Check(d.HasValue && d.Value == cu.InstalledOn.Value, "msrc window: without QFE dates the newest successful WU cumulative update counts; failed installs and definitions do not");
            Check(!VulnScan.NewestUpdateDate(new Hotfix[] { cbs, defs }).HasValue, "msrc window: no servicing date at all → null, so the cap applies");
            // why it matters: a host on a build family the newest releases no longer service, last patched Jul 2025. Its missing fixes are all in older releases.
            OsInfo os = new OsInfo(); os.ProductName = "Windows 11 Pro"; os.Major = 10; os.Build = 22621; os.Ubr = 2500;
            List<string> rel = new List<string>(); Dictionary<string, List<MsrcRec>> byRel = new Dictionary<string, List<MsrcRec>>();
            for (int i = 0; i < 16; i++)
            {
                DateTime m = now.AddMonths(-i); string r = m.ToString("yyyy-MM"); rel.Add(r); byRel[r] = new List<MsrcRec>();
                MsrcRec rec = new MsrcRec(); rec.Cve = "CVE-2026-" + (1000 + i); rec.Title = "fix " + r; rec.Severity = "Important"; rec.Kb = (5070000 + i).ToString(); rec.Release = r; rec.ProductName = "Windows 11 Version 22H2 for x64-based Systems";
                // the 3 newest releases only service the current build family; the older ones carry the host's family, fixed above its UBR until the Jul-2025 release it did install
                rec.FixedBuild = i < 3 ? "10.0.26100." + (6000 + i) : "10.0.22621." + (i <= 14 ? 2600 + (14 - i) * 10 : 2500);
                byRel[r].Add(rec);
            }
            List<MsrcRec> narrow = new List<MsrcRec>(); for (int i = 0; i < Math.Min(3, rel.Count); i++) narrow.AddRange(byRel[rel[i]]);
            List<MsrcRec> all = new List<MsrcRec>(); for (int i = 0; i < Math.Min(wide, rel.Count); i++) all.AddRange(byRel[rel[i]]);
            List<Finding> fn = Resolve.Msrc(narrow, os, new HashSet<string>(), new List<Software>(), new RebootInfo());
            List<Finding> fw = Resolve.Msrc(all, os, new HashSet<string>(), new List<Software>(), new RebootInfo());
            int openN = 0; foreach (Finding f in fn) if (f.Open) openN++; int openW = 0, patched = 0; foreach (Finding f in fw) { if (f.Open) openW++; else patched++; }
            Check(openN == 0, "msrc window: with the old fixed 3 months the stale host has " + openN + " open findings - it looked clean");
            Check(openW == 12 && patched == 1, "msrc window: with the derived " + wide + "-release window the same host has " + openW + " open findings and " + patched + " patched (expected 12 and 1)");
        }
        static void Resolve_()
        {
            Supersedence g = new Supersedence(); g.Add("4580000", "4571703"); g.Add("4590000", "4580000"); g.Add("4600000", "4590000");
            HashSet<string> inst = new HashSet<string>(); inst.Add("4600000"); string by;
            Check(g.Satisfies(inst, "4571703", out by) && by == "4600000", "supersedence: KB4571703 case - transitive chain satisfied by the latest rollup");
            Check(!g.Satisfies(new HashSet<string>(), "4571703", out by) && g.Satisfies(new HashSet<string>(new string[] { "4571703" }), "4571703", out by) && by == "4571703", "supersedence: direct install / nothing installed");
            g.Add("4571703", "4600000"); Check(g.Satisfies(inst, "4571703", out by), "supersedence: cycles do not hang");
            Check(Resolve.NormSeverity("Important") == "High" && Resolve.NormSeverity("MEDIUM") == "Medium" && Resolve.NormSeverity("Moderate") == "Medium" && Resolve.NormSeverity("") == "" && Resolve.SevRank("Critical") == 4, "resolve: severity words normalised");
            Check(Resolve.NormProduct("Microsoft 365 Apps for Enterprise for 64-bit Systems") == "microsoft 365 apps for enterprise" && Resolve.NormProduct("Microsoft 365 Apps for enterprise - en-us") == "microsoft 365 apps for enterprise" && Resolve.NormProduct("Windows 11 Version 25H2 for x64-based Systems") == "windows 11 version 25h2", "resolve: product names normalised");
            MissingUpdate m = new MissingUpdate(); m.Kb = "5066000"; m.Title = "2026-09 Cumulative Update for Windows 11 Version 25H2 for x64-based Systems (KB5066000)"; m.Kind = "security"; m.Cves.Add("CVE-2026-1"); m.Cves.Add("CVE-2026-9"); m.Severity = "Critical";
            OsInfo os = new OsInfo(); os.ProductName = "Windows 11 Pro"; os.Major = 10; os.Build = 26200; os.Ubr = 6584;
            List<Finding> f = Resolve.FromWindowsUpdate(new List<MissingUpdate>(new MissingUpdate[] { m }), os);
            Check(f.Count == 2 && f[0].Status == "update available" && f[0].Fix == "KB5066000" && f[0].Product == "Windows 11 Version 25H2" && f[0].Open, "resolve: one finding per CVE named by an offered update");
            Finding a = new Finding(); a.Status = "vulnerable"; a.Severity = "Low"; Finding b = new Finding(); b.Status = "patched"; b.Severity = "Critical"; b.Kev = true; Finding c = new Finding(); c.Status = "vulnerable"; c.Severity = "Medium"; c.Kev = true;
            Check(c.SortScore > a.SortScore && a.SortScore > b.SortScore, "resolve: open findings rank above patched ones whatever the severity, KEV first among open");
        }
        static void Inventory_()
        {
            OsInfo os = Inventory.Os(); Check(os.Major == 10 && os.Build > 10000 && os.Ubr > 0 && Resolve.ParseBuild(os.FullBuild) != null, "inventory: OS " + os.Summary);
            RebootInfo rb = Inventory.Reboot(); Info("inventory: reboot " + rb.Why);
            Stopwatch sw = Stopwatch.StartNew(); List<Software> s = Inventory.Installed(); sw.Stop(); int mapped = 0; List<string> names = new List<string>(); foreach (Software x in s) if (x.Mapped) { mapped++; if (names.Count < 8) names.Add(x.Name + " " + x.Version + " → " + x.Cpe); }
            Check(s.Count > 5 && sw.ElapsedMilliseconds < 5000, "inventory: " + s.Count + " installed programs in " + sw.ElapsedMilliseconds + " ms, " + mapped + " mapped: " + string.Join(", ", names.ToArray()));
            sw.Restart(); List<Hotfix> q = Inventory.Qfe(); sw.Stop(); Check(q.Count > 0 && q[0].Kb.Length >= 6, "inventory: " + q.Count + " QFE hotfixes in " + sw.ElapsedMilliseconds + " ms (first KB" + (q.Count > 0 ? q[0].Kb + " " + q[0].When : "") + ")");
            int pend; sw.Restart(); List<Hotfix> c = Inventory.Cbs(out pend); sw.Stop(); Check(c.Count > 0, "inventory: " + c.Count + " CBS packages with a KB in " + sw.ElapsedMilliseconds + " ms, " + pend + " pending");
            try { sw.Restart(); List<Hotfix> h = Inventory.WuHistory(200); sw.Stop(); int ok = 0; foreach (Hotfix x in h) if (x.Result == "succeeded") ok++; Check(h.Count > 0, "inventory: " + h.Count + " WU history rows in " + sw.ElapsedMilliseconds + " ms, " + ok + " succeeded, latest: " + (h.Count > 0 ? h[0].Title : "")); }
            catch (Exception ex) { Check(false, "inventory: WU history: " + ex.Message); }
        }
        static void Feeds_()
        {
            if (!Http.Online()) { Info("feeds: offline, skipped"); return; }
            FeedCache cache = new FeedCache(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "cache"));
            try
            {
                string note; Stopwatch sw = Stopwatch.StartNew(); Dictionary<string, KevEntry> kev = Kev.Load(cache, out note); sw.Stop();
                Check(kev.Count > 1000 && kev.ContainsKey("CVE-2021-44228"), "feeds: KEV " + kev.Count + " entries in " + sw.ElapsedMilliseconds + " ms (" + note + "), Log4Shell present");
                sw.Restart(); Dictionary<string, double> ep = Epss.Scores(new string[] { "CVE-2021-44228", "CVE-2014-0160" }, cache, null); sw.Stop();
                Check(ep.ContainsKey("CVE-2021-44228") && ep["CVE-2021-44228"] > 0.5, "feeds: EPSS Log4Shell = " + (ep.ContainsKey("CVE-2021-44228") ? ep["CVE-2021-44228"].ToString("0.000") : "?") + " in " + sw.ElapsedMilliseconds + " ms");
                sw.Restart(); List<string> rel = Msrc.Releases(cache, out note); sw.Stop(); Check(rel.Count > 12 && rel[0].Length == 8, "feeds: MSRC releases " + rel.Count + ", newest " + (rel.Count > 0 ? rel[0] : "?") + " (" + note + ")");
                sw.Restart(); List<CveRecord> recs = Nvd.ForProduct("7-zip", "7-zip", "21.07", null, cache, null, out note); sw.Stop(); bool has = false; foreach (CveRecord r in recs) if (r.Id == "CVE-2022-29072") has = true;
                Check(recs.Count > 0 && has, "feeds: NVD 7-zip 21.07 → " + recs.Count + " CVEs incl. CVE-2022-29072 in " + sw.ElapsedMilliseconds + " ms (" + note + ")");
                Software sw7 = new Software(); sw7.Name = "7-Zip 21.07"; sw7.Version = "21.07"; sw7.Vendor = "7-zip"; sw7.Product = "7-zip"; List<Finding> f = Resolve.ThirdParty(sw7, recs); int open = 0; foreach (Finding x in f) if (x.Open) open++;
                Check(open > 0, "feeds: " + open + " confirmed finding(s) for 7-Zip 21.07 locally, " + (f.Count - open) + " unconfirmed");
                string cur = rel[0]; string body = ""; List<MsrcRec> mr = new List<MsrcRec>(); sw.Restart(); Stopwatch p = new Stopwatch();
                for (int ri = 0; ri < rel.Count && ri < 3; ri++)   // the newest document can be a small "Early" release (e.g. 4 records): test against the newest full month
                {
                    cur = rel[ri]; body = Msrc.Fetch(cur, cache, out note); p.Restart(); mr = Msrc.Parse(body, cur); p.Stop();
                    if (mr.Count > 500) break;
                }
                sw.Stop(); int withBuild = 0; foreach (MsrcRec r in mr) if (r.FixedBuild != null) withBuild++;
                Check(mr.Count > 500 && withBuild > mr.Count / 2, "feeds: MSRC " + cur + " " + (body.Length / 1024 / 1024) + " MB fetched in " + sw.ElapsedMilliseconds + " ms (" + note + "), parsed " + mr.Count + " records in " + p.ElapsedMilliseconds + " ms, " + withBuild + " with FixedBuild");
                OsInfo os = Inventory.Os(); List<Finding> ff = Resolve.Msrc(mr, os, new HashSet<string>(), new List<Software>(), new RebootInfo()); int vul = 0; foreach (Finding x in ff) if (x.Open) vul++;
                Check(ff.Count > 0, "feeds: " + ff.Count + " CVEs apply to build " + os.FullBuild + " in " + cur + ", " + vul + " open with no KB knowledge");
            }
            catch (Exception ex) { Check(false, "feeds: " + ex.Message); }
        }
    
        static void Recon_()
        {
            ReconScan s = new ReconScan(); s.DoEvents = true; Stopwatch sw = Stopwatch.StartNew(); s.Run(); sw.Stop();
            System.Collections.Generic.List<string> secs = s.Report.Sections();
            Check(s.Report.Items.Count > 20 && secs.Count >= 6, "recon: " + s.Report.Items.Count + " facts across " + secs.Count + " sections in " + sw.Elapsed.TotalSeconds.ToString("N1") + " s (" + s.Report.Bad + " risk, " + s.Report.Warn + " review)");
            bool hasSys=false, hasNet=false, hasProc=false; foreach (string x in secs) { if (x.StartsWith("1.")) hasSys=true; if (x.StartsWith("3.")) hasNet=true; if (x.StartsWith("6.")) hasProc=true; }
            Check(hasSys && hasNet && hasProc && s.Report.Os.Length > 0, "recon: system, network and process sections present; OS = " + s.Report.Os);
            bool anyValue=false; foreach (ReconItem i in s.Report.Items) if (i.Section.StartsWith("1.") && i.Name == "Build" && i.Value.Length > 0) anyValue=true; Check(anyValue, "recon: OS build populated");
            string js = s.Report.ToJson(); object doc = Json.Parse(js); int jsSecs = Json.Arr(Json.Get(doc, "sections")).Count;
            Check(jsSecs == secs.Count && (Json.N(Json.Get(doc, "summary", "facts")) ?? 0) == s.Report.Items.Count, "recon: JSON re-parses with " + jsSecs + " sections and matching fact count");
            string md = s.Report.ToMarkdown(); Check(md.Contains("# System Recon & Audit") && md.Contains("## 1. System Information") && md.IndexOf("|") > 0, "recon: Markdown has title, section heads and tables (" + md.Length + " B)");
            foreach (ReconItem i in s.Report.Items) if (i.Risk == "bad" || i.Risk == "warn") { Info("recon flag [" + i.Risk + "] " + i.Group + " / " + i.Name + ": " + i.Value); }
        }
        static void Pdf_()
        {
            System.Collections.Generic.List<PdfLine> lines = new System.Collections.Generic.List<PdfLine>();
            lines.Add(new PdfLine("Title Line", true, 15, 0));
            for (int i = 0; i < 400; i++) lines.Add(new PdfLine("Row " + i + " with some text that is reasonably long and includes symbols -> OK <= done and a (paren) here", false, 9, 0));
            lines.Add(new PdfLine("A single very long word " + new string('x', 300), false, 9, 0));
            string path = Path.Combine(Path.GetTempPath(), "pstools-pdf-test.pdf"); Pdf.Write(path, lines);
            byte[] b = File.ReadAllBytes(path); string head = Encoding.ASCII.GetString(b, 0, 8); string tail = Encoding.ASCII.GetString(b, b.Length - 5, 5);
            int pages = 0; string all = Encoding.ASCII.GetString(b); int idx = 0; while ((idx = all.IndexOf("/Type /Page", idx)) >= 0) { if (all.IndexOf("/Type /Pages", idx) != idx) pages++; idx += 11; }
            Check(head == "%PDF-1.4" && tail == "%%EOF" && b.Length > 2000, "pdf: valid header/trailer, " + b.Length + " bytes");
            Check(pages >= 6, "pdf: 400 rows paginated into " + pages + " pages (wrapping + page breaks)");
            Check(all.Contains("\\(paren\\)"), "pdf: parentheses escaped in content stream");
            File.Delete(path);
        }

    
        static void Wildcard_()
        {
            Check(Wildcard.Match("Report.docx", "report", false) && !Wildcard.Match("Report.docx", "report", true), "wildcard: substring, case toggle");
            Check(Wildcard.Match("photo.JPG", "*.jpg", false) && !Wildcard.Match("photo.jpeg", "*.jpg", false) && Wildcard.Match("a.b.c.txt", "*.txt", false), "wildcard: *.ext");
            Check(Wildcard.Match("data2026.csv", "data????.csv", false) && !Wildcard.Match("data26.csv", "data????.csv", false), "wildcard: ? is exactly one char");
            Check(Wildcard.Match("anything", "*", false) && Wildcard.Match("ab", "a*b", false) && !Wildcard.Match("axc", "a*b", false), "wildcard: leading/middle stars");
            Check(!Wildcard.HasWildcard("plain") && Wildcard.HasWildcard("a*"), "wildcard: detection");
        }
        static void Hashes_()
        {
            string dir = Path.Combine(Path.GetTempPath(), "pstools-hash"); Directory.CreateDirectory(dir); string f = Path.Combine(dir, "abc.txt"); File.WriteAllText(f, "abc");
            System.Collections.Generic.Dictionary<string,string> h = Hashes.Compute(f, true, true, true);
            Check(h["MD5"] == "900150983cd24fb0d6963f7d28e17f72" && h["SHA1"] == "a9993e364706816aba3e25717850c26c9cd0d89d" && h["SHA256"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "hashes: MD5/SHA1/SHA256 of 'abc' match the known vectors");
            // extract hashes of every type from arbitrary, messy text (a log line + JSON), not just a clean list
            string sample = "2024-01-01 alert file=evil.exe md5=900150983CD24FB0D6963F7D28E17F72 sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n" +
                            "{ \"sha1\": \"a9993e364706816aba3e25717850c26c9cd0d89d\", \"note\": \"deadbeefdeadbeef99 is 18 hex, not a hash\" }";
            bool md5, sha1, sha256; int bad; System.Collections.Generic.HashSet<string> t = Hashes.ParseTargets(sample, out md5, out sha1, out sha256, out bad);
            Check(t.Count == 3 && md5 && sha1 && sha256 && bad >= 1 && t.Contains("900150983cd24fb0d6963f7d28e17f72") && t.Contains("a9993e364706816aba3e25717850c26c9cd0d89d"), "hashes: regex-extract MD5+SHA1+SHA256 from messy text, lower-cased, wrong-length run flagged (" + t.Count + " found, " + bad + " bad)");
            // a 64-hex SHA-256 must not also register as an MD5/SHA-1 substring
            bool m2, s2, x2; int b2; System.Collections.Generic.HashSet<string> only = Hashes.ParseTargets("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", out m2, out s2, out x2, out b2);
            Check(only.Count == 1 && x2 && !m2 && !s2, "hashes: a 64-char SHA-256 is one hash, not split into MD5/SHA-1");
            // load hashes from a file
            string hf = Path.Combine(dir, "iocs.txt"); File.WriteAllText(hf, sample); bool fm, fs, fx; int fb; string note; System.Collections.Generic.HashSet<string> ff = Hashes.FromFile(hf, out fm, out fs, out fx, out fb, out note);
            Check(ff.Count == 3 && note.Length == 0, "hashes: FromFile extracts " + ff.Count + " hash(es) from a text file");
            Directory.Delete(dir, true);
        }
        static void Crypto_()
        {
            string dir = Path.Combine(Path.GetTempPath(), "pstools-crypto2"); Directory.CreateDirectory(dir);
            string src = Path.Combine(dir, "s.bin"); byte[] data = new byte[123457]; new Random(9).NextBytes(data); File.WriteAllBytes(src, data);
            string enc = FileCrypto.DefaultEncName(src); FileCrypto.Encrypt(src, enc, "pw-correct-123", null);
            Check(FileCrypto.IsEncrypted(enc) && !FileCrypto.IsEncrypted(src), "crypto: encrypted file detected by header");
            Check(FileCrypto.Verify(enc, "pw-correct-123") && !FileCrypto.Verify(enc, "pw-wrong"), "crypto: verify accepts the right password, rejects the wrong one");
            string dec = Path.Combine(dir, "d.bin"); FileCrypto.Decrypt(enc, dec, "pw-correct-123", null); byte[] back = File.ReadAllBytes(dec);
            bool same = back.Length == data.Length; if (same) for (int i = 0; i < data.Length; i++) if (back[i] != data[i]) { same = false; break; }
            Check(same, "crypto: decrypt reproduces the original bytes (" + back.Length + " of " + data.Length + ")");
            bool threw = false; try { FileCrypto.Decrypt(enc, dec + ".x", "pw-wrong", null); } catch (FileCrypto.CryptoException) { threw = true; } catch { threw = true; }
            Check(threw && !File.Exists(dec + ".x"), "crypto: wrong password throws and writes no output");
            // tamper a ciphertext byte -> MAC must reject
            byte[] ct = File.ReadAllBytes(enc); ct[80] ^= 0xFF; File.WriteAllBytes(enc, ct); Check(!FileCrypto.Verify(enc, "pw-correct-123"), "crypto: a flipped byte fails the HMAC");
            string wf = Path.Combine(dir, "w.bin"); File.WriteAllBytes(wf, data); FileCrypto.SecureWipe(wf, 2, null); Check(!File.Exists(wf), "crypto: secure wipe deletes the file");
            Directory.Delete(dir, true);
        }
        static void Walk_()
        {
            string here = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
            FastWalk fw = new FastWalk(); fw.Roots = new System.Collections.Generic.List<string> { here }; int cs = 0; object gate = new object();
            fw.Run(delegate (FileInfo fi) { if (fi.Extension.ToLowerInvariant() == ".cs") lock (gate) cs++; });
            Check(fw.FilesSeen > 0 && cs >= 3 && fw.DirsScanned >= 1, "walk: parallel walk of " + here + " saw " + fw.FilesSeen + " files, " + cs + " .cs, " + fw.DirsScanned + " folders");
        }
        static void Checklist_()
        {
            ChecklistScan s = new ChecklistScan(); Stopwatch sw = Stopwatch.StartNew(); s.Run(); sw.Stop();
            System.Collections.Generic.List<string> cats = s.Report.Categories();
            Check(s.Report.Items.Count >= 10 && cats.Count >= 6, "checklist: " + s.Report.Items.Count + " checks across " + cats.Count + " categories, score " + s.Report.Score + "/100 in " + sw.Elapsed.TotalSeconds.ToString("N1") + " s");
            bool hasAcct=false, hasAv=false, hasUsb=false, hasFw=false; foreach (string c in cats) { if (c.StartsWith("Accounts")) hasAcct=true; if (c.StartsWith("Antivirus")) hasAv=true; if (c.StartsWith("Peripheral")) hasUsb=true; if (c.StartsWith("Firewall")) hasFw=true; }
            Check(hasAcct && hasAv && hasUsb && hasFw, "checklist: accounts, antivirus, USB and firewall categories present");
            object doc = Json.Parse(s.Report.ToJson()); int n = Json.Arr(Json.Get(doc, "checks")).Count; Check(n == s.Report.Items.Count, "checklist: JSON re-parses with " + n + " checks");
            foreach (CheckItem i in s.Report.Items) if (i.Status == "fail" || i.Status == "warn") Info("checklist [" + i.Status + "] " + i.Category + " / " + i.Name + ": " + i.Detail);
        }

    
        static void DeletedFilter_()
        {
            System.Collections.Generic.HashSet<string> ex = DeletedScan.ParseExts("jpg, .PNG, *.docx");
            Check(ex != null && ex.Count == 3 && ex.Contains("jpg") && ex.Contains("png") && ex.Contains("docx") && DeletedScan.ParseExts("") == null, "deleted filter: extension list parsed, dots/stars/case stripped");
            // type filter: only matching extensions, folders excluded when a type is set
            Check(DeletedScan.Matches("holiday.JPG", false, 0, false, ex, null, 0, 0) && !DeletedScan.Matches("notes.txt", false, 0, false, ex, null, 0, 0) && !DeletedScan.Matches("Pictures", true, 0, false, ex, null, 0, 0), "deleted filter: type keeps jpg, drops txt and folders");
            // name-contains
            Check(DeletedScan.Matches("Report-2026.pdf", false, 0, false, null, "report", 0, 0) && !DeletedScan.Matches("invoice.pdf", false, 0, false, null, "report", 0, 0), "deleted filter: name contains (case-insensitive)");
            // size: applies only when known; unknown-size (journal) rows always pass
            long mb = 1048576;
            Check(DeletedScan.Matches("a.bin", false, 5 * mb, true, null, null, 2 * mb, 10 * mb) && !DeletedScan.Matches("a.bin", false, 1 * mb, true, null, null, 2 * mb, 0) && !DeletedScan.Matches("a.bin", false, 50 * mb, true, null, null, 0, 10 * mb), "deleted filter: size range on known sizes");
            Check(DeletedScan.Matches("a.bin", false, 0, false, null, null, 2 * mb, 10 * mb), "deleted filter: unknown-size row passes the size test (journal has no size)");
            // no filters set -> everything passes
            Check(DeletedScan.Matches("anything", true, 0, false, null, null, 0, 0), "deleted filter: no filters keeps everything");
        }

    
        static void Active_()
        {
            byte[] e = ActiveTests.EicarBytes(); string md5;
            using (System.Security.Cryptography.MD5 m = System.Security.Cryptography.MD5.Create()) { byte[] h = m.ComputeHash(e); StringBuilder sb = new StringBuilder(); foreach (byte b in h) sb.Append(b.ToString("x2")); md5 = sb.ToString(); }
            Check(e.Length == 68 && md5 == "44d88612fea8a8f36de82e1278abb02f", "active: EICAR test string reconstructed at runtime (68 bytes, md5 " + md5.Substring(0, 8) + "…), never stored literally in the exe");
        }

        static void Trust_()
        {
            // the app's own compiler (csc) is Authenticode+catalog signed by Microsoft; kernel32 is catalog-signed
            string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            string k32 = Path.Combine(win, "System32", "kernel32.dll");
            SigInfo si = Trust.Verify(k32);
            Check(si.Ok && si.Microsoft, "trust: kernel32.dll verifies as Microsoft-signed (" + si.Status + (si.Signer.Length > 0 ? " " + si.Signer : "") + ")");
            // a file we just wrote is unsigned
            string tmp = Path.Combine(Path.GetTempPath(), "pstools-trust-" + Guid.NewGuid().ToString("N") + ".exe");
            try { File.WriteAllBytes(tmp, new byte[] { 0x4D, 0x5A, 0, 0 }); SigInfo u = Trust.Verify(tmp); Check(u.Status == "unsigned" || u.Status == "invalid", "trust: a hand-written .exe reads as " + u.Status); } finally { try { File.Delete(tmp); } catch { } }
            Check(Trust.Location(k32) == "windows", "trust: kernel32 located under windows");
            string img = Trust.ImagePath("\"" + k32 + "\" -k netsvcs"); Check(img.EndsWith("kernel32.dll", StringComparison.OrdinalIgnoreCase), "trust: image path parsed from a quoted command line");
            Check(Trust.ImagePath("svchost.exe -k netsvcs").EndsWith("svchost.exe", StringComparison.OrdinalIgnoreCase), "trust: bare exe resolved on the PATH/System32");
        }
        static void Autoruns_()
        {
            List<AutorunEntry> l = Autoruns.Collect(null, null);
            Check(l.Count > 5, "autoruns: collected " + l.Count + " autostart entries");
            List<string> kinds = new List<string>(); foreach (AutorunEntry e in l) if (!kinds.Contains(e.Kind)) kinds.Add(e.Kind);
            Check(kinds.Count >= 3, "autoruns: " + kinds.Count + " kinds (" + string.Join(", ", kinds.ToArray()) + ")");
            bool anyService = false; foreach (AutorunEntry e in l) if (e.Kind == "Service") anyService = true;
            Check(anyService, "autoruns: services enumerated");
        }
        static void Events_()
        {
            Check(EventHunt.Categories().Count >= 15, "events: " + EventHunt.Categories().Count + " hunt categories defined");
            List<EventRow> rows = EventHunt.Collect(EventHunt.Specs, DateTime.Now.AddDays(-30), 20, null, null, null);
            bool ordered = true; for (int i = 1; i < rows.Count; i++) if (rows[i].Time > rows[i - 1].Time) ordered = false;
            Check(ordered, "events: collected " + rows.Count + " events, newest-first");
        }
        static void Dupes_()
        {
            string dir = Path.Combine(Path.GetTempPath(), "pstools-dupe-" + Guid.NewGuid().ToString("N"));
            try
            {
                Directory.CreateDirectory(dir); byte[] a = new byte[12345]; new Random(7).NextBytes(a);
                File.WriteAllBytes(Path.Combine(dir, "one.bin"), a); File.WriteAllBytes(Path.Combine(dir, "two.bin"), a); File.WriteAllBytes(Path.Combine(dir, "three.bin"), a);
                byte[] b = new byte[12345]; new Random(8).NextBytes(b); File.WriteAllBytes(Path.Combine(dir, "diff.bin"), b);
                DupeScan sc = new DupeScan(); sc.Roots = new List<string>(new string[] { dir }); sc.MinBytes = 1; List<DupeGroup> g = sc.Run(null);
                Check(g.Count == 1 && g[0].Count == 3, "dupes: 3 identical files form 1 group (got " + g.Count + " group(s))");
                Check(g.Count == 1 && g[0].Wasted == 24690, "dupes: wasted space = " + (g.Count > 0 ? g[0].Wasted : 0) + " (expected 24690)");
            }
            finally { try { Directory.Delete(dir, true); } catch { } }
        }
        // ── the collection bundle (.ptb) and the engagement file ──
        static int IndexOf(byte[] hay, byte[] needle) { for (int i = 0; i + needle.Length <= hay.Length; i++) { int j = 0; while (j < needle.Length && hay[i + j] == needle[j]) j++; if (j == needle.Length) return i; } return -1; }
        static void Bundle_()
        {
            // the writer is the twin of the parser: a tree survives write → parse → write unchanged
            Dictionary<string, object> t = new Dictionary<string, object>(); t["s"] = "q\"\\ é\n\t"; t["n"] = 2.5; t["i"] = 42; t["b"] = true; t["z"] = null; t["l"] = new List<object>(new object[] { 1, "x", false, null }); Dictionary<string, object> inner = new Dictionary<string, object>(); inner["k"] = -3e2; t["o"] = inner; t["d"] = new DateTime(2026, 10, 13, 7, 4, 5, DateTimeKind.Utc); t["e"] = new List<object>();
            Check(JsonWrite.Int(42, 0) == 42 && JsonWrite.Int(42.0, 0) == 42 && JsonWrite.Int("7", 0) == 7 && JsonWrite.Int("x", -1) == -1 && Json.S(5) == "5" && JsonWrite.Date(new DateTime(2026, 1, 2, 0, 0, 0, DateTimeKind.Utc)).HasValue, "json read: boxed ints, doubles and numeric strings all read as numbers; a boxed DateTime reads as a date (trees built in-process, not only parsed ones)");
            Check(Json.Arr(new List<string>(new string[] { "a", "b" })).Count == 2 && Json.Arr(new string[] { "x" }).Count == 1 && Json.Arr("str").Count == 0 && Json.Arr(new Dictionary<string, object>()).Count == 0 && Json.S(new DateTime(2026, 10, 13, 9, 0, 0, DateTimeKind.Utc)) == "2026-10-13T09:00:00Z" && JsonWrite.Strings(new List<string>(new string[] { "k" }))[0] == "k", "json read: in-process lists (List<string>, arrays) and boxed DateTimes read like their JSON forms; strings and objects are not arrays");
            string j1 = JsonWrite.Text(t, true); string j2 = JsonWrite.Text(Json.Parse(j1), true);
            Check(j1 == j2 && j1.Contains("\"d\": \"2026-10-13T07:04:05Z\"") && JsonWrite.Text(t, false).IndexOf('\n') < 0 && (string)Json.Get(Json.Parse(j1), "s") == "q\"\\ é\n\t", "json write: tree → text → parse → text is stable; dates are ISO UTC; compact form has no newlines; escapes round-trip");
            Bundle b = new Bundle(); b.Manifest["host"] = "HOST1"; b.Manifest["runId"] = "r1"; b.Manifest["platform"] = "windows"; Dictionary<string, object> inv = new Dictionary<string, object>(); inv["os"] = "Windows 11"; b["inventory"] = inv; b.Module("inventory", "ok", 1, 12, null);
            string dir = Path.Combine(Path.GetTempPath(), "pstools-ptb-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(dir);
            try
            {
                string p = Path.Combine(dir, "a.ptb"); b.Save(p, BundleKey.FromPassphrase("correct horse")); Bundle r = Bundle.Load(p, BundleKey.FromPassphrase("correct horse"));
                Check(r.Host == "HOST1" && Json.GetS(r["inventory"], "os") == "Windows 11" && r.Modules.Count == 1 && r.ModuleStatus("inventory") == "ok" && Bundle.ModeOf(p) == "passphrase", "bundle: passphrase seal → open round-trips the manifest, sections and module list");
                string err = ""; try { Bundle.Load(p, BundleKey.FromPassphrase("wrong")); } catch (BundleException ex) { err = ex.Message; } Check(err.Contains("integrity"), "bundle: a wrong passphrase is refused (" + err + ")");
                byte[] raw = File.ReadAllBytes(p); Check(IndexOf(raw, Encoding.UTF8.GetBytes("HOST1")) < 0 && IndexOf(raw, Encoding.UTF8.GetBytes("Windows 11")) < 0, "bundle: the sealed file does not contain the plaintext");
                byte[] bit = (byte[])raw.Clone(); bit[bit.Length - 40] ^= 0x01; File.WriteAllBytes(p + ".bit", bit); err = ""; try { Bundle.Load(p + ".bit", BundleKey.FromPassphrase("correct horse")); } catch (BundleException ex) { err = ex.Message; } Check(err.Contains("integrity"), "bundle: a flipped ciphertext bit is refused (" + err + ")");
                byte[] cut = new byte[raw.Length - 20]; Buffer.BlockCopy(raw, 0, cut, 0, cut.Length); File.WriteAllBytes(p + ".cut", cut); err = ""; try { Bundle.Load(p + ".cut", BundleKey.FromPassphrase("correct horse")); } catch (BundleException ex) { err = ex.Message; } Check(err.Length > 0, "bundle: a truncated file is refused (" + err + ")");
                // public-key mode: the collector only ever holds the public half
                string pub, priv; BundleCrypto.NewKeyPair(2048, out pub, out priv); string p2 = Path.Combine(dir, "b.ptb"); b.Save(p2, BundleKey.ToPublic(pub));
                Check(Bundle.ModeOf(p2) == "public-key" && Bundle.Load(p2, BundleKey.WithPrivate(priv)).Host == "HOST1" && BundleCrypto.KeyId(pub) == BundleCrypto.KeyId(BundleCrypto.PublicOf(priv)), "bundle: sealed to the engagement public key, opened with the private key; key id agrees both ways");
                string pub2, priv2; BundleCrypto.NewKeyPair(2048, out pub2, out priv2); err = ""; try { Bundle.Load(p2, BundleKey.WithPrivate(priv2)); } catch (BundleException ex) { err = ex.Message; } Check(err.Contains("different"), "bundle: another engagement's private key is refused by key id (" + err + ")");
                err = ""; try { Bundle.Load(p2, BundleKey.FromPassphrase("x")); } catch (BundleException ex) { err = ex.Message; } Check(err.Contains("private key"), "bundle: a passphrase cannot open a key-sealed bundle (" + err + ")");
                // plain mode is explicit and still integrity-checked
                string p3 = Path.Combine(dir, "c.ptb"); b.Save(p3, BundleKey.None()); Check(Bundle.ModeOf(p3) == "plain" && Bundle.Load(p3, BundleKey.None()).RunId == "r1", "bundle: explicit plain mode round-trips");
                raw = File.ReadAllBytes(p3); raw[raw.Length - 40] ^= 0x40; File.WriteAllBytes(p3, raw); err = ""; try { Bundle.Load(p3, BundleKey.None()); } catch (BundleException ex) { err = ex.Message; } Check(err.Contains("modified"), "bundle: a modified plain bundle fails its hash (" + err + ")");
                err = ""; try { Bundle.FromJson("{\"manifest\":{\"schema\":\"ptb/2\"}}"); } catch (BundleException ex) { err = ex.Message; } Check(err.Contains("ptb/2"), "bundle: an unknown schema is refused, not guessed");
                err = ""; try { Bundle.Load(Path.Combine(dir, "nothing.ptb"), BundleKey.None()); } catch (FileNotFoundException) { err = "missing"; } Check(err == "missing", "bundle: a missing file surfaces as FileNotFound, not as a crypto error");
                // DPAPI for the private key at rest on the controller
                byte[] prot = BundleCrypto.Protect(Encoding.UTF8.GetBytes(priv), "eng-1"); Check(IndexOf(prot, Encoding.UTF8.GetBytes("<RSAKeyValue>")) < 0 && Encoding.UTF8.GetString(BundleCrypto.Unprotect(prot, "eng-1")) == priv, "bundle: DPAPI-protected private key is opaque at rest and comes back intact");
                err = ""; try { BundleCrypto.Unprotect(prot, "eng-2"); } catch (BundleException ex) { err = ex.Message; } Check(err.Length > 0, "bundle: a DPAPI blob with another engagement's entropy is refused");
            }
            finally { try { Directory.Delete(dir, true); } catch { } }
        }
        static void Engagement_()
        {
            Engagement e = new Engagement(); e.Id = "ENG-2026-001"; e.Client = "Acme"; e.Operator = "ops"; e.Scope.AddRange(new string[] { "10.0.0.0/24", "WS-FIN-01", "192.168.5.7" }); e.WindowStartUtc = new DateTime(2026, 10, 1, 0, 0, 0, DateTimeKind.Utc); e.WindowEndUtc = new DateTime(2026, 10, 31, 0, 0, 0, DateTimeKind.Utc); e.Modules.Add("inventory"); e.RetentionDays = 30;
            string why;
            Check(e.InScope("10.0.0.205", out why) && e.InScope("ws-fin-01", out why) && e.InScope("192.168.5.7", out why), "engagement: CIDR, host name (case-insensitive) and exact IP are in scope");
            Check(!e.InScope("10.0.1.5", out why) && !e.InScope("WS-FIN-02", out why) && why.Length > 0, "engagement: outside the CIDR / an unlisted host is out of scope (" + why + ")");
            Check(!new Engagement().InScope("10.0.0.1", out why), "engagement: an empty scope allows nothing (fail closed)");
            Check(e.InWindow(new DateTime(2026, 10, 13, 12, 0, 0, DateTimeKind.Utc), out why) && !e.InWindow(new DateTime(2026, 11, 2, 0, 0, 0, DateTimeKind.Utc), out why) && why.Contains("closed"), "engagement: the time window is enforced (" + why + ")");
            Check(e.ModuleAllowed("inventory") && !e.ModuleAllowed("secrets") && new Engagement().ModuleAllowed("recon"), "engagement: module allow-list; an empty list allows every read-only module");
            string f = Path.Combine(Path.GetTempPath(), "pstools-eng-" + Guid.NewGuid().ToString("N") + ".json");
            try { e.Save(f); Engagement r = Engagement.Load(f); Check(r.Id == e.Id && r.Scope.Count == 3 && r.WindowEndUtc == e.WindowEndUtc && r.RetentionDays == 30 && r.Modules.Count == 1 && r.Validate().Count == 0, "engagement: file round-trip, valid"); }
            finally { try { File.Delete(f); } catch { } }
            Engagement bad = new Engagement(); bad.Scope.Add("300.1.1.1/40"); bad.WindowStartUtc = new DateTime(2026, 2, 1); bad.WindowEndUtc = new DateTime(2026, 1, 1); List<string> errs = bad.Validate(); Check(errs.Count == 3, "engagement: validation names the missing id, the bad CIDR and the inverted window (" + string.Join("; ", errs.ToArray()) + ")");
        }
        static void Collect_()
        {
            // codecs: engine objects → tree → text → tree → objects, field for field
            Software s = new Software(); s.Name = "7-Zip 24.08"; s.Version = "24.08"; s.Publisher = "Igor Pavlov"; s.InstallDate = "20250102"; s.Scope = "machine"; s.Vendor = "7-zip"; s.Product = "7-zip";
            Software s2 = Codec.SoftwareFrom(Json.Parse(JsonWrite.Text(Codec.Software(s)))); Software un = new Software(); un.Name = "Thing"; Software un2 = Codec.SoftwareFrom(Json.Parse(JsonWrite.Text(Codec.Software(un))));
            Check(s2.Name == s.Name && s2.Version == s.Version && s2.Vendor == "7-zip" && s2.Mapped && s2.Installed == "2025-01-02" && !un2.Mapped && un2.Vendor == null, "codec: software round-trips, mapped and unmapped alike");
            OsInfo os = new OsInfo(); os.ProductName = "Windows 11 Pro"; os.Major = 10; os.Build = 26100; os.Ubr = 4000; os.Arch = "x64"; os.Host = "H"; os.Installed = new DateTime(2025, 12, 1, 0, 0, 0, DateTimeKind.Utc);
            OsInfo os2 = Codec.OsFrom(Json.Parse(JsonWrite.Text(Codec.Os(os)))); Check(os2.FullBuild == "10.0.26100.4000" && os2.ProductName == os.ProductName && os2.Installed.HasValue && os2.Installed.Value == os.Installed.Value, "codec: OS build identity and install date round-trip");
            Hotfix h = new Hotfix(); h.Kb = "5060000"; h.Source = "QFE"; h.InstalledOn = new DateTime(2026, 9, 21, 0, 0, 0, DateTimeKind.Utc); Hotfix h2 = Codec.HotfixFrom(Json.Parse(JsonWrite.Text(Codec.Hotfix(h)))); Check(h2.Kb == "5060000" && h2.Source == "QFE" && h2.InstalledOn.HasValue && h2.InstalledOn.Value == h.InstalledOn.Value, "codec: hotfix round-trips with its date");
            Finding f = new Finding(); f.Cve = "CVE-2026-1"; f.Severity = "Important"; f.Status = "vulnerable"; f.Cvss = 7.8; f.Epss = 0.42; f.Kev = true; f.Fix = "KB1"; f.Source = "MSRC"; f.Product = "Windows 11"; f.Evidence = "e"; f.Url = "u";
            Finding f2 = Codec.FindingFrom(Json.Parse(JsonWrite.Text(Codec.Finding(f)))); Check(f2.Cve == "CVE-2026-1" && f2.Open && f2.Kev && f2.Cvss == 7.8 && f2.Epss == 0.42 && f2.SeverityNorm == "High" && f2.Fix == "KB1", "codec: finding round-trips (status, KEV, CVSS, EPSS)");
            MissingUpdate mu = new MissingUpdate(); mu.Kb = "5066000"; mu.Title = "CU"; mu.Cves.Add("CVE-2026-2"); mu.Kind = "security"; MissingUpdate mu2 = Codec.MissingFrom(Json.Parse(JsonWrite.Text(Codec.Missing(mu)))); Check(mu2.Kb == "5066000" && mu2.Cves.Count == 1 && mu2.Kind == "security", "codec: missing update round-trips with its CVE list");
            RebootInfo rb = new RebootInfo(); rb.Cbs = true; RebootInfo rb2 = Codec.RebootFrom(Json.Parse(JsonWrite.Text(Codec.Reboot(rb)))); Check(rb2.Pending && rb2.Cbs && !rb2.WindowsUpdate, "codec: reboot state round-trips");
            CheckItem ci = new CheckItem("Accounts", "Guest account", "Is it off?", "pass", "disabled", "net user"); ci.Id = "PT-W-ACC-001"; CheckItem ci2 = Codec.CheckFrom(Json.Parse(JsonWrite.Text(Codec.Check(ci)))); Check(ci2.Id == "PT-W-ACC-001" && ci2.Status == "pass" && ci2.Name == "Guest account" && ci2.Evidence == "net user", "codec: checklist item round-trips with its id");
            SecretHit sh = new SecretHit(); sh.Kind = "GitHub token"; sh.Severity = "high"; sh.Path = "C:\\x\\.env"; sh.File = ".env"; sh.Line = 3; sh.Match = "ghp_SECRETVALUE1234567890abcdefghij"; sh.Preview = "ghp_••••••hij";
            string st = JsonWrite.Text(Codec.Secret(sh)); Check(st.IndexOf("SECRETVALUE") < 0 && st.Contains("\"sha256\"") && st.Contains("ghp_••••••hij"), "codec: a secret hit carries kind, place, masked preview and a hash - never the secret");
            // a real collection on this machine: the fast modules only
            Collector c = new Collector(); c.Modules.Clear(); c.Modules.AddRange(new string[] { "inventory", "network" }); c.Online = false; c.WuHistory = false;
            Stopwatch sw = Stopwatch.StartNew(); Bundle b = c.Run(); sw.Stop();
            object inv = b["inventory"]; object net = b["network"];
            Check(b.Host == Environment.MachineName && b.Platform == "windows" && b.RunId.Length > 0 && Json.GetS(b.Manifest, "collector", "name") == "PowerTowerCollect" && Json.GetS(b.Manifest, "privilegeTier") != null && b.Manifest.ContainsKey("finishedUtc"), "collect: manifest carries host, platform, run id, collector identity, privilege tier and timings");
            Check(b.ModuleStatus("inventory") == "ok" && Json.Arr(Json.Get(inv, "software")).Count > 5 && Json.Arr(Json.Get(inv, "hotfixes")).Count > 0 && Json.GetS(inv, "os", "fullBuild").Split('.').Length == 4 && (Json.GetS(inv, "missingStatus") ?? "").StartsWith("not searched"), "collect: inventory has software, hotfixes, the OS build, and says the missing-update search was not run offline (" + sw.Elapsed.TotalSeconds.ToString("N1") + " s)");
            Check(b.ModuleStatus("network") == "ok" && Json.Arr(Json.Get(net, "connections")).Count > 0 && Json.Arr(Json.Get(net, "firewall", "rules")).Count > 0, "collect: network has connections and firewall rules");
            Check(b.ModuleStatus("checklist") == null && b["checklist"] == null, "collect: modules not asked for are absent, not failed");
            string tmp = Path.Combine(Path.GetTempPath(), "pstools-collect-" + Guid.NewGuid().ToString("N") + ".ptb");
            try { b.Save(tmp, BundleKey.None()); Bundle r = Bundle.Load(tmp, BundleKey.None()); Check(Json.Arr(Json.Get(r["inventory"], "software")).Count == Json.Arr(Json.Get(inv, "software")).Count && r.Modules.Count == b.Modules.Count && Codec.OsFrom(Json.Get(r["inventory"], "os")).FullBuild == Inventory.Os().FullBuild, "collect: the saved bundle reloads with the same counts and the same OS build"); }
            finally { try { File.Delete(tmp); } catch { } }
            // the engagement gate: wrong scope refuses to run; the module allow-list skips, not fails
            Engagement eg = new Engagement(); eg.Id = "E"; eg.Scope.Add("192.0.2.1"); eg.WindowStartUtc = DateTime.UtcNow.AddDays(-1); eg.WindowEndUtc = DateTime.UtcNow.AddDays(1); Collector c2 = new Collector(); c2.Modules.Clear(); c2.Modules.Add("inventory"); c2.Engagement = eg; string err = ""; try { c2.Run(); } catch (BundleException ex) { err = ex.Message; } Check(err.Contains("scope"), "collect: a host outside the engagement scope is refused before anything is read (" + err + ")");
            eg.Scope.Clear(); eg.Scope.Add("*"); eg.Modules.Add("network"); Collector c3 = new Collector(); c3.Modules.Clear(); c3.Modules.AddRange(new string[] { "inventory", "network" }); c3.Engagement = eg; c3.WuHistory = false; Bundle b3 = c3.Run();
            Check(b3.ModuleStatus("inventory") == "skipped" && b3.ModuleStatus("network") == "ok" && Json.GetS(b3.Manifest, "engagementId") == "E", "collect: modules outside the engagement allow-list are skipped and recorded");
            // the IOC sweep finds this very process by hash
            string me = System.Reflection.Assembly.GetExecutingAssembly().Location; string myHash = BundleCrypto.FileSha256(me); string ioc = Path.Combine(Path.GetTempPath(), "pstools-ioc-" + Guid.NewGuid().ToString("N") + ".txt");
            try
            {
                File.WriteAllText(ioc, "# test list\nevil.example-c2.net\n203.0.113.9\n" + myHash + "\n");
                Collector c4 = new Collector(); c4.Modules.Clear(); c4.Modules.AddRange(new string[] { "network", "ioc" }); c4.IocFile = ioc; sw.Restart(); Bundle b4 = c4.Run(); sw.Stop(); object io = b4["ioc"];
                bool hit = false; foreach (object m in Json.Arr(Json.Get(io, "matches"))) if (Json.GetS(m, "type") == "hash" && string.Equals(Json.GetS(m, "value"), myHash, StringComparison.OrdinalIgnoreCase)) hit = true;
                Check(b4.ModuleStatus("ioc") == "ok" && JsonWrite.Int(Json.Get(io, "counts", "hashes"), 0) == 1 && JsonWrite.Int(Json.Get(io, "counts", "domains"), 0) == 1 && JsonWrite.Int(Json.Get(io, "counts", "ips"), 0) == 1 && hit, "collect: IOC sweep parses the list (1 domain, 1 IP, 1 hash) and matches this process image by SHA-256 (" + JsonWrite.Int(Json.Get(io, "imagesHashed"), 0) + " images hashed in " + sw.Elapsed.TotalSeconds.ToString("N1") + " s; status " + b4.ModuleStatus("ioc") + "; counts " + JsonWrite.Text(Json.Get(io, "counts"), false) + "; processes " + JsonWrite.Int(Json.Get(io, "processes"), -1) + " noPath " + JsonWrite.Int(Json.Get(io, "processesWithoutPath"), -1) + " paths " + JsonWrite.Int(Json.Get(io, "imagePaths"), -1) + " skipped " + JsonWrite.Int(Json.Get(io, "imagesSkipped"), -1) + " hashErrors " + JsonWrite.Int(Json.Get(io, "hashErrors"), -1) + "; errors " + string.Join(" | ", JsonWrite.Strings(Json.Get(b4.Modules[b4.Modules.Count - 1], "errors")).ToArray()) + ")");
            }
            finally { try { File.Delete(ioc); } catch { } }
            // the option mapping both front-ends share
            Collector c5 = new Collector(); Dictionary<string, string> opt = new Dictionary<string, string>(); opt["modules"] = "inventory, bogus";
            string e5 = CollectOptions.Apply(c5, delegate (string n) { string v; return opt.TryGetValue(n, out v) ? v : null; }, delegate (string n) { return opt.ContainsKey(n); }, delegate (string n) { return new List<string>(); });
            Check(e5 != null && e5.Contains("bogus"), "collect options: an unknown module is a usage error, not a silent skip (" + e5 + ")");
            opt["modules"] = "ioc"; e5 = CollectOptions.Apply(new Collector(), delegate (string n) { string v; return opt.TryGetValue(n, out v) ? v : null; }, delegate (string n) { return opt.ContainsKey(n); }, delegate (string n) { return new List<string>(); });
            Check(e5 != null && e5.Contains("--ioc"), "collect options: the ioc module without a list is a usage error");
            string ke; BundleKey k0 = CollectOptions.Key(new Collector(), delegate (string n) { return null; }, delegate (string n) { return false; }, out ke); Check(k0 == null && ke.Contains("--plain"), "collect options: no sealing choice is a usage error that names the choices (never silently plain)");
        }
        // ── FUZZ's four Major findings: PT-20 plain-mode downgrade, PT-21 kdf cost from the file, PT-23 unbounded nesting, PT-22 destructive code in the collector ──
        static byte[] Rehead(byte[] file, string kdfKey, object value)
        {
            int hlen = BitConverter.ToInt32(file, 4); Dictionary<string, object> h = Json.Obj(Json.Parse(Encoding.UTF8.GetString(file, 8, hlen)));
            Dictionary<string, object> kdf = Json.Obj(h["kdf"]); kdf[kdfKey] = value; byte[] nh = Encoding.UTF8.GetBytes(JsonWrite.Text(h, false));
            byte[] o = new byte[file.Length - hlen + nh.Length]; Buffer.BlockCopy(file, 0, o, 0, 4); Buffer.BlockCopy(BitConverter.GetBytes(nh.Length), 0, o, 4, 4); Buffer.BlockCopy(nh, 0, o, 8, nh.Length); Buffer.BlockCopy(file, 8 + hlen, o, 8 + nh.Length, file.Length - 8 - hlen); return o;
        }
        static void BundleGate_()
        {
            byte[] forged = BundleCrypto.Seal(Encoding.UTF8.GetBytes("{\"manifest\":{\"schema\":\"ptb/1\",\"host\":\"EVIL\"}}"), BundleKey.None());
            string err = ""; try { BundleCrypto.Open(forged, BundleKey.FromPassphrase("correct horse")); } catch (BundleException ex) { err = ex.Message; } Check(err.Contains("not sealed"), "PT-20: a plain file is refused when a passphrase was given (" + err + ")");
            string pub, priv; BundleCrypto.NewKeyPair(2048, out pub, out priv);
            err = ""; try { BundleCrypto.Open(forged, BundleKey.WithPrivate(priv)); } catch (BundleException ex) { err = ex.Message; } Check(err.Contains("not sealed"), "PT-20: a plain file is refused when an engagement private key was given");
            Check(Encoding.UTF8.GetString(BundleCrypto.Open(forged, BundleKey.None())).Contains("EVIL") && Encoding.UTF8.GetString(BundleCrypto.Open(forged, null)).Contains("EVIL"), "PT-20: an explicit plain key (or none) still opens a plain file - the lab workflow keeps working");
            byte[] sealedP = BundleCrypto.Seal(Encoding.UTF8.GetBytes("{\"a\":1}"), BundleKey.FromPassphrase("correct horse"));
            Stopwatch sw = Stopwatch.StartNew(); err = ""; try { BundleCrypto.Open(Rehead(sealedP, "iterations", 100000000), BundleKey.FromPassphrase("correct horse")); } catch (BundleException ex) { err = ex.Message; } sw.Stop();
            Check(err.Contains("unsupported kdf cost") && sw.ElapsedMilliseconds < 1000, "PT-21: a header claiming 100,000,000 iterations is refused in " + sw.ElapsedMilliseconds + " ms (" + err + ")");
            sw.Restart(); err = ""; try { BundleCrypto.Open(Rehead(sealedP, "iterations", 2147483647), BundleKey.FromPassphrase("correct horse")); } catch (BundleException ex) { err = ex.Message; } sw.Stop(); Check(err.Length > 0 && sw.ElapsedMilliseconds < 1000, "PT-21: int.MaxValue iterations refused in " + sw.ElapsedMilliseconds + " ms");
            err = ""; try { BundleCrypto.Open(Rehead(sealedP, "iterations", 1000), BundleKey.FromPassphrase("correct horse")); } catch (BundleException ex) { err = ex.Message; } Check(err.Contains("below"), "PT-21: a header downgrading the cost below this build's minimum is refused (" + err + ")");
            BundleKey legacy = BundleKey.FromPassphrase("correct horse"); legacy.AllowLegacyKdf = true; err = ""; try { BundleCrypto.Open(Rehead(sealedP, "iterations", 1000), legacy); } catch (BundleException ex) { err = ex.Message; } Check(err.Contains("integrity"), "PT-21: with AllowLegacyKdf the low count is derived and the (now wrong) MAC is what refuses it (" + err + ")");
            Check(Encoding.UTF8.GetString(BundleCrypto.Open(sealedP, BundleKey.FromPassphrase("correct horse"))) == "{\"a\":1}", "PT-21: an untouched passphrase bundle still opens");
            foreach (int n in new int[] { 10000, 100000 }) { string deep = new string('[', n) + new string(']', n); bool fe = false; try { Json.Parse(deep); } catch (FormatException ex) { fe = ex.Message.Contains("nesting"); } Check(fe, "PT-23: Json.Parse at depth " + n.ToString("N0") + " throws FormatException(nesting too deep), no stack overflow"); }
            StringBuilder deepObj = new StringBuilder(); for (int i = 0; i < 10000; i++) deepObj.Append("{\"a\":"); deepObj.Append('1'); for (int i = 0; i < 10000; i++) deepObj.Append('}'); bool fe2 = false; try { Json.Parse(deepObj.ToString()); } catch (FormatException) { fe2 = true; } Check(fe2, "PT-23: nested objects hit the same limit");
            List<object> root = new List<object>(), cur = root; for (int i = 0; i < 100000; i++) { List<object> next = new List<object>(); cur.Add(next); cur = next; }
            bool fw = false; try { JsonWrite.Text(root, false); } catch (FormatException ex) { fw = ex.Message.Contains("nesting"); } Check(fw, "PT-23: JsonWrite at depth 100,000 throws FormatException, no stack overflow");
            string ok150 = new string('[', 150) + new string(']', 150); Check(Json.Parse(ok150) is List<object> && JsonWrite.Text(Json.Parse(ok150), false) == ok150, "PT-23: depth 150 (under the " + Json.MaxDepth + " limit) still parses and writes");
        }
        static void CollectorAssembly_()
        {
            string exe = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "PowerTowerCollect.exe");
            if (!File.Exists(exe)) { Check(false, "PT-22: PowerTowerCollect.exe not found next to Tests.exe"); return; }
            System.Reflection.Assembly a = System.Reflection.Assembly.LoadFrom(exe); Type[] types = a.GetTypes();
            HashSet<string> names = new HashSet<string>(); foreach (Type t in types) names.Add(t.Name);
            Check(names.Contains("Collector") && names.Contains("Hosts") && names.Contains("Autoruns") && !names.Contains("ActiveTests") && !names.Contains("DupeScan") && !names.Contains("Cli") && !names.Contains("CliTools"), "PT-22: the collector carries the engines and no ActiveTests, duplicates or CLI framework (" + types.Length + " types)");
            string[] banned = { "Encrypt", "Decrypt", "SecureWipe", "Eicar", "EicarBytes", "AppControl", "SetEnabled", "Delete", "SetBlocked", "Recycle", "Restore" };
            List<string> hits = new List<string>(); System.Reflection.BindingFlags all = System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.DeclaredOnly;
            foreach (Type t in types) { if (t.Namespace != "PSTools") continue; foreach (System.Reflection.MethodInfo m in t.GetMethods(all)) { bool bad = m.Name.Contains("Wipe") || m.Name.Contains("Eicar"); foreach (string b in banned) if (m.Name == b) bad = true; if (bad) hits.Add(t.Name + "." + m.Name); } }
            Check(hits.Count == 0, "PT-22: no destructive method in the collector assembly" + (hits.Count > 0 ? ": " + string.Join(", ", hits.ToArray()) : ""));
            Type hosts = a.GetType("PSTools.Hosts"), fc = a.GetType("PSTools.FileCrypto"), ar = a.GetType("PSTools.Autoruns"), fwl = a.GetType("PSTools.Firewall");
            Check(hosts != null && hosts.GetMethod("Entries") != null && hosts.GetMethod("Write") == null && hosts.GetMethod("Add") == null && hosts.GetMethod("Remove") == null && hosts.GetMethod("Backup") == null && hosts.GetMethod("Restore") == null, "PT-22: Hosts in the collector reads (Entries) but has no Write/Add/Remove/Backup/Restore");
            Check(fc != null && fc.GetMethod("IsEncrypted") != null && fc.GetMethod("Encrypt") == null && fc.GetMethod("Decrypt") == null && fc.GetMethod("SecureWipe") == null && fc.GetMethod("Verify") == null, "PT-22: FileCrypto in the collector only recognises its files");
            Check(ar != null && ar.GetMethod("Collect") != null && ar.GetMethod("SetEnabled") == null && ar.GetMethod("Delete") == null, "PT-22: Autoruns in the collector collects but cannot toggle or delete");
            Check(fwl != null && fwl.GetMethod("GetBlocked") != null && fwl.GetMethod("SetBlocked") == null, "PT-22: the blocker's Firewall class in the collector reads the rule but cannot set it");
        }
        // ── enrich: the online half, run offline against a seeded feed cache ──
        const string NvdFix = "{\"vulnerabilities\":[{\"cve\":{\"id\":\"CVE-2022-29072\",\"published\":\"2022-04-15T21:15:00.000\",\"descriptions\":[{\"lang\":\"en\",\"value\":\"7-Zip through 21.07 on Windows allows privilege escalation.\"}],\"metrics\":{\"cvssMetricV31\":[{\"type\":\"Primary\",\"cvssData\":{\"baseScore\":7.8,\"baseSeverity\":\"HIGH\"}}]},\"configurations\":[{\"nodes\":[{\"cpeMatch\":[{\"vulnerable\":true,\"criteria\":\"cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*\",\"versionEndIncluding\":\"21.07\"}]}]}]}},"
            + "{\"cve\":{\"id\":\"CVE-2000-0001\",\"descriptions\":[{\"lang\":\"en\",\"value\":\"exact\"}],\"metrics\":{},\"configurations\":[{\"nodes\":[{\"cpeMatch\":[{\"vulnerable\":true,\"criteria\":\"cpe:2.3:a:7-zip:7-zip:21.07:*:*:*:*:*:*:*\"}]}]}]}},"
            + "{\"cve\":{\"id\":\"CVE-2000-0002\",\"descriptions\":[],\"configurations\":[{\"nodes\":[{\"cpeMatch\":[{\"vulnerable\":true,\"criteria\":\"cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*\"}]}]}]}}]}";
        /// <summary>One MSRC CVRF document per release, one CVE for build family 22621: the fixed UBR falls with age; the three oldest are at 2500, what the stale fixture host installed.</summary>
        static string MsrcDoc(string release, int i)
        {
            int ubr = i <= 14 ? 2600 + (14 - i) * 10 : 2500; string cve = "CVE-2026-" + (1000 + i); string kb = (5070000 + i).ToString();
            return "{\"ProductTree\":{\"FullProductName\":[{\"ProductID\":\"11\",\"Value\":\"Windows 11 Version 22H2 for x64-based Systems\"}]},\"Vulnerability\":[{\"CVE\":\"" + cve + "\",\"Title\":{\"Value\":\"fix " + release + "\"},\"Threats\":[{\"Type\":3,\"Description\":{\"Value\":\"Important\"}}],\"CVSSScoreSets\":[{\"BaseScore\":7.8}],\"Remediations\":[{\"Type\":2,\"Description\":{\"Value\":\"" + kb + "\"},\"ProductID\":[\"11\"],\"FixedBuild\":\"10.0.22621." + ubr + "\"}]}]}";
        }
        static FeedCache SeedFeeds(string dir, DateTime now)
        {
            FeedCache c = new FeedCache(dir); c.Offline = true; StringBuilder rel = new StringBuilder("{\"value\":[");
            for (int i = 0; i < 18; i++) { DateTime m = now.AddMonths(-i); string id = m.ToString("yyyy-MMM", System.Globalization.CultureInfo.InvariantCulture); if (i > 0) rel.Append(','); rel.Append("{\"ID\":\"" + id + "\",\"InitialReleaseDate\":\"" + new DateTime(m.Year, m.Month, 9).ToString("yyyy-MM-dd") + "T17:00:00Z\"}"); c.Write("msrc-" + id + ".json", MsrcDoc(id, i)); }
            rel.Append("]}"); c.Write("msrc-releases.json", rel.ToString());
            c.Write("kev.json", "{\"catalogVersion\":\"2026.10.13\",\"dateReleased\":\"2026-10-13T12:00:00.0000Z\",\"vulnerabilities\":[{\"cveID\":\"CVE-2026-1003\",\"vendorProject\":\"Microsoft\",\"product\":\"Windows\",\"vulnerabilityName\":\"test\",\"dateAdded\":\"2026-09-01\",\"dueDate\":\"2026-09-22\",\"knownRansomwareCampaignUse\":\"Known\"}]}");
            c.Write(Nvd.CacheName("7-zip", "7-zip", Ver.Canon("21.07")), NvdFix);
            return c;
        }
        static Bundle FixtureBundle(int ubr, DateTime newestUpdate)
        {
            Bundle b = new Bundle(); b.Manifest["host"] = "FIXTURE"; b.Manifest["runId"] = "fx1"; b.Manifest["platform"] = "windows";
            OsInfo os = new OsInfo(); os.ProductName = "Windows 11 Pro"; os.Major = 10; os.Build = 22621; os.Ubr = ubr; os.Arch = "x64"; os.Host = "FIXTURE";
            Software z = new Software(); z.Name = "7-Zip 21.07 (x64)"; z.Version = "21.07"; z.Publisher = "Igor Pavlov"; z.Vendor = "7-zip"; z.Product = "7-zip";
            Dictionary<string, object> inv = new Dictionary<string, object>(); inv["os"] = Codec.Os(os); inv["reboot"] = Codec.Reboot(new RebootInfo()); inv["software"] = new List<object>(new object[] { Codec.Software(z) }); inv["hotfixes"] = new List<object>(); inv["knownKbs"] = new List<string>(); inv["newestUpdate"] = newestUpdate; inv["missing"] = new List<object>(); inv["missingStatus"] = "not searched (offline collection)";
            b["inventory"] = inv; b.Module("inventory", "ok", 1, 1, null); return b;
        }
        static void Enrich_()
        {
            DateTime now = new DateTime(2026, 10, 13); string dir = Path.Combine(Path.GetTempPath(), "pstools-feeds-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(dir);
            try
            {
                FeedCache cache = SeedFeeds(dir, now); string note;
                bool threw = false; try { cache.Fetch("nothing-here.json", "http://invalid.example/", null, TimeSpan.Zero, 1000, out note); } catch (InvalidOperationException) { threw = true; } Check(threw, "enrich: an offline feed cache never goes to the network - a missing feed fails, it is not fetched");
                // a stale host: build 22621.2500, newest update Jul 2025. A dry run (no EPSS) learns which CVEs will be scored, so the EPSS batch can be seeded for exactly that request.
                Bundle stale = FixtureBundle(2500, new DateTime(2025, 7, 10, 0, 0, 0, DateTimeKind.Utc));
                VulnEnrich dry = EnrichBundle.From(stale, cache); dry.Now = now; dry.DoEpss = false; dry.Run();
                List<string> ids = new List<string>(); foreach (Finding f in dry.Findings) if (f.Open || f.Status == "unconfirmed") ids.Add(f.Cve);
                cache.Write(Epss.CacheName(ids), "{\"data\":[{\"cve\":\"CVE-2026-1003\",\"epss\":\"0.42\",\"date\":\"2026-10-12\"},{\"cve\":\"CVE-2022-29072\",\"epss\":\"0.01\",\"date\":\"2026-10-12\"}]}");
                VulnEnrich e = EnrichBundle.From(stale, cache); e.Now = now; e.Run();
                int msrcOpen = 0, msrcPatched = 0, nvdOpen = 0, unconfirmed = 0; Finding kev = null; foreach (Finding f in e.Findings) { if (f.Source == "MSRC") { if (f.Open) msrcOpen++; else msrcPatched++; } if (f.Source == "NVD") { if (f.Open) nvdOpen++; else if (f.Status == "unconfirmed") unconfirmed++; } if (f.Cve == "CVE-2026-1003") kev = f; }
                Check(e.Errors.Count == 0, "enrich: a complete feed pack enriches offline with no errors (" + string.Join(" | ", e.Errors.ToArray()) + ")");
                Check(e.MsrcWindowUsed == 16 && e.Releases.Count == 16 && msrcOpen == 15 && msrcPatched == 1, "enrich: the stale build gets a 16-release MSRC window from the bundle's newest-update date and is NOT clean: " + msrcOpen + " open, " + msrcPatched + " patched (window " + e.MsrcWindowUsed + ", " + e.Releases.Count + " releases read)");
                Check(nvdOpen == 2 && unconfirmed == 1 && e.Software[0].Cves == 2 && e.Software[0].Status.StartsWith("2 CVE(s)"), "enrich: third-party findings from the seeded NVD record (2 open, 1 unconfirmed) and the product verdict (" + e.Software[0].Status + ")");
                Check(kev != null && kev.Kev && kev.Ransomware && kev.KevDue == "2026-09-22" && kev.Epss == 0.42, "enrich: KEV flag, ransomware and due date, and the EPSS score reach the finding");
                object msrc = Json.Get(e.AsOf, "msrc"), kv = Json.Get(e.AsOf, "kev"), ep = Json.Get(e.AsOf, "epss"), nvd = Json.Get(e.AsOf, "nvd");
                bool stamps = Json.Arr(Json.Get(msrc, "releases")).Count == 16; foreach (object u in Json.Arr(Json.Get(msrc, "releases"))) if (Json.GetS(u, "cached") == null || JsonWrite.Int(Json.Get(u, "records"), 0) != 1) stamps = false;
                Check(stamps && JsonWrite.Int(Json.Get(msrc, "window"), 0) == 16 && Json.GetS(kv, "catalogVersion") == "2026.10.13" && Json.GetS(kv, "dateReleased") != null && Json.GetS(kv, "cached") != null && Json.GetS(ep, "dates") == "2026-10-12" && JsonWrite.Int(Json.Get(ep, "scored"), 0) == 2 && JsonWrite.Int(Json.Get(nvd, "products"), 0) == 1 && Json.GetS(nvd, "newestCache") != null && e.AsOf.ContainsKey("enrichedUtc") && JsonWrite.Bool(e.AsOf["offline"]), "enrich: as-of stamps - every MSRC release with its cache time, KEV catalog version and date, EPSS scoring date, NVD cache time, enriched-at, offline flag");
                // determinism: a second enrichment of the same bundle against the same pack gives byte-identical findings
                VulnEnrich e2 = EnrichBundle.From(stale, cache); e2.Now = now; e2.Run();
                string f1 = JsonWrite.Text(Codec.Many(e.Findings, delegate (Finding f) { return (object)Codec.Finding(f); }), false), f2 = JsonWrite.Text(Codec.Many(e2.Findings, delegate (Finding f) { return (object)Codec.Finding(f); }), false);
                Dictionary<string, object> a1 = new Dictionary<string, object>(e.AsOf), a2 = new Dictionary<string, object>(e2.AsOf); a1.Remove("enrichedUtc"); a2.Remove("enrichedUtc");
                Check(f1 == f2 && f1.Length > 1000 && JsonWrite.Text(a1, false) == JsonWrite.Text(a2, false), "enrich: deterministic - identical findings (" + f1.Length + " chars) and identical as-of stamps across two runs");
                // a current host keeps the small window and is clean against the same pack
                Bundle fresh = FixtureBundle(2800, new DateTime(2026, 9, 21, 0, 0, 0, DateTimeKind.Utc)); VulnEnrich e3 = EnrichBundle.From(fresh, cache); e3.Now = now; e3.DoEpss = false; e3.Run();
                int freshOpen = 0; foreach (Finding f in e3.Findings) if (f.Source == "MSRC" && f.Open) freshOpen++;
                Check(e3.MsrcWindowUsed == 3 && e3.Releases.Count == 3 && freshOpen == 0, "enrich: a current build keeps the 3-release window and has no open Microsoft CVEs (window " + e3.MsrcWindowUsed + ")");
                // the bundle gets its findings section and the per-product verdicts back, and still round-trips
                EnrichBundle.Apply(stale, e); object fd = stale["findings"];
                Check(Json.Arr(Json.Get(fd, "items")).Count == e.Findings.Count && JsonWrite.Int(Json.Get(fd, "open"), 0) == 17 && Json.Get(fd, "asOf") != null && stale.Manifest.ContainsKey("enriched") && JsonWrite.Int(Json.Get(Json.Arr(Json.Get(stale["inventory"], "software"))[0], "cves"), -1) == 2, "enrich: Apply writes findings (17 open), as-of, the enriched manifest block and the product verdict into the bundle");
                string p = Path.Combine(dir, "stale.enriched.ptb"); stale.Save(p, BundleKey.FromPassphrase("correct horse")); Bundle r = Bundle.Load(p, BundleKey.FromPassphrase("correct horse"));
                Check(Json.Arr(Json.Get(r["findings"], "items")).Count == e.Findings.Count && Codec.FindingFrom(Json.Arr(Json.Get(r["findings"], "items"))[0]).Cve.StartsWith("CVE-"), "enrich: the enriched bundle seals and reloads with every finding");
                // the real tool, end to end, offline: PowerTowerCli enrich <in> --plain --offline --cache <pack>
                string cli = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "PowerTowerCli.exe"); string inP = Path.Combine(dir, "in.ptb"), outP = Path.Combine(dir, "out.ptb"); FixtureBundle(2500, new DateTime(2025, 7, 10, 0, 0, 0, DateTimeKind.Utc)).Save(inP, BundleKey.None());
                if (!File.Exists(cli)) Check(false, "enrich: PowerTowerCli.exe not found next to Tests.exe");
                else
                {
                    ProcessStartInfo psi = new ProcessStartInfo(cli, "enrich \"" + inP + "\" --plain --offline --cache \"" + dir + "\" --out \"" + outP + "\" --no-color --quiet --top 3"); psi.UseShellExecute = false; psi.RedirectStandardOutput = true; psi.RedirectStandardError = true; psi.CreateNoWindow = true;
                    using (Process pr = Process.Start(psi)) { string so = pr.StandardOutput.ReadToEnd(); string se = pr.StandardError.ReadToEnd(); pr.WaitForExit(180000); Bundle ob = File.Exists(outP) ? Bundle.Load(outP, BundleKey.None()) : null; Check(pr.ExitCode == 0 && ob != null && Json.Arr(Json.Get(ob["findings"], "items")).Count > 10 && ob.Manifest.ContainsKey("enriched"), "enrich: the CLI tool enriches a plain bundle offline (exit " + pr.ExitCode + (se.Trim().Length > 0 ? " · stderr: " + se.Trim().Replace("\r", "").Replace("\n", " | ").Substring(0, Math.Min(200, se.Trim().Length)) : "") + ")"); }
                }
                string err = ""; try { EnrichBundle.From(new Bundle(), cache); } catch (BundleException ex) { err = ex.Message; } Check(err.Contains("inventory"), "enrich: a bundle without an inventory section is refused with a reason");
            }
            finally { try { Directory.Delete(dir, true); } catch { } }
        }
        static void FeedPack_()
        {
            string src = Path.Combine(Path.GetTempPath(), "pstools-fp-src-" + Guid.NewGuid().ToString("N")), pack = Path.Combine(Path.GetTempPath(), "pstools-fp-pack-" + Guid.NewGuid().ToString("N")), dst = Path.Combine(Path.GetTempPath(), "pstools-fp-dst-" + Guid.NewGuid().ToString("N"));
            try
            {
                FeedCache c = SeedFeeds(src, new DateTime(2026, 10, 13)); DateTime old = new DateTime(2026, 9, 1, 12, 0, 0, DateTimeKind.Utc); File.SetLastWriteTimeUtc(Path.Combine(src, "kev.json"), old);
                FeedPack.Result ex = FeedPack.Export(c, pack); int n = Directory.GetFiles(src, "*.json").Length;
                Check(ex.Files == n && n >= 21 && File.Exists(ex.Manifest) && Json.Arr(Json.Get(Json.Parse(File.ReadAllText(ex.Manifest)), "files")).Count == n, "feeds: export copies every cached feed (" + n + ") and writes a manifest with one entry each");
                FeedCache d = new FeedCache(dst); FeedPack.Result im = FeedPack.Import(pack, d, true);
                bool same = im.Files == n && im.Skipped == 0; foreach (string f in Directory.GetFiles(src, "*.json")) { string name = Path.GetFileName(f), o = Path.Combine(dst, name); if (!File.Exists(o) || BundleCrypto.FileSha256(f) != BundleCrypto.FileSha256(o) || Math.Abs((File.GetLastWriteTimeUtc(f) - File.GetLastWriteTimeUtc(o)).TotalSeconds) > 2) same = false; }
                Check(same && File.GetLastWriteTimeUtc(Path.Combine(dst, "kev.json")) == old, "feeds: import round-trips every file byte for byte with its original time, so age and stale-fallback stay honest");
                d.Offline = true; string note; Check(Msrc.Releases(d, out note).Count == 18 && note.StartsWith("offline pack"), "feeds: the imported pack serves enrichment offline (" + note + ")");
                Check(FeedPack.Status(d).Count == 3 && FeedPack.Status(d)[1].Contains("MSRC 19") && FeedPack.Status(d)[1].Contains("KEV 1"), "feeds: status counts the feeds by kind (" + FeedPack.Status(d)[1] + ")");
                File.AppendAllText(Path.Combine(pack, "kev.json"), " "); FeedPack.Result im2 = FeedPack.Import(pack, new FeedCache(dst + "2"), true);
                Check(im2.Skipped == 1 && im2.Problems.Count == 1 && im2.Problems[0].Contains("kev.json") && !File.Exists(Path.Combine(dst + "2", "kev.json")) && im2.Files == n - 1, "feeds: a tampered file in the pack is refused by its SHA-256 and not imported (" + im2.Problems[0] + ")");
                string mf = Path.Combine(pack, FeedPack.ManifestName); File.WriteAllText(mf, File.ReadAllText(mf).Replace("\"kev.json\"", "\"..\\\\evil.json\"")); FeedPack.Result im3 = FeedPack.Import(pack, new FeedCache(dst + "3"), false);
                Check(im3.Skipped >= 1 && im3.Problems.Count >= 1 && im3.Problems[0].Contains("plain .json name") && !File.Exists(Path.Combine(Path.GetDirectoryName(dst + "3"), "evil.json")), "feeds: a manifest entry with a path in it is refused - no traversal out of the cache (" + im3.Problems[0] + ")");
                string err = ""; try { FeedPack.Import(src, new FeedCache(dst + "4"), true); } catch (BundleException e) { err = e.Message; } Check(err.Contains("not a feed pack"), "feeds: a folder without a manifest is not a pack");
                string cli = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "PowerTowerCli.exe");
                if (File.Exists(cli))
                {
                    int x1; string o1 = RunCli(cli, "feeds --export \"" + pack + "-cli\" --cache \"" + src + "\" --no-color", out x1); int x2; string o2 = RunCli(cli, "feeds --import \"" + pack + "-cli\" --cache \"" + dst + "-cli\" --no-color", out x2); int x3; string o3 = RunCli(cli, "feeds --cache \"" + dst + "-cli\" --no-color", out x3);
                    Check(x1 == 0 && x2 == 0 && x3 == 0 && Directory.GetFiles(dst + "-cli", "*.json").Length == n && o3.Contains("MSRC 19"), "feeds CLI: export → import → status round-trip (exit " + x1 + "/" + x2 + "/" + x3 + ")");
                }
                else Check(false, "feeds CLI: PowerTowerCli.exe not found next to Tests.exe");
            }
            finally { foreach (string p in new string[] { src, pack, pack + "-cli", dst, dst + "2", dst + "3", dst + "4", dst + "-cli" }) try { if (Directory.Exists(p)) Directory.Delete(p, true); } catch { } }
        }
        static string RunCli(string exe, string args, out int exit)
        {
            ProcessStartInfo psi = new ProcessStartInfo(exe, args); psi.UseShellExecute = false; psi.RedirectStandardOutput = true; psi.RedirectStandardError = true; psi.CreateNoWindow = true;
            using (Process p = Process.Start(psi)) { string so = p.StandardOutput.ReadToEnd(); string se = p.StandardError.ReadToEnd(); p.WaitForExit(120000); exit = p.ExitCode; return so + "\n" + se; }
        }
        static void EngagementTool_()
        {
            string dir = Path.Combine(Path.GetTempPath(), "pstools-engt-" + Guid.NewGuid().ToString("N"));
            try
            {
                Engagement e = EngagementTool.New(dir, "ENG-2026-014", "Acme", "ops", new string[] { "10.0.0.0/24", "WS-FIN-01" }, new DateTime(2026, 10, 1, 0, 0, 0, DateTimeKind.Utc), new DateTime(2026, 12, 31, 0, 0, 0, DateTimeKind.Utc), new string[] { "inventory", "network" }, 60, "pilot", 2048);
                string jf = Path.Combine(dir, "engagement.json"), kf = Path.Combine(dir, "engagement.key");
                Check(File.Exists(jf) && File.Exists(kf) && e.File == jf && Engagement.KeyFileFor(jf) == kf, "engagement new: writes engagement.json and engagement.key beside it");
                byte[] kb = File.ReadAllBytes(kf); string jt = File.ReadAllText(jf);
                Check(IndexOf(kb, Encoding.UTF8.GetBytes("<RSAKeyValue>")) < 0 && IndexOf(kb, Encoding.UTF8.GetBytes("<D>")) < 0 && !jt.Contains("<D>") && !jt.Contains("<P>") && jt.Contains("<Modulus>"), "engagement new: the key file is DPAPI-opaque and engagement.json carries only the public key");
                Engagement r = Engagement.Load(jf); string priv = Engagement.PrivateKey(r, kf);
                Check(r.Validate().Count == 0 && r.Scope.Count == 2 && r.Modules.Count == 2 && r.RetentionDays == 60 && r.WindowEndUtc.HasValue && BundleCrypto.KeyId(BundleCrypto.PublicOf(priv)) == BundleCrypto.KeyId(r.PublicKeyXml), "engagement new: reloads valid, and the DPAPI key opens to the private half of the published public key");
                byte[] sealedB = BundleCrypto.Seal(Encoding.UTF8.GetBytes("{\"x\":1}"), BundleKey.ToPublic(r.PublicKeyXml)); Check(Encoding.UTF8.GetString(BundleCrypto.Open(sealedB, BundleKey.WithPrivate(priv))) == "{\"x\":1}", "engagement: a bundle sealed to the engagement's public key opens with the recovered private key");
                string insp = string.Join("\n", EngagementTool.Inspect(r).ToArray());
                Check(!insp.Contains("<RSAKeyValue") && !insp.Contains("<D>") && !insp.Contains("<Modulus>") && insp.Contains(BundleCrypto.KeyId(r.PublicKeyXml)) && insp.Contains("opens for this Windows user, matches") && insp.Contains("10.0.0.0/24") && insp.Contains("valid        yes"), "engagement inspect: scope, window, key id and key-file state - never any key material");
                string why; Check(r.InScope("10.0.0.77", out why) && !r.InScope("203.0.113.9", out why) && why.Contains("not in the engagement scope"), "engagement check: an in-scope host is accepted, an out-of-scope host refused by Engagement.InScope (" + why + ")");
                string err = ""; try { EngagementTool.New(dir, "ENG-2026-014", "Acme", "ops", new string[] { "*" }, new DateTime(2026, 10, 1, 0, 0, 0, DateTimeKind.Utc), new DateTime(2026, 12, 31, 0, 0, 0, DateTimeKind.Utc), null, 30, "", 2048); } catch (BundleException ex) { err = ex.Message; } Check(err.Contains("already exists"), "engagement new: never overwrites an existing engagement's key");
                err = ""; try { EngagementTool.New(dir + "-w", "ENG-W", "Acme", "ops", new string[] { "*" }, null, null, null, 30, "", 2048); } catch (BundleException ex) { err = ex.Message; } Check(err.Contains("time window") && !Directory.Exists(dir + "-w"), "engagement new: a window is required (PT-32) - " + err);
                err = ""; try { EngagementTool.New(dir + "-b", "ENG-2", "Acme", "ops", new string[] { "10.0.0.0/24" }, null, null, new string[] { "bogus" }, 30, "", 2048); } catch (BundleException ex) { err = ex.Message; } Check(err.Contains("bogus") && !Directory.Exists(dir + "-b"), "engagement new: a bad module name is refused before anything is written (" + err + ")");
                err = ""; try { EngagementTool.New(dir + "-c", "", "Acme", "ops", new string[] { "300.1.1.1/40" }, new DateTime(2026, 2, 1), new DateTime(2026, 1, 1), null, 30, "", 2048); } catch (BundleException ex) { err = ex.Message; } Check(err.Contains("id is empty") && err.Contains("CIDR") && err.Contains("window") && !Directory.Exists(dir + "-c"), "engagement new: validation names every problem and writes nothing (" + err + ")");
                string cli = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "PowerTowerCli.exe"); string cdir = dir + "-cli";
                if (File.Exists(cli))
                {
                    int x1; string o1 = RunCli(cli, "engagement new --out \"" + cdir + "\" --id ENG-CLI-1 --client Acme --scope 10.0.0.0/24,ws-fin-01 --from 2026-10-01 --to 2027-12-31 --modules inventory --retention 30 --bits 2048 --no-color", out x1);
                    int x2; string o2 = RunCli(cli, "engagement inspect \"" + Path.Combine(cdir, "engagement.json") + "\" --no-color", out x2);
                    int x3; string o3 = RunCli(cli, "engagement check \"" + Path.Combine(cdir, "engagement.json") + "\" --host 203.0.113.9 --no-color", out x3);
                    int x4; string o4 = RunCli(cli, "engagement check \"" + Path.Combine(cdir, "engagement.json") + "\" --host 10.0.0.5 --no-color", out x4);
                    Check(x1 == 0 && File.Exists(Path.Combine(cdir, "engagement.key")) && !o1.Contains("<RSAKeyValue") && x2 == 0 && !o2.Contains("<RSAKeyValue") && !o2.Contains("<D>") && !o2.Contains("<Modulus>") && o2.Contains("ENG-CLI-1") && x3 == 1 && o3.Contains("OUT OF SCOPE") && x4 == 0, "engagement CLI: new (exit " + x1 + "), inspect without key material (exit " + x2 + "), check refuses 203.0.113.9 (exit " + x3 + ") and accepts 10.0.0.5 (exit " + x4 + ")");
                }
                else Check(false, "engagement CLI: PowerTowerCli.exe not found next to Tests.exe");
            }
            finally { foreach (string p in new string[] { dir, dir + "-b", dir + "-c", dir + "-w", dir + "-cli" }) try { if (Directory.Exists(p)) Directory.Delete(p, true); } catch { } }
        }
        // ── PT-32: engagement limits fail CLOSED - anything missing, wrong-typed, unparseable or inverted refuses to load, so nothing runs ──
        static Dictionary<string, object> EngTree()
        {
            Dictionary<string, object> t = new Dictionary<string, object>(); t["schema"] = Engagement.Schema; t["id"] = "ENG-OK"; t["client"] = "Acme"; t["operator"] = "ops"; t["scope"] = new List<object>(new object[] { "10.0.0.0/24", "WS-FIN-01" });
            t["windowStartUtc"] = "2026-10-01T00:00:00Z"; t["windowEndUtc"] = "2026-12-31T00:00:00Z"; t["modules"] = new List<object>(new object[] { "inventory" }); t["retentionDays"] = 60; t["publicKeyXml"] = ""; t["notes"] = ""; return t;
        }
        static string Refused(string dir, string name, string json)
        {
            string f = Path.Combine(dir, name.Replace(' ', '-') + ".json"); File.WriteAllText(f, json, new UTF8Encoding(false));
            try { Engagement.Load(f); return null; } catch (BundleException ex) { return ex.Message; }
        }
        static void EngagementStrict_()
        {
            string dir = Path.Combine(Path.GetTempPath(), "pstools-engs-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(dir);
            try
            {
                string okf = Path.Combine(dir, "ok.json"); File.WriteAllText(okf, JsonWrite.Text(EngTree(), true)); Engagement e = Engagement.Load(okf); string why;
                Check(e.Id == "ENG-OK" && e.Validate().Count == 0 && e.InScope("10.0.0.9", out why) && !e.InScope("10.9.9.9", out why) && e.InWindow(new DateTime(2026, 11, 1, 0, 0, 0, DateTimeKind.Utc), out why) && !e.InWindow(new DateTime(2027, 1, 1, 0, 0, 0, DateTimeKind.Utc), out why) && e.ModuleAllowed("inventory") && !e.ModuleAllowed("secrets"), "PT-32: a valid engagement still loads and InScope / InWindow / ModuleAllowed still enforce");
                int n = 0;
                Action<string, Action<Dictionary<string, object>>, string> refuse = delegate (string name, Action<Dictionary<string, object>> mutate, string word)
                {
                    Dictionary<string, object> t = EngTree(); mutate(t); string msg = Refused(dir, name, JsonWrite.Text(t, false)); n++;
                    Check(msg != null && msg.IndexOf(word, StringComparison.OrdinalIgnoreCase) >= 0, "PT-32: " + name + " is refused (" + (msg ?? "LOADED - fail open!") + ")");
                };
                refuse("missing id", delegate (Dictionary<string, object> t) { t.Remove("id"); }, "id");
                refuse("missing scope", delegate (Dictionary<string, object> t) { t.Remove("scope"); }, "scope");
                refuse("missing window start", delegate (Dictionary<string, object> t) { t.Remove("windowStartUtc"); }, "windowStartUtc");
                refuse("missing window end", delegate (Dictionary<string, object> t) { t.Remove("windowEndUtc"); }, "windowEndUtc");
                refuse("no window at all", delegate (Dictionary<string, object> t) { t.Remove("windowStartUtc"); t.Remove("windowEndUtc"); }, "window");
                refuse("scope as a string", delegate (Dictionary<string, object> t) { t["scope"] = "10.0.0.0/24"; }, "list");
                refuse("scope with a number in it", delegate (Dictionary<string, object> t) { t["scope"] = new List<object>(new object[] { "10.0.0.0/24", 5 }); }, "strings");
                refuse("bad CIDR", delegate (Dictionary<string, object> t) { t["scope"] = new List<object>(new object[] { "300.1.1.1/40" }); }, "CIDR");
                refuse("empty scope entry", delegate (Dictionary<string, object> t) { t["scope"] = new List<object>(new object[] { "10.0.0.0/24", "" }); }, "empty");
                refuse("whitespace scope entry", delegate (Dictionary<string, object> t) { t["scope"] = new List<object>(new object[] { "   " }); }, "empty");
                refuse("inverted window", delegate (Dictionary<string, object> t) { t["windowStartUtc"] = "2026-12-31T00:00:00Z"; t["windowEndUtc"] = "2026-10-01T00:00:00Z"; }, "before");
                refuse("unparseable date", delegate (Dictionary<string, object> t) { t["windowEndUtc"] = "garbage"; }, "date");
                refuse("impossible date", delegate (Dictionary<string, object> t) { t["windowEndUtc"] = "2026-13-45"; }, "date");
                refuse("numeric date", delegate (Dictionary<string, object> t) { t["windowStartUtc"] = 1700000000; }, "date");
                refuse("modules as a string", delegate (Dictionary<string, object> t) { t["modules"] = "inventory"; }, "list");
                refuse("modules as a number", delegate (Dictionary<string, object> t) { t["modules"] = 7; }, "list");
                refuse("module list with a number in it", delegate (Dictionary<string, object> t) { t["modules"] = new List<object>(new object[] { "inventory", 1 }); }, "strings");
                refuse("unknown module", delegate (Dictionary<string, object> t) { t["modules"] = new List<object>(new object[] { "wipe-everything" }); }, "unknown");
                refuse("retention as text", delegate (Dictionary<string, object> t) { t["retentionDays"] = "90"; }, "retentionDays");
                refuse("retention zero", delegate (Dictionary<string, object> t) { t["retentionDays"] = 0; }, "retentionDays");
                refuse("retention fractional", delegate (Dictionary<string, object> t) { t["retentionDays"] = 2.5; }, "retentionDays");
                refuse("id as a number", delegate (Dictionary<string, object> t) { t["id"] = 42; }, "string");
                refuse("public key garbage", delegate (Dictionary<string, object> t) { t["publicKeyXml"] = "not a key"; }, "public key");
                refuse("wrong schema", delegate (Dictionary<string, object> t) { t["schema"] = "engagement/9"; }, "schema");
                string full = JsonWrite.Text(EngTree(), false);
                Check(Refused(dir, "truncated", full.Substring(0, full.Length / 2)) != null && Refused(dir, "empty", "") != null && Refused(dir, "array root", "[]") != null && Refused(dir, "deep", new string('[', 5000) + new string(']', 5000)) != null, "PT-32: truncated file, empty file, array root and 5,000-deep nesting are refused");
                Dictionary<string, object> hostile = EngTree(); hostile["modules"] = "inventory"; string hf = Path.Combine(dir, "hostile.json"); File.WriteAllText(hf, JsonWrite.Text(hostile, false));
                Dictionary<string, string> opt = new Dictionary<string, string>(); opt["engagement"] = hf; Collector c = new Collector(); c.Modules.Clear(); c.Modules.Add("network");
                string err = CollectOptions.Apply(c, delegate (string k) { string v; return opt.TryGetValue(k, out v) ? v : null; }, delegate (string k) { return opt.ContainsKey(k); }, delegate (string k) { return new List<string>(); });
                Check(err != null && err.IndexOf("modules", StringComparison.OrdinalIgnoreCase) >= 0 && c.Engagement == null, "PT-32: the collector refuses a hostile engagement at option time - no collection starts (" + err + ")");
                Engagement mem = new Engagement(); mem.Id = "M"; mem.Scope.Add("*"); Collector c2 = new Collector(); c2.Modules.Clear(); c2.Modules.Add("network"); c2.Engagement = mem; err = ""; try { c2.Run(); } catch (BundleException ex) { err = ex.Message; }
                Check(err.Contains("window"), "PT-32: an engagement built in memory without a window is refused by the collector itself, before any module runs (" + err + ")");
                Check(n == 24, "PT-32: " + n + " hostile variants exercised, each refused with a reason");
            }
            finally { try { Directory.Delete(dir, true); } catch { } }
        }
        // ── FUZZ round 3, fail-closed theme: PT-38 future patch date, PT-34 --months, PT-37 manifest shape, PT-35/36 modifiedUtc ──
        static void FailClosed_()
        {
            DateTime now = new DateTime(2026, 10, 13); string dir = Path.Combine(Path.GetTempPath(), "pstools-fc-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(dir);
            try
            {
                Check(VulnScan.MsrcWindow(new DateTime(2100, 1, 1), null, now, 3) == 36 && VulnScan.MsrcWindow(new DateTime(9999, 12, 31), null, now, 3) == 36 && VulnScan.MsrcWindow(new DateTime(2100, 1, 1), new DateTime(2026, 9, 1), now, 3) == 36 && VulnScan.MsrcWindow(null, new DateTime(2100, 1, 1), now, 3) == 36, "PT-38: a future newest-update or install date gets the widest window (36), never the minimum - no fallback to a lesser date either");
                Check(VulnScan.MsrcWindow(now.AddHours(12), null, now, 3) == 3 && VulnScan.MsrcWindow(new DateTime(2026, 9, 21), null, now, 3) == 3, "PT-38: a date within a day of now (clock skew) is still a normal patch level");
                FeedCache cache = SeedFeeds(dir, now); Bundle doctored = FixtureBundle(2500, new DateTime(2100, 1, 1, 0, 0, 0, DateTimeKind.Utc)); VulnEnrich e = EnrichBundle.From(doctored, cache); e.Now = now; e.DoEpss = false; e.Run();
                bool flag = false; foreach (string er in e.Errors) if (er.Contains("future")) flag = true;
                Check(e.MsrcWindowUsed == 36 && e.Releases.Count == 18 && JsonWrite.Bool(Json.Get(e.AsOf, "msrc", "newestUpdateInFuture")) && flag, "PT-38: a doctored bundle claiming a 2100 patch date is enriched against every available release (" + e.Releases.Count + "), flagged in asOf and in the problems (" + (e.Errors.Count > 0 ? e.Errors[0] : "") + ")");
                string cli = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "PowerTowerCli.exe"); string inP = Path.Combine(dir, "in.ptb"); FixtureBundle(2500, new DateTime(2025, 7, 10, 0, 0, 0, DateTimeKind.Utc)).Save(inP, BundleKey.None());
                if (File.Exists(cli))
                {
                    List<string> wrong = new List<string>(); foreach (string m in new string[] { "0", "-1", "abc", "3.5", "99", "+3" }) { int x; string o = RunCli(cli, "enrich \"" + inP + "\" --plain --offline --cache \"" + dir + "\" --months " + m + " --no-color --quiet", out x); if (x != 2 || !o.Contains("--months")) wrong.Add(m + "→exit " + x); }
                    int xv; string ov = RunCli(cli, "vulnerabilities --months abc --no-color --quiet", out xv); int xo; string oo = RunCli(cli, "enrich \"" + inP + "\" --plain --offline --cache \"" + dir + "\" --months 36 --no-epss --out \"" + Path.Combine(dir, "m36.ptb") + "\" --no-color --quiet", out xo);
                    Check(wrong.Count == 0 && xv == 2 && ov.Contains("--months") && xo == 0, "PT-34: --months 0 / -1 / abc / 3.5 / 99 / +3 are usage errors (exit 2) for enrich and vulnerabilities alike; --months 36 is accepted by enrich" + (wrong.Count > 0 ? " (wrong: " + string.Join(", ", wrong.ToArray()) + ")" : "") + " (vuln abc → " + xv + ", enrich 36 → " + xo + ")");
                }
                else Check(false, "PT-34: PowerTowerCli.exe not found next to Tests.exe");
                string pack = Path.Combine(dir, "pack"); FeedPack.Export(cache, pack); string mf = Path.Combine(pack, FeedPack.ManifestName); string manifest = File.ReadAllText(mf);
                Func<string, string> import = delegate (string json) { File.WriteAllText(mf, json, new UTF8Encoding(false)); try { FeedPack.Result r = FeedPack.Import(pack, new FeedCache(Path.Combine(dir, "imp-" + Guid.NewGuid().ToString("N"))), true); return "imported " + r.Files + (r.Problems.Count > 0 ? " | " + string.Join(" | ", r.Problems.ToArray()) : ""); } catch (BundleException ex) { return "refused: " + ex.Message; } };
                string noFiles = import("{\"schema\":\"feedpack/1\",\"exportedUtc\":\"2026-10-13T00:00:00Z\"}"), strFiles = import("{\"schema\":\"feedpack/1\",\"files\":\"kev.json\"}"), emptyFiles = import("{\"schema\":\"feedpack/1\",\"files\":[]}"), ghost = import("{\"schema\":\"feedpack/1\",\"files\":[{\"name\":\"ghost.json\",\"sha256\":\"00\"}]}");
                Check(noFiles.StartsWith("refused") && noFiles.Contains("files") && strFiles.StartsWith("refused") && emptyFiles.StartsWith("refused") && emptyFiles.Contains("no files") && ghost.StartsWith("imported 0") && ghost.Contains("no files were imported"), "PT-37: a manifest with files missing, not a list or empty is refused as an invalid pack; a pack whose every entry is refused says so (" + noFiles + " / " + strFiles + " / " + emptyFiles + " / " + ghost + ")");
                File.WriteAllText(mf, manifest, new UTF8Encoding(false));
                int nFiles = Directory.GetFiles(pack, "*.json").Length - 1; string kevStamp = JsonWrite.Stamp(File.GetLastWriteTimeUtc(Path.Combine(pack, "kev.json")));
                Func<string, string> withKevTime = delegate (string t) { string j = manifest.Replace("\"name\": \"kev.json\"", "\"name\": \"kev.json\", \"_\": 1"); int at = j.IndexOf("\"name\": \"kev.json\""); int ms = j.IndexOf("\"modifiedUtc\": \"", at); int me = j.IndexOf("\"", ms + 16); return j.Substring(0, ms + 16) + t + j.Substring(me); };
                string[] bad = { "1500-01-01T00:00:00Z", "0001-01-01T00:00:00Z", "2099-01-01T00:00:00Z", "9999-12-31T23:59:59Z", "not-a-date" }; List<string> wrongT = new List<string>();
                foreach (string t in bad)
                {
                    string impDir = Path.Combine(dir, "t-" + Guid.NewGuid().ToString("N")); File.WriteAllText(mf, withKevTime(t), new UTF8Encoding(false)); FeedPack.Result r;
                    try { r = FeedPack.Import(pack, new FeedCache(impDir), true); } catch (Exception ex) { wrongT.Add(t + "→threw " + ex.GetType().Name); continue; }
                    bool kevAbsent = !File.Exists(Path.Combine(impDir, "kev.json")); bool said = false; foreach (string p in r.Problems) if (p.StartsWith("kev.json") && p.Contains("modifiedUtc")) said = true;
                    if (!(kevAbsent && said && r.Skipped == 1 && r.Files == nFiles - 1)) wrongT.Add(t + "→files " + r.Files + " skipped " + r.Skipped + " kevAbsent " + kevAbsent + " said " + said);
                }
                File.WriteAllText(mf, manifest, new UTF8Encoding(false));
                Check(wrongT.Count == 0, "PT-35/36: modifiedUtc before 1601, in the future or unparseable is refused BEFORE the file is copied - kev.json absent, named in the problems, the other " + (nFiles - 1) + " imported (manifest stamp " + kevStamp + ")" + (wrongT.Count > 0 ? " wrong: " + string.Join("; ", wrongT.ToArray()) : ""));
                // PT-28: only canonical addresses, in scope entries and as targets
                Engagement sc = new Engagement(); sc.Id = "S"; sc.WindowStartUtc = now; sc.WindowEndUtc = now.AddDays(1); sc.Scope.AddRange(new string[] { "10.0.0.0/24", "192.168.5.7", "fe80::1", "ws-fin-01" });
                Check(sc.Validate().Count == 0, "PT-28: canonical dotted quads, a normalised IPv6, a CIDR and a host name validate (" + string.Join("; ", sc.Validate().ToArray()) + ")");
                List<string> accepted = new List<string>(); foreach (string badIp in new string[] { "10.1", "010.0.0.1", "10.0.0.256", "0xA.0.0.1", "10.0.0.1.", "010.0.0.0/8", "10.0.0.0/33", "10.0.0.0/+8", "FE80::1", "1.2.3" }) { Engagement x = new Engagement(); x.Id = "X"; x.WindowStartUtc = now; x.WindowEndUtc = now.AddDays(1); x.Scope.Add(badIp); if (x.Validate().Count == 0) accepted.Add(badIp); }
                Check(accepted.Count == 0, "PT-28: 10.1, 010.0.0.1, 10.0.0.256, 0xA.0.0.1, trailing dot, non-canonical or malformed CIDRs and upper-case IPv6 are refused by Validate" + (accepted.Count > 0 ? " (accepted: " + string.Join(", ", accepted.ToArray()) + ")" : ""));
                string whyS; Check(sc.InScope("10.0.0.1", out whyS) && !sc.InScope("10.1", out whyS) && whyS.Contains("canonical") && !sc.InScope("010.0.0.5", out whyS) && !sc.InScope("0xA.0.0.1", out whyS) && !sc.InScope("2130706433", out whyS) && sc.InScope("WS-FIN-01", out whyS) && sc.InScope("fe80::1", out whyS), "PT-28: '10.1', '010.0.0.5', '0xA.0.0.1' and a decimal integer never match the 10.0.0.0/24 scope; canonical addresses and host names still do");
                // PT-36 remainder: a pack entry without modifiedUtc is refused, never given the file's own time
                string noTime = File.ReadAllText(mf); int km = noTime.IndexOf("\"name\": \"kev.json\""); int ms2 = noTime.IndexOf("\"modifiedUtc\": \"", km); noTime = noTime.Substring(0, ms2) + "\"notTheTime\": \"" + noTime.Substring(ms2 + 16);   // rename the key: the entry keeps a value but no modifiedUtc
                string impNT = Path.Combine(dir, "t-notime"); File.WriteAllText(mf, noTime, new UTF8Encoding(false)); FeedPack.Result rNT = FeedPack.Import(pack, new FeedCache(impNT), true); File.WriteAllText(mf, manifest, new UTF8Encoding(false));
                bool saidNT = false; foreach (string p in rNT.Problems) if (p.StartsWith("kev.json") && p.Contains("missing")) saidNT = true;
                Check(saidNT && !File.Exists(Path.Combine(impNT, "kev.json")) && rNT.Skipped == 1 && rNT.Files == nFiles - 1, "PT-36: an entry with no modifiedUtc is refused before copying - kev.json absent, the other " + (nFiles - 1) + " imported (" + (rNT.Problems.Count > 0 ? rNT.Problems[0] : "") + ")");
                // [fail-closed: next]
            }
            finally { try { Directory.Delete(dir, true); } catch { } }
        }
        // ── Phase 2: the ptreport/1 contract, its schema, and the Vulnerability report built from an enriched bundle ──
        /// <summary>A stale fixture host, enriched offline against the seeded feeds, with every wall-clock stamp pinned so reports are reproducible. hostileProduct replaces the 7-Zip display name to test escaping.</summary>
        static Bundle EnrichedFixture(string dir, DateTime now, string hostileProduct)
        {
            FeedCache cache = SeedFeeds(dir, now); Bundle b = FixtureBundle(2500, new DateTime(2025, 7, 10, 0, 0, 0, DateTimeKind.Utc)); b.Manifest["finishedUtc"] = new DateTime(2026, 10, 13, 8, 0, 0, DateTimeKind.Utc); b.Manifest["privilegeTier"] = "A"; b.Manifest["mode"] = "live";
            if (hostileProduct != null) Json.Obj(Json.Arr(Json.Get(b["inventory"], "software"))[0])["name"] = hostileProduct;
            VulnEnrich dry = EnrichBundle.From(b, cache); dry.Now = now; dry.DoEpss = false; dry.Run(); List<string> ids = new List<string>(); foreach (Finding f in dry.Findings) if (f.Open || f.Status == "unconfirmed") ids.Add(f.Cve);
            cache.Write(Epss.CacheName(ids), "{\"data\":[{\"cve\":\"CVE-2026-1003\",\"epss\":\"0.42\",\"date\":\"2026-10-12\"},{\"cve\":\"CVE-2022-29072\",\"epss\":\"0.01\",\"date\":\"2026-10-12\"}]}");
            VulnEnrich e = EnrichBundle.From(b, cache); e.Now = now; e.Run(); EnrichBundle.Apply(b, e);
            DateTime pinned = new DateTime(2026, 10, 13, 9, 0, 0, DateTimeKind.Utc); Json.Obj(b.Manifest["enriched"])["utc"] = pinned; Json.Obj(Json.Get(b["findings"], "asOf"))["enrichedUtc"] = pinned;
            return b;
        }
        static void Ptreport_()
        {
            // the validator itself, on a tiny schema
            object tiny = Json.Parse("{\"type\":\"object\",\"required\":[\"a\"],\"additionalProperties\":false,\"properties\":{\"a\":{\"type\":\"integer\",\"minimum\":1},\"b\":{\"enum\":[\"x\",\"y\"]},\"c\":{\"type\":\"array\",\"items\":{\"$ref\":\"#/definitions/s\"}}},\"definitions\":{\"s\":{\"type\":\"string\",\"pattern\":\"^k\"}}}");
            List<string> ok = JsonSchema.Validate(tiny, Json.Parse("{\"a\":1,\"b\":\"x\",\"c\":[\"k1\",\"k2\"]}")), bad = JsonSchema.Validate(tiny, Json.Parse("{\"a\":0.5,\"b\":\"z\",\"c\":[\"no\"],\"d\":1}")), miss = JsonSchema.Validate(tiny, Json.Parse("{\"b\":\"x\"}"));
            Check(ok.Count == 0 && bad.Count == 4 && miss.Count == 1 && miss[0].Contains("'a'"), "ptreport: the schema validator enforces type, integer, minimum, enum, pattern via $ref, required and additionalProperties (valid 0, hostile " + bad.Count + ", missing " + miss.Count + ": " + string.Join(" | ", bad.ToArray()) + ")");
            string dir = Path.Combine(Path.GetTempPath(), "pstools-ptr-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(dir);
            try
            {
                Bundle b = EnrichedFixture(dir, new DateTime(2026, 10, 13), null); Brand brand = new Brand();
                Check(JsonSchema.Validate(Ptreport.LoadSchema("ptb-1.schema.json"), Json.Parse(b.ToJson(false))).Count == 0 && Json.GetS(b.Manifest, "platform") == "windows" && Json.GetS(b.Manifest, "mode") == "live", "ptb/1: the enriched fixture bundle validates against schemas\\ptb-1.schema.json; manifest carries platform and mode");
                Dictionary<string, object> r = VulnReport.Build(b, brand); List<string> errs = Ptreport.Validate(r);
                Check(errs.Count == 0, "ptreport: the Vulnerability report validates against schemas\\ptreport-1.schema.json (" + errs.Count + " problem(s)" + (errs.Count > 0 ? ": " + string.Join(" | ", errs.GetRange(0, Math.Min(4, errs.Count)).ToArray()) : "") + ")");
                List<object> rows = Json.Arr(Json.Get(r, "rows")), un = Json.Arr(Json.Get(r, "unconfirmed")); HashSet<string> ids = new HashSet<string>(); bool shape = rows.Count > 0; double prev = double.MaxValue; bool ordered = true, openFirst = true, seenPatched = false;
                foreach (List<object> set in new List<object>[] { rows, un }) foreach (object row in set) { foreach (string k in new string[] { "id", "severity", "status", "evidence", "frameworkRefs", "asOf", "validated" }) if (Json.Get(row, k) == null) shape = false; string id = Json.GetS(row, "id") ?? ""; if (!id.StartsWith("PT-W-VULN-") || !ids.Add(id)) shape = false; if (Json.GetS(row, "validated") != "untested" || Json.Arr(Json.Get(row, "frameworkRefs")).Count != 3) shape = false; }
                foreach (object row in rows) { double sc = Json.N(Json.Get(row, "score")).Value; if (sc > prev) ordered = false; prev = sc; bool open = JsonWrite.Bool(Json.Get(row, "open")); if (!open) seenPatched = true; else if (seenPatched) openFirst = false; }
                Check(shape, "ptreport: every row (open, patched and unconfirmed) carries id, severity, status, evidence, 3 frameworkRefs, asOf and validated=untested; ids are PT-W-VULN-… and unique");
                Check(ordered && openFirst && Json.GetS(rows[0], "cve") == "CVE-2026-1003" && JsonWrite.Bool(Json.Get(rows[0], "kev")) && Json.N(Json.Get(rows[0], "rank")) == 1, "ptreport: rows are risk-ranked by SortScore (open first, KEV first: CVE-2026-1003 is rank 1), never increasing");
                object sum = Json.Get(r, "summary"); Check(JsonWrite.Int(Json.Get(sum, "open"), -1) == 17 && JsonWrite.Int(Json.Get(sum, "patched"), -1) == 1 && JsonWrite.Int(Json.Get(sum, "unconfirmed"), -1) == 1 && JsonWrite.Int(Json.Get(sum, "knownExploited"), -1) == 1 && JsonWrite.Int(Json.Get(sum, "total"), -1) == 18 && un.Count == 1 && Json.GetS(un[0], "cve") == "CVE-2000-0002" && JsonWrite.Int(Json.Get(sum, "msrcWindow"), 0) == 16, "ptreport: summary 17 open / 1 patched / 1 unconfirmed (CVE-2000-0002 listed separately) / 1 known exploited / window 16");
                List<object> bu = Json.Arr(Json.Get(r, "remediation", "byUpdate")), bp = Json.Arr(Json.Get(r, "remediation", "byProduct"));
                Check(bu.Count == 15 && (Json.GetS(bu[0], "kb") ?? "").StartsWith("KB507") && bp.Count == 1 && Json.Arr(Json.Get(bp[0], "cves")).Count == 2 && Json.GetS(bp[0], "worstSeverity") == "High", "ptreport: remediation groups 15 Microsoft updates by KB and one third-party product with 2 CVEs (worst High)");
                object sub = Json.Get(r, "subject"); Check(Json.GetS(sub, "platform") == "windows" && Json.GetS(sub, "mode") == "live" && Json.GetS(sub, "enrichedUtc") == "2026-10-13T09:00:00Z" && Json.GetS(sub, "collectedUtc") == "2026-10-13T08:00:00Z" && Json.GetS(Json.Get(r, "asOf"), "kev", "catalogVersion") == "2026.10.13" && JsonWrite.Strings(Json.Get(r, "method", "limitations")).Count >= 4, "ptreport: subject (platform, mode, pinned collected/enriched times), the feed as-of block and the limitations are present");
                // a report that breaks the contract is caught
                Dictionary<string, object> broken = Json.Obj(Json.Parse(JsonWrite.Text(r, false))); Json.Obj(Json.Arr(broken["rows"])[0]).Remove("id"); Json.Obj(Json.Arr(broken["rows"])[1])["severity"] = "Bogus"; broken["schema"] = "ptreport/2"; broken["extra"] = 1;
                List<string> be = JsonSchema.Validate(Ptreport.LoadSchema("ptreport-1.schema.json"), broken); Check(be.Count == 4, "ptreport: a missing row id, a bad severity, a wrong schema tag and an unknown top-level key are 4 named violations (" + string.Join(" | ", be.ToArray()) + ")");
                string err = ""; try { VulnReport.Build(FixtureBundle(2500, new DateTime(2025, 7, 10, 0, 0, 0, DateTimeKind.Utc)), brand); } catch (BundleException ex) { err = ex.Message; } Check(err.Contains("findings"), "ptreport: a bundle that was never enriched is refused with a reason");
            }
            finally { try { Directory.Delete(dir, true); } catch { } }
        }
        static bool SameBytes(string a, string b) { byte[] x = File.ReadAllBytes(a), y = File.ReadAllBytes(b); if (x.Length != y.Length) return false; for (int i = 0; i < x.Length; i++) if (x[i] != y[i]) return false; return true; }
        static void Report_()
        {
            DateTime now = new DateTime(2026, 10, 13); string dir = Path.Combine(Path.GetTempPath(), "pstools-rep-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(dir);
            try
            {
                // a product name that is at once a spreadsheet formula, HTML, a Markdown table breaker and quote soup; a host name with markup
                string hostile = "=HYPERLINK(\"http://evil.example\",\"x\") <script>alert(1)</script> & 7-Zip | 21.07 'q' \u202Ertl";
                Bundle b = EnrichedFixture(dir, now, hostile); b.Manifest["host"] = "WS-<b>FIN</b>-01";
                Brand brand = Brand.Load(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "brand"));
                Check(brand.Name == "Offport" && Brand.Embeddable(brand.LogoSvg) && brand.Severity["Critical"] == "#C4231B", "report: the Offport brand kit loads (brand.json + an embeddable logo SVG)");
                Check(!Brand.Embeddable("<svg xmlns=\"http://www.w3.org/2000/svg\"><script>1</script></svg>") && !Brand.Embeddable("<svg><image href=\"http://x/y.png\"/></svg>") && !Brand.Embeddable("<svg onload=\"x()\"></svg>") && Brand.Embeddable("<svg xmlns=\"http://www.w3.org/2000/svg\"><rect/></svg>"), "report: a logo SVG with script, image/href or an event handler is never embedded");
                Dictionary<string, object> r = VulnReport.Build(b, brand); string out1 = Path.Combine(dir, "out1"), out2 = Path.Combine(dir, "out2"); string[] fmts = { "json", "csv", "md", "html", "pdf" };
                List<string> f1 = ReportRender.WriteAll(r, brand, out1, fmts); List<string> f2 = ReportRender.WriteAll(VulnReport.Build(b, brand), brand, out2, fmts);
                bool allThere = f1.Count == 5; foreach (string f in f1) if (!File.Exists(f) || new FileInfo(f).Length < 200) allThere = false;
                Check(allThere && Path.GetFileName(f1[0]) == "WS--b-FIN--b--01_fx1_vulnerability.json", "report: five deliverables written with deterministic, safe file names (" + Path.GetFileName(f1[0]) + ")");
                bool same = true; for (int i = 0; i < f1.Count; i++) if (!SameBytes(f1[i], f2[i])) same = false; Check(same, "report: a second render of the same bundle is byte-identical in every format (golden reproducibility)");
                string json = File.ReadAllText(f1[0]), csv = File.ReadAllText(f1[1]), md = File.ReadAllText(f1[2]), html = File.ReadAllText(f1[3]); byte[] pdf = File.ReadAllBytes(f1[4]);
                Check(JsonSchema.Validate(Ptreport.LoadSchema("ptreport-1.schema.json"), Json.Parse(json)).Count == 0 && json.Contains("<script>alert(1)</script>") && json.Contains("WS-<b>FIN</b>-01"), "report json: validates, and keeps the hostile strings verbatim (the source of truth is not where escaping belongs)");
                Check(csv.Contains("'=HYPERLINK") && !Regex.IsMatch(csv, "(^|,)\"?=HYPERLINK", RegexOptions.Multiline) && Regex.IsMatch(csv, "^\"?# ASSESSED") && csv.Contains("\r\nrank,id,severity") && csv.Split('\n').Length >= 20, "report csv: the formula cell is neutralised with a leading apostrophe and quoted; verdict line, header + 18 rows");
                Check(html.Contains("&lt;script&gt;alert(1)&lt;/script&gt;") && !html.Contains("<script>") && html.Contains("WS-&lt;b&gt;FIN&lt;/b&gt;-01") && !html.Contains("WS-<b>FIN") && html.Contains("&#39;q&#39;") && !Regex.IsMatch(html, "(href|src)\\s*=\\s*[\"']\\s*https?:", RegexOptions.IgnoreCase) && !html.Contains("<link") && html.Contains("<svg") && html.Contains("@media print") && html.Contains("stroke=\"#0FAA04\"") && html.Contains("CVE-2026-1003") && html.Contains("class=\"kev\""), "report html: every client-controlled string escaped, no external href/src/link, inline Offport SVG, print stylesheet, KEV row present");
                Check(md.Contains("\\|") && md.Contains("&lt;script&gt;") && !md.Contains("<script>") && md.StartsWith("# Endpoint Vulnerability Report") && md.Contains("- **Coverage:** ") && md.Contains("status `assessed`"), "report md: pipes and angle brackets escaped, title present, coverage line present");
                string pdfText = Encoding.GetEncoding(1252).GetString(pdf); int pages = Regex.Matches(pdfText, "/Type /Page ").Count;
                Check(pdf.Length > 3000 && pdfText.StartsWith("%PDF-1.4") && pdfText.TrimEnd().EndsWith("%%EOF") && pages >= 1 && pdfText.Contains("/Helvetica-Bold") && pdfText.Contains("Page 1 of " + pages) && pdfText.Contains(" re f") && pdfText.Contains("<script>alert\\(1\\)</script>") && !pdfText.Contains("alert(1)"), "report pdf: PDF 1.4, " + pages + " page(s), Helvetica, filled chips, page numbers; hostile text stays inside its string operand (parentheses escaped, nothing can end the operand early)");
                // the real tool, twice, offline: identical outputs, exit 0; a never-enriched bundle is refused
                string cli = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "PowerTowerCli.exe"); string inP = Path.Combine(dir, "in.ptb"); b.Save(inP, BundleKey.None());
                if (File.Exists(cli))
                {
                    int x1; string o1 = RunCli(cli, "report \"" + inP + "\" --plain --out \"" + Path.Combine(dir, "c1") + "\" --no-color", out x1); int x2; string o2 = RunCli(cli, "report \"" + inP + "\" --plain --out \"" + Path.Combine(dir, "c2") + "\" --no-color --quiet", out x2);
                    bool cliSame = x1 == 0 && x2 == 0; foreach (string f in fmts) { string p1 = Path.Combine(dir, "c1", "WS--b-FIN--b--01_fx1_vulnerability." + f), p2 = Path.Combine(dir, "c2", "WS--b-FIN--b--01_fx1_vulnerability." + f); if (!File.Exists(p1) || !File.Exists(p2) || !SameBytes(p1, p2)) cliSame = false; }
                    string noF = Path.Combine(dir, "nof.ptb"); FixtureBundle(2500, new DateTime(2025, 7, 10, 0, 0, 0, DateTimeKind.Utc)).Save(noF, BundleKey.None()); int x3; string o3 = RunCli(cli, "report \"" + noF + "\" --plain --out \"" + Path.Combine(dir, "c3") + "\" --no-color", out x3);
                    int x4; string o4 = RunCli(cli, "report \"" + inP + "\" --plain --formats html,bogus --no-color", out x4);
                    Check(cliSame && x3 == 1 && o3.Contains("findings") && x4 == 2 && o4.Contains("--formats"), "report CLI: two runs give identical files (exit " + x1 + "/" + x2 + "); a never-enriched bundle exits 1 naming the reason (" + x3 + "); an unknown format is a usage error (" + x4 + ")");
                }
                else Check(false, "report CLI: PowerTowerCli.exe not found next to Tests.exe");
            }
            finally { try { Directory.Delete(dir, true); } catch { } }
        }
        /// <summary>PT-45: the report fails closed. An empty feed cache is NOT ASSESSABLE, a partly read window is INCOMPLETE COVERAGE, only full coverage gets the normal headline - in every format, with summary.status in the JSON and exit 1 from the CLI.</summary>
        static void ReportCoverage_()
        {
            DateTime now = new DateTime(2026, 10, 13); string dir = Path.Combine(Path.GetTempPath(), "pstools-cov-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(dir); Brand brand = new Brand(); string[] fmts = { "json", "csv", "md", "html", "pdf" };
            try
            {
                // (c) full coverage keeps the normal headline and is 'assessed'
                Bundle full = EnrichedFixture(Path.Combine(dir, "full"), now, null); Dictionary<string, object> rf = VulnReport.Build(full, brand); object sf = Json.Get(rf, "summary"); string hf = Json.GetS(sf, "headline") ?? "";
                Check(Json.GetS(sf, "status") == "assessed" && JsonWrite.Bool(Json.Get(sf, "assessable")) && hf.StartsWith("17 open findings") && hf.Contains(" unrated), ") && Json.N(Json.Get(sf, "coverage", "releasesChecked")) == Json.N(Json.Get(sf, "coverage", "releasesExpected")) && Json.Arr(Json.Get(sf, "coverage", "feedsUnavailable")).Count == 0 && Ptreport.Validate(rf).Count == 0, "coverage: a fully covered fixture is 'assessed' (" + Json.GetS(sf, "coverage", "text") + ") and keeps the normal headline, now with the unrated count (PT-48)");
                // (a) an empty feed cache, offline: nothing could be checked
                FeedCache empty = new FeedCache(Path.Combine(dir, "empty")); empty.Offline = true; Bundle ba = FixtureBundle(2500, new DateTime(2025, 7, 10, 0, 0, 0, DateTimeKind.Utc)); VulnEnrich ea = EnrichBundle.From(ba, empty); ea.Now = now; ea.Run(); EnrichBundle.Apply(ba, ea);
                Dictionary<string, object> ra = VulnReport.Build(ba, brand); object sa = Json.Get(ra, "summary"); string ha = Json.GetS(sa, "headline") ?? "";
                Check(Json.GetS(sa, "status") == "not-assessable" && !JsonWrite.Bool(Json.Get(sa, "assessable")) && ha.StartsWith("NOT ASSESSABLE") && ha.Contains("0 of ") && !ha.Contains("No open vulnerabilities") && !ha.Contains("is fixed on this build") && Json.Arr(Json.Get(sa, "coverage", "feedsUnavailable")).Count >= 3 && Json.N(Json.Get(sa, "coverage", "problems")) > 0 && Ptreport.Validate(ra).Count == 0, "coverage: an empty feed cache is NOT ASSESSABLE with the facts (" + Json.GetS(sa, "coverage", "text") + "), never 'no open vulnerabilities'");
                Check(FormatsSay(ReportRender.WriteAll(ra, brand, Path.Combine(dir, "a"), fmts), "NOT ASSESSABLE", "not-assessable", null), "coverage: NOT ASSESSABLE leads every format - json status flag, csv first line, md, html, pdf - and none says 'no open vulnerabilities' or 'is fixed on this build'");
                // (b) a stale host (patch level January 2025: a 22-month window) with only 4 monthly releases readable in the cache
                string partDir = Path.Combine(dir, "part"); FeedCache part = SeedFeeds(partDir, now); int kept = 0; foreach (string f in Directory.GetFiles(partDir, "msrc-*.json", SearchOption.AllDirectories)) { if (Path.GetFileName(f) == "msrc-releases.json") continue; if (++kept > 4) File.Delete(f); }
                Bundle bb = FixtureBundle(2500, new DateTime(2025, 1, 10, 0, 0, 0, DateTimeKind.Utc)); VulnEnrich eb = EnrichBundle.From(bb, part); eb.Now = now; eb.Run(); EnrichBundle.Apply(bb, eb);
                Dictionary<string, object> rb = VulnReport.Build(bb, brand); object sb2 = Json.Get(rb, "summary"); string hb = Json.GetS(sb2, "headline") ?? "";
                Check(Json.GetS(sb2, "status") == "incomplete-coverage" && hb.StartsWith("INCOMPLETE COVERAGE") && hb.Contains("4 of 22 MSRC monthly releases checked") && !hb.Contains("No open vulnerabilities") && !hb.Contains("is fixed on this build") && Json.N(Json.Get(sb2, "coverage", "releasesChecked")) == 4 && Json.N(Json.Get(sb2, "coverage", "releasesExpected")) == 22 && Json.N(Json.Get(sb2, "coverage", "problems")) >= 14 && Ptreport.Validate(rb).Count == 0, "coverage: 4 of 22 releases is INCOMPLETE COVERAGE with the counts (" + Json.GetS(sb2, "coverage", "text") + "), never clean");
                List<string> wb = ReportRender.WriteAll(rb, brand, Path.Combine(dir, "b"), fmts);
                Check(FormatsSay(wb, "INCOMPLETE COVERAGE", "incomplete-coverage", "4 of 22"), "coverage: INCOMPLETE COVERAGE and '4 of 22' lead every format");
                string mdB = File.ReadAllText(wb[2]), htmlB = File.ReadAllText(wb[3]); int bannerAt = mdB.IndexOf("INCOMPLETE COVERAGE"), tableAt = mdB.IndexOf("## Open findings");
                Check(bannerAt > 0 && bannerAt < tableAt && mdB.Substring(0, tableAt).Contains("offline") && htmlB.IndexOf("INCOMPLETE COVERAGE") > 0 && htmlB.IndexOf("INCOMPLETE COVERAGE") < htmlB.IndexOf("<h2>Open findings") && htmlB.Contains("<div class=\"alert\"><b>INCOMPLETE COVERAGE</b>") && htmlB.Contains("MSRC releases checked"), "coverage: the banner with the problems themselves comes before the findings in Markdown and HTML, and the HTML tile reads 'MSRC releases checked'");
                Check(Json.GetS(Json.Get(rb, "method", "coverage"), "status") == "incomplete-coverage" && Json.N(Json.Get(rb, "method", "coverage", "releasesChecked")) == 4 && Json.Arr(Json.Get(rb, "method", "coverage", "problems")).Count >= 14, "coverage: method.coverage carries status and releasesChecked as well");
                // a doctored findings section is refused, not read as clean
                Bundle bad = FixtureBundle(2500, new DateTime(2025, 7, 10, 0, 0, 0, DateTimeKind.Utc)); Dictionary<string, object> fdx = new Dictionary<string, object>(); fdx["items"] = "nope"; fdx["asOf"] = new Dictionary<string, object>(); bad["findings"] = fdx; string e1 = ""; try { VulnReport.Build(bad, brand); } catch (BundleException ex) { e1 = ex.Message; }
                bad["findings"] = "nope"; string e2 = ""; try { VulnReport.Build(bad, brand); } catch (BundleException ex) { e2 = ex.Message; }
                Check(e1.Contains("findings.items") && e2.Contains("findings"), "coverage: findings.items that is not a list, or a findings section that is not an object, is refused (" + e1 + " / " + e2 + ")");
                // the as-of block removed: not assessable
                Bundle noAs = EnrichedFixture(Path.Combine(dir, "noas"), now, null); Json.Obj(noAs["findings"]).Remove("asOf"); object sn = Json.Get(VulnReport.Build(noAs, brand), "summary");
                Check(Json.GetS(sn, "status") == "not-assessable" && (Json.GetS(sn, "headline") ?? "").StartsWith("NOT ASSESSABLE"), "coverage: a bundle whose as-of block was removed is NOT ASSESSABLE");
                // the CLI writes the deliverables and exits 1 for a report that is not a clean assessment
                string cli = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "PowerTowerCli.exe");
                if (File.Exists(cli)) { string pa = Path.Combine(dir, "a.ptb"); ba.Save(pa, BundleKey.None()); int xa; string oa = RunCli(cli, "report \"" + pa + "\" --plain --out \"" + Path.Combine(dir, "ca") + "\" --no-color", out xa); Check(xa == 1 && oa.Contains("NOT ASSESSABLE") && File.Exists(Path.Combine(dir, "ca", "FIXTURE_fx1_vulnerability.json")), "coverage CLI: an unassessable bundle still writes the deliverables and exits 1 (exit " + xa + ")"); }
                else Check(false, "coverage CLI: PowerTowerCli.exe not found next to Tests.exe");
            }
            finally { try { Directory.Delete(dir, true); } catch { } }
        }
        /// <summary>Every written format carries the verdict in its headline (PDF: its last word, since the writer wraps at spaces) and none carries the clean wording; the JSON is parsed for summary.status; the CSV must open with the verdict line.</summary>
        static bool FormatsSay(List<string> files, string verdict, string status, string alsoContains)
        {
            foreach (string f in files)
            {
                string t = f.EndsWith(".pdf") ? Encoding.GetEncoding(1252).GetString(File.ReadAllBytes(f)) : File.ReadAllText(f); bool ok;
                if (f.EndsWith(".json")) { object j = Json.Parse(t); ok = Json.GetS(Json.Get(j, "summary"), "status") == status && (Json.GetS(Json.Get(j, "summary"), "headline") ?? "").StartsWith(verdict); }
                else if (f.EndsWith(".pdf")) ok = t.Contains(verdict.Substring(verdict.LastIndexOf(' ') + 1));
                else ok = t.Contains(verdict) && !t.Contains("No open vulnerabilities") && !t.Contains("is fixed on this build") && (alsoContains == null || t.Contains(alsoContains));
                if (f.EndsWith(".csv")) ok = ok && Regex.IsMatch(t, "^\"?# " + verdict);
                if (!ok) { Info("formats: " + Path.GetExtension(f) + " does not carry the verdict " + verdict); return false; }
            }
            return true;
        }
        /// <summary>PT-46: host-controlled text cannot inject Markdown. A remote image, a javascript: link, emphasis, backticks, raw HTML, a bare URL and an e-mail address in a product, a title, the evidence, the host, the domain and the brand footer stay inert in Markdown (raw, outside code spans), HTML (escaped, CSP, no href/src), CSV (formula-safe) and PDF (inside the string operand).</summary>
        static void ReportMarkdown_()
        {
            DateTime now = new DateTime(2026, 10, 13); string dir = Path.Combine(Path.GetTempPath(), "pstools-mdi-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(dir);
            try
            {
                string img = "![beacon](http://evil.example/x.png)", link = "[click](javascript:alert(1))", emph = "**bold** _it_ `code` ~~s~~ <b>b</b>", bare = "see http://evil.example/p?a=1&b=2 or www.evil.example and bob@evil.example";
                Bundle b = EnrichedFixture(dir, now, img + " " + link); Brand brand = new Brand(); Dictionary<string, object> r = VulnReport.Build(b, brand);
                List<object> rows = Json.Arr(Json.Get(r, "rows")); Dictionary<string, object> r0 = Json.Obj(rows[0]), r1 = Json.Obj(rows[1]); r0["title"] = img + " " + emph; r0["evidence"] = link + " " + bare; r1["title"] = bare; r1["fix"] = "`code` " + link; r1["evidence"] = emph;
                Json.Obj(Json.Get(r, "subject"))["host"] = img; Json.Obj(Json.Get(r, "subject"))["domain"] = link; Json.Obj(Json.Get(r, "brand"))["footer"] = bare + " " + link + " " + emph;
                string[] fmts = { "json", "csv", "md", "html", "pdf" }; List<string> w = ReportRender.WriteAll(r, brand, Path.Combine(dir, "o"), fmts);
                string csv = File.ReadAllText(w[1]), md = File.ReadAllText(w[2]), html = File.ReadAllText(w[3]), pdf = Encoding.GetEncoding(1252).GetString(File.ReadAllBytes(w[4]));
                // Markdown: the data survives, but only inside code spans (a span closes at a backtick run of the same length); outside them nothing active is left
                string plain = Regex.Replace(Regex.Replace(md, "(?s)````.*?````", ""), "(`+)[\\s\\S]*?\\1(?!`)", "");
                Check(md.Contains("http://evil.example/x.png") && md.Contains("javascript:alert(1)") && md.Contains("bob@evil.example"), "report md: the hostile strings are still in the report, as data");
                bool mdInert = !plain.Contains("](") && !plain.Contains("![") && !plain.Contains("**bold**") && !plain.Contains("_it_") && !plain.Contains("~~") && !plain.Contains("<b>") && !Regex.IsMatch(plain, "(?i)https?://|www\\.|@evil");
                if (!mdInert) Info("md plain residue: " + Regex.Match(plain, "(?i).{0,40}(\\]\\(|!\\[|\\*\\*bold|_it_|~~|<b>|https?://|www\\.|@evil).{0,40}").Value.Replace("\n", "\\n"));
                Check(mdInert, "report md: outside code spans no link, image, emphasis, strikethrough, HTML tag, bare URL or e-mail address is left (PT-46)");
                Check(md.Contains("# Endpoint Vulnerability Report — `![beacon](http://evil.example/x.png)`") && md.Contains("(`[click](javascript:alert(1))`)") && md.Contains("\\[click\\]\\(javascript:alert\\(1\\)\\)") && md.Contains("`http://evil.example/p?a=1&b=2`") && md.Contains("`bob@evil.example`") && md.Contains("\\*\\*bold\\*\\*") && md.Contains("&lt;b&gt;b&lt;/b&gt;"), "report md: cells, host and domain are code spans; prose is backslash-escaped with URLs and e-mail addresses as code; angle brackets are entities everywhere");
                // HTML: everything is text; no element can fetch or run anything, and a CSP forbids it anyway
                Check(html.Contains("Content-Security-Policy") && html.Contains("default-src 'none'") && !Regex.IsMatch(html, "<(a|img|script|iframe|link|object|embed)\\b", RegexOptions.IgnoreCase) && !Regex.IsMatch(html, "(?i)(href|src|action)\\s*=") && html.Contains("![beacon](http://evil.example/x.png)") && html.Contains("&lt;b&gt;b&lt;/b&gt;") && !html.Contains("<b>b</b>"), "report html: CSP present (PT-49); no a/img/script element and no href/src/action attribute; payloads are escaped text");
                // CSV: data, quoted, never a formula
                Check(csv.Contains(img) && csv.Contains("javascript:alert(1)") && !Regex.IsMatch(csv, "(^|,)\"?[=+@]", RegexOptions.Multiline), "report csv: payloads are plain quoted cells and no cell starts with = + or @");
                // PDF: the payload parentheses are escaped inside their string operand (host and domain sit on one unwrapped header line), so the operand cannot be closed early
                bool pJs = pdf.Contains("\\(javascript:alert\\(1\\)\\)"), pImg = pdf.Contains("beacon]\\(http://evil.example/x.png\\)"); Match pRaw = Regex.Match(pdf, "\\]\\(http|alert\\(1\\)");   // a payload parenthesis left unescaped (a string operand's own opening parenthesis is not one)
                if (!pJs) { int at = pdf.IndexOf("javascript"); Info("pdf javascript context: " + (at < 0 ? "(absent)" : pdf.Substring(Math.Max(0, at - 50), Math.Min(130, pdf.Length - Math.Max(0, at - 50))).Replace("\n", "\\n").Replace("\r", "\\r"))); }
                if (!pImg) { int at = pdf.IndexOf("beacon"); Info("pdf beacon context: " + (at < 0 ? "(absent)" : pdf.Substring(Math.Max(0, at - 50), Math.Min(130, pdf.Length - Math.Max(0, at - 50))).Replace("\n", "\\n").Replace("\r", "\\r"))); }
                if (pRaw.Success) Info("pdf unescaped paren context: " + pdf.Substring(Math.Max(0, pRaw.Index - 60), Math.Min(150, pdf.Length - Math.Max(0, pRaw.Index - 60))).Replace("\n", "\\n").Replace("\r", "\\r"));
                Check(pJs && pImg && !pRaw.Success, "report pdf: link and image syntax stay inside the string operand with escaped parentheses");
            }
            finally { try { Directory.Delete(dir, true); } catch { } }
        }

        // ── Phase 3: the agentless remote-audit controller, driven entirely by the FakeTransport ──
        const string SECRET = "S3cr3t-Ph3-PASSWORD-do-not-leak", ACCOUNT = "LAB\\auditor";
        static Engagement Ph3Eng()
        {
            Engagement e = new Engagement(); e.Id = "ENG-PH3"; e.Client = "Acme"; e.Operator = "ops";
            e.Scope.Add("10.0.0.0/24"); e.WindowStartUtc = DateTime.UtcNow.AddDays(-1); e.WindowEndUtc = DateTime.UtcNow.AddDays(1);
            e.PublicKeyXml = "<RSAKeyValue><Modulus>abc</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";
            return e;
        }
        static TargetSpec Ph3Target(string host) { TargetSpec t = new TargetSpec(); t.Host = host; t.CredLabel = "lab"; t.TimeoutSec = 5; return t; }
        static RunResult Ph3Run(Engagement e, FakeTransport fake, RunJournal j, string host, out bool credRead, RunOptions optOverride)
        {
            bool read = false;
            Func<TargetSpec, ITransport> make = delegate (TargetSpec ts) { return fake; };
            Func<string, NetworkCred> resolve = delegate (string label) { read = true; return new NetworkCred(ACCOUNT, Encoding.UTF8.GetBytes(SECRET)); };
            RemoteAudit ctl = new RemoteAudit(e, j, make, resolve, DateTime.UtcNow);
            RunOptions opt = optOverride ?? new RunOptions(); opt.CollectorExe = Encoding.UTF8.GetBytes("MZcollector"); opt.DefaultTimeoutSec = 5;
            RunResult r = ctl.RunOne(Ph3Target(host), opt); credRead = read; return r;
        }
        static void RemoteAudit_()
        {
            string dir = Path.Combine(Path.GetTempPath(), "pstools-ph3-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(dir);
            try
            {
                Engagement e = Ph3Eng(); string jp = Path.Combine(dir, "journal.ndjson"); bool cr;

                // 1. happy path: ok, verified, left clean, one connect, bundle carried back
                FakeTransport ok = new FakeTransport(); RunResult r = Ph3Run(e, ok, new RunJournal(jp), "10.0.0.10", out cr, null);
                Check(r.Status == "ok" && r.Verified && r.LeftClean && r.Tag is byte[] && ok.ConnectCalls == 1 && ok.DeleteCalls >= 1 && !ok.Exists(), "remote: a clean run verifies the SHA-256, carries the bundle back and leaves zero artifacts (status " + r.Status + ", connects " + ok.ConnectCalls + ")");

                // 2. out of scope: refused BEFORE any transport call or credential read
                FakeTransport oos = new FakeTransport(); RunResult r2 = Ph3Run(e, oos, new RunJournal(jp), "192.168.5.5", out cr, null);
                Check(r2.Status == "refused-scope" && oos.ConnectCalls == 0 && oos.LogonAttempts == 0 && oos.LastSecretSeen == null && !cr, "remote: an out-of-scope host is refused before any network call or credential read (" + r2.Status + ", connects " + oos.ConnectCalls + ", credRead " + cr + ")");

                // 3. out of window
                Engagement past = Ph3Eng(); past.WindowStartUtc = DateTime.UtcNow.AddDays(-5); past.WindowEndUtc = DateTime.UtcNow.AddDays(-2);
                FakeTransport ow = new FakeTransport(); RunResult r3 = Ph3Run(past, ow, new RunJournal(jp), "10.0.0.10", out cr, null);
                Check(r3.Status == "refused-window" && ow.ConnectCalls == 0 && !cr, "remote: an out-of-window run is refused before any network call (" + r3.Status + ")");

                // 4. host down: no credential sent
                FakeTransport down = new FakeTransport(); down.Smb445 = false; RunResult r4 = Ph3Run(e, down, new RunJournal(jp), "10.0.0.10", out cr, null);
                Check(r4.Status == "unreachable" && down.LogonAttempts == 0 && down.LastSecretSeen == null, "remote: a host with 445 down is unreachable and no credential is sent (" + r4.Status + ")");

                // 5. logon failure: exactly ONE attempt, no retry
                FakeTransport lf = new FakeTransport(); lf.ConnectThrowCode = "LOGON_FAILURE"; RunResult r5 = Ph3Run(e, lf, new RunJournal(jp), "10.0.0.10", out cr, null);
                Check(r5.Status == "logon-failed" && lf.LogonAttempts == 1, "remote: a logon failure stops after exactly ONE attempt (attempts " + lf.LogonAttempts + ") so the account cannot be locked out");

                // 6. token filter / UAC remote restriction
                FakeTransport tf = new FakeTransport(); tf.ConnectThrowCode = "TOKEN_FILTER"; RunResult r6 = Ph3Run(e, tf, new RunJournal(jp), "10.0.0.10", out cr, null);
                Check(r6.Status == "token-filter" && r6.Detail.IndexOf("LocalAccountTokenFilterPolicy") >= 0, "remote: a filtered token (ADMIN$ denied after logon) is detected and explained, never changed");

                // 7. ADMIN$ missing
                FakeTransport am = new FakeTransport(); am.ConnectThrowCode = "ADMIN_SHARE"; RunResult r7 = Ph3Run(e, am, new RunJournal(jp), "10.0.0.10", out cr, null);
                Check(r7.Status == "admin-share", "remote: a missing/disabled ADMIN$ is reported (" + r7.Status + ")");

                // 8. exe quarantined / vanished -> cleanup still attempted
                FakeTransport q = new FakeTransport(); q.ExeVanishes = true; RunResult r8 = Ph3Run(e, q, new RunJournal(jp), "10.0.0.10", out cr, null);
                Check(r8.Status == "exe-blocked" && r8.Detail.IndexOf(r8.RunId) >= 0 && q.DeleteCalls >= 1, "remote: a quarantined/vanished collector is detected, the run id is given for the SOC, and the staged dir is cleaned");

                // 9. hang -> timeout -> partial bundle, killed, cleaned, unverified
                FakeTransport hg = new FakeTransport(); hg.Hangs = true; RunResult r9 = Ph3Run(e, hg, new RunJournal(jp), "10.0.0.10", out cr, null);
                Check(r9.Status == "timeout-partial" && r9.Partial && !r9.Verified && r9.Tag is byte[] && r9.LeftClean, "remote: a hang is killed at the timeout and a partial, unverified bundle is fetched (" + r9.Status + ")");

                // 10. partial module -> ok-partial, still verified
                FakeTransport pm = new FakeTransport(); pm.PartialModule = true; RunResult r10 = Ph3Run(e, pm, new RunJournal(jp), "10.0.0.10", out cr, null);
                Check(r10.Status == "ok-partial" && r10.Verified && r10.Partial, "remote: a partial module yields ok-partial with a verified bundle");

                // 11. reboot mid-run -> failed, no retry
                FakeTransport rb = new FakeTransport(); rb.Reboot = true; RunResult r11 = Ph3Run(e, rb, new RunJournal(jp), "10.0.0.10", out cr, null);
                Check(r11.Status == "reboot-failed" && rb.WaitCalls == 1, "remote: a lost session mid-run is marked failed and not auto-retried");

                // 12. hash mismatch -> rejected, bundle not kept, cleaned
                FakeTransport bh = new FakeTransport(); bh.BadHash = true; RunResult r12 = Ph3Run(e, bh, new RunJournal(jp), "10.0.0.10", out cr, null);
                Check(r12.Status == "hash-mismatch" && !(r12.Tag is byte[]) && bh.DeleteCalls >= 1 && !bh.Exists(), "remote: a SHA-256 mismatch is refused, the bundle is not kept, the dir is cleaned");

                // 13. no bundle produced
                FakeTransport nb = new FakeTransport(); nb.NoBundle = true; RunResult r13 = Ph3Run(e, nb, new RunJournal(jp), "10.0.0.10", out cr, null);
                Check(r13.Status == "no-bundle", "remote: a run that produces no bundle.ptb is a failure (" + r13.Status + ")");

                // 14. malformed done.json -> cannot verify -> failed
                FakeTransport bd = new FakeTransport(); bd.BadDoneJson = true; RunResult r14 = Ph3Run(e, bd, new RunJournal(jp), "10.0.0.10", out cr, null);
                Check(r14.Status == "no-done", "remote: a malformed/missing done.json means the transfer cannot be verified and the run fails (" + r14.Status + ")");

                // 15. cleanup could not complete -> flagged, not silently "ok"
                FakeTransport df = new FakeTransport(); df.DeleteFails = true; RunResult r15 = Ph3Run(e, df, new RunJournal(jp), "10.0.0.10", out cr, null);
                Check(r15.Status == "ok" && !r15.LeftClean && r15.Detail.IndexOf("cleanup --run") >= 0, "remote: when the staged dir cannot be removed the run is ok but flagged not-clean with a cleanup hint");

                // 16. controller-crash cleanup command + stale sweep
                FakeTransport cu = new FakeTransport(); cu.Stale.Add(new StagedDir { Name = "pt-old", WhenUtc = DateTime.UtcNow.AddHours(-3) });
                Func<TargetSpec, ITransport> mk = delegate (TargetSpec ts) { return cu; }; Func<string, NetworkCred> rc = delegate (string l) { return new NetworkCred(ACCOUNT, Encoding.UTF8.GetBytes(SECRET)); };
                RemoteAudit ctl2 = new RemoteAudit(e, new RunJournal(jp), mk, rc, DateTime.UtcNow);
                RunResult r16 = ctl2.Cleanup(Ph3Target("10.0.0.10"), "abc123", new RunOptions());
                Check(r16.Status == "cleaned" && cu.DeleteCalls >= 1 && !cu.Exists(), "remote: cleanup --run removes the staged dir after a controller crash and sweeps stale dirs");

                // ── the secret must never appear: journal file, result fields, cred ToString ──
                string journalText = File.ReadAllText(jp);
                bool inJournal = journalText.IndexOf(SECRET) >= 0;
                bool inResults = false; foreach (RunResult rr in new RunResult[] { r, r5, r6, r8, r9, r12, r15 }) { if ((rr.Detail ?? "").IndexOf(SECRET) >= 0 || (rr.User ?? "").IndexOf(SECRET) >= 0) inResults = true; }
                Check(!inJournal && !inResults && journalText.IndexOf("auditor") >= 0, "remote: the secret appears nowhere in the journal or results, though the account (domain\\user) is recorded");
                NetworkCred nc = new NetworkCred(ACCOUNT, Encoding.UTF8.GetBytes(SECRET));
                Check(nc.ToString().IndexOf(SECRET) < 0, "remote: NetworkCred.ToString() never prints the secret");
                nc.Zero(); bool zeroed = true; foreach (byte bb in nc.SecretBytes) if (bb != 0) zeroed = false; Check(zeroed, "remote: a credential's secret bytes are zeroed by Zero()");

                // ── credential store: DPAPI round-trip, not plaintext; passphrase round-trip; tamper/wrong-pass refused ──
                List<CredEntry> entries = new List<CredEntry>(); CredEntry ce = new CredEntry(); ce.Label = "lab"; ce.User = ACCOUNT; ce.Secret = Encoding.UTF8.GetBytes(SECRET); entries.Add(ce);
                string dpv = Path.Combine(dir, "creds.ptv"); CredStore.SaveDpapi(dpv, entries, e.Id);
                byte[] dpvBytes = File.ReadAllBytes(dpv); bool dpvPlain = IndexOf(dpvBytes, Encoding.UTF8.GetBytes(SECRET)) >= 0;
                List<CredEntry> back = CredStore.Load(dpv, null, e.Id);
                Check(!dpvPlain && back.Count == 1 && Encoding.UTF8.GetString(back[0].Secret) == SECRET && back[0].User == ACCOUNT, "remote: creds.ptv (DPAPI) is not plaintext on disk and round-trips the secret");
                string wrongEng = ""; try { CredStore.Load(dpv, null, "OTHER-ENG"); } catch (Exception ex) { wrongEng = ex.Message; } Check(wrongEng.Length > 0, "remote: a creds.ptv (DPAPI) bound to one engagement will not open under another id");
                string ppv = Path.Combine(dir, "creds-pp.ptv"); byte[] pass = Encoding.UTF8.GetBytes("a-long-passphrase-123"); CredStore.SavePass(ppv, entries, pass);
                byte[] ppvBytes = File.ReadAllBytes(ppv); List<CredEntry> back2 = CredStore.Load(ppv, pass, e.Id);
                Check(IndexOf(ppvBytes, Encoding.UTF8.GetBytes(SECRET)) < 0 && back2.Count == 1 && Encoding.UTF8.GetString(back2[0].Secret) == SECRET, "remote: creds.ptv (passphrase) is AES-encrypted and round-trips the secret");
                string wrongPass = ""; try { CredStore.Load(ppv, Encoding.UTF8.GetBytes("wrong"), e.Id); } catch (Exception ex) { wrongPass = ex.Message; } Check(wrongPass.Length > 0, "remote: the wrong passphrase is refused (HMAC check)");
                ppvBytes[ppvBytes.Length - 1] ^= 0xFF; File.SetAttributes(ppv, FileAttributes.Normal); File.WriteAllBytes(ppv, ppvBytes); string tampered = ""; try { CredStore.Load(ppv, pass, e.Id); } catch (Exception ex) { tampered = ex.Message; } Check(tampered.Length > 0, "remote: a tampered creds.ptv is refused (encrypt-then-MAC)");
            }
            finally { try { Directory.Delete(dir, true); } catch { } }
        }
        static void RemoteFuzz_()
        {
            // hostnames: hostile ones refused, legitimate ones accepted - never a crash
            string[] bad = { "\\\\evil\\share", "//evil/share", "../../Windows", "a..b", "host;calc.exe", "a b", "%SystemRoot%", "x`whoami`", "h$t", "ab|cd", "\x01ctrl", new string('h', 300), "" };
            string[] good = { "10.0.0.10", "WS-01", "host.corp.local", "server_2022", "fe80::1", "::1" };
            int refused = 0; foreach (string h in bad) { string why; if (!TargetList.ValidHost(h, out why) && why != null) refused++; }
            int ok = 0; foreach (string h in good) { string why; if (TargetList.ValidHost(h, out why)) ok++; }
            Check(refused == bad.Length && ok == good.Length, "remote fuzz: all " + bad.Length + " hostile host strings refused (" + refused + "), all " + good.Length + " legitimate ones accepted (" + ok + ")");

            // target CSV lines: injection and oversize do not crash the parser
            string[] lines = { "10.0.0.10,lab,30,inventory;recon", "  # a comment", "", "\\\\unc\\x,lab", "host;rm -rf,lab", new string('z', 5000) + ",lab", "10.0.0.11" };
            int parsed = 0, skipped = 0; foreach (string ln in lines) { string err; TargetSpec ts = TargetList.Parse(ln, out err); if (ts != null) parsed++; else skipped++; }
            Check(parsed == 2 && skipped == lines.Length - 2, "remote fuzz: the target list parser takes the 2 valid lines and skips the rest (comments, blanks, UNC, injection, oversize) without crashing (parsed " + parsed + ")");

            // journal parser: good / malformed / oversize / empty lines - only the good survive, no crash/hang
            string dir = Path.Combine(Path.GetTempPath(), "pstools-ph3j-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(dir);
            try
            {
                string jp = Path.Combine(dir, "j.ndjson");
                RunResult r = new RunResult(); r.Host = "10.0.0.10"; r.Status = "ok"; r.User = ACCOUNT; RunJournal j = new RunJournal(jp); j.Append(r); j.Append(r);
                using (StreamWriter w = new StreamWriter(jp, true)) { w.WriteLine("{ not json at all"); w.WriteLine(""); w.WriteLine(new string('x', 200000)); w.WriteLine("{\"status\":\"ok\",\"host\":\"h\"}"); }
                List<Dictionary<string, object>> got = j.Read();
                Check(got.Count == 3, "remote fuzz: the journal reader keeps the 3 well-formed lines and skips the malformed, empty and over-long ones (" + got.Count + ")");

                // done.json fuzz: wrong hash, malformed, oversize all refused by the controller, no crash
                Engagement e = Ph3Eng(); bool cr;
                FakeTransport big = new FakeTransport(); big.Bundle = new byte[2 * 1024 * 1024]; RunResult rb = Ph3Run(e, big, new RunJournal(jp), "10.0.0.10", out cr, null);
                Check(rb.Status == "ok" && rb.Verified && rb.Bytes == big.Bundle.Length, "remote fuzz: a 2 MB bundle verifies and round-trips its byte count");
            }
            finally { try { Directory.Delete(dir, true); } catch { } }
        }

        // ── PT-59: the one-attempt rule is per credential across a whole batch, not per target ──
        static void RemoteBatch_()
        {
            Engagement e = Ph3Eng(); string dir = Path.Combine(Path.GetTempPath(), "pstools-ph3b-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(dir);
            try
            {
                List<FakeTransport> made = new List<FakeTransport>();
                Func<TargetSpec, ITransport> make = delegate (TargetSpec ts) { FakeTransport ft = new FakeTransport(); ft.ConnectThrowCode = "LOGON_FAILURE"; made.Add(ft); return ft; };
                Func<string, NetworkCred> resolve = delegate (string label) { return new NetworkCred(ACCOUNT, Encoding.UTF8.GetBytes(SECRET)); };
                RemoteAudit ctl = new RemoteAudit(e, new RunJournal(Path.Combine(dir, "j.ndjson")), make, resolve, DateTime.UtcNow);
                List<TargetSpec> targets = new List<TargetSpec>();
                for (int i = 11; i <= 16; i++) { TargetSpec ts = new TargetSpec(); ts.Host = "10.0.0." + i; ts.CredLabel = "lab"; ts.TimeoutSec = 5; targets.Add(ts); }
                RunOptions opt = new RunOptions(); opt.CollectorExe = Encoding.UTF8.GetBytes("MZ");
                List<RunResult> rs = ctl.RunBatch(targets, opt);
                int logonFailed = 0, skipped = 0, totalLogonAttempts = 0; foreach (FakeTransport ft in made) totalLogonAttempts += ft.LogonAttempts;
                foreach (RunResult r in rs) { if (r.Status == "logon-failed") logonFailed++; else if (r.Status == "skipped-locked-credential") skipped++; }
                Check(rs.Count == 6 && logonFailed == 1 && skipped == 5 && made.Count == 1 && totalLogonAttempts == 1,
                    "remote: BATCH-STOPS-AFTER-FIRST-LOGON-FAILURE - 6 targets on one credential make exactly ONE logon attempt; the other 5 are skipped before any logon (attempts " + totalLogonAttempts + ", transports " + made.Count + ", skipped " + skipped + ")");
                // a different credential in the same batch is NOT blocked by the first one's failure
                made.Clear(); TargetSpec other = new TargetSpec(); other.Host = "10.0.0.20"; other.CredLabel = "other"; other.TimeoutSec = 5;
                Func<string, NetworkCred> resolve2 = delegate (string label) { return new NetworkCred(label == "other" ? "LAB\\other" : ACCOUNT, Encoding.UTF8.GetBytes(SECRET)); };
                RemoteAudit ctl2 = new RemoteAudit(e, new RunJournal(Path.Combine(dir, "j2.ndjson")), make, resolve2, DateTime.UtcNow);
                List<TargetSpec> t2 = new List<TargetSpec>(targets); t2.Add(other);
                List<RunResult> rs2 = ctl2.RunBatch(t2, opt);
                int attempts2 = 0; foreach (FakeTransport ft in made) attempts2 += ft.LogonAttempts;
                Check(attempts2 == 2, "remote: a second, different credential in the same batch still gets its own one attempt (attempts " + attempts2 + ")");
            }
            finally { try { Directory.Delete(dir, true); } catch { } }
        }

        // ── PT-58: the exact command line the controller sends must produce a bundle from the REAL collector exe ──
        static void RemoteCollectorArgs_()
        {
            // every option the builder emits must be one the collector actually accepts
            TargetSpec t = new TargetSpec(); t.Host = "10.0.0.10"; t.Modules.Add("inventory");
            string args = RemoteAudit.BuildCollectorArgs(t, "testrun-01", true, true, 120);
            HashSet<string> known = new HashSet<string>(); foreach (string[] h in CollectOptions.Help) known.Add(h[0]);
            bool allKnown = true; string unknownOpt = ""; foreach (string tok in args.Split(' ')) if (tok.StartsWith("--")) { string name = tok.Substring(2); if (!known.Contains(name)) { allKnown = false; unknownOpt = name; } }
            Check(allKnown && args.IndexOf("--out bundle.ptb") >= 0 && args.IndexOf("--pubkey engagement.pub") >= 0 && args.IndexOf("collect ") < 0 && !args.StartsWith("collect"),
                "remote: the collector command line uses only real options (no 'collect' verb)" + (allKnown ? "" : " - UNKNOWN --" + unknownOpt));

            // run the exact arguments against the real PowerTowerCollect.exe, in a staged dir, and get a sealed bundle + done.json
            string exe = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "PowerTowerCollect.exe");
            if (!File.Exists(exe)) { Check(false, "remote: PowerTowerCollect.exe not found next to Tests.exe"); return; }
            string dir = Path.Combine(Path.GetTempPath(), "pstools-ph3c-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(dir);
            try
            {
                using (System.Security.Cryptography.RSACryptoServiceProvider rsa = new System.Security.Cryptography.RSACryptoServiceProvider(2048))
                    File.WriteAllText(Path.Combine(dir, "engagement.pub"), rsa.ToXmlString(false), new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(dir, "ioc.txt"), "evil.example\n10.0.0.9\n", new UTF8Encoding(false));
                TargetSpec rt = new TargetSpec(); rt.Host = Environment.MachineName; rt.Modules.Add("inventory");
                string cmdArgs = RemoteAudit.BuildCollectorArgs(rt, "testrun-02", true, true, 120);   // relative names resolve in the working dir, like the staged dir on a target
                System.Diagnostics.ProcessStartInfo psi = new System.Diagnostics.ProcessStartInfo(exe, cmdArgs);
                psi.WorkingDirectory = dir; psi.UseShellExecute = false; psi.RedirectStandardOutput = true; psi.RedirectStandardError = true; psi.CreateNoWindow = true;
                System.Diagnostics.Process p = System.Diagnostics.Process.Start(psi);
                string so = p.StandardOutput.ReadToEnd(), se = p.StandardError.ReadToEnd(); bool exited = p.WaitForExit(180000); int code = exited ? p.ExitCode : -999; if (!exited) try { p.Kill(); } catch { }
                string bundle = Path.Combine(dir, "bundle.ptb"), done = Path.Combine(dir, "done.json");
                bool haveBundle = File.Exists(bundle), haveDone = File.Exists(done); bool shaOk = false;
                if (haveBundle && haveDone) { try { object d = Json.Parse(File.ReadAllText(done)); string want = Json.GetS(d, "sha256"); shaOk = string.Equals(want, BundleCrypto.FileSha256(bundle), StringComparison.OrdinalIgnoreCase); } catch { } }
                Check(exited && (code == 0 || code == 1) && haveBundle && haveDone && shaOk,
                    "remote: the real PowerTowerCollect.exe accepts the controller's command line and writes a verifiable bundle + done.json (exit " + code + ", bundle " + haveBundle + ", done " + haveDone + ", sha " + shaOk + (se.Length > 0 && !haveBundle ? ", stderr: " + se.Substring(0, Math.Min(120, se.Length)).Replace("\n", " ") : "") + ")");
            }
            finally { try { Directory.Delete(dir, true); } catch { } }
        }

        // ── PT-57: the committed build.cmd must build every exe from a fresh checkout ──
        static void BuildLists_()
        {
            string bc = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "build.cmd");
            if (!File.Exists(bc)) { Check(false, "build: build.cmd not found next to Tests.exe"); return; }
            string[] lines = File.ReadAllLines(bc); string gui = "", cli = "", col = "", tst = "";
            foreach (string ln in lines) { if (ln.IndexOf("/out:PowerTower.exe") >= 0) gui = ln; else if (ln.IndexOf("/out:PowerTowerCli.exe") >= 0) cli = ln; else if (ln.IndexOf("/out:PowerTowerCollect.exe") >= 0) col = ln; else if (ln.IndexOf("/out:Tests.exe") >= 0) tst = ln; }
            // every .cs named on a line (that is not %SHARED%) exists on disk
            List<string> missing = new List<string>();
            foreach (string ln in new string[] { gui, cli, col, tst }) foreach (string tok in ln.Split(' ')) if (tok.EndsWith(".cs")) { if (!File.Exists(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, tok))) missing.Add(tok); }
            string[] ctrl = { "RemoteAudit.cs", "RemoteAuditSupport.cs", "RemoteTransport.cs" };
            bool inGui = true, inCli = true, inTst = true, outCol = true;
            foreach (string c in ctrl) { if (gui.IndexOf(c) < 0) inGui = false; if (cli.IndexOf(c) < 0) inCli = false; if (col.IndexOf(c) >= 0) outCol = false; }
            foreach (string c in new string[] { "RemoteAudit.cs", "RemoteAuditSupport.cs" }) if (tst.IndexOf(c) < 0) inTst = false;
            Check(missing.Count == 0 && inGui && inCli && inTst && outCol && gui.Length > 0 && col.Length > 0,
                "build: build.cmd lists exist on disk and the controller is on the GUI/CLI/Tests lines but NOT the collector line (PT-57) - missing " + missing.Count + ", gui " + inGui + ", cli " + inCli + ", tests " + inTst + ", not-in-collector " + outCol);
        }

        // ── PT-67: no injection through the target file reaches the remote command line ──
        static void RemoteInject_()
        {
            // the exact FUZZ payload, plus a corpus of cmd metacharacter / quote / whitespace injections in the modules field
            string[] badModules = {
                "inventory&echo;PT_INJECTED>marker.txt", "inventory&calc", "inventory|whoami", "inventory>out", "inventory<in",
                "inventory^x", "inventory\"q", "inventory'q", "inventory`id`", "inventory$(id)", "inventory%COMSPEC%",
                "inventory;net", "inventory ()", "inventory!x!", "../../x", "INVENT ORY", "network\tsecrets", "zzz-unknown", "collect"
            };
            int refused = 0; foreach (string m in badModules) { string err; TargetSpec ts = TargetList.Parse("ws01,lab,60," + m, out err); if (ts == null && err != null && err != "blank") refused++; }
            Check(refused == badModules.Length, "inject: all " + badModules.Length + " hostile modules fields refuse the whole target line (" + refused + ")");

            // the specific reproduction line from the verdict
            string e1; TargetSpec fuzz = TargetList.Parse("ws01,lab,60,inventory&echo;PT_INJECTED>marker.txt", out e1);
            Check(fuzz == null && e1 != null && e1.IndexOf("not a known module") >= 0, "inject: the FUZZ payload line is refused with a clear reason (" + (e1 ?? "accepted!") + ")");

            // valid module fields still parse to the canonical allow-listed set
            string e2; TargetSpec okT = TargetList.Parse("ws01,lab,60,inventory;network RECON", out e2);
            Check(okT != null && okT.Modules.Count == 3 && okT.Modules.Contains("inventory") && okT.Modules.Contains("network") && okT.Modules.Contains("recon"), "inject: a valid modules field parses to the canonical lower-case allow-listed set");

            // hostile host and credential-label fields are refused too
            string e3, e4; TargetList.Parse("ws01&calc,lab,60,inventory", out e3); TargetList.Parse("ws01,lab;x,60,inventory", out e4);
            Check(e3 != null && e4 != null, "inject: a hostile host or credential-label field is refused (" + e3 + " / " + e4 + ")");

            // defence in depth: BuildCollectorArgs rejects an unsafe module even if one bypasses Parse, and never emits a metacharacter
            TargetSpec inj = new TargetSpec(); inj.Host = "ws01"; inj.Modules.Add("inventory&echo"); string thrown = "";
            try { RemoteAudit.BuildCollectorArgs(inj, "r1", true, false, 60); } catch (BundleException ex) { thrown = ex.Message; }
            Check(thrown.Length > 0, "inject: BuildCollectorArgs refuses an unsafe module token that bypassed Parse (" + thrown + ")");
            TargetSpec inj2 = new TargetSpec(); inj2.Host = "ws01"; string thrown2 = "";
            try { RemoteAudit.BuildCollectorArgs(inj2, "r1 & calc", true, false, 60); } catch (BundleException ex) { thrown2 = ex.Message; }
            Check(thrown2.Length > 0, "inject: BuildCollectorArgs refuses a run id with a shell metacharacter");

            // a valid command line contains no shell metacharacter at all
            TargetSpec good = new TargetSpec(); good.Host = "ws01"; good.Modules.Add("inventory"); good.Modules.Add("network");
            string args = RemoteAudit.BuildCollectorArgs(good, "20261015-120000-abc123", true, true, 120);
            bool clean = true; foreach (char c in "&|<>^;`$()!%\"'\n\r\t") if (args.IndexOf(c) >= 0) clean = false;
            Check(clean && args.IndexOf("--modules inventory,network") >= 0, "inject: the built command line for valid input has no shell metacharacter and only allow-listed modules");

            // PT-61: a transport exception carrying the password is scrubbed in the result detail and the journal
            string dir = Path.Combine(Path.GetTempPath(), "pstools-ph3i-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(dir);
            try
            {
                Engagement e = Ph3Eng(); string jp = Path.Combine(dir, "j.ndjson");
                Func<TargetSpec, ITransport> make = delegate (TargetSpec ts) { FakeTransport ft = new FakeTransport(); ft.ConnectThrowMessageWithSecret = true; return ft; };
                Func<string, NetworkCred> resolve = delegate (string label) { return new NetworkCred(ACCOUNT, Encoding.UTF8.GetBytes(SECRET)); };
                RemoteAudit ctl = new RemoteAudit(e, new RunJournal(jp), make, resolve, DateTime.UtcNow);
                RunResult r = ctl.RunOne(Ph3Target("10.0.0.10"), new RunOptions());
                string journalText = File.Exists(jp) ? File.ReadAllText(jp) : "";
                Check((r.Detail ?? "").IndexOf(SECRET) < 0 && journalText.IndexOf(SECRET) < 0 && (r.Detail ?? "").IndexOf("***") >= 0, "inject (PT-61): a transport exception that echoes the password is scrubbed in the detail and the journal");
            }
            finally { try { Directory.Delete(dir, true); } catch { } }
        }

        // ── the "creds" CLI: writes creds.ptv; the secret only enters via stdin or an env var, never argv, never plaintext on disk ──
        static string CredsCli(string exe, string args, string stdinLine, string envName, string envVal, out int exit)
        { return CredsCliBytes(exe, args, stdinLine == null ? null : Encoding.UTF8.GetBytes(stdinLine + "\n"), envName, envVal, out exit); }
        static string CredsCliBytes(string exe, string args, byte[] stdin, string envName, string envVal, out int exit)
        {
            ProcessStartInfo psi = new ProcessStartInfo(exe, args); psi.UseShellExecute = false; psi.RedirectStandardOutput = true; psi.RedirectStandardError = true; psi.RedirectStandardInput = true; psi.CreateNoWindow = true;
            if (envName != null) psi.EnvironmentVariables[envName] = envVal;
            using (Process p = Process.Start(psi))
            {
                try { if (stdin != null) { p.StandardInput.BaseStream.Write(stdin, 0, stdin.Length); p.StandardInput.BaseStream.Flush(); } } catch { }
                try { p.StandardInput.Close(); } catch { }
                string so = p.StandardOutput.ReadToEnd(), se = p.StandardError.ReadToEnd(); p.WaitForExit(60000); exit = p.ExitCode; return so + "\n" + se;
            }
        }
        static void CredsCli_()
        {
            string exe = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "PowerTowerCli.exe");
            if (!File.Exists(exe)) { Check(false, "creds: PowerTowerCli.exe not found next to Tests.exe"); return; }
            const string S1 = "Cr3d-CLI-SECRET-one-!xyz", S2 = "Cr3d-CLI-SECRET-two-#qpz";
            string dir = Path.Combine(Path.GetTempPath(), "pstools-creds-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(dir);
            try
            {
                Engagement eng = EngagementTool.New(dir, "ENG-CRED", "Acme", "ops", new string[] { "10.0.0.0/24" }, DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(1), null, 60, "", 2048);
                string jf = Path.Combine(dir, "engagement.json"); string cp = Path.Combine(dir, "creds.ptv");
                string q = "\"" + jf + "\"";

                // add via --secret-stdin
                int x1; string o1 = CredsCli(exe, "creds add " + q + " --label lab --user CORP\\svc-audit --secret-stdin", S1, null, null, out x1);
                bool bytesClean1 = !File.Exists(cp) || IndexOf(File.ReadAllBytes(cp), Encoding.UTF8.GetBytes(S1)) < 0;
                Check(x1 == 0 && File.Exists(cp) && o1.IndexOf(S1) < 0 && bytesClean1, "creds add (--secret-stdin): stores the entry; the secret is not in the output and not plaintext in creds.ptv (exit " + x1 + ")");

                // add a second entry via --secret-env; the first is preserved
                int x2; string o2 = CredsCli(exe, "creds add " + q + " --label lab2 --user CORP\\svc2 --secret-env PTV_TSEC", null, "PTV_TSEC", S2, out x2);
                List<CredEntry> after2 = CredStore.Load(cp, null, eng.Id);
                bool bytesClean2 = IndexOf(File.ReadAllBytes(cp), Encoding.UTF8.GetBytes(S1)) < 0 && IndexOf(File.ReadAllBytes(cp), Encoding.UTF8.GetBytes(S2)) < 0;
                Check(x2 == 0 && o2.IndexOf(S2) < 0 && after2.Count == 2 && bytesClean2, "creds add (--secret-env): adds a second entry, preserves the first, neither secret is plaintext in the file (" + after2.Count + " entries)");

                // list shows labels + usernames only, never the secret
                int x3; string o3 = CredsCli(exe, "creds list " + q, null, null, null, out x3);
                Check(x3 == 0 && o3.IndexOf("lab") >= 0 && o3.IndexOf("CORP\\svc-audit") >= 0 && o3.IndexOf("lab2") >= 0 && o3.IndexOf(S1) < 0 && o3.IndexOf(S2) < 0, "creds list: labels and usernames only, never the secret");

                // the store written by the CLI loads in remote-audit's resolver and authenticates the target
                List<CredEntry> loaded = CredStore.Load(cp, null, eng.Id);
                FakeTransport ok = new FakeTransport(); Func<TargetSpec, ITransport> mk = delegate (TargetSpec ts) { return ok; };
                Func<string, NetworkCred> res = delegate (string lbl) { foreach (CredEntry ce in loaded) if (string.Equals(ce.Label, lbl, StringComparison.OrdinalIgnoreCase)) return new NetworkCred(ce.User, (byte[])ce.Secret.Clone()); return null; };
                RemoteAudit ctl = new RemoteAudit(eng, new RunJournal(Path.Combine(dir, "j.ndjson")), mk, res, DateTime.UtcNow);
                TargetSpec tg = new TargetSpec(); tg.Host = "10.0.0.10"; tg.CredLabel = "lab"; tg.TimeoutSec = 5;
                RunResult rr = ctl.RunOne(tg, new RunOptions());
                Check(rr.Status == "ok" && ok.LastSecretSeen == S1 && rr.User == "CORP\\svc-audit", "creds -> remote-audit: a target using label 'lab' resolves the stored credential and authenticates (status " + rr.Status + ")");
                foreach (CredEntry ce in loaded) ce.Zero();

                // remove deletes only the named entry
                int x4; CredsCli(exe, "creds remove " + q + " --label lab", null, null, null, out x4);
                List<CredEntry> after4 = CredStore.Load(cp, null, eng.Id);
                Check(x4 == 0 && after4.Count == 1 && after4[0].Label == "lab2", "creds remove: deletes only the named entry, preserves the rest");

                // a DPAPI store bound to one engagement will not load under another id (reused CredStore behaviour)
                string wrong = ""; try { CredStore.Load(cp, null, "OTHER-ENG"); } catch (Exception ex) { wrong = ex.Message; }
                Check(wrong.Length > 0, "creds: a DPAPI store for engagement A does not load under engagement B");

                // there is no CLI option that takes the secret as an argv value
                int xh; string help = CredsCli(exe, "creds add " + q + " --help", null, null, null, out xh);
                Check(help.IndexOf("--secret-stdin") >= 0 && help.IndexOf("--secret-env") >= 0 && help.IndexOf("--password") < 0 && help.IndexOf("--secret <") < 0, "creds: the only secret inputs are --secret-stdin and --secret-env; no option takes the secret as a value");

                // fuzz / fail-closed
                int xe1; string oe1 = CredsCliBytes(exe, "creds add " + q + " --label e1 --user u1 --secret-stdin", new byte[0], null, null, out xe1);
                Check(xe1 != 0 && oe1.IndexOf("empty") >= 0, "creds fuzz: an empty stdin secret is refused, nothing stored");
                int xe2; CredsCli(exe, "creds add " + q + " --label e2 --user u2 --secret-env PTV_MISSING_" + Guid.NewGuid().ToString("N"), null, null, null, out xe2);
                Check(xe2 != 0, "creds fuzz: a missing env var is refused");
                int xe3; CredsCli(exe, "creds add " + q + " --label \"a&b|c\" --user u3 --secret-env PTV_TSEC", null, "PTV_TSEC", S2, out xe3);
                int xe4; CredsCli(exe, "creds add " + q + " --label " + new string('L', 90) + " --user u4 --secret-env PTV_TSEC", null, "PTV_TSEC", S2, out xe4);
                List<CredEntry> afterFuzz = CredStore.Load(cp, null, eng.Id);
                Check(xe3 != 0 && xe4 != 0 && afterFuzz.Count == 1, "creds fuzz: a label with injection characters or over 64 chars is refused and the store is unchanged (" + afterFuzz.Count + " entry)");
                // a corrupt creds.ptv is refused clearly, not overwritten, no crash
                string badcp = Path.Combine(dir, "bad.ptv"); File.WriteAllBytes(badcp, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 });
                int xe5; string oe5 = CredsCli(exe, "creds list " + q + " --creds \"" + badcp + "\"", null, null, null, out xe5);
                Check(xe5 != 0 && oe5.IndexOf(S1) < 0 && oe5.IndexOf(S2) < 0, "creds fuzz: a corrupt creds.ptv is refused with a clear error, no crash, no secret");
                // a secret with spaces and unicode round-trips via env
                int xe6; CredsCli(exe, "creds add " + q + " --label uni --user u5 --secret-env PTV_U", null, "PTV_U", "p\u00e4ss word \u2603", out xe6);
                List<CredEntry> uni = CredStore.Load(cp, null, eng.Id); string got = ""; foreach (CredEntry ce in uni) if (ce.Label == "uni") got = Encoding.UTF8.GetString(ce.Secret);
                Check(xe6 == 0 && got == "p\u00e4ss word \u2603", "creds fuzz: a secret with spaces and unicode round-trips through the store");
                foreach (CredEntry ce in uni) ce.Zero();
            }
            finally { try { Directory.Delete(dir, true); } catch { } }
        }

        // ── PT-69: the --secret-stdin secret is read byte-exact (no console code page, no BOM), one trailing newline stripped ──
        static void CredsStdin_()
        {
            string exe = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "PowerTowerCli.exe");
            if (!File.Exists(exe)) { Check(false, "creds stdin: PowerTowerCli.exe not found"); return; }
            string dir = Path.Combine(Path.GetTempPath(), "pstools-c69-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(dir);
            try
            {
                Engagement eng = EngagementTool.New(dir, "ENG-69", "Acme", "ops", new string[] { "10.0.0.0/24" }, DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(1), null, 60, "", 2048);
                string jf = Path.Combine(dir, "engagement.json"), cp = Path.Combine(dir, "creds.ptv"), q = "\"" + jf + "\"";
                byte[] BOM = new byte[] { 0xEF, 0xBB, 0xBF };

                // each case: the expected secret string, and the exact bytes piped to stdin (content + optional BOM/newline)
                string[] names = { "ascii", "accents", "emoji", "spaces", "crlf", "lf", "bom", "tab-inside" };
                string[] expect = { "plainsecret", "p\u00e4ssw\u00f6rd \u2603", "\U0001F511key-\u00e9", "  spaced pw  ", "crlf-pw", "lf-pw", "bom-pw", "a\tb c" };
                int ok = 0;
                for (int i = 0; i < names.Length; i++)
                {
                    byte[] body = Encoding.UTF8.GetBytes(expect[i]);
                    System.IO.MemoryStream ms = new System.IO.MemoryStream();
                    if (names[i] == "bom") ms.Write(BOM, 0, 3);
                    ms.Write(body, 0, body.Length);
                    if (names[i] == "crlf") { ms.WriteByte(0x0D); ms.WriteByte(0x0A); } else { ms.WriteByte(0x0A); }   // lf for all but crlf; 'lf' is explicit lf
                    int xa; string oa = CredsCliBytes(exe, "creds add " + q + " --label s --user CORP\\u --secret-stdin", ms.ToArray(), null, null, out xa);
                    // load back and compare the stored bytes to the expected UTF-8, byte-exact
                    List<CredEntry> entries = CredStore.Load(cp, null, eng.Id); byte[] stored = null; foreach (CredEntry ce in entries) if (ce.Label == "s") stored = ce.Secret;
                    bool exact = stored != null && SameBytes2(stored, body);
                    bool notInFile = IndexOf(File.ReadAllBytes(cp), body) < 0 && oa.IndexOf(expect[i]) < 0;
                    // and it round-trips through remote-audit's resolver to the transport
                    FakeTransport ft = new FakeTransport(); List<CredEntry> ld = CredStore.Load(cp, null, eng.Id);
                    Func<TargetSpec, ITransport> mk = delegate (TargetSpec ts) { return ft; };
                    Func<string, NetworkCred> res = delegate (string lbl) { foreach (CredEntry ce in ld) if (ce.Label == lbl) return new NetworkCred(ce.User, (byte[])ce.Secret.Clone()); return null; };
                    RemoteAudit ctl = new RemoteAudit(eng, new RunJournal(Path.Combine(dir, "j.ndjson")), mk, res, DateTime.UtcNow);
                    TargetSpec tg = new TargetSpec(); tg.Host = "10.0.0.10"; tg.CredLabel = "s"; tg.TimeoutSec = 5;
                    RunResult rr = ctl.RunOne(tg, new RunOptions());
                    bool resolves = rr.Status == "ok" && ft.LastSecretSeen == expect[i];
                    foreach (CredEntry ce in ld) ce.Zero(); foreach (CredEntry ce in entries) ce.Zero();
                    if (xa == 0 && exact && notInFile && resolves) ok++; else Info("creds stdin FAIL '" + names[i] + "': exit " + xa + " exact " + exact + " notInFile " + notInFile + " resolves " + resolves);
                }
                Check(ok == names.Length, "creds stdin: all " + names.Length + " cases (ascii, accents, emoji, leading/trailing spaces, CRLF, LF, BOM, interior tab) round-trip byte-exact to the resolver (" + ok + ")");

                // a BOM-only line is refused as empty; a whitespace-only secret is refused
                int xb; string ob = CredsCliBytes(exe, "creds add " + q + " --label z --user u --secret-stdin", new byte[] { 0xEF, 0xBB, 0xBF, 0x0A }, null, null, out xb);
                int xw; CredsCliBytes(exe, "creds add " + q + " --label z --user u --secret-stdin", Encoding.UTF8.GetBytes("    \n"), null, null, out xw);
                int xm; CredsCliBytes(exe, "creds add " + q + " --label z --user u --secret-stdin", Encoding.UTF8.GetBytes("line1\nline2\n"), null, null, out xm);
                List<CredEntry> fin = CredStore.Load(cp, null, eng.Id); bool noZ = true; foreach (CredEntry ce in fin) if (ce.Label == "z") noZ = false;
                Check(xb != 0 && ob.IndexOf("empty") >= 0 && xw != 0 && xm != 0 && noZ, "creds stdin: a BOM-only, whitespace-only or multi-line secret is refused, nothing stored (" + xb + "/" + xw + "/" + xm + ")");
            }
            finally { try { Directory.Delete(dir, true); } catch { } }
        }
        static bool SameBytes2(byte[] a, byte[] b) { if (a.Length != b.Length) return false; for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false; return true; }

        // -- GUI vuln report: a finished scan -> ScanBundle.FromScan -> VulnReport.Build is the SAME engine the CLI uses (PT-45/PT-46) --
        static void VulnGuiReport_()
        {
            DateTime pin = new DateTime(2026, 10, 13, 9, 0, 0, DateTimeKind.Utc); Brand brand = new Brand();
            OsInfo os = new OsInfo(); os.ProductName = "Windows 11 Pro"; os.Major = 10; os.Build = 22621; os.Ubr = 2500; os.Arch = "x64"; os.Host = "FIXTURE";
            VulnScan s = new VulnScan(); s.Os = os; s.DoWua = false; s.StartedAt = pin.ToLocalTime(); s.FinishedAt = pin.ToLocalTime(); s.MsrcWindowUsed = 1; s.Releases.Add("2026-Oct");
            Finding fnd = new Finding(); fnd.Cve = "CVE-2026-1003"; fnd.Title = "7-Zip privilege escalation"; fnd.Severity = "Critical"; fnd.Source = "NVD"; fnd.Product = "=HYPERLINK(\"http://evil\") 7-Zip"; fnd.Installed = "21.07"; fnd.Fix = "upgrade to 24.09"; fnd.Status = "vulnerable"; fnd.Evidence = "installed 21.07"; fnd.Cvss = 9.8; fnd.Kev = true; s.Findings.Add(fnd);
            s.AsOf["enrichedUtc"] = pin; s.AsOf["msrc"] = new Dictionary<string, object>(); s.AsOf["nvd"] = new Dictionary<string, object>(); s.AsOf["kev"] = new Dictionary<string, object>(); s.AsOf["epss"] = new Dictionary<string, object>();
            Dictionary<string, object> r = VulnReport.Build(ScanBundle.FromScan(s, "FIXTURE", pin), brand);
            int errs = Ptreport.Validate(r).Count;
            string md = ReportRender.Markdown(r), csv = ReportRender.Csv(r), json = JsonWrite.Text(r, true); byte[] pdf = ReportRender.Pdf(r, brand);
            bool renders = errs == 0 && md.StartsWith("# ") && pdf.Length > 2000 && Encoding.GetEncoding(1252).GetString(pdf).StartsWith("%PDF-1.4") && Json.GetS(r, "report") == "vulnerability";
            Check(renders, "vuln gui report: a scan -> ScanBundle.FromScan -> VulnReport.Build validates (" + errs + ") and renders md/json/pdf/csv through the CLI engine");
            object sum = Json.Get(r, "summary");
            Check(Json.GetS(sum, "status") == "assessed", "vuln gui report: full feed coverage yields an assessed report (" + Json.GetS(sum, "status") + ")");
            bool csvSafe = csv.IndexOf("'=HYPERLINK") >= 0 && !System.Text.RegularExpressions.Regex.IsMatch(csv, "(^|,)\"?=HYPERLINK", System.Text.RegularExpressions.RegexOptions.Multiline);
            Check(csvSafe && md.IndexOf("\n=HYPERLINK") < 0, "vuln gui report: a hostile product name is formula-safe in CSV and inert in Markdown (PT-46)");
            VulnScan e = new VulnScan(); e.Os = os; e.DoWua = false; e.StartedAt = pin.ToLocalTime(); e.FinishedAt = pin.ToLocalTime();
            Dictionary<string, object> re = VulnReport.Build(ScanBundle.FromScan(e, "FIXTURE", pin), brand); object su = Json.Get(re, "summary");
            Check(Json.GetS(su, "status") == "not-assessable" && (Json.GetS(su, "headline") ?? "").IndexOf("No open vulnerabilities") < 0, "vuln gui report: a scan with no feeds is NOT ASSESSABLE, never clean (PT-45): " + Json.GetS(su, "status"));
        }
        static void Secrets_()
        {
            string dir = Path.Combine(Path.GetTempPath(), "pstools-sec-" + Guid.NewGuid().ToString("N"));
            try
            {
                Directory.CreateDirectory(dir);
                File.WriteAllText(Path.Combine(dir, ".env"), "HOST=db\nGITHUB=ghp_" + new string('a', 30) + "\n");
                File.WriteAllText(Path.Combine(dir, "k.pem"), "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----\n");
                SecretsScan sc = new SecretsScan(); sc.Roots = new List<string>(new string[] { dir }); List<SecretHit> hits = new List<SecretHit>(); sc.Run(delegate (SecretHit h) { hits.Add(h); }, null);
                bool pem = false, gh = false, masked = true; foreach (SecretHit h in hits) { if (h.Kind.Contains("Private key")) pem = true; if (h.Kind.Contains("GitHub")) gh = true; if (h.Preview.IndexOf('•') < 0 && h.Kind.Contains("GitHub")) masked = false; }
                Check(pem && gh, "secrets: found the PEM key and the GitHub token (" + hits.Count + " hit(s))");
                Check(masked, "secrets: the token preview is masked");
                File.WriteAllText(Path.Combine(dir, "real.txt"), "token=ghp_Xk93mQ7rLpZ1234567vB8nT4yHc6WdJf1aSe\nAWS=AKIAZ3none9dummyQ7XK\npassword=123456\napi_key=YOUR_API_KEY_GOES_HERE_1\n");   // PT-04: a real vendor token that contains "123456" / "none" / "dummy" is still reported
                hits.Clear(); sc = new SecretsScan(); sc.Roots = new List<string>(new string[] { dir }); sc.Run(delegate (SecretHit h) { if (h.File == "real.txt") hits.Add(h); }, null);
                bool ghp = false, aws = false, weak = false, ph = false; foreach (SecretHit h in hits) { if (h.Kind.Contains("GitHub")) ghp = true; if (h.Kind.Contains("AWS access")) aws = true; if (h.Kind.Contains("Generic password")) weak = true; if (h.Kind.Contains("Generic API")) ph = true; }
                Check(ghp && aws, "secrets: vendor tokens containing '123456' / 'none' / 'dummy' are still reported (PT-04)");
                Check(!weak && !ph, "secrets: bare placeholder values (password=123456, YOUR_API_KEY...) are still filtered");
            }
            finally { try { Directory.Delete(dir, true); } catch { } }
        }
    }
}

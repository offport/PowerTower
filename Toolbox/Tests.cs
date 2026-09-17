// Engine tests, no UI. Run Tests.exe; exit code = number of failures. Everything that touches the real
// machine is read-only (hosts-file edits happen on a temp copy).
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
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
            foreach (Action t in new Action[] { Extractor_, Hosts_, Firewall_, Reach_, Conns_, Procs_, Storage_, Journal_, BinRecord_, ExFat_, Csv_, Json_, Ver_, ProductMap_, Cpe_, MsrcParse_, Resolve_, Inventory_, Feeds_, Recon_, Pdf_, Wildcard_, Hashes_, Crypto_, Walk_, Checklist_, DeletedFilter_, Active_, Trust_, Autoruns_, Events_, Dupes_, Secrets_ }) { try { t(); } catch (Exception ex) { Check(false, t.Method.Name + " threw " + ex.GetType().Name + ": " + ex.Message); } }
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
                sw.Restart(); string body = Msrc.Fetch(rel[0], cache, out note); sw.Stop(); Stopwatch p = Stopwatch.StartNew(); List<MsrcRec> mr = Msrc.Parse(body, rel[0]); p.Stop(); int withBuild = 0; foreach (MsrcRec r in mr) if (r.FixedBuild != null) withBuild++;
                Check(mr.Count > 500 && withBuild > mr.Count / 2, "feeds: MSRC " + rel[0] + " " + (body.Length / 1024 / 1024) + " MB fetched in " + sw.ElapsedMilliseconds + " ms (" + note + "), parsed " + mr.Count + " records in " + p.ElapsedMilliseconds + " ms, " + withBuild + " with FixedBuild");
                OsInfo os = Inventory.Os(); List<Finding> ff = Resolve.Msrc(mr, os, new HashSet<string>(), new List<Software>(), new RebootInfo()); int vul = 0; foreach (Finding x in ff) if (x.Open) vul++;
                Check(ff.Count > 0, "feeds: " + ff.Count + " CVEs apply to build " + os.FullBuild + " in " + rel[0] + ", " + vul + " open with no KB knowledge");
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
            }
            finally { try { Directory.Delete(dir, true); } catch { } }
        }
    }
}

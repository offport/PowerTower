// Every table the tools show, defined once: the columns (key, title, width, accessor, format, tone), the
// tree grouping, the row tone and the export name. The GUI panels and the command line both render from
// these, so a column added here appears in the grid, the details pane, the tree, the CSV and the console
// at the same time, with the same header. No UI code here; tones instead of colours.
using System;
using System.Collections.Generic;
using System.IO;

namespace PSTools
{
    public static class Columns
    {
        // typed accessors keep the column lambdas short
        static BlockItem B(object o) { return (BlockItem)o; }
        static ReachRow R(object o) { return (ReachRow)o; }
        static Conn C(object o) { return (Conn)o; }
        static ProcRow P(object o) { return (ProcRow)o; }
        static Node N(object o) { return (Node)o; }
        static ExtStat X(object o) { return (ExtStat)o; }
        static DeletedRow D(object o) { return (DeletedRow)o; }
        static ReconItem RI(object o) { return (ReconItem)o; }
        static CheckItem CI(object o) { return (CheckItem)o; }
        static FileEntry F(object o) { return (FileEntry)o; }
        static HashHit HH(object o) { return (HashHit)o; }
        static Finding FD(object o) { return (Finding)o; }
        static MissingUpdate MU(object o) { return (MissingUpdate)o; }
        static Software SW(object o) { return (Software)o; }
        static Hotfix HF(object o) { return (Hotfix)o; }
        static AutorunEntry AE(object o) { return (AutorunEntry)o; }
        static EventRow EV(object o) { return (EventRow)o; }
        static SecretHit SH(object o) { return (SecretHit)o; }
        static DupeFile DF(object o) { return (DupeFile)o; }
        static FwRule FW(object o) { return (FwRule)o; }
        static WifiProfile WP(object o) { return (WifiProfile)o; }
        static VaultCred VC(object o) { return (VaultCred)o; }
        static VisitRow VR(object o) { return (VisitRow)o; }
        static DomainStat DS(object o) { return (DomainStat)o; }
        static LoginRow LR(object o) { return (LoginRow)o; }
        static ModuleInfo MI(object o) { return (ModuleInfo)o; }

        // ═══════════════ Domain and IP Blocker ═══════════════
        /// <summary>The loaded list. The value column is editable; the panel passes what to do after an edit (re-classify against what is blocked now).</summary>
        public static TableDef BlockerLoaded(Action<BlockItem> reclassify)
        {
            TableDef t = new TableDef("block-list");
            t.Add(new Col("value", "Domain / IP", 260, o => B(o).Value).Edit(delegate (object o, string v) { BlockItem b = B(o); b.Value = v.Trim().ToLowerInvariant(); b.Kind = Extractor.Classify(b.Value); b.Note = b.Kind == Kind.Invalid ? "not a domain or IP" : ""; if (reclassify != null) reclassify(b); }));
            t.Add(new Col("kind", "Kind", 80, o => B(o).KindText));
            t.Add(new Col("status", "Status", 150, o => B(o).Status).Tint(o => Tones.Status(B(o).Status)));
            t.Add(new Col("where", "Blocked by", 150, delegate (object o) { BlockItem b = B(o); List<string> w = new List<string>(); if (b.BlockedHosts) w.Add("hosts file"); if (b.BlockedFw) w.Add("firewall"); return string.Join(" + ", w.ToArray()); }));
            t.Add(new Col("note", "Note", 160, o => B(o).Note).Tint(Tone.Dim));
            t.Add(new Col("line", "Line", 50, o => B(o).Line == 0 ? (object)"" : B(o).Line).Num(o => B(o).Line == 0 ? "" : B(o).Line.ToString()));
            t.Add(new Col("source", "Source line", 400, o => B(o).Source).Tint(Tone.Dim));
            t.Group(o => new string[] { B(o).KindText, B(o).Group, B(o).Value });
            return t;
        }
        /// <summary>What is blocked right now: the tagged hosts-file lines and the firewall rule's addresses.</summary>
        public static TableDef BlockerBlocked()
        {
            TableDef t = new TableDef("blocked-now");
            t.Add(new Col("value", "Domain / IP", 260, o => B(o).Value));
            t.Add(new Col("kind", "Kind", 80, o => B(o).KindText));
            t.Add(new Col("where", "Blocked by", 150, o => B(o).Where).Tint(Tone.Good));
            t.Add(new Col("note", "Detail", 400, o => B(o).Note).Tint(Tone.Dim));
            t.Group(o => new string[] { B(o).KindText, B(o).Group, B(o).Value });
            return t;
        }

        // ═══════════════ Reachability Verifier ═══════════════
        /// <summary>One column per checked TCP port, so the table follows the ports you typed.</summary>
        public static TableDef Reach(int[] ports)
        {
            TableDef t = new TableDef("reachability");
            t.Add(new Col("target", "Target", 240, o => R(o).Value));
            t.Add(new Col("kind", "Kind", 70, o => R(o).Target.Kind.ToString()));
            t.Add(new Col("status", "Status", 110, o => R(o).Status).Tint(o => Tones.Status(R(o).Status)));
            t.Add(new Col("dns", "DNS", 70, o => R(o).DnsMs).Num(delegate (object o) { ReachRow r = R(o); return r.DnsMs < 0 ? (r.DnsError != null ? "fail" : "") : r.DnsMs + " ms"; }));
            t.Add(new Col("ip", "Resolves to", 170, o => string.Join(", ", R(o).Resolved.ToArray())));
            t.Add(new Col("ping", "Ping", 70, o => R(o).PingMs).Num(delegate (object o) { int p = R(o).PingMs; return p == -2 ? "" : p < 0 ? "no reply" : p + " ms"; }).Tint(delegate (object o) { int p = R(o).PingMs; return p >= 0 ? Tone.Good : p == -1 ? Tone.Bad : Tone.Dim; }));
            foreach (int port in ports ?? new int[0])
            {
                int pp = port;
                t.Add(new Col("p" + pp, "TCP " + pp, 80, delegate (object o) { PortResult pr; return R(o).Ports.TryGetValue(pp, out pr) ? (pr.Ok ? 1 : 0) : (object)-1; })
                    .Num(delegate (object o) { PortResult pr; if (!R(o).Ports.TryGetValue(pp, out pr)) return ""; return pr.Ok ? "open " + pr.Ms + " ms" : (pr.Error == "timeout" ? "timeout" : "closed"); })
                    .Tint(delegate (object o) { PortResult pr; if (!R(o).Ports.TryGetValue(pp, out pr)) return Tone.Dim; return pr.Ok ? Tone.Good : Tone.Bad; }));
            }
            t.Add(new Col("source", "Source line", 360, o => R(o).Target.Source).Tint(Tone.Dim));
            t.Group(o => new string[] { R(o).Status, R(o).Target.Kind.ToString(), R(o).Value });
            return t;
        }

        // ═══════════════ Connections Monitor ═══════════════
        public static TableDef Connections()
        {
            TableDef t = new TableDef("connections");
            t.Add(new Col("proto", "Proto", 60, o => C(o).Proto));
            t.Add(new Col("proc", "Process", 150, o => C(o).Process));
            t.Add(new Col("pid", "PID", 60, o => C(o).Pid).Num(o => C(o).Pid.ToString()));
            t.Add(new Col("local", "Local", 150, o => C(o).Local));
            t.Add(new Col("lport", "L.port", 60, o => C(o).LocalPort).Num(o => C(o).LocalPort.ToString()));
            t.Add(new Col("remote", "Remote", 150, o => C(o).Remote));
            t.Add(new Col("rport", "R.port", 60, o => C(o).RemotePort).Num(o => C(o).RemotePort == 0 ? "" : C(o).RemotePort.ToString()));
            t.Add(new Col("host", "Remote host", 220, o => C(o).Host).Tint(Tone.Dim));
            t.Add(new Col("state", "State", 100, o => C(o).State).Tint(o => Tones.Status(C(o).State)));
            t.Add(new Col("first", "First seen", 80, o => C(o).FirstSeen).Num(o => C(o).FirstSeen.ToString("HH:mm:ss")));
            t.Add(new Col("last", "Last seen", 80, o => C(o).LastSeen).Num(o => C(o).LastSeen.ToString("HH:mm:ss")));
            t.Add(new Col("alive", "", 60, o => C(o).Alive ? "open" : "closed").Tint(o => C(o).Alive ? Tone.Dim : Tone.Faint));
            t.Dim(o => !C(o).Alive);
            t.Group(delegate (object o) { Conn c = C(o); return new string[] { c.Process + " [" + c.Pid + "]", c.Remote.Length > 0 ? c.Remote + (c.Host.Length > 0 && c.Host != "…" ? "  " + c.Host : "") : "(" + c.State.ToLowerInvariant() + ")", c.Proto + " " + c.Local + ":" + c.LocalPort + (c.Remote.Length > 0 ? " → " + c.Remote + ":" + c.RemotePort : "") }; });
            return t;
        }

        // ═══════════════ Resource Usage ═══════════════
        public static TableDef Processes()
        {
            TableDef t = new TableDef("process-hogs");
            t.Add(new Col("name", "Process", 200, delegate (object o) { ProcRow p = P(o); return p.Pid == 0 ? p.Name + "  ×" + p.Count : p.Name; }));
            t.Add(new Col("pid", "PID", 60, o => P(o).Pid).Num(o => P(o).Pid == 0 ? "" : P(o).Pid.ToString()));
            t.Add(new Col("cpu", "CPU %", 70, o => P(o).CpuPct).Num(o => P(o).CpuPct.ToString("N1")).Tint(delegate (object o) { double v = P(o).CpuPct; return v >= 50 ? Tone.Bad : v >= 15 ? Tone.Warn : Tone.Normal; }));
            t.Add(new Col("cput", "CPU time", 80, o => P(o).CpuCum).Num(o => Fmt.Secs(P(o).CpuCum)));
            t.Add(new Col("share", "Share", 70, o => P(o).Share).Num(o => P(o).Share.ToString("P0")).Tint(Tone.Accent));
            t.Add(new Col("trend", "Trend", 130, o => Fmt.Spark(P(o).CpuHist, 20)).Tint(Tone.Accent));
            t.Add(new Col("mem", "Memory", 90, o => P(o).MemCur).Num(o => Fmt.Bytes(P(o).MemCur)));
            t.Add(new Col("peak", "Peak", 90, o => P(o).MemPeak).Num(o => Fmt.Bytes(P(o).MemPeak)).Tint(Tone.Dim));
            t.Add(new Col("ior", "Disk read", 90, o => P(o).IoCumR).Num(o => Fmt.Bytes(P(o).IoCumR)));
            t.Add(new Col("iow", "Disk write", 90, o => P(o).IoCumW).Num(o => Fmt.Bytes(P(o).IoCumW)));
            t.Add(new Col("ion", "I/O now", 90, o => P(o).IoRate).Num(o => Fmt.Bytes(P(o).IoRate) + "/s").Tint(Tone.Info));
            t.Add(new Col("state", "", 60, o => P(o).Alive ? "" : "exited").Tint(Tone.Bad));
            t.Dim(o => !P(o).Alive);
            t.Group(delegate (object o) { ProcRow p = P(o); return p.Pid == 0 ? new string[] { p.Name } : new string[] { p.Name, p.Name + " [" + p.Pid + "]" }; });
            return t;
        }
        /// <summary>The DLLs loaded in one process (Resource Usage → Loaded modules).</summary>
        public static TableDef Modules(string processName)
        {
            TableDef t = new TableDef("modules-" + processName);
            t.Add(new Col("name", "Module", 240, o => MI(o).Name));
            t.Add(new Col("sig", "Signature", 200, o => MI(o).Sig.Status.Length == 0 ? "" : MI(o).Sig.Short).Tint(o => Tones.Sig(MI(o).Sig)));
            t.Add(new Col("where", "Location", 110, o => MI(o).Location).Tint(o => MI(o).Location == "user-writable" || MI(o).Location == "other" ? Tone.Warn : Tone.Dim));
            t.Add(new Col("company", "Company", 200, o => MI(o).Company).Tint(Tone.Dim));
            t.Add(new Col("path", "Path", 420, o => MI(o).Path).Tint(Tone.Faint));
            t.Rows(delegate (object o) { ModuleInfo m = MI(o); return m.Sig.Status == "invalid" ? Tone.Bad : m.Sig.Status == "unsigned" && (m.Location == "user-writable" || m.Location == "other") ? Tone.Warn : Tone.Normal; });
            t.Group(o => new string[] { MI(o).Location, MI(o).Name });
            return t;
        }

        // ═══════════════ Disk Usage ═══════════════
        /// <summary>Largest files or biggest folders under the scanned root; the tree follows the folder structure with sizes.</summary>
        public static TableDef DiskNodes(bool dirs, Func<string> rootPath)
        {
            TableDef t = new TableDef(dirs ? "storage-folders" : "storage-largest-files");
            t.Add(new Col("name", dirs ? "Folder" : "File", 260, o => N(o).Name));
            t.Add(new Col("size", "Size", 110, o => N(o).Size).Num(o => Fmt.Bytes(N(o).Size)));
            t.Add(new Col("share", "Of parent", 90, o => N(o).ShareOfParent).Num(o => N(o).ShareOfParent.ToString("P0")).Tint(Tone.Accent));
            if (dirs)
            {
                t.Add(new Col("files", "Files", 80, o => N(o).Files).Num(o => N(o).Files.ToString("N0")));
                t.Add(new Col("subs", "Folders", 80, o => N(o).Dirs).Num(o => N(o).Dirs.ToString("N0")));
                t.Add(new Col("depth", "Depth", 60, o => N(o).Depth).Num(o => N(o).Depth.ToString()));
            }
            else t.Add(new Col("ext", "Type", 70, o => N(o).Ext));
            t.Add(new Col("mod", "Modified", 120, o => N(o).Modified));
            t.Add(new Col("path", "Path", 500, o => N(o).Path).Tint(Tone.Dim));
            t.Group(delegate (object o) { Node n = N(o); string root = rootPath(); string rel = root != null && n.Path.StartsWith(root, StringComparison.OrdinalIgnoreCase) ? n.Path.Substring(root.Length) : n.Path; List<string> segs = new List<string>(); segs.Add(root ?? ""); foreach (string s in rel.Split('\\')) if (s.Length > 0) segs.Add(s); return segs.ToArray(); });
            t.TreeText = delegate (string name, List<object> items) { long size = 0; Node exact = null; foreach (object o in items) { Node n = N(o); if (dirs) { if (n.Name == name || n.Path == name) { if (exact == null || n.Depth < exact.Depth) exact = n; } } else size += n.Size; } if (dirs && exact != null) return name + "   " + Fmt.Bytes(exact.Size) + "  ·  " + exact.Files.ToString("N0") + " files"; return name + (items.Count > 1 || !dirs ? "   " + Fmt.Bytes(size) + "  (" + items.Count.ToString("N0") + ")" : ""); };
            return t;
        }
        /// <summary>Space by file type; the share needs the scan total.</summary>
        public static TableDef DiskTypes(Func<long> totalBytes)
        {
            TableDef t = new TableDef("storage-file-types");
            t.Add(new Col("ext", "Type", 120, o => "." + X(o).Ext));
            t.Add(new Col("bytes", "Total size", 120, o => X(o).Bytes).Num(o => Fmt.Bytes(X(o).Bytes)));
            t.Add(new Col("share", "Share", 80, o => X(o).Bytes).Num(delegate (object o) { long tot = totalBytes(); return tot > 0 ? ((double)X(o).Bytes / tot).ToString("P1") : ""; }).Tint(Tone.Accent));
            t.Add(new Col("count", "Files", 100, o => X(o).Count).Num(o => X(o).Count.ToString("N0")));
            t.Add(new Col("avg", "Average", 100, delegate (object o) { ExtStat e = X(o); return e.Count > 0 ? e.Bytes / e.Count : 0; }).Num(delegate (object o) { ExtStat e = X(o); return e.Count > 0 ? Fmt.Bytes((double)e.Bytes / e.Count) : ""; }).Tint(Tone.Dim));
            t.Group(o => new string[] { "." + X(o).Ext });
            return t;
        }

        // ═══════════════ Deleted Files Finder ═══════════════
        public static TableDef Deleted()
        {
            TableDef t = new TableDef("deleted-files");
            t.Add(new Col("when", "When", 120, o => D(o).When));
            t.Add(new Col("type", "Type", 60, o => D(o).Type).Tint(o => D(o).Type == "folder" ? Tone.Warn : Tone.Normal));
            t.Add(new Col("rec", "Recoverable", 90, o => D(o).Recoverable ? "yes" : "").Tint(Tone.Good));
            t.Add(new Col("path", "Path", 480, o => D(o).Path));
            t.Add(new Col("size", "Size", 90, o => D(o).Size).Num(delegate (object o) { DeletedRow d = D(o); return d.Source == "exFAT" && d.Type == "file" ? Fmt.Bytes(d.Size) : ""; }));
            t.Add(new Col("state", "Data", 130, o => D(o).State).Tint(o => Tones.Status(D(o).State)));
            t.Add(new Col("source", "Source", 70, o => D(o).Source).Tint(Tone.Dim));
            t.Add(new Col("note", "Note", 260, o => D(o).Note).Tint(Tone.Dim));
            t.Add(new Col("times", "×", 40, o => D(o).Times).Num(delegate (object o) { int n = D(o).Times; return n > 1 ? n.ToString() : ""; }));
            t.Add(new Col("shadow", "Shadow source", 300, o => D(o).ShadowSource).Tint(Tone.Faint));
            t.Add(new Col("recto", "Recovered to", 300, o => D(o).RecoveredTo).Tint(Tone.Good));
            t.Group(delegate (object o) { List<string> segs = new List<string>(); foreach (string s in D(o).Path.Split('\\')) if (s.Length > 0) segs.Add(s); return segs.ToArray(); });
            return t;
        }

        // ═══════════════ System Recon & Audit ═══════════════
        public static TableDef Recon()
        {
            TableDef t = new TableDef("recon-audit");
            t.Add(new Col("section", "Section", 180, o => RI(o).Section).Tint(Tone.Dim));
            t.Add(new Col("group", "Category", 210, o => RI(o).Group).Tint(Tone.Faint));
            t.Add(new Col("name", "Item", 240, o => RI(o).Name));
            t.Add(new Col("value", "Value", 420, o => RI(o).Value));
            t.Add(new Col("risk", "Flag", 74, o => RI(o).RiskText).Tint(o => Tones.Risk(RI(o).Risk)));
            t.Add(new Col("note", "Note", 460, o => RI(o).Note).Tint(delegate (object o) { string r = RI(o).Risk; return r == "bad" ? Tone.Bad : r == "warn" ? Tone.Warn : Tone.Dim; }));
            // only the rows that need attention are tinted; good/normal rows stay in the default ink (the Flag column carries the colour)
            t.Rows(delegate (object o) { string r = RI(o).Risk; return r == "bad" ? Tone.Bad : r == "warn" ? Tone.Warn : Tone.Normal; });
            t.Group(o => new string[] { RI(o).Section, RI(o).Group.Length > 0 ? RI(o).Group : "(general)" });
            return t;
        }

        // ═══════════════ Security Checklist ═══════════════
        static int CheckRank(string s) { return s == "fail" ? 0 : s == "warn" ? 1 : s == "na" ? 2 : s == "info" ? 3 : 4; }
        public static Tone CheckTone(string s) { return s == "pass" ? Tone.Good : s == "fail" ? Tone.Bad : s == "warn" ? Tone.Warn : s == "na" ? Tone.Faint : Tone.Dim; }
        public static TableDef Checklist()
        {
            TableDef t = new TableDef("security-checklist");
            t.Add(new Col("cat", "Category", 200, o => CI(o).Category).Tint(Tone.Dim));
            t.Add(new Col("name", "Check", 320, o => CI(o).Name));
            t.Add(new Col("res", "Result", 80, o => CheckRank(CI(o).Status)).Num(o => CI(o).StatusText).Tint(o => CheckTone(CI(o).Status)));
            t.Add(new Col("detail", "Detail", 420, o => CI(o).Detail));
            t.Add(new Col("ev", "Evidence", 360, o => CI(o).Evidence).Tint(Tone.Faint));
            t.Add(new Col("q", "Question", 460, o => CI(o).Question).Tint(Tone.Dim));
            t.Rows(delegate (object o) { string r = CI(o).Status; return r == "fail" ? Tone.Bad : r == "warn" ? Tone.Warn : Tone.Normal; });
            t.Group(o => new string[] { CI(o).Category, CI(o).Name });
            return t;
        }

        // ═══════════════ File Explorer / Find Files ═══════════════
        public static TableDef Folder()
        {
            TableDef t = new TableDef("folder");
            t.Add(new Col("name", "Name", 300, o => F(o).Name));
            t.Add(new Col("type", "Type", 90, o => F(o).Kind).Tint(Tone.Dim));
            t.Add(new Col("size", "Size", 100, o => F(o).Size).Num(o => F(o).IsDir ? "" : Fmt.Bytes(F(o).Size)));
            t.Add(new Col("mod", "Modified", 130, o => F(o).Modified));
            t.Add(new Col("sig", "Signature", 160, delegate (object o) { FileEntry f = F(o); if (f.IsDir || !Trust.IsSignable(f.Path)) return ""; SigInfo si = Trust.Verify(f.Path); return si.Status.Length == 0 ? "" : si.Short; }).Tint(delegate (object o) { FileEntry f = F(o); if (f.IsDir || !Trust.IsSignable(f.Path)) return Tone.Faint; return Tones.Sig(Trust.Verify(f.Path)); }));
            t.Add(new Col("attr", "Attributes", 150, o => F(o).AttrText).Tint(Tone.Faint));
            t.Add(new Col("path", "Path", 460, o => F(o).Path).Tint(Tone.Dim));
            t.Rows(delegate (object o) { FileEntry f = F(o); return f.IsDir ? Tone.Accent : f.Encrypted ? Tone.Warn : Tone.Normal; });
            t.Group(o => new string[] { F(o).IsDir ? "folders" : "files", F(o).Name });
            return t;
        }
        public static TableDef FindByName()
        {
            TableDef t = new TableDef("find-by-name");
            t.Add(new Col("name", "Name", 300, o => F(o).Name));
            t.Add(new Col("size", "Size", 100, o => F(o).Size).Num(o => F(o).IsDir ? "" : Fmt.Bytes(F(o).Size)));
            t.Add(new Col("mod", "Modified", 130, o => F(o).Modified));
            t.Add(new Col("type", "Type", 80, o => F(o).Kind).Tint(Tone.Dim));
            t.Add(new Col("dir", "Folder", 480, o => F(o).Dir).Tint(Tone.Dim));
            t.Group(o => new string[] { F(o).Dir });
            return t;
        }
        public static TableDef FindByHash()
        {
            TableDef t = new TableDef("find-by-hash");
            t.Add(new Col("name", "File", 280, o => HH(o).Name));
            t.Add(new Col("algo", "Algorithm", 90, o => HH(o).Algo).Tint(Tone.Accent));
            t.Add(new Col("hash", "Matched hash", 300, o => HH(o).Hash).Tint(Tone.Warn));
            t.Add(new Col("size", "Size", 100, o => HH(o).Size).Num(o => Fmt.Bytes(HH(o).Size)));
            t.Add(new Col("mod", "Modified", 130, o => HH(o).Modified));
            t.Add(new Col("path", "Path", 460, o => HH(o).Path).Tint(Tone.Dim));
            t.Group(o => new string[] { HH(o).Algo, HH(o).Dir });
            return t;
        }

        // ═══════════════ Vulnerability Management ═══════════════
        public static TableDef Findings()
        {
            TableDef t = new TableDef("vulnerability-findings");
            t.Add(new Col("cve", "CVE", 128, o => FD(o).Cve));
            t.Add(new Col("sev", "Severity", 78, o => Resolve.SevRank(FD(o).SeverityNorm)).Num(o => FD(o).SeverityNorm).Tint(o => Tones.Severity(FD(o).SeverityNorm)));
            t.Add(new Col("cvss", "CVSS", 56, o => FD(o).Cvss ?? -1).Num(o => FD(o).Cvss.HasValue ? FD(o).Cvss.Value.ToString("0.0") : ""));
            t.Add(new Col("kev", "Exploited", 112, o => FD(o).ExploitText).Tint(Tone.Bad));
            t.Add(new Col("epss", "EPSS", 62, o => FD(o).Epss ?? -1).Num(o => FD(o).Epss.HasValue ? (FD(o).Epss.Value * 100).ToString("0.0") + " %" : ""));
            t.Add(new Col("status", "Status", 118, o => FD(o).Status).Tint(o => Tones.Status(FD(o).Status)));
            t.Add(new Col("product", "Product", 230, o => FD(o).Product));
            t.Add(new Col("inst", "Installed", 116, o => FD(o).Installed).Tint(Tone.Dim));
            t.Add(new Col("fix", "Fix", 210, o => FD(o).Fix).Tint(Tone.Good));
            t.Add(new Col("src", "Source", 104, o => FD(o).Source).Tint(Tone.Dim));
            t.Add(new Col("title", "Title", 340, o => FD(o).Title));
            t.Add(new Col("ev", "Evidence", 460, o => FD(o).Evidence).Tint(Tone.Dim));
            t.Add(new Col("rel", "Release", 76, o => FD(o).Release).Tint(Tone.Faint));
            t.Add(new Col("due", "KEV due", 90, o => FD(o).KevDue).Tint(Tone.Faint));
            t.Group(o => new string[] { FD(o).Source, FD(o).Product, FD(o).Cve });
            return t;
        }
        public static TableDef MissingUpdates()
        {
            TableDef t = new TableDef("missing-updates");
            t.Add(new Col("kb", "KB", 96, o => MU(o).Kb.Length > 0 ? "KB" + MU(o).Kb : ""));
            t.Add(new Col("title", "Title", 430, o => MU(o).Title));
            t.Add(new Col("sev", "Severity", 80, o => Resolve.NormSeverity(MU(o).Severity)).Tint(o => Tones.Severity(MU(o).Severity)));
            t.Add(new Col("kind", "Kind", 90, o => MU(o).Kind).Tint(delegate (object o) { string k = MU(o).Kind; return k == "security" || k == "critical" ? Tone.Warn : Tone.Dim; }));
            t.Add(new Col("cves", "CVEs", 200, o => MU(o).CveText));
            t.Add(new Col("dl", "Downloaded", 90, o => MU(o).Downloaded ? "yes" : "no").Tint(o => MU(o).Downloaded ? Tone.Good : Tone.Dim));
            t.Add(new Col("size", "Size", 80, o => MU(o).SizeBytes).Num(delegate (object o) { double s = MU(o).SizeBytes; return s > 0 ? Fmt.Bytes(s) : ""; }));
            t.Add(new Col("pub", "Published", 90, o => MU(o).PublishedText).Tint(Tone.Dim));
            t.Add(new Col("reboot", "Reboot", 70, o => MU(o).Reboot).Tint(Tone.Dim));
            t.Add(new Col("cat", "Categories", 240, o => MU(o).Categories).Tint(Tone.Faint));
            t.Group(o => new string[] { MU(o).Kind, MU(o).Title });
            return t;
        }
        /// <summary>The installed-software table inside Vulnerability Management (the Software Inventory tool has its own, richer table).</summary>
        public static TableDef VulnSoftware()
        {
            TableDef t = new TableDef("installed-software");
            t.Add(new Col("name", "Program", 290, o => SW(o).Name));
            t.Add(new Col("ver", "Version", 120, o => SW(o).Version));
            t.Add(new Col("cves", "CVEs", 56, o => SW(o).Cves).Num(delegate (object o) { int n = SW(o).Cves; return n < 0 ? "" : n.ToString(); }).Tint(o => SW(o).Cves > 0 ? Tone.Bad : Tone.Good));
            t.Add(new Col("cpe", "NVD product", 190, o => SW(o).Cpe).Tint(Tone.Accent));
            t.Add(new Col("status", "Status", 300, o => SW(o).Status).Tint(delegate (object o) { Software s = SW(o); return s.Cves > 0 ? Tone.Warn : s.Status.StartsWith("lookup failed") ? Tone.Bad : Tone.Dim; }));
            t.Add(new Col("pub", "Publisher", 190, o => SW(o).Publisher).Tint(Tone.Dim));
            t.Add(new Col("inst", "Installed", 90, o => SW(o).Installed).Tint(Tone.Dim));
            t.Add(new Col("scope", "Scope", 110, o => SW(o).Scope).Tint(Tone.Faint));
            t.Group(delegate (object o) { Software s = SW(o); return new string[] { s.Mapped ? "in the product map" : "not mapped", s.Publisher.Length > 0 ? s.Publisher : "(no publisher)", s.Name + " " + s.Version }; });
            return t;
        }
        public static TableDef Hotfixes()
        {
            TableDef t = new TableDef("hotfixes");
            t.Add(new Col("kb", "KB", 100, o => HF(o).Kb.Length > 0 ? "KB" + HF(o).Kb : ""));
            t.Add(new Col("src", "Source", 90, o => HF(o).Source).Tint(Tone.Dim));
            t.Add(new Col("when", "Installed on", 100, o => HF(o).When));
            t.Add(new Col("result", "Result", 130, o => HF(o).Result).Tint(delegate (object o) { string r = HF(o).Result; return r == "failed" || r == "aborted" ? Tone.Bad : r == "install pending" || r == "superseded" ? Tone.Warn : Tone.Dim; }));
            t.Add(new Col("desc", "Description", 150, o => HF(o).Description).Tint(Tone.Dim));
            t.Add(new Col("title", "Title", 520, o => HF(o).Title));
            t.Group(delegate (object o) { Hotfix h = HF(o); return new string[] { h.Source, "KB" + h.Kb + (h.Title.Length > 0 && h.Source == "WU history" ? " · " + h.Title : "") }; });
            return t;
        }

        // ═══════════════ Software Inventory ═══════════════
        static int SoftRank(Software s) { return s.Vulnerable ? 0 : s.Mapped ? 1 : 2; }
        public static TableDef Software()
        {
            TableDef t = new TableDef("software-inventory");
            t.Add(new Col("name", "Program", 290, o => SW(o).Name));
            t.Add(new Col("ver", "Version", 120, o => SW(o).Version));
            t.Add(new Col("state", "Vulnerable", 92, o => SoftRank(SW(o))).Num(o => SW(o).VulnState).Tint(delegate (object o) { Software s = SW(o); return s.Vulnerable ? Tone.Bad : s.Mapped ? Tone.Good : Tone.Dim; }));
            t.Add(new Col("sev", "Severity", 82, o => Resolve.SevRank(SW(o).WorstSeverity)).Num(o => SW(o).WorstSeverity).Tint(o => Tones.Severity(SW(o).WorstSeverity)));
            t.Add(new Col("cvss", "CVSS", 58, o => SW(o).WorstCvss ?? -1).Num(o => SW(o).WorstCvss.HasValue ? SW(o).WorstCvss.Value.ToString("0.0") : ""));
            t.Add(new Col("cves", "CVEs", 58, o => SW(o).Cves).Num(delegate (object o) { Software s = SW(o); return s.Cves < 0 ? "" : s.Cves.ToString() + (s.Unconfirmed > 0 ? " +" + s.Unconfirmed : ""); }).Tint(o => SW(o).Cves > 0 ? Tone.Bad : Tone.Dim));
            t.Add(new Col("worst", "Worst CVE", 130, o => SW(o).WorstCve));
            t.Add(new Col("expl", "Exploited", 108, o => SW(o).ExploitText).Tint(Tone.Bad));
            t.Add(new Col("epss", "EPSS", 62, o => SW(o).WorstEpss ?? -1).Num(o => SW(o).WorstEpss.HasValue ? (SW(o).WorstEpss.Value * 100).ToString("0.0") + " %" : ""));
            t.Add(new Col("fix", "Fix", 190, o => SW(o).Fix).Tint(Tone.Good));
            t.Add(new Col("pub", "Publisher", 180, o => SW(o).Publisher).Tint(Tone.Dim));
            t.Add(new Col("inst", "Installed", 90, o => SW(o).Installed).Tint(Tone.Dim));
            t.Add(new Col("scope", "Scope", 110, o => SW(o).Scope).Tint(Tone.Faint));
            t.Add(new Col("cpe", "NVD product", 170, o => SW(o).Cpe).Tint(Tone.Accent));
            t.Add(new Col("status", "Status", 260, o => SW(o).Status).Tint(delegate (object o) { Software s = SW(o); return s.Cves > 0 ? Tone.Warn : s.Status.StartsWith("lookup failed") ? Tone.Bad : Tone.Dim; }));
            t.Rows(delegate (object o) { Software s = SW(o); if (!s.Vulnerable) return Tone.Normal; Tone sev = Tones.Severity(s.WorstSeverity); return sev == Tone.Faint ? Tone.Bad : sev; });
            t.Group(delegate (object o) { Software s = SW(o); return new string[] { s.VulnState.Length > 0 ? s.VulnState : "not checked", s.Publisher.Length > 0 ? s.Publisher : "(no publisher)", s.Name }; });
            return t;
        }

        // ═══════════════ Autoruns ═══════════════
        static int AutorunRank(AutorunEntry e) { return e.Risk == "high" ? 0 : e.Risk == "medium" ? 1 : e.Risk == "low" ? 2 : 3; }
        static Tone AutorunSig(AutorunEntry e) { if (e.Image.Length == 0) return Tone.Faint; if (!e.Exists) return Tone.Warn; return Tones.Sig(e.Sig); }
        public static TableDef Autoruns()
        {
            TableDef t = new TableDef("autoruns");
            t.Add(new Col("risk", "Risk", 68, o => AutorunRank(AE(o))).Num(o => AE(o).Risk).Tint(o => Tones.Risk(AE(o).Risk)));
            t.Add(new Col("kind", "Kind", 130, o => AE(o).Kind).Tint(Tone.Accent));
            t.Add(new Col("name", "Name", 210, o => AE(o).Name));
            t.Add(new Col("on", "Enabled", 76, o => AE(o).Enabled ? "enabled" : "disabled").Tint(o => AE(o).Enabled ? Tone.Good : Tone.Faint));
            t.Add(new Col("sig", "Signature", 170, delegate (object o) { AutorunEntry e = AE(o); return e.Image.Length == 0 ? "" : e.Sig.Status.Length == 0 ? (e.Exists ? "" : "file missing") : e.Sig.Short; }).Tint(o => AutorunSig(AE(o))));
            t.Add(new Col("where", "Location on disk", 110, o => AE(o).Where).Tint(delegate (object o) { string w = AE(o).Where; return w == "user-writable" || w == "other" ? Tone.Warn : Tone.Dim; }));
            t.Add(new Col("cmd", "Command", 300, o => AE(o).Command).Tint(Tone.Dim));
            t.Add(new Col("why", "Why flagged", 240, o => AE(o).RiskWhy).Tint(Tone.Warn));
            t.Add(new Col("desc", "Description", 200, o => AE(o).Description.Length > 0 ? AE(o).Description : AE(o).Company).Tint(Tone.Faint));
            t.Add(new Col("scope", "Scope", 70, o => AE(o).Scope).Tint(Tone.Faint));
            t.Add(new Col("loc", "Registry / path", 320, o => AE(o).Location).Tint(Tone.Faint));
            t.Rows(o => Tones.Risk(AE(o).Risk));
            t.Group(o => new string[] { AE(o).Kind, AE(o).Name });
            return t;
        }

        // ═══════════════ Event Log Triage ═══════════════
        public static TableDef Events()
        {
            TableDef t = new TableDef("events");
            t.Add(new Col("time", "When", 150, o => EV(o).Time).Num(o => EV(o).When));
            t.Add(new Col("risk", "Risk", 62, delegate (object o) { string r = EV(o).Risk; return r == "high" ? 0 : r == "medium" ? 1 : 2; }).Num(o => EV(o).Risk).Tint(o => Tones.Risk(EV(o).Risk)));
            t.Add(new Col("cat", "Category", 190, o => EV(o).Category).Tint(Tone.Accent));
            t.Add(new Col("id", "Event", 62, o => EV(o).Id).Num(o => EV(o).Id.ToString()));
            t.Add(new Col("who", "Account", 170, o => EV(o).Who));
            t.Add(new Col("detail", "Detail", 520, o => EV(o).Detail));
            t.Add(new Col("level", "Level", 90, o => EV(o).Level).Tint(delegate (object o) { string l = EV(o).Level; return l == "error" || l == "critical" ? Tone.Bad : l == "warning" ? Tone.Warn : Tone.Dim; }));
            t.Add(new Col("src", "Source", 220, o => EV(o).Source).Tint(Tone.Faint));
            t.Add(new Col("log", "Log", 200, o => EV(o).Log).Tint(Tone.Faint));
            t.Rows(o => Tones.Risk(EV(o).Risk));
            t.Group(o => new string[] { EV(o).Category, EV(o).When });
            return t;
        }

        // ═══════════════ Secrets Scanner ═══════════════
        public static Tone SecretTone(string s) { return s == "high" ? Tone.Bad : s == "medium" ? Tone.Warn : Tone.Info; }
        public static TableDef Secrets()
        {
            TableDef t = new TableDef("secrets");
            t.Add(new Col("sev", "Severity", 82, delegate (object o) { string s = SH(o).Severity; return s == "high" ? 0 : s == "medium" ? 1 : 2; }).Num(o => SH(o).Severity).Tint(o => SecretTone(SH(o).Severity)));
            t.Add(new Col("kind", "Kind", 180, o => SH(o).Kind).Tint(Tone.Accent));
            t.Add(new Col("file", "File", 220, o => SH(o).File));
            t.Add(new Col("line", "Line", 56, o => SH(o).Line).Num(o => SH(o).Line.ToString()));
            t.Add(new Col("preview", "Masked preview", 260, o => SH(o).Preview).Tint(Tone.Warn));
            t.Add(new Col("where", "Location", 100, o => SH(o).Where).Tint(Tone.Faint));
            t.Add(new Col("dir", "Folder", 420, o => Path.GetDirectoryName(SH(o).Path) ?? "").Tint(Tone.Dim));
            t.Rows(o => SecretTone(SH(o).Severity));
            t.Group(o => new string[] { SH(o).Kind, SH(o).File });
            return t;
        }

        // ═══════════════ Duplicate Finder ═══════════════
        public static TableDef Duplicates()
        {
            TableDef t = new TableDef("duplicates");
            t.Add(new Col("keep", "Copy", 74, o => DF(o).Keep ? "keep" : "extra").Tint(o => DF(o).Keep ? Tone.Good : Tone.Warn));
            t.Add(new Col("name", "Name", 260, o => DF(o).Name));
            t.Add(new Col("size", "Size", 100, o => DF(o).Size).Num(o => Fmt.Bytes(DF(o).Size)));
            t.Add(new Col("group", "Group", 90, o => DF(o).Group).Tint(Tone.Accent));
            t.Add(new Col("mod", "Modified", 130, o => DF(o).Modified));
            t.Add(new Col("where", "Location", 100, o => DF(o).Where).Tint(Tone.Faint));
            t.Add(new Col("dir", "Folder", 460, o => DF(o).Dir).Tint(Tone.Dim));
            t.Rows(o => DF(o).Keep ? Tone.Good : Tone.Normal);
            t.Group(o => new string[] { Fmt.Bytes(DF(o).Size) + " · " + DF(o).Group, DF(o).Name });
            return t;
        }

        // ═══════════════ Firewall Rules ═══════════════
        public static TableDef FirewallRules()
        {
            TableDef t = new TableDef("firewall-rules");
            t.Add(new Col("risk", "Risk", 62, delegate (object o) { string r = FW(o).Risk; return r == "high" ? 0 : r == "medium" ? 1 : r == "low" ? 2 : 3; }).Num(o => FW(o).Risk).Tint(o => Tones.Risk(FW(o).Risk)));
            t.Add(new Col("name", "Rule", 280, o => FW(o).Name));
            t.Add(new Col("on", "Enabled", 74, o => FW(o).Enabled ? "on" : "off").Tint(o => FW(o).Enabled ? Tone.Good : Tone.Faint));
            t.Add(new Col("dir", "Direction", 84, o => FW(o).Direction == "in" ? "inbound" : "outbound"));
            t.Add(new Col("act", "Action", 70, o => FW(o).Action).Tint(o => FW(o).Action == "allow" ? Tone.Good : Tone.Bad));
            t.Add(new Col("proto", "Protocol", 74, o => FW(o).Protocol));
            t.Add(new Col("lports", "Local ports", 110, o => FW(o).LocalPorts.Length == 0 ? "any" : FW(o).LocalPorts));
            t.Add(new Col("remote", "Remote address", 150, o => FW(o).RemoteAddresses.Length == 0 || FW(o).RemoteAddresses == "*" ? "any" : FW(o).RemoteAddresses).Tint(delegate (object o) { FwRule f = FW(o); return (f.RemoteAddresses.Length == 0 || f.RemoteAddresses == "*") && f.Inbound && f.Allow ? Tone.Warn : Tone.Dim; }));
            t.Add(new Col("profiles", "Profiles", 130, o => FW(o).Profiles).Tint(o => FW(o).Profiles.Contains("public") || FW(o).Profiles == "all" ? Tone.Normal : Tone.Dim));
            t.Add(new Col("why", "Why flagged", 260, o => FW(o).RiskWhy).Tint(Tone.Warn));
            t.Add(new Col("prog", "Program", 320, delegate (object o) { FwRule f = FW(o); return f.Program.Length > 0 ? f.Program : (f.Service.Length > 0 ? "service: " + f.Service : "(any program)"); }).Tint(Tone.Faint));
            t.Add(new Col("group", "Group", 200, o => FW(o).Group).Tint(Tone.Faint));
            t.Rows(delegate (object o) { FwRule f = FW(o); return f.Risk.Length > 0 ? Tones.Risk(f.Risk) : f.Enabled ? Tone.Normal : Tone.Faint; });
            t.Group(o => new string[] { FW(o).Direction == "in" ? "inbound" : "outbound", FW(o).Action, FW(o).Name });
            return t;
        }

        // ═══════════════ Wi-Fi & Credentials ═══════════════
        /// <summary>Saved Wi-Fi networks; the key column shows dots until the caller says the keys are revealed.</summary>
        public static TableDef Wifi(Func<bool> revealed)
        {
            TableDef t = new TableDef("wifi-networks");
            t.Add(new Col("ssid", "Network (SSID)", 240, o => WP(o).Ssid));
            t.Add(new Col("risk", "Security risk", 100, delegate (object o) { string r = WP(o).Risk; return r == "high" ? 0 : r == "medium" ? 1 : 2; }).Num(o => WP(o).Risk).Tint(delegate (object o) { string r = WP(o).Risk; return r == "high" ? Tone.Bad : r == "medium" ? Tone.Warn : Tone.Good; }));
            t.Add(new Col("sec", "Security", 200, o => WP(o).Security).Tint(Tone.Dim));
            t.Add(new Col("key", "Key", 220, delegate (object o) { WifiProfile w = WP(o); return w.HasKey ? (revealed() ? w.Key : "••••••••") : (revealed() ? "(none stored)" : ""); }).Tint(o => revealed() ? Tone.Warn : Tone.Faint));
            t.Add(new Col("auto", "Auto-connect", 100, o => WP(o).AutoConnect ? "yes" : "no").Tint(Tone.Dim));
            t.Add(new Col("why", "Note", 240, o => WP(o).RiskWhy).Tint(Tone.Warn));
            t.Add(new Col("scope", "Stored for", 110, o => WP(o).Where).Tint(Tone.Faint));
            t.Rows(delegate (object o) { string r = WP(o).Risk; return r == "high" ? Tone.Bad : r == "medium" ? Tone.Warn : Tone.Normal; });
            t.Group(o => new string[] { WP(o).Security.Length > 0 ? WP(o).Security : "unknown", WP(o).Ssid });
            return t;
        }
        public static TableDef Vault(Func<bool> revealed)
        {
            TableDef t = new TableDef("credential-vault");
            t.Add(new Col("target", "Target", 320, o => VC(o).Target));
            t.Add(new Col("user", "User", 200, o => VC(o).User));
            t.Add(new Col("type", "Type", 160, o => VC(o).Type).Tint(Tone.Accent));
            t.Add(new Col("secret", "Secret", 200, delegate (object o) { VaultCred v = VC(o); return v.HasSecret ? (revealed() ? v.Preview : "••••••") : "(none)"; }).Tint(o => revealed() ? Tone.Warn : Tone.Faint));
            t.Add(new Col("persist", "Persistence", 120, o => VC(o).Persist).Tint(Tone.Dim));
            t.Add(new Col("when", "Last written", 140, o => VC(o).Written).Num(o => VC(o).When));
            t.Group(o => new string[] { VC(o).Type, VC(o).Target });
            return t;
        }

        // ═══════════════ Browsing Data ═══════════════
        public static TableDef BrowserHistory()
        {
            TableDef t = new TableDef("browsing-history");
            t.Add(new Col("when", "Last visit", 150, o => VR(o).When).Num(o => VR(o).WhenText));
            t.Add(new Col("visits", "Visits", 62, o => VR(o).VisitCount).Num(o => VR(o).VisitCount.ToString()));
            t.Add(new Col("title", "Title", 300, o => VR(o).Title));
            t.Add(new Col("domain", "Site", 190, o => VR(o).Domain).Tint(Tone.Accent));
            t.Add(new Col("url", "URL", 420, o => VR(o).Url).Tint(o => VR(o).Secure ? Tone.Dim : Tone.Warn));
            t.Add(new Col("browser", "Browser", 120, o => VR(o).Browser + (VR(o).Profile.Length > 0 && VR(o).Profile != "Default" ? " · " + VR(o).Profile : "")).Tint(Tone.Faint));
            t.Rows(o => VR(o).Secure ? Tone.Normal : Tone.Warn);
            t.Group(delegate (object o) { VisitRow v = VR(o); return new string[] { v.Domain.Length > 0 ? v.Domain : "(local)", v.Title.Length > 0 ? v.Title : v.Url }; });
            return t;
        }
        public static TableDef BrowserDownloads()
        {
            TableDef t = new TableDef("browsing-downloads");
            t.Add(new Col("when", "When", 150, o => VR(o).When).Num(o => VR(o).WhenText));
            t.Add(new Col("file", "File", 300, o => VR(o).Title));
            t.Add(new Col("size", "Size", 100, o => VR(o).Bytes).Num(delegate (object o) { long b = VR(o).Bytes; return b > 0 ? Fmt.Bytes(b) : ""; }));
            t.Add(new Col("state", "State", 100, o => VR(o).State).Tint(delegate (object o) { string s = VR(o).State; return s == "complete" ? Tone.Good : s == "interrupted" || s == "cancelled" ? Tone.Bad : Tone.Dim; }));
            t.Add(new Col("domain", "From site", 180, o => VR(o).Domain).Tint(Tone.Accent));
            t.Add(new Col("url", "Source URL", 380, o => VR(o).Url).Tint(Tone.Dim));
            t.Add(new Col("path", "Saved to", 360, o => VR(o).File).Tint(Tone.Faint));
            t.Add(new Col("browser", "Browser", 110, o => VR(o).Browser).Tint(Tone.Faint));
            t.Group(o => new string[] { VR(o).Domain.Length > 0 ? VR(o).Domain : "(unknown)", VR(o).Title });
            return t;
        }
        public static TableDef BrowserSearches()
        {
            TableDef t = new TableDef("browsing-searches");
            t.Add(new Col("when", "When", 150, o => VR(o).When).Num(o => VR(o).WhenText));
            t.Add(new Col("term", "Search term", 340, o => VR(o).Term));
            t.Add(new Col("domain", "Engine / site", 200, o => VR(o).Domain).Tint(Tone.Accent));
            t.Add(new Col("url", "URL", 420, o => VR(o).Url).Tint(Tone.Dim));
            t.Add(new Col("browser", "Browser", 120, o => VR(o).Browser).Tint(Tone.Faint));
            t.Group(o => new string[] { VR(o).Browser, VR(o).Term });
            return t;
        }
        /// <summary>Sites ranked by visits; the rank and share bar need the ranked list itself.</summary>
        public static TableDef BrowserDomains(List<DomainStat> ranked)
        {
            TableDef t = new TableDef("browsing-domains");
            t.Add(new Col("rank", "#", 46, o => ranked.IndexOf(DS(o)) + 1).Num(o => (ranked.IndexOf(DS(o)) + 1).ToString()).Tint(Tone.Faint));
            t.Add(new Col("domain", "Site", 300, o => DS(o).Domain).Tint(Tone.Accent));
            t.Add(new Col("visits", "Visits", 90, o => DS(o).Visits).Num(o => DS(o).Visits.ToString("N0")));
            t.Add(new Col("pages", "Pages", 80, o => DS(o).Pages).Num(o => DS(o).Pages.ToString("N0")).Tint(Tone.Dim));
            t.Add(new Col("bar", "Share", 160, o => DS(o).Visits).Num(delegate (object o) { long mx = ranked.Count > 0 ? ranked[0].Visits : 1; if (mx < 1) mx = 1; int w = (int)Math.Round(20.0 * DS(o).Visits / mx); return new string('▮', Math.Max(DS(o).Visits > 0 ? 1 : 0, w)); }).Tint(Tone.Accent));
            t.Add(new Col("last", "Last visit", 110, o => DS(o).Last).Num(o => DS(o).LastText));
            t.Add(new Col("first", "First visit", 110, o => DS(o).First == DateTime.MaxValue ? DateTime.MinValue : DS(o).First).Num(o => DS(o).FirstText).Tint(Tone.Dim));
            t.Add(new Col("browsers", "Browsers", 150, o => DS(o).BrowsersText).Tint(Tone.Faint));
            t.Group(delegate (object o) { DomainStat d = DS(o); string first = d.Domain.Length > 0 ? char.ToUpper(d.Domain[0]).ToString() : "#"; return new string[] { first, d.Domain }; });
            return t;
        }
        public static TableDef BrowserPasswords(Func<bool> revealed)
        {
            TableDef t = new TableDef("browsing-passwords");
            t.Add(new Col("site", "Site", 220, o => LR(o).Domain.Length > 0 ? LR(o).Domain : LR(o).Url));
            t.Add(new Col("user", "Username", 240, o => LR(o).User));
            t.Add(new Col("pass", "Password", 220, delegate (object o) { LoginRow l = LR(o); return !l.HasPassword ? "(none)" : revealed() ? (l.Password.Length > 0 ? l.Password : "—") : "••••••••"; }).Tint(o => revealed() ? Tone.Warn : Tone.Faint));
            t.Add(new Col("weak", "Weak", 60, o => LR(o).Weak ? "weak" : "").Tint(Tone.Bad));
            t.Add(new Col("when", "Saved", 140, o => LR(o).When).Num(o => LR(o).WhenText));
            t.Add(new Col("note", "Note", 300, o => LR(o).Note).Tint(Tone.Faint));
            t.Add(new Col("url", "URL", 360, o => LR(o).Url).Tint(o => LR(o).Url.StartsWith("http:", StringComparison.OrdinalIgnoreCase) ? Tone.Warn : Tone.Dim));
            t.Add(new Col("browser", "Browser", 110, o => LR(o).Browser).Tint(Tone.Faint));
            t.Rows(delegate (object o) { LoginRow l = LR(o); return l.Weak ? Tone.Warn : l.Url.StartsWith("http:", StringComparison.OrdinalIgnoreCase) ? Tone.Warn : Tone.Normal; });
            t.Group(o => new string[] { LR(o).Domain.Length > 0 ? LR(o).Domain : LR(o).Url, LR(o).User });
            return t;
        }
        public static TableDef RemoteAudit()
        {
            Func<object, RunResult> R = delegate (object o) { return (RunResult)o; };
            Func<string, Tone> tone = delegate (string s) { if (s == "ok" || s == "cleaned" || s == "preflight-ok") return Tone.Good; if (s == "ok-partial" || s == "timeout-partial" || s == "unreachable-preflight") return Tone.Warn; return Tone.Bad; };
            TableDef t = new TableDef("remote-audit");
            t.Add(new Col("host", "Host", 150, o => R(o).Host));
            t.Add(new Col("status", "Status", 120, o => R(o).Status).Tint(o => tone(R(o).Status)));
            t.Add(new Col("user", "Account", 130, o => R(o).User).Tint(Tone.Dim));
            t.Add(new Col("verified", "Verified", 70, o => R(o).Verified ? "yes" : "").Tint(o => R(o).Verified ? Tone.Good : Tone.Dim));
            t.Add(new Col("partial", "Partial", 60, o => R(o).Partial ? "yes" : "").Tint(Tone.Warn));
            t.Add(new Col("clean", "Left clean", 70, o => R(o).LeftClean ? "yes" : "no").Tint(o => R(o).LeftClean ? Tone.Good : Tone.Bad));
            t.Add(new Col("bytes", "Bundle", 80, o => R(o).Bytes == 0 ? (object)"" : R(o).Bytes).Num(o => R(o).Bytes == 0 ? "" : R(o).Bytes.ToString("N0")));
            t.Add(new Col("seconds", "Secs", 50, o => R(o).Seconds).Num(o => R(o).Seconds.ToString("0.0")));
            t.Add(new Col("runId", "Run id", 150, o => R(o).RunId).Tint(Tone.Dim));
            t.Add(new Col("sha256", "SHA-256", 150, o => R(o).Sha).Tint(Tone.Dim));
            t.Add(new Col("detail", "Detail", 600, o => R(o).Detail).Tint(Tone.Dim));
            return t;
        }
    }
}

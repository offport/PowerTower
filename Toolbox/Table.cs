// The UI-free half of the view kit, shared by PowerTower.exe (WinForms), PowerTowerCli.exe (console) and
// Tests.exe: column definitions with semantic tones instead of colours, filter rules, CSV, the settings
// file, the shared row types that are not engine output, and the one registry of tools that gives the
// sidebar, the About page and the command line the same names in the same order.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace PSTools
{
    /// <summary>What a cell or row means, not what colour it is. The GUI maps a tone to the theme's colour, the CLI to a console colour.</summary>
    public enum Tone { Normal, Dim, Faint, Accent, Good, Warn, Bad, Info }

    public static class Tones
    {
        /// <summary>The tone of a status word, the same words the tools produce: reachable/blocked/ok are good, unreachable/error/vulnerable are bad, pending/checking/listening are a warning.</summary>
        public static Tone Status(string s)
        {
            string t = (s ?? "").ToLowerInvariant();
            if (t.StartsWith("reachable") || t == "blocked" || t.StartsWith("intact") || t == "recoverable" || t == "ok" || t == "established" || t == "patched" || t == "installed") return Tone.Good;
            if (t.StartsWith("unreach") || t == "invalid" || t == "no dns" || t == "overwritten" || t == "chain lost" || t == "error" || t.StartsWith("not a valid") || t == "vulnerable" || t.StartsWith("failed")) return Tone.Bad;
            if (t.StartsWith("partly") || t == "ping only" || t == "resolves" || t == "pending" || t.StartsWith("checking") || t == "listening" || t == "update available" || t == "reboot pending" || t.StartsWith("scanning")) return Tone.Warn;
            return Tone.Dim;
        }
        /// <summary>The tone of a severity word (MSRC or CVSS wording).</summary>
        public static Tone Severity(string s)
        {
            string t = (s ?? "").ToLowerInvariant();
            if (t == "critical") return Tone.Bad; if (t == "high" || t == "important") return Tone.Warn; if (t == "medium" || t == "moderate") return Tone.Info; if (t == "low") return Tone.Dim; return Tone.Faint;
        }
        /// <summary>The tone of a risk flag: high/bad, medium/warn, low, good.</summary>
        public static Tone Risk(string r) { return r == "high" || r == "bad" ? Tone.Bad : r == "medium" || r == "warn" ? Tone.Warn : r == "low" ? Tone.Info : r == "good" ? Tone.Good : Tone.Normal; }
        /// <summary>The tone of a signature: invalid is bad, unsigned a warning, Microsoft-signed dim, other signers good, unknown faint.</summary>
        public static Tone Sig(SigInfo si) { if (si == null || si.Status.Length == 0) return Tone.Faint; if (si.Status == "invalid") return Tone.Bad; if (si.Status == "unsigned") return Tone.Warn; if (si.Ok) return si.Microsoft ? Tone.Dim : Tone.Good; return Tone.Faint; }
    }

    // ───────────────────────────── columns and rows ─────────────────────────────
    /// <summary>One column: a key for the CLI and filters, a title for headers and CSV, a width hint, an accessor, an optional formatter, tone, editor and sort key.</summary>
    public class Col
    {
        public string Key, Title; public int Width; public bool Right, Editable, Hidden; public Func<object, object> Get; public Func<object, string> Fmt; public Func<object, Tone> ToneOf; public Action<object, string> Set; public Func<object, object> SortKey;
        public Col(string key, string title, int width, Func<object, object> get) { Key = key; Title = title; Width = width; Get = get; }
        public Col Num(Func<object, string> fmt) { Right = true; Fmt = fmt; return this; }
        public Col Tint(Func<object, Tone> t) { ToneOf = t; return this; }
        public Col Tint(Tone fixedTone) { Tone t = fixedTone; ToneOf = delegate (object o) { return t; }; return this; }
        public Col Edit(Action<object, string> set) { Editable = true; Set = set; return this; }
        public string Text(object item) { object v = Get(item); if (Fmt != null) return Fmt(item); return v == null ? "" : (v is DateTime ? (((DateTime)v) == DateTime.MinValue ? "" : ((DateTime)v).ToString("yyyy-MM-dd HH:mm")) : v.ToString()); }
        public object Sortable(object item) { if (SortKey != null) return SortKey(item); object v = Get(item); return v; }
        /// <summary>A cell text that can never throw: an accessor applied to a row of another type (mid mode-switch) or odd data yields "" instead of an exception.</summary>
        public string SafeText(object item) { try { return Text(item) ?? ""; } catch { return ""; } }
        /// <summary>The tone of this cell for a row, or the row's own tone, or Normal; never throws.</summary>
        public Tone SafeTone(object item, Tone rowTone) { try { return ToneOf != null ? ToneOf(item) : rowTone; } catch { return rowTone; } }
    }

    /// <summary>Everything a view needs to show one kind of row: the columns, the tree grouping, the row tone, which rows are dimmed, and the export name. Built once in Columns.cs and used by both the GUI and the CLI.</summary>
    public class TableDef
    {
        public string Export = "export"; public List<Col> Cols = new List<Col>();
        public Func<object, string[]> Tree; public Func<string, List<object>, string> TreeText; public Func<object, Tone> RowTone; public Func<object, bool> Dimmed;
        public TableDef(string export) { Export = export; }
        public TableDef Add(Col c) { Cols.Add(c); return this; }
        public TableDef Group(Func<object, string[]> tree) { Tree = tree; return this; }
        public TableDef Rows(Func<object, Tone> rowTone) { RowTone = rowTone; return this; }
        public TableDef Dim(Func<object, bool> dimmed) { Dimmed = dimmed; return this; }
        public Col Find(string keyOrTitle)
        {
            if (keyOrTitle == null) return null;
            foreach (Col c in Cols) if (string.Equals(c.Key, keyOrTitle, StringComparison.OrdinalIgnoreCase)) return c;
            foreach (Col c in Cols) if (string.Equals(c.Title, keyOrTitle, StringComparison.OrdinalIgnoreCase)) return c;
            return null;
        }
    }

    /// <summary>One filter condition on a column: operator + value. Rules on a view are ANDed. Key "*" means any column.</summary>
    public class FilterRule
    {
        public string Key, Op, Value = ""; public bool MatchCase; public HashSet<string> AnyOf; // AnyOf: header value checklist - the cell must be one of these
        public static readonly string[] Ops = { "contains", "does not contain", "equals", "does not equal", "starts with", "ends with", "matches regex", "is empty", "is not empty", "greater than", "less than", "at least", "at most" };
        public static bool NeedsValue(string op) { return op != "is empty" && op != "is not empty"; }
        public bool Negative { get { return Op == "does not contain" || Op == "does not equal" || Op == "is empty"; } }
        public string Describe(IList<Col> cols) { string n = Key == "*" ? "any column" : Key; foreach (Col c in cols) if (c.Key == Key) n = c.Title; if (AnyOf != null) return n + " is one of " + AnyOf.Count + " value" + (AnyOf.Count == 1 ? "" : "s"); return n + " " + Op + (NeedsValue(Op) ? " “" + Value + "”" : ""); }
        public bool Test(string text)
        {
            if (AnyOf != null) return AnyOf.Contains((text ?? "").Trim());
            string t = text ?? ""; string v = Value ?? ""; StringComparison sc = MatchCase ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase;
            switch (Op)
            {
                case "contains": return t.IndexOf(v, sc) >= 0;
                case "does not contain": return t.IndexOf(v, sc) < 0;
                case "equals": return string.Equals(t.Trim(), v.Trim(), sc);
                case "does not equal": return !string.Equals(t.Trim(), v.Trim(), sc);
                case "starts with": return t.TrimStart().StartsWith(v, sc);
                case "ends with": return t.TrimEnd().EndsWith(v, sc);
                case "matches regex": try { return Regex.IsMatch(t, v, MatchCase ? RegexOptions.None : RegexOptions.IgnoreCase); } catch { return false; }
                case "is empty": return t.Trim().Length == 0;
                case "is not empty": return t.Trim().Length > 0;
                case "greater than": case "less than": case "at least": case "at most":
                    {
                        double a, b; int r; if (Number(t, out a) && Number(v, out b)) r = a.CompareTo(b); else r = string.Compare(t, v, sc);
                        return Op == "greater than" ? r > 0 : Op == "less than" ? r < 0 : Op == "at least" ? r >= 0 : r <= 0;
                    }
            }
            return true;
        }
        static readonly Regex NumRx = new Regex(@"^\s*(-?[\d,]*\.?\d+)\s*(%|ms|s|B|KB|MB|GB|TB|K|M|G)?(?![A-Za-z])", RegexOptions.IgnoreCase);
        /// <summary>The leading number of a cell, with KB/MB/GB/TB scaled to bytes, so "Size at least 10 MB" and "DNS less than 50" read naturally.</summary>
        public static bool Number(string s, out double d)
        {
            d = 0; if (s == null) return false; Match m = NumRx.Match(s); if (!m.Success) return false;
            if (!double.TryParse(m.Groups[1].Value.Replace(",", ""), NumberStyles.Float, CultureInfo.InvariantCulture, out d)) return false;
            string u = m.Groups[2].Value.ToUpperInvariant();
            if (u == "KB" || u == "K") d *= 1024; else if (u == "MB" || u == "M") d *= 1048576; else if (u == "GB" || u == "G") d *= 1073741824.0; else if (u == "TB") d *= 1099511627776.0;
            return true;
        }
        /// <summary>Parses the command-line form: "<column> <operator> [value]", longest operator first, e.g. "size at least 10 MB", "status does not contain blocked", "note is empty". Column may be a key or a title; "any" / "*" means any column. Null when it does not parse.</summary>
        public static FilterRule Parse(string text, IList<Col> cols, out string error)
        {
            error = null; string s = (text ?? "").Trim(); if (s.Length == 0) { error = "empty rule"; return null; }
            List<string> ops = new List<string>(Ops); ops.Sort(delegate (string a, string b) { return b.Length.CompareTo(a.Length); });
            foreach (string op in ops)
            {
                int i = s.IndexOf(" " + op, StringComparison.OrdinalIgnoreCase); if (i <= 0) continue;
                string colText = s.Substring(0, i).Trim(); string rest = s.Substring(i + 1 + op.Length);
                if (rest.Length > 0 && rest[0] != ' ') continue;                       // "at least" must not match inside "at leastX"
                string val = rest.Trim(); if (val.Length >= 2 && ((val[0] == '"' && val[val.Length - 1] == '"') || (val[0] == '\'' && val[val.Length - 1] == '\''))) val = val.Substring(1, val.Length - 2);
                if (NeedsValue(op) && val.Length == 0) { error = "the operator '" + op + "' needs a value"; return null; }
                string key = "*";
                if (colText != "*" && !string.Equals(colText, "any", StringComparison.OrdinalIgnoreCase) && !string.Equals(colText, "any column", StringComparison.OrdinalIgnoreCase))
                {
                    Col c = null; foreach (Col x in cols) if (string.Equals(x.Key, colText, StringComparison.OrdinalIgnoreCase) || string.Equals(x.Title, colText, StringComparison.OrdinalIgnoreCase)) { c = x; break; }
                    if (c == null) { error = "no column '" + colText + "'"; return null; }
                    key = c.Key;
                }
                FilterRule r = new FilterRule(); r.Key = key; r.Op = op; r.Value = val; return r;
            }
            error = "no operator found - use one of: " + string.Join(", ", Ops); return null;
        }
        /// <summary>Applies a set of rules to one row exactly as the GUI does: a rule on a column tests that column; a rule on any column needs one column to pass (or, for a negative rule, every column).</summary>
        public static bool Pass(IList<FilterRule> rules, IList<Col> cols, object o)
        {
            foreach (FilterRule r in rules)
            {
                if (r.Key != "*") { Col c = null; foreach (Col x in cols) if (x.Key == r.Key) { c = x; break; } if (c == null) continue; if (!r.Test(c.SafeText(o))) return false; continue; }
                bool neg = r.Negative, any = false, allOk = true;
                foreach (Col c in cols) { bool ok = r.Test(c.SafeText(o)); if (ok) any = true; else allOk = false; }
                if (neg ? !allOk : !any) return false;
            }
            return true;
        }
    }

    /// <summary>The one sort the app uses everywhere: by the column's sortable value, IComparable when both sides share a type, otherwise case-insensitive text; nulls first.</summary>
    public static class RowSort
    {
        public static void Sort(List<object> rows, Col c, bool asc)
        {
            if (c == null) return;
            rows.Sort(delegate (object a, object b) { try { object va = c.Sortable(a), vb = c.Sortable(b); int r; if (va == null && vb == null) r = 0; else if (va == null) r = -1; else if (vb == null) r = 1; else if (va is IComparable && va.GetType() == vb.GetType()) r = ((IComparable)va).CompareTo(vb); else r = string.Compare(va.ToString(), vb.ToString(), StringComparison.OrdinalIgnoreCase); return asc ? r : -r; } catch { return 0; } });
        }
    }

    public static class Csv
    {
        public static void Write(string path, IList<Col> cols, IList<object> items) { File.WriteAllText(path, Text(cols, items), new UTF8Encoding(true)); }
        public static string Text(IList<Col> cols, IList<object> items)
        {
            StringBuilder sb = new StringBuilder(); List<string> h = new List<string>(); foreach (Col c in cols) h.Add(Q(c.Title)); sb.AppendLine(string.Join(",", h.ToArray()));
            foreach (object o in items) { List<string> r = new List<string>(); foreach (Col c in cols) r.Add(Q(c.SafeText(o))); sb.AppendLine(string.Join(",", r.ToArray())); }
            return sb.ToString();
        }
        public static string Q(string s) { return Fmt.CsvQ(s); }
        /// <summary>Number of CSV records in a text, honouring quoted fields that contain newlines (RFC 4180).</summary>
        public static int CountRecords(string text) { if (string.IsNullOrEmpty(text)) return 0; int n = 0; bool q = false, content = false; for (int i = 0; i < text.Length; i++) { char ch = text[i]; if (ch == '"') { q = !q; content = true; } else if (ch == '\n' && !q) { n++; content = false; } else if (ch != '\r') content = true; } if (content) n++; return n; }
    }

    /// <summary>settings.ini next to the exe: key=value lines, shared by the GUI and the CLI.</summary>
    public class Settings
    {
        readonly string file; readonly Dictionary<string, string> kv = new Dictionary<string, string>();
        public Settings(string path) { file = path; try { if (File.Exists(file)) foreach (string l in File.ReadAllLines(file)) { int i = l.IndexOf('='); if (i > 0) kv[l.Substring(0, i)] = l.Substring(i + 1); } } catch { } }
        public string Get(string k, string d) { string v; return kv.TryGetValue(k, out v) ? v : d; }
        public void Set(string k, string v) { kv[k] = v; }
        public void Save() { try { StringBuilder sb = new StringBuilder(); foreach (KeyValuePair<string, string> p in kv) sb.Append(p.Key).Append('=').Append(p.Value).Append("\r\n"); File.WriteAllText(file, sb.ToString()); } catch { } }
    }

    // ───────────────────────────── shared row types that are not engine output ─────────────────────────────
    /// <summary>A row of the Domain and IP Blocker: a value pulled out of a file or paste, classified, with where it is blocked.</summary>
    public class BlockItem
    {
        public string Value, Source, Where = "", Note = ""; public Kind Kind; public int Line; public bool BlockedHosts, BlockedFw;
        public string Status { get { if (Kind == Kind.Invalid) return "not a valid domain or IP"; if (BlockedHosts || BlockedFw) return "blocked"; return "not blocked"; } }
        public string KindText { get { return Kind == Kind.Domain ? "domain" : Kind == Kind.IPv4 ? "IPv4" : Kind == Kind.IPv6 ? "IPv6" : "invalid"; } }
        /// <summary>The tree group under the kind: the registered domain, the /24, or the IPv6 prefix.</summary>
        public string Group
        {
            get
            {
                if (Kind == Kind.Domain) { string[] p = Value.Split('.'); return p.Length >= 2 ? p[p.Length - 2] + "." + p[p.Length - 1] : Value; }
                if (Kind == Kind.IPv4) { int i = Value.LastIndexOf('.'); return i > 0 ? Value.Substring(0, i) + ".x" : Value; }
                if (Kind == Kind.IPv6) { int i = Value.IndexOf(':'); i = i > 0 ? Value.IndexOf(':', i + 1) : -1; return i > 0 ? Value.Substring(0, i) + ":…" : Value; }
                return "invalid";
            }
        }
    }
    /// <summary>A Find Files hash-sweep match.</summary>
    public class HashHit { public string Name = "", Path = "", Dir = "", Algo = "", Hash = ""; public long Size; public DateTime Modified; }

    // ───────────────────────────── the tool registry ─────────────────────────────
    /// <summary>One tool: its command-line name, GUI panel class, title, one-line blurb, the group it sits in on the About page, and its short About description.</summary>
    public class ToolInfo
    {
        public string Key, Panel, Title, Blurb, Group, About; public bool NeedsAdmin, GuiOnly, CliOnly;
        /// <summary>What the tool does beyond reading, shown in the sidebar and the header: changes it can make to this machine, what it sends over the network, secrets it can put on screen. All three empty = read-only.</summary>
        public string Writes = "", Online = "", Caution = "";
        public string Effects { get { List<string> l = new List<string>(); if (Writes.Length > 0) l.Add("\u25b2  changes this machine: " + Writes); if (Online.Length > 0) l.Add("\u25c6  uses the network: " + Online); if (Caution.Length > 0) l.Add("\u25b2  " + Caution); return string.Join("     \u00b7     ", l.ToArray()); } }
        public bool ReadOnly { get { return Writes.Length == 0 && Online.Length == 0 && Caution.Length == 0; } }
        public ToolInfo(string key, string panel, string title, string group, bool admin, bool guiOnly, string blurb, string about) { Key = key; Panel = panel; Title = title; Group = group; NeedsAdmin = admin; GuiOnly = guiOnly; Blurb = blurb; About = about; }
        /// <summary>A command-line-only tool (no panel): listed by the CLI and the console, skipped by the app's sidebar and About page.</summary>
        public ToolInfo(string key, string title, string group, bool admin, string blurb) { Key = key; Panel = "Cli-" + key; Title = title; Group = group; NeedsAdmin = admin; CliOnly = true; Blurb = blurb; About = blurb; }
    }

    /// <summary>The tools, in sidebar order. The GUI builds its sidebar and About page from this list; the CLI builds its command list and help from it, so both name the same things in the same order.</summary>
    public static class Tools
    {
        public const string RECON = "Recon & network", FILES = "Files & storage", VULN = "Vulnerabilities & software", HUNT = "Threat hunting & incident response", SECRETS = "Secrets & credentials", TOGETHER = "Putting it together", AUDIT = "Remote audit & reporting";
        public static readonly string[] Groups = { RECON, FILES, VULN, HUNT, SECRETS, TOGETHER, AUDIT };
        public static readonly List<ToolInfo> All = new List<ToolInfo>(new ToolInfo[] {
            new ToolInfo("recon", "ReconPanel", "System Recon & Audit", RECON, true, false,
                "A read-only security enumeration of this machine: system, users and groups, network, security posture, persistence surface, running processes and recent security events. Risky settings are flagged. Download the whole report as Markdown, JSON or PDF. For authorized use only.",
                "A read-only sweep of the machine — system, users and groups, network, security posture, persistence, processes and recent security events — flagging risky settings. Exports to Markdown, JSON or PDF."),
            new ToolInfo("blocker", "BlockerPanel", "Domain and IP Blocker", RECON, true, false,
                "Load domains and IPs from any file or paste, review them as rows, block or unblock the ones you pick. Domains go to the hosts file, IPs to one firewall rule; everything is tagged, backed up and reversible.",
                "Pull domains and IPs out of any file or paste, then block them via the hosts file and a firewall rule. Backs up the hosts file first; everything is reversible.") { Writes = "the hosts file and one outbound firewall rule (backed up, reversible)" },
            new ToolInfo("reachability", "ReachPanel", "Reachability Verifier", RECON, false, false,
                "Pull every IP and domain out of a file or a paste and check whether this machine can reach them: DNS, ping, and the TCP ports you choose. Send the ones that answer straight to the blocker.",
                "For each target: DNS, an optional ping, and a TCP connect to each port you list — to see what is reachable from here.") { Online = "DNS, ping and TCP connects go to every target you list" },
            new ToolInfo("connections", "ConnPanel", "Connections Monitor", RECON, false, false,
                "Every TCP and UDP endpoint this machine has open, live: process, ports, remote host and state. Closed connections linger greyed for a while. Block a remote address in two clicks.",
                "Every live TCP/UDP endpoint, refreshed each second: process, PID, addresses, state and remote host name. Block or copy the remote IPs."),
            new ToolInfo("network-map", "NetMapPanel", "Network Map", RECON, false, true,
                "This machine's live network connections on a world map. Every connection to a public address is geolocated and drawn as an animated arc — outbound and inbound in different colours. Hover a country to light it up, hover a connection for its ports and protocols.",
                "This machine’s live connections drawn on a world map: every connection to a public address is geolocated (opt-in) and shown as an animated arc, updated in real time.") { Online = "remote addresses go to ip-api.com for geolocation (opt-in, confirmed)" },
            new ToolInfo("firewall", "FirewallPanel", "Firewall Rules", RECON, false, false,
                "Every Windows Firewall rule as a sortable table, with the risky ones flagged: inbound Allow rules open to any address, rules that open all ports, or rules not tied to a program. The profile bar shows whether the firewall is actually on.",
                "Every Windows Firewall rule, with the risky inbound-allow rules flagged, plus whether the firewall is actually on for each profile."),
            new ToolInfo("resource-usage", "HogsPanel", "Resource Usage", FILES, false, false,
                "Which processes have used the most CPU time, memory and disk I/O since you opened this, not just right now. Exited processes stay in the table, greyed, because their totals still count.",
                "Which processes have used the most CPU time, memory and disk I/O since you opened the tool — plus, per process, the DLLs it has loaded and which are unsigned.") { Writes = "ends the processes you pick (confirmed)" },
            new ToolInfo("disk-usage", "DiskPanel", "Disk Usage", FILES, false, false,
                "Scan a drive or a folder and see where the space went: the folder tree with sizes, the largest files, the biggest folders, and what kinds of files they are. Open, copy or send the ones you pick to the Recycle Bin.",
                "Scan a drive or folder to see where the space went: the largest files, the biggest folders, the file types, and the folder tree with sizes.") { Writes = "moves the items you pick to the Recycle Bin (confirmed)" },
            new ToolInfo("deleted-files", "DeletedPanel", "Deleted Files Finder", FILES, true, false,
                "What was permanently deleted on each drive and whether it can come back: the NTFS change journal for C:, the directory tables of exFAT externals, shadow copies, and files emptied from the Recycle Bin. Recover the ones you pick to another drive.",
                "What was permanently deleted on each drive and whether it can come back, read from the NTFS journal and the exFAT directory table. Filter by type, name and size.") { Writes = "recovered files are copied to a drive you choose (confirmed)" },
            new ToolInfo("file-explorer", "FileExplorerPanel", "File Explorer", FILES, false, false,
                "Browse the machine, pick files across folders, and act on the whole selection at once: encrypt them with a password, decrypt them back, or destroy them for good with a permanent delete or a secure wipe. Encryption is AES-256; a lost password cannot be recovered.",
                "Browse the machine, pick files across folders, see each file's signature, and act on the whole selection — including AES-256 encrypt/decrypt and secure wipe.") { Writes = "encrypts, decrypts, deletes or wipes the files you pick (confirmed)" },
            new ToolInfo("find-files", "FindPanel", "Find Files", FILES, false, false,
                "Find files anywhere on the machine. By name: type a full or partial name, or a *.ext wildcard, and it streams matches as it walks the drives. By hash: paste one or more MD5, SHA-1 or SHA-256 hashes and it reports every file that matches, with a size cap so it stays fast.",
                "Find files anywhere by name (wildcards) or by hash (MD5/SHA-1/SHA-256), with a size cap on the hash sweep."),
            new ToolInfo("duplicates", "DupesPanel", "Duplicate Finder", FILES, false, false,
                "Find files whose contents are identical — grouped, with the space each group wastes. Compares by size first, then hashes only the files that could match, so it is fast. Keep one copy and send the rest to the Recycle Bin.",
                "Find files whose contents are identical and see how much space each group wastes. Keep one copy, recycle the rest.") { Writes = "sends the copies you pick to the Recycle Bin (confirmed)" },
            new ToolInfo("vulnerabilities", "VulnPanel", "Vulnerability Management", VULN, false, false,
                "Which CVEs this machine is exposed to and why: the OS build and installed hotfixes against Microsoft's monthly security releases, installed software against the NVD, and what Windows Update is offering right now. CISA's known-exploited list and EPSS rank the findings; every one shows its evidence.",
                "Which CVEs this machine is exposed to and why: the OS build and installed software matched against Microsoft's CVRF, the NVD, CISA KEV and EPSS.") { Online = "product names, versions and CVE ids go to Microsoft, the NVD, CISA and FIRST - each feed can be switched off" },
            new ToolInfo("software", "SoftwarePanel", "Software Inventory", VULN, false, false,
                "Every program installed on this machine and its version. Scan for CVEs to flag the vulnerable ones with their severity, worst CVE, whether it is known-exploited, and the version to upgrade to. Filter by anything — vulnerable only, severity, publisher, or any column.",
                "Every installed program and its version; scan to flag the vulnerable ones by severity, worst CVE, known-exploited status and the version to upgrade to.") { Online = "product names and versions go to the NVD when you scan for CVEs" },
            new ToolInfo("autoruns", "AutorunsPanel", "Autoruns", HUNT, true, false,
                "Every place Windows starts a program on its own: run keys, startup folders, scheduled tasks, services, Winlogon, image hijacks and WMI subscriptions. Each shows the program it runs, its signer and a risk flag. Disable or delete what you don't want.",
                "Every place Windows starts a program on its own — run keys, tasks, services, Winlogon, image hijacks, WMI subscriptions — with each program's signer and a risk flag. Disable or delete what you don't want.") { Writes = "disables, enables or deletes the autostart entries you pick (confirmed)" },
            new ToolInfo("events", "EventsPanel", "Event Log Triage", HUNT, true, false,
                "The event-log records that matter for an incident: failed and successful logons, new services and scheduled tasks, PowerShell activity, Defender detections, account changes and cleared logs. Pick a time range and hunt across every column.",
                "The security-relevant event-log records over a time range: logons and failures, new services and tasks, PowerShell activity, Defender detections, account changes and cleared logs."),
            new ToolInfo("checklist", "ChecklistPanel", "Security Checklist", HUNT, true, false,
                "A pass or fail review of the most common endpoint audit items: default and blank-password accounts, disk encryption, antivirus and EDR products with their state, remote-access and VPN tools, USB control and the firewall. Each check shows its evidence; export the whole report as Markdown, JSON or PDF.",
                "A pass/fail review of the common endpoint audit items — accounts, disk encryption, antivirus and EDR, remote access, USB, firewall — with an EICAR anti-malware test and an application-control policy read.") { Caution = "Active tests write the EICAR test file to your temp folder (opt-in, confirmed)" },
            new ToolInfo("secrets", "SecretsPanel", "Secrets Scanner", SECRETS, false, false,
                "Search a folder or drive for exposed secrets: private keys, cloud API keys, tokens and passwords sitting in .env and config files. Each hit shows the file, line and a masked preview — the whole secret is never put on screen.",
                "Search a folder or drive for exposed secrets — keys, tokens and passwords in config files — each shown with a masked preview."),
            new ToolInfo("credentials", "CredsPanel", "Wi-Fi & Credentials", SECRETS, false, false,
                "The secrets saved on this machine: Wi-Fi networks with their security type (weak ones flagged) and, when elevated, the stored key; plus the Windows Credential Manager vault. Revealing a Wi-Fi key or a stored secret is opt-in and confirmed.",
                "The secrets saved on this machine: Wi-Fi networks with their security (weak ones flagged) and, when elevated, the key; plus the Windows Credential Manager vault.") { Caution = "can show saved Wi-Fi keys and vault secrets in clear text (opt-in, confirmed)" },
            new ToolInfo("browsing", "BrowserPanel", "Browsing Data", SECRETS, false, false,
                "History, downloads, searches and saved passwords from every browser on this machine — Chrome, Edge, Brave and Firefox — read straight from their databases (including the Microsoft Store build of Firefox). The Domains view ranks every site by visits. Passwords stay masked until you reveal them.",
                "History, downloads, searches and saved passwords from every browser (Chrome, Edge, Brave, Firefox), read from their databases. Passwords stay masked until you reveal them.") { Caution = "can show saved browser passwords in clear text (opt-in, confirmed)" },
            new ToolInfo("findings-map", "MapPanel", "Findings Map", TOGETHER, false, true,
                "This machine at the centre of a live force-directed graph, wired to everything the tools found: users, network, software, autoruns, firewall, Wi-Fi, browsers, the security checklist and any vulnerabilities. Drag nodes, scroll to zoom, click to expand.",
                "This machine at the centre of a map, wired to what was found: users, network, software, checklist results and vulnerabilities. Click a node to expand."),
            new ToolInfo("collect", "Collect", AUDIT, false,
                "Run the read-only engines on this host and write everything they find into one sealed bundle (.ptb): inventory, checklist, recon, persistence, events, network, and - opt-in - secrets and an IOC sweep. No network unless asked; the same code is PowerTowerCollect.exe, the exe the remote audit stages on a target."),
            new ToolInfo("enrich", "Enrich", AUDIT, false,
                "Take a bundle collected offline and add the vulnerability findings on a connected box: Microsoft CVEs (MSRC, window widened to the host's patch level), third-party CVEs (NVD), CISA KEV and EPSS. Only product names, versions and CVE ids leave the machine."),
            new ToolInfo("feeds", "Feeds", AUDIT, false,
                "Export the downloaded vulnerability feeds as a feed pack, or import one, so an analyst box without internet can still enrich bundles."),
            new ToolInfo("report", "Report", AUDIT, false,
                "Turn an enriched bundle into the deliverables: Endpoint Hardening Audit, Endpoint Vulnerability Report and Compromise Assessment, as HTML, Markdown, CSV, JSON and PDF, with the framework mapping."),
            new ToolInfo("creds", "Credential store", AUDIT, false,
                "Manage the credential store (creds.ptv) for an engagement: add or replace an entry, list the labels and usernames, or remove one. The secret is read only from stdin (--secret-stdin) or an environment variable (--secret-env NAME), never from the command line, and is kept only inside the DPAPI- or passphrase-encrypted creds.ptv that remote-audit reads."),
            new ToolInfo("remote-audit", "Remote Audit (agentless)", AUDIT, false,
                "Run the read-only collector on remote Windows hosts over SMB+WMI with supplied admin credentials, pull the sealed bundle and leave nothing behind. Engagement scope and window are enforced before any credential is sent; one logon attempt per target (no lockout); the staged files are removed and the removal is verified; an append-only journal records every run. --preflight tests reachability only."),
            new ToolInfo("engagement", "Engagement", AUDIT, false,
                "Create and inspect an engagement file: scope, window, modules, retention, and the key pair bundles are sealed to (private half DPAPI-protected on this machine)."),
            new ToolInfo("about", "AboutPanel", "Home", "", false, false,
                "Start here: every tool by job, what each one reads or changes, and what needs administrator rights. A portable, read-mostly security workbench for this one machine — no installer, no services, no scripts.",
                ""),
        });
        public static ToolInfo ByPanel(string panelClass) { foreach (ToolInfo t in All) if (t.Panel == panelClass) return t; return null; }
        public static ToolInfo ByKey(string key) { if (key == null) return null; foreach (ToolInfo t in All) if (string.Equals(t.Key, key, StringComparison.OrdinalIgnoreCase)) return t; return null; }
        public static string Title(string panelClass) { ToolInfo t = ByPanel(panelClass); return t == null ? panelClass : t.Title; }
        public static string Blurb(string panelClass) { ToolInfo t = ByPanel(panelClass); return t == null ? "" : t.Blurb; }
        public static bool Admin(string panelClass) { ToolInfo t = ByPanel(panelClass); return t != null && t.NeedsAdmin; }
    }
}

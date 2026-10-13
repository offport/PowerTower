// The command-line side of every tool. Each one mirrors its panel: the same controls as options, the same
// summary cards, the same table (from Columns.cs), and the same selection-bar actions as flags that act on
// the ticked rows. Nothing here talks to the machine directly - it all goes through the shared engines.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;

namespace PSTools
{
    public static class CliTools
    {
        static Out.Toned T(string s, Tone t) { return Out.T(s, t); }
        static Tone GoodIfZero(int n) { return n > 0 ? Tone.Bad : Tone.Good; }
        static Tone WarnIfAny(int n) { return n > 0 ? Tone.Warn : Tone.Normal; }
        static string Plural(int n, string noun) { return n.ToString("N0") + " " + noun + (n == 1 ? "" : "s"); }
        static void RunOnThread(Action work, Action onCancel, Action poll)
        {
            Thread t = new Thread(delegate () { try { work(); } catch (Exception ex) { Out.Error(ex.Message); } }); t.IsBackground = true; t.Start();
            bool cancelled = false;
            while (t.IsAlive) { t.Join(250); if (poll != null) poll(); if (Cli.Cancelled && !cancelled) { cancelled = true; if (onCancel != null) onCancel(); } }
        }
        /// <summary>--md / --json / --pdf <file>: the app's Save Markdown… / Save JSON… / Save PDF… buttons. An empty value means "next to the exe, named like the app names it".</summary>
        static void SaveReports(Args a, string stem, Func<string> md, Func<string> json, Action<string> pdf)
        {
            foreach (string fmt in new string[] { "md", "json", "pdf" })
            {
                if (!a.Has(fmt)) continue; string path = a.Get(fmt, ""); if (path.Length == 0 || path == "auto") path = stem + "." + fmt;
                try
                {
                    if (fmt == "md") File.WriteAllText(path, md(), new UTF8Encoding(true)); else if (fmt == "json") File.WriteAllText(path, json(), new UTF8Encoding(false)); else pdf(path);
                    Out.Ok("saved " + Path.GetFullPath(path));
                }
                catch (Exception ex) { Out.Error("could not save " + path + ": " + ex.Message); }
            }
        }
        static void PrintLog(string title, IList<string> errors, IList<string> log)
        {
            Out.Blank(); Out.Line(title, Tone.Accent);
            if (errors.Count > 0) { Out.Line("LIMITED / UNAVAILABLE", Tone.Warn); foreach (string e in errors) Out.Line("  " + e, Tone.Warn); }
            Out.Line("LOG", Tone.Dim); foreach (string s in log) Out.Line("  " + s, Tone.Dim);
        }

        public static List<CliTool> All()
        {
            List<CliTool> l = new List<CliTool>();
            l.Add(new CliTool("recon").Opt("no-events", null, "skip the Security / System / PowerShell event logs (the app's 'recent event logs' toggle)").Opt("section", "name", "only this section, e.g. \"3. Network\" or just \"3.\"").Opt("flagged", null, "only the facts flagged risk or review").Opt("md", "file", "save the report as Markdown (no value: recon_<host>_<time>.md)").Opt("json", "file", "save the report as JSON").Opt("pdf", "file", "save the report as PDF").Opt("log", null, "print the audit log and what was limited")
                .Example("--flagged").Example("--section \"4.\" --view tree").Example("--where \"flag equals risk\" --csv risks.csv --md"));
            l[l.Count - 1].Run = Recon; l[l.Count - 1].Tables = delegate { return new List<TableDef>(new TableDef[] { Columns.Recon() }); };

            l.Add(new CliTool("blocker").Opt("file", "path", "add the domains and IPs found in this file (any text: lists, CSV, logs, defanged names); repeatable").Opt("add", "value", "add one domain or IP; repeatable").Opt("stdin", null, "add what is piped in").Opt("blocked", null, "show what is blocked right now instead of the loaded list (the 'Blocked now' button)").Opt("block", null, "block the ticked rows (or --all): domains to the hosts file, IPs to the firewall rule").Opt("unblock", null, "unblock the ticked rows (or --all)").Opt("no-hosts", null, "do not touch the hosts file").Opt("no-firewall", null, "do not touch the firewall rule").Opt("no-www", null, "do not add the www. variant of each domain").Opt("sink", "ip", "the address blocked domains resolve to (default from settings, else 0.0.0.0)").Opt("backups", null, "list the hosts-file backups").Opt("restore", "backup-file", "restore the hosts file from one of its backups").Opt("flush-dns", null, "flush the DNS cache after changing the hosts file")
                .Example("--file samples\\sample-blocklist.txt").Example("--file threats.txt --block --all").Example("--blocked --view tree").Example("--blocked --select \"kind equals domain\" --unblock"));
            l[l.Count - 1].Run = Blocker; l[l.Count - 1].Tables = delegate { return new List<TableDef>(new TableDef[] { Columns.BlockerLoaded(null), Columns.BlockerBlocked() }); };

            l.Add(new CliTool("reachability").Opt("file", "path", "targets from this file (any text); repeatable").Opt("add", "value", "one domain or IP; repeatable").Opt("stdin", null, "targets piped in").Opt("ports", "list", "TCP ports to connect to, comma-separated (default 80,443)").Opt("timeout", "seconds", "per-attempt timeout (default 3)").Opt("parallel", "n", "targets checked at once (default 32)").Opt("no-ping", null, "skip the ICMP ping").Opt("block", null, "send the ticked rows (or --all) to the blocker and block them")
                .Example("--add example.com --add 1.1.1.1 --ports 53,443").Example("--file targets.txt --where \"status equals reachable\" --csv reachable.csv").Example("--file targets.txt --select \"status equals reachable\" --block"));
            l[l.Count - 1].Run = Reachability; l[l.Count - 1].Tables = delegate { return new List<TableDef>(new TableDef[] { Columns.Reach(new int[] { 80, 443 }) }); };

            l.Add(new CliTool("connections").Opt("interval", "1|2|5", "seconds between refreshes (default 1)").Opt("duration", "seconds", "stop after this long (default: until Ctrl+C on a console, one snapshot when piped)").Opt("once", null, "one snapshot").Opt("tcp", null, "TCP only").Opt("udp", null, "UDP only").Opt("established", null, "established connections only").Opt("listening", null, "listening ports only").Opt("other", null, "other states only").Opt("loopback", null, "include loopback endpoints").Opt("no-resolve", null, "do not resolve remote host names").Opt("no-keep", null, "drop closed connections at once instead of keeping them 30 s").Opt("process", "name", "only processes whose name contains this").Opt("block", null, "after the snapshot, block the remote IPs of the ticked rows (or --all)")
                .Example("--once").Example("--established --process chrome --duration 20").Example("--once --where \"remote is not empty\" --csv now.csv"));
            l[l.Count - 1].Run = Connections; l[l.Count - 1].Tables = delegate { return new List<TableDef>(new TableDef[] { Columns.Connections() }); };

            l.Add(new CliTool("network-map")); l[l.Count - 1].Run = GuiOnly;

            CliTool col = new CliTool("collect"); foreach (string[] h in CollectOptions.Help) col.Opt(h[0], h[1], h[2]);
            col.Example("--plain --modules inventory,network").Example("--engagement C:\\eng\\acme.json --out C:\\eng\\ws01.ptb").Example("--pass \"long passphrase\" --ioc iocs.txt --modules inventory,persistence,network,ioc");
            l.Add(col); l[l.Count - 1].Run = Collect_;

            l.Add(new CliTool("enrich").Opt("in", "file", "the bundle to enrich (or give it as the first argument)").Opt("out", "file", "where to write the enriched bundle (default: <in>.enriched.ptb)")
                .Opt("pass", "passphrase", "the passphrase the bundle was sealed with; the output is sealed with it too").Opt("key", "file", "the engagement private key as RSA XML; the output is re-sealed to the same key pair").Opt("engagement", "file", "engagement.json: opens with the DPAPI-protected engagement.key beside it, re-seals to the engagement key").Opt("plain", null, "the bundle is unsealed; the output is written unsealed too")
                .Opt("cache", "folder", "the feed cache to use (default: the cache next to the exe)").Opt("offline", null, "never touch the network: use the feed pack as it is and fail on a feed that is not there").Opt("no-msrc", null, "skip Microsoft's monthly CVEs").Opt("no-nvd", null, "skip third-party software (NVD)").Opt("no-kev", null, "skip CISA KEV").Opt("no-epss", null, "skip EPSS")
                .Opt("months", "n", "the fewest MSRC releases to check; widened to the bundle's patch level, up to 36 (default from settings, else 3)").Opt("nvd-key", "key", "an NVD API key for faster third-party lookups").Opt("status", "open|all", "which findings to list (default open)").Opt("log", null, "print the enrichment log").Opt("json", "file", "also write the enriched bundle as pretty JSON, unsealed, for inspection")
                .Example("ws01.ptb --engagement C:\\eng\\acme.json").Example("--in ws01.ptb --pass \"long passphrase\" --offline --cache D:\\feedpack").Example("ws01.ptb --plain --status all --csv ws01-findings.csv"));
            l[l.Count - 1].Run = Enrich_; l[l.Count - 1].Tables = delegate { return new List<TableDef>(new TableDef[] { Columns.Findings() }); };

            l.Add(new CliTool("feeds").Opt("export", "folder", "copy every cached feed into this folder as a feed pack, with a manifest (name, size, SHA-256, time per file)").Opt("import", "folder", "copy a feed pack into the cache, keeping each file's original time; files whose SHA-256 does not match the manifest are refused")
                .Opt("cache", "folder", "the cache to export from or import into (default: the cache next to the exe)").Opt("no-verify", null, "import without checking the SHA-256s")
                .Example("").Example("--export D:\\feedpack-2026-10-13").Example("--import D:\\feedpack-2026-10-13 --cache C:\\analyst\\cache"));
            l[l.Count - 1].Run = Feeds_;

            l.Add(new CliTool("engagement").Opt("out", "folder", "new: where engagement.json and engagement.key are written (default: the current folder)").Opt("id", "id", "new: the engagement id, e.g. ENG-2026-014 (letters, digits, - _ .)").Opt("client", "name", "new: the client").Opt("operator", "name", "new: who runs it (default: you)")
                .Opt("scope", "list", "new: hosts, IPs or CIDRs that may be audited - repeatable or comma-separated; nothing outside it is ever touched").Opt("from", "utc", "new: the window opens (2026-10-01 or 2026-10-01T09:00Z)").Opt("to", "utc", "new: the window closes").Opt("modules", "list", "new: the modules a collector may run (default: every read-only module)")
                .Opt("retention", "days", "new: how long collected data is kept (default 90)").Opt("notes", "text", "new: free text").Opt("bits", "2048|3072|4096", "new: RSA key size (default 3072)").Opt("file", "file", "inspect / check: the engagement.json (or give it as the second argument)").Opt("host", "name or ip", "check: is this target in scope right now?")
                .Example("new --out C:\\eng\\acme --id ENG-2026-014 --client Acme --scope 10.0.0.0/24,ws-fin-01 --from 2026-10-01 --to 2026-10-31").Example("inspect C:\\eng\\acme\\engagement.json").Example("check C:\\eng\\acme\\engagement.json --host 10.0.0.205"));
            l[l.Count - 1].Run = Engagement_;

            l.Add(new CliTool("firewall").Opt("inbound", null, "inbound rules only").Opt("outbound", null, "outbound rules only").Opt("risky", null, "flagged rules only").Opt("enabled", null, "enabled rules only")
                .Example("--risky").Example("--inbound --enabled --where \"action equals allow\" --sort name"));
            l[l.Count - 1].Run = Firewall_; l[l.Count - 1].Tables = delegate { return new List<TableDef>(new TableDef[] { Columns.FirewallRules() }); };

            l.Add(new CliTool("resource-usage").Opt("interval", "1|2|5", "seconds between samples (default 1)").Opt("duration", "seconds", "stop after this long (default: until Ctrl+C on a console, one sample when piped)").Opt("once", null, "one sample (two readings a second apart)").Opt("by-pid", null, "one row per process instead of grouping by name").Opt("modules", "pid", "list the DLLs loaded in one process with their signatures (Loaded modules…)").Opt("end", null, "end the ticked processes (or --all): a kill, nothing is saved")
                .Example("--once --top 15").Example("--by-pid --duration 30 --sort mem --desc").Example("--modules 4312"));
            l[l.Count - 1].Run = ResourceUsage; l[l.Count - 1].Tables = delegate { return new List<TableDef>(new TableDef[] { Columns.Processes(), Columns.Modules("process") }); };

            l.Add(new CliTool("disk-usage").Opt("path", "drive-or-folder", "what to scan (default: the first fixed drive)").Opt("min-mb", "n", "only files at least this big are kept in the largest-files list (default 50)").Opt("show", "files|folders|types", "largest files, folders, or file types (default files)").Opt("recycle", null, "move the ticked rows (or --all) to the Recycle Bin")
                .Example("--path D:\\ --show folders --view tree").Example("--path C:\\Users --show types").Example("--path C:\\Temp --select \"size at least 1 GB\" --recycle"));
            l[l.Count - 1].Run = DiskUsage; l[l.Count - 1].Tables = delegate { return new List<TableDef>(new TableDef[] { Columns.DiskNodes(false, delegate { return ""; }), Columns.DiskNodes(true, delegate { return ""; }), Columns.DiskTypes(delegate { return 1L; }) }); };

            l.Add(new CliTool("deleted-files").Opt("drives", "letters", "drives to scan, e.g. C,E (default: every NTFS and exFAT drive)").Opt("days", "n", "how far back (default 30)").Opt("under", "path", "only entries under this folder").Opt("type", "list", "only these extensions, e.g. jpg,png,docx").Opt("name", "text", "only names containing this").Opt("min", "n", "minimum size in --unit (exFAT only; the journal records no size)").Opt("max", "n", "maximum size in --unit").Opt("unit", "KB|MB|GB", "the unit of --min and --max (default MB)").Opt("noise", null, "include temp files, caches and other noise").Opt("no-shadows", null, "do not look for copies in shadow copies").Opt("source", "all|journal|exfat", "which source to show (default all)").Opt("recoverable", null, "recoverable entries only").Opt("recover-to", "folder", "copy the ticked recoverable files (or --all) into this folder, on another drive")
                .Example("--days 7").Example("--drives E --type jpg,mp4 --recoverable").Example("--drives E --select \"recoverable equals yes\" --recover-to D:\\recovered"));
            l[l.Count - 1].Run = DeletedFiles; l[l.Count - 1].Tables = delegate { return new List<TableDef>(new TableDef[] { Columns.Deleted() }); };

            l.Add(new CliTool("file-explorer").Opt("path", "folder", "the folder to list (default: your profile)").Opt("hidden", null, "show hidden and system entries").Opt("encrypt", null, "encrypt the ticked files with a password to .enc and delete the originals").Opt("decrypt", null, "decrypt the ticked .enc files next to themselves").Opt("password", "text", "the password for --encrypt / --decrypt (asked for when omitted)").Opt("delete", null, "permanently delete the ticked entries (bypasses the Recycle Bin)").Opt("wipe", null, "overwrite the ticked entries with random data, then delete them").Opt("new-folder", "name", "create a folder here first")
                .Example("--path C:\\Users\\alice\\Documents").Example("--path .\\drafts --select \"type equals docx\" --encrypt").Example("--path .\\drafts --select \"name ends with .enc\" --decrypt"));
            l[l.Count - 1].Run = FileExplorer; l[l.Count - 1].Tables = delegate { return new List<TableDef>(new TableDef[] { Columns.Folder() }); };

            l.Add(new CliTool("find-files").Opt("name", "pattern", "search by name: a full or partial name, or a *.ext wildcard").Opt("hash", "hashes", "search by hash: MD5, SHA-1 or SHA-256, several separated by spaces; repeatable").Opt("hash-file", "path", "read hashes out of any text file (lists, CSV, IOC reports)").Opt("in", "root", "where to search; repeatable (default: every fixed drive)").Opt("match-case", null, "case-sensitive name match").Opt("max-mb", "n", "skip files bigger than this when hashing (default 100)").Opt("include-windows", null, "hash inside the Windows folder too")
                .Example("--name *.pfx").Example("--name invoice --in C:\\Users --match-case").Example("--hash-file iocs.txt --in D:\\ --csv hits.csv"));
            l[l.Count - 1].Run = FindFiles; l[l.Count - 1].Tables = delegate { return new List<TableDef>(new TableDef[] { Columns.FindByName(), Columns.FindByHash() }); };

            l.Add(new CliTool("duplicates").Opt("path", "folder", "the folder to scan (default: your profile)").Opt("min", "size", "ignore files smaller than this, e.g. 1KB, 100KB, 1MB, 10MB (default 100KB)").Opt("recycle", null, "send the ticked files (or --all) to the Recycle Bin").Opt("recycle-extras", null, "send every extra copy to the Recycle Bin, keeping the oldest of each group")
                .Example("--path D:\\Photos --min 1MB").Example("--path D:\\Photos --view tree").Example("--path D:\\Photos --recycle-extras"));
            l[l.Count - 1].Run = Duplicates; l[l.Count - 1].Tables = delegate { return new List<TableDef>(new TableDef[] { Columns.Duplicates() }); };

            l.Add(new CliTool("vulnerabilities").Opt("show", "findings|missing|software|hotfixes", "which table (default findings)").Opt("no-wua", null, "skip Windows Update").Opt("no-msrc", null, "skip Microsoft's monthly CVEs").Opt("no-nvd", null, "skip third-party software (NVD)").Opt("no-kev", null, "skip CISA KEV").Opt("no-epss", null, "skip EPSS").Opt("months", "n", "the fewest monthly MSRC releases to check, newest first; the scan widens this to the host's patch level, up to 36 (default from settings, else 3)").Opt("nvd-key", "key", "an NVD API key (saved to settings.ini like the app does)").Opt("severity", "critical|high|medium", "findings at least this severe").Opt("status", "open|all|vulnerable|update available|reboot pending|patched|unconfirmed", "finding status (default open)").Opt("source", "MSRC|NVD|Windows Update", "finding source").Opt("exploited", null, "known-exploited findings only").Opt("feeds", null, "list the cached feed files and stop").Opt("clear-feeds", null, "delete the cached feeds and stop").Opt("log", null, "print the scan log")
                .Example("").Example("--show software --where \"cves greater than 0\"").Example("--status all --source MSRC --csv msrc.csv").Example("--no-wua --no-nvd --months 6 --exploited"));
            l[l.Count - 1].Run = Vulnerabilities; l[l.Count - 1].Tables = delegate { return new List<TableDef>(new TableDef[] { Columns.Findings(), Columns.MissingUpdates(), Columns.VulnSoftware(), Columns.Hotfixes() }); };

            l.Add(new CliTool("software").Opt("scan", null, "look the mapped programs up on the NVD and flag the vulnerable ones").Opt("nvd-key", "key", "an NVD API key (saved to settings.ini)").Opt("no-kev", null, "skip CISA KEV").Opt("no-epss", null, "skip EPSS").Opt("severity", "critical|high|medium", "programs whose worst CVE is at least this severe").Opt("vulnerable", null, "vulnerable programs only").Opt("exploited", null, "known-exploited only").Opt("mapped", null, "only programs in the CVE product map")
                .Example("").Example("--scan --vulnerable").Example("--scan --select \"vulnerable equals vulnerable\" --csv vulnerable.csv"));
            l[l.Count - 1].Run = Software; l[l.Count - 1].Tables = delegate { return new List<TableDef>(new TableDef[] { Columns.Software() }); };

            l.Add(new CliTool("autoruns").Opt("kind", "name", "one kind only, e.g. \"Run key\", \"Scheduled task\", Service").Opt("risky", null, "flagged entries only").Opt("unsigned", null, "unsigned or invalid signatures only").Opt("non-microsoft", null, "hide Microsoft-signed entries").Opt("disable", null, "disable the ticked entries").Opt("enable", null, "enable the ticked entries").Opt("delete", null, "delete the ticked entries for good")
                .Example("--risky").Example("--non-microsoft --view tree").Example("--select \"name equals backup-helper.exe\" --disable"));
            l[l.Count - 1].Run = Autoruns_; l[l.Count - 1].Tables = delegate { return new List<TableDef>(new TableDef[] { Columns.Autoruns() }); };

            l.Add(new CliTool("events").Opt("since", "1h|24h|7d|30d", "how far back (default 24h)").Opt("max", "50|100|250|500", "records per category (default 100)").Opt("category", "name", "one category only").Opt("risky", null, "flagged events only")
                .Example("--since 7d --risky").Example("--category \"Failed logon\" --view tree").Example("--since 30d --csv events.csv"));
            l[l.Count - 1].Run = Events_; l[l.Count - 1].Tables = delegate { return new List<TableDef>(new TableDef[] { Columns.Events() }); };

            l.Add(new CliTool("checklist").Opt("category", "name", "one category only").Opt("show", "everything|failures|fail|review|pass|info", "which results (default everything)").Opt("active", null, "also run the two active tests: the EICAR file drop and the application-control policy read (your antivirus will react on purpose)").Opt("md", "file", "save the report as Markdown").Opt("json", "file", "save the report as JSON").Opt("pdf", "file", "save the report as PDF").Opt("log", null, "print the run log")
                .Example("").Example("--show failures --view tree").Example("--active --md --pdf"));
            l[l.Count - 1].Run = Checklist; l[l.Count - 1].Tables = delegate { return new List<TableDef>(new TableDef[] { Columns.Checklist() }); };

            l.Add(new CliTool("secrets").Opt("path", "folder", "the folder to scan (default: your profile)").Opt("max-kb", "256|1024|4096", "skip files bigger than this (default 1024)").Opt("severity", "high|medium", "high only, or medium and up").Opt("writable", null, "hits in user-writable locations only")
                .Example("--path C:\\projects").Example("--path C:\\projects --severity high --csv secrets.csv"));
            l[l.Count - 1].Run = Secrets_; l[l.Count - 1].Tables = delegate { return new List<TableDef>(new TableDef[] { Columns.Secrets() }); };

            l.Add(new CliTool("credentials").Opt("show", "wifi|vault", "saved Wi-Fi networks or the Credential Manager vault (default wifi)").Opt("reveal", null, "show the Wi-Fi keys / a masked preview of vault secrets (confirmed, as in the app)")
                .Example("").Example("--reveal --csv wifi.csv").Example("--show vault --view tree"));
            l[l.Count - 1].Run = Credentials; l[l.Count - 1].Tables = delegate { return new List<TableDef>(new TableDef[] { Columns.Wifi(delegate { return false; }), Columns.Vault(delegate { return false; }) }); };

            l.Add(new CliTool("browsing").Opt("show", "history|domains|downloads|searches|passwords", "which table (default history)").Opt("browser", "label", "one browser profile whose label contains this, e.g. Chrome, Edge, Firefox").Opt("max", "1000|5000|20000|all", "history rows per profile (default 5000)").Opt("insecure", null, "http (not https) rows only").Opt("reveal", null, "decrypt and show the saved passwords (confirmed, as in the app)")
                .Example("--show domains --top 25").Example("--show downloads --browser Edge").Example("--show passwords --reveal --csv logins.csv"));
            l[l.Count - 1].Run = Browsing; l[l.Count - 1].Tables = delegate { return new List<TableDef>(new TableDef[] { Columns.BrowserHistory(), Columns.BrowserDomains(new List<DomainStat>()), Columns.BrowserDownloads(), Columns.BrowserSearches(), Columns.BrowserPasswords(delegate { return false; }) }); };

            l.Add(new CliTool("findings-map")); l[l.Count - 1].Run = GuiOnly;
            l.Add(new CliTool("about")); l[l.Count - 1].Run = About;
            return l;
        }

        static int GuiOnly(Args a)
        {
            ToolInfo t = Tools.ByKey(a.Tool) ?? Tools.ByPanel("MapPanel"); Out.Header(t);
            Out.Line("This tool is visual and lives in the desktop app only: open PowerTower.exe and pick " + t.Title + " in the sidebar.", Tone.Warn);
            return Cli.OK;
        }
        static int About(Args a)
        {
            Out.Line("▌ POWERTOWER · ABOUT & GUIDE", Tone.Accent);
            Out.Line(Out.Wrap("A portable security workbench for this machine. Every job is a table you can sort, search, filter by any column, tick and act on. In the desktop app that is the grid, the search box, the Filter bar and the checkboxes; here it is --view, --search, --where, --select and the action flags - the same names, the same columns, the same order of tools.", Out.ConsoleWidth() - 2, "  "), Tone.Dim); Out.Blank();
            foreach (string grp in Tools.Groups)
            {
                Out.Line(grp, Tone.Accent);
                foreach (ToolInfo t in Tools.All) { if (t.Group != grp) continue; Out.Write("  " + t.Key.PadRight(16), Tone.Normal); Out.Line(t.Title + (t.GuiOnly ? "   (desktop app only)" : t.NeedsAdmin ? "   (administrator for some actions)" : ""), t.GuiOnly ? Tone.Faint : Tone.Normal); Out.Line(Out.Wrap(t.About, Out.ConsoleWidth() - 20, "                    "), Tone.Dim); }
                Out.Blank();
            }
            Out.Line("the app's view bar, as options", Tone.Accent);
            string[][] map = { new string[] { "Grid / Details / Tree", "--view grid|details|tree" }, new string[] { "search box", "--search <text>" }, new string[] { "click a column header", "--sort <column> [--desc]" }, new string[] { "Filter → add rule", "--where \"<column> <op> <value>\" (repeat)" }, new string[] { "tick rows / Select all", "--select \"<column> <op> <value>\" / --all" }, new string[] { "the bar under the rows", "the tool's action flags, e.g. --block, --recover-to, --disable" }, new string[] { "Export CSV…", "--csv <file>" }, new string[] { "Yes in a confirmation", "--yes" } };
            foreach (string[] m in map) { Out.Write("  " + m[0].PadRight(26), Tone.Dim); Out.Line(m[1], Tone.Normal); }
            Out.Blank(); Out.Line("Self-contained C#: nothing runs through powershell.exe, nothing is installed, and the only network traffic is the vulnerability feeds, each of which can be switched off. Settings and the feed cache are shared with the desktop app (settings.ini and cache\\ next to the exe).", Tone.Dim);
            return Cli.OK;
        }

        // ═══════════════════════════════ System Recon & Audit ═══════════════════════════════
        static int Recon(Args a)
        {
            ToolInfo info = Tools.ByKey("recon"); Out.Header(info);
            if (!Cli.IsElevated) Out.Warn("Running without administrator rights: the Security event log, BitLocker and some settings will be limited.");
            ReconScan s = new ReconScan(); s.DoEvents = !a.Has("no-events"); Throttle th = new Throttle(150);
            s.Progress += delegate (string m) { th.Say(m); }; s.Step += delegate (string label, string state, string note) { if (state == "running") Out.Note("· " + label); };
            RunOnThread(s.Run, delegate { s.Cancel = true; }, null);
            ReconReport r = s.Report;
            Out.Cards("OS", r.Os, "host", r.Host, "elevated", T(r.Elevated ? "yes" : "no", r.Elevated ? Tone.Good : Tone.Warn), "sections", r.Sections().Count, "facts", r.Items.Count, "to review", T(r.Warn.ToString(), WarnIfAny(r.Warn)), "risks", T(r.Bad.ToString(), GoodIfZero(r.Bad)));
            View v = new View(Columns.Recon()); string section = a.Get("section", null); bool flagged = a.Has("flagged");
            v.Filter = delegate (object o) { ReconItem i = (ReconItem)o; if (section != null && !i.Section.StartsWith(section, StringComparison.OrdinalIgnoreCase)) return false; if (flagged && i.Risk != "warn" && i.Risk != "bad") return false; return true; };
            v.Configure(a); v.Set(Cli.Boxed(s.Snapshot())); v.Show(a);
            SaveReports(a, r.FileStem, r.ToMarkdown, r.ToJson, r.SavePdf);
            if (a.Has("log")) PrintLog("audit log", s.Errors, s.LogSnapshot());
            else if (s.Errors.Count > 0) Out.Warn(s.Errors.Count + " section(s) were limited - add --log to see which.");
            return Cli.Cancelled ? Cli.CANCELLED : Cli.OK;
        }

        // ═══════════════════════════════ Domain and IP Blocker ═══════════════════════════════
        /// <summary>The blocker's state and actions, shared with the tools that send rows to it (reachability, connections).</summary>
        class BlockerCli
        {
            public readonly Hosts hosts = new Hosts(); public readonly HashSet<string> hostsBlocked = new HashSet<string>(StringComparer.OrdinalIgnoreCase), fwBlocked = new HashSet<string>(StringComparer.OrdinalIgnoreCase); public readonly List<BlockItem> blocked = new List<BlockItem>(); public string HostsError = "";
            public void Refresh()
            {
                hostsBlocked.Clear(); fwBlocked.Clear(); blocked.Clear(); HostsError = "";
                try { foreach (HostsEntry e in hosts.Entries(false)) { hostsBlocked.Add(e.Host); BlockItem b = new BlockItem(); b.Value = e.Host; b.Kind = Kind.Domain; b.Where = "hosts file"; b.Note = "→ " + e.Sink + " · line " + e.LineNo; b.BlockedHosts = true; blocked.Add(b); } } catch (Exception ex) { HostsError = "hosts file: " + ex.Message; }
                foreach (string ip in Firewall.GetBlocked()) { fwBlocked.Add(ip); BlockItem b = new BlockItem(); b.Value = ip; b.Kind = Extractor.Classify(ip); b.Where = "firewall"; b.Note = "outbound block · rule '" + Firewall.RuleName + "'"; b.BlockedFw = true; blocked.Add(b); }
            }
            public void Classify(BlockItem b) { b.BlockedHosts = b.Kind == Kind.Domain && (hostsBlocked.Contains(b.Value) || hostsBlocked.Contains("www." + b.Value)); b.BlockedFw = (b.Kind == Kind.IPv4 || b.Kind == Kind.IPv6) && fwBlocked.Contains(b.Value); }
            public List<BlockItem> Load(IEnumerable<string> lines, string origin)
            {
                List<BlockItem> l = new List<BlockItem>(); HashSet<string> have = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (Target t in Extractor.Extract(lines)) { if (!have.Add(t.Value)) continue; BlockItem b = new BlockItem(); b.Value = t.Value; b.Kind = t.Kind; b.Source = t.Source; b.Line = t.Line; b.Note = origin; Classify(b); l.Add(b); }
                return l;
            }
            public string Status() { return hostsBlocked.Count + " domain(s) in the hosts file · " + fwBlocked.Count + " IP(s) in the firewall rule" + (Firewall.Available() ? "" : " · firewall API unavailable") + (HostsError.Length > 0 ? " · " + HostsError : ""); }
            /// <summary>Block selected: domains to the hosts file, IPs to the firewall rule, after the same confirmation the app shows.</summary>
            public int Block(List<BlockItem> items, Args a)
            {
                bool doHosts = !a.Has("no-hosts"), doFw = !a.Has("no-firewall"), www = !a.Has("no-www");
                List<string> domains = new List<string>(), ips = new List<string>();
                foreach (BlockItem b in items) { if (b.Kind == Kind.Domain && doHosts && !b.BlockedHosts) domains.Add(b.Value); if ((b.Kind == Kind.IPv4 || b.Kind == Kind.IPv6) && doFw && !b.BlockedFw) ips.Add(b.Value); }
                if (www) domains = Extractor.ExpandDomains(domains);
                if (domains.Count == 0 && ips.Count == 0) { Out.Warn("Nothing to block: pick rows that are not blocked yet, and check what goes where."); return Cli.OK; }
                string sink = a.Get("sink", Cli.S.Get("block.sink", "0.0.0.0")).Trim(); if (sink.Length == 0) sink = "0.0.0.0";
                string msg = domains.Count + " domain(s) → hosts file → " + sink + (domains.Count > 0 ? ": " + Cli.Preview(domains, 10) : "") + "\n" + ips.Count + " IP(s) → firewall outbound block rule '" + Firewall.RuleName + "'" + (ips.Count > 0 ? ": " + Cli.Preview(ips, 10) : "") + "\nThe hosts file is backed up first. Everything can be undone with --blocked --unblock.";
                if (!Cli.Confirm(a, "Block " + (domains.Count + ips.Count) + " item(s)?", msg)) return Cli.CANCELLED;
                if (Cli.NeedAdmin("Writing the hosts file and the firewall rule")) return Cli.ADMIN;
                try
                {
                    if (domains.Count > 0) { Hosts.AddResult r = hosts.Add(domains, sink); Out.Ok("hosts file: added " + r.Added + ", skipped " + r.Skipped + " already present · backup " + Path.GetFileName(r.Backup)); }
                    if (ips.Count > 0) { List<string> cur = Firewall.GetBlocked(); int before = cur.Count; foreach (string ip in ips) if (!cur.Contains(ip)) cur.Add(ip); Firewall.SetBlocked(cur); Out.Ok("firewall: added " + (cur.Count - before) + ", the rule now holds " + cur.Count + " address(es)"); }
                    Out.Note("Browsers cache DNS: add --flush-dns, or restart the browser, to apply immediately.");
                    if (a.Has("flush-dns")) FlushDns();
                    Refresh(); Cli.S.Set("block.sink", sink); Cli.S.Save(); return Cli.OK;
                }
                catch (Exception ex) { Refresh(); Out.Error("Blocking stopped: " + ex.Message + (ex.Message.IndexOf("denied", StringComparison.OrdinalIgnoreCase) >= 0 ? " - if this is denied even as administrator, security software may be protecting the hosts file (Defender tamper protection / controlled folder access)." : "")); return Cli.PROBLEMS; }
            }
            public int Unblock(List<BlockItem> items, Args a)
            {
                List<string> domains = new List<string>(), ips = new List<string>();
                foreach (BlockItem b in items) { if (b.Kind == Kind.Domain) { domains.Add(b.Value); domains.Add("www." + b.Value); } else if (b.Kind != Kind.Invalid) ips.Add(b.Value); }
                if (!Cli.Confirm(a, "Unblock " + items.Count + " item(s)?", "Only lines this tool added (tagged " + Hosts.Marker + ") are removed from the hosts file; the addresses are taken out of the firewall rule. The hosts file is backed up first.")) return Cli.CANCELLED;
                if (Cli.NeedAdmin("Writing the hosts file and the firewall rule")) return Cli.ADMIN;
                try
                {
                    if (domains.Count > 0) { Hosts.RemoveResult r = hosts.Remove(domains); Out.Ok("hosts file: removed " + r.Removed + " line(s) · backup " + Path.GetFileName(r.Backup)); }
                    if (ips.Count > 0) { List<string> cur = Firewall.GetBlocked(); int before = cur.Count; cur.RemoveAll(delegate (string s) { return ips.Contains(s); }); Firewall.SetBlocked(cur); Out.Ok("firewall: removed " + (before - cur.Count) + ", " + cur.Count + " remain" + (cur.Count == 0 ? " (rule removed)" : "")); }
                    if (a.Has("flush-dns")) FlushDns();
                    Refresh(); return Cli.OK;
                }
                catch (Exception ex) { Refresh(); Out.Error("Unblocking stopped: " + ex.Message); return Cli.PROBLEMS; }
            }
            public static void FlushDns() { try { ProcessStartInfo si = new ProcessStartInfo("ipconfig.exe", "/flushdns"); si.UseShellExecute = false; si.CreateNoWindow = true; Process.Start(si).WaitForExit(); Out.Ok("DNS cache flushed."); } catch (Exception ex) { Out.Warn("flush failed: " + ex.Message); } }
        }
        static int Blocker(Args a)
        {
            ToolInfo info = Tools.ByKey("blocker"); Out.Header(info);
            BlockerCli bl = new BlockerCli(); bl.Refresh();
            if (a.Has("backups"))
            {
                List<FileInfo> b = bl.hosts.Backups(); Out.Line(b.Count == 0 ? "No backups yet. One is taken before every change." : "Every change backs the hosts file up here first: " + bl.hosts.BackupDir, Tone.Dim);
                foreach (FileInfo fi in b) Out.Line("  " + fi.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss") + "   " + fi.Length.ToString("N0").PadLeft(8) + " bytes   " + fi.Name, Tone.Normal);
                return Cli.OK;
            }
            string restore = a.Get("restore", null);
            if (restore != null)
            {
                if (!File.Exists(restore)) { string inDir = Path.Combine(bl.hosts.BackupDir, restore); if (File.Exists(inDir)) restore = inDir; else throw new UsageException("--restore: no such backup: " + restore); }
                if (!Cli.Confirm(a, "Restore the hosts file?", "Overwrite the current hosts file with " + Path.GetFileName(restore) + " from " + File.GetLastWriteTime(restore) + "? The current file is backed up first, so this is undoable. Firewall IPs are not affected.")) return Cli.CANCELLED;
                if (Cli.NeedAdmin("Writing the hosts file")) return Cli.ADMIN;
                try { string safety = bl.hosts.Restore(restore); Out.Ok("Hosts file restored from " + Path.GetFileName(restore) + ". The previous state was saved as " + Path.GetFileName(safety) + "."); if (a.Has("flush-dns")) BlockerCli.FlushDns(); return Cli.OK; } catch (Exception ex) { Out.Error("Restore failed: " + ex.Message); return Cli.PROBLEMS; }
            }
            if (a.Has("blocked"))
            {
                Out.Cards("loaded list", "0", "blocked now", bl.blocked.Count, "status", bl.Status());
                View v = new View(Columns.BlockerBlocked()); v.Configure(a); v.Set(Cli.Boxed(bl.blocked)); v.Show(a);
                if (a.Has("unblock")) { List<object> t = Cli.ActionTargets(v, a, "--unblock"); if (t == null) return Cli.USAGE; if (t.Count == 0) return Cli.OK; List<BlockItem> items = new List<BlockItem>(); foreach (object o in t) items.Add((BlockItem)o); return bl.Unblock(items, a); }
                if (a.Has("flush-dns")) BlockerCli.FlushDns();
                return Cli.OK;
            }
            string origin; List<string> lines = Cli.InputLines(a, out origin);
            if (lines.Count == 0 && !a.Has("flush-dns")) { Out.Line("Give it a list: --file <path>, --add <value> or --stdin (URLs, log lines, CSV and defanged evil[.]com forms are all understood); or --blocked to see what is blocked now.", Tone.Warn); return Cli.USAGE; }
            List<BlockItem> loaded = bl.Load(lines, origin);
            Out.Cards("loaded list", loaded.Count, "blocked now", bl.blocked.Count, "status", bl.Status());
            View lv = new View(Columns.BlockerLoaded(bl.Classify)); lv.Configure(a); lv.Set(Cli.Boxed(loaded)); lv.Show(a);
            if (a.Has("block") || a.Has("unblock"))
            {
                List<object> t = Cli.ActionTargets(lv, a, a.Has("block") ? "--block" : "--unblock"); if (t == null) return Cli.USAGE; if (t.Count == 0) return Cli.OK;
                List<BlockItem> items = new List<BlockItem>(); foreach (object o in t) items.Add((BlockItem)o);
                int rc = a.Has("block") ? bl.Block(items, a) : bl.Unblock(items, a);
                if (rc == Cli.OK) { foreach (BlockItem b in loaded) bl.Classify(b); Out.Blank(); Out.Line("after the change:", Tone.Dim); lv.Refresh(); lv.Show(a); }
                return rc;
            }
            if (a.Has("flush-dns")) BlockerCli.FlushDns();
            return Cli.OK;
        }
        /// <summary>"Send to blocker" from another tool: the values become a loaded list and are blocked.</summary>
        static int SendToBlocker(List<string> values, string origin, Args a)
        {
            if (values.Count == 0) { Out.Warn("The selected rows have no address to block."); return Cli.OK; }
            BlockerCli bl = new BlockerCli(); bl.Refresh(); List<BlockItem> items = bl.Load(values, origin);
            Out.Blank(); Out.Line("→ Domain and IP Blocker: " + items.Count + " item(s) from the " + origin, Tone.Accent);
            return bl.Block(items, a);
        }

        // ═══════════════════════════════ Reachability Verifier ═══════════════════════════════
        static int Reachability(Args a)
        {
            ToolInfo info = Tools.ByKey("reachability"); Out.Header(info);
            string origin; List<string> lines = Cli.InputLines(a, out origin);
            if (lines.Count == 0) { Out.Line("Give it targets: --file <path>, --add <value> or --stdin.", Tone.Warn); return Cli.USAGE; }
            List<int> ports = new List<int>(); foreach (string s in a.Get("ports", "80, 443").Split(new char[] { ',', ' ', ';' }, StringSplitOptions.RemoveEmptyEntries)) { int p; if (int.TryParse(s.Trim(), out p) && p > 0 && p < 65536 && !ports.Contains(p)) ports.Add(p); }
            List<ReachRow> rows = new List<ReachRow>(); HashSet<string> have = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (Target t in Extractor.Extract(lines)) { if (!have.Add(t.Value)) continue; ReachRow r = new ReachRow(); r.Target = t; r.Status = "checking"; rows.Add(r); }
            if (rows.Count == 0) { Out.Warn("No domains or IPs were found in the input."); return Cli.OK; }
            Reach e = new Reach(); e.Ports = ports.ToArray(); e.TimeoutSec = Math.Max(1, Math.Min(30, a.Dbl("timeout", 3))); e.Concurrency = Math.Max(1, Math.Min(256, a.Int("parallel", 32))); e.DoPing = !a.Has("no-ping");
            ManualResetEvent done = new ManualResetEvent(false); Throttle th = new Throttle(200);
            e.Progress += delegate (int d, int t) { th.Say("checking " + d + " / " + t); }; e.Finished += delegate { done.Set(); };
            Out.Note("checking " + rows.Count + " target(s) on TCP " + string.Join(",", Array.ConvertAll(e.Ports, delegate (int p) { return p.ToString(); })) + (e.DoPing ? " + ping" : "") + " · timeout " + e.TimeoutSec + " s · " + e.Concurrency + " parallel");
            e.Run(new List<ReachRow>(rows)); bool finished = Cli.Wait(done, e.Cancel);
            int ok = 0; foreach (ReachRow r in rows) if (r.Status == "reachable") ok++;
            Out.Cards("targets", rows.Count, "reachable", T(ok.ToString(), ok > 0 ? Tone.Good : Tone.Dim), "result", finished ? "done" : "cancelled");
            View v = new View(Columns.Reach(e.Ports)); v.Configure(a); v.Set(Cli.Boxed(rows)); v.Show(a);
            if (a.Has("block")) { List<object> t = Cli.ActionTargets(v, a, "--block"); if (t == null) return Cli.USAGE; List<string> vals = new List<string>(); foreach (object o in t) vals.Add(((ReachRow)o).Value); return SendToBlocker(vals, "reachability check", a); }
            return finished ? Cli.OK : Cli.CANCELLED;
        }

        // ═══════════════════════════════ Connections Monitor ═══════════════════════════════
        static bool LiveMode(Args a) { return !a.Has("once") && (a.Has("duration") || !Console.IsOutputRedirected); }
        static void LiveSleep(int seconds, DateTime end) { DateTime until = DateTime.Now.AddSeconds(seconds); while (DateTime.Now < until && !Cli.Cancelled && DateTime.Now < end) Thread.Sleep(100); }
        static void ClearForRedraw() { if (!Console.IsOutputRedirected) { try { Console.Clear(); } catch { } } else Out.Blank(); }
        static int Connections(Args a)
        {
            ToolInfo info = Tools.ByKey("connections");
            int interval = int.Parse(a.Choice("interval", "1", "1", "2", "5")); bool live = LiveMode(a); double dur = a.Dbl("duration", 0); DateTime end = dur > 0 ? DateTime.Now.AddSeconds(dur) : DateTime.MaxValue;
            bool tcpOnly = a.Has("tcp") && !a.Has("udp"), udpOnly = a.Has("udp") && !a.Has("tcp"), loop = a.Has("loopback"), resolve = !a.Has("no-resolve"), keep = !a.Has("no-keep"); string proc = a.Get("process", "").Trim();
            int stateMode = a.Has("established") ? 1 : a.Has("listening") ? 2 : a.Has("other") ? 3 : 0;
            Dictionary<string, Conn> conns = new Dictionary<string, Conn>(); NameCache names = new NameCache();
            View v = new View(Columns.Connections());
            v.Filter = delegate (object o)
            {
                Conn c = (Conn)o;
                if (tcpOnly && !c.Proto.StartsWith("TCP")) return false; if (udpOnly && !c.Proto.StartsWith("UDP")) return false;
                if (stateMode == 1 && c.State != "ESTABLISHED") return false; if (stateMode == 2 && c.State != "LISTENING") return false; if (stateMode == 3 && (c.State == "ESTABLISHED" || c.State == "LISTENING")) return false;
                if (!loop && c.Loopback) return false;
                if (proc.Length > 0 && (c.Process ?? "").IndexOf(proc, StringComparison.OrdinalIgnoreCase) < 0) return false;
                return true;
            };
            v.Configure(a); string csv = a.Get("csv", null); Args quietCsv = a;
            do
            {
                DateTime now = DateTime.Now; List<Conn> snap = ConnTable.Snapshot(true, true); HashSet<string> seen = new HashSet<string>();
                foreach (Conn c in snap)
                {
                    seen.Add(c.Key); Conn cur;
                    if (conns.TryGetValue(c.Key, out cur)) { cur.LastSeen = now; cur.State = c.State; cur.Alive = true; }
                    else { c.Process = names.ProcessName(c.Pid); c.Host = resolve && c.Remote.Length > 0 && !c.Loopback ? names.HostOf(c.Remote) : ""; conns[c.Key] = c; }
                }
                List<string> drop = new List<string>(); foreach (KeyValuePair<string, Conn> kv in conns) { if (seen.Contains(kv.Key)) continue; kv.Value.Alive = false; if (!keep || (now - kv.Value.LastSeen).TotalSeconds > 30) drop.Add(kv.Key); } foreach (string k in drop) conns.Remove(k);
                if (!live && resolve) { Thread.Sleep(1500); }                  // one snapshot: give reverse DNS a moment
                foreach (Conn c in conns.Values) if (c.Host == "…") c.Host = names.HostOf(c.Remote);
                List<Conn> all = new List<Conn>(conns.Values); all.Sort(delegate (Conn x, Conn y) { int r = y.Alive.CompareTo(x.Alive); if (r != 0) return r; r = string.Compare(x.Process, y.Process, StringComparison.OrdinalIgnoreCase); if (r != 0) return r; return x.LocalPort.CompareTo(y.LocalPort); });
                int est = 0, lis = 0; foreach (Conn c in all) { if (c.State == "ESTABLISHED") est++; if (c.State == "LISTENING") lis++; }
                if (live) ClearForRedraw();
                Out.Header(info); Out.Cards("endpoints", all.Count, "established", est, "listening", lis, "time", now.ToString("HH:mm:ss"), "every", interval + " s" + (live ? " · Ctrl+C to stop" : ""));
                v.Set(Cli.Boxed(all)); v.Show(a);
                if (!live) break;
                LiveSleep(interval, end);
            } while (!Cli.Cancelled && DateTime.Now < end);
            if (a.Has("block")) { List<object> t = Cli.ActionTargets(v, a, "--block"); if (t == null) return Cli.USAGE; List<string> vals = new List<string>(); foreach (object o in t) { Conn c = (Conn)o; if (c.Remote.Length > 0 && !c.Loopback && !vals.Contains(c.Remote)) vals.Add(c.Remote); } return SendToBlocker(vals, "connections monitor", a); }
            return Cli.OK;
        }

        // ═══════════════════════════════ Firewall Rules ═══════════════════════════════
        // ═══════════════════════════════ Collect (the bundle) ═══════════════════════════
        static int Collect_(Args a)
        {
            ToolInfo info = Tools.ByKey("collect"); Out.Header(info);
            Collector c = new Collector(); string err = CollectOptions.Apply(c, delegate (string n) { return a.Get(n, null); }, a.Has, a.All); if (err != null) throw new UsageException(err);
            BundleKey key = CollectOptions.Key(c, delegate (string n) { return a.Get(n, null); }, a.Has, out err); if (key == null) throw new UsageException(err);
            Out.Note("modules: " + string.Join(", ", c.Modules.ToArray()) + " · " + (c.Online ? "online (Windows Update search allowed)" : "offline") + " · sealing: " + key.Mode + (c.Engagement != null ? " · engagement " + c.Engagement.Id : ""));
            Throttle th = new Throttle(200); c.Progress = delegate (string m) { th.Say(m); };
            Bundle b;
            try { b = c.Run(); } catch (BundleException ex) { Out.Error("refused: " + ex.Message); return Cli.PROBLEMS; }
            string outPath = a.Has("out") ? a.Get("out", "") : CollectOptions.DefaultOut(b, Cli.ReportsDir());
            try { string parent = Path.GetDirectoryName(Path.GetFullPath(outPath)); if (parent.Length > 0) Directory.CreateDirectory(parent); b.Save(outPath, key); CollectOptions.WriteDone(b, outPath); if (a.Has("json")) File.WriteAllText(a.Get("json", ""), b.ToJson(true), new UTF8Encoding(false)); }
            catch (Exception ex) { if (ex is IOException || ex is UnauthorizedAccessException || ex is ArgumentException || ex is NotSupportedException) throw new UsageException("--out: cannot write " + outPath + ": " + ex.Message); throw; }
            foreach (object m in b.Modules) { string st = Json.GetS(m, "status"); Out.Line("  " + CollectOptions.Summary(m), st == "ok" ? Tone.Normal : st == "skipped" ? Tone.Dim : Tone.Warn); }
            int failed = CollectOptions.Failed(b);
            Out.Ok("bundle " + new FileInfo(outPath).Length.ToString("N0") + " bytes · " + key.Mode + " · sha256 " + BundleCrypto.FileSha256(outPath) + " → " + Path.GetFullPath(outPath) + (failed > 0 ? " · " + failed + " module(s) partial or failed" : ""));
            return failed > 0 ? Cli.PROBLEMS : Cli.OK;
        }

        // ═══════════════════════════════ Enrich (bundle in, findings out) ═══════════════════════════
        /// <summary>How a sealed bundle opens and how what we write back is sealed, from exactly one of --pass / --key / --engagement / --plain.</summary>
        static void BundleKeys(Args a, out BundleKey open, out BundleKey seal, out Engagement eng)
        {
            eng = null; int n = (a.Has("pass") ? 1 : 0) + (a.Has("key") ? 1 : 0) + (a.Has("engagement") ? 1 : 0) + (a.Has("plain") ? 1 : 0);
            if (n != 1) throw new UsageException("say how the bundle is sealed: exactly one of --pass <passphrase>, --key <private key xml>, --engagement <engagement.json>, --plain");
            if (a.Has("pass")) { open = seal = BundleKey.FromPassphrase(a.Get("pass", "")); return; }
            if (a.Has("plain")) { open = seal = BundleKey.None(); return; }
            string priv;
            if (a.Has("key")) { string f = a.Get("key", ""); if (!File.Exists(f)) throw new UsageException("--key: no such file: " + f); priv = File.ReadAllText(f, Encoding.UTF8).Trim(); if (!priv.StartsWith("<RSAKeyValue")) throw new UsageException("--key: expected an RSA private key in XML; for a DPAPI-protected engagement.key use --engagement"); }
            else { string ef = a.Get("engagement", ""); if (!File.Exists(ef)) throw new UsageException("--engagement: no such file: " + ef); eng = Engagement.Load(ef); string kf = Engagement.KeyFileFor(ef); if (!File.Exists(kf)) throw new UsageException("--engagement: no " + Path.GetFileName(kf) + " beside " + ef); priv = Engagement.PrivateKey(eng, kf); }
            open = BundleKey.WithPrivate(priv); seal = BundleKey.ToPublic(BundleCrypto.PublicOf(priv));
        }
        /// <summary>--months, else the saved setting, else 3. An explicit value that is not a whole number in range is a usage error - never silently 3, which once turned "--months 99" into the narrowest scan (PT-34).</summary>
        static int MonthsOption(Args a, Settings st, int max)
        {
            string v = a.Get("months", null); int n;
            if (v != null) { if (!int.TryParse(v.Trim(), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out n) || n < 1 || n > max) throw new UsageException("--months must be a whole number from 1 to " + max + " (got '" + v + "')"); return n; }
            return int.TryParse(st.Get("vuln.months", "3"), out n) && n >= 1 && n <= max ? n : 3;
        }
        static int Enrich_(Args a)
        {
            ToolInfo info = Tools.ByKey("enrich"); Out.Header(info);
            string inPath = a.Get("in", a.Positional.Count > 0 ? a.Positional[0] : null); if (inPath == null) throw new UsageException("--in <bundle.ptb>, or give the bundle as the first argument"); if (!File.Exists(inPath)) throw new UsageException("--in: no such file: " + inPath);
            BundleKey open, seal; Engagement eng; BundleKeys(a, out open, out seal, out eng);
            Bundle b; try { b = Bundle.Load(inPath, open); } catch (BundleException ex) { Out.Error(ex.Message); return Cli.PROBLEMS; }
            FeedCache cache = a.Has("cache") ? new FeedCache(Cli.FullFolder(a.Get("cache", ""))) : Cli.OpenCache(); cache.Offline = a.Has("offline");
            if (cache.Offline && !Directory.Exists(cache.Dir)) throw new UsageException("--cache: no such folder: " + cache.Dir);
            Settings st = Cli.S; string key = a.Get("nvd-key", st.Get("vuln.key", "")).Trim();
            VulnEnrich e; try { e = EnrichBundle.From(b, cache); } catch (BundleException ex) { Out.Error(ex.Message); return Cli.PROBLEMS; }
            e.NvdApiKey = key; e.DoMsrc = !a.Has("no-msrc"); e.DoNvd = !a.Has("no-nvd"); e.DoKev = !a.Has("no-kev"); e.DoEpss = !a.Has("no-epss");
            e.Months = MonthsOption(a, st, VulnScan.MaxMonths);
            Out.Note("bundle " + b.Host + " · run " + b.RunId + " · build " + e.Os.FullBuild + " · " + e.Software.Count + " programs · newest update " + (e.NewestUpdate.HasValue ? e.NewestUpdate.Value.ToString("yyyy-MM-dd") : "not dated") + " · feeds: " + (cache.Offline ? "offline pack " : "") + cache.Dir);
            Throttle th = new Throttle(200); e.Progress = delegate (string m) { th.Say(m); }; e.Step += delegate (string label, string state, string note) { if (state == "running") Out.Note("· " + label); else if (state == "done" || state == "failed") Out.Note("  " + label + ": " + state + (note != null ? " · " + note : "")); }; e.Cancelled = delegate { return Cli.Cancelled; };
            e.Run(); EnrichBundle.Apply(b, e);
            string outPath = a.Get("out", null); if (outPath == null) outPath = inPath.EndsWith(".ptb", StringComparison.OrdinalIgnoreCase) ? inPath.Substring(0, inPath.Length - 4) + ".enriched.ptb" : inPath + ".enriched.ptb";
            try { b.Save(outPath, seal); if (a.Has("json")) File.WriteAllText(a.Get("json", ""), b.ToJson(true), new UTF8Encoding(false)); }
            catch (Exception ex) { if (ex is IOException || ex is UnauthorizedAccessException || ex is ArgumentException || ex is NotSupportedException) throw new UsageException("--out: cannot write " + outPath + ": " + ex.Message); throw; }
            List<Finding> fs = e.Findings; int crit = 0, high = 0, kev = 0, open_ = 0; foreach (Finding f in fs) { if (!f.Open) continue; open_++; if (f.SeverityNorm == "Critical") crit++; else if (f.SeverityNorm == "High") high++; if (f.Kev || f.Exploited) kev++; }
            object msrc = Json.Get(e.AsOf, "msrc"), kv = Json.Get(e.AsOf, "kev"), ep = Json.Get(e.AsOf, "epss");
            Out.Cards("OS build", e.Os.FullBuild, "MSRC window", e.MsrcWindowUsed + " release(s)", "open", T(open_.ToString(), GoodIfZero(open_)), "critical", T(crit.ToString(), GoodIfZero(crit)), "high", T(high.ToString(), GoodIfZero(high)), "known exploited", T(kev.ToString(), GoodIfZero(kev)), "total", fs.Count);
            Out.Line("  as of: MSRC " + string.Join(", ", e.Releases.ToArray()) + (kv != null ? " · KEV " + (Json.GetS(kv, "catalogVersion") ?? Json.GetS(kv, "cached") ?? "?") : "") + (ep != null && (Json.GetS(ep, "dates") ?? "").Length > 0 ? " · EPSS " + Json.GetS(ep, "dates") : "") + (msrc != null ? " · newest update " + (Json.GetS(msrc, "newestUpdate") ?? "not dated") : ""), Tone.Dim);
            View v = new View(Columns.Findings()); string status = a.Choice("status", "open", "open", "all"); v.Filter = delegate (object o) { return status == "all" || ((Finding)o).Open; }; v.Configure(a); v.Set(Cli.Boxed(fs)); v.Show(a);
            if (a.Has("log")) PrintLog("enrichment log", e.Errors, e.Log); else if (e.Errors.Count > 0) Out.Warn(e.Errors.Count + " problem(s) during enrichment - add --log to see them.");
            Out.Ok("enriched bundle " + new FileInfo(outPath).Length.ToString("N0") + " bytes · sealed: " + seal.Mode + " → " + Path.GetFullPath(outPath));
            return Cli.Cancelled ? Cli.CANCELLED : e.Errors.Count > 0 ? Cli.PROBLEMS : Cli.OK;
        }

        // ═══════════════════════════════ Feeds (the feed pack) ═══════════════════════════
        static int Feeds_(Args a)
        {
            ToolInfo info = Tools.ByKey("feeds"); Out.Header(info);
            FeedCache cache = a.Has("cache") ? new FeedCache(Cli.FullFolder(a.Get("cache", ""))) : Cli.OpenCache();
            if (a.Has("export") && a.Has("import")) throw new UsageException("--export or --import, not both");
            if (a.Has("export"))
            {
                string dir = Cli.FullFolder(a.Get("export", "")); FeedPack.Result r;
                try { r = FeedPack.Export(cache, dir); } catch (Exception ex) { if (ex is IOException || ex is UnauthorizedAccessException) throw new UsageException("--export: cannot write " + dir + ": " + ex.Message); throw; }
                Out.Ok("feed pack: " + r.Files + " file(s), " + FeedPack.Size(r.Bytes) + " → " + dir + " (" + FeedPack.ManifestName + " lists every file with its SHA-256 and time)"); return Cli.OK;
            }
            if (a.Has("import"))
            {
                string dir = Cli.FullFolder(a.Get("import", "")); if (!Directory.Exists(dir)) throw new UsageException("--import: no such folder: " + dir); FeedPack.Result r;
                try { r = FeedPack.Import(dir, cache, !a.Has("no-verify")); } catch (BundleException ex) { Out.Error(ex.Message); return Cli.PROBLEMS; }
                foreach (string p in r.Problems) Out.Warn(p);
                Out.Ok("imported " + r.Files + " file(s), " + FeedPack.Size(r.Bytes) + " into " + cache.Dir + (r.Skipped > 0 ? " · " + r.Skipped + " refused" : "")); return r.Skipped > 0 || r.Files == 0 ? Cli.PROBLEMS : Cli.OK;
            }
            foreach (string line in FeedPack.Status(cache)) Out.Line("  " + line); return Cli.OK;
        }

        // ═══════════════════════════════ Engagement (scope, window, keys) ═══════════════════════════
        static int Engagement_(Args a)
        {
            ToolInfo info = Tools.ByKey("engagement"); Out.Header(info);
            string verb = a.Positional.Count > 0 ? a.Positional[0].ToLowerInvariant() : ""; if (verb != "new" && verb != "inspect" && verb != "check") throw new UsageException("engagement new --out <folder> --id <id> --scope <list> --from <utc> --to <utc> … | engagement inspect <engagement.json> | engagement check <engagement.json> --host <name or ip>");
            if (verb == "new")
            {
                string dir = Cli.FullFolder(a.Get("out", Directory.GetCurrentDirectory())); DateTime? from = UtcDate(a, "from"), to = UtcDate(a, "to");
                List<string> scope = new List<string>(); foreach (string s in a.All("scope")) scope.AddRange(s.Split(',')); List<string> mods = new List<string>(); foreach (string s in a.All("modules")) mods.AddRange(s.Split(','));
                int ret; if (!int.TryParse(a.Get("retention", "90"), out ret) || ret < 1) throw new UsageException("--retention: a number of days, at least 1"); int bits = int.Parse(a.Choice("bits", "3072", "2048", "3072", "4096"));
                if (!a.Has("id")) throw new UsageException("--id is required (e.g. ENG-2026-014)"); if (scope.Count == 0) throw new UsageException("--scope is required: host names, IPs or CIDRs, repeatable or comma-separated");
                Engagement e; try { e = EngagementTool.New(dir, a.Get("id", ""), a.Get("client", ""), a.Get("operator", Environment.UserName), scope, from, to, mods, ret, a.Get("notes", ""), bits); } catch (BundleException ex) { throw new UsageException(ex.Message); }
                foreach (string l in EngagementTool.Inspect(e)) Out.Line("  " + l);
                Out.Ok("written " + e.File + " and " + Path.GetFileName(Engagement.KeyFileFor(e.File)) + " - the private key is DPAPI-protected for " + Environment.UserDomainName + "\\" + Environment.UserName + " on this machine; keep a backup of the folder");
                return Cli.OK;
            }
            string file = a.Get("file", a.Positional.Count > 1 ? a.Positional[1] : null); if (file == null) throw new UsageException("engagement " + verb + " <engagement.json>"); if (!File.Exists(file)) throw new UsageException("no such file: " + file);
            Engagement eng; try { eng = Engagement.Load(file); } catch (BundleException ex) { Out.Error(ex.Message); return Cli.PROBLEMS; }
            if (verb == "inspect") { foreach (string l in EngagementTool.Inspect(eng)) Out.Line("  " + l); return eng.Validate().Count == 0 ? Cli.OK : Cli.PROBLEMS; }
            string host = a.Get("host", null); if (host == null) throw new UsageException("check needs --host <name or ip>");
            string why; bool ok = eng.InScope(host, out why); string whyW; bool inWin = eng.InWindow(DateTime.UtcNow, out whyW);
            Out.Line("  " + host + ": " + (ok ? "in scope" : "OUT OF SCOPE - " + why), ok ? Tone.Good : Tone.Bad); Out.Line("  window: " + (inWin ? "open now" : whyW), inWin ? Tone.Good : Tone.Warn);
            return ok && inWin ? Cli.OK : Cli.PROBLEMS;
        }
        static DateTime? UtcDate(Args a, string name)
        {
            if (!a.Has(name)) return null; DateTime d;
            if (!DateTime.TryParse(a.Get(name, ""), System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal, out d)) throw new UsageException("--" + name + ": give a UTC date like 2026-10-01 or 2026-10-01T09:00Z");
            return d;
        }

        static int Firewall_(Args a)
        {
            ToolInfo info = Tools.ByKey("firewall"); Out.Header(info);
            string pnote; List<FwProfile> profiles = WinFirewall.ReadProfiles(out pnote); string note; List<FwRule> rules = WinFirewall.ReadRules(out note);
            if (note.Length > 0 && rules.Count == 0) { Out.Error("could not read rules: " + note); return Cli.PROBLEMS; }
            int enabled = 0, inbound = 0, risky = 0; foreach (FwRule f in rules) { if (f.Enabled) enabled++; if (f.Inbound && f.Allow && f.Enabled) inbound++; if (f.Risk.Length > 0) risky++; }
            int on = 0, off = 0; string offNames = ""; foreach (FwProfile p in profiles) { if (p.On) on++; else { off++; offNames += (offNames.Length > 0 ? "," : "") + p.Name; } }
            Out.Cards("rules", rules.Count, "enabled", enabled, "inbound allow", T(inbound.ToString(), WarnIfAny(inbound)), "risky", T(risky.ToString(), GoodIfZero(risky)), "firewall", T(profiles.Count == 0 ? "?" : off == 0 ? "on for all profiles" : on + "/" + profiles.Count + " · off: " + offNames, off == 0 ? Tone.Good : Tone.Bad));
            foreach (FwProfile p in profiles) Out.Line("  " + p.Name.PadRight(8) + (p.On ? "on " : "OFF") + "  default inbound " + p.DefaultInbound + (p.DefaultOutbound.Length > 0 ? " · outbound " + p.DefaultOutbound : ""), p.On ? Tone.Dim : Tone.Bad);
            View v = new View(Columns.FirewallRules()); bool inb = a.Has("inbound"), outb = a.Has("outbound"), riskyOnly = a.Has("risky"), enOnly = a.Has("enabled");
            v.Filter = delegate (object o) { FwRule f = (FwRule)o; if (enOnly && !f.Enabled) return false; if (riskyOnly && f.Risk.Length == 0) return false; if (inb && !outb && f.Direction != "in") return false; if (outb && !inb && f.Direction != "out") return false; return true; };
            v.Configure(a); v.Set(Cli.Boxed(rules)); v.Show(a);
            return Cli.OK;
        }

        // ═══════════════════════════════ Resource Usage ═══════════════════════════════
        static int ResourceUsage(Args a)
        {
            ToolInfo info = Tools.ByKey("resource-usage");
            if (a.Has("modules"))
            {
                int pid = a.Int("modules", -1); if (pid < 0) throw new UsageException("--modules needs a PID");
                string name; try { name = Process.GetProcessById(pid).ProcessName; } catch (Exception ex) { Out.Error("PID " + pid + ": " + ex.Message); return Cli.PROBLEMS; }
                Out.Header(info); Out.Line("Modules loaded in " + name + " (PID " + pid + ")", Tone.Accent);
                List<ModuleInfo> mods; try { mods = Trust.Modules(pid); } catch (Exception ex) { Out.Error("could not read modules: " + ex.Message + (Cli.IsElevated ? "" : " - try an elevated prompt")); return Cli.PROBLEMS; }
                Throttle th = new Throttle(200); int k = 0; foreach (ModuleInfo m in mods) { m.Sig = Trust.Verify(m.Path); string[] vi = Trust.VersionInfo(m.Path); m.Company = vi[0]; th.Say("verifying " + (++k) + " / " + mods.Count); }
                int unsigned = 0, odd = 0; foreach (ModuleInfo m in mods) { if (m.Sig.Status == "unsigned" || m.Sig.Status == "invalid") unsigned++; if (m.Location == "user-writable" || m.Location == "other") odd++; }
                Out.Cards("modules", mods.Count, "unsigned / invalid", T(unsigned.ToString(), WarnIfAny(unsigned)), "outside Windows / Program Files", T(odd.ToString(), WarnIfAny(odd)));
                View mv = new View(Columns.Modules(name)); mv.Configure(a); mv.Set(Cli.Boxed(mods)); mv.Show(a); return Cli.OK;
            }
            int interval = int.Parse(a.Choice("interval", "1", "1", "2", "5")); bool live = LiveMode(a); double dur = a.Dbl("duration", 0); DateTime end = dur > 0 ? DateTime.Now.AddSeconds(dur) : DateTime.MaxValue; bool group = !a.Has("by-pid");
            ProcSampler sampler = new ProcSampler(); View v = new View(Columns.Processes()); v.Configure(a);
            sampler.Sample(); Thread.Sleep(Math.Min(1000, interval * 1000));
            do
            {
                sampler.Sample();
                List<ProcRow> rows = group ? sampler.Grouped() : new List<ProcRow>(sampler.Procs.Values); rows.Sort(delegate (ProcRow x, ProcRow y) { return y.CpuCum.CompareTo(x.CpuCum); });
                double ioMb = sampler.SysIo / 1048576.0;
                if (live) ClearForRedraw();
                Out.Header(info);
                Out.Cards("CPU", T(sampler.SysCpu.ToString("N1") + " %", sampler.SysCpu >= 85 ? Tone.Bad : sampler.SysCpu >= 60 ? Tone.Warn : Tone.Accent), "memory", Fmt.Bytes(sampler.RamUsed) + " / " + Fmt.Bytes(sampler.RamTotal) + (sampler.RamTotal > 0 ? " (" + (sampler.RamUsed / sampler.RamTotal).ToString("P0") + ")" : ""), "disk I/O", ioMb.ToString("N1") + " MB/s", "since", sampler.StartedAt.ToString("HH:mm:ss"), "samples", sampler.Ticks, "processes", sampler.Procs.Count + (group ? " · grouped by name" : " · by PID") + (live ? " · Ctrl+C to stop" : ""));
                v.Set(Cli.Boxed(rows)); v.Show(a);
                if (!live) break;
                LiveSleep(interval, end);
            } while (!Cli.Cancelled && DateTime.Now < end);
            if (a.Has("end"))
            {
                List<object> t = Cli.ActionTargets(v, a, "--end"); if (t == null) return Cli.USAGE;
                List<ProcRow> l = new List<ProcRow>(); foreach (object o in t) { ProcRow p = (ProcRow)o; if (p.Alive && p.Pid > 4) l.Add(p); }
                if (l.Count == 0) { Out.Warn("Pick live processes with a PID (use --by-pid; grouped rows have none)."); return Cli.OK; }
                if (!Cli.Confirm(a, "End " + l.Count + " process(es)?", "This kills them without saving anything they hold open: " + string.Join(", ", l.ConvertAll(delegate (ProcRow p) { return p.Name + " [" + p.Pid + "]"; }).ToArray()))) return Cli.CANCELLED;
                int ok = 0; foreach (ProcRow p in l) { try { Process.GetProcessById(p.Pid).Kill(); ok++; } catch (Exception ex) { Out.Warn(p.Name + ": " + ex.Message); } } Out.Ok(ok + " ended");
            }
            return Cli.OK;
        }

        // ═══════════════════════════════ Disk Usage ═══════════════════════════════
        static int DiskUsage(Args a)
        {
            ToolInfo info = Tools.ByKey("disk-usage"); Out.Header(info);
            string root = a.Get("path", null);
            if (root == null) { foreach (DriveInfoRow d in Drives.List()) if (!string.IsNullOrEmpty(d.Fs) && d.Kind == "fixed") { root = d.Letter + ":\\"; break; } }
            if (root == null || !Directory.Exists(root)) throw new UsageException("--path: pick a drive or a folder that exists" + (root != null ? " (" + root + ")" : ""));
            if (root.Length == 2 && root[1] == ':') root += "\\";
            string show = a.Choice("show", "files", "files", "folders", "types");
            Storage storage = new Storage(); storage.MinFileBytes = (long)Math.Max(0, a.Int("min-mb", 50)) * 1048576L;
            Out.Note("scanning " + root + " · files ≥ " + (storage.MinFileBytes / 1048576) + " MB kept in the largest-files list");
            Throttle th = new Throttle(400);
            RunOnThread(delegate { storage.Scan(root); }, delegate { storage.Cancel = true; }, delegate { th.Say(storage.TotalFiles.ToString("N0") + " files · " + Fmt.Bytes(storage.TotalBytes) + " · " + storage.Clock.Elapsed.TotalSeconds.ToString("N0") + " s"); });
            if (storage.Root == null) return Cli.PROBLEMS;
            Out.Cards("scanned", root, "files", storage.TotalFiles.ToString("N0"), "folders", storage.TotalDirs.ToString("N0"), "size", Fmt.Bytes(storage.TotalBytes), "time", storage.Clock.Elapsed.TotalSeconds.ToString("N1") + " s", "not readable", T(storage.Denied.ToString(), WarnIfAny(storage.Denied)), "result", storage.Cancel ? "cancelled" : "done");
            View v; List<object> rows;
            if (show == "types") { v = new View(Columns.DiskTypes(delegate { return storage.TotalBytes; })); List<ExtStat> l = new List<ExtStat>(storage.ByExt.Values); l.Sort(delegate (ExtStat x, ExtStat y) { return y.Bytes.CompareTo(x.Bytes); }); rows = Cli.Boxed(l); }
            else { bool dirs = show == "folders"; v = new View(Columns.DiskNodes(dirs, delegate { return storage.Root.Path; })); rows = Cli.Boxed(dirs ? storage.AllDirs : storage.LargestFiles); }
            v.Configure(a); v.Set(rows); v.Show(a);
            if (a.Has("recycle"))
            {
                if (show == "types") { Out.Error("--recycle works on files or folders, not on types."); return Cli.USAGE; }
                List<object> t = Cli.ActionTargets(v, a, "--recycle"); if (t == null) return Cli.USAGE; List<Node> l = new List<Node>(); long bytes = 0; foreach (object o in t) { Node n = (Node)o; l.Add(n); bytes += n.Size; }
                if (l.Count == 0) return Cli.OK;
                if (!Cli.Confirm(a, "Move " + l.Count + " item(s) to the Recycle Bin?", Fmt.Bytes(bytes) + " in total. They can be restored from the Recycle Bin afterwards: " + Cli.Preview(l.ConvertAll(delegate (Node n) { return n.Path; }), 12))) return Cli.CANCELLED;
                int ok = 0; foreach (Node n in l) { try { Cli.Recycle(n.Path, n.IsDir); ok++; } catch (Exception ex) { Out.Warn(n.Name + ": " + ex.Message); } }
                Out.Ok(ok + " item(s) moved to the Recycle Bin - scan again to refresh the numbers");
            }
            return storage.Cancel ? Cli.CANCELLED : Cli.OK;
        }

        // ═══════════════════════════════ Deleted Files Finder ═══════════════════════════════
        static int DeletedFiles(Args a)
        {
            ToolInfo info = Tools.ByKey("deleted-files"); Out.Header(info);
            List<DriveInfoRow> drives = Drives.List(), chosen = new List<DriveInfoRow>();
            string want = a.Get("drives", null);
            foreach (DriveInfoRow d in drives)
            {
                bool usable = d.Journalable || d.ExFat; bool asked = want == null || Array.IndexOf(Array.ConvertAll(want.ToUpperInvariant().Split(new char[] { ',', ' ', ';' }, StringSplitOptions.RemoveEmptyEntries), delegate (string s) { return s.TrimEnd(':', '\\'); }), d.Letter.ToUpperInvariant()) >= 0;
                if (!asked) continue;
                if (!usable) { Out.Warn(d.Letter + ": skipped - " + d.Why); continue; }
                if (d.Journalable && !Cli.IsElevated) { Out.Warn(d.Letter + ": skipped - reading the NTFS change journal needs administrator rights"); continue; }
                chosen.Add(d);
            }
            Out.Line("drives: " + string.Join("  ", drives.ConvertAll(delegate (DriveInfoRow d) { return d.Letter + ": " + (string.IsNullOrEmpty(d.Fs) ? "no media" : d.Fs) + " (" + d.Why + ")"; }).ToArray()), Tone.Dim);
            if (chosen.Count == 0) { Out.Error("nothing to scan" + (Cli.IsElevated ? "." : " - run from an elevated prompt for NTFS drives, or pick an exFAT drive with --drives.")); return Cli.IsElevated ? Cli.PROBLEMS : Cli.ADMIN; }
            int days = Math.Max(1, a.Int("days", 30)); string under = a.Get("under", "").Trim(); bool noise = a.Has("noise"), shadows = !a.Has("no-shadows"); string ext = a.Get("type", "").Trim(), nameHas = a.Get("name", "").Trim();
            string unit = a.Choice("unit", "MB", "KB", "MB", "GB"); long mult = unit == "KB" ? 1024L : unit == "GB" ? 1073741824L : 1048576L; long minB = (long)Math.Max(0, a.Int("min", 0)) * mult, maxB = (long)Math.Max(0, a.Int("max", 0)) * mult;
            bool filtered = ext.Length > 0 || nameHas.Length > 0 || minB > 0 || maxB > 0;
            List<DeletedScan> scans = new List<DeletedScan>(); List<object> all = new List<object>(); List<string> summary = new List<string>();
            try
            {
                foreach (DriveInfoRow d in chosen)
                {
                    if (Cli.Cancelled) break;
                    DeletedScan s = new DeletedScan(); s.Drive = d; s.Days = days; s.PathFilter = under; s.ShowNoise = noise; s.CheckShadows = shadows; s.ExtFilter = ext; s.NameContains = nameHas; s.MinBytes = minB; s.MaxBytes = maxB; s.Cancelled = delegate { return Cli.Cancelled; };
                    Throttle th = new Throttle(300); s.Progress = delegate (string m) { th.Say(d.Letter + ": " + m); };
                    Out.Note("· " + d.Letter + ": " + d.Why);
                    try { s.Run(); } catch (Exception ex) { s.Message = ex.Message; }
                    scans.Add(s); foreach (DeletedRow r in s.Rows) all.Add(r);
                    string line = d.Letter + ": " + s.Rows.Count.ToString("N0") + (filtered ? " matching" : "") + " entries";
                    if (s.Journal != null && s.Journal.Active) line += " · journal sees back " + s.Journal.CoverageDays.ToString("N1") + " days (" + s.Journal.Records.ToString("N0") + " records)" + (s.Journal.CoverageDays < days ? " - shorter than your window" : "");
                    if (s.Ex != null) line += " · " + s.Ex.IntactCount.ToString("N0") + " files intact (" + Fmt.Bytes(s.Ex.IntactBytes) + ")";
                    if (s.NoiseHidden > 0) line += " · " + s.NoiseHidden.ToString("N0") + " noise hidden"; if (s.Message.Length > 0) line += " · " + s.Message;
                    summary.Add(line);
                }
                foreach (string s in summary) Out.Line(s, Tone.Dim);
                int bins = 0; foreach (DeletedScan s in scans) foreach (BinItem b in s.Bins) { if (bins++ == 0) Out.Line("emptied from the Recycle Bin:", Tone.Accent); Out.Line("  " + b.Name + " · " + (b.IsDir ? "folder" : "file") + " · " + (b.When.HasValue ? "deleted " + b.When.Value.ToString("yyyy-MM-dd HH:mm") : "deletion time unknown") + (b.Named ? "" : " · original name lost") + " · " + b.Files.ToString("N0") + " files inside, " + b.Intact.ToString("N0") + " intact (" + Fmt.Bytes(b.Bytes) + ")" + (b.Empty > 0 ? ", " + b.Empty.ToString("N0") + " empty" : ""), Tone.Normal); }
                string source = a.Choice("source", "all", "all", "journal", "exfat"); bool recOnly = a.Has("recoverable");
                View v = new View(Columns.Deleted());
                v.Filter = delegate (object o) { DeletedRow r = (DeletedRow)o; if (source == "journal" && r.Source != "journal") return false; if (source == "exfat" && r.Source != "exFAT") return false; if (recOnly && !r.Recoverable) return false; return true; };
                v.Configure(a); v.Set(all); v.Show(a);
                string dest = a.Get("recover-to", null);
                if (dest != null)
                {
                    List<object> t = Cli.ActionTargets(v, a, "--recover-to"); if (t == null) return Cli.USAGE;
                    List<DeletedRow> l = new List<DeletedRow>(); long bytes = 0; foreach (object o in t) { DeletedRow r = (DeletedRow)o; if (r.Recoverable) { l.Add(r); bytes += r.Size; } }
                    if (l.Count == 0) { Out.Warn("None of the selected entries is recoverable."); return Cli.OK; }
                    if (!Cli.Confirm(a, "Recover " + l.Count + " file(s)?", Fmt.Bytes(bytes) + " will be copied into " + dest + " keeping the folder structure. The source drive is never written to. Make sure the destination is on ANOTHER drive than the one they come from.")) return Cli.CANCELLED;
                    Cli.S.Set("deleted.dest", dest); Cli.S.Save(); int ok = 0, fail = 0;
                    foreach (DeletedRow r in l) { DeletedScan s = scans.Find(delegate (DeletedScan x) { return x.Rows.Contains(r); }); if (s == null) { fail++; continue; } try { string p = s.Recover(r, dest); ok++; Out.Line("  " + p, Tone.Good); } catch (Exception ex) { fail++; Out.Warn("  " + r.Name + ": " + ex.Message); } }
                    Out.Ok(ok + " file(s) copied to " + dest + (fail > 0 ? " · " + fail + " failed" : "") + ". Open a few to confirm they are whole; a file whose clusters were reused will look damaged.");
                }
                return Cli.Cancelled ? Cli.CANCELLED : Cli.OK;
            }
            finally { foreach (DeletedScan s in scans) s.Close(); }
        }

        // ═══════════════════════════════ File Explorer ═══════════════════════════════
        static int FileExplorer(Args a)
        {
            ToolInfo info = Tools.ByKey("file-explorer"); Out.Header(info);
            string path = a.Get("path", Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)); path = Cli.FullFolder(path);
            if (File.Exists(path)) path = Path.GetDirectoryName(path);
            if (!Directory.Exists(path)) throw new UsageException("--path: no such folder: " + path);
            string nf = a.Get("new-folder", null); if (nf != null) { try { Directory.CreateDirectory(Path.Combine(path, nf)); Out.Ok("created " + Path.Combine(path, nf)); } catch (Exception ex) { Out.Error("could not create the folder: " + ex.Message); return Cli.PROBLEMS; } }
            bool hidden = a.Has("hidden"); List<FileEntry> dirs = new List<FileEntry>(), files = new List<FileEntry>();
            try
            {
                foreach (FileSystemInfo fsi in new DirectoryInfo(path).EnumerateFileSystemInfos())
                {
                    FileAttributes at; try { at = fsi.Attributes; } catch { continue; }
                    if (!hidden && (at & (FileAttributes.Hidden | FileAttributes.System)) != 0) continue;
                    FileEntry e = new FileEntry(); e.Name = fsi.Name; e.Path = fsi.FullName; e.Dir = path; e.Attributes = at; e.IsDir = (at & FileAttributes.Directory) != 0;
                    try { e.Modified = fsi.LastWriteTime; } catch { } if (!e.IsDir) { FileInfo fi = fsi as FileInfo; try { e.Size = fi.Length; } catch { } e.Ext = fi.Extension.ToLowerInvariant(); }
                    (e.IsDir ? dirs : files).Add(e);
                }
            }
            catch (UnauthorizedAccessException) { Out.Error("Access denied: " + path); return Cli.PROBLEMS; }
            dirs.Sort(delegate (FileEntry x, FileEntry y) { return string.Compare(x.Name, y.Name, StringComparison.OrdinalIgnoreCase); }); files.Sort(delegate (FileEntry x, FileEntry y) { return string.Compare(x.Name, y.Name, StringComparison.OrdinalIgnoreCase); });
            List<object> items = new List<object>(); foreach (FileEntry e in dirs) items.Add(e); foreach (FileEntry e in files) items.Add(e);
            long total = 0; foreach (FileEntry e in files) total += e.Size;
            Out.Cards("path", path, "folders", dirs.Count, "files", files.Count, "size", Fmt.Bytes(total));
            TableDef def = Columns.Folder(); def.Export = "folder-" + new DirectoryInfo(path).Name; View v = new View(def); v.Configure(a); v.Set(items); v.Show(a);
            string action = a.Has("encrypt") ? "encrypt" : a.Has("decrypt") ? "decrypt" : a.Has("wipe") ? "wipe" : a.Has("delete") ? "delete" : null;
            if (action == null) return Cli.OK;
            List<object> t = Cli.ActionTargets(v, a, "--" + action); if (t == null) return Cli.USAGE;
            List<FileEntry> sel = new List<FileEntry>(); foreach (object o in t) sel.Add((FileEntry)o);
            if (action == "encrypt" || action == "decrypt") sel.RemoveAll(delegate (FileEntry f) { return f.IsDir || f.Encrypted != (action == "decrypt"); });
            if (sel.Count == 0) { Out.Warn(action == "encrypt" ? "Select one or more files to encrypt (folders and .enc files are skipped)." : action == "decrypt" ? "Select one or more .enc files to decrypt." : "Select items to " + action + "."); return Cli.OK; }
            long bytes = 0; foreach (FileEntry f in sel) bytes += f.Size; string preview = Cli.Preview(sel.ConvertAll(delegate (FileEntry f) { return f.Name; }), 12);
            int okN = 0, failN = 0; Action<FileEntry> op = null; string verb = "";
            if (action == "encrypt")
            {
                string pw = Cli.Password(a, "Choose a password - it is the only way to open these files again; if you lose it, the data is gone", true); if (pw == null) return Cli.CANCELLED;
                if (!Cli.Confirm(a, "Encrypt " + sel.Count + " file(s)?", Fmt.Bytes(bytes) + " total. Each file is encrypted to a new .enc file, verified, and then the original is permanently deleted. " + preview)) return Cli.CANCELLED;
                verb = "Encrypting"; op = delegate (FileEntry f) { string outp = FileCrypto.DefaultEncName(f.Path); if (File.Exists(outp)) throw new IOException(Path.GetFileName(outp) + " already exists"); FileCrypto.Encrypt(f.Path, outp, pw, null); if (!FileCrypto.Verify(outp, pw)) { try { File.Delete(outp); } catch { } throw new Exception("verification failed, original kept"); } File.Delete(f.Path); };
            }
            else if (action == "decrypt")
            {
                string pw = Cli.Password(a, "Enter the password these files were encrypted with", false); if (pw == null) return Cli.CANCELLED;
                try { if (!FileCrypto.Verify(sel[0].Path, pw)) { Out.Error("Wrong password: it does not open " + sel[0].Name + "."); return Cli.PROBLEMS; } } catch (Exception ex) { Out.Error("Cannot decrypt: " + ex.Message); return Cli.PROBLEMS; }
                if (!Cli.Confirm(a, "Decrypt " + sel.Count + " file(s)?", "The decrypted files are written next to the .enc files, which are kept. " + preview)) return Cli.CANCELLED;
                verb = "Decrypting"; op = delegate (FileEntry f) { string outp = FileCrypto.DefaultDecName(f.Path); int i = 1; string dir = Path.GetDirectoryName(outp), nm = Path.GetFileNameWithoutExtension(outp), ex = Path.GetExtension(outp); while (File.Exists(outp)) outp = Path.Combine(dir, nm + " (" + (i++) + ")" + ex); FileCrypto.Decrypt(f.Path, outp, pw, null); };
            }
            else if (action == "delete")
            {
                if (!Cli.Confirm(a, "Permanently delete " + sel.Count + " item(s)?", "This bypasses the Recycle Bin. Deleted items cannot be restored. " + Fmt.Bytes(bytes) + " total. " + preview)) return Cli.CANCELLED;
                verb = "Deleting"; op = delegate (FileEntry f) { if (f.IsDir) Directory.Delete(f.Path, true); else { try { File.SetAttributes(f.Path, FileAttributes.Normal); } catch { } File.Delete(f.Path); } };
            }
            else
            {
                if (!Cli.Confirm(a, "Securely wipe " + sel.Count + " item(s)?", "Each file is overwritten with random data, then deleted. This cannot be undone. On SSDs, wear-levelling means it defeats casual recovery, not forensic recovery. " + Fmt.Bytes(bytes) + " total. " + preview)) return Cli.CANCELLED;
                verb = "Wiping"; op = delegate (FileEntry f) { if (f.IsDir) { foreach (string file in Directory.EnumerateFiles(f.Path, "*", SearchOption.AllDirectories)) { try { File.SetAttributes(file, FileAttributes.Normal); } catch { } FileCrypto.SecureWipe(file, 3, null); } Directory.Delete(f.Path, true); } else { try { File.SetAttributes(f.Path, FileAttributes.Normal); } catch { } FileCrypto.SecureWipe(f.Path, 3, null); } };
            }
            for (int i = 0; i < sel.Count; i++) { FileEntry f = sel[i]; Out.Progress(verb + " " + (i + 1) + " / " + sel.Count + ": " + f.Name); try { op(f); okN++; } catch (Exception ex) { failN++; Out.Warn(f.Name + ": " + ex.Message); } if (Cli.Cancelled) break; }
            Out.Ok(verb + " done · " + okN + " ok" + (failN > 0 ? " · " + failN + " failed" : ""));
            return failN > 0 ? Cli.PROBLEMS : Cli.OK;
        }

        // ═══════════════════════════════ Find Files ═══════════════════════════════
        static int FindFiles(Args a)
        {
            ToolInfo info = Tools.ByKey("find-files"); Out.Header(info);
            List<string> roots = a.All("in"); if (roots.Count == 0) roots = FastWalk.FixedDrives(); foreach (string r in roots) if (!Directory.Exists(r)) throw new UsageException("--in: no such folder: " + r);
            string name = a.Get("name", null); List<string> hashText = a.All("hash"); string hashFile = a.Get("hash-file", null);
            if (hashFile != null) { bool ha, hb, hc; int bad; string note; HashSet<string> hs = Hashes.FromFile(hashFile, out ha, out hb, out hc, out bad, out note); if (note.Length > 0) { Out.Error(note); return Cli.USAGE; } hashText.Add(string.Join(" ", new List<string>(hs).ToArray())); Out.Note(hs.Count + " hash(es) read from " + Path.GetFileName(hashFile)); }
            bool byHash = hashText.Count > 0; if (!byHash && string.IsNullOrEmpty(name)) throw new UsageException("give --name <pattern>, or --hash / --hash-file for a hash sweep");
            FastWalk walk = new FastWalk(); walk.Roots = roots; List<object> hits = new List<object>(); object gate = new object(); int found = 0;
            Action<object> push = delegate (object o) { lock (gate) { hits.Add(o); found++; } if (found >= 20000) walk.Stop(); };
            HashSet<string> targets = null; bool md5 = false, sha1 = false, sha256 = false; long cap = (long)Math.Max(1, a.Int("max-mb", 100)) * 1048576L; bool skipWin = !a.Has("include-windows"); string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLowerInvariant();
            if (byHash) { int bad; targets = Hashes.ParseTargets(string.Join(" ", hashText.ToArray()), out md5, out sha1, out sha256, out bad); if (targets.Count == 0) throw new UsageException("no valid MD5, SHA-1 or SHA-256 hash in --hash" + (bad > 0 ? " (" + bad + " value(s) are not hashes)" : "")); Out.Note("sweeping " + targets.Count + " hash(es) under " + string.Join(", ", roots.ToArray()) + " · files up to " + (cap / 1048576) + " MB" + (skipWin ? " · skipping the Windows folder" : "")); }
            else Out.Note("searching " + name + " under " + string.Join(", ", roots.ToArray()) + (a.Has("match-case") ? " · match case" : ""));
            bool cs = a.Has("match-case"); Throttle th = new Throttle(300);
            RunOnThread(delegate
            {
                if (byHash) walk.Run(delegate (FileInfo fi) { long len; try { len = fi.Length; } catch { return; } if (len > cap) return; if (skipWin) { try { if (fi.FullName.ToLowerInvariant().StartsWith(win)) return; } catch { } } Dictionary<string, string> h; try { h = Hashes.Compute(fi.FullName, md5, sha1, sha256); } catch { return; } foreach (KeyValuePair<string, string> kv in h) if (targets.Contains(kv.Value)) { HashHit hit = new HashHit(); hit.Name = fi.Name; hit.Path = fi.FullName; hit.Dir = fi.DirectoryName; hit.Algo = kv.Key; hit.Hash = kv.Value; hit.Size = len; try { hit.Modified = fi.LastWriteTime; } catch { } push(hit); } });
                else walk.Run(delegate (FileInfo fi) { if (Wildcard.Match(fi.Name, name, cs)) { FileEntry e = new FileEntry(); e.Name = fi.Name; e.Path = fi.FullName; e.Dir = fi.DirectoryName; try { e.Size = fi.Length; e.Modified = fi.LastWriteTime; } catch { } e.Ext = fi.Extension.ToLowerInvariant(); push(e); } });
            }, walk.Stop, delegate { string cur = walk.Current ?? ""; if (cur.Length > 60) cur = "…" + cur.Substring(cur.Length - 60); th.Say((byHash ? "hashing" : "scanning") + " · " + walk.DirsScanned.ToString("N0") + " folders · " + walk.FilesSeen.ToString("N0") + " files · " + found.ToString("N0") + " match(es) · " + cur); });
            Out.Cards("matches", T(found.ToString("N0"), found > 0 ? Tone.Accent : Tone.Dim), "folders", walk.DirsScanned.ToString("N0"), "files", walk.FilesSeen.ToString("N0"), "denied", T(walk.Denied.ToString("N0"), WarnIfAny((int)Math.Min(int.MaxValue, walk.Denied))), "result", walk.Cancel ? (found >= 20000 ? "stopped at 20,000 matches" : "cancelled") : "done");
            View v = new View(byHash ? Columns.FindByHash() : Columns.FindByName()); v.Configure(a); lock (gate) v.Set(new List<object>(hits)); v.Show(a);
            return Cli.Cancelled ? Cli.CANCELLED : Cli.OK;
        }

        // ═══════════════════════════════ Duplicate Finder ═══════════════════════════════
        static int Duplicates(Args a)
        {
            ToolInfo info = Tools.ByKey("duplicates"); Out.Header(info);
            string root = Cli.FullFolder(a.Get("path", Environment.GetFolderPath(Environment.SpecialFolder.UserProfile))); if (!Directory.Exists(root)) throw new UsageException("--path: no such folder: " + root);
            double minB; if (!FilterRule.Number(a.Get("min", "100 KB").Replace("KB", " KB").Replace("MB", " MB").Replace("GB", " GB"), out minB)) throw new UsageException("--min: give a size such as 1KB, 100KB, 1MB or 10MB");
            DupeScan scan = new DupeScan(); scan.Roots = new List<string>(new string[] { root }); scan.MinBytes = (long)minB;
            Out.Note("scanning " + root + " · files ≥ " + Fmt.Bytes(minB)); Throttle th = new Throttle(400); List<DupeGroup> groups = new List<DupeGroup>();
            RunOnThread(delegate { groups = scan.Run(null); }, scan.Stop, delegate { string cur = scan.Current ?? ""; if (cur.Length > 60) cur = "…" + cur.Substring(cur.Length - 60); th.Say(scan.Phase + "… " + scan.FilesSeen.ToString("N0") + " files seen, " + scan.Hashed.ToString("N0") + " hashed · " + cur); });
            List<DupeFile> items = new List<DupeFile>(); long wasted = 0; int extra = 0; foreach (DupeGroup g in groups) { items.AddRange(g.Files); wasted += g.Wasted; extra += g.Count - 1; }
            Out.Cards("groups", groups.Count, "extra copies", T(extra.ToString(), WarnIfAny(extra)), "reclaimable", T(Fmt.Bytes(wasted), wasted > 0 ? Tone.Accent : Tone.Normal), "files seen", scan.FilesSeen.ToString("N0"), "hashed", scan.Hashed.ToString("N0"), "result", scan.Cancel ? "cancelled" : "done");
            View v = new View(Columns.Duplicates()); v.Configure(a); v.Set(Cli.Boxed(items)); v.Show(a);
            if (a.Has("recycle") || a.Has("recycle-extras"))
            {
                List<DupeFile> t = new List<DupeFile>();
                if (a.Has("recycle-extras")) { foreach (DupeFile d in items) if (!d.Keep) t.Add(d); }
                else { List<object> tt = Cli.ActionTargets(v, a, "--recycle"); if (tt == null) return Cli.USAGE; foreach (object o in tt) t.Add((DupeFile)o); }
                if (t.Count == 0) { Out.Warn("Nothing to recycle."); return Cli.OK; }
                int keepers = 0; long free = 0; foreach (DupeFile d in t) { if (d.Keep) keepers++; free += d.Size; }
                if (!Cli.Confirm(a, "Recycle " + t.Count + " file(s)?", "This sends " + t.Count + " file(s) to the Recycle Bin, freeing about " + Fmt.Bytes(free) + "." + (keepers > 0 ? " WARNING: " + keepers + " of them are marked \"keep\" (the only/oldest copy in their group) - removing those loses the last copy." : "") + " They go to the Recycle Bin, so this can be undone.")) return Cli.CANCELLED;
                int ok = 0; foreach (DupeFile d in t) { try { Cli.Recycle(d.Path, false); ok++; } catch (Exception ex) { Out.Warn(d.Name + ": " + ex.Message); } }
                Out.Ok(ok + " sent to the Recycle Bin");
            }
            return scan.Cancel ? Cli.CANCELLED : Cli.OK;
        }

        // ═══════════════════════════════ Vulnerability Management ═══════════════════════════════
        static int Vulnerabilities(Args a)
        {
            ToolInfo info = Tools.ByKey("vulnerabilities"); Out.Header(info); FeedCache cache = Cli.OpenCache();
            if (a.Has("feeds")) { Out.Line("Downloaded feeds are kept here so repeated scans are quick and an offline scan can still use the last copy: " + cache.Dir, Tone.Dim); int n = 0; try { foreach (string p in Directory.GetFiles(cache.Dir, "*.json")) { FileInfo fi = new FileInfo(p); Out.Line("  " + fi.LastWriteTime.ToString("yyyy-MM-dd HH:mm") + "   " + Fmt.Bytes(fi.Length).PadLeft(9) + "   " + fi.Name, Tone.Normal); n++; } } catch { } if (n == 0) Out.Line("  (empty - the first scan fills it)", Tone.Dim); return Cli.OK; }
            if (a.Has("clear-feeds")) { if (!Cli.Confirm(a, "Delete cached feeds", "Delete every cached feed file? The next scan downloads them again (the MSRC releases are about 10 MB each).")) return Cli.CANCELLED; int n = cache.Clear(); Out.Ok(n + " file(s) deleted"); return Cli.OK; }
            Settings st = Cli.S; string key = a.Get("nvd-key", st.Get("vuln.key", "")).Trim(); if (a.Has("nvd-key")) { st.Set("vuln.key", key); st.Save(); }
            VulnScan s = new VulnScan(); s.Cache = cache; s.NvdApiKey = key;
            s.DoWua = !a.Has("no-wua") && st.Get("vuln.wua", "1") == "1"; s.DoMsrc = !a.Has("no-msrc") && st.Get("vuln.msrc", "1") == "1"; s.DoNvd = !a.Has("no-nvd") && st.Get("vuln.nvd", "1") == "1"; s.DoKev = !a.Has("no-kev") && st.Get("vuln.kev", "1") == "1"; s.DoEpss = !a.Has("no-epss") && st.Get("vuln.epss", "1") == "1";
            s.Months = MonthsOption(a, st, 12);
            if (!s.DoWua && !s.DoMsrc && !s.DoNvd) { Out.Error("Keep at least one source: Windows Update, Microsoft CVEs or third-party."); return Cli.USAGE; }
            Out.Note("sources: " + (s.DoWua ? "Windows Update · " : "") + (s.DoMsrc ? "Microsoft CVEs (" + s.Months + "+ months, widened to the host's patch level) · " : "") + (s.DoNvd ? "third-party (NVD" + (key.Length > 0 ? ", keyed" : ", no key: one product every 6.5 s") + ") · " : "") + (s.DoKev ? "KEV · " : "") + (s.DoEpss ? "EPSS" : "") + " · feed cache " + cache.Dir);
            Throttle th = new Throttle(200); s.Progress += delegate (string m) { th.Say(m); }; s.Step += delegate (string label, string state, string note) { if (state == "running") Out.Note("· " + label); else if (state == "done" || state == "failed") Out.Note("  " + label + ": " + state + (note != null ? " · " + note : "")); };
            RunOnThread(s.Run, delegate { s.Cancel = true; }, null);
            List<Finding> fs = s.FindingsSnapshot(); int crit = 0, high = 0, kev = 0, open = 0; foreach (Finding f in fs) { if (!f.Open) continue; open++; if (f.SeverityNorm == "Critical") crit++; else if (f.SeverityNorm == "High") high++; if (f.Kev || f.Exploited) kev++; }
            List<MissingUpdate> ms = s.MissingSnapshot(); int sec = 0; foreach (MissingUpdate m in ms) if (m.Kind == "security" || m.Kind == "critical") sec++;
            List<Software> sw = s.SoftwareSnapshot(); int mapped = 0; foreach (Software x in sw) if (x.Mapped) mapped++;
            Out.Cards("OS build", s.Os != null ? s.Os.FullBuild + " · " + s.Os.ProductName + (s.Os.DisplayVersion.Length > 0 ? " " + s.Os.DisplayVersion : "") + " · " + s.Os.Arch : "?", "reboot", T(s.Reboot == null ? "?" : s.Reboot.Pending ? "pending · " + s.Reboot.Why : "none", s.Reboot != null && s.Reboot.Pending ? Tone.Warn : Tone.Good), "open findings", T(open.ToString(), GoodIfZero(open)), "critical", T(crit.ToString(), GoodIfZero(crit)), "high", T(high.ToString(), WarnIfAny(high)), "known exploited", T(kev.ToString(), GoodIfZero(kev)), "missing updates", T(ms.Count + " (" + sec + " security)", WarnIfAny(sec)), "software", sw.Count + " (" + mapped + " in the product map)");
            string show = a.Choice("show", "findings", "findings", "missing", "software", "hotfixes"); View v; List<object> rows;
            if (show == "findings")
            {
                v = new View(Columns.Findings()); rows = Cli.Boxed(fs);
                int sevMin = Resolve.SevRank(a.Has("severity") ? Resolve.NormSeverity(a.Choice("severity", "", "critical", "high", "medium")) : ""); string status = a.Choice("status", "open", "open", "all", "vulnerable", "update available", "reboot pending", "patched", "unconfirmed"); string source = a.Get("source", null); bool expl = a.Has("exploited");
                v.Filter = delegate (object o) { Finding f = (Finding)o; if (sevMin > 0 && Resolve.SevRank(f.SeverityNorm) < sevMin) return false; if (status == "open") { if (!f.Open) return false; } else if (status != "all" && f.Status != status) return false; if (source != null && !string.Equals(f.Source, source, StringComparison.OrdinalIgnoreCase)) return false; if (expl && !f.Kev && !f.Exploited) return false; return true; };
            }
            else if (show == "missing") { v = new View(Columns.MissingUpdates()); rows = Cli.Boxed(ms); }
            else if (show == "software") { v = new View(Columns.VulnSoftware()); rows = Cli.Boxed(sw); }
            else { v = new View(Columns.Hotfixes()); rows = Cli.Boxed(s.HotfixSnapshot()); }
            v.Configure(a); v.Set(rows); v.Show(a);
            if (a.Has("log")) { PrintLog("scan log", s.Errors, s.LogSnapshot()); if (s.Releases.Count > 0) Out.Line("MSRC releases checked: " + string.Join(", ", s.Releases.ToArray()), Tone.Dim); }
            else if (s.Errors.Count > 0) Out.Warn(s.Errors.Count + " problem(s) during the scan - add --log to see them.");
            return Cli.Cancelled ? Cli.CANCELLED : s.Errors.Count > 0 ? Cli.PROBLEMS : Cli.OK;
        }

        // ═══════════════════════════════ Software Inventory ═══════════════════════════════
        static void Summarize(Software s, List<Finding> vuln)
        {
            s.WorstSeverity = ""; s.WorstCve = ""; s.WorstCvss = null; s.Fix = ""; s.WorstEpss = null; s.Kev = false; s.Exploited = false;
            Finding worst = null; foreach (Finding f in vuln) { if (f.Kev) s.Kev = true; if (f.Exploited) s.Exploited = true; if (worst == null || f.SortScore > worst.SortScore) worst = f; }
            if (worst != null) { s.WorstSeverity = worst.SeverityNorm; s.WorstCve = worst.Cve; s.WorstCvss = worst.Cvss; s.Fix = worst.Fix; s.WorstEpss = worst.Epss; }
        }
        static string Short(string s) { s = (s ?? "").Replace("\r", " ").Replace("\n", " "); return s.Length > 60 ? s.Substring(0, 60) + "…" : s; }
        static int Software(Args a)
        {
            ToolInfo info = Tools.ByKey("software"); Out.Header(info);
            List<Software> items = Inventory.Installed(); int mappedN = 0; foreach (Software s in items) if (s.Mapped) mappedN++;
            if (a.Has("scan"))
            {
                FeedCache cache = Cli.OpenCache(); string key = a.Get("nvd-key", Cli.S.Get("vuln.key", "")).Trim(); if (a.Has("nvd-key")) { Cli.S.Set("vuln.key", key); Cli.S.Save(); }
                List<Software> targets = new List<Software>(); foreach (Software s in items) { if (!s.Mapped) continue; if (Ver.Parse(s.Version) == null) { s.Status = "version '" + s.Version + "' is not comparable"; continue; } targets.Add(s); }
                Out.Note("looking up " + targets.Count + " mapped program(s) on the NVD" + (key.Length > 0 ? " (keyed)" : " (no key: one product every 6.5 s)"));
                Dictionary<Software, List<Finding>> vulns = new Dictionary<Software, List<Finding>>(); int done = 0; bool doKev = !a.Has("no-kev"), doEpss = !a.Has("no-epss");
                foreach (Software s in targets)
                {
                    if (Cli.Cancelled) break; Out.Progress("NVD · " + s.Vendor + ":" + s.Product + " " + s.Version + " (" + (done + 1) + " of " + targets.Count + ")");
                    try
                    {
                        string note; List<CveRecord> recs = Nvd.ForProduct(s.Vendor, s.Product, s.Version, key, cache, delegate (string m) { Out.Progress(m); }, out note);
                        List<Finding> fs = Resolve.ThirdParty(s, recs); List<Finding> vuln = new List<Finding>(); int unconf = 0; foreach (Finding f in fs) { if (f.Status == "vulnerable") vuln.Add(f); else if (f.Status == "unconfirmed") unconf++; }
                        vulns[s] = vuln; s.Cves = vuln.Count; s.Unconfirmed = unconf; s.Status = vuln.Count == 0 ? (unconf > 0 ? unconf + " unconfirmed at " + s.Version + " (" + note + ")" : "no known CVEs at " + s.Version + " (" + note + ")") : vuln.Count + " CVE(s) at " + s.Version + " (" + note + ")"; Summarize(s, vuln);
                    }
                    catch (Exception ex) { s.Cves = -1; s.Status = "lookup failed: " + Short(ex.Message); }
                    done++;
                }
                if (doKev && !Cli.Cancelled) { Out.Progress("CISA KEV…"); try { string note; Dictionary<string, KevEntry> kev = Kev.Load(cache, out note); foreach (KeyValuePair<Software, List<Finding>> kv in vulns) foreach (Finding f in kv.Value) { KevEntry e; if (kev.TryGetValue(f.Cve, out e)) { f.Kev = true; f.Ransomware = e.Ransomware; } } } catch (Exception ex) { Out.Warn("KEV: " + Short(ex.Message)); } }
                if (doEpss && !Cli.Cancelled) { Out.Progress("EPSS…"); try { List<string> ids = new List<string>(); foreach (KeyValuePair<Software, List<Finding>> kv in vulns) foreach (Finding f in kv.Value) ids.Add(f.Cve); if (ids.Count > 0) { Dictionary<string, double> sc = Epss.Scores(ids, cache, delegate (string m) { Out.Progress(m); }); foreach (KeyValuePair<Software, List<Finding>> kv in vulns) foreach (Finding f in kv.Value) { double x; if (sc.TryGetValue(f.Cve, out x)) f.Epss = x; } } } catch (Exception ex) { Out.Warn("EPSS: " + Short(ex.Message)); } }
                foreach (KeyValuePair<Software, List<Finding>> kv in vulns) Summarize(kv.Key, kv.Value);
            }
            int total = items.Count, checkedN = 0, vulnN = 0, crit = 0, high = 0, expl = 0; foreach (Software s in items) { if (s.Cves >= 0) checkedN++; if (s.Vulnerable) { vulnN++; if (s.WorstSeverity == "Critical") crit++; else if (s.WorstSeverity == "High") high++; if (s.Kev || s.Exploited) expl++; } }
            Out.Cards("programs", total, "checked", checkedN, "vulnerable", T(vulnN.ToString(), checkedN > 0 ? GoodIfZero(vulnN) : Tone.Dim), "critical", T(crit.ToString(), GoodIfZero(crit)), "high", T(high.ToString(), WarnIfAny(high)), "exploited", T(expl.ToString(), GoodIfZero(expl)), "in CVE map", mappedN);
            if (!a.Has("scan")) Out.Line("add --scan to look the mapped programs up on the NVD and flag the vulnerable ones", Tone.Dim);
            View v = new View(Columns.Software()); int want = Resolve.SevRank(a.Has("severity") ? Resolve.NormSeverity(a.Choice("severity", "", "critical", "high", "medium")) : ""); bool vo = a.Has("vulnerable"), eo = a.Has("exploited"), mo = a.Has("mapped");
            v.Filter = delegate (object o) { Software s = (Software)o; if (mo && !s.Mapped) return false; if (vo && !s.Vulnerable) return false; if (eo && !(s.Kev || s.Exploited)) return false; if (want > 0 && Resolve.SevRank(s.WorstSeverity) < want) return false; return true; };
            v.Configure(a); v.Set(Cli.Boxed(items)); v.Show(a);
            return Cli.Cancelled ? Cli.CANCELLED : Cli.OK;
        }

        // ═══════════════════════════════ Autoruns ═══════════════════════════════
        static int Autoruns_(Args a)
        {
            ToolInfo info = Tools.ByKey("autoruns"); Out.Header(info);
            Throttle th = new Throttle(200); List<AutorunEntry> found = new List<AutorunEntry>();
            RunOnThread(delegate { found = PSTools.Autoruns.Collect(delegate (string m) { th.Say(m); }, delegate { return Cli.Cancelled; }); Out.Note("· " + found.Count + " entries, verifying signatures"); PSTools.Autoruns.Verify(found, delegate (int i, int n) { th.Say("verifying signatures… " + i + " / " + n); }, delegate { return Cli.Cancelled; }); }, null, null);
            int risky = 0, unsigned = 0, missing = 0; List<string> kinds = new List<string>(); foreach (AutorunEntry e in found) { if (e.Risk.Length > 0) risky++; if (e.Sig.Status == "unsigned" || e.Sig.Status == "invalid") unsigned++; if (e.Image.Length > 0 && !e.Exists) missing++; if (!kinds.Contains(e.Kind)) kinds.Add(e.Kind); }
            Out.Cards("entries", found.Count, "risky", T(risky.ToString(), GoodIfZero(risky)), "unsigned", T(unsigned.ToString(), WarnIfAny(unsigned)), "missing file", T(missing.ToString(), WarnIfAny(missing)), "kinds", kinds.Count);
            string kind = a.Get("kind", null); bool riskyOnly = a.Has("risky"), unsOnly = a.Has("unsigned"), nonMs = a.Has("non-microsoft");
            View v = new View(Columns.Autoruns());
            v.Filter = delegate (object o) { AutorunEntry e = (AutorunEntry)o; if (riskyOnly && e.Risk.Length == 0) return false; if (unsOnly && !(e.Sig.Status == "unsigned" || e.Sig.Status == "invalid")) return false; if (nonMs && e.Sig.Microsoft) return false; if (kind != null && !string.Equals(e.Kind, kind, StringComparison.OrdinalIgnoreCase)) return false; return true; };
            v.Configure(a); v.Set(Cli.Boxed(found)); v.Show(a);
            string what = a.Has("delete") ? "delete" : a.Has("disable") ? "disable" : a.Has("enable") ? "enable" : null; if (what == null) return Cli.Cancelled ? Cli.CANCELLED : Cli.OK;
            List<object> t = Cli.ActionTargets(v, a, "--" + what); if (t == null) return Cli.USAGE; if (t.Count == 0) return Cli.OK;
            if (Cli.NeedAdmin(what == "delete" ? "Deleting an autostart entry" : (what == "disable" ? "Disabling" : "Enabling") + " an autostart entry")) return Cli.ADMIN;
            List<AutorunEntry> l = new List<AutorunEntry>(); foreach (object o in t) l.Add((AutorunEntry)o);
            if (what == "delete") { if (!Cli.Confirm(a, "Delete " + l.Count + " entry(ies)?", "This permanently removes them so they no longer start automatically: " + Cli.Preview(l.ConvertAll(delegate (AutorunEntry e) { return e.Kind + ": " + e.Name; }), 15) + ". Services and tasks it runs are removed; the program files themselves are left on disk.")) return Cli.CANCELLED; }
            else if (!Cli.Confirm(a, (what == "disable" ? "Disable " : "Enable ") + l.Count + " entry(ies)?", Cli.Preview(l.ConvertAll(delegate (AutorunEntry e) { return e.Kind + ": " + e.Name; }), 15))) return Cli.CANCELLED;
            int ok = 0, fail = 0; foreach (AutorunEntry e in l) { string err = what == "delete" ? PSTools.Autoruns.Delete(e) : PSTools.Autoruns.SetEnabled(e, what == "enable"); if (err == null) ok++; else { fail++; Out.Warn(e.Name + ": " + err); } }
            Out.Ok(ok + " " + (what == "delete" ? "deleted" : what + "d") + (fail > 0 ? ", " + fail + " failed" : ""));
            return fail > 0 ? Cli.PROBLEMS : Cli.OK;
        }

        // ═══════════════════════════════ Event Log Triage ═══════════════════════════════
        static int Events_(Args a)
        {
            ToolInfo info = Tools.ByKey("events"); Out.Header(info);
            string since = a.Choice("since", "24h", "1h", "24h", "7d", "30d"); DateTime from = DateTime.Now.AddHours(since == "1h" ? -1 : since == "24h" ? -24 : since == "7d" ? -168 : -720);
            int max = int.Parse(a.Choice("max", "100", "50", "100", "250", "500")); List<string> notes = new List<string>(); List<EventRow> rows = new List<EventRow>();
            RunOnThread(delegate { rows = EventHunt.Collect(EventHunt.Specs, from, max, delegate (string cname) { Out.Progress("reading " + cname + "…"); }, delegate { return Cli.Cancelled; }, delegate (string n) { lock (notes) notes.Add(n); }); }, null, null);
            int hi = 0, failed = 0; List<string> cats = new List<string>(); DateTime oldest = DateTime.MaxValue; foreach (EventRow e in rows) { if (e.Risk == "high") hi++; if (e.Category == "Failed logon") failed++; if (!cats.Contains(e.Category)) cats.Add(e.Category); if (e.Time != DateTime.MinValue && e.Time < oldest) oldest = e.Time; }
            Out.Cards("events", rows.Count, "high-risk", T(hi.ToString(), GoodIfZero(hi)), "failed logons", T(failed.ToString(), WarnIfAny(failed)), "categories", cats.Count + " of " + EventHunt.Categories().Count, "earliest", oldest == DateTime.MaxValue ? "—" : oldest.ToString("MM-dd HH:mm"), "since", since);
            if (notes.Count > 0) Out.Warn(notes.Count + " log(s) need administrator rights" + (Cli.IsElevated ? "" : " - run from an elevated prompt for the Security log") + ": " + Cli.Preview(notes, 4));
            string cat = a.Get("category", null); bool risky = a.Has("risky");
            View v = new View(Columns.Events()); v.Filter = delegate (object o) { EventRow e = (EventRow)o; if (risky && e.Risk.Length == 0) return false; if (cat != null && !string.Equals(e.Category, cat, StringComparison.OrdinalIgnoreCase)) return false; return true; };
            v.Configure(a); v.Set(Cli.Boxed(rows)); v.Show(a);
            return Cli.Cancelled ? Cli.CANCELLED : Cli.OK;
        }

        // ═══════════════════════════════ Security Checklist ═══════════════════════════════
        static int Checklist(Args a)
        {
            ToolInfo info = Tools.ByKey("checklist"); Out.Header(info);
            if (!Cli.IsElevated) Out.Warn("Running without administrator rights: BitLocker and some checks will report N/A.");
            ChecklistScan s = new ChecklistScan(); try { s.Report.Os = Inventory.Os().Summary; } catch { } Throttle th = new Throttle(150);
            s.Progress += delegate (string m) { th.Say(m); }; s.Step += delegate (string label, string state, string note) { if (state == "running") Out.Note("· " + label); };
            RunOnThread(s.Run, delegate { s.Cancel = true; }, null);
            if (a.Has("active") && !Cli.Cancelled)
            {
                if (Cli.Confirm(a, "Run active tests", "Two checks: the EICAR anti-malware test writes the harmless EICAR standard test file to your temp folder and checks that real-time antivirus removes it - your antivirus WILL alert on that one file and quarantine it; that is the pass. Application control reads the AppLocker / SRP / WDAC / SmartScreen policy from the registry; it does not run or drop anything."))
                {
                    Out.Note("· EICAR"); CheckItem e = ActiveTests.Eicar(); s.Report.Items.Add(e); Out.Note("  EICAR: " + (e.Status == "pass" ? "detected" : "not detected"));
                    Out.Note("· App control"); List<CheckItem> ep = ActiveTests.AppControl(delegate (string m) { th.Say(m); }); foreach (CheckItem c in ep) s.Report.Items.Add(c); Out.Note("  App control: " + ep.Count + " check(s)");
                }
            }
            CheckReport r = s.Report;
            Out.Cards("score", T(r.Score + "/100", r.Score >= 80 ? Tone.Good : r.Score >= 50 ? Tone.Warn : Tone.Bad), "fail", T(r.Fail.ToString(), GoodIfZero(r.Fail)), "review", T(r.Warn.ToString(), WarnIfAny(r.Warn)), "pass", T(r.Pass.ToString(), Tone.Good), "not checked", r.Count("na"), "categories", r.Categories().Count, "elevated", T(r.Elevated ? "yes" : "no", r.Elevated ? Tone.Good : Tone.Warn));
            string cat = a.Get("category", null); string show = a.Choice("show", "everything", "everything", "failures", "fail", "review", "pass", "info");
            View v = new View(Columns.Checklist());
            v.Filter = delegate (object o) { CheckItem i = (CheckItem)o; if (cat != null && !string.Equals(i.Category, cat, StringComparison.OrdinalIgnoreCase)) return false; switch (show) { case "failures": return i.Status == "fail" || i.Status == "warn"; case "fail": return i.Status == "fail"; case "review": return i.Status == "warn"; case "pass": return i.Status == "pass"; case "info": return i.Status == "info" || i.Status == "na"; } return true; };
            v.Configure(a); v.Set(Cli.Boxed(s.Snapshot())); v.Show(a);
            SaveReports(a, r.FileStem, r.ToMarkdown, r.ToJson, r.SavePdf);
            if (a.Has("log")) PrintLog("checklist log", s.Errors, s.LogSnapshot()); else if (s.Errors.Count > 0) Out.Warn(s.Errors.Count + " check(s) could not run - add --log to see which.");
            return Cli.Cancelled ? Cli.CANCELLED : Cli.OK;
        }

        // ═══════════════════════════════ Secrets Scanner ═══════════════════════════════
        static int Secrets_(Args a)
        {
            ToolInfo info = Tools.ByKey("secrets"); Out.Header(info);
            string root = Cli.FullFolder(a.Get("path", Environment.GetFolderPath(Environment.SpecialFolder.UserProfile))); if (!Directory.Exists(root)) throw new UsageException("--path: no such folder: " + root);
            SecretsScan scan = new SecretsScan(); scan.Roots = new List<string>(new string[] { root }); scan.MaxFileKB = int.Parse(a.Choice("max-kb", "1024", "256", "1024", "4096"));
            List<SecretHit> hits = new List<SecretHit>(); object gate = new object(); Throttle th = new Throttle(300);
            Out.Note("scanning " + root + " · files up to " + scan.MaxFileKB + " KB");
            RunOnThread(delegate { scan.Run(delegate (SecretHit h) { lock (gate) hits.Add(h); }, delegate { string cur = scan.Current ?? ""; if (cur.Length > 60) cur = "…" + cur.Substring(cur.Length - 60); th.Say("scanning… " + scan.FilesScanned.ToString("N0") + " files read, " + hits.Count + " hits · " + cur); }); }, scan.Stop, null);
            int hi = 0; List<string> kinds = new List<string>(); foreach (SecretHit h in hits) { if (h.Severity == "high") hi++; if (!kinds.Contains(h.Kind)) kinds.Add(h.Kind); }
            Out.Cards("secrets", T(hits.Count.ToString(), hits.Count > 0 ? Tone.Warn : Tone.Good), "high", T(hi.ToString(), GoodIfZero(hi)), "files read", scan.FilesScanned.ToString("N0"), "kinds", kinds.Count, "folders", scan.DirsScanned.ToString("N0"), "result", scan.Cancel ? "cancelled" : "done");
            string sev = a.Get("severity", null); if (sev != null) sev = a.Choice("severity", "", "high", "medium"); bool writable = a.Has("writable");
            View v = new View(Columns.Secrets()); v.Filter = delegate (object o) { SecretHit h = (SecretHit)o; if (writable && h.Where != "user-writable" && h.Where != "other") return false; if (sev == "high" && h.Severity != "high") return false; if (sev == "medium" && h.Severity == "low") return false; return true; };
            v.Configure(a); v.Set(Cli.Boxed(hits)); v.Show(a);
            return scan.Cancel ? Cli.CANCELLED : Cli.OK;
        }

        // ═══════════════════════════════ Wi-Fi & Credentials ═══════════════════════════════
        static int Credentials(Args a)
        {
            ToolInfo info = Tools.ByKey("credentials"); Out.Header(info);
            string show = a.Choice("show", "wifi", "wifi", "vault"); bool reveal = a.Has("reveal");
            if (reveal && !Cli.Confirm(a, "Reveal saved secrets", show == "wifi" ? "This puts the saved Wi-Fi passwords on screen in clear text. Make sure nobody is looking over your shoulder." : "This puts a masked preview of the stored secrets on screen. Only credentials your account can read are shown.")) return Cli.CANCELLED;
            string wnote; List<WifiProfile> wifi = Creds.Wifi(out wnote, reveal); string vnote; List<VaultCred> vault = Creds.Vault(out vnote, reveal);
            int weak = 0, open = 0; foreach (WifiProfile w in wifi) { if (w.Risk == "high") { if (w.Authentication.ToLowerInvariant().Contains("open") || w.Authentication.Length == 0) open++; weak++; } else if (w.Risk == "medium") weak++; }
            int shown = 0; if (reveal) foreach (WifiProfile w in wifi) if (w.HasKey) shown++;
            Out.Cards("saved", (show == "wifi" ? wifi.Count : vault.Count) + (show == "wifi" ? " networks" : " credentials"), "weak Wi-Fi", T(weak.ToString(), WarnIfAny(weak)), "open networks", T(open.ToString(), GoodIfZero(open)), "vault items", vault.Count, "keys shown", T(reveal ? shown.ToString() : "hidden", reveal ? Tone.Warn : Tone.Dim));
            string note = show == "wifi" ? wnote : vnote; if (note.Length > 0) Out.Warn(note);
            View v = new View(show == "wifi" ? Columns.Wifi(delegate { return reveal; }) : Columns.Vault(delegate { return reveal; })); v.Configure(a); v.Set(show == "wifi" ? Cli.Boxed(wifi) : Cli.Boxed(vault)); v.Show(a);
            return Cli.OK;
        }

        // ═══════════════════════════════ Browsing Data ═══════════════════════════════
        static int Browsing(Args a)
        {
            ToolInfo info = Tools.ByKey("browsing"); Out.Header(info);
            string mode = a.Choice("show", "history", "history", "domains", "downloads", "searches", "passwords"); string which = a.Get("browser", null); string maxS = a.Choice("max", "5000", "1000", "5000", "20000", "all"); int max = maxS == "all" ? int.MaxValue : int.Parse(maxS); bool reveal = a.Has("reveal") && mode == "passwords";
            List<BrowserProfile> profiles; try { profiles = Browser.Profiles(); } catch { profiles = new List<BrowserProfile>(); }
            List<BrowserProfile> targets = new List<BrowserProfile>(); foreach (BrowserProfile p in profiles) if (which == null || p.Label.IndexOf(which, StringComparison.OrdinalIgnoreCase) >= 0) targets.Add(p);
            Out.Line("browsers: " + (profiles.Count == 0 ? "none found" : string.Join("  ·  ", profiles.ConvertAll(delegate (BrowserProfile p) { return p.Label; }).ToArray())), Tone.Dim);
            if (targets.Count == 0) { Out.Error(profiles.Count == 0 ? "no supported browsers found" : "no browser profile matches --browser " + which); return Cli.PROBLEMS; }
            if (reveal && !Cli.Confirm(a, "Reveal saved passwords", "This decrypts and shows the passwords this browser saved, in clear text. They are decrypted locally with your own Windows account - nothing leaves this machine - but make sure nobody is looking over your shoulder. Passwords protected by newer app-bound encryption, or a Firefox master password, may not be recoverable and will show a note instead.")) return Cli.CANCELLED;
            List<VisitRow> h = new List<VisitRow>(), d = new List<VisitRow>(), s = new List<VisitRow>(); List<LoginRow> lg = new List<LoginRow>(); int skipped = 0;
            foreach (BrowserProfile p in targets)
            {
                Out.Progress("reading " + mode + " · " + p.Label);
                try
                {
                    if (mode == "history" || mode == "domains") h.AddRange(Browser.History(p, max)); else if (mode == "downloads") d.AddRange(Browser.Downloads(p)); else if (mode == "searches") s.AddRange(Browser.Searches(p));
                    else { if (p.Family == "chromium") lg.AddRange(BrowserCreds.Chromium(p, Directory.GetParent(p.Dir).FullName, reveal)); else lg.AddRange(BrowserCreds.Firefox(p, reveal)); }
                }
                catch (Exception ex) { skipped++; Out.Warn(p.Label + ": " + Short(ex.Message)); }
            }
            View v; List<object> rows; bool insecure = a.Has("insecure");
            List<string> browsers = new List<string>(); foreach (BrowserProfile p in targets) if (!browsers.Contains(p.Browser)) browsers.Add(p.Browser);
            if (mode == "passwords")
            {
                int weak = 0, dec = 0; List<string> sites = new List<string>(); foreach (LoginRow l in lg) { if (l.Weak) weak++; if (reveal && l.Password.Length > 0) dec++; string x = l.Domain.Length > 0 ? l.Domain : l.Url; if (!sites.Contains(x)) sites.Add(x); }
                Out.Cards("saved logins", lg.Count, "browsers", browsers.Count, "sites", sites.Count, "passwords", T(reveal ? dec + " decrypted" : "hidden", reveal ? Tone.Warn : Tone.Dim), "weak (<8 chars)", T(weak.ToString(), GoodIfZero(weak)));
                v = new View(Columns.BrowserPasswords(delegate { return reveal; })); rows = Cli.Boxed(lg);
            }
            else if (mode == "domains")
            {
                List<DomainStat> stats = Browser.Domains(h); long visits = 0; foreach (DomainStat ds in stats) visits += ds.Visits;
                Out.Cards("unique sites", stats.Count.ToString("N0"), "browsers", browsers.Count, "total visits", T(visits.ToString("N0"), Tone.Accent), "top site", T(stats.Count > 0 ? stats[0].Domain + " (" + stats[0].Visits + " visits)" : "—", Tone.Accent));
                v = new View(Columns.BrowserDomains(stats)); rows = Cli.Boxed(stats);
            }
            else
            {
                List<VisitRow> list = mode == "history" ? h : mode == "downloads" ? d : s; list.Sort(delegate (VisitRow x, VisitRow y) { return y.When.CompareTo(x.When); });
                Dictionary<string, int> dom = new Dictionary<string, int>(); DateTime oldest = DateTime.MaxValue, newest = DateTime.MinValue; foreach (VisitRow vr in list) { if (vr.Domain.Length > 0) { int n; dom.TryGetValue(vr.Domain, out n); dom[vr.Domain] = n + 1; } if (vr.When != DateTime.MinValue) { if (vr.When < oldest) oldest = vr.When; if (vr.When > newest) newest = vr.When; } }
                string top = ""; int topN = 0; foreach (KeyValuePair<string, int> kv in dom) if (kv.Value > topN) { topN = kv.Value; top = kv.Key; }
                Out.Cards("records", list.Count.ToString("N0") + " " + mode, "browsers", browsers.Count, "distinct sites", dom.Count.ToString("N0"), "top site", T(top.Length > 0 ? top + " (" + topN + ")" : "—", Tone.Accent), "span", oldest == DateTime.MaxValue ? "—" : oldest.ToString("yyyy-MM-dd") + " to " + newest.ToString("MM-dd"));
                v = new View(mode == "history" ? Columns.BrowserHistory() : mode == "downloads" ? Columns.BrowserDownloads() : Columns.BrowserSearches()); rows = Cli.Boxed(list);
            }
            v.Filter = delegate (object o) { if (!insecure) return true; if (o is VisitRow) return !((VisitRow)o).Secure; if (o is LoginRow) return ((LoginRow)o).Url.StartsWith("http:", StringComparison.OrdinalIgnoreCase); return true; };
            v.Configure(a); v.Set(rows); v.Show(a);
            if (skipped > 0) Out.Warn(skipped + " source(s) skipped");
            return Cli.OK;
        }
    }
}

// Collect.cs - the collector: runs the read-only engines on this host and writes everything they find into one
// bundle (.ptb, Bundle.cs). No network unless asked (and then only the Windows Update search), no writes outside its
// own output, every module time-boxed and failure-contained: a module that breaks records why and the bundle is
// still produced. The same code serves `PowerTowerCli collect` and the stand-alone PowerTowerCollect.exe that the
// agentless controller stages on a target. Codec turns engine objects into the plain JSON tree and back; secret
// values and live handles never cross.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.Net;
using System.Reflection;
using System.Security.Principal;
using System.Text;
using System.Threading;

namespace PSTools
{
    // ───────────────────────────── engine objects <-> bundle trees ─────────────────────────────
    public static class Codec
    {
        static Dictionary<string, object> D() { return new Dictionary<string, object>(); }
        static string S(object o, string k) { return Json.GetS(o, k) ?? ""; }
        static bool B(object o, string k) { return JsonWrite.Bool(Json.Get(o, k)); }
        static int I(object o, string k) { return JsonWrite.Int(Json.Get(o, k), 0); }
        static double? N(object o, string k) { return Json.N(Json.Get(o, k)); }
        static DateTime? T(object o, string k) { return JsonWrite.Date(Json.Get(o, k)); }
        public static List<object> Many<T>(IEnumerable<T> items, Func<T, object> f) { List<object> l = new List<object>(); if (items != null) foreach (T t in items) l.Add(f(t)); return l; }

        public static Dictionary<string, object> Os(OsInfo o)
        {
            Dictionary<string, object> d = D(); d["productName"] = o.ProductName; d["edition"] = o.Edition; d["displayVersion"] = o.DisplayVersion; d["arch"] = o.Arch; d["host"] = o.Host;
            d["major"] = o.Major; d["minor"] = o.Minor; d["build"] = o.Build; d["ubr"] = o.Ubr; d["fullBuild"] = o.FullBuild; d["summary"] = o.Summary; d["installed"] = o.Installed.HasValue ? (object)o.Installed.Value : null; return d;
        }
        public static OsInfo OsFrom(object t)
        {
            OsInfo o = new OsInfo(); if (t == null) return o; o.ProductName = S(t, "productName"); o.Edition = S(t, "edition"); o.DisplayVersion = S(t, "displayVersion"); o.Arch = S(t, "arch"); o.Host = S(t, "host");
            o.Major = I(t, "major"); o.Minor = I(t, "minor"); o.Build = I(t, "build"); o.Ubr = I(t, "ubr"); o.Installed = T(t, "installed"); return o;
        }
        public static Dictionary<string, object> Reboot(RebootInfo r) { Dictionary<string, object> d = D(); d["cbs"] = r.Cbs; d["windowsUpdate"] = r.WindowsUpdate; d["pendingFileRename"] = r.PendingFileRename; d["pending"] = r.Pending; d["why"] = r.Why; return d; }
        public static RebootInfo RebootFrom(object t) { RebootInfo r = new RebootInfo(); if (t == null) return r; r.Cbs = B(t, "cbs"); r.WindowsUpdate = B(t, "windowsUpdate"); r.PendingFileRename = B(t, "pendingFileRename"); return r; }
        public static Dictionary<string, object> Software(Software s)
        {
            Dictionary<string, object> d = D(); d["name"] = s.Name; d["version"] = s.Version; d["publisher"] = s.Publisher; d["installDate"] = s.InstallDate; d["scope"] = s.Scope; d["vendor"] = s.Vendor; d["product"] = s.Product; d["ecosystem"] = "windows"; return d;
        }
        public static Software SoftwareFrom(object t)
        {
            Software s = new Software(); s.Name = S(t, "name"); s.Version = S(t, "version"); s.Publisher = S(t, "publisher"); s.InstallDate = S(t, "installDate"); s.Scope = S(t, "scope"); s.Vendor = Json.GetS(t, "vendor"); s.Product = Json.GetS(t, "product"); return s;
        }
        public static Dictionary<string, object> Hotfix(Hotfix h) { Dictionary<string, object> d = D(); d["kb"] = h.Kb; d["description"] = h.Description; d["source"] = h.Source; d["title"] = h.Title; d["result"] = h.Result; d["installedOn"] = h.InstalledOn.HasValue ? (object)h.InstalledOn.Value : null; return d; }
        public static Hotfix HotfixFrom(object t) { Hotfix h = new Hotfix(); h.Kb = S(t, "kb"); h.Description = S(t, "description"); h.Source = S(t, "source"); h.Title = S(t, "title"); h.Result = S(t, "result"); h.InstalledOn = T(t, "installedOn"); return h; }
        public static Dictionary<string, object> Missing(MissingUpdate m)
        {
            Dictionary<string, object> d = D(); d["kb"] = m.Kb; d["title"] = m.Title; d["severity"] = m.Severity; d["kind"] = m.Kind; d["updateId"] = m.UpdateId; d["reboot"] = m.Reboot; d["categories"] = m.Categories; d["cves"] = new List<string>(m.Cves);
            d["downloaded"] = m.Downloaded; d["mandatory"] = m.Mandatory; d["sizeBytes"] = m.SizeBytes; d["published"] = m.Published.HasValue ? (object)m.Published.Value : null; return d;
        }
        public static MissingUpdate MissingFrom(object t)
        {
            MissingUpdate m = new MissingUpdate(); m.Kb = S(t, "kb"); m.Title = S(t, "title"); m.Severity = S(t, "severity"); m.Kind = S(t, "kind"); m.UpdateId = S(t, "updateId"); m.Reboot = S(t, "reboot"); m.Categories = S(t, "categories"); m.Cves.AddRange(JsonWrite.Strings(Json.Get(t, "cves")));
            m.Downloaded = B(t, "downloaded"); m.Mandatory = B(t, "mandatory"); double? sz = N(t, "sizeBytes"); m.SizeBytes = sz.HasValue ? sz.Value : 0; m.Published = T(t, "published"); return m;
        }
        public static Dictionary<string, object> Finding(Finding f)
        {
            Dictionary<string, object> d = D(); d["cve"] = f.Cve; d["title"] = f.Title; d["severity"] = f.Severity; d["severityNorm"] = f.SeverityNorm; d["source"] = f.Source; d["product"] = f.Product; d["installed"] = f.Installed; d["fix"] = f.Fix; d["status"] = f.Status; d["open"] = f.Open;
            d["evidence"] = f.Evidence; d["description"] = f.Description; d["url"] = f.Url; d["release"] = f.Release; d["cvss"] = f.Cvss.HasValue ? (object)f.Cvss.Value : null; d["epss"] = f.Epss.HasValue ? (object)f.Epss.Value : null; d["kev"] = f.Kev; d["exploited"] = f.Exploited; d["ransomware"] = f.Ransomware; d["kevDue"] = f.KevDue; return d;
        }
        public static Finding FindingFrom(object t)
        {
            Finding f = new Finding(); f.Cve = S(t, "cve"); f.Title = S(t, "title"); f.Severity = S(t, "severity"); f.Source = S(t, "source"); f.Product = S(t, "product"); f.Installed = S(t, "installed"); f.Fix = S(t, "fix"); f.Status = S(t, "status");
            f.Evidence = S(t, "evidence"); f.Description = S(t, "description"); f.Url = S(t, "url"); f.Release = S(t, "release"); f.Cvss = N(t, "cvss"); f.Epss = N(t, "epss"); f.Kev = B(t, "kev"); f.Exploited = B(t, "exploited"); f.Ransomware = B(t, "ransomware"); f.KevDue = S(t, "kevDue"); return f;
        }
        public static Dictionary<string, object> Check(CheckItem c) { Dictionary<string, object> d = D(); d["id"] = c.Id; d["category"] = c.Category; d["name"] = c.Name; d["question"] = c.Question; d["status"] = c.Status; d["detail"] = c.Detail; d["evidence"] = c.Evidence; return d; }
        public static CheckItem CheckFrom(object t) { CheckItem c = new CheckItem(S(t, "category"), S(t, "name"), S(t, "question"), S(t, "status"), S(t, "detail"), S(t, "evidence")); c.Id = S(t, "id"); return c; }
        public static Dictionary<string, object> Recon(ReconItem r) { Dictionary<string, object> d = D(); d["section"] = r.Section; d["group"] = r.Group; d["name"] = r.Name; d["value"] = r.Value; d["note"] = r.Note; d["risk"] = r.Risk; return d; }
        public static ReconItem ReconFrom(object t) { return new ReconItem(S(t, "section"), S(t, "group"), S(t, "name"), S(t, "value"), S(t, "note"), S(t, "risk")); }
        public static Dictionary<string, object> Autorun(AutorunEntry e)
        {
            Dictionary<string, object> d = D(); d["kind"] = e.Kind; d["name"] = e.Name; d["command"] = e.Command; d["image"] = e.Image; d["location"] = e.Location; d["scope"] = e.Scope; d["description"] = e.Description; d["company"] = e.Company; d["note"] = e.Note;
            d["enabled"] = e.Enabled; d["exists"] = e.Exists; d["where"] = e.Where; d["risk"] = e.Risk; d["riskWhy"] = e.RiskWhy;
            Dictionary<string, object> v = D(); v["method"] = "authenticode"; v["status"] = e.Sig.Status; v["signer"] = e.Sig.Signer; v["detail"] = e.Sig.Detail; v["ok"] = e.Sig.Ok; v["microsoft"] = e.Sig.Microsoft; d["verified"] = v; return d;
        }
        public static Dictionary<string, object> Event(EventRow e) { Dictionary<string, object> d = D(); d["time"] = e.Time; d["id"] = e.Id; d["log"] = e.Log; d["source"] = e.Source; d["level"] = e.Level; d["category"] = e.Category; d["who"] = e.Who; d["detail"] = e.Detail; d["computer"] = e.Computer; d["risk"] = e.Risk; return d; }
        public static Dictionary<string, object> Conn(Conn c) { Dictionary<string, object> d = D(); d["proto"] = c.Proto; d["local"] = c.Local; d["localPort"] = c.LocalPort; d["remote"] = c.Remote; d["remotePort"] = c.RemotePort; d["state"] = c.State; d["pid"] = c.Pid; d["process"] = c.Process; d["host"] = c.Host; d["loopback"] = c.Loopback; return d; }
        public static Dictionary<string, object> Rule(FwRule f)
        {
            Dictionary<string, object> d = D(); d["name"] = f.Name; d["group"] = f.Group; d["direction"] = f.Direction; d["action"] = f.Action; d["program"] = f.Program; d["service"] = f.Service; d["protocol"] = f.Protocol; d["localPorts"] = f.LocalPorts; d["remotePorts"] = f.RemotePorts; d["remoteAddresses"] = f.RemoteAddresses; d["profiles"] = f.Profiles; d["enabled"] = f.Enabled; d["risk"] = f.Risk; d["riskWhy"] = f.RiskWhy; return d;
        }
        public static Dictionary<string, object> Profile(FwProfile p) { Dictionary<string, object> d = D(); d["name"] = p.Name; d["on"] = p.On; d["defaultInbound"] = p.DefaultInbound; d["defaultOutbound"] = p.DefaultOutbound; d["notifyOnBlock"] = p.NotifyOnBlock; return d; }
        public static Dictionary<string, object> HostsEntry(HostsEntry h) { Dictionary<string, object> d = D(); d["host"] = h.Host; d["sink"] = h.Sink; d["line"] = h.LineNo; d["ours"] = h.Ours; return d; }
        /// <summary>Kind, place, severity, the masked preview and a SHA-256 of the match - never the match itself.</summary>
        public static Dictionary<string, object> Secret(SecretHit h)
        {
            Dictionary<string, object> d = D(); d["kind"] = h.Kind; d["severity"] = h.Severity; d["path"] = h.Path; d["file"] = h.File; d["line"] = h.Line; d["preview"] = h.Preview; d["entropy"] = h.Entropy; d["where"] = h.Where;
            d["sha256"] = BundleCrypto.Sha256Hex(Encoding.UTF8.GetBytes(h.Match ?? "")); return d;
        }
    }

    // ───────────────────────────── the collector ─────────────────────────────
    public class Collector
    {
        public const string Name = "PowerTowerCollect";
        public static readonly string[] AllModules = { "inventory", "checklist", "recon", "persistence", "events", "network", "secrets", "ioc" };
        /// <summary>secrets (privacy) and ioc (needs a list) are opt-in.</summary>
        public static readonly string[] DefaultModules = { "inventory", "checklist", "recon", "persistence", "events", "network" };
        public readonly List<string> Modules = new List<string>(DefaultModules);
        public bool Online;                 // the Windows Update search for missing updates is the collector's only network use, and only when asked
        public bool WuHistory = true;       // the WUA history is local but slow-ish; tests switch it off
        public int EventDays = 30, EventsPerCategory = 500, SecretsMaxFileKB = 1024, IocHashCapMB = 32, BudgetSeconds = 0;
        public readonly List<string> SecretRoots = new List<string>();
        public string IocFile;
        public Engagement Engagement;
        public string RunId = Guid.NewGuid().ToString("N").Substring(0, 12);
        public Action<string> Progress; public volatile bool Cancel;
        public readonly List<string> Log = new List<string>();
        List<AutorunEntry> autoruns; List<Conn> conns; DateTime started;

        void Say(string s) { Log.Add(DateTime.Now.ToString("HH:mm:ss") + "  " + s); if (Progress != null) Progress(s); }
        bool Cancelled() { return Cancel || (BudgetSeconds > 0 && (DateTime.UtcNow - started).TotalSeconds > BudgetSeconds); }
        public static bool IsAdmin() { try { return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); } catch { return false; } }
        static List<string> LocalNames()
        {
            List<string> l = new List<string>(); l.Add(Environment.MachineName);
            try { string fq = Dns.GetHostEntry("").HostName; if (!l.Contains(fq)) l.Add(fq); } catch { }
            try { foreach (IPAddress ip in Dns.GetHostAddresses(Dns.GetHostName())) l.Add(ip.ToString()); } catch { }
            return l;
        }

        public Bundle Run()
        {
            started = DateTime.UtcNow; Bundle b = new Bundle(); bool admin = IsAdmin();
            Dictionary<string, object> col = new Dictionary<string, object>(); col["name"] = Name; string exe = ""; try { exe = Assembly.GetEntryAssembly().Location; } catch { }
            col["version"] = Assembly.GetExecutingAssembly().GetName().Version.ToString(2); col["exe"] = Path.GetFileName(exe); try { col["sha256"] = exe.Length > 0 ? BundleCrypto.FileSha256(exe) : ""; } catch { col["sha256"] = ""; }
            b.Manifest["runId"] = RunId; b.Manifest["engagementId"] = Engagement != null ? Engagement.Id : ""; b.Manifest["host"] = Environment.MachineName; b.Manifest["domain"] = Environment.UserDomainName; b.Manifest["platform"] = "windows"; b.Manifest["mode"] = "live";
            b.Manifest["collector"] = col; b.Manifest["startedUtc"] = started; b.Manifest["user"] = Environment.UserDomainName + "\\" + Environment.UserName; b.Manifest["elevated"] = admin; b.Manifest["privilegeTier"] = admin ? "A" : "B";
            List<string> run = new List<string>(Modules), skipped = new List<string>();
            if (Engagement != null)
            {
                string why; List<string> names = LocalNames(); bool inScope = false; foreach (string n in names) if (Engagement.InScope(n, out why)) { inScope = true; break; }
                if (!inScope) throw new BundleException("this host (" + string.Join(", ", names.ToArray()) + ") is not in the engagement scope - nothing was collected");
                if (!Engagement.InWindow(DateTime.UtcNow, out why)) throw new BundleException(why + " - nothing was collected");
                foreach (string m in Modules) if (!Engagement.ModuleAllowed(m)) { skipped.Add(m); run.Remove(m); }
            }
            foreach (string m in Modules)
            {
                if (skipped.Contains(m)) { b.Module(m, "skipped", 0, 0, new List<string>(new string[] { "not in the engagement's module list" })); continue; }
                if (Array.IndexOf(AllModules, m) < 0) { b.Module(m, "failed", 0, 0, new List<string>(new string[] { "unknown module" })); continue; }
                if (Cancelled()) { b.Module(m, "skipped", 0, 0, new List<string>(new string[] { "cancelled or over the time budget" })); continue; }
                Stopwatch sw = Stopwatch.StartNew(); List<string> errors = new List<string>(); int count = 0; string status = "ok";
                Say("· " + m);
                try
                {
                    switch (m)
                    {
                        case "inventory": count = Inventory_(b, errors); break;
                        case "checklist": count = Checklist_(b, errors); break;
                        case "recon": count = Recon_(b, errors); break;
                        case "persistence": count = Persistence_(b, errors); break;
                        case "events": count = Events_(b, errors); break;
                        case "network": count = Network_(b, errors); break;
                        case "secrets": count = Secrets_(b, errors); break;
                        case "ioc": count = Ioc_(b, errors); break;
                    }
                    if (errors.Count > 0) status = "partial";
                }
                catch (Exception ex) { status = "failed"; errors.Add(ex.GetType().Name + ": " + ex.Message); }
                sw.Stop(); b.Module(m, status, count, sw.ElapsedMilliseconds, errors); Say("  " + m + ": " + status + " · " + count + " item(s) · " + Fmt.Secs(sw.Elapsed.TotalSeconds));
            }
            b.Manifest["finishedUtc"] = DateTime.UtcNow; b.Manifest["durationMs"] = (long)(DateTime.UtcNow - started).TotalMilliseconds;
            return b;
        }

        int Inventory_(Bundle b, List<string> errors)
        {
            Dictionary<string, object> d = new Dictionary<string, object>();
            OsInfo os = Inventory.Os(); RebootInfo rb = Inventory.Reboot(); d["os"] = Codec.Os(os); d["reboot"] = Codec.Reboot(rb);
            List<Software> sw = new List<Software>(); try { sw = Inventory.Installed(); } catch (Exception ex) { errors.Add("installed software: " + ex.Message); }
            List<Hotfix> hf = new List<Hotfix>();
            try { hf.AddRange(Inventory.Qfe()); } catch (Exception ex) { errors.Add("hotfixes (WMI): " + ex.Message); }
            try { int pend; hf.AddRange(Inventory.Cbs(out pend)); d["cbsPending"] = pend; } catch (Exception ex) { errors.Add("CBS packages: " + ex.Message); }
            if (WuHistory) { try { hf.AddRange(Inventory.WuHistory(1000)); } catch (Exception ex) { errors.Add("Windows Update history: " + ex.Message); } }
            HashSet<string> kbs = new HashSet<string>(); foreach (Hotfix h in hf) if (h.Kb.Length > 0 && (h.Source != "WU history" || (h.Result == "succeeded" && h.Description == "installation"))) kbs.Add(h.Kb);
            d["software"] = Codec.Many(sw, delegate (Software s) { return (object)Codec.Software(s); }); d["hotfixes"] = Codec.Many(hf, delegate (Hotfix h) { return (object)Codec.Hotfix(h); }); d["knownKbs"] = new List<string>(kbs);
            DateTime? newest = VulnScan.NewestUpdateDate(hf); d["newestUpdate"] = newest.HasValue ? (object)newest.Value : null;
            List<MissingUpdate> missing = new List<MissingUpdate>();
            if (Online) { try { missing = Inventory.WuMissing(Say); d["missingStatus"] = "searched"; } catch (Exception ex) { errors.Add("Windows Update search: " + ex.Message); d["missingStatus"] = "failed"; } }
            else d["missingStatus"] = "not searched (offline collection)";
            d["missing"] = Codec.Many(missing, delegate (MissingUpdate m) { return (object)Codec.Missing(m); });
            b["inventory"] = d; return sw.Count + hf.Count;
        }
        int Checklist_(Bundle b, List<string> errors)
        {
            ChecklistScan s = new ChecklistScan(); s.Progress += Say; Thread w = Watch(delegate { s.Cancel = true; }); s.Run(); w.Abort();
            errors.AddRange(s.Errors); Dictionary<string, object> d = new Dictionary<string, object>(); d["host"] = s.Report.Host; d["os"] = s.Report.Os; d["elevated"] = s.Report.Elevated; d["when"] = s.Report.When;
            d["score"] = s.Report.Score; d["pass"] = s.Report.Pass; d["fail"] = s.Report.Fail; d["warn"] = s.Report.Warn; d["items"] = Codec.Many(s.Snapshot(), delegate (CheckItem c) { return (object)Codec.Check(c); });
            b["checklist"] = d; return s.Report.Items.Count;
        }
        int Recon_(Bundle b, List<string> errors)
        {
            ReconScan s = new ReconScan(); s.DoEvents = !Modules.Contains("events"); s.Progress += Say; Thread w = Watch(delegate { s.Cancel = true; }); s.Run(); w.Abort();
            errors.AddRange(s.Errors); Dictionary<string, object> d = new Dictionary<string, object>(); d["os"] = s.Report.Os; d["elevated"] = s.Report.Elevated; d["when"] = s.Report.When; d["risk"] = s.Report.Bad; d["review"] = s.Report.Warn;
            d["items"] = Codec.Many(s.Snapshot(), delegate (ReconItem r) { return (object)Codec.Recon(r); }); b["recon"] = d; return s.Report.Items.Count;
        }
        int Persistence_(Bundle b, List<string> errors)
        {
            autoruns = Autoruns.Collect(Say, Cancelled); Autoruns.Verify(autoruns, null, Cancelled);
            Dictionary<string, object> d = new Dictionary<string, object>(); int high = 0; foreach (AutorunEntry e in autoruns) if (e.Risk == "high") high++;
            d["high"] = high; d["items"] = Codec.Many(autoruns, delegate (AutorunEntry e) { return (object)Codec.Autorun(e); }); b["persistence"] = d; return autoruns.Count;
        }
        int Events_(Bundle b, List<string> errors)
        {
            DateTime since = DateTime.Now.AddDays(-EventDays); List<string> notes = new List<string>();
            List<EventRow> rows = EventHunt.Collect(EventHunt.Specs, since, EventsPerCategory, Say, Cancelled, delegate (string n) { notes.Add(n); });
            Dictionary<string, object> d = new Dictionary<string, object>(); d["since"] = since; d["perCategoryCap"] = EventsPerCategory; d["notes"] = notes;
            List<string> logs = new List<string>(); foreach (EventSpec sp in EventHunt.Specs) if (!logs.Contains(sp.Log)) logs.Add(sp.Log);
            List<object> health = new List<object>(); foreach (string log in logs) health.Add(LogHealth(log)); d["logHealth"] = health;
            d["rows"] = Codec.Many(rows, delegate (EventRow r) { return (object)Codec.Event(r); }); b["events"] = d;
            foreach (string n in notes) if (n.IndexOf("denied", StringComparison.OrdinalIgnoreCase) >= 0 || n.IndexOf("administrator", StringComparison.OrdinalIgnoreCase) >= 0) { errors.Add(n); break; }
            return rows.Count;
        }
        /// <summary>How far back a log reaches and how big it is: "nothing found" means little when the Security log covers 31 hours.</summary>
        static Dictionary<string, object> LogHealth(string log)
        {
            Dictionary<string, object> h = new Dictionary<string, object>(); h["log"] = log;
            try
            {
                EventLogInformation i = EventLogSession.GlobalSession.GetLogInformation(log, PathType.LogName);
                h["records"] = i.RecordCount; h["sizeBytes"] = i.FileSize; h["lastWrite"] = i.LastWriteTime.HasValue ? (object)i.LastWriteTime.Value : null; h["isFull"] = i.IsLogFull;
                using (EventLogReader r = new EventLogReader(new EventLogQuery(log, PathType.LogName))) using (EventRecord e = r.ReadEvent()) if (e != null && e.TimeCreated.HasValue) h["oldest"] = e.TimeCreated.Value;
                using (EventLogConfiguration c = new EventLogConfiguration(log)) { h["maxSizeBytes"] = c.MaximumSizeInBytes; h["enabled"] = c.IsEnabled; }
            }
            catch (Exception ex) { h["error"] = ex.Message; }
            return h;
        }
        int Network_(Bundle b, List<string> errors)
        {
            conns = ConnTable.Snapshot(true, true); Dictionary<string, object> d = new Dictionary<string, object>();
            d["connections"] = Codec.Many(conns, delegate (Conn c) { return (object)Codec.Conn(c); });
            Dictionary<string, object> fw = new Dictionary<string, object>(); string pn, rn; List<FwProfile> profiles = new List<FwProfile>(); List<FwRule> rules = new List<FwRule>();
            try { profiles = WinFirewall.ReadProfiles(out pn); if (pn.Length > 0) fw["profilesNote"] = pn; } catch (Exception ex) { errors.Add("firewall profiles: " + ex.Message); }
            try { rules = WinFirewall.ReadRules(out rn); if (rn.Length > 0) fw["rulesNote"] = rn; } catch (Exception ex) { errors.Add("firewall rules: " + ex.Message); }
            fw["profiles"] = Codec.Many(profiles, delegate (FwProfile p) { return (object)Codec.Profile(p); }); fw["rules"] = Codec.Many(rules, delegate (FwRule r) { return (object)Codec.Rule(r); }); d["firewall"] = fw;
            List<HostsEntry> hosts = new List<HostsEntry>(); try { hosts = new Hosts().Entries(true); } catch (Exception ex) { errors.Add("hosts file: " + ex.Message); }
            d["hosts"] = Codec.Many(hosts, delegate (HostsEntry h) { return (object)Codec.HostsEntry(h); });
            b["network"] = d; return conns.Count + rules.Count;
        }
        int Secrets_(Bundle b, List<string> errors)
        {
            SecretsScan sc = new SecretsScan(); sc.MaxFileKB = SecretsMaxFileKB;
            List<string> roots = new List<string>(SecretRoots); if (roots.Count == 0) roots.Add(Path.GetDirectoryName(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)));
            sc.Roots = roots; List<SecretHit> hits = new List<SecretHit>(); Thread w = Watch(delegate { sc.Stop(); }); sc.Run(delegate (SecretHit h) { hits.Add(h); }, null); w.Abort();
            Dictionary<string, object> d = new Dictionary<string, object>(); d["roots"] = roots; d["filesScanned"] = sc.FilesScanned; d["filesSkipped"] = sc.FilesSkipped; d["denied"] = sc.Denied; d["dirsScanned"] = sc.DirsScanned;
            d["hits"] = Codec.Many(hits, delegate (SecretHit h) { return (object)Codec.Secret(h); }); b["secrets"] = d; return hits.Count;
        }
        /// <summary>The IOC list (domains, IPs, MD5/SHA-1/SHA-256) against live connections, the hosts file, and the hashes of every running process image and persistence target.</summary>
        int Ioc_(Bundle b, List<string> errors)
        {
            if (string.IsNullOrEmpty(IocFile)) throw new BundleException("the ioc module needs --ioc <file>");
            string text = File.ReadAllText(IocFile); string[] lines = text.Split('\n');
            List<Target> targets = Extractor.Extract(lines); bool md5, sha1, sha256; int bad; HashSet<string> hashes = Hashes.ParseTargets(text, out md5, out sha1, out sha256, out bad);
            HashSet<string> hl = new HashSet<string>(StringComparer.OrdinalIgnoreCase); foreach (string h in hashes) hl.Add(h);
            HashSet<string> doms = new HashSet<string>(StringComparer.OrdinalIgnoreCase), ips = new HashSet<string>(); foreach (Target t in targets) { if (t.Kind == Kind.Domain) doms.Add(t.Value); else if (t.Kind != Kind.Invalid) ips.Add(t.Value); }
            Dictionary<string, object> d = new Dictionary<string, object>(); d["list"] = Path.GetFileName(IocFile); d["listSha256"] = BundleCrypto.Sha256Hex(Encoding.UTF8.GetBytes(text));
            Dictionary<string, object> counts = new Dictionary<string, object>(); counts["domains"] = doms.Count; counts["ips"] = ips.Count; counts["hashes"] = hl.Count; counts["unparsed"] = bad; d["counts"] = counts;
            List<object> matches = new List<object>();
            if (conns == null) conns = ConnTable.Snapshot(true, true);
            foreach (Conn c in conns)
            {
                if (c.Remote != null && ips.Contains(c.Remote)) matches.Add(Match("ip", c.Remote, "connection", c.Process + " (pid " + c.Pid + ") " + c.Proto + " " + c.Local + ":" + c.LocalPort + " -> " + c.Remote + ":" + c.RemotePort + " " + c.State));
                if (c.Host != null && c.Host.Length > 0 && doms.Contains(c.Host)) matches.Add(Match("domain", c.Host, "connection", c.Process + " (pid " + c.Pid + ") -> " + c.Remote + ":" + c.RemotePort));
            }
            try { foreach (HostsEntry h in new Hosts().Entries(true)) if (doms.Contains(h.Host)) matches.Add(Match("domain", h.Host, "hosts file", "line " + h.LineNo + " -> " + h.Sink)); } catch (Exception ex) { errors.Add("hosts file: " + ex.Message); }
            // image hashes: running processes and persistence targets, each file once, bounded by size
            Dictionary<string, string> images = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (hl.Count > 0)
            {
                int procs = 0, noPath = 0, skippedSize = 0, hashErrors = 0;
                foreach (Process p in Process.GetProcesses()) { procs++; try { string path = Trust.ProcessPath(p.Id); if (path.Length == 0) noPath++; else if (!images.ContainsKey(path)) images[path] = "process " + p.ProcessName + " (pid " + p.Id + ")"; } catch { noPath++; } finally { p.Dispose(); } }
                if (autoruns != null) foreach (AutorunEntry e in autoruns) if (e.Image.Length > 0 && !images.ContainsKey(e.Image)) images[e.Image] = e.Kind + " " + e.Name;
                int hashed = 0; long cap = (long)IocHashCapMB * 1048576L;
                foreach (KeyValuePair<string, string> kv in images)
                {
                    if (Cancelled()) break;
                    try
                    {
                        FileInfo fi = new FileInfo(kv.Key); if (!fi.Exists || fi.Length > cap) { skippedSize++; continue; } Dictionary<string, string> hs = Hashes.Compute(kv.Key, md5, sha1, sha256); hashed++;
                        foreach (KeyValuePair<string, string> h in hs) if (hl.Contains(h.Value)) matches.Add(Match("hash", h.Value.ToLowerInvariant(), kv.Value, kv.Key + " (" + h.Key + ")"));
                    }
                    catch { hashErrors++; }
                }
                // coverage of the hash sweep, so a report can say how much was actually looked at
                d["processes"] = procs; d["processesWithoutPath"] = noPath; d["imagePaths"] = images.Count; d["imagesHashed"] = hashed; d["imagesSkipped"] = skippedSize; d["hashErrors"] = hashErrors;
            }
            d["matches"] = matches; b["ioc"] = d; return matches.Count;
        }
        static Dictionary<string, object> Match(string type, string value, string where, string detail) { Dictionary<string, object> m = new Dictionary<string, object>(); m["type"] = type; m["value"] = value; m["where"] = where; m["detail"] = detail; return m; }
        /// <summary>A watchdog that cancels a synchronous engine when the run's budget is exceeded; aborted once the engine returns.</summary>
        Thread Watch(Action cancel)
        {
            Thread t = new Thread(delegate () { try { while (true) { Thread.Sleep(500); if (Cancelled()) { cancel(); return; } } } catch (ThreadAbortException) { } });
            t.IsBackground = true; t.Start(); return t;
        }
    }

    /// <summary>The collector's options, mapped the same way by `PowerTowerCli collect` and PowerTowerCollect.exe.</summary>
    public static class CollectOptions
    {
        public static readonly string[][] Help = {
            new string[] { "out", "file", "where to write the bundle (default: bundle_<host>_<stamp>.ptb next to the exe, or the reports folder from the CLI)" },
            new string[] { "modules", "list", "comma-separated: " + string.Join(",", Collector.AllModules) + " (default: " + string.Join(",", Collector.DefaultModules) + "; secrets and ioc are opt-in)" },
            new string[] { "engagement", "file", "engagement.json: refuse to run outside its scope, window or module list, and seal to its public key" },
            new string[] { "pubkey", "file", "RSA public key (XML) to seal the bundle to - the host cannot read its own bundle" },
            new string[] { "pass", "passphrase", "seal with a passphrase instead (PBKDF2-SHA256 → AES-256-CBC + HMAC)" },
            new string[] { "plain", null, "write an unsealed bundle - explicit, never the default" },
            new string[] { "online", null, "allow the Windows Update search for missing updates: the collector's only network use" },
            new string[] { "no-wu-history", null, "skip the Windows Update history (faster; QFE and CBS still give the patch level)" },
            new string[] { "ioc", "file", "IOC list for the ioc module: domains, IPs and MD5/SHA-1/SHA-256 hashes, any layout" },
            new string[] { "secrets-root", "folder", "where the secrets module looks (repeatable; default: the Users folder)" },
            new string[] { "event-days", "n", "how far back the events module reads (default 30)" },
            new string[] { "budget", "seconds", "stop collecting after this long; what is done is kept, the rest is marked skipped" },
            new string[] { "run-id", "id", "run id for the manifest (the controller sets it; default random)" },
            new string[] { "json", "file", "also write the unsealed JSON, pretty-printed, for inspection" },
        };
        /// <summary>Applies the options; returns a usage error or null.</summary>
        public static string Apply(Collector c, Func<string, string> get, Func<string, bool> has, Func<string, List<string>> all)
        {
            if (has("modules")) { c.Modules.Clear(); foreach (string m in (get("modules") ?? "").Split(',')) { string t = m.Trim().ToLowerInvariant(); if (t.Length == 0) continue; if (Array.IndexOf(Collector.AllModules, t) < 0) return "--modules: unknown module '" + t + "' (choose from " + string.Join(", ", Collector.AllModules) + ")"; if (!c.Modules.Contains(t)) c.Modules.Add(t); } if (c.Modules.Count == 0) return "--modules: nothing to run"; }
            if (has("engagement")) { try { c.Engagement = Engagement.Load(get("engagement")); } catch (BundleException ex) { return ex.Message; } List<string> bad = c.Engagement.Validate(); if (bad.Count > 0) return "--engagement: " + string.Join("; ", bad.ToArray()); }
            c.Online = has("online"); c.WuHistory = !has("no-wu-history");
            if (has("ioc")) { c.IocFile = get("ioc"); if (!File.Exists(c.IocFile)) return "--ioc: no such file: " + c.IocFile; if (!c.Modules.Contains("ioc")) c.Modules.Add("ioc"); }
            if (c.Modules.Contains("ioc") && string.IsNullOrEmpty(c.IocFile)) return "the ioc module needs --ioc <file>";
            foreach (string r in all("secrets-root")) { if (!Directory.Exists(r)) return "--secrets-root: no such folder: " + r; c.SecretRoots.Add(r); }
            if (has("event-days")) { int n; if (!int.TryParse(get("event-days"), out n) || n < 1 || n > 3650) return "--event-days must be 1-3650"; c.EventDays = n; }
            if (has("budget")) { int n; if (!int.TryParse(get("budget"), out n) || n < 10) return "--budget must be at least 10 seconds"; c.BudgetSeconds = n; }
            if (has("run-id")) { string id = (get("run-id") ?? "").Trim(); foreach (char ch in id) if (!char.IsLetterOrDigit(ch) && ch != '-' && ch != '_') return "--run-id: letters, digits, - and _ only"; if (id.Length == 0 || id.Length > 64) return "--run-id: 1-64 characters"; c.RunId = id; }
            return null;
        }
        /// <summary>The sealing key from the options: engagement public key, --pubkey, --pass, or --plain; exactly one, or a usage error.</summary>
        public static BundleKey Key(Collector c, Func<string, string> get, Func<string, bool> has, out string error)
        {
            error = null; int n = (has("pubkey") ? 1 : 0) + (has("pass") ? 1 : 0) + (has("plain") ? 1 : 0);
            if (n > 1) { error = "choose one of --pubkey, --pass, --plain"; return null; }
            if (has("pubkey")) { try { return BundleKey.ToPublic(File.ReadAllText(get("pubkey"), Encoding.UTF8)); } catch (Exception ex) { error = "--pubkey: " + ex.Message; return null; } }
            if (has("pass")) return BundleKey.FromPassphrase(get("pass"));
            if (has("plain")) return BundleKey.None();
            if (c.Engagement != null && c.Engagement.PublicKeyXml.Length > 0) return BundleKey.ToPublic(c.Engagement.PublicKeyXml);
            error = "say how to seal the bundle: --engagement (with a public key), --pubkey <file>, --pass <passphrase>, or --plain"; return null;
        }
        public static string DefaultOut(Bundle b, string dir) { return Path.Combine(dir, "bundle_" + b.Host + "_" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".ptb"); }
        /// <summary>done.json beside the bundle: what the controller reads to verify the pull.</summary>
        public static void WriteDone(Bundle b, string bundlePath)
        {
            Dictionary<string, object> d = new Dictionary<string, object>(); d["bundle"] = Path.GetFileName(bundlePath); FileInfo fi = new FileInfo(bundlePath); d["bytes"] = fi.Length; d["sha256"] = BundleCrypto.FileSha256(bundlePath);
            d["host"] = b.Host; d["runId"] = b.RunId; d["finishedUtc"] = b.Manifest.ContainsKey("finishedUtc") ? b.Manifest["finishedUtc"] : null; d["modules"] = b.Modules;
            File.WriteAllText(Path.Combine(Path.GetDirectoryName(bundlePath), "done.json"), JsonWrite.Text(d, true), new UTF8Encoding(false));
        }
        public static int Failed(Bundle b) { int n = 0; foreach (object m in b.Modules) { string s = Json.GetS(m, "status"); if (s == "failed" || s == "partial") n++; } return n; }
        public static string Summary(object module) { return (Json.GetS(module, "name") ?? "").PadRight(12) + (Json.GetS(module, "status") ?? "").PadRight(9) + JsonWrite.Int(Json.Get(module, "count"), 0).ToString("N0").PadLeft(7) + " item(s)" + (JsonWrite.Long(Json.Get(module, "durationMs"), 0) / 1000.0).ToString("N1").PadLeft(8) + " s" + (Json.Arr(Json.Get(module, "errors")).Count > 0 ? "   " + string.Join(" | ", JsonWrite.Strings(Json.Get(module, "errors")).ToArray()) : ""); }
    }
}

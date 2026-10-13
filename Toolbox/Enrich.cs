// Enrich.cs - the online half of a vulnerability scan, on its own so it can run in two places: inside the desktop app
// and the CLI right after inventory (VulnScan hands it the live host), and later, on a connected analyst box, from a
// bundle that was collected offline (`enrich`). Inputs are plain data - OS build, software, known KBs, missing
// updates, the newest installed update - and outputs are findings plus the feed as-of stamps every finding was
// judged against. The network is reached only through FeedCache, which can be told to stay offline.
using System;
using System.Collections.Generic;
using System.Globalization;

namespace PSTools
{
    public class VulnEnrich
    {
        // what the host looked like
        public OsInfo Os = new OsInfo(); public RebootInfo Reboot = new RebootInfo(); public List<Software> Software = new List<Software>(); public HashSet<string> KnownKbs = new HashSet<string>(); public List<MissingUpdate> Missing = new List<MissingUpdate>(); public DateTime? NewestUpdate;
        // what to do
        public bool DoWua = true, DoMsrc = true, DoNvd = true, DoKev = true, DoEpss = true; public int Months = 3, NvdLimit = int.MaxValue; public string NvdApiKey = ""; public FeedCache Cache; public DateTime Now = DateTime.Now;
        // results
        public readonly List<Finding> Findings = new List<Finding>(); public readonly List<string> Releases = new List<string>(), Log = new List<string>(), Errors = new List<string>();
        public Dictionary<string, KevEntry> KevCatalog = new Dictionary<string, KevEntry>(); public int MsrcWindowUsed;
        /// <summary>What the findings were judged against: per feed, when its copy was fetched and what it said about itself. A vulnerability list without this is not defensible.</summary>
        public readonly Dictionary<string, object> AsOf = new Dictionary<string, object>();
        // hooks for a host: VulnScan wires its progress strip and findings list, the CLI wires the console
        public Action<string> Progress; public Action<string, string, string> Step; public Action<string, Exception> Failed; public Action<List<Finding>> Published; public Func<bool> Cancelled; public Action<float> FractionChanged;
        readonly Dictionary<string, Finding> merged = new Dictionary<string, Finding>();

        void Say(string s) { Log.Add(DateTime.Now.ToString("HH:mm:ss") + "  " + s); if (Progress != null) Progress(s); }
        void StepTo(string label, string state, string note) { if (Step != null) Step(label, state, note); }
        void Fail(string what, Exception ex) { Errors.Add(what + ": " + ex.Message); if (Failed != null) Failed(what, ex); else Say("✗ " + what + ": " + ex.Message); }
        bool Cancel() { return Cancelled != null && Cancelled(); }
        void Frac(float f) { if (FractionChanged != null) FractionChanged(f); }
        void Publish()
        {
            List<Finding> l = new List<Finding>(merged.Values); l.Sort(delegate (Finding a, Finding b) { int c = b.SortScore.CompareTo(a.SortScore); return c != 0 ? c : string.CompareOrdinal(b.Cve, a.Cve); });
            Findings.Clear(); Findings.AddRange(l); if (Published != null) Published(new List<Finding>(l));
        }
        static string Stamp(FeedCache c, string name) { DateTime? d = c == null ? null : c.Stamp(name); return d.HasValue ? d.Value.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture) : null; }
        /// <summary>Start from findings that already exist (the Software view's "look up these").</summary>
        public void Seed(IEnumerable<Finding> existing) { merged.Clear(); foreach (Finding f in existing) merged[f.Key] = f; }

        public void Run()
        {
            merged.Clear(); Releases.Clear(); AsOf.Clear(); AsOf["enrichedUtc"] = DateTime.UtcNow; AsOf["offline"] = Cache != null && Cache.Offline;
            if (DoWua) foreach (Finding f in Resolve.FromWindowsUpdate(Missing, Os)) merged[f.Key] = f;
            if (DoMsrc && !Cancel()) { Msrc_(); if (Cancel()) return; }
            if (DoNvd && !Cancel()) Nvd_();
            if (DoKev && !Cancel()) Kev_();
            if (DoEpss && !Cancel()) Epss_();
            Publish();
        }
        void Msrc_()
        {
            StepTo("Microsoft CVEs", "running", null); Dictionary<string, object> so = new Dictionary<string, object>(); AsOf["msrc"] = so;
            try
            {
                int window = VulnScan.MsrcWindow(NewestUpdate, Os.Installed, Now, Months); MsrcWindowUsed = window; so["window"] = window; so["minimum"] = Months; so["newestUpdate"] = NewestUpdate.HasValue ? (object)NewestUpdate.Value : null; so["osInstalled"] = Os.Installed.HasValue ? (object)Os.Installed.Value : null;
                Say("newest installed update " + (NewestUpdate.HasValue ? NewestUpdate.Value.ToString("yyyy-MM-dd") : ("not dated" + (Os.Installed.HasValue ? ", OS installed " + Os.Installed.Value.ToString("yyyy-MM-dd") : ""))) + " → checking " + window + " MSRC release" + (window == 1 ? "" : "s") + " (at least " + Months + ", at most " + VulnScan.MaxMonths + ")");
                string note; List<string> rel = Msrc.Releases(Cache, out note); Say("MSRC releases list " + note); so["releasesList"] = note; so["releasesListCached"] = Stamp(Cache, "msrc-releases.json"); List<MsrcRec> all = new List<MsrcRec>(); List<object> used = new List<object>(); so["releases"] = used;
                for (int i = 0; i < Math.Min(window, rel.Count) && !Cancel(); i++)
                {
                    Frac((float)i / Math.Max(1, Math.Min(window, rel.Count))); Say("MSRC " + rel[i] + " · fetching (about 10 MB the first time)…"); string body; try { body = Msrc.Fetch(rel[i], Cache, out note); } catch (Exception ex) { Fail("MSRC " + rel[i], ex); continue; }
                    Say("MSRC " + rel[i] + " · " + note + " · parsing…"); List<MsrcRec> recs = Msrc.Parse(body, rel[i]); all.AddRange(recs); Releases.Add(rel[i]); Say("MSRC " + rel[i] + " · " + recs.Count.ToString("N0") + " remediation records");
                    Dictionary<string, object> u = new Dictionary<string, object>(); u["release"] = rel[i]; u["note"] = note; u["cached"] = Stamp(Cache, "msrc-" + rel[i] + ".json"); u["records"] = recs.Count; used.Add(u);
                }
                Say("resolving Microsoft CVEs against build " + Os.FullBuild + " and " + KnownKbs.Count + " known KBs…");
                int vul = 0, pat = 0;
                foreach (Finding f in Resolve.Msrc(all, Os, KnownKbs, Software, Reboot))
                {
                    Finding wu; if (merged.TryGetValue(f.Key, out wu) && wu.Source == "Windows Update") { f.Fix += " · offered by Windows Update as " + wu.Fix; f.Evidence += " | " + wu.Evidence; if (f.Status == "vulnerable") f.Status = "update available"; }
                    else { foreach (Finding w in merged.Values) if (w.Cve == f.Cve && w.Source == "Windows Update") { f.Fix += " · offered by Windows Update as " + w.Fix; if (f.Status == "vulnerable") f.Status = "update available"; } }
                    merged[f.Key] = f; if (f.Open) vul++; else pat++;
                }
                // a WU-only finding whose CVE MSRC also resolved is now represented by the MSRC row
                List<string> drop = new List<string>(); foreach (KeyValuePair<string, Finding> p in merged) if (p.Value.Source == "Windows Update") foreach (Finding f in merged.Values) if (f.Source == "MSRC" && f.Cve == p.Value.Cve) { drop.Add(p.Key); break; }
                foreach (string k in drop) merged.Remove(k);
                so["open"] = vul; so["patched"] = pat;
                Say("Microsoft: " + vul + " open, " + pat + " patched"); StepTo("Microsoft CVEs", "done", vul + " open · " + pat + " patched");
            }
            catch (Exception ex) { Fail("MSRC", ex); StepTo("Microsoft CVEs", "failed", null); }
            Frac(-1); Publish();
        }
        void Nvd_()
        {
            StepTo("Third-party (NVD)", "running", null); Dictionary<string, object> so = new Dictionary<string, object>(); AsOf["nvd"] = so; so["keyed"] = !string.IsNullOrEmpty(NvdApiKey);
            int looked = 0, mapped = 0, hits = 0; foreach (Software s in Software) if (s.Mapped && Ver.Parse(s.Version) != null) mapped++;
            string oldest = null, newest = null;
            foreach (Software s in Software)
            {
                if (Cancel()) break; if (!s.Mapped) continue; if (Ver.Parse(s.Version) == null) { s.Status = "version '" + s.Version + "' is not comparable"; continue; } if (looked >= NvdLimit) { s.Status = "skipped (limit)"; continue; }
                Frac((float)looked / Math.Max(1, Math.Min(mapped, NvdLimit))); looked++; LookupOne(s); if (s.Cves > 0) hits++; Publish();
                string st = Stamp(Cache, Nvd.CacheName(s.Vendor, s.Product, Ver.Canon(s.Version) ?? s.Version)); if (st != null) { if (oldest == null || string.CompareOrdinal(st, oldest) < 0) oldest = st; if (newest == null || string.CompareOrdinal(st, newest) > 0) newest = st; }
            }
            so["products"] = looked; so["withCves"] = hits; so["oldestCache"] = oldest; so["newestCache"] = newest;
            Frac(-1); Say("NVD: " + looked + " product(s) looked up"); StepTo("Third-party (NVD)", Cancel() ? "failed" : "done", looked + " looked up · " + hits + " with CVEs");
        }
        void Kev_()
        {
            StepTo("KEV", "running", null); Dictionary<string, object> so = new Dictionary<string, object>(); AsOf["kev"] = so;
            try
            {
                string note; KevCatalog = Kev.Load(Cache, out note); so["note"] = note; so["cached"] = Stamp(Cache, "kev.json"); so["entries"] = KevCatalog.Count;
                try { object cat = Json.Parse(Cache.ReadAny("kev.json") ?? "{}"); so["catalogVersion"] = Json.GetS(cat, "catalogVersion"); so["dateReleased"] = Json.GetS(cat, "dateReleased"); } catch { }
                Say("CISA KEV · " + KevCatalog.Count.ToString("N0") + " entries · " + note); int n = 0; foreach (Finding f in merged.Values) { KevEntry k; if (KevCatalog.TryGetValue(f.Cve, out k)) { f.Kev = true; f.Ransomware = k.Ransomware; f.KevDue = k.DueDate; n++; } } so["flagged"] = n;
                Say("KEV: " + n + " finding(s) are known exploited"); StepTo("KEV", "done", n + " exploited");
            }
            catch (Exception ex) { Fail("KEV", ex); StepTo("KEV", "failed", null); }
            Publish();
        }
        void Epss_()
        {
            StepTo("EPSS", "running", null); Dictionary<string, object> so = new Dictionary<string, object>(); AsOf["epss"] = so;
            try
            {
                List<string> ids = new List<string>(); foreach (Finding f in merged.Values) if (f.Open || f.Status == "unconfirmed") ids.Add(f.Cve); so["requested"] = ids.Count;
                if (ids.Count > 0)
                {
                    string asOf; Dictionary<string, double> sc = Epss.Scores(ids, Cache, Say, out asOf); foreach (Finding f in merged.Values) { double v; if (sc.TryGetValue(f.Cve, out v)) f.Epss = v; }
                    so["scored"] = sc.Count; so["dates"] = asOf; so["cached"] = Stamp(Cache, Epss.CacheName(ids)); Say("EPSS: " + sc.Count + " of " + ids.Count + " open CVEs scored"); StepTo("EPSS", "done", sc.Count + " scored");
                }
                else { so["scored"] = 0; StepTo("EPSS", "done", "nothing open"); }
            }
            catch (Exception ex) { Fail("EPSS", ex); StepTo("EPSS", "failed", null); }
        }
        /// <summary>One product against the NVD: fetch (cached), match the installed version, replace that product's findings.</summary>
        public void LookupOne(Software s)
        {
            List<string> stale = new List<string>(); foreach (KeyValuePair<string, Finding> p in merged) if (p.Value.Source == "NVD" && p.Value.Product == s.Name) stale.Add(p.Key); foreach (string k in stale) merged.Remove(k);
            try
            {
                string note; List<CveRecord> recs = Nvd.ForProduct(s.Vendor, s.Product, s.Version, NvdApiKey, Cache, Say, out note); List<Finding> fs = Resolve.ThirdParty(s, recs); int open = 0;
                foreach (Finding f in fs) { KevEntry k; if (KevCatalog.TryGetValue(f.Cve, out k)) { f.Kev = true; f.Ransomware = k.Ransomware; f.KevDue = k.DueDate; } merged[f.Key] = f; if (f.Open) open++; }
                s.Cves = open; s.Status = open == 0 ? "no known CVEs at " + s.Version + " (" + note + ")" : open + " CVE(s) at " + s.Version + " (" + note + ")";
            }
            catch (Exception ex) { s.Status = "lookup failed: " + ex.Message; Fail("NVD " + s.Cpe, ex); }
        }
        /// <summary>Look up just these programs and merge the results into the seeded findings (the Software view's action).</summary>
        public void LookupSoftware(List<Software> items)
        {
            if (KevCatalog.Count == 0 && DoKev && Cache != null) { try { string note; KevCatalog = Kev.Load(Cache, out note); } catch (Exception ex) { Fail("KEV", ex); } }
            int n = 0; foreach (Software s in items) { if (Cancel()) break; if (Ver.Parse(s.Version) == null) { s.Status = "version '" + s.Version + "' is not comparable"; continue; } LookupOne(s); n++; Publish(); }
            if (DoEpss && Cache != null) { try { List<string> ids = new List<string>(); foreach (Finding f in merged.Values) if (f.Source == "NVD" && (f.Open || f.Status == "unconfirmed") && !f.Epss.HasValue) ids.Add(f.Cve); if (ids.Count > 0) { Dictionary<string, double> sc = Epss.Scores(ids, Cache, Say); foreach (Finding f in merged.Values) { double v; if (sc.TryGetValue(f.Cve, out v)) f.Epss = v; } } } catch (Exception ex) { Fail("EPSS", ex); } }
            Publish(); Say("looked up " + n + " program(s)");
        }
    }

    /// <summary>A collected bundle in, the same bundle with a findings section out: the glue between Bundle.cs and VulnEnrich.</summary>
    public static class EnrichBundle
    {
        public static VulnEnrich From(Bundle b, FeedCache cache)
        {
            object inv = b["inventory"]; if (inv == null) throw new BundleException("the bundle has no inventory section - collect with the inventory module first");
            VulnEnrich e = new VulnEnrich(); e.Cache = cache; e.Os = Codec.OsFrom(Json.Get(inv, "os")); e.Reboot = Codec.RebootFrom(Json.Get(inv, "reboot"));
            if (e.Os.Build == 0) throw new BundleException("the bundle's inventory has no OS build to resolve against");
            foreach (object s in Json.Arr(Json.Get(inv, "software"))) e.Software.Add(Codec.SoftwareFrom(s));
            foreach (string k in JsonWrite.Strings(Json.Get(inv, "knownKbs"))) e.KnownKbs.Add(k);
            foreach (object m in Json.Arr(Json.Get(inv, "missing"))) e.Missing.Add(Codec.MissingFrom(m));
            e.NewestUpdate = JsonWrite.Date(Json.Get(inv, "newestUpdate")); e.DoWua = e.Missing.Count > 0;   // Windows Update findings only when the collector could ask it
            return e;
        }
        /// <summary>Writes the findings, the per-product verdicts and the as-of stamps into the bundle.</summary>
        public static void Apply(Bundle b, VulnEnrich e)
        {
            Dictionary<string, object> d = new Dictionary<string, object>(); int open = 0; foreach (Finding f in e.Findings) if (f.Open) open++;
            d["open"] = open; d["total"] = e.Findings.Count; d["msrcWindow"] = e.MsrcWindowUsed; d["releases"] = new List<string>(e.Releases); d["errors"] = new List<string>(e.Errors); d["asOf"] = e.AsOf;
            d["items"] = Codec.Many(e.Findings, delegate (Finding f) { return (object)Codec.Finding(f); }); b["findings"] = d;
            Dictionary<string, object> inv = Json.Obj(b["inventory"]); if (inv != null) inv["software"] = Codec.Many(e.Software, delegate (Software s) { return (object)Codec.Software(s); });
            Dictionary<string, object> en = new Dictionary<string, object>(); en["utc"] = DateTime.UtcNow; en["on"] = Environment.MachineName; en["offline"] = e.Cache != null && e.Cache.Offline; en["open"] = open; en["total"] = e.Findings.Count; b.Manifest["enriched"] = en;
        }
    }
}

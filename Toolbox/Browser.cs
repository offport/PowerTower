// Browser: find the browsers and profiles on this machine and pull their browsing data - history, downloads
// and searches - out of the SQLite databases with the dependency-free reader in Sqlite.cs. Chromium family
// (Chrome, Edge, Brave, Vivaldi, Opera) and Firefox. Read-only; the running browser's DB is snapshotted.
using System;
using System.Collections.Generic;
using System.IO;

namespace PSTools
{
    public class BrowserProfile
    {
        public string Browser = "", Name = "", Family = "", Dir = "", HistoryDb = "";
        public string Label { get { return Browser + (Name.Length > 0 && Name != "Default" ? " · " + Name : ""); } }
    }

    public class DomainStat
    {
        public string Domain = ""; public long Visits; public int Pages; public DateTime First = DateTime.MaxValue, Last; public readonly List<string> Browsers = new List<string>();
        public string BrowsersText { get { return string.Join(", ", Browsers.ToArray()); } }
        public string FirstText { get { return First == DateTime.MaxValue || First == DateTime.MinValue ? "" : First.ToString("yyyy-MM-dd"); } }
        public string LastText { get { return Last == DateTime.MinValue ? "" : Last.ToString("yyyy-MM-dd"); } }
    }

    public class VisitRow
    {
        public string Browser = "", Profile = "", Kind = "", Url = "", Title = "", Domain = "", Term = "", File = "", State = ""; public long VisitCount; public long Bytes; public DateTime When;
        public string WhenText { get { return When == DateTime.MinValue ? "" : When.ToString("yyyy-MM-dd HH:mm"); } }
        public bool Secure { get { return Url.StartsWith("https:", StringComparison.OrdinalIgnoreCase); } }
    }

    public static class Browser
    {
        static string Local { get { return Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData); } }
        static string Roaming { get { return Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData); } }

        static readonly string[][] Chromium = {
            new string[] { "Chrome", @"Google\Chrome\User Data" },
            new string[] { "Edge", @"Microsoft\Edge\User Data" },
            new string[] { "Brave", @"BraveSoftware\Brave-Browser\User Data" },
            new string[] { "Vivaldi", @"Vivaldi\User Data" },
            new string[] { "Opera", @"Opera Software\Opera Stable" },
            new string[] { "Opera GX", @"Opera Software\Opera GX Stable" },
            new string[] { "Chromium", @"Chromium\User Data" },
        };

        public static List<BrowserProfile> Profiles()
        {
            List<BrowserProfile> outp = new List<BrowserProfile>();
            foreach (string[] b in Chromium)
            {
                string root = Path.Combine(Local, b[1]); if (!Directory.Exists(root)) continue;
                // Opera stores the profile directly in the root; Chrome/Edge/Brave use Default + Profile N
                bool operaFlat = b[0].StartsWith("Opera");
                if (operaFlat) { string db = Path.Combine(root, "History"); if (File.Exists(db)) outp.Add(Chrome(b[0], "Default", root, db)); continue; }
                foreach (string dir in SafeDirs(root))
                {
                    string name = Path.GetFileName(dir); if (name != "Default" && !name.StartsWith("Profile ")) continue;
                    string db = Path.Combine(dir, "History"); if (File.Exists(db)) outp.Add(Chrome(b[0], name, dir, db));
                }
            }
            // Firefox — classic install, plus the Microsoft Store (MSIX) version, plus Beta/Developer/Nightly
            HashSet<string> ffSeen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string ffRoot in FirefoxProfileRoots())
            {
                if (!Directory.Exists(ffRoot)) continue;
                foreach (string dir in SafeDirs(ffRoot))
                {
                    string db = Path.Combine(dir, "places.sqlite"); if (!File.Exists(db) || !ffSeen.Add(db)) continue;
                    BrowserProfile p = new BrowserProfile(); p.Browser = "Firefox"; p.Family = "firefox"; p.Name = CleanFfName(Path.GetFileName(dir)); p.Dir = dir; p.HistoryDb = db; outp.Add(p);
                }
            }
            return outp;
        }
        static BrowserProfile Chrome(string browser, string name, string dir, string db) { BrowserProfile p = new BrowserProfile(); p.Browser = browser; p.Family = "chromium"; p.Name = name; p.Dir = dir; p.HistoryDb = db; return p; }

        /// <summary>Every folder Firefox might keep its profiles in: the classic %APPDATA% path and the Microsoft Store (MSIX) package's redirected AppData.</summary>
        static IEnumerable<string> FirefoxProfileRoots()
        {
            yield return Path.Combine(Roaming, @"Mozilla\Firefox\Profiles");
            string packages = Path.Combine(Local, "Packages"); string[] dirs; try { dirs = Directory.GetDirectories(packages, "Mozilla.Firefox*"); } catch { dirs = new string[0]; }
            foreach (string pkg in dirs) yield return Path.Combine(pkg, @"LocalCache\Roaming\Mozilla\Firefox\Profiles");
        }
        static IEnumerable<string> SafeDirs(string root) { string[] dirs; try { dirs = Directory.GetDirectories(root); } catch { yield break; } foreach (string d in dirs) yield return d; }
        static string CleanFfName(string s) { int dot = s.IndexOf('.'); return dot > 0 ? s.Substring(dot + 1) : s; }

        // ── history ──
        public static List<VisitRow> History(BrowserProfile p, int max)
        {
            List<VisitRow> rows = new List<VisitRow>();
            if (p.Family == "chromium")
            {
                SqliteTable t = Sqlite.Read(p.HistoryDb, "urls", max);
                foreach (object[] r in t.Rows) { VisitRow v = new VisitRow(); v.Browser = p.Browser; v.Profile = p.Name; v.Kind = "history"; v.Url = t.Str(r, "url"); v.Title = t.Str(r, "title"); v.VisitCount = t.Long(r, "visit_count"); v.When = Sqlite.ChromeTime(t.Long(r, "last_visit_time")); v.Domain = DomainOf(v.Url); rows.Add(v); }
            }
            else
            {
                SqliteTable t = Sqlite.Read(p.HistoryDb, "moz_places", max);
                foreach (object[] r in t.Rows) { string url = t.Str(r, "url"); if (url.StartsWith("place:")) continue; VisitRow v = new VisitRow(); v.Browser = p.Browser; v.Profile = p.Name; v.Kind = "history"; v.Url = url; v.Title = t.Str(r, "title"); v.VisitCount = t.Long(r, "visit_count"); v.When = Sqlite.UnixMicros(t.Long(r, "last_visit_date")); v.Domain = DomainOf(v.Url); rows.Add(v); }
            }
            return rows;
        }

        // ── downloads ──
        public static List<VisitRow> Downloads(BrowserProfile p)
        {
            List<VisitRow> rows = new List<VisitRow>();
            if (p.Family == "chromium")
            {
                SqliteTable t; try { t = Sqlite.Read(p.HistoryDb, "downloads", int.MaxValue); } catch { return rows; }
                foreach (object[] r in t.Rows)
                {
                    VisitRow v = new VisitRow(); v.Browser = p.Browser; v.Profile = p.Name; v.Kind = "download";
                    v.File = t.Str(r, "target_path"); v.Url = t.Str(r, "tab_url"); if (v.Url.Length == 0) v.Url = t.Str(r, "referrer");
                    v.Bytes = t.Long(r, "total_bytes"); v.When = Sqlite.ChromeTime(t.Long(r, "start_time")); v.State = DownloadState(t.Long(r, "state")); v.Domain = DomainOf(v.Url); v.Title = Path.GetFileName(v.File.Replace('/', '\\')); rows.Add(v);
                }
            }
            else
            {
                // Firefox stores downloads as annotations on moz_places; best-effort via moz_annos
                try
                {
                    SqliteTable annos = Sqlite.Read(p.HistoryDb, "moz_annos", int.MaxValue); SqliteTable attrs = Sqlite.Read(p.HistoryDb, "moz_anno_attributes", int.MaxValue);
                    long destAttr = -1; foreach (object[] a in attrs.Rows) if (attrs.Str(a, "name") == "downloads/destFileURI") destAttr = attrs.Long(a, "id");
                    foreach (object[] r in annos.Rows) { if (annos.Long(r, "anno_attribute_id") != destAttr) continue; VisitRow v = new VisitRow(); v.Browser = p.Browser; v.Profile = p.Name; v.Kind = "download"; v.File = Uri.UnescapeDataString(annos.Str(r, "content").Replace("file:///", "").Replace('/', '\\')); v.When = Sqlite.UnixMicros(annos.Long(r, "dateAdded")); v.Title = Path.GetFileName(v.File); rows.Add(v); }
                }
                catch { }
            }
            return rows;
        }
        static string DownloadState(long s) { switch (s) { case 0: return "in progress"; case 1: return "complete"; case 2: return "cancelled"; case 3: return "interrupted"; case 4: return "interrupted"; default: return "state " + s; } }

        // ── searches ──
        public static List<VisitRow> Searches(BrowserProfile p)
        {
            List<VisitRow> rows = new List<VisitRow>();
            if (p.Family == "chromium")
            {
                SqliteTable kt; try { kt = Sqlite.Read(p.HistoryDb, "keyword_search_terms", int.MaxValue); } catch { return rows; }
                SqliteTable urls = Sqlite.Read(p.HistoryDb, "urls", int.MaxValue);
                Dictionary<long, object[]> byId = new Dictionary<long, object[]>(); foreach (object[] u in urls.Rows) byId[urls.Long(u, "id")] = u;
                foreach (object[] r in kt.Rows) { VisitRow v = new VisitRow(); v.Browser = p.Browser; v.Profile = p.Name; v.Kind = "search"; v.Term = kt.Str(r, "term"); object[] u; if (byId.TryGetValue(kt.Long(r, "url_id"), out u)) { v.Url = urls.Str(u, "url"); v.When = Sqlite.ChromeTime(urls.Long(u, "last_visit_time")); v.VisitCount = urls.Long(u, "visit_count"); v.Domain = DomainOf(v.Url); } rows.Add(v); }
            }
            else
            {
                // Firefox search terms live in moz_inputhistory (typed) - best effort
                try { SqliteTable t = Sqlite.Read(p.HistoryDb, "moz_inputhistory", int.MaxValue); foreach (object[] r in t.Rows) { VisitRow v = new VisitRow(); v.Browser = p.Browser; v.Profile = p.Name; v.Kind = "search"; v.Term = t.Str(r, "input"); rows.Add(v); } } catch { }
            }
            return rows;
        }

        /// <summary>Aggregate history rows into one entry per unique site: total visits, page count, first/last seen, browsers.</summary>
        public static List<DomainStat> Domains(IEnumerable<VisitRow> history)
        {
            Dictionary<string, DomainStat> map = new Dictionary<string, DomainStat>(StringComparer.OrdinalIgnoreCase);
            foreach (VisitRow v in history)
            {
                string d = v.Domain; if (string.IsNullOrEmpty(d)) continue;
                DomainStat s; if (!map.TryGetValue(d, out s)) { s = new DomainStat(); s.Domain = d; map[d] = s; }
                s.Visits += v.VisitCount > 0 ? v.VisitCount : 1; s.Pages++;
                if (v.When != DateTime.MinValue) { if (v.When < s.First) s.First = v.When; if (v.When > s.Last) s.Last = v.When; }
                if (!s.Browsers.Contains(v.Browser)) s.Browsers.Add(v.Browser);
            }
            List<DomainStat> l = new List<DomainStat>(map.Values);
            l.Sort(delegate (DomainStat a, DomainStat b) { if (b.Visits != a.Visits) return b.Visits.CompareTo(a.Visits); return b.Pages.CompareTo(a.Pages); });
            return l;
        }

        public static string DomainOf(string url)
        {
            if (string.IsNullOrEmpty(url)) return "";
            try { Uri u; if (Uri.TryCreate(url, UriKind.Absolute, out u)) { string h = u.Host; if (h.StartsWith("www.")) h = h.Substring(4); return h; } } catch { }
            int s = url.IndexOf("://"); if (s >= 0) { int e = url.IndexOf('/', s + 3); string h = e > 0 ? url.Substring(s + 3, e - s - 3) : url.Substring(s + 3); if (h.StartsWith("www.")) h = h.Substring(4); int c = h.IndexOf(':'); if (c > 0) h = h.Substring(0, c); return h; }
            return "";
        }
    }
}

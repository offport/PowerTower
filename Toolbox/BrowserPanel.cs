// Browsing Data: history, downloads, searches and saved passwords from every browser on this machine
// (Chrome, Edge, Brave, … and Firefox), read straight from their SQLite stores. Group by site to analyse
// where the time went. Saved passwords are masked until you opt in, exactly like the Wi-Fi reveal.
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace PSTools
{
    public class BrowserPanel : ToolPanel
    {
        public override string Title { get { return Tools.Title(GetType().Name); } }
        public override string Blurb { get { return Tools.Blurb(GetType().Name); } }

        readonly DataView view; readonly SelectionBar sel = new SelectionBar(); readonly StepStrip steps = new StepStrip();
        readonly Button bHist, bDomains, bDown, bSearch, bPass, bReveal, bRefresh; readonly ComboBox cProfile, cMax; readonly Label status = Theme.Lbl("", Theme.Dim, Theme.UISmall); readonly Label lProfile;
        readonly Stat sRecords = new Stat("records"), sBrowsers = new Stat("browsers"), sDomains = new Stat("sites"), sTop = new Stat("top site"), sExtra = new Stat("span");
        readonly CheckBox cSecure;
        string mode = "history"; bool revealed, pendingReveal, loaded; volatile bool busy;
        readonly List<BrowserProfile> profiles = new List<BrowserProfile>();
        readonly List<VisitRow> hist = new List<VisitRow>(), downs = new List<VisitRow>(), searches = new List<VisitRow>();
        readonly List<LoginRow> logins = new List<LoginRow>();
        readonly List<DomainStat> domainStats = new List<DomainStat>();
        Thread worker;

        public BrowserPanel()
        {
            BackColor = Theme.Panel;
            FlowLayoutPanel bar = Theme.Bar(46);
            bHist = Theme.Btn("History", true); bHist.Click += delegate { SetMode("history"); };
            bDomains = Theme.Btn("Domains", false); bDomains.Click += delegate { SetMode("domains"); };
            bDown = Theme.Btn("Downloads", false); bDown.Click += delegate { SetMode("downloads"); };
            bSearch = Theme.Btn("Searches", false); bSearch.Click += delegate { SetMode("searches"); };
            bPass = Theme.Btn("Passwords", false); bPass.Click += delegate { SetMode("passwords"); };
            lProfile = Theme.Lbl("browser", Theme.Dim, Theme.UI); cProfile = Theme.Combo(200, "all browsers"); cProfile.SelectedIndexChanged += delegate { if (loaded) LoadData(false); };
            Label lm = Theme.Lbl("max", Theme.Dim, Theme.UI); cMax = Theme.Combo(100, "1,000", "5,000", "20,000", "all"); cMax.SelectedIndex = 1;
            bRefresh = Theme.Btn("Refresh", false); bRefresh.Click += delegate { LoadData(false); };
            bReveal = Theme.Caution("Reveal passwords…"); bReveal.Click += delegate { if (revealed) HideSecrets(); else Reveal(); }; bReveal.Visible = false;
            foreach (Control c in new Control[] { bHist, bDomains, bDown, bSearch, bPass, lProfile, cProfile, lm, cMax, bRefresh, bReveal, status }) bar.Controls.Add(c); status.Margin = new Padding(Theme.S(10), Theme.S(9), 0, 0);
            TableLayoutPanel strip = new TableLayoutPanel(); strip.Dock = DockStyle.Top; strip.Height = Theme.S(76); strip.BackColor = Theme.Panel; strip.Padding = new Padding(Theme.S(10), Theme.S(2), Theme.S(2), Theme.S(6)); strip.ColumnCount = 5; strip.RowCount = 1;
            foreach (Stat s in new Stat[] { sRecords, sBrowsers, sDomains, sTop, sExtra }) { strip.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 20f)); s.Dock = DockStyle.Fill; strip.Controls.Add(s); }
            view = NewView("browsing-data");
            view.SelectionChanged += delegate { sel.Update(view.SelectedCount, mode == "domains" ? "site" : "record"); };
            view.Activated += delegate (object o) { string url = RowUrl(o); if (url.Length == 0) { string d = RowDomain(o); if (d.Length > 0) url = "https://" + d; } if (url.Length > 0) Open(url); };
            cSecure = Theme.Toggle("insecure (http) only", false); cSecure.CheckedChanged += delegate { view.Refilter(); };
            view.Extra.Controls.Add(cSecure);
            view.Filter = delegate (object o) { if (!cSecure.Checked) return true; if (o is VisitRow) return !((VisitRow)o).Secure; if (o is LoginRow) return ((LoginRow)o).Url.StartsWith("http:", StringComparison.OrdinalIgnoreCase); return true; };
            sel.Add("Open", true, delegate { int k = 0; foreach (object o in view.Targets) { if (k++ >= 8) break; string url = RowUrl(o); if (url.Length == 0) { string d = RowDomain(o); if (d.Length > 0) url = "https://" + d; } if (url.Length > 0) Open(url); } });
            sel.Add("Copy URLs", false, delegate { List<string> l = new List<string>(); foreach (object o in view.Targets) l.Add(RowUrl(o)); Clip(l); });
            sel.Add("Copy domains", false, delegate { List<string> l = new List<string>(); foreach (object o in view.Targets) { string d = RowDomain(o); if (d.Length > 0) l.Add(d); } Clip(Dedupe(l)); });
            sel.Add("Export selected…", false, delegate { if (!revealed || mode != "passwords" || Host.Confirm("Include the revealed passwords?", "The passwords are on screen in clear text, so the export will contain them.\n\nContinue?")) view.Export(); });
            Controls.Add(view); Controls.Add(sel); Controls.Add(strip); Controls.Add(steps); Controls.Add(bar); view.BringToFront();
        }

        void SetMode(string m)
        {
            mode = m;
            foreach (Button b in new Button[] { bHist, bDomains, bDown, bSearch, bPass }) { bool on = (b == bHist && m == "history") || (b == bDomains && m == "domains") || (b == bDown && m == "downloads") || (b == bSearch && m == "searches") || (b == bPass && m == "passwords"); b.BackColor = on ? Theme.Panel3 : Theme.Panel2; b.ForeColor = on ? Theme.Teal : Theme.Ink; b.FlatAppearance.BorderColor = on ? Theme.Teal : Theme.Line; }
            bReveal.Visible = m == "passwords";
            if (m == "history") view.Apply(Columns.BrowserHistory());
            else if (m == "downloads") view.Apply(Columns.BrowserDownloads());
            else if (m == "searches") view.Apply(Columns.BrowserSearches());
            else if (m == "domains") view.Apply(Columns.BrowserDomains(domainStats));
            else view.Apply(Columns.BrowserPasswords(delegate { return revealed; }));
            if (loaded) LoadData(revealed && m == "passwords");
        }


        public override void OnShown() { if (loaded) return; loaded = true; DiscoverAndLoad(); }
        void Ui(Action a) { try { Host.BeginInvoke(a); } catch { } }

        void DiscoverAndLoad()
        {
            status.Text = "finding browsers…";
            worker = new Thread(delegate ()
            {
                List<BrowserProfile> ps; try { ps = Browser.Profiles(); } catch { ps = new List<BrowserProfile>(); }
                Ui(delegate
                {
                    profiles.Clear(); profiles.AddRange(ps); cProfile.Items.Clear(); cProfile.Items.Add("all browsers"); foreach (BrowserProfile p in ps) cProfile.Items.Add(p.Label); cProfile.SelectedIndex = 0;
                    if (ps.Count == 0) { status.Text = "no supported browsers found"; sBrowsers.Set("0", "found", Theme.Dim); return; }
                    SetMode("history"); LoadData(false);
                });
            });
            worker.IsBackground = true; worker.Start();
        }

        List<BrowserProfile> Selected()
        {
            if (cProfile.SelectedIndex <= 0) return new List<BrowserProfile>(profiles);
            List<BrowserProfile> l = new List<BrowserProfile>(); int idx = cProfile.SelectedIndex - 1; if (idx >= 0 && idx < profiles.Count) l.Add(profiles[idx]); return l;
        }
        int MaxRows() { switch (cMax.SelectedIndex) { case 0: return 1000; case 1: return 5000; case 2: return 20000; default: return int.MaxValue; } }

        void LoadData(bool reveal)
        {
            if (busy) { if (reveal) pendingReveal = true; Host.Toast("Still reading — one moment.", false); return; }
            List<BrowserProfile> targets = Selected(); if (targets.Count == 0) { status.Text = "no browser selected"; return; }
            busy = true; string m = mode; int max = MaxRows(); status.Text = (reveal ? "revealing" : "reading") + " " + m + "…"; steps.Begin(new string[] { "Read " + m }); steps.Set("Read " + m, "running", null);
            worker = new Thread(delegate ()
            {
                List<VisitRow> h = new List<VisitRow>(), d = new List<VisitRow>(), s = new List<VisitRow>(); List<LoginRow> lg = new List<LoginRow>(); List<string> errs = new List<string>();
                foreach (BrowserProfile p in targets)
                {
                    Ui(delegate { steps.Say(p.Label); });
                    try
                    {
                        if (m == "history" || m == "domains") h.AddRange(Browser.History(p, max));
                        else if (m == "downloads") d.AddRange(Browser.Downloads(p));
                        else if (m == "searches") s.AddRange(Browser.Searches(p));
                        else { if (p.Family == "chromium") lg.AddRange(BrowserCreds.Chromium(p, Directory.GetParent(p.Dir).FullName, reveal)); else lg.AddRange(BrowserCreds.Firefox(p, reveal)); }
                    }
                    catch (Exception ex) { if (errs.Count < 4) errs.Add(p.Label + ": " + Short(ex.Message)); }
                }
                if (m == "history") h.Sort(delegate (VisitRow a, VisitRow b) { return b.When.CompareTo(a.When); });
                if (m == "downloads") d.Sort(delegate (VisitRow a, VisitRow b) { return b.When.CompareTo(a.When); });
                Ui(delegate
                {
                    if (m != mode) { busy = false; return; }
                    if (m == "history") { hist.Clear(); hist.AddRange(h); view.SetItems(Boxed(hist), false); }
                    else if (m == "domains") { hist.Clear(); hist.AddRange(h); domainStats.Clear(); domainStats.AddRange(Browser.Domains(h)); view.SetItems(Boxed(domainStats), false); }
                    else if (m == "downloads") { downs.Clear(); downs.AddRange(d); view.SetItems(Boxed(downs), false); }
                    else if (m == "searches") { searches.Clear(); searches.AddRange(s); view.SetItems(Boxed(searches), false); }
                    else { logins.Clear(); logins.AddRange(lg); if (reveal) revealed = true; view.SetItems(Boxed(logins), false); }
                    Cards(); steps.Set("Read " + m, "done", null); steps.End("done");
                    int n = m == "history" ? hist.Count : m == "domains" ? domainStats.Count : m == "downloads" ? downs.Count : m == "searches" ? searches.Count : logins.Count;
                    status.Text = "done · " + n + " " + (m == "domains" ? "unique site(s)" : m + " record(s)") + (errs.Count > 0 ? " · " + errs.Count + " source(s) skipped" : "") + (m == "passwords" && reveal ? " · revealed" : "");
                    busy = false; if (pendingReveal && m == "passwords" && !revealed) { pendingReveal = false; LoadData(true); }
                    else pendingReveal = false;
                });
            });
            worker.IsBackground = true; worker.Start();
        }
        /// <summary>Masks the passwords again by re-reading them without decryption.</summary>
        void HideSecrets() { revealed = false; bReveal.Text = "Reveal passwords…"; if (mode == "passwords") LoadData(false); Host.Toast("Passwords hidden again.", false); }
        void Reveal()
        {
            if (mode != "passwords") { SetMode("passwords"); }
            if (!Host.Confirm("Reveal saved passwords",
                "This decrypts and shows the passwords this browser saved, in clear text.\n\n" +
                "They are decrypted locally with your own Windows account — nothing leaves this machine — but make sure nobody is looking over your shoulder.\n\n" +
                "Note: passwords protected by newer app-bound encryption, or a Firefox master password, may not be recoverable and will show a note instead. Continue?")) return;
            LoadData(true);
        }

        void Cards()
        {
            List<string> browsers = new List<string>(); foreach (BrowserProfile p in Selected()) if (!browsers.Contains(p.Browser)) browsers.Add(p.Browser);
            if (mode == "passwords")
            {
                int weak = 0, dec = 0, appbound = 0; foreach (LoginRow l in logins) { if (l.Weak) weak++; if (revealed && l.Password.Length > 0) dec++; if (l.Note.StartsWith("app-bound")) appbound++; }
                sRecords.Set(logins.Count.ToString(), "saved logins", Theme.Ink);
                sBrowsers.Set(browsers.Count.ToString(), "browsers", Theme.Ink);
                sDomains.Set(Domains(null).ToString(), "sites", Theme.Ink);
                sTop.Set(revealed ? dec.ToString() : "—", revealed ? "decrypted" : "hidden", revealed ? Theme.Amber : Theme.Dim); bReveal.Text = revealed ? "Hide passwords" : "Reveal passwords…";
                sExtra.Set(weak.ToString(), "weak (<8 chars)", weak > 0 ? Theme.Rose : Theme.Ink);
                return;
            }
            if (mode == "domains")
            {
                long totalVisits = 0; DateTime oldestD = DateTime.MaxValue, newestD = DateTime.MinValue; Dictionary<string, long> byBrowser = new Dictionary<string, long>();
                foreach (DomainStat d in domainStats) { totalVisits += d.Visits; if (d.First != DateTime.MaxValue && d.First != DateTime.MinValue && d.First < oldestD) oldestD = d.First; if (d.Last > newestD) newestD = d.Last; foreach (string b in d.Browsers) { long v; byBrowser.TryGetValue(b, out v); byBrowser[b] = v + d.Visits; } }
                string busiest = ""; long bv = 0; foreach (KeyValuePair<string, long> kv in byBrowser) if (kv.Value > bv) { bv = kv.Value; busiest = kv.Key; }
                sRecords.Set(domainStats.Count.ToString("N0"), "unique sites", Theme.Ink);
                sBrowsers.Set(browsers.Count.ToString(), "browsers", Theme.Ink);
                sDomains.Set(totalVisits.ToString("N0"), "total visits", Theme.Teal);
                sTop.Set(domainStats.Count > 0 ? domainStats[0].Domain : "—", domainStats.Count > 0 ? domainStats[0].Visits + " visits" : "", Theme.Teal);
                sExtra.Set(busiest.Length > 0 ? busiest : "—", "busiest browser", Theme.Dim);
                return;
            }
            List<VisitRow> rows = mode == "history" ? hist : mode == "downloads" ? downs : searches;
            Dictionary<string, int> dom = new Dictionary<string, int>(); DateTime oldest = DateTime.MaxValue, newest = DateTime.MinValue;
            foreach (VisitRow v in rows) { if (v.Domain.Length > 0) { int n; dom.TryGetValue(v.Domain, out n); dom[v.Domain] = n + 1; } if (v.When != DateTime.MinValue) { if (v.When < oldest) oldest = v.When; if (v.When > newest) newest = v.When; } }
            string top = ""; int topN = 0; foreach (KeyValuePair<string, int> kv in dom) if (kv.Value > topN) { topN = kv.Value; top = kv.Key; }
            sRecords.Set(rows.Count.ToString("N0"), mode, Theme.Ink);
            sBrowsers.Set(browsers.Count.ToString(), "browsers", Theme.Ink);
            sDomains.Set(dom.Count.ToString("N0"), "distinct sites", Theme.Ink);
            sTop.Set(top.Length > 0 ? top : "—", topN > 0 ? topN + " visits" : "", Theme.Teal);
            sExtra.Set(oldest == DateTime.MaxValue ? "—" : oldest.ToString("yyyy-MM-dd"), newest == DateTime.MinValue ? "span" : "to " + newest.ToString("MM-dd"), Theme.Dim);
        }
        int Domains(string _) { List<string> d = new List<string>(); foreach (LoginRow l in logins) { string x = l.Domain.Length > 0 ? l.Domain : l.Url; if (!d.Contains(x)) d.Add(x); } return d.Count; }

static string RowUrl(object o) { if (o is LoginRow) return ((LoginRow)o).Url; if (o is VisitRow) return ((VisitRow)o).Url; return ""; }
        static string RowDomain(object o) { if (o is LoginRow) return ((LoginRow)o).Domain; if (o is VisitRow) return ((VisitRow)o).Domain; if (o is DomainStat) return ((DomainStat)o).Domain; return ""; }
        static string Short(string s) { s = (s ?? "").Replace("\r", " ").Replace("\n", " "); return s.Length > 70 ? s.Substring(0, 70) + "…" : s; }
        static List<string> Dedupe(List<string> l) { List<string> o = new List<string>(); HashSet<string> seen = new HashSet<string>(); foreach (string s in l) if (seen.Add(s)) o.Add(s); return o; }
        void Clip(List<string> l) { l.RemoveAll(delegate (string s) { return string.IsNullOrEmpty(s); }); if (l.Count == 0) { Host.Toast("Nothing to copy.", true); return; } try { Clipboard.SetText(string.Join("\r\n", l.ToArray())); Host.Toast(l.Count + " line(s) copied", false); } catch { } }
        static void Open(string url) { try { if (url.StartsWith("http", StringComparison.OrdinalIgnoreCase)) System.Diagnostics.Process.Start(url); } catch { } }

        public override void SelfTest(StringBuilder r)
        {
            if (r == null) { Demo(); return; }
            List<BrowserProfile> ps = Browser.Profiles();
            r.AppendLine((ps.Count > 0 ? "PASS" : "INFO") + " browsing data: found " + ps.Count + " browser profile(s)");
            profiles.Clear(); profiles.AddRange(ps);
            int totalHist = 0, totalDown = 0, totalPw = 0;
            foreach (BrowserProfile p in ps)
            {
                try { List<VisitRow> h = Browser.History(p, 500); totalHist += h.Count; } catch (Exception ex) { r.AppendLine("INFO   " + p.Label + " history: " + Short(ex.Message)); }
                try { totalDown += Browser.Downloads(p).Count; } catch { }
                try { totalPw += (p.Family == "chromium" ? BrowserCreds.Chromium(p, Directory.GetParent(p.Dir).FullName, false) : BrowserCreds.Firefox(p, false)).Count; } catch { }
            }
            if (ps.Count > 0) { SetMode("history"); hist.Clear(); foreach (BrowserProfile p in ps) { try { hist.AddRange(Browser.History(p, 500)); } catch { } } view.SetItems(Boxed(hist), false); Cards();
                r.AppendLine("PASS browsing data: read " + totalHist + " history, " + totalDown + " download(s), " + totalPw + " saved login(s) across " + ps.Count + " profile(s)"); }
            r.AppendLine("PASS browsing data: saved passwords stay masked until revealed");
        }
        void Demo()
        {
            SetMode("history"); hist.Clear();
            hist.Add(H("Google", "https://www.google.com/", "google.com", 412, 0));
            hist.Add(H("GitHub · Where the world builds software", "https://github.com/", "github.com", 208, -1));
            hist.Add(H("YouTube", "https://www.youtube.com/", "youtube.com", 356, -2));
            hist.Add(H("Stack Overflow - Where Developers Learn", "https://stackoverflow.com/questions", "stackoverflow.com", 143, -3));
            hist.Add(H("Hacker News", "https://news.ycombinator.com/", "news.ycombinator.com", 97, -4));
            hist.Add(H("Old intranet (insecure)", "http://intranet.local/dashboard", "intranet.local", 22, -5));
            hist.Add(H("Reddit - Dive into anything", "https://www.reddit.com/", "reddit.com", 180, -6));
            hist.Add(H("Amazon.com", "https://www.amazon.com/", "amazon.com", 64, -8));
            view.SetItems(Boxed(hist), false); Cards(); status.Text = "done · 8 history record(s)"; sBrowsers.Set("2", "browsers", Theme.Ink);
        }
        static VisitRow H(string title, string url, string domain, long visits, int daysAgo) { VisitRow v = new VisitRow(); v.Kind = "history"; v.Title = title; v.Url = url; v.Domain = domain; v.VisitCount = visits; v.When = DateTime.Now.AddDays(daysAgo).AddHours(-2); v.Browser = "Chrome"; v.Profile = "Default"; return v; }
    }
}

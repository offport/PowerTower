// 7 · Vulnerability Management: the panel over Vuln.cs. Four row sets (findings, missing updates, installed
// software, hotfixes) in one DataView, a summary strip, filters for severity / status / source / exploited,
// and per-mode actions on the selection (copy CVE IDs, open advisories, look up selected software, export).
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Text;
using System.Windows.Forms;

namespace PSTools
{
    /// <summary>A summary card: caption, big value, one sub-line.</summary>
    public class Stat : Control
    {
        public string Caption, Value = "—", Sub = ""; public Color Colour = Theme.Ink;
        public Stat(string caption) { Caption = caption; SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true); BackColor = Theme.Side; Margin = new Padding(0, 0, Theme.S(8), 0); }
        public void Set(string value, string sub, Color colour) { Value = value; Sub = sub; Colour = colour; Invalidate(); }
        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics; g.Clear(Theme.Side);
            TextRenderer.DrawText(g, Caption.ToUpperInvariant(), Theme.UISmall, new Point(Theme.S(10), Theme.S(6)), Theme.Faint, TextFormatFlags.NoPrefix);
            TextRenderer.DrawText(g, Value, Theme.Big, new Rectangle(Theme.S(8), Theme.S(20), Width - Theme.S(12), Theme.S(24)), Colour, TextFormatFlags.NoPrefix | TextFormatFlags.EndEllipsis | TextFormatFlags.SingleLine);
            TextRenderer.DrawText(g, Sub, Theme.UISmall, new Rectangle(Theme.S(10), Theme.S(46), Width - Theme.S(14), Theme.S(16)), Theme.Dim, TextFormatFlags.NoPrefix | TextFormatFlags.EndEllipsis | TextFormatFlags.SingleLine);
            using (Pen p = new Pen(Colour == Theme.Ink ? Theme.Line : Colour)) g.DrawLine(p, 0, 0, 0, Height);
        }
    }

    public class VulnPanel : ToolPanel
    {
        public override string Title { get { return "Vulnerability Management"; } }
        public override string Blurb { get { return "Which CVEs this machine is exposed to and why: the OS build and installed hotfixes against Microsoft's monthly security releases, installed software against the NVD, and what Windows Update is offering right now. CISA's known-exploited list and EPSS rank the findings; every one shows its evidence."; } }
        readonly DataView view; readonly SelectionBar sel = new SelectionBar(); readonly Button bFind, bMissing, bSoft, bFix, bScan, bCancel, bFeeds, bLog; readonly CheckBox cWua, cMsrc, cNvd, cKev, cEpss; readonly NumericUpDown nMonths; readonly TextBox tKey; readonly Label status = Theme.Lbl("", Theme.Dim, Theme.UISmall);
        readonly Stat sOs = new Stat("OS build"), sReboot = new Stat("reboot"), sCrit = new Stat("critical"), sHigh = new Stat("high"), sKev = new Stat("known exploited"), sMissing = new Stat("missing updates"), sSoft = new Stat("software");
        readonly ComboBox cSev, cStatus, cSource; readonly CheckBox cKevOnly; readonly Label lSev, lStatus, lSource;
        string mode = "findings"; VulnScan scan; FeedCache cache; bool settingsLoaded; readonly StepStrip steps = new StepStrip();
        /// <summary>The open findings from the last scan this session (empty if none), for the Findings Map.</summary>
        public List<Finding> OpenFindings() { List<Finding> l = new List<Finding>(); if (scan != null) foreach (Finding f in scan.FindingsSnapshot()) if (f.Open) l.Add(f); return l; }

        public VulnPanel()
        {
            BackColor = Theme.Panel;
            FlowLayoutPanel bar = Theme.Bar(46);
            bFind = Theme.Btn("Findings", false); bMissing = Theme.Btn("Missing updates", false); bSoft = Theme.Btn("Software", false); bFix = Theme.Btn("Hotfixes", false);
            bFind.Click += delegate { SetMode("findings"); }; bMissing.Click += delegate { SetMode("missing"); }; bSoft.Click += delegate { SetMode("software"); }; bFix.Click += delegate { SetMode("hotfixes"); };
            bScan = Theme.Btn("Scan this machine", true); bScan.Click += delegate { Scan(); }; bCancel = Theme.Btn("Cancel", false); bCancel.Enabled = false; bCancel.Click += delegate { if (scan != null) { scan.Cancel = true; Host.Toast("Stopping after the current step…", true); } };
            cWua = Theme.Toggle("Windows Update", true); cMsrc = Theme.Toggle("Microsoft CVEs", true); cNvd = Theme.Toggle("third-party (NVD)", true); cKev = Theme.Toggle("KEV", true); cEpss = Theme.Toggle("EPSS", true);
            ToolTip tip = new ToolTip(); tip.AutoPopDelay = 12000;
            tip.SetToolTip(cWua, "Ask the Windows Update Agent which updates apply here and are not installed (slow: 20 s to a few minutes), plus the install history."); tip.SetToolTip(cMsrc, "Microsoft's monthly security releases (CVRF): compare the OS build/UBR with each fix's FixedBuild, KB supersedence as fallback."); tip.SetToolTip(cNvd, "Installed software in the product map, looked up on the NVD at the installed version. Without a key: one product every 6.5 s.");
            tip.SetToolTip(cKev, "Flag CVEs in CISA's Known Exploited Vulnerabilities catalogue."); tip.SetToolTip(cEpss, "Exploit Prediction Scoring System: how likely each open CVE is to be exploited in the next 30 days.");
            Label lm = Theme.Lbl("months", Theme.Dim, Theme.UI); nMonths = Theme.Num(3, 1, 12, 52); tip.SetToolTip(nMonths, "How many monthly MSRC releases to check, newest first. A machine that is a year behind needs 12."); Label lk = Theme.Lbl("NVD key", Theme.Dim, Theme.UI); tKey = Theme.Text("", 130); tKey.UseSystemPasswordChar = true; tip.SetToolTip(tKey, "Optional free NVD API key (nvd.nist.gov/developers/request-an-api-key): 50 requests per 30 s instead of 5. Saved in settings.ini next to the exe.");
            bFeeds = Theme.Btn("Feed cache…", false); bFeeds.Click += delegate { FeedsDialog(); }; bLog = Theme.Btn("Log…", false); bLog.Click += delegate { ShowLog(); };
            Panel gap = new Panel(); gap.Width = Theme.S(14); gap.Height = 1;
            foreach (Control c in new Control[] { bFind, bMissing, bSoft, bFix, gap, bScan, bCancel, cWua, cMsrc, cNvd, cKev, cEpss, lm, nMonths, lk, tKey, bFeeds, bLog, status }) bar.Controls.Add(c); status.Margin = new Padding(Theme.S(10), Theme.S(9), 0, 0);
            // the summary strip
            TableLayoutPanel strip = new TableLayoutPanel(); strip.Dock = DockStyle.Top; strip.Height = Theme.S(76); strip.BackColor = Theme.Panel; strip.Padding = new Padding(Theme.S(10), Theme.S(2), Theme.S(2), Theme.S(6)); strip.ColumnCount = 7; strip.RowCount = 1;
            foreach (Stat s in new Stat[] { sOs, sReboot, sCrit, sHigh, sKev, sMissing, sSoft }) { strip.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, s == sOs ? 22 : s == sReboot ? 16 : 12.4f)); s.Dock = DockStyle.Fill; strip.Controls.Add(s); }
            // the rows
            view = NewView("vulnerability-findings");
            lSev = Theme.Lbl("severity", Theme.Dim, Theme.UI); cSev = Theme.Combo(96, "all", "critical", "high +", "medium +"); lStatus = Theme.Lbl("status", Theme.Dim, Theme.UI); cStatus = Theme.Combo(128, "open", "all", "vulnerable", "update available", "reboot pending", "patched", "unconfirmed"); lSource = Theme.Lbl("source", Theme.Dim, Theme.UI); cSource = Theme.Combo(130, "all", "MSRC", "NVD", "Windows Update"); cKevOnly = Theme.Toggle("exploited only", false);
            foreach (Control c in new Control[] { lSev, cSev, lStatus, cStatus, lSource, cSource, cKevOnly }) view.Extra.Controls.Add(c);
            cSev.SelectedIndexChanged += delegate { view.Refilter(); }; cStatus.SelectedIndexChanged += delegate { view.Refilter(); }; cSource.SelectedIndexChanged += delegate { view.Refilter(); }; cKevOnly.CheckedChanged += delegate { view.Refilter(); };
            view.Filter = FilterRow;
            view.SelectionChanged += delegate { sel.Update(view.SelectedCount, Noun()); };
            view.Activated += delegate (object o)
            {
                Finding f = o as Finding; if (f != null && f.Url.Length > 0) { Open(f.Url); return; }
                MissingUpdate m = o as MissingUpdate; if (m != null && m.Kb.Length > 0) { Open("https://support.microsoft.com/help/" + m.Kb); return; }
                Hotfix h = o as Hotfix; if (h != null && h.Kb.Length > 0) { Open("https://support.microsoft.com/help/" + h.Kb); return; }
                Software s = o as Software; if (s != null && s.Mapped) Open("https://nvd.nist.gov/vuln/search/results?form_type=Advanced&cpe_vendor=cpe%3A%2F%3A" + Uri.EscapeDataString(s.Vendor) + "&cpe_product=cpe%3A%2F%3A" + Uri.EscapeDataString(s.Vendor) + "%3A" + Uri.EscapeDataString(s.Product));
            };
            Controls.Add(view); Controls.Add(sel); Controls.Add(strip); Controls.Add(steps); Controls.Add(bar); view.BringToFront();
            SetMode("findings");
        }

        public override void OnShown()
        {
            if (settingsLoaded) return; settingsLoaded = true;
            Settings st = Host.Settings; tKey.Text = st.Get("vuln.key", ""); decimal m; if (decimal.TryParse(st.Get("vuln.months", "3"), out m) && m >= 1 && m <= 12) nMonths.Value = m;
            cWua.Checked = st.Get("vuln.wua", "1") == "1"; cMsrc.Checked = st.Get("vuln.msrc", "1") == "1"; cNvd.Checked = st.Get("vuln.nvd", "1") == "1"; cKev.Checked = st.Get("vuln.kev", "1") == "1"; cEpss.Checked = st.Get("vuln.epss", "1") == "1";
            cache = OpenCache();
            // the cheap facts right away, so the strip is never empty
            try { scan = new VulnScan(); scan.Os = Inventory.Os(); scan.Reboot = Inventory.Reboot(); Cards(); status.Text = "not scanned yet · feed cache: " + cache.Dir; } catch (Exception ex) { status.Text = ex.Message; }
        }
        public override void OnHidden() { if (settingsLoaded) SaveSettings(); }
        void SaveSettings()
        {
            Settings st = Host.Settings; st.Set("vuln.key", tKey.Text.Trim()); st.Set("vuln.months", ((int)nMonths.Value).ToString()); st.Set("vuln.wua", cWua.Checked ? "1" : "0"); st.Set("vuln.msrc", cMsrc.Checked ? "1" : "0"); st.Set("vuln.nvd", cNvd.Checked ? "1" : "0"); st.Set("vuln.kev", cKev.Checked ? "1" : "0"); st.Set("vuln.epss", cEpss.Checked ? "1" : "0"); st.Save();
        }
        static FeedCache OpenCache()
        {
            string local = Path.Combine(Path.GetDirectoryName(Application.ExecutablePath), "cache");
            try { Directory.CreateDirectory(local); string probe = Path.Combine(local, ".write-test"); File.WriteAllText(probe, "ok"); File.Delete(probe); return new FeedCache(local); }
            catch { return new FeedCache(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PowerTower", "cache")); }
        }

        // ── modes ──
        string Noun() { return mode == "findings" ? "finding" : mode == "missing" ? "update" : mode == "software" ? "program" : "hotfix"; }
        void SetMode(string m)
        {
            mode = m;
            foreach (Button b in new Button[] { bFind, bMissing, bSoft, bFix }) { bool on = (b == bFind && m == "findings") || (b == bMissing && m == "missing") || (b == bSoft && m == "software") || (b == bFix && m == "hotfixes"); b.BackColor = on ? Theme.Panel3 : Theme.Panel2; b.ForeColor = on ? Theme.Teal : Theme.Ink; b.FlatAppearance.BorderColor = on ? Theme.Teal : Theme.Line; }
            bool findings = m == "findings"; foreach (Control c in new Control[] { lSev, cSev, lStatus, cStatus, lSource, cSource, cKevOnly }) c.Visible = findings;
            view.ExportName = findings ? "vulnerability-findings" : m == "missing" ? "missing-updates" : m == "software" ? "installed-software" : "hotfixes";
            sel.Clear();
            if (findings)
            {
                view.SetColumns(FindingCols()); view.TreePath = delegate (object o) { Finding f = (Finding)o; return new string[] { f.Source, f.Product, f.Cve }; }; view.TreeNodeText = null;
                sel.Add("Copy CVE IDs", true, delegate { CopyLines(delegate (object o) { return ((Finding)o).Cve; }); }); sel.Add("Open advisories", false, delegate { OpenSelected(); });
                sel.Add("Copy as text", false, delegate { CopyLines(delegate (object o) { Finding f = (Finding)o; return f.Cve + "\t" + f.SeverityNorm + "\t" + (f.Cvss.HasValue ? f.Cvss.Value.ToString("0.0") : "") + "\t" + f.ExploitText + "\t" + f.Status + "\t" + f.Product + "\t" + f.Fix + "\t" + f.Evidence; }); });
                sel.Add("Send fix KBs to clipboard", false, delegate { CopyLines(delegate (object o) { Finding f = (Finding)o; int i = f.Fix.IndexOf("KB"); return i < 0 ? null : f.Fix.Substring(i).Split(' ')[0]; }); });
            }
            else if (m == "missing")
            {
                view.SetColumns(MissingCols()); view.TreePath = delegate (object o) { MissingUpdate u = (MissingUpdate)o; return new string[] { u.Kind, u.Title }; };
                sel.Add("Copy KBs", true, delegate { CopyLines(delegate (object o) { MissingUpdate u = (MissingUpdate)o; return u.Kb.Length > 0 ? "KB" + u.Kb : null; }); }); sel.Add("Copy CVE IDs", false, delegate { List<string> l = new List<string>(); foreach (object o in view.Targets) l.AddRange(((MissingUpdate)o).Cves); Clip(l); });
                sel.Add("Open Windows Update", false, delegate { try { Process.Start("ms-settings:windowsupdate"); } catch { } }); sel.Add("Copy titles", false, delegate { CopyLines(delegate (object o) { return ((MissingUpdate)o).Title; }); });
            }
            else if (m == "software")
            {
                view.SetColumns(SoftwareCols()); view.TreePath = delegate (object o) { Software s = (Software)o; return new string[] { s.Mapped ? "in the product map" : "not mapped", s.Publisher.Length > 0 ? s.Publisher : "(no publisher)", s.Name + " " + s.Version }; };
                sel.Add("Look up CVEs for selected", true, delegate { Lookup(); }); sel.Add("Copy names", false, delegate { CopyLines(delegate (object o) { Software s = (Software)o; return s.Name + "\t" + s.Version + "\t" + s.Publisher; }); });
            }
            else
            {
                view.SetColumns(HotfixCols()); view.TreePath = delegate (object o) { Hotfix h = (Hotfix)o; return new string[] { h.Source, "KB" + h.Kb + (h.Title.Length > 0 && h.Source == "WU history" ? " · " + h.Title : "") }; };
                sel.Add("Copy KBs", true, delegate { CopyLines(delegate (object o) { Hotfix h = (Hotfix)o; return h.Kb.Length > 0 ? "KB" + h.Kb : null; }); });
            }
            sel.Add("Export selected", false, delegate { view.Export(); }); sel.Add("Clear selection", false, delegate { view.ClearSelection(); });
            Reload();
        }
        bool FilterRow(object o)
        {
            Finding f = o as Finding; if (f == null) return true;
            int sev = Resolve.SevRank(f.SeverityNorm);
            switch (cSev.SelectedIndex) { case 1: if (sev < 4) return false; break; case 2: if (sev < 3) return false; break; case 3: if (sev < 2) return false; break; }
            string st = (string)cStatus.SelectedItem; if (st == "open") { if (!f.Open) return false; } else if (st != "all" && f.Status != st) return false;
            if (cSource.SelectedIndex > 0 && f.Source != (string)cSource.SelectedItem) return false;
            if (cKevOnly.Checked && !f.Kev && !f.Exploited) return false;
            return true;
        }

        List<Col> FindingCols()
        {
            List<Col> c = new List<Col>();
            c.Add(new Col("cve", "CVE", 128, delegate (object o) { return ((Finding)o).Cve; }));
            c.Add(new Col("sev", "Severity", 78, delegate (object o) { return Resolve.SevRank(((Finding)o).SeverityNorm); }).Num(delegate (object o) { return ((Finding)o).SeverityNorm; }).Colour(delegate (object o) { return Theme.SeverityColor(((Finding)o).SeverityNorm); }));
            c.Add(new Col("cvss", "CVSS", 56, delegate (object o) { return ((Finding)o).Cvss ?? -1; }).Num(delegate (object o) { Finding f = (Finding)o; return f.Cvss.HasValue ? f.Cvss.Value.ToString("0.0") : ""; }));
            c.Add(new Col("kev", "Exploited", 112, delegate (object o) { return ((Finding)o).ExploitText; }).Colour(delegate (object o) { return Theme.Rose; }));
            c.Add(new Col("epss", "EPSS", 62, delegate (object o) { return ((Finding)o).Epss ?? -1; }).Num(delegate (object o) { Finding f = (Finding)o; return f.Epss.HasValue ? (f.Epss.Value * 100).ToString("0.0") + " %" : ""; }));
            c.Add(new Col("status", "Status", 118, delegate (object o) { return ((Finding)o).Status; }).Colour(delegate (object o) { return Theme.StatusColor(((Finding)o).Status); }));
            c.Add(new Col("product", "Product", 230, delegate (object o) { return ((Finding)o).Product; }));
            c.Add(new Col("inst", "Installed", 116, delegate (object o) { return ((Finding)o).Installed; }).Colour(delegate (object o) { return Theme.Dim; }));
            c.Add(new Col("fix", "Fix", 210, delegate (object o) { return ((Finding)o).Fix; }).Colour(delegate (object o) { return Theme.Green; }));
            c.Add(new Col("src", "Source", 104, delegate (object o) { return ((Finding)o).Source; }).Colour(delegate (object o) { return Theme.Dim; }));
            c.Add(new Col("title", "Title", 340, delegate (object o) { return ((Finding)o).Title; }));
            c.Add(new Col("ev", "Evidence", 460, delegate (object o) { return ((Finding)o).Evidence; }).Colour(delegate (object o) { return Theme.Dim; }));
            c.Add(new Col("rel", "Release", 76, delegate (object o) { return ((Finding)o).Release; }).Colour(delegate (object o) { return Theme.Faint; }));
            c.Add(new Col("due", "KEV due", 90, delegate (object o) { return ((Finding)o).KevDue; }).Colour(delegate (object o) { return Theme.Faint; }));
            return c;
        }
        List<Col> MissingCols()
        {
            List<Col> c = new List<Col>();
            c.Add(new Col("kb", "KB", 96, delegate (object o) { MissingUpdate u = (MissingUpdate)o; return u.Kb.Length > 0 ? "KB" + u.Kb : ""; }));
            c.Add(new Col("title", "Title", 430, delegate (object o) { return ((MissingUpdate)o).Title; }));
            c.Add(new Col("sev", "Severity", 80, delegate (object o) { return Resolve.NormSeverity(((MissingUpdate)o).Severity); }).Colour(delegate (object o) { return Theme.SeverityColor(((MissingUpdate)o).Severity); }));
            c.Add(new Col("kind", "Kind", 90, delegate (object o) { return ((MissingUpdate)o).Kind; }).Colour(delegate (object o) { string k = ((MissingUpdate)o).Kind; return k == "security" || k == "critical" ? Theme.Amber : Theme.Dim; }));
            c.Add(new Col("cves", "CVEs", 200, delegate (object o) { return ((MissingUpdate)o).CveText; }));
            c.Add(new Col("dl", "Downloaded", 90, delegate (object o) { return ((MissingUpdate)o).Downloaded ? "yes" : "no"; }).Colour(delegate (object o) { return ((MissingUpdate)o).Downloaded ? Theme.Green : Theme.Dim; }));
            c.Add(new Col("size", "Size", 80, delegate (object o) { return ((MissingUpdate)o).SizeBytes; }).Num(delegate (object o) { double s = ((MissingUpdate)o).SizeBytes; return s > 0 ? Fmt.Bytes(s) : ""; }));
            c.Add(new Col("pub", "Published", 90, delegate (object o) { return ((MissingUpdate)o).PublishedText; }).Colour(delegate (object o) { return Theme.Dim; }));
            c.Add(new Col("reboot", "Reboot", 70, delegate (object o) { return ((MissingUpdate)o).Reboot; }).Colour(delegate (object o) { return Theme.Dim; }));
            c.Add(new Col("cat", "Categories", 240, delegate (object o) { return ((MissingUpdate)o).Categories; }).Colour(delegate (object o) { return Theme.Faint; }));
            return c;
        }
        List<Col> SoftwareCols()
        {
            List<Col> c = new List<Col>();
            c.Add(new Col("name", "Program", 290, delegate (object o) { return ((Software)o).Name; }));
            c.Add(new Col("ver", "Version", 120, delegate (object o) { return ((Software)o).Version; }));
            c.Add(new Col("cves", "CVEs", 56, delegate (object o) { return ((Software)o).Cves; }).Num(delegate (object o) { int n = ((Software)o).Cves; return n < 0 ? "" : n.ToString(); }).Colour(delegate (object o) { return ((Software)o).Cves > 0 ? Theme.Rose : Theme.Green; }));
            c.Add(new Col("cpe", "NVD product", 190, delegate (object o) { return ((Software)o).Cpe; }).Colour(delegate (object o) { return Theme.Teal; }));
            c.Add(new Col("status", "Status", 300, delegate (object o) { return ((Software)o).Status; }).Colour(delegate (object o) { Software s = (Software)o; return s.Cves > 0 ? Theme.Amber : s.Status.StartsWith("lookup failed") ? Theme.Rose : Theme.Dim; }));
            c.Add(new Col("pub", "Publisher", 190, delegate (object o) { return ((Software)o).Publisher; }).Colour(delegate (object o) { return Theme.Dim; }));
            c.Add(new Col("inst", "Installed", 90, delegate (object o) { return ((Software)o).Installed; }).Colour(delegate (object o) { return Theme.Dim; }));
            c.Add(new Col("scope", "Scope", 110, delegate (object o) { return ((Software)o).Scope; }).Colour(delegate (object o) { return Theme.Faint; }));
            return c;
        }
        List<Col> HotfixCols()
        {
            List<Col> c = new List<Col>();
            c.Add(new Col("kb", "KB", 100, delegate (object o) { Hotfix h = (Hotfix)o; return h.Kb.Length > 0 ? "KB" + h.Kb : ""; }));
            c.Add(new Col("src", "Source", 90, delegate (object o) { return ((Hotfix)o).Source; }).Colour(delegate (object o) { return Theme.Dim; }));
            c.Add(new Col("when", "Installed on", 100, delegate (object o) { return ((Hotfix)o).When; }));
            c.Add(new Col("result", "Result", 130, delegate (object o) { return ((Hotfix)o).Result; }).Colour(delegate (object o) { string r = ((Hotfix)o).Result; return r == "failed" || r == "aborted" ? Theme.Rose : r == "install pending" || r == "superseded" ? Theme.Amber : Theme.Dim; }));
            c.Add(new Col("desc", "Description", 150, delegate (object o) { return ((Hotfix)o).Description; }).Colour(delegate (object o) { return Theme.Dim; }));
            c.Add(new Col("title", "Title", 520, delegate (object o) { return ((Hotfix)o).Title; }));
            return c;
        }

        // ── data in, data out ──
        void Reload()
        {
            List<object> items = new List<object>();
            if (scan != null)
            {
                if (mode == "findings") foreach (Finding f in scan.FindingsSnapshot()) items.Add(f);
                else if (mode == "missing") foreach (MissingUpdate m in scan.MissingSnapshot()) items.Add(m);
                else if (mode == "software") foreach (Software s in scan.SoftwareSnapshot()) items.Add(s);
                else foreach (Hotfix h in scan.HotfixSnapshot()) items.Add(h);
            }
            view.SetItems(items, true); Cards();
        }
        void Cards()
        {
            OsInfo os = scan != null ? scan.Os : null; RebootInfo rb = scan != null ? scan.Reboot : null;
            sOs.Set(os != null ? os.FullBuild : "—", os != null ? os.ProductName + (os.DisplayVersion.Length > 0 ? " " + os.DisplayVersion : "") + " · " + os.Arch : "scan to read", Theme.Ink);
            sReboot.Set(rb == null ? "—" : rb.Pending ? "pending" : "none", rb == null ? "" : rb.Why, rb != null && rb.Pending ? Theme.Amber : Theme.Green);
            int crit = 0, high = 0, kev = 0; List<Finding> fs = scan != null ? scan.FindingsSnapshot() : new List<Finding>();
            foreach (Finding f in fs) { if (!f.Open) continue; string s = f.SeverityNorm; if (s == "Critical") crit++; else if (s == "High") high++; if (f.Kev || f.Exploited) kev++; }
            bool scanned = scan != null && scan.FinishedAt != DateTime.MinValue;
            sCrit.Set(scanned || fs.Count > 0 ? crit.ToString() : "—", "open findings", crit > 0 ? Theme.Rose : scanned ? Theme.Green : Theme.Ink); sHigh.Set(scanned || fs.Count > 0 ? high.ToString() : "—", "open findings", high > 0 ? Theme.Amber : scanned ? Theme.Green : Theme.Ink); sKev.Set(scanned || fs.Count > 0 ? kev.ToString() : "—", "KEV or MSRC exploited", kev > 0 ? Theme.Rose : scanned ? Theme.Green : Theme.Ink);
            List<MissingUpdate> ms = scan != null ? scan.MissingSnapshot() : new List<MissingUpdate>(); int sec = 0; foreach (MissingUpdate m in ms) if (m.Kind == "security" || m.Kind == "critical") sec++;
            sMissing.Set(scanned || ms.Count > 0 ? ms.Count.ToString() : "—", scanned || ms.Count > 0 ? sec + " security" : "from Windows Update", sec > 0 ? Theme.Amber : Theme.Ink);
            List<Software> sw = scan != null ? scan.SoftwareSnapshot() : new List<Software>(); int mapped = 0; foreach (Software s in sw) if (s.Mapped) mapped++;
            sSoft.Set(sw.Count > 0 ? sw.Count.ToString() : "—", sw.Count > 0 ? mapped + " in the product map" : "installed programs", Theme.Ink);
        }
        void Ui(Action a) { try { Host.BeginInvoke(a); } catch { } }
        VulnScan NewScan()
        {
            VulnScan s = new VulnScan(); s.DoWua = cWua.Checked; s.DoMsrc = cMsrc.Checked; s.DoNvd = cNvd.Checked; s.DoKev = cKev.Checked; s.DoEpss = cEpss.Checked; s.Months = (int)nMonths.Value; s.NvdApiKey = tKey.Text.Trim(); s.Cache = cache;
            s.Progress += delegate (string msg) { Ui(delegate { status.Text = msg; if (scan == s) { steps.Fraction = s.Fraction; steps.Say(msg); } }); };
            s.Step += delegate (string label, string state, string note) { Ui(delegate { if (scan == s) steps.Set(label, state, note); }); };
            s.Phase += delegate { Ui(delegate { if (scan == s) Reload(); }); };
            s.Finished += delegate { Ui(delegate { if (scan != s) return; bScan.Enabled = true; bCancel.Enabled = false; Reload(); int open = 0; foreach (Finding f in s.FindingsSnapshot()) if (f.Open) open++; steps.End((s.Cancel ? "cancelled · " : "finished · ") + open + " open finding(s) of " + s.Findings.Count + (s.Errors.Count > 0 ? " · " + s.Errors.Count + " problem(s), see Log…" : "")); Host.Toast(s.Errors.Count > 0 ? "Finished with " + s.Errors.Count + " problem(s) - see Log… · " + open + " open finding(s)" : "Scan finished: " + open + " open finding(s)", s.Errors.Count > 0); }); };
            return s;
        }
        void Scan()
        {
            if (scan != null && scan.Running) { Host.Toast("A scan is already running.", true); return; }
            if (!cWua.Checked && !cMsrc.Checked && !cNvd.Checked) { Host.Toast("Tick at least one source: Windows Update, Microsoft CVEs or third-party.", true); return; }
            SaveSettings(); scan = NewScan(); bScan.Enabled = false; bCancel.Enabled = true; status.Text = "starting…"; steps.Begin(VulnScan.StepLabels); if (mode != "findings") SetMode("findings"); else Reload();
            scan.RunInBackground();
        }
        void Lookup()
        {
            if (scan == null) return; if (scan.Running) { Host.Toast("A scan is already running.", true); return; }
            List<Software> l = new List<Software>(); int unmapped = 0; foreach (object o in view.Targets) { Software s = (Software)o; if (s.Mapped) l.Add(s); else unmapped++; }
            if (l.Count == 0) { Host.Toast(unmapped > 0 ? "None of the selected programs is in the product map." : "Nothing selected.", true); return; }
            scan.NvdApiKey = tKey.Text.Trim(); scan.Cache = cache; bScan.Enabled = false; bCancel.Enabled = true; scan.Cancel = false;
            steps.Begin("Third-party (NVD)", "KEV", "EPSS"); steps.Set("Third-party (NVD)", "running", l.Count + " program(s)");
            scan.LookupInBackground(l);
        }
        void CopyLines(Func<object, string> f) { List<string> l = new List<string>(); foreach (object o in view.Targets) { string s = f(o); if (!string.IsNullOrEmpty(s)) l.Add(s); } Clip(l); }
        void Clip(List<string> l)
        {
            HashSet<string> seen = new HashSet<string>(); List<string> u = new List<string>(); foreach (string s in l) if (seen.Add(s)) u.Add(s);
            if (u.Count == 0) { Host.Toast("Nothing to copy.", true); return; } try { Clipboard.SetText(string.Join("\r\n", u.ToArray())); Host.Toast(u.Count + " line(s) copied", false); } catch (Exception ex) { Host.Toast("clipboard: " + ex.Message, true); }
        }
        void OpenSelected()
        {
            List<string> urls = new List<string>(); foreach (object o in view.Targets) { Finding f = o as Finding; if (f != null && f.Url.Length > 0 && !urls.Contains(f.Url)) urls.Add(f.Url); }
            if (urls.Count == 0) { Host.Toast("Nothing selected.", true); return; }
            if (urls.Count > 6 && !Host.Confirm("Open advisories", "Open " + urls.Count + " browser tabs?")) return;
            foreach (string u in urls) Open(u);
        }
        static void Open(string url) { try { Process.Start(url); } catch { } }

        // ── dialogs ──
        void FeedsDialog()
        {
            if (cache == null) cache = OpenCache();
            using (Form f = new Form())
            {
                f.Text = "Feed cache"; f.BackColor = Theme.Panel; f.ForeColor = Theme.Ink; f.Font = Theme.UI; f.Width = Theme.S(700); f.Height = Theme.S(460); f.StartPosition = FormStartPosition.CenterParent; f.FormBorderStyle = FormBorderStyle.FixedDialog; f.MinimizeBox = false; f.MaximizeBox = false;
                ListBox lb = new ListBox(); lb.Dock = DockStyle.Fill; lb.BackColor = Theme.Panel2; lb.ForeColor = Theme.Ink; lb.Font = Theme.Mono; lb.BorderStyle = BorderStyle.None; lb.ItemHeight = Theme.S(22);
                Action fill = delegate { lb.Items.Clear(); try { foreach (string p in Directory.GetFiles(cache.Dir, "*.json")) { FileInfo fi = new FileInfo(p); lb.Items.Add(fi.LastWriteTime.ToString("yyyy-MM-dd HH:mm") + "   " + Fmt.Bytes(fi.Length).PadLeft(9) + "   " + fi.Name); } } catch { } if (lb.Items.Count == 0) lb.Items.Add("(empty - the first scan fills it)"); };
                fill();
                Label l = Theme.Lbl("Downloaded feeds are kept here so repeated scans are quick and an offline scan can still use the last copy:  " + cache.Dir, Theme.Dim, Theme.UISmall); l.Dock = DockStyle.Top; l.AutoSize = false; l.Height = Theme.S(44); l.Padding = new Padding(Theme.S(10), Theme.S(8), Theme.S(10), 0);
                FlowLayoutPanel bar = new FlowLayoutPanel(); bar.Dock = DockStyle.Bottom; bar.Height = Theme.S(46); bar.Padding = new Padding(Theme.S(10), Theme.S(8), Theme.S(10), 0); bar.BackColor = Theme.Panel;
                Button open = Theme.Btn("Open folder", false), clear = Theme.Danger("Delete all cached feeds"), close = Theme.Btn("Close", true); close.DialogResult = DialogResult.Cancel;
                open.Click += delegate { Dialogs.OpenInExplorer(cache.Dir); };
                clear.Click += delegate { if (Host.Confirm("Delete cached feeds", "Delete every cached feed file? The next scan downloads them again (the MSRC releases are about 10 MB each).")) { int n = cache.Clear(); fill(); Host.Toast(n + " file(s) deleted", false); } };
                bar.Controls.Add(open); bar.Controls.Add(clear); bar.Controls.Add(close);
                Panel body = new Panel(); body.Dock = DockStyle.Fill; body.Padding = new Padding(Theme.S(10), 0, Theme.S(10), 0); body.Controls.Add(lb);
                f.Controls.Add(body); f.Controls.Add(l); f.Controls.Add(bar); body.BringToFront(); f.CancelButton = close; f.ShowDialog(this);
            }
        }
        void ShowLog()
        {
            using (Form f = new Form())
            {
                f.Text = "Scan log"; f.BackColor = Theme.Panel; f.ForeColor = Theme.Ink; f.Font = Theme.UI; f.Width = Theme.S(820); f.Height = Theme.S(520); f.StartPosition = FormStartPosition.CenterParent; f.MinimizeBox = false;
                TextBox t = new TextBox(); t.Multiline = true; t.ReadOnly = true; t.Dock = DockStyle.Fill; t.BackColor = Theme.Panel2; t.ForeColor = Theme.Ink; t.Font = Theme.Mono; t.ScrollBars = ScrollBars.Both; t.WordWrap = false; t.BorderStyle = BorderStyle.FixedSingle;
                StringBuilder sb = new StringBuilder();
                if (scan == null || scan.Log.Count == 0) sb.AppendLine("No scan yet."); else { if (scan.Errors.Count > 0) { sb.AppendLine("PROBLEMS"); foreach (string e in scan.Errors) sb.AppendLine("  " + e); sb.AppendLine(); } sb.AppendLine("LOG"); foreach (string s in scan.LogSnapshot()) sb.AppendLine("  " + s); if (scan.Releases.Count > 0) sb.AppendLine().Append("MSRC releases checked: " + string.Join(", ", scan.Releases.ToArray())); }
                t.Text = sb.ToString();
                FlowLayoutPanel bar = new FlowLayoutPanel(); bar.Dock = DockStyle.Bottom; bar.Height = Theme.S(46); bar.FlowDirection = FlowDirection.RightToLeft; bar.Padding = new Padding(Theme.S(10), Theme.S(8), Theme.S(10), 0); bar.BackColor = Theme.Panel;
                Button close = Theme.Btn("Close", true), copy = Theme.Btn("Copy", false); close.DialogResult = DialogResult.Cancel; copy.Click += delegate { try { Clipboard.SetText(t.Text); } catch { } }; bar.Controls.Add(close); bar.Controls.Add(copy);
                Panel body = new Panel(); body.Dock = DockStyle.Fill; body.Padding = new Padding(Theme.S(10), Theme.S(10), Theme.S(10), 0); body.Controls.Add(t);
                f.Controls.Add(body); f.Controls.Add(bar); body.BringToFront(); f.CancelButton = close; f.ShowDialog(this);
            }
        }

        // ── self-test and screenshots ──
        /// <summary>Switches through every mode with a cell highlighted (the path that used to crash) and exercises the view in each.</summary>
        public override void Exercise(StringBuilder r)
        {
            foreach (string m in new string[] { "hotfixes", "software", "missing", "findings", "hotfixes", "findings" })
            {
                try { if (view.VisibleItems.Count > 0) view.SetCurrent(0, Math.Min(3, view.Cols.Count - 1)); view.SortBy(view.Cols[view.Cols.Count - 1].Key, false); SetMode(m); Application.DoEvents(); ExerciseView(view, r); }
                catch (Exception ex) { r.AppendLine("FAIL ui vuln/" + m + ": " + ex.GetType().Name + ": " + ex.Message); }
            }
        }
        public override void SelfTest(StringBuilder r)
        {
            if (r == null) { Demo(); return; }
            OsInfo os = Inventory.Os(); r.AppendLine((os.Build > 0 && os.Ubr > 0 ? "PASS" : "FAIL") + " vuln: OS " + os.Summary + " · " + Inventory.Reboot().Why);
            List<Software> sw = Inventory.Installed(); int mapped = 0; foreach (Software s in sw) if (s.Mapped) mapped++; r.AppendLine((sw.Count > 0 ? "PASS" : "FAIL") + " vuln: " + sw.Count + " installed programs, " + mapped + " in the product map");
            bool online = Http.Online(); r.AppendLine("INFO vuln: network " + (online ? "available" : "unavailable - feed tests skipped"));
            VulnScan s2 = NewScan(); s2.Months = 1; s2.NvdLimit = 3; s2.DoMsrc = online; s2.DoNvd = online; s2.DoKev = online; s2.DoEpss = online; scan = s2;
            Stopwatch sw2 = Stopwatch.StartNew(); s2.Run(); sw2.Stop(); Reload();
            int open = 0, wu = 0, msrc = 0, nvd = 0; foreach (Finding f in s2.FindingsSnapshot()) { if (f.Open) open++; if (f.Source == "Windows Update") wu++; else if (f.Source == "MSRC") msrc++; else nvd++; }
            r.AppendLine((s2.Errors.Count == 0 ? "PASS" : "WARN") + " vuln: scan in " + sw2.Elapsed.TotalSeconds.ToString("N0") + " s · " + s2.Hotfixes.Count + " hotfix rows, " + s2.KnownKbs.Count + " known KBs, " + s2.Missing.Count + " missing updates, " + s2.Findings.Count + " findings (" + open + " open: " + msrc + " MSRC, " + nvd + " NVD, " + wu + " WU)" + (s2.Errors.Count > 0 ? " · problems: " + string.Join(" / ", s2.Errors.ToArray()) : ""));
            int shown = 0; foreach (Finding f in s2.FindingsSnapshot()) { if (!f.Open || shown++ >= 6) continue; r.AppendLine("INFO   " + f.Cve + " " + f.SeverityNorm + " " + f.Status + " · " + f.Product + " · " + f.Fix + " · " + f.ExploitText + " · " + f.Evidence); }
            foreach (Software s in s2.SoftwareSnapshot()) if (s.Mapped && s.Cves >= 0) r.AppendLine("INFO   " + s.Name + " " + s.Version + " → " + s.Status);
        }
        void Demo()
        {
            VulnScan s = new VulnScan(); s.Os = new OsInfo(); s.Os.ProductName = "Windows 11 Pro"; s.Os.DisplayVersion = "25H2"; s.Os.Major = 10; s.Os.Build = 26200; s.Os.Ubr = 6584; s.Os.Arch = "x64"; s.Reboot = new RebootInfo(); s.Reboot.WindowsUpdate = true; s.FinishedAt = DateTime.Now;
            string host = s.Os.FullBuild;
            s.Findings.Add(F("CVE-2026-31234", "Critical", 9.8, "vulnerable", "MSRC", "Windows 11 Version 25H2 for x64-based Systems", host, "KB5066000 · build 10.0.26200.6900", "Windows TCP/IP Remote Code Execution Vulnerability", "build comparison: host " + host + " < fixed 10.0.26200.6900 (KB5066000) → not patched", "2026-Sep", true, true, 0.71));
            s.Findings.Add(F("CVE-2026-29871", "High", 7.8, "update available", "MSRC", "Windows 11 Version 25H2 for x64-based Systems", host, "KB5066000 · build 10.0.26200.6900 · offered by Windows Update as KB5066000", "Windows Kernel Elevation of Privilege Vulnerability", "build comparison: host " + host + " < fixed 10.0.26200.6900 (KB5066000) → not patched | Windows Update offers KB5066000 (security, downloaded)", "2026-Sep", false, true, 0.12));
            s.Findings.Add(F("CVE-2026-27101", "High", 8.8, "vulnerable", "NVD", "Google Chrome", "140.0.7339.80", "upgrade to 140.0.7339.128 or later", "Use after free in V8 in Google Chrome prior to 140.0.7339.128 allowed a remote attacker to exploit heap corruption via a crafted HTML page.", "installed 140.0.7339.80 vs google:chrome: ✓ < 140.0.7339.128", "2026-09", true, false, 0.44));
            s.Findings.Add(F("CVE-2026-30555", "High", 7.5, "reboot pending", "MSRC", "Windows 11 Version 25H2 for x64-based Systems", host, "KB5065999 · build 10.0.26200.6600", "Windows SMB Server Denial of Service Vulnerability", "build comparison: host " + host + " < fixed 10.0.26200.6600 (KB5065999) → not patched | KB5065999 is installed but the running build is still " + host + " · Windows Update RebootRequired", "2026-Aug", false, false, 0.03));
            s.Findings.Add(F("CVE-2026-22500", "Medium", 6.5, "vulnerable", "NVD", "7-Zip 24.08 (x64)", "24.08", "upgrade to 24.09 or later", "7-Zip before 24.09 mishandles a crafted 7z archive header, leading to an out-of-bounds read.", "installed 24.08 vs 7-zip:7-zip: ✓ < 24.09", "2026-07", false, false, 0.01));
            s.Findings.Add(F("CVE-2026-24000", "Medium", 5.5, "vulnerable", "MSRC", "Microsoft 365 Apps for Enterprise for 64-bit Systems", host, "KB5002800", "Microsoft Office Information Disclosure Vulnerability", "KB check: KB5002800 not installed and nothing installed supersedes it (microsoft 365 apps for enterprise)", "2026-Sep", false, false, 0.02));
            s.Findings.Add(F("CVE-2025-99999", "Low", 3.3, "unconfirmed", "NVD", "Wireshark 4.4.1", "4.4.1", "", "Wireshark dissector crash with a malformed capture file.", "NVD lists wireshark:wireshark with no version bounds; not verifiable against 4.4.1", "2025-12", false, false, null));
            s.Findings.Add(F("CVE-2026-21000", "Critical", 9.1, "patched", "MSRC", "Windows 11 Version 25H2 for x64-based Systems", host, "KB5064000 · build 10.0.26200.5000", "Windows LDAP Remote Code Execution Vulnerability", "build comparison: host " + host + " ≥ fixed 10.0.26200.5000 (KB5064000) → patched", "2026-Jul", false, false, null));
            MissingUpdate m1 = new MissingUpdate(); m1.Kb = "5066000"; m1.Title = "2026-09 Cumulative Update for Windows 11 Version 25H2 for x64-based Systems (KB5066000)"; m1.Severity = "Critical"; m1.Kind = "security"; m1.Cves.AddRange(new string[] { "CVE-2026-31234", "CVE-2026-29871", "CVE-2026-29872", "CVE-2026-29880" }); m1.Downloaded = true; m1.SizeBytes = 812345678; m1.Published = new DateTime(2026, 9, 9); m1.Reboot = "always"; m1.Categories = "Security Updates, Windows 11"; s.Missing.Add(m1);
            MissingUpdate m2 = new MissingUpdate(); m2.Kb = "2267602"; m2.Title = "Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.437.120.0)"; m2.Kind = "definitions"; m2.SizeBytes = 130000000; m2.Published = DateTime.Today; m2.Reboot = "no"; m2.Categories = "Definition Updates, Microsoft Defender Antivirus"; s.Missing.Add(m2);
            MissingUpdate m3 = new MissingUpdate(); m3.Title = "Intel Corporation - Display - 32.0.101.6881"; m3.Kind = "driver"; m3.SizeBytes = 1400000000; m3.Published = new DateTime(2026, 8, 20); m3.Reboot = "may ask"; m3.Categories = "Drivers"; s.Missing.Add(m3);
            s.Software.Add(SW("Google Chrome", "140.0.7339.80", "Google LLC", "google", "chrome", 1, "1 CVE(s) at 140.0.7339.80 (downloaded)")); s.Software.Add(SW("7-Zip 24.08 (x64)", "24.08", "Igor Pavlov", "7-zip", "7-zip", 1, "1 CVE(s) at 24.08 (cached 2026-09-14 20:10)")); s.Software.Add(SW("Mozilla Firefox (x64 en-US)", "143.0.1", "Mozilla", "mozilla", "firefox", 0, "no known CVEs at 143.0.1 (downloaded)"));
            s.Software.Add(SW("Git", "2.51.0", "The Git Development Community", "git-scm", "git", 0, "no known CVEs at 2.51.0 (downloaded)")); s.Software.Add(SW("Wireshark 4.4.1 x64", "4.4.1", "The Wireshark developer community", "wireshark", "wireshark", 0, "no known CVEs at 4.4.1 (downloaded)")); s.Software.Add(SW("Microsoft Visual Studio Code (User)", "1.104.0", "Microsoft Corporation", "microsoft", "visual_studio_code", 0, "no known CVEs at 1.104.0 (downloaded)"));
            s.Software.Add(SW("Microsoft 365 Apps for enterprise - en-us", "16.0.19127.20182", "Microsoft Corporation", null, null, -1, "not in the product map")); s.Software.Add(SW("Notion", "4.19.0", "Notion Labs, Inc.", null, null, -1, "not in the product map")); s.Software.Add(SW("Python 3.12.6 (64-bit)", "3.12.6150.0", "Python Software Foundation", null, null, -1, "not in the product map"));
            s.Hotfixes.Add(HF("5065999", "QFE", "Security Update", "KB5065999", "installed", new DateTime(2026, 8, 13))); s.Hotfixes.Add(HF("5064000", "CBS", "servicing package", "Package_for_RollupFix~31bf3856ad364e35~amd64~~26200.5000.1.11", "superseded", null)); s.Hotfixes.Add(HF("5065999", "WU history", "installation", "2026-08 Cumulative Update for Windows 11 Version 25H2 for x64-based Systems (KB5065999)", "succeeded", new DateTime(2026, 8, 13, 9, 12, 0))); s.Hotfixes.Add(HF("2267602", "WU history", "installation", "Security Intelligence Update for Microsoft Defender Antivirus - KB2267602 (Version 1.437.98.0)", "succeeded", DateTime.Today.AddDays(-1)));
            scan = s; if (mode != "findings") SetMode("findings"); else Reload(); status.Text = "NVD · google:chrome 140.0.7339.80";
            steps.Begin(VulnScan.StepLabels); steps.Set("Inventory", "done", "50 programs · 448 hotfix rows"); steps.Set("Windows Update", "done", "3 offered"); steps.Set("Microsoft CVEs", "done", "4 open · 623 patched"); steps.Set("Third-party (NVD)", "running", null); steps.Fraction = 0.45; steps.Say("NVD · google:chrome 140.0.7339.80 (product 5 of 12)");
        }
        static Finding F(string cve, string sev, double cvss, string status, string src, string product, string installed, string fix, string title, string ev, string rel, bool kev, bool exploited, double? epss)
        { Finding f = new Finding(); f.Cve = cve; f.Severity = sev; f.Cvss = cvss; f.Status = status; f.Source = src; f.Product = product; f.Installed = installed; f.Fix = fix; f.Title = title; f.Description = title; f.Evidence = ev; f.Release = rel; f.Kev = kev; f.Exploited = exploited; f.Epss = epss; f.Url = src == "NVD" ? "https://nvd.nist.gov/vuln/detail/" + cve : "https://msrc.microsoft.com/update-guide/vulnerability/" + cve; if (kev) f.KevDue = "2026-10-05"; return f; }
        static Software SW(string name, string ver, string pub, string vendor, string product, int cves, string status) { Software s = new Software(); s.Name = name; s.Version = ver; s.Publisher = pub; s.Vendor = vendor; s.Product = product; s.Cves = cves; s.Status = status; s.Scope = "machine"; s.InstallDate = "20260901"; return s; }
        static Hotfix HF(string kb, string src, string desc, string title, string result, DateTime? when) { Hotfix h = new Hotfix(); h.Kb = kb; h.Source = src; h.Description = desc; h.Title = title; h.Result = result; h.InstalledOn = when; return h; }
    }
}

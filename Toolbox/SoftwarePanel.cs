// Software Inventory: every installed program with its version, publisher and install date, and — after a
// CVE scan — which ones are vulnerable, at what severity, with the worst CVE and the fix. Reuses the NVD /
// KEV / EPSS engines from Vuln.cs. Advanced filtering via the shared column-header funnels, the rule bar,
// and dedicated vulnerable/severity/exploited/mapped filters.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace PSTools
{
    public class SoftwarePanel : ToolPanel
    {
        public override string Title { get { return Tools.Title(GetType().Name); } }
        public override string Blurb { get { return Tools.Blurb(GetType().Name); } }
        readonly DataView view; readonly SelectionBar sel = new SelectionBar(); readonly StepStrip steps = new StepStrip();
        readonly Button bRefresh, bScan, bCancel; readonly TextBox tKey; readonly CheckBox cKev, cEpss; readonly Label status = Theme.Lbl("", Theme.Dim, Theme.UISmall);
        readonly Stat sTotal = new Stat("programs"), sChecked = new Stat("checked"), sVuln = new Stat("vulnerable"), sCrit = new Stat("critical"), sHigh = new Stat("high"), sExpl = new Stat("exploited"), sMapped = new Stat("in CVE map");
        readonly ComboBox cSev; readonly CheckBox cVulnOnly, cExplOnly, cMappedOnly; readonly Label lSev;
        readonly List<Software> items = new List<Software>(); readonly Dictionary<Software, List<Finding>> vulns = new Dictionary<Software, List<Finding>>();
        FeedCache cache; Thread worker; volatile bool scanning, cancel; bool loaded;

        public SoftwarePanel()
        {
            BackColor = Theme.Panel;
            FlowLayoutPanel bar = Theme.Bar(46);
            bRefresh = Theme.Btn("Refresh list", false); bRefresh.Click += delegate { LoadList(); };
            bScan = Theme.Btn("Scan for CVEs", true); bScan.Click += delegate { Scan(null); }; bCancel = Theme.Btn("Cancel", false); bCancel.Enabled = false; bCancel.Click += delegate { cancel = true; Host.Toast("Stopping…", true); };
            Label lk = Theme.Lbl("NVD key", Theme.Dim, Theme.UI); tKey = Theme.Text("", 130); tKey.UseSystemPasswordChar = true; new ToolTip().SetToolTip(tKey, "Optional free NVD API key (nvd.nist.gov) — 50 requests per 30 s instead of 5, so the scan is far faster. Shared with Vulnerability Management.");
            cKev = Theme.Toggle("KEV", true); cEpss = Theme.Toggle("EPSS", true);
            foreach (Control c in new Control[] { bRefresh, bScan, bCancel, lk, tKey, cKev, cEpss, status }) bar.Controls.Add(c); status.Margin = new Padding(Theme.S(10), Theme.S(9), 0, 0);
            TableLayoutPanel strip = new TableLayoutPanel(); strip.Dock = DockStyle.Top; strip.Height = Theme.S(76); strip.BackColor = Theme.Panel; strip.Padding = new Padding(Theme.S(10), Theme.S(2), Theme.S(2), Theme.S(6)); strip.ColumnCount = 7; strip.RowCount = 1;
            foreach (Stat s in new Stat[] { sTotal, sChecked, sVuln, sCrit, sHigh, sExpl, sMapped }) { strip.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f / 7)); s.Dock = DockStyle.Fill; strip.Controls.Add(s); }
            view = NewView("software-inventory");
            view.Apply(Columns.Software());
            lSev = Theme.Lbl("severity", Theme.Dim, Theme.UI); cSev = Theme.Combo(96, "all", "critical", "high +", "medium +"); cVulnOnly = Theme.Toggle("vulnerable only", false); cExplOnly = Theme.Toggle("exploited only", false); cMappedOnly = Theme.Toggle("in CVE map only", false);
            foreach (Control c in new Control[] { lSev, cSev, cVulnOnly, cExplOnly, cMappedOnly }) view.Extra.Controls.Add(c);
            cSev.SelectedIndexChanged += delegate { view.Refilter(); }; cVulnOnly.CheckedChanged += delegate { view.Refilter(); }; cExplOnly.CheckedChanged += delegate { view.Refilter(); }; cMappedOnly.CheckedChanged += delegate { view.Refilter(); };
            view.Filter = FilterRow;
            view.SelectionChanged += delegate { sel.Update(view.SelectedCount, "program"); };
            view.Activated += delegate (object o) { Software s = (Software)o; if (s.WorstCve.Length > 0) Open("https://nvd.nist.gov/vuln/detail/" + s.WorstCve); else if (s.Mapped) Open("https://nvd.nist.gov/products/cpe/search/results?keyword=" + Uri.EscapeDataString(s.Vendor + " " + s.Product)); };
            sel.Add("Scan selected", true, delegate { List<Software> l = new List<Software>(); foreach (object o in view.Targets) l.Add((Software)o); Scan(l); });
            sel.Add("Copy CVE list", false, delegate { CopyCves(); });
            sel.Add("Copy names + versions", false, delegate { List<string> l = new List<string>(); foreach (object o in view.Targets) { Software s = (Software)o; l.Add(s.Name + "\t" + s.Version + "\t" + s.Publisher); } Clip(l); });
            sel.Add("Open on NVD", false, delegate { int k = 0; foreach (object o in view.Targets) { if (k++ >= 6) break; Software s = (Software)o; if (s.WorstCve.Length > 0) Open("https://nvd.nist.gov/vuln/detail/" + s.WorstCve); } });
            sel.Add("Export", false, delegate { view.Export(); });
            Controls.Add(view); Controls.Add(sel); Controls.Add(strip); Controls.Add(steps); Controls.Add(bar); view.BringToFront();
        }


        bool FilterRow(object o)
        {
            Software s = (Software)o;
            if (cMappedOnly.Checked && !s.Mapped) return false;
            if (cVulnOnly.Checked && !s.Vulnerable) return false;
            if (cExplOnly.Checked && !(s.Kev || s.Exploited)) return false;
            int want = Resolve.SevRank(cSev.SelectedIndex == 1 ? "Critical" : cSev.SelectedIndex == 2 ? "High" : cSev.SelectedIndex == 3 ? "Medium" : "");
            if (want > 0 && Resolve.SevRank(s.WorstSeverity) < want) return false;
            return true;
        }

        public override void OnShown()
        {
            if (loaded) return; loaded = true; tKey.Text = Host.Settings.Get("vuln.key", ""); cache = OpenCache();
            if (items.Count == 0) LoadList();
        }
        static FeedCache OpenCache()
        {
            string local = Path.Combine(Path.GetDirectoryName(Application.ExecutablePath), "cache");
            try { Directory.CreateDirectory(local); string probe = Path.Combine(local, ".write-test"); File.WriteAllText(probe, "ok"); File.Delete(probe); return new FeedCache(local); }
            catch { return new FeedCache(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PowerTower", "cache")); }
        }
        void LoadList()
        {
            try { items.Clear(); items.AddRange(Inventory.Installed()); vulns.Clear(); view.SetItems(Boxed(items), false); Cards(); status.Text = items.Count + " program(s) installed — Scan for CVEs to flag the vulnerable ones"; }
            catch (Exception ex) { Host.Error("Could not read installed software", ex.Message); }
        }
        void Ui(Action a) { try { Host.BeginInvoke(a); } catch { } }

        void Scan(List<Software> only)
        {
            if (scanning) { Host.Toast("A scan is already running.", true); return; }
            if (cache == null) cache = OpenCache();
            List<Software> targets = new List<Software>();
            foreach (Software s in (only ?? items)) { if (!s.Mapped) { if (only != null) s.Status = "not in the CVE product map"; continue; } if (Ver.Parse(s.Version) == null) { s.Status = "version '" + s.Version + "' is not comparable"; continue; } targets.Add(s); }
            if (targets.Count == 0) { Host.Toast(only != null ? "None of the selected programs is in the CVE product map." : "No mapped, comparable programs to scan.", true); return; }
            Host.Settings.Set("vuln.key", tKey.Text.Trim()); Host.Settings.Save();
            scanning = true; cancel = false; bScan.Enabled = false; bCancel.Enabled = true; steps.Begin(new string[] { "NVD lookups", "KEV", "EPSS" });
            string apiKey = tKey.Text.Trim(); bool doKev = cKev.Checked, doEpss = cEpss.Checked;
            worker = new Thread(delegate ()
            {
                try
                {
                    Ui(delegate { steps.Set("NVD lookups", "running", null); });
                    Dictionary<string, KevEntry> kev = new Dictionary<string, KevEntry>();
                    int done = 0;
                    foreach (Software s in targets)
                    {
                        if (cancel) break; string label = s.Vendor + ":" + s.Product + " " + s.Version;
                        Ui(delegate { status.Text = "NVD · " + label; steps.Say(label); steps.Fraction = (float)done / targets.Count; });
                        try
                        {
                            string note; List<CveRecord> recs = Nvd.ForProduct(s.Vendor, s.Product, s.Version, apiKey, cache, delegate (string m) { Ui(delegate { status.Text = m; }); }, out note);
                            List<Finding> fs = Resolve.ThirdParty(s, recs); List<Finding> vuln = new List<Finding>(); int unconf = 0;
                            foreach (Finding f in fs) { if (f.Status == "vulnerable") vuln.Add(f); else if (f.Status == "unconfirmed") unconf++; }
                            lock (vulns) vulns[s] = vuln;
                            s.Cves = vuln.Count; s.Unconfirmed = unconf; s.Status = vuln.Count == 0 ? (unconf > 0 ? unconf + " unconfirmed at " + s.Version + " (" + note + ")" : "no known CVEs at " + s.Version + " (" + note + ")") : vuln.Count + " CVE(s) at " + s.Version + " (" + note + ")";
                            Summarize(s, vuln);
                        }
                        catch (Exception ex) { s.Cves = -1; s.Status = "lookup failed: " + Short(ex.Message); }
                        done++; Ui(delegate { view.Invalidate2(); Cards(); });
                    }
                    Ui(delegate { steps.Set("NVD lookups", cancel ? "failed" : "done", done + " looked up"); steps.Fraction = -1; });
                    if (doKev && !cancel)
                    {
                        Ui(delegate { steps.Set("KEV", "running", null); status.Text = "CISA KEV…"; });
                        try { string note; kev = Kev.Load(cache, out note); int n = 0; lock (vulns) foreach (KeyValuePair<Software, List<Finding>> kv in vulns) foreach (Finding f in kv.Value) { KevEntry e; if (kev.TryGetValue(f.Cve, out e)) { f.Kev = true; f.Ransomware = e.Ransomware; n++; } } int nn = n; Ui(delegate { steps.Set("KEV", "done", nn + " exploited"); }); }
                        catch (Exception ex) { Ui(delegate { steps.Set("KEV", "failed", Short(ex.Message)); }); }
                    }
                    if (doEpss && !cancel)
                    {
                        Ui(delegate { steps.Set("EPSS", "running", null); status.Text = "EPSS…"; });
                        try { List<string> ids = new List<string>(); lock (vulns) foreach (KeyValuePair<Software, List<Finding>> kv in vulns) foreach (Finding f in kv.Value) ids.Add(f.Cve); if (ids.Count > 0) { Dictionary<string, double> sc = Epss.Scores(ids, cache, delegate (string m) { Ui(delegate { status.Text = m; }); }); lock (vulns) foreach (KeyValuePair<Software, List<Finding>> kv in vulns) foreach (Finding f in kv.Value) { double v; if (sc.TryGetValue(f.Cve, out v)) f.Epss = v; } } Ui(delegate { steps.Set("EPSS", "done", null); }); }
                        catch (Exception ex) { Ui(delegate { steps.Set("EPSS", "failed", Short(ex.Message)); }); }
                    }
                    // re-summarize now that KEV/EPSS are known (worst is scored with them)
                    lock (vulns) foreach (KeyValuePair<Software, List<Finding>> kv in vulns) Summarize(kv.Key, kv.Value);
                }
                catch (Exception ex) { Ui(delegate { Host.Toast("scan: " + ex.Message, true); }); }
                finally { Ui(delegate { scanning = false; bScan.Enabled = true; bCancel.Enabled = false; view.Invalidate2(); Cards(); int v = 0; foreach (Software s in items) if (s.Vulnerable) v++; steps.End((cancel ? "cancelled · " : "done · ") + v + " vulnerable of " + targets.Count + " scanned"); status.Text = "done · " + v + " vulnerable program(s)"; }); }
            });
            worker.IsBackground = true; worker.Start();
        }
        static void Summarize(Software s, List<Finding> vuln)
        {
            s.WorstSeverity = ""; s.WorstCve = ""; s.WorstCvss = null; s.Fix = ""; s.WorstEpss = null; s.Kev = false; s.Exploited = false;
            Finding worst = null; foreach (Finding f in vuln) { if (f.Kev) s.Kev = true; if (f.Exploited) s.Exploited = true; if (worst == null || f.SortScore > worst.SortScore) worst = f; }
            if (worst != null) { s.WorstSeverity = worst.SeverityNorm; s.WorstCve = worst.Cve; s.WorstCvss = worst.Cvss; s.Fix = worst.Fix; s.WorstEpss = worst.Epss; }
        }
        static string Short(string s) { s = (s ?? "").Replace("\r", " ").Replace("\n", " "); return s.Length > 60 ? s.Substring(0, 60) + "…" : s; }

        void Cards()
        {
            int total = items.Count, mapped = 0, checkedN = 0, vuln = 0, crit = 0, high = 0, expl = 0;
            foreach (Software s in items) { if (s.Mapped) mapped++; if (s.Cves >= 0) checkedN++; if (s.Vulnerable) { vuln++; if (s.WorstSeverity == "Critical") crit++; else if (s.WorstSeverity == "High") high++; if (s.Kev || s.Exploited) expl++; } }
            sTotal.Set(total > 0 ? total.ToString() : "—", "installed", Theme.Ink);
            sChecked.Set(checkedN > 0 ? checkedN.ToString() : "—", "for CVEs", Theme.Dim);
            sVuln.Set(checkedN > 0 ? vuln.ToString() : "—", "programs", vuln > 0 ? Theme.Rose : checkedN > 0 ? Theme.Green : Theme.Ink);
            sCrit.Set(checkedN > 0 ? crit.ToString() : "—", "worst = critical", crit > 0 ? Theme.Rose : Theme.Ink);
            sHigh.Set(checkedN > 0 ? high.ToString() : "—", "worst = high", high > 0 ? Theme.Amber : Theme.Ink);
            sExpl.Set(checkedN > 0 ? expl.ToString() : "—", "known exploited", expl > 0 ? Theme.Rose : Theme.Ink);
            sMapped.Set(total > 0 ? mapped.ToString() : "—", "CVE-mappable", Theme.Ink);
        }
        void CopyCves()
        {
            HashSet<string> set = new HashSet<string>(); foreach (object o in view.Targets) { Software s = (Software)o; List<Finding> f; lock (vulns) if (vulns.TryGetValue(s, out f)) foreach (Finding x in f) set.Add(x.Cve); else if (s.WorstCve.Length > 0) set.Add(s.WorstCve); }
            List<string> l = new List<string>(set); l.Sort(); Clip(l);
        }
        void Clip(List<string> l) { if (l.Count == 0) { Host.Toast("Nothing to copy.", true); return; } try { Clipboard.SetText(string.Join("\r\n", l.ToArray())); Host.Toast(l.Count + " line(s) copied", false); } catch (Exception ex) { Host.Toast("clipboard: " + ex.Message, true); } }
        static void Open(string url) { try { Process.Start(url); } catch { } }

        public override void SelfTest(StringBuilder r)
        {
            if (r == null) { Demo(); return; }
            cache = OpenCache(); LoadList();
            int mapped = 0; foreach (Software s in items) if (s.Mapped) mapped++;
            r.AppendLine((items.Count > 5 ? "PASS" : "FAIL") + " software inventory: " + items.Count + " programs, " + mapped + " in the CVE product map");
            if (Http.Online())
            {
                List<Software> two = new List<Software>(); foreach (Software s in items) { if (s.Mapped && Ver.Parse(s.Version) != null) { two.Add(s); if (two.Count >= 2) break; } }
                foreach (Software s in two) { try { string note; List<CveRecord> recs = Nvd.ForProduct(s.Vendor, s.Product, s.Version, tKey.Text.Trim(), cache, delegate (string m) { }, out note); List<Finding> fs = Resolve.ThirdParty(s, recs); List<Finding> v = new List<Finding>(); foreach (Finding f in fs) if (f.Status == "vulnerable") v.Add(f); s.Cves = v.Count; Summarize(s, v); r.AppendLine("INFO   " + s.Name + " " + s.Version + " → " + s.Cves + " CVE(s)" + (s.WorstCve.Length > 0 ? ", worst " + s.WorstCve + " " + s.WorstSeverity : "")); } catch (Exception ex) { r.AppendLine("INFO   " + s.Name + ": " + Short(ex.Message)); } }
                r.AppendLine((two.Count > 0 ? "PASS" : "INFO") + " software inventory: scanned " + two.Count + " mapped product(s) against the NVD");
                view.Invalidate2(); Cards();
            }
            else r.AppendLine("INFO software inventory: offline, CVE scan skipped");
        }
        void Demo()
        {
            items.Clear();
            items.Add(SW("Google Chrome", "140.0.7339.80", "Google LLC", "google", "chrome", 3, "High", "CVE-2026-27101", 8.8, "upgrade to 140.0.7339.128 or later", true, 0.44));
            items.Add(SW("7-Zip 24.08 (x64)", "24.08", "Igor Pavlov", "7-zip", "7-zip", 1, "Medium", "CVE-2026-22500", 6.5, "upgrade to 24.09 or later", false, 0.01));
            items.Add(SW("Mozilla Firefox (x64 en-US)", "143.0.1", "Mozilla", "mozilla", "firefox", 0, "", "", null, "", false, null));
            items.Add(SW("OpenSSL 3.0.11", "3.0.11", "OpenSSL Project", "openssl", "openssl", 2, "Critical", "CVE-2026-30111", 9.8, "upgrade to 3.0.15 or later", true, 0.71));
            items.Add(SW("Git", "2.51.0", "The Git Development Community", "git-scm", "git", 0, "", "", null, "", false, null));
            items.Add(SW("Wireshark 4.4.1 x64", "4.4.1", "The Wireshark developer community", "wireshark", "wireshark", 0, "", "", null, "", false, null));
            items.Add(SW("Microsoft Visual Studio Code (User)", "1.104.0", "Microsoft Corporation", "microsoft", "visual_studio_code", 0, "", "", null, "", false, null));
            items.Add(SW("Notion", "4.19.0", "Notion Labs, Inc.", null, null, -1, "", "", null, "", false, null));
            items.Add(SW("Python 3.12.6 (64-bit)", "3.12.6150.0", "Python Software Foundation", null, null, -1, "", "", null, "", false, null));
            items.Add(SW("NordVPN", "7.30.1.0", "Nord Security", "nordvpn", "nordvpn", 0, "", "", null, "", false, null));
            view.SetItems(Boxed(items), false); Cards(); status.Text = "done · 3 vulnerable program(s)";
        }
        static Software SW(string name, string ver, string pub, string vendor, string product, int cves, string sev, string worst, double? cvss, string fix, bool kev, double? epss)
        { Software s = new Software(); s.Name = name; s.Version = ver; s.Publisher = pub; s.Vendor = vendor; s.Product = product; s.Cves = cves; s.WorstSeverity = sev; s.WorstCve = worst; s.WorstCvss = cvss; s.Fix = fix; s.Kev = kev; s.WorstEpss = epss; s.Scope = "machine"; s.InstallDate = "20260901"; s.Status = cves < 0 ? "not in the CVE product map" : cves == 0 ? "no known CVEs at " + ver : cves + " CVE(s) at " + ver; return s; }
    }
}

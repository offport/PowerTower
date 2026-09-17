// Security Checklist panel over Checklist.cs. Runs the pass/fail hardening review, shows each check as a
// row grouped by category, scores it, and exports the report as Markdown, JSON or PDF.
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
    public class ChecklistPanel : ToolPanel
    {
        public override string Title { get { return "Security Checklist"; } }
        public override string Blurb { get { return "A pass or fail review of the most common endpoint audit items: default and blank-password accounts, disk encryption, antivirus and EDR products with their state, remote-access and VPN tools, USB control and the firewall. Each check shows its evidence; export the whole report as Markdown, JSON or PDF."; } }
        public override bool NeedsAdmin { get { return true; } }
        readonly DataView view; readonly SelectionBar sel = new SelectionBar(); readonly StepStrip steps = new StepStrip();
        readonly Button bRun, bCancel, bActive, bMd, bJson, bPdf, bLog; readonly ComboBox cCat, cStatus; readonly Label lCat, lStatus, status = Theme.Lbl("", Theme.Dim, Theme.UISmall); bool activeRunning;
        readonly Stat sScore = new Stat("score"), sFail = new Stat("fail"), sReview = new Stat("review"), sPass = new Stat("pass"), sNa = new Stat("not checked"), sCats = new Stat("categories"), sElev = new Stat("elevated");
        ChecklistScan scan; bool loaded;

        public ChecklistPanel()
        {
            BackColor = Theme.Panel;
            FlowLayoutPanel bar = Theme.Bar(46);
            bRun = Theme.Btn("Run checklist", true); bRun.Click += delegate { Run(); }; bCancel = Theme.Btn("Cancel", false); bCancel.Enabled = false; bCancel.Click += delegate { if (scan != null) { scan.Cancel = true; Host.Toast("Stopping…", true); } };
            bMd = Theme.Btn("Save Markdown…", false); bJson = Theme.Btn("Save JSON…", false); bPdf = Theme.Btn("Save PDF…", false); bLog = Theme.Btn("Log…", false);
            bActive = Theme.Btn("Active tests…", false); bActive.Click += delegate { RunActive(); }; new ToolTip().SetToolTip(bActive, "Run the two active tests: drop the EICAR anti-malware test file to check detection, and try running an unsigned program from each writable folder. Your antivirus and any application-control policy will react on purpose.");
            bMd.Click += delegate { Save("md"); }; bJson.Click += delegate { Save("json"); }; bPdf.Click += delegate { Save("pdf"); }; bLog.Click += delegate { ShowLog(); };
            foreach (Button b in new Button[] { bMd, bJson, bPdf }) b.Enabled = false;
            Panel gap = new Panel(); gap.Width = Theme.S(14); gap.Height = 1;
            foreach (Control c in new Control[] { bRun, bCancel, bActive, gap, bMd, bJson, bPdf, bLog, status }) bar.Controls.Add(c); status.Margin = new Padding(Theme.S(10), Theme.S(9), 0, 0);
            TableLayoutPanel strip = new TableLayoutPanel(); strip.Dock = DockStyle.Top; strip.Height = Theme.S(76); strip.BackColor = Theme.Panel; strip.Padding = new Padding(Theme.S(10), Theme.S(2), Theme.S(2), Theme.S(6)); strip.ColumnCount = 7; strip.RowCount = 1;
            foreach (Stat s in new Stat[] { sScore, sFail, sReview, sPass, sNa, sCats, sElev }) { strip.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, s == sScore ? 18 : 13.6f)); s.Dock = DockStyle.Fill; strip.Controls.Add(s); }
            view = NewView("security-checklist");
            view.SetColumns(Cols());
            view.RowColor = delegate (object o) { string r = ((CheckItem)o).Status; return r == "fail" ? Theme.Rose : r == "warn" ? Theme.Amber : Theme.Ink; };
            view.TreePath = delegate (object o) { CheckItem i = (CheckItem)o; return new string[] { i.Category, i.Name }; };
            lCat = Theme.Lbl("category", Theme.Dim, Theme.UI); cCat = Theme.Combo(230, "all categories"); lStatus = Theme.Lbl("show", Theme.Dim, Theme.UI); cStatus = Theme.Combo(150, "everything", "failures & review", "fail only", "review only", "pass only", "info / N/A");
            foreach (Control c in new Control[] { lCat, cCat, lStatus, cStatus }) view.Extra.Controls.Add(c);
            cCat.SelectedIndexChanged += delegate { view.Refilter(); }; cStatus.SelectedIndexChanged += delegate { view.Refilter(); };
            view.Filter = delegate (object o) { CheckItem i = (CheckItem)o; if (cCat.SelectedIndex > 0 && i.Category != (string)cCat.SelectedItem) return false; switch (cStatus.SelectedIndex) { case 1: if (i.Status != "fail" && i.Status != "warn") return false; break; case 2: if (i.Status != "fail") return false; break; case 3: if (i.Status != "warn") return false; break; case 4: if (i.Status != "pass") return false; break; case 5: if (i.Status != "info" && i.Status != "na") return false; break; } return true; };
            view.SelectionChanged += delegate { sel.Update(view.SelectedCount, "check"); };
            sel.Add("Copy as text", true, delegate { CopyText(); }); sel.Add("Export selected", false, delegate { view.Export(); }); sel.Add("Clear selection", false, delegate { view.ClearSelection(); });
            Controls.Add(view); Controls.Add(sel); Controls.Add(strip); Controls.Add(steps); Controls.Add(bar); view.BringToFront();
        }

        List<Col> Cols()
        {
            List<Col> c = new List<Col>();
            c.Add(new Col("cat", "Category", 200, delegate (object o) { return ((CheckItem)o).Category; }).Colour(delegate (object o) { return Theme.Dim; }));
            c.Add(new Col("name", "Check", 320, delegate (object o) { return ((CheckItem)o).Name; }));
            c.Add(new Col("res", "Result", 80, delegate (object o) { return Rank(((CheckItem)o).Status); }).Num(delegate (object o) { return ((CheckItem)o).StatusText; }).Colour(delegate (object o) { return StatusColor(((CheckItem)o).Status); }));
            c.Add(new Col("detail", "Detail", 420, delegate (object o) { return ((CheckItem)o).Detail; }));
            c.Add(new Col("ev", "Evidence", 360, delegate (object o) { return ((CheckItem)o).Evidence; }).Colour(delegate (object o) { return Theme.Faint; }));
            c.Add(new Col("q", "Question", 460, delegate (object o) { return ((CheckItem)o).Question; }).Colour(delegate (object o) { return Theme.Dim; }));
            return c;
        }
        static int Rank(string s) { return s == "fail" ? 0 : s == "warn" ? 1 : s == "na" ? 2 : s == "info" ? 3 : 4; }
        static Color StatusColor(string s) { return s == "pass" ? Theme.Green : s == "fail" ? Theme.Rose : s == "warn" ? Theme.Amber : s == "na" ? Theme.Faint : Theme.Dim; }

        public override void OnShown() { if (loaded) return; loaded = true; scan = new ChecklistScan(); scan.Report.Elevated = Host.IsElevated; try { scan.Report.Os = Inventory.Os().Summary; } catch { } Cards(); status.Text = "not run yet · Run checklist to review this machine"; }

        void Ui(Action a) { try { Host.BeginInvoke(a); } catch { } }
        void RunActive()
        {
            if ((scan != null && scan.Running) || activeRunning) { Host.Toast("Wait for the current run to finish.", true); return; }
            if (!Host.Confirm("Run active tests", "Two checks:\n\n• EICAR anti-malware test — writes the harmless EICAR standard test file to your temp folder and checks that real-time antivirus removes it. Your antivirus WILL alert on that one file and quarantine it; that is the pass. Nothing else is touched.\n\n• Application control — reads the AppLocker / SRP / WDAC / SmartScreen policy from the registry. It does not run or drop anything.\n\nContinue?")) return;
            if (scan == null || scan.Report.Items.Count == 0) { scan = new ChecklistScan(); scan.Report.Elevated = Host.IsElevated; try { scan.Report.Os = Inventory.Os().Summary; } catch { } }
            ChecklistScan s = scan; activeRunning = true; bActive.Enabled = false; bRun.Enabled = false; steps.Begin(new string[] { "EICAR", "App control" }); status.Text = "running active tests…";
            Thread t = new Thread(delegate ()
            {
                try
                {
                    Ui(delegate { steps.Set("EICAR", "running", null); });
                    CheckItem e = ActiveTests.Eicar();
                    Ui(delegate { s.Report.Items.Add(e); steps.Set("EICAR", e.Status == "pass" ? "done" : "failed", e.Status == "pass" ? "detected" : "not detected"); Reload(); FillCats(); });
                    Ui(delegate { steps.Set("App control", "running", null); });
                    List<CheckItem> ep = ActiveTests.AppControl(delegate (string m) { Ui(delegate { status.Text = m; steps.Say(m); }); });
                    Ui(delegate { foreach (CheckItem c in ep) s.Report.Items.Add(c); steps.Set("App control", "done", ep.Count + " check(s)"); Reload(); FillCats(); });
                }
                catch (Exception ex) { Ui(delegate { Host.Toast("active tests: " + ex.Message, true); }); }
                finally { Ui(delegate { activeRunning = false; bActive.Enabled = true; bRun.Enabled = true; foreach (Button b in new Button[] { bMd, bJson, bPdf }) b.Enabled = true; steps.End("active tests done"); Host.Toast("Active tests done — see the Active Tests category", false); }); }
            });
            t.IsBackground = true; t.Start();
        }
        void Run()
        {
            if (scan != null && scan.Running) { Host.Toast("A checklist run is already going.", true); return; }
            scan = new ChecklistScan(); ChecklistScan s = scan;
            s.Progress += delegate (string m) { Ui(delegate { status.Text = m; if (scan == s) steps.Say(m); }); };
            s.Step += delegate (string label, string state, string note) { Ui(delegate { if (scan == s) steps.Set(label, state, note); }); };
            s.Phase += delegate { Ui(delegate { if (scan == s) Reload(); }); };
            s.Finished += delegate { Ui(delegate { if (scan != s) return; bRun.Enabled = true; bCancel.Enabled = false; foreach (Button b in new Button[] { bMd, bJson, bPdf }) b.Enabled = true; Reload(); FillCats(); steps.End((s.Cancel ? "cancelled · " : "finished · ") + "score " + s.Report.Score + "/100 · " + s.Report.Fail + " fail · " + s.Report.Warn + " review"); Host.Toast("Score " + s.Report.Score + "/100 · " + s.Report.Fail + " fail, " + s.Report.Warn + " to review", s.Report.Fail > 0); }); };
            bRun.Enabled = false; bCancel.Enabled = true; foreach (Button b in new Button[] { bMd, bJson, bPdf }) b.Enabled = false; status.Text = "starting…"; view.SetItems(new object[0], false); steps.Begin(ChecklistScan.StepLabels);
            if (!Host.IsElevated) Host.Toast("Running without administrator rights: BitLocker and some checks will report N/A.", true);
            s.RunInBackground();
        }
        void Reload() { if (scan == null) return; List<object> l = new List<object>(); foreach (CheckItem i in scan.Snapshot()) l.Add(i); view.SetItems(l, true); Cards(); }
        void FillCats() { string cur = cCat.SelectedItem as string; cCat.Items.Clear(); cCat.Items.Add("all categories"); if (scan != null) foreach (string c in scan.Report.Categories()) cCat.Items.Add(c); int i = cur == null ? 0 : cCat.Items.IndexOf(cur); cCat.SelectedIndex = i < 0 ? 0 : i; }
        void Cards()
        {
            CheckReport r = scan != null ? scan.Report : null; bool ran = scan != null && scan.FinishedAt != DateTime.MinValue;
            int score = r != null ? r.Score : 0;
            sScore.Set(ran || (r != null && r.Items.Count > 0) ? score + "/100" : "—", "hardening score", score >= 80 ? Theme.Green : score >= 50 ? Theme.Amber : (ran ? Theme.Rose : Theme.Ink));
            sFail.Set(ran ? (r.Fail).ToString() : "—", "must fix", r != null && r.Fail > 0 ? Theme.Rose : ran ? Theme.Green : Theme.Ink);
            sReview.Set(ran ? (r.Warn).ToString() : "—", "worth a look", r != null && r.Warn > 0 ? Theme.Amber : ran ? Theme.Green : Theme.Ink);
            sPass.Set(ran ? (r.Pass).ToString() : "—", "passing", Theme.Green);
            sNa.Set(ran ? (r.Count("na")).ToString() : "—", "needs rights/manual", Theme.Dim);
            sCats.Set(r != null && r.Items.Count > 0 ? r.Categories().Count.ToString() : "—", "areas", Theme.Ink);
            sElev.Set(r == null ? "—" : r.Elevated ? "yes" : "no", r != null && !r.Elevated ? "some checks limited" : "full access", r != null && r.Elevated ? Theme.Green : Theme.Amber);
        }

        void Save(string fmt)
        {
            if (scan == null || scan.Report.Items.Count == 0) { Host.Toast("Run the checklist first.", true); return; }
            string filter = fmt == "md" ? "Markdown (*.md)|*.md" : fmt == "json" ? "JSON (*.json)|*.json" : "PDF (*.pdf)|*.pdf";
            using (SaveFileDialog d = new SaveFileDialog())
            {
                d.Filter = filter + "|All files|*.*"; d.FileName = scan.Report.FileStem + "." + fmt; d.Title = "Save the checklist as " + fmt.ToUpperInvariant();
                if (d.ShowDialog(this) != DialogResult.OK) return;
                try
                {
                    if (fmt == "md") File.WriteAllText(d.FileName, scan.Report.ToMarkdown(), new UTF8Encoding(true));
                    else if (fmt == "json") File.WriteAllText(d.FileName, scan.Report.ToJson(), new UTF8Encoding(false));
                    else scan.Report.SavePdf(d.FileName);
                    Host.Toast("Saved " + Path.GetFileName(d.FileName), false);
                    if (Host.Confirm("Report saved", "Saved to:\n" + d.FileName + "\n\nOpen it now?")) { try { Process.Start(d.FileName); } catch { Dialogs.OpenInExplorer(d.FileName); } }
                }
                catch (Exception ex) { Host.Error("Save failed", ex.Message); }
            }
        }
        void CopyText()
        {
            List<string> l = new List<string>(); foreach (object o in view.Targets) { CheckItem i = (CheckItem)o; l.Add(i.StatusText + "\t" + i.Category + "\t" + i.Name + "\t" + i.Detail + (i.Evidence.Length > 0 ? "\t" + i.Evidence : "")); }
            if (l.Count == 0) { Host.Toast("Nothing selected.", true); return; } try { Clipboard.SetText(string.Join("\r\n", l.ToArray())); Host.Toast(l.Count + " check(s) copied", false); } catch (Exception ex) { Host.Toast("clipboard: " + ex.Message, true); }
        }
        void ShowLog()
        {
            using (Form f = new Form())
            {
                f.Text = "Checklist log"; f.BackColor = Theme.Panel; f.ForeColor = Theme.Ink; f.Font = Theme.UI; f.Width = Theme.S(760); f.Height = Theme.S(480); f.StartPosition = FormStartPosition.CenterParent; f.MinimizeBox = false;
                TextBox t = new TextBox(); t.Multiline = true; t.ReadOnly = true; t.Dock = DockStyle.Fill; t.BackColor = Theme.Panel2; t.ForeColor = Theme.Ink; t.Font = Theme.Mono; t.ScrollBars = ScrollBars.Both; t.WordWrap = false; t.BorderStyle = BorderStyle.FixedSingle;
                StringBuilder sb = new StringBuilder(); if (scan == null || scan.Log.Count == 0) sb.AppendLine("No run yet."); else { if (scan.Errors.Count > 0) { sb.AppendLine("LIMITED / UNAVAILABLE"); foreach (string e in scan.Errors) sb.AppendLine("  " + e); sb.AppendLine(); } sb.AppendLine("LOG"); foreach (string s in scan.LogSnapshot()) sb.AppendLine("  " + s); } t.Text = sb.ToString();
                FlowLayoutPanel bbar = new FlowLayoutPanel(); bbar.Dock = DockStyle.Bottom; bbar.Height = Theme.S(46); bbar.FlowDirection = FlowDirection.RightToLeft; bbar.Padding = new Padding(Theme.S(10), Theme.S(8), Theme.S(10), 0); bbar.BackColor = Theme.Panel;
                Button close = Theme.Btn("Close", true); close.DialogResult = DialogResult.Cancel; bbar.Controls.Add(close);
                Panel body = new Panel(); body.Dock = DockStyle.Fill; body.Padding = new Padding(Theme.S(10), Theme.S(10), Theme.S(10), 0); body.Controls.Add(t);
                f.Controls.Add(body); f.Controls.Add(bbar); body.BringToFront(); f.CancelButton = close; f.ShowDialog(this);
            }
        }

        public override void SelfTest(StringBuilder r)
        {
            if (r == null) { Demo(); return; }
            ChecklistScan s = new ChecklistScan(); scan = s; Stopwatch sw = Stopwatch.StartNew(); s.Run(); sw.Stop(); Reload(); FillCats();
            r.AppendLine((s.Report.Items.Count >= 10 && s.Report.Categories().Count >= 6 ? "PASS" : "FAIL") + " checklist: " + s.Report.Items.Count + " checks in " + s.Report.Categories().Count + " categories, score " + s.Report.Score + "/100 (" + s.Report.Pass + " pass, " + s.Report.Fail + " fail, " + s.Report.Warn + " review) in " + sw.Elapsed.TotalSeconds.ToString("N1") + " s");
            foreach (CheckItem i in s.Report.Items) if (i.Status == "fail" || i.Status == "warn") r.AppendLine("INFO   [" + i.Status + "] " + i.Category + " · " + i.Name + ": " + i.Detail);
            try { object doc = Json.Parse(s.Report.ToJson()); int n = Json.Arr(Json.Get(doc, "checks")).Count; r.AppendLine((n == s.Report.Items.Count ? "PASS" : "FAIL") + " checklist: JSON re-parses with " + n + " checks · Markdown " + s.Report.ToMarkdown().Length + " B"); string tmp = Path.Combine(Path.GetTempPath(), "pstools-checklist.pdf"); s.Report.SavePdf(tmp); byte[] b = File.ReadAllBytes(tmp); File.Delete(tmp); r.AppendLine((b.Length > 800 && b[0] == (byte)'%' ? "PASS" : "FAIL") + " checklist: PDF " + b.Length + " B"); } catch (Exception ex) { r.AppendLine("FAIL checklist: report writers: " + ex.Message); }
        }
        void Demo()
        {
            ChecklistScan s = new ChecklistScan(); CheckReport r = s.Report; r.Os = "Microsoft Windows 11 Home 10.0.26200"; r.Elevated = true;
            Action<string, string, string, string, string, string> A = delegate (string cat, string name, string q, string st, string det, string ev) { r.Items.Add(new CheckItem(cat, name, q, st, det, ev)); };
            A("Accounts & Credentials", "Administrator without a password", "Is there an admin account with no password required?", "pass", "no enabled admin account allows a blank password", "");
            A("Accounts & Credentials", "Accounts with no password required", "Do any enabled accounts allow a blank password?", "warn", "1 account does not require a password", "kiosk");
            A("Accounts & Credentials", "Built-in Administrator account", "Is the built-in Administrator account disabled?", "pass", "disabled", "");
            A("Accounts & Credentials", "Guest account", "Is the Guest account disabled?", "pass", "disabled", "");
            A("Accounts & Credentials", "Stored auto-logon password", "Is a plaintext logon password stored in the registry?", "pass", "no stored logon password", "");
            A("Accounts & Credentials", "Default / manufacturer credentials", "Have default administrator and vendor credentials been changed on every endpoint?", "info", "cannot be verified from software alone — checks the local indicators above", "");
            A("Disk Encryption", "Disk encryption (BitLocker)", "Is the disk encrypted?", "warn", "1 of 2 volume(s) not encrypted", "unprotected: D:");
            A("Antivirus & Security Products", "Antivirus available and enabled", "Is antivirus present and turned on?", "pass", "1 of 1 registered antivirus product(s) enabled", "");
            A("Antivirus & Security Products", "Microsoft Defender real-time protection", "Is real-time antivirus protection on?", "pass", "enabled", "running mode: Normal");
            A("Antivirus & Security Products", "Registered antivirus: Windows Defender", "Which security products are installed and enabled?", "info", "enabled · up to date", "Security Center state 0x61100");
            A("Antivirus & Security Products", "Endpoint detection & response (EDR)", "Is an EDR or monitoring agent present?", "info", "Sysmon", "matched by service or process name");
            A("Remote Access", "Remote Desktop (RDP)", "Is inbound Remote Desktop disabled?", "pass", "disabled", "fDenyTSConnections=1");
            A("Remote Access", "Remote-access tools", "Are unauthorized remote-access tools installed?", "warn", "1 tool(s): TeamViewer", "installed, or running as a service/process");
            A("VPN Tools", "VPN clients", "Which VPN clients are present?", "info", "2 client(s): NordVPN, Tailscale", "installed, or running as a service/process");
            A("Peripheral & USB Control", "USB mass storage", "Are USB ports and external storage controlled to prevent data theft and malware?", "warn", "USB mass storage is allowed", "USBSTOR Start=3");
            A("Firewall & Updates", "Windows Firewall", "Is the firewall on for every profile?", "fail", "3 profile(s) off", "off: Domain, Private, Public");
            A("Firewall & Updates", "Pending reboot", "Is the machine free of a pending reboot?", "warn", "a reboot is pending — updates may not be fully applied", "PendingFileRenameOperations");
            s.FinishedAt = DateTime.Now; scan = s; Reload(); FillCats(); foreach (Button b in new Button[] { bMd, bJson, bPdf }) b.Enabled = true;
            steps.Begin(ChecklistScan.StepLabels); foreach (string l in ChecklistScan.StepLabels) steps.Set(l, "done", null); steps.End("finished · score " + r.Score + "/100 · " + r.Fail + " fail · " + r.Warn + " review");
            status.Text = "done · score " + r.Score + "/100";
        }
    }
}

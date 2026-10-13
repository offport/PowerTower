// 1 · System Recon & Audit: the panel over Recon.cs. Runs the read-only audit, shows every fact as a
// row (grouped by section in the tree), flags risks, and downloads the whole report as Markdown, JSON
// or PDF. The first tool in the sidebar.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Text;
using System.Windows.Forms;

namespace PSTools
{
    public class ReconPanel : ToolPanel
    {
        public override string Title { get { return Tools.Title(GetType().Name); } }
        public override string Blurb { get { return Tools.Blurb(GetType().Name); } }
        public override bool NeedsAdmin { get { return Tools.Admin(GetType().Name); } }
        readonly DataView view; readonly SelectionBar sel = new SelectionBar();
        readonly Button bRun, bCancel, bMd, bJson, bPdf, bLog; readonly CheckBox cEvents, cRiskOnly; readonly ComboBox cSection; readonly Label lSection, status = Theme.Lbl("", Theme.Dim, Theme.UISmall);
        readonly Stat sOs = new Stat("OS"), sElev = new Stat("elevated"), sSecs = new Stat("sections"), sFacts = new Stat("facts"), sReview = new Stat("to review"), sRisk = new Stat("risks"), sProc = new Stat("processes");
        ReconScan scan; bool loaded; readonly StepStrip steps = new StepStrip();

        public ReconPanel()
        {
            BackColor = Theme.Panel;
            FlowLayoutPanel bar = Theme.Bar(46);
            bRun = Theme.Btn("Run audit", true); bRun.Click += delegate { Run(); }; bCancel = Theme.Btn("Cancel", false); bCancel.Enabled = false; bCancel.Click += delegate { if (scan != null) { scan.Cancel = true; Host.Toast("Stopping after the current step…", true); } };
            cEvents = Theme.Toggle("recent event logs", true); ToolTip tip = new ToolTip(); tip.AutoPopDelay = 12000; tip.SetToolTip(cEvents, "Read the Security, System and PowerShell logs (failed logons, new services, script blocks). The Security log needs administrator rights.");
            bMd = Theme.Btn("Save Markdown…", false); bJson = Theme.Btn("Save JSON…", false); bPdf = Theme.Btn("Save PDF…", false); bLog = Theme.Btn("Log…", false);
            bMd.Click += delegate { Save("md"); }; bJson.Click += delegate { Save("json"); }; bPdf.Click += delegate { Save("pdf"); }; bLog.Click += delegate { ShowLog(); };
            foreach (Button b in new Button[] { bMd, bJson, bPdf }) b.Enabled = false;
            Panel gap = new Panel(); gap.Width = Theme.S(14); gap.Height = 1;
            foreach (Control c in new Control[] { bRun, bCancel, cEvents, gap, bMd, bJson, bPdf, bLog, status }) bar.Controls.Add(c); status.Margin = new Padding(Theme.S(10), Theme.S(9), 0, 0);
            // summary strip
            TableLayoutPanel strip = new TableLayoutPanel(); strip.Dock = DockStyle.Top; strip.Height = Theme.S(76); strip.BackColor = Theme.Panel; strip.Padding = new Padding(Theme.S(10), Theme.S(2), Theme.S(2), Theme.S(6)); strip.ColumnCount = 7; strip.RowCount = 1;
            foreach (Stat s in new Stat[] { sOs, sElev, sSecs, sFacts, sReview, sRisk, sProc }) { strip.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, s == sOs ? 24 : s == sElev ? 14 : 12.4f)); s.Dock = DockStyle.Fill; strip.Controls.Add(s); }
            // rows
            view = NewView("recon-audit");
            view.Apply(Columns.Recon());
            lSection = Theme.Lbl("section", Theme.Dim, Theme.UI); cSection = Theme.Combo(230, "all sections"); cRiskOnly = Theme.Toggle("flagged only", false);
            foreach (Control c in new Control[] { lSection, cSection, cRiskOnly }) view.Extra.Controls.Add(c);
            cSection.SelectedIndexChanged += delegate { view.Refilter(); }; cRiskOnly.CheckedChanged += delegate { view.Refilter(); };
            view.Filter = delegate (object o) { ReconItem i = (ReconItem)o; if (cSection.SelectedIndex > 0 && i.Section != (string)cSection.SelectedItem) return false; if (cRiskOnly.Checked && i.Risk != "warn" && i.Risk != "bad") return false; return true; };
            view.SelectionChanged += delegate { sel.Update(view.SelectedCount, "fact"); };
            view.Activated += delegate (object o) { ReconItem i = (ReconItem)o; string p = ExtractPath(i.Value); if (p != null) Dialogs.OpenInExplorer(p); };
            sel.Add("Copy as text", true, delegate { CopyText(); }); sel.Add("Export selected", false, delegate { view.Export(); }); sel.Add("Clear selection", false, delegate { view.ClearSelection(); });
            Controls.Add(view); Controls.Add(sel); Controls.Add(strip); Controls.Add(steps); Controls.Add(bar); view.BringToFront();
        }

        public override void OnShown()
        {
            if (loaded) return; loaded = true; scan = new ReconScan(); scan.Report.Elevated = Host.IsElevated; Cards(); status.Text = "not run yet · Run audit to enumerate this machine";
        }

        static string ExtractPath(string v) { if (string.IsNullOrEmpty(v)) return null; int i = v.IndexOfAny(new char[] { 'C', 'c' }); if (i >= 0 && i + 2 < v.Length && v[i + 1] == ':' && v[i + 2] == '\\') { string p = v.Substring(i).Split(' ')[0].Trim('"'); return p; } return null; }

        void Ui(Action a) { try { Host.BeginInvoke(a); } catch { } }
        void Run()
        {
            if (scan != null && scan.Running) { Host.Toast("An audit is already running.", true); return; }
            scan = new ReconScan(); scan.DoEvents = cEvents.Checked;
            ReconScan s = scan;
            s.Progress += delegate (string m) { Ui(delegate { status.Text = m; if (scan == s) steps.Say(m); }); };
            s.Step += delegate (string label, string state, string note) { Ui(delegate { if (scan == s) steps.Set(label, state, note); }); };
            s.Phase += delegate { Ui(delegate { Reload(); }); };
            s.Finished += delegate { Ui(delegate { bRun.Enabled = true; bCancel.Enabled = false; foreach (Button b in new Button[] { bMd, bJson, bPdf }) b.Enabled = true; Reload(); FillSections(); steps.End((s.Cancel ? "cancelled · " : "finished · ") + s.Report.Items.Count + " facts · " + s.Report.Bad + " risk · " + s.Report.Warn + " to review"); Host.Toast(scan.Report.Bad + " risk · " + scan.Report.Warn + " to review · " + scan.Report.Items.Count + " facts" + (scan.Errors.Count > 0 ? " · " + scan.Errors.Count + " section(s) limited - see Log…" : ""), scan.Report.Bad > 0); }); };
            bRun.Enabled = false; bCancel.Enabled = true; foreach (Button b in new Button[] { bMd, bJson, bPdf }) b.Enabled = false; status.Text = "starting…"; view.SetItems(new object[0], false); steps.Begin(ReconScan.StepLabels);
            if (!Host.IsElevated) Host.Toast("Running without administrator rights: the Security event log, BitLocker and some settings will be limited.", true);
            scan.RunInBackground();
        }
        void Reload() { if (scan == null) return; List<object> items = new List<object>(); foreach (ReconItem i in scan.Snapshot()) items.Add(i); view.SetItems(items, true); Cards(); }
        void FillSections() { string cur = cSection.SelectedItem as string; cSection.Items.Clear(); cSection.Items.Add("all sections"); if (scan != null) foreach (string s in scan.Report.Sections()) cSection.Items.Add(s); int idx = cur == null ? 0 : cSection.Items.IndexOf(cur); cSection.SelectedIndex = idx < 0 ? 0 : idx; }
        void Cards()
        {
            ReconReport r = scan != null ? scan.Report : null; bool ran = scan != null && scan.FinishedAt != DateTime.MinValue;
            sOs.Set(r != null && r.Os.Length > 0 ? r.Os : "—", r != null && r.Os.Length > 0 ? r.Host : "run to read", Theme.Ink);
            sElev.Set(r == null ? "—" : r.Elevated ? "yes" : "no", r != null && !r.Elevated ? "some checks limited" : "full access", r != null && r.Elevated ? Theme.Green : Theme.Amber);
            int facts = r != null ? r.Items.Count : 0; int secs = r != null ? r.Sections().Count : 0;
            sSecs.Set(secs > 0 ? secs.ToString() : "—", "enumerated", Theme.Ink); sFacts.Set(facts > 0 ? facts.ToString() : "—", "collected", Theme.Ink);
            int warn = r != null ? r.Warn : 0, bad = r != null ? r.Bad : 0;
            sReview.Set(ran ? warn.ToString() : "—", "worth a look", warn > 0 ? Theme.Amber : ran ? Theme.Green : Theme.Ink); sRisk.Set(ran ? bad.ToString() : "—", "hardening gaps", bad > 0 ? Theme.Rose : ran ? Theme.Green : Theme.Ink);
            int procs = 0; if (r != null) foreach (ReconItem i in r.Items) if (i.Section.StartsWith("6.") && i.Name == "total") { string d = i.Value.Split(' ')[0]; int.TryParse(d, out procs); }
            sProc.Set(procs > 0 ? procs.ToString() : "—", "running", Theme.Ink);
        }

        void Save(string fmt)
        {
            if (scan == null || scan.Report.Items.Count == 0) { Host.Toast("Run the audit first.", true); return; }
            string ext = fmt, filter = fmt == "md" ? "Markdown (*.md)|*.md" : fmt == "json" ? "JSON (*.json)|*.json" : "PDF (*.pdf)|*.pdf";
            using (SaveFileDialog d = new SaveFileDialog())
            {
                d.Filter = filter + "|All files|*.*"; d.FileName = scan.Report.FileStem + "." + ext; d.Title = "Save the recon report as " + fmt.ToUpperInvariant();
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
            List<string> l = new List<string>(); foreach (object o in view.Targets) { ReconItem i = (ReconItem)o; l.Add(i.Section + " | " + i.Group + " | " + i.Name + " | " + i.Value + (i.Note.Length > 0 ? " | " + i.Note : "")); }
            if (l.Count == 0) { Host.Toast("Nothing selected.", true); return; } try { Clipboard.SetText(string.Join("\r\n", l.ToArray())); Host.Toast(l.Count + " fact(s) copied", false); } catch (Exception ex) { Host.Toast("clipboard: " + ex.Message, true); }
        }
        void ShowLog()
        {
            using (Form f = new Form())
            {
                f.Text = "Audit log"; f.BackColor = Theme.Panel; f.ForeColor = Theme.Ink; f.Font = Theme.UI; f.Width = Theme.S(820); f.Height = Theme.S(520); f.StartPosition = FormStartPosition.CenterParent; f.MinimizeBox = false;
                TextBox t = new TextBox(); t.Multiline = true; t.ReadOnly = true; t.Dock = DockStyle.Fill; t.BackColor = Theme.Panel2; t.ForeColor = Theme.Ink; t.Font = Theme.Mono; t.ScrollBars = ScrollBars.Both; t.WordWrap = false; t.BorderStyle = BorderStyle.FixedSingle;
                StringBuilder sb = new StringBuilder();
                if (scan == null || scan.Log.Count == 0) sb.AppendLine("No audit yet."); else { if (scan.Errors.Count > 0) { sb.AppendLine("LIMITED / UNAVAILABLE"); foreach (string e in scan.Errors) sb.AppendLine("  " + e); sb.AppendLine(); } sb.AppendLine("LOG"); foreach (string s in scan.LogSnapshot()) sb.AppendLine("  " + s); }
                t.Text = sb.ToString();
                FlowLayoutPanel bar = new FlowLayoutPanel(); bar.Dock = DockStyle.Bottom; bar.Height = Theme.S(46); bar.FlowDirection = FlowDirection.RightToLeft; bar.Padding = new Padding(Theme.S(10), Theme.S(8), Theme.S(10), 0); bar.BackColor = Theme.Panel;
                Button close = Theme.Btn("Close", true), copy = Theme.Btn("Copy", false); close.DialogResult = DialogResult.Cancel; copy.Click += delegate { try { Clipboard.SetText(t.Text); } catch { } }; bar.Controls.Add(close); bar.Controls.Add(copy);
                Panel body = new Panel(); body.Dock = DockStyle.Fill; body.Padding = new Padding(Theme.S(10), Theme.S(10), Theme.S(10), 0); body.Controls.Add(t);
                f.Controls.Add(body); f.Controls.Add(bar); body.BringToFront(); f.CancelButton = close; f.ShowDialog(this);
            }
        }

        // ── self-test and screenshots ──
        public override void SelfTest(StringBuilder r)
        {
            if (r == null) { Demo(); return; }
            ReconScan s = new ReconScan(); scan = s; Stopwatch sw = Stopwatch.StartNew(); s.Run(); sw.Stop(); Reload(); FillSections();
            List<string> secs = s.Report.Sections();
            r.AppendLine((s.Report.Items.Count > 20 && secs.Count >= 6 ? "PASS" : "FAIL") + " recon: " + s.Report.Items.Count + " facts across " + secs.Count + " sections in " + sw.Elapsed.TotalSeconds.ToString("N1") + " s · " + s.Report.Bad + " risk, " + s.Report.Warn + " to review" + (s.Errors.Count > 0 ? " · limited: " + string.Join(" / ", s.Errors.ToArray()) : ""));
            foreach (string sec in secs) { int n = s.Report.Items.FindAll(delegate (ReconItem i) { return i.Section == sec; }).Count; r.AppendLine("INFO   " + sec + ": " + n + " facts"); }
            foreach (ReconItem i in s.Report.Items) if (i.Risk == "bad" || i.Risk == "warn") r.AppendLine("INFO   [" + i.Risk + "] " + i.Group + " / " + i.Name + ": " + i.Value + (i.Note.Length > 0 ? " (" + i.Note + ")" : ""));
            // report writers round-trip
            try
            {
                string dir = Path.Combine(Path.GetTempPath(), "pstools-recon-test"); Directory.CreateDirectory(dir);
                string md = Path.Combine(dir, "r.md"), js = Path.Combine(dir, "r.json"), pdf = Path.Combine(dir, "r.pdf");
                File.WriteAllText(md, s.Report.ToMarkdown()); File.WriteAllText(js, s.Report.ToJson()); s.Report.SavePdf(pdf);
                object parsed = Json.Parse(File.ReadAllText(js)); int jsSecs = Json.Arr(Json.Get(parsed, "sections")).Count;
                byte[] pdfBytes = File.ReadAllBytes(pdf); bool pdfOk = pdfBytes.Length > 800 && pdfBytes[0] == (byte)'%' && pdfBytes[1] == (byte)'P' && System.Text.Encoding.ASCII.GetString(pdfBytes, pdfBytes.Length - 5, 5) == "%%EOF";
                r.AppendLine((jsSecs == secs.Count ? "PASS" : "FAIL") + " recon: JSON re-parses with " + jsSecs + " sections · Markdown " + new FileInfo(md).Length + " B");
                r.AppendLine((pdfOk ? "PASS" : "FAIL") + " recon: PDF " + pdfBytes.Length + " B, header %PDF and trailer %%EOF present");
                Directory.Delete(dir, true);
            }
            catch (Exception ex) { r.AppendLine("FAIL recon: report writers: " + ex.Message); }
        }
        void Demo()
        {
            ReconScan s = new ReconScan(); ReconReport r = s.Report; r.Os = "Microsoft Windows 11 Home 10.0.26200"; r.Elevated = true;
            Action<string, string, string, string, string, string> A = delegate (string sec, string grp, string name, string val, string note, string risk) { r.Items.Add(new ReconItem(sec, grp, name, val, note, risk)); };
            A("1. System Information", "OS & Version", "Caption", "Microsoft Windows 11 Home", "", ""); A("1. System Information", "OS & Version", "Build", "26200", "", ""); A("1. System Information", "OS & Version", "Architecture", "64-bit", "", "");
            A("1. System Information", "Uptime", "Uptime", "42d 6h 11m", "up for over a month - patches may be pending a reboot", "warn"); A("1. System Information", "PowerShell", "Windows PowerShell", "5.1.26200.6584", "", ""); A("1. System Information", "PowerShell", "PowerShell v2 engine", "2.0", "the v2 engine is present - a downgrade-attack surface; remove if unused", "warn");
            A("1. System Information", "Installed Hotfixes (last 10)", "KB5065999", "2026-08-13 · Security Update", "", ""); A("1. System Information", "Installed Hotfixes (last 10)", "KB5064000", "2026-07-09 · Update", "", "");
            A("2. Users & Groups", "Local Users", "Administrator", "enabled · password not required · expires no", "built-in Administrator is enabled", "warn"); A("2. Users & Groups", "Local Users", "alice", "enabled · password required · expires no", "", ""); A("2. Users & Groups", "Local Users", "DefaultAccount", "disabled · password not required · expires no", "", "");
            A("2. Users & Groups", "Local Administrators", "WORKSTATION-01\\alice", "Win32_UserAccount", "member of Administrators", ""); A("2. Users & Groups", "Local Administrators", "WORKSTATION-01\\Administrator", "Win32_UserAccount", "member of Administrators", ""); A("2. Users & Groups", "Logged On Users", "WORKSTATION-01\\alice", "", "", "");
            A("3. Network", "IP Configuration", "Ethernet", "192.168.1.42/24", "Realtek Gaming 2.5GbE", ""); A("3. Network", "IP Configuration", "Tailscale", "100.104.12.7/32", "Tailscale Tunnel", "");
            A("3. Network", "Listening Ports", "TCP 445", "System (PID 4)", "0.0.0.0", ""); A("3. Network", "Listening Ports", "TCP 3389", "svchost (PID 1180)", "0.0.0.0", "review: remote desktop is listening"); A("3. Network", "Listening Ports", "TCP 135", "svchost (PID 980)", "0.0.0.0", "");
            A("3. Network", "Network Shares", "C$", "C:\\ · Default share", "administrative share", ""); A("3. Network", "Network Shares", "Backups", "D:\\Backups", "review who can reach this share", "");
            A("3. Network", "Active TCP Connections", "192.168.1.42:52344 → 140.82.113.25:443", "msedge", "", ""); A("3. Network", "Active TCP Connections", "192.168.1.42:52350 → 20.190.160.14:443", "svchost", "", "");
            A("3. Network", "Firewall Profiles", "Domain", "enabled · default inbound block", "", "good"); A("3. Network", "Firewall Profiles", "Private", "enabled · default inbound block", "", "good"); A("3. Network", "Firewall Profiles", "Public", "DISABLED · default inbound allow", "the firewall is off for this profile", "warn");
            A("4. Security Posture", "Defender Status", "Real-time protection", "enabled", "", "good"); A("4. Security Posture", "Defender Status", "Signatures updated", "2026-09-14 08:12", "", "good");
            A("4. Security Posture", "Defender Exclusions", "path exclusion", "C:\\Tools", "excluded from scanning", "warn"); A("4. Security Posture", "BitLocker", "C:", "protection on", "", "good"); A("4. Security Posture", "BitLocker", "D:", "protection OFF", "this volume is not encrypted", "warn");
            A("4. Security Posture", "PowerShell hardening", "Script block logging", "disabled", "logging is off - PowerShell activity is not recorded", "info"); A("4. Security Posture", "PowerShell hardening", "Execution policy", "Bypass", "execution policy is permissive", "warn");
            A("4. Security Posture", "Credential Protection", "WDigest UseLogonCredential", "1", "plaintext credentials are cached in memory (0 = hardened)", "bad"); A("4. Security Posture", "Credential Protection", "LSA RunAsPPL", "0", "LSASS is not protected (1 = protected)", "warn");
            A("4. Security Posture", "Privilege Escalation", "AlwaysInstallElevated", "HKCU=1 HKLM=1", "both set - any user can install as SYSTEM", "bad");
            A("5. Persistence Surface", "Services (non-Microsoft)", "TailscaleService", "Running · Auto · C:\\Program Files\\Tailscale\\tailscaled.exe", "", ""); A("5. Persistence Surface", "Unquoted Service Paths", "MyApp Updater", "C:\\Program Files\\My App\\updater.exe", "unquoted path with a space - privilege-escalation surface", "bad");
            A("5. Persistence Surface", "Scheduled Tasks (non-Microsoft)", "GoogleUpdateTaskMachineUA", "ready · \\GoogleUpdateTaskMachineUA", "", ""); A("5. Persistence Surface", "Registry Run Keys (HKCU)", "OneDrive", "C:\\Users\\alice\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe /background", "runs at logon", ""); A("5. Persistence Surface", "Startup Folders", "backup.lnk", "C:\\Users\\alice\\...\\Startup", "modified 2026-09-01", "");
            A("6. Running Processes", "Running Processes", "explorer.exe (PID 6120)", "C:\\Windows\\Explorer.EXE", "parent PID 5980", ""); A("6. Running Processes", "Running Processes", "svchost.exe (PID 1180)", "C:\\Windows\\system32\\svchost.exe -k termsvcs", "parent PID 980", ""); A("6. Running Processes", "Running Processes", "total", "312 processes", "showing the first 600", "info");
            A("7. Recent Security Events", "Failed Logons (4625)", "2026-09-14 03:22:10", "An account failed to log on · Account Name: admin · Source Network Address: 203.0.113.9", "", "warn"); A("7. Recent Security Events", "Failed Logons (4625)", "2026-09-14 03:22:07", "An account failed to log on · Account Name: administrator · Source Network Address: 203.0.113.9", "", "warn");
            A("7. Recent Security Events", "New Services Installed (7045)", "2026-08-13 09:12:44", "A service was installed in the system · Service Name: TailscaleService", "", ""); A("7. Recent Security Events", "PowerShell Script Block (4104)", "2026-09-13 21:40:02", "Creating Scriptblock text: Get-Process | Sort CPU", "", "");
            r.When = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"); r.Host = "WORKSTATION-01"; s.FinishedAt = DateTime.Now; scan = s;
            Reload(); FillSections(); foreach (Button b in new Button[] { bMd, bJson, bPdf }) b.Enabled = true; status.Text = "done · 42 facts, 3 risk, 8 to review, in 3.4 s";
            steps.Begin(ReconScan.StepLabels); foreach (string l in ReconScan.StepLabels) steps.Set(l, "done", null); steps.End("finished · 42 facts · 3 risk · 8 to review");
            view.AddRule("section", "does not contain", "6.", false); view.AddRule("value", "is not empty", "", false); view.OpenFilterBar();
        }
    }
}

// The six tool panels. Each one: an action bar on top, the DataView in the middle (grid / details / tree,
// search, sort, checkbox multi-select, CSV export), a selection bar at the bottom with the actions that
// apply to the checked rows. Engines live in Net.cs and Sys.cs.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;

namespace PSTools
{
    static class Dialogs
    {
        public static string PasteText(IWin32Window owner, string title, string hint)
        {
            using (Form f = new Form())
            {
                f.Text = title; f.BackColor = Theme.Panel; f.ForeColor = Theme.Ink; f.Font = Theme.UI; f.Width = Theme.S(640); f.Height = Theme.S(460); f.StartPosition = FormStartPosition.CenterParent; f.FormBorderStyle = FormBorderStyle.FixedDialog; f.MinimizeBox = false; f.MaximizeBox = false;
                Label l = Theme.Lbl(hint, Theme.Dim, Theme.UISmall); l.Dock = DockStyle.Top; l.AutoSize = false; l.Height = Theme.S(34); l.Padding = new Padding(Theme.S(10), Theme.S(8), Theme.S(10), 0);
                TextBox t = new TextBox(); t.Multiline = true; t.Dock = DockStyle.Fill; t.BackColor = Theme.Panel2; t.ForeColor = Theme.Ink; t.Font = Theme.Mono; t.ScrollBars = ScrollBars.Both; t.AcceptsReturn = true; t.WordWrap = false; t.BorderStyle = BorderStyle.FixedSingle;
                FlowLayoutPanel b = new FlowLayoutPanel(); b.Dock = DockStyle.Bottom; b.Height = Theme.S(46); b.FlowDirection = FlowDirection.RightToLeft; b.Padding = new Padding(Theme.S(10), Theme.S(8), Theme.S(10), 0); b.BackColor = Theme.Panel;
                Button ok = Theme.Btn("Add", true), cancel = Theme.Btn("Cancel", false); ok.DialogResult = DialogResult.OK; cancel.DialogResult = DialogResult.Cancel; b.Controls.Add(ok); b.Controls.Add(cancel);
                Panel body = new Panel(); body.Dock = DockStyle.Fill; body.Padding = new Padding(Theme.S(10), 0, Theme.S(10), 0); body.Controls.Add(t);
                f.Controls.Add(body); f.Controls.Add(l); f.Controls.Add(b); body.BringToFront(); f.AcceptButton = null; f.CancelButton = cancel;
                return f.ShowDialog(owner) == DialogResult.OK ? t.Text : null;
            }
        }
        public static string PickFolder(IWin32Window owner, string title, string start)
        {
            using (FolderBrowserDialog d = new FolderBrowserDialog()) { d.Description = title; d.ShowNewFolderButton = true; if (!string.IsNullOrEmpty(start) && Directory.Exists(start)) d.SelectedPath = start; return d.ShowDialog(owner) == DialogResult.OK ? d.SelectedPath : null; }
        }
        public static string PickFile(IWin32Window owner, string title, string filter)
        {
            using (OpenFileDialog d = new OpenFileDialog()) { d.Title = title; d.Filter = filter; return d.ShowDialog(owner) == DialogResult.OK ? d.FileName : null; }
        }
        public static void OpenInExplorer(string path) { try { if (Directory.Exists(path)) Process.Start("explorer.exe", "\"" + path + "\""); else Process.Start("explorer.exe", "/select,\"" + path + "\""); } catch { } }
        public static string Spark(List<double> h, int width) { return Fmt.Spark(h, width); }
    }

    // ═══════════════════════════════ 1 · Domain and IP Blocker ═══════════════════════════════
    public class BlockerPanel : ToolPanel
    {
        public override string Title { get { return Tools.Title(GetType().Name); } }
        public override string Blurb { get { return Tools.Blurb(GetType().Name); } }
        public override bool NeedsAdmin { get { return Tools.Admin(GetType().Name); } }
        readonly DataView view; readonly SelectionBar sel = new SelectionBar(); readonly Hosts hosts = new Hosts();
        readonly List<BlockItem> loaded = new List<BlockItem>(); readonly List<BlockItem> blocked = new List<BlockItem>(); bool showBlocked;
        readonly Button bList, bBlocked, bFile, bPaste, bAdd, bBlockAll, bRefresh, bBackups, bFlush; readonly CheckBox cHosts, cFw, cWww; readonly TextBox tSink; readonly Label status = Theme.Lbl("", Theme.Dim, Theme.UISmall);
        HashSet<string> hostsBlocked = new HashSet<string>(StringComparer.OrdinalIgnoreCase), fwBlocked = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        public BlockerPanel()
        {
            BackColor = Theme.Panel;
            FlowLayoutPanel bar = Theme.Bar(46);
            bList = Theme.Btn("Loaded list", false); bBlocked = Theme.Btn("Blocked now", false); bList.Click += delegate { SetMode(false); }; bBlocked.Click += delegate { SetMode(true); };
            bFile = Theme.Btn("Add from file…", true); bPaste = Theme.Btn("Paste…", false); bAdd = Theme.Btn("Add entry", false); bBlockAll = Theme.Btn("Block all listed", false); bRefresh = Theme.Btn("Refresh", false); bBackups = Theme.Btn("Backups…", false); bFlush = Theme.Btn("Flush DNS", false);
            bFile.Click += delegate { string f = Dialogs.PickFile(this, "The file of domains and IPs", "Lists (*.txt;*.csv;*.log)|*.txt;*.csv;*.log|All files|*.*"); if (f != null) LoadFile(f); };
            bPaste.Click += delegate { string t = Dialogs.PasteText(this, "Paste domains and IPs", "URLs, log lines and defanged names like evil[.]com are fine - one thing per line or mixed in prose."); if (t != null) AddLines(t.Split('\n'), "pasted"); };
            bAdd.Click += delegate { BlockItem it = new BlockItem(); it.Value = ""; it.Kind = Kind.Invalid; it.Source = "typed"; it.Note = "type the value in the row"; loaded.Add(it); view.Add(new object[] { it }); view.Select(new object[] { it }, true); };
            bBlockAll.Click += delegate { Block(loaded); };
            bRefresh.Click += delegate { RefreshBlocked(); Host.Toast("Re-read the hosts file and the firewall rule.", false); };
            bBackups.Click += delegate { Backups(); };
            bFlush.Click += delegate { try { ProcessStartInfo si = new ProcessStartInfo("ipconfig.exe", "/flushdns"); si.UseShellExecute = false; si.CreateNoWindow = true; Process.Start(si).WaitForExit(); Host.Toast("DNS cache flushed.", false); } catch (Exception ex) { Host.Toast("flush failed: " + ex.Message, true); } };
            cHosts = Theme.Toggle("domains → hosts file", true); cFw = Theme.Toggle("IPs → firewall", true); cWww = Theme.Toggle("add www. variant", true);
            Label ls = Theme.Lbl("resolve to", Theme.Dim, Theme.UI); tSink = Theme.Text(Host == null ? "0.0.0.0" : "0.0.0.0", 110);
            Panel gap = new Panel(); gap.Width = Theme.S(14); gap.Height = 1;
            foreach (Control c in new Control[] { bList, bBlocked, gap, bFile, bPaste, bAdd, bBlockAll, bRefresh, bBackups, bFlush }) bar.Controls.Add(c);
            FlowLayoutPanel bar2 = Theme.Bar(40); bar2.Padding = new Padding(Theme.S(10), 0, Theme.S(10), 0);
            foreach (Control c in new Control[] { cHosts, cFw, cWww, ls, tSink, status }) bar2.Controls.Add(c);
            status.Margin = new Padding(Theme.S(16), Theme.S(9), 0, 0);
            // the rows
            view = NewView("block-list");
            view.Apply(Columns.BlockerLoaded(Classify));
            view.SelectionChanged += delegate { sel.Update(view.SelectedCount, "item"); };
            view.Activated += delegate (object o) { view.Select(new object[] { o }, !view.SelectedItems.Contains(o)); };
            // selection bar
            sel.Add("Block selected", true, delegate { Block(Sel()); }); sel.Add("Unblock selected", false, delegate { Unblock(Sel()); }); sel.Add("Remove from list", false, delegate { RemoveFromList(Sel()); }); sel.Add("Export selected", false, delegate { view.Export(); }); sel.Add("Clear selection", false, delegate { view.ClearSelection(); });
            Controls.Add(view); Controls.Add(sel); Controls.Add(bar2); Controls.Add(bar); view.BringToFront();
            SetMode(false);
        }
        List<BlockItem> Sel() { List<BlockItem> l = new List<BlockItem>(); foreach (object o in view.Targets) l.Add((BlockItem)o); return l; }
        void SetMode(bool blockedMode)
        {
            showBlocked = blockedMode; view.ExportName = blockedMode ? "blocked-now" : "block-list";
            foreach (Button b in new Button[] { bList, bBlocked }) { bool on = (b == bBlocked) == blockedMode; b.BackColor = on ? Theme.Panel3 : Theme.Panel2; b.ForeColor = on ? Theme.Teal : Theme.Ink; b.FlatAppearance.BorderColor = on ? Theme.Teal : Theme.Line; }
            bBlockAll.Enabled = !blockedMode; bAdd.Enabled = !blockedMode;
            if (blockedMode) { RefreshBlocked(); view.Apply(Columns.BlockerBlocked()); view.SetItems(Boxed(blocked), false); }
            else { view.Apply(Columns.BlockerLoaded(Classify)); view.SetItems(Boxed(loaded), false); }
            UpdateStatus();
        }
        public override void OnShown() { RefreshBlocked(); UpdateStatus(); tSink.Text = Host.Settings.Get("block.sink", "0.0.0.0"); }
        public override void Exercise(StringBuilder r)
        {
            foreach (bool m in new bool[] { true, false }) { try { if (view.VisibleItems.Count > 0) view.SetCurrent(0, 1); SetMode(m); Application.DoEvents(); ExerciseView(view, r); } catch (Exception ex) { r.AppendLine("FAIL ui blocker/" + (m ? "blocked" : "loaded") + ": " + ex.GetType().Name + ": " + ex.Message); } }
        }
        public override void OnHidden() { if (Host != null) Host.Settings.Set("block.sink", tSink.Text); }
        void UpdateStatus() { bList.Text = "Loaded list (" + loaded.Count + ")"; bBlocked.Text = "Blocked now (" + blocked.Count + ")"; status.Text = hostsBlocked.Count + " domain(s) in the hosts file · " + fwBlocked.Count + " IP(s) in the firewall rule" + (Firewall.Available() ? "" : " · firewall API unavailable"); }
        void RefreshBlocked()
        {
            hostsBlocked.Clear(); fwBlocked.Clear(); blocked.Clear();
            try { foreach (HostsEntry e in hosts.Entries(false)) { hostsBlocked.Add(e.Host); BlockItem b = new BlockItem(); b.Value = e.Host; b.Kind = Kind.Domain; b.Where = "hosts file"; b.Note = "→ " + e.Sink + " · line " + e.LineNo; b.BlockedHosts = true; blocked.Add(b); } } catch (Exception ex) { status.Text = "hosts file: " + ex.Message; }
            foreach (string ip in Firewall.GetBlocked()) { fwBlocked.Add(ip); BlockItem b = new BlockItem(); b.Value = ip; b.Kind = Extractor.Classify(ip); b.Where = "firewall"; b.Note = "outbound block · rule '" + Firewall.RuleName + "'"; b.BlockedFw = true; blocked.Add(b); }
            foreach (BlockItem b in loaded) Classify(b);
            if (showBlocked) view.SetItems(Boxed(blocked), true); else view.Invalidate2();
            UpdateStatus();
        }
        void Classify(BlockItem b)
        {
            b.BlockedHosts = b.Kind == Kind.Domain && (hostsBlocked.Contains(b.Value) || hostsBlocked.Contains("www." + b.Value));
            b.BlockedFw = (b.Kind == Kind.IPv4 || b.Kind == Kind.IPv6) && fwBlocked.Contains(b.Value);
        }
        public void LoadFile(string path) { try { AddLines(File.ReadAllLines(path), Path.GetFileName(path)); } catch (Exception ex) { Host.Error("Could not read the file", ex.Message); } }
        public int AddLines(IEnumerable<string> lines, string origin)
        {
            HashSet<string> have = new HashSet<string>(StringComparer.OrdinalIgnoreCase); foreach (BlockItem b in loaded) have.Add(b.Value);
            List<BlockItem> added = new List<BlockItem>();
            foreach (Target t in Extractor.Extract(lines)) { if (have.Contains(t.Value)) continue; BlockItem b = new BlockItem(); b.Value = t.Value; b.Kind = t.Kind; b.Source = t.Source; b.Line = t.Line; b.Note = origin; Classify(b); loaded.Add(b); added.Add(b); have.Add(t.Value); }
            if (showBlocked) SetMode(false); else view.Add(Boxed(added));
            UpdateStatus(); if (Host != null) Host.Toast(added.Count + " new item" + (added.Count == 1 ? "" : "s") + " from " + origin + (added.Count == 0 ? " (nothing new found)" : ""), added.Count == 0);
            return added.Count;
        }
        public void AddValues(IEnumerable<string> values, string origin) { AddLines(values, origin); }
        void RemoveFromList(List<BlockItem> items) { foreach (BlockItem b in items) loaded.Remove(b); view.Remove(Boxed(items)); UpdateStatus(); }
        void Block(List<BlockItem> items)
        {
            List<string> domains = new List<string>(), ips = new List<string>();
            foreach (BlockItem b in items) { if (b.Kind == Kind.Domain && cHosts.Checked && !b.BlockedHosts) domains.Add(b.Value); if ((b.Kind == Kind.IPv4 || b.Kind == Kind.IPv6) && cFw.Checked && !b.BlockedFw) ips.Add(b.Value); }
            if (cWww.Checked) domains = Extractor.ExpandDomains(domains);
            if (domains.Count == 0 && ips.Count == 0) { Host.Toast("Nothing to block: pick rows that are not blocked yet, and check what goes where.", true); return; }
            string sink = tSink.Text.Trim(); if (sink.Length == 0) sink = "0.0.0.0";
            StringBuilder msg = new StringBuilder();
            msg.AppendLine(domains.Count + " domain(s) → hosts file → " + sink + (domains.Count > 0 ? "\n   " + Preview(domains) : ""));
            msg.AppendLine(ips.Count + " IP(s) → firewall outbound block rule '" + Firewall.RuleName + "'" + (ips.Count > 0 ? "\n   " + Preview(ips) : ""));
            msg.AppendLine(); msg.AppendLine("The hosts file is backed up first. Everything can be undone from 'Blocked now'.");
            if (!Host.Confirm("Block " + (domains.Count + ips.Count) + " item(s)?", msg.ToString())) return;
            if (Host.NeedAdmin("Writing the hosts file and the firewall rule")) return;
            StringBuilder done = new StringBuilder();
            try
            {
                if (domains.Count > 0) { Hosts.AddResult r = hosts.Add(domains, sink); done.AppendLine("hosts file: added " + r.Added + ", skipped " + r.Skipped + " already present · backup " + Path.GetFileName(r.Backup)); }
                if (ips.Count > 0) { List<string> cur = Firewall.GetBlocked(); int before = cur.Count; foreach (string ip in ips) if (!cur.Contains(ip)) cur.Add(ip); Firewall.SetBlocked(cur); done.AppendLine("firewall: added " + (cur.Count - before) + ", the rule now holds " + cur.Count + " address(es)"); }
                done.AppendLine(); done.AppendLine("Browsers cache DNS: use Flush DNS, or restart the browser, to apply immediately.");
                RefreshBlocked(); Host.Info("Blocked", done.ToString());
            }
            catch (Exception ex) { RefreshBlocked(); Host.Error("Blocking stopped", ex.Message + "\n\n" + done + (ex.Message.IndexOf("denied", StringComparison.OrdinalIgnoreCase) >= 0 ? "\nIf this is denied even as administrator, security software may be protecting the hosts file (Defender tamper protection / controlled folder access)." : "")); }
        }
        void Unblock(List<BlockItem> items)
        {
            List<string> domains = new List<string>(), ips = new List<string>();
            foreach (BlockItem b in items) { if (b.Kind == Kind.Domain) { domains.Add(b.Value); domains.Add("www." + b.Value); } else if (b.Kind != Kind.Invalid) ips.Add(b.Value); }
            if (!Host.Confirm("Unblock " + items.Count + " item(s)?", "Only lines this tool added (tagged " + Hosts.Marker + ") are removed from the hosts file; the addresses are taken out of the firewall rule. The hosts file is backed up first.")) return;
            if (Host.NeedAdmin("Writing the hosts file and the firewall rule")) return;
            try
            {
                StringBuilder done = new StringBuilder();
                if (domains.Count > 0) { Hosts.RemoveResult r = hosts.Remove(domains); done.AppendLine("hosts file: removed " + r.Removed + " line(s) · backup " + Path.GetFileName(r.Backup)); }
                if (ips.Count > 0) { List<string> cur = Firewall.GetBlocked(); int before = cur.Count; cur.RemoveAll(delegate (string s) { return ips.Contains(s); }); Firewall.SetBlocked(cur); done.AppendLine("firewall: removed " + (before - cur.Count) + ", " + cur.Count + " remain" + (cur.Count == 0 ? " (rule removed)" : "")); }
                RefreshBlocked(); Host.Info("Unblocked", done.ToString());
            }
            catch (Exception ex) { RefreshBlocked(); Host.Error("Unblocking stopped", ex.Message); }
        }
        static string Preview(List<string> l) { List<string> p = l.GetRange(0, Math.Min(10, l.Count)); return string.Join(", ", p) + (l.Count > 10 ? " … +" + (l.Count - 10) : ""); }
        void Backups()
        {
            List<FileInfo> b = hosts.Backups();
            using (Form f = new Form())
            {
                f.Text = "Hosts file backups"; f.BackColor = Theme.Panel; f.ForeColor = Theme.Ink; f.Font = Theme.UI; f.Width = Theme.S(620); f.Height = Theme.S(440); f.StartPosition = FormStartPosition.CenterParent; f.FormBorderStyle = FormBorderStyle.FixedDialog; f.MinimizeBox = false; f.MaximizeBox = false;
                ListBox lb = new ListBox(); lb.Dock = DockStyle.Fill; lb.BackColor = Theme.Panel2; lb.ForeColor = Theme.Ink; lb.Font = Theme.Mono; lb.BorderStyle = BorderStyle.None; lb.ItemHeight = Theme.S(22);
                foreach (FileInfo fi in b) lb.Items.Add(fi.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss") + "   " + fi.Length.ToString("N0").PadLeft(8) + " bytes   " + fi.Name);
                Label l = Theme.Lbl(b.Count == 0 ? "No backups yet. One is taken before every change." : "Every change backs the hosts file up here first: " + hosts.BackupDir, Theme.Dim, Theme.UISmall); l.Dock = DockStyle.Top; l.AutoSize = false; l.Height = Theme.S(40); l.Padding = new Padding(Theme.S(10), Theme.S(8), Theme.S(10), 0);
                FlowLayoutPanel bar = new FlowLayoutPanel(); bar.Dock = DockStyle.Bottom; bar.Height = Theme.S(46); bar.Padding = new Padding(Theme.S(10), Theme.S(8), Theme.S(10), 0); bar.BackColor = Theme.Panel;
                Button restore = Theme.Btn("Restore selected", true), open = Theme.Btn("Open folder", false), close = Theme.Btn("Close", false); close.DialogResult = DialogResult.Cancel;
                open.Click += delegate { Directory.CreateDirectory(hosts.BackupDir); Dialogs.OpenInExplorer(hosts.BackupDir); };
                restore.Click += delegate
                {
                    if (lb.SelectedIndex < 0) return; FileInfo fi = b[lb.SelectedIndex];
                    if (!Host.Confirm("Restore the hosts file?", "Overwrite the current hosts file with " + fi.Name + " from " + fi.LastWriteTime + "?\n\nThe current file is backed up first, so this is undoable. Firewall IPs are not affected.")) return;
                    if (Host.NeedAdmin("Writing the hosts file")) return;
                    try { string safety = hosts.Restore(fi.FullName); RefreshBlocked(); Host.Info("Restored", "Hosts file restored from " + fi.Name + ".\nThe previous state was saved as " + Path.GetFileName(safety) + "."); f.Close(); } catch (Exception ex) { Host.Error("Restore failed", ex.Message); }
                };
                bar.Controls.Add(restore); bar.Controls.Add(open); bar.Controls.Add(close);
                Panel body = new Panel(); body.Dock = DockStyle.Fill; body.Padding = new Padding(Theme.S(10), 0, Theme.S(10), 0); body.Controls.Add(lb);
                f.Controls.Add(body); f.Controls.Add(l); f.Controls.Add(bar); body.BringToFront(); f.CancelButton = close; f.ShowDialog(this);
            }
        }
        public override void SelfTest(StringBuilder r)
        {
            string sample = Path.Combine(Path.Combine(Path.GetDirectoryName(Application.ExecutablePath), "samples"), "sample-blocklist.txt");
            loaded.Clear(); int n = File.Exists(sample) ? AddLines(File.ReadAllLines(sample), "sample-blocklist.txt") : AddLines(new string[] { "doubleclick.net", "hxxps://malware-c2[.]net/gate.php", "203.0.113.45", "2001:db8:dead:beef::1", "notes.md", "localhost" }, "built-in");
            if (r == null) { SetMode(false); return; }
            int dom = 0, ip = 0; foreach (BlockItem b in loaded) { if (b.Kind == Kind.Domain) dom++; else if (b.Kind != Kind.Invalid) ip++; }
            r.AppendLine((n >= 6 && dom >= 3 && ip >= 2 ? "PASS" : "FAIL") + " blocker: loaded " + n + " items (" + dom + " domains, " + ip + " IPs) from " + (File.Exists(sample) ? "the sample list" : "built-in lines"));
            bool hasC2 = false, hasIp = false, noMd = true; foreach (BlockItem b in loaded) { if (b.Value == "malware-c2.net") hasC2 = true; if (b.Value == "203.0.113.45") hasIp = true; if (b.Value == "notes.md") noMd = false; }
            r.AppendLine((hasC2 && hasIp && noMd ? "PASS" : "FAIL") + " blocker: defanged c2 found=" + hasC2 + ", ip found=" + hasIp + ", notes.md excluded=" + noMd);
            BlockItem e = new BlockItem(); e.Value = "Example.COM"; view.Cols[0].Set(e, "Example.COM"); r.AppendLine((e.Kind == Kind.Domain && e.Value == "example.com" ? "PASS" : "FAIL") + " blocker: editing a row re-classifies it (" + e.Value + " → " + e.KindText + ")");
            view.Cols[0].Set(e, "not a host"); r.AppendLine((e.Kind == Kind.Invalid ? "PASS" : "FAIL") + " blocker: an invalid edit is flagged (" + e.Status + ")");
            RefreshBlocked(); r.AppendLine("INFO blocker: hosts file has " + hostsBlocked.Count + " tagged domain(s); firewall rule holds " + fwBlocked.Count + " address(es); firewall API " + (Firewall.Available() ? "available" : "MISSING"));
            view.SetView("tree"); r.AppendLine("PASS blocker: tree view built"); view.SetView("details"); view.SetView("grid");
        }
    }

    // ═══════════════════════════════ 2 · Reachability Verifier ═══════════════════════════════
    public class ReachPanel : ToolPanel
    {
        public override string Title { get { return Tools.Title(GetType().Name); } }
        public override string Blurb { get { return Tools.Blurb(GetType().Name); } }
        readonly DataView view; readonly SelectionBar sel = new SelectionBar(); readonly List<ReachRow> rows = new List<ReachRow>(); Reach engine;
        readonly Button bFile, bPaste, bClear, bRun, bCancel; readonly TextBox tPorts; readonly NumericUpDown nTimeout, nConc; readonly CheckBox cPing; readonly Label status = Theme.Lbl("", Theme.Dim, Theme.UISmall); readonly ProgressBar prog = new ProgressBar();
        public ReachPanel()
        {
            BackColor = Theme.Panel;
            FlowLayoutPanel bar = Theme.Bar(46);
            bFile = Theme.Btn("Load file…", true); bPaste = Theme.Btn("Paste…", false); bClear = Theme.Btn("Clear", false); bRun = Theme.Btn("Check reachability", true); bCancel = Theme.Btn("Cancel", false); bCancel.Enabled = false;
            bFile.Click += delegate { string f = Dialogs.PickFile(this, "The file of domains and IPs", "Lists (*.txt;*.csv;*.log)|*.txt;*.csv;*.log|All files|*.*"); if (f != null) { try { AddLines(File.ReadAllLines(f)); } catch (Exception ex) { Host.Error("Could not read the file", ex.Message); } } };
            bPaste.Click += delegate { string t = Dialogs.PasteText(this, "Paste domains and IPs", "One per line or mixed in prose; URLs and defanged names are fine."); if (t != null) AddLines(t.Split('\n')); };
            bClear.Click += delegate { rows.Clear(); view.SetItems(new object[0], false); };
            bRun.Click += delegate { Run(); }; bCancel.Click += delegate { if (engine != null) engine.Cancel(); };
            Label lp = Theme.Lbl("ports", Theme.Dim, Theme.UI); tPorts = Theme.Text("80, 443", 120); Label lt = Theme.Lbl("timeout s", Theme.Dim, Theme.UI); nTimeout = Theme.Num(3, 1, 30, 56); Label lc = Theme.Lbl("parallel", Theme.Dim, Theme.UI); nConc = Theme.Num(32, 1, 256, 60); cPing = Theme.Toggle("ping", true);
            prog.Width = Theme.S(160); prog.Height = Theme.S(10); prog.Margin = new Padding(Theme.S(10), Theme.S(12), Theme.S(8), 0); prog.Style = ProgressBarStyle.Continuous; prog.Visible = false;
            foreach (Control c in new Control[] { bFile, bPaste, bClear, lp, tPorts, lt, nTimeout, lc, nConc, cPing, bRun, bCancel, prog, status }) bar.Controls.Add(c);
            status.Margin = new Padding(Theme.S(6), Theme.S(9), 0, 0);
            view = NewView("reachability"); SetCols(new int[] { 80, 443 });
            view.SelectionChanged += delegate { sel.Update(view.SelectedCount, "target"); };
            sel.Add("Send to blocker", true, delegate { List<string> v = new List<string>(); foreach (object o in view.Targets) v.Add(((ReachRow)o).Value); Host.ShowTool<BlockerPanel>(delegate (BlockerPanel b) { b.AddValues(v, "reachability check"); }); });
            sel.Add("Re-check selected", false, delegate { List<ReachRow> l = new List<ReachRow>(); foreach (object o in view.Targets) l.Add((ReachRow)o); Run(l); });
            sel.Add("Remove", false, delegate { List<object> t = view.Targets; foreach (object o in t) rows.Remove((ReachRow)o); view.Remove(t); });
            sel.Add("Export selected", false, delegate { view.Export(); });
            Controls.Add(view); Controls.Add(sel); Controls.Add(bar); view.BringToFront();
        }
        void SetCols(int[] ports) { view.Apply(Columns.Reach(ports)); }
        int[] ParsePorts() { List<int> l = new List<int>(); foreach (string s in Regex.Split(tPorts.Text, @"[,\s;]+")) { int p; if (int.TryParse(s.Trim(), out p) && p > 0 && p < 65536 && !l.Contains(p)) l.Add(p); } return l.ToArray(); }
        public void AddLines(IEnumerable<string> lines)
        {
            HashSet<string> have = new HashSet<string>(StringComparer.OrdinalIgnoreCase); foreach (ReachRow r in rows) have.Add(r.Value);
            List<ReachRow> added = new List<ReachRow>();
            foreach (Target t in Extractor.Extract(lines)) { if (!have.Add(t.Value)) continue; ReachRow r = new ReachRow(); r.Target = t; rows.Add(r); added.Add(r); }
            view.Add(Boxed(added)); if (Host != null) Host.Toast(added.Count + " target" + (added.Count == 1 ? "" : "s") + " added", added.Count == 0);
        }
        void Run() { Run(rows); }
        void Run(List<ReachRow> which)
        {
            if (engine != null && bCancel.Enabled) { Host.Toast("A check is already running.", true); return; }
            if (which.Count == 0) { Host.Toast("Load or paste some targets first.", true); return; }
            int[] ports = ParsePorts(); SetCols(ports);
            foreach (ReachRow r in which) { r.Status = "checking"; r.Done = false; r.Ports.Clear(); r.Resolved.Clear(); r.DnsMs = -1; r.DnsError = null; r.PingMs = -2; }
            view.Invalidate2();
            engine = new Reach(); engine.Ports = ports; engine.TimeoutSec = (double)nTimeout.Value; engine.Concurrency = (int)nConc.Value; engine.DoPing = cPing.Checked;
            prog.Visible = true; prog.Value = 0; prog.Maximum = which.Count; bCancel.Enabled = true; bRun.Enabled = false; status.Text = "checking " + which.Count + " target(s)…";
            engine.Progress += delegate (int d, int t) { BeginInvoke((Action)delegate { prog.Value = Math.Min(d, prog.Maximum); status.Text = d + " / " + t; view.Invalidate2(); }); };
            engine.Finished += delegate { BeginInvoke((Action)delegate { bCancel.Enabled = false; bRun.Enabled = true; prog.Visible = false; int ok = 0; foreach (ReachRow r in rows) if (r.Status == "reachable") ok++; status.Text = "done · " + ok + " of " + rows.Count + " reachable"; view.Invalidate2(); }); };
            engine.Run(new List<ReachRow>(which));
        }
        /// <summary>Fabricated reachability results for screenshots (nothing is resolved or connected to).</summary>
        void DemoReach()
        {
            rows.Clear(); tPorts.Text = "80, 443"; SetCols(new int[] { 80, 443 }); int line = 1;
            Action<string, Kind, int, string, int, int, int, string> add = delegate (string value, Kind kind, int dnsMs, string resolved, int pingMs, int ms80, int ms443, string st)
            {
                ReachRow row = new ReachRow(); Target t = new Target(); t.Value = value; t.Kind = kind; t.Source = "targets.txt"; t.Line = line++; row.Target = t;
                row.DnsMs = dnsMs; if (dnsMs < 0) row.DnsError = "no such host"; if (!string.IsNullOrEmpty(resolved)) row.Resolved.Add(resolved); row.PingMs = pingMs;
                if (dnsMs >= 0 && kind != Kind.Invalid) { PortResult a = new PortResult(); a.Port = 80; a.Ok = ms80 >= 0; a.Ms = Math.Max(0, ms80); if (!a.Ok) a.Error = "refused"; row.Ports[80] = a; PortResult b = new PortResult(); b.Port = 443; b.Ok = ms443 >= 0; b.Ms = Math.Max(0, ms443); if (!b.Ok) b.Error = "timed out"; row.Ports[443] = b; }
                row.Status = st; row.Done = true; rows.Add(row);
            };
            add("cdn.example.com", Kind.Domain, 12, "203.0.113.10", 18, 21, 24, "reachable");
            add("api.example.net", Kind.Domain, 9, "198.51.100.40", -1, -1, 33, "reachable");
            add("updates.vendor.example", Kind.Domain, 22, "203.0.113.77", 31, 35, 36, "reachable");
            add("print-server", Kind.Domain, 3, "192.168.1.20", 2, 3, -1, "reachable");
            add("malware-c2.net", Kind.Domain, 15, "185.220.101.4", -1, -1, 210, "reachable");
            add("203.0.113.9", Kind.IPv4, 0, "203.0.113.9", 40, -1, -1, "ping only");
            add("192.0.2.1", Kind.IPv4, 0, "192.0.2.1", -1, -1, -1, "unreachable");
            add("2001:db8:dead:beef::1", Kind.IPv6, 0, "2001:db8:dead:beef::1", -1, -1, -1, "unreachable");
            add("intranet.local", Kind.Domain, -1, "", -2, -1, -1, "no DNS");
            add("invalid..name", Kind.Invalid, -1, "", -2, -1, -1, "invalid");
            view.SetItems(Boxed(rows), false); status.Text = rows.Count + " targets · 5 reachable · 1 ping only · 2 unreachable · 1 no DNS · 1 invalid";
        }

        public override void SelfTest(StringBuilder r)
        {
            if (r == null) { DemoReach(); return; }
            TcpListener lis = new TcpListener(IPAddress.Loopback, 0); lis.Start(); int port = ((IPEndPoint)lis.LocalEndpoint).Port;
            try
            {
                rows.Clear(); view.SetItems(new object[0], false);
                AddLines(new string[] { "127.0.0.1", "google.com", "192.0.2.1 (documentation range, never answers)", "invalid..name" });
                tPorts.Text = port.ToString(); cPing.Checked = false; nTimeout.Value = 2;
                if (r == null) { Run(); return; }
                Reach e = new Reach(); e.Ports = new int[] { port }; e.TimeoutSec = 2; e.DoPing = false; e.Concurrency = 4; ManualResetEvent done = new ManualResetEvent(false); e.Finished += delegate { done.Set(); };
                e.Run(new List<ReachRow>(rows)); done.WaitOne(20000); view.Invalidate2();
                ReachRow lo = rows.Find(delegate (ReachRow x) { return x.Value == "127.0.0.1"; }), dg = rows.Find(delegate (ReachRow x) { return x.Value == "google.com"; }), doc = rows.Find(delegate (ReachRow x) { return x.Value == "192.0.2.1"; });
                r.AppendLine((lo != null && lo.Status == "reachable" ? "PASS" : "FAIL") + " reachability: 127.0.0.1:" + port + " → " + (lo == null ? "missing" : lo.Status));
                r.AppendLine((dg != null && dg.Resolved.Count > 0 ? "PASS" : "INFO") + " reachability: google.com resolves to " + (dg == null ? "?" : string.Join(",", dg.Resolved.ToArray())) + " → " + (dg == null ? "" : dg.Status));
                r.AppendLine((doc != null && doc.Status == "unreachable" ? "PASS" : "FAIL") + " reachability: 192.0.2.1 → " + (doc == null ? "missing" : doc.Status) + " (timeout expected)");
                r.AppendLine((rows.Count == 3 ? "PASS" : "FAIL") + " reachability: 'invalid..name' was not extracted (" + rows.Count + " rows)");
            }
            finally { lis.Stop(); }
        }
    }

    // ═══════════════════════════════ 3 · Connections Monitor ═══════════════════════════════
    public class ConnPanel : ToolPanel
    {
        public override string Title { get { return Tools.Title(GetType().Name); } }
        public override string Blurb { get { return Tools.Blurb(GetType().Name); } }
        readonly DataView view; readonly SelectionBar sel = new SelectionBar(); readonly Dictionary<string, Conn> conns = new Dictionary<string, Conn>(); readonly NameCache names = new NameCache(); readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer();
        readonly Button bRun; readonly ComboBox cInterval, cProto, cState; readonly CheckBox cLoop, cResolve, cKeep; readonly TextBox tProc; readonly Label status = Theme.Lbl("", Theme.Dim, Theme.UISmall); bool running;
        public ConnPanel()
        {
            BackColor = Theme.Panel;
            FlowLayoutPanel bar = Theme.Bar(46);
            bRun = Theme.Btn("Pause", true); bRun.Click += delegate { running = !running; bRun.Text = running ? "Pause" : "Resume"; if (running) Tick(); };
            Label li = Theme.Lbl("every", Theme.Dim, Theme.UI); cInterval = Theme.Combo(70, "1 s", "2 s", "5 s"); cInterval.SelectedIndexChanged += delegate { timer.Interval = new int[] { 1000, 2000, 5000 }[cInterval.SelectedIndex]; };
            cProto = Theme.Combo(100, "TCP + UDP", "TCP only", "UDP only"); cState = Theme.Combo(130, "all states", "established", "listening", "other");
            cLoop = Theme.Toggle("loopback", false); cResolve = Theme.Toggle("resolve hosts", true); cKeep = Theme.Toggle("keep closed 30 s", true);
            Label lpz = Theme.Lbl("process", Theme.Dim, Theme.UI); tProc = Theme.Text("", 130);
            foreach (Control c in new Control[] { bRun, li, cInterval, cProto, cState, cLoop, cResolve, cKeep, lpz, tProc, status }) bar.Controls.Add(c);
            status.Margin = new Padding(Theme.S(10), Theme.S(9), 0, 0);
            cProto.SelectedIndexChanged += delegate { view.Refilter(); }; cState.SelectedIndexChanged += delegate { view.Refilter(); }; cLoop.CheckedChanged += delegate { view.Refilter(); }; tProc.TextChanged += delegate { view.Refilter(); };
            view = NewView("connections");
            view.Apply(Columns.Connections());
            view.Filter = delegate (object o)
            {
                Conn c = (Conn)o;
                if (cProto.SelectedIndex == 1 && !c.Proto.StartsWith("TCP")) return false; if (cProto.SelectedIndex == 2 && !c.Proto.StartsWith("UDP")) return false;
                if (cState.SelectedIndex == 1 && c.State != "ESTABLISHED") return false; if (cState.SelectedIndex == 2 && c.State != "LISTENING") return false; if (cState.SelectedIndex == 3 && (c.State == "ESTABLISHED" || c.State == "LISTENING")) return false;
                if (!cLoop.Checked && c.Loopback) return false;
                string pf = tProc.Text.Trim(); if (pf.Length > 0 && (c.Process ?? "").IndexOf(pf, StringComparison.OrdinalIgnoreCase) < 0) return false;
                return true;
            };
            view.SelectionChanged += delegate { sel.Update(view.SelectedCount, "connection"); };
            sel.Add("Block remote IPs", true, delegate { List<string> v = new List<string>(); foreach (object o in view.Targets) { Conn c = (Conn)o; if (c.Remote.Length > 0 && !c.Loopback && !v.Contains(c.Remote)) v.Add(c.Remote); } if (v.Count == 0) { Host.Toast("The selected rows have no remote address.", true); return; } Host.ShowTool<BlockerPanel>(delegate (BlockerPanel b) { b.AddValues(v, "connections monitor"); }); });
            sel.Add("Copy remote IPs", false, delegate { List<string> v = new List<string>(); foreach (object o in view.Targets) { Conn c = (Conn)o; if (c.Remote.Length > 0 && !v.Contains(c.Remote)) v.Add(c.Remote); } if (v.Count > 0) Clipboard.SetText(string.Join("\r\n", v.ToArray())); Host.Toast(v.Count + " address(es) copied", false); });
            sel.Add("Export selected", false, delegate { view.Export(); });
            names.HostResolved += delegate { try { BeginInvoke((Action)delegate { foreach (Conn c in conns.Values) if (c.Host == "…") c.Host = names.HostOf(c.Remote); view.Invalidate2(); }); } catch { } };
            timer.Interval = 1000; timer.Tick += delegate { if (running) Tick(); };
            Controls.Add(view); Controls.Add(sel); Controls.Add(bar); view.BringToFront();
        }
        public override void OnShown() { running = true; bRun.Text = "Pause"; Tick(); timer.Start(); }
        public override void OnHidden() { timer.Stop(); running = false; }
        void Tick()
        {
            DateTime now = DateTime.Now; List<Conn> snap = ConnTable.Snapshot(true, true); HashSet<string> seen = new HashSet<string>();
            foreach (Conn c in snap)
            {
                seen.Add(c.Key); Conn cur;
                if (conns.TryGetValue(c.Key, out cur)) { cur.LastSeen = now; cur.State = c.State; cur.Alive = true; }
                else { c.Process = names.ProcessName(c.Pid); c.Host = cResolve.Checked && c.Remote.Length > 0 && !c.Loopback ? names.HostOf(c.Remote) : ""; conns[c.Key] = c; }
            }
            List<string> drop = new List<string>();
            foreach (KeyValuePair<string, Conn> kv in conns) { if (seen.Contains(kv.Key)) continue; kv.Value.Alive = false; if (!cKeep.Checked || (now - kv.Value.LastSeen).TotalSeconds > 30) drop.Add(kv.Key); }
            foreach (string k in drop) conns.Remove(k);
            List<Conn> all = new List<Conn>(conns.Values); all.Sort(delegate (Conn a, Conn b) { int r = b.Alive.CompareTo(a.Alive); if (r != 0) return r; r = string.Compare(a.Process, b.Process, StringComparison.OrdinalIgnoreCase); if (r != 0) return r; return a.LocalPort.CompareTo(b.LocalPort); });
            view.SetItems(Boxed(all), true);
            int est = 0, lis = 0; foreach (Conn c in all) { if (c.State == "ESTABLISHED") est++; if (c.State == "LISTENING") lis++; }
            status.Text = all.Count + " endpoints · " + est + " established · " + lis + " listening · " + now.ToString("HH:mm:ss");
        }
        /// <summary>Fabricated endpoints for screenshots (demo mode never reads the real connection table).</summary>
        void DemoConns()
        {
            List<Conn> l = new List<Conn>(); DateTime now = DateTime.Now;
            Action<string, string, int, string, int, string, string, int, bool, int> add = delegate (string proto, string local, int lport, string remote, int rport, string state, string proc, int pid, bool alive, int minsAgo)
            { Conn c = new Conn(); c.Proto = proto; c.Local = local; c.LocalPort = lport; c.Remote = remote; c.RemotePort = rport; c.State = state; c.Process = proc; c.Pid = pid; c.Alive = alive; c.FirstSeen = now.AddMinutes(-minsAgo); c.LastSeen = alive ? now : now.AddSeconds(-12); c.Host = remote == "142.250.80.46" ? "lhr48s29-in-f14.1e100.net" : remote == "151.101.1.69" ? "prod.fastly.net" : ""; l.Add(c); };
            add("TCP", "192.168.1.42", 52344, "142.250.80.46", 443, "ESTABLISHED", "chrome", 4312, true, 14);
            add("TCP", "192.168.1.42", 52350, "13.107.42.14", 443, "ESTABLISHED", "svchost", 1180, true, 41);
            add("TCP", "192.168.1.42", 52360, "151.101.1.69", 443, "ESTABLISHED", "firefox", 7720, true, 3);
            add("TCP", "192.168.1.42", 52377, "203.0.113.9", 8886, "ESTABLISHED", "Code", 9932, true, 1);
            add("TCP", "192.168.1.42", 52381, "198.51.100.23", 443, "TIME_WAIT", "", 0, false, 2);
            add("TCP", "0.0.0.0", 445, "", 0, "LISTENING", "System", 4, true, 120);
            add("TCP", "0.0.0.0", 3389, "", 0, "LISTENING", "svchost", 1180, true, 120);
            add("TCP", "127.0.0.1", 9333, "127.0.0.1", 52400, "ESTABLISHED", "chrome", 4312, true, 9);
            add("UDP", "0.0.0.0", 5353, "", 0, "bound", "chrome", 4312, true, 14);
            add("UDP", "192.168.1.42", 51820, "", 0, "bound", "tailscaled", 2210, true, 118);
            view.SetItems(Boxed(l), false); status.Text = l.Count + " endpoints · 5 established · 2 listening · " + now.ToString("HH:mm:ss");
        }

        public override void SelfTest(StringBuilder r)
        {
            if (r == null) { DemoConns(); return; }
            TcpListener lis = new TcpListener(IPAddress.Loopback, 0); lis.Start(); int port = ((IPEndPoint)lis.LocalEndpoint).Port;
            try
            {
                cLoop.Checked = true; Tick();
                if (r == null) return;
                bool found = false; foreach (Conn c in conns.Values) if (c.Proto == "TCP" && c.LocalPort == port && c.State == "LISTENING" && c.Pid == Process.GetCurrentProcess().Id) found = true;
                r.AppendLine((found ? "PASS" : "FAIL") + " connections: our own listener on 127.0.0.1:" + port + " appears with our PID (" + conns.Count + " endpoints total)");
                bool anyEst = false; foreach (Conn c in conns.Values) if (c.State == "ESTABLISHED") anyEst = true; r.AppendLine("INFO connections: established=" + anyEst + " · processes named=" + (conns.Count > 0));
            }
            finally { lis.Stop(); }
        }
    }

    // ═══════════════════════════════ 4 · Process Hogs ═══════════════════════════════
    public class HogsPanel : ToolPanel
    {
        public override string Title { get { return Tools.Title(GetType().Name); } }
        public override string Blurb { get { return Tools.Blurb(GetType().Name); } }
        readonly DataView view; readonly SelectionBar sel = new SelectionBar(); readonly ProcSampler sampler = new ProcSampler(); readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer();
        readonly Button bRun, bReset; readonly ComboBox cInterval; readonly CheckBox cGroup; readonly Gauge gCpu = new Gauge(), gRam = new Gauge(), gIo = new Gauge(); readonly Label status = Theme.Lbl("", Theme.Dim, Theme.UISmall); bool running;
        public HogsPanel()
        {
            BackColor = Theme.Panel;
            FlowLayoutPanel bar = Theme.Bar(46);
            bRun = Theme.Btn("Pause", true); bRun.Click += delegate { running = !running; bRun.Text = running ? "Pause" : "Resume"; };
            bReset = Theme.Btn("Reset counters", false); bReset.Click += delegate { sampler.Reset(); Tick(); };
            Label li = Theme.Lbl("every", Theme.Dim, Theme.UI); cInterval = Theme.Combo(70, "1 s", "2 s", "5 s"); cInterval.SelectedIndexChanged += delegate { timer.Interval = new int[] { 1000, 2000, 5000 }[cInterval.SelectedIndex]; };
            cGroup = Theme.Toggle("group by name", true); cGroup.CheckedChanged += delegate { view.SetItems(new object[0], false); Tick(); };
            foreach (Control c in new Control[] { bRun, bReset, li, cInterval, cGroup, status }) bar.Controls.Add(c); status.Margin = new Padding(Theme.S(10), Theme.S(9), 0, 0);
            TableLayoutPanel gauges = new TableLayoutPanel(); gauges.Dock = DockStyle.Top; gauges.Height = Theme.S(58); gauges.ColumnCount = 3; gauges.BackColor = Theme.Line; gauges.Padding = new Padding(0, 0, 0, 1);
            for (int i = 0; i < 3; i++) gauges.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33.3f));
            gCpu.Label = "CPU"; gRam.Label = "MEMORY"; gRam.Bar = Theme.Amber; gIo.Label = "DISK I/O"; gIo.Bar = Theme.Blue;
            foreach (Gauge g in new Gauge[] { gCpu, gRam, gIo }) { g.Dock = DockStyle.Fill; g.Margin = new Padding(0, 0, 1, 0); gauges.Controls.Add(g); }
            view = NewView("process-hogs");
            view.Apply(Columns.Processes());
            view.SelectionChanged += delegate { sel.Update(view.SelectedCount, "process"); };
            sel.Add("Open file location", false, delegate { foreach (object o in view.Targets) { ProcRow p = (ProcRow)o; if (p.Pid == 0) continue; try { Dialogs.OpenInExplorer(Process.GetProcessById(p.Pid).MainModule.FileName); } catch (Exception ex) { Host.Toast(p.Name + ": " + ex.Message, true); } } });
            sel.Add("Loaded modules…", false, delegate { ProcRow p = null; foreach (object o in view.Targets) { ProcRow r = (ProcRow)o; if (r.Pid > 4) { p = r; break; } } if (p == null) { Host.Toast("Pick a process with a PID (switch off \"group by name\").", true); return; } ModuleViewer.Show(Host, p.Pid, p.Name); });
            sel.AddDanger("End selected processes…", delegate
            {
                List<ProcRow> l = new List<ProcRow>(); foreach (object o in view.Targets) { ProcRow p = (ProcRow)o; if (p.Alive && p.Pid > 4) l.Add(p); }
                if (l.Count == 0) { Host.Toast("Pick live processes with a PID (by-PID view).", true); return; }
                if (!Host.Confirm("End " + l.Count + " process(es)?", "This kills them without saving anything they hold open.\n\n" + string.Join("\n", l.ConvertAll(delegate (ProcRow p) { return p.Name + " [" + p.Pid + "]"; }).ToArray()))) return;
                int ok = 0; foreach (ProcRow p in l) { try { Process.GetProcessById(p.Pid).Kill(); ok++; } catch (Exception ex) { Host.Toast(p.Name + ": " + ex.Message, true); } } Host.Toast(ok + " ended", false);
            });
            sel.Add("Export selected", false, delegate { view.Export(); });
            timer.Interval = 1000; timer.Tick += delegate { if (running) Tick(); };
            Controls.Add(view); Controls.Add(sel); Controls.Add(gauges); Controls.Add(bar); view.BringToFront();
        }
        public override void OnShown() { running = true; bRun.Text = "Pause"; Tick(); timer.Start(); }
        public override void OnHidden() { timer.Stop(); running = false; }
        void Tick()
        {
            sampler.Sample();
            List<ProcRow> rows = cGroup.Checked ? sampler.Grouped() : new List<ProcRow>(sampler.Procs.Values);
            rows.Sort(delegate (ProcRow a, ProcRow b) { return b.CpuCum.CompareTo(a.CpuCum); });
            view.SetItems(Boxed(rows), true);
            gCpu.Value = sampler.SysCpu.ToString("N1") + " %"; gCpu.Fraction = sampler.SysCpu / 100; gCpu.History = sampler.SysCpuHist; gCpu.Invalidate();
            gRam.Value = Fmt.Bytes(sampler.RamUsed) + " / " + Fmt.Bytes(sampler.RamTotal); gRam.Fraction = sampler.RamTotal > 0 ? sampler.RamUsed / sampler.RamTotal : 0; gRam.Invalidate();
            double ioMax = 10; foreach (double v in sampler.SysIoHist) if (v > ioMax) ioMax = v; gIo.Value = (sampler.SysIo / 1048576.0).ToString("N1") + " MB/s"; gIo.Fraction = sampler.SysIo / 1048576.0 / ioMax; gIo.History = sampler.SysIoHist; gIo.Invalidate();
            status.Text = "since " + sampler.StartedAt.ToString("HH:mm:ss") + " · " + sampler.Ticks + " samples · " + sampler.Procs.Count + " processes tracked";
        }
        /// <summary>Fabricated process rows and gauges for screenshots.</summary>
        void DemoProcs()
        {
            List<ProcRow> l = new List<ProcRow>(); Random rnd = new Random(3);
            Action<string, int, double, double, double, double, double, double, bool> add = delegate (string name, int pid, double cpuPct, double cpuCum, double memMb, double ioRmb, double ioWmb, double ioRate, bool alive)
            { ProcRow p = new ProcRow(); p.Name = name; p.Pid = pid; p.CpuPct = cpuPct; p.CpuCum = cpuCum; p.MemCur = memMb * 1048576; p.MemPeak = memMb * 1048576 * 1.25; p.IoCumR = ioRmb * 1048576; p.IoCumW = ioWmb * 1048576; p.IoRate = ioRate * 1048576; p.Alive = alive; p.FirstSeen = DateTime.Now.AddMinutes(-40); p.LastSeen = DateTime.Now; for (int i = 0; i < 20; i++) p.CpuHist.Add(Math.Max(0, cpuPct + Math.Sin(i * 0.7 + pid) * cpuPct * 0.6 + rnd.NextDouble() * 2)); l.Add(p); };
            add("chrome", 4312, 12.4, 184.2, 1180, 2140, 340, 1.2, true);
            add("msedgewebview2", 6108, 6.1, 96.7, 610, 420, 88, 0.3, true);
            add("Code", 9932, 4.8, 72.0, 890, 310, 120, 0.1, true);
            add("MsMpEng", 3120, 3.9, 61.5, 240, 5100, 12, 2.8, true);
            add("svchost", 1180, 1.2, 40.3, 96, 180, 40, 0.0, true);
            add("explorer", 6120, 0.9, 31.8, 150, 60, 15, 0.0, true);
            add("steam", 8850, 0.6, 18.2, 420, 900, 210, 0.0, true);
            add("Spotify", 7420, 0.4, 12.1, 310, 150, 20, 0.1, true);
            add("SearchHost", 5230, 0.0, 8.4, 0, 30, 4, 0.0, false);
            double total = 0; foreach (ProcRow p in l) total += p.CpuCum; foreach (ProcRow p in l) p.Share = total > 0 ? p.CpuCum / total : 0;
            view.SetItems(Boxed(l), false);
            gCpu.Value = "31.2 %"; gCpu.Fraction = 0.312; gCpu.History = new List<double>(); for (int i = 0; i < 40; i++) gCpu.History.Add(18 + 12 * Math.Sin(i * 0.4) + rnd.NextDouble() * 6); gCpu.Invalidate();
            gRam.Value = "11.4 GB / 32.0 GB"; gRam.Fraction = 0.356; gRam.Invalidate();
            gIo.Value = "4.3 MB/s"; gIo.Fraction = 0.43; gIo.History = new List<double>(); for (int i = 0; i < 40; i++) gIo.History.Add(Math.Abs(3 + 4 * Math.Sin(i * 0.9)) + rnd.NextDouble()); gIo.Invalidate();
            status.Text = "since 09:12:04 · 2,412 samples · 9 processes tracked";
        }

        public override void SelfTest(StringBuilder r)
        {
            if (r == null) { DemoProcs(); return; }
            sampler.Sample(); Thread.Sleep(400); Tick();
            ProcRow me = null; foreach (ProcRow p in sampler.Procs.Values) if (p.Pid == Process.GetCurrentProcess().Id) me = p;
            r.AppendLine((me != null && me.MemCur > 0 ? "PASS" : "FAIL") + " process hogs: our own process is tracked (" + (me == null ? "missing" : Fmt.Bytes(me.MemCur) + " working set, cpu time " + Fmt.Secs(me.CpuCum)) + ")");
            r.AppendLine((sampler.RamTotal > 0 && sampler.Ticks >= 2 ? "PASS" : "FAIL") + " process hogs: system memory " + Fmt.Bytes(sampler.RamUsed) + " of " + Fmt.Bytes(sampler.RamTotal) + ", " + sampler.Ticks + " samples, " + sampler.Procs.Count + " processes");
            bool ioAny = false; foreach (ProcRow p in sampler.Procs.Values) if (p.IoCumR + p.IoCumW > 0 || p.IoLastR > 0) ioAny = true; r.AppendLine((ioAny ? "PASS" : "WARN") + " process hogs: disk I/O counters readable for at least one process");
        }
    }

    // ═══════════════════════════════ 5 · Storage Hogs ═══════════════════════════════
    public class DiskPanel : ToolPanel
    {
        public override string Title { get { return Tools.Title(GetType().Name); } }
        public override string Blurb { get { return Tools.Blurb(GetType().Name); } }
        readonly DataView view; readonly SelectionBar sel = new SelectionBar(); readonly Storage storage = new Storage(); readonly ComboBox cTarget, cShow; readonly Button bFolder, bScan, bCancel; readonly NumericUpDown nMin; readonly Label status = Theme.Lbl("", Theme.Dim, Theme.UISmall); readonly System.Windows.Forms.Timer prog = new System.Windows.Forms.Timer(); Thread worker; string customFolder;
        public DiskPanel()
        {
            BackColor = Theme.Panel;
            FlowLayoutPanel bar = Theme.Bar(46);
            Label lt = Theme.Lbl("scan", Theme.Dim, Theme.UI); cTarget = Theme.Combo(220); bFolder = Theme.Btn("Folder…", false); bFolder.Click += delegate { string f = Dialogs.PickFolder(this, "Folder to scan", null); if (f != null) { customFolder = f; if (!cTarget.Items.Contains(f)) cTarget.Items.Add(f); cTarget.SelectedItem = f; } };
            Label lm = Theme.Lbl("files ≥", Theme.Dim, Theme.UI); nMin = Theme.Num(50, 0, 100000, 70); Label lmb = Theme.Lbl("MB", Theme.Dim, Theme.UI);
            bScan = Theme.Btn("Scan", true); bScan.Click += delegate { Scan(); }; bCancel = Theme.Btn("Cancel", false); bCancel.Enabled = false; bCancel.Click += delegate { storage.Cancel = true; };
            Label ls = Theme.Lbl("show", Theme.Dim, Theme.UI); cShow = Theme.Combo(150, "largest files", "folders", "file types"); cShow.SelectedIndexChanged += delegate { ShowRows(); };
            foreach (Control c in new Control[] { lt, cTarget, bFolder, lm, nMin, lmb, bScan, bCancel, ls, cShow, status }) bar.Controls.Add(c); status.Margin = new Padding(Theme.S(10), Theme.S(9), 0, 0);
            view = NewView("storage");
            view.SelectionChanged += delegate { sel.Update(view.SelectedCount, "item"); };
            view.Activated += delegate (object o) { Node n = o as Node; if (n != null) Dialogs.OpenInExplorer(n.Path); };
            sel.Add("Open in Explorer", true, delegate { int k = 0; foreach (object o in view.Targets) { Node n = o as Node; if (n != null && k++ < 8) Dialogs.OpenInExplorer(n.Path); } });
            sel.Add("Copy paths", false, delegate { List<string> l = new List<string>(); foreach (object o in view.Targets) { Node n = o as Node; if (n != null) l.Add(n.Path); } if (l.Count > 0) Clipboard.SetText(string.Join("\r\n", l.ToArray())); Host.Toast(l.Count + " path(s) copied", false); });
            sel.Add("Export selected", false, delegate { view.Export(); });
            sel.AddDanger("Move to Recycle Bin…", delegate
            {
                List<Node> l = new List<Node>(); long bytes = 0; foreach (object o in view.Targets) { Node n = o as Node; if (n != null) { l.Add(n); bytes += n.Size; } }
                if (l.Count == 0) return;
                if (!Host.Confirm("Move " + l.Count + " item(s) to the Recycle Bin?", Fmt.Bytes(bytes) + " in total. They can be restored from the Recycle Bin afterwards.\n\n" + string.Join("\n", l.GetRange(0, Math.Min(12, l.Count)).ConvertAll(delegate (Node n) { return n.Path; }).ToArray()) + (l.Count > 12 ? "\n… and " + (l.Count - 12) + " more" : ""))) return;
                int ok = 0; foreach (Node n in l) { try { if (n.IsDir) Microsoft.VisualBasic.FileIO.FileSystem.DeleteDirectory(n.Path, Microsoft.VisualBasic.FileIO.UIOption.OnlyErrorDialogs, Microsoft.VisualBasic.FileIO.RecycleOption.SendToRecycleBin); else Microsoft.VisualBasic.FileIO.FileSystem.DeleteFile(n.Path, Microsoft.VisualBasic.FileIO.UIOption.OnlyErrorDialogs, Microsoft.VisualBasic.FileIO.RecycleOption.SendToRecycleBin); ok++; } catch (Exception ex) { Host.Toast(n.Name + ": " + ex.Message, true); } }
                Host.Toast(ok + " item(s) moved to the Recycle Bin - scan again to refresh the numbers", false);
            });
            prog.Interval = 400; prog.Tick += delegate { status.Text = storage.TotalFiles.ToString("N0") + " files · " + Fmt.Bytes(storage.TotalBytes) + " · " + storage.Clock.Elapsed.TotalSeconds.ToString("N0") + " s"; };
            Controls.Add(view); Controls.Add(sel); Controls.Add(bar); view.BringToFront();
        }
        public override void OnShown() { if (cTarget.Items.Count == 0) { foreach (DriveInfoRow d in Drives.List()) if (!string.IsNullOrEmpty(d.Fs)) cTarget.Items.Add(d.Letter + ":\\  " + d.Fs + "  " + (d.Label.Length > 0 ? d.Label + "  " : "") + Fmt.Bytes(d.Size - d.Free) + " used of " + Fmt.Bytes(d.Size)); if (cTarget.Items.Count > 0) cTarget.SelectedIndex = 0; } }
        string TargetPath { get { string s = cTarget.SelectedItem as string; if (s == null) return null; if (s.Length > 3 && s[1] == ':' && s[2] == '\\' && s[3] == ' ') return s.Substring(0, 3); return s; } }
        void Scan()
        {
            string root = TargetPath; if (root == null || !Directory.Exists(root)) { Host.Toast("Pick a drive or a folder.", true); return; }
            if (worker != null && worker.IsAlive) { Host.Toast("A scan is running.", true); return; }
            storage.MinFileBytes = (long)nMin.Value * 1048576L; bScan.Enabled = false; bCancel.Enabled = true; prog.Start(); view.SetItems(new object[0], false);
            worker = new Thread(delegate () { try { storage.Scan(root); } catch (Exception ex) { BeginInvoke((Action)delegate { Host.Error("Scan failed", ex.Message); }); } BeginInvoke((Action)delegate { prog.Stop(); bScan.Enabled = true; bCancel.Enabled = false; status.Text = storage.TotalFiles.ToString("N0") + " files in " + storage.TotalDirs.ToString("N0") + " folders · " + Fmt.Bytes(storage.TotalBytes) + " · " + storage.Clock.Elapsed.TotalSeconds.ToString("N1") + " s" + (storage.Denied > 0 ? " · " + storage.Denied + " not readable" : "") + (storage.Cancel ? " · cancelled" : ""); ShowRows(); }); });
            worker.IsBackground = true; worker.Start();
        }
        public override void Exercise(StringBuilder r)
        {
            for (int i = 2; i >= 0; i--) { try { if (view.VisibleItems.Count > 0) view.SetCurrent(0, 1); cShow.SelectedIndex = i; Application.DoEvents(); ExerciseView(view, r); } catch (Exception ex) { r.AppendLine("FAIL ui disk/" + i + ": " + ex.GetType().Name + ": " + ex.Message); } }
        }
        void ShowRows()
        {
            if (storage.Root == null) return;
            if (cShow.SelectedIndex == 2)
            {
                view.Apply(Columns.DiskTypes(delegate { return storage.TotalBytes; }));
                List<ExtStat> l = new List<ExtStat>(storage.ByExt.Values); l.Sort(delegate (ExtStat a, ExtStat b) { return b.Bytes.CompareTo(a.Bytes); }); view.SetItems(Boxed(l), false); return;
            }
            bool dirs = cShow.SelectedIndex == 1;
            view.Apply(Columns.DiskNodes(dirs, delegate { return storage.Root == null ? null : storage.Root.Path; }));
            List<Node> src = dirs ? storage.AllDirs : storage.LargestFiles; view.SetItems(Boxed(src), false);
        }
        /// <summary>A fabricated drive scan for screenshots.</summary>
        void DemoDisk()
        {
            Node root = new Node(); root.Name = "C:\\"; root.Path = "C:\\"; root.IsDir = true; root.Size = 412L * 1073741824; root.Files = 388102; root.Dirs = 41220; root.Modified = DateTime.Now;
            storage.Root = root; storage.TotalBytes = root.Size; storage.TotalFiles = root.Files; storage.TotalDirs = root.Dirs; storage.LargestFiles.Clear(); storage.AllDirs.Clear(); storage.ByExt.Clear();
            Func<string, long, bool, int, Node> N = delegate (string path, long size, bool dir, int files) { Node n = new Node(); n.Path = path; n.Name = path.TrimEnd('\\').Substring(path.TrimEnd('\\').LastIndexOf('\\') + 1); n.IsDir = dir; n.Size = size; n.Files = files; n.Dirs = dir ? Math.Max(1, files / 40) : 0; n.Modified = DateTime.Now.AddDays(-(size % 90)); n.Parent = root; return n; };
            storage.LargestFiles.Add(N(@"C:\Users\alice\Videos\conference-2026.mp4", 14L * 1073741824, false, 0));
            storage.LargestFiles.Add(N(@"C:\Users\alice\VirtualMachines\ubuntu-lab.vhdx", 38L * 1073741824, false, 0));
            storage.LargestFiles.Add(N(@"C:\hiberfil.sys", 12L * 1073741824, false, 0));
            storage.LargestFiles.Add(N(@"C:\pagefile.sys", 8L * 1073741824, false, 0));
            storage.LargestFiles.Add(N(@"C:\Users\alice\Downloads\Win11_24H2.iso", 5L * 1073741824 + 300000000, false, 0));
            storage.LargestFiles.Add(N(@"C:\Users\alice\AppData\Local\Docker\wsl\ext4.vhdx", 4L * 1073741824, false, 0));
            storage.LargestFiles.Add(N(@"C:\Users\alice\Pictures\RAW\2026-08-trip.zip", 2L * 1073741824 + 700000000, false, 0));
            storage.LargestFiles.Add(N(@"C:\Program Files\Adobe\Photoshop\Photoshop.exe", 900000000, false, 0));
            storage.LargestFiles.Sort(delegate (Node x, Node y) { return y.Size.CompareTo(x.Size); });
            storage.AllDirs.Add(N(@"C:\Users", 168L * 1073741824, true, 210400)); storage.AllDirs.Add(N(@"C:\Program Files", 61L * 1073741824, true, 88120)); storage.AllDirs.Add(N(@"C:\Windows", 34L * 1073741824, true, 71200)); storage.AllDirs.Add(N(@"C:\ProgramData", 12L * 1073741824, true, 9800)); storage.AllDirs.Add(N(@"C:\Users\alice\VirtualMachines", 52L * 1073741824, true, 6));
            string[] exts = { "vhdx", "mp4", "sys", "iso", "zip", "exe", "dll", "jpg", "pdf", "docx" }; long[] bytes = { 94L * 1073741824, 61L * 1073741824, 21L * 1073741824, 19L * 1073741824, 16L * 1073741824, 14L * 1073741824, 11L * 1073741824, 8L * 1073741824, 3L * 1073741824, 1L * 1073741824 }; int[] counts = { 3, 412, 18, 4, 260, 2210, 18450, 22100, 1840, 3100 };
            for (int i = 0; i < exts.Length; i++) { ExtStat e = new ExtStat(); e.Ext = exts[i]; e.Bytes = bytes[i]; e.Count = counts[i]; storage.ByExt[exts[i]] = e; }
            if (!cTarget.Items.Contains("C:\\  NTFS  Windows")) cTarget.Items.Add("C:\\  NTFS  Windows"); cTarget.SelectedItem = "C:\\  NTFS  Windows"; cShow.SelectedIndex = 0; ShowRows();
        }

        public override void SelfTest(StringBuilder r)
        {
            if (r == null) { DemoDisk(); return; }
            string here = Path.GetDirectoryName(Application.ExecutablePath); storage.MinFileBytes = 0; storage.Scan(here); cShow.SelectedIndex = 0; if (!cTarget.Items.Contains(here)) cTarget.Items.Add(here); cTarget.SelectedItem = here; ShowRows();
            if (r == null) return;
            r.AppendLine((storage.TotalFiles >= 5 && storage.TotalBytes > 100000 ? "PASS" : "FAIL") + " storage: scanned " + here + " → " + storage.TotalFiles + " files, " + Fmt.Bytes(storage.TotalBytes) + ", largest " + (storage.LargestFiles.Count > 0 ? storage.LargestFiles[0].Name + " " + Fmt.Bytes(storage.LargestFiles[0].Size) : "-"));
            long sum = 0; foreach (Node n in storage.Root.Children) sum += n.Size; r.AppendLine((storage.Root.Size == storage.TotalBytes ? "PASS" : "FAIL") + " storage: root size equals the sum of everything (" + storage.Root.Size + " = " + storage.TotalBytes + ")");
            cShow.SelectedIndex = 1; ShowRows(); view.SetView("tree"); r.AppendLine("PASS storage: folder tree built with " + storage.AllDirs.Count + " folder rows"); view.SetView("grid"); cShow.SelectedIndex = 2; ShowRows(); r.AppendLine((storage.ByExt.ContainsKey("cs") ? "PASS" : "FAIL") + " storage: by-type view has .cs files"); cShow.SelectedIndex = 0; ShowRows();
        }
    }

    // ═══════════════════════════════ 6 · Deleted Files Finder ═══════════════════════════════
    public class DeletedPanel : ToolPanel
    {
        public override string Title { get { return Tools.Title(GetType().Name); } }
        public override string Blurb { get { return Tools.Blurb(GetType().Name); } }
        public override bool NeedsAdmin { get { return Tools.Admin(GetType().Name); } }
        readonly DataView view; readonly SelectionBar sel = new SelectionBar(); readonly FlowLayoutPanel drives = new FlowLayoutPanel(); readonly List<CheckBox> driveBoxes = new List<CheckBox>(); readonly List<DriveInfoRow> driveRows = new List<DriveInfoRow>();
        readonly NumericUpDown nDays, nMin, nMax; readonly TextBox tPath, tExt, tName; readonly StepStrip steps = new StepStrip(); readonly CheckBox cNoise, cShadow, cRecov; readonly ComboBox cSource, cUnit; readonly Button bScan, bCancel; readonly Label status = Theme.Lbl("", Theme.Dim, Theme.UISmall); readonly Panel binPanel = new Panel(); readonly FlowLayoutPanel binFlow = new FlowLayoutPanel();
        readonly List<DeletedScan> scans = new List<DeletedScan>(); Thread worker; volatile bool cancel;
        public DeletedPanel()
        {
            BackColor = Theme.Panel;
            FlowLayoutPanel bar = Theme.Bar(46);
            Label ld = Theme.Lbl("drives", Theme.Dim, Theme.UI); drives.AutoSize = true; drives.WrapContents = false; drives.BackColor = Theme.Panel; drives.Margin = new Padding(0);
            Label lday = Theme.Lbl("last", Theme.Dim, Theme.UI); nDays = Theme.Num(30, 1, 3650, 60); Label ldays = Theme.Lbl("days", Theme.Dim, Theme.UI);
            Label lp = Theme.Lbl("under", Theme.Dim, Theme.UI); tPath = Theme.Text("", 170);
            ToolTip tip = new ToolTip(); tip.AutoPopDelay = 12000;
            Label lty = Theme.Lbl("type", Theme.Dim, Theme.UI); tExt = Theme.Text("", 96); tip.SetToolTip(tExt, "Only files of these extensions, comma-separated (e.g. jpg, png, docx). Leave empty for all.");
            Label lnm = Theme.Lbl("name has", Theme.Dim, Theme.UI); tName = Theme.Text("", 120); tip.SetToolTip(tName, "Only entries whose name contains this text.");
            Label lsz = Theme.Lbl("size", Theme.Dim, Theme.UI); nMin = Theme.Num(0, 0, 999999, 56); Label lsz2 = Theme.Lbl("to", Theme.Dim, Theme.UI); nMax = Theme.Num(0, 0, 999999, 56); cUnit = Theme.Combo(56, "KB", "MB", "GB"); cUnit.SelectedIndex = 1; tip.SetToolTip(nMin, "Size range (0 = no limit) in the chosen unit. Applies to exFAT files; the NTFS change journal does not record size, so those rows are not size-filtered.");
            cNoise = Theme.Toggle("include noise", false); cShadow = Theme.Toggle("shadow copies", true);
            bScan = Theme.Btn("Scan", true); bScan.Click += delegate { Scan(); }; bCancel = Theme.Btn("Cancel", false); bCancel.Enabled = false; bCancel.Click += delegate { cancel = true; };
            foreach (Control c in new Control[] { ld, drives, lday, nDays, ldays, lp, tPath, lty, tExt, lnm, tName, lsz, nMin, lsz2, nMax, cUnit, cNoise, cShadow, bScan, bCancel, status }) bar.Controls.Add(c); status.Margin = new Padding(Theme.S(10), Theme.S(9), 0, 0);
            // the emptied-from-the-bin strip
            binPanel.Dock = DockStyle.Top; binPanel.AutoSize = true; binPanel.BackColor = Theme.Side; binPanel.Visible = false; binPanel.Padding = new Padding(Theme.S(10), Theme.S(6), Theme.S(10), Theme.S(6));
            Label bt = Theme.Cap("emptied from the Recycle Bin"); bt.Dock = DockStyle.Top; bt.Margin = new Padding(0);
            binFlow.Dock = DockStyle.Top; binFlow.AutoSize = true; binFlow.BackColor = Theme.Side; binFlow.WrapContents = true;
            binPanel.Controls.Add(binFlow); binPanel.Controls.Add(bt);
            view = NewView("deleted-files");
            view.Apply(Columns.Deleted());
            Label lsrc = Theme.Lbl("source", Theme.Dim, Theme.UI); cSource = Theme.Combo(110, "all", "journal", "exFAT"); cRecov = Theme.Toggle("recoverable only", false);
            view.Extra.Controls.Add(lsrc); view.Extra.Controls.Add(cSource); view.Extra.Controls.Add(cRecov); cSource.SelectedIndexChanged += delegate { view.Refilter(); }; cRecov.CheckedChanged += delegate { view.Refilter(); };
            view.Filter = delegate (object o) { DeletedRow d = (DeletedRow)o; if (cSource.SelectedIndex == 1 && d.Source != "journal") return false; if (cSource.SelectedIndex == 2 && d.Source != "exFAT") return false; if (cRecov.Checked && !d.Recoverable) return false; return true; };
            view.SelectionChanged += delegate { sel.Update(view.SelectedCount, "entry"); };
            sel.Add("Recover selected to…", true, delegate { Recover(); });
            sel.Add("Copy paths", false, delegate { List<string> l = new List<string>(); foreach (object o in view.Targets) l.Add(((DeletedRow)o).Path); if (l.Count > 0) Clipboard.SetText(string.Join("\r\n", l.ToArray())); Host.Toast(l.Count + " path(s) copied", false); });
            sel.Add("Export selected", false, delegate { view.Export(); });
            Controls.Add(view); Controls.Add(sel); Controls.Add(binPanel); Controls.Add(steps); Controls.Add(bar); view.BringToFront();
        }
        public override void OnShown() { if (driveBoxes.Count == 0) LoadDrives(); }
        void LoadDrives()
        {
            driveRows.Clear(); driveRows.AddRange(Drives.List()); drives.Controls.Clear(); driveBoxes.Clear();
            foreach (DriveInfoRow d in driveRows)
            {
                CheckBox c = Theme.Toggle(d.Letter + ":  " + (string.IsNullOrEmpty(d.Fs) ? "no media" : d.Fs), d.Journalable || d.ExFat); c.Enabled = d.Journalable || d.ExFat; c.Checked = c.Enabled; c.ForeColor = c.Enabled ? Theme.Ink : Theme.Faint; c.Margin = new Padding(0, Theme.S(6), Theme.S(10), 0);
                new ToolTip().SetToolTip(c, d.Why + (d.Label.Length > 0 ? " · " + d.Label : "") + " · " + Fmt.Bytes(d.Size)); drives.Controls.Add(c); driveBoxes.Add(c);
            }
        }
        void Scan()
        {
            if (worker != null && worker.IsAlive) { Host.Toast("A scan is running.", true); return; }
            List<DriveInfoRow> chosen = new List<DriveInfoRow>(); for (int i = 0; i < driveBoxes.Count; i++) if (driveBoxes[i].Checked && driveBoxes[i].Enabled) chosen.Add(driveRows[i]);
            if (chosen.Count == 0) { Host.Toast("Tick at least one drive.", true); return; }
            bool needAdmin = false; foreach (DriveInfoRow d in chosen) if (d.Journalable) needAdmin = true;
            if (needAdmin && !Host.IsElevated) { if (Host.NeedAdmin("Reading the change journal of an NTFS drive")) return; }
            foreach (DeletedScan s in scans) s.Close(); scans.Clear(); view.SetItems(new object[0], false); binFlow.Controls.Clear(); binPanel.Visible = false;
            cancel = false; bScan.Enabled = false; bCancel.Enabled = true; int days = (int)nDays.Value; string pathFilter = tPath.Text.Trim(); bool noise = cNoise.Checked, shadows = cShadow.Checked;
            string ext = tExt.Text.Trim(), nameHas = tName.Text.Trim(); long unit = cUnit.SelectedIndex == 0 ? 1024L : cUnit.SelectedIndex == 2 ? 1073741824L : 1048576L; long minB = (long)nMin.Value * unit, maxB = (long)nMax.Value * unit;
            bool filtered = ext.Length > 0 || nameHas.Length > 0 || minB > 0 || maxB > 0;
            List<string> letters = new List<string>(); foreach (DriveInfoRow d in chosen) letters.Add(d.Letter + ":");
            steps.Begin(letters.ToArray());
            worker = new Thread(delegate ()
            {
                List<string> summary = new List<string>();
                foreach (DriveInfoRow d in chosen)
                {
                    if (cancel) { BeginInvoke((Action)delegate { steps.Set(d.Letter + ":", "skipped", null); }); continue; }
                    BeginInvoke((Action)delegate { steps.Set(d.Letter + ":", "running", null); });
                    DeletedScan s = new DeletedScan(); s.Drive = d; s.Days = days; s.PathFilter = pathFilter; s.ShowNoise = noise; s.CheckShadows = shadows; s.ExtFilter = ext; s.NameContains = nameHas; s.MinBytes = minB; s.MaxBytes = maxB; s.Cancelled = delegate { return cancel; };
                    s.Progress += delegate (string msg) { try { BeginInvoke((Action)delegate { status.Text = d.Letter + ": " + msg; steps.Say(d.Letter + ": " + msg); }); } catch { } };
                    try { s.Run(); } catch (Exception ex) { s.Message = ex.Message; }
                    scans.Add(s);
                    string line = d.Letter + ": " + s.Rows.Count.ToString("N0") + (filtered ? " matching" : "") + " entries";
                    if (s.Journal != null && s.Journal.Active) line += " · journal sees back " + s.Journal.CoverageDays.ToString("N1") + " days (" + s.Journal.Records.ToString("N0") + " records)" + (s.Journal.CoverageDays < days ? " - shorter than your window" : "");
                    if (s.Ex != null) line += " · " + s.Ex.IntactCount.ToString("N0") + " files intact (" + Fmt.Bytes(s.Ex.IntactBytes) + ")";
                    if (s.NoiseHidden > 0) line += " · " + s.NoiseHidden.ToString("N0") + " noise hidden"; if (s.Message.Length > 0) line += " · " + s.Message;
                    summary.Add(line); DeletedScan sc0 = s; string note = s.Rows.Count.ToString("N0") + (filtered ? " match" : "") + (s.Message.Length > 0 ? " · " + s.Message : "");
                    BeginInvoke((Action)delegate { steps.Set(d.Letter + ":", sc0.Message.Length > 0 && sc0.Rows.Count == 0 ? "failed" : "done", note); List<object> all = new List<object>(); foreach (DeletedScan sc in scans) foreach (DeletedRow r in sc.Rows) all.Add(r); view.SetItems(all, false); ShowBins(); status.Text = string.Join("   ", summary.ToArray()); });
                }
                BeginInvoke((Action)delegate { bScan.Enabled = true; bCancel.Enabled = false; int total = 0; foreach (DeletedScan sc in scans) total += sc.Rows.Count; steps.End((cancel ? "cancelled · " : "done · ") + total.ToString("N0") + (filtered ? " matching" : "") + " deleted ent(ries) across " + scans.Count + " drive(s)"); if (summary.Count == 0) status.Text = "nothing scanned"; });
            });
            worker.IsBackground = true; worker.Start();
        }
        void ShowBins()
        {
            binFlow.Controls.Clear(); int n = 0;
            foreach (DeletedScan s in scans) foreach (BinItem b in s.Bins)
                {
                    if (n++ >= 8) break;
                    Panel card = new Panel(); card.BackColor = Theme.Panel2; card.Width = Theme.S(330); card.Height = Theme.S(58); card.Margin = new Padding(0, 0, Theme.S(8), Theme.S(4));
                    Label t = Theme.Lbl(b.Name.Length > 46 ? "…" + b.Name.Substring(b.Name.Length - 45) : b.Name, Theme.Ink, Theme.UIBold); t.Location = new Point(Theme.S(8), Theme.S(6)); t.AutoSize = false; t.Width = card.Width - Theme.S(16); t.AutoEllipsis = true;
                    Label d = Theme.Lbl((b.IsDir ? "folder" : "file") + " · " + (b.When.HasValue ? "deleted " + b.When.Value.ToString("yyyy-MM-dd HH:mm") : "deletion time unknown") + (b.Named ? "" : " · original name lost") + "\n" + b.Files.ToString("N0") + " files inside, " + b.Intact.ToString("N0") + " intact (" + Fmt.Bytes(b.Bytes) + ")" + (b.Empty > 0 ? ", " + b.Empty.ToString("N0") + " empty" : ""), Theme.Dim, Theme.UISmall); d.Location = new Point(Theme.S(8), Theme.S(26)); d.AutoSize = false; d.Width = card.Width - Theme.S(16); d.Height = Theme.S(30);
                    new ToolTip().SetToolTip(t, b.Name); card.Controls.Add(t); card.Controls.Add(d);
                    string id = b.Id; card.Cursor = Cursors.Hand; card.Click += delegate { List<object> l = new List<object>(); foreach (object o in view.VisibleItems) if (((DeletedRow)o).BinId == id) l.Add(o); view.Select(l, true); Host.Toast(l.Count + " entries of that item selected", false); };
                    binFlow.Controls.Add(card);
                }
            binPanel.Visible = binFlow.Controls.Count > 0;
        }
        void Recover()
        {
            List<DeletedRow> l = new List<DeletedRow>(); foreach (object o in view.Targets) { DeletedRow d = (DeletedRow)o; if (d.Recoverable) l.Add(d); }
            if (l.Count == 0) { Host.Toast("None of the selected entries is recoverable.", true); return; }
            string dest = Dialogs.PickFolder(this, "Folder to copy the recovered files into - on ANOTHER drive than the one they come from", Host.Settings.Get("deleted.dest", "")); if (dest == null) return; Host.Settings.Set("deleted.dest", dest);
            long bytes = 0; foreach (DeletedRow d in l) bytes += d.Size;
            if (!Host.Confirm("Recover " + l.Count + " file(s)?", Fmt.Bytes(bytes) + " will be copied into\n" + dest + "\n\nkeeping the folder structure. The source drive is never written to.")) return;
            int ok = 0, fail = 0; string firstErr = null;
            foreach (DeletedRow d in l)
            {
                DeletedScan s = scans.Find(delegate (DeletedScan x) { return x.Rows.Contains(d); }); if (s == null) { fail++; continue; }
                try { s.Recover(d, dest); ok++; } catch (Exception ex) { fail++; if (firstErr == null) firstErr = ex.Message; }
            }
            view.Invalidate2();
            Host.Info("Recovery", ok + " file(s) copied to " + dest + (fail > 0 ? "\n" + fail + " failed" + (firstErr != null ? ": " + firstErr : "") : "") + "\n\nOpen a few to confirm they are whole; a file whose clusters were reused will look damaged.");
        }
        /// <summary>Fabricated journal / exFAT / Recycle Bin rows for screenshots.</summary>
        void DemoDeleted()
        {
            List<object> all = new List<object>(); DateTime now = DateTime.Now;
            Action<int, string, string, string, string, string, long, bool, string> add = delegate (int hoursAgo, string type, string path, string source, string state, string note, long size, bool rec, string drive)
            { DeletedRow d = new DeletedRow(); d.When = now.AddHours(-hoursAgo); d.Type = type; d.Path = path; d.Source = source; d.State = state; d.Note = note; d.Size = size; d.Recoverable = rec; d.Drive = drive; all.Add(d); };
            add(2, "file", @"C:\Users\alice\Documents\contract-draft.docx", "USN journal", "deleted", "not in a shadow copy", 48 * 1024, false, "C");
            add(5, "file", @"C:\Users\alice\Downloads\installer-setup.exe", "USN journal", "deleted", "", 12 * 1048576, false, "C");
            add(9, "folder", @"C:\Users\alice\Desktop\old-photos", "USN journal", "deleted", "folder with 214 entries", 0, false, "C");
            add(26, "file", @"C:\Users\alice\AppData\Local\Temp\~report.tmp", "USN journal", "deleted", "temporary file", 3 * 1048576, false, "C");
            add(30, "file", @"C:\Users\alice\Documents\budget-2025.xlsx", "Recycle Bin", "in bin", "restorable from the Recycle Bin", 210 * 1024, true, "C");
            add(48, "file", @"E:\DCIM\100CANON\IMG_0042.JPG", "exFAT directory table", "intact", "data still on disk - copy it out now", 6 * 1048576, true, "E");
            add(50, "file", @"E:\DCIM\100CANON\IMG_0043.JPG", "exFAT directory table", "overwritten", "clusters reused by a newer file", 6 * 1048576, false, "E");
            add(120, "file", @"C:\Users\alice\Pictures\wallpaper.png", "shadow copy", "recoverable", "present in the 2026-09-10 shadow copy", 2 * 1048576, true, "C");
            view.SetItems(all, false);
        }

        public override void SelfTest(StringBuilder r)
        {
            if (r == null) { DemoDeleted(); return; }
            LoadDrives();
            r.AppendLine((driveRows.Count > 0 ? "PASS" : "FAIL") + " deleted files: drives listed: " + string.Join(", ", driveRows.ConvertAll(delegate (DriveInfoRow d) { return d.Letter + ":" + d.Fs + "/" + d.Why; }).ToArray()));
            DriveInfoRow ex = driveRows.Find(delegate (DriveInfoRow d) { return d.ExFat; });
            if (ex != null)
            {
                DeletedScan s = new DeletedScan(); s.Drive = ex; s.Days = 30; s.ShowNoise = false; s.CheckShadows = false;
                Stopwatch sw = Stopwatch.StartNew(); s.Run(); sw.Stop();
                r.AppendLine((s.Rows.Count > 0 ? "PASS" : "WARN") + " deleted files: exFAT " + ex.Letter + ": " + s.Rows.Count.ToString("N0") + " entries, " + s.Bins.Count + " bin items, " + (s.Ex != null ? s.Ex.IntactCount.ToString("N0") + " intact" : "no reader") + " in " + sw.Elapsed.TotalSeconds.ToString("N1") + " s " + s.Message);
                foreach (BinItem b in s.Bins) r.AppendLine("INFO   bin: " + b.Name + " · " + (b.When.HasValue ? b.When.Value.ToString("s") : "?") + " · " + b.Files + " files, " + b.Intact + " intact");
                scans.Add(s); List<object> all = new List<object>(); foreach (DeletedRow d in s.Rows) all.Add(d); view.SetItems(all, false); ShowBins();
                DeletedRow first = s.Rows.Find(delegate (DeletedRow d) { return d.Recoverable && d.Size > 0 && d.Size < 200000; });
                if (first != null) { string tmp = Path.Combine(Path.GetTempPath(), "pstools-recover-test"); try { string dest = s.Recover(first, tmp); long len = new FileInfo(dest).Length; r.AppendLine((len == first.Size ? "PASS" : "FAIL") + " deleted files: recovered " + first.Name + " (" + len + " of " + first.Size + " bytes) to " + dest); Directory.Delete(tmp, true); } catch (Exception e2) { r.AppendLine("FAIL deleted files: recovery threw " + e2.Message); } }
            }
            else r.AppendLine("INFO deleted files: no exFAT drive to test the directory-table reader on");
            if (Host.IsElevated) { DriveInfoRow c = driveRows.Find(delegate (DriveInfoRow d) { return d.Letter == "C"; }); if (c != null) { DeletedScan s = new DeletedScan(); s.Drive = c; s.Days = 2; s.CheckShadows = false; s.Run(); r.AppendLine((s.Journal != null && s.Journal.Active ? "PASS" : "FAIL") + " deleted files: C: journal " + (s.Journal == null ? s.Message : s.Journal.Records.ToString("N0") + " records, " + s.Rows.Count + " deletions in 2 days, sees back " + s.Journal.CoverageDays.ToString("N1") + " days")); } }
            else r.AppendLine("INFO deleted files: not elevated, the journal read was skipped");
        }
    }
}

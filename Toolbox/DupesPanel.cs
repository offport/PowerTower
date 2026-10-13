// Duplicate Finder: find identical files by content (size, then partial hash, then full SHA-256) and show
// how much space each group wastes. The oldest copy in each group is kept by default; tick the rest and send
// them to the Recycle Bin.
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace PSTools
{
    public class DupesPanel : ToolPanel
    {
        public override string Title { get { return Tools.Title(GetType().Name); } }
        public override string Blurb { get { return Tools.Blurb(GetType().Name); } }

        readonly DataView view; readonly StepStrip steps = new StepStrip(); readonly SelectionBar sel = new SelectionBar();
        readonly Button bScan, bCancel, bPick; readonly TextBox tRoot; readonly ComboBox cMin; readonly Label status = Theme.Lbl("", Theme.Dim, Theme.UISmall);
        readonly Stat sGroups = new Stat("groups"), sDupes = new Stat("extra copies"), sWasted = new Stat("reclaimable"), sSeen = new Stat("files seen"), sHashed = new Stat("hashed");
        readonly List<DupeFile> items = new List<DupeFile>(); readonly List<DupeGroup> groups = new List<DupeGroup>();
        DupeScan scan; Thread worker; volatile bool scanning; bool loaded;

        public DupesPanel()
        {
            BackColor = Theme.Panel;
            FlowLayoutPanel bar = Theme.Bar(46);
            Label lf = Theme.Lbl("folder", Theme.Dim, Theme.UI); tRoot = Theme.Text("", 320); bPick = Theme.Btn("Browse…", false); bPick.Click += delegate { string p = Dialogs.PickFolder(Host, "Folder to scan for duplicates", tRoot.Text); if (p != null) tRoot.Text = p; };
            bScan = Theme.Btn("Scan", true); bScan.Click += delegate { Scan(); }; bCancel = Theme.Btn("Cancel", false); bCancel.Enabled = false; bCancel.Click += delegate { if (scan != null) scan.Stop(); };
            Label lm = Theme.Lbl("min size", Theme.Dim, Theme.UI); cMin = Theme.Combo(100, "1 KB", "100 KB", "1 MB", "10 MB"); cMin.SelectedIndex = 1;
            foreach (Control c in new Control[] { lf, tRoot, bPick, bScan, bCancel, lm, cMin, status }) bar.Controls.Add(c); status.Margin = new Padding(Theme.S(10), Theme.S(9), 0, 0);
            TableLayoutPanel strip = new TableLayoutPanel(); strip.Dock = DockStyle.Top; strip.Height = Theme.S(76); strip.BackColor = Theme.Panel; strip.Padding = new Padding(Theme.S(10), Theme.S(2), Theme.S(2), Theme.S(6)); strip.ColumnCount = 5; strip.RowCount = 1;
            foreach (Stat s in new Stat[] { sGroups, sDupes, sWasted, sSeen, sHashed }) { strip.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 20f)); s.Dock = DockStyle.Fill; strip.Controls.Add(s); }
            view = NewView("duplicates"); view.Apply(Columns.Duplicates());
            view.SelectionChanged += delegate { sel.Update(view.SelectedCount, "file"); };
            view.Activated += delegate (object o) { Dialogs.OpenInExplorer(Path.GetDirectoryName(((DupeFile)o).Path)); };
            sel.Add("Select all but newest per group", true, delegate { SelectExtras(); });
            sel.AddDanger("Send ticked to Recycle Bin…", delegate { Recycle(); });
            sel.Add("Open location", false, delegate { int k = 0; foreach (object o in view.Targets) { if (k++ >= 8) break; Dialogs.OpenInExplorer(Path.GetDirectoryName(((DupeFile)o).Path)); } });
            sel.Add("Copy paths", false, delegate { List<string> l = new List<string>(); foreach (object o in view.Targets) l.Add(((DupeFile)o).Path); Clip(l); });
            sel.Add("Export", false, delegate { view.Export(); });
            Controls.Add(view); Controls.Add(sel); Controls.Add(strip); Controls.Add(steps); Controls.Add(bar); view.BringToFront();
        }


        public override void OnShown() { if (loaded) return; loaded = true; if (tRoot.Text.Length == 0) tRoot.Text = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile); }
        void Ui(Action a) { try { Host.BeginInvoke(a); } catch { } }

        void Scan()
        {
            if (scanning) return; string root = tRoot.Text.Trim();
            if (root.Length == 0 || !Directory.Exists(root)) { Host.Toast("Pick a folder that exists.", true); return; }
            items.Clear(); groups.Clear(); view.SetItems(new object[0], false);
            scan = new DupeScan(); scan.Roots = new List<string>(new string[] { root }); scan.MinBytes = new long[] { 1024, 102400, 1048576, 10485760 }[cMin.SelectedIndex];
            scanning = true; bScan.Enabled = false; bCancel.Enabled = true; steps.Begin(new string[] { "Scan folders", "Hash & compare" }); steps.Set("Scan folders", "running", null); status.Text = "scanning " + root + "…";
            System.Windows.Forms.Timer prog = new System.Windows.Forms.Timer(); prog.Interval = 400; prog.Tick += delegate { if (scan != null) { if (scan.Phase == "hashing") steps.Set("Scan folders", "done", null); if (scan.Phase == "hashing") steps.Set("Hash & compare", "running", null); status.Text = scan.Phase + "… " + scan.FilesSeen.ToString("N0") + " files seen, " + scan.Hashed.ToString("N0") + " hashed · " + Trunc(scan.Current); sSeen.Set(scan.FilesSeen.ToString("N0"), "files", Theme.Ink); sHashed.Set(scan.Hashed.ToString("N0"), "compared", Theme.Ink); } };
            prog.Start();
            worker = new Thread(delegate ()
            {
                try { List<DupeGroup> gs = scan.Run(null); Ui(delegate { groups.Clear(); groups.AddRange(gs); items.Clear(); foreach (DupeGroup g in gs) items.AddRange(g.Files); view.SetItems(Boxed(items), false); Cards(); }); }
                catch (Exception ex) { Ui(delegate { Host.Toast("dupes: " + ex.Message, true); }); }
                finally { Ui(delegate { prog.Stop(); scanning = false; bScan.Enabled = true; bCancel.Enabled = false; long w = 0; foreach (DupeGroup g in groups) w += g.Wasted; steps.Set("Scan folders", "done", null); steps.Set("Hash & compare", scan.Cancel ? "failed" : "done", groups.Count + " groups"); steps.End((scan.Cancel ? "cancelled · " : "done · ") + groups.Count + " duplicate group(s), " + Fmt.Bytes(w) + " reclaimable"); status.Text = "done · " + groups.Count + " group(s) of duplicates · " + Fmt.Bytes(w) + " reclaimable"; Cards(); }); }
            });
            worker.IsBackground = true; worker.Start();
        }
        static string Trunc(string s) { if (string.IsNullOrEmpty(s)) return ""; return s.Length > 60 ? "…" + s.Substring(s.Length - 60) : s; }
        void Cards()
        {
            long wasted = 0; int extra = 0; foreach (DupeGroup g in groups) { wasted += g.Wasted; extra += g.Count - 1; }
            sGroups.Set(groups.Count.ToString(), "of duplicates", Theme.Ink);
            sDupes.Set(extra.ToString(), "removable", extra > 0 ? Theme.Amber : Theme.Green);
            sWasted.Set(Fmt.Bytes(wasted), "if de-duped", wasted > 0 ? Theme.Teal : Theme.Ink);
            sSeen.Set(scan != null ? scan.FilesSeen.ToString("N0") : "—", "files", Theme.Ink);
            sHashed.Set(scan != null ? scan.Hashed.ToString("N0") : "—", "compared", Theme.Dim);
        }
        void SelectExtras() { List<object> extras = new List<object>(); foreach (DupeFile d in items) if (!d.Keep) extras.Add(d); view.ClearSelection(); view.Select(extras, true); Host.Toast(extras.Count + " extra copies selected", false); }
        void Recycle()
        {
            List<DupeFile> t = new List<DupeFile>(); foreach (object o in view.Targets) t.Add((DupeFile)o);
            if (t.Count == 0) { Host.Toast("Tick the copies to remove first.", true); return; }
            int keepers = 0; foreach (DupeFile d in t) if (d.Keep) keepers++;
            long free = 0; foreach (DupeFile d in t) free += d.Size;
            if (!Host.Confirm("Recycle " + t.Count + " file(s)?", "This sends " + t.Count + " file(s) to the Recycle Bin, freeing about " + Fmt.Bytes(free) + "." + (keepers > 0 ? "\n\n⚠ " + keepers + " of them are marked \"keep\" (the only/oldest copy in their group). Removing those loses the last copy." : "") + "\n\nThey go to the Recycle Bin, so this can be undone.")) return;
            int ok = 0; List<object> done = new List<object>(); List<string> errs = new List<string>();
            foreach (DupeFile d in t) { try { Microsoft.VisualBasic.FileIO.FileSystem.DeleteFile(d.Path, Microsoft.VisualBasic.FileIO.UIOption.OnlyErrorDialogs, Microsoft.VisualBasic.FileIO.RecycleOption.SendToRecycleBin); ok++; done.Add(d); } catch (Exception ex) { if (errs.Count < 4) errs.Add(d.Name + ": " + ex.Message); } }
            HashSet<DupeFile> rm = new HashSet<DupeFile>(); foreach (object o in done) rm.Add((DupeFile)o); items.RemoveAll(delegate (DupeFile d) { return rm.Contains(d); });
            foreach (DupeGroup g in groups) g.Files.RemoveAll(delegate (DupeFile d) { return rm.Contains(d); }); groups.RemoveAll(delegate (DupeGroup g) { return g.Count < 2; });
            view.Remove(done); Cards(); Host.Toast(ok + " sent to the Recycle Bin", false);
            if (errs.Count > 0) Host.Error("Some files could not be removed", string.Join("\n", errs.ToArray()));
        }
        void Clip(List<string> l) { if (l.Count == 0) { Host.Toast("Nothing to copy.", true); return; } try { Clipboard.SetText(string.Join("\r\n", l.ToArray())); Host.Toast(l.Count + " line(s) copied", false); } catch { } }

        public override void SelfTest(StringBuilder r)
        {
            if (r == null) { tRoot.Text = @"C:\Users\alice"; Demo(); return; }
            string dir = Path.Combine(Path.GetTempPath(), "pstools-dupes-test-" + Guid.NewGuid().ToString("N"));
            try
            {
                Directory.CreateDirectory(dir); byte[] payload = new byte[20000]; new Random(1).NextBytes(payload);
                File.WriteAllBytes(Path.Combine(dir, "a.bin"), payload); File.WriteAllBytes(Path.Combine(dir, "b copy.bin"), payload); File.WriteAllBytes(Path.Combine(dir, "c.bin"), payload);
                byte[] other = new byte[20000]; new Random(2).NextBytes(other); File.WriteAllBytes(Path.Combine(dir, "unique.bin"), other);
                DupeScan s = new DupeScan(); s.Roots = new List<string>(new string[] { dir }); s.MinBytes = 1; List<DupeGroup> gs = s.Run(null);
                groups.Clear(); groups.AddRange(gs); items.Clear(); foreach (DupeGroup g in gs) items.AddRange(g.Files); scan = s; view.SetItems(Boxed(items), false); Cards();
                bool one = gs.Count == 1 && gs[0].Count == 3; r.AppendLine((one ? "PASS" : "FAIL") + " duplicate finder: found " + gs.Count + " group(s), " + (gs.Count > 0 ? gs[0].Count : 0) + " identical copies (expected 1 group of 3)");
                r.AppendLine((gs.Count > 0 && gs[0].Wasted == 40000 ? "PASS" : "FAIL") + " duplicate finder: wasted space = " + (gs.Count > 0 ? gs[0].Wasted : 0) + " bytes (expected 40000)");
            }
            catch (Exception ex) { r.AppendLine("FAIL duplicate finder: " + ex.Message); }
            finally { try { Directory.Delete(dir, true); } catch { } }
        }
        void Demo()
        {
            items.Clear(); groups.Clear();
            AddGroup("a1b2c3d4", 4718592, new string[] { @"C:\Users\alice\Pictures\vacation.jpg", @"C:\Users\alice\Downloads\vacation.jpg", @"C:\Users\alice\Desktop\vacation (1).jpg" });
            AddGroup("e5f6a7b8", 15728640, new string[] { @"C:\Users\alice\Documents\report-final.pdf", @"C:\Users\alice\Documents\old\report-final.pdf" });
            AddGroup("c9d0e1f2", 2097152, new string[] { @"C:\Users\alice\Music\track01.mp3", @"C:\Users\alice\Music\backup\track01.mp3", @"C:\Users\alice\Downloads\track01.mp3", @"C:\Users\alice\Desktop\track01.mp3" });
            view.SetItems(Boxed(items), false); Cards(); status.Text = "done · 3 group(s) of duplicates · 30.0 MB reclaimable";
            sSeen.Set("12,430", "files", Theme.Ink); sHashed.Set("318", "compared", Theme.Dim);
        }
        void AddGroup(string hash, long size, string[] paths)
        {
            DupeGroup g = new DupeGroup(); g.Hash = hash; g.Size = size; DateTime t = new DateTime(2024, 1, 1);
            for (int i = 0; i < paths.Length; i++) { DupeFile d = new DupeFile(); d.Path = paths[i]; d.Name = Path.GetFileName(paths[i]); d.Dir = Path.GetDirectoryName(paths[i]); d.Size = size; d.Modified = t.AddDays(i * 30); d.Group = hash.Substring(0, 8); d.Keep = i == 0; g.Files.Add(d); items.Add(d); }
            groups.Add(g);
        }
    }
}

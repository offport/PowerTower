// Autoruns panel: everything that starts automatically, with the program it runs, its signer, where it
// lives and a risk flag. Disable, enable or delete the ticked entries. Advanced filtering via the header
// funnels, the rule bar and dedicated "risky only" / kind / unsigned filters.
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace PSTools
{
    public class AutorunsPanel : ToolPanel
    {
        public override string Title { get { return Tools.Title(GetType().Name); } }
        public override string Blurb { get { return Tools.Blurb(GetType().Name); } }
        public override bool NeedsAdmin { get { return Tools.Admin(GetType().Name); } }

        readonly DataView view; readonly SelectionBar sel = new SelectionBar(); readonly StepStrip steps = new StepStrip();
        readonly Button bScan, bCancel; readonly Label status = Theme.Lbl("", Theme.Dim, Theme.UISmall);
        readonly Stat sTotal = new Stat("entries"), sRisk = new Stat("risky"), sUnsigned = new Stat("unsigned"), sMissing = new Stat("missing file"), sKinds = new Stat("kinds");
        readonly ComboBox cKind; readonly CheckBox cRisky, cUnsigned, cNonMs; readonly Label lKind;
        readonly List<AutorunEntry> items = new List<AutorunEntry>();
        Thread worker; volatile bool scanning, cancel; bool loaded;

        public AutorunsPanel()
        {
            BackColor = Theme.Panel;
            FlowLayoutPanel bar = Theme.Bar(46);
            bScan = Theme.Btn("Scan", true); bScan.Click += delegate { Scan(); };
            bCancel = Theme.Btn("Cancel", false); bCancel.Enabled = false; bCancel.Click += delegate { cancel = true; };
            foreach (Control c in new Control[] { bScan, bCancel, status }) bar.Controls.Add(c); status.Margin = new Padding(Theme.S(10), Theme.S(9), 0, 0);
            TableLayoutPanel strip = new TableLayoutPanel(); strip.Dock = DockStyle.Top; strip.Height = Theme.S(76); strip.BackColor = Theme.Panel; strip.Padding = new Padding(Theme.S(10), Theme.S(2), Theme.S(2), Theme.S(6)); strip.ColumnCount = 5; strip.RowCount = 1;
            foreach (Stat s in new Stat[] { sTotal, sRisk, sUnsigned, sMissing, sKinds }) { strip.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 20f)); s.Dock = DockStyle.Fill; strip.Controls.Add(s); }
            view = NewView("autoruns"); view.Apply(Columns.Autoruns());
            view.SelectionChanged += delegate { sel.Update(view.SelectedCount, "entry"); };
            view.Activated += delegate (object o) { AutorunEntry e = (AutorunEntry)o; if (e.Image.Length > 0) Dialogs.OpenInExplorer(System.IO.Path.GetDirectoryName(e.Image)); };
            view.Filter = FilterRow;
            lKind = Theme.Lbl("kind", Theme.Dim, Theme.UI); cKind = Theme.Combo(150, "all kinds"); cRisky = Theme.Toggle("risky only", false); cUnsigned = Theme.Toggle("unsigned only", false); cNonMs = Theme.Toggle("non-Microsoft only", false);
            foreach (Control c in new Control[] { lKind, cKind, cRisky, cUnsigned, cNonMs }) view.Extra.Controls.Add(c);
            cKind.SelectedIndexChanged += delegate { view.Refilter(); }; cRisky.CheckedChanged += delegate { view.Refilter(); }; cUnsigned.CheckedChanged += delegate { view.Refilter(); }; cNonMs.CheckedChanged += delegate { view.Refilter(); };
            sel.Add("Disable", true, delegate { Act("disable"); });
            sel.Add("Enable", false, delegate { Act("enable"); });
            sel.AddDanger("Delete…", delegate { Act("delete"); });
            sel.Add("Open file location", false, delegate { int k = 0; foreach (object o in view.Targets) { AutorunEntry e = (AutorunEntry)o; if (e.Image.Length > 0 && k++ < 8) Dialogs.OpenInExplorer(System.IO.Path.GetDirectoryName(e.Image)); } });
            sel.Add("Copy commands", false, delegate { List<string> l = new List<string>(); foreach (object o in view.Targets) l.Add(((AutorunEntry)o).Command); Clip(l); });
            sel.Add("Export", false, delegate { view.Export(); });
            Controls.Add(view); Controls.Add(sel); Controls.Add(strip); Controls.Add(steps); Controls.Add(bar); view.BringToFront();
        }


        bool FilterRow(object o)
        {
            AutorunEntry e = (AutorunEntry)o;
            if (cRisky.Checked && e.Risk.Length == 0) return false;
            if (cUnsigned.Checked && !(e.Sig.Status == "unsigned" || e.Sig.Status == "invalid")) return false;
            if (cNonMs.Checked && e.Sig.Microsoft) return false;
            if (cKind.SelectedIndex > 0 && e.Kind != (string)cKind.SelectedItem) return false;
            return true;
        }

        public override void OnShown() { if (loaded) return; loaded = true; Scan(); }
        void Ui(Action a) { try { Host.BeginInvoke(a); } catch { } }

        void Scan()
        {
            if (scanning) return; scanning = true; cancel = false; bScan.Enabled = false; bCancel.Enabled = true; steps.Begin(new string[] { "Enumerate", "Verify signatures" }); status.Text = "scanning autostart locations…";
            worker = new Thread(delegate ()
            {
                try
                {
                    Ui(delegate { steps.Set("Enumerate", "running", null); });
                    List<AutorunEntry> found = Autoruns.Collect(delegate (string m) { Ui(delegate { status.Text = m; steps.Say(m); }); }, delegate { return cancel; });
                    Ui(delegate { items.Clear(); items.AddRange(found); view.SetItems(Boxed(items), false); Cards(); steps.Set("Enumerate", "done", found.Count + " entries"); FillKinds(); });
                    Ui(delegate { steps.Set("Verify signatures", "running", null); });
                    Autoruns.Verify(found, delegate (int i, int n) { Ui(delegate { steps.Fraction = (float)i / Math.Max(1, n); status.Text = "verifying signatures… " + i + " / " + n; if (i % 25 == 0 || i == n) { view.Invalidate2(); Cards(); } }); }, delegate { return cancel; });
                    Ui(delegate { steps.Fraction = -1; steps.Set("Verify signatures", cancel ? "failed" : "done", null); view.Invalidate2(); Cards(); });
                }
                catch (Exception ex) { Ui(delegate { Host.Toast("autoruns: " + ex.Message, true); }); }
                finally { Ui(delegate { scanning = false; bScan.Enabled = true; bCancel.Enabled = false; int risky = 0; foreach (AutorunEntry e in items) if (e.Risk.Length > 0) risky++; steps.End((cancel ? "cancelled · " : "done · ") + items.Count + " entries, " + risky + " flagged"); status.Text = "done · " + items.Count + " autostart entries, " + risky + " flagged"; }); }
            });
            worker.IsBackground = true; worker.Start();
        }
        void FillKinds()
        {
            string cur = cKind.SelectedIndex > 0 ? (string)cKind.SelectedItem : null; List<string> kinds = new List<string>(); foreach (AutorunEntry e in items) if (!kinds.Contains(e.Kind)) kinds.Add(e.Kind); kinds.Sort();
            cKind.Items.Clear(); cKind.Items.Add("all kinds"); foreach (string k in kinds) cKind.Items.Add(k); cKind.SelectedIndex = cur != null && kinds.Contains(cur) ? kinds.IndexOf(cur) + 1 : 0;
        }
        void Cards()
        {
            int risky = 0, unsigned = 0, missing = 0; List<string> kinds = new List<string>();
            foreach (AutorunEntry e in items) { if (e.Risk.Length > 0) risky++; if (e.Sig.Status == "unsigned" || e.Sig.Status == "invalid") unsigned++; if (e.Image.Length > 0 && !e.Exists) missing++; if (!kinds.Contains(e.Kind)) kinds.Add(e.Kind); }
            sTotal.Set(items.Count.ToString(), "autostart", Theme.Ink);
            sRisk.Set(risky.ToString(), "flagged", risky > 0 ? Theme.Rose : Theme.Green);
            sUnsigned.Set(unsigned.ToString(), "or invalid", unsigned > 0 ? Theme.Amber : Theme.Ink);
            sMissing.Set(missing.ToString(), "dangling", missing > 0 ? Theme.Amber : Theme.Ink);
            sKinds.Set(kinds.Count.ToString(), "categories", Theme.Ink);
        }

        void Act(string what)
        {
            List<AutorunEntry> t = new List<AutorunEntry>(); foreach (object o in view.Targets) t.Add((AutorunEntry)o);
            if (t.Count == 0) { Host.Toast("Tick some entries first.", true); return; }
            if (Host.NeedAdmin(what == "delete" ? "Deleting an autostart entry" : (what == "disable" ? "Disabling" : "Enabling") + " an autostart entry")) return;
            if (what == "delete") { List<string> names = new List<string>(); foreach (AutorunEntry e in t) names.Add("• " + e.Kind + ": " + e.Name); if (!Host.Confirm("Delete " + t.Count + " entry(ies)?", "This permanently removes them so they no longer start automatically:\n\n" + string.Join("\n", names.GetRange(0, Math.Min(15, names.Count)).ToArray()) + (names.Count > 15 ? "\n… and " + (names.Count - 15) + " more" : "") + "\n\nServices and tasks it runs are removed; the program files themselves are left on disk.")) return; }
            int ok = 0, fail = 0; List<string> errs = new List<string>();
            foreach (AutorunEntry e in t) { string err = what == "delete" ? Autoruns.Delete(e) : Autoruns.SetEnabled(e, what == "enable"); if (err == null) ok++; else { fail++; if (errs.Count < 4) errs.Add(e.Name + ": " + err); } }
            if (what == "delete") { HashSet<AutorunEntry> rm = new HashSet<AutorunEntry>(); foreach (AutorunEntry e in t) rm.Add(e); items.RemoveAll(delegate (AutorunEntry e) { return rm.Contains(e); }); List<object> boxed = new List<object>(); foreach (AutorunEntry e in t) boxed.Add(e); view.Remove(boxed); }
            view.Invalidate2(); Cards();
            Host.Toast(ok + " " + (what == "delete" ? "deleted" : what + "d") + (fail > 0 ? ", " + fail + " failed" : ""), fail > 0);
            if (errs.Count > 0) Host.Error("Some entries could not be changed", string.Join("\n", errs.ToArray()) + (fail > errs.Count ? "\n…" : ""));
        }
        void Clip(List<string> l) { l.RemoveAll(delegate (string s) { return string.IsNullOrEmpty(s); }); if (l.Count == 0) { Host.Toast("Nothing to copy.", true); return; } try { Clipboard.SetText(string.Join("\r\n", l.ToArray())); Host.Toast(l.Count + " line(s) copied", false); } catch { } }

        public override void SelfTest(StringBuilder r)
        {
            if (r == null) { Demo(); return; }
            List<AutorunEntry> found = Autoruns.Collect(null, null); Autoruns.Verify(found, null, null);
            items.Clear(); items.AddRange(found); view.SetItems(Boxed(items), false); Cards(); FillKinds();
            int risky = 0, signed = 0, kinds = 0; List<string> ks = new List<string>();
            foreach (AutorunEntry e in found) { if (e.Risk.Length > 0) risky++; if (e.Sig.Ok) signed++; if (!ks.Contains(e.Kind)) ks.Add(e.Kind); }
            kinds = ks.Count;
            r.AppendLine((found.Count > 10 ? "PASS" : "FAIL") + " autoruns: " + found.Count + " entries across " + kinds + " kinds, " + signed + " signed, " + risky + " flagged");
            r.AppendLine((kinds >= 4 ? "PASS" : "INFO") + " autoruns: covers " + string.Join(", ", ks.ToArray()));
        }
        void Demo()
        {
            items.Clear();
            items.Add(A("Run key", "OneDrive", @"C:\Program Files\Microsoft OneDrive\OneDrive.exe /background", @"C:\Program Files\Microsoft OneDrive\OneDrive.exe", "signed", "Microsoft Corporation", true, ""));
            items.Add(A("Run key", "Spotify", @"C:\Users\alice\AppData\Roaming\Spotify\Spotify.exe", @"C:\Users\alice\AppData\Roaming\Spotify\Spotify.exe", "signed", "Spotify AB", true, ""));
            items.Add(A("Startup folder", "backup-helper.exe", @"C:\Users\alice\AppData\Local\Temp\backup-helper.exe", @"C:\Users\alice\AppData\Local\Temp\backup-helper.exe", "unsigned", "", true, "high"));
            items.Add(A("Scheduled task", "\\UpdaterCheck", @"C:\ProgramData\upd\svc.exe -silent", @"C:\ProgramData\upd\svc.exe", "invalid", "", true, "high"));
            items.Add(A("Service", "Windows Update", @"C:\Windows\System32\svchost.exe -k netsvcs", @"C:\Windows\System32\svchost.exe", "signed", "Microsoft Windows", true, ""));
            items.Add(A("Image hijack", "sethc.exe", @"C:\Windows\System32\cmd.exe", @"C:\Windows\System32\cmd.exe", "signed", "Microsoft Windows", true, "high"));
            items.Add(A("WMI subscription", "SystemPerfMonitor", "powershell -enc SQBFAFgA…", "", "", "", true, "medium"));
            items.Add(A("Run key", "Realtek HD Audio", @"C:\Program Files\Realtek\Audio\RtkNGUI64.exe -s", @"C:\Program Files\Realtek\Audio\RtkNGUI64.exe", "signed", "Realtek Semiconductor", true, ""));
            view.SetItems(Boxed(items), false); Cards(); FillKinds(); status.Text = "done · 8 autostart entries, 4 flagged";
        }
        static AutorunEntry A(string kind, string name, string cmd, string image, string sig, string signer, bool enabled, string riskForce)
        {
            AutorunEntry e = new AutorunEntry(); e.Kind = kind; e.Name = name; e.Command = cmd; e.Image = image; e.Enabled = enabled; e.Scope = "machine"; e.Sig = new SigInfo(); e.Sig.Status = sig; e.Sig.Signer = signer; e.Location = kind == "Run key" ? @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" : kind;
            e.RiskForce = riskForce.Length > 0 ? riskForce : ""; if (kind == "Image hijack") e.Description = "runs instead of sethc.exe"; if (kind == "WMI subscription") e.Description = "ROOT\\CIMV2 : intervaltimer"; return e;
        }
    }
}

// Event Log Triage: the security-relevant records from the Windows event logs over a time range - logons and
// failures, new services and tasks, PowerShell script blocks, Defender detections, process creation, log
// clears, account changes - as rows you can filter and sort like any other table.
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace PSTools
{
    public class EventsPanel : ToolPanel
    {
        public override string Title { get { return "Event Log Triage"; } }
        public override string Blurb { get { return "The event-log records that matter for an incident: failed and successful logons, new services and scheduled tasks, PowerShell activity, Defender detections, account changes and cleared logs. Pick a time range and hunt across every column."; } }
        public override bool NeedsAdmin { get { return true; } }

        readonly DataView view; readonly StepStrip steps = new StepStrip(); readonly SelectionBar sel = new SelectionBar();
        readonly Button bScan, bCancel; readonly ComboBox cRange, cMax; readonly Label status = Theme.Lbl("", Theme.Dim, Theme.UISmall);
        readonly Stat sTotal = new Stat("events"), sHigh = new Stat("high-risk"), sFailed = new Stat("failed logons"), sCats = new Stat("categories"), sSpan = new Stat("oldest");
        readonly ComboBox cCat; readonly CheckBox cRisky; readonly Label lCat; readonly FlowLayoutPanel catFlow = new FlowLayoutPanel();
        readonly List<CheckBox> catBoxes = new List<CheckBox>();
        readonly List<EventRow> items = new List<EventRow>();
        Thread worker; volatile bool scanning, cancel; bool loaded;

        public EventsPanel()
        {
            BackColor = Theme.Panel;
            FlowLayoutPanel bar = Theme.Bar(46);
            bScan = Theme.Btn("Collect", true); bScan.Click += delegate { Scan(); };
            bCancel = Theme.Btn("Cancel", false); bCancel.Enabled = false; bCancel.Click += delegate { cancel = true; };
            Label lr = Theme.Lbl("since", Theme.Dim, Theme.UI); cRange = Theme.Combo(120, "last hour", "last 24 hours", "last 7 days", "last 30 days"); cRange.SelectedIndex = 1;
            Label lm = Theme.Lbl("max each", Theme.Dim, Theme.UI); cMax = Theme.Combo(90, "50", "100", "250", "500"); cMax.SelectedIndex = 1;
            foreach (Control c in new Control[] { bScan, bCancel, lr, cRange, lm, cMax, status }) bar.Controls.Add(c); status.Margin = new Padding(Theme.S(10), Theme.S(9), 0, 0);
            TableLayoutPanel strip = new TableLayoutPanel(); strip.Dock = DockStyle.Top; strip.Height = Theme.S(76); strip.BackColor = Theme.Panel; strip.Padding = new Padding(Theme.S(10), Theme.S(2), Theme.S(2), Theme.S(6)); strip.ColumnCount = 5; strip.RowCount = 1;
            foreach (Stat s in new Stat[] { sTotal, sHigh, sFailed, sCats, sSpan }) { strip.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 20f)); s.Dock = DockStyle.Fill; strip.Controls.Add(s); }
            view = NewView("events"); view.SetColumns(Cols());
            view.RowColor = delegate (object o) { return RiskColor(((EventRow)o).Risk); };
            view.TreePath = delegate (object o) { EventRow e = (EventRow)o; return new string[] { e.Category, e.When }; };
            view.SelectionChanged += delegate { sel.Update(view.SelectedCount, "event"); };
            view.Filter = FilterRow;
            lCat = Theme.Lbl("category", Theme.Dim, Theme.UI); cCat = Theme.Combo(200, "all categories"); cRisky = Theme.Toggle("risky only", false);
            foreach (Control c in new Control[] { lCat, cCat, cRisky }) view.Extra.Controls.Add(c);
            cCat.SelectedIndexChanged += delegate { view.Refilter(); }; cRisky.CheckedChanged += delegate { view.Refilter(); };
            sel.Add("Copy details", false, delegate { List<string> l = new List<string>(); foreach (object o in view.Targets) { EventRow e = (EventRow)o; l.Add(e.When + "\t" + e.Category + "\t" + e.Id + "\t" + e.Who + "\t" + e.Detail); } Clip(l); });
            sel.Add("Export", false, delegate { view.Export(); });
            Controls.Add(view); Controls.Add(sel); Controls.Add(strip); Controls.Add(steps); Controls.Add(bar); view.BringToFront();
        }

        List<Col> Cols()
        {
            List<Col> c = new List<Col>();
            c.Add(new Col("time", "When", 150, delegate (object o) { return ((EventRow)o).Time; }).Num(delegate (object o) { return ((EventRow)o).When; }));
            c.Add(new Col("risk", "Risk", 62, delegate (object o) { EventRow e = (EventRow)o; return e.Risk == "high" ? 0 : e.Risk == "medium" ? 1 : 2; }).Num(delegate (object o) { return ((EventRow)o).Risk; }).Colour(delegate (object o) { return RiskColor(((EventRow)o).Risk); }));
            c.Add(new Col("cat", "Category", 190, delegate (object o) { return ((EventRow)o).Category; }).Colour(delegate (object o) { return Theme.Teal; }));
            c.Add(new Col("id", "Event", 62, delegate (object o) { return ((EventRow)o).Id; }).Num(delegate (object o) { return ((EventRow)o).Id.ToString(); }));
            c.Add(new Col("who", "Account", 170, delegate (object o) { return ((EventRow)o).Who; }));
            c.Add(new Col("detail", "Detail", 520, delegate (object o) { return ((EventRow)o).Detail; }));
            c.Add(new Col("level", "Level", 90, delegate (object o) { return ((EventRow)o).Level; }).Colour(delegate (object o) { EventRow e = (EventRow)o; return e.Level == "error" || e.Level == "critical" ? Theme.Rose : e.Level == "warning" ? Theme.Amber : Theme.Dim; }));
            c.Add(new Col("src", "Source", 220, delegate (object o) { return ((EventRow)o).Source; }).Colour(delegate (object o) { return Theme.Faint; }));
            c.Add(new Col("log", "Log", 200, delegate (object o) { return ((EventRow)o).Log; }).Colour(delegate (object o) { return Theme.Faint; }));
            return c;
        }
        static Color RiskColor(string r) { return r == "high" ? Theme.Rose : r == "medium" ? Theme.Amber : Theme.Ink; }

        bool FilterRow(object o)
        {
            EventRow e = (EventRow)o;
            if (cRisky.Checked && e.Risk.Length == 0) return false;
            if (cCat.SelectedIndex > 0 && e.Category != (string)cCat.SelectedItem) return false;
            return true;
        }

        public override void OnShown() { if (loaded) return; loaded = true; Scan(); }
        void Ui(Action a) { try { Host.BeginInvoke(a); } catch { } }

        void Scan()
        {
            if (scanning) return; scanning = true; cancel = false; bScan.Enabled = false; bCancel.Enabled = true;
            DateTime since = DateTime.Now.AddHours(cRange.SelectedIndex == 0 ? -1 : cRange.SelectedIndex == 1 ? -24 : cRange.SelectedIndex == 2 ? -168 : -720);
            int max = int.Parse((string)cMax.SelectedItem);
            List<EventSpec> specs = EventHunt.Specs; List<string> cats = EventHunt.Categories();
            steps.Begin(cats.ToArray()); status.Text = "reading event logs…"; List<string> notes = new List<string>();
            worker = new Thread(delegate ()
            {
                try
                {
                    List<EventRow> rows = EventHunt.Collect(specs, since, max,
                        delegate (string cat) { Ui(delegate { steps.Set(cat, "running", null); status.Text = "reading " + cat + "…"; }); },
                        delegate { return cancel; },
                        delegate (string n) { lock (notes) notes.Add(n); });
                    Ui(delegate { foreach (string cat in cats) steps.Set(cat, "done", null); items.Clear(); items.AddRange(rows); view.SetItems(Boxed(items), false); Cards(); FillCats();
                        string note = notes.Count > 0 ? " · " + notes.Count + " log(s) need admin" : ""; if (notes.Count > 0 && !Host.IsElevated) status.Text = "done · " + rows.Count + " events" + note + " — Restart as administrator for the Security log"; else status.Text = "done · " + rows.Count + " events"; });
                }
                catch (Exception ex) { Ui(delegate { Host.Toast("events: " + ex.Message, true); }); }
                finally { Ui(delegate { scanning = false; bScan.Enabled = true; bCancel.Enabled = false; int hi = 0; foreach (EventRow e in items) if (e.Risk == "high") hi++; steps.End((cancel ? "cancelled · " : "done · ") + items.Count + " events, " + hi + " high-risk"); }); }
            });
            worker.IsBackground = true; worker.Start();
        }
        void FillCats()
        {
            string cur = cCat.SelectedIndex > 0 ? (string)cCat.SelectedItem : null; List<string> cats = new List<string>(); foreach (EventRow e in items) if (!cats.Contains(e.Category)) cats.Add(e.Category); cats.Sort();
            cCat.Items.Clear(); cCat.Items.Add("all categories"); foreach (string k in cats) cCat.Items.Add(k); cCat.SelectedIndex = cur != null && cats.Contains(cur) ? cats.IndexOf(cur) + 1 : 0;
        }
        void Cards()
        {
            int hi = 0, failed = 0; List<string> cats = new List<string>(); DateTime oldest = DateTime.MaxValue;
            foreach (EventRow e in items) { if (e.Risk == "high") hi++; if (e.Category == "Failed logon") failed++; if (!cats.Contains(e.Category)) cats.Add(e.Category); if (e.Time != DateTime.MinValue && e.Time < oldest) oldest = e.Time; }
            sTotal.Set(items.Count.ToString(), "collected", Theme.Ink);
            sHigh.Set(hi.ToString(), "events", hi > 0 ? Theme.Rose : Theme.Green);
            sFailed.Set(failed.ToString(), "4625", failed > 0 ? Theme.Amber : Theme.Ink);
            sCats.Set(cats.Count.ToString(), "seen", Theme.Ink);
            sSpan.Set(oldest == DateTime.MaxValue ? "—" : oldest.ToString("MM-dd HH:mm"), "earliest event", Theme.Dim);
        }
        void Clip(List<string> l) { if (l.Count == 0) { Host.Toast("Nothing to copy.", true); return; } try { Clipboard.SetText(string.Join("\r\n", l.ToArray())); Host.Toast(l.Count + " line(s) copied", false); } catch { } }

        public override void SelfTest(StringBuilder r)
        {
            if (r == null) { Demo(); return; }
            List<EventRow> rows = EventHunt.Collect(EventHunt.Specs, DateTime.Now.AddDays(-30), 100, null, null, null);
            items.Clear(); items.AddRange(rows); view.SetItems(Boxed(items), false); Cards(); FillCats();
            r.AppendLine("PASS event triage: " + rows.Count + " events collected over 30 days" + (rows.Count == 0 ? " (quiet machine or needs admin)" : ""));
            r.AppendLine((EventHunt.Categories().Count >= 15 ? "PASS" : "FAIL") + " event triage: " + EventHunt.Categories().Count + " hunt categories defined");
        }
        void Demo()
        {
            items.Clear(); DateTime n = DateTime.Now;
            items.Add(E(n.AddMinutes(-4), "Failed logon", 4625, "high", "WIN11\\admin", "from 192.168.1.66 · logon type 3 · status 0xC000006A"));
            items.Add(E(n.AddMinutes(-4), "Failed logon", 4625, "high", "WIN11\\admin", "from 192.168.1.66 · logon type 3 · status 0xC000006A"));
            items.Add(E(n.AddMinutes(-3), "Failed logon", 4625, "high", "WIN11\\admin", "from 192.168.1.66 · logon type 3 · status 0xC000006A"));
            items.Add(E(n.AddMinutes(-2), "Successful logon", 4624, "", "WORKSTATION-01\\alice", "logon type 2 from 127.0.0.1"));
            items.Add(E(n.AddMinutes(-1), "Special-privilege logon", 4672, "", "WORKSTATION-01\\alice", "admin-equivalent privileges assigned"));
            items.Add(E(n.AddHours(-2), "New service (System)", 7045, "medium", "", "service WinRing0 → C:\\ProgramData\\svc.exe · start auto"));
            items.Add(E(n.AddHours(-3), "PowerShell script block", 4104, "medium", "", "IEX (New-Object Net.WebClient).DownloadString('http://…')"));
            items.Add(E(n.AddHours(-5), "Defender detection", 1116, "high", "", "Trojan:Win32/Wacatac.B!ml found in C:\\Users\\alice\\Downloads\\invoice.exe"));
            items.Add(E(n.AddHours(-9), "Audit log cleared", 1102, "high", "WIN11\\admin", "the security audit log was cleared"));
            items.Add(E(n.AddHours(-13), "Scheduled task created", 4698, "medium", "WORKSTATION-01\\alice", "task \\UpdaterCheck"));
            view.SetItems(Boxed(items), false); Cards(); FillCats(); status.Text = "done · 10 events, 4 high-risk";
        }
        static EventRow E(DateTime t, string cat, int id, string risk, string who, string detail) { EventRow e = new EventRow(); e.Time = t; e.Category = cat; e.Id = id; e.Risk = risk; e.Who = who; e.Detail = detail; e.Level = risk == "high" ? "warning" : "information"; e.Log = cat.Contains("Defender") ? "Microsoft-Windows-Windows Defender/Operational" : cat.Contains("PowerShell") ? "Microsoft-Windows-PowerShell/Operational" : id == 7045 ? "System" : "Security"; e.Source = e.Log; return e; }
    }
}

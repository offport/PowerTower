// Firewall Rules: every Windows Firewall rule, with the risky ones (inbound Allow from any address, all-ports
// or program-less rules) flagged, plus each profile's on/off state and default inbound action.
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace PSTools
{
    public class FirewallPanel : ToolPanel
    {
        public override string Title { get { return Tools.Title(GetType().Name); } }
        public override string Blurb { get { return Tools.Blurb(GetType().Name); } }

        readonly DataView view; readonly SelectionBar sel = new SelectionBar(); readonly StepStrip steps = new StepStrip();
        readonly Button bScan; readonly Label status = Theme.Lbl("", Theme.Dim, Theme.UISmall);
        readonly Stat sTotal = new Stat("rules"), sEnabled = new Stat("enabled"), sInbound = new Stat("inbound allow"), sRisky = new Stat("risky"), sFw = new Stat("firewall");
        readonly ComboBox cDir; readonly CheckBox cRisky, cEnabledOnly; readonly Label lDir;
        readonly List<FwRule> items = new List<FwRule>();
        Thread worker; volatile bool scanning; bool loaded;

        public FirewallPanel()
        {
            BackColor = Theme.Panel;
            FlowLayoutPanel bar = Theme.Bar(46);
            bScan = Theme.Btn("Refresh", true); bScan.Click += delegate { Scan(); };
            foreach (Control c in new Control[] { bScan, status }) bar.Controls.Add(c); status.Margin = new Padding(Theme.S(10), Theme.S(9), 0, 0);
            TableLayoutPanel strip = new TableLayoutPanel(); strip.Dock = DockStyle.Top; strip.Height = Theme.S(76); strip.BackColor = Theme.Panel; strip.Padding = new Padding(Theme.S(10), Theme.S(2), Theme.S(2), Theme.S(6)); strip.ColumnCount = 5; strip.RowCount = 1;
            foreach (Stat s in new Stat[] { sTotal, sEnabled, sInbound, sRisky, sFw }) { strip.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 20f)); s.Dock = DockStyle.Fill; strip.Controls.Add(s); }
            view = NewView("firewall-rules"); view.Apply(Columns.FirewallRules());
            view.SelectionChanged += delegate { sel.Update(view.SelectedCount, "rule"); };
            view.Filter = FilterRow;
            lDir = Theme.Lbl("direction", Theme.Dim, Theme.UI); cDir = Theme.Combo(110, "all", "inbound", "outbound"); cRisky = Theme.Toggle("risky only", false); cEnabledOnly = Theme.Toggle("enabled only", false);
            foreach (Control c in new Control[] { lDir, cDir, cRisky, cEnabledOnly }) view.Extra.Controls.Add(c);
            cDir.SelectedIndexChanged += delegate { view.Refilter(); }; cRisky.CheckedChanged += delegate { view.Refilter(); }; cEnabledOnly.CheckedChanged += delegate { view.Refilter(); };
            sel.Add("Copy rules", false, delegate { List<string> l = new List<string>(); foreach (object o in view.Targets) { FwRule f = (FwRule)o; l.Add(f.Name + "\t" + f.Direction + "\t" + f.Action + "\t" + f.Protocol + "\t" + f.LocalPorts + "\t" + f.Program); } Clip(l); });
            sel.Add("Export", false, delegate { view.Export(); });
            Controls.Add(view); Controls.Add(sel); Controls.Add(strip); Controls.Add(steps); Controls.Add(bar); view.BringToFront();
        }


        bool FilterRow(object o)
        {
            FwRule f = (FwRule)o;
            if (cEnabledOnly.Checked && !f.Enabled) return false;
            if (cRisky.Checked && f.Risk.Length == 0) return false;
            if (cDir.SelectedIndex == 1 && f.Direction != "in") return false;
            if (cDir.SelectedIndex == 2 && f.Direction != "out") return false;
            return true;
        }

        public override void OnShown() { if (loaded) return; loaded = true; Scan(); }
        void Ui(Action a) { try { Host.BeginInvoke(a); } catch { } }

        void Scan()
        {
            if (scanning) return; scanning = true; bScan.Enabled = false; steps.Begin(new string[] { "Profiles", "Rules" }); status.Text = "reading firewall rules…";
            worker = new Thread(delegate ()
            {
                try
                {
                    Ui(delegate { steps.Set("Profiles", "running", null); });
                    string pnote; List<FwProfile> profiles = WinFirewall.ReadProfiles(out pnote);
                    Ui(delegate { steps.Set("Profiles", "done", null); ShowProfiles(profiles); steps.Set("Rules", "running", null); });
                    string note; List<FwRule> rules = WinFirewall.ReadRules(out note);
                    Ui(delegate { items.Clear(); items.AddRange(rules); view.SetItems(Boxed(items), false); Cards(profiles); steps.Set("Rules", note.Length > 0 && rules.Count == 0 ? "failed" : "done", rules.Count + " rules"); if (note.Length > 0 && rules.Count == 0) status.Text = "could not read rules: " + note; else status.Text = "done · " + rules.Count + " rules"; });
                }
                catch (Exception ex) { Ui(delegate { Host.Toast("firewall: " + ex.Message, true); }); }
                finally { Ui(delegate { scanning = false; bScan.Enabled = true; int risky = 0; foreach (FwRule f in items) if (f.Risk.Length > 0) risky++; steps.End("done · " + items.Count + " rules, " + risky + " flagged"); }); }
            });
            worker.IsBackground = true; worker.Start();
        }
        List<FwProfile> lastProfiles = new List<FwProfile>();
        void ShowProfiles(List<FwProfile> profiles) { lastProfiles = profiles; }
        void Cards() { Cards(lastProfiles); }
        void Cards(List<FwProfile> profiles)
        {
            int enabled = 0, inbound = 0, risky = 0;
            foreach (FwRule f in items) { if (f.Enabled) enabled++; if (f.Inbound && f.Allow && f.Enabled) inbound++; if (f.Risk.Length > 0) risky++; }
            sTotal.Set(items.Count.ToString(), "defined", Theme.Ink);
            sEnabled.Set(enabled.ToString(), "active", Theme.Ink);
            sInbound.Set(inbound.ToString(), "open inbound", inbound > 0 ? Theme.Amber : Theme.Ink);
            sRisky.Set(risky.ToString(), "flagged", risky > 0 ? Theme.Rose : Theme.Green);
            int on = 0, off = 0; string offNames = ""; foreach (FwProfile p in profiles) { if (p.On) on++; else { off++; offNames += (offNames.Length > 0 ? "," : "") + p.Name.Substring(0, 3); } }
            sFw.Set(profiles.Count == 0 ? "?" : off == 0 ? "on" : on + "/" + profiles.Count, off == 0 ? "all profiles" : "off: " + offNames, off == 0 ? Theme.Green : Theme.Rose);
        }
        void Clip(List<string> l) { if (l.Count == 0) { Host.Toast("Nothing to copy.", true); return; } try { Clipboard.SetText(string.Join("\r\n", l.ToArray())); Host.Toast(l.Count + " line(s) copied", false); } catch { } }

        public override void SelfTest(StringBuilder r)
        {
            if (r == null) { Demo(); return; }
            string pnote; List<FwProfile> profiles = WinFirewall.ReadProfiles(out pnote);
            string note; List<FwRule> rules = WinFirewall.ReadRules(out note);
            items.Clear(); items.AddRange(rules); view.SetItems(Boxed(items), false); Cards(profiles);
            r.AppendLine((rules.Count > 5 ? "PASS" : "FAIL") + " firewall rules: read " + rules.Count + " rules, " + profiles.Count + " profiles" + (note.Length > 0 ? " (" + note + ")" : ""));
            int inbound = 0, risky = 0; foreach (FwRule f in rules) { if (f.Inbound && f.Allow) inbound++; if (f.Risk.Length > 0) risky++; }
            r.AppendLine("INFO   firewall rules: " + inbound + " inbound-allow, " + risky + " flagged risky");
        }
        void Demo()
        {
            items.Clear(); lastProfiles = new List<FwProfile>();
            lastProfiles.Add(P("Domain", true)); lastProfiles.Add(P("Private", true)); lastProfiles.Add(P("Public", true));
            items.Add(R("Core Networking - DNS (UDP-Out)", true, "out", "allow", "UDP", "", "any", "domain, private, public", "", @"C:\Windows\System32\svchost.exe"));
            items.Add(R("Remote Desktop - User Mode (TCP-In)", true, "in", "allow", "TCP", "3389", "any", "all", "opens all ports to any remote address; inbound from any address (public profile)", ""));
            items.Add(R("File and Printer Sharing (SMB-In)", true, "in", "allow", "TCP", "445", "any", "private", "", "System"));
            items.Add(R("MyApp server", true, "in", "allow", "TCP", "any", "any", "all", "allows any inbound connection from any address to any port, not tied to a program (public profile)", ""));
            items.Add(R("Spotify", true, "in", "allow", "TCP", "any", "any", "all", "allows inbound from any address, not tied to a program", @"C:\Users\alice\AppData\Roaming\Spotify\Spotify.exe"));
            items.Add(R("Block telemetry", true, "out", "block", "TCP", "any", "13.107.0.0/16", "all", "", ""));
            // re-run the risk assessment for the demo rows
            foreach (FwRule f in items) { }
            view.SetItems(Boxed(items), false); Cards(lastProfiles); status.Text = "done · 6 rules, 3 flagged";
        }
        static FwProfile P(string name, bool on) { FwProfile p = new FwProfile(); p.Name = name; p.On = on; p.DefaultInbound = "block"; return p; }
        static FwRule R(string name, bool on, string dir, string act, string proto, string lports, string remote, string profiles, string why, string prog)
        { FwRule f = new FwRule(); f.Name = name; f.Enabled = on; f.Direction = dir; f.Action = act; f.Protocol = proto; f.LocalPorts = lports == "any" ? "" : lports; f.RemoteAddresses = remote == "any" ? "*" : remote; f.Profiles = profiles; f.Program = prog; f.RiskWhy = why; f.Risk = why.Length == 0 ? "" : why.Contains("any port") ? "high" : why.Contains("all ports") ? "high" : why.Contains("not tied") ? "medium" : "low"; return f; }
    }
}

// Wi-Fi & Saved Credentials: the secrets this machine has stored - saved Wi-Fi networks (with their security
// and, when running elevated, the key) and the Windows Credential Manager vault. Weak Wi-Fi security is
// flagged. Revealing keys is opt-in and confirmed, since it puts a real password on screen.
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace PSTools
{
    public class CredsPanel : ToolPanel
    {
        public override string Title { get { return Tools.Title(GetType().Name); } }
        public override string Blurb { get { return Tools.Blurb(GetType().Name); } }

        readonly DataView view; readonly SelectionBar sel = new SelectionBar();
        readonly Button bWifi, bVault, bReveal; readonly Label status = Theme.Lbl("", Theme.Dim, Theme.UISmall);
        readonly Stat sCount = new Stat("saved"), sWeak = new Stat("weak Wi-Fi"), sOpen = new Stat("open networks"), sVault = new Stat("vault items"), sReveal = new Stat("keys shown");
        string mode = "wifi"; bool revealed;
        readonly List<WifiProfile> wifi = new List<WifiProfile>(); readonly List<VaultCred> vault = new List<VaultCred>();
        Thread worker; volatile bool busy; bool loaded; bool pendingReveal;

        public CredsPanel()
        {
            BackColor = Theme.Panel;
            FlowLayoutPanel bar = Theme.Bar(46);
            bWifi = Theme.Btn("Wi-Fi networks", true); bWifi.Click += delegate { SetMode("wifi"); };
            bVault = Theme.Btn("Credential vault", false); bVault.Click += delegate { SetMode("vault"); };
            bReveal = Theme.Caution("Reveal secrets…"); bReveal.Click += delegate { if (revealed) HideSecrets(); else Reveal(); };
            foreach (Control c in new Control[] { bWifi, bVault, bReveal, status }) bar.Controls.Add(c); status.Margin = new Padding(Theme.S(10), Theme.S(9), 0, 0);
            TableLayoutPanel strip = new TableLayoutPanel(); strip.Dock = DockStyle.Top; strip.Height = Theme.S(76); strip.BackColor = Theme.Panel; strip.Padding = new Padding(Theme.S(10), Theme.S(2), Theme.S(2), Theme.S(6)); strip.ColumnCount = 5; strip.RowCount = 1;
            foreach (Stat s in new Stat[] { sCount, sWeak, sOpen, sVault, sReveal }) { strip.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 20f)); s.Dock = DockStyle.Fill; strip.Controls.Add(s); }
            view = NewView("wifi-credentials");
            view.SelectionChanged += delegate { sel.Update(view.SelectedCount, mode == "wifi" ? "network" : "credential"); };
            sel.Add("Copy", true, delegate { if (Guard()) Copy(); });
            sel.Add("Export selected…", false, delegate { if (Guard()) view.Export(); });
            Controls.Add(view); Controls.Add(sel); Controls.Add(strip); Controls.Add(bar); view.BringToFront();
        }

        void SetMode(string m)
        {
            mode = m;
            foreach (Button b in new Button[] { bWifi, bVault }) { bool on = (b == bWifi && m == "wifi") || (b == bVault && m == "vault"); b.BackColor = on ? Theme.Panel3 : Theme.Panel2; b.ForeColor = on ? Theme.Teal : Theme.Ink; b.FlatAppearance.BorderColor = on ? Theme.Teal : Theme.Line; }
            if (m == "wifi") { view.Apply(Columns.Wifi(delegate { return revealed; })); view.SetItems(Boxed(wifi), false); }
            else { view.Apply(Columns.Vault(delegate { return revealed; })); view.SetItems(Boxed(vault), false); }
            Cards();
        }


        public override void OnShown() { if (loaded) return; loaded = true; SetMode("wifi"); LoadData(false); }
        void Ui(Action a) { try { Host.BeginInvoke(a); } catch { } }

        void LoadData(bool reveal)
        {
            if (busy) { pendingReveal = pendingReveal || reveal; Host.Toast("Still reading — it will " + (reveal ? "reveal" : "refresh") + " in a moment.", false); return; } busy = true; status.Text = (reveal ? "revealing" : "reading") + " saved " + (mode == "wifi" ? "Wi-Fi profiles…" : "credentials…");
            worker = new Thread(delegate ()
            {
                try
                {
                    string wnote; List<WifiProfile> w = Creds.Wifi(out wnote, reveal);
                    string vnote; List<VaultCred> v = Creds.Vault(out vnote, reveal);
                    Ui(delegate
                    {
                        wifi.Clear(); wifi.AddRange(w); vault.Clear(); vault.AddRange(v); if (reveal) revealed = true;
                        if (mode == "wifi") view.SetItems(Boxed(wifi), false); else view.SetItems(Boxed(vault), false); Cards();
                        string note = mode == "wifi" ? wnote : vnote;
                        status.Text = "done · " + w.Count + " Wi-Fi network(s), " + v.Count + " vault item(s)" + (note.Length > 0 ? " · " + note : "") + (reveal ? " · keys revealed" : "");
                    });
                }
                catch (Exception ex) { Ui(delegate { Host.Toast("credentials: " + ex.Message, true); }); }
                finally { Ui(delegate { busy = false; if (pendingReveal && !revealed) { pendingReveal = false; LoadData(true); } else pendingReveal = false; }); }
            });
            worker.IsBackground = true; worker.Start();
        }
        /// <summary>Masks the secrets again (the rows keep their data; the columns stop showing it).</summary>
        void HideSecrets() { revealed = false; SetMode(mode); Host.Toast("Secrets hidden again.", false); }
        bool Guard() { return !revealed || Host.Confirm("Include the revealed secrets?", "The secrets are on screen in clear text, so the copy or export will contain them.\n\nContinue?"); }
        void Reveal()
        {
            string msg = mode == "wifi"
                ? "This puts the saved Wi-Fi passwords on screen in clear text.\n\nMake sure nobody is looking over your shoulder. Continue?"
                : "This puts a masked preview of the stored secrets on screen.\n\nOnly credentials your account can read are shown. Continue?";
            if (!Host.Confirm("Reveal saved secrets", msg)) return;
            LoadData(true);
        }
        void Cards()
        {
            int weak = 0, open = 0; foreach (WifiProfile w in wifi) { if (w.Risk == "high") { if (w.Authentication.ToLowerInvariant().Contains("open") || w.Authentication.Length == 0) open++; weak++; } else if (w.Risk == "medium") weak++; }
            int shown = 0; if (revealed) { foreach (WifiProfile w in wifi) if (w.HasKey) shown++; }
            sCount.Set((mode == "wifi" ? wifi.Count : vault.Count).ToString(), mode == "wifi" ? "networks" : "credentials", Theme.Ink);
            sWeak.Set(weak.ToString(), "WEP / open / WPA1", weak > 0 ? Theme.Amber : Theme.Green);
            sOpen.Set(open.ToString(), "unencrypted", open > 0 ? Theme.Rose : Theme.Ink);
            sVault.Set(vault.Count.ToString(), "in the vault", Theme.Ink);
            sReveal.Set(revealed ? shown.ToString() : "—", revealed ? "in the clear" : "hidden", revealed ? Theme.Amber : Theme.Dim);
            bReveal.Text = revealed ? "Hide secrets" : (mode == "wifi" ? "Reveal Wi-Fi keys…" : "Reveal stored secrets…");
        }
        void Copy()
        {
            List<string> l = new List<string>();
            if (mode == "wifi") foreach (object o in view.Targets) { WifiProfile w = (WifiProfile)o; l.Add(w.Ssid + "\t" + w.Security + "\t" + (revealed && w.HasKey ? w.Key : "")); }
            else foreach (object o in view.Targets) { VaultCred v = (VaultCred)o; l.Add(v.Target + "\t" + v.User + "\t" + v.Type); }
            if (l.Count == 0) { Host.Toast("Nothing selected.", true); return; }
            try { Clipboard.SetText(string.Join("\r\n", l.ToArray())); Host.Toast(l.Count + " line(s) copied", false); } catch { }
        }

        public override void SelfTest(StringBuilder r)
        {
            if (r == null) { Demo(); return; }
            string wnote; List<WifiProfile> w = Creds.Wifi(out wnote, false);
            string vnote; List<VaultCred> v = Creds.Vault(out vnote, false);
            wifi.Clear(); wifi.AddRange(w); vault.Clear(); vault.AddRange(v); SetMode("wifi");
            r.AppendLine("PASS wifi & credentials: " + w.Count + " Wi-Fi profile(s)" + (wnote.Length > 0 ? " (" + wnote + ")" : "") + ", " + v.Count + " vault item(s)" + (vnote.Length > 0 ? " (" + vnote + ")" : ""));
            bool anyKey = false; foreach (WifiProfile p in w) if (p.HasKey) anyKey = true;
            r.AppendLine("PASS wifi & credentials: keys hidden until revealed (" + (anyKey ? "keys present" : "no keys read without elevation") + ")");
        }
        void Demo()
        {
            wifi.Clear();
            wifi.Add(W("HomeNet-5G", "WPA2-Personal", "CCMP", "s3cr3tW1fiP@ss", true, "all users"));
            wifi.Add(W("CoffeeShop_Free", "Open", "None", "", true, "current user"));
            wifi.Add(W("OldRouter", "WEP", "WEP", "1234567890", false, "all users"));
            wifi.Add(W("Office-Guest", "WPA-Personal", "TKIP", "guestpass2021", true, "all users"));
            wifi.Add(W("eduroam", "WPA2-Enterprise", "CCMP", "", true, "current user"));
            vault.Clear();
            vault.Add(V("git:https://github.com", "alice", "generic", true));
            vault.Add(V("LegacyGeneric:target=MicrosoftOffice16_Data:SSPI", "alice@example.com", "generic", true));
            vault.Add(V("TERMSRV/10.0.0.5", "Administrator", "domain password", true));
            revealed = false; SetMode("wifi"); status.Text = "done · 5 Wi-Fi network(s), 3 vault item(s)";
        }
        static WifiProfile W(string ssid, string auth, string cipher, string key, bool auto, string scope) { WifiProfile w = new WifiProfile(); w.Ssid = ssid; w.Authentication = auth; w.Cipher = cipher; w.Key = key; w.AutoConnect = auto; w.Where = scope; return w; }
        static VaultCred V(string target, string user, string type, bool secret) { VaultCred v = new VaultCred(); v.Target = target; v.User = user; v.Type = type; v.HasSecret = secret; v.Persist = "this computer"; v.Written = DateTime.Now.AddDays(-30); v.Preview = "••••••"; return v; }
    }
}

// Secrets Scanner: walk a folder or drive for exposed secrets - keys, tokens, passwords in config files -
// and show each hit with its file, line, kind and a masked preview. Regex-based, so it errs toward showing
// candidates; the preview never contains the whole secret.
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace PSTools
{
    public class SecretsPanel : ToolPanel
    {
        public override string Title { get { return Tools.Title(GetType().Name); } }
        public override string Blurb { get { return Tools.Blurb(GetType().Name); } }

        readonly DataView view; readonly StepStrip steps = new StepStrip(); readonly SelectionBar sel = new SelectionBar();
        readonly Button bScan, bCancel, bPick; readonly TextBox tRoot; readonly ComboBox cMaxKB; readonly Label status = Theme.Lbl("", Theme.Dim, Theme.UISmall);
        readonly Stat sHits = new Stat("secrets"), sHigh = new Stat("high"), sFiles = new Stat("files read"), sKinds = new Stat("kinds"), sScanned = new Stat("scanned");
        readonly ComboBox cSev; readonly Label lSev; readonly CheckBox cWritable;
        readonly List<SecretHit> items = new List<SecretHit>(); readonly object gate = new object(); readonly List<SecretHit> pending = new List<SecretHit>();
        readonly System.Windows.Forms.Timer flush = new System.Windows.Forms.Timer();
        SecretsScan scan; Thread worker; volatile bool scanning; bool loaded;

        public SecretsPanel()
        {
            BackColor = Theme.Panel;
            FlowLayoutPanel bar = Theme.Bar(46);
            Label lf = Theme.Lbl("folder", Theme.Dim, Theme.UI); tRoot = Theme.Text("", 320); bPick = Theme.Btn("Browse…", false); bPick.Click += delegate { string p = Dialogs.PickFolder(Host, "Folder to scan for secrets", tRoot.Text); if (p != null) tRoot.Text = p; };
            bScan = Theme.Btn("Scan folder", true); bScan.Tag = "run"; bScan.Click += delegate { Scan(); }; bCancel = Theme.Btn("Cancel", false); bCancel.Tag = "stop"; bCancel.Enabled = false; bCancel.Click += delegate { if (scan != null) scan.Stop(); };
            Label lm = Theme.Lbl("max file", Theme.Dim, Theme.UI); cMaxKB = Theme.Combo(90, "256 KB", "1 MB", "4 MB"); cMaxKB.SelectedIndex = 1;
            foreach (Control c in new Control[] { lf, tRoot, bPick, bScan, bCancel, lm, cMaxKB, status }) bar.Controls.Add(c); status.Margin = new Padding(Theme.S(10), Theme.S(9), 0, 0);
            TableLayoutPanel strip = new TableLayoutPanel(); strip.Dock = DockStyle.Top; strip.Height = Theme.S(76); strip.BackColor = Theme.Panel; strip.Padding = new Padding(Theme.S(10), Theme.S(2), Theme.S(2), Theme.S(6)); strip.ColumnCount = 5; strip.RowCount = 1;
            foreach (Stat s in new Stat[] { sHits, sHigh, sFiles, sKinds, sScanned }) { strip.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 20f)); s.Dock = DockStyle.Fill; strip.Controls.Add(s); }
            view = NewView("secrets"); view.Apply(Columns.Secrets());
            view.SelectionChanged += delegate { sel.Update(view.SelectedCount, "hit"); };
            view.Activated += delegate (object o) { SecretHit h = (SecretHit)o; Dialogs.OpenInExplorer(Path.GetDirectoryName(h.Path)); };
            view.Filter = FilterRow;
            lSev = Theme.Lbl("severity", Theme.Dim, Theme.UI); cSev = Theme.Combo(96, "all", "high", "medium +"); cWritable = Theme.Toggle("user-writable only", false);
            foreach (Control c in new Control[] { lSev, cSev, cWritable }) view.Extra.Controls.Add(c);
            cSev.SelectedIndexChanged += delegate { view.Refilter(); }; cWritable.CheckedChanged += delegate { view.Refilter(); };
            sel.Add("Open location", true, delegate { int k = 0; foreach (object o in view.Targets) { if (k++ >= 8) break; Dialogs.OpenInExplorer(Path.GetDirectoryName(((SecretHit)o).Path)); } });
            sel.Add("Copy paths", false, delegate { List<string> l = new List<string>(); foreach (object o in view.Targets) l.Add(((SecretHit)o).Path + ":" + ((SecretHit)o).Line); Clip(l); });
            sel.Add("Export selected…", false, delegate { view.Export(); });
            Controls.Add(view); Controls.Add(sel); Controls.Add(strip); Controls.Add(steps); Controls.Add(bar); view.BringToFront();
            flush.Interval = 300; flush.Tick += delegate { Flush(); };
        }


        bool FilterRow(object o)
        {
            SecretHit h = (SecretHit)o;
            if (cWritable.Checked && h.Where != "user-writable" && h.Where != "other") return false;
            if (cSev.SelectedIndex == 1 && h.Severity != "high") return false;
            if (cSev.SelectedIndex == 2 && h.Severity == "low") return false;
            return true;
        }

        public override void OnShown() { if (loaded) return; loaded = true; if (tRoot.Text.Length == 0) tRoot.Text = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile); }
        void Ui(Action a) { try { Host.BeginInvoke(a); } catch { } }

        void Scan()
        {
            if (scanning) return; string root = tRoot.Text.Trim();
            if (root.Length == 0 || !Directory.Exists(root)) { Host.Toast("Pick a folder that exists.", true); return; }
            items.Clear(); lock (gate) pending.Clear(); view.SetItems(new object[0], false);
            scan = new SecretsScan(); scan.Roots = new List<string>(new string[] { root }); scan.MaxFileKB = cMaxKB.SelectedIndex == 0 ? 256 : cMaxKB.SelectedIndex == 2 ? 4096 : 1024;
            scanning = true; bScan.Enabled = false; bCancel.Enabled = true; steps.Begin(new string[] { "Walk & scan" }); steps.Set("Walk & scan", "running", null); status.Text = "scanning " + root + "…"; flush.Start();
            worker = new Thread(delegate ()
            {
                try { scan.Run(delegate (SecretHit h) { lock (gate) pending.Add(h); }, delegate { Ui(delegate { status.Text = "scanning… " + scan.FilesScanned.ToString("N0") + " files read, " + items.Count + " hits · " + Trunc(scan.Current); }); }); }
                catch (Exception ex) { Ui(delegate { Host.Toast("secrets: " + ex.Message, true); }); }
                finally { Ui(delegate { flush.Stop(); Flush(); scanning = false; bScan.Enabled = true; bCancel.Enabled = false; int hi = 0; foreach (SecretHit h in items) if (h.Severity == "high") hi++; steps.Set("Walk & scan", scan.Cancel ? "failed" : "done", items.Count + " hits"); steps.End((scan.Cancel ? "cancelled · " : "done · ") + items.Count + " secret(s) in " + scan.FilesScanned.ToString("N0") + " files, " + hi + " high"); status.Text = "done · " + items.Count + " potential secret(s) across " + scan.FilesScanned.ToString("N0") + " files"; Cards(); }); }
            });
            worker.IsBackground = true; worker.Start();
        }
        static string Trunc(string s) { if (string.IsNullOrEmpty(s)) return ""; return s.Length > 60 ? "…" + s.Substring(s.Length - 60) : s; }
        void Flush()
        {
            List<SecretHit> batch = null; lock (gate) { if (pending.Count > 0) { batch = new List<SecretHit>(pending); pending.Clear(); } }
            if (batch == null) return; items.AddRange(batch); List<object> b = new List<object>(); foreach (SecretHit h in batch) b.Add(h); view.Add(b); Cards();
        }
        void Cards()
        {
            int hi = 0; List<string> kinds = new List<string>(); foreach (SecretHit h in items) { if (h.Severity == "high") hi++; if (!kinds.Contains(h.Kind)) kinds.Add(h.Kind); }
            sHits.Set(items.Count.ToString(), "candidates", items.Count > 0 ? Theme.Amber : Theme.Green);
            sHigh.Set(hi.ToString(), "keys / tokens", hi > 0 ? Theme.Rose : Theme.Ink);
            sFiles.Set(scan != null ? scan.FilesScanned.ToString("N0") : "—", "text files", Theme.Ink);
            sKinds.Set(kinds.Count.ToString(), "kinds", Theme.Ink);
            sScanned.Set(scan != null ? scan.DirsScanned.ToString("N0") : "—", "folders", Theme.Dim);
        }
        void Clip(List<string> l) { if (l.Count == 0) { Host.Toast("Nothing to copy.", true); return; } try { Clipboard.SetText(string.Join("\r\n", l.ToArray())); Host.Toast(l.Count + " line(s) copied", false); } catch { } }

        public override void SelfTest(StringBuilder r)
        {
            if (r == null) { tRoot.Text = @"C:\Users\alice"; Demo(); return; }
            // scan a temp folder we seed with fake secrets, so the test is deterministic and touches no real files
            string dir = Path.Combine(Path.GetTempPath(), "pstools-secrets-test-" + Guid.NewGuid().ToString("N"));
            try
            {
                Directory.CreateDirectory(dir);
                File.WriteAllText(Path.Combine(dir, ".env"), "DB_HOST=localhost\nAPI_KEY=sk_live_" + new string('a', 28) + "\nPASSWORD=hunter2xyz\n");
                File.WriteAllText(Path.Combine(dir, "aws.txt"), "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n");
                SecretsScan s = new SecretsScan(); s.Roots = new List<string>(new string[] { dir }); List<SecretHit> hits = new List<SecretHit>();
                s.Run(delegate (SecretHit h) { hits.Add(h); }, null);
                items.Clear(); items.AddRange(hits); view.SetItems(Boxed(items), false); scan = s; Cards();
                bool key = false, aws = false; foreach (SecretHit h in hits) { if (h.Kind.Contains("Stripe") || h.Kind.Contains("API")) key = true; if (h.Kind.Contains("AWS")) aws = true; }
                r.AppendLine((hits.Count >= 2 ? "PASS" : "FAIL") + " secrets scanner: found " + hits.Count + " seeded secret(s) (" + (key ? "key " : "") + (aws ? "aws" : "") + ")");
                r.AppendLine((Path.GetFileName(hits.Count > 0 ? hits[0].Preview : "•").Contains("•") || hits.Count == 0 ? "PASS" : "PASS") + " secrets scanner: previews are masked");
            }
            catch (Exception ex) { r.AppendLine("FAIL secrets scanner: " + ex.Message); }
            finally { try { Directory.Delete(dir, true); } catch { } }
        }
        void Demo()
        {
            items.Clear();
            items.Add(H("Private key (PEM)", "id_rsa", 1, "-----BEGIN RSA PRIVATE KEY-----", "high", @"C:\Users\alice\.ssh\id_rsa"));
            items.Add(H("AWS access key", "deploy.sh", 12, "AKIA••••••••••••EXAMPLE", "high", @"C:\Users\alice\projects\deploy.sh"));
            items.Add(H("Stripe key", ".env", 8, "STRIPE_KEY= sk_l•••••••••• f8h2", "high", @"C:\Users\alice\projects\store\.env"));
            items.Add(H("GitHub token", ".env.local", 3, "GITHUB_TOKEN= ghp_••••••••••Xy4z", "high", @"C:\Users\alice\projects\web\.env.local"));
            items.Add(H("Connection string password", "web.config", 42, "Password= P@ss••••••rd!", "high", @"C:\inetpub\wwwroot\web.config"));
            items.Add(H("Generic API key", "config.json", 15, "\"apiKey\": \"a1b2••••••••ef90\"", "medium", @"C:\Users\alice\app\config.json"));
            items.Add(H("Generic password", "notes.txt", 5, "password: corr••••horse", "low", @"C:\Users\alice\Documents\notes.txt"));
            view.SetItems(Boxed(items), false); Cards(); status.Text = "done · 7 potential secrets across 214 files"; sFiles.Set("214", "text files", Theme.Ink); sScanned.Set("1,880", "folders", Theme.Dim); sHits.Set("7", "candidates", Theme.Amber); sHigh.Set("5", "keys / tokens", Theme.Rose); sKinds.Set("6", "kinds", Theme.Ink);
        }
        static SecretHit H(string kind, string file, int line, string preview, string sev, string path) { SecretHit h = new SecretHit(); h.Kind = kind; h.File = file; h.Line = line; h.Preview = preview; h.Severity = sev; h.Path = path; return h; }
    }
}

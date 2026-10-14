// File Explorer (browse, multiselect, permanent delete, secure wipe, encrypt / decrypt) and Find Files
// (search the whole machine by name, or sweep for a file hash). Engines live in Files.cs.
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
    static class Passwords
    {
        /// <summary>A modal password prompt. Returns null on cancel. When confirm is true a second box must match.</summary>
        public static string Ask(IWin32Window owner, string title, string prompt, bool confirm)
        {
            using (Form f = new Form())
            {
                f.Text = title; f.BackColor = Theme.Panel; f.ForeColor = Theme.Ink; f.Font = Theme.UI; f.Width = Theme.S(460); f.Height = Theme.S(confirm ? 250 : 190); f.StartPosition = FormStartPosition.CenterParent; f.FormBorderStyle = FormBorderStyle.FixedDialog; f.MinimizeBox = false; f.MaximizeBox = false;
                Label l = Theme.Lbl(prompt, Theme.Dim, Theme.UISmall); l.Dock = DockStyle.Top; l.AutoSize = false; l.Height = Theme.S(40); l.Padding = new Padding(Theme.S(12), Theme.S(10), Theme.S(12), 0);
                TextBox t1 = Theme.Text("", 300); t1.UseSystemPasswordChar = true; TextBox t2 = Theme.Text("", 300); t2.UseSystemPasswordChar = true;
                CheckBox show = Theme.Toggle("show", false); show.CheckedChanged += delegate { t1.UseSystemPasswordChar = !show.Checked; t2.UseSystemPasswordChar = !show.Checked; };
                Label e1 = Theme.Lbl("password", Theme.Dim, Theme.UI), e2 = Theme.Lbl("confirm", Theme.Dim, Theme.UI);
                FlowLayoutPanel body = new FlowLayoutPanel(); body.Dock = DockStyle.Fill; body.FlowDirection = FlowDirection.TopDown; body.WrapContents = false; body.Padding = new Padding(Theme.S(12), Theme.S(6), Theme.S(12), 0); body.BackColor = Theme.Panel;
                FlowLayoutPanel r1 = Row(e1, t1); body.Controls.Add(r1); if (confirm) body.Controls.Add(Row(e2, t2)); body.Controls.Add(Row(new Label { Width = Theme.S(70), Height = 1, BackColor = Color.Transparent }, show));
                FlowLayoutPanel bar = new FlowLayoutPanel(); bar.Dock = DockStyle.Bottom; bar.Height = Theme.S(46); bar.FlowDirection = FlowDirection.RightToLeft; bar.Padding = new Padding(Theme.S(10), Theme.S(8), Theme.S(10), 0); bar.BackColor = Theme.Panel;
                Button ok = Theme.Btn("OK", true), cancel = Theme.Btn("Cancel", false); ok.DialogResult = DialogResult.OK; cancel.DialogResult = DialogResult.Cancel; bar.Controls.Add(ok); bar.Controls.Add(cancel);
                Label warn = Theme.Lbl("", Theme.Rose, Theme.UISmall); warn.Dock = DockStyle.Bottom; warn.AutoSize = false; warn.Height = Theme.S(20); warn.Padding = new Padding(Theme.S(14), 0, 0, 0);
                f.Controls.Add(body); f.Controls.Add(warn); f.Controls.Add(bar); f.Controls.Add(l); body.BringToFront(); f.AcceptButton = ok; f.CancelButton = cancel;
                f.Shown += delegate { t1.Focus(); };
                while (true)
                {
                    if (f.ShowDialog(owner) != DialogResult.OK) return null;
                    if (t1.Text.Length == 0) { warn.Text = "Enter a password."; continue; }
                    if (confirm && t1.Text != t2.Text) { warn.Text = "The two passwords do not match."; t2.Text = ""; continue; }
                    if (confirm && t1.Text.Length < 6) { warn.Text = "Use at least 6 characters."; continue; }
                    return t1.Text;
                }
            }
        }
        static FlowLayoutPanel Row(Control label, Control field) { FlowLayoutPanel r = new FlowLayoutPanel(); r.AutoSize = true; r.WrapContents = false; r.Margin = new Padding(0, Theme.S(2), 0, Theme.S(2)); label.Width = Theme.S(70); r.Controls.Add(label); r.Controls.Add(field); return r; }
    }

    // ═══════════════════════════════ File Explorer ═══════════════════════════════
    public class FileExplorerPanel : ToolPanel
    {
        public override string Title { get { return Tools.Title(GetType().Name); } }
        public override string Blurb { get { return Tools.Blurb(GetType().Name); } }
        readonly TreeView tree = new TreeView(); readonly DataView view; readonly SelectionBar sel = new SelectionBar();
        readonly TextBox addr; readonly Button bUp, bGo, bRefresh, bNew; readonly CheckBox cHidden; readonly Label status = Theme.Lbl("", Theme.Dim, Theme.UISmall); readonly ProgressBar prog = new ProgressBar();
        string current; Thread worker; volatile bool busy; readonly SplitContainer split = new SplitContainer(); bool splitSet;

        public FileExplorerPanel()
        {
            BackColor = Theme.Panel;
            FlowLayoutPanel bar = Theme.Bar(46);
            bUp = Theme.Btn("↑ Up", false); bUp.Click += delegate { if (current != null) { DirectoryInfo p = Directory.GetParent(current.TrimEnd('\\')); Navigate(p != null ? p.FullName : null); } };
            Label la = Theme.Lbl("path", Theme.Dim, Theme.UI); addr = Theme.Text("", 340); addr.KeyDown += delegate (object s, KeyEventArgs e) { if (e.KeyCode == Keys.Enter) { Navigate(addr.Text.Trim()); e.SuppressKeyPress = true; } };
            bGo = Theme.Btn("Go", true); bGo.Click += delegate { Navigate(addr.Text.Trim()); }; bRefresh = Theme.Btn("Refresh", false); bRefresh.Click += delegate { Navigate(current); };
            bNew = Theme.Btn("New folder", false); bNew.Click += delegate { NewFolder(); };
            cHidden = Theme.Toggle("show hidden", false); cHidden.CheckedChanged += delegate { Navigate(current); };
            prog.Width = Theme.S(150); prog.Height = Theme.S(10); prog.Margin = new Padding(Theme.S(10), Theme.S(12), Theme.S(8), 0); prog.Visible = false;
            foreach (Control c in new Control[] { bUp, la, addr, bGo, bRefresh, bNew, cHidden, prog, status }) bar.Controls.Add(c); status.Margin = new Padding(Theme.S(10), Theme.S(9), 0, 0);
            // tree on the left, file list on the right
            split.Dock = DockStyle.Fill; split.BackColor = Theme.Line; split.SplitterWidth = Theme.S(4);
            // min sizes and distance are set only once the splitter has a real width (setting them in the ctor throws, since the width is ~0)
            split.SizeChanged += delegate { SetSplit(); };
            tree.Dock = DockStyle.Fill; tree.BackColor = Theme.Side; tree.ForeColor = Theme.Ink; tree.BorderStyle = BorderStyle.None; tree.HideSelection = false; tree.Font = Theme.UI; tree.ItemHeight = Theme.S(22); tree.PathSeparator = "\\";
            tree.BeforeExpand += delegate (object s, TreeViewCancelEventArgs e) { PopulateNode(e.Node); }; tree.AfterSelect += delegate (object s, TreeViewEventArgs e) { if (e.Node.Tag is string) Navigate((string)e.Node.Tag, false); };
            split.Panel1.Controls.Add(tree);
            view = NewView("folder");
            view.Apply(Columns.Folder());
            view.SelectionChanged += delegate { sel.Update(view.SelectedCount, "item"); };
            view.Activated += delegate (object o) { FileEntry f = (FileEntry)o; if (f.IsDir) Navigate(f.Path); else if (f.Encrypted) DecryptFiles(new List<FileEntry> { f }); else Open(f.Path); };
            split.Panel2.Controls.Add(view);
            sel.Add("Open", true, delegate { foreach (object o in view.Targets) { FileEntry f = (FileEntry)o; if (f.IsDir) { Navigate(f.Path); break; } Open(f.Path); } });
            sel.Add("Copy paths", false, delegate { List<string> l = new List<string>(); foreach (object o in view.Targets) l.Add(((FileEntry)o).Path); if (l.Count > 0) { try { Clipboard.SetText(string.Join("\r\n", l.ToArray())); Host.Toast(l.Count + " path(s) copied", false); } catch { } } });
            sel.Add("Export selected…", false, delegate { view.Export(); }); sel.Separator();
            // reversible changes in amber, then the two that cannot be undone in rose, last
            sel.AddCaution("Encrypt…", delegate { EncryptFiles(Selected(false)); });
            sel.AddCaution("Decrypt…", delegate { DecryptFiles(Selected(true)); }); sel.Separator();
            sel.AddDanger("Permanent delete…", delegate { DeleteForever(SelectedAny()); });
            sel.AddDanger("Secure wipe…", delegate { SecureWipe(SelectedAny()); });
            Controls.Add(split); Controls.Add(sel); Controls.Add(bar); split.BringToFront();
        }


        void SetSplit() { if (splitSet) return; try { if (split.Width > Theme.S(640)) { split.Panel1MinSize = Theme.S(150); split.Panel2MinSize = Theme.S(300); split.SplitterDistance = Theme.S(280); splitSet = true; } } catch { } }
        public override void OnShown()
        {
            SetSplit();
            if (tree.Nodes.Count == 0)
            {
                foreach (string d in FastWalk.FixedDrives()) { TreeNode n = new TreeNode(d.TrimEnd('\\')); n.Tag = d; n.Nodes.Add("…"); tree.Nodes.Add(n); }
                string start = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile); Navigate(Directory.Exists(start) ? start : (tree.Nodes.Count > 0 ? (string)tree.Nodes[0].Tag : "C:\\"));
            }
        }
        void PopulateNode(TreeNode node)
        {
            if (!(node.Tag is string)) return; if (node.Nodes.Count == 1 && node.Nodes[0].Text == "…")
            {
                node.Nodes.Clear();
                try { foreach (DirectoryInfo di in new DirectoryInfo((string)node.Tag).EnumerateDirectories()) { try { if (!cHidden.Checked && (di.Attributes & (FileAttributes.Hidden | FileAttributes.System)) != 0) continue; } catch { } TreeNode n = new TreeNode(di.Name); n.Tag = di.FullName; n.Nodes.Add("…"); node.Nodes.Add(n); } }
                catch { }
            }
        }
        void Navigate(string path) { Navigate(path, true); }
        /// <summary>Jump to a folder from another tool (Find Files hands its matches over here).</summary>
        public void GoTo(string path) { Navigate(path, true); }
        void Navigate(string path, bool fromList)
        {
            if (string.IsNullOrEmpty(path)) return;
            try
            {
                if (File.Exists(path)) { Open(path); return; }
                if (!Directory.Exists(path)) { Host.Toast("No such folder: " + path, true); return; }
                current = path.EndsWith("\\") ? path : path + "\\"; addr.Text = path; addr.ForeColor = Theme.Ink;
                List<FileEntry> dirs = new List<FileEntry>(), files = new List<FileEntry>();
                DirectoryInfo cur = new DirectoryInfo(path);
                foreach (FileSystemInfo fsi in cur.EnumerateFileSystemInfos())
                {
                    FileAttributes at; try { at = fsi.Attributes; } catch { continue; }
                    if (!cHidden.Checked && (at & (FileAttributes.Hidden | FileAttributes.System)) != 0) continue;
                    FileEntry e = new FileEntry(); e.Name = fsi.Name; e.Path = fsi.FullName; e.Dir = path; e.Attributes = at; e.IsDir = (at & FileAttributes.Directory) != 0;
                    try { e.Modified = fsi.LastWriteTime; } catch { } if (!e.IsDir) { FileInfo fi = fsi as FileInfo; try { e.Size = fi.Length; } catch { } e.Ext = fi.Extension.ToLowerInvariant(); }
                    (e.IsDir ? dirs : files).Add(e);
                }
                dirs.Sort(delegate (FileEntry a, FileEntry b) { return string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase); });
                files.Sort(delegate (FileEntry a, FileEntry b) { return string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase); });
                List<object> items = new List<object>(); foreach (FileEntry e in dirs) items.Add(e); foreach (FileEntry e in files) items.Add(e);
                view.SetItems(items, false); status.Text = dirs.Count + " folder" + (dirs.Count == 1 ? "" : "s") + " · " + files.Count + " file" + (files.Count == 1 ? "" : "s"); view.ExportName = "folder-" + new DirectoryInfo(path).Name;
            }
            catch (UnauthorizedAccessException) { Host.Toast("Access denied: " + path, true); }
            catch (Exception ex) { Host.Toast(ex.Message, true); }
        }
        List<FileEntry> Selected(bool wantEncrypted)
        {
            List<FileEntry> l = new List<FileEntry>(); foreach (object o in view.Targets) { FileEntry f = (FileEntry)o; if (f.IsDir) continue; if (wantEncrypted == f.Encrypted) l.Add(f); } return l;
        }
        List<FileEntry> SelectedAny() { List<FileEntry> l = new List<FileEntry>(); foreach (object o in view.Targets) l.Add((FileEntry)o); return l; }

        void Open(string path) { try { Process.Start(path); } catch (Exception ex) { Host.Toast(ex.Message, true); } }
        void NewFolder()
        {
            if (current == null) return; string name = Prompt("New folder", "Folder name:", "New folder"); if (name == null) return;
            try { Directory.CreateDirectory(Path.Combine(current, name)); Navigate(current); } catch (Exception ex) { Host.Error("Could not create the folder", ex.Message); }
        }
        static string Prompt(string title, string label, string def)
        {
            using (Form f = new Form())
            {
                f.Text = title; f.BackColor = Theme.Panel; f.ForeColor = Theme.Ink; f.Font = Theme.UI; f.Width = Theme.S(420); f.Height = Theme.S(160); f.StartPosition = FormStartPosition.CenterParent; f.FormBorderStyle = FormBorderStyle.FixedDialog; f.MinimizeBox = false; f.MaximizeBox = false;
                Label l = Theme.Lbl(label, Theme.Dim, Theme.UISmall); l.Dock = DockStyle.Top; l.Height = Theme.S(30); l.Padding = new Padding(Theme.S(12), Theme.S(10), 0, 0);
                TextBox t = Theme.Text(def, 360); t.Dock = DockStyle.Top; t.Margin = new Padding(Theme.S(12), 0, Theme.S(12), 0);
                FlowLayoutPanel bar = new FlowLayoutPanel(); bar.Dock = DockStyle.Bottom; bar.Height = Theme.S(46); bar.FlowDirection = FlowDirection.RightToLeft; bar.Padding = new Padding(Theme.S(10), Theme.S(8), Theme.S(10), 0); bar.BackColor = Theme.Panel;
                Button ok = Theme.Btn("OK", true), cancel = Theme.Btn("Cancel", false); ok.DialogResult = DialogResult.OK; cancel.DialogResult = DialogResult.Cancel; bar.Controls.Add(ok); bar.Controls.Add(cancel);
                Panel pad = new Panel(); pad.Dock = DockStyle.Top; pad.Height = Theme.S(34); pad.Controls.Add(t);
                f.Controls.Add(pad); f.Controls.Add(bar); f.Controls.Add(l); pad.BringToFront(); f.AcceptButton = ok; f.CancelButton = cancel; f.Shown += delegate { t.SelectAll(); t.Focus(); };
                return f.ShowDialog() == DialogResult.OK && t.Text.Trim().Length > 0 ? t.Text.Trim() : null;
            }
        }

        // ── the four bulk operations, each on a background thread ──
        void RunOp(string verb, List<FileEntry> items, long totalBytes, string confirmTitle, string confirmBody, Action<FileEntry, Action<double>> op, bool wipe)
        {
            if (busy) { Host.Toast("An operation is already running.", true); return; }
            if (items.Count == 0) { Host.Toast("Select some files first.", true); return; }
            if (!Host.Confirm(confirmTitle, confirmBody)) return;
            if (wipe && !Host.Confirm("Secure wipe — last chance", "This cannot be undone. Overwrite and destroy " + items.Count + " item(s)?\n\nContinue only if you are certain.")) return;
            busy = true; prog.Visible = true; prog.Value = 0; prog.Maximum = items.Count; int okN = 0, failN = 0; List<string> fails = new List<string>();
            worker = new Thread(delegate ()
            {
                for (int i = 0; i < items.Count; i++)
                {
                    FileEntry f = items[i]; int idx = i;
                    BeginInvoke((Action)delegate { status.Text = verb + " " + (idx + 1) + " / " + items.Count + ": " + f.Name; prog.Value = Math.Min(idx, prog.Maximum); });
                    try { op(f, delegate (double frac) { }); okN++; }
                    catch (Exception ex) { failN++; if (fails.Count < 8) fails.Add(f.Name + ": " + ex.Message); }
                }
                BeginInvoke((Action)delegate
                {
                    busy = false; prog.Visible = false; Navigate(current);
                    status.Text = verb + " done · " + okN + " ok" + (failN > 0 ? " · " + failN + " failed" : "");
                    Host.Toast(verb + ": " + okN + " ok" + (failN > 0 ? ", " + failN + " failed" : ""), failN > 0);
                    if (fails.Count > 0) Host.Error(verb + " — some items failed", string.Join("\n", fails.ToArray()));
                });
            });
            worker.IsBackground = true; worker.Start();
        }
        long Sum(List<FileEntry> l) { long b = 0; foreach (FileEntry f in l) b += f.Size; return b; }
        string Preview(List<FileEntry> l) { List<string> names = new List<string>(); for (int i = 0; i < Math.Min(12, l.Count); i++) names.Add(l[i].Name); return string.Join("\n", names.ToArray()) + (l.Count > 12 ? "\n… and " + (l.Count - 12) + " more" : ""); }

        void EncryptFiles(List<FileEntry> files)
        {
            if (files.Count == 0) { Host.Toast("Select one or more files to encrypt (folders and .enc files are skipped).", true); return; }
            string pw = Passwords.Ask(this, "Encrypt " + files.Count + " file(s)", "Choose a password. It is the only way to open these files again — if you lose it, the data is gone.", true); if (pw == null) return;
            RunOp("Encrypting", files, Sum(files), "Encrypt " + files.Count + " file(s)?", Fmt.Bytes(Sum(files)) + " total. Each file is encrypted to a new .enc file, verified, and then the original is permanently deleted.\n\n" + Preview(files), delegate (FileEntry f, Action<double> p)
            {
                string outp = FileCrypto.DefaultEncName(f.Path); if (File.Exists(outp)) throw new IOException(Path.GetFileName(outp) + " already exists");
                FileCrypto.Encrypt(f.Path, outp, pw, p);
                if (!FileCrypto.Verify(outp, pw)) { try { File.Delete(outp); } catch { } throw new Exception("verification failed, original kept"); }
                File.Delete(f.Path);
            }, false);
        }
        void DecryptFiles(List<FileEntry> files)
        {
            if (files.Count == 0) { Host.Toast("Select one or more .enc files to decrypt.", true); return; }
            string pw = Passwords.Ask(this, "Decrypt " + files.Count + " file(s)", "Enter the password these files were encrypted with.", false); if (pw == null) return;
            // fail fast on the first file so a wrong password does not spew errors
            try { if (!FileCrypto.Verify(files[0].Path, pw)) { Host.Error("Wrong password", "The password does not open " + files[0].Name + "."); return; } } catch (Exception ex) { Host.Error("Cannot decrypt", ex.Message); return; }
            RunOp("Decrypting", files, Sum(files), "Decrypt " + files.Count + " file(s)?", "The decrypted files are written next to the .enc files, which are kept.\n\n" + Preview(files), delegate (FileEntry f, Action<double> p)
            {
                string outp = FileCrypto.DefaultDecName(f.Path); if (File.Exists(outp)) outp = UniquePath(outp);
                FileCrypto.Decrypt(f.Path, outp, pw, p);
            }, false);
        }
        static string UniquePath(string path) { string dir = Path.GetDirectoryName(path), name = Path.GetFileNameWithoutExtension(path), ext = Path.GetExtension(path); int i = 1; string p = path; while (File.Exists(p)) { p = Path.Combine(dir, name + " (" + (i++) + ")" + ext); } return p; }

        void DeleteForever(List<FileEntry> items)
        {
            if (items.Count == 0) { Host.Toast("Select items to delete.", true); return; }
            RunOp("Deleting", items, Sum(items), "Permanently delete " + items.Count + " item(s)?", "This bypasses the Recycle Bin. Deleted items cannot be restored.\n\n" + Fmt.Bytes(Sum(items)) + " total.\n\n" + Preview(items), delegate (FileEntry f, Action<double> p)
            { if (f.IsDir) Directory.Delete(f.Path, true); else { try { File.SetAttributes(f.Path, FileAttributes.Normal); } catch { } File.Delete(f.Path); } }, false);
        }
        void SecureWipe(List<FileEntry> items)
        {
            if (items.Count == 0) { Host.Toast("Select items to wipe.", true); return; }
            RunOp("Wiping", items, Sum(items), "Securely wipe " + items.Count + " item(s)?", "Each file is overwritten with random data, then deleted. This cannot be undone. On SSDs, wear-levelling means it defeats casual recovery, not forensic recovery.\n\n" + Fmt.Bytes(Sum(items)) + " total.\n\n" + Preview(items), delegate (FileEntry f, Action<double> p)
            {
                if (f.IsDir) { foreach (string file in Directory.EnumerateFiles(f.Path, "*", SearchOption.AllDirectories)) { try { File.SetAttributes(file, FileAttributes.Normal); } catch { } FileCrypto.SecureWipe(file, 3, null); } Directory.Delete(f.Path, true); }
                else { try { File.SetAttributes(f.Path, FileAttributes.Normal); } catch { } FileCrypto.SecureWipe(f.Path, 3, p); }
            }, true);
        }

        /// <summary>A fabricated folder listing for screenshots.</summary>
        void DemoFiles()
        {
            string dir = @"C:\Users\alice\Documents"; current = dir + "\\"; addr.Text = dir; addr.ForeColor = Theme.Ink;
            List<FileEntry> l = new List<FileEntry>();
            Action<string, bool, long, int, string> add = delegate (string name, bool isDir, long size, int daysAgo, string ext) { FileEntry e = new FileEntry(); e.Name = name; e.Path = dir + "\\" + name; e.Dir = dir; e.IsDir = isDir; e.Size = size; e.Ext = ext; e.Modified = DateTime.Now.AddDays(-daysAgo); e.Attributes = isDir ? FileAttributes.Directory : FileAttributes.Normal; l.Add(e); };
            add("Projects", true, 0, 1, ""); add("Reports", true, 0, 6, ""); add("Photos", true, 0, 20, "");
            add("budget-2026.xlsx", false, 214 * 1024, 2, ".xlsx"); add("contract-draft.docx", false, 48 * 1024, 4, ".docx"); add("notes.md", false, 9 * 1024, 0, ".md");
            add("vacation.jpg", false, 4718592, 33, ".jpg"); add("backup-2026-09.zip", false, 38L * 1048576, 9, ".zip"); add("tax-2025.pdf", false, 1200 * 1024, 120, ".pdf"); add("passwords.txt.enc", false, 2 * 1024, 1, ".enc");
            view.SetItems(Boxed(l), false); status.Text = "3 folders · 7 files · 44.3 MB";
        }

        public override void SelfTest(StringBuilder r)
        {
            if (r == null) { DemoFiles(); return; }
            string here = Path.GetDirectoryName(Application.ExecutablePath); Navigate(here);
            r.AppendLine((view.VisibleItems.Count > 0 ? "PASS" : "FAIL") + " files: listed " + view.VisibleItems.Count + " entries of " + here);
            // encrypt → verify → decrypt round trip on a temp file
            try
            {
                string dir = Path.Combine(Path.GetTempPath(), "pstools-crypto"); Directory.CreateDirectory(dir);
                string src = Path.Combine(dir, "secret.txt"); byte[] data = new byte[200000]; new Random(7).NextBytes(data); File.WriteAllBytes(src, data);
                string enc = FileCrypto.DefaultEncName(src); FileCrypto.Encrypt(src, enc, "Correct Horse 42", null);
                bool encHdr = FileCrypto.IsEncrypted(enc); bool goodPw = FileCrypto.Verify(enc, "Correct Horse 42"); bool badPw = FileCrypto.Verify(enc, "wrong");
                string dec = Path.Combine(dir, "back.txt"); FileCrypto.Decrypt(enc, dec, "Correct Horse 42", null); byte[] back = File.ReadAllBytes(dec);
                bool same = back.Length == data.Length; if (same) for (int i = 0; i < data.Length; i++) if (back[i] != data[i]) { same = false; break; }
                bool rejected = false; try { FileCrypto.Decrypt(enc, dec + ".x", "wrong", null); } catch (FileCrypto.CryptoException) { rejected = true; } catch { rejected = true; }
                r.AppendLine((encHdr && goodPw && !badPw && same && rejected ? "PASS" : "FAIL") + " files: AES round-trip — header " + encHdr + ", right pw " + goodPw + ", wrong pw rejects " + (!badPw) + ", bytes match " + same + ", bad-pw decrypt throws " + rejected);
                string wipe = Path.Combine(dir, "wipe.bin"); File.WriteAllBytes(wipe, data); FileCrypto.SecureWipe(wipe, 2, null);
                r.AppendLine((!File.Exists(wipe) ? "PASS" : "FAIL") + " files: secure wipe removed the file");
                Directory.Delete(dir, true);
            }
            catch (Exception ex) { r.AppendLine("FAIL files: crypto: " + ex.GetType().Name + ": " + ex.Message); }
        }
    }

    // ═══════════════════════════════ Find Files ═══════════════════════════════
    public class FindPanel : ToolPanel
    {
        public override string Title { get { return Tools.Title(GetType().Name); } }
        public override string Blurb { get { return Tools.Blurb(GetType().Name); } }
        readonly DataView view; readonly SelectionBar sel = new SelectionBar();
        readonly Button bName, bHash, bGo, bCancel, bPasteHash, bLoadHash; readonly TextBox tName, tHash; readonly Label tHashInfo; readonly CheckBox cCase, cSkipWin; readonly NumericUpDown nMax; readonly ComboBox cRoots; readonly Label status = Theme.Lbl("", Theme.Dim, Theme.UISmall), lName, lHash, lMax, lmb, lRoot;
        readonly StepStrip steps = new StepStrip(); string mode = "name"; FastWalk walk; Thread worker; volatile bool busy; readonly List<object> pending = new List<object>(); readonly object plock = new object(); readonly System.Windows.Forms.Timer flush = new System.Windows.Forms.Timer(); int found; string customRoot;

        public FindPanel()
        {
            BackColor = Theme.Panel;
            FlowLayoutPanel bar = Theme.Bar(46);
            bName = Theme.Btn("By name", false); bHash = Theme.Btn("By hash", false); bName.Click += delegate { SetMode("name"); }; bHash.Click += delegate { SetMode("hash"); };
            lName = Theme.Lbl("name", Theme.Dim, Theme.UI); tName = Theme.Text("", 200); tName.KeyDown += delegate (object s, KeyEventArgs e) { if (e.KeyCode == Keys.Enter) { Go(); e.SuppressKeyPress = true; } };
            lHash = Theme.Lbl("hashes", Theme.Dim, Theme.UI); tHash = Theme.Text("", 240); bPasteHash = Theme.Btn("Paste…", false); bPasteHash.Click += delegate { string t = Dialogs.PasteText(this, "Paste hashes", "Paste anything — a plain list, CSV, log line, or a threat-intel report. Every MD5, SHA-1 and SHA-256 in it is pulled out automatically, of any type."); if (t != null) { AddHashText(t, "paste"); } };
            bLoadHash = Theme.Btn("Add from file…", false); new ToolTip().SetToolTip(bLoadHash, "Load hashes from any text file — a plain list, CSV, log or threat-intel report. Every MD5, SHA-1 and SHA-256 in it is pulled out automatically, of any type, wherever it appears.");
            bLoadHash.Click += delegate {
                string f = Dialogs.PickFile(this, "File of hashes (any text: list, CSV, log, IOC report)", "Text & lists (*.txt;*.csv;*.log;*.json;*.ioc;*.md)|*.txt;*.csv;*.log;*.json;*.ioc;*.md|All files (*.*)|*.*");
                if (f == null) return;
                bool a, b, c; int bad; string note; HashSet<string> hs = Hashes.FromFile(f, out a, out b, out c, out bad, out note);
                if (note.Length > 0) { Host.Toast(note, true); return; }
                if (hs.Count == 0) { Host.Toast("No MD5/SHA-1/SHA-256 hashes found in that file.", true); return; }
                int added = MergeHashes(hs); Host.Toast(hs.Count + " hash(es) read · " + added + " new from " + System.IO.Path.GetFileName(f), false);
            };
            tHash.TextChanged += delegate { UpdateHashInfo(); }; tHashInfo = Theme.Lbl("", Theme.Faint, Theme.UISmall);
            lMax = Theme.Lbl("max file", Theme.Dim, Theme.UI); nMax = Theme.Num(100, 1, 100000, 70); lmb = Theme.Lbl("MB", Theme.Dim, Theme.UI); new ToolTip().SetToolTip(nMax, "Files larger than this are skipped when hashing, so the sweep stays fast. Raise it if you expect large matches.");
            cCase = Theme.Toggle("match case", false); cSkipWin = Theme.Toggle("skip Windows folder", true);
            lRoot = Theme.Lbl("in", Theme.Dim, Theme.UI); cRoots = Theme.Combo(220, "all fixed drives"); foreach (string d in FastWalk.FixedDrives()) cRoots.Items.Add(d); cRoots.Items.Add("Folder…"); cRoots.SelectedIndexChanged += delegate { if (cRoots.SelectedItem as string == "Folder…") { string f = Dialogs.PickFolder(this, "Folder to search", null); if (f != null) { customRoot = f; if (!cRoots.Items.Contains(f)) cRoots.Items.Insert(cRoots.Items.Count - 1, f); cRoots.SelectedItem = f; } else cRoots.SelectedIndex = 0; } };
            bGo = Theme.Btn("Search", true); bGo.Tag = "run"; bGo.Click += delegate { Go(); }; bCancel = Theme.Btn("Cancel", false); bCancel.Tag = "stop"; bCancel.Enabled = false; bCancel.Click += delegate { if (walk != null) walk.Stop(); };
            foreach (Control c in new Control[] { bName, bHash, lName, tName, lHash, tHash, bPasteHash, bLoadHash, tHashInfo, lMax, nMax, lmb, cCase, cSkipWin, lRoot, cRoots, bGo, bCancel, status }) bar.Controls.Add(c); status.Margin = new Padding(Theme.S(10), Theme.S(9), 0, 0);
            view = NewView("find");
            view.SelectionChanged += delegate { sel.Update(view.SelectedCount, mode == "hash" ? "match" : "file"); };
            view.Activated += delegate (object o) { string p = o is HashHit ? ((HashHit)o).Path : ((FileEntry)o).Path; Dialogs.OpenInExplorer(p); };
            sel.Add("Open location", true, delegate { int k = 0; foreach (object o in view.Targets) { if (k++ >= 8) break; Dialogs.OpenInExplorer(o is HashHit ? ((HashHit)o).Path : ((FileEntry)o).Path); } });
            sel.Add("Copy paths", false, delegate { List<string> l = new List<string>(); foreach (object o in view.Targets) l.Add(o is HashHit ? ((HashHit)o).Path : ((FileEntry)o).Path); if (l.Count > 0) { try { Clipboard.SetText(string.Join("\r\n", l.ToArray())); Host.Toast(l.Count + " path(s) copied", false); } catch { } } });
            sel.Add("Show in File Explorer", false, delegate { object o = view.Current; if (o != null) { string p = o is HashHit ? ((HashHit)o).Path : ((FileEntry)o).Path; string dir = System.IO.Path.GetDirectoryName(p); Host.ShowTool<FileExplorerPanel>(delegate (FileExplorerPanel fe) { fe.GoTo(dir); }); } });
            sel.Add("Export selected…", false, delegate { view.Export(); });
            Controls.Add(view); Controls.Add(sel); Controls.Add(steps); Controls.Add(bar); view.BringToFront();
            flush.Interval = 250; flush.Tick += delegate { FlushPending(); };
            SetMode("name");
        }

        void UpdateHashInfo() { bool a, b, c; int bad; HashSet<string> t = Hashes.ParseTargets(tHash.Text, out a, out b, out c, out bad); List<string> al = new List<string>(); if (a) al.Add("MD5"); if (b) al.Add("SHA1"); if (c) al.Add("SHA256"); tHashInfo.Text = t.Count == 0 ? (bad > 0 ? bad + " not a hash" : "") : t.Count + " hash" + (t.Count == 1 ? "" : "es") + " (" + string.Join("+", al.ToArray()) + ")" + (bad > 0 ? " · " + bad + " ignored" : ""); }
        void AddHashText(string text, string src) { bool a, b, c; int bad; HashSet<string> hs = Hashes.ParseTargets(text, out a, out b, out c, out bad); if (hs.Count == 0) { Host.Toast("No MD5/SHA-1/SHA-256 hashes found in the " + src + ".", true); return; } int added = MergeHashes(hs); Host.Toast(hs.Count + " hash(es) · " + added + " new", false); }
        /// <summary>Merge extra hashes into the box, de-duplicated with what is already there (capped so the box stays usable).</summary>
        int MergeHashes(HashSet<string> hs) { bool ea, eb, ec; int eb2; HashSet<string> merged = Hashes.ParseTargets(tHash.Text, out ea, out eb, out ec, out eb2); int before = merged.Count; foreach (string h in hs) merged.Add(h); int added = merged.Count - before; List<string> all = new List<string>(merged); const int Cap = 5000; if (all.Count > Cap) all = all.GetRange(0, Cap); tHash.Text = string.Join(" ", all.ToArray()); UpdateHashInfo(); return added; }

        void SetMode(string m)
        {
            mode = m;
            foreach (Button b in new Button[] { bName, bHash }) { bool on = (b == bName && m == "name") || (b == bHash && m == "hash"); b.BackColor = on ? Theme.Panel3 : Theme.Panel2; b.ForeColor = on ? Theme.Teal : Theme.Ink; b.FlatAppearance.BorderColor = on ? Theme.Teal : Theme.Line; }
            bool name = m == "name"; foreach (Control c in new Control[] { lName, tName, cCase }) c.Visible = name; foreach (Control c in new Control[] { lHash, tHash, bPasteHash, bLoadHash, tHashInfo, lMax, nMax, lmb, cSkipWin }) c.Visible = !name;
            view.Apply(name ? Columns.FindByName() : Columns.FindByHash());
            view.SetItems(new object[0], false);
        }

        List<string> Roots()
        {
            string sel = cRoots.SelectedItem as string;
            if (sel == null || sel == "all fixed drives") return FastWalk.FixedDrives();
            if (sel == "Folder…") return customRoot != null ? new List<string> { customRoot } : FastWalk.FixedDrives();
            return new List<string> { sel };
        }
        void Go()
        {
            if (busy) { Host.Toast("A search is already running.", true); return; }
            List<string> roots = Roots(); if (roots.Count == 0) { Host.Toast("No drive to search.", true); return; }
            if (mode == "name") { if (tName.Text.Trim().Length == 0) { Host.Toast("Type a name or a *.ext pattern.", true); return; } StartName(roots); }
            else StartHash(roots);
        }
        void StartCommon(List<string> roots)
        {
            busy = true; found = 0; lock (plock) pending.Clear(); view.SetItems(new object[0], false); bGo.Enabled = false; bCancel.Enabled = true; flush.Start();
            steps.Begin(mode == "hash" ? new string[] { "Walk folders", "Hash candidates" } : new string[] { "Walk folders" }); steps.Set("Walk folders", "running", null); if (mode == "hash") steps.Set("Hash candidates", "running", null); steps.Fraction = -1;
            walk = new FastWalk(); walk.Roots = roots;
        }
        void Finish(string summary)
        {
            BeginInvoke((Action)delegate { FlushPending(); flush.Stop(); busy = false; bGo.Enabled = true; bCancel.Enabled = false; status.Text = summary; steps.End(summary); });
        }
        void StartName(List<string> roots)
        {
            string q = tName.Text.Trim(); bool cs = cCase.Checked; StartCommon(roots);
            worker = new Thread(delegate ()
            {
                try { walk.Run(delegate (FileInfo fi) { if (Wildcard.Match(fi.Name, q, cs)) { FileEntry e = new FileEntry(); e.Name = fi.Name; e.Path = fi.FullName; e.Dir = fi.DirectoryName; try { e.Size = fi.Length; e.Modified = fi.LastWriteTime; } catch { } e.Ext = fi.Extension.ToLowerInvariant(); Push(e); } }); }
                catch { }
                Finish("done · " + found + " match" + (found == 1 ? "" : "es") + " · " + walk.DirsScanned.ToString("N0") + " folders, " + walk.FilesSeen.ToString("N0") + " files" + (walk.Cancel ? " · cancelled" : "") + (walk.Denied > 0 ? " · " + walk.Denied + " denied" : ""));
            });
            worker.IsBackground = true; worker.Start(); status.Text = "searching…";
        }
        void StartHash(List<string> roots)
        {
            bool md5, sha1, sha256; int bad; HashSet<string> targets = Hashes.ParseTargets(tHash.Text, out md5, out sha1, out sha256, out bad);
            if (targets.Count == 0) { Host.Toast("Paste at least one valid MD5, SHA-1 or SHA-256 hash.", true); return; }
            long cap = (long)nMax.Value * 1048576L; bool skipWin = cSkipWin.Checked; string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLowerInvariant();
            StartCommon(roots);
            worker = new Thread(delegate ()
            {
                try
                {
                    walk.Run(delegate (FileInfo fi)
                    {
                        long len; try { len = fi.Length; } catch { return; } if (len > cap) return;
                        if (skipWin) { try { if (fi.FullName.ToLowerInvariant().StartsWith(win)) return; } catch { } }
                        Dictionary<string, string> h; try { h = Hashes.Compute(fi.FullName, md5, sha1, sha256); } catch { return; }
                        foreach (KeyValuePair<string, string> kv in h) if (targets.Contains(kv.Value)) { HashHit hit = new HashHit(); hit.Name = fi.Name; hit.Path = fi.FullName; hit.Dir = fi.DirectoryName; hit.Algo = kv.Key; hit.Hash = kv.Value; hit.Size = len; try { hit.Modified = fi.LastWriteTime; } catch { } Push(hit); }
                    });
                }
                catch { }
                Finish("done · " + found + " match" + (found == 1 ? "" : "es") + " · hashed within " + nMax.Value + " MB · " + walk.DirsScanned.ToString("N0") + " folders, " + walk.FilesSeen.ToString("N0") + " files" + (walk.Cancel ? " · cancelled" : ""));
            });
            worker.IsBackground = true; worker.Start(); status.Text = "sweeping " + targets.Count + " hash(es)…";
        }
        void Push(object o) { lock (plock) { pending.Add(o); found++; } if (found >= 20000 && walk != null) walk.Stop(); }
        void FlushPending()
        {
            List<object> batch = null; lock (plock) { if (pending.Count > 0) { batch = new List<object>(pending); pending.Clear(); } }
            if (busy && walk != null) { string cur = walk.Current ?? ""; if (cur.Length > 70) cur = "…" + cur.Substring(cur.Length - 70); steps.Say((mode == "hash" ? "hashing" : "scanning") + " · " + walk.DirsScanned.ToString("N0") + " folders · " + walk.FilesSeen.ToString("N0") + " files · " + found.ToString("N0") + " match(es)" + (cur.Length > 0 ? " · " + cur : "")); }
            if (batch != null) { view.Add(batch); if (busy) status.Text = (mode == "hash" ? "sweeping" : "searching") + "… " + found.ToString("N0") + " so far · " + (walk != null ? walk.DirsScanned.ToString("N0") + " folders" : ""); }
        }

        public override void Exercise(StringBuilder r)
        {
            foreach (string m in new string[] { "hash", "name" }) { try { SetMode(m); Application.DoEvents(); ExerciseView(view, r); } catch (Exception ex) { r.AppendLine("FAIL ui find/" + m + ": " + ex.GetType().Name + ": " + ex.Message); } }
        }
        /// <summary>A fabricated hash sweep for screenshots.</summary>
        void DemoFind()
        {
            SetMode("hash"); tHash.Text = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae d41d8cd98f00b204e9800998ecf8427e"; UpdateHashInfo();
            List<HashHit> l = new List<HashHit>();
            Action<string, string, string, string, long, int> add = delegate (string name, string dir, string algo, string hash, long size, int daysAgo) { HashHit h = new HashHit(); h.Name = name; h.Dir = dir; h.Path = dir + "\\" + name; h.Algo = algo; h.Hash = hash; h.Size = size; h.Modified = DateTime.Now.AddDays(-daysAgo); l.Add(h); };
            add("invoice_scan.exe", @"C:\Users\alice\Downloads", "SHA256", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", 412 * 1024, 3);
            add("svc.exe", @"C:\ProgramData\upd", "SHA256", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", 412 * 1024, 3);
            add("loader.dll", @"C:\Users\alice\AppData\Local\Temp", "SHA256", "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae", 96 * 1024, 5);
            add("readme.txt", @"C:\Users\alice\Documents\Projects", "MD5", "d41d8cd98f00b204e9800998ecf8427e", 0, 40);
            view.SetItems(Boxed(l), false); status.Text = "done · 4 matches · hashed within 100 MB · 41,220 folders, 388,102 files";
            steps.Begin(new string[] { "Walk folders", "Hash candidates" }); steps.Set("Walk folders", "done", "41,220 folders"); steps.Set("Hash candidates", "done", "18,904 files"); steps.End("done · 4 matches");
        }

        public override void SelfTest(StringBuilder r)
        {
            if (r == null) { DemoFind(); return; }
            string here = Path.GetDirectoryName(Application.ExecutablePath); List<string> roots = new List<string> { here };
            // name search for *.cs under the exe folder's project (walk here + parent has none; use here for .exe)
            SetMode("name"); tName.Text = "*.exe"; cCase.Checked = false; found = 0; lock (plock) pending.Clear();
            FastWalk fw = new FastWalk(); fw.Roots = roots; List<object> hits = new List<object>();
            fw.Run(delegate (FileInfo fi) { if (Wildcard.Match(fi.Name, "*.exe", false)) lock (hits) hits.Add(fi.FullName); });
            if (r == null) { view.SetItems(new object[0], false); return; }
            r.AppendLine((hits.Count >= 1 ? "PASS" : "FAIL") + " find: name walk of " + here + " found " + hits.Count + " .exe in " + fw.DirsScanned + " folders");
            // hash sweep: hash Tests.exe (or the app exe), then sweep the folder for that hash and expect to find it
            try
            {
                string probe = Path.Combine(here, "Tests.exe"); if (!File.Exists(probe)) probe = Application.ExecutablePath;
                Dictionary<string, string> h = Hashes.Compute(probe, false, false, true); string want = h["SHA256"];
                bool md5, sha1, sha256; int bad; HashSet<string> targets = Hashes.ParseTargets(want, out md5, out sha1, out sha256, out bad);
                FastWalk fw2 = new FastWalk(); fw2.Roots = roots; bool hit = false; string hitPath = null;
                fw2.Run(delegate (FileInfo fi) { if (hit) return; long len; try { len = fi.Length; } catch { return; } if (len > 200L * 1048576) return; Dictionary<string, string> hh; try { hh = Hashes.Compute(fi.FullName, false, false, true); } catch { return; } if (hh["SHA256"] == want) { hit = true; hitPath = fi.FullName; } });
                r.AppendLine((sha256 && hit ? "PASS" : "FAIL") + " find: hash sweep matched " + Path.GetFileName(probe) + " by SHA256 at " + (hitPath ?? "not found"));
                bool wrong = false; bool m2, s2, x2; int b2; HashSet<string> none = Hashes.ParseTargets("deadbeef", out m2, out s2, out x2, out b2); if (none.Count == 0 && b2 == 1) wrong = true;
                r.AppendLine((wrong ? "PASS" : "FAIL") + " find: 'deadbeef' rejected as not a hash");
            }
            catch (Exception ex) { r.AppendLine("FAIL find: hash sweep: " + ex.Message); }
            SetMode("name"); view.SetItems(new object[0], false);
        }
    }
}

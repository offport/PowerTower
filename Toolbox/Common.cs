// Shared GUI helpers (the app exe only, never the CLI or the collector): the one log window, the one
// "save a report" flow, the feed-cache opener. Several panels used to carry their own copy of each.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Windows.Forms;

namespace PSTools
{
    public static class Common
    {
        /// <summary>A modal, read-only, monospace log window with Copy all and Close - every panel's "Log…" opens this.</summary>
        public static void LogWindow(Control owner, string title, string text)
        {
            using (Form f = new Form())
            {
                f.Text = title; f.BackColor = Theme.Panel; f.ForeColor = Theme.Ink; f.Font = Theme.UI; f.Width = Theme.S(820); f.Height = Theme.S(520); f.StartPosition = FormStartPosition.CenterParent; f.MinimizeBox = false; f.ShowIcon = false;
                TextBox t = new TextBox(); t.Multiline = true; t.ReadOnly = true; t.Dock = DockStyle.Fill; t.BackColor = Theme.Panel2; t.ForeColor = Theme.Ink; t.Font = Theme.Mono; t.ScrollBars = ScrollBars.Both; t.WordWrap = false; t.BorderStyle = BorderStyle.FixedSingle; t.Text = text ?? "";
                FlowLayoutPanel bar = new FlowLayoutPanel(); bar.Dock = DockStyle.Bottom; bar.Height = Theme.S(46); bar.FlowDirection = FlowDirection.RightToLeft; bar.Padding = new Padding(Theme.S(10), Theme.S(8), Theme.S(10), 0); bar.BackColor = Theme.Panel;
                Button close = Theme.Btn("Close", true), copy = Theme.Btn("Copy all", false); close.DialogResult = DialogResult.Cancel; copy.Click += delegate { try { Clipboard.SetText(t.Text); } catch { } }; bar.Controls.Add(close); bar.Controls.Add(copy);
                Panel body = new Panel(); body.Dock = DockStyle.Fill; body.Padding = new Padding(Theme.S(10), Theme.S(10), Theme.S(10), 0); body.Controls.Add(t);
                f.Controls.Add(body); f.Controls.Add(bar); body.BringToFront(); f.CancelButton = close; f.ShowDialog(owner);
            }
        }
        /// <summary>The text of a scan log: the problems first under their own heading, then the log lines; or the "nothing yet" message.</summary>
        public static string LogText(IList<string> errors, IEnumerable<string> log, string problemsHead, string empty)
        {
            StringBuilder sb = new StringBuilder(); bool any = false;
            if (errors != null && errors.Count > 0) { sb.AppendLine(problemsHead); foreach (string e in errors) sb.AppendLine("  " + e); sb.AppendLine(); any = true; }
            if (log != null) { List<string> l = new List<string>(log); if (l.Count > 0) { sb.AppendLine("LOG"); foreach (string s in l) sb.AppendLine("  " + s); any = true; } }
            return any ? sb.ToString() : empty;
        }
        /// <summary>Save a report: pick the file, write it through the callback (fmt, path), toast, offer to open it. Formats: md, json, pdf.</summary>
        public static void SaveReport(Shell host, Control owner, string what, string stem, string fmt, Action<string, string> write)
        {
            string filter = fmt == "md" ? "Markdown (*.md)|*.md" : fmt == "json" ? "JSON (*.json)|*.json" : fmt == "csv" ? "CSV (*.csv)|*.csv" : "PDF (*.pdf)|*.pdf";
            using (SaveFileDialog d = new SaveFileDialog())
            {
                d.Filter = filter + "|All files|*.*"; d.FileName = stem + "." + fmt; d.Title = "Save the " + what + " as " + fmt.ToUpperInvariant();
                if (d.ShowDialog(owner) != DialogResult.OK) return;
                try
                {
                    write(fmt, d.FileName); host.Toast("Saved " + Path.GetFileName(d.FileName), false);
                    if (host.Confirm("Report saved", "Saved to:\n" + d.FileName + "\n\nOpen it now?")) { try { Process.Start(d.FileName); } catch { Dialogs.OpenInExplorer(d.FileName); } }
                }
                catch (Exception ex) { host.Error("Save failed", ex.Message); }
            }
        }
        /// <summary>The feed cache next to the exe, or under LocalAppData when that folder is not writable (a read-only USB stick).</summary>
        public static FeedCache OpenFeedCache()
        {
            string local = Path.Combine(Path.GetDirectoryName(Application.ExecutablePath), "cache");
            try { Directory.CreateDirectory(local); string probe = Path.Combine(local, ".write-test"); File.WriteAllText(probe, "ok"); File.Delete(probe); return new FeedCache(local); }
            catch { return new FeedCache(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PowerTower", "cache")); }
        }
    }
}

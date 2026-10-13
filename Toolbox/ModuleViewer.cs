// ModuleViewer: a modal window listing the DLLs loaded in a process, with each module's signer and whether
// it lives somewhere unusual - the way injected or side-loaded code shows up. Opened from Resource Usage.
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Threading;
using System.Windows.Forms;

namespace PSTools
{
    public static class ModuleViewer
    {
        public static void Show(Shell host, int pid, string name)
        {
            Form f = new Form(); f.Text = "Modules loaded in " + name + " (PID " + pid + ")"; f.BackColor = Theme.Bg; f.ForeColor = Theme.Ink; f.Font = Theme.UI;
            f.StartPosition = FormStartPosition.CenterParent; f.Width = Theme.S(900); f.Height = Theme.S(600); f.ShowIcon = false; f.MinimizeBox = false;
            Label status = Theme.Lbl("reading modules…", Theme.Dim, Theme.UISmall); status.Dock = DockStyle.Bottom; status.Height = Theme.S(24); status.Padding = new Padding(Theme.S(10), Theme.S(4), 0, 0);
            DataView view = new DataView(); view.ExportName = "modules-" + name; view.Dock = DockStyle.Fill;
            view.Apply(Columns.Modules(name));
            f.Controls.Add(view); f.Controls.Add(status);

            Thread t = new Thread(delegate ()
            {
                try
                {
                    List<ModuleInfo> mods = Trust.Modules(pid);
                    foreach (ModuleInfo m in mods) { m.Sig = Trust.Verify(m.Path); string[] vi = Trust.VersionInfo(m.Path); m.Company = vi[0]; }
                    int unsigned = 0, odd = 0; foreach (ModuleInfo m in mods) { if (m.Sig.Status == "unsigned" || m.Sig.Status == "invalid") unsigned++; if (m.Location == "user-writable" || m.Location == "other") odd++; }
                    int u = unsigned, od = odd; List<ModuleInfo> ms = mods;
                    try { f.BeginInvoke((Action)delegate { object[] boxed = ms.ToArray(); view.SetItems(boxed, false); status.Text = ms.Count + " module(s) · " + u + " unsigned/invalid · " + od + " outside Windows/Program Files"; }); } catch { }
                }
                catch (Exception ex) { try { f.BeginInvoke((Action)delegate { status.Text = "could not read modules: " + ex.Message + (host != null && !host.IsElevated ? " — try Restart as administrator" : ""); }); } catch { } }
            });
            t.IsBackground = true; t.Start();
            f.ShowDialog(host);
        }
    }
}

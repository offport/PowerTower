// About: what this toolbox is and what each module does, grouped by job, each with its own icon. Drawn as a
// scrolling page rather than a grid, since it is prose, not data.
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;

namespace PSTools
{
    public class AboutPanel : ToolPanel
    {
        public override string Title { get { return Tools.Title(GetType().Name); } }
        public override string Blurb { get { return Tools.Blurb(GetType().Name); } }

        readonly Panel page = new Panel();

        public AboutPanel()
        {
            BackColor = Theme.Panel; page.Dock = DockStyle.Fill; page.AutoScroll = true; page.BackColor = Theme.Panel; page.Padding = new Padding(Theme.S(24), Theme.S(18), Theme.S(24), Theme.S(24));
            Controls.Add(page);
            int y = 0; int w = Theme.S(860);
            y = AddIntro(y, w);
            foreach (string grp in Tools.Groups)
            {
                bool any = false; foreach (ToolInfo ti in Tools.All) if (ti.Group == grp && !ti.CliOnly) any = true; if (!any) continue;   // command-line-only groups have no page here
                y += Theme.S(14);
                Label h = Theme.Lbl(grp, Theme.Teal, Theme.Big); h.Location = new Point(Theme.S(4), y); page.Controls.Add(h); y += Theme.S(30);
                Panel rule = new Panel(); rule.BackColor = Theme.Line; rule.Location = new Point(Theme.S(4), y); rule.Size = new Size(w, 1); page.Controls.Add(rule); y += Theme.S(8);
                foreach (ToolInfo ti in Tools.All) { if (ti.Group != grp || ti.CliOnly) continue; AboutRow row = new AboutRow(ti.Panel, ti.Title, ti.About, w); row.Location = new Point(0, y); row.Picked += delegate (string key) { Jump(key); }; page.Controls.Add(row); y += row.Height; }
            }
            Label foot = Theme.Lbl("Self-contained C#: nothing runs through powershell.exe, nothing is installed, and the only network traffic is the vulnerability feeds, each of which can be switched off. Every tool here except the two maps is also available from the command line as PowerTowerCli.exe, with the same names, columns and filters.", Theme.Dim, Theme.UISmall);
            foot.AutoSize = false; foot.Location = new Point(Theme.S(4), y + Theme.S(16)); foot.Size = new Size(w, Theme.S(48)); page.Controls.Add(foot);
        }

        int AddIntro(int y, int w)
        {
            Label t = Theme.Lbl("A portable security workbench for this machine", Theme.Ink, Theme.Title); t.Location = new Point(Theme.S(4), y); page.Controls.Add(t); y += Theme.S(34);
            Label d = Theme.Lbl("Every job is a table you can sort, search, filter by any column, tick and act on. Long scans show a step strip; anything that needs administrator rights says so. Results export to CSV, and several tools export full reports. Click any tool below to open it.", Theme.Dim, Theme.UI);
            d.AutoSize = false; d.Location = new Point(Theme.S(4), y); d.Size = new Size(w, Theme.S(44)); page.Controls.Add(d); y += Theme.S(46);
            return y;
        }
        void Jump(string key) { foreach (ToolPanel p in new ToolPanel[0]) { } try { Host.GetType(); } catch { } SelectByClass(key); }
        void SelectByClass(string key)
        {
            // Shell has no public "select by class name", so use the reflection-free ShowTool<T> via a small map
            switch (key)
            {
                case "ReconPanel": Host.ShowTool<ReconPanel>(null); break;
                case "BlockerPanel": Host.ShowTool<BlockerPanel>(null); break;
                case "ReachPanel": Host.ShowTool<ReachPanel>(null); break;
                case "ConnPanel": Host.ShowTool<ConnPanel>(null); break;
                case "HogsPanel": Host.ShowTool<HogsPanel>(null); break;
                case "DiskPanel": Host.ShowTool<DiskPanel>(null); break;
                case "DeletedPanel": Host.ShowTool<DeletedPanel>(null); break;
                case "FileExplorerPanel": Host.ShowTool<FileExplorerPanel>(null); break;
                case "FindPanel": Host.ShowTool<FindPanel>(null); break;
                case "DupesPanel": Host.ShowTool<DupesPanel>(null); break;
                case "VulnPanel": Host.ShowTool<VulnPanel>(null); break;
                case "SoftwarePanel": Host.ShowTool<SoftwarePanel>(null); break;
                case "AutorunsPanel": Host.ShowTool<AutorunsPanel>(null); break;
                case "EventsPanel": Host.ShowTool<EventsPanel>(null); break;
                case "ChecklistPanel": Host.ShowTool<ChecklistPanel>(null); break;
                case "SecretsPanel": Host.ShowTool<SecretsPanel>(null); break;
                case "CredsPanel": Host.ShowTool<CredsPanel>(null); break;
                case "FirewallPanel": Host.ShowTool<FirewallPanel>(null); break;
                case "MapPanel": Host.ShowTool<MapPanel>(null); break;
            }
        }
    }

    class AboutRow : Control
    {
        readonly string key, title, desc; bool hover;
        public event Action<string> Picked;
        public AboutRow(string key, string title, string desc, int width)
        {
            this.key = key; this.title = title; this.desc = desc;
            SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
            Width = width; Height = Theme.S(58); Cursor = Cursors.Hand; BackColor = Theme.Panel;
            MouseEnter += delegate { hover = true; Invalidate(); }; MouseLeave += delegate { hover = false; Invalidate(); };
            Click += delegate { if (Picked != null) Picked(key); };
        }
        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics; g.Clear(hover ? Theme.Panel2 : Theme.Panel);
            int ic = Theme.S(30); Icons.Paint(g, key, new Rectangle(Theme.S(10), (Height - ic) / 2, ic, ic), hover ? Theme.Teal : Theme.TealSoft);
            TextRenderer.DrawText(g, title, Theme.UIBold, new Point(Theme.S(54), Theme.S(9)), Theme.Ink, TextFormatFlags.NoPrefix);
            TextRenderer.DrawText(g, desc, Theme.UISmall, new Rectangle(Theme.S(54), Theme.S(28), Width - Theme.S(70), Theme.S(28)), Theme.Dim, TextFormatFlags.WordBreak | TextFormatFlags.NoPrefix | TextFormatFlags.EndEllipsis);
            if (hover) using (Pen p = new Pen(Theme.Teal)) g.DrawLine(p, 0, 0, 0, Height);
        }
    }
}

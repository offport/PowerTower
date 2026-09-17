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
        public override string Title { get { return "About & Guide"; } }
        public override string Blurb { get { return "What each tool in this toolbox does, grouped by job. A portable, read-mostly security workbench for this one machine — no installer, no services, no scripts."; } }

        readonly Panel page = new Panel();

        // group heading, then {panel class name, tool title, one-line description}…
        static readonly object[][] Groups = new object[][] {
            new object[] { "Recon & network", new string[][] {
                new string[] { "ReconPanel", "System Recon & Audit", "A read-only sweep of the machine — system, users and groups, network, security posture, persistence, processes and recent security events — flagging risky settings. Exports to Markdown, JSON or PDF." },
                new string[] { "BlockerPanel", "Domain and IP Blocker", "Pull domains and IPs out of any file or paste, then block them via the hosts file and a firewall rule. Backs up the hosts file first; everything is reversible." },
                new string[] { "ReachPanel", "Reachability Verifier", "For each target: DNS, an optional ping, and a TCP connect to each port you list — to see what is reachable from here." },
                new string[] { "ConnPanel", "Connections Monitor", "Every live TCP/UDP endpoint, refreshed each second: process, PID, addresses, state and remote host name. Block or copy the remote IPs." },
                new string[] { "FirewallPanel", "Firewall Rules", "Every Windows Firewall rule, with the risky inbound-allow rules flagged, plus whether the firewall is actually on for each profile." },
                new string[] { "NetMapPanel", "Network Map", "This machine’s live connections drawn on a world map: every connection to a public address is geolocated (opt-in) and shown as an animated arc, updated in real time." },
            } },
            new object[] { "Files & storage", new string[][] {
                new string[] { "HogsPanel", "Resource Usage", "Which processes have used the most CPU time, memory and disk I/O since you opened the tool — plus, per process, the DLLs it has loaded and which are unsigned." },
                new string[] { "DiskPanel", "Disk Usage", "Scan a drive or folder to see where the space went: the largest files, the biggest folders, the file types, and the folder tree with sizes." },
                new string[] { "DeletedPanel", "Deleted Files Finder", "What was permanently deleted on each drive and whether it can come back, read from the NTFS journal and the exFAT directory table. Filter by type, name and size." },
                new string[] { "FileExplorerPanel", "File Explorer", "Browse the machine, pick files across folders, see each file's signature, and act on the whole selection — including AES-256 encrypt/decrypt and secure wipe." },
                new string[] { "FindPanel", "Find Files", "Find files anywhere by name (wildcards) or by hash (MD5/SHA-1/SHA-256), with a size cap on the hash sweep." },
                new string[] { "DupesPanel", "Duplicate Finder", "Find files whose contents are identical and see how much space each group wastes. Keep one copy, recycle the rest." },
            } },
            new object[] { "Vulnerabilities & software", new string[][] {
                new string[] { "VulnPanel", "Vulnerability Management", "Which CVEs this machine is exposed to and why: the OS build and installed software matched against Microsoft's CVRF, the NVD, CISA KEV and EPSS." },
                new string[] { "SoftwarePanel", "Software Inventory", "Every installed program and its version; scan to flag the vulnerable ones by severity, worst CVE, known-exploited status and the version to upgrade to." },
            } },
            new object[] { "Threat hunting & incident response", new string[][] {
                new string[] { "AutorunsPanel", "Autoruns", "Every place Windows starts a program on its own — run keys, tasks, services, Winlogon, image hijacks, WMI subscriptions — with each program's signer and a risk flag. Disable or delete what you don't want." },
                new string[] { "EventsPanel", "Event Log Triage", "The security-relevant event-log records over a time range: logons and failures, new services and tasks, PowerShell activity, Defender detections, account changes and cleared logs." },
                new string[] { "ChecklistPanel", "Security Checklist", "A pass/fail review of the common endpoint audit items — accounts, disk encryption, antivirus and EDR, remote access, USB, firewall — with an EICAR anti-malware test and an application-control policy read." },
            } },
            new object[] { "Secrets & credentials", new string[][] {
                new string[] { "SecretsPanel", "Secrets Scanner", "Search a folder or drive for exposed secrets — keys, tokens and passwords in config files — each shown with a masked preview." },
                new string[] { "CredsPanel", "Wi-Fi & Credentials", "The secrets saved on this machine: Wi-Fi networks with their security (weak ones flagged) and, when elevated, the key; plus the Windows Credential Manager vault." },
                new string[] { "BrowserPanel", "Browsing Data", "History, downloads, searches and saved passwords from every browser (Chrome, Edge, Brave, Firefox), read from their databases. Passwords stay masked until you reveal them." },
            } },
            new object[] { "Putting it together", new string[][] {
                new string[] { "MapPanel", "Findings Map", "This machine at the centre of a map, wired to what was found: users, network, software, checklist results and vulnerabilities. Click a node to expand." },
            } },
        };

        public AboutPanel()
        {
            BackColor = Theme.Panel; page.Dock = DockStyle.Fill; page.AutoScroll = true; page.BackColor = Theme.Panel; page.Padding = new Padding(Theme.S(24), Theme.S(18), Theme.S(24), Theme.S(24));
            Controls.Add(page);
            int y = 0; int w = Theme.S(860);
            y = AddIntro(y, w);
            foreach (object[] grp in Groups)
            {
                y += Theme.S(14);
                Label h = Theme.Lbl((string)grp[0], Theme.Teal, Theme.Big); h.Location = new Point(Theme.S(4), y); page.Controls.Add(h); y += Theme.S(30);
                Panel rule = new Panel(); rule.BackColor = Theme.Line; rule.Location = new Point(Theme.S(4), y); rule.Size = new Size(w, 1); page.Controls.Add(rule); y += Theme.S(8);
                foreach (string[] tool in (string[][])grp[1]) { AboutRow row = new AboutRow(tool[0], tool[1], tool[2], w); row.Location = new Point(0, y); row.Picked += delegate (string key) { Jump(key); }; page.Controls.Add(row); y += row.Height; }
            }
            Label foot = Theme.Lbl("The scripts beside this app are untouched — this is a separate C# port of their logic. Nothing runs through powershell.exe, nothing is installed, and the only network traffic is the vulnerability feeds, each of which can be switched off.", Theme.Dim, Theme.UISmall);
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

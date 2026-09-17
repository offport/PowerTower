// ConnSidebar: the live list beside the Network Map, like the "top attacks" column on the big threat maps.
// Apps ranked by how many public connections they hold right now, each with its destinations - country,
// IP, port, protocol and direction - refreshed on every poll. Hover a destination to light it up on the map.
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace PSTools
{
    public class ConnSidebar : Control
    {
        class Dest { public string Ip = "", Country = "", Proto = ""; public int Port, Count; public bool Outbound; public Rectangle Hit; }
        class App { public string Proc = ""; public int Total; public readonly List<Dest> Dests = new List<Dest>(); }

        readonly List<App> apps = new List<App>(); int scroll; Dest hover; float pulse; int totalConns;
        readonly System.Windows.Forms.Timer anim = new System.Windows.Forms.Timer();
        /// <summary>Raised with the destination IP under the mouse (or null when the mouse leaves a row).</summary>
        public event Action<string> Pick;

        public ConnSidebar()
        {
            SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
            BackColor = Theme.Bg; DoubleBuffered = true; Width = Theme.S(340);
            anim.Interval = 60; anim.Tick += delegate { pulse += 0.12f; if (pulse > 6.283f) pulse -= 6.283f; Invalidate(new Rectangle(0, 0, Width, Theme.S(40))); };
            MouseWheel += delegate (object s, MouseEventArgs e) { scroll = Math.Max(0, scroll - Math.Sign(e.Delta) * Theme.S(48)); Invalidate(); };
            MouseMove += delegate (object s, MouseEventArgs e) { Dest d = HitTest(e.Location); if (d != hover) { hover = d; Cursor = d != null ? Cursors.Hand : Cursors.Default; if (Pick != null) Pick(d != null ? d.Ip : null); Invalidate(); } };
            MouseLeave += delegate { if (hover != null) { hover = null; if (Pick != null) Pick(null); Invalidate(); } };
        }
        public void Animate(bool on) { if (on) anim.Start(); else anim.Stop(); }

        /// <summary>Rebuild the ranking from the current public connections. countryOf resolves an IP to a country name (may return "").</summary>
        public void Update(List<Conn> remote, Func<string, string> countryOf)
        {
            Dictionary<string, App> byProc = new Dictionary<string, App>(StringComparer.OrdinalIgnoreCase);
            foreach (Conn c in remote)
            {
                string proc = c.Process; if (string.IsNullOrEmpty(proc) || proc == "?") proc = c.Pid > 0 ? "PID " + c.Pid : c.Pid == 4 ? "System" : "System";
                App a; if (!byProc.TryGetValue(proc, out a)) { a = new App(); a.Proc = proc; byProc[proc] = a; }
                a.Total++;
                string proto = (c.Proto ?? "").Replace("6", ""); bool outb = c.RemotePort <= c.LocalPort;
                Dest d = null; foreach (Dest x in a.Dests) if (x.Ip == c.Remote && x.Port == c.RemotePort && x.Proto == proto) { d = x; break; }
                if (d == null) { d = new Dest(); d.Ip = c.Remote ?? ""; d.Port = c.RemotePort; d.Proto = proto; d.Outbound = outb; d.Country = countryOf != null ? (countryOf(d.Ip) ?? "") : ""; a.Dests.Add(d); }
                d.Count++;
            }
            List<App> list = new List<App>(byProc.Values);
            list.Sort(delegate (App x, App y) { if (y.Total != x.Total) return y.Total.CompareTo(x.Total); return string.Compare(x.Proc, y.Proc, StringComparison.OrdinalIgnoreCase); });
            foreach (App a in list) a.Dests.Sort(delegate (Dest x, Dest y) { if (y.Count != x.Count) return y.Count.CompareTo(x.Count); return string.Compare(x.Country, y.Country, StringComparison.OrdinalIgnoreCase); });
            string keep = hover != null ? hover.Ip + ":" + hover.Port : null;
            apps.Clear(); apps.AddRange(list); totalConns = remote.Count;
            hover = null; if (keep != null) foreach (App a in apps) foreach (Dest d in a.Dests) if (d.Ip + ":" + d.Port == keep) hover = d;
            Invalidate();
        }

        Dest HitTest(Point p) { foreach (App a in apps) foreach (Dest d in a.Dests) if (d.Hit.Contains(p)) return d; return null; }

        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics; g.SmoothingMode = SmoothingMode.AntiAlias;
            using (Brush bg = new LinearGradientBrush(ClientRectangle, Theme.MapBg, Theme.MapBg2, 90f)) g.FillRectangle(bg, ClientRectangle);
            using (Pen edge = new Pen(Theme.Line)) g.DrawLine(edge, 0, 0, 0, Height);
            int x = Theme.S(14), w = Width - Theme.S(28), y = Theme.S(12) - scroll;
            // header with a live pulse
            TextRenderer.DrawText(g, "TOP APPS", Theme.UIBold, new Point(x, y), Theme.Teal, TextFormatFlags.NoPrefix);
            float dotA = 0.55f + 0.45f * (float)Math.Sin(pulse); using (Brush live = new SolidBrush(Color.FromArgb((int)(255 * dotA), Theme.Rose))) g.FillEllipse(live, x + Theme.S(74), y + Theme.S(6), Theme.S(7), Theme.S(7));
            TextRenderer.DrawText(g, "live", Theme.UISmall, new Point(x + Theme.S(85), y + Theme.S(1)), Theme.Dim, TextFormatFlags.NoPrefix);
            string tot = totalConns + " conn"; Size ts = TextRenderer.MeasureText(g, tot, Theme.UISmall); TextRenderer.DrawText(g, tot, Theme.UISmall, new Point(x + w - ts.Width, y + Theme.S(1)), Theme.Dim, TextFormatFlags.NoPrefix);
            y += Theme.S(26);
            if (apps.Count == 0) { TextRenderer.DrawText(g, "no public connections yet", Theme.UISmall, new Point(x, y), Theme.Faint, TextFormatFlags.NoPrefix); return; }
            int max = apps[0].Total; int shownApps = 0;
            foreach (App a in apps)
            {
                if (shownApps++ >= 14) { TextRenderer.DrawText(g, "+" + (apps.Count - 14) + " more app(s)", Theme.UISmall, new Point(x, y), Theme.Faint, TextFormatFlags.NoPrefix); break; }
                // app row: name, count, share bar
                if (y > -Theme.S(60) && y < Height)
                {
                    string cnt = a.Total.ToString(); Size cs = TextRenderer.MeasureText(g, cnt, Theme.UIBold);
                    TextRenderer.DrawText(g, a.Proc, Theme.UIBold, new Rectangle(x, y, w - cs.Width - Theme.S(8), Theme.S(18)), Theme.Ink, TextFormatFlags.NoPrefix | TextFormatFlags.EndEllipsis);
                    TextRenderer.DrawText(g, cnt, Theme.UIBold, new Point(x + w - cs.Width, y), Theme.Teal, TextFormatFlags.NoPrefix);
                    int bw = (int)(w * (double)a.Total / Math.Max(1, max));
                    using (Brush bb = new SolidBrush(Color.FromArgb(40, Theme.Teal))) g.FillRectangle(bb, x, y + Theme.S(19), w, Theme.S(3));
                    using (Brush bf = new SolidBrush(Color.FromArgb(200, Theme.Teal))) g.FillRectangle(bf, x, y + Theme.S(19), Math.Max(2, bw), Theme.S(3));
                }
                y += Theme.S(26);
                int shown = 0;
                foreach (Dest d in a.Dests)
                {
                    if (shown++ >= 4) { TextRenderer.DrawText(g, "+" + (a.Dests.Count - 4) + " more", Theme.UISmall, new Point(x + Theme.S(12), y), Theme.Faint, TextFormatFlags.NoPrefix); y += Theme.S(16); break; }
                    d.Hit = new Rectangle(0, y - Theme.S(1), Width, Theme.S(17));
                    if (y > -Theme.S(20) && y < Height)
                    {
                        bool hot = d == hover; Color dir = d.Outbound ? Theme.Teal : Theme.Amber;
                        if (hot) using (Brush hb = new SolidBrush(Color.FromArgb(38, Theme.Teal))) g.FillRectangle(hb, x - Theme.S(6), y - Theme.S(1), w + Theme.S(12), Theme.S(17));
                        TextRenderer.DrawText(g, d.Outbound ? "→" : "←", Theme.UISmall, new Point(x, y), dir, TextFormatFlags.NoPrefix);
                        string country = d.Country.Length > 0 ? d.Country : "—"; Size cs2 = TextRenderer.MeasureText(g, country, Theme.UISmall); int cw = Math.Min(cs2.Width, Theme.S(110));
                        TextRenderer.DrawText(g, country, Theme.UISmall, new Rectangle(x + Theme.S(14), y, cw, Theme.S(16)), hot ? Color.White : Theme.Ink, TextFormatFlags.NoPrefix | TextFormatFlags.EndEllipsis);
                        string rest = d.Ip + " :" + d.Port + "  " + d.Proto + (d.Count > 1 ? "  ×" + d.Count : "");
                        TextRenderer.DrawText(g, rest, Theme.UISmall, new Rectangle(x + Theme.S(18) + cw, y, w - Theme.S(18) - cw, Theme.S(16)), hot ? Theme.Ink : Theme.Dim, TextFormatFlags.NoPrefix | TextFormatFlags.EndEllipsis);
                    }
                    y += Theme.S(16);
                }
                y += Theme.S(8);
            }
        }

        /// <summary>Fabricated rows for screenshots.</summary>
        public void Demo(Func<string, string> countryOf)
        {
            List<Conn> l = new List<Conn>();
            Action<string, string, int, string, int> add = delegate (string proc, string ip, int port, string proto, int n) { for (int i = 0; i < n; i++) { Conn c = new Conn(); c.Process = proc; c.Remote = ip; c.RemotePort = port; c.LocalPort = 50000 + i; c.Proto = proto; c.State = "ESTABLISHED"; l.Add(c); } };
            add("chrome.exe", "142.250.80.46", 443, "TCP", 5); add("chrome.exe", "151.101.1.69", 443, "TCP", 4); add("chrome.exe", "142.250.80.46", 443, "UDP", 1);
            add("svchost.exe", "13.107.42.14", 443, "TCP", 3); add("steam.exe", "110.75.30.10", 27015, "UDP", 2); add("steam.exe", "110.75.30.10", 443, "TCP", 1);
            add("Spotify.exe", "200.147.67.142", 4070, "TCP", 2); add("firefox.exe", "104.244.42.1", 443, "TCP", 2); add("Code.exe", "203.0.113.9", 22, "TCP", 1); add("unknown", "77.88.55.60", 3389, "TCP", 1);
            Update(l, countryOf); anim.Start();
        }
    }
}

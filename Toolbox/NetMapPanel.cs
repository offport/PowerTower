// Network Map: this machine's live connections on a world map, in the style of the big threat maps. The world is
// a dense dot grid of real country shapes (baked in, nothing downloaded); hover a country and it lights up with
// its name and borders; each connection to a public IP is geolocated and drawn as an animated great-circle arc
// with pulses travelling along it; hover an arc or endpoint for the ports, protocols and processes behind it.
// Polls the same connection scanner as the Connections Monitor; geolocation is opt-in (ip-api.com) and cached.
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Threading;
using System.Windows.Forms;

namespace PSTools
{
    public class NetMapPanel : ToolPanel
    {
        public override string Title { get { return "Network Map"; } }
        public override string Blurb { get { return "This machine's live network connections on a world map. Every connection to a public address is geolocated and drawn as an animated arc — outbound and inbound in different colours. Hover a country to light it up, hover a connection for its ports and protocols."; } }

        readonly WorldFlowMap map = new WorldFlowMap(); readonly ConnSidebar side = new ConnSidebar(); readonly NameCache names = new NameCache();
        readonly Button bStart, bGeo; readonly CheckBox cUdp; readonly Label status = Theme.Lbl("", Theme.Dim, Theme.UISmall);
        readonly System.Windows.Forms.Timer poll = new System.Windows.Forms.Timer();
        bool geoEnabled, loaded; volatile bool locating;

        public NetMapPanel()
        {
            BackColor = Theme.Bg;
            FlowLayoutPanel bar = Theme.Bar(46); bar.BackColor = Theme.Bg;
            bStart = Theme.Btn("Pause", true); bStart.Click += delegate { if (poll.Enabled) { poll.Stop(); map.Animate(false); bStart.Text = "Resume"; } else { poll.Start(); map.Animate(true); bStart.Text = "Pause"; } };
            bGeo = Theme.Btn("Enable geolocation…", false); bGeo.Click += delegate { EnableGeo(); };
            cUdp = Theme.Toggle("include UDP", false); cUdp.CheckedChanged += delegate { Tick(); };
            Button bFit = Theme.Btn("Fit", false); bFit.Click += delegate { map.Fit(); };
            foreach (Control c in new Control[] { bStart, bGeo, cUdp, bFit, status }) bar.Controls.Add(c); status.Margin = new Padding(Theme.S(10), Theme.S(9), 0, 0);
            map.Dock = DockStyle.Fill;
            side.Dock = DockStyle.Right; side.Width = Theme.S(340); side.Pick += delegate (string ip) { map.Highlight(ip); }; Controls.Add(map); Controls.Add(side); Controls.Add(bar); map.BringToFront();
            poll.Interval = 2000; poll.Tick += delegate { Tick(); };
        }

        public override void OnShown()
        {
            if (!loaded) { loaded = true; geoEnabled = Host.Settings.Get("netmap.geo", "0") == "1"; if (geoEnabled) { bGeo.Text = "Geolocation on"; bGeo.Enabled = false; LocateMine(); } }
            map.Animate(true); side.Animate(true); poll.Start(); Tick();
        }
        public override void OnHidden() { poll.Stop(); map.Animate(false); side.Animate(false); }

        void EnableGeo()
        {
            if (!Host.Confirm("Enable IP geolocation",
                "To place your connections on the world map, this looks up the geographic location of each remote IP address you are connected to.\n\n" +
                "It uses the free ip-api.com service, so the remote IPs your machine talks to are sent there (over HTTP) and cached locally. This is the only part of this tool that uses the network.\n\nEnable geolocation?")) return;
            geoEnabled = true; Host.Settings.Set("netmap.geo", "1"); Host.Settings.Save(); bGeo.Text = "Geolocation on"; bGeo.Enabled = false;
            LocateMine(); Tick();
        }
        void LocateMine()
        {
            new Thread(delegate () { try { GeoLoc me = GeoIp.Mine(); if (me != null && me.Ok) try { map.BeginInvoke((Action)delegate { map.SetHome(me); }); } catch { } } catch { } }) { IsBackground = true }.Start();
        }

        void Tick()
        {
            List<Conn> conns; try { conns = ConnTable.Snapshot(true, cUdp.Checked); } catch { conns = new List<Conn>(); }
            List<Conn> remote = new List<Conn>(); HashSet<string> ips = new HashSet<string>();
            foreach (Conn c in conns) { if (string.IsNullOrEmpty(c.Remote) || c.Loopback) continue; if (!GeoIp.IsPublic(c.Remote)) continue; if (c.Pid == 0 && c.State == "TIME_WAIT") continue; if (string.IsNullOrEmpty(c.Process) && c.Pid > 0) { string n = names.ProcessName(c.Pid); c.Process = n == "?" ? "" : n; } remote.Add(c); ips.Add(c.Remote); }
            side.Update(remote, CountryOf); if (!geoEnabled) { status.Text = remote.Count + " connection(s) to public addresses · click \"Enable geolocation\" to place them on the map"; map.SetPending(remote.Count); return; }
            map.Update(remote);
            status.Text = remote.Count + " public connection(s) · " + ips.Count + " remote host(s) · " + map.LocatedCount + " located" + (locating ? " · locating…" : "");
            List<string> need = new List<string>(); foreach (string ip in ips) if (GeoIp.Cached(ip) == null) need.Add(ip);
            if (need.Count > 0 && !locating)
            {
                locating = true;
                new Thread(delegate ()
                {
                    try { GeoIp.Locate(need, null); } catch { }
                    try { map.BeginInvoke((Action)delegate { locating = false; Tick(); }); } catch { locating = false; }
                }) { IsBackground = true }.Start();
            }
        }

        static string CountryOf(string ip) { GeoLoc g = GeoIp.Cached(ip); return g != null && g.Ok ? g.Country : ""; }
        static string DemoCountry(string ip) { switch (ip) { case "142.250.80.46": case "104.244.42.1": return "United States"; case "151.101.1.69": return "United Kingdom"; case "13.107.42.14": return "Netherlands"; case "110.75.30.10": return "Japan"; case "200.147.67.142": return "Brazil"; case "203.0.113.9": return "Singapore"; case "77.88.55.60": return "Russia"; default: return ""; } }
        public override void SelfTest(System.Text.StringBuilder r)
        {
            if (r == null) { map.Demo(); side.Demo(DemoCountry); return; }
            r.AppendLine((WorldMap.CountryCount > 150 && WorldMap.Land(300, 80) ? "PASS" : "FAIL") + " network map: country grid loaded (" + WorldMap.W + "x" + WorldMap.H + ", " + WorldMap.CountryCount + " countries)");
            PointF lon = WorldMap.Norm(51.5, -0.13); int gx = (int)(lon.X * WorldMap.W), gy = (int)(lon.Y * WorldMap.H); string uk = WorldMap.Name(WorldMap.Country(gx, gy));
            r.AppendLine((uk.IndexOf("United Kingdom", StringComparison.OrdinalIgnoreCase) >= 0 ? "PASS" : "FAIL") + " network map: London resolves to “" + uk + "”");
            r.AppendLine((!GeoIp.IsPublic("192.168.1.5") && !GeoIp.IsPublic("127.0.0.1") && GeoIp.IsPublic("8.8.8.8") ? "PASS" : "FAIL") + " network map: public/private IP classification");
            map.Demo(); side.Demo(DemoCountry);
        }
    }

    /// <summary>The animated world map control: dense country dot grid with borders, hover-lit countries, geolocated
    /// endpoints, great-circle arcs with travelling pulses, tooltips with ports and protocols, and a red "you are here" pin.</summary>
    public class WorldFlowMap : Control
    {
        class Node { public string Ip = "", Proc = "", Country = ""; public GeoLoc Loc; public PointF Norm; public float Glow; public int Conns; public DateTime Last; public bool Outbound; public readonly List<string> Details = new List<string>(); }
        class Pulse { public Node N; public float T; public float Speed; public bool Fwd; public Color C; }

        readonly Dictionary<string, Node> nodes = new Dictionary<string, Node>(StringComparer.OrdinalIgnoreCase);
        readonly List<Pulse> pulses = new List<Pulse>();
        GeoLoc home; PointF homeNorm = new PointF(0.5f, 0.35f); bool hasHome;
        readonly System.Windows.Forms.Timer anim = new System.Windows.Forms.Timer();
        float scale = 1f; PointF pan = PointF.Empty; bool panning; Point panStart; PointF panOrig;
        int pending; float homePulse; readonly Random rng = new Random(12345);
        readonly List<string[]> ticker = new List<string[]>();
        Node hoverNode; int hoverCountry; Point mouseAt;
        // the world dots are expensive (~60k) so they are rendered once per view into a bitmap and blitted every frame
        Bitmap worldCache; float cacheScale = -1; PointF cachePan; Size cacheSize;

        public WorldFlowMap()
        {
            SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
            BackColor = Theme.Bg; DoubleBuffered = true;
            anim.Interval = 33; anim.Tick += delegate { Step(); };
            MouseDown += delegate (object s, MouseEventArgs e) { if (e.Button == MouseButtons.Left) { panning = true; panStart = e.Location; panOrig = pan; } };
            MouseUp += delegate { if (panning) { panning = false; Invalidate(); } };
            MouseMove += delegate (object s, MouseEventArgs e)
            {
                mouseAt = e.Location;
                if (panning) { pan = new PointF(panOrig.X + (e.X - panStart.X), panOrig.Y + (e.Y - panStart.Y)); Invalidate(); return; }
                Node h = HitNode(e.Location); if (h == null) h = HitArc(e.Location);
                int c = CountryAt(e.Location);
                if (h != hoverNode || c != hoverCountry) { hoverNode = h; hoverCountry = c; Cursor = h != null ? Cursors.Hand : Cursors.Default; Invalidate(); }
            };
            MouseLeave += delegate { hoverNode = null; hoverCountry = 0; Invalidate(); };
            MouseWheel += delegate (object s, MouseEventArgs e) { Zoom(e.Delta > 0 ? 1.15f : 1 / 1.15f, e.Location); };
            Resize += delegate { Invalidate(); };
        }
        public int LocatedCount { get { int n = 0; lock (nodes) foreach (Node x in nodes.Values) if (x.Loc != null) n++; return n; } }
        public void Animate(bool on) { if (on) anim.Start(); else anim.Stop(); }
        public void SetPending(int n) { pending = n; Invalidate(); }
        public void SetHome(GeoLoc me) { home = me; homeNorm = WorldMap.Norm(me.Lat, me.Lon); hasHome = true; Invalidate(); }
        public void Fit() { scale = 1f; pan = PointF.Empty; Invalidate(); }
        /// <summary>Light up the endpoint for an IP (from the sidebar); null clears it.</summary>
        public void Highlight(string ip) { Node n = null; if (ip != null) lock (nodes) nodes.TryGetValue(ip, out n); if (n != null && n.Loc == null) n = null; if (n != hoverNode) { hoverNode = n; Invalidate(); } }
        void Zoom(float f, Point at)
        {
            float ns = Math.Max(0.6f, Math.Min(10f, scale * f)); if (ns == scale) return;
            PointF before = ToWorld(at); scale = ns; PointF afterScreen = ToScreen(before);
            pan = new PointF(pan.X + (at.X - afterScreen.X), pan.Y + (at.Y - afterScreen.Y)); Invalidate();
        }

        // ── layout: map fills the width at 2:1, centred, with pan/zoom ──
        float MapW { get { return Width * scale; } }
        float MapH { get { return Width * scale / 2f; } }
        float Ox { get { return (Width - MapW) / 2f + pan.X; } }
        float Oy { get { return (Height - MapH) / 2f + pan.Y + Height * 0.03f; } }
        PointF ToScreen(PointF norm) { return new PointF(Ox + norm.X * MapW, Oy + norm.Y * MapH); }
        PointF ToWorld(Point p) { return new PointF((p.X - Ox) / MapW, (p.Y - Oy) / MapH); }
        int CountryAt(Point p) { PointF w = ToWorld(p); if (w.X < 0 || w.X >= 1 || w.Y < 0 || w.Y >= 1) return 0; return WorldMap.Country((int)(w.X * WorldMap.W), (int)(w.Y * WorldMap.H)); }

        // ── data ──
        public void Update(List<Conn> remote)
        {
            lock (nodes)
            {
                DateTime now = DateTime.Now; HashSet<string> present = new HashSet<string>();
                Dictionary<string, Dictionary<string, int>> detail = new Dictionary<string, Dictionary<string, int>>(StringComparer.OrdinalIgnoreCase);
                Dictionary<string, Dictionary<string, int>> procs = new Dictionary<string, Dictionary<string, int>>(StringComparer.OrdinalIgnoreCase);
                foreach (Conn c in remote)
                {
                    present.Add(c.Remote); Node n; bool isNew = !nodes.TryGetValue(c.Remote, out n);
                    if (isNew) { n = new Node(); n.Ip = c.Remote; nodes[c.Remote] = n; }
                    n.Last = now; n.Outbound = c.RemotePort <= c.LocalPort;
                    string proto = (c.Proto ?? "").Replace("6", "") ; string state = (c.State ?? "").ToLowerInvariant(); string proc = c.Process ?? "";
                    string key = proto + " " + c.RemotePort + (proc.Length > 0 ? " · " + proc : "") + (state.Length > 0 && state != "bound" ? " · " + state : "");
                    Dictionary<string, int> d; if (!detail.TryGetValue(c.Remote, out d)) { d = new Dictionary<string, int>(); detail[c.Remote] = d; } int v; d.TryGetValue(key, out v); d[key] = v + 1;
                    Dictionary<string, int> pc; if (!procs.TryGetValue(c.Remote, out pc)) { pc = new Dictionary<string, int>(); procs[c.Remote] = pc; } int pv; pc.TryGetValue(proc, out pv); pc[proc] = pv + 1;
                    GeoLoc g = GeoIp.Cached(c.Remote); if (g != null && g.Ok) { if (n.Loc == null) { n.Glow = 1f; n.Loc = g; n.Norm = WorldMap.Norm(g.Lat, g.Lon); n.Country = g.Country; SpawnPulses(n, 3); AddTicker(n); } n.Loc = g; n.Norm = WorldMap.Norm(g.Lat, g.Lon); n.Country = g.Country; }
                }
                foreach (KeyValuePair<string, Node> kv in nodes)
                {
                    Dictionary<string, int> d; kv.Value.Details.Clear(); int total = 0;
                    if (detail.TryGetValue(kv.Key, out d))
                    {
                        List<KeyValuePair<string, int>> l = new List<KeyValuePair<string, int>>(d); l.Sort(delegate (KeyValuePair<string, int> a, KeyValuePair<string, int> b) { return b.Value - a.Value; });
                        foreach (KeyValuePair<string, int> e in l) { total += e.Value; if (kv.Value.Details.Count < 8) kv.Value.Details.Add(e.Key + (e.Value > 1 ? "  ×" + e.Value : "")); }
                    }
                    kv.Value.Conns = total;
                    Dictionary<string, int> pc; if (procs.TryGetValue(kv.Key, out pc)) { string best = ""; int bv = 0; foreach (KeyValuePair<string, int> e in pc) if (e.Value > bv && e.Key.Length > 0) { bv = e.Value; best = e.Key; } kv.Value.Proc = best; }
                }
                List<string> dead = new List<string>(); foreach (KeyValuePair<string, Node> kv in nodes) if (!present.Contains(kv.Key) && (now - kv.Value.Last).TotalSeconds > 20) dead.Add(kv.Key);
                foreach (string k in dead) nodes.Remove(k);
            }
            Invalidate();
        }
        void SpawnPulses(Node n, int count) { if (n.Loc == null) return; Color c = n.Outbound ? Theme.Teal : Theme.Amber; for (int i = 0; i < count; i++) { Pulse p = new Pulse(); p.N = n; p.T = (float)rng.NextDouble(); p.Speed = 0.010f + (float)rng.NextDouble() * 0.010f; p.Fwd = n.Outbound; p.C = c; lock (pulses) pulses.Add(p); } }
        void AddTicker(Node n) { lock (ticker) { ticker.Insert(0, new string[] { DateTime.Now.ToString("HH:mm:ss"), (n.Outbound ? "→ " : "← ") + (n.Country.Length > 0 ? n.Country : n.Ip) + (n.Proc.Length > 0 ? "  " + n.Proc : ""), n.Outbound ? "out" : "in" }); while (ticker.Count > 8) ticker.RemoveAt(ticker.Count - 1); } }

        void Step()
        {
            homePulse += 0.05f; if (homePulse > 6.283f) homePulse -= 6.283f;
            lock (pulses) { for (int i = pulses.Count - 1; i >= 0; i--) { Pulse p = pulses[i]; p.T += p.Speed; if (p.T >= 1f) { p.T -= 1f; if (p.N.Conns == 0) pulses.RemoveAt(i); } } }
            lock (nodes) { foreach (Node n in nodes.Values) { if (n.Conns > 0 && n.Loc != null) { n.Glow = Math.Min(1f, n.Glow + 0.02f); if (PulseCount(n) < Math.Min(4, 1 + n.Conns / 2)) SpawnPulses(n, 1); } else n.Glow = Math.Max(0f, n.Glow - 0.03f); } }
            Invalidate();
        }
        int PulseCount(Node n) { int c = 0; lock (pulses) foreach (Pulse p in pulses) if (p.N == n) c++; return c; }

        // ── paint ──
        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics; g.SmoothingMode = SmoothingMode.AntiAlias;
            using (Brush bg = new LinearGradientBrush(ClientRectangle, Theme.MapBg, Theme.MapBg2, 90f)) g.FillRectangle(bg, ClientRectangle);
            DrawWorld(g);
            DrawCountryHighlight(g);
            PointF hs = ToScreen(homeNorm);
            List<Node> live; lock (nodes) live = new List<Node>(nodes.Values);
            foreach (Node n in live) { if (n.Loc == null || n.Glow <= 0.02f) continue; DrawArc(g, hs, ToScreen(n.Norm), n, n == hoverNode); }
            List<Pulse> ps; lock (pulses) ps = new List<Pulse>(pulses);
            foreach (Pulse p in ps) { if (p.N.Loc == null || p.N.Glow <= 0.02f) continue; PointF pt = ArcPoint(hs, ToScreen(p.N.Norm), p.Fwd ? p.T : 1f - p.T); if (!Bad(pt)) DrawGlowDot(g, pt, 3.0f, p.C, p.N.Glow); }
            foreach (Node n in live) { if (n.Loc == null || n.Glow <= 0.02f) continue; DrawNode(g, ToScreen(n.Norm), n, n == hoverNode); }
            DrawHome(g, hs);
            DrawOverlay(g, live);
        }

        void EnsureCache()
        {
            if (worldCache != null && cacheScale == scale && cacheSize == ClientSize && !(!panning && (Math.Abs(pan.X - cachePan.X) > 0.5f || Math.Abs(pan.Y - cachePan.Y) > 0.5f))) return;
            if (Width < 10 || Height < 10) return;
            if (worldCache == null || worldCache.Size != ClientSize) { if (worldCache != null) worldCache.Dispose(); worldCache = new Bitmap(Width, Height); }
            cacheScale = scale; cachePan = pan; cacheSize = ClientSize;
            using (Graphics g = Graphics.FromImage(worldCache))
            {
                g.Clear(Color.Transparent); g.SmoothingMode = SmoothingMode.HighSpeed;
                float mapW = MapW, mapH = MapH, ox = Ox, oy = Oy;
                float top = Math.Max(0, oy), bot = Math.Min(Height, oy + mapH), lft = Math.Max(0, ox), rgt = Math.Min(Width, ox + mapW);
                using (Pen grat = new Pen(Color.FromArgb(18, Theme.MapGrat), 1f))
                {
                    for (int lon = -180; lon <= 180; lon += 30) { float x = ox + (lon + 180) / 360f * mapW; if (x >= -2 && x <= Width + 2) g.DrawLine(grat, x, top, x, bot); }
                    for (int lat = -60; lat <= 60; lat += 30) { float y = oy + (90 - lat) / 180f * mapH; if (y >= -2 && y <= Height + 2) g.DrawLine(grat, lft, y, rgt, y); }
                }
                float cellW = mapW / WorldMap.W, cellH = mapH / WorldMap.H; float dot = Math.Max(0.8f, Math.Min(cellW, cellH) * 0.55f); bool round = dot >= 2.6f;
                int step = cellW < 1.1f ? 2 : 1;
                using (Brush bLand = new SolidBrush(Color.FromArgb(95, Theme.MapLand)))
                using (Brush bCoast = new SolidBrush(Color.FromArgb(150, Theme.MapCoast)))
                using (Brush bBorder = new SolidBrush(Color.FromArgb(175, Theme.MapBorder)))
                {
                    int gy0 = Math.Max(0, (int)((top - oy) / cellH) - 1), gy1 = Math.Min(WorldMap.H - 1, (int)((bot - oy) / cellH) + 1);
                    int gx0 = Math.Max(0, (int)((lft - ox) / cellW) - 1), gx1 = Math.Min(WorldMap.W - 1, (int)((rgt - ox) / cellW) + 1);
                    for (int gy = gy0; gy <= gy1; gy += step)
                    {
                        float sy = oy + gy * cellH + (cellH - dot) / 2;
                        for (int gx = gx0; gx <= gx1; gx += step)
                        {
                            int c = WorldMap.Country(gx, gy); if (c == 0) continue; float sx = ox + gx * cellW + (cellW - dot) / 2;
                            Brush b = WorldMap.Border(gx, gy) ? bBorder : WorldMap.Coast(gx, gy) ? bCoast : bLand;
                            if (round) g.FillEllipse(b, sx, sy, dot, dot); else g.FillRectangle(b, sx, sy, dot, dot);
                        }
                    }
                }
            }
        }
        void DrawWorld(Graphics g)
        {
            EnsureCache(); if (worldCache == null) return;
            g.DrawImageUnscaled(worldCache, (int)Math.Round(pan.X - cachePan.X), (int)Math.Round(pan.Y - cachePan.Y));
        }
        // the hovered country lit up: every one of its dots brighter and bigger, its border dots brightest, and its name
        void DrawCountryHighlight(Graphics g)
        {
            if (hoverCountry <= 0) return; List<int> cells = WorldMap.CellsOf(hoverCountry); if (cells.Count == 0) return;
            float mapW = MapW, mapH = MapH, ox = Ox, oy = Oy; float cellW = mapW / WorldMap.W, cellH = mapH / WorldMap.H; float dot = Math.Max(1.2f, Math.Min(cellW, cellH) * 0.72f);
            double sx = 0, sy = 0; int cnt = 0;
            using (Brush fill = new SolidBrush(Color.FromArgb(200, Theme.Teal)))
            using (Brush edge = new SolidBrush(Theme.MapLit))
            {
                foreach (int idx in cells)
                {
                    int gx = idx % WorldMap.W, gy = idx / WorldMap.W; float px = ox + gx * cellW + (cellW - dot) / 2, py = oy + gy * cellH + (cellH - dot) / 2;
                    sx += px; sy += py; cnt++;
                    if (px < -4 || py < -4 || px > Width + 4 || py > Height + 4) continue;
                    bool ed = WorldMap.Border(gx, gy) || WorldMap.Coast(gx, gy);
                    if (ed) g.FillEllipse(edge, px - 0.4f, py - 0.4f, dot + 0.8f, dot + 0.8f); else g.FillEllipse(fill, px, py, dot, dot);
                }
            }
            string name = WorldMap.Name(hoverCountry); if (name.Length == 0 || cnt == 0) return;
            PointF ctr = new PointF((float)(sx / cnt), (float)(sy / cnt)); Size ns = TextRenderer.MeasureText(g, name, Theme.Big);
            int nx = (int)(ctr.X - ns.Width / 2), ny = (int)(ctr.Y - ns.Height / 2); nx = Math.Max(Theme.S(6), Math.Min(Width - ns.Width - Theme.S(6), nx)); ny = Math.Max(Theme.S(6), Math.Min(Height - ns.Height - Theme.S(6), ny));
            using (Brush halo = new SolidBrush(Color.FromArgb(170, Theme.Halo))) g.FillRectangle(halo, nx - Theme.S(6), ny - Theme.S(2), ns.Width + Theme.S(12), ns.Height + Theme.S(4));
            TextRenderer.DrawText(g, name, Theme.Big, new Point(nx, ny), Color.FromArgb(240, Theme.MapText), TextFormatFlags.NoPrefix);
        }

        // quadratic bezier bowed upward
        PointF ArcCtrl(PointF a, PointF b)
        {
            PointF mid = new PointF((a.X + b.X) / 2, (a.Y + b.Y) / 2); float dx = b.X - a.X, dy = b.Y - a.Y; float len = (float)Math.Sqrt(dx * dx + dy * dy); if (len < 1) len = 1;
            float lift = Math.Min(len * 0.32f, Height * 0.4f); float px = -dy / len, py = dx / len; if (py > 0) { px = -px; py = -py; }
            return new PointF(mid.X + px * lift, mid.Y + py * lift);
        }
        static bool Bad(PointF p) { return float.IsNaN(p.X) || float.IsNaN(p.Y) || float.IsInfinity(p.X) || float.IsInfinity(p.Y) || Math.Abs(p.X) > 60000 || Math.Abs(p.Y) > 60000; }
        PointF ArcPoint(PointF a, PointF b, float t) { PointF c = ArcCtrl(a, b); float u = 1 - t; return new PointF(u * u * a.X + 2 * u * t * c.X + t * t * b.X, u * u * a.Y + 2 * u * t * c.Y + t * t * b.Y); }
        void DrawArc(Graphics g, PointF a, PointF b, Node n, bool hot)
        {
            if (Bad(a) || Bad(b)) return; PointF c = ArcCtrl(a, b); if (Bad(c)) return;
            using (GraphicsPath path = new GraphicsPath())
            {
                path.AddBezier(a, Lerp(a, c, 0.66f), Lerp(b, c, 0.66f), b); Color col = n.Outbound ? Theme.Teal : Theme.Amber; int alpha = (int)((hot ? 200 : 90) * n.Glow);
                float adx = b.X - a.X, ady = b.Y - a.Y; float alen = adx * adx + ady * ady; if (float.IsNaN(alen) || alen < 1f || alen > 9e8f) return;
                try { using (Pen p2 = new Pen(Color.FromArgb((int)((hot ? 70 : 30) * n.Glow), col), hot ? 5f : 3.4f)) g.DrawPath(p2, path);
                using (Pen p = new Pen(Color.FromArgb(alpha, col), hot ? 2.2f : 1.4f)) { p.StartCap = LineCap.Round; p.EndCap = LineCap.Round; g.DrawPath(p, path); } } catch (OutOfMemoryException) { } catch (System.Runtime.InteropServices.ExternalException) { }
            }
        }
        static PointF Lerp(PointF a, PointF b, float t) { return new PointF(a.X + (b.X - a.X) * t, a.Y + (b.Y - a.Y) * t); }
        void DrawGlowDot(Graphics g, PointF p, float r, Color c, float intensity)
        {
            int a = (int)(220 * Math.Min(1f, intensity)); if (a < 8) return;
            using (GraphicsPath gp = new GraphicsPath()) { gp.AddEllipse(p.X - r * 3, p.Y - r * 3, r * 6, r * 6); using (PathGradientBrush pg = new PathGradientBrush(gp)) { pg.CenterColor = Color.FromArgb(a, c); pg.SurroundColors = new Color[] { Color.FromArgb(0, c) }; g.FillEllipse(pg, p.X - r * 3, p.Y - r * 3, r * 6, r * 6); } }
            using (Brush b = new SolidBrush(Color.FromArgb(Math.Min(255, a + 30), Lighten(c)))) g.FillEllipse(b, p.X - r * 0.6f, p.Y - r * 0.6f, r * 1.2f, r * 1.2f);
        }
        static Color Lighten(Color c) { return Color.FromArgb(Math.Min(255, c.R + 60), Math.Min(255, c.G + 60), Math.Min(255, c.B + 60)); }
        void DrawNode(Graphics g, PointF p, Node n, bool hot)
        {
            float r = 2.2f + Math.Min(6f, n.Conns * 0.8f) + (hot ? 1.5f : 0); Color c = n.Outbound ? Theme.Teal : Theme.Amber;
            DrawGlowDot(g, p, r, c, 0.5f + 0.5f * n.Glow);
            using (Pen pen = new Pen(Color.FromArgb((int)(180 * n.Glow), hot ? Color.White : c), hot ? 1.8f : 1.2f)) g.DrawEllipse(pen, p.X - r, p.Y - r, r * 2, r * 2);
        }
        // a red map pin: "you are here"
        void DrawHome(Graphics g, PointF p)
        {
            if (Bad(p)) return;
            Color red = Theme.Rose; float pr = 7 + 3 * (float)Math.Sin(homePulse);
            using (Pen ring = new Pen(Color.FromArgb(90, red), 1.6f)) g.DrawEllipse(ring, p.X - pr, p.Y - pr * 0.5f, pr * 2, pr);
            using (Pen ring2 = new Pen(Color.FromArgb(45, red), 1.2f)) { float pr2 = pr + 7; g.DrawEllipse(ring2, p.X - pr2, p.Y - pr2 * 0.5f, pr2 * 2, pr2); }
            float h = Theme.S(22), w = Theme.S(14); float cx = p.X, cy = p.Y - h * 0.62f;
            using (GraphicsPath pin = new GraphicsPath())
            {
                pin.AddArc(cx - w / 2, cy - w / 2, w, w, 150, 240); pin.AddLine(cx + w / 2 * 0.5f, cy + w * 0.35f, cx, p.Y); pin.AddLine(cx, p.Y, cx - w / 2 * 0.5f, cy + w * 0.35f); pin.CloseFigure();
                using (Brush shadow = new SolidBrush(Color.FromArgb(120, 0, 0, 0))) { g.TranslateTransform(1.5f, 2f); g.FillPath(shadow, pin); g.TranslateTransform(-1.5f, -2f); }
                using (Brush fill = new SolidBrush(red)) g.FillPath(fill, pin);
                using (Pen edge = new Pen(Color.FromArgb(220, 255, 200, 195), 1f)) { try { g.DrawPath(edge, pin); } catch (OutOfMemoryException) { } catch (System.Runtime.InteropServices.ExternalException) { } }
            }
            using (Brush hole = new SolidBrush(Color.FromArgb(230, 20, 8, 10))) g.FillEllipse(hole, cx - w * 0.18f, cy - w * 0.18f, w * 0.36f, w * 0.36f);
            string label = "You are here" + (hasHome && home != null && home.City.Length > 0 ? " · " + home.City : "");
            Size ls = TextRenderer.MeasureText(g, label, Theme.UIBold);
            using (Brush halo = new SolidBrush(Color.FromArgb(150, Theme.Halo))) g.FillRectangle(halo, p.X + Theme.S(10), p.Y - ls.Height / 2 - Theme.S(1), ls.Width + Theme.S(8), ls.Height + Theme.S(2));
            TextRenderer.DrawText(g, label, Theme.UIBold, new Point((int)p.X + Theme.S(14), (int)p.Y - ls.Height / 2), red, TextFormatFlags.NoPrefix);
        }

        void DrawOverlay(Graphics g, List<Node> live)
        {
            TextRenderer.DrawText(g, "LIVE CONNECTIONS", Theme.UIBold, new Point(Theme.S(14), Theme.S(10)), Theme.Teal, TextFormatFlags.NoPrefix);
            if (!hasHome && pending >= 0 && LocatedCount == 0)
                TextRenderer.DrawText(g, pending + " public connection(s) waiting for geolocation", Theme.UISmall, new Point(Theme.S(14), Theme.S(30)), Theme.Dim, TextFormatFlags.NoPrefix);
            int outb = 0, inb = 0; Dictionary<string, int> byCountry = new Dictionary<string, int>();
            foreach (Node n in live) { if (n.Loc == null || n.Conns == 0) continue; if (n.Outbound) outb++; else inb++; if (n.Country.Length > 0) { int v; byCountry.TryGetValue(n.Country, out v); byCountry[n.Country] = v + 1; } }
            TextRenderer.DrawText(g, LocatedCount + " hosts   →" + outb + " out   ←" + inb + " in", Theme.UI, new Point(Theme.S(14), Theme.S(46)), Theme.Ink, TextFormatFlags.NoPrefix);
            List<KeyValuePair<string, int>> top = new List<KeyValuePair<string, int>>(byCountry); top.Sort(delegate (KeyValuePair<string, int> a, KeyValuePair<string, int> b) { return b.Value - a.Value; });
            int y = Height - Theme.S(20) - Math.Min(6, top.Count) * Theme.S(18);
            if (top.Count > 0) { TextRenderer.DrawText(g, "TOP COUNTRIES", Theme.UISmall, new Point(Theme.S(14), y - Theme.S(18)), Theme.Faint, TextFormatFlags.NoPrefix); for (int i = 0; i < top.Count && i < 6; i++) TextRenderer.DrawText(g, top[i].Value + "  " + top[i].Key, Theme.UISmall, new Point(Theme.S(14), y + i * Theme.S(18)), Theme.Dim, TextFormatFlags.NoPrefix); }
            List<string[]> tk; lock (ticker) tk = new List<string[]>(ticker);
            int tx = Width - Theme.S(300), ty = Theme.S(12);
            if (tk.Count > 0) { TextRenderer.DrawText(g, "RECENT", Theme.UISmall, new Point(tx, ty), Theme.Faint, TextFormatFlags.NoPrefix); ty += Theme.S(18); foreach (string[] t in tk) { Color c = t[2] == "out" ? Theme.Teal : Theme.Amber; TextRenderer.DrawText(g, t[0], Theme.UISmall, new Point(tx, ty), Theme.Faint, TextFormatFlags.NoPrefix); TextRenderer.DrawText(g, t[1], Theme.UISmall, new Point(tx + Theme.S(62), ty), c, TextFormatFlags.NoPrefix | TextFormatFlags.EndEllipsis); ty += Theme.S(17); } }
            int lx = Width - Theme.S(150), ly = Height - Theme.S(74);
            LegendDot(g, lx, ly, Theme.Teal, "outbound"); LegendDot(g, lx, ly + Theme.S(17), Theme.Amber, "inbound"); LegendDot(g, lx, ly + Theme.S(34), Theme.Rose, "you are here");
            TextRenderer.DrawText(g, "hover a country or a connection · scroll to zoom · drag to pan", Theme.UISmall, new Point(Width - Theme.S(380), Height - Theme.S(20)), Theme.Faint, TextFormatFlags.NoPrefix);
            if (hoverNode != null && hoverNode.Loc != null) DrawNodeTip(g, hoverNode);
            else if (hoverCountry > 0) { string nm = WorldMap.Name(hoverCountry); Size s = TextRenderer.MeasureText(g, nm, Theme.UI); int bx = Math.Min(Width - s.Width - Theme.S(20), mouseAt.X + Theme.S(14)), by = Math.Max(Theme.S(4), mouseAt.Y - s.Height - Theme.S(12)); using (Brush b = new SolidBrush(Color.FromArgb(225, Theme.Tip))) g.FillRectangle(b, bx, by, s.Width + Theme.S(14), s.Height + Theme.S(6)); TextRenderer.DrawText(g, nm, Theme.UI, new Point(bx + Theme.S(7), by + Theme.S(3)), Theme.Ink, TextFormatFlags.NoPrefix); }
        }
        void DrawNodeTip(Graphics g, Node n)
        {
            PointF p = ToScreen(n.Norm); List<string> lines = new List<string>(); List<Color> cols = new List<Color>(); List<Font> fonts = new List<Font>();
            Color dir = n.Outbound ? Theme.Teal : Theme.Amber;
            lines.Add(n.Loc.Place.Length > 0 ? n.Loc.Place : n.Ip); cols.Add(Theme.Ink); fonts.Add(Theme.UIBold);
            lines.Add(n.Ip + (n.Loc.Isp.Length > 0 ? "  ·  " + n.Loc.Isp : "")); cols.Add(Theme.Dim); fonts.Add(Theme.UISmall);
            lines.Add((n.Outbound ? "→ outbound" : "← inbound") + "  ·  " + n.Conns + " connection(s)"); cols.Add(dir); fonts.Add(Theme.UISmall);
            if (n.Details.Count > 0) { lines.Add("PORTS & PROTOCOLS"); cols.Add(Theme.Faint); fonts.Add(Theme.UISmall); foreach (string d in n.Details) { lines.Add(d); cols.Add(Theme.Ink); fonts.Add(Theme.UISmall); } }
            int bw = 0, bh = Theme.S(10); List<Size> sz = new List<Size>(); for (int i = 0; i < lines.Count; i++) { Size s = TextRenderer.MeasureText(g, lines[i], fonts[i]); sz.Add(s); bw = Math.Max(bw, s.Width); bh += s.Height; } bw += Theme.S(18);
            int bx = (int)Math.Min(Width - bw - Theme.S(6), Math.Max(Theme.S(6), p.X + Theme.S(14))), by = (int)Math.Min(Height - bh - Theme.S(6), Math.Max(Theme.S(6), p.Y - bh - Theme.S(10)));
            using (Brush bb = new SolidBrush(Color.FromArgb(240, Theme.Tip))) g.FillRectangle(bb, bx, by, bw, bh); using (Pen pp = new Pen(Color.FromArgb(190, dir))) g.DrawRectangle(pp, bx, by, bw, bh);
            int cy = by + Theme.S(5); for (int i = 0; i < lines.Count; i++) { TextRenderer.DrawText(g, lines[i], fonts[i], new Point(bx + Theme.S(9), cy), cols[i], TextFormatFlags.NoPrefix); cy += sz[i].Height; }
        }
        void LegendDot(Graphics g, int x, int y, Color c, string label) { using (Brush b = new SolidBrush(c)) g.FillEllipse(b, x, y + Theme.S(3), Theme.S(8), Theme.S(8)); TextRenderer.DrawText(g, label, Theme.UISmall, new Point(x + Theme.S(14), y), Theme.Dim, TextFormatFlags.NoPrefix); }
        Node HitNode(Point p) { Node best = null; float bestD = 14 * 14; lock (nodes) foreach (Node n in nodes.Values) { if (n.Loc == null || n.Glow <= 0.05f) continue; PointF s = ToScreen(n.Norm); float dx = s.X - p.X, dy = s.Y - p.Y; float d = dx * dx + dy * dy; if (d < bestD) { bestD = d; best = n; } } return best; }
        /// <summary>The connection arc under the cursor, if any: sample each arc and take the closest within a few pixels.</summary>
        Node HitArc(Point p)
        {
            Node best = null; float bestD = 7f * 7f; PointF hs = ToScreen(homeNorm);
            lock (nodes) foreach (Node n in nodes.Values)
            {
                if (n.Loc == null || n.Glow <= 0.05f) continue; PointF b = ToScreen(n.Norm); if (Bad(b)) continue;
                for (int i = 1; i < 32; i++) { PointF q = ArcPoint(hs, b, i / 32f); float dx = q.X - p.X, dy = q.Y - p.Y; float d = dx * dx + dy * dy; if (d < bestD) { bestD = d; best = n; } }
            }
            return best;
        }

        // ── demo data for screenshots (fabricated, offline) ──
        public void Demo()
        {
            hasHome = true; home = new GeoLoc(); home.Ok = true; home.City = "Lisbon"; home.Country = "Portugal"; home.Lat = 38.72; home.Lon = -9.14; homeNorm = WorldMap.Norm(38.72, -9.14);
            lock (nodes)
            {
                nodes.Clear();
                AddDemo("142.250.80.46", "Mountain View", "United States", 37.4, -122.1, 6, true, "chrome.exe", new string[] { "TCP 443 · chrome.exe · established  ×5", "UDP 443 · chrome.exe" });
                AddDemo("13.107.42.14", "Amsterdam", "Netherlands", 52.37, 4.9, 3, true, "svchost.exe", new string[] { "TCP 443 · svchost.exe · established  ×3" });
                AddDemo("104.244.42.1", "San Francisco", "United States", 37.77, -122.4, 2, true, "firefox.exe", new string[] { "TCP 443 · firefox.exe · established  ×2" });
                AddDemo("151.101.1.69", "London", "United Kingdom", 51.5, -0.13, 4, true, "chrome.exe", new string[] { "TCP 443 · chrome.exe · established  ×4" });
                AddDemo("203.0.113.9", "Singapore", "Singapore", 1.29, 103.85, 1, false, "Code.exe", new string[] { "TCP 22 · Code.exe · established" });
                AddDemo("77.88.55.60", "Moscow", "Russia", 55.75, 37.62, 1, false, "unknown", new string[] { "TCP 3389 · unknown · syn_received" });
                AddDemo("200.147.67.142", "São Paulo", "Brazil", -23.55, -46.63, 2, true, "Spotify.exe", new string[] { "TCP 4070 · Spotify.exe · established  ×2" });
                AddDemo("110.75.30.10", "Tokyo", "Japan", 35.68, 139.69, 3, true, "steam.exe", new string[] { "UDP 27015 · steam.exe  ×2", "TCP 443 · steam.exe · established" });
            }
            lock (pulses) pulses.Clear(); lock (nodes) foreach (Node n in nodes.Values) SpawnPulses(n, 3);
            Invalidate();
        }
        void AddDemo(string ip, string city, string country, double lat, double lon, int conns, bool outb, string proc, string[] details)
        {
            Node n = new Node(); n.Ip = ip; n.Loc = new GeoLoc(); n.Loc.Ok = true; n.Loc.City = city; n.Loc.Country = country; n.Loc.Lat = lat; n.Loc.Lon = lon; n.Loc.Isp = "demo"; n.Norm = WorldMap.Norm(lat, lon); n.Country = country; n.Conns = conns; n.Outbound = outb; n.Proc = proc; n.Glow = 1f; n.Last = DateTime.Now; n.Details.AddRange(details); nodes[ip] = n; AddTicker(n);
        }
    }
}

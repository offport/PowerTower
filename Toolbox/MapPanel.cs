// Findings Map: this machine at the centre of a live force-directed graph, wired to what every tool found —
// system, users, network, software, autoruns, firewall, Wi-Fi, browsers, the security checklist, recent
// events and vulnerabilities. The layout is a physics simulation (nodes repel, edges pull, a gentle gravity
// keeps it centred), so it settles smoothly and you can drag any node, scroll to zoom and drag to pan.
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Management;
using System.Net.NetworkInformation;
using System.Threading;
using System.Windows.Forms;

namespace PSTools
{
    /// <summary>One node in the findings graph. Carries its physics state (position + velocity).</summary>
    public class MapNode
    {
        public string Label = "", Detail = "", Kind = "", Icon = ""; public Color Fill = Theme.Teal; public List<MapNode> Children; public bool Expanded; public MapNode Parent; public int Depth;
        public float X, Y, R, Vx, Vy; public bool Seeded, Pinned;
        public MapNode Ico(string icon) { Icon = icon; return this; }
        /// <summary>This node's icon, inheriting a smaller version of the nearest ancestor's when it has none.</summary>
        public string IconKey { get { MapNode a = this; while (a != null) { if (a.Icon.Length > 0) return a.Icon; a = a.Parent; } return "map:generic"; } }
        public MapNode(string label, Color fill) { Label = label; Fill = fill; }
        public MapNode(string label, Color fill, string detail) { Label = label; Fill = fill; Detail = detail; }
        public MapNode Add(MapNode c) { if (Children == null) Children = new List<MapNode>(); c.Parent = this; Children.Add(c); return c; }
        public bool HasChildren { get { return Children != null && Children.Count > 0; } }
        public int Count { get { return Children == null ? 0 : Children.Count; } }
    }

    /// <summary>A force-directed graph: nodes repel, parent/child edges act as springs, a gentle gravity centres it.
    /// Nodes are draggable; the view pans and zooms smoothly. Click a node with children to expand/collapse.</summary>
    public class GraphView : Control
    {
        public MapNode Root; public event Action<MapNode> Selected;
        readonly List<MapNode> shown = new List<MapNode>(); MapNode hover, selected, dragNode;
        float zoom = 1f, zoomTarget = 1f; PointF pan, panTarget; bool panning, movedWhileDown; Point downAt; PointF panFrom; MapNode downNode;
        float alpha; readonly System.Windows.Forms.Timer sim = new System.Windows.Forms.Timer(); readonly Random rng = new Random(7);
        // physics constants
        const float Repulsion = 14000f, Spring = 0.035f, Gravity = 0.009f, Damping = 0.85f, MaxV = 70f;

        public GraphView()
        {
            SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
            BackColor = Theme.Bg; Dock = DockStyle.Fill;
            sim.Interval = 30; sim.Tick += delegate { Step(); };
        }

        public void SetRoot(MapNode root)
        {
            Root = root; if (Root != null) { Root.Expanded = true; Root.X = 0; Root.Y = 0; Root.Seeded = true; }
            Rebuild(); SeedPositions();
            // pre-warm the simulation so the graph is spread out and settled before the first frame
            for (int i = 0; i < 160; i++) Iterate(Math.Max(0.08f, 1f - i / 200f));
            alpha = 0.12f; FitNow(); zoom = zoomTarget; pan = panTarget; sim.Start(); Invalidate();
        }
        public void ExpandAll() { Walk(Root, delegate (MapNode n) { if (n.HasChildren) n.Expanded = true; }); Rebuild(); SeedPositions(); Reheat(0.8f); }
        public void CollapseAll() { if (Root != null && Root.Children != null) foreach (MapNode c in Root.Children) Walk(c, delegate (MapNode n) { n.Expanded = false; }); Rebuild(); Reheat(0.8f); }
        public void FitView() { FitNow(); }
        /// <summary>Re-flow the layout tidily: release every pinned node, re-warm the simulation and re-fit. Keeps expansions and does not reset the view to defaults beyond fitting.</summary>
        public void Reformat()
        {
            if (Root == null) return; foreach (MapNode n in shown) { n.Pinned = false; n.Vx = 0; n.Vy = 0; }
            for (int i = 0; i < 140; i++) Iterate(Math.Max(0.08f, 1f - i / 180f));
            alpha = 0.14f; FitNow(); sim.Start(); Invalidate();
        }
        static void Walk(MapNode n, Action<MapNode> f) { if (n == null) return; f(n); if (n.Children != null) foreach (MapNode c in n.Children) Walk(c, f); }
        void Reheat(float a) { alpha = Math.Max(alpha, a); if (!sim.Enabled) sim.Start(); Invalidate(); }

        void Rebuild() { shown.Clear(); if (Root != null) Collect(Root, 0); }
        void Collect(MapNode n, int depth) { n.Depth = depth; n.R = depth == 0 ? 24 : depth == 1 ? 16 : 11; shown.Add(n); if (n.Expanded && n.HasChildren) foreach (MapNode c in n.Children) Collect(c, depth + 1); }

        void SeedPositions()
        {
            foreach (MapNode n in shown)
            {
                if (n.Seeded) continue; n.Seeded = true;
                if (n.Parent == null) { n.X = 0; n.Y = 0; continue; }
                // fan children out evenly around the parent, pointing away from the grandparent, at a ring sized to fit them all
                MapNode par = n.Parent; int cnt = par.Children != null ? par.Children.Count : 1; int idx = par.Children != null ? par.Children.IndexOf(n) : 0;
                double baseAng = 0; if (par.Parent != null) baseAng = Math.Atan2(par.Y - par.Parent.Y, par.X - par.Parent.X);
                double spread = cnt <= 1 ? 0 : (par.Parent == null ? Math.PI * 2 : Math.Min(Math.PI * 2, 0.6 + cnt * 0.32));
                double ang = baseAng + (cnt <= 1 ? 0 : spread * ((double)idx / Math.Max(1, cnt - (par.Parent == null ? 0 : 1)) - 0.5));
                float dist = RestFor(n) * (0.9f + (float)rng.NextDouble() * 0.2f);
                n.X = par.X + (float)Math.Cos(ang) * dist; n.Y = par.Y + (float)Math.Sin(ang) * dist;
            }
        }
        static float Rest(int depth) { return depth <= 1 ? 175f : depth == 2 ? 110f : 82f; }
        static float RestFor(MapNode c) { float r = Rest(c.Depth); int sib = c.Parent != null && c.Parent.Children != null ? c.Parent.Children.Count : 1; if (sib > 8) r += (float)Math.Sqrt(sib) * 12f; return r; }

        void Step()
        {
            if (shown.Count == 0) { return; }
            // ease zoom + pan toward targets (smooth wheel/fit)
            zoom += (zoomTarget - zoom) * 0.25f; pan = new PointF(pan.X + (panTarget.X - pan.X) * 0.25f, pan.Y + (panTarget.Y - pan.Y) * 0.25f);
            bool moving = Math.Abs(zoom - zoomTarget) > 0.001f || Math.Abs(pan.X - panTarget.X) > 0.3f || Math.Abs(pan.Y - panTarget.Y) > 0.3f;
            if (alpha > 0.02f) { Iterate(alpha); alpha += (0f - alpha) * 0.02f; Invalidate(); }
            else if (moving) Invalidate();
            else if (dragNode == null) sim.Stop();
        }

        /// <summary>One physics iteration at the given alpha (0..1). Used by the animation timer and the pre-warm settle.</summary>
        void Iterate(float a)
        {
            int n = shown.Count;
            for (int i = 0; i < n; i++)
            {
                MapNode p1 = shown[i];
                for (int j = i + 1; j < n; j++)
                {
                    MapNode p2 = shown[j]; float dx = p1.X - p2.X, dy = p1.Y - p2.Y; float d2 = dx * dx + dy * dy + 0.01f; float d = (float)Math.Sqrt(d2);
                    // extra push when the discs actually overlap, so labels don't collide
                    float minD = p1.R + p2.R + 26f; float f = Repulsion / d2; if (d < minD) f += (minD - d) * 0.9f;
                    float ux = dx / d, uy = dy / d; float fx = ux * f, fy = uy * f; p1.Vx += fx; p1.Vy += fy; p2.Vx -= fx; p2.Vy -= fy;
                }
            }
            foreach (MapNode c in shown)
            {
                if (c.Parent == null) continue; MapNode p = c.Parent; float dx = c.X - p.X, dy = c.Y - p.Y; float d = (float)Math.Sqrt(dx * dx + dy * dy) + 0.01f;
                float rest = RestFor(c); float f = Spring * (d - rest); float ux = dx / d, uy = dy / d; float fx = ux * f, fy = uy * f;
                c.Vx -= fx; c.Vy -= fy; p.Vx += fx * 0.5f; p.Vy += fy * 0.5f;
            }
            foreach (MapNode nd in shown)
            {
                if (nd == dragNode || nd.Pinned) { nd.Vx = 0; nd.Vy = 0; continue; }
                nd.Vx += -nd.X * Gravity; nd.Vy += -nd.Y * Gravity; nd.Vx *= Damping; nd.Vy *= Damping;
                float v = (float)Math.Sqrt(nd.Vx * nd.Vx + nd.Vy * nd.Vy); if (v > MaxV) { nd.Vx = nd.Vx / v * MaxV; nd.Vy = nd.Vy / v * MaxV; }
                if (nd.Parent == null) { nd.X += nd.Vx * 0.12f * a; nd.Y += nd.Vy * 0.12f * a; } else { nd.X += nd.Vx * a; nd.Y += nd.Vy * a; }
                if (float.IsNaN(nd.X) || float.IsInfinity(nd.X)) { nd.X = 0; nd.Vx = 0; } if (float.IsNaN(nd.Y) || float.IsInfinity(nd.Y)) { nd.Y = 0; nd.Vy = 0; }
                const float Bound = 6000f; if (nd.X < -Bound) nd.X = -Bound; else if (nd.X > Bound) nd.X = Bound; if (nd.Y < -Bound) nd.Y = -Bound; else if (nd.Y > Bound) nd.Y = Bound;
            }
        }

        // ── view transform ──
        PointF ToScreen(float x, float y) { return new PointF(ClientSize.Width / 2f + pan.X + x * zoom, ClientSize.Height / 2f + pan.Y + y * zoom); }
        bool OffCanvas(PointF p) { return float.IsNaN(p.X) || float.IsNaN(p.Y) || p.X < -4000 || p.Y < -4000 || p.X > Width + 4000 || p.Y > Height + 4000; }
        PointF ToWorld(int sx, int sy) { return new PointF((sx - ClientSize.Width / 2f - pan.X) / zoom, (sy - ClientSize.Height / 2f - pan.Y) / zoom); }
        bool fitPending;
        void FitLater() { fitPending = true; }
        void FitNow()
        {
            if (shown.Count == 0) return; float minX = 1e9f, minY = 1e9f, maxX = -1e9f, maxY = -1e9f;
            foreach (MapNode n in shown) { minX = Math.Min(minX, n.X - n.R); minY = Math.Min(minY, n.Y - n.R); maxX = Math.Max(maxX, n.X + n.R); maxY = Math.Max(maxY, n.Y + n.R); }
            float w = Math.Max(1, maxX - minX) + 120, h = Math.Max(1, maxY - minY) + 120; int cw = Math.Max(50, ClientSize.Width), ch = Math.Max(50, ClientSize.Height);
            zoomTarget = Math.Min(1.8f, Math.Max(0.12f, Math.Min(cw / w, ch / h))); panTarget = new PointF(-((minX + maxX) / 2) * zoomTarget, -((minY + maxY) / 2) * zoomTarget);
            if (!sim.Enabled) sim.Start();
        }

        // ── paint ──
        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics;
            using (Brush bg = new LinearGradientBrush(ClientRectangle, Theme.MapBg, Theme.MapBg2, 90f)) g.FillRectangle(bg, ClientRectangle);
            if (Root == null) { TextRenderer.DrawText(g, "Click “Build map” to gather this machine's findings.", Theme.UI, ClientRectangle, Theme.Dim, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter); return; }
            if (fitPending && shown.Count > 0) { fitPending = false; FitNow(); }
            g.SmoothingMode = SmoothingMode.AntiAlias; g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
            // edges (curved, flat — one calm colour, no glow)
            foreach (MapNode n in shown)
            {
                if (n.Parent == null) continue; PointF a = ToScreen(n.Parent.X, n.Parent.Y), b = ToScreen(n.X, n.Y);
                if (OffCanvas(a) && OffCanvas(b)) continue; float edx = b.X - a.X, edy = b.Y - a.Y; float elen = edx * edx + edy * edy; if (float.IsNaN(elen) || elen < 1f || elen > 9e8f) continue;
                bool hot = n == hover || n == selected || n.Parent == hover; int alphaE = hot ? 170 : 55;
                PointF mid = new PointF((a.X + b.X) / 2, (a.Y + b.Y) / 2 - Math.Abs(b.X - a.X) * 0.06f);
                using (GraphicsPath gp = new GraphicsPath()) { gp.AddBezier(a, new PointF((a.X + mid.X) / 2, (a.Y + mid.Y) / 2), new PointF((b.X + mid.X) / 2, (b.Y + mid.Y) / 2), b);
                    using (Pen p = new Pen(Color.FromArgb(alphaE, hot ? Theme.Teal : Theme.TealSoft), hot ? 1.8f : 1.0f)) { try { g.DrawPath(p, gp); } catch (OutOfMemoryException) { } catch (System.Runtime.InteropServices.ExternalException) { } } }
            }
            // nodes — a small flat icon in the one theme colour; a thin ring carries severity; no glow
            foreach (MapNode n in shown)
            {
                PointF c = ToScreen(n.X, n.Y); float r = n.R * zoom; bool hot = n == hover || n == selected;
                if (OffCanvas(c)) continue;
                using (Brush disc = new SolidBrush(Color.FromArgb(hot ? 235 : 200, Theme.Disc))) g.FillEllipse(disc, c.X - r, c.Y - r, r * 2, r * 2);
                Color ring = n.Fill == Theme.Rose || n.Fill == Theme.Amber ? n.Fill : Theme.NeutralRing; // keep red/amber risk cue, else neutral
                using (Pen rp = new Pen(hot ? Theme.Teal : Color.FromArgb(190, ring), hot ? 1.8f : 1.2f)) g.DrawEllipse(rp, c.X - r, c.Y - r, r * 2, r * 2);
                float ir = r * 0.92f; Icons.Paint(g, n.IconKey, new Rectangle((int)(c.X - ir), (int)(c.Y - ir), (int)(ir * 2), (int)(ir * 2)), hot ? Color.White : Theme.Teal);
                if (n.Pinned) { float pr = Math.Max(2.4f, r * 0.22f); using (Brush b = new SolidBrush(Theme.Teal)) g.FillEllipse(b, c.X + r * 0.62f, c.Y - r * 0.62f - pr, pr * 2, pr * 2); }
                if (n.HasChildren && !n.Expanded)
                {
                    string badge = n.Count.ToString(); float br = Math.Max(Theme.S(6), r * 0.52f); RectangleF brc = new RectangleF(c.X + r - br * 0.8f, c.Y + r - br * 1.2f, br * 2, br * 2);
                    using (Brush b = new SolidBrush(Color.FromArgb(248, Theme.Badge))) g.FillEllipse(b, brc); using (Pen p = new Pen(Color.FromArgb(170, Theme.Teal), 1f)) g.DrawEllipse(p, brc);
                    TextRenderer.DrawText(g, badge, Theme.UISmall, Rectangle.Round(brc), Theme.Teal, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPrefix);
                }
                Font lf = n.Depth <= 1 ? Theme.UIBold : Theme.UISmall; string label = n.Label; if (label.Length > 34 && n.Depth > 1) label = label.Substring(0, 33) + "…";
                if (zoom > 0.32f || n.Depth <= 1)
                {
                    Size ls = TextRenderer.MeasureText(g, label, lf); int lx = (int)(c.X - ls.Width / 2), ly = (int)(c.Y + r + Theme.S(2));
                    using (Brush bgl = new SolidBrush(Color.FromArgb(160, Theme.Halo))) g.FillRectangle(bgl, lx - Theme.S(3), ly, ls.Width + Theme.S(6), ls.Height);
                    TextRenderer.DrawText(g, label, lf, new Point(lx, ly), hot ? Color.White : n.Depth == 0 ? Theme.Teal : n.Fill == Theme.Rose || n.Fill == Theme.Amber ? n.Fill : Theme.Ink, TextFormatFlags.NoPrefix);
                }
            }
            DrawInfo(g);
            TextRenderer.DrawText(g, "drag a node to move it (it stays put) · right-click a node to release it · Reformat to re-flow · scroll to zoom · click to expand", Theme.UISmall, new Point(Theme.S(10), ClientSize.Height - Theme.S(20)), Theme.Faint, TextFormatFlags.NoPrefix);
        }
        void DrawInfo(Graphics g)
        {
            MapNode info = hover ?? selected; if (info == null || (info.Detail.Length == 0 && !info.HasChildren)) return;
            string t1 = info.Label; string t2 = info.Detail.Length > 0 ? info.Detail : (info.Count + " item(s) — " + (info.Expanded ? "click to collapse" : "click to expand"));
            Size s1 = TextRenderer.MeasureText(g, t1, Theme.UIBold), s2 = TextRenderer.MeasureText(g, t2, Theme.UISmall);
            int bw = Math.Min(ClientSize.Width - Theme.S(20), Math.Max(s1.Width, s2.Width) + Theme.S(20)); int bh = s1.Height + s2.Height + Theme.S(14);
            Rectangle box = new Rectangle(ClientSize.Width - bw - Theme.S(10), Theme.S(10), bw, bh);
            using (Brush b = new SolidBrush(Color.FromArgb(238, Theme.Panel2))) g.FillRectangle(b, box); using (Pen p = new Pen(info.Fill)) g.DrawRectangle(p, box);
            TextRenderer.DrawText(g, t1, Theme.UIBold, new Rectangle(box.X + Theme.S(8), box.Y + Theme.S(5), box.Width - Theme.S(12), s1.Height), info.Fill, TextFormatFlags.NoPrefix | TextFormatFlags.EndEllipsis);
            TextRenderer.DrawText(g, t2, Theme.UISmall, new Rectangle(box.X + Theme.S(8), box.Y + Theme.S(6) + s1.Height, box.Width - Theme.S(12), s2.Height), Theme.Dim, TextFormatFlags.NoPrefix | TextFormatFlags.EndEllipsis);
        }
        static Color Lighten(Color c) { return Color.FromArgb(Math.Min(255, c.R + 45), Math.Min(255, c.G + 45), Math.Min(255, c.B + 45)); }
        static Color Darken(Color c) { return Color.FromArgb(c.R / 2, c.G / 2, c.B / 2); }

        // ── interaction ──
        MapNode HitTest(int sx, int sy) { for (int i = shown.Count - 1; i >= 0; i--) { MapNode n = shown[i]; PointF c = ToScreen(n.X, n.Y); float r = n.R * zoom + 4; if ((sx - c.X) * (sx - c.X) + (sy - c.Y) * (sy - c.Y) <= r * r) return n; } return null; }
        protected override void OnMouseDown(MouseEventArgs e)
        {
            downAt = e.Location; movedWhileDown = false; downNode = HitTest(e.X, e.Y);
            if (e.Button == MouseButtons.Right) { if (downNode != null && downNode.Depth > 0) { downNode.Pinned = false; Reheat(0.4f); } return; }
            if (downNode != null) { selected = downNode; if (Selected != null) Selected(downNode); dragNode = downNode; if (!sim.Enabled) sim.Start(); }
            else { panning = true; panFrom = panTarget; }
            base.OnMouseDown(e);
        }
        protected override void OnMouseMove(MouseEventArgs e)
        {
            if (Math.Abs(e.X - downAt.X) + Math.Abs(e.Y - downAt.Y) > 3) movedWhileDown = true;
            if (dragNode != null)
            {
                PointF w = ToWorld(e.X, e.Y); dragNode.X = w.X; dragNode.Y = w.Y; dragNode.Vx = 0; dragNode.Vy = 0; Reheat(0.5f);
            }
            else if (panning) { panTarget = new PointF(panFrom.X + (e.X - downAt.X), panFrom.Y + (e.Y - downAt.Y)); pan = panTarget; Invalidate(); }
            else { MapNode n = HitTest(e.X, e.Y); Cursor = n != null ? Cursors.Hand : Cursors.Default; if (n != hover) { hover = n; Invalidate(); } }
            base.OnMouseMove(e);
        }
        protected override void OnMouseUp(MouseEventArgs e)
        {
            if (dragNode != null)
            {
                MapNode dn = dragNode; dragNode = null;
                if (!movedWhileDown) { if (dn.HasChildren && dn.Depth > 0) { dn.Expanded = !dn.Expanded; Rebuild(); SeedPositions(); Reheat(0.7f); } }
                else { dn.Pinned = true; dn.Vx = 0; dn.Vy = 0; Reheat(0.35f); } // dropped here → stays put
            }
            panning = false; base.OnMouseUp(e);
        }
        protected override void OnMouseDoubleClick(MouseEventArgs e) { MapNode n = HitTest(e.X, e.Y); if (n != null && n.Depth == 0) CollapseAll(); base.OnMouseDoubleClick(e); }
        protected override void OnMouseWheel(MouseEventArgs e)
        {
            float f = e.Delta > 0 ? 1.18f : 1 / 1.18f; float ns = Math.Max(0.1f, Math.Min(4f, zoomTarget * f)); if (ns == zoomTarget) return;
            PointF w = ToWorld(e.X, e.Y); zoomTarget = ns; panTarget = new PointF(e.X - ClientSize.Width / 2f - w.X * zoomTarget, e.Y - ClientSize.Height / 2f - w.Y * zoomTarget);
            if (!sim.Enabled) sim.Start(); base.OnMouseWheel(e);
        }
    }

    public class MapPanel : ToolPanel
    {
        public override string Title { get { return Tools.Title(GetType().Name); } }
        public override string Blurb { get { return Tools.Blurb(GetType().Name); } }
        readonly GraphView graph = new GraphView(); readonly StepStrip steps = new StepStrip(); readonly Button bBuild, bExpand, bCollapse, bFit, bReformat; readonly CheckBox cDeep; readonly Label status = Theme.Lbl("", Theme.Dim, Theme.UISmall);
        Thread worker; volatile bool building;

        public MapPanel()
        {
            BackColor = Theme.Panel;
            FlowLayoutPanel bar = Theme.Bar(46);
            bBuild = Theme.Btn("Build map", true); bBuild.Click += delegate { Build(); };
            cDeep = Theme.Toggle("deep scan (checklist + events, slower)", true); new ToolTip().SetToolTip(cDeep, "Also run the security checklist and read recent security events. Adds about 20-30 seconds.");
            bExpand = Theme.Btn("Expand all", false); bExpand.Click += delegate { graph.ExpandAll(); }; bCollapse = Theme.Btn("Collapse all", false); bCollapse.Click += delegate { graph.CollapseAll(); }; bFit = Theme.Btn("Fit", false); bFit.Click += delegate { graph.FitView(); }; bReformat = Theme.Btn("Reformat", false); new ToolTip().SetToolTip(bReformat, "Re-flow the whole map tidily: releases any nodes you dragged and lets the layout settle again. Keeps what is expanded."); bReformat.Click += delegate { graph.Reformat(); };
            foreach (Control c in new Control[] { bBuild, cDeep, bExpand, bCollapse, bReformat, bFit, status }) bar.Controls.Add(c); status.Margin = new Padding(Theme.S(10), Theme.S(9), 0, 0);
            Controls.Add(graph); Controls.Add(steps); Controls.Add(bar); graph.BringToFront();
        }
        void Ui(Action a) { try { Host.BeginInvoke(a); } catch { } }

        void Build()
        {
            if (building) { Host.Toast("Still building the map.", true); return; }
            building = true; bBuild.Enabled = false; bool deep = cDeep.Checked;
            List<string> stepList = new List<string>(new string[] { "System", "Users", "Network", "Software", "Autoruns", "Firewall", "Wi-Fi", "Browsers" });
            if (deep) { stepList.Add("Checklist"); stepList.Add("Events"); } stepList.Add("Vulnerabilities");
            steps.Begin(stepList.ToArray());
            worker = new Thread(delegate ()
            {
                MapNode root = null;
                try { root = Collect(deep, delegate (string label, string state, string note) { Ui(delegate { steps.Set(label, state, note); }); }, delegate (string m) { Ui(delegate { status.Text = m; steps.Say(m); }); }); }
                catch (Exception ex) { Ui(delegate { Host.Toast("map: " + ex.Message, true); }); }
                Ui(delegate { building = false; bBuild.Enabled = true; if (root != null) { graph.SetRoot(root); int total = 0; Count(root, ref total); steps.End("done · " + (root.Children == null ? 0 : root.Children.Count) + " branches · " + total + " nodes"); status.Text = "map built — drag a node, scroll to zoom, click to expand"; } });
            });
            worker.IsBackground = true; worker.Start();
        }

        MapNode Collect(bool deep, Action<string, string, string> step, Action<string> say)
        {
            OsInfo os = null; try { os = Inventory.Os(); } catch { }
            MapNode root = new MapNode(os != null ? os.Host : Environment.MachineName, Theme.Teal, os != null ? os.Summary : "this machine"); root.Icon = "map:host";

            step("System", "running", null); say("system…");
            MapNode sys = root.Add(new MapNode("System", Theme.Blue, os != null ? os.Summary : "").Ico("map:system"));
            if (os != null) { sys.Add(new MapNode(os.ProductName, Theme.Blue, "build " + os.FullBuild)); sys.Add(new MapNode("Build " + os.FullBuild, Theme.Blue, os.Edition + " · " + os.Arch)); }
            try { RebootInfo rb = Inventory.Reboot(); sys.Add(new MapNode(rb.Pending ? "Reboot pending" : "No reboot pending", rb.Pending ? Theme.Amber : Theme.Green, rb.Why)); } catch { }
            step("System", "done", null);

            step("Users", "running", null); say("users…");
            MapNode users = root.Add(new MapNode("Users", Theme.Violet, "").Ico("map:users"));
            try
            {
                HashSet<string> admins = Admins(); int nu = 0;
                using (ManagementObjectSearcher q = new ManagementObjectSearcher("SELECT Name, Disabled, PasswordRequired FROM Win32_UserAccount WHERE LocalAccount=True"))
                    foreach (ManagementObject o in q.Get())
                    {
                        string name = Convert.ToString(o["Name"]); bool disabled = ToBool(o["Disabled"]); bool pwReq = ToBool(o["PasswordRequired"]); bool admin = admins.Contains(name); nu++;
                        Color col = (!disabled && !pwReq) ? Theme.Rose : admin ? Theme.Amber : disabled ? Theme.Faint : Theme.Violet;
                        users.Add(new MapNode(name + (admin ? "  (admin)" : ""), col, (disabled ? "disabled" : "enabled") + " · password " + (pwReq ? "required" : "not required")).Ico("map:user"));
                    }
                users.Detail = nu + " local account(s)";
            }
            catch (Exception ex) { users.Add(new MapNode("unavailable", Theme.Faint, ex.Message)); }
            step("Users", "done", users.Count + "");

            step("Network", "running", null); say("network…");
            MapNode net = root.Add(new MapNode("Network", Theme.Blue, "").Ico("map:network"));
            try
            {
                MapNode ips = net.Add(new MapNode("Addresses", Theme.Blue, ""));
                foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces()) { if (ni.OperationalStatus != OperationalStatus.Up || ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue; foreach (UnicastIPAddressInformation ip in ni.GetIPProperties().UnicastAddresses) if (ip.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) ips.Add(new MapNode(ip.Address.ToString(), Theme.Blue, ni.Name + " · " + ni.Description)); }
                ips.Detail = ips.Count + " IPv4 address(es)";
                List<Conn> conns = ConnTable.Snapshot(true, true); NameCache nc = new NameCache();
                MapNode listen = net.Add(new MapNode("Listening ports", Theme.Blue, "")); HashSet<string> seen = new HashSet<string>();
                foreach (Conn c in conns) { if (c.State == null || !c.State.StartsWith("LISTEN")) continue; string key = c.Proto + ":" + c.LocalPort; if (!seen.Add(key)) continue; string proc = nc.ProcessName(c.Pid); listen.Add(new MapNode(c.Proto + " " + c.LocalPort, Theme.Blue, (proc.Length > 0 ? proc : "?") + " (PID " + c.Pid + ")").Ico("map:port")); }
                listen.Detail = listen.Count + " listening port(s)";
                int est = 0; foreach (Conn c in conns) if (c.State == "ESTABLISHED" && !c.Loopback) est++; net.Add(new MapNode(est + " active connection(s)", Theme.Blue, "established, non-loopback"));
            }
            catch (Exception ex) { net.Add(new MapNode("unavailable", Theme.Faint, ex.Message)); }
            step("Network", "done", null);

            step("Software", "running", null); say("installed software…");
            MapNode sw = root.Add(new MapNode("Software", Theme.Blue, "").Ico("map:software"));
            try
            {
                List<Software> list = Inventory.Installed(); int mapped = 0, shownN = 0;
                foreach (Software s in list) { if (shownN++ >= 60) break; if (s.Mapped) mapped++; sw.Add(new MapNode(s.Name + (s.Version.Length > 0 ? "  " + s.Version : ""), s.Mapped ? Theme.Teal : Theme.Blue, s.Publisher)); }
                sw.Detail = list.Count + " program(s), " + mapped + " in the CVE product map" + (list.Count > 60 ? " (showing 60)" : "");
            }
            catch (Exception ex) { sw.Add(new MapNode("unavailable", Theme.Faint, ex.Message)); }
            step("Software", "done", sw.Count + "");

            // Autoruns (collect only, no signature verify, to keep it quick)
            step("Autoruns", "running", null); say("autostart entries…");
            try
            {
                List<AutorunEntry> ar = Autoruns.Collect(null, null);
                MapNode arn = root.Add(new MapNode("Autoruns", Theme.Teal, ar.Count + " entries").Ico("map:autoruns"));
                Dictionary<string, MapNode> byKind = new Dictionary<string, MapNode>(); int risky = 0;
                foreach (AutorunEntry a in ar) { MapNode kn; if (!byKind.TryGetValue(a.Kind, out kn)) { kn = arn.Add(new MapNode(a.Kind, Theme.Blue, "")); byKind[a.Kind] = kn; } bool r = a.Where == "user-writable" || a.Where == "other"; if (r) risky++; if (kn.Count < 40) kn.Add(new MapNode(a.Name, r ? Theme.Amber : Theme.Blue, a.Command)); }
                foreach (KeyValuePair<string, MapNode> kv in byKind) kv.Value.Detail = kv.Value.Count + " entr" + (kv.Value.Count == 1 ? "y" : "ies");
                arn.Fill = risky > 0 ? Theme.Amber : Theme.Teal; arn.Detail = ar.Count + " entries · " + risky + " in writable folders";
                step("Autoruns", "done", ar.Count + " · " + risky + " risky");
            }
            catch (Exception ex) { root.Add(new MapNode("Autoruns", Theme.Faint, ex.Message)); step("Autoruns", "failed", null); }

            // Firewall
            step("Firewall", "running", null); say("firewall…");
            try
            {
                string pnote; List<FwProfile> profs = WinFirewall.ReadProfiles(out pnote); string rnote; List<FwRule> rules = WinFirewall.ReadRules(out rnote);
                int off = 0; foreach (FwProfile p in profs) if (!p.On) off++; int risky = 0; foreach (FwRule f in rules) if (f.Risk.Length > 0) risky++;
                MapNode fw = root.Add(new MapNode("Firewall", off > 0 ? Theme.Rose : risky > 0 ? Theme.Amber : Theme.Green, (off == 0 ? "on" : off + " profile(s) off") + " · " + rules.Count + " rules").Ico("map:firewall"));
                foreach (FwProfile p in profs) fw.Add(new MapNode(p.Name + ": " + (p.On ? "on" : "off"), p.On ? Theme.Green : Theme.Rose, "default inbound " + p.DefaultInbound));
                if (risky > 0) { MapNode rn = fw.Add(new MapNode(risky + " risky rule(s)", Theme.Amber, "")); int k = 0; foreach (FwRule f in rules) { if (f.Risk.Length == 0 || k++ >= 20) continue; rn.Add(new MapNode(f.Name, f.Risk == "high" ? Theme.Rose : Theme.Amber, f.RiskWhy)); } }
                step("Firewall", "done", rules.Count + " rules · " + risky + " risky");
            }
            catch (Exception ex) { root.Add(new MapNode("Firewall", Theme.Faint, ex.Message)); step("Firewall", "failed", null); }

            // Wi-Fi
            step("Wi-Fi", "running", null); say("saved Wi-Fi…");
            try
            {
                string wnote; List<WifiProfile> wifi = Creds.Wifi(out wnote, false); int weak = 0; foreach (WifiProfile w in wifi) if (w.Risk.Length > 0) weak++;
                MapNode wn = root.Add(new MapNode("Wi-Fi", weak > 0 ? Theme.Amber : Theme.Teal, wifi.Count + " saved network(s)").Ico("map:wifi"));
                foreach (WifiProfile w in wifi) wn.Add(new MapNode(w.Ssid, w.Risk == "high" ? Theme.Rose : w.Risk == "medium" ? Theme.Amber : Theme.Teal, w.Security.Length > 0 ? w.Security : "unknown"));
                step("Wi-Fi", "done", wifi.Count + " · " + weak + " weak");
            }
            catch (Exception ex) { root.Add(new MapNode("Wi-Fi", Theme.Faint, ex.Message)); step("Wi-Fi", "failed", null); }

            // Browsers
            step("Browsers", "running", null); say("browsers…");
            try
            {
                List<BrowserProfile> ps = Browser.Profiles();
                MapNode bn = root.Add(new MapNode("Browsers", Theme.Violet, ps.Count + " profile(s)").Ico("map:browser"));
                foreach (BrowserProfile p in ps) { MapNode pn = bn.Add(new MapNode(p.Label, Theme.Violet, p.Family)); try { List<VisitRow> h = Browser.History(p, 400); pn.Detail = h.Count + " history record(s)"; Dictionary<string, int> dom = new Dictionary<string, int>(); foreach (VisitRow v in h) if (v.Domain.Length > 0) { int c; dom.TryGetValue(v.Domain, out c); dom[v.Domain] = c + 1; } List<KeyValuePair<string, int>> top = new List<KeyValuePair<string, int>>(dom); top.Sort(delegate (KeyValuePair<string, int> x, KeyValuePair<string, int> y) { return y.Value - x.Value; }); for (int i = 0; i < top.Count && i < 8; i++) pn.Add(new MapNode(top[i].Key, Theme.Violet, top[i].Value + " visits")); } catch { } }
                step("Browsers", "done", ps.Count + " profile(s)");
            }
            catch (Exception ex) { root.Add(new MapNode("Browsers", Theme.Faint, ex.Message)); step("Browsers", "failed", null); }

            if (deep)
            {
                step("Checklist", "running", null); say("security checklist…");
                try
                {
                    ChecklistScan cs = new ChecklistScan(); cs.Run();
                    MapNode sec = root.Add(new MapNode("Security checklist", Theme.Amber, "score " + cs.Report.Score + "/100").Ico("map:checklist"));
                    MapNode fails = sec.Add(new MapNode("Failed", Theme.Rose, "").Ico("map:fail")); MapNode rev = sec.Add(new MapNode("To review", Theme.Amber, "").Ico("map:warn")); MapNode ok = sec.Add(new MapNode("Passed", Theme.Green, "").Ico("map:check"));
                    foreach (CheckItem i in cs.Report.Items) { if (i.Status == "fail") fails.Add(new MapNode(i.Name, Theme.Rose, i.Detail)); else if (i.Status == "warn") rev.Add(new MapNode(i.Name, Theme.Amber, i.Detail)); else if (i.Status == "pass") ok.Add(new MapNode(i.Name, Theme.Green, i.Detail)); }
                    fails.Detail = fails.Count + " fail"; rev.Detail = rev.Count + " to review"; ok.Detail = ok.Count + " pass";
                    sec.Fill = cs.Report.Fail > 0 ? Theme.Rose : cs.Report.Warn > 0 ? Theme.Amber : Theme.Green;
                    step("Checklist", "done", cs.Report.Fail + " fail · " + cs.Report.Warn + " review");
                }
                catch (Exception ex) { root.Add(new MapNode("Security checklist", Theme.Faint, ex.Message)); step("Checklist", "failed", null); }

                step("Events", "running", null); say("recent security events…");
                try
                {
                    List<EventRow> ev = EventHunt.Collect(EventHunt.Specs, DateTime.Now.AddHours(-24), 40, null, null, null);
                    int hi = 0; foreach (EventRow e in ev) if (e.Risk == "high") hi++;
                    MapNode en = root.Add(new MapNode("Recent events", hi > 0 ? Theme.Rose : Theme.Blue, ev.Count + " in 24h" + (hi > 0 ? " · " + hi + " high-risk" : "")).Ico("map:events"));
                    Dictionary<string, MapNode> byCat = new Dictionary<string, MapNode>();
                    foreach (EventRow e in ev) { MapNode cn; if (!byCat.TryGetValue(e.Category, out cn)) { cn = en.Add(new MapNode(e.Category, e.Risk == "high" ? Theme.Rose : e.Risk == "medium" ? Theme.Amber : Theme.Blue, "")); byCat[e.Category] = cn; } if (cn.Count < 20) cn.Add(new MapNode(e.When.Substring(5), cn.Fill, e.Detail)); }
                    foreach (KeyValuePair<string, MapNode> kv in byCat) kv.Value.Detail = kv.Value.Count + " event(s)";
                    step("Events", "done", ev.Count + " · " + hi + " high");
                }
                catch (Exception ex) { root.Add(new MapNode("Recent events", Theme.Faint, ex.Message)); step("Events", "failed", null); }
            }

            step("Vulnerabilities", "running", null); say("vulnerabilities…");
            try
            {
                VulnPanel vp = Host != null ? Host.Panel<VulnPanel>() : null; List<Finding> open = vp != null ? vp.OpenFindings() : new List<Finding>();
                MapNode vuln = root.Add(new MapNode("Vulnerabilities", open.Count > 0 ? Theme.Rose : Theme.Faint, "").Ico("map:vuln"));
                if (open.Count == 0) vuln.Add(new MapNode("not scanned this session", Theme.Faint, "run Vulnerability Management to populate this"));
                else { int shownV = 0; foreach (Finding f in open) { if (shownV++ >= 60) break; Color col = f.SeverityNorm == "Critical" ? Theme.Rose : f.SeverityNorm == "High" ? Theme.Amber : Theme.Blue; vuln.Add(new MapNode(f.Cve + "  " + f.SeverityNorm, col, f.Product + " · " + f.Fix).Ico("map:cve")); } vuln.Detail = open.Count + " open finding(s)"; }
            }
            catch (Exception ex) { root.Add(new MapNode("Vulnerabilities", Theme.Faint, ex.Message)); }
            step("Vulnerabilities", "done", null);
            return root;
        }
        static HashSet<string> Admins()
        {
            HashSet<string> a = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try { string host = Environment.MachineName.Replace("'", "''"); using (ManagementObjectSearcher q = new ManagementObjectSearcher(new ManagementScope(@"\\.\root\cimv2"), new ObjectQuery("ASSOCIATORS OF {Win32_Group.Domain='" + host + "',Name='Administrators'} WHERE ResultClass=Win32_Account"))) foreach (ManagementObject o in q.Get()) a.Add(Convert.ToString(o["Name"])); } catch { }
            return a;
        }
        static bool ToBool(object o) { try { return o != null && Convert.ToBoolean(o); } catch { return false; } }

        public override void SelfTest(System.Text.StringBuilder r)
        {
            if (r == null) { graph.SetRoot(Demo()); return; }
            MapNode root = Collect(false, delegate (string a, string b, string c) { }, delegate (string m) { });
            int branches = root.Children == null ? 0 : root.Children.Count; int total = 0; Count(root, ref total);
            r.AppendLine((branches >= 6 && total > 20 ? "PASS" : "FAIL") + " map: built endpoint “" + root.Label + "” with " + branches + " branches, " + total + " nodes");
            List<string> names = new List<string>(); if (root.Children != null) foreach (MapNode c in root.Children) names.Add(c.Label);
            bool core = names.Contains("Users") && names.Contains("Network") && names.Contains("Software") && names.Contains("Autoruns") && names.Contains("Firewall") && names.Contains("Wi-Fi") && names.Contains("Browsers");
            r.AppendLine((core ? "PASS" : "FAIL") + " map: branches present — " + string.Join(", ", names.ToArray()));
            graph.SetRoot(root);
        }
        static void Count(MapNode n, ref int c) { c++; if (n.Children != null) foreach (MapNode k in n.Children) Count(k, ref c); }
        MapNode Demo()
        {
            MapNode root = new MapNode("WORKSTATION-01", Theme.Teal, "Windows 11 Home · build 10.0.26200.6584 · x64"); root.Expanded = true; root.Icon = "map:host";
            MapNode users = root.Add(new MapNode("Users", Theme.Violet, "3 local accounts").Ico("map:users")); users.Add(new MapNode("alice  (admin)", Theme.Amber, "enabled · password required")); users.Add(new MapNode("Administrator", Theme.Faint, "disabled")); users.Add(new MapNode("kiosk", Theme.Rose, "enabled · password not required"));
            MapNode net = root.Add(new MapNode("Network", Theme.Blue, "").Ico("map:network")); MapNode ips = net.Add(new MapNode("Addresses", Theme.Blue, "2 IPv4")); ips.Add(new MapNode("192.168.1.42", Theme.Blue, "Ethernet")); ips.Add(new MapNode("100.104.12.7", Theme.Blue, "Tailscale")); MapNode lp = net.Add(new MapNode("Listening ports", Theme.Blue, "3")); lp.Add(new MapNode("TCP 445", Theme.Blue, "System")); lp.Add(new MapNode("TCP 3389", Theme.Amber, "svchost"));
            MapNode sw = root.Add(new MapNode("Software", Theme.Blue, "50 programs, 12 mapped").Ico("map:software")); sw.Add(new MapNode("Google Chrome  140.0", Theme.Teal, "Google LLC")); sw.Add(new MapNode("7-Zip  24.08", Theme.Teal, "Igor Pavlov")); sw.Add(new MapNode("NordVPN", Theme.Blue, "Nord"));
            MapNode ar = root.Add(new MapNode("Autoruns", Theme.Amber, "8 entries · 2 risky").Ico("map:autoruns")); MapNode rk = ar.Add(new MapNode("Run key", Theme.Blue, "4 entries")); rk.Add(new MapNode("OneDrive", Theme.Blue, "Microsoft")); rk.Add(new MapNode("backup-helper.exe", Theme.Amber, "Temp folder")); ar.Add(new MapNode("Scheduled task", Theme.Blue, "3 entries"));
            MapNode fw = root.Add(new MapNode("Firewall", Theme.Rose, "1 profile off · 636 rules").Ico("map:firewall")); fw.Add(new MapNode("Public: off", Theme.Rose, "default inbound block")); fw.Add(new MapNode("3 risky rule(s)", Theme.Amber, ""));
            MapNode wf = root.Add(new MapNode("Wi-Fi", Theme.Amber, "5 saved networks").Ico("map:wifi")); wf.Add(new MapNode("HomeNet-5G", Theme.Teal, "WPA2")); wf.Add(new MapNode("CoffeeShop_Free", Theme.Rose, "open")); wf.Add(new MapNode("OldRouter", Theme.Rose, "WEP"));
            MapNode br = root.Add(new MapNode("Browsers", Theme.Violet, "2 profiles").Ico("map:browser")); MapNode ch = br.Add(new MapNode("Chrome", Theme.Violet, "176 history")); ch.Add(new MapNode("google.com", Theme.Violet, "28 visits")); ch.Add(new MapNode("github.com", Theme.Violet, "19 visits"));
            MapNode sec = root.Add(new MapNode("Security checklist", Theme.Rose, "score 73/100").Ico("map:checklist")); MapNode fa = sec.Add(new MapNode("Failed", Theme.Rose, "1 fail").Ico("map:fail")); fa.Add(new MapNode("Windows Firewall", Theme.Rose, "3 profiles off")); sec.Add(new MapNode("To review", Theme.Amber, "5").Ico("map:warn")); sec.Add(new MapNode("Passed", Theme.Green, "7 pass").Ico("map:check"));
            MapNode vuln = root.Add(new MapNode("Vulnerabilities", Theme.Rose, "3 open").Ico("map:vuln")); vuln.Add(new MapNode("CVE-2026-31234  Critical", Theme.Rose, "Windows · KB5066000")); vuln.Add(new MapNode("CVE-2026-27101  High", Theme.Amber, "Chrome · upgrade"));
            foreach (MapNode c in root.Children) c.Expanded = c.Label == "Security checklist" || c.Label == "Firewall" || c.Label == "Wi-Fi" || c.Label == "Autoruns";
            return root;
        }
    }
}

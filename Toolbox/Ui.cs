// The UI kit: theme, buttons, the DataView (grid / details / tree with multi-select, sorting, search,
// CSV export), the selection bar, the app shell with the sidebar and elevation. No tool logic here.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace PSTools
{
    // ───────────────────────────── theme ─────────────────────────────
    public static class Theme
    {
        // ── palette: mutable so the theme can change at run time; every colour in the app comes from here ──
        public static Color Bg, Side, Panel, Panel2, Panel3, Line, Ink, Dim, Faint, Teal, TealSoft, TealDark, Amber, Rose, Violet, Green, Blue;
        public static Color OnAccent, AccentHover, DangerBorder, AltRow, SelBar, SelRow, Tip, Halo, Disc, Badge, NeutralRing, MapBg, MapBg2, MapGrat, MapLand, MapCoast, MapBorder, MapLit, MapText;
        public static readonly string[] Names = { "Dark teal", "Hacker green", "Red", "Windows" };
        public static string Current = "Dark teal";
        public static bool IsLight { get { return Bg.GetBrightness() > 0.5f; } }
        static Theme() { Apply("Dark teal"); }
        static Color C(int r, int g, int b) { return Color.FromArgb(r, g, b); }
        static Color[] Snapshot() { return new Color[] { Bg, Side, Panel, Panel2, Panel3, Line, Ink, Dim, Faint, Teal, TealSoft, TealDark, Amber, Rose, Violet, Green, Blue, OnAccent, AccentHover, DangerBorder, AltRow, SelBar, SelRow, Tip, Halo, Disc, Badge, NeutralRing, MapBg, MapBg2, MapGrat, MapLand, MapCoast, MapBorder, MapLit, MapText }; }
        /// <summary>Switch palette. Returns old colour -> new colour so controls built under the previous theme can be re-tinted in place.</summary>
        public static Dictionary<int, Color> Apply(string name)
        {
            Color[] before = Snapshot();
            switch ((name ?? "").Trim().ToLowerInvariant())
            {
                case "hacker green": HackerGreen(); Current = "Hacker green"; break;
                case "red": RedTheme(); Current = "Red"; break;
                case "windows": WindowsTheme(); Current = "Windows"; break;
                default: DarkTeal(); Current = "Dark teal"; break;
            }
            Color[] after = Snapshot(); Dictionary<int, Color> map = new Dictionary<int, Color>();
            for (int i = 0; i < before.Length; i++) { int k = before[i].ToArgb(); if (!map.ContainsKey(k)) map[k] = after[i]; }
            return map;
        }
        static void DarkTeal()
        {
            Bg = C(13, 22, 28); Side = C(17, 29, 36); Panel = C(21, 35, 43); Panel2 = C(27, 45, 55); Panel3 = C(34, 56, 68); Line = C(40, 63, 74);
            Ink = C(218, 234, 240); Dim = C(128, 156, 170); Faint = C(76, 100, 114);
            Teal = C(47, 217, 197); TealSoft = C(38, 168, 154); TealDark = C(18, 92, 86); Amber = C(240, 165, 60); Rose = C(255, 107, 94); Violet = C(170, 140, 255); Green = C(110, 214, 130); Blue = C(110, 170, 255);
            OnAccent = C(8, 28, 30); AccentHover = C(96, 236, 220); DangerBorder = C(120, 60, 56); AltRow = C(24, 39, 48); SelBar = C(19, 52, 54); SelRow = C(28, 60, 66);
            Tip = C(12, 20, 26); Halo = C(8, 13, 18); Disc = C(12, 19, 26); Badge = C(18, 27, 34); NeutralRing = C(70, 120, 130);
            MapBg = C(8, 14, 20); MapBg2 = C(4, 8, 12); MapGrat = C(58, 120, 130); MapLand = C(40, 96, 100); MapCoast = C(58, 130, 132); MapBorder = C(96, 150, 150); MapLit = C(200, 255, 245); MapText = C(220, 255, 248);
        }
        static void HackerGreen()
        {
            Bg = C(0, 0, 0); Side = C(4, 10, 4); Panel = C(7, 15, 7); Panel2 = C(11, 24, 11); Panel3 = C(18, 38, 18); Line = C(22, 64, 22);
            Ink = C(150, 255, 150); Dim = C(70, 190, 70); Faint = C(35, 120, 35);
            Teal = C(0, 255, 65); TealSoft = C(0, 205, 55); TealDark = C(0, 110, 30); Amber = C(255, 204, 0); Rose = C(255, 64, 64); Violet = C(110, 240, 180); Green = C(60, 255, 120); Blue = C(70, 210, 160);
            OnAccent = C(0, 20, 0); AccentHover = C(120, 255, 150); DangerBorder = C(120, 40, 30); AltRow = C(0, 10, 0); SelBar = C(0, 28, 8); SelRow = C(0, 48, 16);
            Tip = C(4, 14, 6); Halo = C(0, 8, 0); Disc = C(2, 12, 4); Badge = C(6, 20, 8); NeutralRing = C(40, 130, 60);
            MapBg = C(0, 4, 0); MapBg2 = C(0, 1, 0); MapGrat = C(0, 120, 40); MapLand = C(0, 110, 35); MapCoast = C(0, 160, 50); MapBorder = C(60, 210, 90); MapLit = C(200, 255, 200); MapText = C(220, 255, 220);
        }
        // blood red on black and grey: neutral dark surfaces, light grey text, a deep red accent
        static void RedTheme()
        {
            Bg = C(9, 9, 9); Side = C(15, 15, 15); Panel = C(21, 21, 21); Panel2 = C(31, 31, 31); Panel3 = C(46, 46, 46); Line = C(60, 60, 60);
            Ink = C(224, 224, 224); Dim = C(148, 148, 148); Faint = C(98, 98, 98);
            Teal = C(196, 18, 18); TealSoft = C(150, 12, 12); TealDark = C(96, 6, 6); Amber = C(228, 150, 40); Rose = C(255, 76, 48); Violet = C(190, 118, 118); Green = C(120, 200, 120); Blue = C(160, 160, 190);
            OnAccent = C(255, 238, 238); AccentHover = C(228, 36, 36); DangerBorder = C(140, 40, 30); AltRow = C(17, 17, 17); SelBar = C(38, 14, 14); SelRow = C(62, 20, 20);
            Tip = C(24, 24, 24); Halo = C(10, 10, 10); Disc = C(19, 19, 19); Badge = C(29, 29, 29); NeutralRing = C(110, 110, 110);
            MapBg = C(12, 12, 12); MapBg2 = C(4, 4, 4); MapGrat = C(88, 88, 88); MapLand = C(96, 40, 40); MapCoast = C(140, 50, 50); MapBorder = C(190, 70, 70); MapLit = C(255, 210, 210); MapText = C(255, 226, 226);
        }
        // light, in the spirit of Windows settings / Sysinternals: mica grey, white cards, Windows blue accent
        static void WindowsTheme()
        {
            Bg = C(243, 243, 243); Side = C(236, 236, 236); Panel = C(250, 250, 250); Panel2 = C(255, 255, 255); Panel3 = C(229, 238, 248); Line = C(218, 218, 218);
            Ink = C(27, 27, 27); Dim = C(96, 96, 96); Faint = C(150, 150, 150);
            Teal = C(0, 120, 212); TealSoft = C(0, 95, 184); TealDark = C(0, 66, 140); Amber = C(176, 105, 0); Rose = C(196, 43, 28); Violet = C(98, 58, 178); Green = C(16, 124, 16); Blue = C(0, 90, 158);
            OnAccent = C(255, 255, 255); AccentHover = C(25, 140, 225); DangerBorder = C(196, 44, 28); AltRow = C(247, 247, 247); SelBar = C(232, 240, 250); SelRow = C(204, 228, 247);
            Tip = C(254, 254, 254); Halo = C(253, 253, 253); Disc = C(252, 252, 252); Badge = C(240, 244, 250); NeutralRing = C(150, 170, 190);
            MapBg = C(250, 250, 252); MapBg2 = C(240, 242, 246); MapGrat = C(160, 180, 200); MapLand = C(150, 170, 190); MapCoast = C(110, 135, 160); MapBorder = C(70, 100, 130); MapLit = C(0, 90, 170); MapText = C(20, 40, 70);
        }
        public static Font UI = new Font("Segoe UI", 9.75f), UISmall = new Font("Segoe UI", 8.5f), UIBold = new Font("Segoe UI Semibold", 9.75f), Title = new Font("Segoe UI Semibold", 15f), Big = new Font("Segoe UI Semibold", 12f), Mono = MonoFont(9.5f);
        public static float Dpi = 1f; public static int S(int px) { return (int)Math.Round(px * Dpi); }
        static Font MonoFont(float size) { foreach (string n in new string[] { "Cascadia Mono", "Consolas" }) { Font f = new Font(n, size); if (f.Name == n) return f; } return new Font(FontFamily.GenericMonospace, size); }

        public static Button Btn(string text, bool primary)
        {
            Button b = new Button(); b.Text = text; b.FlatStyle = FlatStyle.Flat; b.Font = primary ? UIBold : UI; b.Cursor = Cursors.Hand; b.UseVisualStyleBackColor = false;
            b.BackColor = primary ? Teal : Panel2; b.ForeColor = primary ? OnAccent : Ink; b.FlatAppearance.BorderColor = primary ? Teal : Line; b.FlatAppearance.BorderSize = 1;
            b.FlatAppearance.MouseOverBackColor = primary ? AccentHover : Panel3; b.FlatAppearance.MouseDownBackColor = primary ? TealDark : Line;
            b.AutoSize = true; b.AutoSizeMode = AutoSizeMode.GrowAndShrink; b.Padding = new Padding(S(10), S(4), S(10), S(4)); b.MinimumSize = new Size(0, S(30)); b.Margin = new Padding(0, 0, S(6), S(6));
            return b;
        }
        /// <summary>A button for something destructive or irreversible: delete, wipe, kill. Rose. Sits last in its bar.</summary>
        public static Button Danger(string text) { Button b = Btn(text, false); b.ForeColor = Rose; b.FlatAppearance.BorderColor = DangerBorder; b.Tag = "danger"; return b; }
        /// <summary>A button for something that changes the machine but can be undone, or shows a secret: block, disable, recycle, encrypt, reveal. Amber, so it reads as "careful", never as the default.</summary>
        public static Button Caution(string text) { Button b = Btn(text, false); b.ForeColor = Amber; b.FlatAppearance.BorderColor = Amber; b.Tag = "caution"; return b; }
        /// <summary>A button that drops a small menu under itself: one "Save report" instead of three Save buttons.</summary>
        public static Button MenuBtn(string text, string[] items, Action<int> pick)
        {
            Button b = Btn(text + "  \u25be", false); ContextMenuStrip m = new ContextMenuStrip(); m.Renderer = new ToolStripProfessionalRenderer(new DarkMenuColors()); m.BackColor = Panel2; m.ForeColor = Ink; m.Font = UI; m.ShowImageMargin = false;
            for (int i = 0; i < items.Length; i++) { int k = i; ToolStripMenuItem it = new ToolStripMenuItem(items[i]); it.ForeColor = Ink; it.Click += delegate { pick(k); }; m.Items.Add(it); }
            b.Click += delegate { m.Show(b, new Point(0, b.Height)); }; return b;
        }
        /// <summary>Styles a button as a mode tab (Findings / Missing updates / …): lit when it is the current mode.</summary>
        public static void SetTab(Button b, bool on) { b.BackColor = on ? Panel3 : Panel2; b.ForeColor = on ? Teal : Ink; b.FlatAppearance.BorderColor = on ? Teal : Line; }
        public static CheckBox Toggle(string text, bool on) { CheckBox c = new CheckBox(); c.Text = text; c.Checked = on; c.ForeColor = Ink; c.Font = UI; c.AutoSize = true; c.Cursor = Cursors.Hand; c.Margin = new Padding(0, S(6), S(12), 0); return c; }
        public static TextBox Text(string value, int width) { TextBox t = new TextBox(); t.Text = value; t.BackColor = Panel2; t.ForeColor = Ink; t.BorderStyle = BorderStyle.FixedSingle; t.Font = UI; t.Width = S(width); t.Margin = new Padding(0, S(3), S(8), 0); return t; }
        public static ComboBox Combo(int width, params string[] items) { ComboBox c = new ComboBox(); c.DropDownStyle = ComboBoxStyle.DropDownList; c.Items.AddRange(items); if (items.Length > 0) c.SelectedIndex = 0; c.BackColor = Panel2; c.ForeColor = Ink; c.FlatStyle = FlatStyle.Flat; c.Font = UI; c.Width = S(width); c.Margin = new Padding(0, S(3), S(8), 0); return c; }
        public static NumericUpDown Num(decimal value, decimal min, decimal max, int width) { NumericUpDown n = new NumericUpDown(); n.Minimum = min; n.Maximum = max; n.Value = value; n.BackColor = Panel2; n.ForeColor = Ink; n.BorderStyle = BorderStyle.FixedSingle; n.Font = UI; n.Width = S(width); n.Margin = new Padding(0, S(3), S(8), 0); return n; }
        public static Label Lbl(string text, Color color, Font font) { Label l = new Label(); l.Text = text; l.ForeColor = color; l.Font = font; l.AutoSize = true; l.BackColor = Color.Transparent; l.UseMnemonic = false; l.Margin = new Padding(0, S(7), S(6), 0); return l; }
        public static Label Cap(string text) { Label l = Lbl(text.ToUpperInvariant(), Faint, UISmall); l.Margin = new Padding(S(6), S(9), S(4), 0); return l; }
        public static Panel Rule() { Panel p = new Panel(); p.Height = 1; p.Dock = DockStyle.Top; p.BackColor = Line; return p; }
        /// <summary>A top action bar. Wraps onto a second row when the window is narrow instead of clipping.</summary>
        public static FlowLayoutPanel Bar(int height) { FlowLayoutPanel f = new FlowLayoutPanel(); f.Dock = DockStyle.Top; f.AutoSize = true; f.AutoSizeMode = AutoSizeMode.GrowAndShrink; f.MinimumSize = new Size(0, S(height)); f.Padding = new Padding(S(10), S(6), S(10), S(4)); f.BackColor = Panel; f.WrapContents = true; return f; }
        public static Color SeverityColor(string s)
        {
            string t = (s ?? "").ToLowerInvariant();
            if (t == "critical") return Rose; if (t == "high" || t == "important") return Amber; if (t == "medium" || t == "moderate") return Blue; if (t == "low") return Dim; return Faint;
        }
        /// <summary>The theme colour for a semantic tone (the shared column definitions speak in tones).</summary>
        public static Color Of(Tone t)
        {
            switch (t) { case Tone.Dim: return Dim; case Tone.Faint: return Faint; case Tone.Accent: return Teal; case Tone.Good: return Green; case Tone.Warn: return Amber; case Tone.Bad: return Rose; case Tone.Info: return Blue; default: return Ink; }
        }
        public static void DoubleBuffer(Control c) { try { typeof(Control).GetProperty("DoubleBuffered", BindingFlags.Instance | BindingFlags.NonPublic).SetValue(c, true, null); } catch { } }
        public static Color StatusColor(string s)
        {
            string t = (s ?? "").ToLowerInvariant();
            if (t.StartsWith("reachable") || t == "blocked" || t.StartsWith("intact") || t == "recoverable" || t == "ok" || t == "established" || t == "patched" || t == "installed") return Green;
            if (t.StartsWith("unreach") || t == "invalid" || t == "no dns" || t == "overwritten" || t == "chain lost" || t == "error" || t.StartsWith("not a valid") || t == "vulnerable" || t.StartsWith("failed")) return Rose;
            if (t.StartsWith("partly") || t == "ping only" || t == "resolves" || t == "pending" || t.StartsWith("checking") || t == "listening" || t == "update available" || t == "reboot pending" || t.StartsWith("scanning")) return Amber;
            return Dim;
        }
    }

    /// <summary>Dark colours for context menus.</summary>
    class DarkMenuColors : ProfessionalColorTable
    {
        public override Color MenuItemSelected { get { return Theme.Panel3; } }
        public override Color MenuItemSelectedGradientBegin { get { return Theme.Panel3; } }
        public override Color MenuItemSelectedGradientEnd { get { return Theme.Panel3; } }
        public override Color MenuItemBorder { get { return Theme.Teal; } }
        public override Color MenuBorder { get { return Theme.Line; } }
        public override Color ToolStripDropDownBackground { get { return Theme.Panel2; } }
        public override Color ImageMarginGradientBegin { get { return Theme.Panel2; } }
        public override Color ImageMarginGradientMiddle { get { return Theme.Panel2; } }
        public override Color ImageMarginGradientEnd { get { return Theme.Panel2; } }
        public override Color SeparatorDark { get { return Theme.Line; } }
        public override Color SeparatorLight { get { return Theme.Line; } }
    }

    /// <summary>A quick-filter chip for the filter bar (shared GUI kit). Two kinds: a toggle (on/off) and a dropdown
    /// (a labelled value chosen from a small menu). Owner-drawn from Theme.* so it re-tints with the theme; active
    /// (toggle on, or dropdown value past the first/default) shows the selection fill + accent border + a marker, so
    /// a live filter is visible at a glance and never conveyed by colour alone. Keyboard: Space/Enter toggles or
    /// opens the menu; the dropdown also opens on Down. Changed fires when the value changes.</summary>
    public class FilterChip : Control
    {
        public readonly bool IsToggle; readonly string[] opts; int index; bool on, hover; public event Action Changed;
        public FilterChip(string label, string[] options) { IsToggle = false; opts = options; Init(label); }   // dropdown
        public FilterChip(string label) { IsToggle = true; opts = null; Init(label); }                          // toggle
        void Init(string label)
        {
            Text = label; SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint | ControlStyles.ResizeRedraw | ControlStyles.Selectable, true);
            TabStop = true; Cursor = Cursors.Hand; Height = Theme.S(26); Margin = new Padding(0, Theme.S(3), Theme.S(6), Theme.S(3)); BackColor = Theme.Side; AccessibleName = label; AccessibleRole = AccessibleRole.CheckButton;
            Click += delegate { Activate(); }; GotFocus += delegate { Invalidate(); }; LostFocus += delegate { Invalidate(); };
            MouseEnter += delegate { hover = true; Invalidate(); }; MouseLeave += delegate { hover = false; Invalidate(); };
            KeyDown += delegate (object s, KeyEventArgs e) { if (e.KeyCode == Keys.Space || e.KeyCode == Keys.Enter || (!IsToggle && e.KeyCode == Keys.Down)) { e.Handled = true; Activate(); } };
            Measure();
        }
        public int Index { get { return index; } set { index = value; Measure(); Invalidate(); } }
        public bool On { get { return on; } set { on = value; Measure(); Invalidate(); } }
        public string Value { get { return opts != null ? opts[index] : (on ? "on" : "off"); } }
        public bool Active { get { return IsToggle ? on : index > 0; } }
        public void Reset() { index = 0; on = false; Measure(); Invalidate(); }
        void Activate() { if (IsToggle) { on = !on; Measure(); Invalidate(); Fire(); } else ShowMenu(); }
        void Fire() { if (Changed != null) Changed(); }
        string Caption() { return IsToggle || index == 0 ? Text : Text + ": " + opts[index]; }
        void Measure() { using (Graphics g = CreateGraphics()) { int w = TextRenderer.MeasureText(g, Caption(), Theme.UIBold).Width; Width = w + Theme.S(IsToggle ? 22 : 30); } }
        void ShowMenu()
        {
            ContextMenuStrip m = new ContextMenuStrip(); m.Renderer = new ToolStripProfessionalRenderer(new DarkMenuColors()); m.BackColor = Theme.Panel2; m.ForeColor = Theme.Ink; m.Font = Theme.UI; m.ShowImageMargin = false;
            for (int i = 0; i < opts.Length; i++) { int k = i; ToolStripMenuItem it = new ToolStripMenuItem(opts[i]); it.ForeColor = Theme.Ink; it.Checked = i == index; it.Click += delegate { if (index != k) { index = k; Measure(); Invalidate(); Fire(); } }; m.Items.Add(it); }
            m.Show(this, new Point(0, Height));
        }
        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics; g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            bool act = Active; Color border = act ? Theme.Teal : (hover ? Theme.Line : Theme.Line), fill = act ? Theme.SelBar : (hover ? Theme.Panel2 : Theme.Panel2), ink = act ? Theme.Teal : Theme.Dim;
            Rectangle r = new Rectangle(0, 1, Width - 1, Height - 3); int rad = Theme.S(13);
            using (System.Drawing.Drawing2D.GraphicsPath p = Round(r, rad)) { using (Brush b = new SolidBrush(fill)) g.FillPath(b, p); using (Pen pen = new Pen(border)) g.DrawPath(pen, p); }
            if (Focused) using (Pen fp = new Pen(Theme.Teal) { DashStyle = System.Drawing.Drawing2D.DashStyle.Dot }) g.DrawPath(fp, Round(new Rectangle(2, 3, Width - 5, Height - 7), rad - 2));
            Rectangle tr = new Rectangle(Theme.S(10), 0, Width - Theme.S(IsToggle ? 14 : 24), Height);
            TextRenderer.DrawText(g, Caption(), act ? Theme.UIBold : Theme.UI, tr, ink, TextFormatFlags.VerticalCenter | TextFormatFlags.Left | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);
            string mark = IsToggle ? (on ? "✕" : "") : "▾";
            if (mark.Length > 0) TextRenderer.DrawText(g, mark, Theme.UISmall, new Rectangle(Width - Theme.S(16), 0, Theme.S(14), Height), ink, TextFormatFlags.VerticalCenter | TextFormatFlags.HorizontalCenter | TextFormatFlags.NoPrefix);
        }
        static System.Drawing.Drawing2D.GraphicsPath Round(Rectangle r, int rad)
        {
            int d = rad * 2; System.Drawing.Drawing2D.GraphicsPath p = new System.Drawing.Drawing2D.GraphicsPath();
            if (d > r.Height) d = r.Height; if (d > r.Width) d = r.Width;
            p.AddArc(r.X, r.Y, d, d, 180, 90); p.AddArc(r.Right - d, r.Y, d, d, 270, 90); p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90); p.AddArc(r.X, r.Bottom - d, d, d, 90, 90); p.CloseFigure(); return p;
        }
    }

    /// <summary>A grid, a details layout, or a tree over the same rows, with checkbox multi-select, sort, search, per-column filter rules, export.</summary>
    public class DataView : UserControl
    {
        public List<Col> Cols = new List<Col>(); public Func<object, string[]> TreePath; public Func<string, List<object>, string> TreeNodeText; public Func<object, bool> Filter; public Func<object, Tone> RowTone; public Func<object, bool> Dimmed;
        public event Action SelectionChanged; public event Action<object> Activated; public event Action ViewChanged;
        readonly List<object> all = new List<object>(); List<object> rows = new List<object>(); readonly HashSet<object> selected = new HashSet<object>();
        readonly DataGridView grid = new DataGridView(); readonly TreeView tree = new TreeView(); readonly Panel detail = new Panel(); readonly DataGridView props = new DataGridView(); readonly SplitContainer detailSplit = new SplitContainer();
        readonly Panel top = new Panel(); readonly TextBox search = Theme.Text("", 200); readonly Label count = Theme.Lbl("", Theme.Dim, Theme.UISmall); readonly Button bGrid = Theme.Btn("Grid", false), bDetails = Theme.Btn("Details", false), bTree = Theme.Btn("Tree", false), bAll = Theme.Btn("Select all", false), bNone = Theme.Btn("None", false), bInvert = Theme.Btn("Invert", false), bExport = Theme.Btn("Export CSV…", false), bFilter = Theme.Btn("Filter", false);
        public readonly FlowLayoutPanel Extra = new FlowLayoutPanel();
        // filter bar
        readonly FlowLayoutPanel fbar = new FlowLayoutPanel(), chips = new FlowLayoutPanel(); readonly ComboBox fCol = Theme.Combo(180), fOp = Theme.Combo(150, FilterRule.Ops); readonly TextBox fVal = Theme.Text("", 190); readonly CheckBox fCase = Theme.Toggle("match case", false); readonly Button bAddRule = Theme.Btn("Add rule", true), bClearRules = Theme.Btn("Clear all", false); readonly List<FilterRule> rules = new List<FilterRule>(); bool filterOpen;
        readonly ContextMenuStrip menu = new ContextMenuStrip(); int menuRow = -1, menuCol = -1;
        public string View = "grid"; string sortKey; bool sortAsc = true; int lastClick = -1; public string ExportName = "export"; bool treeDirty = true; readonly Dictionary<TreeNode, List<object>> nodeItems = new Dictionary<TreeNode, List<object>>(); bool building;

        public DataView()
        {
            BackColor = Theme.Panel; Dock = DockStyle.Fill;
            // top bar: view switch · search · select · export · filter · extras
            top.Dock = DockStyle.Top; top.AutoSize = true; top.AutoSizeMode = AutoSizeMode.GrowAndShrink; top.MinimumSize = new Size(0, Theme.S(44)); top.BackColor = Theme.Panel; top.Padding = new Padding(Theme.S(10), Theme.S(6), Theme.S(10), 0);
            FlowLayoutPanel f = new FlowLayoutPanel(); f.Dock = DockStyle.Top; f.AutoSize = true; f.AutoSizeMode = AutoSizeMode.GrowAndShrink; f.WrapContents = true; f.BackColor = Theme.Panel;
            foreach (Button b in new Button[] { bGrid, bDetails, bTree }) { b.Margin = new Padding(0, 0, 0, Theme.S(6)); b.MinimumSize = new Size(Theme.S(66), Theme.S(28)); }
            bGrid.Click += delegate { SetView("grid"); }; bDetails.Click += delegate { SetView("details"); }; bTree.Click += delegate { SetView("tree"); };
            search.Margin = new Padding(Theme.S(14), Theme.S(1), Theme.S(6), 0); search.TextChanged += delegate { Apply(); }; SetPlaceholder(search, "search…");
            bAll.Click += delegate { foreach (object o in rows) selected.Add(o); Changed(); }; bNone.Click += delegate { selected.Clear(); Changed(); }; bInvert.Click += delegate { foreach (object o in rows) { if (!selected.Remove(o)) selected.Add(o); } Changed(); };
            bExport.Click += delegate { Export(); };
            bFilter.Click += delegate { filterOpen = !filterOpen; fbar.Visible = filterOpen || rules.Count > 0; if (fbar.Visible) fVal.Focus(); UpdateFilterButton(); };
            new ToolTip().SetToolTip(bFilter, "Filter rows by any column: contains, equals, starts with, regex, number comparisons… Rules combine with AND. Right-click a cell for quick filters.");
            Extra.AutoSize = true; Extra.WrapContents = false; Extra.BackColor = Theme.Panel; Extra.Margin = new Padding(Theme.S(10), 0, 0, 0);
            count.Margin = new Padding(Theme.S(10), Theme.S(9), 0, 0);
            f.Controls.Add(bGrid); f.Controls.Add(bDetails); f.Controls.Add(bTree); f.Controls.Add(search); f.Controls.Add(bAll); f.Controls.Add(bNone); f.Controls.Add(bInvert); f.Controls.Add(bExport); f.Controls.Add(bFilter); f.Controls.Add(Extra); f.Controls.Add(count);
            top.Controls.Add(f);
            // the filter bar: where [column] [operator] [value] [match case] [Add rule] [Clear all]  chips…
            fbar.Dock = DockStyle.Top; fbar.AutoSize = true; fbar.AutoSizeMode = AutoSizeMode.GrowAndShrink; fbar.WrapContents = true; fbar.BackColor = Theme.Side; fbar.Padding = new Padding(Theme.S(10), Theme.S(5), Theme.S(10), Theme.S(1)); fbar.Visible = false;
            Label fl = Theme.Lbl("where", Theme.Dim, Theme.UI); fOp.SelectedIndex = 0; fOp.SelectedIndexChanged += delegate { fVal.Enabled = FilterRule.NeedsValue((string)fOp.SelectedItem); };
            fVal.KeyDown += delegate (object s, KeyEventArgs e) { if (e.KeyCode == Keys.Enter) { AddRuleFromBar(); e.SuppressKeyPress = true; e.Handled = true; } };
            bAddRule.Click += delegate { AddRuleFromBar(); }; bClearRules.Click += delegate { ClearRules(); };
            chips.AutoSize = true; chips.AutoSizeMode = AutoSizeMode.GrowAndShrink; chips.WrapContents = true; chips.BackColor = Theme.Side; chips.Margin = new Padding(Theme.S(6), 0, 0, 0);
            foreach (Control c in new Control[] { fl, fCol, fOp, fVal, fCase, bAddRule, bClearRules, chips }) fbar.Controls.Add(c);
            // grid
            grid.Dock = DockStyle.Fill; grid.VirtualMode = true; grid.AllowUserToAddRows = false; grid.AllowUserToDeleteRows = false; grid.AllowUserToResizeRows = false; grid.RowHeadersVisible = false; grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect; grid.MultiSelect = true;
            grid.BackgroundColor = Theme.Bg; grid.BorderStyle = BorderStyle.None; grid.GridColor = Theme.Line; grid.EnableHeadersVisualStyles = false; grid.ColumnHeadersBorderStyle = DataGridViewHeaderBorderStyle.Single; grid.CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal;
            grid.ColumnHeadersDefaultCellStyle.BackColor = Theme.Side; grid.ColumnHeadersDefaultCellStyle.ForeColor = Theme.Dim; grid.ColumnHeadersDefaultCellStyle.Font = Theme.UISmall; grid.ColumnHeadersDefaultCellStyle.SelectionBackColor = Theme.Side; grid.ColumnHeadersHeight = Theme.S(30); grid.ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.DisableResizing;
            grid.DefaultCellStyle.BackColor = Theme.Panel; grid.DefaultCellStyle.ForeColor = Theme.Ink; grid.DefaultCellStyle.SelectionBackColor = Theme.Panel3; grid.DefaultCellStyle.SelectionForeColor = Theme.Ink; grid.DefaultCellStyle.Font = Theme.UI; grid.RowTemplate.Height = Theme.S(26); grid.AlternatingRowsDefaultCellStyle.BackColor = Theme.AltRow;
            grid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.None; grid.AutoSizeRowsMode = DataGridViewAutoSizeRowsMode.None; grid.EditMode = DataGridViewEditMode.EditOnKeystrokeOrF2; grid.StandardTab = true;
            Theme.DoubleBuffer(grid);
            grid.CellValueNeeded += GridValueNeeded; grid.CellValuePushed += GridValuePushed; grid.CellFormatting += GridFormatting; grid.CellClick += GridClick; grid.ColumnHeaderMouseClick += HeaderClick; grid.CellPainting += HeaderPaint; grid.CellDoubleClick += delegate (object s, DataGridViewCellEventArgs e) { if (e.RowIndex >= 0 && e.RowIndex < rows.Count && Activated != null) Activated(rows[e.RowIndex]); };
            grid.SelectionChanged += delegate { if (View == "details") ShowProps(Current); };
            grid.KeyDown += delegate (object s, KeyEventArgs e) { if (e.KeyCode == Keys.Space) { foreach (DataGridViewRow r in grid.SelectedRows) { object o = rows[r.Index]; if (!selected.Remove(o)) selected.Add(o); } Changed(); e.Handled = true; } if (e.Control && e.KeyCode == Keys.A) { foreach (object o in rows) selected.Add(o); Changed(); e.Handled = true; } if (e.Control && e.KeyCode == Keys.C) { CopyRows(); e.Handled = true; } };
            grid.CellMouseDown += delegate (object s, DataGridViewCellMouseEventArgs e) { if (e.Button == MouseButtons.Right && e.RowIndex >= 0 && e.RowIndex < rows.Count && e.ColumnIndex > 0) { menuRow = e.RowIndex; menuCol = e.ColumnIndex - 1; try { grid.CurrentCell = grid[e.ColumnIndex, e.RowIndex]; } catch { } BuildMenu(); menu.Show(Cursor.Position); } };
            menu.Renderer = new ToolStripProfessionalRenderer(new DarkMenuColors()); menu.BackColor = Theme.Panel2; menu.ForeColor = Theme.Ink; menu.Font = Theme.UI; menu.ShowImageMargin = false;
            // tree
            tree.Dock = DockStyle.Fill; tree.BackColor = Theme.Panel; tree.ForeColor = Theme.Ink; tree.BorderStyle = BorderStyle.None; tree.CheckBoxes = true; tree.Font = Theme.UI; tree.ShowLines = false; tree.FullRowSelect = true; tree.ItemHeight = Theme.S(24); tree.Visible = false; tree.HideSelection = false;
            tree.AfterCheck += delegate (object s, TreeViewEventArgs e) { if (building) return; building = true; try { CheckDown(e.Node, e.Node.Checked); } finally { building = false; } Changed(); };
            tree.NodeMouseDoubleClick += delegate (object s, TreeNodeMouseClickEventArgs e) { List<object> l; if (nodeItems.TryGetValue(e.Node, out l) && l.Count == 1 && Activated != null) Activated(l[0]); };
            // details: grid on the left, properties of the current row on the right
            detailSplit.Dock = DockStyle.Fill; detailSplit.Orientation = Orientation.Vertical; detailSplit.BackColor = Theme.Line; detailSplit.SplitterWidth = 4; detailSplit.Visible = false;
            props.Dock = DockStyle.Fill; props.AllowUserToAddRows = false; props.RowHeadersVisible = false; props.ColumnHeadersVisible = false; props.ReadOnly = true; props.BackgroundColor = Theme.Side; props.BorderStyle = BorderStyle.None; props.GridColor = Theme.Line; props.CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal; props.SelectionMode = DataGridViewSelectionMode.CellSelect; props.MultiSelect = false;
            props.DefaultCellStyle.BackColor = Theme.Side; props.DefaultCellStyle.ForeColor = Theme.Ink; props.DefaultCellStyle.SelectionBackColor = Theme.Panel3; props.DefaultCellStyle.SelectionForeColor = Theme.Ink; props.DefaultCellStyle.Font = Theme.UI; props.DefaultCellStyle.WrapMode = DataGridViewTriState.True; props.AutoSizeRowsMode = DataGridViewAutoSizeRowsMode.AllCells; props.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
            props.Columns.Add("k", "Field"); props.Columns.Add("v", "Value"); props.Columns[0].FillWeight = 32; props.Columns[0].DefaultCellStyle.ForeColor = Theme.Dim; props.Columns[1].FillWeight = 68;
            Label dt = Theme.Lbl("DETAILS OF THE HIGHLIGHTED ROW", Theme.Faint, Theme.UISmall); dt.Dock = DockStyle.Top; dt.Padding = new Padding(Theme.S(8), Theme.S(6), 0, 0); dt.AutoSize = false; dt.Height = Theme.S(28); dt.BackColor = Theme.Side;
            detail.Dock = DockStyle.Fill; detail.BackColor = Theme.Side; detail.Controls.Add(props); detail.Controls.Add(dt);
            Controls.Add(grid); Controls.Add(tree); Controls.Add(detailSplit); Controls.Add(fbar); Controls.Add(top);
            grid.BringToFront(); tree.BringToFront(); detailSplit.BringToFront();
            FillFilterColumns(); SetView("grid");
        }
        static void SetPlaceholder(TextBox t, string text)
        {
            t.ForeColor = Theme.Dim; t.Text = text;
            t.GotFocus += delegate { if (t.Text == text && t.ForeColor == Theme.Dim) { t.Text = ""; t.ForeColor = Theme.Ink; } };
            t.LostFocus += delegate { if (t.Text.Length == 0) { t.ForeColor = Theme.Dim; t.Text = text; } };
        }
        string SearchText { get { return search.ForeColor == Theme.Dim ? "" : search.Text.Trim(); } }

        // ---- public API ----
        /// <summary>Replaces the column set. Rows are dropped first so the grid never asks for a cell of a column that no longer exists, then re-applied.</summary>
        public void SetColumns(IEnumerable<Col> cols)
        {
            List<Col> next = new List<Col>(cols);
            grid.SuspendLayout();
            try
            {
                try { grid.EndEdit(); grid.CurrentCell = null; } catch { }
                grid.AllowUserToAddRows = false; try { grid.RowCount = 0; } catch { }
                Cols = next; grid.Columns.Clear();
                DataGridViewCheckBoxColumn cb = new DataGridViewCheckBoxColumn(); cb.HeaderText = ""; cb.Width = Theme.S(30); cb.Name = "__sel"; cb.Resizable = DataGridViewTriState.False; cb.SortMode = DataGridViewColumnSortMode.NotSortable; grid.Columns.Add(cb);
                foreach (Col c in Cols)
                {
                    DataGridViewTextBoxColumn tc = new DataGridViewTextBoxColumn(); tc.HeaderText = c.Title; tc.Name = c.Key; tc.Width = Theme.S(c.Width); tc.SortMode = DataGridViewColumnSortMode.Programmatic; tc.ReadOnly = !c.Editable; tc.Visible = !c.Hidden;
                    if (c.Right) { tc.DefaultCellStyle.Alignment = DataGridViewContentAlignment.MiddleRight; tc.HeaderCell.Style.Alignment = DataGridViewContentAlignment.MiddleRight; }
                    if (c.Editable) tc.DefaultCellStyle.ForeColor = Theme.Teal;
                    grid.Columns.Add(tc);
                }
                if (grid.Columns.Count > 1) grid.Columns[grid.Columns.Count - 1].AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;
                grid.ReadOnly = false;
            }
            finally { grid.ResumeLayout(); }
            sortKey = null; // a new column set is a new sort context: the old rows must never be sorted with the new accessors
            if (rules.RemoveAll(delegate (FilterRule r) { return r.Key != "*" && Cols.Find(delegate (Col x) { return x.Key == r.Key; }) == null; }) > 0) { RebuildChips(); UpdateFilterButton(); }
            FillFilterColumns(); treeDirty = true; Apply();
        }
        /// <summary>Takes a whole table definition - export name, tree grouping, row tone, dimming and columns - the one call a panel makes per mode. The same definition drives the command line.</summary>
        public void Apply(TableDef d) { ExportName = d.Export; TreePath = d.Tree; TreeNodeText = d.TreeText; RowTone = d.RowTone; Dimmed = d.Dimmed; SetColumns(d.Cols); }
        public void SetItems(IEnumerable<object> items, bool keepSelection)
        {
            HashSet<object> keep = keepSelection ? new HashSet<object>(selected) : null;
            all.Clear(); all.AddRange(items); selected.Clear();
            if (keep != null) foreach (object o in all) if (keep.Contains(o)) selected.Add(o);
            treeDirty = true; Apply();
        }
        public void Add(IEnumerable<object> items) { all.AddRange(items); treeDirty = true; Apply(); }
        public void Remove(IEnumerable<object> items) { HashSet<object> rm = new HashSet<object>(items); all.RemoveAll(delegate (object o) { return rm.Contains(o); }); foreach (object o in rm) selected.Remove(o); treeDirty = true; Apply(); }
        public void Invalidate2() { grid.Invalidate(); if (View == "details") ShowProps(Current); if (View == "tree") { treeDirty = true; BuildTree(); } UpdateCount(); }
        public void Refilter() { treeDirty = true; Apply(); }
        public IList<object> AllItems { get { return all; } }
        public IList<object> VisibleItems { get { return rows; } }
        public List<object> SelectedItems { get { List<object> l = new List<object>(); foreach (object o in rows) if (selected.Contains(o)) l.Add(o); return l; } }
        public int SelectedCount { get { return SelectedItems.Count; } }
        public object Current { get { if (View == "tree") { List<object> l; return tree.SelectedNode != null && nodeItems.TryGetValue(tree.SelectedNode, out l) && l.Count > 0 ? l[0] : null; } return grid.CurrentRow != null && grid.CurrentRow.Index < rows.Count ? rows[grid.CurrentRow.Index] : null; } }
        /// <summary>The checked rows, or the highlighted ones when nothing is checked.</summary>
        public List<object> Targets { get { List<object> l = SelectedItems; if (l.Count > 0) return l; if (View != "tree") foreach (DataGridViewRow r in grid.SelectedRows) if (r.Index < rows.Count) l.Add(rows[r.Index]); return l; } }
        public void Select(IEnumerable<object> items, bool on) { foreach (object o in items) { if (on) selected.Add(o); else selected.Remove(o); } Changed(); }
        public void ClearSelection() { selected.Clear(); Changed(); }
        public void SetView(string v)
        {
            View = v; grid.Visible = v == "grid" || v == "details"; tree.Visible = v == "tree"; detailSplit.Visible = v == "details";
            if (v == "details") { if (grid.Parent != detailSplit.Panel1) { Controls.Remove(grid); detailSplit.Panel1.Controls.Add(grid); if (detail.Parent == null) detailSplit.Panel2.Controls.Add(detail); } ShowProps(Current); }
            else if (grid.Parent == detailSplit.Panel1) { detailSplit.Panel1.Controls.Remove(grid); Controls.Add(grid); grid.BringToFront(); }
            if (v == "tree") BuildTree();
            foreach (Button b in new Button[] { bGrid, bDetails, bTree }) { bool on = (b == bGrid && v == "grid") || (b == bDetails && v == "details") || (b == bTree && v == "tree"); b.BackColor = on ? Theme.Panel3 : Theme.Panel2; b.ForeColor = on ? Theme.Teal : Theme.Ink; b.FlatAppearance.BorderColor = on ? Theme.Teal : Theme.Line; }
            if (ViewChanged != null) ViewChanged();
        }
        public void Export()
        {
            using (SaveFileDialog d = new SaveFileDialog())
            {
                d.Filter = "CSV|*.csv"; d.FileName = ExportName + "-" + DateTime.Now.ToString("yyyyMMdd-HHmm") + ".csv";
                if (d.ShowDialog(this) != DialogResult.OK) return;
                int n = ExportTo(d.FileName);
                MessageBox.Show(this, n.ToString("N0") + " row" + (n == 1 ? "" : "s") + (SelectedItems.Count > 0 ? " (the selected ones)" : " (everything shown)") + " written to\n" + d.FileName, "Exported", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        }
        /// <summary>Writes the ticked rows, or every shown row, as CSV. Returns the row count.</summary>
        /// <summary>Puts the caret in the search box (Ctrl+F).</summary>
        public void FocusSearch() { try { search.Focus(); search.SelectAll(); } catch { } }
        public int ExportTo(string path) { List<object> what = SelectedItems.Count > 0 ? SelectedItems : new List<object>(rows); Csv.Write(path, Cols, what); return what.Count; }
        // filters and search, also used by the self-test
        public IList<FilterRule> Rules { get { return rules; } }
        public int FilterCount { get { return rules.Count; } }
        public void AddRule(string key, string op, string value, bool matchCase) { FilterRule r = new FilterRule(); r.Key = key; r.Op = op; r.Value = value ?? ""; r.MatchCase = matchCase; rules.Add(r); RulesChanged(); }
        public void RemoveRule(FilterRule r) { rules.Remove(r); RulesChanged(); }
        public void ClearRules() { rules.Clear(); RulesChanged(); }
        public void SearchFor(string text) { if (string.IsNullOrEmpty(text)) { search.ForeColor = Theme.Dim; search.Text = "search…"; } else { search.ForeColor = Theme.Ink; search.Text = text; } Apply(); }
        public void SortBy(string key, bool asc) { sortKey = key; sortAsc = asc; Refilter(); }
        public string SortKey { get { return sortKey; } }
        public void SetCurrent(int row, int col) { try { if (row >= 0 && row < rows.Count && col + 1 < grid.Columns.Count && grid.Columns[col + 1].Visible) grid.CurrentCell = grid[col + 1, row]; } catch { } }
        public void OpenFilterBar() { filterOpen = true; fbar.Visible = true; UpdateFilterButton(); }
        /// <summary>Re-apply theme colours to the parts a generic colour remap cannot reach (grid styles, context menu).</summary>
        public void Retheme()
        {
            grid.BackgroundColor = Theme.Bg; grid.GridColor = Theme.Line;
            grid.ColumnHeadersDefaultCellStyle.BackColor = Theme.Side; grid.ColumnHeadersDefaultCellStyle.ForeColor = Theme.Dim; grid.ColumnHeadersDefaultCellStyle.SelectionBackColor = Theme.Side;
            grid.DefaultCellStyle.BackColor = Theme.Panel; grid.DefaultCellStyle.ForeColor = Theme.Ink; grid.DefaultCellStyle.SelectionBackColor = Theme.Panel3; grid.DefaultCellStyle.SelectionForeColor = Theme.Ink; grid.AlternatingRowsDefaultCellStyle.BackColor = Theme.AltRow;
            tree.BackColor = Theme.Panel; tree.ForeColor = Theme.Ink;
            props.BackgroundColor = Theme.Side; props.GridColor = Theme.Line; props.DefaultCellStyle.BackColor = Theme.Side; props.DefaultCellStyle.ForeColor = Theme.Ink; props.DefaultCellStyle.SelectionBackColor = Theme.Panel3; props.DefaultCellStyle.SelectionForeColor = Theme.Ink; if (props.Columns.Count > 0) props.Columns[0].DefaultCellStyle.ForeColor = Theme.Dim;
            detail.BackColor = Theme.Side; detailSplit.BackColor = Theme.Line; menu.BackColor = Theme.Panel2; menu.ForeColor = Theme.Ink;
            grid.Invalidate(); tree.Invalidate(); props.Invalidate();
        }

        // ---- filter internals ----
        void FillFilterColumns()
        {
            string was = fCol.SelectedItem as string; fCol.Items.Clear(); fCol.Items.Add("any column"); foreach (Col c in Cols) if (!c.Hidden) fCol.Items.Add(c.Title);
            int idx = was == null ? 0 : fCol.Items.IndexOf(was); fCol.SelectedIndex = idx < 0 ? 0 : idx;
        }
        string KeyOfTitle(string title) { if (title == null || title == "any column") return "*"; foreach (Col c in Cols) if (c.Title == title) return c.Key; return "*"; }
        void AddRuleFromBar()
        {
            string op = (string)fOp.SelectedItem; string v = fVal.Text; if (FilterRule.NeedsValue(op) && v.Length == 0) { fVal.Focus(); return; }
            AddRule(KeyOfTitle(fCol.SelectedItem as string), op, v, fCase.Checked); fVal.Text = ""; fVal.Focus();
        }
        void RulesChanged() { RebuildChips(); UpdateFilterButton(); if (rules.Count > 0) fbar.Visible = true; else fbar.Visible = filterOpen; Refilter(); }
        void RebuildChips()
        {
            chips.SuspendLayout(); chips.Controls.Clear();
            foreach (FilterRule r in rules)
            {
                FilterRule rr = r; Button chip = Theme.Btn(rr.Describe(Cols) + "   ×", false); chip.ForeColor = Theme.Teal; chip.FlatAppearance.BorderColor = Theme.TealDark; chip.Font = Theme.UISmall; chip.MinimumSize = new Size(0, Theme.S(26)); chip.Margin = new Padding(0, Theme.S(2), Theme.S(6), Theme.S(4));
                new ToolTip().SetToolTip(chip, "remove this rule"); chip.Click += delegate { RemoveRule(rr); }; chips.Controls.Add(chip);
            }
            chips.ResumeLayout();
        }
        void UpdateFilterButton() { bFilter.Text = rules.Count > 0 ? "Filter (" + rules.Count + ")" : "Filter"; bFilter.ForeColor = rules.Count > 0 ? Theme.Teal : Theme.Ink; bFilter.FlatAppearance.BorderColor = rules.Count > 0 || fbar.Visible ? Theme.Teal : Theme.Line; }
        bool PassRules(object o) { return FilterRule.Pass(rules, Cols, o); }
        void BuildMenu()
        {
            menu.Items.Clear(); if (menuRow < 0 || menuRow >= rows.Count || menuCol < 0 || menuCol >= Cols.Count) return;
            object o = rows[menuRow]; Col c = Cols[menuCol]; string v = SafeText(c, o); string vs = v.Length > 40 ? v.Substring(0, 40) + "…" : v;
            if (v.Trim().Length > 0)
            {
                menu.Items.Add(Item("Filter: " + c.Title + " contains “" + vs + "”", delegate { AddRule(c.Key, "contains", v, false); }));
                menu.Items.Add(Item("Filter: " + c.Title + " equals “" + vs + "”", delegate { AddRule(c.Key, "equals", v, false); }));
                menu.Items.Add(Item("Exclude rows where " + c.Title + " equals “" + vs + "”", delegate { AddRule(c.Key, "does not equal", v, false); }));
            }
            else { menu.Items.Add(Item("Filter: " + c.Title + " is empty", delegate { AddRule(c.Key, "is empty", "", false); })); menu.Items.Add(Item("Filter: " + c.Title + " is not empty", delegate { AddRule(c.Key, "is not empty", "", false); })); }
            menu.Items.Add(Item("Filter: any column contains “" + vs + "”", delegate { AddRule("*", "contains", v, false); }));
            if (rules.Count > 0) menu.Items.Add(Item("Clear " + rules.Count + " filter" + (rules.Count == 1 ? "" : "s"), delegate { ClearRules(); }));
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add(Item("Copy cell", delegate { Clip(v); }));
            menu.Items.Add(Item("Copy row", delegate { Clip(RowText(o)); }));
            menu.Items.Add(Item("Copy " + c.Title + " of every shown row", delegate { List<string> l = new List<string>(); foreach (object x in rows) l.Add(c.Text(x)); Clip(string.Join("\r\n", l.ToArray())); }));
            menu.Items.Add(Item("Copy the " + (SelectedItems.Count > 0 ? SelectedItems.Count + " ticked" : rows.Count + " shown") + " rows (tab-separated)", delegate { CopyRows(); }));
            menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add(Item(selected.Contains(o) ? "Untick this row" : "Tick this row", delegate { if (!selected.Remove(o)) selected.Add(o); Changed(); }));
            menu.Items.Add(Item("Sort by " + c.Title + (sortKey == c.Key && sortAsc ? " (descending)" : ""), delegate { SortBy(c.Key, !(sortKey == c.Key && sortAsc)); }));
        }
        static ToolStripMenuItem Item(string text, EventHandler h) { ToolStripMenuItem m = new ToolStripMenuItem(text); m.ForeColor = Theme.Ink; m.Click += h; return m; }
        string RowText(object o) { List<string> l = new List<string>(); foreach (Col c in Cols) if (!c.Hidden) l.Add(SafeText(c, o)); return string.Join("\t", l.ToArray()); }
        /// <summary>A cell text that can never throw: a column accessor applied to a row of another type (mid mode-switch) or odd data yields "" instead of an exception.</summary>
        public static string SafeText(Col c, object o) { return c.SafeText(o); }
        void CopyRows() { List<object> what = SelectedItems.Count > 0 ? SelectedItems : new List<object>(rows); List<string> l = new List<string>(); List<string> h = new List<string>(); foreach (Col c in Cols) if (!c.Hidden) h.Add(c.Title); l.Add(string.Join("\t", h.ToArray())); foreach (object o in what) l.Add(RowText(o)); Clip(string.Join("\r\n", l.ToArray())); }
        static void Clip(string s) { try { Clipboard.SetText(s ?? ""); } catch { } }

        // ---- internals ----
        void Apply()
        {
            string q = SearchText.ToLowerInvariant(); rows = new List<object>();
            foreach (object o in all)
            {
                if (Filter != null && !Filter(o)) continue;
                if (q.Length > 0) { bool hit = false; foreach (Col c in Cols) { if (SafeText(c, o).ToLowerInvariant().IndexOf(q) >= 0) { hit = true; break; } } if (!hit) continue; }
                if (rules.Count > 0 && !PassRules(o)) continue;
                rows.Add(o);
            }
            if (sortKey != null) Sort();
            grid.AllowUserToAddRows = false; grid.ReadOnly = false;
            try { if (grid.RowCount != rows.Count) grid.RowCount = rows.Count; } catch { try { grid.RowCount = Math.Max(0, rows.Count); } catch { } }
            grid.Invalidate();
            if (View == "tree") BuildTree();
            UpdateCount(); if (SelectionChanged != null) SelectionChanged();
        }
        void Sort()
        {
            Col c = Cols.Find(delegate (Col x) { return x.Key == sortKey; }); if (c == null) return;
            RowSort.Sort(rows, c, sortAsc);
            grid.Invalidate();
        }
        void HeaderClick(object s, DataGridViewCellMouseEventArgs e)
        {
            if (e.ColumnIndex <= 0) { if (e.ColumnIndex == 0) { bool allOn = rows.Count > 0 && SelectedItems.Count == rows.Count; selected.Clear(); if (!allOn) foreach (object o in rows) selected.Add(o); Changed(); } return; }
            // the right ~18px of each header is the filter funnel; the rest sorts
            if (e.X >= grid.Columns[e.ColumnIndex].Width - Theme.S(18) && e.ColumnIndex - 1 < Cols.Count) { OpenHeaderFilter(e.ColumnIndex); return; }
            string k = grid.Columns[e.ColumnIndex].Name; if (sortKey == k) sortAsc = !sortAsc; else { sortKey = k; sortAsc = true; } Sort(); grid.Invalidate();
        }
        /// <summary>Draws each header ourselves: title, a sort arrow on the sorted column, and a filter funnel (teal when that column has a filter).</summary>
        void HeaderPaint(object s, DataGridViewCellPaintingEventArgs e)
        {
            if (e.RowIndex != -1 || e.ColumnIndex < 1) return;
            e.PaintBackground(e.ClipBounds, true);
            Rectangle b = e.CellBounds; string title = e.Value == null ? "" : e.Value.ToString();
            bool right = e.CellStyle.Alignment == DataGridViewContentAlignment.MiddleRight || e.CellStyle.Alignment == DataGridViewContentAlignment.TopRight || e.CellStyle.Alignment == DataGridViewContentAlignment.BottomRight;
            TextFormatFlags tf = TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix | (right ? TextFormatFlags.Right : TextFormatFlags.Left);
            TextRenderer.DrawText(e.Graphics, title, Theme.UISmall, new Rectangle(b.X + Theme.S(6), b.Y, b.Width - Theme.S(32), b.Height), Theme.Dim, tf);
            string key = grid.Columns[e.ColumnIndex].Name; bool active = false; foreach (FilterRule r in rules) if (r.Key == key) { active = true; break; }
            if (key == sortKey)
            {
                int ax = b.Right - Theme.S(28), ay = b.Y + b.Height / 2;
                Point[] tri = sortAsc ? new Point[] { new Point(ax, ay + Theme.S(2)), new Point(ax + Theme.S(7), ay + Theme.S(2)), new Point(ax + Theme.S(3), ay - Theme.S(3)) } : new Point[] { new Point(ax, ay - Theme.S(2)), new Point(ax + Theme.S(7), ay - Theme.S(2)), new Point(ax + Theme.S(3), ay + Theme.S(3)) };
                using (Brush br = new SolidBrush(Theme.Teal)) e.Graphics.FillPolygon(br, tri);
            }
            int fx = b.Right - Theme.S(15), fy = b.Y + b.Height / 2 - Theme.S(3); Color fc = active ? Theme.Teal : Theme.Faint;
            using (Pen p = new Pen(fc, active ? 1.6f : 1.2f)) { e.Graphics.DrawLine(p, fx, fy, fx + Theme.S(8), fy); e.Graphics.DrawLine(p, fx + Theme.S(1), fy + Theme.S(3), fx + Theme.S(7), fy + Theme.S(3)); e.Graphics.DrawLine(p, fx + Theme.S(3), fy + Theme.S(6), fx + Theme.S(5), fy + Theme.S(6)); }
            using (Pen ln = new Pen(Theme.Line)) e.Graphics.DrawLine(ln, b.Right - 1, b.Top + Theme.S(6), b.Right - 1, b.Bottom - Theme.S(6));
            e.Handled = true;
        }
        void ClearColumnRules(string key) { rules.RemoveAll(delegate (FilterRule r) { return r.Key == key; }); }
        /// <summary>The per-column header filter popup: a value checklist and a contains box, plus sort. Applies rules keyed to that column.</summary>
        void OpenHeaderFilter(int colIndex)
        {
            Col col = Cols[colIndex - 1];
            Dictionary<string, int> counts = new Dictionary<string, int>(); List<string> order = new List<string>();
            foreach (object o in all) { if (Filter != null && !Filter(o)) continue; string v = SafeText(col, o); int c; if (counts.TryGetValue(v, out c)) counts[v] = c + 1; else { counts[v] = 1; order.Add(v); } }
            order.Sort(StringComparer.OrdinalIgnoreCase);
            string containsPrefill = ""; HashSet<string> anyPrefill = null;
            foreach (FilterRule r in rules) if (r.Key == col.Key) { if (r.AnyOf != null) anyPrefill = r.AnyOf; else if (r.Op == "contains") containsPrefill = r.Value; }
            bool tooMany = order.Count > 400;
            using (Form f = new Form())
            {
                f.Text = col.Title; f.BackColor = Theme.Panel; f.ForeColor = Theme.Ink; f.Font = Theme.UI; f.FormBorderStyle = FormBorderStyle.FixedToolWindow; f.StartPosition = FormStartPosition.Manual; f.ShowInTaskbar = false; f.Width = Theme.S(280); f.Height = Theme.S(tooMany ? 200 : 400); f.MinimizeBox = false; f.MaximizeBox = false;
                try { Rectangle hr = grid.GetCellDisplayRectangle(colIndex, -1, false); Point p = grid.PointToScreen(new Point(hr.Left, hr.Bottom)); Rectangle scr = Screen.FromControl(grid).WorkingArea; f.Location = new Point(Math.Max(scr.Left, Math.Min(p.X, scr.Right - f.Width)), Math.Min(p.Y, scr.Bottom - f.Height)); } catch { f.StartPosition = FormStartPosition.CenterParent; }
                Label cap = Theme.Lbl("Filter “" + col.Title + "”", Theme.Teal, Theme.UIBold); cap.Dock = DockStyle.Top; cap.Height = Theme.S(26); cap.Padding = new Padding(Theme.S(10), Theme.S(6), 0, 0);
                FlowLayoutPanel sortbar = new FlowLayoutPanel(); sortbar.Dock = DockStyle.Top; sortbar.Height = Theme.S(38); sortbar.Padding = new Padding(Theme.S(8), Theme.S(4), 0, 0); sortbar.BackColor = Theme.Panel;
                Button sa = Theme.Btn("Sort ↑", false), sd = Theme.Btn("Sort ↓", false); sa.Click += delegate { SortBy(col.Key, true); f.Close(); }; sd.Click += delegate { SortBy(col.Key, false); f.Close(); }; sortbar.Controls.Add(sa); sortbar.Controls.Add(sd);
                Label lc = Theme.Lbl("contains", Theme.Dim, Theme.UISmall); lc.Dock = DockStyle.Top; lc.Height = Theme.S(18); lc.Padding = new Padding(Theme.S(10), 0, 0, 0);
                TextBox tc = Theme.Text(containsPrefill, 230); tc.Dock = DockStyle.Top; tc.Margin = new Padding(Theme.S(10), 0, Theme.S(10), 0);
                Panel tcpad = new Panel(); tcpad.Dock = DockStyle.Top; tcpad.Height = Theme.S(28); tcpad.Padding = new Padding(Theme.S(10), 0, Theme.S(10), 0); tcpad.Controls.Add(tc);
                CheckedListBox clb = new CheckedListBox(); clb.Dock = DockStyle.Fill; clb.BackColor = Theme.Panel2; clb.ForeColor = Theme.Ink; clb.BorderStyle = BorderStyle.None; clb.CheckOnClick = true; clb.IntegralHeight = false; clb.Font = Theme.UISmall;
                CheckBox allBox = Theme.Toggle("(all values)", true); allBox.Dock = DockStyle.Top; allBox.Margin = new Padding(Theme.S(10), Theme.S(2), 0, 0);
                List<string> vals = new List<string>();
                if (!tooMany)
                {
                    foreach (string v in order) { vals.Add(v); bool on = anyPrefill == null || anyPrefill.Contains(v.Trim()); clb.Items.Add((v.Length == 0 ? "(blank)" : v.Length > 46 ? v.Substring(0, 46) + "…" : v) + "   (" + counts[v] + ")", on); }
                    allBox.Checked = anyPrefill == null; bool guard = false;
                    allBox.CheckedChanged += delegate { if (guard) return; for (int i = 0; i < clb.Items.Count; i++) clb.SetItemChecked(i, allBox.Checked); };
                    clb.ItemCheck += delegate { BeginInvoke((Action)delegate { int on = 0; for (int i = 0; i < clb.Items.Count; i++) if (clb.GetItemChecked(i)) on++; guard = true; allBox.Checked = on == clb.Items.Count; guard = false; }); };
                }
                FlowLayoutPanel bar = new FlowLayoutPanel(); bar.Dock = DockStyle.Bottom; bar.Height = Theme.S(46); bar.FlowDirection = FlowDirection.RightToLeft; bar.Padding = new Padding(Theme.S(8), Theme.S(8), Theme.S(8), 0); bar.BackColor = Theme.Panel;
                Button apply = Theme.Btn("Apply", true), clear = Theme.Btn("Clear", false), cancel = Theme.Btn("Cancel", false); cancel.DialogResult = DialogResult.Cancel;
                apply.Click += delegate
                {
                    ClearColumnRules(col.Key); string ct = tc.Text.Trim(); if (ct.Length > 0) rules.Add(new FilterRule { Key = col.Key, Op = "contains", Value = ct });
                    if (!tooMany) { HashSet<string> set = new HashSet<string>(StringComparer.OrdinalIgnoreCase); int on = 0; for (int i = 0; i < clb.Items.Count; i++) if (clb.GetItemChecked(i)) { on++; set.Add(vals[i].Trim()); } if (on < vals.Count) rules.Add(new FilterRule { Key = col.Key, Op = "is any of", AnyOf = set }); }
                    RulesChanged(); f.Close();
                };
                clear.Click += delegate { ClearColumnRules(col.Key); RulesChanged(); f.Close(); };
                bar.Controls.Add(apply); bar.Controls.Add(clear); bar.Controls.Add(cancel);
                Label note = Theme.Lbl(tooMany ? order.Count + " distinct values — use contains" : "untick values to hide them", Theme.Faint, Theme.UISmall); note.Dock = DockStyle.Top; note.Height = Theme.S(16); note.Padding = new Padding(Theme.S(10), 0, 0, 0);
                f.Controls.Add(clb); if (!tooMany) f.Controls.Add(allBox); f.Controls.Add(note); f.Controls.Add(tcpad); f.Controls.Add(lc); f.Controls.Add(sortbar); f.Controls.Add(cap); f.Controls.Add(bar);
                clb.BringToFront(); f.AcceptButton = apply; f.CancelButton = cancel;
                f.ShowDialog(this);
            }
            grid.Invalidate();
        }
        void GridValueNeeded(object s, DataGridViewCellValueEventArgs e)
        {
            if (e.RowIndex < 0 || e.RowIndex >= rows.Count) return; object o = rows[e.RowIndex];
            if (e.ColumnIndex == 0) { e.Value = selected.Contains(o); return; }
            int ci = e.ColumnIndex - 1; if (ci < 0 || ci >= Cols.Count) return; Col c = Cols[ci]; e.Value = SafeText(c, o);
        }
        void GridValuePushed(object s, DataGridViewCellValueEventArgs e)
        {
            if (e.RowIndex < 0 || e.RowIndex >= rows.Count) return; object o = rows[e.RowIndex];
            if (e.ColumnIndex == 0) { bool on = e.Value is bool && (bool)e.Value; if (on) selected.Add(o); else selected.Remove(o); Changed(); return; }
            int ci = e.ColumnIndex - 1; if (ci < 0 || ci >= Cols.Count) return; Col c = Cols[ci]; if (c.Editable && c.Set != null) { c.Set(o, e.Value == null ? "" : e.Value.ToString()); grid.InvalidateRow(e.RowIndex); if (View == "details") ShowProps(o); }
        }
        void GridFormatting(object s, DataGridViewCellFormattingEventArgs e)
        {
            if (e.RowIndex < 0 || e.RowIndex >= rows.Count || e.ColumnIndex == 0) return; int ci = e.ColumnIndex - 1; if (ci < 0 || ci >= Cols.Count) return; object o = rows[e.RowIndex]; Col c = Cols[ci];
            Color fore = Theme.Ink;
            try { if (RowTone != null) fore = Theme.Of(RowTone(o)); if (c.ToneOf != null) fore = Theme.Of(c.ToneOf(o)); if (c.Editable) fore = Theme.Teal; if (Dimmed != null && Dimmed(o)) fore = Theme.Faint; } catch { }
            e.CellStyle.ForeColor = fore;
            if (selected.Contains(o)) e.CellStyle.BackColor = Theme.SelRow;
        }
        void GridClick(object s, DataGridViewCellEventArgs e)
        {
            if (e.RowIndex < 0 || e.RowIndex >= rows.Count) return;
            if (e.ColumnIndex == 0)
            {
                object o = rows[e.RowIndex]; bool on = !selected.Contains(o);
                if ((ModifierKeys & Keys.Shift) != 0 && lastClick >= 0 && lastClick < rows.Count) { int a = Math.Min(lastClick, e.RowIndex), b = Math.Max(lastClick, e.RowIndex); for (int i = a; i <= b; i++) { if (on) selected.Add(rows[i]); else selected.Remove(rows[i]); } }
                else { if (on) selected.Add(o); else selected.Remove(o); }
                lastClick = e.RowIndex; grid.InvalidateColumn(0); grid.Invalidate(); Changed();
            }
        }
        void Changed() { grid.Invalidate(); UpdateCount(); if (SelectionChanged != null) SelectionChanged(); }
        void UpdateCount() { int sel = SelectedItems.Count; count.Text = rows.Count.ToString("N0") + (rows.Count != all.Count ? " of " + all.Count.ToString("N0") : "") + " rows" + (sel > 0 ? " · " + sel.ToString("N0") + " selected" : "") + (rules.Count > 0 ? " · " + rules.Count + " filter" + (rules.Count == 1 ? "" : "s") : ""); }
        void ShowProps(object o)
        {
            props.Rows.Clear(); if (o == null) return;
            foreach (Col c in Cols) { int i = props.Rows.Add(c.Title, SafeText(c, o)); try { if (c.ToneOf != null) props.Rows[i].Cells[1].Style.ForeColor = Theme.Of(c.ToneOf(o)); } catch { } }
        }
        void BuildTree()
        {
            if (!treeDirty) return; treeDirty = false; building = true;
            try
            {
                tree.BeginUpdate(); tree.Nodes.Clear(); nodeItems.Clear();
                if (TreePath == null) { tree.Nodes.Add("(no tree grouping for this tool)"); return; }
                Dictionary<string, TreeNode> index = new Dictionary<string, TreeNode>(StringComparer.OrdinalIgnoreCase);
                foreach (object o in rows)
                {
                    string[] path = TreePath(o); if (path == null || path.Length == 0) continue;
                    TreeNodeCollection level = tree.Nodes; string key = ""; TreeNode node = null;
                    for (int i = 0; i < path.Length; i++)
                    {
                        key += "\\" + path[i]; TreeNode n;
                        if (!index.TryGetValue(key, out n)) { n = new TreeNode(path[i]); n.ForeColor = i == path.Length - 1 ? Theme.Ink : Theme.Dim; level.Add(n); index[key] = n; nodeItems[n] = new List<object>(); }
                        nodeItems[n].Add(o); level = n.Nodes; node = n;
                    }
                }
                foreach (TreeNode n in index.Values)
                {
                    int cnt = nodeItems[n].Count;
                    if (TreeNodeText != null) n.Text = TreeNodeText(n.Text, nodeItems[n]);
                    else if (n.Nodes.Count > 0) n.Text = n.Text + "   (" + cnt.ToString("N0") + ")";
                    bool allSel = cnt > 0; foreach (object o in nodeItems[n]) if (!selected.Contains(o)) { allSel = false; break; } n.Checked = allSel;
                }
                foreach (TreeNode n in tree.Nodes) n.Expand();
            }
            finally { tree.EndUpdate(); building = false; }
        }
        void CheckDown(TreeNode n, bool on) { List<object> l; if (nodeItems.TryGetValue(n, out l)) foreach (object o in l) { if (on) selected.Add(o); else selected.Remove(o); } foreach (TreeNode c in n.Nodes) { c.Checked = on; CheckDown(c, on); } }
    }

    /// <summary>A row of steps (pending · running · done · failed · skipped), a progress line, the current message and the elapsed time: the visual for long scans.</summary>
    public class StepStrip : Control
    {
        public class Step { public string Label, State = "pending", Note = ""; }
        public readonly List<Step> Steps = new List<Step>(); public string Message = ""; public double Fraction = -1; public bool Active; DateTime startedAt, endedAt; readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer(); int tick;
        public StepStrip() { SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true); BackColor = Theme.Side; Height = Theme.S(72); Dock = DockStyle.Top; Visible = false; timer.Interval = 70; timer.Tick += delegate { tick++; Invalidate(); }; }
        public void Begin(params string[] labels) { Steps.Clear(); foreach (string l in labels) { Step s = new Step(); s.Label = l; Steps.Add(s); } Message = "starting…"; Fraction = -1; startedAt = DateTime.Now; Active = true; timer.Start(); Visible = true; Invalidate(); }
        public void Set(string label, string state, string note) { foreach (Step s in Steps) if (s.Label == label) { s.State = state; if (note != null) s.Note = note; } Invalidate(); }
        public void Say(string message) { Message = message ?? ""; Invalidate(); }
        public void End(string message) { Message = message ?? Message; Active = false; endedAt = DateTime.Now; Fraction = -1; timer.Stop(); foreach (Step s in Steps) if (s.State == "running") s.State = "done"; Invalidate(); }
        public string Elapsed { get { if (startedAt == DateTime.MinValue) return ""; return Fmt.Secs(((Active ? DateTime.Now : endedAt) - startedAt).TotalSeconds); } }
        static Color StateColor(string s) { return s == "running" ? Theme.Teal : s == "done" ? Theme.Green : s == "failed" ? Theme.Rose : s == "skipped" ? Theme.Faint : Theme.Faint; }
        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics; g.Clear(Theme.Side); g.SmoothingMode = SmoothingMode.AntiAlias;
            int x = Theme.S(12), y = Theme.S(10), dot = Theme.S(11);
            for (int i = 0; i < Steps.Count; i++)
            {
                Step s = Steps[i]; Color col = StateColor(s.State); Font font = s.State == "running" ? Theme.UIBold : Theme.UI;
                Rectangle dr = new Rectangle(x, y + Theme.S(4), dot, dot);
                if (s.State == "running") { using (Pen p = new Pen(Theme.Teal, 2f)) g.DrawArc(p, dr, (tick * 14) % 360, 260); }
                else if (s.State == "done") { using (Brush b = new SolidBrush(Theme.Green)) g.FillEllipse(b, dr); using (Pen p = new Pen(Theme.Side, 1.6f)) { g.DrawLine(p, dr.X + dr.Width * 0.25f, dr.Y + dr.Height * 0.55f, dr.X + dr.Width * 0.45f, dr.Y + dr.Height * 0.75f); g.DrawLine(p, dr.X + dr.Width * 0.45f, dr.Y + dr.Height * 0.75f, dr.X + dr.Width * 0.78f, dr.Y + dr.Height * 0.3f); } }
                else if (s.State == "failed") { using (Brush b = new SolidBrush(Theme.Rose)) g.FillEllipse(b, dr); }
                else if (s.State == "skipped") { using (Pen p = new Pen(Theme.Faint, 1.2f)) { g.DrawEllipse(p, dr); g.DrawLine(p, dr.X + 2, dr.Y + dr.Height - 2, dr.X + dr.Width - 2, dr.Y + 2); } }
                else { using (Pen p = new Pen(Theme.Faint, 1.2f)) g.DrawEllipse(p, dr); }
                Color tc = s.State == "running" ? Theme.Teal : s.State == "done" ? Theme.Ink : s.State == "failed" ? Theme.Rose : s.State == "skipped" ? Theme.Faint : Theme.Dim;
                string label = s.Label + (s.Note.Length > 0 && s.State != "pending" ? "  " + s.Note : ""); if (s.State == "skipped") label = s.Label + "  (off)";
                Size sz = TextRenderer.MeasureText(g, label, font, new Size(int.MaxValue, int.MaxValue), TextFormatFlags.NoPrefix);
                TextRenderer.DrawText(g, label, font, new Point(x + dot + Theme.S(6), y), tc, TextFormatFlags.NoPrefix);
                x += dot + Theme.S(6) + sz.Width + Theme.S(10);
                if (i < Steps.Count - 1) { using (Pen p = new Pen(Theme.Line, 1f)) g.DrawLine(p, x, y + Theme.S(10), x + Theme.S(14), y + Theme.S(10)); x += Theme.S(22); }
            }
            // progress line
            int bx = Theme.S(12), by = y + Theme.S(30), bw = Width - Theme.S(24), bh = Theme.S(5);
            using (Brush bg = new SolidBrush(Theme.Panel2)) g.FillRectangle(bg, bx, by, bw, bh);
            if (!Active) { using (Brush fg = new SolidBrush(Theme.Green)) g.FillRectangle(fg, bx, by, bw, bh); }
            else if (Fraction >= 0) { using (Brush fg = new SolidBrush(Theme.Teal)) g.FillRectangle(fg, bx, by, (int)(bw * Math.Min(1, Fraction)), bh); }
            else { int seg = Math.Max(40, bw / 5); int pos = (tick * 9) % (bw + seg) - seg; int a = Math.Max(bx, bx + pos), b = Math.Min(bx + bw, bx + pos + seg); if (b > a) using (Brush fg = new SolidBrush(Theme.Teal)) g.FillRectangle(fg, a, by, b - a, bh); }
            // message + elapsed
            string el = Elapsed; Size es = TextRenderer.MeasureText(g, el, Theme.UISmall);
            TextRenderer.DrawText(g, Message, Theme.UISmall, new Rectangle(bx, by + Theme.S(9), bw - es.Width - Theme.S(10), Theme.S(18)), Active ? Theme.Ink : Theme.Dim, TextFormatFlags.NoPrefix | TextFormatFlags.EndEllipsis | TextFormatFlags.SingleLine);
            TextRenderer.DrawText(g, el, Theme.UISmall, new Point(bx + bw - es.Width, by + Theme.S(9)), Theme.Dim, TextFormatFlags.NoPrefix);
        }
    }

    /// <summary>The bar that appears when rows are selected, with the actions that apply to them.</summary>
    public class SelectionBar : Panel
    {
        readonly Label lbl = Theme.Lbl("", Theme.Teal, Theme.UIBold); readonly FlowLayoutPanel flow = new FlowLayoutPanel();
        public SelectionBar() { Dock = DockStyle.Bottom; AutoSize = true; AutoSizeMode = AutoSizeMode.GrowAndShrink; MinimumSize = new Size(0, Theme.S(44)); BackColor = Theme.SelBar; Padding = new Padding(Theme.S(10), Theme.S(6), Theme.S(10), 0); Visible = false; flow.Dock = DockStyle.Top; flow.AutoSize = true; flow.AutoSizeMode = AutoSizeMode.GrowAndShrink; flow.WrapContents = true; flow.BackColor = Color.Transparent; lbl.Margin = new Padding(0, Theme.S(7), Theme.S(16), 0); flow.Controls.Add(lbl); Controls.Add(flow); }
        public Button Add(string text, bool primary, EventHandler onClick) { Button b = primary ? Theme.Btn(text, true) : Theme.Btn(text, false); b.Click += onClick; flow.Controls.Add(b); return b; }
        public Button AddDanger(string text, EventHandler onClick) { Button b = Theme.Danger(text); b.Click += onClick; flow.Controls.Add(b); return b; }
        public Button AddCaution(string text, EventHandler onClick) { Button b = Theme.Caution(text); b.Click += onClick; flow.Controls.Add(b); return b; }
        /// <summary>A small gap: the read-only actions on the left of it, the ones that change the machine on the right.</summary>
        public void Separator() { Panel p = new Panel(); p.Width = Theme.S(14); p.Height = 1; p.Margin = new Padding(0); flow.Controls.Add(p); }
        /// <summary>Removes every action button (keeps the count label) so a panel can swap actions per mode.</summary>
        public void Clear() { for (int i = flow.Controls.Count - 1; i >= 1; i--) flow.Controls.RemoveAt(i); }
        public void Update(int count, string noun) { Visible = count > 0; lbl.Text = count.ToString("N0") + " " + noun + (count == 1 ? "" : "s") + " selected"; }
    }

    /// <summary>A small live gauge: label, bar, value, sparkline.</summary>
    public class Gauge : Control
    {
        public string Label = "", Value = ""; public double Fraction; public List<double> History; public Color Bar = Theme.Teal;
        public Gauge() { SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true); BackColor = Theme.Side; Height = Theme.S(54); }
        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics; g.Clear(Theme.Side); g.SmoothingMode = SmoothingMode.AntiAlias;
            TextRenderer.DrawText(g, Label, Theme.UISmall, new Point(Theme.S(10), Theme.S(6)), Theme.Faint, TextFormatFlags.NoPrefix);
            TextRenderer.DrawText(g, Value, Theme.UIBold, new Point(Theme.S(10), Theme.S(22)), Theme.Ink, TextFormatFlags.NoPrefix);
            int bx = Theme.S(120), by = Theme.S(30), bw = Math.Max(20, Width / 3), bh = Theme.S(8);
            using (Brush bg = new SolidBrush(Theme.Panel2)) g.FillRectangle(bg, bx, by, bw, bh);
            using (Brush fg = new SolidBrush(Fraction >= 0.85 ? Theme.Rose : Fraction >= 0.6 ? Theme.Amber : Bar)) g.FillRectangle(fg, bx, by, (int)(bw * Math.Max(0, Math.Min(1, Fraction))), bh);
            if (History != null && History.Count > 1)
            {
                int sx = bx + bw + Theme.S(16), sw = Width - sx - Theme.S(10), sh = Theme.S(36), sy = Theme.S(10); if (sw < 30) return;
                double max = 0; foreach (double v in History) if (v > max) max = v; if (max <= 0) max = 1;
                PointF[] pts = new PointF[History.Count]; for (int i = 0; i < History.Count; i++) pts[i] = new PointF(sx + (float)sw * i / Math.Max(1, History.Count - 1), sy + sh - (float)(sh * History[i] / max));
                using (Pen p = new Pen(Bar, 1.6f)) g.DrawLines(p, pts);
            }
        }
    }

    // ───────────────────────────── the shell ─────────────────────────────
    public abstract class ToolPanel : UserControl
    {
        public Shell Host; public abstract string Title { get; } public abstract string Blurb { get; } public virtual bool NeedsAdmin { get { return false; } }
        public virtual void OnShown() { } public virtual void OnHidden() { }
        public virtual void SelfTest(StringBuilder report) { }
        /// <summary>Drives every DataView in the panel through the views, every sort, search, filter rules, selection and a CSV export. The self-test calls it after SelfTest(); panels with modes override it to cover each mode.</summary>
        public virtual void Exercise(StringBuilder r) { foreach (DataView v in FindViews(this)) ExerciseView(v, r); }
        protected static List<DataView> FindViews(Control c) { List<DataView> l = new List<DataView>(); foreach (Control x in c.Controls) { DataView v = x as DataView; if (v != null) l.Add(v); else l.AddRange(FindViews(x)); } return l; }
        protected void ExerciseView(DataView v, StringBuilder r)
        {
            string name = GetType().Name.Replace("Panel", "").ToLowerInvariant() + "/" + v.ExportName; int n = v.VisibleItems.Count; List<string> problems = new List<string>(); int sorted = 0;
            try
            {
                foreach (string view in new string[] { "details", "tree", "grid" }) { v.SetView(view); Application.DoEvents(); }
                if (n > 0) v.SetCurrent(Math.Min(1, n - 1), 0);
                foreach (Col c in new List<Col>(v.Cols)) { v.SortBy(c.Key, true); v.SortBy(c.Key, false); if (v.VisibleItems.Count != n) problems.Add("sort on " + c.Key + " changed the row count"); sorted++; }
                v.SortBy(null, true);
                string probe = ""; Col probeCol = null;
                if (n > 0) foreach (Col c in v.Cols) { string t = c.Text(v.VisibleItems[0]); if (t.Trim().Length >= 3) { probe = t.Trim().Substring(0, Math.Min(4, t.Trim().Length)); probeCol = c; break; } }
                if (probe.Length > 0)
                {
                    v.SearchFor(probe); if (v.VisibleItems.Count < 1) problems.Add("search '" + probe + "' found nothing"); v.SearchFor(""); if (v.VisibleItems.Count != n) problems.Add("clearing the search left " + v.VisibleItems.Count + " of " + n);
                    v.AddRule(probeCol.Key, "contains", probe, false); int a = v.VisibleItems.Count; v.ClearRules(); v.AddRule(probeCol.Key, "does not contain", probe, false); int b = v.VisibleItems.Count; v.ClearRules();
                    if (a < 1) problems.Add("rule contains '" + probe + "' matched nothing"); if (a + b != n) problems.Add("contains + does-not-contain = " + a + " + " + b + " but " + n + " rows");
                    v.AddRule("*", "is not empty", "", false); if (v.VisibleItems.Count != n) problems.Add("'any column is not empty' dropped rows"); v.AddRule(probeCol.Key, "equals", "\u0001never", false); if (v.VisibleItems.Count != 0) problems.Add("two rules did not AND"); v.ClearRules();
                    if (v.VisibleItems.Count != n) problems.Add("rules not cleared (" + v.VisibleItems.Count + ")");
                }
                v.Select(v.VisibleItems, true); if (v.SelectedCount != n) problems.Add("select all gave " + v.SelectedCount); v.ClearSelection(); if (v.SelectedCount != 0) problems.Add("clear selection left " + v.SelectedCount);
                string tmp = Path.Combine(Path.GetTempPath(), "pstools-export-" + v.ExportName + ".csv"); int wrote = v.ExportTo(tmp); string csv = File.ReadAllText(tmp); File.Delete(tmp); int recs = Csv.CountRecords(csv); string header = csv.Split('\n')[0];
                if (wrote != n || recs != n + 1) problems.Add("csv has " + (recs - 1) + " records for " + n + " rows");
                foreach (Col c in v.Cols) if (header.IndexOf(c.Title) < 0) problems.Add("csv header lacks '" + c.Title + "'");
                v.SetView("grid"); Application.DoEvents();
            }
            catch (Exception ex) { problems.Add("exception: " + ex.GetType().Name + ": " + ex.Message); }
            r.AppendLine((problems.Count == 0 ? "PASS" : "FAIL") + " ui " + name + ": " + n + " rows · " + sorted + " columns sorted both ways · views · search · rules · select · csv" + (problems.Count > 0 ? " · " + string.Join("; ", problems.ToArray()) : ""));
        }
        protected DataView NewView(string exportName) { DataView v = new DataView(); v.ExportName = exportName; return v; }
        protected static object[] Boxed<T>(IEnumerable<T> items) { List<object> l = new List<object>(); foreach (T t in items) l.Add(t); return l.ToArray(); }
    }

    public class Shell : Form
    {
        public readonly bool IsElevated; public readonly Settings Settings; readonly Panel side = new Panel(), head = new Panel(), host = new Panel(), list = new Panel(); readonly List<Control> sideRows = new List<Control>(); readonly Label hTitle = Theme.Lbl("", Theme.Ink, Theme.Title), hBlurb = Theme.Lbl("", Theme.Dim, Theme.UI), hAdmin = Theme.Lbl("", Theme.Amber, Theme.UISmall), toast = Theme.Lbl("", Theme.Teal, Theme.UI);
        readonly Panel hIcon = new Panel(); string iconKey = ""; readonly List<SideItem> items = new List<SideItem>(); readonly List<SideHeader> headers = new List<SideHeader>(); readonly Panel statusBar = new Panel(); readonly Label sLeft = Theme.Lbl("", Theme.Dim, Theme.UISmall), sRight = Theme.Lbl("", Theme.Faint, Theme.UISmall); readonly List<ToolPanel> panels = new List<ToolPanel>(); ToolPanel current; public string ShotDir, SelfTestFile; readonly System.Windows.Forms.Timer toastTimer = new System.Windows.Forms.Timer();
        public Shell(IList<ToolPanel> tools, string startKey)
        {
            string exeDir = Path.GetDirectoryName(Application.ExecutablePath); Settings = new Settings(Path.Combine(exeDir, "settings.ini"));
            IsElevated = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
            using (Graphics g = CreateGraphics()) Theme.Dpi = g.DpiX / 96f;
            Text = "PowerTower" + (IsElevated ? "  ·  administrator" : ""); BackColor = Theme.Bg; ForeColor = Theme.Ink; Font = Theme.UI; Icon = AppIcon();
            Rectangle wa = Screen.PrimaryScreen.WorkingArea; Width = Math.Min(int.Parse(Settings.Get("win.w", Theme.S(1280).ToString())), wa.Width); Height = Math.Min(int.Parse(Settings.Get("win.h", Theme.S(820).ToString())), wa.Height);   /* never taller or wider than the work area (PT-17) */ MinimumSize = new Size(Theme.S(980), Theme.S(640)); StartPosition = FormStartPosition.CenterScreen;
            if (Settings.Get("win.max", "0") == "1") WindowState = FormWindowState.Maximized;
            side.Dock = DockStyle.Left; side.Width = Theme.S(250); side.BackColor = Theme.Side;
            Panel brand = new Panel(); brand.Dock = DockStyle.Top; brand.Height = Theme.S(66); brand.BackColor = Theme.Side;
            Label bTitle = Theme.Lbl("▌ POWERTOWER", Theme.Teal, Theme.UIBold); bTitle.Location = new Point(Theme.S(14), Theme.S(14)); Label bSub = Theme.Lbl("portable security workbench", Theme.Faint, Theme.UISmall); bSub.Location = new Point(Theme.S(16), Theme.S(36)); brand.Controls.Add(bTitle); brand.Controls.Add(bSub);
            list.Dock = DockStyle.Fill; list.BackColor = Theme.Side; list.AutoScroll = true;
            // sidebar rows in display order: a collapsible group heading before the first tool of each group (remembered), then the tools; Home has no group
            List<Control> rows = new List<Control>(); string grp = null; HashSet<string> collapsed = new HashSet<string>(Settings.Get("side.collapsed", "").Split('|'));
            foreach (ToolPanel tp in tools)
            {
                tp.Host = this; panels.Add(tp); ToolInfo ti = Tools.ByPanel(tp.GetType().Name); string g = ti == null ? "" : ti.Group;
                if (g.Length > 0 && g != grp) { SideHeader h = new SideHeader(g, !collapsed.Contains(g)); h.Toggled += delegate { SaveCollapsed(); LayoutSide(); }; headers.Add(h); rows.Add(h); grp = g; }
                SideItem si = new SideItem(tp, ti); si.Picked += Select; si.Moved += SelectAdjacent; items.Add(si); rows.Add(si); if (g.Length > 0) { headers[headers.Count - 1].Items.Add(si); si.Visible = !collapsed.Contains(g); }
            }
            foreach (Control c in rows) { c.Dock = DockStyle.None; list.Controls.Add(c); } sideRows.AddRange(rows); list.Resize += delegate { LayoutSide(); }; LayoutSide();   // explicit positions: docking inside an AutoScroll panel drifts once it scrolls
            Panel foot = new Panel(); foot.Dock = DockStyle.Bottom; foot.Height = Theme.S(100); foot.BackColor = Theme.Side; foot.Padding = new Padding(Theme.S(12), Theme.S(8), Theme.S(12), Theme.S(10));
            Button bElev = Theme.Btn("Restart as administrator", false); bElev.Dock = DockStyle.Fill; bElev.AutoSize = false; bElev.Visible = !IsElevated; bElev.Click += delegate { RestartElevated(); };
            Label elevOk = Theme.Lbl("● running as administrator", Theme.Green, Theme.UISmall); elevOk.Dock = DockStyle.Fill; elevOk.Visible = IsElevated; elevOk.TextAlign = ContentAlignment.MiddleLeft; elevOk.AutoSize = false;
            foot.Controls.Add(bElev); foot.Controls.Add(elevOk);
            Panel gap = new Panel(); gap.Dock = DockStyle.Top; gap.Height = Theme.S(6); gap.BackColor = Theme.Side; foot.Controls.Add(gap);
            ComboBox cTheme = Theme.Combo(200, Theme.Names); cTheme.Dock = DockStyle.Top; cTheme.SelectedItem = Theme.Current; foot.Controls.Add(cTheme);
            Label lTheme = Theme.Cap("theme"); lTheme.Dock = DockStyle.Top; lTheme.AutoSize = false; lTheme.Height = Theme.S(18); lTheme.Padding = new Padding(0); foot.Controls.Add(lTheme);
            cTheme.SelectedIndexChanged += delegate { string n = cTheme.SelectedItem as string; if (n == null || n == Theme.Current) return; Dictionary<int, Color> map = Theme.Apply(n); Settings.Set("theme", n); Settings.Save(); Retheme(map); Toast("Theme: " + n, false); };
            side.Controls.Add(list); side.Controls.Add(foot); side.Controls.Add(brand); list.BringToFront();
            head.Dock = DockStyle.Top; head.Height = Theme.S(100); head.BackColor = Theme.Bg;
            hIcon.Location = new Point(Theme.S(18), Theme.S(15)); hIcon.Size = new Size(Theme.S(26), Theme.S(26)); hIcon.BackColor = Theme.Bg; hIcon.Paint += delegate (object s, PaintEventArgs e) { Icons.Paint(e.Graphics, iconKey, new Rectangle(0, 0, hIcon.Width, hIcon.Height), Theme.Teal); }; hTitle.Location = new Point(Theme.S(52), Theme.S(12));
            hBlurb.AutoSize = false; hBlurb.AutoEllipsis = true; hBlurb.Location = new Point(Theme.S(20), Theme.S(42)); hBlurb.Height = Theme.S(36); hBlurb.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            hAdmin.Location = new Point(Theme.S(20), Theme.S(78)); toast.Anchor = AnchorStyles.Top | AnchorStyles.Right; toast.Location = new Point(Theme.S(600), Theme.S(18)); toast.AutoSize = true;
            head.Resize += delegate { hBlurb.Width = Math.Max(Theme.S(200), head.Width - Theme.S(40)); if (toast.Text.Length > 0) toast.Left = head.Width - toast.Width - Theme.S(20); };
            head.Controls.Add(hIcon); head.Controls.Add(hTitle); head.Controls.Add(hBlurb); head.Controls.Add(hAdmin); head.Controls.Add(toast);
            toastTimer.Interval = 6000; toastTimer.Tick += delegate { toast.Text = ""; toastTimer.Stop(); };
            host.Dock = DockStyle.Fill; host.BackColor = Theme.Panel; host.Padding = new Padding(0);
            // a persistent status strip: the last message stays until the next one (the header toast fades), plus the keys that work everywhere
            statusBar.Dock = DockStyle.Bottom; statusBar.Height = Theme.S(26); statusBar.BackColor = Theme.Side; sLeft.Location = new Point(Theme.S(12), Theme.S(5)); sLeft.AutoEllipsis = true; sRight.Location = new Point(Theme.S(600), Theme.S(5)); sRight.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            sRight.Text = "F5 run   \u00b7   Esc cancel   \u00b7   Ctrl+F search   \u00b7   Ctrl+E export CSV   \u00b7   Ctrl+\u2191\u2193 switch tool"; statusBar.Controls.Add(sLeft); statusBar.Controls.Add(sRight); statusBar.Resize += delegate { sRight.Left = statusBar.Width - sRight.Width - Theme.S(12); sLeft.MaximumSize = new Size(Math.Max(100, statusBar.Width - sRight.Width - Theme.S(40)), 0); };
            KeyPreview = true;
            Controls.Add(host); Controls.Add(statusBar); Controls.Add(head); Controls.Add(side); host.BringToFront();
            FormClosing += delegate { Settings.Set("win.w", Width.ToString()); Settings.Set("win.h", Height.ToString()); Settings.Set("win.max", WindowState == FormWindowState.Maximized ? "1" : "0"); Settings.Save(); foreach (ToolPanel p in panels) { try { p.OnHidden(); } catch { } } };
            ToolPanel first = panels[0]; foreach (ToolPanel p in panels) if (p.GetType().Name.ToLowerInvariant().StartsWith(startKey.ToLowerInvariant()) && startKey.Length > 0) first = p;
            Load += delegate { Select(first); if (SelfTestFile != null) RunSelfTest(); else if (ShotDir != null) RunShots(); };
        }
        void Select(ToolPanel p)
        {
            if (current == p) return;
            if (current != null) { current.OnHidden(); host.Controls.Remove(current); }
            current = p; foreach (SideItem si in items) { si.Selected = si.Panel == p; if (si.Selected && si.Visible) list.ScrollControlIntoView(si); } toast.Text = ""; toastTimer.Stop();
            iconKey = p.GetType().Name; hIcon.Invalidate(); hTitle.Text = p.Title; hBlurb.Text = p.Blurb;
            // one line under the blurb says what the tool can do beyond reading, and whether it wants administrator rights
            ToolInfo ti = Tools.ByPanel(p.GetType().Name); bool ro = ti == null || ti.ReadOnly; string fx = ro ? "\u25cf  read-only" : ti.Effects;
            string admin = p.NeedsAdmin ? (IsElevated ? "administrator: yes" : "some actions need administrator rights - use Restart as administrator") : "";
            hAdmin.Text = fx + (admin.Length > 0 ? "     \u00b7     " + admin : ""); hAdmin.ForeColor = (p.NeedsAdmin && !IsElevated) || (ti != null && (ti.Writes.Length > 0 || ti.Caution.Length > 0)) ? Theme.Amber : ro ? Theme.Green : Theme.Blue;
            sLeft.Text = p.Title + (ro ? "  \u00b7  read-only" : ""); sLeft.ForeColor = Theme.Dim;
            p.Dock = DockStyle.Fill; host.Controls.Add(p); if (!Program.DemoMode) p.OnShown(); p.Focus();
        }
        /// <summary>Re-tint every control (visible or not) from the old palette to the new one, then repaint.</summary>
        public void Retheme(Dictionary<int, Color> map)
        {
            Walk(this, map, host); foreach (ToolPanel p in panels) Walk(p, map, null); Invalidate(true);
        }
        static void Walk(Control c, Dictionary<int, Color> map, Control skip)
        {
            Color nc;
            if (map.TryGetValue(c.BackColor.ToArgb(), out nc)) c.BackColor = nc;
            if (map.TryGetValue(c.ForeColor.ToArgb(), out nc)) c.ForeColor = nc;
            Button b = c as Button;
            if (b != null) { if (map.TryGetValue(b.FlatAppearance.BorderColor.ToArgb(), out nc)) b.FlatAppearance.BorderColor = nc; if (map.TryGetValue(b.FlatAppearance.MouseOverBackColor.ToArgb(), out nc)) b.FlatAppearance.MouseOverBackColor = nc; if (map.TryGetValue(b.FlatAppearance.MouseDownBackColor.ToArgb(), out nc)) b.FlatAppearance.MouseDownBackColor = nc; }
            DataView dv = c as DataView; if (dv != null) dv.Retheme();
            foreach (Control k in c.Controls) { if (k == skip) continue; Walk(k, map, skip); }
            c.Invalidate();
        }
        public void Toast(string msg, bool warn) { toast.Text = msg; toast.ForeColor = warn ? Theme.Amber : Theme.Teal; toast.Left = head.Width - toast.Width - Theme.S(20); toastTimer.Stop(); toastTimer.Start(); sLeft.Text = msg; sLeft.ForeColor = warn ? Theme.Amber : Theme.Dim; }
        /// <summary>Stacks the visible sidebar rows from the top and sizes the scroll range to them.</summary>
        void LayoutSide() { int y = 0, w = list.ClientSize.Width; Point sp = list.AutoScrollPosition; foreach (Control c in sideRows) { if (!c.Visible) continue; c.SetBounds(sp.X, y + sp.Y, w, c.Height); y += c.Height; } list.AutoScrollMinSize = new Size(0, y); }
        void SaveCollapsed() { List<string> c = new List<string>(); foreach (SideHeader h in headers) if (!h.Open) c.Add(h.Group); Settings.Set("side.collapsed", string.Join("|", c.ToArray())); Settings.Save(); }
        /// <summary>Move to the previous or next visible tool in the sidebar (Ctrl+Up / Ctrl+Down, or the arrow keys on a sidebar row).</summary>
        public void SelectAdjacent(int dir)
        {
            int i = -1; for (int k = 0; k < items.Count; k++) if (items[k].Panel == current) i = k;
            for (int k = i + dir; k >= 0 && k < items.Count; k += dir) if (items[k].Visible) { Select(items[k].Panel); items[k].Focus(); return; }
        }
        /// <summary>The keys that work on every tool: F5 runs it, Esc cancels a running scan, Ctrl+F searches, Ctrl+E exports the CSV, Ctrl+Up/Down switch tools. Buttons opt in by Tag ("run" / "stop").</summary>
        protected override bool ProcessCmdKey(ref Message msg, Keys keyData)
        {
            if (current != null)
            {
                if (keyData == Keys.F5 && ClickTagged(current, "run")) return true;
                if (keyData == Keys.Escape && ClickTagged(current, "stop")) return true;
                if (keyData == (Keys.Control | Keys.F)) { DataView v = FirstView(current); if (v != null) { v.FocusSearch(); return true; } }
                if (keyData == (Keys.Control | Keys.E)) { DataView v = FirstView(current); if (v != null) { v.Export(); return true; } }
                if (keyData == (Keys.Control | Keys.Up)) { SelectAdjacent(-1); return true; }
                if (keyData == (Keys.Control | Keys.Down)) { SelectAdjacent(1); return true; }
            }
            return base.ProcessCmdKey(ref msg, keyData);
        }
        static bool ClickTagged(Control c, string tag) { Button b = c as Button; if (b != null) { if ((b.Tag as string) == tag && b.Enabled && b.Visible) { b.PerformClick(); return true; } return false; } foreach (Control k in c.Controls) if (ClickTagged(k, tag)) return true; return false; }
        static DataView FirstView(Control c) { DataView v = c as DataView; if (v != null) return v; foreach (Control k in c.Controls) { DataView r = FirstView(k); if (r != null) return r; } return null; }
        public bool Confirm(string title, string text) { return MessageBox.Show(this, text, title, MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes; }
        public void Info(string title, string text) { MessageBox.Show(this, text, title, MessageBoxButtons.OK, MessageBoxIcon.Information); }
        public void Error(string title, string text) { MessageBox.Show(this, text, title, MessageBoxButtons.OK, MessageBoxIcon.Error); }
        /// <summary>True when the caller should stop: not elevated, and the user chose to restart (or not).</summary>
        public bool NeedAdmin(string what)
        {
            if (IsElevated) return false;
            if (MessageBox.Show(this, what + " needs administrator rights.\n\nRestart PowerTower as administrator now? Windows will ask to confirm.", "Administrator needed", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.Yes) RestartElevated();
            return true;
        }
        public void RestartElevated()
        {
            try { Settings.Save(); ProcessStartInfo si = new ProcessStartInfo(Application.ExecutablePath, "--tool " + (current != null ? current.GetType().Name : "")); si.UseShellExecute = true; si.Verb = "runas"; Process.Start(si); Application.Exit(); }
            catch { Toast("Elevation was cancelled.", true); }
        }
        public void ShowTool<T>(Action<T> then) where T : ToolPanel { foreach (ToolPanel p in panels) if (p is T) { Select(p); if (then != null) then((T)p); return; } }
        /// <summary>Open a tool by its panel class name (the Home page and --tool use this).</summary>
        public void ShowTool(string panelClass) { foreach (ToolPanel p in panels) if (p.GetType().Name == panelClass) { Select(p); return; } }
        /// <summary>The instance of a tool panel, so one tool can read another's collected state (e.g. the map reading the vuln findings). Null if not present.</summary>
        public T Panel<T>() where T : ToolPanel { foreach (ToolPanel p in panels) if (p is T) return (T)p; return null; }
        void RunSelfTest()
        {
            StringBuilder sb = new StringBuilder(); sb.AppendLine("PowerTower self-test · " + DateTime.Now.ToString("s") + " · elevated=" + IsElevated);
            Program.OnCrash = delegate (Exception ex) { sb.AppendLine("FAIL ui: unhandled exception in " + (current == null ? "?" : current.Title) + ": " + ex); };
            foreach (ToolPanel p in panels)
            {
                Select(p); Application.DoEvents();
                try { p.SelfTest(sb); } catch (Exception ex) { sb.AppendLine("FAIL " + p.Title + ": " + ex); } Application.DoEvents();
                try { p.Exercise(sb); } catch (Exception ex) { sb.AppendLine("FAIL ui " + p.Title + ": " + ex); } Application.DoEvents();
            }
            Program.OnCrash = null;
            File.WriteAllText(SelfTestFile, sb.ToString(), new UTF8Encoding(true)); Close();
        }
        void RunShots()
        {
            Program.DemoMode = true; System.Windows.Forms.Timer t = new System.Windows.Forms.Timer(); t.Interval = 900; int idx = panels.Count - 1;
            t.Tick += delegate
            {
                if (idx < 0) { t.Stop(); Close(); return; }
                ToolPanel p = panels[idx]; Select(p); Application.DoEvents();
                try { p.SelfTest(null); } catch { }
                Application.DoEvents();
                using (Bitmap b = new Bitmap(Width, Height)) { DrawToBitmap(b, new Rectangle(0, 0, Width, Height)); b.Save(Path.Combine(ShotDir, "shot-" + p.GetType().Name + ".png"), System.Drawing.Imaging.ImageFormat.Png); }
                idx--;
            };
            t.Start();
        }
        static Icon AppIcon()
        {
            try { using (Bitmap bmp = new Bitmap(32, 32)) using (Graphics g = Graphics.FromImage(bmp)) { g.SmoothingMode = SmoothingMode.AntiAlias; g.Clear(Color.Transparent); using (Brush b = new SolidBrush(Theme.Side)) g.FillEllipse(b, 1, 1, 30, 30); using (Pen p = new Pen(Theme.Teal, 2.5f)) { g.DrawEllipse(p, 2, 2, 28, 28); g.DrawLine(p, 10, 22, 16, 10); g.DrawLine(p, 16, 10, 22, 22); } return Icon.FromHandle(bmp.GetHicon()); } }
            catch { return null; }
        }
    }

    /// <summary>One sidebar row: the tool's icon and title; the blurb is the tooltip.</summary>
    class SideItem : Panel
    {
        public readonly ToolPanel Panel; readonly ToolInfo info; bool selected, hover; public event Action<ToolPanel> Picked; public event Action<int> Moved;
        public SideItem(ToolPanel p, ToolInfo info) { Panel = p; this.info = info; Height = Theme.S(32); Cursor = Cursors.Hand; SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint | ControlStyles.Selectable, true); TabStop = true; Text = p.Title; AccessibleName = p.Title; AccessibleRole = AccessibleRole.PushButton; Name = "side_" + p.GetType().Name; GotFocus += delegate { Invalidate(); }; LostFocus += delegate { Invalidate(); }; KeyDown += delegate (object s, KeyEventArgs e) { if (e.KeyCode == Keys.Enter || e.KeyCode == Keys.Space) { e.Handled = true; if (Picked != null) Picked(Panel); } else if (e.KeyCode == Keys.Up || e.KeyCode == Keys.Down) { e.Handled = true; if (Moved != null) Moved(e.KeyCode == Keys.Up ? -1 : 1); } }; MouseEnter += delegate { hover = true; Invalidate(); }; MouseLeave += delegate { hover = false; Invalidate(); }; Click += delegate { if (Picked != null) Picked(Panel); }; new ToolTip().SetToolTip(this, p.Blurb + (info != null && !info.ReadOnly ? "\r\n\r\n" + info.Effects : "\r\n\r\nread-only")); }
        public bool Selected { get { return selected; } set { selected = value; Invalidate(); } }
        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics; g.Clear(selected ? Theme.Panel2 : (hover ? Theme.Panel : Theme.Side));
            if (selected) using (Brush b = new SolidBrush(Theme.Teal)) g.FillRectangle(b, 0, 0, 3, Height);
            if (Focused) using (Pen fp = new Pen(Theme.Teal)) g.DrawRectangle(fp, 1, 1, Width - 3, Height - 3);
            int ic = Theme.S(20); Icons.Paint(g, Panel.GetType().Name, new Rectangle(Theme.S(14), (Height - ic) / 2, ic, ic), selected || hover ? Theme.Teal : Theme.TealSoft);
            TextRenderer.DrawText(g, Panel.Title, selected ? Theme.UIBold : Theme.UI, new Rectangle(Theme.S(44), 0, Width - Theme.S(70), Height), Theme.Ink, TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);
            // a dot on the right marks a tool that can change this machine or show secrets (amber) or that uses the network (blue); read-only tools have none
            if (info != null && !info.ReadOnly) { int d = Theme.S(7); using (Brush b = new SolidBrush(info.Writes.Length > 0 || info.Caution.Length > 0 ? Theme.Amber : Theme.Blue)) g.FillEllipse(b, Width - Theme.S(20), (Height - d) / 2, d, d); }
            using (Pen p = new Pen(Theme.Line)) g.DrawLine(p, 0, Height - 1, Width, Height - 1);
        }
    }

    /// <summary>A sidebar group heading. Click it to fold or unfold the tools under it; the state is remembered in settings.ini.</summary>
    class SideHeader : Panel
    {
        public readonly string Group; public bool Open; public readonly List<SideItem> Items = new List<SideItem>(); public event Action Toggled;
        public SideHeader(string group, bool open) { Group = group; Open = open; Height = Theme.S(26); Cursor = Cursors.Hand; SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint, true); Name = "group_" + group; AccessibleName = group; Click += delegate { Toggle(); }; }
        public void Toggle() { Open = !Open; foreach (SideItem i in Items) i.Visible = Open; Invalidate(); if (Toggled != null) Toggled(); }
        protected override void OnPaint(PaintEventArgs e)
        {
            Graphics g = e.Graphics; g.Clear(Theme.Side);
            TextRenderer.DrawText(g, (Open ? "\u25be  " : "\u25b8  ") + Group.Replace("incident response", "IR").ToUpperInvariant(), Theme.UISmall, new Rectangle(Theme.S(14), Theme.S(4), Width - Theme.S(18), Height - Theme.S(4)), Theme.Faint, TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);
        }
    }

    /// <summary>The tool icons: simple line drawings in one colour, drawn in code so nothing external is needed. Keyed by the panel class name.</summary>
    public static class Icons
    {
        public static void Paint(Graphics g, string key, Rectangle r, Color c)
        {
            if (r.Width < 4 || r.Height < 4) return;
            SmoothingMode sm = g.SmoothingMode; g.SmoothingMode = SmoothingMode.AntiAlias;
            float s = Math.Min(r.Width, r.Height) / 24f; float ox = r.X + (r.Width - 24 * s) / 2, oy = r.Y + (r.Height - 24 * s) / 2;
            Func<float, float> X = delegate (float v) { return ox + v * s; }; Func<float, float> Y = delegate (float v) { return oy + v * s; };
            using (Pen p = new Pen(c, Math.Max(1.2f, 1.9f * s))) using (Brush b = new SolidBrush(c)) using (Brush soft = new SolidBrush(Color.FromArgb(70, c)))
            {
                p.StartCap = LineCap.Round; p.EndCap = LineCap.Round; p.LineJoin = LineJoin.Round;
                Action<float, float, float, float> L = delegate (float x1, float y1, float x2, float y2) { g.DrawLine(p, X(x1), Y(y1), X(x2), Y(y2)); };
                Action<float, float, float> C = delegate (float cx, float cy, float rad) { g.DrawEllipse(p, X(cx - rad), Y(cy - rad), 2 * rad * s, 2 * rad * s); };
                Action<float, float, float> D = delegate (float cx, float cy, float rad) { g.FillEllipse(b, X(cx - rad), Y(cy - rad), 2 * rad * s, 2 * rad * s); };
                Action<float[]> P = delegate (float[] pts) { PointF[] q = new PointF[pts.Length / 2]; for (int i = 0; i < q.Length; i++) q[i] = new PointF(X(pts[2 * i]), Y(pts[2 * i + 1])); g.DrawPolygon(p, q); };
                Action<float[]> PF = delegate (float[] pts) { PointF[] q = new PointF[pts.Length / 2]; for (int i = 0; i < q.Length; i++) q[i] = new PointF(X(pts[2 * i]), Y(pts[2 * i + 1])); g.FillPolygon(b, q); };
                // Findings-map nodes reuse the sidebar glyphs where a tool matches, so the map reads like the app.
                if (key.Length > 4 && key[0] == 'm' && key[1] == 'a' && key[2] == 'p' && key[3] == ':')
                {
                    switch (key)
                    {
                        case "map:firewall": key = "FirewallPanel"; break;
                        case "map:browser": case "map:site": key = "BrowserPanel"; break;
                        case "map:vuln": key = "VulnPanel"; break;
                        case "map:checklist": key = "ChecklistPanel"; break;
                        case "map:events": case "map:event": key = "EventsPanel"; break;
                        case "map:autoruns": case "map:autorun": key = "AutorunsPanel"; break;
                        case "map:network": case "map:ip": key = "NetMapPanel"; break;
                        case "map:software": case "map:program": key = "SoftwarePanel"; break;
                    }
                }
                switch (key)
                {
                    case "map:host": g.DrawRectangle(p, X(3.5f), Y(4.5f), 17 * s, 11 * s); L(12, 15.5f, 12, 18.5f); L(8, 19.5f, 16, 19.5f); L(6, 7.5f, 9.5f, 7.5f); break;
                    case "map:system": g.DrawRectangle(p, X(7), Y(7), 10 * s, 10 * s); g.DrawRectangle(p, X(10), Y(10), 4 * s, 4 * s); L(9.5f, 4, 9.5f, 7); L(14.5f, 4, 14.5f, 7); L(9.5f, 17, 9.5f, 20); L(14.5f, 17, 14.5f, 20); L(4, 9.5f, 7, 9.5f); L(4, 14.5f, 7, 14.5f); L(17, 9.5f, 20, 9.5f); L(17, 14.5f, 20, 14.5f); break;
                    case "map:users": C(9, 9, 3); g.DrawArc(p, X(4), Y(12.5f), 10 * s, 9 * s, 180, 180); C(16, 8, 2.4f); g.DrawArc(p, X(13.5f), Y(11.5f), 8 * s, 8 * s, 200, 140); break;
                    case "map:user": C(12, 8, 3.1f); g.DrawArc(p, X(5.5f), Y(12.5f), 13 * s, 11 * s, 180, 180); break;
                    case "map:port": g.DrawRectangle(p, X(6), Y(9), 12 * s, 8 * s); L(9, 9, 9, 5.5f); L(15, 9, 15, 5.5f); L(11, 17, 11, 20); L(13, 17, 13, 20); break;
                    case "map:wifi": g.DrawArc(p, X(4), Y(6), 16 * s, 16 * s, 210, 120); g.DrawArc(p, X(7), Y(9), 10 * s, 10 * s, 210, 120); D(12, 17, 1.5f); break;
                    case "map:check": L(5, 12.5f, 10, 17.5f); L(10, 17.5f, 19, 6.5f); break;
                    case "map:warn": P(new float[] { 12, 4, 21, 20, 3, 20 }); L(12, 10, 12, 15); D(12, 17.6f, 1.1f); break;
                    case "map:fail": L(6.5f, 6.5f, 17.5f, 17.5f); L(17.5f, 6.5f, 6.5f, 17.5f); break;
                    case "map:cve": C(12, 12, 4.5f); L(12, 3.5f, 12, 7.5f); L(12, 16.5f, 12, 20.5f); L(3.5f, 12, 7.5f, 12); L(16.5f, 12, 20.5f, 12); L(6, 6, 8.6f, 8.6f); L(15.4f, 15.4f, 18, 18); L(18, 6, 15.4f, 8.6f); L(8.6f, 15.4f, 6, 18); break;
                    case "map:generic": D(12, 12, 2.4f); break;
                    case "ReconPanel": P(new float[] { 5, 4, 19, 4, 19, 22, 5, 22 }); g.FillRectangle(b, X(9), Y(2.5f), 6 * s, 3 * s); L(8, 10, 16, 10); L(8, 14, 16, 14); L(8, 18, 13, 18); break;
                    case "BlockerPanel": C(12, 12, 8.5f); L(6, 6, 18, 18); break;
                    case "ReachPanel": C(12, 12, 9); C(12, 12, 5.2f); D(12, 12, 1.8f); break;
                    case "ConnPanel": L(4.5f, 18, 12, 6); L(12, 6, 19.5f, 18); L(4.5f, 18, 19.5f, 18); D(4.5f, 18, 2.2f); D(12, 6, 2.2f); D(19.5f, 18, 2.2f); break;
                    case "HogsPanel": g.DrawArc(p, X(3), Y(5), 18 * s, 18 * s, 180, 180); L(12, 14, 16.5f, 7.5f); D(12, 14, 1.8f); L(3, 14, 21, 14); break;
                    case "DiskPanel": C(12, 12, 9); L(12, 12, 12, 3); L(12, 12, 20.5f, 9); g.FillPie(soft, X(3), Y(3), 18 * s, 18 * s, -90, 71); break;
                    case "DeletedPanel": L(5, 6.5f, 19, 6.5f); L(10, 4, 14, 4); P(new float[] { 7, 6.5f, 17, 6.5f, 16, 21, 8, 21 }); L(10.5f, 10, 10.5f, 18); L(13.5f, 10, 13.5f, 18); break;
                    case "FileExplorerPanel": P(new float[] { 3, 5.5f, 9.5f, 5.5f, 11.5f, 8, 21, 8, 21, 19.5f, 3, 19.5f }); L(3, 11, 21, 11); break;
                    case "FindPanel": C(10, 10, 6.2f); L(14.8f, 14.8f, 21, 21); break;
                    case "DupesPanel": g.DrawRectangle(p, X(3.5f), Y(3.5f), 12 * s, 12 * s); g.FillRectangle(soft, X(8.5f), Y(8.5f), 12 * s, 12 * s); g.DrawRectangle(p, X(8.5f), Y(8.5f), 12 * s, 12 * s); break;
                    case "SecretsPanel": C(8, 8, 4.5f); L(11.3f, 11.3f, 20.5f, 20.5f); L(16, 16, 18.5f, 13.5f); L(18.7f, 18.7f, 21.2f, 16.2f); break;
                    case "VulnPanel": P(new float[] { 12, 2.5f, 20, 5.5f, 20, 12, 12, 21.5f, 4, 12, 4, 5.5f }); L(12, 8, 12, 13); D(12, 16.5f, 1.3f); break;
                    case "SoftwarePanel": P(new float[] { 12, 3, 20, 7.5f, 20, 16.5f, 12, 21, 4, 16.5f, 4, 7.5f }); L(4, 7.5f, 12, 12); L(12, 12, 20, 7.5f); L(12, 12, 12, 21); break;
                    case "AutorunsPanel": C(12, 12, 9); g.FillPolygon(b, new PointF[] { new PointF(X(9.5f), Y(7.5f)), new PointF(X(17.5f), Y(12)), new PointF(X(9.5f), Y(16.5f)) }); break;
                    case "EventsPanel": C(12, 12, 9); L(12, 12, 12, 6.5f); L(12, 12, 16, 14.5f); break;
                    case "FirewallPanel": g.DrawRectangle(p, X(3), Y(5), 18 * s, 14 * s); L(3, 9.7f, 21, 9.7f); L(3, 14.3f, 21, 14.3f); L(12, 5, 12, 9.7f); L(7.5f, 9.7f, 7.5f, 14.3f); L(16.5f, 9.7f, 16.5f, 14.3f); L(12, 14.3f, 12, 19); break;
                    case "CredsPanel": g.DrawArc(p, X(7.5f), Y(3), 9 * s, 10 * s, 180, 180); g.DrawRectangle(p, X(5), Y(11), 14 * s, 10 * s); D(12, 16, 1.6f); break;
                    case "ChecklistPanel": g.DrawRectangle(p, X(4), Y(4), 5 * s, 5 * s); L(5.2f, 6.6f, 6.6f, 8); L(6.6f, 8, 8.3f, 5.3f); L(12, 6.5f, 20, 6.5f); g.DrawRectangle(p, X(4), Y(11.5f), 5 * s, 5 * s); L(5.2f, 14.1f, 6.6f, 15.5f); L(6.6f, 15.5f, 8.3f, 12.8f); L(12, 14, 20, 14); L(12, 20.5f, 20, 20.5f); break;
                    case "NetMapPanel": C(12, 12, 9); D(12, 12, 1.8f); D(5.5f, 7, 1.5f); D(19, 8, 1.5f); D(15.5f, 18.5f, 1.5f); L(12, 12, 5.5f, 7); L(12, 12, 19, 8); L(12, 12, 15.5f, 18.5f); break;
                    case "BrowserPanel": C(12, 12, 9); g.DrawEllipse(p, X(7.5f), Y(3), 9 * s, 18 * s); L(3, 12, 21, 12); L(5, 7.5f, 19, 7.5f); L(5, 16.5f, 19, 16.5f); break;
                    case "MapPanel": L(12, 12, 4.5f, 5); L(12, 12, 19.5f, 5); L(12, 12, 12, 20.5f); D(12, 12, 3); D(4.5f, 5, 2); D(19.5f, 5, 2); D(12, 20.5f, 2); break;
                    case "AboutPanel": C(12, 12, 9); D(12, 8, 1.3f); L(12, 11.5f, 12, 17); break;
                    default: C(12, 12, 8); break;
                }
            }
            g.SmoothingMode = sm;
        }
    }

}

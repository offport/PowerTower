// PowerTowerCli.exe: the PowerTower tools from the command line, with the desktop app's grammar - the same
// tool names in the same order, the same columns, and the same view bar: grid / details / tree, search,
// sort, filter rules, tick rows (--select) and act on them, export CSV. The engines and the column
// definitions are the very files the app compiles; only the rendering here is console-specific.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Principal;
using System.Text;
using System.Threading;

namespace PSTools
{
    /// <summary>One command-line option: --name, the placeholder of its value (null for a flag), and its help line.</summary>
    public class Opt
    {
        public string Name, Value, Help; public bool Flag { get { return Value == null; } }
        public Opt(string name, string value, string help) { Name = name; Value = value; Help = help; }
    }

    /// <summary>The parsed command line: the tool, then --options (repeatable, --name value or --name=value) and positionals.</summary>
    public class Args
    {
        public string Tool = ""; public readonly List<string> Positional = new List<string>(); public readonly List<string> Unknown = new List<string>();
        readonly Dictionary<string, List<string>> opts = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        public Args(string[] argv, IList<Opt> known)
        {
            Dictionary<string, Opt> map = new Dictionary<string, Opt>(StringComparer.OrdinalIgnoreCase); foreach (Opt o in known) map[o.Name] = o;
            int i = 0; if (argv.Length > 0 && !argv[0].StartsWith("-")) { Tool = argv[0]; i = 1; }
            for (; i < argv.Length; i++)
            {
                string a = argv[i];
                if (a == "--") { for (i++; i < argv.Length; i++) Positional.Add(argv[i]); break; }
                if (!a.StartsWith("-") || a.Length < 2) { Positional.Add(a); continue; }
                string name = a.TrimStart('-'), val = null; int eq = name.IndexOf('='); if (eq > 0) { val = name.Substring(eq + 1); name = name.Substring(0, eq); }
                if (name == "h" || name == "?") name = "help";
                Opt o; if (!map.TryGetValue(name, out o)) { Unknown.Add(a); continue; }
                if (o.Flag) val = "true"; else if (val == null) { if (i + 1 < argv.Length) val = argv[++i]; else val = ""; }
                List<string> l; if (!opts.TryGetValue(o.Name, out l)) opts[o.Name] = l = new List<string>(); l.Add(val);
            }
            if (Tool.Length == 0 && Positional.Count > 0) { Tool = Positional[0]; Positional.RemoveAt(0); }   // "PowerTowerCli --no-color firewall" works too
        }
        public bool Has(string name) { return opts.ContainsKey(name); }
        public string Get(string name, string def) { List<string> l; return opts.TryGetValue(name, out l) && l.Count > 0 ? l[l.Count - 1] : def; }
        public List<string> All(string name) { List<string> l; return opts.TryGetValue(name, out l) ? new List<string>(l) : new List<string>(); }
        public int Int(string name, int def) { int v; return int.TryParse(Get(name, ""), out v) ? v : def; }
        public double Dbl(string name, double def) { double v; return double.TryParse(Get(name, ""), NumberStyles.Float, CultureInfo.InvariantCulture, out v) ? v : def; }
        /// <summary>A value that must be one of a fixed set (the app's combo boxes); exits with a usage error otherwise.</summary>
        public string Choice(string name, string def, params string[] allowed)
        {
            string v = Get(name, def); foreach (string a in allowed) if (string.Equals(a, v, StringComparison.OrdinalIgnoreCase)) return a;
            throw new UsageException("--" + name + " must be one of: " + string.Join(", ", allowed) + " (got '" + v + "')");
        }
    }
    public class UsageException : Exception { public UsageException(string m) : base(m) { } }

    /// <summary>Console output. Tones become console colours; tables go to stdout, progress and notes to stderr, so output can be piped.</summary>
    public static class Out
    {
        public static bool Color = true; public static int Width; public static bool Quiet;
        static readonly object gate = new object(); static bool lastWasProgress;
        public static ConsoleColor Of(Tone t)
        {
            switch (t) { case Tone.Dim: return ConsoleColor.DarkGray; case Tone.Faint: return ConsoleColor.DarkGray; case Tone.Accent: return ConsoleColor.Cyan; case Tone.Good: return ConsoleColor.Green; case Tone.Warn: return ConsoleColor.Yellow; case Tone.Bad: return ConsoleColor.Red; case Tone.Info: return ConsoleColor.DarkCyan; default: return ConsoleColor.Gray; }
        }
        public static void Write(string s, Tone t)
        {
            EndProgress();
            if (!Color || t == Tone.Normal) { Console.Write(s); return; }
            ConsoleColor c = Console.ForegroundColor; try { Console.ForegroundColor = Of(t); Console.Write(s); } finally { Console.ForegroundColor = c; }
        }
        public static void Line(string s) { EndProgress(); Console.WriteLine(s); }
        public static void Line(string s, Tone t) { Write(s, t); Console.WriteLine(); }
        public static void Blank() { EndProgress(); Console.WriteLine(); }
        /// <summary>The tool header the app shows above every panel: title, the administrator note, the blurb.</summary>
        public static void Header(ToolInfo t)
        {
            Line("▌ " + t.Title.ToUpperInvariant(), Tone.Accent);
            if (t.NeedsAdmin) Line(Cli.IsElevated ? "  administrator: yes" : "  some actions here need administrator rights - run from an elevated prompt", Cli.IsElevated ? Tone.Dim : Tone.Warn);
            Line(Wrap(t.Blurb, ConsoleWidth() - 2, "  "), Tone.Dim);
            Blank();
        }
        /// <summary>The summary cards above a table: KEY value pairs on one line.</summary>
        public static void Cards(params object[] kv)
        {
            EndProgress(); bool first = true;
            for (int i = 0; i + 1 < kv.Length; i += 2)
            {
                if (!first) Write("  ·  ", Tone.Faint); first = false;
                Write(kv[i].ToString().ToUpperInvariant() + " ", Tone.Dim);
                object v = kv[i + 1]; Toned tv = v as Toned; if (tv != null) Write(tv.Text, tv.Tone); else Write(v == null ? "" : v.ToString(), Tone.Normal);
            }
            Console.WriteLine();
        }
        public class Toned { public string Text; public Tone Tone; public Toned(string text, Tone tone) { Text = text; Tone = tone; } }
        public static Toned T(string text, Tone tone) { return new Toned(text, tone); }
        // ── stderr: notes, warnings, errors, progress ──
        static void Err(string s, ConsoleColor c)
        {
            lock (gate)
            {
                EndProgress();
                if (Color) { ConsoleColor o = Console.ForegroundColor; try { Console.ForegroundColor = c; Console.Error.WriteLine(s); } finally { Console.ForegroundColor = o; } }
                else Console.Error.WriteLine(s);
            }
        }
        public static void Note(string s) { if (!Quiet) Err(s, ConsoleColor.DarkGray); }
        public static void Warn(string s) { Err(s, ConsoleColor.Yellow); }
        public static void Error(string s) { Err(s, ConsoleColor.Red); }
        public static void Ok(string s) { Err(s, ConsoleColor.Green); }
        /// <summary>A progress line that overwrites itself on an interactive console and is dropped when stderr is a file.</summary>
        public static void Progress(string s)
        {
            if (Quiet) return;
            lock (gate)
            {
                if (Console.IsErrorRedirected) return;
                int w = 0; try { w = Console.WindowWidth - 1; } catch { w = 120; } if (w < 20) w = 120;
                if (s.Length > w) s = s.Substring(0, w - 1) + "…";
                ConsoleColor o = Console.ForegroundColor; try { if (Color) Console.ForegroundColor = ConsoleColor.DarkGray; Console.Error.Write("\r" + s.PadRight(w)); } finally { Console.ForegroundColor = o; }
                lastWasProgress = true;
            }
        }
        static void EndProgress() { if (lastWasProgress) { try { int w = Console.WindowWidth - 1; Console.Error.Write("\r" + new string(' ', Math.Max(1, w)) + "\r"); } catch { Console.Error.WriteLine(); } lastWasProgress = false; } }
        public static int ConsoleWidth()
        {
            if (Width > 0) return Width;
            try { if (!Console.IsOutputRedirected) return Math.Max(60, Console.WindowWidth - 1); } catch { }
            return 160;
        }
        public static string Wrap(string s, int width, string indent)
        {
            if (string.IsNullOrEmpty(s)) return ""; if (width < 20) width = 20; StringBuilder sb = new StringBuilder(); int col = 0; bool first = true;
            foreach (string word in s.Split(' '))
            {
                if (!first && col + 1 + word.Length > width - indent.Length) { sb.Append('\n'); col = 0; first = true; }
                if (col == 0) { sb.Append(indent); } else { sb.Append(' '); col++; }
                sb.Append(word); col += word.Length; first = false;
            }
            return sb.ToString();
        }
        static string Fit(string s, int w, bool right)
        {
            s = (s ?? "").Replace("\r", " ").Replace("\n", " ").Replace("\t", " ");
            if (s.Length > w) s = w > 1 ? s.Substring(0, w - 1) + "…" : s.Substring(0, w);
            return right ? s.PadLeft(w) : s.PadRight(w);
        }

        // ── the three views, rendered the way the app lays them out ──
        static List<Col> Visible(TableDef t) { List<Col> l = new List<Col>(); foreach (Col c in t.Cols) if (!c.Hidden) l.Add(c); return l; }
        static Tone RowTone(TableDef t, object o) { try { if (t.Dimmed != null && t.Dimmed(o)) return Tone.Faint; return t.RowTone != null ? t.RowTone(o) : Tone.Normal; } catch { return Tone.Normal; } }
        static Tone CellTone(TableDef t, Col c, object o) { Tone row = RowTone(t, o); if (row == Tone.Faint) return Tone.Faint; return c.SafeTone(o, row); }
        /// <summary>The grid: one line per row, columns sized from the app's width hints and the actual content, cells toned like the app's cells. Ticked rows carry a mark.</summary>
        public static void Grid(TableDef t, List<object> rows, HashSet<object> selected, int top)
        {
            List<Col> cols = Visible(t); if (cols.Count == 0) return; int n = cols.Count; bool marks = selected != null && selected.Count > 0;
            int shown = top > 0 && top < rows.Count ? top : rows.Count;
            // natural width: the longest of title and content (sampling the shown rows)
            int[] nat = new int[n], hint = new int[n]; string[][] cells = new string[shown][];
            for (int i = 0; i < n; i++) { nat[i] = Math.Max(2, cols[i].Title.Length); hint[i] = Math.Max(4, cols[i].Width / 7); }
            for (int r = 0; r < shown; r++) { cells[r] = new string[n]; for (int i = 0; i < n; i++) { string s = cols[i].SafeText(rows[r]); cells[r][i] = s; if (s.Length > nat[i]) nat[i] = Math.Min(s.Length, 400); } }
            int avail = ConsoleWidth() - (n - 1) * 2 - (marks ? 2 : 0); if (avail < n * 4) avail = n * 4;
            int[] w = new int[n]; int sum = 0; for (int i = 0; i < n; i++) { w[i] = Math.Min(nat[i], Math.Max(4, hint[i])); sum += w[i]; }
            // grow toward the natural width while there is room, widest deficit first; shrink the widest when there is not
            while (sum < avail) { int best = -1, deficit = 0; for (int i = 0; i < n; i++) { int d = nat[i] - w[i]; if (d > deficit) { deficit = d; best = i; } } if (best < 0) break; w[best]++; sum++; }
            while (sum > avail) { int best = -1, widest = 0; for (int i = 0; i < n; i++) if (w[i] > widest && w[i] > 4) { widest = w[i]; best = i; } if (best < 0) break; w[best]--; sum--; }
            // header
            StringBuilder h = new StringBuilder(); if (marks) h.Append("  ");
            for (int i = 0; i < n; i++) { if (i > 0) h.Append("  "); h.Append(Fit(cols[i].Title, w[i], cols[i].Right)); }
            Line(h.ToString(), Tone.Dim);
            Line(new string('─', Math.Min(sum + (n - 1) * 2 + (marks ? 2 : 0), ConsoleWidth())), Tone.Faint);
            for (int r = 0; r < shown; r++)
            {
                object o = rows[r];
                if (marks) Write(selected.Contains(o) ? "▶ " : "  ", Tone.Accent);
                for (int i = 0; i < n; i++) { if (i > 0) Write("  ", Tone.Normal); Write(Fit(cells[r][i], w[i], cols[i].Right), CellTone(t, cols[i], o)); }
                Console.WriteLine();
            }
        }
        /// <summary>Details: every column of every row as "Field  value" lines, one block per row - the app's details pane for each row in turn.</summary>
        public static void Details(TableDef t, List<object> rows, HashSet<object> selected, int top)
        {
            List<Col> cols = Visible(t); int shown = top > 0 && top < rows.Count ? top : rows.Count; int lw = 0; foreach (Col c in cols) lw = Math.Max(lw, c.Title.Length);
            for (int r = 0; r < shown; r++)
            {
                object o = rows[r]; bool sel = selected != null && selected.Contains(o);
                Line((sel ? "▶ " : "") + "row " + (r + 1) + " of " + rows.Count, sel ? Tone.Accent : Tone.Faint);
                foreach (Col c in cols) { string v = c.SafeText(o); if (v.Length == 0) continue; Write("  " + c.Title.PadRight(lw) + "  ", Tone.Dim); Line(v, CellTone(t, c, o)); }
                if (r < shown - 1) Blank();
            }
        }
        class TNode { public string Name; public readonly List<object> Items = new List<object>(); public readonly List<TNode> Kids = new List<TNode>(); public readonly Dictionary<string, TNode> Index = new Dictionary<string, TNode>(StringComparer.OrdinalIgnoreCase); }
        /// <summary>The tree: rows grouped by the table's tree path, parents with counts, exactly as the app's Tree view builds it.</summary>
        public static void Tree(TableDef t, List<object> rows, HashSet<object> selected, int top)
        {
            if (t.Tree == null) { Line("(no tree grouping for this tool)", Tone.Dim); return; }
            TNode root = new TNode(); int shown = top > 0 && top < rows.Count ? top : rows.Count;
            for (int r = 0; r < shown; r++)
            {
                object o = rows[r]; string[] path; try { path = t.Tree(o); } catch { path = null; } if (path == null || path.Length == 0) continue;
                TNode level = root;
                foreach (string seg in path) { TNode k; if (!level.Index.TryGetValue(seg, out k)) { k = new TNode(); k.Name = seg; level.Index[seg] = k; level.Kids.Add(k); } k.Items.Add(o); level = k; }
            }
            PrintTree(t, root, 0, selected);
        }
        static void PrintTree(TableDef t, TNode n, int depth, HashSet<object> selected)
        {
            foreach (TNode k in n.Kids)
            {
                string text; try { text = t.TreeText != null ? t.TreeText(k.Name, k.Items) : (k.Kids.Count > 0 ? k.Name + "   (" + k.Items.Count.ToString("N0") + ")" : k.Name); } catch { text = k.Name; }
                bool leaf = k.Kids.Count == 0; bool sel = false; if (leaf && selected != null && selected.Count > 0) { sel = true; foreach (object o in k.Items) if (!selected.Contains(o)) { sel = false; break; } }
                Tone tone = leaf ? (k.Items.Count == 1 ? RowTone(t, k.Items[0]) : Tone.Normal) : Tone.Dim;
                Line(new string(' ', depth * 2) + (sel ? "▶ " : (leaf ? "· " : "▸ ")) + text, sel ? Tone.Accent : tone);
                PrintTree(t, k, depth + 1, selected);
            }
        }
    }

    /// <summary>Progress that does not flood: at most one line per interval, always the last one.</summary>
    public class Throttle
    {
        DateTime last = DateTime.MinValue; readonly int ms;
        public Throttle(int intervalMs) { ms = intervalMs; }
        public void Say(string s) { if ((DateTime.Now - last).TotalMilliseconds < ms) return; last = DateTime.Now; Out.Progress(s); }
    }

    /// <summary>The app's DataView without the window: the rows, the search, the filter rules, the sort and the ticked rows, applied in the same order the app applies them.</summary>
    public class View
    {
        public TableDef Def; public readonly List<object> All = new List<object>(); public List<object> Rows = new List<object>(); public readonly HashSet<object> Selected = new HashSet<object>();
        public string Search = ""; public readonly List<FilterRule> Rules = new List<FilterRule>(), Picks = new List<FilterRule>(); public string SortKey; public bool SortAsc = true;
        /// <summary>The tool's own mode filter (the app's combo boxes and toggles next to the search box), applied before the rules.</summary>
        public Func<object, bool> Filter;
        public string Mode = "grid"; public int Top;
        public View(TableDef def) { Def = def; }
        public void Set(IEnumerable<object> items) { All.Clear(); All.AddRange(items); Refresh(); }
        public void Refresh()
        {
            string q = Search.Trim().ToLowerInvariant(); Rows = new List<object>();
            foreach (object o in All)
            {
                if (Filter != null && !Filter(o)) continue;
                if (q.Length > 0) { bool hit = false; foreach (Col c in Def.Cols) if (c.SafeText(o).ToLowerInvariant().IndexOf(q) >= 0) { hit = true; break; } if (!hit) continue; }
                if (Rules.Count > 0 && !FilterRule.Pass(Rules, Def.Cols, o)) continue;
                Rows.Add(o);
            }
            if (SortKey != null) RowSort.Sort(Rows, Def.Find(SortKey), SortAsc);
            Selected.Clear(); if (Picks.Count > 0) foreach (object o in Rows) if (FilterRule.Pass(Picks, Def.Cols, o)) Selected.Add(o);
        }
        /// <summary>The ticked rows in display order.</summary>
        public List<object> SelectedRows { get { List<object> l = new List<object>(); foreach (object o in Rows) if (Selected.Contains(o)) l.Add(o); return l; } }
        /// <summary>The ticked rows, or every shown row when nothing is ticked - what "Export CSV…" writes.</summary>
        public List<object> ExportRows { get { return Selected.Count > 0 ? SelectedRows : new List<object>(Rows); } }
        /// <summary>Reads the shared view options: --view --search --sort --desc --where --select --top. Throws a usage error for a rule that does not parse or a column that does not exist.</summary>
        public void Configure(Args a)
        {
            Mode = a.Choice("view", "grid", "grid", "details", "tree");
            Search = a.Get("search", ""); Top = a.Int("top", 0); int topv; if (a.Has("top") && (!int.TryParse(a.Get("top", ""), out topv) || topv < 0)) throw new UsageException("--top must be a whole number of rows, 0 or more (got '" + a.Get("top", "") + "')");
            string sort = a.Get("sort", null); if (sort != null) { Col c = Def.Find(sort); if (c == null) throw new UsageException("--sort: no column '" + sort + "'. Columns: " + ColumnList()); SortKey = c.Key; SortAsc = !a.Has("desc"); }
            foreach (string w in a.All("where")) { string err; FilterRule r = FilterRule.Parse(w, Def.Cols, out err); if (r == null) throw new UsageException("--where \"" + w + "\": " + err + ". Columns: " + ColumnList()); Rules.Add(r); }
            foreach (string w in a.All("select")) { string err; FilterRule r = FilterRule.Parse(w, Def.Cols, out err); if (r == null) throw new UsageException("--select \"" + w + "\": " + err + ". Columns: " + ColumnList()); Picks.Add(r); }
        }
        public string ColumnList() { List<string> l = new List<string>(); foreach (Col c in Def.Cols) if (!c.Hidden) l.Add(c.Key); return string.Join(", ", l.ToArray()); }
        /// <summary>Renders the rows in the chosen view and the count line the app shows under its top bar, then writes the CSV if asked.</summary>
        public void Show(Args a)
        {
            if (Mode == "details") Out.Details(Def, Rows, Selected, Top); else if (Mode == "tree") Out.Tree(Def, Rows, Selected, Top); else Out.Grid(Def, Rows, Selected, Top);
            string count = Rows.Count.ToString("N0") + (Rows.Count != All.Count ? " of " + All.Count.ToString("N0") : "") + " rows" + (Selected.Count > 0 ? " · " + Selected.Count.ToString("N0") + " selected" : "") + (Rules.Count > 0 ? " · " + Rules.Count + " filter" + (Rules.Count == 1 ? "" : "s") : "") + (SortKey != null ? " · sorted by " + SortKey + (SortAsc ? "" : " (descending)") : "") + (Top > 0 && Top < Rows.Count ? " · showing the first " + Top : "");
            Out.Line(count, Tone.Dim);
            string csv = a.Get("csv", null);
            if (csv != null) { List<object> what = ExportRows; string dest = Cli.ResolveCsv(csv); try { Csv.Write(dest, Def.Cols, what); } catch (Exception ex) { if (ex is IOException || ex is UnauthorizedAccessException || ex is ArgumentException || ex is NotSupportedException) throw new UsageException("--csv: cannot write " + dest + ": " + ex.Message); throw; } Out.Ok(what.Count.ToString("N0") + " row" + (what.Count == 1 ? "" : "s") + (Selected.Count > 0 ? " (the selected ones)" : " (everything shown)") + " written to " + dest); }
        }
    }

    /// <summary>One command: its registry entry, its own options, what it runs, and the tables it can show (for --help).</summary>
    public class CliTool
    {
        public ToolInfo Info; public readonly List<Opt> Opts = new List<Opt>(); public Func<Args, int> Run; public Func<List<TableDef>> Tables; public readonly List<string> Examples = new List<string>();
        public CliTool(string key) { Info = Tools.ByKey(key); }
        public CliTool Opt(string name, string value, string help) { Opts.Add(new Opt(name, value, help)); return this; }
        public CliTool Example(string e) { Examples.Add(e); return this; }
    }

    public static class Cli
    {
        public const int OK = 0, PROBLEMS = 1, USAGE = 2, ADMIN = 3, CANCELLED = 4;
        public static readonly string ExeDir = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
        public static readonly Settings S = new Settings(Path.Combine(ExeDir, "settings.ini"));
        public static readonly bool IsElevated = Elevated();
        public static volatile bool Cancelled;
        static bool Elevated() { try { return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); } catch { return false; } }

        /// <summary>The view bar every tool shares - the app's Grid / Details / Tree, search, header sort, Filter rules, checkboxes and Export CSV… as options.</summary>
        public static readonly List<Opt> ViewOpts = new List<Opt>(new Opt[] {
            new Opt("view", "grid|details|tree", "how to show the rows: the app's Grid, Details or Tree button"),
            new Opt("search", "text", "keep the rows where any column contains this text: the search box"),
            new Opt("sort", "column", "sort by a column (its key or title); add --desc for descending: clicking a header"),
            new Opt("desc", null, "sort descending"),
            new Opt("where", "\"column op value\"", "a filter rule, repeatable; rules combine with AND: the Filter bar. Column is a key, a title or 'any'; op is one of: contains, does not contain, equals, does not equal, starts with, ends with, matches regex, is empty, is not empty, greater than, less than, at least, at most (numbers understand KB/MB/GB, %, ms)"),
            new Opt("select", "\"column op value\"", "tick the rows that match, repeatable; actions and --csv then apply to the ticked rows: the row checkboxes"),
            new Opt("all", null, "let an action apply to every shown row when nothing is ticked: Select all"),
            new Opt("csv", "file", "write the shown rows, or the ticked ones, as CSV with the app's headers: Export CSV… A bare filename goes into the reports folder next to the exe; give a path (e.g. C:\\out\\x.csv) to write elsewhere."),
            new Opt("top", "n", "print only the first n rows (the CSV is never cut)"),
            new Opt("yes", null, "answer yes to every confirmation (required when input is not a terminal)"),
            new Opt("no-color", null, "plain output"),
            new Opt("width", "n", "lay the grid out for this many columns instead of the console width"),
            new Opt("quiet", null, "no progress on stderr"),
            new Opt("help", null, "help for the tool"),
        });

        static int Main(string[] argv)
        {
            try { Console.OutputEncoding = new UTF8Encoding(false); } catch { }
            Out.Color = !Console.IsOutputRedirected;
            Console.CancelKeyPress += delegate (object s, ConsoleCancelEventArgs e) { if (!Cancelled) { Cancelled = true; e.Cancel = true; Out.Warn("stopping…"); } };
            List<CliTool> tools = CliTools.All();
            // a first pass with only the view options finds the tool; the second knows the tool's own options
            Args pre = new Args(argv, ViewOpts);
            bool wantsConsole = pre.Tool == "console" || pre.Tool == "shell" || pre.Tool == "interactive";
            // bare `PowerTowerCli` in a real terminal drops into the interactive console; piped or redirected
            // (scripts, `| more`, no TTY) it keeps printing the usage list, so nothing that parses it breaks.
            if (!wantsConsole && argv.Length == 0) { try { wantsConsole = !Console.IsInputRedirected && !Console.IsOutputRedirected; } catch { wantsConsole = false; } }
            if (wantsConsole) return Repl.Run();
            if (pre.Tool.Length == 0 || pre.Tool == "help") { Usage(tools); return pre.Has("help") || pre.Tool == "help" || argv.Length == 0 ? OK : USAGE; }
            if (pre.Tool == "version" || pre.Tool == "--version") { Out.Line("PowerTowerCli " + Version()); return OK; }
            CliTool tool = null; foreach (CliTool t in tools) if (string.Equals(t.Info.Key, pre.Tool, StringComparison.OrdinalIgnoreCase)) tool = t;
            if (tool == null) { List<CliTool> near = new List<CliTool>(); foreach (CliTool t in tools) if (t.Info.Key.StartsWith(pre.Tool, StringComparison.OrdinalIgnoreCase) || t.Info.Title.IndexOf(pre.Tool, StringComparison.OrdinalIgnoreCase) >= 0) near.Add(t); if (near.Count == 1) tool = near[0]; else { Out.Error("no tool called '" + pre.Tool + "'." + (near.Count > 1 ? " Did you mean: " + Keys(near) + "?" : " Run PowerTowerCli with no arguments for the list.")); return USAGE; } }
            List<Opt> known = new List<Opt>(ViewOpts); known.AddRange(tool.Opts);
            Args a = new Args(argv, known);
            if (a.Has("no-color")) Out.Color = false; if (a.Has("width")) Out.Width = a.Int("width", 0); if (a.Has("quiet")) Out.Quiet = true;
            if (a.Has("help")) { ToolHelp(tool); return OK; }
            if (a.Unknown.Count > 0) { Out.Error("unknown option" + (a.Unknown.Count == 1 ? "" : "s") + " " + string.Join(" ", a.Unknown.ToArray()) + " - see PowerTowerCli " + tool.Info.Key + " --help"); return USAGE; }
            try { return tool.Run(a); }
            catch (UsageException ex) { Out.Error(ex.Message); return USAGE; }
            catch (Exception ex) { Out.Error(tool.Info.Title + ": " + ex.GetType().Name + ": " + ex.Message); try { File.AppendAllText(Path.Combine(ExeDir, "crash.log"), DateTime.Now.ToString("s") + "  cli " + tool.Info.Key + "  " + ex + "\r\n\r\n"); } catch { } return PROBLEMS; }
        }
        static string Keys(List<CliTool> l) { List<string> k = new List<string>(); foreach (CliTool t in l) k.Add(t.Info.Key); return string.Join(", ", k.ToArray()); }
        public static string Version() { try { return System.Reflection.Assembly.GetExecutingAssembly().GetName().Version.ToString(2) + " · " + File.GetLastWriteTime(System.Reflection.Assembly.GetExecutingAssembly().Location).ToString("yyyy-MM-dd"); } catch { return ""; } }

        // ── help ──
        /// <summary>The tool list, grouped and ordered like the app's sidebar and About page.</summary>
        public static void Usage(List<CliTool> tools)
        {
            Out.Line("▌ POWERTOWER", Tone.Accent); Out.Line("  portable security workbench · command line" + (IsElevated ? " · administrator" : ""), Tone.Dim);
            Out.Blank(); Out.Line("usage:  PowerTowerCli <tool> [options]", Tone.Normal); Out.Line("        PowerTowerCli <tool> --help        options, actions and columns of one tool", Tone.Dim);
            Out.Line("        PowerTowerCli console              interactive console — a Metasploit-style shell over these tools", Tone.Accent); Out.Blank();
            int w = 0; foreach (CliTool t in tools) w = Math.Max(w, t.Info.Key.Length);
            foreach (string grp in Tools.Groups)
            {
                Out.Line(grp, Tone.Accent);
                foreach (CliTool t in tools) { if (t.Info.Group != grp) continue; Out.Write("  " + t.Info.Key.PadRight(w + 2), Tone.Normal); Out.Write(t.Info.Title.PadRight(28), Tone.Dim); Out.Line(t.Info.GuiOnly ? "desktop app only (visual)" : t.Info.NeedsAdmin ? "needs administrator for some actions" : "", t.Info.GuiOnly ? Tone.Faint : Tone.Warn); }
                Out.Blank();
            }
            Out.Line("  " + "about".PadRight(w + 2), Tone.Normal); Out.Line("  " + "version".PadRight(w + 2), Tone.Normal); Out.Blank();
            Out.Line("Every tool shows rows the way the app does and takes the same view options:", Tone.Normal);
            int vp = PadFor(ViewOpts); foreach (Opt o in ViewOpts) OptLine(o, vp);
            Out.Blank(); Out.Line("Tables go to stdout, progress to stderr. Exit codes: 0 ok · 1 problems · 2 usage · 3 administrator needed · 4 cancelled.", Tone.Dim);
        }
        static int PadFor(IEnumerable<Opt> opts) { int pad = 12; foreach (Opt o in opts) pad = Math.Max(pad, o.Name.Length + (o.Flag ? 0 : o.Value.Length + 3) + 4); return pad; }
        static void OptLine(Opt o, int pad) { string head = "  --" + o.Name + (o.Flag ? "" : " <" + o.Value + ">"); int w = Math.Max(pad + 2, head.Length + 2); Out.Write(head.PadRight(w), Tone.Normal); Out.Line(Out.Wrap(o.Help, Out.ConsoleWidth() - w - 2, "").Replace("\n", "\n" + new string(' ', w)), Tone.Dim); }
        public static void ToolHelp(CliTool t)
        {
            Out.Header(t.Info);
            Out.Line("usage:  PowerTowerCli " + t.Info.Key + " [options]", Tone.Normal); Out.Blank();
            if (t.Info.GuiOnly) { Out.Line("This tool is visual and lives in the desktop app: open PowerTower.exe and pick " + t.Info.Title + " in the sidebar.", Tone.Warn); return; }
            List<Opt> allOpts = new List<Opt>(t.Opts); allOpts.AddRange(ViewOpts); int pad = PadFor(allOpts);
            if (t.Opts.Count > 0) { Out.Line("options and actions", Tone.Accent); foreach (Opt o in t.Opts) OptLine(o, pad); Out.Blank(); }
            Out.Line("view options (every tool)", Tone.Accent); foreach (Opt o in ViewOpts) OptLine(o, pad); Out.Blank();
            if (t.Tables != null)
            {
                foreach (TableDef d in t.Tables())
                {
                    Out.Line("columns of " + d.Export + (d.Tree != null ? "   (tree view groups the rows)" : ""), Tone.Accent);
                    StringBuilder sb = new StringBuilder(); int col = 2;
                    foreach (Col c in d.Cols) { if (c.Hidden) continue; string item = c.Key + (c.Key != c.Title.ToLowerInvariant() ? " (" + c.Title + ")" : ""); if (col + item.Length + 3 > Out.ConsoleWidth()) { Out.Line("  " + sb.ToString().TrimEnd(), Tone.Dim); sb.Length = 0; col = 2; } sb.Append(item).Append(" · "); col += item.Length + 3; }
                    if (sb.Length > 0) Out.Line("  " + sb.ToString().TrimEnd(' ', '·'), Tone.Dim);
                }
                Out.Blank();
            }
            if (t.Examples.Count > 0) { Out.Line("examples", Tone.Accent); foreach (string e in t.Examples) Out.Line("  PowerTowerCli " + t.Info.Key + " " + e, Tone.Normal); }
        }

        // ── the shared behaviours of the app's selection bar and dialogs ──
        /// <summary>The rows an action applies to: the ticked ones, or every shown row with --all. Null (with a message) when neither was given, since actions never guess.</summary>
        public static List<object> ActionTargets(View v, Args a, string action)
        {
            if (v.Picks.Count > 0) { List<object> l = v.SelectedRows; if (l.Count == 0) Out.Warn(action + ": no shown row matches --select, nothing to do."); return l; }
            if (a.Has("all")) return new List<object>(v.Rows);
            Out.Error(action + " acts on ticked rows: add --select \"<column> <op> <value>\" to tick them, or --all for every shown row."); return null;
        }
        /// <summary>The app's Yes/No confirmation: --yes answers it; otherwise it asks on the console, and refuses when there is no console to ask.</summary>
        public static bool Confirm(Args a, string title, string text)
        {
            Out.Line(title, Tone.Warn); if (!string.IsNullOrEmpty(text)) Out.Line(Out.Wrap(text.Replace("\n\n", "\n").Replace("\n", " "), Out.ConsoleWidth() - 2, "  "), Tone.Dim);
            if (a.Has("yes")) { Out.Line("  confirmed with --yes", Tone.Dim); return true; }
            if (Console.IsInputRedirected) { Out.Error("  not confirmed: input is not a terminal - run again with --yes to confirm."); return false; }
            Console.Write("  proceed? [y/N] "); string ans = Console.ReadLine(); bool ok = ans != null && (ans.Trim().Equals("y", StringComparison.OrdinalIgnoreCase) || ans.Trim().Equals("yes", StringComparison.OrdinalIgnoreCase));
            if (!ok) Out.Line("  cancelled", Tone.Dim); return ok;
        }
        /// <summary>True when the caller should stop: the action needs administrator rights and this process has none.</summary>
        public static bool NeedAdmin(string what)
        {
            if (IsElevated) return false;
            Out.Error(what + " needs administrator rights. Run PowerTowerCli from an elevated prompt (right-click the terminal → Run as administrator)."); return true;
        }
        /// <summary>A password from --password, or typed without echo.</summary>
        public static string Password(Args a, string prompt, bool confirm)
        {
            string p = a.Get("password", null); if (p != null) { if (p.Length == 0) { Out.Error("the password must not be empty"); return null; } return p; }
            if (Console.IsInputRedirected) { Out.Error("no --password given and input is not a terminal"); return null; }
            while (true)
            {
                Console.Error.Write(prompt + ": "); string one = ReadHidden(); if (one.Length == 0) { Out.Warn("Enter a password."); continue; }
                if (!confirm) return one;
                if (one.Length < 6) { Out.Warn("Use at least 6 characters."); continue; }
                Console.Error.Write("confirm: "); string two = ReadHidden(); if (one != two) { Out.Warn("The two passwords do not match."); continue; }
                return one;
            }
        }
        static string ReadHidden() { StringBuilder sb = new StringBuilder(); while (true) { ConsoleKeyInfo k = Console.ReadKey(true); if (k.Key == ConsoleKey.Enter) { Console.Error.WriteLine(); return sb.ToString(); } if (k.Key == ConsoleKey.Backspace) { if (sb.Length > 0) sb.Length--; } else if (k.KeyChar != '\0') sb.Append(k.KeyChar); } }
        /// <summary>Lines from --file (repeatable), --add values and --stdin: the app's "Add from file…", "Add entry" and "Paste…".</summary>
        public static List<string> InputLines(Args a, out string origin)
        {
            List<string> lines = new List<string>(); List<string> src = new List<string>();
            foreach (string f in a.All("file")) { if (!File.Exists(f)) throw new UsageException("--file: no such file: " + f); lines.AddRange(File.ReadAllLines(f)); src.Add(Path.GetFileName(f)); }
            List<string> adds = a.All("add"); if (adds.Count > 0) { lines.AddRange(adds); src.Add("typed"); }
            if (a.Has("stdin")) { string l; while ((l = Console.In.ReadLine()) != null) lines.Add(l); src.Add("stdin"); }
            origin = src.Count == 0 ? "" : string.Join(" + ", src.ToArray()); return lines;
        }
        public static List<object> Boxed<T>(IEnumerable<T> items) { List<object> l = new List<object>(); foreach (T t in items) l.Add(t); return l; }
        public static string Preview(List<string> l, int max) { List<string> p = l.GetRange(0, Math.Min(max, l.Count)); return string.Join(", ", p.ToArray()) + (l.Count > max ? " … +" + (l.Count - max) : ""); }
        /// <summary>Where a --csv export lands. A bare filename goes into the reports folder; an explicit path
        /// (absolute, or with any directory part) is written exactly as given, so scripts keep full control.</summary>
        /// <summary>--path as an absolute folder path; an illegal or empty value is a usage error, not a raw .NET exception.</summary>
        public static string FullFolder(string path)
        {
            try { if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException(); return Path.GetFullPath(path); }
            catch (Exception ex) { if (ex is ArgumentException || ex is NotSupportedException || ex is PathTooLongException || ex is System.Security.SecurityException) throw new UsageException("--path: not a valid folder path: '" + path + "'"); throw; }
        }
        public static string ResolveCsv(string csv)
        {
            if (string.IsNullOrEmpty(csv)) return csv;
            bool hasDir = csv.IndexOf('/') >= 0 || csv.IndexOf('\\') >= 0 || Path.IsPathRooted(csv);
            return hasDir ? csv : Path.Combine(ReportsDir(), csv);
        }
        /// <summary>The reports folder next to the exe (created on demand), falling back to LocalAppData when the
        /// exe's folder is read-only - the same rule OpenCache uses for the feed cache.</summary>
        public static string ReportsDir()
        {
            string local = Path.Combine(ExeDir, "reports");
            try { Directory.CreateDirectory(local); string probe = Path.Combine(local, ".write-test"); File.WriteAllText(probe, "ok"); File.Delete(probe); return local; }
            catch { string alt = Path.Combine(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PowerTower"), "reports"); try { Directory.CreateDirectory(alt); } catch { } return alt; }
        }
        /// <summary>The feed cache next to the exe, or under LocalAppData when the exe's folder is read-only - the same rule the app uses.</summary>
        public static FeedCache OpenCache()
        {
            string local = Path.Combine(ExeDir, "cache");
            try { Directory.CreateDirectory(local); string probe = Path.Combine(local, ".write-test"); File.WriteAllText(probe, "ok"); File.Delete(probe); return new FeedCache(local); }
            catch { return new FeedCache(Path.Combine(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PowerTower"), "cache")); }
        }
        /// <summary>Waits for a background engine that signals Finished, keeping Ctrl+C working.</summary>
        public static bool Wait(ManualResetEvent done, Action cancel)
        {
            while (!done.WaitOne(200)) { if (Cancelled) { if (cancel != null) cancel(); done.WaitOne(3000); return false; } }
            return true;
        }
        /// <summary>Sends a file or folder to the Recycle Bin, the way the app's "Move to Recycle Bin…" does.</summary>
        public static void Recycle(string path, bool isDir)
        {
            if (isDir) Microsoft.VisualBasic.FileIO.FileSystem.DeleteDirectory(path, Microsoft.VisualBasic.FileIO.UIOption.OnlyErrorDialogs, Microsoft.VisualBasic.FileIO.RecycleOption.SendToRecycleBin);
            else Microsoft.VisualBasic.FileIO.FileSystem.DeleteFile(path, Microsoft.VisualBasic.FileIO.UIOption.OnlyErrorDialogs, Microsoft.VisualBasic.FileIO.RecycleOption.SendToRecycleBin);
        }
    }
}

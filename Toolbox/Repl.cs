// Repl.cs — the interactive PowerTower console: a Metasploit-style shell over the very same tools, options
// and renderers the one-shot CLI uses. `use` a tool as a module, `set` its options, `run` it. Everything a
// module does here is exactly what `PowerTowerCli <tool> --opt value` does; the console just keeps the
// options between commands and prints the equivalent one-shot line so the grammar stays learnable.
using System;
using System.Collections.Generic;
using System.Text;

namespace PSTools
{
    static class Repl
    {
        // "POWER" in the ANSI Shadow block font; "TOWER" rides underneath as a subtitle.
        static readonly string[] Logo = new string[] {
            "██████╗  ██████╗ ██╗    ██╗███████╗██████╗",
            "██╔══██╗██╔═══██╗██║    ██║██╔════╝██╔══██╗",
            "██████╔╝██║   ██║██║ █╗ ██║█████╗  ██████╔╝",
            "██╔═══╝ ██║   ██║██║███╗██║██╔══╝  ██╔══██╗",
            "██║     ╚██████╔╝╚███╔███╔╝███████╗██║  ██║",
            "╚═╝      ╚═════╝  ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝",
        };

        public static int Run()
        {
            List<CliTool> tools = CliTools.All();
            Banner(tools);
            CliTool current = null;
            Dictionary<string, string> vals = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            while (true)
            {
                Prompt(current);
                string line;
                try { line = Console.ReadLine(); } catch { line = null; }
                if (line == null) { Out.Blank(); return Cli.OK; }        // Ctrl+Z / EOF
                Cli.Cancelled = false;                                    // a Ctrl+C at the prompt must not leak into the next run
                line = line.Trim();
                if (line.Length == 0) continue;

                string cmd, rest; int sp = line.IndexOf(' ');
                if (sp < 0) { cmd = line; rest = ""; } else { cmd = line.Substring(0, sp); rest = line.Substring(sp + 1).Trim(); }
                cmd = cmd.ToLowerInvariant();

                switch (cmd)
                {
                    case "exit": case "quit": case "q": return Cli.OK;
                    case "help": case "?": Help(); break;
                    case "banner": Banner(tools); break;
                    case "version": Out.Line("PowerTowerCli " + Cli.Version(), Tone.Normal); break;
                    case "clear": case "cls": try { Console.Clear(); } catch { } break;
                    case "back": if (current != null) { current = null; vals.Clear(); } break;
                    case "show": Show(tools, current, vals, rest); break;
                    case "tools": case "modules": ShowTools(tools, rest); break;
                    case "search": Search(tools, rest); break;
                    case "use": { CliTool t = Resolve(tools, rest); if (t != null) { current = t; vals.Clear(); Selected(current); } break; }
                    case "info": if (Need(current)) Cli.ToolHelp(current); break;
                    case "options": if (Need(current)) Options(current, vals); break;
                    case "set": Set(current, vals, rest); break;
                    case "unset": Unset(current, vals, rest); break;
                    case "run": case "exploit": case "go": if (Need(current)) RunTool(current, vals); break;
                    default:
                        CliTool m = (rest.Length == 0) ? Match(tools, cmd) : null;
                        if (m != null) { current = m; vals.Clear(); Selected(current); }
                        else Out.Error("unknown command '" + cmd + "'. Type help for commands, or show tools for the module list.");
                        break;
                }
            }
        }

        // ── banner & prompt ──
        static void Banner(List<CliTool> tools)
        {
            Out.Blank();
            foreach (string s in Logo) Out.Line("  " + s, Tone.Accent);
            Out.Line("        T O W E R   ·   portable security workbench", Tone.Dim);
            Out.Blank();
            int guiOnly = 0; foreach (CliTool t in tools) if (t.Info.GuiOnly) guiOnly++;
            string who = Cli.IsElevated ? "administrator" : "standard user";
            Out.Write("       ", Tone.Normal);
            Out.Write("[ ", Tone.Faint); Out.Write(tools.Count + " modules", Tone.Normal);
            if (guiOnly > 0) { Out.Write(" (" + (tools.Count - guiOnly) + " runnable, " + guiOnly + " visual)", Tone.Faint); }
            Out.Write("  ·  ", Tone.Faint); Out.Write(who, Cli.IsElevated ? Tone.Good : Tone.Warn);
            Out.Write("  ·  ", Tone.Faint); Out.Write(Cli.Version(), Tone.Dim);
            Out.Line(" ]", Tone.Faint);
            Out.Blank();
            Out.Line("       use <module>   ·   show tools   ·   search <text>   ·   help   ·   exit", Tone.Dim);
            Out.Blank();
        }

        static void Prompt(CliTool current)
        {
            Out.Write("PowerTower", Tone.Accent);
            if (current != null) { Out.Write(" (", Tone.Faint); Out.Write(current.Info.Key, Tone.Warn); Out.Write(")", Tone.Faint); }
            Out.Write(" ", Tone.Normal); Out.Write("»", Tone.Accent); Out.Write(" ", Tone.Normal);
        }

        static bool Need(CliTool current)
        {
            if (current != null) return true;
            Out.Error("no module selected. Pick one first, e.g.  use recon   (show tools for the list)."); return false;
        }

        // ── help ──
        static void Help()
        {
            Out.Blank();
            Out.Line("Console commands", Tone.Accent);
            Cmd("show tools", "list every module, grouped (also: show, modules)");
            Cmd("search <text>", "modules whose name or description match");
            Cmd("use <module|#>", "select a module by name or its number");
            Cmd("info", "the selected module's full help: options, columns, examples");
            Cmd("options", "the module's options and the values you have set");
            Cmd("set <opt> <value>", "set an option, e.g.  set path D:\\Photos   ·   set view tree");
            Cmd("unset <opt|all>", "clear an option");
            Cmd("run", "run the module with the options set (also: exploit, go)");
            Cmd("back", "deselect the module");
            Cmd("banner / version", "reprint the banner / show the version");
            Cmd("clear", "clear the screen");
            Cmd("exit", "leave the console (also: quit, Ctrl+Z)");
            Out.Blank();
            Out.Line("Every module maps 1:1 to the one-shot form: what you run here is printed as", Tone.Dim);
            Out.Line("a PowerTowerCli command line so you can script it later. Options take one value", Tone.Dim);
            Out.Line("each; for stacked --where/--select filters use the one-shot form.", Tone.Dim);
            Out.Blank();
        }
        static void Cmd(string name, string help) { Out.Write("  " + name.PadRight(20), Tone.Normal); Out.Line(help, Tone.Dim); }

        // ── module listing ──
        static List<CliTool> Ordered(List<CliTool> tools)
        {
            List<CliTool> o = new List<CliTool>();
            foreach (string grp in Tools.Groups) foreach (CliTool t in tools) if (t.Info.Group == grp) o.Add(t);
            foreach (CliTool t in tools) if (!o.Contains(t)) o.Add(t);   // any tool whose group is not in the list
            return o;
        }

        static void Show(List<CliTool> tools, CliTool current, Dictionary<string, string> vals, string what)
        {
            string w = what.Trim().ToLowerInvariant();
            if (w == "options" || w == "opts") { if (Need(current)) Options(current, vals); return; }
            if (w == "info") { if (Need(current)) Cli.ToolHelp(current); return; }
            ShowTools(tools, w == "tools" || w == "modules" || w == "all" ? "" : what);
        }

        static void ShowTools(List<CliTool> tools, string filter)
        {
            List<CliTool> ord = Ordered(tools);
            string q = (filter ?? "").Trim().ToLowerInvariant();
            int wk = 0; foreach (CliTool t in ord) wk = Math.Max(wk, t.Info.Key.Length);
            Out.Blank(); Out.Line("Modules", Tone.Accent);
            string grp = null; int n = 0, shown = 0;
            foreach (CliTool t in ord)
            {
                n++;
                if (q.Length > 0 && t.Info.Key.ToLowerInvariant().IndexOf(q) < 0 && t.Info.Title.ToLowerInvariant().IndexOf(q) < 0 && (t.Info.Blurb ?? "").ToLowerInvariant().IndexOf(q) < 0) continue;
                if (t.Info.Group != grp) { grp = t.Info.Group; Out.Blank(); Out.Line("  " + grp, Tone.Info); }
                Out.Write("   " + n.ToString().PadLeft(2) + "  ", Tone.Faint);
                Out.Write(t.Info.Key.PadRight(wk + 2), Tone.Normal);
                Out.Write(t.Info.Title.PadRight(26), Tone.Dim);
                Out.Line(t.Info.GuiOnly ? "visual — desktop app only" : t.Info.NeedsAdmin ? "needs administrator" : "", t.Info.GuiOnly ? Tone.Faint : Tone.Warn);
                shown++;
            }
            Out.Blank();
            Out.Line("  " + shown + " module" + (shown == 1 ? "" : "s") + (q.Length > 0 ? " matching \"" + filter.Trim() + "\"" : "") + " — use <name or #> to select one", Tone.Dim);
            Out.Blank();
        }

        static void Search(List<CliTool> tools, string text)
        {
            if (text.Trim().Length == 0) { Out.Error("search <text> — e.g. search network"); return; }
            ShowTools(tools, text);
        }

        // ── selecting a module ──
        static CliTool Resolve(List<CliTool> tools, string token)
        {
            token = token.Trim();
            if (token.Length == 0) { Out.Error("use <module|#> — show tools for the list."); return null; }
            int num; if (int.TryParse(token, out num)) { List<CliTool> ord = Ordered(tools); if (num >= 1 && num <= ord.Count) return ord[num - 1]; Out.Error("no module #" + num + " (there are " + ord.Count + ")."); return null; }
            CliTool t = Match(tools, token);
            if (t == null) Out.Error("no module '" + token + "'. Try show tools, or search " + token + ".");
            return t;
        }

        static CliTool Match(List<CliTool> tools, string token)
        {
            foreach (CliTool t in tools) if (string.Equals(t.Info.Key, token, StringComparison.OrdinalIgnoreCase)) return t;
            List<CliTool> near = new List<CliTool>();
            foreach (CliTool t in tools) if (t.Info.Key.StartsWith(token, StringComparison.OrdinalIgnoreCase) || t.Info.Title.IndexOf(token, StringComparison.OrdinalIgnoreCase) >= 0) near.Add(t);
            return near.Count == 1 ? near[0] : null;
        }

        static void Selected(CliTool t)
        {
            Out.Blank();
            Out.Write("  ▌ ", Tone.Accent); Out.Write(t.Info.Title, Tone.Normal); Out.Line("   [" + t.Info.Key + "]", Tone.Faint);
            Out.Line("    " + Out.Wrap(t.Info.Blurb, Out.ConsoleWidth() - 6, "").Replace("\n", "\n    "), Tone.Dim);
            if (t.Info.GuiOnly) Out.Line("    This module is visual and only runs in the desktop app (PowerTower.exe).", Tone.Warn);
            else if (t.Info.NeedsAdmin && !Cli.IsElevated) Out.Line("    Some actions here need administrator rights — relaunch the terminal elevated.", Tone.Warn);
            Out.Line("    set the options, then run   ·   options to review   ·   info for the full help", Tone.Dim);
            Out.Blank();
        }

        // ── options ──
        static List<Opt> Known(CliTool t) { List<Opt> k = new List<Opt>(t.Opts); k.AddRange(Cli.ViewOpts); return k; }
        static Opt Find(CliTool t, string name) { foreach (Opt o in Known(t)) if (string.Equals(o.Name, name, StringComparison.OrdinalIgnoreCase)) return o; return null; }

        static void Options(CliTool t, Dictionary<string, string> vals)
        {
            Out.Blank();
            Out.Write("  Module options  ", Tone.Accent); Out.Line("(" + t.Info.Key + ")", Tone.Faint);
            if (t.Info.GuiOnly) { Out.Line("    visual module — no command-line options", Tone.Warn); Out.Blank(); return; }
            PrintOpts("options & actions", t.Opts, vals);
            PrintOpts("view", Cli.ViewOpts, vals);
            Out.Blank();
        }
        static void PrintOpts(string head, List<Opt> opts, Dictionary<string, string> vals)
        {
            if (opts.Count == 0) return;
            int wn = 0; foreach (Opt o in opts) wn = Math.Max(wn, o.Name.Length);
            Out.Blank(); Out.Line("  " + head, Tone.Info);
            Out.Write("    " + "name".PadRight(wn + 2), Tone.Faint); Out.Write("current".PadRight(16), Tone.Faint); Out.Line("expects", Tone.Faint);
            foreach (Opt o in opts)
            {
                string cur; bool set = vals.TryGetValue(o.Name, out cur);
                string curText = o.Flag ? (set ? "on" : "off") : (set ? cur : "—");
                Out.Write("    " + o.Name.PadRight(wn + 2), Tone.Normal);
                Out.Write(Trunc(curText, 15).PadRight(16), set ? Tone.Good : Tone.Faint);
                Out.Line(o.Flag ? "(flag)" : "<" + o.Value + ">", Tone.Dim);
            }
        }
        static string Trunc(string s, int w) { s = s ?? ""; return s.Length > w ? s.Substring(0, w - 1) + "…" : s; }

        static void Set(CliTool t, Dictionary<string, string> vals, string rest)
        {
            if (!Need(t)) return;
            if (rest.Length == 0) { Out.Error("set <option> <value> — options shows the names."); return; }
            string name, value; int sp = rest.IndexOf(' ');
            if (sp < 0) { name = rest; value = ""; } else { name = rest.Substring(0, sp); value = rest.Substring(sp + 1).Trim(); }
            name = name.TrimStart('-'); int eq = name.IndexOf('='); if (eq > 0) { if (value.Length == 0) value = name.Substring(eq + 1); name = name.Substring(0, eq); }
            Opt o = Find(t, name);
            if (o == null) { Out.Error("no option '" + name + "' on this module. Type options to see them."); return; }
            if (o.Flag)
            {
                string v = value.Trim().ToLowerInvariant();
                bool off = v == "false" || v == "off" || v == "no" || v == "0";
                if (off) { vals.Remove(o.Name); Out.Write("  " + o.Name, Tone.Normal); Out.Line(" => off", Tone.Dim); }
                else { vals[o.Name] = "true"; Out.Write("  " + o.Name, Tone.Normal); Out.Line(" => on", Tone.Good); }
                return;
            }
            if (value.Length == 0) { Out.Error("set " + o.Name + " <" + o.Value + "> — give a value."); return; }
            // strip a single pair of wrapping quotes, so  set where "size at least 10 MB"  works
            if (value.Length >= 2 && ((value[0] == '"' && value[value.Length - 1] == '"') || (value[0] == '\'' && value[value.Length - 1] == '\''))) value = value.Substring(1, value.Length - 2);
            vals[o.Name] = value;
            Out.Write("  " + o.Name, Tone.Normal); Out.Write(" => ", Tone.Dim); Out.Line(value, Tone.Good);
        }

        static void Unset(CliTool t, Dictionary<string, string> vals, string rest)
        {
            if (!Need(t)) return;
            string name = rest.Trim().TrimStart('-');
            if (name.Length == 0) { Out.Error("unset <option>  or  unset all"); return; }
            if (string.Equals(name, "all", StringComparison.OrdinalIgnoreCase)) { vals.Clear(); Out.Line("  all options cleared", Tone.Dim); return; }
            if (vals.Remove(name)) Out.Line("  " + name + " cleared", Tone.Dim);
            else Out.Line("  " + name + " was not set", Tone.Faint);
        }

        // ── running ──
        static void RunTool(CliTool t, Dictionary<string, string> vals)
        {
            if (t.Info.GuiOnly) { Out.Error(t.Info.Title + " is a visual module — open PowerTower.exe and pick it in the sidebar."); return; }

            List<string> argv = new List<string>(); argv.Add(t.Info.Key);
            foreach (KeyValuePair<string, string> kv in vals)
            {
                Opt o = Find(t, kv.Key); argv.Add("--" + kv.Key);
                if (o == null || !o.Flag) argv.Add(kv.Value);
            }

            // echo the equivalent one-shot line, quoting values that contain spaces
            StringBuilder line = new StringBuilder("PowerTowerCli");
            foreach (string a in argv) { line.Append(' '); line.Append(a.IndexOf(' ') >= 0 ? "\"" + a + "\"" : a); }
            Out.Blank(); Out.Line("  [»] " + line.ToString(), Tone.Faint); Out.Blank();

            List<Opt> known = new List<Opt>(Cli.ViewOpts); known.AddRange(t.Opts);
            Args a2 = new Args(argv.ToArray(), known);
            Cli.Cancelled = false;
            try { int rc = t.Run(a2); if (rc == Cli.CANCELLED) Out.Warn("  (cancelled)"); }
            catch (UsageException ex) { Out.Error(ex.Message); }
            catch (Exception ex) { Out.Error(t.Info.Title + ": " + ex.GetType().Name + ": " + ex.Message); }
            Out.Blank();
        }
    }
}

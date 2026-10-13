// CollectMain.cs - PowerTowerCollect.exe: the collector as its own small console exe, the thing the agentless
// controller stages on a target and the agent runs on a schedule. One verb (collect), read-only, no GUI, no
// CLI framework; it writes bundle.ptb and done.json and exits. Options are the same as `PowerTowerCli collect`.
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace PSTools
{
    static class CollectProgram
    {
        static int Main(string[] argv)
        {
            try { Console.OutputEncoding = new UTF8Encoding(false); } catch { }
            Dictionary<string, List<string>> o = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase); List<string> bad = new List<string>();
            HashSet<string> flags = new HashSet<string>(StringComparer.OrdinalIgnoreCase); foreach (string[] h in CollectOptions.Help) if (h[1] == null) flags.Add(h[0]);
            for (int i = 0; i < argv.Length; i++)
            {
                string a = argv[i]; if (!a.StartsWith("--")) { bad.Add(a); continue; } string name = a.Substring(2), val = ""; int eq = name.IndexOf('='); if (eq >= 0) { val = name.Substring(eq + 1); name = name.Substring(0, eq); }
                if (name == "help" || name == "h" || name == "?") { Usage(); return 0; }
                if (name == "version") { Console.WriteLine(Collector.Name + " " + System.Reflection.Assembly.GetExecutingAssembly().GetName().Version.ToString(2)); return 0; }
                bool known = false; foreach (string[] h in CollectOptions.Help) if (h[0] == name) known = true; if (!known) { bad.Add(a); continue; }
                if (!flags.Contains(name) && eq < 0) { if (i + 1 >= argv.Length) { Console.Error.WriteLine("--" + name + " needs a value"); return 2; } val = argv[++i]; }
                List<string> l; if (!o.TryGetValue(name, out l)) o[name] = l = new List<string>(); l.Add(val);
            }
            if (bad.Count > 0) { Console.Error.WriteLine("unknown option" + (bad.Count == 1 ? "" : "s") + ": " + string.Join(" ", bad.ToArray()) + " (--help lists them)"); return 2; }
            Func<string, bool> has = delegate (string n) { return o.ContainsKey(n); };
            Func<string, string> get = delegate (string n) { List<string> l; return o.TryGetValue(n, out l) && l.Count > 0 ? l[l.Count - 1] : null; };
            Func<string, List<string>> all = delegate (string n) { List<string> l; return o.TryGetValue(n, out l) ? new List<string>(l) : new List<string>(); };
            Collector c = new Collector(); string err = CollectOptions.Apply(c, get, has, all); if (err != null) { Console.Error.WriteLine(err); return 2; }
            BundleKey key = CollectOptions.Key(c, get, has, out err); if (key == null) { Console.Error.WriteLine(err); return 2; }
            string dir = AppDomain.CurrentDomain.BaseDirectory;
            c.Progress = delegate (string s) { Console.Error.WriteLine("  " + s); };
            Console.Error.WriteLine(Collector.Name + " on " + Environment.MachineName + (c.Engagement != null ? " · engagement " + c.Engagement.Id : "") + " · modules " + string.Join(",", c.Modules.ToArray()) + (c.Online ? " · online" : " · offline") + " · " + (Collector.IsAdmin() ? "administrator" : "standard user"));
            Bundle b;
            try { b = c.Run(); }
            catch (BundleException ex) { Console.Error.WriteLine("refused: " + ex.Message); return 3; }
            string outPath = has("out") ? get("out") : CollectOptions.DefaultOut(b, dir);
            try
            {
                string parent = Path.GetDirectoryName(Path.GetFullPath(outPath)); if (parent.Length > 0) Directory.CreateDirectory(parent);
                b.Save(outPath, key); CollectOptions.WriteDone(b, outPath);
                if (has("json")) File.WriteAllText(get("json"), b.ToJson(true), new UTF8Encoding(false));
            }
            catch (Exception ex) { Console.Error.WriteLine("could not write the bundle: " + ex.Message); return 1; }
            Console.Error.WriteLine(); foreach (object m in b.Modules) Console.Error.WriteLine("  " + CollectOptions.Summary(m));
            int failed = CollectOptions.Failed(b);
            Console.WriteLine(Path.GetFullPath(outPath)); Console.Error.WriteLine("  bundle " + new FileInfo(outPath).Length.ToString("N0") + " bytes · sealed: " + key.Mode + " · sha256 " + BundleCrypto.FileSha256(outPath) + (failed > 0 ? " · " + failed + " module(s) partial or failed" : ""));
            return failed > 0 ? 1 : 0;
        }
        static void Usage()
        {
            Console.WriteLine(Collector.Name + " - collect everything the read-only PowerTower engines can see about this host into one sealed bundle (.ptb).");
            Console.WriteLine("usage: PowerTowerCollect [options]      exit 0 ok · 1 a module was partial or failed · 2 usage · 3 refused by the engagement");
            foreach (string[] h in CollectOptions.Help) Console.WriteLine("  --" + (h[0] + (h[1] != null ? " <" + h[1] + ">" : "")).PadRight(26) + h[2]);
            Console.WriteLine("  --help · --version");
        }
    }
}

// Entry point. Flags: --tool <PanelClassName>  --selftest <report.txt>  --shots <folder>
using System;
using System.Collections.Generic;
using System.IO;
using System.Windows.Forms;

namespace PSTools
{
    static class Program
    {
        /// <summary>Set by the self-test to collect unhandled exceptions instead of showing a dialog.</summary>
        public static Action<Exception> OnCrash;
        /// <summary>Screenshot/demo mode: panels show fabricated data only and never touch the real machine.</summary>
        public static bool DemoMode;
        static void Crash(Exception ex, bool fatal)
        {
            if (ex == null) return;
            try { File.AppendAllText(Path.Combine(Path.GetDirectoryName(Application.ExecutablePath), "crash.log"), DateTime.Now.ToString("s") + (fatal ? "  FATAL  " : "  ") + ex + "\r\n\r\n"); } catch { }
            if (OnCrash != null) { try { OnCrash(ex); } catch { } return; }
            try { MessageBox.Show("This action hit an error, but the app kept running:\n\n" + ex.Message + "\n\nDetails were written to crash.log next to the exe.", "PowerTower", MessageBoxButtons.OK, MessageBoxIcon.Warning); } catch { }
        }
        [STAThread]
        static void Main(string[] args)
        {
            Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false);
            // never die silently: log every unhandled exception and keep the window open
            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
            Application.ThreadException += delegate (object s, System.Threading.ThreadExceptionEventArgs e) { Crash(e.Exception, false); };
            AppDomain.CurrentDomain.UnhandledException += delegate (object s, UnhandledExceptionEventArgs e) { Crash(e.ExceptionObject as Exception, true); };
            string tool = "", selfTest = null, shots = null, theme = null;
            for (int i = 0; i < args.Length - 1; i++) { if (args[i] == "--tool") tool = args[i + 1]; if (args[i] == "--selftest") selfTest = args[i + 1]; if (args[i] == "--shots") shots = args[i + 1]; if (args[i] == "--theme") theme = args[i + 1]; }
            foreach (string a in args) if (a == "--demo") DemoMode = true;
            if (shots != null) DemoMode = true;   // --shots only makes sense on the fabricated demo data (without it the run hung for minutes and wrote nothing)
            Settings pre = new Settings(Path.Combine(Path.GetDirectoryName(Application.ExecutablePath), "settings.ini")); Theme.Apply(theme ?? pre.Get("theme", Theme.Names[0]));
            List<ToolPanel> tools = new List<ToolPanel>();
            tools.Add(new ReconPanel()); tools.Add(new BlockerPanel()); tools.Add(new ReachPanel()); tools.Add(new ConnPanel()); tools.Add(new NetMapPanel()); tools.Add(new FirewallPanel()); tools.Add(new HogsPanel()); tools.Add(new DiskPanel()); tools.Add(new DeletedPanel()); tools.Add(new FileExplorerPanel()); tools.Add(new FindPanel()); tools.Add(new DupesPanel()); tools.Add(new VulnPanel()); tools.Add(new SoftwarePanel()); tools.Add(new AutorunsPanel()); tools.Add(new EventsPanel()); tools.Add(new ChecklistPanel()); tools.Add(new SecretsPanel()); tools.Add(new CredsPanel()); tools.Add(new BrowserPanel()); tools.Add(new MapPanel()); tools.Add(new AboutPanel());
            Shell shell = new Shell(tools, tool); shell.SelfTestFile = selfTest; shell.ShotDir = shots;
            Application.Run(shell);
        }
    }
}

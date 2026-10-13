// Autoruns: every place Windows starts a program without being asked - run keys, RunOnce, policy run keys,
// Winlogon, image-hijacks (IFEO), AppInit DLLs, boot execute, Active Setup, startup folders, scheduled tasks,
// services and WMI event subscriptions - with the program each one runs, its signer and where it lives.
// Disable / enable follow the Sysinternals convention (an "AutorunsDisabled" subkey / subfolder) so the two tools agree.
using System;
using System.Collections.Generic;
using System.IO;
using System.Management;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace PSTools
{
    public class AutorunEntry
    {
        public string Kind = "", Name = "", Command = "", Image = "", Location = "", Scope = "", Description = "", Company = "", Note = "";
        public bool Enabled = true, Removable = true, Toggleable = true; public SigInfo Sig = new SigInfo(); public object Handle; public string RiskForce;
        public string Where { get { return Image.Length == 0 ? "" : Trust.Location(Image); } }
        public bool Exists { get { try { return Image.Length > 0 && File.Exists(Image); } catch { return false; } } }
        public string Signer { get { return Sig.Signer; } }
        public bool Microsoft { get { return Sig.Microsoft; } }
        /// <summary>high · medium · low · "" - unsigned or invalid programs in user-writable folders, hijacks, non-default Winlogon values.</summary>
        public string Risk
        {
            get
            {
                if (RiskForce != null) return RiskForce;
                if (Note.StartsWith("non-default") || Kind == "AppInit DLL") return "high";
                if (Kind == "Image hijack") return Sig.Microsoft ? "medium" : "high";
                if (Kind == "WMI subscription") return "medium";
                if (Image.Length == 0) return "";
                if (!Exists) return "medium";
                if (Sig.Status == "invalid") return "high";
                if (Sig.Status == "unsigned") return Where == "user-writable" || Where == "other" ? "high" : "medium";
                if (Sig.Ok && !Sig.Microsoft && Where == "user-writable") return "low";
                return "";
            }
        }
        public string RiskWhy
        {
            get
            {
                if (Note.Length > 0) return Note;
                if (Image.Length == 0) return Kind == "WMI subscription" ? "WMI persistence is rarely legitimate" : "";
                if (!Exists) return "program not found - a dangling entry can be hijacked";
                if (Sig.Status == "invalid") return "signature invalid: " + Sig.Detail;
                if (Sig.Status == "unsigned") return "unsigned program in " + (Where == "user-writable" ? "a user-writable folder" : Where == "other" ? "a non-standard folder" : Where);
                if (Sig.Ok && !Sig.Microsoft && Where == "user-writable") return "signed, but runs from a user-writable folder";
                return "";
            }
        }
    }

    public static partial class Autoruns   // collect + verify; AutorunsWrite.cs holds SetEnabled/Delete and is left out of the collector
    {
        const string Disabled = "AutorunsDisabled";
        class RegHandle { public RegistryHive Hive; public RegistryView View; public string Key, Value; public bool InDisabled; }
        class TaskHandle { public string Path; }
        class FileHandle { public string Path; }
        class ServiceHandle { public string Name; }
        class WmiHandle { public string Filter, Consumer, Binding; }

        public static List<AutorunEntry> Collect(Action<string> progress, Func<bool> cancelled)
        {
            List<AutorunEntry> l = new List<AutorunEntry>();
            Action<string> say = delegate (string m) { if (progress != null) progress(m); };
            Func<bool> stop = delegate { return cancelled != null && cancelled(); };
            say("run keys"); RunKeys(l); if (stop()) return l;
            say("Winlogon, image hijacks, AppInit, boot execute, Active Setup"); Winlogon(l); Ifeo(l); AppInit(l); BootExecute(l); ActiveSetup(l); LogonScripts(l); if (stop()) return l;
            say("startup folders"); StartupFolders(l); if (stop()) return l;
            say("scheduled tasks"); Tasks(l); if (stop()) return l;
            say("services"); Services(l); if (stop()) return l;
            say("WMI subscriptions"); Wmi(l);
            return l;
        }
        /// <summary>Signature + version info for every entry; call after Collect (slow part, ~10-50 ms per file).</summary>
        public static void Verify(List<AutorunEntry> l, Action<int, int> progress, Func<bool> cancelled)
        {
            int i = 0; foreach (AutorunEntry e in l)
            {
                if (cancelled != null && cancelled()) return; i++;
                if (e.Image.Length > 0) { e.Sig = Trust.Verify(e.Image); string[] v = Trust.VersionInfo(e.Image); e.Company = v[0]; if (e.Description.Length == 0) e.Description = v[1]; }
                if (progress != null && (i % 5 == 0 || i == l.Count)) progress(i, l.Count);
            }
        }

        // ── registry ──
        static readonly string[][] RunKeyList = {
            new string[] { "LocalMachine", "64", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Run key" },
            new string[] { "LocalMachine", "64", @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "RunOnce key" },
            new string[] { "LocalMachine", "64", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "Policy run key" },
            new string[] { "LocalMachine", "32", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Run key (32-bit)" },
            new string[] { "LocalMachine", "32", @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "RunOnce key (32-bit)" },
            new string[] { "CurrentUser", "64", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Run key" },
            new string[] { "CurrentUser", "64", @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "RunOnce key" },
            new string[] { "CurrentUser", "64", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "Policy run key" },
        };
        static RegistryHive HiveOf(string s) { return s == "CurrentUser" ? RegistryHive.CurrentUser : RegistryHive.LocalMachine; }
        static void RunKeys(List<AutorunEntry> l)
        {
            foreach (string[] k in RunKeyList)
            {
                RegistryHive hive = HiveOf(k[0]); RegistryView view = k[1] == "32" ? RegistryView.Registry32 : RegistryView.Registry64; string scope = hive == RegistryHive.CurrentUser ? "user" : "machine";
                try
                {
                    using (RegistryKey b = RegistryKey.OpenBaseKey(hive, view))
                    {
                        using (RegistryKey key = b.OpenSubKey(k[2])) if (key != null) foreach (string name in key.GetValueNames()) { if (name.Length == 0) continue; AddReg(l, k[3], hive, view, k[2], name, Convert.ToString(key.GetValue(name)), scope, false); }
                        using (RegistryKey key = b.OpenSubKey(k[2] + "\\" + Disabled)) if (key != null) foreach (string name in key.GetValueNames()) { if (name.Length == 0) continue; AddReg(l, k[3], hive, view, k[2], name, Convert.ToString(key.GetValue(name)), scope, true); }
                    }
                }
                catch { }
            }
        }
        static AutorunEntry AddReg(List<AutorunEntry> l, string kind, RegistryHive hive, RegistryView view, string key, string name, string cmd, string scope, bool disabled)
        {
            AutorunEntry e = new AutorunEntry(); e.Kind = kind; e.Name = name; e.Command = cmd ?? ""; e.Image = Trust.ImagePath(e.Command); e.Scope = scope; e.Enabled = !disabled;
            e.Location = (hive == RegistryHive.CurrentUser ? "HKCU\\" : "HKLM\\") + key + (view == RegistryView.Registry32 ? " (32-bit)" : "") + (disabled ? "\\" + Disabled : "");
            RegHandle h = new RegHandle(); h.Hive = hive; h.View = view; h.Key = key; h.Value = name; h.InDisabled = disabled; e.Handle = h; l.Add(e); return e;
        }
        static string RegStr(RegistryHive hive, RegistryView view, string key, string name)
        {
            try { using (RegistryKey b = RegistryKey.OpenBaseKey(hive, view)) using (RegistryKey k = b.OpenSubKey(key)) { object v = k == null ? null : k.GetValue(name); if (v == null) return null; if (v is string[]) return string.Join(" | ", (string[])v); return Convert.ToString(v); } } catch { return null; }
        }
        static void Winlogon(List<AutorunEntry> l)
        {
            const string K = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            string[][] vals = { new string[] { "Userinit", (win + "\\system32\\userinit.exe,").ToLowerInvariant() }, new string[] { "Shell", "explorer.exe" }, new string[] { "Taskman", "" }, new string[] { "AppSetup", "" }, new string[] { "VmApplet", "" } };
            foreach (string[] v in vals)
            {
                foreach (RegistryHive hive in new RegistryHive[] { RegistryHive.LocalMachine, RegistryHive.CurrentUser })
                {
                    string val = RegStr(hive, RegistryView.Registry64, K, v[0]); if (val == null || val.Trim().Length == 0) { if (hive == RegistryHive.LocalMachine && v[1].Length > 0) { } continue; }
                    string first = val.Split(',')[0].Trim(); bool def = v[1].Length > 0 && (val.Trim().ToLowerInvariant() == v[1] || first.ToLowerInvariant() == v[1].TrimEnd(','));
                    AutorunEntry e = new AutorunEntry(); e.Kind = "Winlogon"; e.Name = v[0]; e.Command = val; e.Image = Trust.ImagePath(first); e.Scope = hive == RegistryHive.CurrentUser ? "user" : "machine"; e.Location = (hive == RegistryHive.CurrentUser ? "HKCU\\" : "HKLM\\") + K; e.Toggleable = false; e.Removable = hive == RegistryHive.CurrentUser || v[1].Length == 0;
                    if (hive == RegistryHive.CurrentUser && (v[0] == "Shell" || v[0] == "Userinit")) e.Note = "non-default: a per-user " + v[0] + " override"; else if (!def && v[1].Length > 0) e.Note = "non-default " + v[0] + " (expected " + v[1] + ")"; else if (v[1].Length == 0) e.Note = "non-default: " + v[0] + " is normally empty";
                    RegHandle h = new RegHandle(); h.Hive = hive; h.View = RegistryView.Registry64; h.Key = K; h.Value = v[0]; e.Handle = h; l.Add(e);
                }
            }
        }
        static void Ifeo(List<AutorunEntry> l)
        {
            const string K = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
            try
            {
                using (RegistryKey b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)) using (RegistryKey k = b.OpenSubKey(K))
                {
                    if (k == null) return;
                    foreach (string sub in k.GetSubKeyNames())
                    {
                        try
                        {
                            using (RegistryKey s = k.OpenSubKey(sub))
                            {
                                string dbg = s == null ? null : Convert.ToString(s.GetValue("Debugger")); if (!string.IsNullOrEmpty(dbg)) { AutorunEntry e = new AutorunEntry(); e.Kind = "Image hijack"; e.Name = sub; e.Command = dbg; e.Image = Trust.ImagePath(dbg); e.Scope = "machine"; e.Location = "HKLM\\" + K + "\\" + sub + " · Debugger"; e.Toggleable = false; e.Description = "runs instead of " + sub; RegHandle h = new RegHandle(); h.Hive = RegistryHive.LocalMachine; h.View = RegistryView.Registry64; h.Key = K + "\\" + sub; h.Value = "Debugger"; e.Handle = h; l.Add(e); }
                            }
                        }
                        catch { }
                    }
                }
                using (RegistryKey b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)) using (RegistryKey k = b.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit"))
                {
                    if (k == null) return;
                    foreach (string sub in k.GetSubKeyNames())
                    {
                        try { using (RegistryKey s = k.OpenSubKey(sub)) { string mon = s == null ? null : Convert.ToString(s.GetValue("MonitorProcess")); if (!string.IsNullOrEmpty(mon)) { AutorunEntry e = new AutorunEntry(); e.Kind = "Image hijack"; e.Name = sub; e.Command = mon; e.Image = Trust.ImagePath(mon); e.Scope = "machine"; e.Location = @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\" + sub + " · MonitorProcess"; e.Toggleable = false; e.Description = "runs when " + sub + " exits"; RegHandle h = new RegHandle(); h.Hive = RegistryHive.LocalMachine; h.View = RegistryView.Registry64; h.Key = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\" + sub; h.Value = "MonitorProcess"; e.Handle = h; l.Add(e); } } } catch { }
                    }
                }
            }
            catch { }
        }
        static void AppInit(List<AutorunEntry> l)
        {
            foreach (RegistryView view in new RegistryView[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                const string K = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";
                string v = RegStr(RegistryHive.LocalMachine, view, K, "AppInit_DLLs"); if (string.IsNullOrEmpty(v) || v.Trim().Length == 0) continue;
                string load = RegStr(RegistryHive.LocalMachine, view, K, "LoadAppInit_DLLs");
                foreach (string dll in v.Split(new char[] { ',', ' ', ';' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    AutorunEntry e = new AutorunEntry(); e.Kind = "AppInit DLL"; e.Name = Path.GetFileName(dll); e.Command = dll; e.Image = Trust.ImagePath(dll); e.Scope = "machine"; e.Location = "HKLM\\" + K + (view == RegistryView.Registry32 ? " (32-bit)" : "") + " · AppInit_DLLs"; e.Enabled = load != "0"; e.Toggleable = false; e.Description = "loaded into every process that uses user32.dll";
                    RegHandle h = new RegHandle(); h.Hive = RegistryHive.LocalMachine; h.View = view; h.Key = K; h.Value = "AppInit_DLLs"; e.Handle = h; l.Add(e);
                }
            }
        }
        static void BootExecute(List<AutorunEntry> l)
        {
            const string K = @"SYSTEM\CurrentControlSet\Control\Session Manager";
            try
            {
                using (RegistryKey b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)) using (RegistryKey k = b.OpenSubKey(K))
                {
                    string[] v = k == null ? null : k.GetValue("BootExecute") as string[]; if (v == null) return;
                    foreach (string line in v)
                    {
                        if (line.Trim().Length == 0) continue; bool def = line.Trim().StartsWith("autocheck autochk", StringComparison.OrdinalIgnoreCase);
                        AutorunEntry e = new AutorunEntry(); e.Kind = "Boot execute"; e.Name = line.Split(' ')[0]; e.Command = line; e.Image = Trust.ImagePath(line.Split(' ')[0]); e.Scope = "machine"; e.Location = "HKLM\\" + K + " · BootExecute"; e.Toggleable = false; e.Removable = false; e.Description = "native program run by the session manager before logon"; if (!def) e.Note = "non-default boot-execute entry"; l.Add(e);
                    }
                }
            }
            catch { }
        }
        static void ActiveSetup(List<AutorunEntry> l)
        {
            foreach (RegistryView view in new RegistryView[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                const string K = @"SOFTWARE\Microsoft\Active Setup\Installed Components";
                try
                {
                    using (RegistryKey b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view)) using (RegistryKey k = b.OpenSubKey(K))
                    {
                        if (k == null) continue;
                        foreach (string sub in k.GetSubKeyNames())
                        {
                            try
                            {
                                using (RegistryKey s = k.OpenSubKey(sub))
                                {
                                    string stub = s == null ? null : Convert.ToString(s.GetValue("StubPath")); if (string.IsNullOrEmpty(stub)) continue;
                                    string name = Convert.ToString(s.GetValue("")); string enabled = Convert.ToString(s.GetValue("IsInstalled"));
                                    AutorunEntry e = new AutorunEntry(); e.Kind = "Active Setup"; e.Name = string.IsNullOrEmpty(name) ? sub : name; e.Command = stub; e.Image = Trust.ImagePath(stub); e.Scope = "machine"; e.Location = "HKLM\\" + K + "\\" + sub + (view == RegistryView.Registry32 ? " (32-bit)" : ""); e.Enabled = enabled != "0"; e.Toggleable = false; e.Description = "runs once per user at first logon";
                                    RegHandle h = new RegHandle(); h.Hive = RegistryHive.LocalMachine; h.View = view; h.Key = K + "\\" + sub; h.Value = "StubPath"; e.Handle = h; l.Add(e);
                                }
                            }
                            catch { }
                        }
                    }
                }
                catch { }
            }
        }
        static void LogonScripts(List<AutorunEntry> l)
        {
            foreach (RegistryHive hive in new RegistryHive[] { RegistryHive.CurrentUser, RegistryHive.LocalMachine })
            {
                string v = RegStr(hive, RegistryView.Registry64, "Environment", "UserInitMprLogonScript"); if (string.IsNullOrEmpty(v)) continue;
                AutorunEntry e = new AutorunEntry(); e.Kind = "Logon script"; e.Name = "UserInitMprLogonScript"; e.Command = v; e.Image = Trust.ImagePath(v); e.Scope = hive == RegistryHive.CurrentUser ? "user" : "machine"; e.Location = (hive == RegistryHive.CurrentUser ? "HKCU" : "HKLM") + "\\Environment"; e.Toggleable = false; e.Note = "non-default: logon script via the Environment key"; RegHandle h = new RegHandle(); h.Hive = hive; h.View = RegistryView.Registry64; h.Key = "Environment"; h.Value = "UserInitMprLogonScript"; e.Handle = h; l.Add(e);
            }
        }

        // ── startup folders ──
        static void StartupFolders(List<AutorunEntry> l)
        {
            foreach (string[] d in new string[][] { new string[] { Environment.GetFolderPath(Environment.SpecialFolder.Startup), "user" }, new string[] { Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), "machine" } })
            {
                if (string.IsNullOrEmpty(d[0])) continue;
                StartupDir(l, d[0], d[1], false); StartupDir(l, Path.Combine(d[0], Disabled), d[1], true);
            }
        }
        static void StartupDir(List<AutorunEntry> l, string dir, string scope, bool disabled)
        {
            try
            {
                if (!Directory.Exists(dir)) return;
                foreach (string f in Directory.GetFiles(dir))
                {
                    string name = Path.GetFileName(f); if (name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
                    AutorunEntry e = new AutorunEntry(); e.Kind = "Startup folder"; e.Name = name; e.Scope = scope; e.Location = dir; e.Enabled = !disabled; e.Command = f;
                    if (f.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase)) { string target, args; ShortcutTarget(f, out target, out args); e.Command = target.Length > 0 ? (args.Length > 0 ? "\"" + target + "\" " + args : target) : f; e.Image = target.Length > 0 ? Trust.ImagePath(target) : ""; e.Description = "shortcut"; }
                    else e.Image = f;
                    FileHandle h = new FileHandle(); h.Path = f; e.Handle = h; l.Add(e);
                }
            }
            catch { }
        }
        static void ShortcutTarget(string lnk, out string target, out string args)
        {
            target = ""; args = "";
            try { object shell = Com.Create("WScript.Shell"); object sc = Com.Call(shell, "CreateShortcut", lnk); target = Com.S(sc, "TargetPath"); args = Com.S(sc, "Arguments"); } catch { }
        }

        // ── scheduled tasks ──
        static void Tasks(List<AutorunEntry> l)
        {
            try { object svc = Com.Create("Schedule.Service"); Com.Call(svc, "Connect", Type.Missing, Type.Missing, Type.Missing, Type.Missing); object root = Com.Call(svc, "GetFolder", "\\"); WalkTasks(l, root, 0); }
            catch { }
        }
        static void WalkTasks(List<AutorunEntry> l, object folder, int depth)
        {
            if (depth > 8) return;
            try
            {
                object tasks = Com.Call(folder, "GetTasks", 1); int n = Com.Count(tasks);
                for (int i = 1; i <= n; i++)
                {
                    try
                    {
                        object t = Com.Item(tasks, i); string tpath = Com.S(t, "Path"); int state = 0; int.TryParse(Com.S(t, "State"), out state);
                        object def = Com.Prop(t, "Definition"); object actions = Com.Prop(def, "Actions"); int na = Com.Count(actions); object reg = Com.Prop(def, "RegistrationInfo"); object principal = Com.Prop(def, "Principal");
                        string author = Com.S(reg, "Author"), desc = Com.S(reg, "Description"), user = Com.S(principal, "UserId"), runLevel = Com.S(principal, "RunLevel");
                        bool any = false;
                        for (int a = 1; a <= na; a++)
                        {
                            object act = Com.Item(actions, a); int type = 0; int.TryParse(Com.S(act, "Type"), out type);
                            AutorunEntry e = new AutorunEntry(); e.Kind = "Scheduled task"; e.Name = Com.S(t, "Name"); e.Location = tpath; e.Scope = "machine"; e.Enabled = Com.S(t, "Enabled") != "False" && state != 1; e.Description = desc.Length > 0 ? desc : (author.Length > 0 ? "by " + author : "");
                            if (type == 0) { string path = Com.S(act, "Path"), args = Com.S(act, "Arguments"); e.Command = args.Length > 0 ? path + " " + args : path; e.Image = Trust.ImagePath(path); }
                            else if (type == 5) { e.Command = "COM handler " + Com.S(act, "ClassId"); e.Image = ComHandlerDll(Com.S(act, "ClassId")); }
                            else if (type == 6) e.Command = "send e-mail"; else if (type == 7) e.Command = "show message"; else e.Command = "action type " + type;
                            if (user.Length > 0) e.Company = ""; e.Note = runLevel == "1" && e.Image.Length > 0 && Trust.Location(e.Image) == "user-writable" ? "" : "";
                            TaskHandle h = new TaskHandle(); h.Path = tpath; e.Handle = h; l.Add(e); any = true;
                        }
                        if (!any) { AutorunEntry e = new AutorunEntry(); e.Kind = "Scheduled task"; e.Name = Com.S(t, "Name"); e.Location = tpath; e.Scope = "machine"; e.Enabled = Com.S(t, "Enabled") != "False"; e.Command = "(no actions)"; TaskHandle h = new TaskHandle(); h.Path = tpath; e.Handle = h; l.Add(e); }
                    }
                    catch { }
                }
                object subs = Com.Call(folder, "GetFolders", 0); int m = Com.Count(subs);
                for (int i = 1; i <= m; i++) { try { WalkTasks(l, Com.Item(subs, i), depth + 1); } catch { } }
            }
            catch { }
        }
        static string ComHandlerDll(string clsid)
        {
            if (string.IsNullOrEmpty(clsid)) return "";
            foreach (RegistryView view in new RegistryView[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                string v = RegStr(RegistryHive.ClassesRoot, view, "CLSID\\" + clsid + "\\InprocServer32", ""); if (!string.IsNullOrEmpty(v)) return Trust.ImagePath(v);
                v = RegStr(RegistryHive.ClassesRoot, view, "CLSID\\" + clsid + "\\LocalServer32", ""); if (!string.IsNullOrEmpty(v)) return Trust.ImagePath(v);
            }
            return "";
        }

        // ── services ──
        static void Services(List<AutorunEntry> l)
        {
            try
            {
                using (ManagementObjectSearcher q = new ManagementObjectSearcher("SELECT Name, DisplayName, PathName, StartMode, State, StartName, Description FROM Win32_Service"))
                    foreach (ManagementObject o in q.Get())
                    {
                        AutorunEntry e = new AutorunEntry(); e.Kind = "Service"; e.Name = Convert.ToString(o["DisplayName"]) ?? ""; string sname = Convert.ToString(o["Name"]) ?? ""; if (e.Name.Length == 0) e.Name = sname;
                        e.Command = Convert.ToString(o["PathName"]) ?? ""; e.Image = Trust.ImagePath(e.Command); string mode = Convert.ToString(o["StartMode"]) ?? ""; string state = Convert.ToString(o["State"]) ?? "";
                        e.Enabled = mode != "Disabled"; e.Scope = "machine"; e.Location = "service " + sname + " · " + mode.ToLowerInvariant() + " · " + state.ToLowerInvariant() + (Convert.ToString(o["StartName"]) != null && Convert.ToString(o["StartName"]).Length > 0 ? " · " + Convert.ToString(o["StartName"]) : ""); e.Description = Convert.ToString(o["Description"]) ?? "";
                        if (e.Command.Length > 0 && e.Command[0] != '"' && e.Command.Contains(" ") && e.Command.IndexOf(".exe", StringComparison.OrdinalIgnoreCase) > 0 && e.Command.Substring(0, e.Command.IndexOf(".exe", StringComparison.OrdinalIgnoreCase)).Contains(" ")) e.Note = "non-default: unquoted service path with a space";
                        ServiceHandle h = new ServiceHandle(); h.Name = sname; e.Handle = h; l.Add(e);
                    }
            }
            catch { }
        }

        // ── WMI event subscriptions ──
        static void Wmi(List<AutorunEntry> l)
        {
            try
            {
                ManagementScope scope = new ManagementScope(@"\\.\root\subscription"); scope.Connect();
                Dictionary<string, string> filters = new Dictionary<string, string>(), consumers = new Dictionary<string, string>(), ctype = new Dictionary<string, string>();
                using (ManagementObjectSearcher q = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM __EventFilter"))) foreach (ManagementObject o in q.Get()) filters[Convert.ToString(o["Name"])] = Convert.ToString(o["Query"]);
                foreach (string cls in new string[] { "CommandLineEventConsumer", "ActiveScriptEventConsumer" })
                {
                    try { using (ManagementObjectSearcher q = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM " + cls))) foreach (ManagementObject o in q.Get()) { string n = Convert.ToString(o["Name"]); string cmd = cls == "CommandLineEventConsumer" ? (Convert.ToString(o["CommandLineTemplate"]) ?? Convert.ToString(o["ExecutablePath"])) : (Convert.ToString(o["ScriptFileName"]) ?? "") + " " + (Convert.ToString(o["ScriptText"]) ?? ""); consumers[n] = (cmd ?? "").Trim(); ctype[n] = cls; } } catch { }
                }
                HashSet<string> bound = new HashSet<string>();
                using (ManagementObjectSearcher q = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM __FilterToConsumerBinding")))
                    foreach (ManagementObject o in q.Get())
                    {
                        string f = RefName(Convert.ToString(o["Filter"])), c = RefName(Convert.ToString(o["Consumer"])); bound.Add(c);
                        string cmd; if (!consumers.TryGetValue(c, out cmd)) cmd = "(consumer " + c + ")"; string query; if (!filters.TryGetValue(f, out query)) query = "";
                        AutorunEntry e = new AutorunEntry(); e.Kind = "WMI subscription"; e.Name = c; e.Command = cmd; e.Image = Trust.ImagePath(cmd); e.Scope = "machine"; e.Location = "root\\subscription · filter " + f; e.Description = query; e.Toggleable = false;
                        WmiHandle h = new WmiHandle(); h.Filter = f; h.Consumer = c; h.Binding = o.Path.RelativePath; e.Handle = h; l.Add(e);
                    }
                foreach (KeyValuePair<string, string> kv in consumers) if (!bound.Contains(kv.Key)) { AutorunEntry e = new AutorunEntry(); e.Kind = "WMI subscription"; e.Name = kv.Key; e.Command = kv.Value; e.Image = Trust.ImagePath(kv.Value); e.Scope = "machine"; e.Location = "root\\subscription · " + ctype[kv.Key] + " (not bound)"; e.Enabled = false; e.Toggleable = false; WmiHandle h = new WmiHandle(); h.Consumer = kv.Key; e.Handle = h; l.Add(e); }
            }
            catch { }
        }
        static string RefName(string path) { if (path == null) return ""; Match m = Regex.Match(path, "Name=\"([^\"]*)\""); return m.Success ? m.Groups[1].Value : path; }

    }
}
